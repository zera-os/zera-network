#pragma once

// Filesystem-only restore transaction. Call before opening any live databases.
// Keep this independent of validator globals so failure cases can be tested.
#include <filesystem>
#include <fstream>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

namespace safe_restore {
namespace fs = std::filesystem;

inline bool safe_component(const std::string& value)
{
    if (value.empty() || value.size() > 128 || value == "." || value == "..") return false;
    for (unsigned char c : value)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') || c == '_' || c == '-' || c == '.')) return false;
    return true;
}

inline void sync_path(const fs::path& path)
{
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) throw std::runtime_error("Cannot open for fsync: " + path.string());
    const int result = ::fsync(fd);
    const int error = errno;
    ::close(fd);
    if (result != 0) throw std::runtime_error("Cannot fsync " + path.string() + ": " + std::strerror(error));
}

inline void write_new_file(const fs::path& path, const std::string& text)
{
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) throw std::runtime_error("Cannot create recovery record: " + path.string());
    size_t offset = 0;
    while (offset < text.size()) {
        const auto count = ::write(fd, text.data() + offset, text.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { ::close(fd); throw std::runtime_error("Cannot write recovery record: " + path.string()); }
        offset += static_cast<size_t>(count);
    }
    const int result = ::fsync(fd);
    ::close(fd);
    if (result != 0) throw std::runtime_error("Cannot fsync recovery record: " + path.string());
    sync_path(path.parent_path());
}

class DataDirectoryLock {
    int fd_ = -1;
public:
    explicit DataDirectoryLock(const fs::path& root) {
        fs::create_directories(root);
        fd_ = ::open((root / ".validator.lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd_ < 0 || ::flock(fd_, LOCK_EX | LOCK_NB) != 0) {
            if (fd_ >= 0) ::close(fd_);
            throw std::runtime_error("Another validator owns this data directory, or its lock is unavailable");
        }
    }
    ~DataDirectoryLock() { if (fd_ >= 0) ::close(fd_); }
    DataDirectoryLock(const DataDirectoryLock&) = delete;
    DataDirectoryLock& operator=(const DataDirectoryLock&) = delete;
};

inline void reject_links(const fs::path& path)
{
    if (fs::is_symlink(fs::symlink_status(path)))
        throw std::runtime_error("Symlink is not allowed in recovery: " + path.string());
    for (const auto& entry : fs::recursive_directory_iterator(path)) {
        const auto type = entry.symlink_status().type();
        if (type != fs::file_type::regular && type != fs::file_type::directory)
            throw std::runtime_error("Non-regular recovery entry: " + entry.path().string());
    }
}

inline void check_database_files(const fs::path& path)
{
    if (!fs::is_directory(path)) throw std::runtime_error("Missing database directory: " + path.string());
    reject_links(path);
    const auto current = path / "CURRENT";
    if (!fs::is_regular_file(current) || fs::file_size(current) > 256)
        throw std::runtime_error("Missing or invalid CURRENT: " + path.string());
    std::ifstream file(current);
    std::string manifest;
    std::getline(file, manifest);
    if (!manifest.empty() && manifest.back() == '\r') manifest.pop_back();
    if (!safe_component(manifest) || manifest.rfind("MANIFEST-", 0) != 0 ||
        !fs::is_regular_file(path / manifest))
        throw std::runtime_error("Missing or invalid MANIFEST: " + path.string());
}

inline void copy_tree(const fs::path& source, const fs::path& target)
{
    fs::create_directory(target);
    for (const auto& entry : fs::directory_iterator(source)) {
        const auto destination = target / entry.path().filename();
        const auto type = entry.symlink_status().type();
        if (type == fs::file_type::directory) copy_tree(entry.path(), destination);
        else if (type == fs::file_type::regular) {
            fs::copy_file(entry.path(), destination); // Never overwrite or share mutable hardlinks.
            if (fs::file_size(entry.path()) != fs::file_size(destination))
                throw std::runtime_error("Incomplete restore copy: " + destination.string());
            sync_path(destination);
        } else throw std::runtime_error("Non-regular recovery entry: " + entry.path().string());
    }
    sync_path(target);
}

struct Result {
    bool ok = false;
    fs::path retained;
    std::string error;
};

// A marker survives an interrupted rename or failed rollback. Startup must refuse
// to open/create databases until an operator resolves it using retained evidence.
inline void check_no_interrupted_restore(const fs::path& data_root)
{
    if (fs::symlink_status(data_root / "restore.in-progress").type() != fs::file_type::not_found)
        throw std::runtime_error("Interrupted restore: inspect restore.in-progress and recovery/ before restarting");
}

inline Result restore(const fs::path& data_root, const fs::path& source_path,
                      const std::vector<std::string>& databases,
                      const std::function<void(const fs::path&)>& validate,
                      const std::function<void(const std::string&)>& fault = {})
{
    Result result;
    fs::path live, stage, previous, marker;
    bool old_moved = false, installed = false, marked = false;
    auto step = [&](const std::string& name) { if (fault) fault(name); };
    try {
        const auto root = fs::canonical(data_root);
        check_no_interrupted_restore(root);
        live = root / "blockchain";
        marker = root / "restore.in-progress";
        if (fs::is_symlink(fs::symlink_status(live))) throw std::runtime_error("Live database root is a symlink");
        const auto source = fs::canonical(source_path);
        const auto relative = source.lexically_relative(root);
        auto part = relative.begin();
        if (part == relative.end() || (*part != "reorgs" && *part != "copy" && *part != "checkpoints"))
            throw std::runtime_error("Restore source must be in this data directory's reorgs, copy or checkpoints root");
        if (++part == relative.end() || !safe_component(part->string()) || ++part != relative.end())
            throw std::runtime_error("Restore source must be one snapshot directory");
        if (fs::weakly_canonical(source_path) != fs::absolute(source_path).lexically_normal())
            throw std::runtime_error("Restore source path contains a symlink");
        if (databases.empty()) throw std::runtime_error("Empty database inventory");
        for (const auto& name : databases) {
            if (!safe_component(name)) throw std::runtime_error("Invalid database name");
            check_database_files(source / name);
        }
        const auto recovery = root / "recovery";
        if (fs::is_symlink(fs::symlink_status(recovery))) throw std::runtime_error("Recovery root is a symlink");
        fs::create_directories(recovery);
        const auto id = "restore-" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + "-" + std::to_string(::getpid());
        result.retained = recovery / id;
        if (!fs::create_directory(result.retained)) throw std::runtime_error("Restore directory already exists");
        fs::permissions(result.retained, fs::perms::owner_all);
        stage = result.retained / "staged-blockchain";
        previous = result.retained / "previous-blockchain";
        fs::create_directory(stage);
        write_new_file(result.retained / "source.txt", source.string() + "\n");
        for (const auto& name : databases) {
            copy_tree(source / name, stage / name);
            validate(stage / name); // Open without create-if-missing and verify RocksDB checksums.
        }
        sync_path(stage);
        sync_path(result.retained);
        sync_path(recovery);
        step("staged");
        write_new_file(marker, id + "\nsource=" + source.string() + "\n");
        marked = true;
        step("before-retain");
        if (fs::exists(live)) {
            fs::rename(live, previous);
            old_moved = true;
            sync_path(root);
            sync_path(result.retained);
        }
        step("after-retain");
        fs::rename(stage, live);
        installed = true;
        sync_path(root);
        sync_path(result.retained);
        step("installed");
        write_new_file(result.retained / "completed.txt", "Installed validated snapshot; previous-blockchain is retained for manual recovery.\n");
        fs::remove(marker);
        step("marker-removed");
        sync_path(root);
        result.ok = true;
    } catch (const std::exception& error) {
        result.error = error.what();
        if (marked) {
            try {
                // A completion fsync may fail after unlinking the marker. Make
                // startup fail closed before attempting any rollback renames.
                if (fs::symlink_status(marker).type() == fs::file_type::not_found)
                    write_new_file(marker, "Incomplete restore: " + result.retained.string() + "\n");
                if (installed) fs::rename(live, result.retained / "failed-blockchain");
                if (old_moved) fs::rename(previous, live);
                sync_path(data_root);
                sync_path(result.retained);
            } catch (const std::exception& rollback) {
                result.error += "; rollback requires manual recovery: " + std::string(rollback.what());
            }
            // Keep the marker even after successful rollback; no automatic empty DB creation.
        }
    }
    return result;
}
} // namespace safe_restore
