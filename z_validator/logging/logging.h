#pragma once

#include <string>
#include <memory>

namespace spdlog {
    class logger;
}

class logging {
public:
    // Initialize the logging system (call once at startup)
    static bool init();

    // Shutdown the logging system (call once at exit)
    static void shutdown();

    // Legacy log function (writes to file with rotation)
    static void log(const std::string &msg);

    // Print functions with dev mode support
    static void print(const std::string &msg, bool dev = true);
    static void print(const std::string &msg, const std::string &msg2, bool dev = true);
    static void print(const std::string &msg, const std::string &msg2, const std::string &msg3, bool dev = true);
    static void print(const std::string &msg, const std::string &msg2, const std::string &msg3, const std::string &msg4, bool dev = true);

    // New structured logging methods (recommended)
    static void info(const std::string &msg);
    static void warn(const std::string &msg);
    static void error(const std::string &msg);
    static void debug(const std::string &msg);
    static void critical(const std::string &msg);

private:
    static std::shared_ptr<spdlog::logger> file_logger_;
    static std::shared_ptr<spdlog::logger> console_logger_;
    static bool initialized_;

    static void ensure_initialized();
};
