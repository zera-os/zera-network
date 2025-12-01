#include "logging.h"

#include <iostream>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/daily_file_sink.h>

#include "validators.h"
#include "const.h"

// Static member initialization
std::shared_ptr<spdlog::logger> logging::file_logger_ = nullptr;
std::shared_ptr<spdlog::logger> logging::console_logger_ = nullptr;
bool logging::initialized_ = false;

bool logging::init()
{
    if (initialized_)
    {
        return true;
    }

    try
    {
        // Configure rotating file sink
        // Max file size: 100MB, Max files: 10 (keeps ~1GB of logs)
        std::string logging_path = LOG_DIRECTORY + "zera-validator.log";
        auto rotating_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            logging_path,
            100 * 1024 * 1024,  // 100MB per file
            10                   // Keep 10 rotated files
        );
        rotating_sink->set_level(spdlog::level::trace);

        // Configure console sink with colors
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::info);

        // Create multi-sink logger for file
        file_logger_ = std::make_shared<spdlog::logger>("file", rotating_sink);
        file_logger_->set_level(spdlog::level::trace);
        file_logger_->flush_on(spdlog::level::info);  // Auto-flush on info and above
        file_logger_->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");

        // Create console logger
        console_logger_ = std::make_shared<spdlog::logger>("console", console_sink);
        console_logger_->set_level(spdlog::level::info);
        console_logger_->set_pattern("[%Y-%m-%d %H:%M:%S] [%^%l%$] %v");

        // Register loggers
        spdlog::register_logger(file_logger_);
        spdlog::register_logger(console_logger_);

        initialized_ = true;

        info("Logging system initialized with rotation (100MB max per file, 10 files max)");
    }
    catch (const spdlog::spdlog_ex &ex)
    {
        std::cerr << "Log initialization failed: " << ex.what() << std::endl;
        // Fallback to stdout
        initialized_ = false;

        return false;
    }

    return true;
}

void logging::shutdown()
{
    if (file_logger_)
    {
        file_logger_->flush();
        file_logger_.reset();
    }
    if (console_logger_)
    {
        console_logger_->flush();
        console_logger_.reset();
    }
    spdlog::shutdown();
    initialized_ = false;
}

void logging::ensure_initialized()
{
    if (!initialized_)
    {
        init();
    }
}

// Legacy log function - writes to file
void logging::log(const std::string &msg)
{
    ensure_initialized();

    if (file_logger_)
    {
        file_logger_->info(msg);
    }
    else
    {
        // Fallback if logger isn't available
        std::cerr << msg << std::endl;
    }
}

// Print function with dev mode support - simple output without log level prefix
void logging::print(const std::string &msg, bool dev)
{
    bool should_print = false;

    if (ValidatorConfig::get_dev_mode())
    {
        should_print = true;
    }

    if (!dev && !ValidatorConfig::get_dev_mode())
    {
        should_print = true;
    }

    if (should_print)
    {
        std::cout << msg << std::endl;
    }
}

void logging::print(const std::string &msg, const std::string &msg2, bool dev)
{
    bool should_print = false;

    if (ValidatorConfig::get_dev_mode())
    {
        should_print = true;
    }

    if (!dev && !ValidatorConfig::get_dev_mode())
    {
        should_print = true;
    }

    if (should_print)
    {
        std::cout << msg << " " << msg2 << std::endl;
    }
}

void logging::print(const std::string &msg, const std::string &msg2, const std::string &msg3, bool dev)
{
    bool should_print = false;

    if (ValidatorConfig::get_dev_mode())
    {
        should_print = true;
    }

    if (!dev && !ValidatorConfig::get_dev_mode())
    {
        should_print = true;
    }

    if (should_print)
    {
        std::cout << msg << " " << msg2 << " " << msg3 << std::endl;
    }
}

void logging::print(const std::string &msg, const std::string &msg2, const std::string &msg3, const std::string &msg4, bool dev)
{
    bool should_print = false;

    if (ValidatorConfig::get_dev_mode())
    {
        should_print = true;
    }

    if (!dev && !ValidatorConfig::get_dev_mode())
    {
        should_print = true;
    }

    if (should_print)
    {
        std::cout << msg << " " << msg2 << " " << msg3 << " " << msg4 << std::endl;
    }
}

// New structured logging methods
void logging::info(const std::string &msg)
{
    ensure_initialized();

    if (file_logger_)
    {
        file_logger_->info(msg);
    }
    if (console_logger_ && ValidatorConfig::get_dev_mode())
    {
        console_logger_->info(msg);
    }
}

void logging::warn(const std::string &msg)
{
    ensure_initialized();

    if (file_logger_)
    {
        file_logger_->warn(msg);
    }
    if (console_logger_)
    {
        console_logger_->warn(msg);
    }
}

void logging::error(const std::string &msg)
{
    ensure_initialized();

    if (file_logger_)
    {
        file_logger_->error(msg);
    }
    if (console_logger_)
    {
        console_logger_->error(msg);
    }
}

void logging::debug(const std::string &msg)
{
    ensure_initialized();

    if (file_logger_)
    {
        file_logger_->debug(msg);
    }
    if (console_logger_ && ValidatorConfig::get_dev_mode())
    {
        console_logger_->debug(msg);
    }
}

void logging::critical(const std::string &msg)
{
    ensure_initialized();

    if (file_logger_)
    {
        file_logger_->critical(msg);
        file_logger_->flush();  // Immediately flush critical messages
    }
    if (console_logger_)
    {
        console_logger_->critical(msg);
        console_logger_->flush();
    }
}
