#include "logging.h"

#include <iostream>
#include <fstream>
#include <ctime>
#include <iomanip>

#include "validators.h"

void logging::log(const std::string &msg)
{
    std::ofstream log_file;
    log_file.open("/data/logs/grpc-service.log", std::ios_base::app); // Open in append mode
    if (!log_file.is_open())
    {
        // Handle error if the file cannot be opened
        std::cerr << "Unable to open log file" << std::endl;
        return;
    }
    std::time_t t = std::time(nullptr);
    std::tm tm = *std::localtime(&t);
    log_file << std::put_time(&tm, "%d-%m-%Y %H-%M-%S") << " " << msg << std::endl;
    log_file.close();
}

void logging::print(const std::string &msg, bool dev)
{
    bool print_line = false;

    if (ValidatorConfig::get_dev_mode())
    {
        print_line = true;
    }

    if (!dev && !ValidatorConfig::get_dev_mode())
    {
        print_line = true;
    }

    if(print_line)
    {
        std::cout << msg << std::endl;
    }
}

void logging::print(const std::string &msg, const std::string &msg2, bool dev)
{
    bool print_line = false;

    if (ValidatorConfig::get_dev_mode())
    {
        print_line = true;
    }

    if (!dev && !ValidatorConfig::get_dev_mode())
    {
        print_line = true;
    }

    if(print_line)
    {
        std::cout << msg << " " << msg2 << std::endl;
    }
}

void logging::print(const std::string &msg, const std::string &msg2, const std::string &msg3, bool dev)
{
    bool print_line = false;

    if (ValidatorConfig::get_dev_mode())
    {
        print_line = true;
    }

    if (!dev && !ValidatorConfig::get_dev_mode())
    {
        print_line = true;
    }

    if(print_line)
    {
        std::cout << msg << " " << msg2 << " " << msg3 << std::endl;
    }
}

void logging::print(const std::string &msg, const std::string &msg2, const std::string &msg3, const std::string &msg4, bool dev)
{
    bool print_line = false;

    if (ValidatorConfig::get_dev_mode())
    {
        print_line = true;
    }

    if (!dev && !ValidatorConfig::get_dev_mode())
    {
        print_line = true;
    }

    if(print_line)
    {
        std::cout << msg << " " << msg2 << " " << msg3 << " " << msg4 << std::endl;
    }
}