#pragma once

#include <string>

class logging{
public:
    static void log(const std::string &msg);
    static void print(const std::string &msg, bool dev = true);
    static void print(const std::string &msg, const std::string &msg2, bool dev = true);
    static void print(const std::string &msg, const std::string &msg2, const std::string &msg3, bool dev = true);
    static void print(const std::string &msg, const std::string &msg2, const std::string &msg3, const std::string &msg4, bool dev = true);
};