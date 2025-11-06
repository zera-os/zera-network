#include <iostream>
#include <chrono>
#include <iomanip>

#include "time_calc.h"

int time_calc::testing_int = 0;

std::tm time_calc::get_start_date(const google::protobuf::Timestamp& timestamp)
{
    std::time_t t = timestamp.seconds();
    std::tm now;

    localtime_r(&t, &now); // Use localtime_s for thread safety

    return now;
}

std::tm time_calc::get_process_date_cycle(const google::protobuf::Timestamp& timestamp, uint32_t add_days, uint32_t add_months)
{
    std::tm original = get_start_date(timestamp);
    std::time_t t = std::time(nullptr);
    std::tm now;

    localtime_r(&t, &now); // Use localtime_s for thread safety

    now.tm_hour = original.tm_hour;
    std::mktime(&now); // Normalize after setting the month and day
    now.tm_mon += add_months;
    std::mktime(&now); // Normalize after setting the month and day
    now.tm_mday += add_days;
    std::mktime(&now); // Normalize after setting the month and day

    return now;
}

google::protobuf::Timestamp time_calc::get_end_date_cycle(const google::protobuf::Timestamp& timestamp, uint32_t add_days, uint32_t add_months)
{
    std::tm original = get_start_date(timestamp);

    original.tm_mon += add_months;
    std::mktime(&original); // Normalize after setting the month and day
    original.tm_mday += add_days;
    std::mktime(&original); // Normalize after setting the month and day

    std::time_t time = std::mktime(&original);
    google::protobuf::Timestamp ts;
    ts.set_seconds(time);
    ts.set_nanos(0);

    return ts;
}

std::tm time_calc::process_date_staggered(const google::protobuf::Timestamp& timestamp, uint32_t add_days, uint32_t add_months)
{
    std::time_t t = timestamp.seconds();
    std::tm now;

    localtime_r(&t, &now); // Use localtime_s for thread safety

    now.tm_mday += add_days;
    std::mktime(&now); // Normalize after setting the month and day

    now.tm_mon += add_months;
    std::mktime(&now); // Normalize after setting the month and day

    return now;
}

std::string time_calc::convert_to_key_hours(const google::protobuf::Timestamp& timestamp)
{
    std::time_t t = timestamp.seconds();
    std::tm date;

    localtime_r(&t, &date); // Use localtime_s for thread safety

    std::string key = std::to_string(date.tm_year + 1900) +
                      std::to_string(date.tm_mon + 1) +
                      std::to_string(date.tm_mday) +
                      std::to_string(date.tm_hour);

    return key;
}

std::string time_calc::convert_to_key_hours(std::tm &date)
{
    std::string key = std::to_string(date.tm_year + 1900) +
                      std::to_string(date.tm_mon + 1) +
                      std::to_string(date.tm_mday) +
                      std::to_string(date.tm_hour);

    return key;
}

std::string time_calc::convert_to_key_minutes(std::tm &date)
{
    std::string key = std::to_string(date.tm_year + 1900) +
                      std::to_string(date.tm_mon + 1) +
                      std::to_string(date.tm_mday) +
                      std::to_string(date.tm_hour) +
                      std::to_string(date.tm_min);

    return key;
}

std::string time_calc::get_key_hour(){

    std::time_t t = std::time(nullptr);
    std::tm now;
    localtime_r(&t, &now); // Use localtime_s for thread safety

    std::string key = convert_to_key_hours(now);

    return convert_to_key_hours(now);
}

std::string time_calc::get_key_minute(){
    std::time_t t = std::time(nullptr);
    std::tm now;

    localtime_r(&t, &now); // Use localtime_s for thread safety

    return convert_to_key_minutes(now);
}

std::string time_calc::get_last_hour(){

    std::time_t t = std::time(nullptr);
    std::tm now;

    localtime_r(&t, &now); // Use localtime_s for thread safety

    now.tm_hour -= 1;

    std::mktime(&now); // Normalize after setting the month and day

    return convert_to_key_hours(now);
}
std::string time_calc::get_last_minute(){
    std::time_t t = std::time(nullptr);
    std::tm now;

    localtime_r(&t, &now); // Use localtime_s for thread safety
    now.tm_min -= 1;

    std::mktime(&now); // Normalize after setting the month and day

    return convert_to_key_minutes(now);
}

void time_calc::get_txn_duplicate_keys(const google::protobuf::Timestamp& txn_timestamp, std::string& txn_key)
{
    std::time_t txn_t = txn_timestamp.seconds();
    std::tm txn_date;

    localtime_r(&txn_t, &txn_date);

    txn_date.tm_hour += 2;
    std::mktime(&txn_date);

    txn_key = convert_to_key_hours(txn_date);
}