#pragma once

#include <iostream>
#include <chrono>
#include <iomanip>

#include <google/protobuf/timestamp.pb.h>

class time_calc
{
public:
    static google::protobuf::Timestamp get_end_date_cycle(const google::protobuf::Timestamp& timestamp, uint32_t add_days, uint32_t add_months);
    static std::tm get_start_date(const google::protobuf::Timestamp& timestamp);
    static std::tm get_process_date_cycle(const google::protobuf::Timestamp& timestamp, uint32_t add_days, uint32_t add_months);
    static std::tm process_date_staggered(const google::protobuf::Timestamp& timestamp, uint32_t add_days, uint32_t add_months);
    static std::string convert_to_key_hours(std::tm &date);
    static std::string convert_to_key_hours(const google::protobuf::Timestamp& timestamp);
    static std::string convert_to_key_minutes(std::tm &date);
    static std::string get_key_hour();
    static std::string get_key_minute();
    static std::string get_last_hour();
    static std::string get_last_minute();
    static void get_txn_duplicate_keys(const google::protobuf::Timestamp& txn_timestamp, std::string& txn_key);
    
private:
    static int testing_int;
};