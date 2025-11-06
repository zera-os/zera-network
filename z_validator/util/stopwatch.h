#pragma once
#include <iostream>
#include <chrono>
#include <thread>

class Stopwatch {
    public:
        void start() {
            start_time = std::chrono::high_resolution_clock::now();
            running = true;
        }
    
        void stop() {
            if (running) {
                end_time = std::chrono::high_resolution_clock::now();
                running = false;
            }
        }
    
        void reset() {
            running = false;
        }
    
        double elapsed_seconds() const {
            if (running) {
                auto now = std::chrono::high_resolution_clock::now();
                return std::chrono::duration<double>(now - start_time).count();
            } else {
                return std::chrono::duration<double>(end_time - start_time).count();
            }
        }
    
    private:
        std::chrono::high_resolution_clock::time_point start_time;
        std::chrono::high_resolution_clock::time_point end_time;
        bool running = false;
    };