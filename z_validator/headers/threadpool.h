#pragma once
#include <iostream>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <atomic>
#include "../logging/logging.h"

// size_t maxQueueSize = 1500;

class ThreadPool
{
public:
    // Initialize or resize the thread pool
    static void setNumThreads(size_t numThreads = 0);
    // Enqueue a task into the thread pool
    static void enqueueTask(std::function<void()> task);
    static void enqueueTaskFront(std::function<void()> task);

    // Shutdown the thread pool
    static void shutdown();

private:
    // Private constructor to prevent instantiation
    ThreadPool() = default;

    // Worker thread function
    static void workerThread();

    static std::vector<std::thread> workers;        // Shared worker threads
    static std::queue<std::function<void()>> tasks; // Shared task queue
    static std::mutex queueMutex;                   // Shared mutex for task queue
    static std::condition_variable condition;       // Shared condition variable
    static std::atomic<bool> stop;                  // Shared stop flag
    static std::atomic<bool> initialized;           // Indicates if the thread pool is initialized
    static size_t maxQueueSize;                      // Maximum size of the task queue
};
class ValidatorThreadPool
{
public:
    // Initialize or resize the thread pool
    static void setNumThreads(size_t numThreads = 0);

    // Enqueue a task into the thread pool
    static void enqueueTask(std::function<void()> task);
    // Shutdown the thread pool
    static void shutdown();

private:
    // Private constructor to prevent instantiation
    ValidatorThreadPool() = default;

    // Worker thread function
    static void workerThread();

    static std::vector<std::thread> workers;        // Shared worker threads
    static std::queue<std::function<void()>> tasks; // Shared task queue
    static std::mutex queueMutex;                   // Shared mutex for task queue
    static std::condition_variable condition;       // Shared condition variable
    static std::atomic<bool> stop;                  // Shared stop flag
    static std::atomic<bool> initialized;           // Indicates if the thread pool is initialized
    static size_t maxQueueSize;   
};