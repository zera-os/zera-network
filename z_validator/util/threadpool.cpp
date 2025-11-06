#include "threadpool.h"


// Define static members
std::vector<std::thread> ThreadPool::workers;
std::queue<std::function<void()>> ThreadPool::tasks;
std::mutex ThreadPool::queueMutex;
std::condition_variable ThreadPool::condition;
std::atomic<bool> ThreadPool::stop(false);
std::atomic<bool> ThreadPool::initialized(false);
size_t ThreadPool::maxQueueSize = 20000; // Maximum size of the task queue

void ThreadPool::setNumThreads(size_t numThreads)
{
    std::unique_lock<std::mutex> lock(queueMutex);

    // Shutdown existing threads if resizing
    if (initialized)
    {
        stop = true;
        condition.notify_all();
        for (std::thread &worker : workers)
        {
            if (worker.joinable())
            {
                worker.join();
            }
        }
        workers.clear();
        stop = false;
    }

    // Calculate 75% of hardware concurrency if numThreads is not provided
    if (numThreads == 0)
    {
        size_t threads = static_cast<size_t>(std::thread::hardware_concurrency() * 1.5);
        numThreads = std::max<size_t>(4, threads); // Ensure at least 1 thread
    }

    logging::print("Initializing ThreadPool with", std::to_string(numThreads) + " threads.");

    // Create new threads
    for (size_t i = 0; i < numThreads; ++i)
    {
        workers.emplace_back(&ThreadPool::workerThread);
    }

    initialized = true;
}

void ThreadPool::enqueueTask(std::function<void()> task)
{
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        condition.wait(lock, []
                       { return tasks.size() < maxQueueSize || stop; });
        if (stop)
        {
            throw std::runtime_error("Cannot enqueue task on stopped ValidatorThreadPool");
        }
        tasks.push(std::move(task));
    }
    condition.notify_one();
}

void ThreadPool::enqueueTaskFront(std::function<void()> task)
{
    // {
    //     std::unique_lock<std::mutex> lock(queueMutex);
    //     condition.wait(lock, []
    //                    { return  stop; });
    //     if (stop)
    //     {
    //         throw std::runtime_error("Cannot enqueue task on stopped ThreadPool");
    //     }
    //     tasks.push_front(std::move(task)); // Push task to the front of the deque
    // }
    // condition.notify_one();
}

void ThreadPool::shutdown()
{
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        stop = true;
    }
    condition.notify_all();
    for (std::thread &worker : workers)
    {
        if (worker.joinable())
        {
            worker.join();
        }
    }
    workers.clear();
    initialized = false;
}

void ThreadPool::workerThread()
{
    while (true)
    {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            condition.wait(lock, []
                           { return stop || !tasks.empty(); });
            if (stop && tasks.empty())
            {
                return;
            }
            task = std::move(tasks.front());
            tasks.pop();
        }
        try
        {
            task();
        }
        catch (const std::exception &e)
        {
            logging::print("Exception in task: " + std::string(e.what()));
        }
        catch (...)
        {
            logging::print("Unknown exception in task.");
        }
    }
}



// Define static members
std::vector<std::thread> ValidatorThreadPool::workers;
std::queue<std::function<void()>> ValidatorThreadPool::tasks;
std::mutex ValidatorThreadPool::queueMutex;
std::condition_variable ValidatorThreadPool::condition;
std::atomic<bool> ValidatorThreadPool::stop(false);
std::atomic<bool> ValidatorThreadPool::initialized(false);
size_t ValidatorThreadPool::maxQueueSize = 10000;

void ValidatorThreadPool::setNumThreads(size_t numThreads)
{
    std::unique_lock<std::mutex> lock(queueMutex);

    // Shutdown existing threads if resizing
    if (initialized)
    {
        stop = true;
        condition.notify_all();
        for (std::thread &worker : workers)
        {
            if (worker.joinable())
            {
                worker.join();
            }
        }
        workers.clear();
        stop = false;
    }

    // Calculate 75% of hardware concurrency if numThreads is not provided
    if (numThreads == 0)
    {
        size_t threads = static_cast<size_t>(std::thread::hardware_concurrency() * 0.5);
        numThreads = std::max<size_t>(4, threads); // Ensure at least 1 thread
    }

    logging::print("Initializing ValidatorThreadPool with", std::to_string(numThreads) + " threads.");

    // Create new threads
    for (size_t i = 0; i < numThreads; ++i)
    {
        workers.emplace_back(&ValidatorThreadPool::workerThread);
    }

    initialized = true;
}

void ValidatorThreadPool::enqueueTask(std::function<void()> task)
{
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        condition.wait(lock, []
                       { return tasks.size() < maxQueueSize || stop; });
        if (stop)
        {
            throw std::runtime_error("Cannot enqueue task on stopped ValidatorThreadPool");
        }
        tasks.push(std::move(task));
    }
    condition.notify_one();
}

void ValidatorThreadPool::shutdown()
{
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        stop = true;
    }
    condition.notify_all();
    for (std::thread &worker : workers)
    {
        if (worker.joinable())
        {
            worker.join();
        }
    }
    workers.clear();
    initialized = false;
}

void ValidatorThreadPool::workerThread()
{
    while (true)
    {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            condition.wait(lock, []
                           { return stop || !tasks.empty(); });
            if (stop && tasks.empty())
            {
                return;
            }
            task = std::move(tasks.front());
            tasks.pop();
        }
        try
        {
            task();
        }
        catch (const std::exception &e)
        {
            logging::print("Exception in task: " + std::string(e.what()));
        }
        catch (...)
        {
            logging::print("Unknown exception in task.");
        }
    }
}