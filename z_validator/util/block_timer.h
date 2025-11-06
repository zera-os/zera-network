#include <iostream>
#include <future>
#include <chrono>
#include "proposer.h"
#include "lottery.h"
#include "validator.pb.h"

class BlockTimer {
public:
    BlockTimer() : timerRunning_(false), restartDuration_(5000) {} // Set restart duration to 5000 milliseconds (5 seconds)

    void StartTimer(int64_t timestampMilliseconds) {
        timeMilliseconds_ = timestampMilliseconds;
        if (!timerRunning_) {
            timerRunning_ = true;
            timerThread_ = std::thread(&BlockTimer::TimerThread, this);
        }
    }

    void StopTimer() {
        if (timerRunning_) {
            timerRunning_ = false;
            if (timerThread_.joinable()) {
                timerThread_.join();
            }
        }
    }

private:
    void TimerThread() {
        auto currentUniversalTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
            ).count();
        auto timeDifference = timeMilliseconds_ - currentUniversalTime;

        if (timeDifference <= 0) {
            TimerCallback();
        }
        else {
            std::this_thread::sleep_for(std::chrono::milliseconds(timeDifference));
            TimerCallback();
        }

        timerRunning_ = false;
    }

    void TimerCallback() {
        uint64_t seed = get_validator_seed();
        std::vector<zera_txn::Validator> validators = SelectValidatorsByWeight(seed);
    }

    int64_t timeMilliseconds_;
    bool timerRunning_;
    std::thread timerThread_;
    const int restartDuration_; // Constant duration for restarting the timer
};