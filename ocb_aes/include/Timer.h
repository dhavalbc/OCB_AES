#ifndef TIMER_H_
#define TIMER_H_

// All timer resolutions are in microseconds.
typedef unsigned long long uint64;
 
class Timer {
    protected:
        uint64 uiStart;
        static uint64 now();
    public:
        Timer(bool start = true);
        bool isElapsed(uint64 us);
        uint64 elapsed() const;
        uint64 restart();
        bool isStarted() const;

        /**
         * Compares the elapsed time, not the start time
         */
        bool operator<(const Timer &other) const;

        /**
         * Compares the elapsed time, not the start time
         */
        bool operator>(const Timer &other) const;
};
#endif