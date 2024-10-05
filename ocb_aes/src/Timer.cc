#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <utils/Log.h>

#include "Timer.h"

Timer::Timer(bool start) {
    uiStart = start ? now() : 0;
}

uint64 Timer::elapsed() const {
    assert(uiStart != 0);
    return now() - uiStart;
}

bool Timer::isElapsed(uint64 us) {
     assert(uiStart != 0);
    if (elapsed() > us) {
        uiStart += us;
        return true;
    }
    return false;
}

uint64 Timer::restart() {
    uint64 n = now();
    uint64 e = n - uiStart;
    uiStart = n;
    return e;
}

bool Timer::isStarted() const {
    return uiStart != 0;
}

bool Timer::operator<(const Timer &other) const {
    return uiStart > other.uiStart;
}

bool Timer::operator>(const Timer &other) const {
    return uiStart < other.uiStart;
}


uint64 Timer::now() {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
         ALOGE("clock_gettime(CLOCK_MONOTONIC) errno=%d", errno);
    }
    uint64 e = ts.tv_sec * 1000000LL;
    e += ts.tv_nsec / 1000LL;
    return e;
}