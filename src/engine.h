/*
 * Copyright 2017 Andrei Pangin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _ENGINE_H
#define _ENGINE_H

#include "arguments.h"
#include "random"
#include <random>

// create per thread
class SubIntervalHandler {

    static long _interval;
    static long _subintervals;
    static thread_local long _n;
    static thread_local long _count;

    static long random_number() {
        static thread_local std::minstd_rand rand{std::random_device()()};
        std::uniform_int_distribution<long> dist(0, _subintervals - 1);
        return dist(rand);
    }

public:
    static long setup(long interval, long subintervals) {
        _interval = interval;
        _subintervals = subintervals ? subintervals : DEFAULT_subintervals;
        _n = random_number();
        _count = 0;
        return actual_interval();
    }

    static long actual_interval() { return _interval / _subintervals; }

    static bool tick() {
        if (_subintervals == 1) {
            return true;
        }
        if (_count == _subintervals) {
            _n = random_number();
            _count = 0;
        }
        if (_count == _n) {
            _count++;
            return true;
        }
        _count++;
        return false;
    }

};


class Engine {
  protected:
    static volatile bool _enabled;

    static bool updateCounter(volatile unsigned long long& counter, unsigned long long value, unsigned long long interval) {
        if (interval <= 1) {
            return true;
        }

        while (true) {
            unsigned long long prev = counter;
            unsigned long long next = prev + value;
            if (next < interval) {
                if (__sync_bool_compare_and_swap(&counter, prev, next)) {
                    return false;
                }
            } else {
                if (__sync_bool_compare_and_swap(&counter, prev, next % interval)) {
                    return true;
                }
            }
        }
    }

  public:
    virtual const char* title() {
        return "Flame Graph";
    }

    virtual const char* units() {
        return "total";
    }

    virtual Error check(Arguments& args);
    virtual Error start(Arguments& args);
    virtual void stop();

    void enableEvents(bool enabled) {
        _enabled = enabled;
    }
};

#endif // _ENGINE_H
