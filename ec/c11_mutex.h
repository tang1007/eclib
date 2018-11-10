/*!
\file c11_mutex.h
\author	jiangyong
\email  kipway@outlook.com
\update 2018.10.6

eclib class mutex with c++11.

eclib Copyright (c) 2017-2018, kipway
source repository : https://github.com/kipway/eclib

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#pragma once

#include <mutex>
#ifdef _WIN32
#include <Windows.h>
#else
#include <pthread.h>
#endif
namespace ec {
	class unique_lock {
	private:
		std::mutex *_pmutex;
	public:
		unique_lock(std::mutex *pmutex) : _pmutex(pmutex) {
			if (_pmutex)
				_pmutex->lock();
		}
		~unique_lock() {
			if (_pmutex)
				_pmutex->unlock();
		}
	};

#ifdef _WIN32
	class spinlock
	{
	public:
		spinlock() {
			InitializeCriticalSectionAndSpinCount(&_v, UINT_MAX);
		}
		~spinlock() {
			DeleteCriticalSection(&_v);
		}
	public:
		void lock() { EnterCriticalSection(&_v); }
		void unlock() { LeaveCriticalSection(&_v); }
	private:
		CRITICAL_SECTION _v;
	};
#else
	class spinlock {
	public:
		spinlock() {
			pthread_spin_init(&_v, PTHREAD_PROCESS_PRIVATE);
		}
		~spinlock() {
			pthread_spin_destroy(&_v);
		}
	public:
		void lock() {
			pthread_spin_lock(&_v);
		}
		void unlock() {
			pthread_spin_unlock(&_v);
		}
	private:
		pthread_spinlock_t  _v;
	};
#endif

	class unique_spinlock {
	private:
		spinlock *_plck;
	public:
		unique_spinlock(spinlock *plck) : _plck(plck) {
			if (_plck)
				_plck->lock();
		}
		~unique_spinlock() {
			if (_plck)
				_plck->unlock();
		}
	};
}