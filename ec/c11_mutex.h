/*!
\file c11_mutex.h
\author	jiangyong
\email  kipway@outlook.com
\update 2018.5.27

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
namespace ec {
	class unique_lock {
	private:
		std::mutex *_pmutex;
	public:
		unique_lock(std::mutex *pmutex)  : _pmutex(pmutex){
			if (_pmutex)
				_pmutex->lock();
		}
		~unique_lock() {
			if (_pmutex)
				_pmutex->unlock();
		}
	};
}