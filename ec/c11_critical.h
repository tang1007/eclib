/*!
\file c11_critical.h
\author kipway@outlook.com
\update 2018.1.3

eclib class cCritical with c++11. Adapt for c_critical.h

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
namespace ec
{
	class cCritical : public std::mutex
	{
	public:
		cCritical() = default;
		inline void Lock() { lock(); }
		inline void Unlock() { unlock(); }
	};

	class cSafeLock
	{
	public:
		cSafeLock(cCritical *pLock) : _pcs(pLock)
		{
			if (_pcs)
				_pcs->Lock();
		};
		~cSafeLock() {
			if (_pcs)
				_pcs->Unlock();
		};
	private:
		cCritical* _pcs;
	};
}
