/*!
\file c11_event.h
\author	jiangyong
\email  kipway@outlook.com
\update 2018.11.7

eclib class cEvent  with c++11. Adapt for c_event.h 

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
#include <condition_variable>
namespace ec {
	class cEvent
	{
	public:
		cEvent(bool bInitiallyOwn = false, bool bManualReset = false) :_nready(bInitiallyOwn), _bManualReset(bManualReset)
		{
		}
		bool SetEvent()
		{			
			_mtx.lock();
			_nready = true;
			_mtx.unlock();
			_cv.notify_one();
			return true;
		};
		bool ResetEvent()
		{			
			_mtx.lock();
			_nready = false;
			_mtx.unlock();
			return true;
		}
		bool Wait(int milliseconds)
		{
			std::unique_lock<std::mutex> lck(_mtx);
			if (!_nready)
				_cv.wait_for(lck, std::chrono::milliseconds(milliseconds));
			if (_nready)
			{
				if (!_bManualReset)
					_nready = false;
				return true;
			}
			return false;		
		}
	protected:
		bool _nready;
		bool _bManualReset;
		std::mutex _mtx;
		std::condition_variable _cv;
	};
}

