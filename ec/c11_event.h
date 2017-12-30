/*!
\file c11_event.h
\brief 	event use C11

ec library is free C++ library.

\author	 kipway@outlook.com
*/
#pragma once
#include <mutex>
#include <condition_variable>
namespace ec {
	class cEvent
	{
	public:
		cEvent(bool bInitiallyOwn = false, bool bManualReset = false)
		{
			_nready = bInitiallyOwn;
			_bManualReset = bManualReset;
		}
		bool SetEvent() {
			std::unique_lock<std::mutex> lck(_mtx);
			_nready = true;
			_cv.notify_one();
			return true;
		};
		bool ResetEvent() {
			std::unique_lock<std::mutex> lck(_mtx);
			_nready = false;
			return true;
		}
		bool Wait(int milliseconds)
		{
			std::unique_lock<std::mutex> lck(_mtx);
			if (_cv.wait_for(lck, std::chrono::milliseconds(milliseconds)) != std::cv_status::timeout)
			{
				if (_nready)
				{
					if (!_bManualReset)
						_nready = false;
					return true;
				}
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

