/*!
\file c11_critical.h
\author kipway@outlook.com
\update 2018.1.3

eclib class cThread with c++11 . Adapt for c_thread.h

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
#include <thread>
#include <atomic>
#include <chrono>
#include "c11_event.h"
namespace ec
{
	class cThread
	{
	public:
		cThread():_bRuning(0),_bKilling(0)
		{
		}
		virtual ~cThread() {
			StopThread();
		}
	protected:
		std::atomic_int	_bRuning;
		std::atomic_int	_bKilling;

		std::thread *_pthread = nullptr;
		cEvent* _pevt = nullptr;  // trigger event

		void *_pdoarg = nullptr;
		bool(*_pdojob)(void *) = nullptr; // Non-derived use, return false will stop thread    
	public:
		void StartThread(cEvent* pevt, bool(*dojob)(void *) = nullptr, void*  pargs = nullptr)
		{
			if (nullptr != _pthread)
				return;
			_pevt = pevt;
			_pdojob = dojob;
			_pdoarg = pargs;
			_pthread = new std::thread(ThreadProcess, this);
		}
		void StopThread()
		{
			if (nullptr != _pthread) {
				_bKilling = 1;
				while (_bRuning)
					std::this_thread::sleep_for(std::chrono::milliseconds(100));
				_pthread->join();
				delete _pthread;
				_pthread = nullptr;
			}
		}
		inline bool IsRun() { return 0 != _bRuning; };
		inline bool Killing() { return 0 != _bKilling; };
		inline void setkill(int n) { _bKilling = n; };
	private:
		static void ThreadProcess(void* pargs)
		{
			cThread* pt = (cThread*)pargs;
			pt->mainloop();
		}
	public:
		void	mainloop()
		{
			OnStart();
			_bKilling = 0;
			_bRuning = 1;
			while (!_bKilling) {
				if (!_pevt || _pevt->Wait(200)) {
					if (!_pdojob)
						dojob();
					else {
						if (!_pdojob(_pdoarg))
							break;
					}
				}
				if (_pevt)
					On100msTimer();
			}
			OnStop();
			_bRuning = 0;
			_bKilling = 0;
		}
	protected:
		virtual bool OnStart() { return true; };
		virtual void OnStop() { };
		virtual	void dojob() { std::this_thread::sleep_for(std::chrono::milliseconds(100)); };
		virtual void On100msTimer() { };
	};
}

