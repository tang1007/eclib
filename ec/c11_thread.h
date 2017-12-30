/*
\file c11_thread.h
\brief thread class use C11

ec library is free C++ library.

\author	 kipway@outlook.com
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
		cThread() :_bRuning(0), _bKilling(0)
		{
			_pevt = nullptr;
			_pdojob = nullptr;
			_pdoarg = nullptr;
			_pthread = nullptr;
		};
		virtual ~cThread() {
			if (_pthread != nullptr)
				delete _pthread;
		}
		bool IsRun() { return 0 != _bRuning; };
	protected:
		std::atomic_int	_bRuning;
		std::atomic_int	_bKilling;

		std::thread *_pthread;
		cEvent*		 _pevt;
		void		*_pdoarg;
		bool(*_pdojob)(void *); //return false will stop thread    
	public:
		void StartThread(cEvent* pevt, bool(*dojob)(void *) = nullptr, void*  pargs = nullptr)
		{
			if (_bRuning)
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
		bool Killing() { return 0 != _bKilling; };
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
			while (!_bKilling)
			{
				if (!_pevt || _pevt->Wait(100)) {
					if (!_pdojob)
						dojob();
					else
					{
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

