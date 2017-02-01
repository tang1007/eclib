/*!
\file c_critical.h
\brief critical lock

ec library is free C++ library.

\author	 kipway
\email   kipway@outlook.com
*/

#ifndef C_RITICAL_H
#define C_RITICAL_H

#ifdef _WIN32
#include <windows.h>
#else 
#include <pthread.h>	
#endif

namespace ec {
#ifdef _WIN32

	class cCritical
	{
	public:
		cCritical() {
			InitializeCriticalSection(&m_sec);
		};
		cCritical(unsigned int ucount) {
			InitializeCriticalSectionAndSpinCount(&m_sec, ucount);
		}
		~cCritical() {
			DeleteCriticalSection(&m_sec);
		};
	public:
		void Lock() { EnterCriticalSection(&m_sec); }
		void Unlock() { LeaveCriticalSection(&m_sec); }
	protected:
		CRITICAL_SECTION m_sec;
	};
#else
	class cCritical
	{
	public:
		cCritical() {
			pthread_mutex_init(&m_mtx, NULL);
		};
		cCritical(unsigned int ucount) {
			pthread_mutex_init(&m_mtx, NULL);
		}
		~cCritical() {
			pthread_mutex_destroy(&m_mtx);
		};
	public:
		void Lock() { pthread_mutex_lock(&m_mtx); }
		void Unlock() { pthread_mutex_unlock(&m_mtx); }
		pthread_mutex_t* GetMutex() { return &m_mtx; };
	protected:
		pthread_mutex_t m_mtx;
	};
#endif

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
};// namespace ec

#endif // C_RITICAL_H

