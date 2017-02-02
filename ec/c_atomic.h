/*!
\file  c_atomic.h
\brief Atomic operator

  ec library is free C++ library.

\author	 kipway@outlook.com
*/
#ifndef C_ATOMIC_H
#define C_ATOMIC_H


#ifdef _WIN32
#include <Windows.h>
#else
#include <pthread.h>
#endif

namespace ec
{
	inline long atomic_addlong(long* pv, long iv) //return old value
	{
#ifdef _WIN32         
		return InterlockedExchangeAdd(pv, iv);
#else
		return __sync_fetch_and_add(pv, iv);
#endif
	}

	inline long atomic_setlong(long* pv, long iv) //return old value
	{
#ifdef _WIN32
		return InterlockedExchange(pv, iv);
#else
		return __sync_lock_test_and_set(pv, iv);
#endif
	}

	inline int atomic_addint(int* pv, int iv) //return old value
	{
#ifdef _WIN32         
		return InterlockedExchangeAdd((long*)pv, iv);
#else
		return __sync_fetch_and_add(pv, iv);
#endif
	}

	inline int atomic_setint(int* pv, int iv) //return old value
	{
#ifdef _WIN32
		return InterlockedExchange((long*)pv, iv);
#else
		return __sync_lock_test_and_set(pv, iv);
#endif
	}

	inline void* atomic_setptr(void** ppv, void* pv) //return old value
	{
#ifdef _WIN32
		return (void*)InterlockedExchangePointer(ppv, pv);
#else
		return (void*)__sync_lock_test_and_set(ppv, pv);
#endif
	}

}; // ec
#endif // C_ATOMIC_H

