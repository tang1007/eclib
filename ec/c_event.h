/*!
\file c_event.h
\brief 	event for windows and linux

  ec library is free C++ library.

\author	 kipway@outlook.com
*/

#ifndef C_EVENT_H
#define C_EVENT_H
#if (0 != USE_ECLIB_C11)
#include "c11_event.h"
#else
#ifndef _WIN32
#include <pthread.h>
#include <sys/time.h>
#include <errno.h>
#else
#include<windows.h>
#endif

namespace ec {
#ifdef _WIN32

    class cEvent
    {
    public:
        cEvent(bool bInitiallyOwn = false, bool bManualReset = false) {
            m_hObject = ::CreateEventA(NULL, bManualReset, bInitiallyOwn, NULL);
        };
        ~cEvent() {
            if (m_hObject != NULL)
            {
                ::CloseHandle(m_hObject);
                m_hObject = NULL;
            }
        };
        HANDLE  m_hObject;
    public:
        bool SetEvent() {
            if (m_hObject)
                return ::SetEvent(m_hObject) != 0;
            return false;
        };
        bool ResetEvent() {
            if (m_hObject)
                return ::ResetEvent(m_hObject) != 0;
            return false;
        };
        bool Wait(long milliseconds)
        {
            return (WAIT_OBJECT_0 == WaitForSingleObject(m_hObject, milliseconds));
        }
    };

#else
    class cEvent
    {
    public:
        cEvent(bool bInitiallyOwn = false, bool bManualReset = false) {
            pthread_mutex_init(&m_mutex, NULL);
            pthread_cond_init(&m_cond, NULL);
            m_state = bInitiallyOwn;
            m_manual = bManualReset;
        };
        ~cEvent() {
            pthread_mutex_destroy(&m_mutex);
            pthread_cond_destroy(&m_cond);
        };
    protected:
        bool                m_manual;
        volatile bool       m_state;
        pthread_mutex_t     m_mutex;
        pthread_cond_t      m_cond;
    public:
        bool SetEvent() {
            pthread_mutex_lock(&m_mutex);
            m_state = true;
            pthread_cond_broadcast(&m_cond);
            pthread_mutex_unlock(&m_mutex);
            return true;
        };
        bool ResetEvent() {
            pthread_mutex_lock(&m_mutex);
            m_state = false;
            pthread_mutex_unlock(&m_mutex);
            return true;
        };
        bool Wait(long milliseconds)
        {
            int rc = 0;
            struct timespec abstime;
            struct timeval tv;
            gettimeofday(&tv, NULL);
            abstime.tv_sec = tv.tv_sec + milliseconds / 1000;
            abstime.tv_nsec = tv.tv_usec * 1000 + (milliseconds % 1000) * 1000000;
            if (abstime.tv_nsec >= 1000000000)
            {
                abstime.tv_nsec -= 1000000000;
                abstime.tv_sec++;
            }
            if (pthread_mutex_lock(&m_mutex) != 0)
                return false;
            while (!m_state)
            {
                if ((rc = pthread_cond_timedwait(&m_cond, &m_mutex, &abstime)))
                {
                    if (rc == ETIMEDOUT) break;
                    pthread_mutex_unlock(&m_mutex);
                    return false;
                }
            }
            if (rc == 0 && (!m_manual))
                m_state = false;
            pthread_mutex_unlock(&m_mutex);
            return rc == 0;
        }
    };
#endif

}; // namespace ec
#endif
#endif // C_EVENT_H

