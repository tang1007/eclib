
/*
\file c_thread.h
\brief thread class

ec library is free C++ library.

\author	 kipway@outlook.com
*/
#ifndef C_THREAD_H
#define C_THREAD_H
#if (0 != USE_ECLIB_C11)
#include "c11_thread.h"
#else
#include "c_event.h"
#include "c_atomic.h"
namespace ec {

#ifdef _WIN32
#include <Windows.h>
#include <process.h>

    class cThread
    {
    public:
        cThread() {
            _lThreadRun = 0;
            _lKillTread = 0;
            _pevt = NULL;
            _pdojob = NULL;
            _pdoarg = NULL;
        };
        virtual ~cThread() {
        }
        bool IsRun() { return 0 != atomic_addlong(&_lThreadRun, 0); };
    protected:
        long		_lThreadRun;
        long		_lKillTread;

        cEvent*		_pevt;
        void		*_pdoarg;
        bool(*_pdojob)(void *); //return false will stop thread    
    public:
        void	StartThread(cEvent* pevt, bool(*dojob)(void *) = NULL, void*  pargs = NULL)
        {
            if (atomic_addlong(&_lThreadRun, 0))
                return;

            _pevt = pevt;
            _pdojob = dojob;
            _pdoarg = pargs;
            _beginthread(ThreadProcess, 0, this);
        }

        void StopThread()
        {
            atomic_setlong(&_lKillTread, 1);
            while (atomic_addlong(&_lThreadRun, 0) > 0)
                Sleep(100);            
        }
        bool Killing() { return 0 != atomic_addlong(&_lKillTread, 0); };
		inline void setkill(int n) { atomic_setlong(&_lKillTread, n); };
    private:
        static void ThreadProcess(void* pargs)
        {
            cThread* pt = (cThread*)pargs;
            pt->mainloop();
            _endthread();
        }
    public:
        void	mainloop()
        {
            OnStart();
            atomic_setlong(&_lKillTread, 0);
            atomic_setlong(&_lThreadRun, 1);
            while (!atomic_addlong(&_lKillTread, 0))
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
            atomic_setlong(&_lThreadRun, 0);
            atomic_setlong(&_lKillTread, 0);
        }
    protected:
        virtual bool OnStart() { return true; };
        virtual void OnStop() { };
        virtual	void dojob() { Sleep(1); };
        virtual void On100msTimer() { };
    };
#else // linux
#include <pthread.h>
#include <unistd.h>
    class cThread
    {
    public:
        cThread() {
            _lThreadRun = 0;
            _lKillTread = 0;
            _pevt = NULL;
            _pdojob = NULL;
            _pdoarg = NULL;
            m_tid = 0;
        };
        virtual ~cThread() {

        }
        bool IsRun() { return 0 != atomic_addlong(&_lThreadRun, 0); };
    protected:
        long		_lThreadRun;
        long		_lKillTread;

        pthread_t   m_tid;
        cEvent*		_pevt;
        void		*_pdoarg;
        bool(*_pdojob)(void *); //return false will stop thread
    public:
        void	StartThread(cEvent* pevt, bool(*dojob)(void *) = NULL, void*  pargs = NULL)
        {
            if (atomic_addlong(&_lThreadRun, 0))
                return;
            _pevt = pevt;
            _pdojob = dojob;
            _pdoarg = pargs;
#ifdef _ARM_LINUX
#	ifndef ARM_STACK_SIZE
#		define ARM_STACK_SIZE 0x100000 // 1MB
#	endif
	    pthread_attr_t attr;
	    pthread_attr_init(&attr);
	    pthread_attr_setstacksize(&attr, ARM_STACK_SIZE);
	    pthread_create(&m_tid, &attr, ThreadProcess, this);
	    pthread_attr_destroy(&attr);
#else
            pthread_create(&m_tid, NULL, ThreadProcess, this);
#endif
        }
        void StopThread()
        {
            atomic_setlong(&_lKillTread, 1);
            if (m_tid) {
                pthread_join(m_tid, NULL);
                m_tid = 0;
            }
        }
        bool Killing() { return 0 != atomic_addlong(&_lKillTread, 0); };
		inline void setkill(int n) { atomic_setlong(&_lKillTread, n); };
        static void* ThreadProcess(void* pargs)
        {
            cThread* pt = (cThread*)pargs;
            pt->mainloop();
            return NULL;
        }
    public:
        void	mainloop()
        {
            OnStart();
            atomic_setlong(&_lKillTread, 0);
            atomic_setlong(&_lThreadRun, 1);
            while (!atomic_addlong(&_lKillTread, 0))
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
            }
            OnStop();
            atomic_setlong(&_lThreadRun, 0);
            atomic_setlong(&_lKillTread, 0);
        }
    protected:
        virtual	void dojob() { usleep(10 * 1000); };
        virtual bool OnStart() { return true; };
        virtual void OnStop() { };
    };
#endif
}; //namespace ec
#endif
#endif

