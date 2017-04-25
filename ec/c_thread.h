
/*
\file c_thread.h
\brief thread class

ec library is free C++ library.

\author	 kipway@outlook.com
*/
#ifndef C_THREAD_H
#define C_THREAD_H

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
        virtual bool OnStart() { return true; };
        virtual void OnStop() { };
        virtual	void dojob() { Sleep(1); };
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
            pthread_create(&m_tid, NULL, ThreadProcess, this);
        }
        void StopThread()
        {
            atomic_setlong(&_lKillTread, 1);
            while (atomic_addlong(&_lThreadRun, 0) > 0)
                usleep(1000);
        }
        bool Killing() { return 0 != atomic_addlong(&_lKillTread, 0); };
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

