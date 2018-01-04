/*!
\file c_handle.h
\author kipway@outlook.com
\update 2018.1.4

eclib class tHandle

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
#ifndef C_HANDLE_H
#define C_HANDLE_H


#define ERRHANDLE		(-1)

#ifndef MAXHANDLES
  #define MAXHANDLES	64	
#endif

#ifndef MAXHANDLEVAL
  #define MAXHANDLEVAL	2048
#endif

#include "c_critical.h"
namespace ec
{
    template<class T>
    class tHandle
    {
    public:
        tHandle() {
            _next = 0;
            int i;
            for (i = 0; i < MAXHANDLES; i++) {
                _h[i].Handle = ERRHANDLE;
                _h[i].pcls = 0;
            }
        };
        ~tHandle() {
            int i;
            for (i = 0; i < MAXHANDLES; i++) {
                if (_h[i].Handle != ERRHANDLE && _h[i].pcls) {
                    delete _h[i].pcls;
                }
                _h[i].Handle = ERRHANDLE;
                _h[i].pcls = 0;
            }
        }

        int  CreateHandle()
        {
            ec::cSafeLock lck(&_cs);
            int i;
            for (i = 0; i < MAXHANDLES; i++)
            {
                if (_h[i].Handle == ERRHANDLE)
                {
                    _h[i].pcls = new T();
                    if (_h[i].pcls)
                    {
                        _h[i].Handle = GetNextHandle();
                        return _h[i].Handle;
                    }
                    else
                    {
                        _h[i].Handle = ERRHANDLE;
                        return ERRHANDLE;
                    }
                }
            }
            return ERRHANDLE;
        }

        void DelHandle(int h)
        {
            ec::cSafeLock lck(&_cs);
            int i;
            for (i = 0; i < MAXHANDLES; i++) {
                if (_h[i].Handle == h) {
                    _h[i].Handle = ERRHANDLE;
                    if (_h[i].pcls) {
                        delete _h[i].pcls;
                        _h[i].pcls = NULL;
                    }
                    return;
                }
            }
        }

        T* GetClsByHandle(int h)
        {
            ec::cSafeLock lck(&_cs);
            int i;
            for (i = 0; i < MAXHANDLES; i++) {
                if (_h[i].Handle == h)
                    return _h[i].pcls;
            }
            return NULL;
        }

    protected:
        int _next;
        ec::cCritical _cs;
        struct T_I
        {
            int Handle;
            T* pcls;
        }_h[MAXHANDLES];
        int GetNextHandle()
        {
            _next++;
            if (_next > MAXHANDLEVAL)
                _next = 0;
            while (isexit(_next)) {
                _next++;
                if (_next > MAXHANDLEVAL)
                    _next = 0;
            }
            return _next;
        }
        bool isexit(int h)
        {
            int i;
            for (i = 0; i < MAXHANDLES; i++)
                if (_h[i].Handle == h)
                    return true;
            return false;
        }
    };	
};
#endif // C_HANDLE_H

