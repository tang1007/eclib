/*!
\file c_tcpcli.h
\brief tcp client for windows/linux

class ec::cTcpCli;

ec library is free C++ library.

\author	 kipway@outlook.com
*/
#pragma once
#ifndef _TCP_CLIENT
#define _TCP_CLIENT

#include <time.h>
#include "c_str.h"
#include "c_thread.h"
#include "c_event.h"
#include "c_tcp_tl.h"
#include "c_critical.h"
namespace ec {
    /*!
    \brief  TCP client auto reconnet
    */
    class cTcpCli : public cThread
    {
    public:
        cTcpCli() {
            _sock = INVALID_SOCKET;
            _nreconnectsec = 5;
            _lastconnectfailed = 0;
            _connecttimeout = 6;
        };
        virtual ~cTcpCli() {};
    protected:
        char _sip[30];
        unsigned short _wport;
        int _connecttimeout;
        time_t  _lastconnectfailed;
        int     _nreconnectsec;// reconnect interval seconds
        ec::cEvent _evtwait;
        volatile  SOCKET _sock; //
        cCritical _cssend;
        char _readbuf[32768];
    public:
        int Send(const void* pd, int nsize) //return send bytes,-1:error
        {
            if (INVALID_SOCKET == _sock)
                return -1;
            _cssend.Lock();
            int nr = ec::tcp_send(_sock, (void*)pd, nsize);
            _cssend.Unlock();
            return nr;
        }
        inline bool IsConnected()
        {
            return (INVALID_SOCKET != _sock);
        }
        bool Open(const char* sip, unsigned short wport, int reconnectsec = 6)
        {
            if (!sip || !wport)
                return false;

            if (IsRun())
                StopThread();
            ec::str_ncpy(_sip, sip, sizeof(_sip)-1);
            _wport = wport;
            _nreconnectsec = reconnectsec;
            if (_nreconnectsec < 1)
                _nreconnectsec = 1;
            if (_nreconnectsec > 60)
                _nreconnectsec = 60;
            StartThread(0);
            return true;
        }
        void Close()
        {
            StopThread();
        }
    protected:
        virtual void OnConnected() = 0;
        virtual void OnDisConnected(int where, int nerrcode) = 0;// where:1 disconnected ;-1 connect failed ;  nerrcode:system error
        virtual void OnRead(const void* pd, int nsize) = 0;
    protected:
        virtual bool OnStart() { return true; };
        virtual void OnStop() {
            if (INVALID_SOCKET != _sock)
            {
#ifdef _WIN32
                closesocket(_sock);
#else
                close(_sock);
#endif
                _sock = INVALID_SOCKET;
            }
        };
        virtual	void dojob() // read and connect
        {
            int nr;
            if (INVALID_SOCKET == _sock)
            {
                time_t tcur = ::time(0);
                if (tcur - _lastconnectfailed < _nreconnectsec)
                {
                    _evtwait.Wait(200);
                    return;
                }
                SOCKET s = tcp_connect(_sip, _wport, _connecttimeout);
                if (s == INVALID_SOCKET)
                {
                    _lastconnectfailed = tcur;
                    int nerrcode = 0;
#ifdef _WIN32
                    nerrcode = WSAGetLastError();
                    closesocket(s);
#else
                    nerrcode = errno;
                    close(s);
#endif
                    OnDisConnected(-1, nerrcode);
                    return;
                }
                _lastconnectfailed = tcur;
                _sock = s;
                OnConnected();
            }
            nr = ec::tcp_read(_sock, _readbuf, sizeof(_readbuf), 100);
            while (nr > 0)
            {
                OnRead(_readbuf, nr);
                nr = ec::tcp_read(_sock, _readbuf, sizeof(_readbuf), 100);
            }
            if (nr < 0)
            {
                SOCKET s = _sock;
                int nerrcode;
                _sock = INVALID_SOCKET;
#ifdef _WIN32
                nerrcode = WSAGetLastError();
                closesocket(s);
#else
                nerrcode = errno;
                close(s);
#endif
                OnDisConnected(1, nerrcode);
            }
        };
    };
}

#endif //_TCP_CLIENT
