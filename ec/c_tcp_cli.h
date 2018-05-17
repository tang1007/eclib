/*!
\file c_tcpcli.h
tcp client for windows & linux

\author	kipway@outlook.com
\update 2018.5.15

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
            _nreconnectsec = 4;
            _lastconnectfailed = 0;
            _connecttimeout = 6;
			_nstatus_con = -1;
        };
        virtual ~cTcpCli() {};
		std::atomic_int  _nstatus_con;//!<状态,-1,未连接,0已连接,1已登录
    protected:
        char _sip[30];
        unsigned short _wport;
        int _connecttimeout;//连接超时
        time_t  _lastconnectfailed;//上次连接失败时间
        int     _nreconnectsec;// reconnect interval seconds
        ec::cEvent _evtwait;
        volatile  SOCKET _sock; //
        
        char _readbuf[32768];
	private:
		cCritical _cs_sock;
    public:
        int Send(const void* pd, int nsize) //return send bytes,-1:error
        {
	        if (INVALID_SOCKET == _sock || _nstatus_con < 0)
                return -1;            
			_cs_sock.Lock();
            int nr = ec::tcp_send(_sock, (void*)pd, nsize);   
			if (nr < 0)
			{
				_nstatus_con = -1;//重连
				_lastconnectfailed = ::time(0);
			}
			_cs_sock.Unlock();			
            return nr;
        }
        
        bool Open(const char* sip, unsigned short wport, int reconnectsec = 4)
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
			_cs_sock.Lock();
			_nstatus_con = -1;
			if (INVALID_SOCKET != _sock)
			{
#ifdef _WIN32
				closesocket(_sock);
#else
				close(_sock);
#endif               
				_sock = INVALID_SOCKET;
				_cs_sock.Unlock();
				OnDisConnected(1, 0);
			}
			else
				_cs_sock.Unlock();
        };
        virtual	void dojob() // read and connect
        {
            int nr;			
            if (_nstatus_con < 0)
            {
				if (!inconnect())
					return;                
            }			
			while (!_bKilling)//read
			{
				nr = ec::tcp_read(_sock, _readbuf, sizeof(_readbuf), 100);
				if (nr > 0)
					OnRead(_readbuf, nr);
				else if (nr < 0)
				{
					_nstatus_con = -1;
					break;
				}
				else
					break;
			}
        };
		private:
			bool inconnect()
			{				
				_cs_sock.Lock();
				if (_sock != INVALID_SOCKET)
				{
#ifdef _WIN32
					int nerrcode = WSAGetLastError();
					closesocket(_sock);
#else
					int nerrcode = errno;
					close(_sock);
#endif
					_sock = INVALID_SOCKET;	
					_cs_sock.Unlock();
					OnDisConnected(1, nerrcode);
					return false;
				}				

				time_t tcur = ::time(0);
				if (tcur - _lastconnectfailed < _nreconnectsec)
				{
					_cs_sock.Unlock();
					_evtwait.Wait(200);	
					return false;
				}

				SOCKET s = tcp_connect(_sip, _wport, _connecttimeout,true);
				if (s == INVALID_SOCKET)
				{
					_lastconnectfailed = tcur;
					_cs_sock.Unlock();
					return false;
				}				
				_lastconnectfailed = tcur;
				_sock = s;				
				_nstatus_con = 0;
				_cs_sock.Unlock();
				OnConnected();
				return true;
			}
    };
}
#endif //_TCP_CLIENT
