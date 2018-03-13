/*!
\file c_minisrv.h
\author	kipway@outlook.com
\update 2018.3.13

eclib class mini tcp server and auto reconnect client
class cMiniSrv
class cMiniCli

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
#include <stdint.h>
#include <time.h>

#ifndef _WIN32
#include <unistd.h>
#include <pthread.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <errno.h>
#include <sys/epoll.h>
#include <fcntl.h>
#endif

#include "ec/c_tcp_tl.h"
#include "ec/c_thread.h"
#include "ec/c11_array.h"
#include "ec/c11_vector.h"
#include "ec/c_critical.h"
#include "ec/c_stream.h"

#ifndef MAX_CONS_TCPMINISRV
#	define MAX_CONS_TCPMINISRV 16 //less 64
#endif
namespace ec {

	class cMiniSrv : public ec::cThread
	{
	public:
		cMiniSrv() :_port(0), _slisten(INVALID_SOCKET), _nextid(100) {
		}
		virtual ~cMiniSrv() {
			stop_srv();
		}
		struct t_id {
			SOCKET s;
			uint32_t uid;
			int  status;
			int64_t timecon;
			void* pcls;
		};
	protected:
		cCritical _cs_send;
	private:

		uint16_t _port;
		SOCKET _slisten; //id = 1
		ec::Array<t_id, MAX_CONS_TCPMINISRV> _socks;
		char _rbuf[16384];// read buffer
		uint32_t _nextid; // start 100;

		uint32_t useid()
		{
			_nextid = _nextid < 100 ? 100 : _nextid + 1;
			while (_socks.find([this](t_id &idv)->bool {
				return _nextid == idv.uid;
			})) {
				_nextid = _nextid < 100 ? 100 : _nextid + 1;
			}
			return _nextid;
		}
	protected:
		SOCKET fromid(uint32_t ucid)
		{
			t_id *pi = _socks.find([&ucid](t_id &v) {return v.uid == ucid; });
			if (!pi)
				return INVALID_SOCKET;
			return pi->s;
		}
		uint32_t fromsock(SOCKET s)
		{
			t_id *pi = _socks.find([&s](t_id &v) {return v.s == s; });
			if (!pi)
				return 0;
			return pi->uid;
		}

	protected:
		virtual bool onreadbytes(t_id* pid, const uint8_t* pd, size_t size) = 0; //Processes messages in pmsg, returning true if successful, false will disconnect
		virtual void onclose(t_id* pid) = 0; // return false diconnect
		virtual bool onconnect(t_id* pid) = 0; // return false diconnect
	public:
		bool start_srv(uint16_t wport, const char* ip = nullptr) {
			if (!wport)
				return false;
			if (_slisten != INVALID_SOCKET)
				return true;
			_port = wport;
			struct sockaddr_in	InternetAddr;

			if ((_slisten = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
			{
#ifndef _WIN32
				fprintf(stderr, "cMiniSrv @port %u bind error!\n", _port);
#endif
				return false;
			}
			InternetAddr.sin_family = AF_INET;
			if (!ip || !(*ip))
				InternetAddr.sin_addr.s_addr = htonl(INADDR_ANY);
			else
				InternetAddr.sin_addr.s_addr = inet_addr(ip);
			InternetAddr.sin_port = htons(_port);
			if (bind(_slisten, (const sockaddr *)&InternetAddr, sizeof(InternetAddr)) == SOCKET_ERROR)
			{
#ifdef _WIN32
				shutdown(_slisten, SD_BOTH);
				closesocket(_slisten);
#else
				fprintf(stderr, "ERR:SVR_PORT[%d] cMiniSrv::start_srv\t bind failed with error %d\n", _port, errno);
				shutdown(_slisten, SHUT_WR);
				close(_slisten);
#endif
				_slisten = INVALID_SOCKET;
				return false;
			}
			if (listen(_slisten, 2) == SOCKET_ERROR)
			{
#ifdef _WIN32
				shutdown(_slisten, SD_BOTH);
				closesocket(_slisten);
#else
				fprintf(stderr, "ERR:SVR_PORT[%d] cMiniSrv::start_srv\t listen failed with error %d\n", _port, errno);
				shutdown(_slisten, SHUT_WR);
				close(_slisten);
#endif
				_slisten = INVALID_SOCKET;
				return false;
			}
			StartThread(nullptr);
			return true;
		}
		void stop_srv() {
			StopThread();
			if (_slisten != INVALID_SOCKET) {
#ifdef _WIN32
                shutdown(_slisten, SD_BOTH);
#else
                shutdown(_slisten, SHUT_WR);
#endif
				closesocket(_slisten);
				_slisten = INVALID_SOCKET;
			}
			_socks.for_each([this](t_id& v) {
				closesocket(v.s);
				v.s = INVALID_SOCKET;
				onclose(&v);
			});
			_socks.clear();
		}
		void set_status(uint32_t ucid, int st) {
			t_id *pi = _socks.find([&](t_id &v) {return v.uid == ucid; });
			if (pi)
				pi->status = st;
		}
#ifndef _WIN32
		static int  SetNoBlock(int sfd)
		{
			int flags, s;

			flags = fcntl(sfd, F_GETFL, 0);
			if (flags == -1)
				return -1;

			flags |= O_NONBLOCK;
			s = fcntl(sfd, F_SETFL, flags);
			if (s == -1)
				return -1;
			return 0;
		}
#endif
		int send(t_id *pid,const void* pd, size_t size)
		{
			cSafeLock lck(&_cs_send);
			if (pid->s == INVALID_SOCKET)
				return -1;
			return tcp_send(pid->s, pd, (int)size);
		}
		int send(uint32_t ucid, const void* pd, size_t size)
		{
			cSafeLock lck(&_cs_send);
			SOCKET s = fromid(ucid);
			if (s == INVALID_SOCKET)
				return -1;
			return tcp_send(s, pd, (int)size);
		}
	private:
		void doAccept()
		{
			SOCKET	sAccept;
			struct  sockaddr_in		 addrClient;
			int		nClientAddrLen = sizeof(addrClient);
#ifdef _WIN32
			if ((sAccept = ::accept(_slisten, (struct sockaddr*)(&addrClient), &nClientAddrLen)) == INVALID_SOCKET)
				return;
			u_long iMode = 1;
			ioctlsocket(sAccept, FIONBIO, &iMode);
#else
			if ((sAccept = ::accept(_slisten, (struct sockaddr*)(&addrClient), (socklen_t*)&nClientAddrLen)) == INVALID_SOCKET)
				return;
			if (SetNoBlock(sAccept) < 0)
				return;
#endif
			t_id t;
			t.pcls = nullptr;

			t.s = sAccept;
			t.status = 0;
			t.timecon = ::time(0);
			t.uid = useid();
			if (!onconnect(&t))
			{
				closesocket(sAccept);
				return;
			}
			_cs_send.Lock();
			_socks.add(t);
			_cs_send.Unlock();
		}
	protected:
		virtual	void dojob()
		{
			int nret, nr;
			TIMEVAL tv01 = { 1,0 };
			fd_set fdr, fde;
			FD_ZERO(&fdr);
			FD_ZERO(&fde);
			SOCKET smax = -1;
			if (!_socks.full()) {
				FD_SET(_slisten, &fdr);
				smax = _slisten;
			}
			_socks.for_each([&fdr](t_id &s) {FD_SET(s.s, &fdr);	});
			_socks.for_each([&fde](t_id &s) {FD_SET(s.s, &fde);	});
			_socks.for_each([&smax](t_id &s) {if (s.s > smax) smax = s.s; });
#ifdef _WIN32
			nret = ::select(0, &fdr, NULL, &fde, &tv01);
#else
			nret = ::select(smax + 1, &fdr, NULL, &fde, &tv01);
#endif
			if (!nret)
				return;
			int  i, n = (int)_socks.size();
			for (i = 0; i < n; i++) {
				if (FD_ISSET(_socks[i].s, &fde))//do error
					_socks[i].status = -1;
			}
			n = (int)_socks.size();
			for (i = 0; i < n; i++)
			{
				if (FD_ISSET(_socks[i].s, &fdr))//do read
				{
					nr = 1;
					while (nr > 0)
					{
#ifdef _WIN32
						nr = ::recv(_socks[i].s, _rbuf, (int)sizeof(_rbuf), 0);
						if (nr < 0)
						{
							if (WSAEWOULDBLOCK != WSAGetLastError())//read end
								_socks[i].status = -1;
						}
#else
						nr = recv(_socks[i].s, _rbuf, sizeof(_rbuf), MSG_DONTWAIT);
						if (nr < 0)
						{
							if(errno != EAGAIN && errno != EWOULDBLOCK)//read end
								_socks[i].status = -1;
						}
#endif
						else if (0 == nr) // peer closed
							_socks[i].status = -1;
						else {
							if (!onreadbytes(&_socks[i], (uint8_t*)_rbuf, nr))
								_socks[i].status = -1;
						}
					} //while(nr > 0)
				}
			}//for

			int64_t ct = ::time(0); //delete long time nologin
			n = (int)_socks.size();
			for (i = 0; i < n; i++)
			{
				if (!_socks[i].status && ct - _socks[i].timecon > 30)
					_socks[i].status = -1;
			}
			_cs_send.Lock();
			n = (int)_socks.size();//delete error socket
			for (i = 0; i < n; i++)
			{
				if (_socks[i].status == -1)
				{
					closesocket(_socks[i].s);
					_socks[i].s = INVALID_SOCKET;
					onclose(&_socks[i]);
					_socks.erase(i);
					i--; n--;
				}
			}
			_cs_send.Unlock();
			if (FD_ISSET(_slisten, &fdr))
				doAccept();
		}
	};

	class cMiniCli : public ec::cThread //mini client
	{
	public:
		cMiniCli() :_port(0), _ip{ 0 }, _sclient(INVALID_SOCKET){
		}
		virtual ~cMiniCli() {
			StopThread();
		}
	public:
		bool start_cli(uint16_t port, const char* ip = nullptr)
		{
			if (IsRun())
				return true;
			_port = port;
			if (ip && *ip)
				ec::str_ncpy(_ip, ip, sizeof(_ip));
			else
				strcpy(_ip, "127.0.0.1");
			StartThread(nullptr);
			return true;
		}
		void stop_cli()
		{
			StopThread();
		}
		int send(const void* pd, size_t size) //return send bytes numbers; <0:error
		{
			ec::cSafeLock lck(&_cs);
			if (INVALID_SOCKET == _sclient)
				return -1;
			return tcp_send(_sclient, pd, size);
		}
	private:
		uint16_t _port;
		char _ip[32];
	protected:
		SOCKET   _sclient;
		ec::cCritical _cs;

		virtual void onconnect() = 0;
		virtual void onclose() = 0;
		virtual bool onreadbytes(const uint8_t* pdata, size_t usize) = 0;

		void closeclient()
		{
			onclose();
			if (INVALID_SOCKET == _sclient)
				return;
#ifdef _WIN32
			shutdown(_sclient, SD_BOTH);
			closesocket(_sclient);
#else
			shutdown(_sclient, SHUT_WR);
			close(_sclient);
#endif
			_sclient = INVALID_SOCKET;
		}

		virtual	void dojob() // read and connect
		{
			int nr;
			uint8_t buf[1024 * 32];
			while (!_bKilling)//connect
			{
				_sclient = tcp_connect(_ip, _port, 4);
				if (INVALID_SOCKET == _sclient)
					continue;
				onconnect();
				while (!_bKilling)//read
				{
					nr = tcp_read(_sclient, buf, (int)sizeof(buf), 100);
					if (SOCKET_ERROR == nr)
					{
						closeclient();
						break;
					}
					else if (nr > 0) {
						if (!onreadbytes(buf, nr)) {
							closeclient();
							break;
						}
					}
				}
				closeclient();
			}
		}
	};
};
