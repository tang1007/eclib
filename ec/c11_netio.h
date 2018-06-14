/*!
@file c11_netio.h

eclibe Asynchronous NETIO for windows & linux

class aiotcpsrvworker
class aiotcpsrv
class aiotcpclient

\author	kipway@outlook.com
\update 2018.5.28

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

#ifndef USE_ECLIB_C11
#	define USE_ECLIB_C11 1 // 1: use std::thread,std:mutex,std::condition_variable and c++11 style code. 0:normal
#endif
#ifdef _WIN32
#	pragma warning(disable : 4996)
#	include <winsock2.h>
#	include <mstcpip.h>
#   include <ws2tcpip.h>
#else
#	include <unistd.h>
#	include <sys/time.h>
#	include <sys/types.h>
#	include <sys/socket.h>
#	include <sys/ioctl.h>
#	include <sys/select.h>
#	include <netinet/tcp.h>
#	include <arpa/inet.h>
#	include <errno.h>
#   include <netdb.h>

#ifndef SOCKET
#	define SOCKET int
#endif 

#ifndef INVALID_SOCKET
#	define INVALID_SOCKET    (-1)
#endif

#ifndef SOCKET_ERROR
#	define SOCKET_ERROR      (-1)
#endif

#ifndef closesocket
#	define closesocket(a) close(a)
#endif 

#ifndef TIMEVAL
#	define TIMEVAL struct timeval
#endif 

#endif

#include "c11_thread.h"
#include "c11_xpoll.h"
#include "c11_keyval.h"
#include "c11_log.h"

namespace ec {
	inline void netio_tcpnodelay(SOCKET s)
	{
		int bNodelay = 1;
		setsockopt(
			s,
			IPPROTO_TCP,
			TCP_NODELAY,
			(char *)&bNodelay,
			sizeof(bNodelay));
	}
#ifndef _WIN32
	inline bool netio_setkeepalive(SOCKET s, bool bfast = false)
	{
		int keepAlive = 1;
		int keepIdle = 30;
		int keepInterval = 1;
		int keepCount = 5;
		if (bfast)
		{
			keepIdle = 5;
			keepInterval = 1;
			keepCount = 3;
		}
		setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepAlive, sizeof(keepAlive));
		setsockopt(s, SOL_TCP, TCP_KEEPIDLE, (void*)&keepIdle, sizeof(keepIdle));
		setsockopt(s, SOL_TCP, TCP_KEEPINTVL, (void *)&keepInterval, sizeof(keepInterval));
		setsockopt(s, SOL_TCP, TCP_KEEPCNT, (void *)&keepCount, sizeof(keepCount));
		return true;
	}
#else
	inline bool netio_setkeepalive(SOCKET sock, bool bfast = false)
	{
		BOOL bKeepAlive = 1;
		int nRet = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE,
			(char*)&bKeepAlive, sizeof(bKeepAlive));
		if (nRet == SOCKET_ERROR)
			return false;
		tcp_keepalive alive_in;
		tcp_keepalive alive_out;
		if (bfast)
		{
			alive_in.keepalivetime = 5 * 1000;
			alive_in.keepaliveinterval = 500;
		}
		else
		{
			alive_in.keepalivetime = 30 * 1000;
			alive_in.keepaliveinterval = 1000;
		}
		alive_in.onoff = 1;
		unsigned long ulBytesReturn = 0;

		nRet = WSAIoctl(sock, SIO_KEEPALIVE_VALS, &alive_in, sizeof(alive_in),
			&alive_out, sizeof(alive_out), &ulBytesReturn, NULL, NULL);
		if (nRet == SOCKET_ERROR)
			return false;
		return true;
	}
#endif 

	inline  SOCKET	netio_tcpconnect(const char* sip, unsigned short suport, int nTimeOutSec, bool bFIONBIO = false)
	{
		if (!sip || !*sip || !inet_addr(sip) || !suport)
			return INVALID_SOCKET;

		struct sockaddr_in ServerHostAddr = { 0 };
		ServerHostAddr.sin_family = AF_INET;
		ServerHostAddr.sin_port = htons(suport);
		ServerHostAddr.sin_addr.s_addr = inet_addr(sip);
		SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		if (s == INVALID_SOCKET)
			return INVALID_SOCKET;

		long ul = 1; // set none block
#ifdef _WIN32
		if (SOCKET_ERROR == ioctlsocket(s, FIONBIO, (unsigned long*)&ul)) {
			::closesocket(s);
			return INVALID_SOCKET;
		}
#else
		if (ioctl(s, FIONBIO, &ul) == -1) {
			::closesocket(s);
			return INVALID_SOCKET;
		}
#endif
		connect(s, (sockaddr *)(&ServerHostAddr), sizeof(ServerHostAddr));

		TIMEVAL tv01 = { nTimeOutSec,0 };
		fd_set fdw;
		FD_ZERO(&fdw);
		FD_SET(s, &fdw);
		int ne;
#ifdef _WIN32
		ne = ::select(0, NULL, &fdw, NULL, &tv01);
#else
		ne = ::select(s + 1, NULL, &fdw, NULL, &tv01);
#endif
		if (ne <= 0 || !FD_ISSET(s, &fdw))
		{
			::closesocket(s);
			return  INVALID_SOCKET;
		}
		ul = 0;
#ifdef _WIN32
		if (!bFIONBIO) {
			if (SOCKET_ERROR == ioctlsocket(s, FIONBIO, (unsigned long*)&ul)) {
				::closesocket(s);
				return INVALID_SOCKET;
			}
		}
#else
		int serr = 0;
		socklen_t serrlen = sizeof(serr);
		getsockopt(s, SOL_SOCKET, SO_ERROR, (void *)&serr, &serrlen);
		if (serr)
		{
			::closesocket(s);
			return INVALID_SOCKET;
		}
		if (!bFIONBIO) {
			if (ioctl(s, FIONBIO, &ul) == -1) {
				::closesocket(s);
				return INVALID_SOCKET;
			}
		}
#endif
		return s;
	}

	//return send bytes size or -1 for error,use for block or nonblocking  mode
	inline int netio_tcpsend(SOCKET s, const void* pbuf, int nsize)
	{
		char *ps = (char*)pbuf;
		int  nsend = 0, ns = 0;
		int  nret;
		while (nsend < nsize)
		{
#ifdef _WIN32            
			nret = ::send(s, ps + nsend, nsize - nsend, 0);
			if (SOCKET_ERROR == nret)
			{
				int nerr = WSAGetLastError();
				if (WSAEWOULDBLOCK == nerr || WSAENOBUFS == nerr)  // nonblocking  mode
				{
					TIMEVAL tv01 = { 0,1000 * 100 };
					fd_set fdw, fde;
					FD_ZERO(&fdw);
					FD_ZERO(&fde);
					FD_SET(s, &fdw);
					FD_SET(s, &fde);
					if (-1 == ::select(0, NULL, &fdw, &fde, &tv01))
						return SOCKET_ERROR;
					if (FD_ISSET(s, &fde))
						return SOCKET_ERROR;
					ns++;
					if (ns > 40) //4 secs
						return SOCKET_ERROR;
					continue;
				}
				else
					return SOCKET_ERROR;
			}
			else if (nret > 0) {
				ns = 0;
				nsend += nret;
			}
#else
			nret = ::send(s, ps + nsend, nsize - nsend, MSG_DONTWAIT | MSG_NOSIGNAL);
			if (SOCKET_ERROR == nret)
			{
				if (errno == EAGAIN || errno == EWOULDBLOCK) // nonblocking  mode
				{
					TIMEVAL tv01 = { 0,1000 * 100 };
					fd_set fdw, fde;
					FD_ZERO(&fdw);
					FD_ZERO(&fde);
					FD_SET(s, &fdw);
					FD_SET(s, &fde);
					if (-1 == ::select(s + 1, NULL, &fdw, &fde, &tv01))
						return SOCKET_ERROR;
					if (FD_ISSET(s, &fde))
						return SOCKET_ERROR;
					ns++;
					if (ns > 40) //4 secs
						return SOCKET_ERROR;
					continue;
				}
				else
					return SOCKET_ERROR;
			}
			else if (nret > 0) {
				nsend += nret;
				ns = 0;
			}
#endif
		}
		return nsend;
	};

	inline  int netio_tcpread(SOCKET s, void* pbuf, int nbufsize, int nTimeOutMsec)
	{
		if (s == INVALID_SOCKET)
			return SOCKET_ERROR;

		TIMEVAL tv01 = { nTimeOutMsec / 1000,1000 * (nTimeOutMsec % 1000) };
		fd_set fdr, fde;
		FD_ZERO(&fdr);
		FD_ZERO(&fde);
		FD_SET(s, &fdr);
		FD_SET(s, &fde);

#ifdef _WIN32
		int nRet = ::select(0, &fdr, NULL, &fde, &tv01);
#else
		int nRet = ::select(s + 1, &fdr, NULL, &fde, &tv01);
#endif

		if (SOCKET_ERROR == nRet)
			return SOCKET_ERROR;

		if (nRet == 0)
			return 0;
		if (FD_ISSET(s, &fde))
			return SOCKET_ERROR;

		nRet = ::recv(s, (char*)pbuf, nbufsize, 0);

		if (nRet <= 0)
			return SOCKET_ERROR;
		return nRet;
	}
	inline unsigned int netio_gethostip(const char* shost) //return net byte order
	{
		unsigned int uip = 0;
		struct addrinfo *result = NULL;
		struct addrinfo *ptr = NULL;
		struct addrinfo hints;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		if (getaddrinfo(shost, NULL, &hints, &result))
			return 0;

		for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
		{
			if (ptr->ai_family == AF_INET)
			{
#ifdef _WIN32
				uip = ((struct sockaddr_in *) ptr->ai_addr)->sin_addr.S_un.S_addr;
#else
				uip = ((struct sockaddr_in *) ptr->ai_addr)->sin_addr.s_addr;
#endif
				break;
			}
		}
		if (result)
			freeaddrinfo(result);
		return uip;
	}


	class aiotcpsrv;

	/*! -----------------------------------------------------------------------------------------
	\brief  Asynchronous TCP server TCP workthread
	send data zero copy. Support for posting custom events
	*/
	class aiotcpsrvworker : public cThread // Asynchronous TCP server TCP workthread
	{
	public:
		aiotcpsrvworker() :_pmem(nullptr), _ppoll(nullptr), _plog(nullptr), _threadno(0), _srvport(0) {
		}
		virtual ~aiotcpsrvworker() {
		}

		inline int getsendnodone(uint32_t ucid) { // get send not done pkg number , < XPOLL_SEND_PKG_NUM
			return _ppoll->sendnodone(ucid);
		}

		bool postdata(uint32_t ucid, void* pdata, size_t bytesize, int timeovermsec = 0) // post send data
		{
			int nerr = _ppoll->post_msg(ucid, pdata, bytesize);
			if (nerr < 0)
				return false;
			int nt = timeovermsec / 10, i = 0;;
			if (nt % 10)
				nt++;
			while (!nerr && i < nt) {
				std::this_thread::sleep_for(std::chrono::milliseconds(10));
				nerr = _ppoll->post_msg(ucid, pdata, bytesize);
			}
			return nerr > 0;
		}

		/*!
		\breif post self event
		\remarkt optcode must >= XPOLL_EVT_OPT_APP
		*/
		bool postselfevent(uint32_t ucid, uint8_t optcode, void *pdata, size_t datasize) // post self event
		{
			if (optcode < XPOLL_EVT_OPT_APP)
				return false;
			_ppoll->add_event(ucid, optcode, 0, pdata, datasize);
			return true;
		}

	protected:
		void setparam(xpoll* ppoll, ec::cLog* plog, memory* pmem, int threadno, uint16_t srvport) {
			_ppoll = ppoll;
			_plog = plog;
			_pmem = pmem;
			_threadno = threadno;
			_srvport = srvport;
		}
		inline void disconnect(uint32_t ucid) {
			_ppoll->remove(ucid);
		}
	protected:
		memory * _pmem;			
		xpoll * _ppoll;		
		ec::cLog* _plog;
		int _threadno;
		uint16_t _srvport;
		friend class aiotcpsrv;
	protected:
		virtual void onconnect(uint32_t ucid, const char* sip) = 0;//connect event
		virtual void ondisconnect(uint32_t ucid) = 0;//disconnect  event
		virtual void onrecv(uint32_t ucid, const void* pdata, size_t size) = 0; //read event
		virtual void onsend(uint32_t ucid, int nstatus, void* pdata, size_t size) = 0; //send complete event
		virtual void onself(uint32_t ucid, int optcode, void* pdata, size_t size) = 0; //self event		
	protected:
		virtual	void dojob() {
			t_xpoll_event evt;
			if (!_ppoll->get_event(&evt))
				return;
			if (XPOLL_EVT_OPT_READ == evt.opt) {
				if (XPOLL_EVT_ST_CONNECT == evt.status) {
					txtkeyval kv((const char*)evt.pdata, evt.ubytes);
					char sip[32] = { 0 };
					if (!kv.get("ip", sip, sizeof(sip)))
						sip[0] = 0;
					onconnect(evt.ucid, sip);
				}
				else if (XPOLL_EVT_ST_OK == evt.status) {
					if (evt.pdata)
						onrecv(evt.ucid, evt.pdata, evt.ubytes);
				}
				else if (XPOLL_EVT_ST_ERR == evt.status || XPOLL_EVT_ST_CLOSE == evt.status) {
					ondisconnect(evt.ucid);
				}
			}
			else if (XPOLL_EVT_OPT_SEND == evt.opt)
				onsend(evt.ucid, evt.status, evt.pdata, evt.ubytes);
			else
				onself(evt.ucid, evt.opt, evt.pdata, evt.ubytes);
			_ppoll->free_event(&evt);
			return;
		}
	};


#define MAX_XPOLLTCPSRV_THREADS 16

	/*! -----------------------------------------------------------------------------------------
	\brief  Asynchronous TCP server
	send data zero copy
	*/
	class aiotcpsrv :public cThread // Asynchronous TCP server accpet thread
	{
	public:
		aiotcpsrv(uint32_t maxconnum, ec::cLog* plog, memory* pmem) : _pmem(pmem), _bkeepalivefast(false), _busebnagle(true), _wport(0),
			_plog(plog), _poll(maxconnum) {
		}
		virtual ~aiotcpsrv() {};

		inline int getsendnodone(uint32_t ucid) { // get send not done pkg number
			return _poll.sendnodone(ucid);
		}
	protected:
		memory * _pmem;
	private:
		bool	_bkeepalivefast;
		bool	_busebnagle;
		uint16_t _wport;
		cLog* _plog;
		xpoll	  _poll;
		SOCKET    _fd_listen;
		ec::Array<aiotcpsrvworker*, MAX_XPOLLTCPSRV_THREADS> _workers;
	protected:
		virtual ec::aiotcpsrvworker* createworkthread() = 0;
	public:
		bool start(uint16_t port, int workthreadnum, const char* sip = nullptr)
		{
			if (IsRun())
				return true;
			_wport = port;
			_fd_listen = listen_port(port, sip);
			if (_fd_listen == INVALID_SOCKET)
				return  false;
			if (!_poll.open()) {
				::closesocket(_fd_listen);
				_fd_listen = INVALID_SOCKET;
				return false;
			}
			int i, n = workthreadnum;
			if (n > MAX_XPOLLTCPSRV_THREADS)
				n = MAX_XPOLLTCPSRV_THREADS;
			ec::aiotcpsrvworker* p;
			for (i = 0; i < n; i++) {
				p = createworkthread();
				p->setparam(&_poll, _plog, _pmem, i, port);
				p->StartThread(nullptr);
				_workers.add(p);
			}
			StartThread(nullptr);
			return true;
		}

		void stop()
		{
			if (_fd_listen) {
				StopThread(); //stop accpet thread
#ifdef _WIN32
				shutdown(_fd_listen, SD_BOTH);
#else
				shutdown(_fd_listen, SHUT_WR);
#endif
				::closesocket(_fd_listen);

				_poll.close();//close fds in poll

				while (_poll.has_event()) // wait for all events done
					std::this_thread::sleep_for(std::chrono::milliseconds(100));

				_workers.for_each([](ec::aiotcpsrvworker* &pt) {pt->StopThread(); });//stop all workers
				_fd_listen = INVALID_SOCKET;
				if (_plog) {
					_plog->add(CLOG_DEFAULT_MSG, "TCP server port %d  close success", _wport);
				}
			}
		}
	private:
		SOCKET listen_port(unsigned short wport, const char* sip = nullptr)
		{
			if (!wport)
				return false;
			SOCKET sl = INVALID_SOCKET;
			struct sockaddr_in	netaddr;
#ifdef _WIN32
			if ((sl = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED)) == INVALID_SOCKET)
#else
			if ((sl = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
#endif
			{
				if (_plog)
					_plog->add(CLOG_DEFAULT_ERR, "TCP port %u socket error!", wport);
				fprintf(stderr, "TCP port %u socket error!\n", wport);
				return false;
			}
			netaddr.sin_family = AF_INET;
			if (!sip || !sip[0])
				netaddr.sin_addr.s_addr = htonl(INADDR_ANY);
			else
				netaddr.sin_addr.s_addr = inet_addr(sip);
			netaddr.sin_port = htons(wport);

			if (bind(sl, (const sockaddr *)&netaddr, sizeof(netaddr)) == SOCKET_ERROR)
			{
				::closesocket(sl);
				if (_plog)
					_plog->add(CLOG_DEFAULT_ERR, "TCP port [%d] bind failed with error %d", wport, errno);
				fprintf(stderr, "ERR:TCP port [%d] bind failed with error %d\n", wport, errno);
				return INVALID_SOCKET;
			}
			if (listen(sl, SOMAXCONN) == SOCKET_ERROR)
			{
				::closesocket(sl);
				if (_plog)
					_plog->add(CLOG_DEFAULT_ERR, "TCP port %d  listen failed with error %d", wport, errno);
				fprintf(stderr, "ERR: TCP port %d  listen failed with error %d\n", wport, errno);
				return INVALID_SOCKET;
			}
			if (_plog) {
				_plog->add(CLOG_DEFAULT_MSG, "TCP server port %d listen success", wport);
			}
			return sl;
		}

	protected:
		virtual	void dojob()// accept thread
		{
			int nRet;
			SOCKET	sAccept;
			struct  sockaddr_in		 addrClient;
			int		nClientAddrLen = sizeof(addrClient);

			TIMEVAL tv01 = { 1,0 };
			fd_set fdr;
			FD_ZERO(&fdr);
			FD_SET(_fd_listen, &fdr);
#ifdef _WIN32
			nRet = ::select(0, &fdr, NULL, NULL, &tv01);
#else
			nRet = ::select(_fd_listen + 1, &fdr, NULL, NULL, &tv01);
#endif
			if (!nRet || !FD_ISSET(_fd_listen, &fdr))
				return;
#ifdef _WIN32
			if ((sAccept = ::accept(_fd_listen, (struct sockaddr*)(&addrClient), &nClientAddrLen)) == INVALID_SOCKET)
				return;
			unsigned long ul = 1;
			if (SOCKET_ERROR == ioctlsocket(sAccept, FIONBIO, (unsigned long*)&ul)) {
				::closesocket(sAccept);
				return;
			}
#else
			if ((sAccept = ::accept(_fd_listen, (struct sockaddr*)(&addrClient), (socklen_t*)&nClientAddrLen)) == INVALID_SOCKET)
				return;
			int nv = 1;
			if (ioctl(sAccept, FIONBIO, &nv) == -1) {
				::closesocket(sAccept);
				return;
			}
#endif
			char        sip[32] = { 0 };
			snprintf(sip, sizeof(sip), "ip:%s\n", inet_ntoa(addrClient.sin_addr));
			sip[sizeof(sip) - 1] = 0;

			netio_setkeepalive(sAccept, _bkeepalivefast);
			if (!_busebnagle)
				netio_tcpnodelay(sAccept);
			if (!_poll.add_fd(sAccept, sip)) { // add to xpoll
#ifdef _WIN32
				shutdown(sAccept, SD_BOTH);
#else
				shutdown(sAccept, SHUT_WR);
#endif
				::closesocket(sAccept);
				return;
			}
		};
	};

	class aiotcpclient : public cThread // Asynchronous auto reconnect TCP client
	{
	public:
		aiotcpclient() :_cpevt(128, &_cpevtlock), _fd(INVALID_SOCKET), _bconnect(false), _fdchanged(false),
#ifdef _ARM_LINUX
			_memblk(1024 * 8, 8, 1024 * 256, 2, 0, 0, &_mem_lock)
#else
			_memblk(1024 * 32, 8, 1024 * 256, 4, 1024 * 1024, 2, &_mem_lock)
#endif
		{
			memset(_sip, 0, sizeof(_sip));
			_port = 0;
			_ucid = 0;
		}
		virtual ~aiotcpclient() {
		}
	public:
		bool open(const char* sip, uint16_t port)
		{
			if (!sip || !sip[0] || !port)
				return false;
			if (IsRun())
				return false;
			if (!_udpevt.open())
				return false;
			strncpy(_sip, sip, sizeof(_sip) - 1);
			_port = port;
			StartThread(nullptr);
			return true;
		}
		void close()
		{
			StopThread();// stop send thread first			
			_disconnect(XPOLL_EVT_ST_CLOSE);
			_udpevt.close();
		}

		bool postdata(const void* pdata, size_t bytesize, int timeovermsec = 0) // post send data
		{
			int nerr = post_msg(pdata, bytesize);
			if (nerr < 0)
				return false;
			int nt = timeovermsec / 10, i = 0;;
			if (nt % 10)
				nt++;
			while (!nerr && i < nt) {
				std::this_thread::sleep_for(std::chrono::milliseconds(10));
				nerr = post_msg(pdata, bytesize);
			}
			return nerr > 0;
		}
	protected:
		virtual void onrecv(const void* pdata, size_t bytesize) = 0;
		virtual void onconnect() = 0;
		virtual void ondisconnect() = 0;
	private:
		udpevt _udpevt;
		std::mutex _cpevtlock;//lock for _cpevt
		ec::fifo<t_xpoll_event> _cpevt;//completely event

		char _sip[32];
		uint16_t _port;
		SOCKET _fd;
		pollfd _pollfd[2];
		std::atomic_bool _bconnect, _fdchanged;
		t_xpoll_item _xitem;
		uint32_t _ucid;
		std::mutex _slock;//lock for socket				

		std::mutex _mem_lock;// lock for _memread
		ec::memory _memblk;// memory for send

		int post_msg(const void *pd, size_t size) //return  -1:error; 0:full ; >0: post bytes
		{
			if (!_bconnect)
				return -1;
			ec::unique_lock lck(&_slock);
			t_xpoll_item* pi = &_xitem;
			if ((pi->utail + 1) % XPOLL_SEND_PKG_NUM == pi->uhead) //full
				return 0;
			pi->pkg[pi->utail].size = (uint32_t)size;
			pi->pkg[pi->utail].pd = (uint8_t *)_memblk.mem_malloc(size); //(uint8_t*)pd;
			if (!pi->pkg[pi->utail].pd)
				return false;
			memcpy(pi->pkg[pi->utail].pd, pd, size);
			pi->utail = (pi->utail + 1) % XPOLL_SEND_PKG_NUM;
			_udpevt.set_event();
			return (int)size;
		}

		void _disconnect(int status) {
			_bconnect = false;
			t_xpoll_item t;
			_slock.lock();
			t = _xitem;

			if (INVALID_SOCKET != _xitem.fd) {
#ifdef _WIN32
				shutdown(_xitem.fd, SD_BOTH);
#else
				shutdown(_xitem.fd, SHUT_WR);
#endif
				::closesocket(_xitem.fd);
				_xitem.fd = INVALID_SOCKET;
				_fd = INVALID_SOCKET;
				ondisconnect();
			}
			_slock.unlock();
			while (t.uhead != t.utail) {
				add_event(_ucid, XPOLL_EVT_OPT_SEND, status, t.pkg[t.uhead].pd, 0);
				_udpevt.set_event();
				t.uhead = (t.uhead + 1) % XPOLL_SEND_PKG_NUM;
			}
			_fdchanged = true;
		}
	protected:
		virtual	void dojob()
		{
			doevent();
			if (!_bconnect) {
				SOCKET s = netio_tcpconnect(_sip, _port, 6, true);
				if (INVALID_SOCKET == s)
					return;
				_fd = s;
				_ucid++;
				while (!_ucid)
					_ucid++;
				memset(&_xitem, 0, sizeof(_xitem));// reset xpollitem
				_xitem.fd = _fd;
				_bconnect = true;
				_fdchanged = true;
				onconnect();
			}
			if (_fdchanged) {
				_pollfd[0].fd = _udpevt.getfd();
				_pollfd[0].events = POLLIN;
				_pollfd[0].revents = 0;

				_pollfd[1].fd = _fd;
				_pollfd[1].events = POLLIN | POLLOUT;
				_pollfd[1].revents = 0;

				_fdchanged = false;
			}
#ifdef _WIN32
			int n = WSAPoll(_pollfd, (ULONG)2, 200);
#else
			int n = poll(_pollfd, 2, 200);
#endif
			if (n <= 0)
				return;
			t_xpoll_send ts;
			for (auto i = 0; i < 2; i++) {
				if (i == 0) { //udpevt
					if (_pollfd[i].revents & POLLIN) {
						_udpevt.reset_event();
						_pollfd[i].revents = 0;
					}
					continue;
				}
				if (_pollfd[i].revents & (POLLERR | POLLHUP | POLLNVAL)) { // error,
					_disconnect(XPOLL_EVT_ST_ERR);
					continue;
				}
				if (get_send(&ts)) { //send first					
					if (sendts(&ts) > 0) // not send complete 
						_pollfd[i].events = POLLIN | POLLOUT;
					else // send complete 
						_pollfd[i].events = POLLIN;
				}
				if (_pollfd[i].revents & POLLIN)  //read
					do_read(_fd);
				_pollfd[i].revents = 0;
			}
			doevent();
		};
	private:
		void add_event(uint32_t ucid, uint8_t opt, uint8_t st, void *pdata, size_t datasize)
		{
			t_xpoll_event evt;
			memset(&evt, 0, sizeof(evt));
			evt.opt = opt;
			evt.status = st;
			evt.ucid = ucid;
			evt.pdata = pdata;
			evt.ubytes = (uint32_t)datasize;
			_cpevt.add(evt);
		}
		bool get_send(t_xpoll_send* ps)
		{
			ec::unique_lock lck(&_slock);
			t_xpoll_item* p = &_xitem;
			if (p->uhead != p->utail) //not empty
			{
				ps->ucid = p->ucid;
				ps->fd = p->fd;
				ps->upos = p->uhead;
				ps->usendsize = p->usendsize;
				ps->pd = p->pkg[p->uhead].pd;
				ps->usize = p->pkg[p->uhead].size;
				return true;
			}
			return false;
		}
		int sendts(t_xpoll_send* ps) // return -1:error; 0:no send ; >0 send byte
		{
			int nret, ns = (int)(ps->usize - ps->usendsize);
			if (ns < 0 || ps->usendsize > ps->usize) {
				do_sendbyte(ps, -1);
				return -1;
			}
#ifdef _WIN32            
			nret = ::send(ps->fd, (char*)ps->pd + ps->usendsize, ns, 0);
			if (-1 == nret) {
				int nerr = WSAGetLastError();
				if (WSAEWOULDBLOCK == nerr || WSAENOBUFS == nerr) {  // nonblocking  mode
					do_sendbyte(ps, 0);
					return 0;
				}
			}
#else
			nret = ::send(ps->fd, (char*)ps->pd + ps->usendsize, ns, MSG_DONTWAIT | MSG_NOSIGNAL);
			if (-1 == nret) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) { // nonblocking  mode
					do_sendbyte(ps, 0);
					return 0;
				}
			}
#endif
			if (nret > 0)
				ps->usendsize += nret; //add to send bytes
			do_sendbyte(ps, nret);
			return nret;
		}
		int  do_sendbyte(t_xpoll_send* ps, int nerr) //return 0:no more send data;  >0：has more send data
		{
			int nret = 0;
			_slock.lock();
			t_xpoll_item* pi = &_xitem;
			if (nerr > 0) //success
			{
				pi->errnum = 0;// reset error counter
				if (ps->usendsize == ps->usize)//complete
				{
					pi->uhead = (pi->uhead + 1) % XPOLL_SEND_PKG_NUM;//next
					pi->lasterr = 0;
					pi->usendsize = 0;
					_slock.unlock();
					add_event(ps->ucid, XPOLL_EVT_OPT_SEND, XPOLL_EVT_ST_OK, ps->pd, ps->usendsize);
					_udpevt.set_event();
					if (pi->uhead != pi->utail)
						nret = 1;
					return nret;
				}
				else
					nret = 1;
			}
			else if (nerr == 0)
			{
				pi->errnum++;
				if (pi->errnum == 1)
					pi->lasterr = ::time(0);
				else if (pi->errnum > 2) {
					time_t tcur = ::time(0);
					if (pi->lasterr && (tcur - pi->lasterr) > 5) {
						_slock.unlock();
						_disconnect(XPOLL_EVT_ST_ERR);
						return 0;
					}
				}
			}
			else if (nerr < 0) {
				_slock.unlock();
				_disconnect(XPOLL_EVT_ST_ERR);
				return 0;
			}
			_slock.unlock();
			return nret;
		}
#ifdef _WIN32
		void do_read(SOCKET fd)
#else
		void do_read(int fd)
#endif
		{
			char rbuf[32 * 1024];
#ifdef _WIN32
			int nr = ::recv(fd, rbuf, (int)sizeof(rbuf), 0);
#else
			int nr = ::recv(fd, rbuf, (int)sizeof(rbuf), MSG_DONTWAIT);
#endif
			if (nr == 0) {//close gracefully			
				_disconnect(XPOLL_EVT_ST_CLOSE);
				return;
			}
			else if (nr < 0) {
#ifdef _WIN32
				if (!(WSAEWOULDBLOCK == WSAGetLastError()))
#else
				if (!(errno == EAGAIN || errno == EWOULDBLOCK))
#endif
					_disconnect(XPOLL_EVT_ST_ERR);

			}
			else //read event			
				onrecv(rbuf, nr);
		}
		void doevent() // do send complete
		{
			t_xpoll_event evt;
			memset(&evt, 0, sizeof(evt));
			while (_cpevt.get(evt)) {
				if (evt.pdata)
					_memblk.mem_free(evt.pdata);//free memory				
			}
		}
	};
}

/* example
#include "ec/c11_system.h"
#include "ec/c11_xpoll.h"
#include "ec/c11_netio.h"

#ifdef _WIN32
#include "ec/c_usews32.h"
ec::cUseWS_32 _wins32;
#endif

class cTstSrvWorker : public ec::aiotcpsrvworker
{
public:
	cTstSrvWorker() {
	}
protected:
	virtual void onconnect(uint32_t ucid, const char* sip)//connect event
	{
		printf("ucid %u ip=%s connect!\n", ucid, sip);
	}
	virtual void ondisconnect(uint32_t ucid)//disconnect  event
	{
		printf("ucid %u ondisconnect!\n", ucid);
	}
	virtual void onrecv(uint32_t ucid, const void* pdata, size_t size) { //read event
		printf("srv dbg: onrecv ucid=%u,size=%zu\n", ucid, size);
		if (pdata) {
			printf("srv onrecv data:%s\n", (const char*)pdata);
			void* p = _pmem->mem_malloc(size);//echo
			if (p) {
				memcpy(p, pdata, size);
				if (!postdata(ucid, p, size))
					_pmem->mem_free(p);
			}
		}
	}
	virtual void onsend(uint32_t ucid, int nstatus, void* pdata, size_t size) { //send complete event
		printf("srv dbg: onsend ucid=%u,nstatus=%d,size=%zu\n", ucid, nstatus, size);
		if (pdata) {
			printf("srv onsend data:%s\n", (const char*)pdata);
			_pmem->mem_free(pdata);
		}
	}
	virtual void onself(uint32_t ucid, int optcode, void* pdata, size_t size) { //self event
		if (pdata)
			_pmem->mem_free((void*)pdata);
	}
};

class cTstSrv : public ec::aiotcpsrv
{
public:
	cTstSrv() : _mem_send(1024 * 8, 16, 1024 * 32, 16, 1024 * 1024, 4, &_mem_lock),
		ec::aiotcpsrv(1024, nullptr, &_mem_send) {
	}
protected:
	virtual ec::aiotcpsrvworker* createworkthread() {
		return new cTstSrvWorker();
	}
private:
	std::mutex _mem_lock;// mutex for _mem_send
	ec::memory _mem_send;// memory for send
};

class cTstClient : public ec::aiotcpclient //client
{
public:
	cTstClient() {
	}
	void sendstr(const char* s) {
		postdata(s, strlen(s) + 1);
	}
protected:
	virtual void onrecv(const void* pdata, size_t bytesize) {
		const char* ps = (const char*)pdata;
		printf("cli:recv %s\n", ps);
	}
	virtual void onconnect() {
		printf("cli:connect!\n");
	}
	virtual void ondisconnect() {
		printf("cli:disconnect!\n");
	}
};

#define CMDOD_LEN 1024
int main(int argc, char* argv[])
{
	cTstSrv srv;
	if (!srv.start(9019, 2)) {
		printf("start srv failed!\n");
		return -1;
	}
	cTstClient cli;
	if (!cli.open("127.0.0.1", 9019)) {
		printf("start cli failed!\n");
		return -2;
	}
	char sod[CMDOD_LEN], sw[128], s1[128];
	memset(sod, 0, sizeof(sod));
	while (1) {
		if (fgets(sod, CMDOD_LEN - 1, stdin)) {
			size_t n = strlen(sod);
			size_t pos = 0;
			if (!ec::str_getnext("\t\x20", sod, n, pos, sw, sizeof(sw)))
				continue;
			if (!strcmp(sw, "exit"))
				break;
			else if (!strcmp(sw, "cs")) {
				if (!ec::str_getnext("\n", sod, n, pos, s1, sizeof(s1)))
					printf("error args!\n");
				else
					cli.sendstr(s1);
			}
			else if (!strcmp(sw, "cc")) {
				cli.close();
			}
			else
				printf("error cmd\n");
		}
	}
	cli.close();
	srv.stop();
	return 0;
}
*/