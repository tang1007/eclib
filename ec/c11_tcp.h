/*!
\file c11_tcp.h
\author	jiangyong
\email  kipway@outlook.com
\update 2018.6.24

eclibe Asynchronous TCP template class for windows & linux

class AioTcpClient
class AioTcpSrv
class AioTcpSrvThread

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

#include <atomic>
#include "c11_keyval.h"
#include "c11_log.h"
#include "c11_netio.h"
#include "c11_xpoll.h"

namespace ec
{
	template<class _CLS>
	class AioTcpClient : public cThread // Asynchronous auto reconnect TCP client, for compatible with windows XP, use the select model
	{
	public:
		AioTcpClient(memory* pmem) : _pmem(pmem), _delaytks(0), _cpevt(128, &_cpevtlock), _bconnect(false)
		{
			memset(_sip, 0, sizeof(_sip));
			_port = 0;
			_ucid = 0;
			memset(&_xitem, 0, sizeof(_xitem));
			_xitem.fd = INVALID_SOCKET;
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
			_delaytks = 0;
			strncpy(_sip, sip, sizeof(_sip) - 1);
			_port = port;
			StartThread(nullptr);
			return true;
		}
		void close()
		{
			StopThread();
			_disconnect(XPOLL_EVT_ST_CLOSE);
			_udpevt.close();
		}
		bool tcp_post(const void* pdata, size_t bytesize, int timeovermsec = 100) // post send data
		{
			int nerr = post_msg(pdata, bytesize);
			if (nerr < 0)
				return false;
			int nt = timeovermsec / 2, i = 0;;
			if (nt % 2)
				nt++;
			while (!nerr && i < nt) {
				std::this_thread::sleep_for(std::chrono::milliseconds(2));
				nerr = post_msg(pdata, bytesize);
				i++;
			}
			return nerr > 0;
		}
		bool tcp_post(ec::vector<uint8_t> *pd, int timeovermsec = 100) // post send data
		{
			int nerr = post_msg(pd);
			if (nerr < 0)
				return false;
			int nt = timeovermsec / 2, i = 0;;
			if (nt % 2)
				nt++;
			while (!nerr && i < nt) {
				std::this_thread::sleep_for(std::chrono::milliseconds(2));
				nerr = post_msg(pd);
				i++;
			}
			return nerr > 0;
		}
	protected:
		memory * _pmem; //memory for send
		std::atomic_int _delaytks; // reconnect delay 100ms tks
		bool post_onread(const void *pd, size_t size) //called in onrecv.
		{
			int nr = post_msg(pd, size);
			if (nr < 0)
				return false;
			else if (nr > 0)
				return true;
			t_xpoll_send ts;
			while (get_send(&ts)) { //send first					
				if (sendts(&ts) < 0) // error
					return false;
				nr = post_msg(pd, size);
				if (nr < 0)
					return false;
				else if (nr > 0)
					break;
			}
			return true;
		}
		bool post_onread(ec::vector<uint8_t> *pvd) //called in onrecv.
		{
			int nr = post_msg(pvd);
			if (nr < 0)
				return false;
			else if (nr > 0)
				return true;
			t_xpoll_send ts;
			while (get_send(&ts)) { //send first					
				if (sendts(&ts) < 0) // error
					return false;
				nr = post_msg(pvd);
				if (nr < 0)
					return false;
				else if (nr > 0)
					break;
			}
			return true;
		}
	private:
		udpevt _udpevt;
		std::mutex _cpevtlock;//lock for _cpevt
		ec::fifo<t_xpoll_event> _cpevt;//completely event

		char _sip[32];
		uint16_t _port;

		std::atomic_bool _bconnect;
		t_xpoll_item _xitem;
		uint32_t _ucid;
		std::mutex _slock;//lock for socket

		int post_msg(const void *pd, size_t size) //return  -1:error; 0:full ; >0: post bytes
		{
			if (!_bconnect)
				return -1;
			ec::unique_lock lck(&_slock);
			t_xpoll_item* pi = &_xitem;
			if ((pi->utail + 1) % XPOLL_SEND_PKG_NUM == pi->uhead) //full
				return 0;
			pi->pkg[pi->utail].size = (uint32_t)size;
			pi->pkg[pi->utail].pd = (uint8_t *)_pmem->mem_malloc(size); //(uint8_t*)pd;
			if (!pi->pkg[pi->utail].pd)
				return -1;
			memcpy(pi->pkg[pi->utail].pd, pd, size);
			pi->utail = (pi->utail + 1) % XPOLL_SEND_PKG_NUM;
			_udpevt.set_event();
			return (int)size;
		}
		int post_msg(ec::vector<uint8_t> *pd) //return  -1:error; 0:full ; >0: post bytes
		{
			if (!_bconnect)
				return -1;
			ec::unique_lock lck(&_slock);
			t_xpoll_item* pi = &_xitem;
			if ((pi->utail + 1) % XPOLL_SEND_PKG_NUM == pi->uhead) //full
				return 0;
			int nret = (int)pd->size();
			pi->pkg[pi->utail].size = (uint32_t)pd->size();
			pi->pkg[pi->utail].pd = (uint8_t*)pd->detach_buf();
			pi->utail = (pi->utail + 1) % XPOLL_SEND_PKG_NUM;
			_udpevt.set_event();
			return (int)nret;
		}
	protected:
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
				static_cast<_CLS*>(this)->ondisconnect();
			}
			_slock.unlock();
			while (t.uhead != t.utail) {
				add_event(_ucid, XPOLL_EVT_OPT_SEND, status, t.pkg[t.uhead].pd, 0);
				_udpevt.set_event();
				t.uhead = (t.uhead + 1) % XPOLL_SEND_PKG_NUM;
			}
		}
	protected:
		virtual	void dojob()
		{
			doevent();
			if (!_bconnect) {
				if (_delaytks > 0) {
					std::this_thread::sleep_for(std::chrono::milliseconds(100));
					_delaytks--;
					return;
				}
				SOCKET s = netio_tcpconnect(_sip, _port, 4, true);
				if (INVALID_SOCKET == s)
					return;
				netio_setkeepalive(s);
				_ucid++;
				while (!_ucid)
					_ucid++;
				memset(&_xitem, 0, sizeof(_xitem));// reset xpollitem
				_xitem.fd = s;
				_bconnect = true;
				static_cast<_CLS*>(this)->onconnect();
			}
			TIMEVAL tv01 = { 0, 100 * 1000 }; // 100 ms
			fd_set fdr, fdw, fde;
			FD_ZERO(&fdr);
			FD_ZERO(&fde);
			FD_ZERO(&fdw);

			FD_SET(_udpevt.getfd(), &fdr);
			FD_SET(_xitem.fd, &fdr);
			if (!isempty())
				FD_SET(_xitem.fd, &fdw);
			FD_SET(_xitem.fd, &fde);
#ifdef _WIN32
			int nret = ::select(0, &fdr, &fdw, &fde, &tv01);
#else
			int nfdmax = _xitem.fd;
			if (nfdmax < _udpevt.getfd())
				nfdmax = _udpevt.getfd();
			int nret = ::select(nfdmax + 1, &fdr, &fdw, &fde, &tv01);
#endif
			if (nret <= 0)
				return;
			if (FD_ISSET(_udpevt.getfd(), &fdr))
				_udpevt.reset_event();
			if (FD_ISSET(_xitem.fd, &fde)) {
				_disconnect(XPOLL_EVT_ST_ERR);
				return;
			}
			t_xpoll_send ts;
			if (get_send(&ts))
				sendts(&ts);
			if (FD_ISSET(_xitem.fd, &fdr))
				do_read(_xitem.fd);
		};
	private:
		bool isempty() {
			ec::unique_lock lck(&_slock);
			return _xitem.uhead == _xitem.utail;
		}
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
			if (ns > 1024 * 64)
				ns = 1024 * 64;
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
					if (pi->uhead != pi->utail)
						nret = 1;
					return nret;
				}
				else {
					pi->usendsize = ps->usendsize;
					nret = 1;
				}
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
			char rbuf[16 * 1024];
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
			else { //read event				
				static_cast<_CLS*>(this)->onrecv(rbuf, nr);
			}
		}
		void doevent() // do send complete
		{
			t_xpoll_event evt;
			memset(&evt, 0, sizeof(evt));
			while (_cpevt.get(evt)) {
				if (evt.pdata)
					_pmem->mem_free(evt.pdata);//free memory				
			}
		}
	};

#if (!defined _WIN32) || (_WIN32_WINNT >= 0x0600)

	/*! -----------------------------------------------------------------------------------------
	\brief  Asynchronous TCP server TCP workthread
	send data zero copy. Support for posting custom events
	*/
	template<class _CLS>
	class AioTcpSrvThread : public cThread // Asynchronous TCP server TCP workthread
	{
	public:
		AioTcpSrvThread(xpoll* ppoll, ec::cLog* plog, memory* pmem, int threadno, uint16_t srvport) :
			_pmem(pmem), _ppoll(ppoll), _plog(plog), _threadno(threadno), _srvport(srvport) {
		}
		inline int get_unsends(uint32_t ucid) { // Get the number of unfinished packages , < XPOLL_SEND_PKG_NUM,used for server put message
			return _ppoll->sendnodone(ucid);
		}
		bool tcp_post(uint32_t ucid, void* pdata, size_t bytesize, int timeovermsec = 100) // post data, warning: zero copy, direct put pdata pointer to send buffer
		{
			int nerr = _ppoll->post_msg(ucid, pdata, bytesize);
			if (nerr < 0)
				return false;
			int nt = timeovermsec / 2, i = 0;;
			if (nt % 2)
				nt++;
			while (!nerr && i < nt) {
				std::this_thread::sleep_for(std::chrono::milliseconds(2));
				nerr = _ppoll->post_msg(ucid, pdata, bytesize);
				i++;
			}
			return nerr > 0;
		}
		bool tcp_post(uint32_t ucid, vector<uint8_t> *pvd, int timeovermsec = 100) // post data, warning: zero copy, direct put pdata pointer to send buffer
		{
			int nerr = _ppoll->post_msg(ucid, pvd);
			if (nerr < 0)
				return false;
			int nt = timeovermsec / 2, i = 0;;
			if (nt % 2)
				nt++;
			while (!nerr && i < nt) {
				std::this_thread::sleep_for(std::chrono::milliseconds(2));
				nerr = _ppoll->post_msg(ucid, pvd);
				i++;
			}
			return nerr > 0;
		}

		bool post_self_event(uint32_t ucid, uint8_t optcode, void *pdata, size_t datasize) // post self event, optcode >= XPOLL_EVT_OPT_APP
		{
			if (optcode < XPOLL_EVT_OPT_APP)
				return false;
			_ppoll->add_event(ucid, optcode, 0, pdata, datasize);
			return true;
		}
		inline void close_ucid(uint32_t ucid) // close ucid graceful,send all unsend messages
		{
			tcp_post(ucid, nullptr, 0, 100);
		}
		inline void disconnect(uint32_t ucid) {
			_ppoll->remove(ucid);
		}
	protected:
		memory * _pmem;
		xpoll * _ppoll;
		cLog* _plog;
		int _threadno;
		uint16_t _srvport;
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
					static_cast<_CLS*>(this)->onconnect(evt.ucid, sip);
				}
				else if (XPOLL_EVT_ST_OK == evt.status) {
					if (evt.pdata)
						static_cast<_CLS*>(this)->onrecv(evt.ucid, evt.pdata, evt.ubytes);
				}
				else if (XPOLL_EVT_ST_ERR == evt.status || XPOLL_EVT_ST_CLOSE == evt.status) {
					static_cast<_CLS*>(this)->ondisconnect(evt.ucid);
				}
			}
			else if (XPOLL_EVT_OPT_SEND == evt.opt)
				static_cast<_CLS*>(this)->onsend(evt.ucid, evt.status, evt.pdata, evt.ubytes);
			else
				static_cast<_CLS*>(this)->onself(evt.ucid, evt.opt, evt.pdata, evt.ubytes);
			_ppoll->free_event(&evt);// free read buffer
			return;
		}
	};

	template<class _THREAD, class _CLS>
	class AioTcpSrv : public cThread // Asynchronous TCP server accpet thread
	{
	public:
		AioTcpSrv(uint32_t maxconnum, ec::cLog* plog, memory* pmem, void* pappcls = nullptr, void* pargs = nullptr) : _pmem(pmem), _bkeepalivefast(false), _busebnagle(true), _wport(0),
			_plog(plog), _poll(maxconnum, plog) {
		}
		inline int getsendnodone(uint32_t ucid) { // get send not done pkg number
			return _poll.sendnodone(ucid);
		}
	protected:
		inline void InitArgs(_THREAD* pthread) {
			static_cast<_CLS*>(this)->InitArgs(pthread);
		}
	protected:
		memory * _pmem; // memory used by threads
		cLog*	_plog;
	private:
		bool	_bkeepalivefast;
		bool	_busebnagle;
		uint16_t _wport;

		xpoll	_poll;
		SOCKET	_fd_listen;

		ec::Array<_THREAD*, MAX_XPOLLTCPSRV_THREADS> _workers;
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
			_THREAD* p;
			for (i = 0; i < n; i++) {
				p = new _THREAD(&_poll, _plog, _pmem, i, port);
				InitArgs(p);
				p->StartThread(nullptr);
				_workers.add(p);
			}
			StartThread(nullptr);
			return true;
		}
		bool post_self_event(uint32_t ucid, uint8_t optcode, void *pdata, size_t datasize) // post self event, optcode >= XPOLL_EVT_OPT_APP
		{
			if (optcode < XPOLL_EVT_OPT_APP)
				return false;
			_poll.add_event(ucid, optcode, 0, pdata, datasize);
			return true;
		}
		bool tcp_post(uint32_t ucid, void* pdata, size_t bytesize, int timeovermsec = 100) // post data, warning: zero copy, direct put pdata pointer to send buffer
		{
			int nerr = _poll.post_msg(ucid, pdata, bytesize);
			if (nerr < 0)
				return false;
			int nt = timeovermsec / 2, i = 0;;
			if (nt % 2)
				nt++;
			while (!nerr && i < nt) {
				std::this_thread::sleep_for(std::chrono::milliseconds(2));
				nerr = _poll.post_msg(ucid, pdata, bytesize);
				i++;
			}
			return nerr > 0;
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

				_workers.for_each([](_THREAD* &pt) {
					pt->StopThread();
					delete pt;
				});//stop all workers
				_workers.clear();
				_fd_listen = INVALID_SOCKET;
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
#endif
} // namespace ec

