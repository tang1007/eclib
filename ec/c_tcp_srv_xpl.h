/*!
\file c_tcp_srv.h
\author	kipway@outlook.com
\update 2018.4.3 modify Linux Epoll to EPOLLET (edge-trigger)

class ec::cTcpServer
class ec::cTcpSvrWorkThread

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

#pragma once //2018/9/19 新版
#include <atomic>
#include "c11_keyval.h"
#include "c11_log.h"
#include "c11_netio.h"
#include "c11_xpoll.h"
#include "c11_thread.h"
#include <time.h>

#define TCPIO_OPT_SEND	 0x20000		       // write
#define TCPIO_OPT_PUT   (TCPIO_OPT_SEND + 12)  //server put

//#define MAX_TCPWORK_THREAD	16		//

namespace ec
{
	/*!
	\brief work thread
	*/
	class cTcpSvrWorkThread : public cThread
	{
	public:
		cTcpSvrWorkThread() {
			_nthreadno = -1;
			_pmem = nullptr;
			_ppoll = nullptr;
			_plog = nullptr;
			_wport = 0;
		};
		virtual ~cTcpSvrWorkThread() {
			Stop();
		};
	protected:
		memory* _pmem;
		xpoll * _ppoll;
		cLog*   _plog;

		unsigned short	_wport;
		int             _nthreadno;

	protected:
		virtual void    OnConnect(unsigned int  ucid, const char* sip) = 0;//连接
		virtual void	OnClientDisconnect(unsigned int  ucid, unsigned int uopt, int nerrorcode) = 0; //uopt = TCPIO_OPT_XXXX
		virtual bool	OnReadBytes(unsigned int ucid, const void* pdata, unsigned int usize) = 0; //return false will disconnect
		virtual	void	DoSelfMsg(unsigned int ucid, unsigned int uevt) = 0;	// uevt = TCPIO_MSG_XXXX
	public:
		bool	Start(int nthreadno, unsigned short wport, memory* pmem, xpoll* pxpoll, cLog* plog)
		{
			if (IsRun())
				return true;
			_pmem = pmem;
			_ppoll = pxpoll;
			_plog = plog;

			_nthreadno = nthreadno;
			_wport = wport;

			StartThread(NULL);
			return true;
		};

		inline void Stop() {
			StopThread();
		};

		/*!
		\return return send bytes,
		0:memery error;
		-1: no ucid or IO error ,call OnClientDisconnect
		*/
		int	SendToUcid(unsigned int ucid, const void* pbuf, unsigned int usize)
		{
			if (!pbuf || !usize)
				return 0;
			vector<uint8_t> vd(usize + 8 - usize % 8, _pmem);
			if (!vd.add((const uint8_t*)pbuf, usize))
				return -1;
			int nerr = _ppoll->post_msg(ucid, &vd);
			if (nerr < 0)
				return -1;
			int nt = 100, i = 0; //200 ms timeover			
			while (!nerr && i < nt) {
				std::this_thread::sleep_for(std::chrono::milliseconds(2));
				nerr = _ppoll->post_msg(ucid, &vd);
				i++;
			}
			return nerr > 0 ? (int)usize : -1;
		};


	protected:
		virtual	void dojob()
		{
			t_xpoll_event evt;
			_watchdog = 0;
			if (!_ppoll->get_event(&evt))
				return;
			if (XPOLL_EVT_OPT_READ == evt.opt) {
				if (XPOLL_EVT_ST_CONNECT == evt.status) {
					txtkeyval kv((const char*)evt.pdata, evt.ubytes);
					char sip[32] = { 0 };
					if (!kv.get("ip", sip, sizeof(sip)))
						sip[0] = 0;
					OnConnect(evt.ucid, sip);
				}
				else if (XPOLL_EVT_ST_OK == evt.status) {
					if (evt.pdata)
						OnReadBytes(evt.ucid, evt.pdata, evt.ubytes);
				}
				else if (XPOLL_EVT_ST_ERR == evt.status || XPOLL_EVT_ST_CLOSE == evt.status) {
					OnClientDisconnect(evt.ucid, 0, 0);
				}
			}
			else if (XPOLL_EVT_OPT_SEND == evt.opt) {
				if (evt.pdata)
					_pmem->mem_free(evt.pdata);
			}
			else
				DoSelfMsg(evt.ucid, evt.opt); //自定义消息
			_ppoll->free_event(&evt);// free read buffer
			return;
		}
	}; //cTcpSvrWorkThread

	/*!
	\brief TCP Server, accept
	*/
	class cTcpServer : public cThread
	{
	public:
		cTcpServer(memory* pmem, uint32_t maxconnum, cLog* plog) : _pmem(pmem), _plog(plog), _poll(maxconnum, plog) {
			unsigned int i;
			_bkeepalivefast = false;
			_busebnagle = true;
			_wport = 0;
			m_uThreads = 0;

			for (i = 0; i < MAX_XPOLLTCPSRV_THREADS; i++)
				m_pThread[i] = NULL;
			_nerr_emfile_count = 0;
		};
		virtual ~cTcpServer() {};

	protected:
		unsigned int		m_uThreads;
	protected:
		memory* _pmem; // memory used by threads
		cLog*	_plog;
		uint16_t _wport;
	private:
		xpoll	_poll;
		SOCKET	_fd_listen;

	protected:
		bool    _bkeepalivefast;
		bool    _busebnagle;
		cTcpSvrWorkThread*	m_pThread[MAX_XPOLLTCPSRV_THREADS];
		int _nerr_emfile_count;
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
		virtual void on_err_accept(uint16_t port, int nerr, cLog* plog) //
		{
		}
		virtual	void dojob()
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
			if ((sAccept = ::accept(_fd_listen, (struct sockaddr*)(&addrClient), &nClientAddrLen)) == INVALID_SOCKET) {
				int nerr = WSAGetLastError();
				if (WSAEWOULDBLOCK == nerr) {
					_nerr_emfile_count = 0;
					return;
				}
				else if (WSAEMFILE == nerr) { //超限,报警日志
					if (_plog)
						_plog->add(CLOG_DEFAULT_WRN, "server port(%d) error EMFILE!", _wport);
					on_err_accept(_wport, nerr, _plog);
					if (!_nerr_emfile_count)
						std::this_thread::sleep_for(std::chrono::milliseconds(10));
					_nerr_emfile_count++;
				}
				else {
					_nerr_emfile_count = 0;
					on_err_accept(_wport, nerr, _plog);
				}
				return;
			}
			unsigned long ul = 1;
			if (SOCKET_ERROR == ioctlsocket(sAccept, FIONBIO, (unsigned long*)&ul)) {
				::closesocket(sAccept);
				return;
			}
#else
			if ((sAccept = ::accept(_fd_listen, (struct sockaddr*)(&addrClient), (socklen_t*)&nClientAddrLen)) == INVALID_SOCKET) {
				int nerr = errno;
				if (EAGAIN == nerr || EWOULDBLOCK == nerr) {
					_nerr_emfile_count = 0;
					return;
				}
				else if (EMFILE == nerr) {
					if (_plog)
						_plog->add(CLOG_DEFAULT_WRN, "server port(%d) error EMFILE!", _wport);
					on_err_accept(_wport, nerr, _plog);
					if (!_nerr_emfile_count)
						std::this_thread::sleep_for(std::chrono::milliseconds(10));
					_nerr_emfile_count++;
				}
				else {
					_nerr_emfile_count = 0;
					on_err_accept(_wport, nerr, _plog);
				}
				return;
			}
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
	protected:
		virtual ec::cTcpSvrWorkThread* CreateWorkThread() = 0;
	protected:
		void	StopAndDeleteThreads()
		{
			unsigned int i;
			for (i = 0; i < m_uThreads; i++)
			{
				m_pThread[i]->Stop();
				delete m_pThread[i];
				m_pThread[i] = NULL;
			}
			m_uThreads = 0;
		}
	public:

		bool	Start(unsigned short wport, unsigned int uThreads, bool bkeepalivefast = false, bool busenagle = true)
		{
			if (IsRun())
				return true;
			_wport = wport;
			_bkeepalivefast = bkeepalivefast;
			_busebnagle = busenagle;

			_fd_listen = listen_port(wport, nullptr);
			if (_fd_listen == INVALID_SOCKET)
				return  false;
			if (!_poll.open()) {
				::closesocket(_fd_listen);
				_fd_listen = INVALID_SOCKET;
				return false;
			}
			uint32_t i, n = uThreads, pos = 0u;
			if (n > MAX_XPOLLTCPSRV_THREADS)
				n = MAX_XPOLLTCPSRV_THREADS;
			cTcpSvrWorkThread*	pt;
			for (i = 0; i < n; i++) {
				pt = CreateWorkThread();
				if (pt) {
					pt->Start((int)pos, _wport, _pmem, &_poll, _plog);
					m_pThread[pos] = pt;
					pos++;
				}
			}
			m_uThreads = pos;
			StartThread(nullptr);
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

		inline void close_ucid(uint32_t ucid) // close ucid graceful,send all unsend messages
		{
			tcp_post(ucid, nullptr, 0, 100);
		}

		inline size_t get_idles(int noverseconds, ec::vector<xpoll::t_idle>*pout) {
			return _poll.get_idles(noverseconds, pout);
		}

		void Stop()
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

				StopAndDeleteThreads();
				_fd_listen = INVALID_SOCKET;
			}
		}
		/*!
		\return return send bytes,
		0:memery error;
		-1: no ucid or IO error ,call OnRemovedUCID
		*/
		int	SendToUcid(unsigned int ucid, const void* pbuf, unsigned int usize)
		{
			if (!pbuf || !usize)
				return 0;
			vector<uint8_t> vd(usize + 8 - usize % 8, _pmem);
			if (!vd.add((const uint8_t*)pbuf, usize))
				return -1;
			int nerr = _poll.post_msg(ucid, &vd);
			if (nerr < 0)
				return -1;
			int nt = 100, i = 0; //200 ms timeover			
			while (!nerr && i < nt) {
				std::this_thread::sleep_for(std::chrono::milliseconds(2));
				nerr = _poll.post_msg(ucid, &vd);
				i++;
			}
			return nerr > 0 ? (int)usize : -1;
		};
	};
}// namespace ec


