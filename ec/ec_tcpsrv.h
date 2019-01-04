/*!
\file ec_tcpsrv.h
\author kipway@outlook.com
\update 2019.1.4

eclib tcp server class. easy to use, no thread , lock-free

eclib Copyright (c) 2017-2018, kipway
source repository : https://github.com/kipway/eclib

Licensed under the Apache License, Version 2.0 (the "License");
*/
#pragma once

#include <stdint.h>

#ifdef _WIN32
#	include <windows.h>
#	include <Winsock2.h>
#	include <mstcpip.h>
#	include <ws2tcpip.h>

#	ifndef pollfd
#		define  pollfd WSAPOLLFD
#   endif

#else
#	define USE_AFUNIX 1
#	include <unistd.h>

#	include <sys/time.h>
#	include <sys/types.h>
#	include <sys/socket.h>
#	include <sys/eventfd.h>
#	include <sys/ioctl.h>

#	include <errno.h>
#	include <poll.h>
#	include <fcntl.h>
#endif

#include "c_str.h"
#include "c11_log.h"
#include "c11_netio.h"
#include "c11_map.h"

#define EC_PROTOC_TCP        0x01000  // base TCP    protocol
#define EC_PROTOC_TLS        0x02000  // base TLS12  protocol
#define EC_PROTOC_LISTEN     0x04000  // base listen protocol
#define EC_PROTOC_CONNECTOUT 0x10000  // base connect out flag

#define EC_PROTOC_ST_PRE     0x00
#define EC_PROTOC_ST_CONNECT 0x01
#define EC_PROTOC_ST_WORK    0x02

#ifndef TCP_PKG_MAXSIZE
#	define TCP_PKG_MAXSIZE (1024 * 1024 * 64)
#endif

#ifndef EC_TCP_SEND_BLOCK_OVERSECOND
#	define EC_TCP_SEND_BLOCK_OVERSECOND 10
#endif

namespace ec {

	namespace tcp {
		inline int send_non_block(SOCKET s, const void* pbuf, int nsize)//return send bytes size or -1 for error,use for nonblocking
		{
			int  nret;
#ifdef _WIN32
			nret = ::send(s, (char*)pbuf, nsize, 0);
			if (SOCKET_ERROR == nret)
			{
				int nerr = WSAGetLastError();
				if (WSAEWOULDBLOCK == nerr || WSAENOBUFS == nerr)  // nonblocking  mode
					return 0;
				else
					return SOCKET_ERROR;
			}
			return nret;
#else
			nret = ::send(s, (char*)pbuf, nsize, MSG_DONTWAIT | MSG_NOSIGNAL);
			if (SOCKET_ERROR == nret)
			{
				if (errno == EAGAIN || errno == EWOULDBLOCK) // nonblocking  mode
					return 0;
				else
					return SOCKET_ERROR;
			}
			return nret;
#endif
		};
		class session // base connect session class
		{
		public:
			session(uint32_t ucid, SOCKET  fd, uint32_t protoc, uint32_t status, ec::memory* pmem, ec::cLog* plog) :
				_protoc(protoc), _status(status), _fd(fd), _ucid(ucid), _u32(0), _u64(0), 
				_pssmem(pmem), _psslog(plog), _timesndblcok(0), _sndpos(0), _sbuf(1024 * 16, true, pmem) {
				_ip[0] = 0;
				_cid[0] = 0;
				_timelastio = ::time(0);
			}
			virtual ~session() {
				if (_fd != INVALID_SOCKET)
#ifdef _WIN32
					::closesocket(_fd);
#else
					::close(_fd);
#endif
				_fd = INVALID_SOCKET;
			}
		public:
			uint32_t _protoc;
			int32_t  _status; // D0:connected; D1:logined
			SOCKET   _fd;
			uint32_t _ucid;
			char     _ip[40];
			char     _cid[40];
			uint32_t _u32;
			uint64_t _u64;
			time_t   _timelastio;
			ec::memory* _pssmem;
			ec::cLog*   _psslog;
			time_t   _timesndblcok;//发送阻塞的开始时间
		private:
			size_t _sndpos;
			ec::vector<uint8_t> _sbuf;
		public:

			virtual void setip(const char* sip) {
				ec::str_lcpy(_ip, sip, sizeof(_ip));
			};

			/*!
			return 0: ok ; -1: error need close;
			\param pmsgout , sendto peer if has data
			*/
			virtual int onrecvbytes(const void* pdata, size_t size, ec::vector<uint8_t>* pmsgout) {
				_timelastio = ::time(0);
				return 0;
			}; //read Raw byte stream from tcp

			virtual int send(const void* pdata, size_t size) {				
				return iosend(pdata, (int)size);// timeoutmsec No longer use 
			}

			int iosend(const void* pdata, size_t size) // tcp sens; return -1:error
			{
				int ns = 0;
				_timelastio = ::time(0);
				if (_sbuf.size() > 0) { // has data in buffer
					if (_sndpos > _sbuf.size()) {
						if (_psslog)
							_psslog->add(CLOG_DEFAULT_ERR, "ucid %u buf error _sndpos=%zu, bufsize=%zu", _ucid, _sndpos, _sbuf.size());
						return -1;
					}
					if (_sbuf.size() + size - _sndpos > TCP_PKG_MAXSIZE + 1024) {
						if (_psslog)
							_psslog->add(CLOG_DEFAULT_ERR, "ucid %u buf oversize _sndpos=%zu, bufsize=%zu, addsize=%zu", _ucid, _sndpos, _sbuf.size(), size);
						return -1;
					}
					if (!_sbuf.add((uint8_t*)pdata, size))
						return -1;
					return send_c();
				}
				ns = send_non_block(_fd, pdata, (int)size);
				if (_psslog)
					_psslog->add(CLOG_DEFAULT_DBG, "iosend send_non_block ucid %u send size %d", _ucid, ns);
				if(ns > 0)
					_timesndblcok = 0;
				if (ns == (int)size || ns < 0)					
					return ns;
				_sndpos = 0;
				_sbuf.clear();
				if (!_sbuf.add(((uint8_t*)pdata) + ns, size - ns)) // add data no send to buffer
					return -1;
				if (ns == 0) { // do send overtime
					if (!_timesndblcok)
						_timesndblcok = _timelastio;
					else if (::time(0) - _timesndblcok > EC_TCP_SEND_BLOCK_OVERSECOND) {
						if (_psslog)
							_psslog->add(CLOG_DEFAULT_WRN, "ucid %u send block over %d seconds", _ucid, EC_TCP_SEND_BLOCK_OVERSECOND);
						return -1; //block 15 second
					}
				}
				return ns;
			}

			int send_c() // continue send form buf,return -1 error
			{
				int ns = 0;
				if (!_sbuf.size())
					return 0;
				_timelastio = ::time(0);
				if (_sndpos > _sbuf.size()) {
					if (_psslog)
						_psslog->add(CLOG_DEFAULT_ERR, "buf error ucid %u _sndpos=%zu,bufsize=%zu", _ucid, _sndpos, _sbuf.size());
					return -1;
				}
				ns = send_non_block(_fd, _sbuf.data() + _sndpos, (int)(_sbuf.size() - _sndpos));
				if (ns < 0) {
					if (_psslog)
						_psslog->add(CLOG_DEFAULT_DBG, "ucid %u send_c failed _sndpos=%zu,bufsize=%zu", _ucid, _sndpos, _sbuf.size());
					return -1;
				}
				_sndpos += ns;
				if (_sndpos == _sbuf.size()) {
					_sndpos = 0;
					_sbuf.clear(true);
				}
				if (ns > 0)
					_timesndblcok = 0;
				else if (ns == 0) { // do send overtime
					if (!_timesndblcok)
						_timesndblcok = _timelastio;
					else if (::time(0) - _timesndblcok > EC_TCP_SEND_BLOCK_OVERSECOND) {
						if (_psslog)
							_psslog->add(CLOG_DEFAULT_WRN, "ucid %u send block over %d seconds", _ucid, EC_TCP_SEND_BLOCK_OVERSECOND);
						return -1; //block 15 second
					}
				}
				if (_psslog)
					_psslog->add(CLOG_DEFAULT_DBG, "ucid %u send_c bytes %d, _sndpos=%zu,bufsize=%zu", _ucid, ns, _sndpos, _sbuf.size());
				return ns;
			}

			inline size_t sndbufsize() {
				return _sbuf.size();
			}
		};

		class listen_session : public session
		{
		public:
			listen_session(SOCKET  fd) : session(1, fd, EC_PROTOC_LISTEN, EC_PROTOC_ST_WORK, nullptr, nullptr) {
			}

			virtual int onrecvbytes(const void* pdata, size_t size, ec::vector<uint8_t>* pmsgout) {
				pmsgout->clear();
				return 0;
			}
		};
	}

	typedef tcp::session* psession;

	template<>
	struct key_equal<uint32_t, psession>
	{
		bool operator()(uint32_t key, const psession &val) {
			return key == val->_ucid;
		}
	};

	template<>
	struct del_node<psession>
	{
		void operator()(psession& val) {
			if (val) {
				delete val;
				val = nullptr;
			}
		}
	};

	namespace tcp {
		class server // TCP server 
		{
		public:
			server(ec::cLog* plog, ec::memory* pmem) : _wport(0), _fd_listen(INVALID_SOCKET), _plog(plog), _pmem(pmem),
				_pollfd(128, true, pmem), _pollkey(128, true, pmem),
				_mapmem(map<uint32_t, psession>::size_node(), 8192), _map(2048, &_mapmem),
				_bmodify_pool(false), _nerr_emfile_count(0), _unextid(100) {
			}
			bool open(uint16_t port, const char* sip = nullptr)
			{
				if (INVALID_SOCKET != _fd_listen)
					return true;

				_wport = port;
				_fd_listen = listen_port(_wport, sip);
				if (INVALID_SOCKET == _fd_listen)
					return false;

				listen_session *p = new listen_session(_fd_listen);
				_map.set(1, (psession)p);
				_bmodify_pool = true;
				return true;
			}
			void close() {
				_map.clear();
			}

			int sendbyucid(uint32_t ucid, const void*pmsg, size_t msgsize) {
				int nr = -1;
				psession pi = nullptr;
				if (_map.get(ucid, pi))
					nr = pi->send(pmsg, msgsize);
				if (nr < 0)
					closeucid(ucid);
				return nr;
			}

			void set_status(uint32_t ucid, uint32_t st) {
				psession pi = nullptr;
				if (_map.get(ucid, pi))
					pi->_status |= st;
			}

			uint32_t get_status(uint32_t ucid) {
				psession pi = nullptr;
				if (_map.get(ucid, pi))
					return pi->_status;
				return -1;
			}

			bool closeucid(uint32_t ucid) {
				ondisconnect(ucid);
				_bmodify_pool = true;
				return _map.erase(ucid);
			}
		protected:
			uint16_t _wport;
			SOCKET _fd_listen;
			ec::cLog* _plog;

			ec::memory* _pmem;
			ec::vector<pollfd> _pollfd;
			ec::vector<uint32_t> _pollkey;

		protected:
			ec::memory _mapmem;
			ec::map<uint32_t, psession> _map;
			bool _bmodify_pool;
			int     _nerr_emfile_count;
		protected:
			virtual bool domessage(uint32_t ucid, const uint8_t*pmsg, size_t msgsize) = 0; // return false will disconnect
			virtual void onconnect(uint32_t ucid) = 0;
			virtual void ondisconnect(uint32_t ucid) = 0;
			virtual session* createsession(uint32_t ucid, SOCKET  fd, uint32_t status, ec::memory* pmem, ec::cLog* plog) {
				return new session(ucid, fd, EC_PROTOC_TCP, status, _pmem, _plog);
			}
		public:
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
			void runtime(int waitmicroseconds) {
				int n = 0;
				make_pollfds();
#ifdef _WIN32
				n = WSAPoll(_pollfd.data(), (ULONG)_pollfd.size(), waitmicroseconds);
#else
				n = poll(_pollfd.data(), _pollfd.size(), waitmicroseconds);
#endif
				if (n <= 0)
					return;

				pollfd* p = _pollfd.data();
				uint32_t* puid = _pollkey.data();
				for (auto i = 0u; i < _pollfd.size(); i++) {
					if (puid[i] == 1) { //listen
						if (p[i].revents & POLLIN) {
							if (acp())
								_bmodify_pool = true;
						}
						p[i].revents = 0;
						continue;
					}
					if (p[i].revents & (POLLERR | POLLHUP | POLLNVAL)) { // error
						closeucid(puid[i]);
						if (_plog)
							_plog->add(CLOG_DEFAULT_MSG, "port(%u) ucid %u disconnect", _wport, puid[i]);
						p[i].revents = 0;
						continue;
					}
					psession pi = nullptr;
					if (p[i].revents & POLLOUT) {						
						if (_map.get(puid[i], pi)) {
							pi->_timelastio = ::time(0);
							if ((pi->_protoc & EC_PROTOC_CONNECTOUT) && !pi->_status) { // connect out session
								pi->_status |= EC_PROTOC_ST_CONNECT; //connected
#ifndef _WIN32
								int serr = 0;
								socklen_t serrlen = sizeof(serr);
								getsockopt(pi->_fd, SOL_SOCKET, SO_ERROR, (void *)&serr, &serrlen);
								if (serr) {
									_bmodify_pool = true;
									_map.erase(puid[i]);  // delete first
									ondisconnect(puid[i]);// you can reconnect in ondisconnect				
									continue;
								}
#endif
								onconnect(puid[i]);
								_bmodify_pool = true;
								p[i].events = POLLIN;
							}
							else if (pi->sndbufsize()) {
								if (pi->send_c() < 0) {
									if (pi->_protoc & EC_PROTOC_CONNECTOUT) { // connect out session
										_bmodify_pool = true;
										_map.erase(puid[i]);  // delete first
										ondisconnect(puid[i]);// you can reconnect in ondisconnect	
									}
									else //connect in session
										closeucid(puid[i]);
									if (_plog)
										_plog->add(CLOG_DEFAULT_MSG, "port(%u) ucid %u disconnect error as send_c", _wport, puid[i]);
									continue;
								}
							}
						}
					}
					if (p[i].revents & POLLIN)
						doread(puid[i], p[i].fd);
					p[i].revents = 0;
					psession ps = nullptr;
					if (!_bmodify_pool && _map.get(puid[i], ps) && ps->sndbufsize())
						_bmodify_pool = true;					
				}
			}
		protected:
			virtual void on_emfile() {
			}
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

				int opt = 1;
#ifdef _WIN32
				setsockopt(sl, SOL_SOCKET, SO_REUSEADDR,
					(const char *)&opt, sizeof(opt));
#else
				setsockopt(sl, SOL_SOCKET, SO_REUSEADDR,
					(const void *)&opt, sizeof(opt));
#endif
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
			uint32_t _unextid;
			uint32_t nextid()
			{
				_unextid++;
				if (_unextid < 100)
					_unextid = 100;
				while (_map.get(_unextid)) {
					_unextid++;
					if (_unextid < 100)
						_unextid = 100;
				}
				return _unextid;
			}
		private:
			void make_pollfds()
			{
				if (!_bmodify_pool) // no change
					return;
				_pollfd.clear();
				_pollkey.clear();
				_map.for_each([this](psession & v) {
					pollfd t;
					t.fd = v->_fd;
					if (((EC_PROTOC_CONNECTOUT & v->_protoc) && !v->_status) || v->sndbufsize())
						t.events = POLLOUT;
					else
						t.events = POLLIN;
					t.revents = 0;
					_pollfd.add(t);
					_pollkey.add(v->_ucid);
				});
				_bmodify_pool = false;
			}

			bool acp() {
				SOCKET	sAccept;
				struct  sockaddr_in		 addrClient;
				int		nClientAddrLen = sizeof(addrClient);
#ifdef _WIN32
				if ((sAccept = ::accept(_fd_listen, (struct sockaddr*)(&addrClient), &nClientAddrLen)) == INVALID_SOCKET) {
					int nerr = WSAGetLastError();
					if (WSAEMFILE == nerr) {
						if (!_nerr_emfile_count && _plog)
							_plog->add(CLOG_DEFAULT_ERR, "server port(%d) error EMFILE!", _wport);
						_nerr_emfile_count++;
						on_emfile();
					}
					else
						_nerr_emfile_count = 0;
					return false;
				}
				u_long iMode = 1;
				ioctlsocket(sAccept, FIONBIO, &iMode);
#else
				if ((sAccept = ::accept(_fd_listen, (struct sockaddr*)(&addrClient), (socklen_t*)&nClientAddrLen)) == INVALID_SOCKET) {
					int nerr = errno;
					if (EMFILE == nerr) {
						if (!_nerr_emfile_count && _plog)
							_plog->add(CLOG_DEFAULT_ERR, "server port(%d) error EMFILE!", _wport);
						_nerr_emfile_count++;
						on_emfile();
					}
					else
						_nerr_emfile_count = 0;
					return false;
				}
				if (SetNoBlock(sAccept) < 0) {
					::close(sAccept);
					return false;
				}
#endif
				if (_plog)
					_plog->add(CLOG_DEFAULT_MSG, "port(%u) connect from %s:%u", _wport, inet_ntoa(addrClient.sin_addr), ntohs(addrClient.sin_port));

				ec::netio_tcpnodelay(sAccept);
				ec::netio_setkeepalive(sAccept);

				session* pi = createsession(nextid(), sAccept, EC_PROTOC_ST_CONNECT, _pmem, _plog);
				if (!pi) {
					::closesocket(sAccept);
					return false;
				}
				pi->setip(inet_ntoa(addrClient.sin_addr));
				_map.set(pi->_ucid, pi);
				onconnect(pi->_ucid);
				return true;
			}

			bool doread(uint32_t ucid, SOCKET fd) {
				char rbuf[1024 * 32];
#ifdef _WIN32
				int nr = ::recv(fd, rbuf, (int)sizeof(rbuf), 0);
#else
				int nr = ::recv(fd, rbuf, (int)sizeof(rbuf), MSG_DONTWAIT);
#endif
				if (nr == 0) { //close gracefully
					closeucid(ucid);
					if (_plog)
						_plog->add(CLOG_DEFAULT_MSG, "port(%u) ucid %u disconnect gracefully", _wport, ucid);
					return true;
				}
				else if (nr < 0) {
#ifdef _WIN32
					int nerr = (int)WSAGetLastError();
					if (WSAEWOULDBLOCK == nerr)
						return false;
#else
					int nerr = errno;
					if (nerr == EAGAIN || nerr == EWOULDBLOCK)
						return false;
#endif
					closeucid(ucid);
					if (_plog)
						_plog->add(CLOG_DEFAULT_MSG, "port(%u) ucid %u disconnect error %d", _wport, ucid, nerr);
					return true;
				}

				psession pi = nullptr;
				if (_map.get(ucid, pi)) {
					pi->_timelastio = ::time(0);
					ec::vector<uint8_t> msgr(1024 * 32, true, _pmem);
					int ndo = pi->onrecvbytes((const uint8_t*)rbuf, nr, &msgr);
					while (ndo != -1 && msgr.size()) {
						if (!domessage(ucid, msgr.data(), msgr.size())) {
							ndo = -1;
							break;
						}
						ndo = pi->onrecvbytes(nullptr, 0, &msgr);
					}
					if (-1 == ndo) {
						closeucid(ucid);
						if (_plog)
							_plog->add(CLOG_DEFAULT_MSG, "port(%u) ucid %u disconnected by the server", _wport, ucid);
						return true;
					}
				}
				return false;
			}
		};
	}// tcp
}// ec
