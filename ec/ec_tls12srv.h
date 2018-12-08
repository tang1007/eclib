/*!
\file ec_tls12srv.h
\author kipway@outlook.com
\update 2018.12.2

eclib TLS1.2 server class. easy to use, no thread , lock-free

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

#else _WIN32
#	define USE_AFUNIX 1
#	include <unistd.h>

#	include <sys/time.h>
#	include <sys/types.h>
#	include <sys/socket.h>
#	include <sys/eventfd.h>
#	include <sys/ioctl.h>
#	include <sys/un.h>

#	include <errno.h>
#	include <poll.h>
#	include <fcntl.h>
#endif
#include "ec/c11_netio.h"

#include "ec/c11_map.h"
#include "ec/c11_tls12.h"

#define EZ_PROTOC_BASETCP    0x01000  // base TCP    protocol
#define EZ_PROTOC_BASETLS12  0x02000  // base TLS12  protocol
#define EZ_PROTOC_BASELISTEN 0x04000  // base listen protocol
#define EZ_PROTOC_CONNECTOUT 0x10000  // base connect out flag


#define EZ_PROTOC_ST_PRE     0x00
#define EZ_PROTOC_ST_CONNECT 0x01
#define EZ_PROTOC_ST_WORK    0x02

namespace ec {

	namespace tls12 {
		/*!
		\brief base session class
		*/
		class base_session {
		public:
			base_session(SOCKET  fd, uint32_t protoc, uint32_t status = EZ_PROTOC_ST_PRE) : _fd(fd), _protoc(protoc), _status(status) {
			}
		public:
			uint32_t _protoc;
			int32_t  _status; // D0:connected; D1:logined
			SOCKET   _fd;
		public:
			virtual uint32_t ucid() = 0;
			virtual void setip(const char* sip) {};
			/*!
			return 0: ok ; -1: error need close;
			\param pmsgout , sendto peer if has data
			*/
			virtual int onrecvbytes(const void* pdata, size_t size, ec::vector<uint8_t>* pmsgout) = 0; //read Raw byte stream from tcp
			virtual int send(const void* pdata, size_t size, int timeoutmsec = 1000) {
				return ec::netio_tcpsend(_fd, pdata, (int)size, timeoutmsec);
			}
		};

		class tls12_listen : public base_session
		{
		public:
			tls12_listen(SOCKET  fd) : base_session(fd, EZ_PROTOC_BASELISTEN, EZ_PROTOC_ST_WORK) {
			}

			virtual uint32_t ucid() {
				return 1u;
			};

			virtual int onrecvbytes(const void* pdata, size_t size, ec::vector<uint8_t>* pmsgout) {
				return 0;
			}
		};

		/*!
		\brief tls12 session
		*/
		class tls12_session : public base_session, public ec::tls_session_srv {
		public:
			tls12_session(SOCKET  fd, uint32_t ucid, const void* pcer, size_t cerlen,
				const void* pcerroot, size_t cerrootlen, std::mutex *pRsaLck, RSA* pRsaPrivate, ec::memory* pmem, ec::cLog* plog, uint32_t protoc = EZ_PROTOC_BASETLS12) :
				base_session(fd, protoc, EZ_PROTOC_ST_CONNECT),
				ec::tls_session_srv(ucid, pcer, cerlen, pcerroot, cerrootlen, pRsaLck, pRsaPrivate, pmem, plog)
			{
			}

		public:
			virtual uint32_t ucid() {
				return _ucid;
			}
			virtual void setip(const char* sip) {
				SetIP(sip);
			};
			virtual int onrecvbytes(const void* pdata, size_t size, ec::vector<uint8_t>* pmsgout) //read Raw byte stream from tcp
			{
				int nr = -1;
				pmsgout->clear();
				int nst = OnTcpRead(pdata, size, pmsgout);
				if (TLS_SESSION_ERR == nst || TLS_SESSION_OK == nst || TLS_SESSION_NONE == nst) {
					nr = TLS_SESSION_ERR == nst ? -1 : 0;
					if (pmsgout->size()) {
						if (ec::netio_tcpsend(_fd, pmsgout->data(), (int)pmsgout->size(), 1000) < 0)
							nr = -1;
					}
					pmsgout->clear();
					return nr;
				}
				else if (TLS_SESSION_HKOK == nst) {
					nr = 0;
					if (pmsgout->size()) {
						if (ec::netio_tcpsend(_fd, pmsgout->data(), (int)pmsgout->size(), 1000) < 0)
							nr = -1;
					}
					pmsgout->clear();
					_status |= EZ_PROTOC_ST_WORK;
					return nr;
				}
				else if (TLS_SESSION_APPDATA == nst)
					nr = 0;
				return nr;
			}

			virtual int send(const void* pdata, size_t size, int timeoutmsec = 1000) {
				ec::vector<uint8_t> tlspkg(size + 1024 - size % 1024, _pmem);
				if (MakeAppRecord(&tlspkg, pdata, size))
					return ec::netio_tcpsend(_fd, tlspkg.data(), (int)tlspkg.size(), timeoutmsec);
				return -1;
			}
		};
	}

	typedef tls12::base_session* ptrbasession;

	template<>
	struct key_equal<uint32_t, ptrbasession>
	{
		bool operator()(uint32_t key, const ptrbasession &val) {
			return key == val->ucid();
		}
	};

	template<>
	struct del_node<ptrbasession>
	{
		void operator()(ptrbasession& val) {
			if (val) {
				delete val;
				val = nullptr;
			}
		}
	};

	namespace tls12 {
		/*!
		\brief TLS1.2 server runtime class no thread,no lock
		*/
		class server
		{
		public:
			server(ec::cLog* plog, ec::memory* pmem) : _wport(0), _fd_listen(INVALID_SOCKET), _plog(plog), _pmem(pmem),
				_pollfd(128, true, pmem), _pollkey(128, true, pmem),
				_mapmem(map<uint32_t, ptrbasession>::size_node(), 8192), _map(2048, &_mapmem),
				_bmodify_pool(false), _unextid(100) {
			}
			bool open(const char* filecert, const char* filerootcert, const char* fileprivatekey, uint16_t port, const char* sip = nullptr)
			{
				if (INVALID_SOCKET != _fd_listen)
					return true;

				_wport = port;
				if (_ca._px509)
					_ca.~tls_srvca();

				if (!_ca._px509 && !_ca.InitCert(filecert, filerootcert, fileprivatekey)) {
					if (_plog)
						_plog->add(CLOG_DEFAULT_ERR, "Load certificate failed! port(%u)", port);
					return false;
				}

				_fd_listen = listen_port(_wport, sip);
				if (INVALID_SOCKET == _fd_listen)
					return false;

				tls12_listen *p = new tls12_listen(_fd_listen);
				_map.set(1, (ptrbasession)p);
				_bmodify_pool = true;
				return true;
			}
			void close() {
				_map.clear();
			}

			int sendbyucid(uint32_t ucid, const uint8_t*pmsg, size_t msgsize) {
				int nr = -1;
				ptrbasession pi = nullptr;
				if (_map.get(ucid, pi))
					nr = pi->send(pmsg, msgsize);
				if (nr < 0) {
					_map.erase(ucid);
					ondisconnect(ucid);
				}
				return nr;
			}
			
			void set_status(uint32_t ucid, uint32_t st) {
				ptrbasession pi = nullptr;
				if (_map.get(ucid, pi))
					pi->_status |= st;
			}
			
			uint32_t get_status(uint32_t ucid) {
				ptrbasession pi = nullptr;
				if (_map.get(ucid, pi))
					return pi->_status;
				return -1;
			}

			void closeucid(uint32_t ucid) {
				ondisconnect(ucid);
				_map.erase(ucid);
			}
		protected:
			uint16_t _wport;
			SOCKET _fd_listen;
			ec::cLog* _plog;
			tls_srvca _ca;  // certificate

			ec::memory* _pmem;
			ec::vector<pollfd> _pollfd;
			ec::vector<uint32_t> _pollkey;

		protected:
			ec::memory _mapmem;
			ec::map<uint32_t, ptrbasession> _map;
			bool _bmodify_pool;
		protected:
			virtual bool domessage(uint32_t ucid, const uint8_t*pmsg, size_t msgsize) = 0; // return false will disconnect
			virtual void onconnect(uint32_t ucid) = 0;
			virtual void ondisconnect(uint32_t ucid) = 0;
			virtual base_session* createsession(SOCKET  fd, uint32_t ucid, const void* pcer, size_t cerlen,
				const void* pcerroot, size_t cerrootlen, std::mutex *pRsaLck, RSA* pRsaPrivate, ec::memory* pmem, ec::cLog* plog) {
				return new tls12_session(fd, nextid(), _ca._pcer.data(), _ca._pcer.size(),
					_ca._prootcer.data(), _ca._prootcer.size(), &_ca._csRsa, _ca._pRsaPrivate, _pmem, _plog);
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
					}
					else if (puid[i] < 100) {
						ptrbasession pi = nullptr;
						if ((p[i].revents & POLLOUT) && _map.get(puid[i], pi)) {
							if ((pi->_protoc & EZ_PROTOC_CONNECTOUT) && !pi->_status) {
								pi->_status |= EZ_PROTOC_ST_CONNECT; //connected
#ifndef _WIN32
								int serr = 0;
								socklen_t serrlen = sizeof(serr);
								getsockopt(pi->_fd, SOL_SOCKET, SO_ERROR, (void *)&serr, &serrlen);
								if (serr) {
									_map.erase(puid[i]);
									ondisconnect(puid[i]);
									return;
								}
#endif
								onconnect(puid[i]);
								_bmodify_pool = true;
								p[i].events = POLLIN;
							}
						}
						else if (p[i].revents & POLLIN)
							doread(puid[i], p[i].fd);
					}
					else {
						if (p[i].revents & (POLLERR | POLLHUP | POLLNVAL)) { // error
							_bmodify_pool = true;
							ondisconnect(puid[i]);
							_map.erase(puid[i]);
							if (_plog)
								_plog->add(CLOG_DEFAULT_MSG, "port(%u) ucid %u disconnect", _wport, puid[i]);
						}
						else if (p[i].revents & POLLIN)
							doread(puid[i], p[i].fd);
					}
					p[i].revents = 0;
				}
			}
		protected:
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
		private:
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

			void make_pollfds()
			{
				if (!_bmodify_pool) // no change
					return;
				_pollfd.clear();
				_pollkey.clear();
				_map.for_each([this](ptrbasession & v) {
					pollfd t;
					t.fd = v->_fd;
					if ((EZ_PROTOC_CONNECTOUT & v->_protoc) && !v->_status)
						t.events = POLLOUT;
					else
						t.events = POLLIN;
					t.revents = 0;
					_pollfd.add(t);
					_pollkey.add(v->ucid());
				});
				_bmodify_pool = false;
			}

			bool acp() {
				SOCKET	sAccept;
				struct  sockaddr_in		 addrClient;
				int		nClientAddrLen = sizeof(addrClient);
#ifdef _WIN32
				if ((sAccept = ::accept(_fd_listen, (struct sockaddr*)(&addrClient), &nClientAddrLen)) == INVALID_SOCKET)
					return false;
				u_long iMode = 1;
				ioctlsocket(sAccept, FIONBIO, &iMode);
#else
				if ((sAccept = ::accept(_fd_listen, (struct sockaddr*)(&addrClient), (socklen_t*)&nClientAddrLen)) == INVALID_SOCKET)
					return false;
				if (SetNoBlock(sAccept) < 0) {
					::close(sAccept);
					return false;
				}
#endif
				if (_plog)
					_plog->add(CLOG_DEFAULT_MSG, "port(%u) connect from %s:%u", _wport, inet_ntoa(addrClient.sin_addr), ntohs(addrClient.sin_port));

				ec::netio_tcpnodelay(sAccept);
				ec::netio_setkeepalive(sAccept);

				base_session* pi = createsession(sAccept, nextid(), _ca._pcer.data(), _ca._pcer.size(),
					_ca._prootcer.data(), _ca._prootcer.size(), &_ca._csRsa, _ca._pRsaPrivate, _pmem, _plog);
				if (!pi) {
					::closesocket(sAccept);
					return false;
				}
				pi->setip(inet_ntoa(addrClient.sin_addr));
				_map.set(pi->ucid(), (ptrbasession)pi);
				onconnect(pi->ucid());
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
					_bmodify_pool = true;
					ondisconnect(ucid);
					_map.erase(ucid);
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
					_bmodify_pool = true;
					ondisconnect(ucid);
					_map.erase(ucid);
					if (_plog)
						_plog->add(CLOG_DEFAULT_MSG, "port(%u) ucid %u disconnect error %d", _wport, ucid, nerr);
					return true;
				}

				ptrbasession pi = nullptr;
				if (_map.get(ucid, pi)) {
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
						_bmodify_pool = true;
						ondisconnect(ucid);
						_map.erase(ucid);
						if (_plog)
							_plog->add(CLOG_DEFAULT_MSG, "port(%u) ucid %u disconnect error package", _wport, ucid);
						return true;
					}
				}
				return false;
			}
		};
	}// tls12
}// ec
