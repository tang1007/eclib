/*!
\file ec_ipc.h
\author kipway@outlook.com
\update 2018.12.20

eclib IPC class easy to use, no thread , lock-free

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
#	include <sys/un.h>

#	include <errno.h>
#	include <poll.h>
#	include <fcntl.h>
#endif


#include "c_str.h"
#include "c11_vector.h"
#include "c_stream.h"
#include "c11_netio.h"
#include "c11_log.h"
#include "c11_map.h"

#ifndef IPCMSG_MAXSIZE
#define IPCMSG_MAXSIZE  (1024 * 1024 * 30)
#endif

#define ECIPC_ST_SEND_ERR		(-1)
#define ECIPC_ST_SEND_NOTLOGIN  (-2)
#define ECIPC_ST_SEND_PKGERR    (-3)

#define ECIPCPKG_ST_ERR (-1)
#define ECIPCPKG_ST_WAIT 0
#define ECIPCPKG_ST_OK   1

namespace ec {
	class ez_ipcpkg // IPC package
	{
	public:
		struct t_head {
			uint8_t  sync;
			uint8_t  flag;
			uint32_t msglen;
		};

	public:
		/*!
		\brief send no copy ,6 bytes blank in front of the pmsg
		*/
		static int sendnocpy(SOCKET sock, void *ppkg, size_t sizepkg, int timeoutms = 200)
		{
			if (sizepkg > IPCMSG_MAXSIZE || sizepkg <= 6)
				return ECIPC_ST_SEND_PKGERR;
			cStream ss(ppkg, 6);
			try {
				ss < (uint8_t)0xF5 < (uint8_t)0x10 < (uint32_t)(sizepkg - 6);
			}
			catch (int) {
				return -1;
			}
			return netio_tcpsend(sock, ppkg, (int)sizepkg, timeoutms);
		}

		static bool make(void *ppkg, size_t sizepkg) {
			if (sizepkg > IPCMSG_MAXSIZE || sizepkg <= 6)
				return false;
			cStream ss(ppkg, 6);
			try {
				ss < (uint8_t)0xF5 < (uint8_t)0x10 < (uint32_t)(sizepkg - 6);
			}
			catch (int) {
				return false;
			}
			return true;
		}

	public:
		static int parse(ec::vector<uint8_t>* pin, const uint8_t* pdata, size_t usize, ec::vector<uint8_t> *pout) {
			if (pdata && usize)
				pin->add(pdata, usize);
			return parsepkg(pin, pout);
		}

	protected:
		static int parsepkg(ec::vector<uint8_t>* pin, ec::vector<uint8_t> *pout)//return 0:wait; -1:err; 1:OK; msg include head 6 bytes for No copy forwarding
		{
			uint8_t* pu = pin->data();
			if (pin->size() < 6)
				return ECIPCPKG_ST_WAIT;
			ec::cStream ss((void*)pu, pin->size());
			t_head h;
			try {
				ss > h.sync > h.flag > h.msglen;
			}
			catch (int) {
			}
			if (h.sync != 0xF5 || h.flag != 0x10 || h.msglen > IPCMSG_MAXSIZE)
				return ECIPCPKG_ST_ERR;
			if (h.msglen + 6 > pin->size())
				return ECIPCPKG_ST_WAIT;
			pout->clear();
			pout->add(pu, h.msglen + 6); //include head 6 bytes
			pin->erase(0, h.msglen + 6);
			pin->shrink(1024 * 32);
			return ECIPCPKG_ST_OK;
		}
	};

	class ipc_seesion_c
	{
	public:
		ipc_seesion_c(uint32_t ucid, SOCKET fd, memory* pmem) : _ucid(ucid), _ust(1), _fd(fd), _rbuf(1024 * 8, true, pmem),
			_ti_connect(::time(0)), _ti_lastcom(0), _u64(0), _n1(0), _n2(0), _ptr(nullptr) {
			_sda[0] = 0;
		}
		ipc_seesion_c() : _ucid(0), _ust(0), _fd(-1), _rbuf(1024 * 8, true),
			_ti_connect(0), _ti_lastcom(0), _u64(0), _n1(0), _n2(0), _ptr(nullptr) {
			_sda[0] = 0;
		}

		ipc_seesion_c(ipc_seesion_c&& v) :_rbuf(1024 * 8, true) {
			_ucid = v._ucid;
			_ust = v._ust;
			_fd = v._fd;
			_rbuf = std::move(v._rbuf);
			_ti_connect = v._ti_connect;
			_ti_lastcom = v._ti_lastcom;
			_u64 = v._u64;
			_n1 = v._n1;
			_n2 = v._n2;
			_ptr = v._ptr;
			memcpy(_sda, v._sda, sizeof(_sda));
		}

		ipc_seesion_c& operator = (ipc_seesion_c&& v)
		{
			this->~ipc_seesion_c();
			_ucid = v._ucid;
			_ust = v._ust;
			_fd = v._fd;
			_rbuf = std::move(v._rbuf);
			_ti_connect = v._ti_connect;
			_ti_lastcom = v._ti_lastcom;
			_u64 = v._u64;
			_n1 = v._n1;
			_n2 = v._n2;
			_ptr = v._ptr;
			memcpy(_sda, v._sda, sizeof(_sda));
			return *this;
		}

		uint32_t   _ucid;
		uint32_t   _ust;  //D0:connected; D1:logined  ;D2-D7 RES; D8 - D31: for user
		SOCKET     _fd;
		ec::vector<uint8_t> _rbuf;
		time_t     _ti_connect; //连接时间
		time_t     _ti_lastcom; //上次读写时间
		uint64_t   _u64; //res
		int32_t	   _n1;  //res
		int32_t    _n2;  //res
		void*      _ptr; //res
		char       _sda[40]; //res for app
	};

	template<>
	struct key_equal<uint32_t, ipc_seesion_c>
	{
		bool operator()(uint32_t key, const ipc_seesion_c& val) {
			return key == val._ucid;
		}
	};

	template<>
	struct del_node<ipc_seesion_c>
	{
		void operator()(ipc_seesion_c& val) {
			val._rbuf.~vector();
			if (val._fd != INVALID_SOCKET) {
#ifdef _WIN32
				shutdown(val._fd, SD_BOTH);
				closesocket(val._fd);
#else
				shutdown(val._fd, SHUT_WR);
				close(val._fd);
#endif
				val._fd = INVALID_SOCKET;
			}
		}
	};

	class ez_ipcsrv
	{
	public:
		ez_ipcsrv(cLog* plog, memory* pmem) :
			_wport(0), _sock(INVALID_SOCKET), _plog(plog), _pmem(pmem), _mapmem(map< uint32_t, ipc_seesion_c>::size_node(), 128),
			_map(128, &_mapmem), _pollfd(128, true, pmem), _pollkey(128, true, pmem), _rmsg(1024 * 32, true, pmem),
			_bmodify_pool(false), _nerr_emfile_count(0), _unextid(100) {
		}
	protected:
		uint16_t _wport;
		SOCKET _sock;
		cLog* _plog;
		memory* _pmem;
		memory _mapmem;
		map< uint32_t, ipc_seesion_c> _map;
		vector<pollfd> _pollfd;
		vector<uint32_t> _pollkey;
		vector<uint8_t> _rmsg;
		bool _bmodify_pool;
		int  _nerr_emfile_count;
	protected:
		virtual bool domessage(uint32_t ucid, const uint8_t*pmsg, size_t msgsize) = 0;
		virtual void onconnect(uint32_t ucid) = 0;
		virtual void ondisconnect(uint32_t ucid) = 0;

		virtual int  pkgparse(ipc_seesion_c* pi, ec::vector<uint8_t>* pin, const uint8_t* pdata, size_t usize, ec::vector<uint8_t> *pout) {
			return ez_ipcpkg::parse(pin, pdata, usize, pout);
		}
		virtual void on_emfile() {
		}
	public:
		void disconnect(uint32_t ucid, bool blogout = true) {
			if (ucid < 100)
				return;
			if (_map.get(ucid)) {
				ondisconnect(ucid);
				if (blogout && _plog)
					_plog->add(CLOG_DEFAULT_MSG, "ipc port(%u) ucid %u disconnect by server", _wport, ucid);
				_map.erase(ucid);
				_bmodify_pool = true;
			}
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
		bool open(uint16_t wport, const char* skeywords = "ezipc", const char* slocalip = "127.0.0.171") {  // c11_ipc.h "ECIPC", "127.0.0.191"
			if (_sock != INVALID_SOCKET)
				return true;
			_wport = wport;
			if (!_wport)
				return false;
#ifdef USE_AFUNIX
			if ((_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == INVALID_SOCKET)
				return false;

			struct sockaddr_un Addr;
			memset(&Addr, 0, sizeof(Addr));
			Addr.sun_family = AF_UNIX;
			snprintf(Addr.sun_path, sizeof(Addr.sun_path), "/var/tmp/%s:%d", skeywords, _wport);
			unlink(Addr.sun_path);
#else
			if ((_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
				return false;
			struct sockaddr_in	Addr;
			memset(&Addr, 0, sizeof(Addr));
			Addr.sin_family = AF_INET;
			Addr.sin_addr.s_addr = inet_addr(slocalip);
			Addr.sin_port = htons(_wport);
#endif

			if (bind(_sock, (const sockaddr *)&Addr, sizeof(Addr)) == SOCKET_ERROR) {
#ifdef _WIN32
				shutdown(_sock, SD_BOTH);
				closesocket(_sock);
#else
				shutdown(_sock, SHUT_WR);
				::close(_sock);
#endif
				_sock = INVALID_SOCKET;
				return false;
			}
			if (listen(_sock, 2) == SOCKET_ERROR) {
#ifdef _WIN32
				shutdown(_sock, SD_BOTH);
				closesocket(_sock);
#else
				shutdown(_sock, SHUT_WR);
				::close(_sock);
#endif
				_sock = INVALID_SOCKET;
				return false;
			}

			_map.set(1, ipc_seesion_c(1, _sock, _pmem));
			_bmodify_pool = true;
			return true;
		}

		void close() {
			_map.for_each([&](ipc_seesion_c &v) {
				ondisconnect(v._ucid);
			});
			_map.clear();
			_sock = INVALID_SOCKET;
		}

		int sendnocpybyucid(uint32_t ucid, void *pmsg, size_t msgsize) {
			if (ucid < 100)
				return 0;
			ipc_seesion_c* p = _map.get(ucid);
			if (!p)
				return -1;
			int nr = ez_ipcpkg::sendnocpy(p->_fd, pmsg, msgsize);
			if (nr < 0) {
				_bmodify_pool = true;
				ondisconnect(ucid);
				_map.erase(ucid);
				if (_plog)
					_plog->add(CLOG_DEFAULT_MSG, "ipc port(%u) ucid %u disconnect as send failed", _wport, ucid);
			}
			return nr;
		}

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
				else {
					if (p[i].revents & (POLLERR | POLLHUP | POLLNVAL)) { // error
						_bmodify_pool = true;
						ondisconnect(puid[i]);
						_map.erase(puid[i]);
						if (_plog)
							_plog->add(CLOG_DEFAULT_MSG, "ipc port(%u) ucid %u disconnect", _wport, puid[i]);
					}
					else if (p[i].revents & POLLIN)
						doread(puid[i], p[i].fd);
				}
				p[i].events = POLLIN;
				p[i].revents = 0;
			}
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
			_map.for_each([this](ipc_seesion_c & v) {
				pollfd t;
				t.fd = v._fd;
				t.events = POLLIN;
				t.revents = 0;
				_pollfd.add(t);
				_pollkey.add(v._ucid);
			});
			_bmodify_pool = false;
		}

		bool acp() {
			SOCKET	sAccept;
#ifdef USE_AFUNIX
			struct  sockaddr_un		 addrClient;
#else
			struct  sockaddr_in		 addrClient;
#endif
			int		nClientAddrLen = sizeof(addrClient);
#ifdef _WIN32
			if ((sAccept = ::accept(_sock, (struct sockaddr*)(&addrClient), &nClientAddrLen)) == INVALID_SOCKET) {
				int nerr = WSAGetLastError();
				if (WSAEMFILE == nerr) {
					if (!_nerr_emfile_count && _plog)
						_plog->add(CLOG_DEFAULT_ERR, "ipc server port(%d) error EMFILE!", _wport);
					_nerr_emfile_count++;
					on_emfile();
				}
				else
					_nerr_emfile_count = 0;
				return false;
			}
			u_long iMode = 1;
			ioctlsocket(sAccept, FIONBIO, &iMode);
			if (_plog)
				_plog->add(CLOG_DEFAULT_MSG, "ipc port(%u) connect from %s:%u", _wport, inet_ntoa(addrClient.sin_addr), ntohs(addrClient.sin_port));
#else
			if ((sAccept = ::accept(_sock, (struct sockaddr*)(&addrClient), (socklen_t*)&nClientAddrLen)) == INVALID_SOCKET) {
				int nerr = errno;
				if (EMFILE == nerr) {
					if (!_nerr_emfile_count && _plog)
						_plog->add(CLOG_DEFAULT_ERR, "ipc server port(%d) error EMFILE!", _wport);
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
			if (_plog)
				_plog->add(CLOG_DEFAULT_MSG, "ipc port(%u) connect from local", _wport);
#endif

			ec::netio_tcpnodelay(sAccept);
			ec::netio_setkeepalive(sAccept);

			uint32_t ucid = nextid();
			_map.set(ucid, ipc_seesion_c(ucid, sAccept, _pmem));
			onconnect(ucid);
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
					_plog->add(CLOG_DEFAULT_MSG, "ipc port(%u) ucid %u disconnect gracefully", _wport, ucid);
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
					_plog->add(CLOG_DEFAULT_MSG, "ipc port(%u) ucid %u disconnect error %d", _wport, ucid, nerr);
				return true;
			}
			ipc_seesion_c* pi = _map.get(ucid);
			if (pi) {
				int ndo = pkgparse(pi, &pi->_rbuf, (const uint8_t*)rbuf, nr, &_rmsg);
				while (ndo > 0) {
					if (!domessage(ucid, _rmsg.data(), _rmsg.size())) {
						ndo = -1;
						break;
					}
					ndo = ez_ipcpkg::parse(&pi->_rbuf, nullptr, 0, &_rmsg);
				}
				if (ndo < 0) {
					_bmodify_pool = true;
					ondisconnect(ucid);
					_map.erase(ucid);
					if (_plog)
						_plog->add(CLOG_DEFAULT_MSG, "ipc port(%u) ucid %u disconnect error package", _wport, ucid);
					return true;
				}
			}
			return false;
		}
	};

	class ez_ipccli
	{
	public:
		ez_ipccli(cLog* plog, memory* pmem) : _wport(0), _plog(plog), _pmem(pmem), _rbuf(1024 * 32, true, pmem), _rmsg(1024 * 32, true, pmem), _nst(0) {
			_pollfd.events = 0;
			_pollfd.revents = 0;
			_pollfd.fd = INVALID_SOCKET;
			_timeconnect = 0;
		}
	protected:
		uint16_t _wport;
		cLog*    _plog;
		memory*  _pmem;
		vector<uint8_t> _rbuf;
		vector<uint8_t> _rmsg;
		int    _nst;
		pollfd _pollfd;
	private:
		time_t _timeconnect;
	protected:
		virtual void ondisconnect() = 0;
		virtual void onconnect() = 0;
		virtual void onmessage(const uint8_t *pmsg, size_t sizemsg) = 0; // pmsg include head 6bytes
	public:
		bool connectasyn(uint16_t wport) {
			if (_pollfd.fd != INVALID_SOCKET)
				return true;
			_wport = wport;
			if (!_wport)
				return false;

#ifdef USE_AFUNIX
			struct sockaddr_un srvaddr;
			memset(&srvaddr, 0, sizeof(srvaddr));
			srvaddr.sun_family = AF_UNIX;
			snprintf(srvaddr.sun_path, sizeof(srvaddr.sun_path), "/var/tmp/ezipc:%d", wport);
			SOCKET s = socket(AF_UNIX, SOCK_STREAM, 0);
#else
			struct sockaddr_in srvaddr;
			memset(&srvaddr, 0, sizeof(srvaddr));
			srvaddr.sin_family = AF_INET;
			srvaddr.sin_port = htons(_wport);
			srvaddr.sin_addr.s_addr = inet_addr("127.0.0.171");
			SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#endif
			if (s == INVALID_SOCKET)
				return false;

			long ul = 1;
#ifdef _WIN32
			if (SOCKET_ERROR == ioctlsocket(s, FIONBIO, (unsigned long*)&ul)) {
				closesocket(s);
				return false;
			}
#else
			if (ioctl(s, FIONBIO, &ul) == -1) {
				closesocket(s);
				return INVALID_SOCKET;
			}
#endif
			if (connect(s, (sockaddr *)(&srvaddr), sizeof(srvaddr)) < 0) {
#ifdef _WIN32
				if (WSAEWOULDBLOCK != WSAGetLastError()) {
					closesocket(s);
					return false;
				}
#else
				if (EINPROGRESS != errno) {
					closesocket(s);
					return false;
				}
#endif
			}
			_pollfd.fd = s;
			_pollfd.events = POLLOUT;
			_nst = 0;
			_timeconnect = ::time(0);
			_rbuf.clear();

			return true;
		}

#		define EZIPCCLICLOSE()\
		{\
			closesocket(_pollfd.fd);\
			_pollfd.fd = INVALID_SOCKET;\
			_pollfd.events = 0;\
			_pollfd.revents = 0;\
			_nst = 0;\
			ondisconnect();\
			return;\
		}\

		void runtime(int waitmicroseconds) {
			if (INVALID_SOCKET == _pollfd.fd)
				return;
			if (!_nst) {
				time_t tcur = ::time(0);
				if (tcur - _timeconnect > 5) {
					EZIPCCLICLOSE()
				}
			}
#ifdef _WIN32
			int n = WSAPoll(&_pollfd, 1, waitmicroseconds);
#else
			int n = poll(&_pollfd, 1, waitmicroseconds);
#endif
			if (n <= 0)
				return;
			if (_pollfd.revents & (POLLERR | POLLHUP | POLLNVAL))
				EZIPCCLICLOSE()

			else if (_pollfd.revents & POLLOUT) {
				if (!_nst) {
					_nst = 1;
#ifndef _WIN32
					int serr = 0;
					socklen_t serrlen = sizeof(serr);
					getsockopt(_pollfd.fd, SOL_SOCKET, SO_ERROR, (void *)&serr, &serrlen);
					if (serr)
						EZIPCCLICLOSE()
#endif
					onconnect();
				}
			}
			else if (_pollfd.revents & POLLIN) {
				char rbuf[1024 * 32];
#ifdef _WIN32
				int nr = ::recv(_pollfd.fd, rbuf, (int)sizeof(rbuf), 0);
#else
				int nr = ::recv(_pollfd.fd, rbuf, (int)sizeof(rbuf), MSG_DONTWAIT);
#endif
				if (nr == 0)   //close gracefully
					EZIPCCLICLOSE()
				else if (nr < 0) {
#ifdef _WIN32
					int nerr = (int)WSAGetLastError();
					if (WSAEWOULDBLOCK == nerr)
						return;
#else
					int nerr = errno;
					if (nerr == EAGAIN || nerr == EWOULDBLOCK)
						return;
#endif
					EZIPCCLICLOSE()
				}

				int ndo = ez_ipcpkg::parse(&_rbuf, (const uint8_t*)rbuf, nr, &_rmsg);
				while (ndo > 0) {
					onmessage(_rmsg.data(), _rmsg.size());
					ndo = ez_ipcpkg::parse(&_rbuf, nullptr, 0, &_rmsg);
				}
				if (ndo < 0)
					EZIPCCLICLOSE()
			}
			if (_nst)
				_pollfd.events = POLLIN;
			else
				_pollfd.events = POLLOUT;
		}

		void disconnect() {
			if (INVALID_SOCKET != _pollfd.fd)
				EZIPCCLICLOSE()
		}

		int sendnocpy(void *pmsg, size_t msgsize) {
			if (INVALID_SOCKET == _pollfd.fd || !_nst)
				return 0;
			int nr = ez_ipcpkg::sendnocpy(_pollfd.fd, pmsg, msgsize);
			if (nr < 0) {
				if (_plog)
					_plog->add(CLOG_DEFAULT_MSG, "ipc disconnect as send to server(%u) failed", _wport);
				closesocket(_pollfd.fd);
				_pollfd.fd = INVALID_SOCKET;
				_pollfd.events = 0;
				_pollfd.revents = 0;
				_nst = 0;
				ondisconnect();
				return -1;
			}
			return nr;
		}
	};
}
