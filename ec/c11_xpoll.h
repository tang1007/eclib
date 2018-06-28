/*!
\file c11_xpoll.h
\author	jiangyong
\email  kipway@outlook.com
\update 2018.5.28

eclibe xpoll for windows & linux, send data with zero copy

class udpevt
class xpoll

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

#include "c_str.h"
#include "c11_thread.h"
#include "c11_memory.h"
#include "c11_map.h"
#include "c11_fifo.h"
#include "c11_vector.h"

#ifdef _WIN32
#	include <windows.h>
#	include <Winsock2.h>
#	include <mstcpip.h>
#	include <ws2tcpip.h>
#	define  pollfd WSAPOLLFD
#else
#	include <sys/socket.h>
#	include <sys/ioctl.h>
#	include <sys/select.h>
#	include <netinet/tcp.h>
#	include <arpa/inet.h>
#	include <string.h>
#	include <errno.h>
#	include <poll.h>
#endif

#ifndef XPOLL_SEND_PKG_NUM
#	define XPOLL_SEND_PKG_NUM   6  // max none send pkg per connect
#endif

#define XPOLL_EVT_ST_OK		 0
#define XPOLL_EVT_ST_ERR	 1
#define XPOLL_EVT_ST_CONNECT 2
#define XPOLL_EVT_ST_CLOSE	 3

#define XPOLL_EVT_OPT_READ	0
#define XPOLL_EVT_OPT_SEND	1
#define XPOLL_EVT_OPT_APP	100

#ifndef XPOLL_READ_BLK_SIZE
#	define XPOLL_READ_BLK_SIZE (1024 * 16)
#endif

#ifndef _WIN32
#	ifndef SOCKET
#	define SOCKET  int
#	endif
#	ifndef INVALID_SOCKET
#	define INVALID_SOCKET (-1)
#	endif
#	ifndef closesocket
#	define closesocket (a)  close(a)
#	endif
#endif
namespace ec {
	class udpevt // udp event used to stop poll/Wsapoll wait
	{
	public:
		udpevt() {
			_fd = INVALID_SOCKET;
		}
		~udpevt() {
			close();
		}
		bool open()
		{
			uint16_t port = (uint16_t)50000;
			SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (s == INVALID_SOCKET)
				return false;
			memset(&_sinaddr, 0, sizeof(_sinaddr));
			_sinaddr.sin_family = AF_INET;
			_sinaddr.sin_addr.s_addr = inet_addr("127.0.0.192");
			_sinaddr.sin_port = htons(port);
			while (SOCKET_ERROR == bind(s, (struct sockaddr *)&_sinaddr, (int)sizeof(_sinaddr)))
			{
				port--;
				_sinaddr.sin_port = htons(port);
				if (port < 9000) {
					::closesocket(s);
					return false;
				}
			}
			_fd = s;
			return true;
		}
		void close()
		{
			if (_fd != INVALID_SOCKET)
			{
				::closesocket(_fd);
				_fd = INVALID_SOCKET;
			}
		}
		void set_event()
		{
			if (_fd != INVALID_SOCKET) {
				char evt[4] = { 0 };
				::sendto(_fd, evt, 1, 0, (struct sockaddr*)&_sinaddr, (socklen_t)sizeof(_sinaddr));//send to itself
			}
		}
		void reset_event()
		{
			if (_fd != INVALID_SOCKET) {
				char evt[4096];
#ifdef _WIN32
				::recv(_fd, evt, (int)sizeof(evt), 0);
#else
				::recv(_fd, evt, (int)sizeof(evt), MSG_DONTWAIT);
#endif
			}
		}
		inline SOCKET getfd() {
			return _fd;
		}
	private:
		SOCKET   _fd; //Non-block
		struct sockaddr_in _sinaddr;
	};

	struct t_xpoll_item //
	{
		uint32_t ucid;  //key
		uint32_t errnum;//send error number
#ifdef _WIN32
		SOCKET   fd; //Non-block
#else
		int		 fd; //Non-block
#endif		
		uint32_t uflag; //d0=1:read event not done; 0：done ,can read continue
		uint32_t uhead; // get position, point first data and current send message
		uint32_t usendsize;//current send bytes
		uint32_t utail; //add position, point empty
		time_t	 lasterr; //last time send failed
		char     sinfo[64];// '\n' seperate, now just has "ip:192.168.1.41\n"
		struct t_pkg {
			uint32_t size; //message bytes size
			uint8_t  *pd;  //message
		} pkg[XPOLL_SEND_PKG_NUM]; //FIFO buffer
	};

	struct t_xpoll_send // send item
	{
		uint32_t ucid;  //key
#ifdef _WIN32
		SOCKET   fd; //Non-blocking socket
#else
		int  fd; //Non-blocking socket
#endif			
		uint32_t upos; //pkg position,
		uint32_t usendsize;// current send completed bytes
		uint32_t usize; //pkg size
		uint8_t  *pd;  // send data
	};

	struct t_xpoll_event //complete event
	{
		uint32_t ucid;  //KEY		
		uint32_t ubytes;//send or read bytes
		uint8_t  opt;   //0(XPOLL_EVT_OPT_READ):read ; 1(XPOLL_EVT_OPT_SEND):send
		uint8_t  status;//0(XPOLL_EVT_ST_OK):OK ; 1(XPOLL_EVT_ST_ERR):failed; 2(XPOLL_EVT_ST_CLOSE): xpoll close
		uint8_t  res[2];//res,set 0
		void*    pdata; //if ucopt==read,pdata is xpoll buffer,else is user buffer
	};

	template<>
	struct key_equal<uint32_t, t_xpoll_item>
	{
		bool operator()(uint32_t key, const t_xpoll_item& val)
		{
			return key == val.ucid;
		}
	};
	class xpoll : public cThread
	{
	private:
		std::mutex _cpevtlock;//lock for _cpevt
		ec::cEvent _evtiocp, _evtcanadd; // for _cpevt
		ec::fifo<t_xpoll_event> _cpevt;//completely event

		std::mutex _memread_lock;// lock for _memread
		ec::memory _memread;// memory for read

		std::mutex _maplock;//lock for _map
		ec::memory _memmap;// memory for _map 
		bool _fdchanged;   //fds changed lock with _map
		ec::map<uint32_t, t_xpoll_item> _map;
		ec::map<uint32_t, t_xpoll_item>::iterator _posnext;

		ec::vector<pollfd> _pollfd;
		ec::vector<uint32_t> _pollkey;
		udpevt _udpevt;
		uint32_t _unextid, _umaxconnects;

	public:
		xpoll(uint32_t maxconnum) :
			_cpevt(maxconnum * 5, &_cpevtlock),
			_memread(XPOLL_READ_BLK_SIZE, 16 + maxconnum / 8, 0, 0, 0, 0, &_memread_lock),
			_memmap(ec::map<uint32_t, t_xpoll_item>::size_node(), maxconnum),
			_map(11 + (uint32_t)(maxconnum / 3), &_memmap),
			_pollfd(maxconnum),
			_pollkey(maxconnum), _unextid(100), _umaxconnects(maxconnum)
		{
			_posnext = 0;
			_fdchanged = false;
		}
		bool open()
		{
			if (!_udpevt.open())
				return false;
			_fdchanged = true;
			StartThread(nullptr);
			return true;
		}
		void close()
		{
			StopThread();// stop send thread first
			_maplock.lock();
			_map.for_each([this](t_xpoll_item & v) //make all complete event
			{
				t_xpoll_event evt;
				while (v.uhead != v.utail) {
					evt.ucid = v.ucid;
					evt.ubytes = 0;
					evt.opt = XPOLL_EVT_OPT_SEND;
					evt.status = XPOLL_EVT_ST_CLOSE;
					evt.pdata = v.pkg[v.uhead].pd;
					add_evt_wait(evt);
					_evtiocp.SetEvent();
					v.uhead = (v.uhead + 1) % XPOLL_SEND_PKG_NUM;
				}
			});
			_map.clear(); // remove all from map
			_maplock.unlock();
			_udpevt.close();
		}

		void add_event(uint32_t ucid, uint8_t opt, uint8_t st, void *pdata, size_t datasize)
		{
			t_xpoll_event evt;//先添加一个connect事件到 _cpevt
			memset(&evt, 0, sizeof(evt));
			evt.opt = opt;
			evt.status = st;
			evt.ucid = ucid;
			evt.pdata = pdata;
			evt.ubytes = (uint32_t)datasize;
			add_evt_wait(evt);
		}
		bool add_fd(SOCKET fd, const char* sinfo) //add to pool
		{
			_maplock.lock();
			uint32_t ucid = alloc_ucid();
			if (!ucid) {
				_maplock.unlock();
				return false; // return false if full
			}
			_maplock.unlock();
			void *pinfo = _memread.mem_malloc(XPOLL_READ_BLK_SIZE);
			if (!pinfo)
				return false;
			str_ncpy((char*)pinfo, sinfo, XPOLL_READ_BLK_SIZE - 1);
			add_event(ucid, XPOLL_EVT_OPT_READ, XPOLL_EVT_ST_CONNECT, pinfo, strlen((char*)pinfo) + 1);//add one connect event

			t_xpoll_item t; //add to map
			memset(&t, 0, sizeof(t));
			t.ucid = ucid;
			t.fd = fd;
			t.uflag = 1; //set read event not done,can't read continue
			_maplock.lock();
			if (!_map.set(ucid, t)) {
				_maplock.unlock();
				add_event(ucid, XPOLL_EVT_OPT_READ, XPOLL_EVT_ST_ERR, 0, 0);
				return true; // return true , delete with event
			}
			_fdchanged = true;
			_udpevt.set_event();
			_maplock.unlock();
			return true;
		}
		inline void remove(uint32_t ucid) // remove from pool
		{
			do_delete(ucid, XPOLL_EVT_ST_CLOSE);
		}
		int post_msg(uint32_t ucid, void *pd, size_t size)//post message,return -1:error  0:full ; 1:one message post
		{
			ec::unique_lock lck(&_maplock);
			t_xpoll_item* pi = _map.get(ucid);
			if (!pi)
				return -1;
			if ((pi->utail + 1) % XPOLL_SEND_PKG_NUM == pi->uhead) //full
				return 0;
			pi->pkg[pi->utail].size = (uint32_t)size;
			pi->pkg[pi->utail].pd = (uint8_t*)pd;
			pi->utail = (pi->utail + 1) % XPOLL_SEND_PKG_NUM;
			_udpevt.set_event();
			return 1;
		}
		int post_msg(uint32_t ucid, vector<uint8_t> *pvd)//post message,return -1:error  0:full ; 1:one message post
		{
			ec::unique_lock lck(&_maplock);
			t_xpoll_item* pi = _map.get(ucid);
			if (!pi)
				return -1;
			if ((pi->utail + 1) % XPOLL_SEND_PKG_NUM == pi->uhead) //full
				return 0;
			pi->pkg[pi->utail].size = (uint32_t)pvd->size();
			pi->pkg[pi->utail].pd = (uint8_t*)pvd->detach_buf();
			pi->utail = (pi->utail + 1) % XPOLL_SEND_PKG_NUM;
			_udpevt.set_event();
			return 1;
		}
		int sendnodone(uint32_t ucid)
		{
			ec::unique_lock lck(&_maplock);
			t_xpoll_item* pi = _map.get(ucid);
			if (!pi)
				return -1;
			uint32_t n = 0, h = pi->uhead, t = pi->utail;
			while (h != t) {
				h = (h + 1) % XPOLL_SEND_PKG_NUM;
				n++;
			}
			return (int)n;
		}
		bool get_event(t_xpoll_event *pout)// get one complete event
		{
			_evtiocp.Wait(100);
			if (_cpevt.get(*pout)) {
				_evtiocp.SetEvent();
				_evtcanadd.SetEvent();
				return true;
			}
			return false;
		}
		void free_event(t_xpoll_event *pi)// when done event by get_event,must call free_event
		{
			if (pi->opt != XPOLL_EVT_OPT_READ)
				return;
			_maplock.lock();
			t_xpoll_item* p = _map.get(pi->ucid);
			if (p)
				p->uflag = 0; //set read done 
			_maplock.unlock();
			_memread.mem_free(pi->pdata);//recycle read memory			
		}
		inline bool has_event()
		{
			return !_cpevt.empty();
		}
	private:
		void make_pollfd()
		{
			ec::unique_lock lck(&_maplock);
			if (!_fdchanged) // no change
				return;
			_pollfd.clear();
			_pollkey.clear();

			pollfd tv;
			tv.fd = _udpevt.getfd(); //add udoevt fd
			tv.events = POLLIN;
			tv.revents = 0;
			_pollfd.add(tv);
			_pollkey.add((uint32_t)0);

			_map.for_each([this](t_xpoll_item & v) {
				pollfd t;
				t.fd = v.fd;
				if (v.uhead != v.utail)
					t.events = POLLIN | POLLOUT;
				else
					t.events = POLLIN;
				t.revents = 0;
				_pollfd.add(t);
				_pollkey.add(v.ucid);
			});
			_fdchanged = false;
		}
		bool add_evt_wait(t_xpoll_event &evt)
		{
			bool bfull = false;
			int i, nr = _cpevt.add(evt, &bfull);
			if (nr > 0)
			{
				if (!bfull)
					_evtcanadd.SetEvent();
				return true;
			}
			else if (nr < 0)
				return false;
			for (i = 0; i < 20; i++) {
				_evtiocp.SetEvent();
				_evtcanadd.Wait(100);
				nr = _cpevt.add(evt, &bfull);
				if (nr > 0)
				{
					if (!bfull)
						_evtcanadd.SetEvent();
					return true;
				}
			}
			return false;
		}
		void add_close_event(uint32_t ucid, int status)
		{
			t_xpoll_event evt;
			memset(&evt, 0, sizeof(evt));
			evt.ucid = ucid;
			evt.opt = XPOLL_EVT_OPT_READ;
			evt.status = status;
			add_evt_wait(evt);
			_evtiocp.SetEvent();
		}

		bool get_send(uint32_t ucid, t_xpoll_send* ps)
		{
			ec::unique_lock lck(&_maplock);
			t_xpoll_item* p = nullptr;
			p = _map.get(ucid);
			if (!p)
				return false;
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

		void do_delete(uint32_t ucid, uint8_t status)
		{
			t_xpoll_item t;
			_maplock.lock();
			t_xpoll_item* pi = _map.get(ucid);
			if (!pi) {
				_maplock.unlock();
				return;
			}

			if (INVALID_SOCKET != pi->fd) {
#ifdef _WIN32
				shutdown(pi->fd, SD_BOTH);
#else
				shutdown(pi->fd, SHUT_WR);
#endif
				::closesocket(pi->fd);
				pi->fd = INVALID_SOCKET;
				add_close_event(ucid, status);
			}

			t = *pi;
			_map.erase(ucid);// delete from map
			_maplock.unlock();
			t_xpoll_event evt;
			while (t.uhead != t.utail) {
				evt.ucid = ucid;
				evt.ubytes = 0;
				evt.opt = XPOLL_EVT_OPT_SEND;
				evt.status = status;
				evt.pdata = t.pkg[t.uhead].pd;
				add_evt_wait(evt);
				_evtiocp.SetEvent();
				t.uhead = (t.uhead + 1) % XPOLL_SEND_PKG_NUM;
			}
			_fdchanged = true;
		}
		int  do_sendbyte(t_xpoll_send* ps, int nerr) //return 0:no more send data;  >0：has more send data
		{
			int nret = 0;
			_maplock.lock();
			t_xpoll_item* pi = _map.get(ps->ucid);
			if (!pi) {
				_maplock.unlock();
				return 0;
			}
			if (nerr > 0) //success
			{
				pi->errnum = 0;// reset error counter
				if (ps->usendsize == ps->usize)//complete
				{
					pi->uhead = (pi->uhead + 1) % XPOLL_SEND_PKG_NUM;//next
					pi->lasterr = 0;
					pi->usendsize = 0;
					_maplock.unlock();
					t_xpoll_event evt;
					evt.ucid = ps->ucid;
					evt.ubytes = ps->usendsize;
					evt.opt = XPOLL_EVT_OPT_SEND;
					evt.status = XPOLL_EVT_ST_OK;
					evt.pdata = ps->pd;
					add_evt_wait(evt);
					_evtiocp.SetEvent();
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
						_maplock.unlock();
						do_delete(ps->ucid, XPOLL_EVT_ST_ERR);
						return 0;
					}
				}
			}
			else if (nerr < 0) {
				_maplock.unlock();
				do_delete(ps->ucid, XPOLL_EVT_ST_ERR);
				return 0;
			}
			_maplock.unlock();
			return nret;
		}
		void set_read_data_flag(uint32_t ucid, bool bhasdata)
		{
			ec::unique_lock lck(&_maplock);
			t_xpoll_item* p = _map.get(ucid);
			if (!p || (p->uflag & 0x01)) {
				_maplock.unlock();
				return;
			}
			if (bhasdata)
				p->uflag |= 0x01; // set bit 0				
			else
				p->uflag ^= ~(0x01);// clear bit0				
		}
#ifdef _WIN32
		void do_read(uint32_t ucid, SOCKET fd)
#else
		void do_read(uint32_t ucid, int fd)
#endif
		{
			_maplock.lock();
			t_xpoll_item* p = _map.get(ucid);
			if (!p || (p->uflag & 0x01)) {
				_maplock.unlock();
				return;
			}
			_maplock.unlock();

			t_xpoll_event evt;//读
			evt.ucid = ucid;
			evt.ubytes = 0;
			evt.opt = XPOLL_EVT_OPT_READ;
			evt.status = XPOLL_EVT_ST_OK;
			evt.pdata = _memread.mem_malloc(XPOLL_READ_BLK_SIZE);
			if (!evt.pdata)
				return;
#ifdef _WIN32
			int nr = ::recv(fd, (char*)evt.pdata, XPOLL_READ_BLK_SIZE, 0);
#else
			int nr = ::recv(fd, (char*)evt.pdata, XPOLL_READ_BLK_SIZE, MSG_DONTWAIT);
#endif
			if (nr == 0) //close gracefully 
			{
				_memread.mem_free(evt.pdata);
				do_delete(ucid, XPOLL_EVT_ST_CLOSE);
				return;
			}
			else if (nr < 0) {
#ifdef _WIN32
				if (WSAEWOULDBLOCK == WSAGetLastError())
					_memread.mem_free(evt.pdata);
#else
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					_memread.mem_free(evt.pdata);
#endif
				else {
					_memread.mem_free(evt.pdata);
					do_delete(ucid, XPOLL_EVT_ST_ERR);
				}
				return;
			}
			else //read event
			{
				evt.ubytes = nr;
				set_read_data_flag(ucid, true);
				if (add_evt_wait(evt))
					_evtiocp.SetEvent();
				else
				{
					set_read_data_flag(ucid, false);
					_memread.mem_free(evt.pdata);//free memory
				}
			}
		}
		unsigned int alloc_ucid()
		{
			if (_map.size() >= _umaxconnects)
				return 0;
			_unextid++;
			while (_unextid < 100 || _map.get(_unextid)) {
				_unextid++;
			}
			return _unextid;// not 0
		}
	protected:
		virtual	void dojob()
		{
			size_t i = 0;
			int n;
			t_xpoll_send ts;
			make_pollfd();
#ifdef _WIN32
			n = WSAPoll(_pollfd.data(), (ULONG)_pollfd.size(), 200);
#else
			n = poll(_pollfd.data(), _pollfd.size(), 200);
#endif
			if (n <= 0)
				return;
			pollfd* p = _pollfd.data();
			uint32_t* puid = _pollkey.data();
			for (i = 0; i < _pollfd.size(); i++) {
				if (i == 0) { //udpevt
					if (p[i].revents & POLLIN) {
						_udpevt.reset_event();
						p[i].revents = 0;
					}
					continue;
				}
				if (p[i].revents & (POLLERR | POLLHUP | POLLNVAL)) { // error
					do_delete(puid[i], XPOLL_EVT_ST_ERR);
					continue;
				}
				if (get_send(puid[i], &ts)) { //send first		
					if (!ts.usize)
						do_delete(puid[i], XPOLL_EVT_ST_CLOSE);// zero size msg will disconenct
					else {
						if (sendts(&ts) > 0) // not send complete 
							p[i].events = POLLIN | POLLOUT;
						else // send complete 
							p[i].events = POLLIN;
					}
				}
				if (p[i].revents & POLLIN)  //read
					do_read(puid[i], p[i].fd);
				p[i].revents = 0;
			}
		};
	};
}
