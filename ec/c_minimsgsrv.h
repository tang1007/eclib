/*!
\file minimsgsrv.h
\author	kipway@outlook.com
\update 2018.3.13

eclib class mini message server and auto reconnect client

class minipkg
class cMiniMsgSrv
class cMiniMsgCli

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
#include "c_minisrv.h"
#include "c_tcp_tl.h"
#ifndef MINI_PKG_FLAG
#	define MINI_PKG_FLAG 0xF5
#endif

#define EC_MINI_SEND_ERR	   (-1)
#define EC_MINI_SEND_PKGERR    (-2)

#ifndef MINI_MSG_MAXSIZE
#	define MINI_MSG_MAXSIZE    (1024 * 1024)
#endif
namespace ec
{
	class minipkg // mini srv package
	{
	public:
		minipkg() : _rbuf(1024 * 16) {
		}
		virtual ~minipkg() {}
		struct t_head {
			uint8_t  sync;
			uint8_t  flag;
			uint32_t msglen;
		};
	public:
		static int send(SOCKET sock, const void *pmsg, size_t sizemsg)
		{
			if (sizemsg > MINI_MSG_MAXSIZE)
				return EC_MINI_SEND_PKGERR;
			unsigned char head[8]; //sync(1),flag(1),pkglen(4)
			ec::cStream ss(head, sizeof(head));
			ss < (uint8_t)MINI_PKG_FLAG;
			ss < (uint8_t)0x10;
			ss < (uint32_t)(sizemsg);
			int ns = tcp_send(sock, head, 6);
			if (ns < 0)
				return EC_MINI_SEND_ERR;
			ns = tcp_send(sock, pmsg, (int)sizemsg);
			if (ns < 0)
				return EC_MINI_SEND_ERR;
			return ns;
		}
		static bool mkhead(void* po,size_t datasize)//out to po 6bytes
		{
			if (datasize > MINI_MSG_MAXSIZE)
				return false;			
			ec::cStream ss(po, 6);
			ss < (uint8_t)MINI_PKG_FLAG;
			ss < (uint8_t)0x10;
			ss < (uint32_t)(datasize);
			return true;
		}
	protected:
		ec::vector<uint8_t>	_rbuf;
	public:
		int parse(const uint8_t* pdata, size_t usize, ec::vector<uint8_t> *pout)
		{
			if (pdata && usize)
				_rbuf.add(pdata, usize);
			return parsepkg(pout);
		}
		inline void clear()
		{
			_rbuf.clear();
		}
	protected:
		int parsepkg(ec::vector<uint8_t> *pout)//return 0:wait; -1:err; 1:OK
		{
			uint8_t* pu = _rbuf.data();
			if (_rbuf.size() < 6)
				return 0;
			ec::cStream ss((void*)pu, _rbuf.size());
			t_head h;
			ss > &h.sync;
			ss > &h.flag;
			ss > &h.msglen;
			if (h.sync != MINI_PKG_FLAG || h.flag != 0x10 || h.msglen > MINI_MSG_MAXSIZE)
				return -1;
			if (h.msglen + 6 > _rbuf.size())
			{
				if (_rbuf.capacity() < h.msglen + 6)
					_rbuf.set_grow(h.msglen + 8);
				return 0;
			}
			pout->clear();
			pout->add(pu + 6, h.msglen);
			_rbuf.erase(0, h.msglen + 6);
			_rbuf.shrink(1024 * 16);
			_rbuf.set_grow(1024 * 16);
			return 1;
		}
	};
	class cMiniMsgSrv : public cMiniSrv
	{
	public:
		cMiniMsgSrv() : _msgr(1024 * 16)
		{
		}
	public:
		int send_msg(t_id *pid, const void* pd, size_t size)
		{
			cSafeLock lck(&_cs_send);
			if (pid->s == INVALID_SOCKET)
				return -1;
			return minipkg::send(pid->s, pd, (int)size);
		}
		int send_msg(uint32_t ucid, const void* pd, size_t size)
		{
			cSafeLock lck(&_cs_send);
			SOCKET s = fromid(ucid);
			if (s == INVALID_SOCKET)
				return -1;
			return minipkg::send(s, pd, (int)size);
		}
	private:
		ec::vector<uint8_t> _msgr;
	protected:
		virtual bool onmsg(t_id* pid, const uint8_t* pd, size_t size) = 0;
	protected:
		virtual bool onreadbytes(t_id* pid, const uint8_t* pd, size_t size)
		{			
			if (!pid->pcls)
				return false;
			minipkg* pi = (minipkg*)pid->pcls;
			int nr = pi->parse(pd, size, &_msgr);
			while (1 == nr)
			{
				if (!onmsg(pid, _msgr.data(), _msgr.size())) {
					_msgr.clear();
					_msgr.shrink(1024 * 32);
					return false;
				}
				_msgr.clear();
				_msgr.shrink(1024 * 32);
				nr = pi->parse(nullptr, 0, &_msgr);
			}
			return -1 != nr;
		}
		virtual void onclose(t_id* pid) // return false diconnect
		{
			if (pid->pcls) {
				delete (minipkg*)pid->pcls;
				pid->pcls = nullptr;
			}
		}
		virtual bool onconnect(t_id* pid) // return false diconnect
		{
			pid->pcls = new minipkg;
			if (!pid->pcls)
				return false;
			SetTcpNoDelay(pid->s);
			SetSocketKeepAlive(pid->s);
			return true;
		}
	};
	class cMiniMsgCli : public cMiniCli
	{
	public:
		cMiniMsgCli():_msgr(1024 * 32){
		}
	public:
		int send_msg(const void* pd, size_t size) {
			ec::cSafeLock lck(&_cs);
			if (INVALID_SOCKET == _sclient)
				return -1;
			return minipkg::send(_sclient, pd, size);
		}
	private:
		minipkg  _pkg;
		ec::vector<uint8_t> _msgr;
	protected:
		virtual void onconnect() {
			SetTcpNoDelay(_sclient);
			SetSocketKeepAlive(_sclient);			
			_pkg.clear();
		};
		virtual void onclose() {
			_pkg.clear();
		};
		virtual bool onreadbytes(const uint8_t* pdata, size_t usize) 
		{
			int nr = _pkg.parse(pdata, usize, &_msgr);
			while (1 == nr)
			{
				if (!onmsg(_msgr.data(), _msgr.size()))
					return false;
				nr = _pkg.parse(nullptr, 0, &_msgr);
			}
			return -1 != nr;
		};
	protected:
		virtual bool onmsg(const uint8_t* pd,size_t size) = 0; //Processes messages in pmsg, returning true if successful, false will disconnect
	};
}