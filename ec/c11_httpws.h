/*!
\file c11_httpws.h
\author	jiangyong
\email  kipway@outlook.com
\update 2018.6.24

eclibe Asynchronous HTTP and websocket server template class for windows & linux

class AioHttpSrv
class AioHttpThread

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

#include "c11_tcp.h"
#include "c11_websocket.h"

namespace ec {
	template<class _THREAD, class _CLS>
	class AioHttpSrv : public AioTcpSrv<_THREAD, AioHttpSrv<_THREAD, _CLS>>
	{
	public:
		typedef AioTcpSrv<_THREAD, AioHttpSrv<_THREAD, _CLS>> base_;
		friend  base_;
		AioHttpSrv(uint32_t maxconnum, cLog* plog, memory* pmem) : base_(maxconnum, plog, pmem), _clients(maxconnum)
		{
		}
		inline void InitHttpArgs(_THREAD* pthread) {
			http_pargs arg1(&_cfg, &_clients);
			pthread->InitWsArgs(&arg1);
		}
	protected:
		inline void InitArgs(_THREAD* pthread) {
			static_cast<_CLS*>(this)->InitArgs(pthread);
		}
	public:
		cHttpCfg        _cfg;
		cHttpClientMap	_clients;
	public:
		bool start(const char* cfgfile, unsigned int uThreads)
		{
			if (!_cfg.fromfile(cfgfile)) {
				if (base_::_plog)
					base_::_plog->add(CLOG_DEFAULT_ERR, "http server load config file %s failed", cfgfile);
				return false;
			}
			return base_::start(_cfg._wport, uThreads);
		}
		void stop()
		{
			base_::stop();
			if (base_::_plog)
				base_::_plog->add(CLOG_DEFAULT_MSG, "http server(port %u) stop success!", _cfg._wport);
		}
	};

	template< class _CLS>
	class AioHttpThread : public cWebsocket<AioHttpThread<_CLS>>, public AioTcpSrvThread<AioHttpThread<_CLS>>
	{
	public:
		typedef AioTcpSrvThread<AioHttpThread<_CLS>> base_;
		friend  base_;
		typedef cWebsocket<AioHttpThread<_CLS>> basews_;
		friend  basews_;
		AioHttpThread(xpoll* ppoll, ec::cLog* plog, memory* pmem, int threadno, uint16_t srvport)
			: base_(ppoll, plog, pmem, threadno, srvport),
			basews_(nullptr, nullptr, plog, pmem, false)
		{
		}
		void InitWsArgs(http_pargs* pargs) {
			basews_::_pcfg = pargs->_pcfg;
			basews_::_pclis = pargs->_pmap;
		}
	protected: // cWebsocket
		inline void onwsread(uint32_t ucid, int bFinal, int wsopcode, const void* pdata, size_t size)
		{
			static_cast<_CLS*>(this)->onwsread(ucid, bFinal, wsopcode, pdata, size);
		}
		inline void dodisconnect(uint32_t ucid) {
			base_::disconnect(ucid);
		};
		int  dosend(uint32_t ucid, vector<char> &vd, int timeovermsec = 0)
		{
			size_t size = vd.size();
			void* pbuf = vd.detach_buf();
			if (!base_::tcp_post(ucid, pbuf, size, timeovermsec))
				return -1;
			return int(size);
		}
		bool onhttprequest(uint32_t ucid, cHttpPacket* pPkg)
		{
			return static_cast<_CLS*>(this)->onhttprequest(ucid, pPkg);
		}
	protected: //AioTcpSrvThread
		void onconnect(uint32_t ucid, const char* sip)//connect event
		{
			basews_::_pclis->Add(ucid, sip);
			static_cast<_CLS*>(this)->onconnect(ucid, sip);
		}
		void onrecv(uint32_t ucid, const void* pdata, size_t size)
		{
			if (pdata)
				basews_::doreadbytes(ucid, pdata, size);
		}
		void onsend(uint32_t ucid, int nstatus, void* pdata, size_t size)//send complete event
		{
			if (pdata)
				basews_::_pmem->mem_free(pdata);
			static_cast<_CLS*>(this)->onsendcomplete(ucid, nstatus);
		}
		inline void onself(uint32_t ucid, int optcode, void* pdata, size_t size)
		{
			static_cast<_CLS*>(this)->onself(ucid, optcode, pdata, size);
		}
		inline void ondisconnect(uint32_t ucid)//disconnect  event
		{
			static_cast<_CLS*>(this)->ondisconnect(ucid);
			basews_::_pclis->Del(ucid);
		}
	};
}//ec
