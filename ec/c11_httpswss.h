/*!
\file c11_httpswss.h
\author	jiangyong
\email  kipway@outlook.com
\update 2018.6.24

eclibe Asynchronous HTTPS and secret websocket server template class for windows & linux

class AioHttpsSrv
class AioHttpsThread


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

#include "c11_tcptls.h"
#include "c11_websocket.h"

namespace ec {

	template<class _THREAD, class _CLS>
	class AioHttpsSrv : public AioTlsSrv<_THREAD, AioHttpsSrv<_THREAD, _CLS>>
	{
	public:
		typedef AioTlsSrv<_THREAD, AioHttpsSrv<_THREAD, _CLS>> base_;
		friend class base_;
		AioHttpsSrv(uint32_t maxconnum, cLog* plog, memory* pmem) : base_(maxconnum, plog, pmem), _clients(maxconnum)
		{
		}
		inline void InitHttpsArgs(_THREAD* pthread) {
			http_pargs arg1(&_cfg, &_clients);
			pthread->InitWsArgs(&arg1);
			base_::InitTlsArgs(pthread);
		}
	protected:
		inline void InitArgs(_THREAD* pthread) {
			static_cast<_CLS*>(this)->InitArgs(pthread);
		}
	public:
		cHttpCfg _cfg;
		cHttpClientMap _clients;
	public:
		bool start(const char* cfgfile, unsigned int uThreads, const char* sip = nullptr)
		{
			if (!_cfg.fromfile(cfgfile)) {
				if (base_::_plog)
					base_::_plog->add(CLOG_DEFAULT_ERR, "https server load config file %s failed", cfgfile);
				return false;
			}
			return base_::start(_cfg._ca_server, _cfg._ca_root, _cfg._private_key, _cfg._wport_wss, uThreads, sip);
		}
		void stop()
		{
			base_::stop();
			if (base_::_plog)
				base_::_plog->add(CLOG_DEFAULT_MSG, "https server(port %u) stop success!", _cfg._wport_wss);
		}
	};

	template< class _CLS>
	class AioHttpsThread : public cWebsocket<AioHttpsThread<_CLS>>, public AioTlsSrvThread<AioHttpsThread<_CLS>>
	{
	public:
		typedef AioTlsSrvThread<AioHttpsThread<_CLS>> base_;
		friend class base_;
		typedef cWebsocket<AioHttpsThread<_CLS>> basews_;
		friend class basews_;
		AioHttpsThread(xpoll* ppoll, ec::cLog* plog, memory* pmem, int threadno, uint16_t srvport)
			: base_(ppoll, plog, pmem, threadno, srvport),
			basews_(nullptr, nullptr, plog, pmem, true)
		{
		}
		void InitWsArgs(http_pargs* pargs) {
			basews_::_pcfg = pargs->_pcfg;
			basews_::_pclis = pargs->_pmap;
		}
	protected: //cWebsocket
		void onwsread(uint32_t ucid, int bFinal, int wsopcode, const void* pdata, size_t size)
		{
			static_cast<_CLS*>(this)->onwsread(ucid, bFinal, wsopcode, pdata, size);
		}
		void dodisconnect(uint32_t ucid) {
			base_::disconnect(ucid);
		};
		int  dosend(uint32_t ucid, vector<char> &vd, int timeovermsec = 0)
		{
			size_t size = vd.size();
			void* pbuf = vd.detach_buf();
			if (!base_::tls_post(ucid, pbuf, size, timeovermsec))
				return -1;
			return int(size);
		}
		bool onhttprequest(uint32_t ucid, cHttpPacket* pPkg)
		{
			return static_cast<_CLS*>(this)->onhttprequest(ucid, pPkg);
		}
	protected: //AioTlsSrvThread
		inline void onconnect(uint32_t ucid, const char* sip)//connect event
		{
			basews_::_pclis->Add(ucid, sip);
			static_cast<_CLS*>(this)->onconnect(ucid, sip);
		}
		inline void onhandshake(uint32_t ucid)
		{
			static_cast<_CLS*>(this)->onhandshake(ucid);
		};

		void onrecv(uint32_t ucid, const void* pdata, size_t size)
		{
			if (pdata)
				basews_::doreadbytes(ucid, pdata, size);
		}
		inline void onsendcomplete(uint32_t ucid, int nstatus)//send complete event
		{
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
} // ec
