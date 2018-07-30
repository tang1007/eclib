/*!
\file c11_tcptls.h
\author	jiangyong
\email  kipway@outlook.com
\update 2018.6.24

eclib secret(TLS1.2 rfc5246) TCP  server and client template class

AioTlsClient
AioTlsSrv
AioTlsSrvThread

support:
CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA256 = { 0x00,0x3C };
CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA256 = { 0x00,0x3D };

will add MAC secrets = 20byte
CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA = {0x00,0x2F};
CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA = {0x00,0x35};

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

#include "c11_tls12.h"
#include "c11_tcp.h"

namespace ec {

	class args_tlsthread {
	public:
		args_tlsthread(tls_srvca* pca, sessiontlsmap* psss) :_pca(pca), _psss(psss) {

		}
		tls_srvca * _pca;
		sessiontlsmap* _psss;
	};

	template<class _THREAD, class _CLS>
	class AioTlsSrv : public AioTcpSrv<_THREAD, AioTlsSrv<_THREAD, _CLS>>
	{
	public:
		typedef AioTcpSrv<_THREAD, AioTlsSrv<_THREAD, _CLS>> base_;
		friend  base_;
		AioTlsSrv(uint32_t maxconnum, cLog* plog, memory* pmem)
			: _sss(maxconnum), base_(maxconnum, plog, pmem)
		{
		}
		void InitTlsArgs(_THREAD* pthread) {
			args_tlsthread arg(&_ca, &_sss);
			pthread->InitTlsArgs(&arg);
		}
	protected:
		inline void InitArgs(_THREAD* pthread) {
			static_cast<_CLS*>(this)->InitArgs(pthread);
		}
	public:
		bool start(const char* filecert, const char* filerootcert, const char* fileprivatekey, uint16_t port, int workthreadnum, const char* sip = nullptr)
		{
			if (!_ca.InitCert(filecert, filerootcert, fileprivatekey)) {
				if (base_::_plog)
					base_::_plog->add(CLOG_DEFAULT_ERR, "Load certificate failed! port(%u)", port);
				return false;
			}
			if (!base_::start(port, workthreadnum, sip)) {
				if (base_::_plog)
					base_::_plog->add(CLOG_DEFAULT_ERR, "Start server port(%u) failed!", port);
				return false;
			}
			return true;
		}
	protected:
		tls_srvca _ca;  // certificate
		sessiontlsmap _sss;  // map for  sessions			
	};

	template<class _CLS>
	class AioTlsSrvThread : public AioTcpSrvThread<AioTlsSrvThread<_CLS>>
	{
	public:
		typedef AioTcpSrvThread<AioTlsSrvThread<_CLS>> base_;
		friend  base_;
		AioTlsSrvThread(xpoll* ppoll, cLog* plog, memory* pmem, int threadno, uint16_t srvport) :
			base_(ppoll, plog, pmem, threadno, srvport)
		{
		}
		void InitTlsArgs(args_tlsthread* pargs) {
			_pca = pargs->_pca;
			_psss = pargs->_psss;
		}

	protected:
		tls_srvca * _pca;
		sessiontlsmap* _psss;
	public:
		bool tls_post(uint32_t ucid, const void* pdata, size_t size, int waitmsec = 0)
		{
			vector<uint8_t> pkg(88 * (size / TLS_CBCBLKSIZE) + size + 88 - size % 88, base_::_pmem);
			if (!_psss->mkr_appdata(ucid, &pkg, pdata, size))
				return false;
			if (pkg.size())
				return base_::tcp_post(ucid, &pkg, waitmsec);			
			return false;
		}	
	protected:
		void onconnect(uint32_t ucid, const char* sip)//connect event
		{
			void *p = _psss->getclsmem()->mem_malloc(sizeof(tls_session_srv));
			tls_session_srv* ps = new(p) tls_session_srv(ucid, _pca->_pcer.data(), _pca->_pcer.size(),
				_pca->_prootcer.data(), _pca->_prootcer.size(), &_pca->_csRsa, _pca->_pRsaPrivate, base_::_pmem,
				base_::_plog);
			if (!ps)
				return;
			ps->SetIP(sip);
			_psss->Add(ucid, ps);
			static_cast<_CLS*>(this)->onconnect(ucid, sip);
		}
		void ondisconnect(uint32_t ucid)//disconnect  event
		{
			static_cast<_CLS*>(this)->ondisconnect(ucid);
			_psss->Del(ucid);
		}
		void onrecv(uint32_t ucid, const void* pdata, size_t size) //read event
		{
			if (!pdata || !size)
				return;
			vector<uint8_t> pkg(32 * 1024, base_::_pmem);			
			int nst = _psss->OnTcpRead(ucid, pdata, size, &pkg);
			if (TLS_SESSION_ERR == nst || TLS_SESSION_OK == nst || TLS_SESSION_NONE == nst) {
				if (pkg.size())
					base_::tcp_post(ucid, &pkg);
				if (TLS_SESSION_ERR == nst)
					base_::close_ucid(ucid);// close graceful
			}
			else if (TLS_SESSION_HKOK == nst) {
				if (pkg.size())
					base_::tcp_post(ucid, &pkg);
				static_cast<_CLS*>(this)->onhandshake(ucid);
			}
			else if (TLS_SESSION_APPDATA == nst) {
				static_cast<_CLS*>(this)->onrecv(ucid, pkg.data(), pkg.size());
			}
		}
		void onsend(uint32_t ucid, int nstatus, void* pdata, size_t size) //send complete event
		{
			if (pdata)
				base_::_pmem->mem_free(pdata);
			static_cast<_CLS*>(this)->onsendcomplete(ucid, nstatus);
		}
		inline void onself(uint32_t ucid, int optcode, void* pdata, size_t size) {
			static_cast<_CLS*>(this)->onself(ucid, optcode, pdata, size);
		};
	};

	template<class _CLS>
	class AioTlsClient : public AioTcpClient<AioTlsClient<_CLS>>
	{
	public:
		typedef AioTcpClient<AioTlsClient<_CLS>> base_;
		friend  base_;
		AioTlsClient(cLog* plog, memory* _pmem) : base_(_pmem), _plog(plog), _tls(0, _pmem, plog), _nstatus(TLS_SESSION_NONE)
		{
		}
		inline bool SetServerPubkey(int len, const unsigned char *pubkey)
		{
			return _tls.SetServerPubkey(len, pubkey);			
		}
		bool start(const char* ip, uint16_t port, const char* srvcafile)
		{
			if (srvcafile) {
				if (!_tls.SetServerCa(srvcafile))
					return false;
			}
			return base_::open(ip, port);
		}
		inline void stop() {
			base_::close();
		}

		bool tls_post(const void* pd, size_t size, int timeovermsec = 100)
		{
			vector<uint8_t> pkg(88 * (size / TLS_CBCBLKSIZE) + size + 88 - size % 88, base_::_pmem);
			if (!_tls.MakeAppRecord(&pkg, pd, size))
				return false;
			return base_::tcp_post(&pkg, timeovermsec);// zero copy
		}	
		inline int status() {
			return _nstatus;
		}
	protected:
		void  onrecv(const void* pdata, size_t bytesize) {
			vector<uint8_t> pkg(1024 * 32, base_::_pmem);
			int nst = _tls.OnTcpRead(pdata, bytesize, &pkg);
			if (TLS_SESSION_ERR == nst || TLS_SESSION_OK == nst || TLS_SESSION_NONE == nst) {
				if (pkg.size())
					base_::tcp_post(pkg.data(), pkg.size());
			}
			else if (TLS_SESSION_HKOK == nst) {
				if (pkg.size())
					base_::tcp_post(pkg.data(), pkg.size());
				_nstatus = TLS_SESSION_HKOK;
				static_cast<_CLS*>(this)->onhandshake();
			}
			else if (TLS_SESSION_APPDATA == nst) {
				static_cast<_CLS*>(this)->onrecv(pkg.data(), pkg.size());
			}
		};
		void onconnect() {
			_tls.Reset();
			vector<uint8_t> pkg(1024 * 12, base_::_pmem);
			_tls.mkr_ClientHelloMsg(&pkg);
			base_::tcp_post(pkg.data(), pkg.size());
		}
		inline void ondisconnect() {
			_nstatus = TLS_SESSION_NONE;
			static_cast<_CLS*>(this)->ondisconnect();
		}
	protected:
		cLog * _plog;
		std::atomic_int   _nstatus;
	private:
		tls_session_cli _tls;
	};
}; //ec
