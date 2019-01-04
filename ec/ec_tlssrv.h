/*!
\file ec_tlssrv.h
\author kipway@outlook.com
\update 2019.1.4

eclib TLS1.2 server class. easy to use, no thread , lock-free

eclib Copyright (c) 2017-2018, kipway
source repository : https://github.com/kipway/eclib

Licensed under the Apache License, Version 2.0 (the "License");
*/
#pragma once
#include "ec_tcpsrv.h"
#include "c11_tls12.h"

namespace ec {
	namespace tcp {		
		class tls_session : public session, public ec::tls_session_srv {
		public:
			tls_session(uint32_t ucid, SOCKET  fd,  const void* pcer, size_t cerlen,
				const void* pcerroot, size_t cerrootlen, std::mutex *pRsaLck, RSA* pRsaPrivate, ec::memory* pmem, ec::cLog* plog, uint32_t protoc = EC_PROTOC_TLS) :
				session(ucid, fd, protoc, EC_PROTOC_ST_CONNECT, pmem, plog),
				ec::tls_session_srv(ucid, pcer, cerlen, pcerroot, cerrootlen, pRsaLck, pRsaPrivate, pmem, plog)
			{
			}
		public:			
			virtual void setip(const char* sip) {
				session::setip(sip);
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
						if (session::send(pmsgout->data(), (int)pmsgout->size()) < 0)
							nr = -1;
					}
					pmsgout->clear();
					return nr;
				}
				else if (TLS_SESSION_HKOK == nst) {
					nr = 0;
					if (pmsgout->size()) {
						if (session::send(pmsgout->data(), (int)pmsgout->size()) < 0)
							nr = -1;
					}
					pmsgout->clear();
					_status |= EC_PROTOC_ST_WORK;
					return nr;
				}
				else if (TLS_SESSION_APPDATA == nst)
					nr = 0;
				return nr;
			}

			virtual int send(const void* pdata, size_t size) {
				ec::vector<uint8_t> tlspkg(size + 1024 - size % 1024, _pmem);
				if (MakeAppRecord(&tlspkg, pdata, size))
					return session::send(tlspkg.data(), (int)tlspkg.size());
				return -1;
			}
		};
		class tls_server : public server
		{
		public:
			tls_server(ec::cLog* plog, ec::memory* pmem) : server(plog, pmem) {

			}
		protected:
			tls_srvca _ca;  // certificate
		public:
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
				return server::open(port, sip);				
			}
		protected:
			virtual session* createsession(uint32_t ucid, SOCKET  fd, uint32_t status, ec::memory* pmem, ec::cLog* plog) {
				return new tls_session(ucid, fd, _ca._pcer.data(), _ca._pcer.size(),
					_ca._prootcer.data(), _ca._prootcer.size(), &_ca._csRsa, _ca._pRsaPrivate, _pmem, _plog);
			}				
		};
	}
}

