/*!
\file c11_tls12.h
\author	jiangyong
\email  kipway@outlook.com
\update 2018.12.20

eclib TLS1.2(rfc5246)  class
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

#define  tls_rec_fragment_len 16384
namespace tls
{
	enum rec_contenttype {
		rec_change_cipher_spec = 20,
		rec_alert = 21,
		rec_handshake = 22,
		rec_application_data = 23,
		rec_max = 255
	};
	enum handshaketype {
		hsk_hello_request = 0,
		hsk_client_hello = 1,
		hsk_server_hello = 2,
		hsk_certificate = 11,
		hsk_server_key_exchange = 12,
		hsk_certificate_request = 13,
		hsk_server_hello_done = 14,
		hsk_certificate_verify = 15,
		hsk_client_key_exchange = 16,
		hsk_finished = 20,
		hsk_max = 255
	};
};

#ifndef _WIN32
#include <dlfcn.h>
#endif
#include <time.h>

#include "c11_event.h"
#include "c11_mutex.h"
#include "c11_log.h"

#include "c_stream.h"
#include "c11_array.h"
#include "c11_vector.h"
#include "c11_map.h"

#include "openssl/rand.h"
#include "openssl/x509.h"
#include "openssl/hmac.h"
#include "openssl/aes.h"
#include "openssl/pem.h"

/*!
\brief CipherSuite
*/
#define TLS_RSA_WITH_AES_128_CBC_SHA    0x2F
#define TLS_RSA_WITH_AES_256_CBC_SHA    0x35 
#define TLS_RSA_WITH_AES_128_CBC_SHA256 0x3C
#define TLS_RSA_WITH_AES_256_CBC_SHA256 0x3D
#define TLS_COMPRESS_NONE   0

#define TLSVER_MAJOR        3
#define TLSVER_NINOR        3

#define TLS_CBCBLKSIZE  16292   // (16384-16-32-32 - 8)

#define TLS_SESSION_ERR		(-1)// error
#define TLS_SESSION_NONE    0 
#define TLS_SESSION_OK		1   // need send data
#define TLS_SESSION_HKOK	2   // handshack ok
#define TLS_SESSION_APPDATA 3   // on app data

namespace ec
{
	inline bool get_cert_pkey(const char* filecert, ec::Array<uint8_t, 2048>* pout)//get ca public key
	{
		uint8_t stmp[8192];
		FILE* pf = fopen(filecert, "rb");
		if (!pf)
			return false;
		size_t size;
		size = fread(stmp, 1, sizeof(stmp), pf);
		fclose(pf);
		if (size >= sizeof(stmp))
			return false;

		X509* _px509;
		const unsigned char* p = stmp;
		_px509 = d2i_X509(0, &p, (long)size);//only use first Certificate
		if (!_px509)
			return false;

		pout->clear();
		pout->add(_px509->cert_info->key->public_key->data, _px509->cert_info->key->public_key->length);

		X509_free(_px509);
		return true;
	}


	/*!
	\brief base class for TLS 1.2 session
	*/
	class tls_session
	{
	public:
		tls_session(bool bserver, unsigned int ucid, memory* pmem, cLog* plog) :
			_pmem(pmem), _plog(plog), _pkgtcp(1024 * 20, pmem)
		{
			_ucid = ucid;
			_bserver = bserver;

			_breadcipher = false;
			_bsendcipher = false;

			_seqno_send = 0;
			_seqno_read = 0;
			_cipher_suite = 0;

			memset(_keyblock, 0, sizeof(_keyblock));
			memset(_serverrand, 0, sizeof(_serverrand));
			memset(_clientrand, 0, sizeof(_clientrand));
			memset(_master_key, 0, sizeof(_master_key));
			memset(_key_block, 0, sizeof(_key_block));
		};
		virtual ~tls_session() {};
		inline uint32_t get_ucid() {
			return _ucid;
		}
	protected:
		memory * _pmem;
		cLog* _plog;

		uint32_t _ucid;
		bool   _bserver;
		bool   _breadcipher; // read start use cipher
		bool   _bsendcipher; // write start use cipher

		uint64_t _seqno_send;
		uint64_t _seqno_read;
		vector<uint8_t> _pkgtcp;

		uint8_t _keyblock[256];

		uint8_t _key_cwmac[32];// client_write_MAC_key
		uint8_t _key_swmac[32];// server_write_MAC_key

		uint8_t _key_cw[32];   // client_write_key
		uint8_t _key_sw[32];   // server_write_key

		Array<uint8_t, 1024> _client_hello;
		Array<uint8_t, 128> _srv_hello;
		Array<uint8_t, 4096> _srv_certificate;
		Array<uint8_t, 128> _srv_hellodone;
		Array<uint8_t, 512 > _cli_key_exchange;
		Array<uint8_t, 128> _cli_finished;

		uint8_t  _serverrand[32];
		uint8_t  _clientrand[32];
		uint16_t _cipher_suite;

		uint8_t _master_key[48];
		uint8_t _key_block[256];

	private:
		bool caldatahmac(uint8_t type, uint64_t seqno, const void* pd, size_t len, uint8_t* pkeymac, uint8_t *outmac)
		{
			unsigned char  stmp[1024 * 20];
			ec::cStream es(stmp, sizeof(stmp));
			try
			{
				es < seqno < type < (char)TLSVER_MAJOR < (char)TLSVER_NINOR < (unsigned short)len;
				es.write(pd, len);
			}
			catch (int) { return false; }
			unsigned int mdlen = 0;
			if (_cipher_suite == TLS_RSA_WITH_AES_128_CBC_SHA || _cipher_suite == TLS_RSA_WITH_AES_256_CBC_SHA)
				return HMAC(EVP_sha1(), pkeymac, 20, stmp, es.getpos(), outmac, &mdlen) != NULL;
			return HMAC(EVP_sha256(), pkeymac, 32, stmp, es.getpos(), outmac, &mdlen) != NULL;
		}

		bool decrypt_record(const uint8_t*pd, size_t len, uint8_t* pout, int *poutsize)
		{
			size_t maclen = 32;
			if (_cipher_suite == TLS_RSA_WITH_AES_128_CBC_SHA || _cipher_suite == TLS_RSA_WITH_AES_256_CBC_SHA)
				maclen = 20;
			if (len < 53) // 5 + pading16(IV + maclen + datasize)
				return false;

			int i;
			unsigned char sout[1024 * 20], iv[AES_BLOCK_SIZE], *pkey = _key_sw, *pkmac = _key_swmac;
			AES_KEY aes_d;
			int nkeybit = 128;
			if (_cipher_suite == TLS_RSA_WITH_AES_256_CBC_SHA256)
				nkeybit = 256;

			if (_bserver)
			{
				pkey = _key_cw;
				pkmac = _key_cwmac;
			}
			memcpy(iv, pd + 5, AES_BLOCK_SIZE);//Decrypt
			if (AES_set_decrypt_key(pkey, nkeybit, &aes_d) < 0)
				return false;
			AES_cbc_encrypt((const unsigned char*)pd + 5 + AES_BLOCK_SIZE, (unsigned char*)sout, len - 5 - AES_BLOCK_SIZE, &aes_d, iv, AES_DECRYPT);

			unsigned int ufsize = sout[len - 5 - AES_BLOCK_SIZE - 1];//verify data MAC
			if (ufsize > 15)
				return false;

			size_t datasize = len - 5 - AES_BLOCK_SIZE - 1 - ufsize - maclen;
			if (datasize > tls_rec_fragment_len)
				return false;

			unsigned char mac[32], macsrv[32];
			memcpy(macsrv, &sout[datasize], maclen);
			if (!caldatahmac(pd[0], _seqno_read, sout, datasize, pkmac, mac))
				return false;
			for (i = 0; i < (int)maclen; i++) {
				if (mac[i] != macsrv[i])
					return false;
			}

			memcpy(pout, pd, 5);
			memcpy(pout + 5, sout, datasize);
			*(pout + 3) = ((datasize >> 8) & 0xFF);
			*(pout + 4) = (datasize & 0xFF);
			*poutsize = (int)datasize + 5;
			_seqno_read++;
			return true;
		}
	protected:
		int MKR_WithAES_BLK(vector<uint8_t> *pout, uint8_t rectype, const uint8_t* sblk, size_t size)
		{
			int i;
			uint8_t* pkeyw = _key_cw, *pkeywmac = _key_cwmac;
			uint8_t IV[AES_BLOCK_SIZE];//rand IV	

			uint8_t srec[1024 * 20];
			uint8_t sv[1024 * 20];
			uint8_t sout_e[1024 * 20];

			uint8_t mac[32];

			if (_bserver) {
				pkeyw = _key_sw;
				pkeywmac = _key_swmac;
			}

			ec::cStream ss(srec, sizeof(srec));
			try
			{
				RAND_bytes(IV, AES_BLOCK_SIZE);
				ss << rectype << (uint8_t)TLSVER_MAJOR << (uint8_t)TLSVER_NINOR << (uint16_t)0;
				ss.write(IV, AES_BLOCK_SIZE);
			}
			catch (int) { return -1; }
			if (!caldatahmac(rectype, _seqno_send, sblk, size, pkeywmac, mac))
				return -1;

			size_t maclen = 32;
			if (_cipher_suite == TLS_RSA_WITH_AES_128_CBC_SHA || _cipher_suite == TLS_RSA_WITH_AES_256_CBC_SHA)
				maclen = 20;

			ec::cStream es(sv, sizeof(sv));
			size_t rl;
			try
			{
				es.write(sblk, size); //content
				es.write(mac, maclen); //MAC 
				size_t len = es.getpos() + 1;
				if (len % AES_BLOCK_SIZE)
				{
					for (i = 0; i < (int)(AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE)) + 1; i++)//padding and   padding_length  
						es << (char)(AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE));
				}
				else
					es << (char)0; //padding_length

				AES_KEY aes_e;
				int nkeybit = 128;
				if (_cipher_suite == TLS_RSA_WITH_AES_256_CBC_SHA256)
					nkeybit = 256;
				if (AES_set_encrypt_key(pkeyw, nkeybit, &aes_e) < 0)
					return -1;

				AES_cbc_encrypt(sv, sout_e, es.getpos(), &aes_e, IV, AES_ENCRYPT);
				ss.write(sout_e, es.getpos());
				rl = ss.getpos();
				ss.setpos(3) < (uint16_t)(es.getpos() + sizeof(IV));
			}
			catch (int)
			{
				return -1;
			}
			pout->add(srec, rl);
			_seqno_send++;
			return (int)rl;
		}

		bool mk_cipher(vector<uint8_t> *pout, uint8_t rectype, const uint8_t* pdata, size_t size)
		{
			int ns = 0;
			size_t us = 0;//TLS_CBCBLKSIZE 
			while (us < size)
			{
				if (us + TLS_CBCBLKSIZE < size)
				{
					ns = MKR_WithAES_BLK(pout, rectype, pdata + us, TLS_CBCBLKSIZE);
					if (ns < 0)
						return false;
					us += TLS_CBCBLKSIZE;
				}
				else
				{
					ns = MKR_WithAES_BLK(pout, rectype, pdata + us, size - us);
					if (ns < 0)
						return false;
					us = size;
					break;
				}
			}
			return true;
		}

		bool mk_nocipher(vector<uint8_t> *pout, int nprotocol, const void* pd, size_t size)
		{
			uint8_t s[TLS_CBCBLKSIZE + 2048];
			const uint8_t *puc = (const uint8_t *)pd;
			size_t pos = 0, ss;

			s[0] = (uint8_t)nprotocol;
			s[1] = TLSVER_MAJOR;
			s[2] = TLSVER_NINOR;
			while (pos < size)
			{
				ss = TLS_CBCBLKSIZE;
				if (pos + ss > size)
					ss = size - pos;
				s[3] = (uint8_t)((ss >> 8) & 0xFF);
				s[4] = (uint8_t)(ss & 0xFF);
				pout->add(s, 5);
				pout->add(puc + pos, ss);
				pos += ss;
			}
			return true;
		}

		bool make_package(vector<uint8_t> *pout, int nprotocol, const void* pd, size_t size)// make send package
		{
			if (_bsendcipher && *((uint8_t*)pd) != (uint8_t)tls::rec_alert)
				return mk_cipher(pout, (uint8_t)nprotocol, (const uint8_t*)pd, size);
			return mk_nocipher(pout, nprotocol, pd, size);
		}

		bool make_keyblock()
		{
			const char *slab = "key expansion";
			unsigned char seed[128];

			memcpy(seed, slab, strlen(slab));
			memcpy(&seed[strlen(slab)], _serverrand, 32);
			memcpy(&seed[strlen(slab) + 32], _clientrand, 32);

			if (!prf_sha256(_master_key, 48, seed, (int)strlen(slab) + 64, _key_block, 128))
				return false;

			SetCipherParam(_key_block, 128);
			return true;
		}

		bool mkr_ClientFinished(vector<uint8_t> *pout)
		{
			const char* slab = "client finished";
			uint8_t hkhash[48];
			memcpy(hkhash, slab, strlen(slab));
			Array<uint8_t, 1024 * 12> tmp;

			tmp.add(_client_hello.data(), _client_hello.size());
			tmp.add(_srv_hello.data(), _srv_hello.size());
			tmp.add(_srv_certificate.data(), _srv_certificate.size());
			tmp.add(_srv_hellodone.data(), _srv_hellodone.size());
			tmp.add(_cli_key_exchange.data(), _cli_key_exchange.size());

			uint8_t verfiy[32], sdata[32];
			SHA256(tmp.data(), tmp.size(), &hkhash[strlen(slab)]); //            
			if (!prf_sha256(_master_key, 48, hkhash, (int)strlen(slab) + 32, verfiy, 32))
				return false;

			sdata[0] = tls::hsk_finished;
			sdata[1] = 0;
			sdata[2] = 0;
			sdata[3] = 12;
			memcpy(&sdata[4], verfiy, 12);

			_seqno_send = 0;
			_bsendcipher = true;

			if (make_package(pout, tls::rec_handshake, sdata, 16))
			{
				_cli_finished.clear();
				_cli_finished.add(sdata, 16);
				return true;
			}
			return false;
		}

		bool mkr_ServerFinished(vector<uint8_t> *pout)
		{
			const char* slab = "server finished";
			uint8_t hkhash[48];
			memcpy(hkhash, slab, strlen(slab));
			Array<uint8_t, 1024 * 12> tmp;

			tmp.add(_client_hello.data(), _client_hello.size());
			tmp.add(_srv_hello.data(), _srv_hello.size());
			tmp.add(_srv_certificate.data(), _srv_certificate.size());
			tmp.add(_srv_hellodone.data(), _srv_hellodone.size());
			tmp.add(_cli_key_exchange.data(), _cli_key_exchange.size());
			tmp.add(_cli_finished.data(), _cli_finished.size());

			uint8_t verfiy[32], sdata[32];
			SHA256(tmp.data(), tmp.size(), &hkhash[strlen(slab)]); //            
			if (!prf_sha256(_master_key, 48, hkhash, (int)strlen(slab) + 32, verfiy, 32))
				return false;

			sdata[0] = tls::hsk_finished;
			sdata[1] = 0;
			sdata[2] = 0;
			sdata[3] = 12;
			memcpy(&sdata[4], verfiy, 12);

			_seqno_send = 0;
			_bsendcipher = true;

			return make_package(pout, tls::rec_handshake, sdata, 16);
		}

		void Alert(uint8_t level, uint8_t desval, vector<uint8_t>* pout)
		{
			pout->clear();
			uint8_t u[8] = { (uint8_t)tls::rec_alert,TLSVER_MAJOR ,TLSVER_NINOR ,0,2,level,desval,0 };
			pout->add(u, 7);
		}
	public:
		virtual bool MakeAppRecord(ec::vector<uint8_t>*po, const void* pd, size_t size) = 0;
		virtual void Reset()
		{
			_breadcipher = false;
			_bsendcipher = false;

			_seqno_send = 0;
			_seqno_read = 0;
			_cipher_suite = 0;

			_pkgtcp.clear(size_t(0));
			_client_hello.clear();
			_srv_hello.clear();
			_srv_certificate.clear();
			_srv_hellodone.clear();
			_cli_key_exchange.clear();

			memset(_keyblock, 0, sizeof(_keyblock));
			memset(_serverrand, 0, sizeof(_serverrand));
			memset(_clientrand, 0, sizeof(_clientrand));
			memset(_master_key, 0, sizeof(_master_key));
			memset(_key_block, 0, sizeof(_key_block));
		}

		static bool prf_sha256(const uint8_t* key, int keylen, const uint8_t* seed, int seedlen, uint8_t *pout, int outlen)
		{
			int nout = 0;
			uint32_t mdlen = 0;
			uint8_t An[32], Aout[32], An_1[32];
			if (!HMAC(EVP_sha256(), key, (int)keylen, seed, seedlen, An_1, &mdlen)) // A1
				return false;
			uint8_t as[1024];
			uint8_t *ps = (uint8_t *)as;
			while (nout < outlen)
			{
				memcpy(ps, An_1, 32);
				memcpy(ps + 32, seed, seedlen);
				if (!HMAC(EVP_sha256(), key, (int)keylen, ps, 32 + seedlen, Aout, &mdlen))
					return false;
				if (nout + 32 < outlen)
				{
					memcpy(pout + nout, Aout, 32);
					nout += 32;
				}
				else
				{
					memcpy(pout + nout, Aout, outlen - nout);
					nout = outlen;
					break;
				}
				if (!HMAC(EVP_sha256(), key, (int)keylen, An_1, 32, An, &mdlen)) // An
					return false;
				memcpy(An_1, An, 32);
			}
			return true;
		}

		void SetCipherParam(uint8_t *pkeyblock, int nsize)
		{
			memcpy(_keyblock, pkeyblock, nsize);
			if (_cipher_suite == TLS_RSA_WITH_AES_128_CBC_SHA256)
			{
				memcpy(_key_cwmac, _keyblock, 32);
				memcpy(_key_swmac, &_keyblock[32], 32);
				memcpy(_key_cw, &_keyblock[64], 16);
				memcpy(_key_sw, &_keyblock[80], 16);
			}
			else if (_cipher_suite == TLS_RSA_WITH_AES_256_CBC_SHA256)
			{
				memcpy(_key_cwmac, _keyblock, 32);
				memcpy(_key_swmac, &_keyblock[32], 32);
				memcpy(_key_cw, &_keyblock[64], 32);
				memcpy(_key_sw, &_keyblock[96], 32);
			}
			else if (_cipher_suite == TLS_RSA_WITH_AES_128_CBC_SHA)
			{
				memcpy(_key_cwmac, _keyblock, 20);
				memcpy(_key_swmac, &_keyblock[20], 20);
				memcpy(_key_cw, &_keyblock[40], 16);
				memcpy(_key_sw, &_keyblock[56], 16);
			}
			else if (_cipher_suite == TLS_RSA_WITH_AES_256_CBC_SHA)
			{
				memcpy(_key_cwmac, _keyblock, 20);
				memcpy(_key_swmac, &_keyblock[20], 20);
				memcpy(_key_cw, &_keyblock[40], 32);
				memcpy(_key_sw, &_keyblock[72], 32);
			}
		}

		bool mkr_ClientHelloMsg(vector<uint8_t>*pout)
		{
			RAND_bytes(_clientrand, sizeof(_clientrand));

			_client_hello.clear();
			_client_hello.add((uint8_t)tls::hsk_client_hello);  // msg type  1byte
			_client_hello.add((uint8_t)0); _client_hello.add((uint8_t)0); _client_hello.add((uint8_t)0); // msg len  3byte 

			_client_hello.add((uint8_t)TLSVER_MAJOR);
			_client_hello.add((uint8_t)TLSVER_NINOR);
			_client_hello.add(_clientrand, 32);// random 32byte 

			_client_hello.add((uint8_t)0);    // SessionID = NULL   1byte

			_client_hello.add((uint8_t)0); _client_hello.add((uint8_t)8); // cipher_suites
			_client_hello.add((uint8_t)0); _client_hello.add((uint8_t)TLS_RSA_WITH_AES_256_CBC_SHA256);
			_client_hello.add((uint8_t)0); _client_hello.add((uint8_t)TLS_RSA_WITH_AES_128_CBC_SHA256);

			_client_hello.add((uint8_t)0); _client_hello.add((uint8_t)TLS_RSA_WITH_AES_256_CBC_SHA);
			_client_hello.add((uint8_t)0); _client_hello.add((uint8_t)TLS_RSA_WITH_AES_128_CBC_SHA);

			_client_hello.add((uint8_t)1); // compression_methods
			_client_hello.add((uint8_t)0);

			*(_client_hello.data() + 3) = (uint8_t)(_client_hello.size() - 4);
			return make_package(pout, tls::rec_handshake, _client_hello.data(), _client_hello.size());
		}

		/*!
		\brief do input bytes from tcp
		return <0 : error if pout not empty is sendback Alert pkg; >0: parse records and pout has decode message
		*/
		int  OnTcpRead(const void* pd, size_t size, vector<uint8_t>* pout) // return TLS_SESSION_XXX
		{
			_pkgtcp.add((const uint8_t*)pd, size);
			uint8_t *p = _pkgtcp.data(), uct, tmp[tls_rec_fragment_len + 2048];
			uint16_t ulen;
			int nl = (int)_pkgtcp.size(), nret = TLS_SESSION_NONE, ndl = 0;
			while (nl >= 5)// type(1byte) version(2byte) length(2byte);
			{
				uct = *p;
				ulen = p[3];
				ulen = (ulen << 8) + p[4];
				if (uct < (uint8_t)tls::rec_change_cipher_spec || uct >(uint8_t)tls::rec_application_data ||
					_pkgtcp[1] != TLSVER_MAJOR || ulen > tls_rec_fragment_len + 48 || _pkgtcp[2] > TLSVER_NINOR)
				{
					if (_plog)
						_plog->add(CLOG_DEFAULT_DBG, "ucid %u protocol error(RECTYPE=%u,TLSVER_MAJOR=%u,TLSVER_NINOR=%u,LEN=%u)!", _ucid,
							uct, _pkgtcp[1], _pkgtcp[2], ulen);
					if (!_breadcipher)
						Alert(2, 70, pout);//protocol_version(70)
					return TLS_SESSION_ERR;
				}
				if (ulen + 5 > nl)
					break;
				if (_breadcipher)
				{
					if (decrypt_record(p, ulen + 5, tmp, &ndl))
					{
						nret = dorecord(tmp, ndl, pout);
						if (nret == TLS_SESSION_ERR)
							return nret;
					}
					else {
						if (_plog) {
							_plog->add(CLOG_DEFAULT_DBG, "ucid %u Alert decode_error(50):record size %u", _ucid, ulen + 5);
							_plog->addbin(CLOG_DEFAULT_DBG, p, ulen > 128 ? 128 : ulen);
						}
						return TLS_SESSION_ERR;
					}
				}
				else
				{
					nret = dorecord(p, (int)ulen + 5, pout);
					if (nret == TLS_SESSION_ERR)
						return nret;
				}
				nl -= (int)ulen + 5;
				p += (int)ulen + 5;
			}
			_pkgtcp.erase(0, _pkgtcp.size() - nl);
			_pkgtcp.shrink(0);
			return nret;
		}
	protected:
		virtual int dorecord(const uint8_t* prec, size_t sizerec, vector<uint8_t>* pout) = 0;
	};


	class tls_session_cli : public tls_session // session for client
	{
	public:
		tls_session_cli(uint32_t ucid, memory* pmem, cLog* plog) : tls_session(false, ucid, pmem, plog), _pkgm(1024 * 20, pmem)
		{
			_bsrvfinished = false;
			_prsa = 0;
			_pevppk = 0;
			_px509 = 0;
			_pubkeylen = 0;
		}
		virtual ~tls_session_cli()
		{
			if (_prsa)
				RSA_free(_prsa);
			if (_pevppk)
				EVP_PKEY_free(_pevppk);
			if (_px509)
				X509_free(_px509);
			_prsa = 0;
			_pevppk = 0;
			_px509 = 0;
		}
	protected:
		bool _bsrvfinished;
		RSA *_prsa;
		EVP_PKEY *_pevppk;
		X509* _px509;
		int _pubkeylen;//The server pubkey length，0 for not use
		unsigned char _pubkey[1024];//The server pubkey is used to verify the server legitimacy
	private:
		vector<uint8_t> _pkgm;
	public:
		bool SetServerPubkey(int len, const unsigned char *pubkey)
		{
			if (!pubkey || len > (int)sizeof(_pubkey))
				return false;
			_pubkeylen = len;
			memcpy(_pubkey, pubkey, len);
			return true;
		}

		bool SetServerCa(const char* scafile)
		{
			Array<uint8_t, 2048> pkey;
			if (!get_cert_pkey(scafile, &pkey))
				return false;
			return SetServerPubkey((int)pkey.size(), pkey.data());
		}

		virtual void Reset()
		{
			tls_session::Reset();
			if (_prsa)
				RSA_free(_prsa);
			if (_pevppk)
				EVP_PKEY_free(_pevppk);
			if (_px509)
				X509_free(_px509);
			_prsa = 0;
			_pevppk = 0;
			_px509 = 0;
			_bsrvfinished = false;
			_pkgm.clear(size_t(0));
		}

		virtual bool MakeAppRecord(ec::vector<uint8_t>*pout, const void* pd, size_t size) //make app data records
		{
			pout->clear();
			if (!_bsrvfinished)
				return false;
			return make_package(pout, tls::rec_application_data, pd, size);
		}
	private:
		bool mkr_ClientKeyExchange(ec::vector<uint8_t> *po)
		{
			unsigned char premasterkey[48], out[512];
			premasterkey[0] = 3;
			premasterkey[1] = 3;
			RAND_bytes(&premasterkey[2], 46); //calculate pre_master_key			

			const char* slab = "master secret";//calculate master_key
			unsigned char seed[128];
			memcpy(seed, slab, strlen(slab));
			memcpy(&seed[strlen(slab)], _clientrand, 32);
			memcpy(&seed[strlen(slab) + 32], _serverrand, 32);
			if (!prf_sha256(premasterkey, 48, seed, (int)strlen(slab) + 64, _master_key, 48))
				return false;

			if (!make_keyblock()) //calculate key_block
				return false;

			int nbytes = RSA_public_encrypt(48, premasterkey, out, _prsa, RSA_PKCS1_PADDING);
			if (nbytes < 0)
				return false;

			_cli_key_exchange.clear();
			_cli_key_exchange.add((unsigned char)(tls::hsk_client_key_exchange));
			uint32_t ulen = nbytes;
			_cli_key_exchange.add((unsigned char)((ulen >> 16) & 0xFF));
			_cli_key_exchange.add((unsigned char)((ulen >> 8) & 0xFF));
			_cli_key_exchange.add((unsigned char)(ulen & 0xFF));
			_cli_key_exchange.add(out, nbytes);

			return make_package(po, tls::rec_handshake, _cli_key_exchange.data(), _cli_key_exchange.size());
		}

		bool OnServerHello(unsigned char* phandshakemsg, size_t size)
		{
			if (size > _srv_hello.capacity())
				return false;
			_srv_hello.clear();
			_srv_hello.add(phandshakemsg, size);

			if (_srv_hello.size() < 40u)
				return false;
			unsigned char* puc = _srv_hello.data();
			uint32_t ulen = puc[1];
			ulen = (ulen << 8) + puc[2];
			ulen = (ulen << 8) + puc[3];

			puc += 6;
			memcpy(_serverrand, puc, 32);
			puc += 32;

			int n = *puc++;
			puc += n;

			if (n + 40 > (int)_srv_hello.size())
				return false;

			_cipher_suite = *puc++;
			_cipher_suite = (_cipher_suite << 8) | *puc++;
			return true;
		}

		bool OnServerCertificate(unsigned char* phandshakemsg, size_t size)
		{
			_srv_certificate.clear();
			_srv_certificate.add(phandshakemsg, size);

			if (!_srv_certificate.size())
				return false;
			const unsigned char* p = _srv_certificate.data(), *pend = 0;
			pend = p + _srv_certificate.size();
			uint32_t ulen = p[7];
			ulen = (ulen << 8) + p[8];
			ulen = (ulen << 8) + p[9];
			p += 10;
			_px509 = d2i_X509(NULL, &p, (long)ulen);//only use first Certificate
			if (!_px509)
				return false;
			if (_pubkeylen) // need to verify the server legitimacy
			{
				bool bok = true;
				int i;
				if (_px509->cert_info->key->public_key->length != _pubkeylen)
					bok = false;
				else {
					for (i = 0; i < _px509->cert_info->key->public_key->length; i++)
					{
						if (_px509->cert_info->key->public_key->data[i] != _pubkey[i])
						{
							bok = false;
							break;
						}
					}
				}
				if (!bok)
				{
					X509_free(_px509);
					_px509 = 0;
					return false;
				}
			}
			_pevppk = X509_get_pubkey(_px509);
			if (!_pevppk)
			{
				X509_free(_px509);
				_px509 = 0;
				return false;
			}
			_prsa = EVP_PKEY_get1_RSA(_pevppk);
			if (!_prsa)
			{
				EVP_PKEY_free(_pevppk);
				X509_free(_px509);
				_pevppk = 0;
				_px509 = 0;
				return false;
			}
			return  true;
		}

		bool  OnServerHelloDone(uint8_t* phandshakemsg, size_t size, vector<uint8_t>* pout)
		{
			_srv_hellodone.clear();
			_srv_hellodone.add(phandshakemsg, size);
			if (!mkr_ClientKeyExchange(pout))
				return false;
			unsigned char change_cipher_spec = 1;// send change_cipher_spec 
			make_package(pout, tls::rec_change_cipher_spec, &change_cipher_spec, 1);
			if (!mkr_ClientFinished(pout))
				return false;
			return true;
		}

		bool OnServerFinished(uint8_t* phandshakemsg, size_t size, vector<uint8_t>* pout)
		{
			const char* slab = "server finished";
			uint8_t hkhash[48];
			memcpy(hkhash, slab, strlen(slab));
			Array<uint8_t, 1024 * 12> tmp;

			tmp.add(_client_hello.data(), _client_hello.size());
			tmp.add(_srv_hello.data(), _srv_hello.size());
			tmp.add(_srv_certificate.data(), _srv_certificate.size());
			tmp.add(_srv_hellodone.data(), _srv_hellodone.size());
			tmp.add(_cli_key_exchange.data(), _cli_key_exchange.size());
			tmp.add(_cli_finished.data(), _cli_finished.size());

			uint8_t verfiy[32];
			SHA256(tmp.data(), tmp.size(), &hkhash[strlen(slab)]); //            
			if (!prf_sha256(_master_key, 48, hkhash, (int)strlen(slab) + 32, verfiy, 32))
				return false;

			int i;
			for (i = 0; i < 12; i++) {
				if (verfiy[i] != phandshakemsg[4 + i]) {
					Alert(2, 40, pout);//handshake_failure(40)
					return false;
				}
			}
			return true;
		}
	protected:
		virtual int dorecord(const uint8_t* prec, size_t sizerec, vector<uint8_t>* pout) // return TLS_SESSION_XXX
		{
			const uint8_t* p = (const uint8_t*)prec;
			uint16_t ulen = p[3];
			ulen = (ulen << 8) + p[4];

			if (p[0] == tls::rec_handshake)
				return dohandshakemsg(p + 5, sizerec - 5, pout);
			else if (p[0] == tls::rec_alert) {
				if (_plog) {
					_plog->add(CLOG_DEFAULT_WRN, "Alert level = %d, AlertDescription = %d,size = %zu", p[5], p[6], sizerec);
					_plog->addbin(CLOG_DEFAULT_DBG, prec, sizerec > 32 ? 32 : sizerec);
				}
			}
			else if (p[0] == tls::rec_change_cipher_spec) {
				_breadcipher = true;
				_seqno_read = 0;
				if (_plog)
					_plog->add(CLOG_DEFAULT_DBG, "server change_cipher_spec");
			}
			else if (p[0] == tls::rec_application_data) {
				pout->add(p + 5, (int)sizerec - 5);
				return TLS_SESSION_APPDATA;
			}
			return TLS_SESSION_NONE;
		}

		int dohandshakemsg(const uint8_t* prec, size_t sizerec, vector<uint8_t>* pout)
		{
			_pkgm.add((const unsigned char*)prec, sizerec);
			int nl = (int)_pkgm.size(), nret = TLS_SESSION_NONE;
			unsigned char* p = _pkgm.data();
			while (nl >= 4)
			{
				uint32_t ulen = p[1];
				ulen = (ulen << 8) + p[2];
				ulen = (ulen << 8) + p[3];
				if (ulen > 1024 * 16)
					return TLS_SESSION_ERR;
				if ((int)ulen + 4 > nl)
					break;
				switch (p[0])
				{
				case tls::hsk_server_hello:
					if (!OnServerHello(p, ulen + 4)) {
						if (_plog)
							_plog->add(CLOG_DEFAULT_DBG, "sever hello package error, size=%u", ulen + 4);
						return TLS_SESSION_ERR;
					}
					break;
				case tls::hsk_certificate:
					if (!OnServerCertificate(p, ulen + 4))
						return TLS_SESSION_ERR;
					break;
				case tls::hsk_server_key_exchange:
					if (_plog)
						_plog->add(CLOG_DEFAULT_DBG, "hsk_server_key_exchange size=%u", ulen + 4);
					break;
				case tls::hsk_certificate_request:
					if (_plog)
						_plog->add(CLOG_DEFAULT_DBG, "hsk_certificate_request size=%u", ulen + 4);
					break;
				case tls::hsk_server_hello_done:
					if (!OnServerHelloDone(p, ulen + 4, pout))
						return TLS_SESSION_ERR;
					break;
				case tls::hsk_finished:
					if (_plog)
						_plog->add(CLOG_DEFAULT_DBG, "hsk_finished size=%u", ulen + 4);
					if (!OnServerFinished(p, ulen + 4, pout))
						return TLS_SESSION_ERR;
					if (_plog)
						_plog->add(CLOG_DEFAULT_DBG, "server hsk_finished chech success");
					_bsrvfinished = true;
					nret = TLS_SESSION_HKOK;
					break;
				default:
					if (_plog)
						_plog->add(CLOG_DEFAULT_ERR, "unkown msgtype = %u", p[0]);
					return TLS_SESSION_ERR;
				}
				nl -= (int)ulen + 4;
				p += (int)ulen + 4;
			}
			_pkgm.erase(0, _pkgm.size() - nl);
			_pkgm.shrink(0);
			return nret;
		}
	};

	class tls_session_srv : public tls_session // session for server
	{
	public:
		tls_session_srv(uint32_t ucid, const void* pcer, size_t cerlen,
			const void* pcerroot, size_t cerrootlen, std::mutex *pRsaLck, RSA* pRsaPrivate, memory* pmem, cLog* plog
		) : tls_session(true, ucid, pmem, plog),
			_pkgm(1024 * 20, pmem)
		{
			_bhandshake_finished = false;
			_pcer = pcer;
			_cerlen = cerlen;
			_pcerroot = pcerroot;
			_cerrootlen = cerrootlen;
			_pRsaLck = pRsaLck;
			_pRsaPrivate = pRsaPrivate;
			memset(_sip, 0, sizeof(_sip));
		}
		virtual ~tls_session_srv()
		{
		}
	protected:
		bool  _bhandshake_finished;
		std::mutex * _pRsaLck;
		RSA* _pRsaPrivate;

		const void* _pcer;
		size_t _cerlen;
		const void* _pcerroot;
		size_t _cerrootlen;
		char _sip[32];
	private:
		vector<uint8_t> _pkgm;
	public:
		void SetIP(const char* sip)
		{
			if (sip && *sip)
				snprintf(_sip, sizeof(_sip), "%s", sip);
		}
		void getip(char *sout, size_t sizeout) {
			snprintf(sout, sizeout, "%s", _sip);
		}
		virtual bool MakeAppRecord(ec::vector<uint8_t>*po, const void* pd, size_t size)
		{
			if (!pd || !size)
				return false;
			po->clear();
			if (!_bhandshake_finished)
				return false;
			return make_package(po, tls::rec_application_data, pd, size);
		}
	protected:
		void MakeServerHello()
		{
			RAND_bytes(_serverrand, sizeof(_serverrand));

			_srv_hello.clear();
			_srv_hello.add((uint8_t)tls::hsk_server_hello);  // msg type  1byte
			_srv_hello.add((uint8_t)0); _srv_hello.add((uint8_t)0); _srv_hello.add((uint8_t)0); // msg len  3byte 

			_srv_hello.add((uint8_t)TLSVER_MAJOR);
			_srv_hello.add((uint8_t)TLSVER_NINOR);
			_srv_hello.add(_serverrand, 32);// random 32byte 

			_srv_hello.add((uint8_t)4);    // SessionID = 4   1byte

			_srv_hello.add((uint8_t)((_ucid >> 24) & 0xFF));
			_srv_hello.add((uint8_t)((_ucid >> 16) & 0xFF));
			_srv_hello.add((uint8_t)((_ucid >> 8) & 0xFF));
			_srv_hello.add((uint8_t)((_ucid >> 0) & 0xFF));

			_srv_hello.add((uint8_t)0); _srv_hello.add((uint8_t)_cipher_suite & 0xFF); //cipher_suites

			_srv_hello.add((uint8_t)0);// compression_methods

			*(_srv_hello.data() + 3) = (uint8_t)(_srv_hello.size() - 4);
		}

		void MakeCertificateMsg()
		{
			_srv_certificate.clear();
			_srv_certificate.add((uint8_t)tls::hsk_certificate);
			_srv_certificate.add((uint8_t)0); _srv_certificate.add((uint8_t)0); _srv_certificate.add((uint8_t)0);//1,2,3

			uint32_t u;
			if (_pcerroot && _cerrootlen) {
				u = (uint32_t)(_cerlen + _cerrootlen + 6);
				_srv_certificate.add((uint8_t)((u >> 16) & 0xFF)); _srv_certificate.add((uint8_t)((u >> 8) & 0xFF)); _srv_certificate.add((uint8_t)(u & 0xFF));//4,5,6

				u = (uint32_t)_cerlen;
				_srv_certificate.add((uint8_t)((u >> 16) & 0xFF)); _srv_certificate.add((uint8_t)((u >> 8) & 0xFF)); _srv_certificate.add((uint8_t)(u & 0xFF));//7,8,9
				_srv_certificate.add((const uint8_t*)_pcer, _cerlen);

				u = (uint32_t)_cerrootlen;
				_srv_certificate.add((uint8_t)((u >> 16) & 0xFF)); _srv_certificate.add((uint8_t)((u >> 8) & 0xFF)); _srv_certificate.add((uint8_t)(u & 0xFF));
				_srv_certificate.add((const uint8_t*)_pcerroot, _cerrootlen);
			}
			else {
				u = (uint32_t)_cerlen + 3;
				_srv_certificate.add((uint8_t)((u >> 16) & 0xFF)); _srv_certificate.add((uint8_t)((u >> 8) & 0xFF)); _srv_certificate.add((uint8_t)(u & 0xFF));//4,5,6

				u = (uint32_t)_cerlen;
				_srv_certificate.add((uint8_t)((u >> 16) & 0xFF)); _srv_certificate.add((uint8_t)((u >> 8) & 0xFF)); _srv_certificate.add((uint8_t)(u & 0xFF));//7,8,9
				_srv_certificate.add((const uint8_t*)_pcer, _cerlen);
			}

			u = (uint32_t)_srv_certificate.size() - 4;
			*(_srv_certificate.data() + 1) = (uint8_t)((u >> 16) & 0xFF);
			*(_srv_certificate.data() + 2) = (uint8_t)((u >> 8) & 0xFF);
			*(_srv_certificate.data() + 3) = (uint8_t)((u >> 0) & 0xFF);
		}

		bool OnClientHello(uint8_t* phandshakemsg, size_t size, vector<uint8_t>* po)
		{
			if (size > _client_hello.capacity())
				return false;
			_client_hello.clear();
			_client_hello.add(phandshakemsg, size);

			unsigned char* puc = phandshakemsg, uct;
			size_t ulen = puc[1];
			ulen = (ulen << 8) + puc[2];
			ulen = (ulen << 8) + puc[3];

			if (size != ulen + 4 || size < 12 + 32) {
				Alert(2, 10, po);//unexpected_message(10)
				return false;
			}
			if (puc[4] != TLSVER_MAJOR || puc[5] < TLSVER_NINOR) {
				if (_plog)
					_plog->add(CLOG_DEFAULT_DBG, "client Hello Ver %d.%d", puc[4], puc[5]);
				Alert(2, 70, po);//protocol_version(70),
				return false;
			}
			ec::cStream ss(phandshakemsg, size);
			unsigned short i, cipherlen = 0;
			try {
				ss.setpos(6).read(_clientrand, 32) >> uct; //session id len
				if (uct > 0)
					ss.setpos(ss.getpos() + uct);
				ss > &cipherlen;
			}
			catch (int) { return false; }
			if (ss.getpos() + cipherlen > size) {
				Alert(2, 10, po);//unexpected_message(10)
				return false;
			}
			_cipher_suite = 0;
			unsigned char* pch = phandshakemsg + ss.getpos();
			if (_plog) {
				ec::Array<char, 1024> ao;
				char stmp[32];
				for (i = 0; i < cipherlen && i < 32; i += 2) {
					snprintf(stmp, sizeof(stmp), "(%02X,%02X) ", pch[i], pch[i + 1]);
					ao.add(stmp, strlen(stmp));
				}
				ao.add(char(0));
				_plog->add(CLOG_DEFAULT_DBG, "client ciphers=%s ", ao.data());
			}
			for (i = 0; i < cipherlen; i += 2) {
				if (pch[i] == 0 && (pch[i + 1] == TLS_RSA_WITH_AES_128_CBC_SHA256 || pch[i + 1] == TLS_RSA_WITH_AES_256_CBC_SHA256
					|| pch[i + 1] == TLS_RSA_WITH_AES_128_CBC_SHA || pch[i + 1] == TLS_RSA_WITH_AES_256_CBC_SHA)
					) {
					_cipher_suite = pch[i + 1];
					break;
				}
			}
			if (!_cipher_suite) {
				Alert(2, 40, po);//handshake_failure(40)
				return false;
			}
			if (_plog)
				_plog->add(CLOG_DEFAULT_DBG, "server cipher = (%02x,%02x)", (_cipher_suite >> 8) & 0xFF, _cipher_suite & 0xFF);

			MakeServerHello();
			MakeCertificateMsg();
			uint8_t umsg[4] = { tls::hsk_server_hello_done,0,0,0 };
			make_package(po, tls::rec_handshake, _srv_hello.data(), _srv_hello.size());// ServerHello     
			make_package(po, tls::rec_handshake, _srv_certificate.data(), _srv_certificate.size());//Certificate
			_srv_hellodone.clear();
			_srv_hellodone.add(umsg, 4);
			make_package(po, tls::rec_handshake, umsg, 4);//ServerHelloDone
			return true;
		}

		bool OnClientKeyExchange(const uint8_t* pmsg, size_t sizemsg, vector<uint8_t>* po)
		{
			if (sizemsg > _cli_key_exchange.capacity())
				return false;
			_cli_key_exchange.clear();
			_cli_key_exchange.add(pmsg, sizemsg);

			uint32_t ulen = pmsg[1];//private key decode
			ulen = (ulen << 8) | pmsg[2];
			ulen = (ulen << 8) | pmsg[3];

			if (ulen + 4 != sizemsg) {
				Alert(2, 10, po);//unexpected_message(10)
				return false;
			}

			int nbytes = 0;
			unsigned char premasterkey[48];
			if (ulen % 16) {
				uint32_t ulen = pmsg[4];//private key decode
				ulen = (ulen << 8) | pmsg[5];
				_pRsaLck->lock();
				nbytes = RSA_private_decrypt((int)ulen, pmsg + 6, premasterkey, _pRsaPrivate, RSA_PKCS1_PADDING);
				_pRsaLck->unlock();
			}
			else {
				_pRsaLck->lock();
				nbytes = RSA_private_decrypt((int)ulen, pmsg + 4, premasterkey, _pRsaPrivate, RSA_PKCS1_PADDING);
				_pRsaLck->unlock();
			}

			if (nbytes != 48) {
				Alert(2, 21, po);//decryption_failed(21),
				return false;
			}

			const char* slab = "master secret";//calculate master_key
			uint8_t seed[128];
			memcpy(seed, slab, strlen(slab));
			memcpy(&seed[strlen(slab)], _clientrand, 32);
			memcpy(&seed[strlen(slab) + 32], _serverrand, 32);
			if (!prf_sha256(premasterkey, 48, seed, (int)strlen(slab) + 64, _master_key, 48)) {
				Alert(2, 80, po);//internal_error(80),
				return false;
			}

			if (!make_keyblock()) { //calculate key_block			
				Alert(2, 80, po);//internal_error(80),
				return false;
			}
			return true;
		}

		bool OnClientFinish(const uint8_t* pmsg, size_t sizemsg, vector<uint8_t>* po)
		{
			const char* slab = "client finished";
			uint8_t hkhash[48];
			memcpy(hkhash, slab, strlen(slab));
			Array<unsigned char, 1024 * 12> tmp;

			tmp.add(_client_hello.data(), _client_hello.size());
			tmp.add(_srv_hello.data(), _srv_hello.size());
			tmp.add(_srv_certificate.data(), _srv_certificate.size());
			tmp.add(_srv_hellodone.data(), _srv_hellodone.size());
			tmp.add(_cli_key_exchange.data(), _cli_key_exchange.size());

			unsigned char verfiy[32];
			SHA256(tmp.data(), tmp.size(), &hkhash[strlen(slab)]); //
			if (!prf_sha256(_master_key, 48, hkhash, (int)strlen(slab) + 32, verfiy, 32)) {
				Alert(2, 80, po);//internal_error(80),				
				return false;
			}

			size_t len = pmsg[1];
			len = (len << 8) | pmsg[2];
			len = (len << 8) | pmsg[3];

			if (len + 4 != sizemsg || len != 12) {
				Alert(2, 10, po);//unexpected_message(10)
				return false;
			}
			int i;
			for (i = 0; i < 12; i++) {
				if (verfiy[i] != pmsg[4 + i]) {
					Alert(2, 40, po);//handshake_failure(40)
					return false;
				}
			}

			unsigned char change_cipher_spec = 1;//send change_cipher_spec 			
			make_package(po, tls::rec_change_cipher_spec, &change_cipher_spec, 1);

			_seqno_send = 0;
			_bsendcipher = true;
			_cli_finished.clear();
			_cli_finished.add(pmsg, sizemsg);
			if (_plog)
				_plog->add(CLOG_DEFAULT_DBG, "rec_change_cipher_spec success!");
			if (!mkr_ServerFinished(po))
				return false;
			if (_plog)
				_plog->add(CLOG_DEFAULT_DBG, "ClientFinished success!");
			return true;
		}

		virtual int dorecord(const uint8_t* prec, size_t sizerec, vector<uint8_t>* po) // return TLS_SESSION_XXX
		{
			const unsigned char* p = (const unsigned char*)prec;
			uint16_t ulen = p[3];
			ulen = (ulen << 8) + p[4];

			if (p[0] == tls::rec_handshake)
				return dohandshakemsg(p + 5, sizerec - 5, po);
			else if (p[0] == tls::rec_alert) {
				if (_plog) {
					_plog->add(CLOG_DEFAULT_DBG, "Alert level = %d,AlertDescription = %d,size = %zu", p[5], p[6], sizerec);
					_plog->addbin(CLOG_DEFAULT_DBG, prec, sizerec > 32 ? 32 : sizerec);
				}
			}
			else if (p[0] == tls::rec_change_cipher_spec) {
				_breadcipher = true;
				_seqno_read = 0;
				if (_plog)
					_plog->add(CLOG_DEFAULT_DBG, "srv: change_cipher_spec");
			}
			else if (p[0] == tls::rec_application_data) {
				po->add(p + 5, (int)sizerec - 5);
				return TLS_SESSION_APPDATA;
			}
			return TLS_SESSION_NONE;
		}

		int dohandshakemsg(const uint8_t* prec, size_t sizerec, vector<uint8_t>* po)
		{
			_pkgm.add((const unsigned char*)prec, sizerec);
			int nl = (int)_pkgm.size(), nret = TLS_SESSION_NONE;
			unsigned char* p = _pkgm.data();
			while (nl >= 4)
			{
				uint32_t ulen = p[1];
				ulen = (ulen << 8) + p[2];
				ulen = (ulen << 8) + p[3];
				if (ulen > 8192) {
					if (_plog)
						_plog->add(CLOG_DEFAULT_ERR, "srvtls ucid %u read handshake message datasize error size=%u", _ucid, ulen);
					return TLS_SESSION_ERR;
				}
				if ((int)ulen + 4 > nl)
					break;
				switch (p[0])
				{
				case tls::hsk_client_hello:
					if (_plog)
						_plog->add(CLOG_DEFAULT_DBG, "srvtls ucid %u read hsk_client_hello size=%u", _ucid, ulen + 4);
					if (!OnClientHello(p, ulen + 4, po)) {
						if (_plog)
							_plog->add(CLOG_DEFAULT_ERR, "srvtls ucid %u client hsk_client_hello failed", _ucid);
						return -1;
					}
					break;
				case tls::hsk_client_key_exchange:
					if (_plog)
						_plog->add(CLOG_DEFAULT_DBG, "srvtls ucid %u read hsk_client_key_exchange size=%u", _ucid, ulen + 4);
					if (!OnClientKeyExchange(p, ulen + 4, po)) {
						if (_plog)
							_plog->add(CLOG_DEFAULT_ERR, "srvtls ucid %u client hsk_client_key_exchange failed", _ucid);
						return TLS_SESSION_ERR;
					}
					break;
				case tls::hsk_finished:
					if (_plog)
						_plog->add(CLOG_DEFAULT_DBG, "srvtls ucid %u read hsk_finished size=%u", _ucid, ulen + 4);
					if (!OnClientFinish(p, ulen + 4, po)) {
						if (_plog)
							_plog->add(CLOG_DEFAULT_ERR, "srvtls ucid %u client hsk_finished failed", _ucid);
						return -1;
					}
					_bhandshake_finished = true;
					nret = TLS_SESSION_HKOK;
					break;
				default:
					if (_plog)
						_plog->add(CLOG_DEFAULT_DBG, "srvtls ucid %u unkown msgtype=%u", _ucid, p[0]);
					return -1;
				}
				nl -= (int)ulen + 4;
				p += (int)ulen + 4;
			}
			_pkgm.erase(0, _pkgm.size() - nl);
			_pkgm.shrink(0);			
			return nret;
		}
	};

	struct t_tls_session
	{
		memory* pmem;
		tls_session_srv* Pss;
	};

	template<>
	struct key_equal<uint32_t, t_tls_session>
	{
		bool operator()(uint32_t key, const t_tls_session& val)
		{
			return key == val.Pss->get_ucid();
		}
	};

	template<>
	struct del_node<t_tls_session>
	{
		void operator()(t_tls_session& val)
		{
			if (val.Pss)
			{
				if (val.pmem) {
					val.Pss->~tls_session_srv();
					val.pmem->mem_free(val.Pss);
				}
				else
					delete val.Pss;
				val.Pss = nullptr;
			}
		}
	};

	class sessiontlsmap
	{
	public:
		sessiontlsmap(uint32_t maxconnect) :
			_memmap(ec::map<uint32_t, t_tls_session>::size_node(), 8192, 0, 0, 0, 0, &_mem_lock),
			_memcls(sizeof(tls_session_srv), maxconnect, 0, 0, 0, 0, &_cscls),
			_map(11 + (uint32_t)(2048), &_memmap)
		{
		}
		~sessiontlsmap()
		{
			_map.clear();
		}
		memory* getclsmem() {
			return &_memcls;
		}
	private:
		ec::spinlock _mem_lock;// lock for _memmap
		ec::memory _memmap;// memory for send

		ec::spinlock _cscls;// lock for _mem
		ec::memory _memcls;// memory for tls_session_srv
	protected:
		unsigned int _ugroups;
		map<uint32_t, t_tls_session> _map;
		ec::spinlock _cs;
	public:
		void Add(uint32_t ucid, tls_session_srv* ps)
		{
			unique_spinlock lck(&_cs);
			t_tls_session v;
			v.pmem = &_memcls;
			v.Pss = ps;
			_map.set(v.Pss->get_ucid(), v);
		}
		void Del(uint32_t ucid)
		{
			unique_spinlock lck(&_cs);
			_map.erase(ucid);
		}

		int OnTcpRead(uint32_t ucid, const void* pd, size_t dsize, vector<uint8_t>* pout)
		{
			unique_spinlock lck(&_cs);
			t_tls_session* pv = _map.get(ucid);
			if (pv)
				return pv->Pss->OnTcpRead(pd, dsize, pout);
			pout->clear();
			return TLS_SESSION_NONE;
		}
		bool mkr_appdata(uint32_t ucid, ec::vector<uint8_t>*po, const void* pd, size_t len)
		{
			t_tls_session* pv = _map.get(ucid);
			if (pv)
				return pv->Pss->MakeAppRecord(po, pd, len);
			return false;
		}
		inline ec::spinlock* getcs() {
			return &_cs;
		}
	};

	class tls_srvca
	{
	public:
		RSA * _pRsaPub;
		RSA* _pRsaPrivate;

		EVP_PKEY *_pevppk;
		X509* _px509;

		Array<uint8_t, 4096> _pcer;
		Array<uint8_t, 4096> _prootcer;

		std::mutex _csRsa;
	public:
		tls_srvca() :_pRsaPub(nullptr), _pRsaPrivate(nullptr), _pevppk(nullptr), _px509(nullptr) {
		}
		~tls_srvca() {
			if (_pRsaPrivate)
				RSA_free(_pRsaPrivate);
			if (_pRsaPub)
				RSA_free(_pRsaPub);
			if (_pevppk)
				EVP_PKEY_free(_pevppk);
			if (_px509)
				X509_free(_px509);
			_pRsaPub = nullptr;
			_pRsaPrivate = nullptr;
			_pevppk = nullptr;
			_px509 = nullptr;
		}
		bool InitCert(const char* filecert, const char* filerootcert, const char* fileprivatekey)
		{
			unsigned char stmp[4096];
			FILE* pf = fopen(filecert, "rb");
			if (!pf)
				return false;
			size_t size;
			_pcer.clear();
			_prootcer.clear();
			while (!feof(pf))
			{
				size = fread(stmp, 1, sizeof(stmp), pf);
				_pcer.add(stmp, size);
			}
			fclose(pf);

			if (filerootcert && *filerootcert)
			{
				pf = fopen(filerootcert, "rb");
				if (!pf)
					return false;

				while (!feof(pf))
				{
					size = fread(stmp, 1, sizeof(stmp), pf);
					_prootcer.add(stmp, size);
				}
				fclose(pf);
			}

			pf = fopen(fileprivatekey, "rb");
			if (!pf)
				return false;

			_pRsaPrivate = PEM_read_RSAPrivateKey(pf, 0, NULL, NULL);
			fclose(pf);

			const unsigned char* p = _pcer.data();
			_px509 = d2i_X509(NULL, &p, (long)_pcer.size());//only use first Certificate
			if (!_px509)
				return false;

			_pevppk = X509_get_pubkey(_px509);
			if (!_pevppk)
			{
				X509_free(_px509);
				_px509 = 0;
				return false;
			}
			_pRsaPub = EVP_PKEY_get1_RSA(_pevppk);
			if (!_pRsaPub)
			{
				EVP_PKEY_free(_pevppk);
				X509_free(_px509);
				_pevppk = 0;
				_px509 = 0;
				return false;
			}
			return true;
		}
	};
}// ec
