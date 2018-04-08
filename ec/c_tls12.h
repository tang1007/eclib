/*!
\file c_tls12.h
\author	kipway@outlook.com
\update 2018.4.3 fix RSA_private_decrypt multithread safety

eclib TLS1.2(rfc5246) server and client class
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

typedef unsigned char  uint8;
typedef unsigned short uint16;
typedef unsigned int   uint32;
typedef unsigned long long   uint64;

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
#include "c_str.h"
#include "c_thread.h"
#include "c_event.h"
#include "c_critical.h"
#include "c_stream.h"
#include "c_array.h"
#include "c_trace.h"
#include "c_tcp_tl.h"
#include "c_tcp_srv.h"

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

#define TLS_CBCBLKSIZE  16303 // (16384-16-32-1-32)

#define TLS_SESSION_NONE    (-2) 
#define TLS_SESSION_ERR		(-1) //错误
#define TLS_SESSION_HKOK	0 //成功
#define TLS_SESSION_RET		1 //成功，需要向对方发送输出的数据
#define TLS_SESSION_APPDATA 2 //成功，有APP层数据

namespace ec
{
    /*!
    \brief base class for TLS 1.2 session
    */
    class cTlsSession
    {
    public:
        cTlsSession(bool bserver, unsigned int ucid) :
            _pkgtcp(1024 * 20),
            _client_hello(512),
            _srv_hello(512),
            _srv_certificate(4096),
            _srv_hellodone(128),
            _cli_key_exchange(1024),
            _cli_finished(512)
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
        virtual ~cTlsSession() {};
    protected:
        unsigned int _ucid;
        bool   _bserver;
        bool   _breadcipher; // read start use cipher
        bool   _bsendcipher; // write start use cipher

        uint64 _seqno_send;
        uint64 _seqno_read;
        ec::tArray<unsigned char> _pkgtcp;

        unsigned char _keyblock[256];

        unsigned char _key_cwmac[32];// client_write_MAC_key
        unsigned char _key_swmac[32];// server_write_MAC_key

        unsigned char _key_cw[32];   // client_write_key
        unsigned char _key_sw[32];   // server_write_key

        ec::tArray<unsigned char> _client_hello;
        ec::tArray<unsigned char> _srv_hello;
        ec::tArray<unsigned char> _srv_certificate;
        ec::tArray<unsigned char> _srv_hellodone;
        ec::tArray<unsigned char> _cli_key_exchange;
        ec::tArray<unsigned char> _cli_finished;

        unsigned char _serverrand[32];
        unsigned char _clientrand[32];
        uint16	_cipher_suite;

        unsigned char _master_key[48];
        unsigned char _key_block[256];

    private:
        bool caldatahmac(unsigned char type, uint64 seqno, const void* pd, size_t len, unsigned char* pkeymac, unsigned char *outmac)
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
        /*!
        解密record并校验
        \param pd [in] 完整的record协议
        \param len [in] pd长度
        \param pout [out]输出缓冲区，不小于pd的长度
        \param poutsize[out]实际输出的字节数，成功解密和验证正确后脱壳数据的长度。
        \remark 输出为一个不加密的record包。
        */
        bool decrypt_record(const unsigned char*pd, size_t len, unsigned char* pout, int *poutsize)
        {
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
            size_t maclen = 32;
            if (_cipher_suite == TLS_RSA_WITH_AES_128_CBC_SHA || _cipher_suite == TLS_RSA_WITH_AES_256_CBC_SHA)
                maclen = 20;
            size_t datasize = len - 5 - AES_BLOCK_SIZE - 1 - ufsize - maclen;
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
        virtual int dorecord(const unsigned char* prec, size_t sizerec, int(*OnData)(void*, unsigned int, int, const void*, int), void* pParam) = 0;

        /*!
        加密打包一个基本数据块为record协议
        \param po [out]输出用的动态数组对象指针。
        \param type [in] record协议的子协议枚举值
        \param sblk [in] 被加密的数据块
        \param size [in] 被加密的数据块的字节数
        */
        int MKR_WithAES_BLK(ec::tArray<unsigned char> *po, unsigned char type, const unsigned char* sblk, size_t size)
        {
            int i;
            unsigned char* pkeyw = _key_cw, *pkeywmac = _key_cwmac;
            unsigned char IV[AES_BLOCK_SIZE];//rand IV	

            unsigned char srec[1024 * 20];
            unsigned char sv[1024 * 20];
            unsigned char sout_e[1024 * 20];

            unsigned char mac[32];

            if (_bserver) {
                pkeyw = _key_sw;
                pkeywmac = _key_swmac;
            }

            ec::cStream ss(srec, sizeof(srec));
            try
            {
                RAND_bytes(IV, AES_BLOCK_SIZE);
                ss << type << (unsigned char)TLSVER_MAJOR << (unsigned char)TLSVER_NINOR << (unsigned short)0;
                ss.write(IV, AES_BLOCK_SIZE);
            }
            catch (int) { return -1; }
            if (!caldatahmac(type, _seqno_send, sblk, size, pkeywmac, mac))
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
                ss.setpos(3) < (unsigned short)(es.getpos() + sizeof(IV));
            }
            catch (int)
            {
                return -1;
            }
            po->Add(srec, rl);
            _seqno_send++;
            return (int)rl;
        }

        bool mk_cipher(ec::tArray<unsigned char> *po, unsigned char rectype, const unsigned char* pdata, size_t size)
        {
            int ns = 0;
            size_t us = 0;//TLS_CBCBLKSIZE 
            while (us < size)
            {
                if (us + TLS_CBCBLKSIZE < size)
                {
                    ns = MKR_WithAES_BLK(po, rectype, pdata + us, TLS_CBCBLKSIZE);
                    if (ns < 0)
                        return false;
                    us += TLS_CBCBLKSIZE;
                }
                else
                {
                    ns = MKR_WithAES_BLK(po, rectype, pdata + us, size - us);
                    if (ns < 0)
                        return false;
                    us = size;
                    break;
                }
            }
            return true;
        }

        bool mk_nocipher(ec::tArray<unsigned char> *po, int nprotocol, const void* pd, size_t size)
        {
            unsigned char s[tls_rec_fragment_len + 2048];
            const uint8 *puc = (const uint8 *)pd;
            size_t pos = 0, ss;

            s[0] = (uint8)nprotocol;
            s[1] = TLSVER_MAJOR;
            s[2] = TLSVER_NINOR;
            while (pos < size)
            {
                ss = tls_rec_fragment_len;
                if (pos + ss > size)
                    ss = size - pos;
                s[3] = (uint8)((ss >> 8) & 0xFF);
                s[4] = (uint8)(ss & 0xFF);
                po->Add(s, 5);
                po->Add(puc + pos, ss);
                pos += ss;
            }
            return true;
        }

        bool SendToBuf(ec::tArray<unsigned char> *po, int nprotocol, const void* pd, size_t size) //发送
        {
            if (_bsendcipher && *((unsigned char*)pd) != (unsigned char)tls::rec_alert)
                return mk_cipher(po, (unsigned char)nprotocol, (const unsigned char*)pd, size);
            return mk_nocipher(po, nprotocol, pd, size);
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

        bool mkr_ClientFinished(ec::tArray<unsigned char> *po)
        {
            const char* slab = "client finished";
            unsigned char hkhash[48];
            memcpy(hkhash, slab, strlen(slab));
            ec::tArray<unsigned char> tmp(8192);

            tmp.Add(_client_hello.GetBuf(), _client_hello.GetSize());
            tmp.Add(_srv_hello.GetBuf(), _srv_hello.GetSize());
            tmp.Add(_srv_certificate.GetBuf(), _srv_certificate.GetSize());
            tmp.Add(_srv_hellodone.GetBuf(), _srv_hellodone.GetSize());
            tmp.Add(_cli_key_exchange.GetBuf(), _cli_key_exchange.GetSize());

            unsigned char verfiy[32], sdata[32];
            SHA256(tmp.GetBuf(), tmp.GetSize(), &hkhash[strlen(slab)]); //            
            if (!prf_sha256(_master_key, 48, hkhash, (int)strlen(slab) + 32, verfiy, 32))
                return false;

            sdata[0] = tls::hsk_finished;
            sdata[1] = 0;
            sdata[2] = 0;
            sdata[3] = 12;
            memcpy(&sdata[4], verfiy, 12);

            _seqno_send = 0;
            _bsendcipher = true;

            if (SendToBuf(po, tls::rec_handshake, sdata, 16))
            {
                _cli_finished.ClearData();
                _cli_finished.Add(sdata, 16);
                return true;
            }
            return false;
        }

        bool mkr_ServerFinished(ec::tArray<unsigned char> *po)
        {
            const char* slab = "server finished";
            unsigned char hkhash[48];
            memcpy(hkhash, slab, strlen(slab));
            ec::tArray<unsigned char> tmp(8192);

            tmp.Add(_client_hello.GetBuf(), _client_hello.GetSize());
            tmp.Add(_srv_hello.GetBuf(), _srv_hello.GetSize());
            tmp.Add(_srv_certificate.GetBuf(), _srv_certificate.GetSize());
            tmp.Add(_srv_hellodone.GetBuf(), _srv_hellodone.GetSize());
            tmp.Add(_cli_key_exchange.GetBuf(), _cli_key_exchange.GetSize());
            tmp.Add(_cli_finished.GetBuf(), _cli_finished.GetSize());

            unsigned char verfiy[32], sdata[32];
            SHA256(tmp.GetBuf(), tmp.GetSize(), &hkhash[strlen(slab)]); //            
            if (!prf_sha256(_master_key, 48, hkhash, (int)strlen(slab) + 32, verfiy, 32))
                return false;

            sdata[0] = tls::hsk_finished;
            sdata[1] = 0;
            sdata[2] = 0;
            sdata[3] = 12;
            memcpy(&sdata[4], verfiy, 12);

            _seqno_send = 0;
            _bsendcipher = true;

            return SendToBuf(po, tls::rec_handshake, sdata, 16);
        }

        void Alert(unsigned char level, unsigned char desval, int(*OnData)(void*, unsigned int, int, const void*, int), void* pParam)
        {
            unsigned char u[8] = { (unsigned char)tls::rec_alert,TLSVER_MAJOR ,TLSVER_NINOR ,0,2,level,desval,0 };
            OnData(pParam, _ucid, TLS_SESSION_RET, u, 7);
        }
    public:
        virtual bool MakeAppRecord(ec::tArray<unsigned char>*po, const void* pd, size_t size) = 0;
        virtual void Reset()
        {
            _breadcipher = false;
            _bsendcipher = false;

            _seqno_send = 0;
            _seqno_read = 0;
            _cipher_suite = 0;

            _pkgtcp.ClearData();
            _client_hello.ClearData();
            _srv_hello.ClearData();
            _srv_certificate.ClearData();
            _srv_hellodone.ClearData();
            _cli_key_exchange.ClearData();

            memset(_keyblock, 0, sizeof(_keyblock));
            memset(_serverrand, 0, sizeof(_serverrand));
            memset(_clientrand, 0, sizeof(_clientrand));
            memset(_master_key, 0, sizeof(_master_key));
            memset(_key_block, 0, sizeof(_key_block));
        }
        /*!
        计算RPF
        PRF(secret,label,seed) = P_sha256(secret,label + seed)
        \param key [in]  密数secret
        \param keylen [in]  密数secret的字节数
        \param seed [in] label+seed合并后的数据
        \param seedlen [in] label+seed合并后的数据字节数
        \param pout [out] 输出区
        \param outlen [in] 输出字节数,即需要扩展到的字节数。
        */
        static bool prf_sha256(const unsigned char* key, int keylen, const unsigned char* seed, int seedlen, unsigned char *pout, int outlen)
        {
            int nout = 0;
            unsigned int mdlen = 0;
            unsigned char An[32], Aout[32], An_1[32];
            if (!HMAC(EVP_sha256(), key, (int)keylen, seed, seedlen, An_1, &mdlen)) // A1
                return false;
            ec::cAp as(32 + seedlen);
            unsigned char *ps = (unsigned char *)as;
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

        void SetCipherParam(unsigned char *pkeyblock, int nsize)
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

        bool mkr_ClientHelloMsg(ec::tArray<unsigned char>*po)
        {
            RAND_bytes(_clientrand, sizeof(_clientrand));

            _client_hello.ClearData();
            _client_hello.Add((uint8)tls::hsk_client_hello);  // msg type  1byte
            _client_hello.Add((uint8)0); _client_hello.Add((uint8)0); _client_hello.Add((uint8)0); // msg len  3byte 

            _client_hello.Add((uint8)TLSVER_MAJOR);
            _client_hello.Add((uint8)TLSVER_NINOR);
            _client_hello.Add(_clientrand, 32);// random 32byte 

            _client_hello.Add((uint8)0);    // SessionID = NULL   1byte

            _client_hello.Add((uint8)0); _client_hello.Add((uint8)8); // cipher_suites
            _client_hello.Add((uint8)0); _client_hello.Add((uint8)TLS_RSA_WITH_AES_256_CBC_SHA256);
            _client_hello.Add((uint8)0); _client_hello.Add((uint8)TLS_RSA_WITH_AES_128_CBC_SHA256);

            _client_hello.Add((uint8)0); _client_hello.Add((uint8)TLS_RSA_WITH_AES_256_CBC_SHA);
            _client_hello.Add((uint8)0); _client_hello.Add((uint8)TLS_RSA_WITH_AES_128_CBC_SHA);

            _client_hello.Add((uint8)1); // compression_methods
            _client_hello.Add((uint8)0);

            *(_client_hello.GetBuf() + 3) = (uint8)(_client_hello.GetSize() - 4);
            return SendToBuf(po, tls::rec_handshake, _client_hello.GetBuf(), _client_hello.GetSize());
        }
        
        int  OnTcpRead(const void* pd, size_t size, int(*OnData)(void*, unsigned int, int, const void*, int), void* pParam)
        {
            _pkgtcp.Add((const unsigned char*)pd, size);
            unsigned char *p = _pkgtcp.GetBuf(), uct, tmp[tls_rec_fragment_len + 2048];
            uint16 ulen;
            int nl = _pkgtcp.GetNum(), nrec = 0, ndl = 0;
            while (nl >= 5)
            {
                uct = *p;
                ulen = p[3];
                ulen = (ulen << 8) + p[4];
                if (uct < (uint8)tls::rec_change_cipher_spec || uct >(uint8)tls::rec_application_data ||
                    _pkgtcp[1] != TLSVER_MAJOR || ulen > tls_rec_fragment_len + 2048)
                {
                    if (_pkgtcp[1] != TLSVER_MAJOR)
                    {
                        ECTRACE("not support Ver %d.%d\n", _pkgtcp[1], _pkgtcp[2]);
                        Alert(2, 70, OnData, pParam);//protocol_version(70)
                    }
                    return -1;
                }
                if (ulen + 5 > nl)
                    break;
                if (_breadcipher)
                {
                    if (!decrypt_record(p, ulen + 5, tmp, &ndl))
                    {
                        Alert(2, 50, OnData, pParam);//decode_error(50)						
                        return -1;
                    }
                    if (dorecord(tmp, ndl, OnData, pParam) < 0)
                        return -1;
                }
                else
                {
                    if (dorecord(p, (int)ulen + 5, OnData, pParam) < 0)
                        return -1;
                }
                nrec++;
                nl -= (int)ulen + 5;
                p += (int)ulen + 5;
            }
            _pkgtcp.LeftMove(_pkgtcp.GetNum() - nl);
            return nrec;
        }

        void trace_serverhello(ec::tArray<unsigned char>*pmsg)
        {
            if (!pmsg || !pmsg->GetBuf() || !pmsg->GetSize())
                return;
            int i;
            unsigned char* puc = pmsg->GetBuf();
            uint32 ulen = puc[1];
            ulen = (ulen << 8) + puc[2];
            ulen = (ulen << 8) + puc[3];

            ECTRACE("server hello:msgtype=%u;len=%u\n", puc[0], ulen);
            ECTRACE("    version=(%d,%d):\n", puc[4], puc[5]);

            puc += 6;
            ECTRACE("    random=\n    ");
            for (i = 0; i < 32; i++) {
                ECTRACE("%02X ", *puc++);
            }
            ECTRACE("\n");

            int n = *puc++;
            ECTRACE("    session_id: len=%d ;val=\n    ", n);
            for (i = 0; i < n; i++) {
                ECTRACE("%02X ", *puc++);
            }
            ECTRACE("\n");

            ECTRACE("    cipher_suite = %02X,", *puc++); ECTRACE("%02X\n", *puc++);

            ECTRACE("    compression_method = %02X\n", *puc++);
            ECTRACE("\n");
        }

        void trace_server_certificate(ec::tArray<unsigned char>*pmsg)
        {
            if (!pmsg || !pmsg->GetBuf() || !pmsg->GetSize())
                return;
            X509* x = 0;
            const unsigned char* p = pmsg->GetBuf(), *pend = 0;
            pend = p + pmsg->GetSize();

            uint32 ulen = p[7];
            ulen = (ulen << 8) + p[8];
            ulen = (ulen << 8) + p[9];
            p += 10;

            long len = (long)ulen;
            x = d2i_X509(NULL, &p, len);
            while (x)
            {
                EVP_PKEY *evp_pk;
                evp_pk = X509_get_pubkey(x);

                RSA *rsa;
                rsa = EVP_PKEY_get1_RSA(evp_pk);

                RSA_free(rsa);
                EVP_PKEY_free(evp_pk);
                X509_free(x);

                if (p >= pend)
                    break;

                ulen = p[0];
                ulen = (ulen << 8) + p[1];
                ulen = (ulen << 8) + p[2];
                len = (long)ulen;
                p += 3;
                x = d2i_X509(NULL, &p, len);

            }
        }
        void tracebin(const char* snote, const void* pd, size_t len)
        {
            const unsigned char* p = (const unsigned char*)pd;
            size_t i;
            ECTRACE("\n%s\n", snote);
            for (i = 0; i < len; i++)
            {
                if (!(i % 8) && i) {
                    ECTRACE("\n%02X ", p[i]);
                }
                else {
                    ECTRACE("%02X ", p[i]);
                }
            }
        }
    };

    class cTlsSession_cli : public cTlsSession
    {
    public:
        cTlsSession_cli(unsigned int ucid) : cTlsSession(false, ucid), _pkgm(1024 * 20)
        {
            _bsrvfinished = false;
            _prsa = 0;
            _pevppk = 0;
            _px509 = 0;
            _pubkeylen = 0;
        }
        virtual ~cTlsSession_cli()
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
        ec::tArray<unsigned char> _pkgm;
    public:
        bool SetServerPubkey(int len, const unsigned char *pubkey)
        {
            if (!pubkey || len > (int)sizeof(_pubkey))
                return false;
            _pubkeylen = len;
            memcpy(_pubkey, pubkey, len);
            return true;
        }
        virtual void Reset()
        {
            cTlsSession::Reset();
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
            _pkgm.ClearData();
        }

        virtual bool MakeAppRecord(ec::tArray<unsigned char>*po, const void* pd, size_t size) //make app data records
        {
            po->ClearData();
            if (!_bsrvfinished)
                return false;
            return SendToBuf(po, tls::rec_application_data, pd, size);
        }
    private:
        bool mkr_ClientKeyExchange(ec::tArray<unsigned char> *po)
        {
            unsigned char premasterkey[48], out[512];
            premasterkey[0] = 3;
            premasterkey[1] = 3;
            RAND_bytes(&premasterkey[2], 46); //calculate pre_master_key

            tracebin("rand:_clientrand", _clientrand, 32);
            tracebin("rand:_serverrand", _serverrand, 32);

            tracebin("cli:premasterkey", premasterkey, 48);

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

            _cli_key_exchange.ClearData();
            _cli_key_exchange.Add((unsigned char)(tls::hsk_client_key_exchange));
            uint32 ulen = nbytes;
            _cli_key_exchange.Add((unsigned char)((ulen >> 16) & 0xFF));
            _cli_key_exchange.Add((unsigned char)((ulen >> 8) & 0xFF));
            _cli_key_exchange.Add((unsigned char)(ulen & 0xFF));
            _cli_key_exchange.Add(out, nbytes);

            return SendToBuf(po, tls::rec_handshake, _cli_key_exchange.GetBuf(), _cli_key_exchange.GetSize());
        }

        void OnServerHello(unsigned char* phandshakemsg, size_t size)
        {
            _srv_hello.ClearData();
            _srv_hello.Add(phandshakemsg, size);
            ec::tArray<unsigned char>* pmsg = &_srv_hello;
#if defined(_WIN32) && defined(_DEBUG)
            trace_serverhello(pmsg);
#endif
            if (!pmsg || !pmsg->GetBuf() || !pmsg->GetSize())
                return;
            unsigned char* puc = pmsg->GetBuf();
            uint32 ulen = puc[1];
            ulen = (ulen << 8) + puc[2];
            ulen = (ulen << 8) + puc[3];

            puc += 6;
            memcpy(_serverrand, puc, 32);
            puc += 32;

            int n = *puc++;
            puc += n;

            _cipher_suite = *puc++;
            _cipher_suite = (_cipher_suite << 8) | *puc++;
            ECTRACE("cipher = %02x,%02x\n", (_cipher_suite >> 8) & 0xFF, _cipher_suite & 0xFF);
        }

        bool OnServerCertificate(unsigned char* phandshakemsg, size_t size)
        {
            _srv_certificate.ClearData();
            _srv_certificate.Add(phandshakemsg, size);
            ec::tArray<unsigned char>*pmsg = &_srv_certificate;

#if defined(_WIN32) && defined(_DEBUG)
            ECTRACE("server certificate size=%u\n", (unsigned int)size);
            trace_server_certificate(pmsg);
#endif
            if (!pmsg || !pmsg->GetBuf() || !pmsg->GetSize())
                return false;
            const unsigned char* p = pmsg->GetBuf(), *pend = 0;
            pend = p + pmsg->GetSize();
            uint32 ulen = p[7];
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
            ECTRACE("ServerCertificate success!\n");
            return  true;
        }

        bool  OnServerHelloDone(unsigned char* phandshakemsg, size_t size, int(*OnData)(void*, unsigned int, int, const void*, int), void* pParam)
        {
            _srv_hellodone.ClearData();
            _srv_hellodone.Add(phandshakemsg, size);
            ECTRACE("server hellodone size=%u\n", (unsigned int)size);

            ec::tArray<unsigned char> s(1024 * 64);
            if (!mkr_ClientKeyExchange(&s))
                return false;
            if (OnData(pParam, _ucid, TLS_SESSION_RET, s.GetBuf(), s.GetNum()) < 0)
                return false;
            ECTRACE("OnClientKeyExchange success!\n");

            unsigned char change_cipher_spec = 1;//send change_cipher_spec 
            s.ClearData();
            SendToBuf(&s, tls::rec_change_cipher_spec, &change_cipher_spec, 1);
            if (OnData(pParam, _ucid, TLS_SESSION_RET, s.GetBuf(), s.GetNum()) < 0)
                return false;

            ECTRACE("rec_change_cipher_spec success!\n");
            s.ClearData();
            if (!mkr_ClientFinished(&s))
                return false;
            ECTRACE("ClientFinished success!send size = %d\n", s.GetNum());
            return OnData(pParam, _ucid, TLS_SESSION_RET, s.GetBuf(), s.GetNum()) >= 0;
        }

        bool OnServerFinished(unsigned char* phandshakemsg, size_t size, int(*OnData)(void*, unsigned int, int, const void*, int), void* pParam)
        {
            const char* slab = "server finished";
            unsigned char hkhash[48];
            memcpy(hkhash, slab, strlen(slab));
            ec::tArray<unsigned char> tmp(8192);

            tmp.Add(_client_hello.GetBuf(), _client_hello.GetSize());
            tmp.Add(_srv_hello.GetBuf(), _srv_hello.GetSize());
            tmp.Add(_srv_certificate.GetBuf(), _srv_certificate.GetSize());
            tmp.Add(_srv_hellodone.GetBuf(), _srv_hellodone.GetSize());
            tmp.Add(_cli_key_exchange.GetBuf(), _cli_key_exchange.GetSize());
            tmp.Add(_cli_finished.GetBuf(), _cli_finished.GetSize());

            unsigned char verfiy[32];
            SHA256(tmp.GetBuf(), tmp.GetSize(), &hkhash[strlen(slab)]); //            
            if (!prf_sha256(_master_key, 48, hkhash, (int)strlen(slab) + 32, verfiy, 32))
                return false;

            int i;
            for (i = 0; i < 12; i++) {
                if (verfiy[i] != phandshakemsg[4 + i]) {
                    Alert(2, 40, OnData, pParam);//handshake_failure(40)
                    return false;
                }
            }
            return true;
        }
    protected:
        virtual int dorecord(const unsigned char* prec, size_t sizerec, int(*OnData)(void*, unsigned int, int, const void*, int), void* pParam)
        {
            const unsigned char* p = (const unsigned char*)prec;
            uint16 ulen = p[3];
            ulen = (ulen << 8) + p[4];
            ECTRACE("protocol=%u,ver=(%d,%d),len = %u\n", p[0], p[1], p[2], ulen);

            if (p[0] == tls::rec_handshake)
            {
                if (dohandshakemsg(p + 5, sizerec - 5, OnData, pParam) < 0)
                    return -1;
            }
            else if (p[0] == tls::rec_alert)
            {
                ECTRACE("Alert level = %d,,AlertDescription = %d\n", p[5], p[6]);
            }
            else if (p[0] == tls::rec_change_cipher_spec)
            {
                _breadcipher = true;
                _seqno_read = 0;
                ECTRACE("server change_cipher_spec\n");
            }
            else if (p[0] == tls::rec_application_data)
                return OnData(pParam, _ucid, TLS_SESSION_APPDATA, p + 5, (int)sizerec - 5);
            return 0;
        }

        int dohandshakemsg(const unsigned char* prec, size_t sizerec, int(*OnData)(void*, unsigned int, int, const void*, int), void* pParam)
        {
            _pkgm.Add((const unsigned char*)prec, sizerec);
            int nl = _pkgm.GetNum(), nrec = 0;
            unsigned char* p = _pkgm.GetBuf();
            while (nl >= 4)
            {
                uint32 ulen = p[1];
                ulen = (ulen << 8) + p[2];
                ulen = (ulen << 8) + p[3];
                if ((int)ulen + 4 > nl)
                    break;
                switch (p[0])
                {
                case tls::hsk_server_hello:
                    OnServerHello(p, ulen + 4);
                    break;
                case tls::hsk_certificate:
                    if (!OnServerCertificate(p, ulen + 4))
                    {
                        OnData(pParam, _ucid, TLS_SESSION_ERR, 0, 0);
                        return -1;
                    }
                    break;
                case tls::hsk_server_key_exchange:
                    ECTRACE("hsk_server_key_exchange size=%u\n", ulen + 4);
                    break;
                case tls::hsk_certificate_request:
                    ECTRACE("hsk_certificate_request size=%u\n", ulen + 4);
                    break;
                case tls::hsk_server_hello_done:
                    if (!OnServerHelloDone(p, ulen + 4, OnData, pParam))                                            
                        return -1;                    
                    break;
                case tls::hsk_finished:
                    ECTRACE("** server hsk_finished size=%u\n", ulen + 4);
                    if (!OnServerFinished(p, ulen + 4, OnData, pParam))
                    {
                        OnData(pParam, _ucid, TLS_SESSION_ERR, 0, 0);
                        ECTRACE("** server hsk_finished chech failed\n");
                        return -1;
                    }
                    ECTRACE("server hsk_finished chech success\n");
                    _bsrvfinished = true;
                    OnData(pParam, _ucid, TLS_SESSION_HKOK, 0, 0);
                    break;
                default:
                    ECTRACE("unkown msgtype=%u\n", p[0]);
                    return -1;
                }
                nrec++;
                nl -= (int)ulen + 4;
                p += (int)ulen + 4;
            }
            _pkgm.LeftMove(_pkgm.GetNum() - nl);
            return nrec;
        }
    };

    class cTlsSession_srv : public cTlsSession
    {
    public:
        cTlsSession_srv(unsigned int ucid, const void* pcer, size_t cerlen,
            const void* pcerroot, size_t cerrootlen, cCritical* pRsaLck, RSA* pRsaPrivate
        ) : cTlsSession(true, ucid),
            _pkgm(1024 * 20)
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
        virtual ~cTlsSession_srv()
        {
        }
    protected:
        bool  _bhandshake_finished;
        cCritical* _pRsaLck;
        RSA* _pRsaPrivate;

        const void* _pcer;
        size_t _cerlen;
        const void* _pcerroot;
        size_t _cerrootlen;
        ec::tArray<unsigned char> _pkgm;
        char _sip[20];
    public:
        void SetIP(const char* sip)
        {
            if (sip && *sip)
                str_ncpy(_sip, sip, sizeof(_sip));
        }
        virtual bool MakeAppRecord(ec::tArray<unsigned char>*po, const void* pd, size_t size)
        {
			if (!pd || !size)
				return false;
            po->ClearData();
            if (!_bhandshake_finished)
                return false;
            return SendToBuf(po, tls::rec_application_data, pd, size);
        }
    protected:
        void MakeServerHello()
        {
            RAND_bytes(_serverrand, sizeof(_serverrand));

            _srv_hello.ClearData();
            _srv_hello.Add((uint8)tls::hsk_server_hello);  // msg type  1byte
            _srv_hello.Add((uint8)0); _srv_hello.Add((uint8)0); _srv_hello.Add((uint8)0); // msg len  3byte 

            _srv_hello.Add((uint8)TLSVER_MAJOR);
            _srv_hello.Add((uint8)TLSVER_NINOR);
            _srv_hello.Add(_serverrand, 32);// random 32byte 

            _srv_hello.Add((uint8)4);    // SessionID = 4   1byte

            _srv_hello.Add((uint8)((_ucid >> 24) & 0xFF));
            _srv_hello.Add((uint8)((_ucid >> 16) & 0xFF));
            _srv_hello.Add((uint8)((_ucid >> 8) & 0xFF));
            _srv_hello.Add((uint8)((_ucid >> 0) & 0xFF));

            _srv_hello.Add((uint8)0); _srv_hello.Add((uint8)_cipher_suite & 0xFF); //cipher_suites

            _srv_hello.Add((uint8)0);// compression_methods

            *(_srv_hello.GetBuf() + 3) = (uint8)(_srv_hello.GetSize() - 4);
        }

        void MakeCertificateMsg()
        {
            _srv_certificate.ClearData();
            _srv_certificate.Add((uint8)tls::hsk_certificate);
            _srv_certificate.Add((uint8)0); _srv_certificate.Add((uint8)0); _srv_certificate.Add((uint8)0);//1,2,3

            uint32 u;
            if (_pcerroot && _cerrootlen)
            {
                u = (uint32)(_cerlen + _cerrootlen + 6);
                _srv_certificate.Add((uint8)((u >> 16) & 0xFF)); _srv_certificate.Add((uint8)((u >> 8) & 0xFF)); _srv_certificate.Add((uint8)(u & 0xFF));//4,5,6

                u = (uint32)_cerlen;
                _srv_certificate.Add((uint8)((u >> 16) & 0xFF)); _srv_certificate.Add((uint8)((u >> 8) & 0xFF)); _srv_certificate.Add((uint8)(u & 0xFF));//7,8,9
                _srv_certificate.Add((const uint8*)_pcer, _cerlen);

                u = (uint32)_cerrootlen;
                _srv_certificate.Add((uint8)((u >> 16) & 0xFF)); _srv_certificate.Add((uint8)((u >> 8) & 0xFF)); _srv_certificate.Add((uint8)(u & 0xFF));
                _srv_certificate.Add((const uint8*)_pcerroot, _cerrootlen);
            }
            else
            {
                u = (uint32)_cerlen + 3;
                _srv_certificate.Add((uint8)((u >> 16) & 0xFF)); _srv_certificate.Add((uint8)((u >> 8) & 0xFF)); _srv_certificate.Add((uint8)(u & 0xFF));//4,5,6

                u = (uint32)_cerlen;
                _srv_certificate.Add((uint8)((u >> 16) & 0xFF)); _srv_certificate.Add((uint8)((u >> 8) & 0xFF)); _srv_certificate.Add((uint8)(u & 0xFF));//7,8,9
                _srv_certificate.Add((const uint8*)_pcer, _cerlen);
            }

            u = _srv_certificate.GetSize() - 4;
            *(_srv_certificate.GetBuf() + 1) = (uint8)((u >> 16) & 0xFF);
            *(_srv_certificate.GetBuf() + 2) = (uint8)((u >> 8) & 0xFF);
            *(_srv_certificate.GetBuf() + 3) = (uint8)((u >> 0) & 0xFF);
        }

        bool OnClientHello(unsigned char* phandshakemsg, size_t size, int(*OnData)(void*, unsigned int, int, const void*, int), void* pParam)
        {
            _client_hello.ClearData();
            _client_hello.Add(phandshakemsg, size);

            unsigned char* puc = phandshakemsg, uct;
            size_t ulen = puc[1];
            ulen = (ulen << 8) + puc[2];
            ulen = (ulen << 8) + puc[3];

            if (size != ulen + 4 || size < 12 + 32)
            {
                Alert(2, 10, OnData, pParam);//unexpected_message(10)
                return false;
            }
            if (puc[4] != TLSVER_MAJOR || puc[5] < TLSVER_NINOR)
            {
                ECTRACE("client Hello Ver %d.%d\n", puc[4], puc[5]);
                Alert(2, 70, OnData, pParam);//protocol_version(70),
                return false;
            }
            ec::cStream ss(phandshakemsg, size);
            unsigned short i, cipherlen = 0;
            try
            {
                ss.setpos(6).read(_clientrand, 32) >> uct; //session id len
                if (uct > 0)
                    ss.setpos(ss.getpos() + uct);
                ss > &cipherlen;
            }
            catch (int) { return false; }
            if (ss.getpos() + cipherlen > size)
            {
                Alert(2, 10, OnData, pParam);//unexpected_message(10)
                return false;
            }
            _cipher_suite = 0;
            unsigned char* pch = phandshakemsg + ss.getpos();
            for (i = 0; i < cipherlen; i += 2)
            {
                ECTRACE("cipher %02X,%02X\n", pch[i], pch[i + 1]);
                if (pch[i] == 0 && (pch[i + 1] == TLS_RSA_WITH_AES_128_CBC_SHA256 || pch[i + 1] == TLS_RSA_WITH_AES_256_CBC_SHA256
                    || pch[i + 1] == TLS_RSA_WITH_AES_128_CBC_SHA || pch[i + 1] == TLS_RSA_WITH_AES_256_CBC_SHA)
                    )
                {
                    _cipher_suite = pch[i + 1];
                    break;
                }
            }
            if (!_cipher_suite)
            {
                Alert(2, 40, OnData, pParam);//handshake_failure(40)
                return false;
            }
            ECTRACE("srv:cipher = %02x,%02x\n", (_cipher_suite >> 8) & 0xFF, _cipher_suite & 0xFF);
            // ServerHello,  Certificate,     ServerHelloDone			
            MakeServerHello();
            MakeCertificateMsg();
            unsigned char umsg[4] = { tls::hsk_server_hello_done,0,0,0 };
            ec::tArray<unsigned char> rec(1024 * 8192);
            SendToBuf(&rec, tls::rec_handshake, _srv_hello.GetBuf(), _srv_hello.GetSize());
            SendToBuf(&rec, tls::rec_handshake, _srv_certificate.GetBuf(), _srv_certificate.GetSize());
            _srv_hellodone.ClearData();
            _srv_hellodone.Add(umsg, 4);
            SendToBuf(&rec, tls::rec_handshake, umsg, 4);
            OnData(pParam, _ucid, TLS_SESSION_RET, rec.GetBuf(), rec.GetNum());
            return true;
        }

        bool OnClientKeyExchange(const unsigned char* pmsg, size_t sizemsg, int(*OnData)(void*, unsigned int, int, const void*, int), void* pParam)
        {
            _cli_key_exchange.ClearData();
            _cli_key_exchange.Add(pmsg, sizemsg);

            uint32 ulen = pmsg[1];//private key decode
            ulen = (ulen << 8) | pmsg[2];
            ulen = (ulen << 8) | pmsg[3];

            if (ulen + 4 != sizemsg)
            {
                Alert(2, 10, OnData, pParam);//unexpected_message(10)
                return false;
            }

            int nbytes = 0;
            unsigned char premasterkey[48];
            if (ulen % 16)
            {
                uint32 ulen = pmsg[4];//private key decode
                ulen = (ulen << 8) | pmsg[5];
				_pRsaLck->Lock();
                nbytes = RSA_private_decrypt((int)ulen, pmsg + 6, premasterkey, _pRsaPrivate, RSA_PKCS1_PADDING);
				_pRsaLck->Unlock();
            }
			else
			{
				_pRsaLck->Lock();
				nbytes = RSA_private_decrypt((int)ulen, pmsg + 4, premasterkey, _pRsaPrivate, RSA_PKCS1_PADDING);
				_pRsaLck->Unlock();
			}

            if (nbytes != 48)
            {
                Alert(2, 21, OnData, pParam);//decryption_failed(21),
                return false;
            }

            const char* slab = "master secret";//calculate master_key
            unsigned char seed[128];
            memcpy(seed, slab, strlen(slab));
            memcpy(&seed[strlen(slab)], _clientrand, 32);
            memcpy(&seed[strlen(slab) + 32], _serverrand, 32);
            if (!prf_sha256(premasterkey, 48, seed, (int)strlen(slab) + 64, _master_key, 48))
            {
                Alert(2, 80, OnData, pParam);//internal_error(80),
                return false;
            }

            if (!make_keyblock()) //calculate key_block
            {
                Alert(2, 80, OnData, pParam);//internal_error(80),
                return false;
            }
            return true;
        }

        bool OnClientFinish(const unsigned char* pmsg, size_t sizemsg, int(*OnData)(void*, unsigned int, int, const void*, int), void* pParam)
        {
            const char* slab = "client finished";
            unsigned char hkhash[48];
            memcpy(hkhash, slab, strlen(slab));
            ec::tArray<unsigned char> tmp(8192);

            tmp.Add(_client_hello.GetBuf(), _client_hello.GetSize());
            tmp.Add(_srv_hello.GetBuf(), _srv_hello.GetSize());
            tmp.Add(_srv_certificate.GetBuf(), _srv_certificate.GetSize());
            tmp.Add(_srv_hellodone.GetBuf(), _srv_hellodone.GetSize());
            tmp.Add(_cli_key_exchange.GetBuf(), _cli_key_exchange.GetSize());

            unsigned char verfiy[32];
            SHA256(tmp.GetBuf(), tmp.GetSize(), &hkhash[strlen(slab)]); //
            if (!prf_sha256(_master_key, 48, hkhash, (int)strlen(slab) + 32, verfiy, 32))
            {
                Alert(2, 80, OnData, pParam);//internal_error(80),				
                return false;
            }

            size_t len = pmsg[1];
            len = (len << 8) | pmsg[2];
            len = (len << 8) | pmsg[3];

            if (len + 4 != sizemsg || len != 12)
            {
                Alert(2, 10, OnData, pParam);//unexpected_message(10)
                return false;
            }
            int i;
            for (i = 0; i < 12; i++) {
                if (verfiy[i] != pmsg[4 + i]) {
                    Alert(2, 40, OnData, pParam);//handshake_failure(40)
                    return false;
                }
            }

            unsigned char change_cipher_spec = 1;//send change_cipher_spec 
            tmp.ClearData();
            SendToBuf(&tmp, tls::rec_change_cipher_spec, &change_cipher_spec, 1);
            if (OnData(pParam, _ucid, TLS_SESSION_RET, tmp.GetBuf(), tmp.GetNum()) < 0)
                return false;

            _seqno_send = 0;
            _bsendcipher = true;

            _cli_finished.ClearData();
            _cli_finished.Add(pmsg, sizemsg);
            ECTRACE("rec_change_cipher_spec success!\n");
            tmp.ClearData();
            if (!mkr_ServerFinished(&tmp))
                return false;
            ECTRACE("ClientFinished success! send size %d\n", tmp.GetNum());
            return OnData(pParam, _ucid, TLS_SESSION_RET, tmp.GetBuf(), tmp.GetNum()) >= 0;
        }

        virtual int dorecord(const unsigned char* prec, size_t sizerec, int(*OnData)(void*, unsigned int, int, const void*, int), void* pParam)
        {
            const unsigned char* p = (const unsigned char*)prec;
            uint16 ulen = p[3];
            ulen = (ulen << 8) + p[4];
            ECTRACE("protocol=%u,ver=(%d,%d),len = %u\n", p[0], p[1], p[2], ulen);

            if (p[0] == tls::rec_handshake)
            {
                if (dohandshakemsg(p + 5, sizerec - 5, OnData, pParam) < 0)
                    return -1;
            }
            else if (p[0] == tls::rec_alert)
            {
                ECTRACE("Alert level = %d,,AlertDescription = %d\n", p[5], p[6]);
            }
            else if (p[0] == tls::rec_change_cipher_spec)
            {
                _breadcipher = true;
                _seqno_read = 0;
                ECTRACE("srv: change_cipher_spec\n");
            }
            else if (p[0] == tls::rec_application_data)
                return OnData(pParam, _ucid, TLS_SESSION_APPDATA, p + 5, (int)sizerec - 5);
            return 0;
        }

        int dohandshakemsg(const unsigned char* prec, size_t sizerec, int(*OnData)(void*, unsigned int, int, const void*, int), void* pParam)
        {
            _pkgm.Add((const unsigned char*)prec, sizerec);
            int nl = _pkgm.GetNum(), nrec = 0;
            unsigned char* p = _pkgm.GetBuf();
            while (nl >= 4)
            {
                uint32 ulen = p[1];
                ulen = (ulen << 8) + p[2];
                ulen = (ulen << 8) + p[3];
                if ((int)ulen + 4 > nl)
                    break;
                switch (p[0])
                {
                case tls::hsk_client_hello:
                    ECTRACE("srv:read hsk_client_hello size=%u\n", ulen + 4);
                    if (!OnClientHello(p, ulen + 4, OnData, pParam))
                    {
                        ECTRACE("srv:client hsk_client_hello failed\n");
                        return -1;
                    }
                    break;
                case tls::hsk_client_key_exchange:
                    ECTRACE("srv:read hsk_client_key_exchange size=%u\n", ulen + 4);
                    if (!OnClientKeyExchange(p, ulen + 4, OnData, pParam))
                    {
                        ECTRACE("srv:client hsk_client_key_exchange failed\n");
                        return -1;
                    }
                    break;
                case tls::hsk_finished:
                    ECTRACE("srv:read hsk_finished size=%u\n", ulen + 4);
                    if (!OnClientFinish(p, ulen + 4, OnData, pParam))
                    {
                        ECTRACE("srv:client hsk_finished failed\n");
                        return -1;
                    }
                    _bhandshake_finished = true;
                    OnData(pParam, _ucid, TLS_SESSION_HKOK, _sip, (int)strlen(_sip));
                    break;
                default:
                    ECTRACE("srv:unkown msgtype=%u\n", p[0]);
                    return -1;
                }
                nrec++;
                nl -= (int)ulen + 4;
                p += (int)ulen + 4;
            }
            _pkgm.LeftMove(_pkgm.GetNum() - nl);
            return nrec;
        }
    };
#define TLSC_ST_OFFLINE    (-1) //断线中
#define TLSC_ST_CONING     (0)  //连接中
#define TLSC_ST_SUCCESS    (1)  //通道可用
    /*!
    \brief  TLS client auto reconnet

    TLS Protocal V1.2
    */
    class cTlsClient : public cThread
    {
    public:
        cTlsClient() :
            _tls(0),
            _pkgrec(1024 * 20),
            _pkgsend(1024 * 64)
        {
            _sock = INVALID_SOCKET;
            _nreconnectsec = 5;
            _lastconnectfailed = 0;
            _connecttimeout = 15;

            _nstatus = TLSC_ST_OFFLINE;

            _lastsessionerr = TLS_SESSION_NONE;
        };
        virtual ~cTlsClient() {};
    protected:
        char _sip[30];
        unsigned short _wport;

        volatile int   _nstatus;
        int     _nsocketerr;
        int     _connecttimeout;
        int     _lastsessionerr;
        time_t  _lastconnectfailed;
        int     _nreconnectsec;// reconnect interval seconds
        ec::cEvent _evtwait;
        volatile  SOCKET _sock;
        cTlsSession_cli      _tls;
        ec::tArray<unsigned char> _pkgrec;
        ec::tArray<unsigned char> _pkgsend;

        char _readbuf[tls_rec_fragment_len + 2048];
    protected:
        void closetcpsocket()
        {
            _nstatus = TLSC_ST_OFFLINE;
            Reset();
            if (_sock == INVALID_SOCKET)
                return;

            SOCKET s = _sock;
            _sock = INVALID_SOCKET;
#ifdef _WIN32
            _nsocketerr = WSAGetLastError();
            closesocket(s);
#else
            _nsocketerr = errno;
            close(s);
#endif
        }
        void Reset()
        {
            _lastsessionerr = TLS_SESSION_NONE;
            _tls.Reset();
        }
    public:
        /*!
        \brief Open the TLS channel
        */
        bool Open(const char* sip, unsigned short wport, int reconnectsec = 15)
        {
            if (!sip || !wport)
                return false;

            if (IsRun())
                StopThread();
            ec::str_ncpy(_sip, sip, sizeof(_sip)-1);
            _wport = wport;

            _nreconnectsec = reconnectsec;
            if (_nreconnectsec < 1)
                _nreconnectsec = 1;
            if (_nreconnectsec > 60)
                _nreconnectsec = 60;
            StartThread(0);
            return true;
        }
        void Close()
        {
            StopThread();
        }
        bool Send(const void* pd, size_t size) //send app data
        {
            if (!_tls.MakeAppRecord(&_pkgsend, pd, size) || _sock == INVALID_SOCKET)
                return false;
            return ec::tcp_send(_sock, _pkgsend.GetBuf(), _pkgsend.GetNum()) == _pkgsend.GetNum();
        }
        inline int GetStatus()
        {
            return _nstatus;
        }
    protected:
        virtual void OnConnected() = 0; // after TLS channel build
        virtual void OnDisConnected(int where, int nerrcode) = 0;// where:1 disconnected ;-1 connect failed ;  nerrcode:system error
        virtual void OnRead(const void* pd, int nsize) = 0; // app data
    private:
        bool SendTcp(const void* pd, int dsize)
        {
            if (_sock == INVALID_SOCKET)
                return false;
            return ec::tcp_send(_sock, pd, dsize) == dsize;
        }

        static int OnData(void* pParam, unsigned int ucid, int datamode, const void* pd, int dsize)
        {
            cTlsClient* pcls = (cTlsClient*)pParam;
            if (datamode == TLS_SESSION_ERR)
            {
                pcls->_lastsessionerr = TLS_SESSION_ERR;
                return -1;
            }
            else if (datamode == TLS_SESSION_HKOK)
            {
                pcls->_lastsessionerr = TLS_SESSION_HKOK;
                pcls->_nstatus = TLSC_ST_SUCCESS;
                pcls->OnConnected();
                return 0;
            }
            else if (datamode == TLS_SESSION_RET)
            {
                if (!pcls->SendTcp(pd, dsize))
                    return -1;
            }
            else if (datamode == TLS_SESSION_APPDATA)
            {
                pcls->OnRead(pd, dsize);
                return 0;
            }
            return 0;
        }

        bool OnTcpConnected()
        {
            ec::SetSocketKeepAlive(_sock);
            Reset();
            _pkgsend.ClearData();
            _tls.mkr_ClientHelloMsg(&_pkgsend);
            return ec::tcp_send(_sock, _pkgsend.GetBuf(), _pkgsend.GetNum()) == _pkgsend.GetNum();
        }

        /*!
        \brief do data on tcp layer
        \remark return false will disconnect tcp
        */
        bool OnTcpRead(const void* pd, int nsize)
        {
            ECTRACE("OnTcpRead=%d\n", nsize);
            return _tls.OnTcpRead(pd, nsize, OnData, this) >= 0;
        }

    protected:
        virtual bool OnStart() { return true; };
        virtual void OnStop() {
            closetcpsocket();
        };
        virtual	void dojob() // read and connect
        {
            int nr;
            if (INVALID_SOCKET == _sock)
            {
                time_t tcur = ::time(0);
                if (tcur - _lastconnectfailed < _nreconnectsec)
                {
                    _evtwait.Wait(200);
                    return;
                }
                _nstatus = TLSC_ST_CONING;
                SOCKET s = tcp_connect(_sip, _wport, _connecttimeout);
                if (s == INVALID_SOCKET)
                {
                    _nstatus = TLSC_ST_OFFLINE;

                    _lastconnectfailed = tcur;
                    int nerrcode = 0;
#ifdef _WIN32
                    nerrcode = WSAGetLastError();
                    closesocket(s);
#else
                    nerrcode = errno;
                    close(s);
#endif
                    OnDisConnected(-1, nerrcode);
                    return;
                }
                _lastconnectfailed = tcur;
                _sock = s;

                if (!OnTcpConnected())
                {
                    closetcpsocket();
                    return;
                }
            }
            nr = ec::tcp_read(_sock, _readbuf, sizeof(_readbuf), 100);
            while (nr > 0)
            {
                if (!OnTcpRead(_readbuf, nr))
                {
                    nr = -1;
                    _lastconnectfailed = ::time(0);
                    break;
                }
                nr = ec::tcp_read(_sock, _readbuf, sizeof(_readbuf), 100);
            }
            if (nr < 0)
            {
                if (_lastsessionerr == TLS_SESSION_ERR)
                    _lastconnectfailed = ::time(0);
                closetcpsocket();
                OnDisConnected(1, _nsocketerr);                
            }
        };
    };
    struct t_tlsse
    {
        unsigned int ucid;
        cTlsSession_srv* Pss;
    };
    template<>
    inline bool tMap<unsigned int, t_tlsse>::ValueKey(unsigned int key, t_tlsse* pcls)
    {
        return key == pcls->ucid;
    }
    template<>
    inline void tMap<unsigned int, t_tlsse>::OnRemoveValue(t_tlsse* pcls)
    {
        if (pcls->Pss)
            delete pcls->Pss;
        pcls->Pss = 0;
    }

    class cTlsSession_srvMap
    {
    public:
        cTlsSession_srvMap(unsigned int ugroups)
        {
            _ugroups = ugroups;
            if (_ugroups < 2)
                _ugroups = 2;
            if (_ugroups > 16)
                _ugroups = 16;
            unsigned int i;
            _css = (cCritical**)malloc(sizeof(void*) * _ugroups);
            _maps = (tMap<unsigned int, t_tlsse> **)malloc(sizeof(void*) * _ugroups);
            for (i = 0; i < _ugroups; i++)
            {
                _css[i] = new cCritical;
                _maps[i] = new tMap<unsigned int, t_tlsse>(4096);
            }
        }
        ~cTlsSession_srvMap()
        {
            unsigned int i;
            for (i = 0; i < _ugroups; i++)
            {
                delete _css[i];
                delete _maps[i];
            }
            free(_css);
            free(_maps);
        }
    protected:
        unsigned int _ugroups;
        tMap<unsigned int, t_tlsse> **_maps;
        cCritical **_css;
    public:
        void Add(unsigned int ucid, cTlsSession_srv* ps)
        {
            cSafeLock lck(_css[ucid%_ugroups]);
            t_tlsse v;
            v.ucid = ucid;
            v.Pss = ps;
            _maps[ucid%_ugroups]->SetAt(ucid, v);
        }
        void Del(unsigned int ucid)
        {
            cSafeLock lck(_css[ucid%_ugroups]);
            _maps[ucid%_ugroups]->RemoveKey(ucid);
        }

        int OnTcpRead(unsigned ucid, const void* pd, size_t dsize, int OnData(void* pParam, unsigned int ucid, int datamode, const void* pd, int dsize), void* pParam)
        {
            cSafeLock lck(_css[ucid%_ugroups]);
            t_tlsse* pv = _maps[ucid%_ugroups]->Lookup(ucid);
            if (pv)
                return pv->Pss->OnTcpRead(pd, dsize, OnData, pParam);
            return -1;
        }
        bool mkr_appdata(unsigned int ucid, ec::tArray<unsigned char>*po, const void* pd, size_t len)
        {
            cSafeLock lck(_css[ucid%_ugroups]);
            t_tlsse* pv = _maps[ucid%_ugroups]->Lookup(ucid);
            if (pv)
                return pv->Pss->MakeAppRecord(po, pd, len);
            return false;
        }
    };

    class cTlsSrvThread : public cTcpSvrWorkThread
    {
    public:
        cTlsSrvThread(cTlsSession_srvMap* psss) : _tlsdata(1024 * 128), _tlsrectmp(1024 * 128)
        {
            _psss = psss;
        }
        virtual ~cTlsSrvThread()
        {
        }

        cTlsSession_srvMap* _psss;
	private:
        ec::tArray<unsigned char> _tlsdata;
		ec::tArray<unsigned char> _tlsrectmp;
    protected:
        virtual bool    OnAppData(unsigned int ucid, const void* pd, unsigned int usize) { return true; };
        virtual void    OnHandshakeSuccess(unsigned int ucid, const char* sip) {};
        virtual void    OnDisconnect(unsigned int ucid, unsigned int uopt, int nerrorcode) {};
    protected:
        virtual void	OnClientDisconnect(unsigned int  ucid, unsigned int uopt, int nerrorcode) //uopt = TCPIO_OPT_XXXX
        {
            OnDisconnect(ucid, uopt, nerrorcode);
            _psss->Del(ucid);
        };
        virtual bool	OnReadBytes(unsigned int ucid, const void* pdata, unsigned int usize) //return false will disconnect
        {
            _tlsdata.ClearData();
            int nr = _psss->OnTcpRead(ucid, pdata, usize, OnData, this);
            if (nr < 0)
                return false;
            else if (_tlsdata.GetSize())
            {
                if (!OnAppData(ucid, _tlsdata.GetBuf(), (unsigned int)_tlsdata.GetSize()))
                    return false;
                _tlsdata.ClearData();
            }
            return true;

        };
        virtual	void	DoSelfMsg(unsigned int uevt) {};	// uevt = TCPIO_MSG_XXXX
        virtual	void	OnOptComplete(unsigned int ucid, unsigned int uopt) {};//uopt = TCPIO_OPT_XXXX
        virtual	void	OnOptError(unsigned int ucid, unsigned int uopt) {};   //uopt = TCPIO_OPT_XXXX
    private:
        static int OnData(void* pParam, unsigned int ucid, int datamode, const void* pd, int dsize)
        {
            cTlsSrvThread* pcls = (cTlsSrvThread*)pParam;
            if (datamode == TLS_SESSION_ERR)
                return -1;
            else if (datamode == TLS_SESSION_HKOK)
            {
                if (pd && *((const char*)pd) && dsize)
                    pcls->OnHandshakeSuccess(ucid, (const char*)pd);
                else
                    pcls->OnHandshakeSuccess(ucid, 0);
            }
            else if (datamode == TLS_SESSION_RET)
            {
                if (pcls->SendToUcid(ucid, pd, dsize) < 0)
                    return -1;
                return 0;
            }
            else if (datamode == TLS_SESSION_APPDATA)
            {
                if (pd && dsize)
                    pcls->_tlsdata.Add((const unsigned char*)pd, dsize);                
            }
            return 0;
        }
    protected:
        bool SendAppData(unsigned ucid, const void* pd, size_t len, bool bAddCount = false, unsigned int uSendOpt = TCPIO_OPT_SEND)
        {
			_tlsrectmp.set_grow(len + 264 - len % 8 + (len / 16384) * 256);            
			if (!_psss->mkr_appdata(ucid, &_tlsrectmp, pd, len)) {
				_tlsrectmp.clear();
				_tlsrectmp.shrink(0xFFFFF);
				return false;
			}
            bool bret =  SendToUcid(ucid, _tlsrectmp.GetBuf(), (unsigned int)_tlsrectmp.GetSize(), bAddCount, uSendOpt) > 0;
			_tlsrectmp.clear();
			_tlsrectmp.shrink(0xFFFFF);
			return bret;
        }
    };

    class cTlsServer : public cTcpServer
    {
    public:
        cTlsServer() :_pcer(1024 * 4), _prootcer(1024 * 4), _sss(MAX_TCPWORK_THREAD)
        {
            _pRsaPub = 0;
            _pRsaPrivate = 0;
            _pevppk = 0;
            _px509 = 0;
        }
        virtual ~cTlsServer()
        {
            if (_pRsaPrivate)
                RSA_free(_pRsaPrivate);
            if (_pRsaPub)
                RSA_free(_pRsaPub);
            if (_pevppk)
                EVP_PKEY_free(_pevppk);
            if (_px509)
                X509_free(_px509);

            _pRsaPub = 0;
            _pRsaPrivate = 0;

            _pevppk = 0;
            _px509 = 0;
        }
    protected:
        RSA* _pRsaPub;
        RSA* _pRsaPrivate;

        EVP_PKEY *_pevppk;
        X509* _px509;

        ec::tArray<unsigned char> _pcer;
        ec::tArray<unsigned char> _prootcer;

        cTlsSession_srvMap _sss;
		cCritical _csRsa;
    public:
        bool InitCert(const char* filecert, const char* filerootcert, const char* fileprivatekey)
        {
            unsigned char stmp[4096];
            FILE* pf = fopen(filecert, "rb");
            if (!pf)
                return false;
            size_t size;
            _pcer.ClearData();
            _prootcer.ClearData();
            while (!feof(pf))
            {
                size = fread(stmp, 1, sizeof(stmp), pf);
                _pcer.Add(stmp, size);
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
                    _prootcer.Add(stmp, size);
                }
                fclose(pf);
            }

            pf = fopen(fileprivatekey, "rb");
            if (!pf)
                return false;

            _pRsaPrivate = PEM_read_RSAPrivateKey(pf, 0, NULL, NULL);
            fclose(pf);

            const unsigned char* p = _pcer.GetBuf();
            _px509 = d2i_X509(NULL, &p, (long)_pcer.GetNum());//only use first Certificate
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
    protected:
        virtual void    OnConnected(unsigned int ucid, const char* sip)
        {
            cTlsSession_srv* psession = new cTlsSession_srv(ucid, _pcer.GetBuf(), _pcer.GetSize(),
                _prootcer.GetBuf(), _prootcer.GetSize(), &_csRsa, _pRsaPrivate);
            psession->SetIP(sip);
            _sss.Add(ucid, psession);
        }
        virtual void	OnRemovedUCID(unsigned int ucid)
        {
            _sss.Del(ucid);
        }
        virtual ec::cTcpSvrWorkThread* CreateWorkThread() {
            cTlsSrvThread* pthread = new cTlsSrvThread(&_sss);
            return pthread;
        };
        virtual void    CheckNotLogin() //chech not login 
        {
        }
    };
};
