/*!
\file c_tls.h
\version 0.01
TLS 1.2 (rfc5246) safe channel client

ec library is free C++ library.
\author jiangyong

support:
CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA256 = { 0x00,0x3C };
CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA256 = { 0x00,0x3D };
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

#include <time.h>
#include "c_str.h"
#include "c_thread.h"
#include "c_event.h"
#include "c_tcp_tl.h"
#include "c_critical.h"
#include "c_stream.h"
#include "c_array.h"
#include "ec/c_trace.h"
#include "openssl/rand.h"
#include "openssl/x509.h"
#include "openssl/hmac.h"
#include "openssl/aes.h"

/*!
\brief CipherSuite
*/
#define TLS_RSA_WITH_AES_128_CBC_SHA256 0x3C
#define TLS_RSA_WITH_AES_256_CBC_SHA256 0x3D
#define TLS_COMPRESS_NONE   0

#define TLSVER_MAJOR        3
#define TLSVER_NINOR        3
extern unsigned int g_uidseqno;

#define TLS_CBCBLKSIZE  16303 // (16384-16-32-1-32)
namespace ec
{
    class cTlsHandshakeProtocol;
    class cTlsClient;

    /*!
    \brief Record Protocol
    */
    class cTlsRecordProtocol //
    {
    public:
        cTlsRecordProtocol() : _pkg(1024 * 20), _send(1024 * 20) {
            _seqno_send = 0;
            _seqno_read = 0;
            _cipher = 0;
            _breadcipher = false;
            _bsendcipher = false;
            memset(_keyblock, 0, sizeof(_keyblock));
        }
    protected:
        bool   _breadcipher; // read(server)start use cipher
        bool   _bsendcipher; // write(client)start use cipher

        uint64 _seqno_send;
        uint64 _seqno_read;
        ec::tArray<unsigned char> _pkg;
        ec::tArray<unsigned char> _send;

        unsigned short _cipher;
        unsigned char _keyblock[256];

        unsigned char _key_wmac[32];// client_write_MAC_key
        unsigned char _key_rmac[32];// server_write_MAC_key

        unsigned char _key_w[32]; // client_write_key
        unsigned char _key_r[32]; // server_write_key

        friend class cTlsHandshakeProtocol;
        friend class cTlsClient;
    protected:
        void Reset()
        {
            _breadcipher = false;
            _bsendcipher = false;

            _seqno_send = 0;
            _seqno_read = 0;
            _cipher = 0;
            memset(_keyblock, 0, sizeof(_keyblock));
            _pkg.ClearData();
        }
        void SetCipherParam(unsigned short chiper, unsigned char *pkeyblock, int nsize)
        {
            _cipher = chiper;
            memcpy(_keyblock, pkeyblock, nsize);
            memcpy(_key_wmac, _keyblock, 32);
            memcpy(_key_rmac, &_keyblock[32], 32);
            if (_cipher == TLS_RSA_WITH_AES_128_CBC_SHA256)
            {
                memcpy(_key_w, &_keyblock[64], 16);
                memcpy(_key_r, &_keyblock[80], 16);
            }
            else
            {
                memcpy(_key_w, &_keyblock[64], 32);
                memcpy(_key_r, &_keyblock[96], 32);
            }
        }

        int  OnRead(const void* pd, size_t size, bool(*dorecord)(void*, const void*, int), void* pParam)
        {
            _pkg.Add((const unsigned char*)pd, size);
            unsigned char *p = _pkg.GetBuf(), uct, tmp[tls_rec_fragment_len + 2048];
            uint16 ulen;
            int nl = _pkg.GetNum(), nrec = 0, ndl = 0;
            while (nl >= 5)
            {
                uct = *p;
                ulen = p[3];
                ulen = (ulen << 8) + p[4];
                if (uct < (uint8)tls::rec_contenttype::rec_change_cipher_spec || uct >(uint8)tls::rec_contenttype::rec_application_data ||
                    _pkg[1] != TLSVER_MAJOR || _pkg[2] != TLSVER_NINOR || ulen > tls_rec_fragment_len + 2048)
                    return -1;
                if (ulen + 5 > nl)
                    break;
                if (_breadcipher)
                {
                    if (!decrypt_record(p, ulen + 5, tmp, &ndl))
                        return -1;
                    if (!dorecord(pParam, tmp, ndl))
                        return -1;
                }
                else
                {
                    if (!dorecord(pParam, p, (int)ulen + 5))
                        return -1;
                }
                nrec++;
                nl -= (int)ulen + 5;
                p += (int)ulen + 5;
            }
            _pkg.LeftMove(_pkg.GetNum() - nl);
            return nrec;
        }

        bool Send(SOCKET sock, int nprotocol, const void* pd, size_t size) //发送
        {
            if (_bsendcipher && *((unsigned char*)pd) != (unsigned char)tls::rec_contenttype::rec_alert)
                return send_cipher(sock, (unsigned char)nprotocol, (const unsigned char*)pd, size);
            return send_nocipher(sock, nprotocol, pd, size);
        }
    private:
        bool caldatahmac(unsigned char type, uint64 seqno, const void* pd, size_t len, unsigned char* pkeymac, unsigned char *outmac)
        {
            int i;
            unsigned char  stmp[1024 * 20];
            ec::cStream es(stmp, sizeof(stmp));

            for (i = 7; i >= 0; i--)
                es << (char)((seqno >> i * 8) & 0xFF);

            es << type; //type
            es << (char)TLSVER_MAJOR; //ver            
            es << (char)TLSVER_NINOR; //ver            

            es << (char)((len >> 8) & 0xFF);
            es << (char)(len & 0xFF); // len

            es.write(pd, len); // data

            unsigned int mdlen = 0;
            return HMAC(EVP_sha256(), pkeymac, 32, stmp, es.getpos(), outmac, &mdlen) != NULL;
        }

        bool decrypt_record(unsigned char*pd, size_t len, unsigned char* pout, int *poutsize)
        {
            int i;
            unsigned char sout[1024 * 20], iv[AES_BLOCK_SIZE];
            AES_KEY aes_d;
            int nkeybit = 128;
            if (_cipher == TLS_RSA_WITH_AES_256_CBC_SHA256)
                nkeybit = 256;

            memcpy(iv, pd + 5, AES_BLOCK_SIZE);//Decrypt
            if (AES_set_decrypt_key(_key_r, nkeybit, &aes_d) < 0)
                return false;
            AES_cbc_encrypt((const unsigned char*)pd + 5 + AES_BLOCK_SIZE, (unsigned char*)sout, len - 5 - AES_BLOCK_SIZE, &aes_d, iv, AES_DECRYPT);

            unsigned int ufsize = sout[len - 5 - AES_BLOCK_SIZE - 1];//verify data MAC
            size_t datasize = len - 5 - AES_BLOCK_SIZE - 1 - ufsize - 32;
            unsigned char mac[32], macsrv[32];
            memcpy(macsrv, &sout[datasize], 32);
            if (!caldatahmac(pd[0], _seqno_read, sout, datasize, _key_rmac, mac))
                return false;
            for (i = 0; i < 32; i++) {
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
        bool decrypt_record2(unsigned char*pd, size_t len, ec::tArray<unsigned char>* pout)
        {
            int i;
            unsigned char sout[1024 * 20], iv[AES_BLOCK_SIZE];
            AES_KEY aes_d;
            int nkeybit = 128;
            if (_cipher == TLS_RSA_WITH_AES_256_CBC_SHA256)
                nkeybit = 256;

            memcpy(iv, pd + 5, AES_BLOCK_SIZE);//Decrypt
            if (AES_set_decrypt_key(_key_r, nkeybit, &aes_d) < 0)
                return false;
            AES_cbc_encrypt((const unsigned char*)pd + 5 + AES_BLOCK_SIZE, (unsigned char*)sout, len - 5 - AES_BLOCK_SIZE, &aes_d, iv, AES_DECRYPT);

            unsigned int ufsize = sout[len - 5 - AES_BLOCK_SIZE - 1];//verify data MAC
            size_t datasize = len - 5 - AES_BLOCK_SIZE - 1 - ufsize - 32;
            unsigned char mac[32], macsrv[32];
            memcpy(macsrv, &sout[datasize], 32);
            if (!caldatahmac(pd[0], _seqno_read, sout, datasize, _key_rmac, mac))
                return false;
            for (i = 0; i < 32; i++) {
                if (mac[i] != macsrv[i])
                    return false;
            }

            pout->Add(pd, 5);
            pout->Add(sout, datasize);
            *(pout->GetBuf() + 3) = ((datasize >> 8) & 0xFF);
            *(pout->GetBuf() + 4) = (datasize & 0xFF);
            _seqno_read++;
            return true;
        }

        int SendWithAES_BLK(SOCKET sock, unsigned char type, const unsigned char* sblk, size_t size)
        {
            int i;
            _send.ClearData();
            _send.Add(type);
            _send.Add(TLSVER_MAJOR); _send.Add(TLSVER_NINOR); // ver3,3
            _send.Add((unsigned char)0); _send.Add((unsigned char)0);
            unsigned char IV[AES_BLOCK_SIZE];//rand IV

            RAND_bytes(IV, AES_BLOCK_SIZE);
            _send.Add(IV, AES_BLOCK_SIZE);

            unsigned char mac[32];
            if (!caldatahmac(type, _seqno_send, sblk, size, _key_wmac, mac))
                return false;

            unsigned char stmp[1024 * 20];
            ec::cStream es(stmp, sizeof(stmp));

            es.write(sblk, size); //content
            es.write(mac, 32); //MAC 
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
            if (_cipher == TLS_RSA_WITH_AES_256_CBC_SHA256)
                nkeybit = 256;
            if (AES_set_encrypt_key(_key_w, nkeybit, &aes_e) < 0)
                return -1;
            unsigned char sout_e[1024 * 18];
            AES_cbc_encrypt(stmp, sout_e, es.getpos(), &aes_e, IV, AES_ENCRYPT);

            _send.Add(sout_e, es.getpos());
            unsigned short uslen = (unsigned short)(es.getpos() + sizeof(IV));

            *(_send.GetBuf() + 3) = (unsigned char)((uslen >> 8) & 0xFF);
            *(_send.GetBuf() + 4) = (unsigned char)(uslen & 0xFF);

            if (ec::tcp_send(sock, _send.GetBuf(), (int)_send.GetSize()) != (int)_send.GetSize())
            {
                ECTRACE("SendWithChiper_BLK failed!\n");
                return -1;
            }
            _seqno_send++;
            return (int)_send.GetSize();
        }

        bool send_cipher(SOCKET sock, unsigned char rectype, const unsigned char* pdata, size_t size)
        {
            int ns = 0;
            size_t us = 0;//TLS_CBCBLKSIZE 
            while (us < size)
            {
                if (us + TLS_CBCBLKSIZE < size)
                {
                    ns = SendWithAES_BLK(sock, rectype, pdata + us, TLS_CBCBLKSIZE);
                    if (ns < 0)
                        return false;
                    us += TLS_CBCBLKSIZE;
                }
                else
                {
                    ns = SendWithAES_BLK(sock, rectype, pdata + us, size - us);
                    if (ns < 0)
                        return false;
                    us = size;
                    break;
                }
            }
            return true;
        }

        bool send_nocipher(SOCKET sock, int nprotocol, const void* pd, size_t size)
        {
            unsigned char s[tls_rec_fragment_len + 2048];
            const uint8 *puc = (const uint8 *)pd;
            size_t pos = 0, ss;

            s[0] = (uint8)nprotocol;
            s[1] = 3;
            s[2] = 3;
            while (pos < size)
            {
                ss = tls_rec_fragment_len;
                if (pos + ss > size)
                    ss = size - pos;

                s[3] = (uint8)((ss >> 8) & 0xFF);
                s[4] = (uint8)(ss & 0xFF);
                memcpy(&s[5], puc + pos, ss);

                if (ec::tcp_send(sock, s, (int)(ss + 5)) != (int)(ss + 5))
                    return false;
                pos += ss;
            }
            return true;
        }
    };

    /*!
    \brief Handshake Protocol
    */
    class cTlsHandshakeProtocol
    {
    public:
        cTlsHandshakeProtocol(cTlsRecordProtocol* precord) :
            _pkg(1024 * 16),
            _client_hello(512),
            _srv_hello(512),
            _srv_certificate(4096),
            _srv_key_exchange(1024),
            _srv_certificate_request(128),
            _srv_hellodone(128),
            _cli_key_exchange(1024)
        {
            _prsa = 0;
            _pevppk = 0;
            _px509 = 0;
            memset(_serverrand, 0, sizeof(_serverrand));
            memset(_clientrand, 0, sizeof(_clientrand));
            memset(_master_key, 0, sizeof(_master_key));
            memset(_key_block, 0, sizeof(_key_block));
            _cipher_suite = 0;
            _compress = 0;
            _precord = precord;
            _bsrvfinished = false;

        }
        ~cTlsHandshakeProtocol()
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
        cTlsRecordProtocol* _precord;
        RSA *_prsa;
        EVP_PKEY *_pevppk;
        X509* _px509 = 0;
        ec::tArray<unsigned char> _pkg;
        ec::tArray<unsigned char> _client_hello;
        ec::tArray<unsigned char> _srv_hello;
        ec::tArray<unsigned char> _srv_certificate;
        ec::tArray<unsigned char> _srv_key_exchange;
        ec::tArray<unsigned char> _srv_certificate_request;
        ec::tArray<unsigned char> _srv_hellodone;
        ec::tArray<unsigned char> _cli_key_exchange;

        unsigned char _serverrand[32];
        unsigned char _clientrand[32];
        uint16 _cipher_suite;
        uint8  _compress;

        unsigned char _master_key[48];
        unsigned char _key_block[256];
        friend class cTlsClient;
    private:
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
            _compress = *puc;
        }

        void OnServerCertificate(unsigned char* phandshakemsg, size_t size)
        {
            _srv_certificate.ClearData();
            _srv_certificate.Add(phandshakemsg, size);
            ec::tArray<unsigned char>*pmsg = &_srv_certificate;

#if defined(_WIN32) && defined(_DEBUG)
            ECTRACE("server certificate size=%u\n", (unsigned int)size);
            trace_server_certificate(pmsg);
#endif
            if (!pmsg || !pmsg->GetBuf() || !pmsg->GetSize())
                return;
            const unsigned char* p = pmsg->GetBuf(), *pend = 0;
            pend = p + pmsg->GetSize();
            uint32 ulen = p[7];
            ulen = (ulen << 8) + p[8];
            ulen = (ulen << 8) + p[9];
            p += 10;
            _px509 = d2i_X509(NULL, &p, (long)ulen);//only use first Certificate
            if (_px509)
            {
                _pevppk = X509_get_pubkey(_px509);
                if (!_pevppk)
                {
                    X509_free(_px509);
                    _px509 = 0;
                    return;
                }
                _prsa = EVP_PKEY_get1_RSA(_pevppk);
                if (!_prsa)
                {
                    EVP_PKEY_free(_pevppk);
                    X509_free(_px509);
                    _pevppk = 0;
                    _px509 = 0;
                    return;
                }
            }
            ECTRACE("ServerCertificate success!\n");
        }
        void OnServerKeyExchange(unsigned char* phandshakemsg, size_t size)
        {
            _srv_key_exchange.ClearData();
            _srv_key_exchange.Add(phandshakemsg, size);
            ECTRACE("server key_exchange size=%u\n", (unsigned int)size);
        }
        void OnCertificateRequest(unsigned char* phandshakemsg, size_t size)
        {
            _srv_certificate_request.ClearData();
            _srv_certificate_request.Add(phandshakemsg, size);
            ECTRACE("server certificate_request size=%u\n", (unsigned int)size);
        }
        bool  OnServerHelloDone(SOCKET s, unsigned char* phandshakemsg, size_t size)
        {
            _srv_hellodone.ClearData();
            _srv_hellodone.Add(phandshakemsg, size);
            ECTRACE("server hellodone size=%u\n", (unsigned int)size);

            if (!SendClientKeyExchange(s))
                return false;
            ECTRACE("OnClientKeyExchange success!\n");

            unsigned char change_cipher_spec = 1;//send change_cipher_spec 
            int nr = _precord->Send(s, tls::rec_change_cipher_spec, &change_cipher_spec, 1);
            if (nr < 0)
                return false;
            ECTRACE("rec_change_cipher_spec success!\n");
            return SendClientFinished(s); // send Finished
        }
        bool SendClientFinished(SOCKET s)
        {
            const char* slab = "client finished";
            unsigned char hkhash[48];
            memcpy(hkhash, slab, strlen(slab));
            ec::tArray<unsigned char> tmp(8192);

            tmp.Add(_client_hello.GetBuf(), _client_hello.GetSize());
            tmp.Add(_srv_hello.GetBuf(), _srv_hello.GetSize());
            tmp.Add(_srv_certificate.GetBuf(), _srv_certificate.GetSize());
            tmp.Add(_srv_key_exchange.GetBuf(), _srv_key_exchange.GetSize());
            tmp.Add(_srv_hellodone.GetBuf(), _srv_hellodone.GetSize());
            tmp.Add(_cli_key_exchange.GetBuf(), _cli_key_exchange.GetSize());

            unsigned char verfiy[32], sdata[32];
            SHA256(tmp.GetBuf(), tmp.GetSize(), &hkhash[strlen(slab)]); //            
            if (!prf_sha256(_master_key, 48, hkhash, strlen(slab) + 32, verfiy, 32))
                return false;

            sdata[0] = tls::hsk_finished;
            sdata[1] = 0;
            sdata[2] = 0;
            sdata[3] = 12;
            memcpy(&sdata[4], verfiy, 12);

            _precord->_seqno_send = 0;
            _precord->_bsendcipher = true;
            if (!_precord->Send(s, tls::rec_handshake, sdata, 16))
                return false;
            ECTRACE("OnClientFinished success!\n");
            return  true;
        }

        bool SendClientKeyExchange(SOCKET s)
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

            _cli_key_exchange.ClearData();
            _cli_key_exchange.Add((unsigned char)(tls::handshaketype::hsk_client_key_exchange));
            uint32 ulen = nbytes;
            _cli_key_exchange.Add((unsigned char)((ulen >> 16) & 0xFF));
            _cli_key_exchange.Add((unsigned char)((ulen >> 8) & 0xFF));
            _cli_key_exchange.Add((unsigned char)(ulen & 0xFF));
            _cli_key_exchange.Add(out, nbytes);

            return _precord->Send(s, tls::rec_handshake, _cli_key_exchange.GetBuf(), _cli_key_exchange.GetSize());
        }

        bool make_keyblock()
        {
            const char *slab = "key expansion";
            unsigned char seed[128];

            memcpy(seed, slab, strlen(slab));
            memcpy(&seed[strlen(slab)], _serverrand, 32);
            memcpy(&seed[strlen(slab) + 32], _clientrand, 32);

            int nout = 128;
            if (TLS_RSA_WITH_AES_128_CBC_SHA256 == _cipher_suite)
                nout = 96;// 32 + 32 + 16 + 16
            if (!prf_sha256(_master_key, 48, seed, (int)strlen(slab) + 64, _key_block, nout))
                return false;

            _precord->SetCipherParam(_cipher_suite, _key_block, nout);
            return true;
        }

        bool SendClientHelloMsg(SOCKET s)
        {
            RAND_bytes(_clientrand, sizeof(_clientrand));

            _client_hello.ClearData();
            _client_hello.Add((uint8)tls::handshaketype::hsk_client_hello);  // msg type  1byte
            _client_hello.Add((uint8)0); _client_hello.Add((uint8)0); _client_hello.Add((uint8)0); // msg len  3byte 

            _client_hello.Add((uint8)TLSVER_MAJOR);
            _client_hello.Add((uint8)TLSVER_NINOR);
            _client_hello.Add(_clientrand, 32);// random 32byte 

            _client_hello.Add((uint8)0);    // SessionID = NULL   1byte

            _client_hello.Add((uint8)0); _client_hello.Add((uint8)4); // cipher_suites
            _client_hello.Add((uint8)0); _client_hello.Add((uint8)TLS_RSA_WITH_AES_256_CBC_SHA256);
            _client_hello.Add((uint8)0); _client_hello.Add((uint8)TLS_RSA_WITH_AES_128_CBC_SHA256);

            _client_hello.Add((uint8)1); // compression_methods
            _client_hello.Add((uint8)0);

            *(_client_hello.GetBuf() + 3) = (uint8)(_client_hello.GetSize() - 4);
            return _precord->Send(s, tls::rec_handshake, _client_hello.GetBuf(), _client_hello.GetSize());
        }
    public:
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
    protected:
        void Reset()
        {
            _pkg.ClearData();
            _client_hello.ClearData();
            _srv_hello.ClearData();
            _srv_certificate.ClearData();
            _srv_key_exchange.ClearData();
            _srv_certificate_request.ClearData();
            _srv_hellodone.ClearData();
            _cli_key_exchange.ClearData();

            if (_prsa)
                RSA_free(_prsa);
            if (_pevppk)
                EVP_PKEY_free(_pevppk);
            if (_px509)
                X509_free(_px509);
            _prsa = 0;
            _pevppk = 0;
            _px509 = 0;

            memset(_serverrand, 0, sizeof(_serverrand));
            memset(_clientrand, 0, sizeof(_clientrand));
            memset(_master_key, 0, sizeof(_master_key));
            memset(_key_block, 0, sizeof(_key_block));

            _cipher_suite = 0;
            _compress = 0;
            _bsrvfinished = false;
        }

        int OnRead(SOCKET s, const void* pd, size_t size) // return done messages,-1 error
        {
            _pkg.Add((const unsigned char*)pd, size);
            int nl = _pkg.GetNum(), nrec = 0;
            unsigned char* p = _pkg.GetBuf();
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
                    OnServerCertificate(p, ulen + 4);
                    break;
                case tls::hsk_server_key_exchange:
                    OnServerKeyExchange(p, ulen + 4);
                    break;
                case tls::hsk_certificate_request:
                    OnCertificateRequest(p, ulen + 4);
                    break;
                case tls::hsk_server_hello_done:
                    if (!OnServerHelloDone(s, p, ulen + 4))
                        return -1;
                    break;
                case tls::hsk_finished:
                    ECTRACE("** server hsk_finished size=%u\n", ulen + 4);
                    _bsrvfinished = true;
                    break;
                default:
                    ECTRACE("unkown msgtype=%u\n", p[0]);
                    return -1;
                }
                nrec++;
                nl -= (int)ulen + 4;
                p += (int)ulen + 4;
            }
            _pkg.LeftMove(_pkg.GetNum() - nl);
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
            for (i = 0; i < 32; i++)
                ECTRACE("%02X ", *puc++);
            ECTRACE("\n");

            int n = *puc++;
            ECTRACE("    session_id: len=%d ;val=\n    ", n);
            for (i = 0; i < n; i++)
                ECTRACE("%02X ", *puc++);
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
    };

    /*!
    \brief  TLS client auto reconnet

    TLS Protocal V1.2
    */
    class cTlsClient : public cThread
    {
    public:
        cTlsClient() :
            _Chandshake(&_Crecord),
            _pkgrec(1024 * 20)
        {
            _sock = INVALID_SOCKET;
            _nreconnectsec = 5;
            _lastconnectfailed = 0;
            _connecttimeout = 15;
        };
        virtual ~cTlsClient() {};
    protected:
        char _sip[30];
        unsigned short _wport;

        int _nsocketerr;
        int     _connecttimeout;
        time_t  _lastconnectfailed;
        int     _nreconnectsec;// reconnect interval seconds
        ec::cEvent _evtwait;
        volatile  SOCKET _sock;
        cCritical   _cssend;
        cTlsRecordProtocol      _Crecord;
        cTlsHandshakeProtocol   _Chandshake;
        ec::tArray<unsigned char> _pkgrec;

        char _readbuf[tls_rec_fragment_len + 2048];
    protected:
        void closetcpsocket()
        {            
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
            _lastconnectfailed = 0;
            _Crecord.Reset();
            _Chandshake.Reset();
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
            ec::str_ncpy(_sip, sip, sizeof(_sip));
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
            if (!_Chandshake._bsrvfinished || INVALID_SOCKET == _sock)
                return false;
            return _Crecord.Send(_sock, tls::rec_contenttype::rec_application_data, pd, size);
        }
    protected:
        virtual void OnConnected() = 0; // after TLS channel build
        virtual void OnDisConnected(int where, int nerrcode) = 0;// where:1 disconnected ;-1 connect failed ;  nerrcode:system error
        virtual void OnRead(const void* pd, int nsize) = 0; // app data
    private:
        static bool DoRecord(void* pParam, const void* pd, int nsize)
        {
            cTlsClient* pcls = (cTlsClient*)pParam;
            return pcls->DoRecPkg(pd, nsize);
        }
        bool OnTcpConnected()
        {
            ec::SetSocketKeepAlive(_sock);
            Reset();
            return _Chandshake.SendClientHelloMsg(_sock);
        }

        /*!
        \brief do data on tcp layer
        \remark return false will disconnect tcp
        */
        bool OnTcpRead(const void* pd, int nsize)
        {
            ECTRACE("OnTcpRead=%d\n", nsize);
            return _Crecord.OnRead(pd, nsize, DoRecord, this) >= 0;
        }

        bool DoRecPkg(const void* pd, size_t size)
        {
            const unsigned char* p = (const unsigned char*)pd;
            uint16 ulen = p[3];
            ulen = (ulen << 8) + p[4];
            ECTRACE("protocol=%u,ver=(%d,%d),len = %u\n", p[0], p[1], p[2], ulen);

            if (p[0] == tls::rec_contenttype::rec_handshake)
            {
                if (_Chandshake.OnRead(_sock, p + 5, size - 5) < 0)
                    return false;
                if (_Chandshake._bsrvfinished)
                    OnConnected();
            }
            else if (p[0] == tls::rec_contenttype::rec_alert)
            {
                ECTRACE("Alert level = %d,,AlertDescription = %d\n", p[5], p[6]);
            }
            else if (p[0] == tls::rec_contenttype::rec_change_cipher_spec)
            {
                _Crecord._breadcipher = true;
                _Crecord._seqno_read = 0;
                ECTRACE("server change_cipher_spec\n");
            }
            else if (p[0] == tls::rec_contenttype::rec_application_data)
                OnRead(p + 5, (int)size - 5);
            return true;
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

                SOCKET s = tcp_connect(_sip, _wport, _connecttimeout);
                if (s == INVALID_SOCKET)
                {
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
                    closetcpsocket();
            }
            nr = ec::tcp_read(_sock, _readbuf, sizeof(_readbuf), 100);
            while (nr > 0)
            {
                if (!OnTcpRead(_readbuf, nr))
                {
                    nr = -1;
                    break;
                }
                nr = ec::tcp_read(_sock, _readbuf, sizeof(_readbuf), 100);
            }
            if (nr < 0)
            {
                closetcpsocket();
                OnDisConnected(1, _nsocketerr);
               // _lKillTread = 1; //debug 
            }
        };
    };
}
