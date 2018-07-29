/*!
\file c11_rpc.h
\author	jiangyong
\email  kipway@outlook.com
\update 2018.7.19

eclibe Asynchronous Remote Procedure Call  template class for windows & linux

class AioRpcClient
class AioRpcSrv
class AioRpcSrvThread

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
#include "c11_event.h"
#include "c11_vector.h"
#include "c11_tcp.h"
#include "c11_map.h"
#include "c_crc32.h"
#include "c_sha1.h"
#include "c_lz4s.h"   //LZ4 src

#ifdef RPC_USE_ZLIB
#	include "c_zlibs.h"  //ZLIB src
#endif
namespace ec {

	enum RPCMSGTYPE //message type
	{
		rpcmsg_sys = 0, //system message
		rpcmsg_sh = 1,  //handshake message
		rpcmsg_request = 10, //client request
		rpcmsg_put = 11,	 //server put
		rpcmsg_response = 12 //server response
	};

	enum RPCCOMPRESS // compression
	{
		rpccomp_none = 0, //no compression
		rpccomp_lz4 = 1,  //LZ4
#ifdef RPC_USE_ZLIB
		rpccomp_zlib = 2, //ZLIB
#endif
	};

	enum RPCUSRST // client status
	{
		rpcusr_connect = 0,  //connected
		rpcusr_sha1info = 1, //sha1info sended
		rpcusr_pass = 2      //login success
	};

	enum RPC_CLINET_EVT
	{
		rpc_c_connecting = 1,
		rpc_c_login_ok = 0,
		rpc_c_login_usrerr = -1,
		rpc_c_login_pswerr = -2,
		rpc_c_connect_tcperr = -3,
		rpc_c_disconnected_tcp = -4,
		rpc_c_disconnected_msgerr = -5
	};
#define RPC_SYNC_BYTE 0xA9
	struct t_rpcpkg // rpc package
	{
		unsigned char sync;      //start char,0xA9
		char          type;      //msg type,
		char          comp;      //compress,0:none;1:LZ4;2:ZLIB;
		unsigned char cflag;     // D0=1: not encryption
		unsigned int  seqno;     // msg seqno(big-endian)

		unsigned int  size_en;   // encode size(big-endian)
		unsigned int  size_dn;   // decode size or source size (big-endian)

		unsigned int  crc32msg;  //msg CRC32(big-endian) for source data
		unsigned int  crc32head; //head CRC32(big-endian) for sync->crc32msg 20 bytes

		unsigned char msg[];     //message
	};//sizeof() = 24

	class CNetInt
	{
	public:
		static bool IsNetBytesOrder()
		{
			unsigned a = 0x12345678;
			return *((unsigned char*)&a) == 0x12;
		}
		static unsigned int NetUInt(unsigned int v)
		{
			if (IsNetBytesOrder())
				return v;
			return (v << 24) | (v >> 24) | ((v & 0xff00) << 8) | ((v & 0xff0000) >> 8);
		}
		inline static  int NetInt(int v) { return (int)NetUInt(v); }
		static unsigned short NetUShort(unsigned short v)
		{
			if (IsNetBytesOrder())
				return v;
			return (v << 8) | (v >> 8);
		}
		inline static  short NetShort(short v) { return (short)NetUShort(v); }
	};

	struct t_msg_notify
	{
		uint32_t seqno;
		cEvent*  pevt;
		vector<uint8_t>* pmsg;
	};

	template<>
	struct key_equal<uint32_t, t_msg_notify>
	{
		bool operator()(uint32_t key, const t_msg_notify &val)
		{
			return key == val.seqno;
		}
	};

	class msg_notify
	{
	public:
		msg_notify() :_mapmem(ec::map<uint32_t, t_msg_notify>::size_node(), 8) {
		}
		~msg_notify() {
			_map.clear();
		}
	public:
		void add(uint32_t seqno, ec::cEvent *pevt, ec::vector<uint8_t>* pmsgout)
		{
			t_msg_notify nty;
			pevt->ResetEvent();
			nty.seqno = seqno;
			nty.pmsg = pmsgout;
			nty.pevt = pevt;

			_cs.lock();
			_map.set(nty.seqno, nty);
			_cs.unlock();
		}

		bool wait(uint32_t seqno, ec::cEvent *pevt, int timeoutmsec)
		{
			if (!pevt->Wait(timeoutmsec)) {
				_cs.lock();
				_map.erase(seqno); //time over erase from map
				_cs.unlock();
				return false;
			}
			return true;//success , erase from map at trigger
		}
		void del(uint32_t seqno)
		{
			_cs.lock();
			_map.erase(seqno);
			_cs.unlock();
		}
		bool trigger(uint32_t seqno, const uint8_t* pmsg, size_t msglen)
		{
			t_msg_notify nty;
			_cs.lock();
			if (!_map.get(seqno, nty)) {
				_cs.unlock();
				return false;
			}
			_map.erase(seqno);
			_cs.unlock();

			uint32_t gr = (uint32_t)msglen;
			if (gr % 8)
				gr += 8 - msglen % 8;
			nty.pmsg->set_grow(gr);
			nty.pmsg->clear();
			nty.pmsg->add(pmsg, msglen);
			nty.pevt->SetEvent();
			return true;
		}

	private:
		std::mutex _cs;
		memory _mapmem;
		ec::map<uint32_t, t_msg_notify> _map;
	};

	struct t_rpcuserinfo
	{
		unsigned int    _ucid;	     //UCID
		int             _nstatus;    //0:no login; 1:logined
		char            _susr[32];
		char            _psw[40];
		unsigned char   _pswsha1[20];//pass word sha1
		char			_sip[32];    //ip addr
	};

	class cRpcCon // client session
	{
	public:
		cRpcCon() :_ucid(0), _pmem(nullptr), _rbuf(16384, nullptr) {
			_timeconnect = ::time(0);
			memset(_sip, 0, sizeof(_sip));
			memset(_susr, 0, sizeof(_susr));
			_nstatus = 0;
			memset(_psw, 0, sizeof(_psw));
			memset(_pswsha1, 0, sizeof(_pswsha1));
			memset(_srandominfo, 0, sizeof(_srandominfo));
		}
		cRpcCon(unsigned int ucid, const char* sip, memory* pmem) : _pmem(pmem), _rbuf(16384, pmem)
		{
			_timeconnect = ::time(0);
			memset(_sip, 0, sizeof(_sip));
			memset(_susr, 0, sizeof(_susr));
			_ucid = ucid;
			if (sip && *sip)
				snprintf(_sip, sizeof(_sip), "%s", sip);
			_nstatus = 0;
			memset(_psw, 0, sizeof(_psw));
			memset(_pswsha1, 0, sizeof(_pswsha1));
			memset(_srandominfo, 0, sizeof(_srandominfo));
		};
		cRpcCon& operator = (cRpcCon& v)
		{
			_ucid = v._ucid;
			_nstatus = v._nstatus;
			_timeconnect = v._timeconnect;
			memcpy(_susr, v._susr, sizeof(_susr));
			memcpy(_psw, v._psw, sizeof(_psw));
			memcpy(_pswsha1, v._pswsha1, sizeof(_pswsha1));
			memcpy(_sip, v._sip, sizeof(_sip));
			memcpy(_srandominfo, v._srandominfo, sizeof(_srandominfo));
			_rbuf = std::move(v._rbuf);
			return *this;
		}
		~cRpcCon() {};
	public:
		uint32_t _ucid;	     //UCID
		int32_t	_nstatus;    //0:no login; 1:logined
		time_t	_timeconnect;//
		char	_susr[32];
		char	_psw[40];    //pass word
		uint8_t	_pswsha1[20];// password sha1
		char	_sip[32];    //ip addr
		char	_srandominfo[48];//random info,40 bytes
	private:
		memory * _pmem;
		vector<uint8_t>	_rbuf; // read buffer
	public:
		int DoReadData(const uint8_t* pdata, size_t usize, vector<uint8_t>* pout) //return -1:err will diconnect; 0:no message; 1:one message in pout
		{
			pout->clear();
			if (!pdata || !usize || !pout)
				return -1;
			_rbuf.add(pdata, usize);
			return DoLeftData(pout);
		}
		int DoLeftData(vector<uint8_t>* pout)//return -1:error will disconnect ; 0: wait ; 1: one msg checked and Decrypt.
		{
			pout->clear();
			size_t ulen = _rbuf.size();
			if (ulen < sizeof(t_rpcpkg))
				return 0;
			t_rpcpkg* pkg = (t_rpcpkg*)_rbuf.data();//check head
			unsigned int c1 = crc32(_rbuf.data(), 20);
			if (pkg->sync != RPC_SYNC_BYTE || c1 != CNetInt::NetUInt(pkg->crc32head))
				return -1;
			unsigned int sizemsg = CNetInt::NetUInt(pkg->size_en);
			if (ulen < sizemsg + sizeof(t_rpcpkg))
				return 0;
			pout->add(_rbuf.data(), sizemsg + sizeof(t_rpcpkg));
			_rbuf.erase(0, sizemsg + sizeof(t_rpcpkg));
			_rbuf.shrink(0);
			unsigned char* puc = pout->data() + sizeof(t_rpcpkg);
			if (pkg->type >= rpcmsg_request) {
				register unsigned int i;
				if (!(pkg->cflag & 0x01)) {
					unsigned int *pu4 = (unsigned int*)puc, u4 = sizemsg / 4;//Decrypt
					unsigned int *pmk4 = (unsigned int*)_pswsha1;
					for (i = 0; i < u4; i++)
						pu4[i] ^= pmk4[i % 5];
					for (i = u4 * 4; i < sizemsg; i++)
						puc[i] ^= _pswsha1[i % 20];
				}
				register unsigned int	crc = 0xffffffff;
				for (i = 0; i < sizemsg; i++) //check CRC32
					crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ puc[i]];
				if (pkg->crc32msg != CNetInt::NetUInt(crc ^ 0xffffffff))
					return -1;
			}
			else {
				if (pkg->crc32msg != CNetInt::NetUInt(crc32(puc, sizemsg)))
					return -1;
			}
			return 1;
		}
	};

	template<>
	struct key_equal<uint32_t, cRpcCon>
	{
		bool operator()(uint32_t key, const cRpcCon& val)
		{
			return key == val._ucid;
		}
	};

	class cRpcClientMap // client sessions map
	{
	public:
		cRpcClientMap(size_t maxconect, memory* pmem) : _memmap(map<uint32_t, cRpcCon>::size_node(), maxconect),
			_map(11 + (uint32_t)(maxconect / 3), &_memmap), _pmem(pmem)
		{
			_bEncryptData = false;
			_tks = ::time(nullptr);
			_tks <<= 24;
			_lseqno = 1;
		}
		~cRpcClientMap() {
			_map.clear();
		}
		long _lseqno;
		inline void SetEncryptData(bool bEncrypt)
		{
			_bEncryptData = bEncrypt;
		}
		inline bool IsEncryptData()
		{
			return _bEncryptData;
		}
		inline memory* get_memory() {
			return _pmem;
		}
	protected:
		bool _bEncryptData;
		uint64_t _tks;
		std::mutex _cs;
		memory _memmap;
		map<uint32_t, cRpcCon> _map;
		memory* _pmem; //memory for read data
	public:
		void Add(uint32_t ucid, const char* sip)
		{
			unique_lock lck(&_cs);
			_map.set(ucid, cRpcCon(ucid, sip, _pmem));
		}
		bool Del(unsigned int ucid)
		{
			unique_lock lck(&_cs);
			return _map.erase(ucid);
		}
		int DoReadData(uint32_t ucid, const uint8_t* pdata, size_t usize, vector<uint8_t>* pout)
		{
			unique_lock lck(&_cs);
			cRpcCon* pcli = _map.get(ucid);
			if (!pcli)
				return -1;
			return pcli->DoReadData(pdata, usize, pout);
		}
		int DoLeftData(uint32_t ucid, vector<uint8_t>* pout)
		{
			unique_lock lck(&_cs);
			cRpcCon* pcli = _map.get(ucid);
			if (!pcli)
				return -1;
			return pcli->DoLeftData(pout);
		}
		bool GetUserInfo(t_rpcuserinfo* puser)
		{
			unique_lock lck(&_cs);
			cRpcCon* pcli = _map.get(puser->_ucid);
			if (!pcli)
				return false;
			puser->_nstatus = pcli->_nstatus;
			memcpy(puser->_susr, pcli->_susr, sizeof(puser->_susr));
			memcpy(puser->_psw, pcli->_psw, sizeof(puser->_psw));
			memcpy(puser->_pswsha1, pcli->_pswsha1, sizeof(puser->_pswsha1));
			memcpy(puser->_sip, pcli->_sip, sizeof(puser->_sip));
			return true;
		}
		bool SetUserPsw(const char* susr, unsigned int ucid, const char* spsw)
		{
			unique_lock lck(&_cs);
			cRpcCon* pcli = _map.get(ucid);
			if (!pcli)
				return false;
			if (!spsw || !(*spsw))
				strcpy(pcli->_psw, "123456");//
			else
				snprintf(pcli->_psw, sizeof(pcli->_psw), "%s", spsw);
			snprintf(pcli->_susr, sizeof(pcli->_susr), "%s", susr);
			pcli->_nstatus = rpcusr_connect;
			encode_sha1(pcli->_psw, (unsigned int)strlen(pcli->_psw), pcli->_pswsha1);// password sha1
			return true;
		}
		bool SetUserRandomInfo(unsigned int ucid, char* sout) //sout > 40 bytes
		{
			unique_lock lck(&_cs);
			cRpcCon* pcli = _map.get(ucid);
			if (!pcli)
				return false;
			_tks++;
			unsigned char usha1[20], uc;
			encode_sha1(&_tks, 8, usha1);// random data
			int i;
			for (i = 0; i < 20; i++) {
				uc = usha1[i] >> 4;
				pcli->_srandominfo[i * 2] = (uc >= 0x0A) ? 'A' + (uc - 0x0A) : '0' + uc;
				uc = usha1[i] & 0x0F;
				pcli->_srandominfo[i * 2 + 1] = (uc >= 0x0A) ? 'A' + (uc - 0x0A) : '0' + uc;
			}
			memcpy(sout, pcli->_srandominfo, 40);
			sout[40] = 0;
			pcli->_nstatus = rpcusr_sha1info;
			return true;
		}
		bool GetUsrInfoSha1(unsigned int ucid, char* pout, char* outusr) // pout >40 bytes,outusr >= 32 bytes
		{
			char sbuf[80] = { 0 };
			unique_lock lck(&_cs);
			cRpcCon* pcli = _map.get(ucid);
			if (!pcli)
				return false;
			memcpy(sbuf, pcli->_srandominfo, 40);
			strcpy(&sbuf[40], pcli->_psw);
			unsigned char hex[20], uc;
			encode_sha1(sbuf, (unsigned int)strlen(sbuf), hex);
			int i;
			for (i = 0; i < 20; i++)
			{
				uc = hex[i] >> 4;
				pout[i * 2] = (uc >= 0x0A) ? 'A' + (uc - 0x0A) : '0' + uc;
				uc = hex[i] & 0x0F;
				pout[i * 2 + 1] = (uc >= 0x0A) ? 'A' + (uc - 0x0A) : '0' + uc;
			}
			pout[40] = 0;
			memcpy(outusr, pcli->_susr, sizeof(pcli->_susr));
			return true;
		}
		void SetUsrStatus(unsigned int ucid, RPCUSRST nst)
		{
			unique_lock lck(&_cs);
			cRpcCon* pcli = _map.get(ucid);
			if (!pcli)
				return;
			pcli->_nstatus = nst;
		}
		int GetTimeOutNoLogin(time_t ltime, time_t timeoutsec, vector<uint32_t>*pucids)
		{
			unique_lock lck(&_cs);
			cRpcCon *p;
			map<uint32_t, cRpcCon>::iterator it = _map.begin();
			pucids->clear();
			while ((p = _map.next(it)) != nullptr) {
				if (p->_nstatus == 0 && ltime - p->_timeconnect > timeoutsec)
					pucids->add(p->_ucid);
			}
			return (int)pucids->size();
		}
	};

	class args_rpc {
	public:
		args_rpc(cRpcClientMap* pssmap) : _pssmap(pssmap) {
		}
		cRpcClientMap * _pssmap;
		static bool MakePkg(const void* pd, size_t size, RPCMSGTYPE msgtype, RPCCOMPRESS compress, uint32_t seqno, const uint8_t* pmask, memory* pmem, bool bEncrypt, vector<uint8_t>* pPkg)
		{
			unsigned char shead[sizeof(t_rpcpkg)] = { 0 };
			pPkg->clear();
			pPkg->add(shead, sizeof(t_rpcpkg));
			t_rpcpkg* ph = (t_rpcpkg*)pPkg->data();

			ph->sync = RPC_SYNC_BYTE;
			ph->type = (char)msgtype;

			void* pdata; // compress first
			size_t ulen = size;
			auto_buffer vtmp(pmem);
			if (compress == rpccomp_lz4) {
				ulen = LZ4_compressBound((int)size);
				if (!vtmp.resize(ulen))
					return false;
				if (encode_lz4(pd, size, vtmp.data(), &ulen)) {
					pdata = vtmp.data();
					ph->comp = rpccomp_lz4;
				}
				else {
					pdata = (void*)pd;
					ph->comp = rpccomp_none;
					ulen = size;
				}
			}
#ifdef RPC_USE_ZLIB
			else if (compress == rpccomp_zlib)
			{
				ulen = size + (size / 1024) * 16 + 1024;
				if (!vtmp.resize(ulen))
					return false;
				if (encode_zlib(pd, size, vtmp.data(), &ulen)) {
					pdata = vtmp.data();
					ph->comp = rpccomp_zlib;
				}
				else {
					pdata = (void*)pd;
					ph->comp = rpccomp_none;
					ulen = size;
				}
			}
#endif
			else {
				pdata = (void*)pd;
				ph->comp = rpccomp_none;
				ulen = size;
			}
			if (bEncrypt && pmask)
				ph->cflag = 0;
			else
				ph->cflag = 1;

			ph->seqno = CNetInt::NetUInt(seqno);
			ph->size_en = CNetInt::NetUInt((unsigned int)ulen);
			ph->size_dn = CNetInt::NetUInt((unsigned int)size);

			if (!pPkg->add((const uint8_t*)pdata, ulen))
				return false;

			ph = (t_rpcpkg*)pPkg->data();
			unsigned char* puc = pPkg->data() + sizeof(t_rpcpkg);
			if (pmask && msgtype >= rpcmsg_request) {
				unsigned int ul = (unsigned int)ulen;
				register unsigned int	crc = 0xffffffff;
				register unsigned int i;

				for (i = 0; i < ul; i++) // make data crc32
					crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ puc[i]];
				ph->crc32msg = CNetInt::NetUInt(crc ^ 0xffffffff);
				if (bEncrypt) {
					unsigned int *pu4 = (unsigned int *)puc, ul4 = ul / 4; //Encrypt
					unsigned int *pmk4 = (unsigned int*)pmask;
					for (i = 0; i < ul4; i++)
						pu4[i] ^= pmk4[i % 5];
					for (i = ul4 * 4; i < ul; i++)
						puc[i] ^= pmask[i % 20];
				}
			}
			else
				ph->crc32msg = CNetInt::NetUInt(crc32(puc, (unsigned int)ulen));// make data crc32
			ph->crc32head = CNetInt::NetUInt(crc32(ph, 20)); // make head crc32
			return true;
		}
	};
#if (!defined _WIN32) || (_WIN32_WINNT >= 0x0600)
	template<class _THREAD, class _CLS>
	class AioRpcSrv : public AioTcpSrv<_THREAD, AioRpcSrv<_THREAD, _CLS>>
	{
	public:
		typedef AioTcpSrv<_THREAD, AioRpcSrv<_THREAD, _CLS>> base_;
		friend  base_;
		AioRpcSrv(uint32_t maxconnum, cLog* plog, memory* pmem)
			: base_(maxconnum, plog, pmem), _mapss(maxconnum, pmem)
		{
			_mapss.SetEncryptData(false);
		}
		void InitRpcArgs(_THREAD* pthread) {
			args_rpc arg(&_mapss);
			pthread->InitRpcArgs(&arg);
		}
	protected:
		inline void InitArgs(_THREAD* pthread) {
			static_cast<_CLS*>(this)->InitArgs(pthread);
		}
	public:
		bool start(uint16_t port, int workthreadnum, const char* sip = nullptr)
		{
			if (!base_::start(port, workthreadnum, sip)) {
				if (base_::_plog)
					base_::_plog->add(CLOG_DEFAULT_ERR, "Start server port(%u) failed!", port);
				return false;
			}
			return true;
		}
	protected:
		cRpcClientMap _mapss;  //map for  sessions
	};

	template<class _CLS>
	class AioRpcSrvThread : public AioTcpSrvThread<AioRpcSrvThread<_CLS>>
	{
	public:
		typedef AioTcpSrvThread<AioRpcSrvThread<_CLS>> base_;
		friend  base_;
		AioRpcSrvThread(xpoll* ppoll, cLog* plog, memory* pmem, int threadno, uint16_t srvport) :
			base_(ppoll, plog, pmem, threadno, srvport)
		{
		}
		inline void InitRpcArgs(args_rpc* pargs) {
			_pssmap = pargs->_pssmap;
		}
		bool rpc_send(uint32_t ucid, const void* pdata, size_t bytesize, RPCMSGTYPE msgtype,
			uint32_t seqno, int timeovermsec = 0) // post send data
		{
			t_rpcuserinfo usrinfo;
			usrinfo._ucid = ucid;
			if (!_pssmap->GetUserInfo(&usrinfo))
				return false;
			if (bytesize > 80)
				return SendRpcMsg(ucid, pdata, bytesize, msgtype, rpccomp_lz4, seqno, usrinfo._pswsha1, timeovermsec);
			else
				return SendRpcMsg(ucid, pdata, bytesize, msgtype, rpccomp_none, seqno, usrinfo._pswsha1, timeovermsec);
		}
	protected:
		cRpcClientMap * _pssmap;
	private:
		bool SendRpcMsg(uint32_t ucid, const void* pd, size_t size, RPCMSGTYPE msgtype, RPCCOMPRESS compress,
			uint32_t seqno, const uint8_t* pmask, int timeovermsec = 0)
		{
			vector<uint8_t> pkg(size, base_::_pmem);
			if (args_rpc::MakePkg(pd, size, msgtype, compress, seqno, pmask, base_::_pmem, _pssmap->IsEncryptData(), &pkg)) {
				size_t pkglen = pkg.size();
				return base_::tcp_post(ucid, pkg.detach_buf(), pkglen, timeovermsec);
			}
			return false;
		}
		inline int RetSysMsg(uint32_t ucid, const char* smsg, unsigned int seqno, bool bclose = false)
		{
			SendRpcMsg(ucid, smsg, strlen(smsg), rpcmsg_sys, rpccomp_none, seqno, nullptr);
			if (bclose) {
				base_::close_ucid(ucid);
				return -1;
			}
			return 0;
		}
		inline int RetShMsg(uint32_t ucid, const char* smsg, unsigned int seqno, bool bclose = false)
		{
			SendRpcMsg(ucid, smsg, strlen(smsg), rpcmsg_sh, rpccomp_none, seqno, nullptr);
			if (bclose) {
				base_::close_ucid(ucid);
				return -1;
			}
			return 0;
		}
		int DoMsg(uint32_t ucid, vector<uint8_t>* pin)// pin Already verified and decrypted
		{
			t_rpcpkg* pkg = (t_rpcpkg*)pin->data();
			void* pmsg = 0;
			size_t ulen = 0;

			auto_buffer vtmp(base_::_pmem);
			if (pkg->comp == rpccomp_none) {
				pmsg = pkg->msg;
				ulen = CNetInt::NetUInt(pkg->size_en);
			}
			else if (pkg->comp == rpccomp_lz4) {
				size_t uen = CNetInt::NetUInt(pkg->size_en), udn = CNetInt::NetUInt(pkg->size_dn);
				if (!vtmp.resize(udn)) {
					base_::close_ucid(ucid);
					return -1;
				}
				if (!decode_lz4(pkg->msg, uen, vtmp.data(), &udn))
					return RetSysMsg(ucid, "msgsys,-1,decode lz4 error!", CNetInt::NetUInt(pkg->seqno), true);
				pmsg = vtmp.data();
				ulen = udn;
			}
#ifdef RPC_USE_ZLIB
			else if (pkg->comp == rpccomp_zlib) {
				size_t uen = CNetInt::NetUInt(pkg->size_en), udn = CNetInt::NetUInt(pkg->size_dn);
				if (!vtmp.resize(udn)) {
					base_::close_ucid(ucid);
					return -1;
				}
				if (!decode_zlib(pkg->msg, uen, vtmp.data(), &udn))
					return RetSysMsg(ucid, "msgsys,-1,decode lz4 error!", CNetInt::NetUInt(pkg->seqno), true);
				pmsg = vtmp.data();
				ulen = udn;
			}
#endif
			else
				return RetSysMsg(ucid, "msgsys,-1,unkown compress type!", CNetInt::NetUInt(pkg->seqno), true);
			if (pkg->type == rpcmsg_sh)
				return Do_shmsg(ucid, pmsg, (unsigned int)ulen, CNetInt::NetUInt(pkg->seqno));
			else if (pkg->type == rpcmsg_request || pkg->type == rpcmsg_put)
				return Do_appMsg(ucid, (RPCMSGTYPE)pkg->type, pmsg, (unsigned int)ulen, CNetInt::NetUInt(pkg->seqno));
			return RetSysMsg(ucid, "msgsys,-1,unkown msgtype!", CNetInt::NetUInt(pkg->seqno), true);
		}
		int  Do_shmsg(uint32_t ucid, const void* pmsg, uint32_t msglen, uint32_t seqno)
		{
			const char* sd = (const char*)pmsg;
			char sod[16];
			t_rpcuserinfo usri;
			memset(&usri, 0, sizeof(usri));
			size_t pos = 0;
			if (!str_getnextstring(',', sd, msglen, pos, sod, sizeof(sod)))//读取命令
				return RetShMsg(ucid, "onconnect,-1,msg format error!", seqno, true);
			if (!strcmp(sod, "connect")) // "connnect,username"
			{
				if (usri._nstatus != rpcusr_connect)
					return RetShMsg(ucid, "onconnect,-1,usr status error!", seqno, true);
				char susr[32], spsw[40] = { 0 }, sinfo[44], sret[128];//"connect,username"
				if (!str_getnextstring(',', sd, msglen, pos, susr, sizeof(susr)))
					return RetShMsg(ucid, "onconnect,-1,msg format error!", seqno, true);
				if (static_cast<_CLS*>(this)->getpswd(susr, spsw, sizeof(spsw)) != 0)
					return RetShMsg(ucid, "onconnect,-1,nouser!", seqno, true);
				if (!_pssmap->SetUserPsw(susr, ucid, spsw) || !_pssmap->SetUserRandomInfo(ucid, sinfo))
					return RetShMsg(ucid, "onconnect,-1,system error!", seqno, true);
				snprintf(sret, sizeof(sret), "onconnect,0,%s", sinfo);//send random info
				return RetShMsg(ucid, sret, seqno);
			}
			else if (!strcmp(sod, "sha1")) //"sha1,usrcalsha1,login info"
			{
				usri._ucid = ucid;
				if (!_pssmap->GetUserInfo(&usri))
					return RetShMsg(ucid, "msgsh,-1,no ucid!", seqno, true);

				if (usri._nstatus != rpcusr_sha1info)
					return RetShMsg(ucid, "onconnect,-1,usr status error!", seqno, true);

				char sha1usr[44], sha1srv[44], susr[32], extinfo[256] = { 0 };
				if (!str_getnextstring(',', sd, msglen, pos, sha1usr, sizeof(sha1usr))) //usrcalsha1
					return RetShMsg(ucid, "onsha1,-1,msg format error!", seqno, true);
				str_getnextstring(',', sd, msglen, pos, extinfo, sizeof(extinfo));
				if (!_pssmap->GetUsrInfoSha1(ucid, sha1srv, susr))
					return RetShMsg(ucid, "onsha1,-1,system error GetUsrInfoSha1 failed!", seqno, true);
				if (strcmp(sha1usr, sha1srv)) //sha1 error
					return RetShMsg(ucid, "onsha1,-2,Authentication failed!", seqno, true);

				int loginerr = static_cast<_CLS*>(this)->onlogin(ucid, susr, usri._sip, extinfo);
				if (loginerr) {
					char sret[64];
					snprintf(sret, sizeof(sret), "onsha1,%d,extinfo failed", loginerr);
					return RetShMsg(ucid, sret, seqno, true);
				}
				_pssmap->SetUsrStatus(ucid, rpcusr_pass);
				return RetShMsg(ucid, "onsha1,0", seqno);//success
			}
			return RetShMsg(ucid, "msgsh,-1,msg format error!", seqno, true);
		}
		int Do_appMsg(uint32_t ucid, RPCMSGTYPE type, const void* pmsg, uint32_t msglen, uint32_t seqno)//处理put和call消息
		{
			t_rpcuserinfo usrinfo;
			usrinfo._ucid = ucid;
			if (!_pssmap->GetUserInfo(&usrinfo))
				return RetSysMsg(ucid, "msgsys,-1,no ucid!", seqno, true);
			if (usrinfo._nstatus != rpcusr_pass)
				return RetSysMsg(ucid, "msgsys,-1,please login!", seqno, true);
			return static_cast<_CLS*>(this)->OnRpcMsg(type, ucid, usrinfo._susr, seqno, pmsg, msglen);
		}
	protected:
		void onconnect(uint32_t ucid, const char* sip)//connect event
		{
			if (base_::_plog)
				base_::_plog->add(CLOG_DEFAULT_MSG, "ucid %u connect to port %d  from ip %s", ucid, base_::_srvport, sip);
			_pssmap->Add(ucid, sip);
		}
		void ondisconnect(uint32_t ucid)//disconnect  event
		{
			static_cast<_CLS*>(this)->ondisconnect(ucid);
			_pssmap->Del(ucid);
		}
		void onrecv(uint32_t ucid, const void* pdata, size_t size) //read event
		{
			if (!pdata || !size)
				return;
			vector<uint8_t> msgr(1024 * 16, base_::_pmem);
			int nr = 0, ndo = 0;
			nr = _pssmap->DoReadData(ucid, (const unsigned char*)pdata, size, &msgr);
			while (nr == 1) {
				ndo = DoMsg(ucid, &msgr);
				if (ndo)
					break; // error or close
				nr = _pssmap->DoLeftData(ucid, &msgr);
			};
			if (nr < 0)
				base_::close_ucid(ucid);
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
#endif
	template <class _CLS>
	class RpcAutoClient : public AioTcpClient<RpcAutoClient<_CLS>> // rpc client
	{
	public:
		typedef AioTcpClient<RpcAutoClient<_CLS>> base_;
		friend  base_;
		RpcAutoClient(cLog* plog, memory* _pmem) : base_(_pmem), _nstatus_con(-1), _bEncrypt(false), _plog(plog), _seqno(1), _rbuf(1024 * 16, _pmem)
		{
			_susr[0] = 0;
			_spass[0] = 0;
			_logininfo[0] = 0;
		}
		bool start(const char* ip, uint16_t port, const char* susr, const char* spass, const char* extinfo)
		{
			snprintf(_susr, sizeof(_susr), "%s", susr);
			snprintf(_spass, sizeof(_spass), "%s", spass);
			if (extinfo && *extinfo)
				snprintf(_logininfo, sizeof(_logininfo), "%s", extinfo);
			else
				_logininfo[0] = 0;
			encode_sha1(spass, (unsigned int)strlen(spass), _pswsha1);
			return base_::open(ip, port);
		}
		inline void stop()
		{
			base_::close();
		}
		inline bool rpc_request(const void* pd, size_t size, uint32_t seqno, int timeovermsec = 0)
		{
			return SendRpcMsg(pd, size, rpcmsg_request, (size > 80) ? rpccomp_lz4 : rpccomp_none, seqno, _pswsha1, timeovermsec);
		}
		inline bool rpc_put(const void* pd, size_t size, uint32_t seqno, int timeovermsec = 0)
		{
			return SendRpcMsg(pd, size, rpcmsg_put, (size > 80) ? rpccomp_lz4 : rpccomp_none, _seqno++, _pswsha1, timeovermsec);
		}
		inline void SetEncrypt(bool bEncrypt)
		{
			_bEncrypt = bEncrypt;
		}
		inline bool IsEncrypt()
		{
			return _bEncrypt;
		}
	public:
		std::atomic_int  _nstatus_con;//-1: unconnect; 0:connected; 1: logined
		uint32_t next_seqno() {
			uint32_t u = 0;
			while (!u)
				u = _seqno++;
			return u;
		}
	private:
		char _susr[24];
		char _spass[48];
		char _logininfo[512];
		uint8_t _pswsha1[20];

	protected:
		bool _bEncrypt;
		cLog * _plog;
		std::atomic_uint _seqno;
		vector<uint8_t> _rbuf;
	protected:
		bool SendRpcMsg(const void* pd, size_t size, RPCMSGTYPE msgtype, RPCCOMPRESS compress, uint32_t seqno, const uint8_t* pmask, int timeovermsec = 0) {
			vector<uint8_t> pkg(size + 64, base_::_pmem);
			if (args_rpc::MakePkg(pd, size, msgtype, compress, seqno, pmask, base_::_pmem, _bEncrypt, &pkg)) {
				size_t pkglen = pkg.size();
				return base_::tcp_post(pkg.data(), pkglen, timeovermsec);
			}
			return false;
		}
		inline int SendShMsg(const char* smsg, unsigned int seqno)
		{
			if (SendRpcMsg(smsg, strlen(smsg), rpcmsg_sh, rpccomp_none, seqno, nullptr))
				return 0;
			return -1;
		}
		void  onrecv(const void* pdata, size_t bytesize)
		{
			_rbuf.add((const uint8_t*)pdata, bytesize);
			vector<uint8_t> msgr(1024 * 16, base_::_pmem);
			int nr = DoLeftData(&msgr);
			while (nr > 0) {
				if (DoMsg(&msgr))
					break;
				nr = DoLeftData(&msgr);
			};
			_rbuf.shrink(0);
		};
		void onconnect() {
			char msgsh[64];
			snprintf(msgsh, sizeof(msgsh), "connect,%s", _susr);
			SendShMsg(msgsh, _seqno++);
			_nstatus_con = 0;
		}
		inline void ondisconnect() {
			_nstatus_con = -1;
			static_cast<_CLS*>(this)->ondisconnect();
		}
	private:
		int DoLeftData(vector<uint8_t>* pout)
		{
			pout->clear();
			size_t  ulen = _rbuf.size();
			uint8_t* pu = _rbuf.data();
			if (ulen < sizeof(t_rpcpkg))
				return 0;
			t_rpcpkg* pkg = (t_rpcpkg*)pu;// check head
			unsigned int c1 = crc32(pu, 20);
			if (pkg->sync != RPC_SYNC_BYTE || c1 != CNetInt::NetUInt(pkg->crc32head))
				return rpc_c_disconnected_msgerr;

			unsigned int sizemsg = CNetInt::NetUInt(pkg->size_en);
			if (ulen < sizemsg + sizeof(t_rpcpkg))
				return 0;
			pout->add(pu, sizemsg + sizeof(t_rpcpkg));
			_rbuf.erase(0, sizemsg + sizeof(t_rpcpkg));
			unsigned char* puc = pout->data() + sizeof(t_rpcpkg);
			if (pkg->type >= rpcmsg_request) {
				if (!(pkg->cflag & 0x01)) { // Decrypt
					unsigned int *pu4 = (unsigned int*)puc, u4 = sizemsg / 4;
					unsigned int *pmk4 = (unsigned int*)_pswsha1;
					for (auto i = 0u; i < u4; i++)
						pu4[i] ^= pmk4[i % 5];
					for (auto i = u4 * 4u; i < sizemsg; i++)
						puc[i] ^= _pswsha1[i % 20];
				}
				register unsigned int	crc = 0xffffffff;//check data CRC32
				for (auto i = 0u; i < sizemsg; i++)
					crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ puc[i]];
				if (pkg->crc32msg != CNetInt::NetUInt(crc ^ 0xffffffff))
					return -1;
			}
			else {
				if (pkg->crc32msg != CNetInt::NetUInt(crc32(puc, sizemsg)))
					return rpc_c_disconnected_msgerr;
			}
			return 1;
		}
		int DoMsg(vector<uint8_t>* pin)// pin Already verified and decrypted
		{
			t_rpcpkg* pkg = (t_rpcpkg*)pin->data();
			void* pmsg = 0;
			size_t ulen = 0;

			auto_buffer vtmp(base_::_pmem);

			if (pkg->comp == rpccomp_none) {
				pmsg = pkg->msg;
				ulen = CNetInt::NetUInt(pkg->size_en);
			}
			else if (pkg->comp == rpccomp_lz4) {
				size_t uen = CNetInt::NetUInt(pkg->size_en), udn = CNetInt::NetUInt(pkg->size_dn);
				if (!vtmp.resize(udn)) {
					return -1;
				}
				if (!decode_lz4(pkg->msg, uen, vtmp.data(), &udn))
					return rpc_c_disconnected_msgerr;
				pmsg = vtmp.data();
				ulen = udn;
			}
#ifdef RPC_USE_ZLIB
			else if (pkg->comp == rpccomp_zlib) {
				size_t uen = CNetInt::NetUInt(pkg->size_en), udn = CNetInt::NetUInt(pkg->size_dn);
				if (!vtmp.resize(udn)) {
					return -1;
				}
				if (!decode_zlib(pkg->msg, uen, vtmp.data(), &udn))
					return rpc_c_disconnected_msgerr;
				pmsg = vtmp.data();
				ulen = udn;
			}
#endif
			else
				return rpc_c_disconnected_msgerr;
			if (pkg->type == rpcmsg_sh)
				return DoMsgSh((const char*)pmsg, ulen);
			else if (pkg->type == rpcmsg_sys) {
				pin->add((unsigned char)0);
				return 0;
			}
			return static_cast<_CLS*>(this)->OnClientMsg((RPCMSGTYPE)pkg->type, CNetInt::NetUInt(pkg->seqno), (unsigned char*)pmsg, ulen);
		}
		int DoMsgSh(const char* ps, size_t len)// return 0: ok ; !=0: error
		{
			char sod[32];
			size_t pos = 0;
			if (!str_getnextstring(',', ps, len, pos, sod, sizeof(sod))) {
				static_cast<_CLS*>(this)->OnLoginEvent(rpc_c_disconnected_msgerr);
				return rpc_c_disconnected_msgerr;
			}
			if (!strcmp(sod, "onconnect")) {
				char sarg[128];
				if (!str_getnextstring(',', ps, len, pos, sarg, sizeof(sarg))) {
					static_cast<_CLS*>(this)->OnLoginEvent(rpc_c_disconnected_msgerr);
					return rpc_c_disconnected_msgerr;
				}
				if (atoi(sarg)) {
					static_cast<_CLS*>(this)->OnLoginEvent(rpc_c_login_usrerr);
					return rpc_c_login_usrerr;
				}
				if (!str_getnextstring(',', ps, len, pos, sarg, sizeof(sarg))) {
					static_cast<_CLS*>(this)->OnLoginEvent(rpc_c_disconnected_msgerr);
					return rpc_c_disconnected_msgerr;
				}

				unsigned char  hex[20], uc, sha[44];
				strcat(sarg, _spass);

				encode_sha1(sarg, (unsigned int)strlen(sarg), hex);
				for (auto i = 0; i < 20; i++) {
					uc = hex[i] >> 4;
					sha[i * 2] = (uc >= 0x0A) ? 'A' + (uc - 0x0A) : '0' + uc;
					uc = hex[i] & 0x0F;
					sha[i * 2 + 1] = (uc >= 0x0A) ? 'A' + (uc - 0x0A) : '0' + uc;
				}
				sha[40] = 0;
				sprintf(sarg, "sha1,%s", sha);

				SendShMsg(sarg, _seqno++);
				return 0;
			}
			else if (!strcmp(sod, "onsha1")) {
				char sarg[128];
				if (!str_getnextstring(',', ps, len, pos, sarg, sizeof(sarg)))
					return rpc_c_disconnected_msgerr;
				if (atoi(sarg)) {
					base_::_delaytks = 150;// 15 seconds reconnect
					static_cast<_CLS*>(this)->OnLoginEvent(rpc_c_login_pswerr);
					return rpc_c_login_pswerr;
				}
				_nstatus_con = 1;//login success
				static_cast<_CLS*>(this)->OnLoginEvent(rpc_c_login_ok);
			}
			return 0;
		}
	};
}
