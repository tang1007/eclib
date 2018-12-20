/*!
\file ec_wss.h
\author kipway@outlook.com
\update 2018.12.20

eclib websocket secret class. easy to use, no thread , lock-free

eclib Copyright (c) 2017-2018, kipway
source repository : https://github.com/kipway/eclib

Licensed under the Apache License, Version 2.0 (the "License");
*/
#pragma once
#include "ec_tlssrv.h"
#include "c11_keyval.h"
#include "c_base64.h"

#include "c_sha1.h"
#include "zlib/zlib.h"

#define EC_PROTOC_WSS     (EC_PROTOC_TLS + 1) // WSS
#define EC_MAX_WSMSG_SIZE (1024 * 1024 * 30) //30MB

#ifndef MAX_FILESIZE_HTTP_DOWN
#define MAX_FILESIZE_HTTP_DOWN (1024 * 1024 * 32u)
#endif

#define EC_SIZE_WS_FRAME (1024 * 62)
#define EC_SIZE_WS_READ_FRAME_MAX (1024 * 1024) // read max ws frame size

#define SIZE_MAX_HTTPHEAD   4096  // max http1.1 head characters
#define SIZE_HTTPMAXREQUEST (1024 * 64) // max http request

#define HTTPENCODE_NONE    0
#define HTTPENCODE_DEFLATE 1

#define PROTOCOL_HTTP   0
#define PROTOCOL_WS     1

#define WS_FINAL	  0x80
#define WS_OP_CONTINUE  0 
#define WS_OP_TXT		1
#define WS_OP_BIN		2
#define WS_OP_CLOSE	    8
#define WS_OP_PING		9
#define WS_OP_PONG		10

#define ws_frame_size  (1024 * 60)
#define ws_permessage_deflate		1  // for google chrome ,firefox
#define ws_x_webkit_deflate_frame   2  // for ios safari

namespace ec {
	enum HTTPERROR
	{
		he_ok = 0,
		he_waitdata,
		he_failed,
		he_method,
		he_url,
		he_ver,
	};
	static const char* http_sret404 = "http/1.1 404  not found!\r\nConnection: keep-alive\r\nContent-type:text/plain\r\nContent-Length:9\r\n\r\nnot found";
	static const char* http_sret404outsize = "http/1.1 404  over size!\r\nConnection: keep-alive\r\nContent-type:text/plain\r\nContent-Length:15\r\n\r\nfile over size!";
	static const char* http_sret400 = "http/1.1 400  Bad Request!\r\nConnection: keep-alive\r\nContent-type:text/plain\r\nContent-Length:11\r\n\r\nBad Request";

	struct t_httpmime
	{
		char sext[16];
		char stype[80];
	};

	template<>
	struct key_equal<const char*, t_httpmime>
	{
		bool operator()(const char* key, const t_httpmime& val)
		{
			return !strcmp(key, val.sext);
		}
	};

#define SIZE_WSZLIBTEMP 32768
	inline int ws_encode_zlib(const void *pSrc, size_t size_src, ec::vector<char>* pout)//pout first two byte x78 and x9c,the end  0x00 x00 xff xff, no  adler32
	{
		z_stream stream;
		int err;
		char outbuf[SIZE_WSZLIBTEMP];

		stream.next_in = (z_const Bytef *)pSrc;
		stream.avail_in = (uInt)size_src;

		stream.zalloc = (alloc_func)0;
		stream.zfree = (free_func)0;
		stream.opaque = (voidpf)0;

		err = deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
		if (err != Z_OK)
			return err;
		uLong uout = 0;
		stream.avail_out = 0;
		while (!stream.avail_out) {
			stream.next_out = (unsigned char*)outbuf;
			stream.avail_out = (unsigned int)sizeof(outbuf);
			err = deflate(&stream, Z_SYNC_FLUSH);
			if (err != Z_OK)
				break;
			if (!pout->add(outbuf, stream.total_out - uout)) {
				err = Z_MEM_ERROR;
				break;
			}
			uout += stream.total_out - uout;
		}
		deflateEnd(&stream);
		return err;
	}

	inline int ws_decode_zlib(const void *pSrc, size_t size_src, ec::vector<char>* pout)//pSrc begin with 0x78 x9c, has no end 0x00 x00 xff xff
	{
		z_stream stream;
		int err;
		char outbuf[SIZE_WSZLIBTEMP];

		stream.next_in = (z_const Bytef *)pSrc;
		stream.avail_in = (uInt)size_src;

		stream.zalloc = (alloc_func)0;
		stream.zfree = (free_func)0;
		stream.opaque = (voidpf)0;

		err = inflateInit(&stream);
		if (err != Z_OK)
			return err;
		uLong uout = 0;
		while (stream.avail_in > 0) {
			stream.next_out = (unsigned char*)outbuf;
			stream.avail_out = (unsigned int)sizeof(outbuf);
			err = inflate(&stream, Z_SYNC_FLUSH);
			if (err != Z_OK)
				break;
			if (!pout->add(outbuf, stream.total_out - uout)) {
				err = Z_MEM_ERROR;
				break;
			}
			uout += stream.total_out - uout;
		}
		inflateEnd(&stream);
		return err;
	}

	inline bool ws_make_permsg(const void* pdata, size_t sizes, unsigned char wsopt, vector<char>* pout, int ncompress) //multi-frame,permessage_deflate
	{
		unsigned char uc;
		const char* pds = (const char*)pdata;
		size_t slen = sizes;
		vector<char> tmp(2048 + sizes - sizes % 1024, pout->get_mem_allocator());
		if (ncompress)
		{
			tmp.set_grow(2048 + sizes / 2 - sizes % 1024);
			if (Z_OK != ws_encode_zlib(pdata, sizes, &tmp) || tmp.size() < 6)
				return false;
			pds = tmp.data() + 2;
			slen = tmp.size() - 6;
		}
		size_t ss = 0, us;
		pout->clear();
		while (ss < slen)
		{
			uc = 0;
			if (0 == ss)//first frame
			{
				uc = 0x0F & wsopt;
				if (ncompress)
					uc |= 0x40;
			}
			us = EC_SIZE_WS_FRAME;
			if (ss + EC_SIZE_WS_FRAME >= slen) // end frame
			{
				uc |= 0x80;
				us = slen - ss;
			}
			pout->add(uc);
			if (us < 126)
			{
				uc = (unsigned char)us;
				pout->add(uc);
			}
			else if (uc < 65536)
			{
				uc = 126;
				pout->add(uc);
				pout->add((char)((us & 0xFF00) >> 8)); //high byte
				pout->add((char)(us & 0xFF)); //low byte
			}
			else // < 4G
			{
				uc = 127;
				pout->add((char)uc);
				pout->add((char)0); pout->add((char)0); pout->add((char)0); pout->add((char)0);//high 4 bytes 0
				pout->add((char)((us & 0xFF000000) >> 24));
				pout->add((char)((us & 0x00FF0000) >> 16));
				pout->add((char)((us & 0x0000FF00) >> 8));
				pout->add((char)(us & 0xFF));
			}
			pout->add(pds + ss, us);
			ss += us;
		}
		return true;
	}

	inline bool ws_make_perfrm(const void* pdata, size_t sizes, unsigned char wsopt, vector< char>* pout)//multi-frame,deflate-frame, for ios safari
	{
		const char* pds = (const char*)pdata;
		char* pf;
		size_t slen = sizes;
		vector<char> tmp(EC_SIZE_WS_FRAME, pout->get_mem_allocator());
		unsigned char uc;
		size_t ss = 0, us, fl;
		pout->clear();
		while (ss < slen)
		{
			uc = 0;
			us = EC_SIZE_WS_FRAME;

			if (0 == ss)//first frame
				uc = 0x0F & wsopt;
			if (us > 256)
				uc |= 0x40;
			if (ss + EC_SIZE_WS_FRAME >= slen) //end frame
			{
				uc |= 0x80;
				us = slen - ss;
			}
			pout->add(uc);
			if (uc & 0x40)
			{
				tmp.clear();
				if (Z_OK != ws_encode_zlib(pds + ss, us, &tmp) || tmp.size() < 6)
					return false;
				pf = tmp.data() + 2;
				fl = tmp.size() - 6;
			}
			else
			{
				pf = (char*)pds + ss;
				fl = us;
			}

			if (fl < 126)
			{
				uc = (unsigned char)fl;
				pout->add(uc);
			}
			else if (uc < 65536)
			{
				uc = 126;
				pout->add(uc);
				pout->add((char)((fl & 0xFF00) >> 8)); //high byte
				pout->add((char)(fl & 0xFF)); //low byte
			}
			else // < 4G
			{
				uc = 127;
				pout->add(uc);
				pout->add((char)0); pout->add((char)0); pout->add((char)0); pout->add((char)0);//high 4 bytes 0
				pout->add((char)((fl & 0xFF000000) >> 24));
				pout->add((char)((fl & 0x00FF0000) >> 16));
				pout->add((char)((fl & 0x0000FF00) >> 8));
				pout->add((char)(fl & 0xFF));
			}
			pout->add(pf, fl);
			ss += us;
		}
		return true;
	}

	inline bool isdir(const char* s)
	{
#ifdef _WIN32
		struct _stat st;
		if (_stat(s, &st))
			return false;
		if (st.st_mode & S_IFDIR)
			return true;
		return false;
#else
		struct stat st;
		if (stat(s, &st))
			return false;
		if (st.st_mode & S_IFDIR)
			return true;
		return false;
#endif
	}
	inline const char *file_extname(const char*s)
	{
		const char *pr = NULL;
		while (*s) {
			if (*s == '.')
				pr = s;
			s++;
		}
		return pr;
	}

	class http_pkg
	{
	public:
		http_pkg(ec::memory* pmem) : _body(1024 * 128, pmem), _pmem(pmem), _fin(0), _opcode(0), _comp(0)
		{
			initbuf();
		};
		~http_pkg() {};
	public:
		int  _nprotocol;   // HTTP_PROTOCOL or WEB_SOCKET
		char _method[32];  // get ,head
		char _request[512];// requet URL
		char _reqargs[256];// request args
		char _version[32];
		char _sline[512];

		Array<char, SIZE_MAX_HTTPHEAD> _txthead;
		txtkeyval _headers;
		vector<char> _body;
		int _fin;   // end
		int _opcode;// operator code
		int _comp;  // encode
	private:
		ec::memory* _pmem;
		void initbuf() {
			_method[0] = '\0';
			_request[0] = '\0';
			_reqargs[0] = '\0';
			_version[0] = '\0';
			_sline[0] = '\0';
		}
	protected:
		int NextLine(const char* in, size_t sizein, size_t &pos, char *out, size_t sizeout)//return -1:err; 0:wait ; > 0 linesize
		{
			size_t i = 0;
			while (pos < sizein) {
				if (in[pos] == '\r')
					pos++;
				else if (in[pos] == '\n') {
					if (i >= sizeout)
						return -1;
					out[i++] = in[pos++];
					out[i] = 0;
					return (int)i;
				}
				else {
					out[i++] = in[pos++];
					if (i >= sizeout)
						return -1;
				}
			}
			return 0;
		}

		int GetContextLength()
		{
			char sval[16] = { 0 };
			if (!_headers.get("Context-Length", sval, sizeof(sval)))
				return 0;
			return atoi(sval);
		}

	public:
		int  HttpParse(const char* stxt, size_t usize, size_t &sizedo)
		{
			if (usize < 3)
				return he_waitdata;
			initbuf();
			int nret;
			size_t pos = 0;
			nret = NextLine(stxt, usize, pos, _sline, sizeof(_sline)); // first line
			if (nret < 0)
				return he_failed;
			else if (nret == 0)
				return he_waitdata;
			char surl[512];
			cStrSplit sp(_sline);
			if (!sp.next("\x20\t", _method, sizeof(_method)) || !sp.next("\x20\t", surl, sizeof(surl))
				|| !sp.next("\x20\t", _version, sizeof(_version)))
				return he_failed;
			if (str_icmp("get", _method) && str_icmp("head", _method))
				return he_failed;
			sp.reset(surl);
			sp.next("?", _request, sizeof(_request));
			sp.next("?", _reqargs, sizeof(_reqargs));

			size_t poshead = pos, poshead_e = 0; //do head
			do {
				nret = NextLine(stxt, usize, pos, _sline, sizeof(_sline));
				if (_sline[0] == '\n')
					break;
			} while (nret > 0);
			if (nret < 0)
				return he_failed;
			else if (nret == 0)
				return he_waitdata;
			if (pos - poshead >= SIZE_MAX_HTTPHEAD)
				return he_failed;

			_txthead.clear();
			_txthead.add(stxt + poshead, pos - poshead);
			_headers.init(_txthead.data(), _txthead.size());

			_nprotocol = PROTOCOL_HTTP;

			_body.clear(size_t(0)); // do body
			int bodylength = GetContextLength();
			if (bodylength < 0)
				return  he_failed;
			if (!bodylength) {
				sizedo = pos;
				return he_ok;
			}
			if (pos + bodylength > usize)
				return he_waitdata;

			_body.add(stxt + pos, bodylength);
			sizedo = pos + bodylength;
			return he_ok;
		}
		void Resetwscomp()
		{
			_body.clear((size_t)0);
		}

		inline bool HasKeepAlive()
		{
			return CheckHeadFiled("Connection", "keep-alive");
		}

		bool GetWebSocketKey(char sout[], int nsize)
		{
			if (!CheckHeadFiled("Connection", "Upgrade") || !CheckHeadFiled("Upgrade", "websocket"))
				return false;
			return _headers.get("Sec-WebSocket-Key", sout, nsize);
		}

		inline bool GetHeadFiled(const char* sname, char sval[], size_t size)
		{
			return _headers.get(sname, sval, size);
		}

		bool CheckHeadFiled(const char* sname, const char* sval)
		{
			char stmp[256], sv[80];
			if (!_headers.get(sname, stmp, sizeof(stmp)))
				return false;
			size_t pos = 0;
			while (str_getnext(",", stmp, strlen(stmp), pos, sv, sizeof(sv)))
			{
				if (!str_icmp(sv, sval))
					return true;
			}
			return false;
		}
	};

	/*!
	\brief mimecfg config

	[mime]
	.323 = text/h323
	.3gp = video/3gpp

	*/
	class mimecfg : public config
	{
	public:
		mimecfg() :
			_mimemem(ec::map<const char*, t_httpmime>::size_node(), 512),
			_mime(512, &_mimemem)
		{
			reset();
		};
		virtual ~mimecfg() {
			_mime.clear();
		};
	public:
		ec::memory _mimemem;// memory for _mime 
		map<const char*, t_httpmime> _mime;
	public:
		bool getmime(const char* sext, char *sout, size_t outsize)
		{
			t_httpmime t;
			if (!_mime.get(sext, t))
				return false;
			str_ncpy(sout, t.stype, outsize);
			return true;
		}
	protected:
		virtual void OnBlkName(const char* lpszBlkName) {};
		virtual void OnDoKeyVal(const char* lpszBlkName, const char* lpszKeyName, const char* lpszKeyVal)
		{
			if (ec::str_ieq("mime", lpszBlkName)) {
				if (lpszKeyName && *lpszKeyName && lpszKeyVal && *lpszKeyVal) {
					t_httpmime t;
					memset(&t, 0, sizeof(t));
					strncpy(t.sext, lpszKeyName, sizeof(t.sext) - 1);
					strncpy(t.stype, lpszKeyVal, sizeof(t.stype) - 1);
					_mime.set(t.sext, t);
				}
			}
		}
		void reset() {
			_mime.clear();
		}
		virtual void OnReadFile() {
			reset();
		}
	};
	namespace tcp {
		class ws_session : public tls_session {
		public:
			ws_session(uint32_t ucid, SOCKET  fd, const void* pcer, size_t cerlen,
				const void* pcerroot, size_t cerrootlen, std::mutex *pRsaLck, RSA* pRsaPrivate, ec::memory* pmem, ec::cLog* plog) :
				tls_session(ucid, fd, pcer, cerlen, pcerroot, cerrootlen, pRsaLck, pRsaPrivate, pmem, plog, EC_PROTOC_WSS),
				_txt(1024 * 16, true, pmem), _wsmsg(1024 * 16, true, pmem), _wsappmsg(1024 * 16, true, pmem)
			{
				memset(_sip, 0, sizeof(_sip));
				_ucid = ucid;
				_protocol = PROTOCOL_HTTP;

				_wscompress = 0;
				_comp = 0;
				_opcode = WS_OP_TXT;
			}
		public:
			int  _wscompress; // ws_x_webkit_deflate_frame or ws_permessage_deflate
			int	 _protocol;   // HTTP_PROTOCOL:http; WEB_SOCKET:websocket        
			uint32_t   _ucid; // client user connect ID

			vector<char> _txt;   // tmp
			vector<char> _wsmsg; // ws frame
			vector<char> _wsappmsg; // complete websocket message
			int _comp;// compress flag
			int _opcode;  // operate code
		private:
			void reset_msg()
			{
				_wsmsg.clear((size_t)0);
				_comp = 0;
				_opcode = WS_OP_TXT;
			}
			int  ParseOneFrame(const char* stxt, size_t usize, int &fin)// reuturn >0 is do bytes
			{
				int comp = 0;
				fin = 0;
				if (usize < 2)
					return 0;
				int i;
				size_t datalen = 0, sizedo = 0;
				size_t datapos = 2;
				unsigned char* pu = (unsigned char*)stxt;

				fin = pu[0] & 0x80;
				comp = (pu[0] & 0x40) ? 1 : 0;
				int bmask = pu[1] & 0x80;
				int payloadlen = pu[1] & 0x7F;

				if (!_wsmsg.size())
					_opcode = pu[0] & 0x0f;

				if (bmask)//client can not use mask
					datapos += 4;

				if (payloadlen == 126) {
					datapos += 2;
					if (usize < datapos)
						return he_waitdata;

					datalen = pu[2];
					datalen <<= 8;
					datalen |= pu[3];
				}
				else if (payloadlen == 127) {
					datapos += 8;
					if (usize < datapos)
						return he_waitdata;

					for (i = 0; i < 8; i++)
					{
						if (i > 0)
							datalen <<= 8;
						datalen |= pu[2 + i];
					}
				}
				else {
					datalen = payloadlen;
					if (usize < datapos)
						return he_waitdata;
				}
				if (usize < datapos + datalen)
					return 0;
				if (bmask) {
					unsigned int umask = pu[datapos - 1];	umask <<= 8;
					umask |= pu[datapos - 2]; umask <<= 8;
					umask |= pu[datapos - 3]; umask <<= 8;
					umask |= pu[datapos - 4];
					fast_xor_le(pu + datapos, (int)datalen, umask);
				}
				sizedo = datapos + datalen;

				if (!comp)
					_wsmsg.add(stxt + datapos, datalen);
				else {
					if (_wscompress == ws_x_webkit_deflate_frame) { //deflate_frame					
						vector<char> debuf(ws_frame_size, _pmem);
						debuf.add('\x78');
						debuf.add('\x9c');
						debuf.add(stxt + datapos, datalen);
						if (!_wsmsg.size()) {
							if (Z_OK != ws_decode_zlib(debuf.data(), debuf.size(), &_wsmsg))
								return -1;
						}
						else {
							vector<char> tmp(4 * debuf.size(), _pmem);
							if (Z_OK != ws_decode_zlib(debuf.data(), debuf.size(), &tmp))
								return -1;
							_wsmsg.add(tmp.data(), tmp.size());
						}
					}
					else {
						_comp = 1;
						_wsmsg.clear(size_t(0));
						_wsmsg.add('\x78');
						_wsmsg.add('\x9c');
						_wsmsg.add(stxt + datapos, datalen);
					}
				}
				return (int)sizedo;
			}

			int WebsocketParse(const char* stxt, size_t usize, size_t &sizedo, http_pkg* pout)//support multi-frame
			{
				const char *pd = stxt;
				int ndo = 0, fin = 0;
				sizedo = 0;
				while (sizedo < usize) {
					ndo = ParseOneFrame(pd, usize - sizedo, fin);
					if (ndo <= 0)
						break;
					sizedo += ndo;
					pd += ndo;
					if (fin) {// end frame					
						pout->_body.clear();
						if (_comp && _wscompress == ws_permessage_deflate) {
							if (_wsmsg.size() > 1024 * 32)
								pout->_body.set_grow(2 * _wsmsg.size());
							if (Z_OK != ws_decode_zlib(_wsmsg.data(), _wsmsg.size(), &pout->_body))
								return he_failed;
						}
						else
							pout->_body.add(_wsmsg.data(), _wsmsg.size());
						pout->_fin = 128;
						pout->_opcode = _opcode;
						reset_msg();
						return he_ok;
					}
				}
				if (ndo < 0)
					return he_failed;
				return he_waitdata;
			}
		public:
			virtual int send(const void* pdata, size_t size, int timeoutmsec = 1000) {
				if (_protocol == PROTOCOL_HTTP)
					return tls_session::send(pdata, size, timeoutmsec);
				else if (_protocol == PROTOCOL_WS) {
					bool bsend;
					vector<char> vret(2048 + size - size % 1024, _pmem);
					if (_wscompress == ws_x_webkit_deflate_frame) { //deflate-frame					
						vret.set_grow(2048 + size / 2 - size % 1024);
						bsend = ws_make_perfrm(pdata, size, WS_OP_TXT, &vret);
					}
					else { // ws_permessage_deflate					
						if (size > 128 && _wscompress)
							vret.set_grow(2048 + size / 2 - size % 1024);
						bsend = ws_make_permsg(pdata, size, WS_OP_TXT, &vret, size > 128 && _wscompress);
					}
					if (!bsend) {
						if (_plog)
							_plog->add(CLOG_DEFAULT_ERR, "send ucid %u make wsframe failed,size %u", _ucid, (unsigned int)size);
						return -1;
					}
					return tls_session::send(vret.data(), vret.size(), timeoutmsec);
				}
				_plog->add(CLOG_DEFAULT_ERR, "wss send failed _protocol = %d", _protocol);
				return -1;
			}

			int OnReadData(const char* pdata, size_t usize, http_pkg* pout)
			{
				pout->Resetwscomp();
				if (!pdata || !usize || !pout)
					return he_failed;
				size_t sizedo = 0;
				pout->_nprotocol = _protocol;
				_txt.add(pdata, usize);
				if (_protocol == PROTOCOL_HTTP) {
					int nr = pout->HttpParse(_txt.data(), _txt.size(), sizedo);
					if (nr == he_ok)
						_txt.erase(0, sizedo);
					else {
						if (nr >= he_failed || _txt.size() > SIZE_HTTPMAXREQUEST)
							_txt.clear((size_t)0);
					}
					_txt.shrink(0);
					return nr;
				}
				int nr = WebsocketParse(_txt.data(), _txt.size(), sizedo, pout);//websocket
				if (nr == he_failed)
					_txt.clear((size_t)0);
				else {
					if (sizedo)
						_txt.erase(0, sizedo);
					else {
						if (_txt.size() > EC_SIZE_WS_READ_FRAME_MAX) {
							_txt.clear((size_t)0);
							return he_failed;
						}
					}
					_txt.shrink(0);
				}
				return nr;
			}

			int DoNextData(http_pkg* pout)
			{
				pout->Resetwscomp();
				size_t sizedo = 0;
				if (_protocol == PROTOCOL_HTTP) {
					int nr = pout->HttpParse(_txt.data(), _txt.size(), sizedo);
					if (nr == he_ok)
						_txt.erase(0, sizedo);
					else {
						if (nr >= he_failed || _txt.size() > SIZE_HTTPMAXREQUEST)
							_txt.clear((size_t)0);
					}
					_txt.shrink(0);
					return nr;
				}
				int nr = WebsocketParse(_txt.data(), _txt.size(), sizedo, pout);
				if (nr == he_failed)
					_txt.clear((size_t)0);
				else {
					if (sizedo)
						_txt.erase(0, sizedo);
					else {
						if (_txt.size() > EC_SIZE_WS_READ_FRAME_MAX) {
							_txt.clear((size_t)0);
							return he_failed;
						}
					}
					_txt.shrink(0);
				}
				return nr;
			}
		};

		class httpserver : public tls_server {
		public:
			httpserver(ec::cLog* plog, ec::memory* pmem, ec::mimecfg* pmime) : tls_server(plog, pmem), _pmime(pmime), _httppkg(pmem) {
			}
		protected:
			ec::mimecfg* _pmime;
			http_pkg _httppkg;
			virtual bool domessage(uint32_t ucid, const uint8_t*pmsg, size_t msgsize) {
				psession pi = nullptr;
				if (!_map.get(ucid, pi))
					return false;
				if (EC_PROTOC_WSS != pi->_protoc)
					return onprotcomessage(pi, pmsg, msgsize);

				ws_session* pws = (ws_session*)pi; //处理WSS协议

				int nr = pws->OnReadData((const char*)pmsg, msgsize, &_httppkg);
				while (nr == he_ok)
				{
					if (_httppkg._nprotocol == PROTOCOL_HTTP) {
						if (!DoHttpRequest(pws))
							return false;
					}
					else if (_httppkg._nprotocol == PROTOCOL_WS) {
						if (_httppkg._opcode <= WS_OP_BIN) {
							pws->_wsappmsg.add(_httppkg._body.data(), _httppkg._body.size());
							if (pws->_wsappmsg.size() > EC_MAX_WSMSG_SIZE) {
								pws->_wsappmsg.clear((size_t)0);
								return false;
							}
							if (_httppkg._fin) {
								if (!onwsmessage(ucid, pws->_wsappmsg.data(), pws->_wsappmsg.size()))
									return false;
								pws->_wsappmsg.clear((size_t)0);
							}
						}
						else if (_httppkg._opcode == WS_OP_CLOSE) {
							if (_plog)
								_plog->add(CLOG_DEFAULT_MSG, "ucid %d WS_OP_CLOSE!", ucid);
							return false;
						}
						else if (_httppkg._opcode == WS_OP_PING) {
							if (pws->send(_httppkg._body.data(), _httppkg._body.size(), WS_OP_PONG) < 0)
								return false;
							if (_plog)
								_plog->add(CLOG_DEFAULT_MSG, "ucid %d WS_OP_PING!", ucid);
						}
					}
					nr = pws->DoNextData(&_httppkg);
				}
				if (nr == he_failed) {
					pws->send(http_sret400, strlen(http_sret400));
					return false;
				}
				return true;
			}

			virtual void onconnect(uint32_t ucid) {
			}
			virtual void ondisconnect(uint32_t ucid) {
			}
			virtual session* createsession(uint32_t ucid, SOCKET  fd, uint32_t status, ec::memory* pmem, ec::cLog* plog) {
				return new ws_session(ucid, fd, _ca._pcer.data(), _ca._pcer.size(),
					_ca._prootcer.data(), _ca._prootcer.size(), &_ca._csRsa, _ca._pRsaPrivate, _pmem, _plog);
			}
		protected:
			virtual bool onhttprequest(uint32_t ucid, http_pkg* phttpmsg) = 0;
			virtual bool onwsmessage(uint32_t ucid, const void* pdata, size_t size) = 0;
			virtual bool onprotcomessage(psession pi, const void* pdata, size_t size) { //other protoc
				return false;
			}
			virtual void onupdatewss(uint32_t ucid) {};
		protected:
			bool getmime(const char* sext, char *sout, size_t outsize)
			{
				if (_pmime)
					return _pmime->getmime(sext, sout, outsize);
				ec::str_lcpy(sout, "text/html", outsize);
				return true;
			}
			bool DoHttpRequest(ws_session* pws)// return false will disconnect
			{
				if (_plog) {
					if (_httppkg._reqargs[0])
						_plog->add(CLOG_DEFAULT_MSG, "ucid %u read: %s %s?%s %s", pws->_ucid, _httppkg._method, _httppkg._request, _httppkg._reqargs, _httppkg._version);
					else
						_plog->add(CLOG_DEFAULT_MSG, "ucid %u read: %s %s %s", pws->_ucid, _httppkg._method, _httppkg._request, _httppkg._version);
				}
				if (ec::str_ieq("GET", _httppkg._method)) { //GET
					char skey[128];
					if (_httppkg.GetWebSocketKey(skey, sizeof(skey))) { //websocket Upgrade
						if (DoUpgradeWebSocket(pws, skey)) {
							onupdatewss(pws->_ucid);
							return true;
						}
						else
							return false;
					}
				}
				return onhttprequest(pws->_ucid, &_httppkg);
			}
			bool httprequest(const char* sroot, uint32_t ucid, http_pkg* pPkg) //default httprequest
			{
				if (ec::str_ieq("GET", _httppkg._method))
					return  DoGetAndHead(sroot, ucid, pPkg);
				else if (ec::str_ieq("HEAD", _httppkg._method))
					return  DoGetAndHead(sroot, ucid, pPkg, false);
				httpreterr(ucid, http_sret400, 400);
				return _httppkg.HasKeepAlive();
			}

			bool DoGetAndHead(const char* sroot, uint32_t ucid, http_pkg* pPkg, bool bGet = true)
			{
				char sfile[1024], tmp[4096];
				const char* sc;
				sfile[0] = '\0';
				tmp[0] = '\0';

				strcpy(sfile, sroot);

				url2utf8(pPkg->_request, tmp, (int)sizeof(tmp));

				strcat(sfile, tmp);

				size_t n = strlen(sfile);
				if (n && (sfile[n - 1] == '/' || sfile[n - 1] == '\\'))
					strcat(sfile, "index.html");
				else if (isdir(sfile)) {
					httpreterr(ucid, http_sret404, 400);
					return pPkg->HasKeepAlive();
				}
				long long flen = ec::IO::filesize(sfile);
				if (flen < 0) {
					httpreterr(ucid, http_sret404, 404);
					return pPkg->HasKeepAlive();
				}
				if (flen > MAX_FILESIZE_HTTP_DOWN) {
					httpreterr(ucid, http_sret404outsize, 404);
					return pPkg->HasKeepAlive();
				}

				vector<char> answer(1024 * 32, true, _pmem);
				sc = "HTTP/1.1 200 ok\r\n";
				answer.add(sc, strlen(sc));

				sc = "Server: rdb5 websocket server\r\n";
				answer.add(sc, strlen(sc));

				if (pPkg->HasKeepAlive()) {
					sc = "Connection: keep-alive\r\n";
					answer.add(sc, strlen(sc));
				}
				const char* sext = file_extname(sfile);
				if (sext && *sext && getmime(sext, tmp, sizeof(tmp))) {
					answer.add("Content-type: ", 13);
					answer.add(tmp, strlen(tmp));
					answer.add("\r\n", 2);
				}
				else {
					sc = "Content-type: application/octet-stream\r\n";
					answer.add(sc, strlen(sc));
				}

				int necnode = 0;
				if (pPkg->GetHeadFiled("Accept-Encoding", tmp, sizeof(tmp))) {
					char sencode[16] = { 0 };
					size_t pos = 0;
					while (ec::str_getnext(";,", tmp, strlen(tmp), pos, sencode, sizeof(sencode))) {
						if (!ec::str_icmp("deflate", sencode)) {
							sc = "Content-Encoding: deflate\r\n";
							answer.add(sc, strlen(sc));
							necnode = HTTPENCODE_DEFLATE;
							break;
						}
					}
				}
				vector<char>	filetmp(1024 * 16, true, _pmem);
				if (!IO::LckRead(sfile, &filetmp)) {
					httpreterr(ucid, http_sret404, 404);
					return pPkg->HasKeepAlive();
				}
				size_t poslen = answer.size(), sizehead;
				sprintf(tmp, "Content-Length: %9d\r\n\r\n", (int)filetmp.size());
				answer.add(tmp, strlen(tmp));
				sizehead = answer.size();
				if (HTTPENCODE_DEFLATE == necnode) {
					if (Z_OK != ec::ws_encode_zlib(filetmp.data(), filetmp.size(), &answer)) {
						if (_plog)
							_plog->add(CLOG_DEFAULT_ERR, "ucid %u ws_encode_zlib failed", ucid);
						return false;
					}
					filetmp.~vector();
					sprintf(tmp, "Content-Length: %9d\r\n\r\n", (int)(answer.size() - sizehead));
					memcpy(answer.data() + poslen, tmp, strlen(tmp));	// reset Content-Length	
					if (!bGet)
						answer.set_size(sizehead);
				}
				else {
					if (bGet)
						answer.add(filetmp.data(), filetmp.size());
				}

				if (_plog)
					_plog->add(CLOG_DEFAULT_MSG, "write ucid %u size %zu", ucid, answer.size());
				return sendbyucid(ucid, answer.data(), answer.size()) > 0;
			}

			void httpreterr(unsigned int ucid, const char* sret, int errcode)
			{
				int nret = sendbyucid(ucid, sret, strlen(sret));
				if (_plog) {
					if (nret > 0)
						_plog->add(CLOG_DEFAULT_DBG, "http write ucid %u: error %d", ucid, errcode);
					else
						_plog->add(CLOG_DEFAULT_DBG, "http write ucid %u failed.", ucid);
				}
			}

			bool DoUpgradeWebSocket(ws_session* pws, const char *skey)
			{
				if (_plog) {
					char stmp[128] = { 0 };
					_plog->add(CLOG_DEFAULT_MSG, "ucid %u upgrade websocket", pws->_ucid);
					if (_httppkg.GetHeadFiled("Origin", stmp, sizeof(stmp)))
						_plog->append(CLOG_DEFAULT_DBG, "\tOrigin: %s\n", stmp);
					if (_httppkg.GetHeadFiled("Sec-WebSocket-Extensions", stmp, sizeof(stmp)))
						_plog->append(CLOG_DEFAULT_DBG, "\tSec-WebSocket-Extensions: %s\n", stmp);
				}

				const char* sc;
				char sProtocol[128] = { 0 }, sVersion[128] = { 0 }, tmp[256] = { 0 };
				_httppkg.GetHeadFiled("Sec-WebSocket-Protocol", sProtocol, sizeof(sProtocol));
				_httppkg.GetHeadFiled("Sec-WebSocket-Version", sVersion, sizeof(sVersion));

				if (atoi(sVersion) != 13) {
					if (_plog)
						_plog->add(CLOG_DEFAULT_MSG, "ws sVersion(%s) error :ucid=%d, ", sVersion, pws->_ucid);
					pws->send(http_sret400, strlen(http_sret400));
					return _httppkg.HasKeepAlive();
				}
				vector<char> vret(1024 * 4, _pmem);
				sc = "HTTP/1.1 101 Switching Protocols\x0d\x0a"
					"Upgrade: websocket\x0d\x0a"
					"Connection: Upgrade\x0d\x0a";
				vret.add(sc, strlen(sc));

				char ss[256];
				strcpy(ss, skey);
				strcat(ss, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

				char sha1out[20] = { 0 }, base64out[32] = { 0 };
				encode_sha1(ss, (unsigned int)strlen(ss), sha1out); //SHA1
				encode_base64(base64out, sha1out, 20);    //BASE64

				sc = "Sec-WebSocket-Accept: ";
				vret.add(sc, strlen(sc));
				vret.add(base64out, strlen(base64out));
				vret.add("\x0d\x0a", 2);

				if (sProtocol[0]) {
					sc = "Sec-WebSocket-Protocol: ";
					vret.add(sc, strlen(sc));
					vret.add(sProtocol, strlen(sProtocol));
					vret.add("\x0d\x0a", 2);
				}

				if (_httppkg.GetHeadFiled("Host", tmp, sizeof(tmp))) {
					sc = "Host: ";
					vret.add(sc, strlen(sc));
					vret.add(tmp, strlen(tmp));
					vret.add("\x0d\x0a", 2);
				}

				int ncompress = 0;
				if (_httppkg.GetHeadFiled("Sec-WebSocket-Extensions", tmp, sizeof(tmp))) {
					char st[64] = { 0 };
					size_t pos = 0, len = strlen(tmp);
					while (ec::str_getnext(";,", tmp, len, pos, st, sizeof(st))) {
						if (!ec::str_icmp("permessage-deflate", st)) {
							sc = "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover";
							vret.add(sc, strlen(sc));
							vret.add("\x0d\x0a", 2);
							ncompress = ws_permessage_deflate;
							break;
						}
						else if (!ec::str_icmp("x-webkit-deflate-frame", st)) {
							sc = "Sec-WebSocket-Extensions: x-webkit-deflate-frame; no_context_takeover";
							vret.add(sc, strlen(sc));
							vret.add("\x0d\x0a", 2);
							ncompress = ws_x_webkit_deflate_frame;
							break;
						}
					}
				}
				vret.add("\x0d\x0a", 2);
				pws->_txt.clear((size_t)0);

				int ns = pws->send(vret.data(), vret.size());
				if (_plog) {
					vret.add((char)0);
					vret.for_each([](char &v) {
						if ('\r' == v)
							v = '\x20';
					});
				}

				if (ns < 0) {
					if (_plog)
						_plog->add(CLOG_DEFAULT_MSG, "ucid %d upggrade WS failed\n%s", pws->_ucid, vret.data());
					return false;
				}

				if (_plog)
					_plog->add(CLOG_DEFAULT_MSG, "ucid %d upggrade WS success\n%s", pws->_ucid, vret.data());

				pws->_protocol = PROTOCOL_WS;
				pws->_wscompress = ncompress;
				pws->_status |= EC_PROTOC_ST_WORK;
				return ns > 0;
			}
		};
	}//tcp
}// ec



