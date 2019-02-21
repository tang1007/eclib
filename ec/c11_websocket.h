/*!
\file c11_websocket.h
\author	jiangyong
\email  kipway@outlook.com
\update 2019.1.22

eclib websocket protocol
http protocol only support get and head. websocket protocol support Sec-WebSocket-Version:13

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

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include "c11_netio.h"
#include "c11_config.h"
#include "c_diskio.h"
#include "c11_keyval.h"
#include "c_base64.h"

#include "c_sha1.h"
#include "zlib/zlib.h"

#ifndef _WIN32
#ifndef stricmp
#define stricmp(a,b)    strcasecmp(a,b)
#endif // stricmp
#endif
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

namespace ec
{
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
	template<class _Tp>
	inline int ws_encode_zlib(const void *pSrc, size_t size_src, ec::vector<_Tp>* pout)//pout first two byte x78 and x9c,the end  0x00 x00 xff xff, no  adler32
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
			if(!pout->add((_Tp*)outbuf, stream.total_out - uout)) {
				err = Z_MEM_ERROR;
				break;
			}
			uout += stream.total_out - uout;
		}
		deflateEnd(&stream);
		return err;
	}	

	template<class _Tp>
	inline int ws_decode_zlib(const void *pSrc, size_t size_src, ec::vector<_Tp>* pout)//pSrc begin with 0x78 x9c, has no end 0x00 x00 xff xff
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
			if(!pout->add((_Tp*)outbuf, stream.total_out - uout)) {
				err = Z_MEM_ERROR;
				break;
			}
			uout += stream.total_out - uout;
		}
		inflateEnd(&stream);
		return err;
	}

	template<class _Tp>
	inline bool ws_make_permsg(const void* pdata, size_t sizes, unsigned char wsopt, vector<_Tp>* pout, int ncompress) //multi-frame,permessage_deflate
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
			pout->add((_Tp)uc);
			if (us < 126)
			{
				uc = (unsigned char)us;
				pout->add(uc);
			}
			else if (uc < 65536)
			{
				uc = 126;
				pout->add(uc);
				pout->add((_Tp)((us & 0xFF00) >> 8)); //high byte
				pout->add((_Tp)(us & 0xFF)); //low byte
			}
			else // < 4G
			{
				uc = 127;
				pout->add((_Tp)uc);
				pout->add((_Tp)0); pout->add((_Tp)0); pout->add((_Tp)0); pout->add((_Tp)0);//high 4 bytes 0
				pout->add((_Tp)((us & 0xFF000000) >> 24));
				pout->add((_Tp)((us & 0x00FF0000) >> 16));
				pout->add((_Tp)((us & 0x0000FF00) >> 8));
				pout->add((_Tp)(us & 0xFF));
			}
			pout->add((_Tp*)(pds + ss), us);
			ss += us;
		}
		return true;
	}
	
	template<class _Tp>
	inline bool ws_make_perfrm(const void* pdata, size_t sizes, unsigned char wsopt, vector< _Tp>* pout)//multi-frame,deflate-frame, for ios safari
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
			pout->add((_Tp)uc);
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
				pout->add((_Tp)((fl & 0xFF00) >> 8)); //high byte
				pout->add((_Tp)(fl & 0xFF)); //low byte
			}
			else // < 4G
			{
				uc = 127;
				pout->add(uc);
				pout->add((_Tp)0); pout->add((_Tp)0); pout->add((_Tp)0); pout->add((_Tp)0);//high 4 bytes 0
				pout->add((_Tp)((fl & 0xFF000000) >> 24));
				pout->add((_Tp)((fl & 0x00FF0000) >> 16));
				pout->add((_Tp)((fl & 0x0000FF00) >> 8));
				pout->add((_Tp)(fl & 0xFF));
			}
			pout->add((_Tp*)pf, fl);
			ss += us;
		}
		return true;
	}

	inline bool IsDir(const char* s)
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
	inline const char *GetFileExtName(const char*s)
	{
		const char *pr = NULL;
		while (*s)
		{
			if (*s == '.')
				pr = s;
			s++;
		}
		return pr;
	}

	/*!
	\brief httpsrv config

	[http]
	port = 9070                #http server port 80 ,0 as not use WS
	rootpath = e:/httptst      #http root

	[https]
	port = 0                   #http server port 443,0 as not use WSS
	rootpath = c:/rdb_https    #http root

	ca_root =
	ca_server = c:/ca/yoursrv.cer
	private_key= c:/ca/yoursrv.key

	[mime]
	.323 = text/h323
	.3gp = video/3gpp

	*/
	class cHttpCfg : public config
	{
	public:
		cHttpCfg() :
			_mimemem(ec::map<const char*, t_httpmime>::size_node(), 512),
			_mime(512, &_mimemem)
		{
			reset();
		};
		virtual ~cHttpCfg() {
			_mime.clear();
		};
	public:
		unsigned short _wport; // http and ws
		char _sroot[512];      // httpdoc root , utf8

		unsigned short _wport_wss;//https and wss
		char _sroot_wss[512];     //httpsdoc root , utf8

		char _ca_server[512]; // ca
		char _ca_root[512];
		char _private_key[512];

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
			if (!stricmp("http", lpszBlkName)) {
				if (!stricmp("rootpath", lpszKeyName)) {
					if (lpszKeyVal && *lpszKeyVal)
						ec::str_ncpy(_sroot, lpszKeyVal, sizeof(_sroot) - 1);
				}
				else if (!stricmp("port", lpszKeyName)) {
					if (lpszKeyVal && *lpszKeyVal)
						_wport = (unsigned short)atoi(lpszKeyVal);
				}
			}
			if (!stricmp("https", lpszBlkName)) {
				if (!stricmp("rootpath", lpszKeyName)) {
					if (lpszKeyVal && *lpszKeyVal)
						ec::str_ncpy(_sroot_wss, lpszKeyVal, sizeof(_sroot_wss) - 1);
				}
				else if (!stricmp("port", lpszKeyName)) {
					if (lpszKeyVal && *lpszKeyVal)
						_wport_wss = (unsigned short)atoi(lpszKeyVal);
				}
				else if (!stricmp("ca_root", lpszKeyName)) {
					if (lpszKeyVal && *lpszKeyVal)
						ec::str_ncpy(_ca_root, lpszKeyVal, sizeof(_ca_root) - 1);
				}
				else if (!stricmp("ca_server", lpszKeyName)) {
					if (lpszKeyVal && *lpszKeyVal)
						ec::str_ncpy(_ca_server, lpszKeyVal, sizeof(_ca_server) - 1);
				}
				else if (!stricmp("private_key", lpszKeyName)) {
					if (lpszKeyVal && *lpszKeyVal)
						ec::str_ncpy(_private_key, lpszKeyVal, sizeof(_private_key) - 1);
				}
			}
			else  if (!stricmp("mime", lpszBlkName)) {
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
			_wport = 0;
			memset(_sroot, 0, sizeof(_sroot));

			_wport_wss = 0;
			memset(_sroot_wss, 0, sizeof(_sroot_wss));

			memset(_ca_server, 0, sizeof(_ca_server));
			memset(_ca_root, 0, sizeof(_ca_root));
			memset(_private_key, 0, sizeof(_private_key));
		}
		virtual void OnReadFile()
		{
			reset();
		}
	};

	/*!
	\brief http packet from client, One class per thread
	*/
	class cHttpPacket
	{
	public:
		cHttpPacket(ec::memory* pmem) : _body(1024 * 128, pmem), _pmem(pmem), _fin(0), _opcode(0), _comp(0)
		{
			initbuf();
		};
		~cHttpPacket() {};
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
	\brief http connections
	*/
	class cHttpClient
	{
	public:
		cHttpClient(unsigned int ucid, const char* sip, ec::memory* pmem) :
			_txt(1024 * 16, pmem), _wsmsg(1024 * 16, pmem), _pmem(pmem)
		{
			memset(_sip, 0, sizeof(_sip));
			_ucid = ucid;
			_protocol = PROTOCOL_HTTP;
			if (sip && *sip)
				strncpy(_sip, sip, sizeof(_sip) - 1);
			_wscompress = 0;
			_comp = 0;
			_opcode = WS_OP_TXT;
		};
		~cHttpClient() {};
	public:
		int  _wscompress; // ws_x_webkit_deflate_frame or ws_permessage_deflate
		int	 _protocol;   // HTTP_PROTOCOL:http; WEB_SOCKET:websocket        
		uint32_t   _ucid; // client user connect ID
		char _sip[32];	  //ip address
		vector<char> _txt;   // tmp
		vector<char> _wsmsg; // complete websocket message
		int _comp;// compress flag
		int _opcode;  // operate code
	private:
		ec::memory* _pmem;
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

			if (payloadlen == 126)
			{
				datapos += 2;
				if (usize < datapos)
					return he_waitdata;

				datalen = pu[2];
				datalen <<= 8;
				datalen |= pu[3];
			}
			else if (payloadlen == 127)
			{
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
			else
			{
				datalen = payloadlen;
				if (usize < datapos)
					return he_waitdata;
			}
			if (usize < datapos + datalen)
				return 0;
			if (bmask)
			{
				unsigned int umask = pu[datapos - 1];	umask <<= 8;
				umask |= pu[datapos - 2]; umask <<= 8;
				umask |= pu[datapos - 3]; umask <<= 8;
				umask |= pu[datapos - 4];
				fast_xor_le(pu + datapos, (int)datalen, umask);
			}
			sizedo = datapos + datalen;

			if (!comp)
				_wsmsg.add(stxt + datapos, datalen);
			else
			{
				if (_wscompress == ws_x_webkit_deflate_frame) //deflate_frame
				{
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
				else
				{
					_comp = 1;
					_wsmsg.clear(size_t(0));
					_wsmsg.add('\x78');
					_wsmsg.add('\x9c');
					_wsmsg.add(stxt + datapos, datalen);
				}
			}
			return (int)sizedo;
		}

		int WebsocketParse(const char* stxt, size_t usize, size_t &sizedo, cHttpPacket* pout)//support multi-frame
		{
			const char *pd = stxt;
			int ndo = 0, fin = 0;
			sizedo = 0;
			while (sizedo < usize)
			{
				ndo = ParseOneFrame(pd, usize - sizedo, fin);
				if (ndo <= 0)
					break;
				sizedo += ndo;
				pd += ndo;
				if (fin)// end frame
				{
					pout->_body.clear();
					if (_comp && _wscompress == ws_permessage_deflate)
					{
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
		int OnReadData(unsigned int ucid, const char* pdata, size_t usize, cHttpPacket* pout)
		{
			if (!pdata || !usize || !pout)
				return he_failed;
			size_t sizedo = 0;
			pout->Resetwscomp();
			pout->_nprotocol = _protocol;
			_txt.add(pdata, usize);
			if (_protocol == PROTOCOL_HTTP)
			{
				int nr = pout->HttpParse(_txt.data(), _txt.size(), sizedo);
				if (nr == he_ok)
					_txt.erase(0, sizedo);
				else
				{
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
				else
				{
					if (_txt.size() > EC_SIZE_WS_READ_FRAME_MAX) {
						_txt.clear((size_t)0);
						return he_failed;
					}
				}
				_txt.shrink(0);
			}
			return nr;
		}

		int DoNextData(unsigned int ucid, cHttpPacket* pout)
		{
			pout->Resetwscomp();
			size_t sizedo = 0;
			if (_protocol == PROTOCOL_HTTP)
			{
				int nr = pout->HttpParse(_txt.data(), _txt.size(), sizedo);
				if (nr == he_ok)
					_txt.erase(0, sizedo);
				else
				{
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
				else
				{
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

	struct t_httpclient
	{
		memory* pmem;
		cHttpClient* pcli;
	};

	template<>
	struct key_equal<uint32_t, t_httpclient>
	{
		inline bool operator()(unsigned int key, const t_httpclient &val)
		{
			return key == val.pcli->_ucid;
		}
	};

	template<>
	struct del_node<t_httpclient>
	{
		inline void operator()(t_httpclient& val)
		{
			if (val.pcli) {
				if (val.pmem) {
					val.pcli->~cHttpClient();
					val.pmem->mem_free(val.pcli);
				}
				else
					delete val.pcli;
				val.pcli = nullptr;
			}
		}
	};

	class cHttpClientMap // HTTP connect map
	{
	public:
		cHttpClientMap(uint32_t nmaxconnect) :
			_mem(ec::map<const char*, t_httpclient>::size_node(), nmaxconnect, 1024 * 16, 64, 1024 * 512, 24, &_lockmem),
			_map(nmaxconnect, &_mem), _memcls(sizeof(cHttpClient), nmaxconnect, 0, 0, 0, 0, &_lockcls)
		{
		}
		~cHttpClientMap()
		{
			_map.clear();
		}
	private:
		std::mutex _cs;
		ec::spinlock _lockmem;
		ec::memory _mem; //memory for map

		map<unsigned int, t_httpclient> _map;

		ec::spinlock _lockcls;
		ec::memory _memcls; // memory for new cHttpClient
	public:

		int OnReadData(unsigned int ucid, const char* pdata, size_t usize, cHttpPacket* pout) // return he_ok: msg in pout
		{
			ec::unique_lock lck(&_cs);
			t_httpclient item;
			if (!_map.get(ucid, item))
				return he_failed;
			return item.pcli->OnReadData(ucid, pdata, usize, pout);
		}

		int DoNextData(unsigned int ucid, cHttpPacket* pout)
		{
			unique_lock lck(&_cs);
			t_httpclient item;
			if (!_map.get(ucid, item))
				return he_failed;
			return item.pcli->DoNextData(ucid, pout);
		}

		void Add(unsigned int ucid, const char* sip)// add one client
		{
			unique_lock lck(&_cs);
			void *p = _memcls.mem_malloc(sizeof(cHttpClient));
			if (!p)
				return;
			cHttpClient* pcli = new (p) cHttpClient(ucid, sip, &_mem);
			if (pcli) {
				t_httpclient item;
				item.pcli = pcli;
				item.pmem = &_memcls;
				_map.set(ucid, item);
			}
		}
		bool Del(unsigned int ucid)
		{
			unique_lock lck(&_cs);
			return _map.erase(ucid);
		}

		void UpgradeWebSocket(unsigned int ucid, int wscompress)
		{
			unique_lock lck(&_cs);
			t_httpclient item;
			if (!_map.get(ucid, item))
				return;
			item.pcli->_protocol = PROTOCOL_WS;
			item.pcli->_wscompress = wscompress;
			item.pcli->_txt.clear((size_t)0);
		}

		int GetCompress(unsigned int ucid)
		{
			unique_lock lck(&_cs);
			t_httpclient item;
			if (!_map.get(ucid, item))
				return 0;
			return item.pcli->_wscompress;
		}
	};

	template<class _CLS>
	class cWebsocket
	{
	public:
		cWebsocket(cHttpClientMap* pclis, cHttpCfg*  pcfg, cLog* plog, ec::memory* pmem, bool bwss) :_bwss(bwss), _pcfg(pcfg), _plog(plog), _pclis(pclis),
			_pmem(pmem), _httppkg(pmem) {
		}
		virtual ~cWebsocket() {};
	protected:
		bool _bwss;
		cHttpCfg * _pcfg;
		cLog*			_plog;
		cHttpClientMap*	_pclis;
		ec::memory*     _pmem;
		cHttpPacket		_httppkg;
	protected:
		/*
		void onwsread(uint32_t ucid, int bFinal, int wsopcode, const void* pdata, size_t size) = 0;
		void dodisconnect(uint32_t ucid) = 0;
		int  dosend(uint32_t ucid, vector<uint8_t> *pvd, int timeovermsec = 0) = 0;
		bool onhttprequest(uint32_t ucid, cHttpPacket* pPkg);
		*/
		bool DoUpgradeWebSocket(int ucid, const char *skey)
		{
			if (_plog) {
				char stmp[128] = { 0 };
				_plog->add(CLOG_DEFAULT_MSG, "ucid %u upgrade websocket", ucid);
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
					_plog->add(CLOG_DEFAULT_MSG, "ws sVersion(%s) error :ucid=%d, ", sVersion, ucid);
				httpreterr(ucid, http_sret400);
				return _httppkg.HasKeepAlive();
			}
			vector<uint8_t> vret(1024 * 4, _pmem);
			sc = "HTTP/1.1 101 Switching Protocols\x0d\x0a"
				"Upgrade: websocket\x0d\x0a"
				"Connection: Upgrade\x0d\x0a";
			vret.add((const uint8_t*)sc, strlen(sc));

			char ss[256];
			strcpy(ss, skey);
			strcat(ss, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

			char sha1out[20] = { 0 }, base64out[32] = { 0 };
			encode_sha1(ss, (unsigned int)strlen(ss), sha1out); //SHA1
			encode_base64(base64out, sha1out, 20);    //BASE64

			sc = "Sec-WebSocket-Accept: ";
			vret.add((const uint8_t*)sc, strlen(sc));
			vret.add((const uint8_t*)base64out, strlen(base64out));
			vret.add((const uint8_t*)"\x0d\x0a", 2);

			if (sProtocol[0]) {
				sc = "Sec-WebSocket-Protocol: ";
				vret.add((const uint8_t*)sc, strlen(sc));
				vret.add((const uint8_t*)sProtocol, strlen(sProtocol));
				vret.add((const uint8_t*)"\x0d\x0a", 2);
			}

			if (_httppkg.GetHeadFiled("Host", tmp, sizeof(tmp))) {
				sc = "Host: ";
				vret.add((const uint8_t*)sc, strlen(sc));
				vret.add((const uint8_t*)tmp, strlen(tmp));
				vret.add((const uint8_t*)"\x0d\x0a", 2);
			}

			int ncompress = 0;
			if (_httppkg.GetHeadFiled("Sec-WebSocket-Extensions", tmp, sizeof(tmp))) {
				char st[64] = { 0 };
				size_t pos = 0, len = strlen(tmp);
				while (ec::str_getnext(";,", tmp, len, pos, st, sizeof(st))) {
					if (!ec::str_icmp("permessage-deflate", st)) {
						sc = "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover";
						vret.add((const uint8_t*)sc, strlen(sc));
						vret.add((const uint8_t*)"\x0d\x0a", 2);
						ncompress = ws_permessage_deflate;
						break;
					}
					else if (!ec::str_icmp("x-webkit-deflate-frame", st)) {
						sc = "Sec-WebSocket-Extensions: x-webkit-deflate-frame; no_context_takeover";
						vret.add((const uint8_t*)sc, strlen(sc));
						vret.add((const uint8_t*)"\x0d\x0a", 2);
						ncompress = ws_x_webkit_deflate_frame;
						break;
					}
				}
			}
			vret.add((const uint8_t*)"\x0d\x0a", 2);
			_pclis->UpgradeWebSocket(ucid, ncompress);

			int ns = 0;
			if (_plog) {
				vector<char> vlog(1024 * 4, _pmem);
				vlog.add((const char*)vret.data(), vret.size());
				vlog.add(char(0));
				ns = http_send(ucid, &vret);
				if (ns < 0) {
					_plog->add(CLOG_DEFAULT_MSG, "ucid %d upggrade WS failed", ucid);
					_plog->append(CLOG_DEFAULT_DBG, "%s", vlog.data());
					return false;
				}
				_plog->add(CLOG_DEFAULT_MSG, "ucid %d upggrade WS success", ucid);
				_plog->append(CLOG_DEFAULT_DBG, "%s", vlog.data());
			}
			else
				ns = http_send(ucid, &vret);
			return ns > 0;
		}

	protected:
		void OnWsPing(unsigned int ucid, const void* pdata, size_t size)
		{
			ws_send(ucid, pdata, size, WS_OP_PONG);
		}

		bool DoHttpRequest(unsigned int ucid)// return false will disconnect
		{
			if (_plog) {
				if (_httppkg._reqargs[0])
					_plog->add(CLOG_DEFAULT_MSG, "ucid %u read: %s %s?%s %s", ucid, _httppkg._method, _httppkg._request, _httppkg._reqargs, _httppkg._version);
				else
					_plog->add(CLOG_DEFAULT_MSG, "ucid %u read: %s %s %s", ucid, _httppkg._method, _httppkg._request, _httppkg._version);
			}
			if (!stricmp("GET", _httppkg._method)) { //GET			
				char skey[128];
				if (_httppkg.GetWebSocketKey(skey, sizeof(skey))) //websocket Upgrade
					return DoUpgradeWebSocket(ucid, skey);
			}
			return static_cast<_CLS*>(this)->onhttprequest(ucid, &_httppkg);
		}

		bool httprequest(uint32_t ucid, cHttpPacket* pPkg) //default httprequest
		{
			if (!stricmp("GET", _httppkg._method))
				return  DoGetAndHead(ucid, pPkg);
			else if (!stricmp("HEAD", _httppkg._method))
				return  DoGetAndHead(ucid, pPkg, false);
			httpreterr(ucid, http_sret400);
			return _httppkg.HasKeepAlive();
		}

		bool DoGetAndHead(uint32_t ucid, cHttpPacket* pPkg, bool bGet = true)
		{
			char sfile[1024], tmp[4096];
			const char* sc;
			sfile[0] = '\0';
			tmp[0] = '\0';

			if (!_bwss)
				strcpy(sfile, _pcfg->_sroot);
			else
				strcpy(sfile, _pcfg->_sroot_wss);

			url2utf8(pPkg->_request, tmp, (int)sizeof(tmp));

			strcat(sfile, tmp);

			size_t n = strlen(sfile);
			if (n && (sfile[n - 1] == '/' || sfile[n - 1] == '\\'))
				strcat(sfile, "index.html");
			else if (IsDir(sfile)) {
				httpreterr(ucid, http_sret404);
				return pPkg->HasKeepAlive();
			}
			size_t flen = ec::IO::filesize(sfile);
			if (flen > MAX_FILESIZE_HTTP_DOWN) {
				httpreterr(ucid, http_sret404outsize);
				return pPkg->HasKeepAlive();
			}
			
			vector<uint8_t> answer(1024 * 32, true, _pmem);
			sc = "HTTP/1.1 200 ok\r\n";
			answer.add((const uint8_t*)sc, strlen(sc));

			sc = "Server: rdb5 websocket server\r\n";
			answer.add((const uint8_t*)sc, strlen(sc));

			if (pPkg->HasKeepAlive()) {
				sc = "Connection: keep-alive\r\n";
				answer.add((const uint8_t*)sc, strlen(sc));
			}
			const char* sext = GetFileExtName(sfile);
			if (sext && *sext && _pcfg->getmime(sext, tmp, sizeof(tmp))) {
				answer.add((const uint8_t*)"Content-type: ", 13);
				answer.add((const uint8_t*)tmp, strlen(tmp));
				answer.add((const uint8_t*)"\r\n", 2);
			}
			else {
				sc = "Content-type: application/octet-stream\r\n";
				answer.add((const uint8_t*)sc, strlen(sc));
			}

			int necnode = 0;
			if (pPkg->GetHeadFiled("Accept-Encoding", tmp, sizeof(tmp))) {
				char sencode[16] = { 0 };
				size_t pos = 0;
				while (ec::str_getnext(";,", tmp, strlen(tmp), pos, sencode, sizeof(sencode))) {
					if (!ec::str_icmp("deflate", sencode)) {
						sc = "Content-Encoding: deflate\r\n";
						answer.add((const uint8_t*)sc, strlen(sc));
						necnode = HTTPENCODE_DEFLATE;
						break;
					}
				}
			}			
			vector<char>	filetmp(1024 * 16, true, _pmem);
			if (!IO::LckRead(sfile, &filetmp)) {
				httpreterr(ucid, http_sret404);
				return pPkg->HasKeepAlive();
			}
			size_t poslen = answer.size(),sizehead;
			sprintf(tmp, "Content-Length: %9d\r\n\r\n", (int)filetmp.size());
			answer.add((const uint8_t*)tmp, strlen(tmp));
			sizehead = answer.size();
			if (HTTPENCODE_DEFLATE == necnode) {
				if (Z_OK != ec::ws_encode_zlib(filetmp.data(), filetmp.size(), &answer)) {		
					if(_plog)
						_plog->add(CLOG_DEFAULT_ERR, "ucid %u ws_encode_zlib failed", ucid);
					return false;
				}
				filetmp.clear(true);
				sprintf(tmp, "Content-Length: %9d\r\n\r\n", (int)(answer.size() - sizehead));
				memcpy(answer.data() + poslen, tmp, strlen(tmp));	// reset Content-Length	
				if (!bGet)
					answer.set_size(sizehead);
			}	
			else {
				if (bGet)
					answer.add((const uint8_t*)filetmp.data(), filetmp.size());
			}

			if (_plog)
				_plog->add(CLOG_DEFAULT_MSG, "write ucid %u size %zu", ucid, answer.size());
			return http_send(ucid, &answer) > 0;			
		}

		void httpreterr(unsigned int ucid, const char* sret)
		{
			vector<uint8_t> vret(1024 * 2, _pmem);
			vret.add((const uint8_t*)sret, strlen(sret));
			int nret = http_send(ucid, &vret);
			if (_plog) {
				if(nret > 0)
					_plog->add(CLOG_DEFAULT_DBG, "http write ucid %u:\n%s", ucid, sret);
				else
					_plog->add(CLOG_DEFAULT_DBG, "http write ucid %u failed.\n%s", ucid, sret);
			}
		}

		void doreadbytes(unsigned int ucid, const void* pdata, size_t usize)
		{
			bool bret = true;
			int nr = _pclis->OnReadData(ucid, (const char*)pdata, usize, &_httppkg);
			while (nr == he_ok)
			{
				if (_httppkg._nprotocol == PROTOCOL_HTTP) {
					if (!DoHttpRequest(ucid))
						static_cast<_CLS*>(this)->dodisconnect(ucid);
				}
				else if (_httppkg._nprotocol == PROTOCOL_WS) {
					if (_httppkg._opcode <= WS_OP_BIN)
						static_cast<_CLS*>(this)->onwsread(ucid, _httppkg._fin, _httppkg._opcode, _httppkg._body.data(), _httppkg._body.size());
					else if (_httppkg._opcode == WS_OP_CLOSE) {
						if (_plog)
							_plog->add(CLOG_DEFAULT_MSG, "ucid %d WS_OP_CLOSE!", ucid);
						static_cast<_CLS*>(this)->dodisconnect(ucid);
					}
					else if (_httppkg._opcode == WS_OP_PING) {
						OnWsPing(ucid, _httppkg._body.data(), _httppkg._body.size());
						if (_plog)
							_plog->add(CLOG_DEFAULT_MSG, "ucid %d WS_OP_PING!", ucid);
						bret = true;
					}
					_httppkg.Resetwscomp();
				}
				nr = _pclis->DoNextData(ucid, &_httppkg);
			}
			if (nr == he_failed) {
				httpreterr(ucid, http_sret400);
				static_cast<_CLS*>(this)->dodisconnect(ucid);
			}
		};
		int ws_send(unsigned int ucid, const void* pdata, size_t size, unsigned char wsopt, int waitmsec = 100) //return -1 error, >0 is send bytes
		{
			bool bsend;
			int ncomp = _pclis->GetCompress(ucid);
			vector<uint8_t> vret(2048 + size - size % 1024, cWebsocket::_pmem);
			if (ncomp == ws_x_webkit_deflate_frame) //deflate-frame
			{				
				vret.set_grow(2048 + size / 2 - size % 1024);
				bsend = ws_make_perfrm(pdata, size, wsopt, &vret);
			}
			else // ws_permessage_deflate
			{
				if(size > 128 && ncomp)
					vret.set_grow(2048 + size / 2 - size % 1024);
				bsend = ws_make_permsg(pdata, size, wsopt, &vret, size > 128 && ncomp);
			}
			if (!bsend) {
				if (cWebsocket::_plog)
					cWebsocket::_plog->add(CLOG_DEFAULT_ERR, "send ucid %u make wsframe failed,size %u", ucid, (unsigned int)size);
				return -1;
			}
			return static_cast<_CLS*>(this)->dosend(ucid, &vret, waitmsec);
		}
		inline int http_send(unsigned int ucid, vector<uint8_t> *pvd, int waitmsec = 100)
		{
			return  static_cast<_CLS*>(this)->dosend(ucid, pvd, waitmsec);
		}
	};

	class http_pargs {
	public:
		http_pargs(cHttpCfg* pcfg, cHttpClientMap* pmap) : _pcfg(pcfg), _pmap(pmap) {}
		cHttpCfg* _pcfg;
		cHttpClientMap* _pmap;
	};
}
