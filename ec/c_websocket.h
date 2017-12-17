﻿/*!
\file w_websocket.h
\brief websocket protocol,http protocol only support get,head ; websocket protocol support Sec-WebSocket-Version:13
\date 2016.8.14

\author	 kipway@outlook.com
*/

#ifndef C_WEBSOCKET_H
#define C_WEBSOCKET_H

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include "c_array.h"
#include "c_map.h"
#include "c_base64.h"
#include "c_diskio.h"
#include "c_log.h"
#include "c_readini.h"
#include "c_tcp_srv.h"
#include "c_sha1.h"
#include "c_str.h"
#include "zlib/zlib.h"
#include "c_zlibs.h"

#ifndef _WIN32
#ifndef stricmp
#define stricmp(a,b)    strcasecmp(a,b)
#endif // stricmp
#endif

#define SIZE_HTTPMAXREQUEST (1024 * 64)
#define SIZE_WSMAXREQUEST   (1024 * 256)

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

	struct t_mime
	{
		char sext[16];
		char stype[128];
	};

	template<>
	inline bool tMap<const char*, t_mime> ::ValueKey(const char* key, t_mime* p)
	{
		return !strcmp(key, p->sext);
	}
	template<>
	inline void tMap<const char*, t_mime>::OnRemoveValue(t_mime* p) {}

#define SIZE_WSZLIBTEMP 32768
	inline int wsencode_zlib(const void *pSrc, size_t size_src, ec::tArray<char>* pout)//zlib压缩，输出pout中 x78 x9c开头, 0x00 x00 xff xff结束,无adler32
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

		stream.avail_out = 0;
		while (!stream.avail_out) {
			stream.next_out = (unsigned char*)outbuf;
			stream.avail_out = (unsigned int)sizeof(outbuf);
			err = deflate(&stream, Z_SYNC_FLUSH);
			if (err != Z_OK)
				break;
			pout->Add(outbuf, stream.total_out - (uLong)pout->GetSize());
		}
		deflateEnd(&stream);
		return err;
	}

	inline int wsdecode_zlib(const void *pSrc, size_t size_src, ec::tArray<char>* pout)//zlib解压,pSrc输入x78 x9c开头,不必使用0x00 x00 xff xff结束
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
		while (stream.avail_in > 0) {
			stream.next_out = (unsigned char*)outbuf;
			stream.avail_out = (unsigned int)sizeof(outbuf);
			err = inflate(&stream, Z_SYNC_FLUSH);
			if (err != Z_OK)
				break;
			pout->Add(outbuf, stream.total_out - (uLong)pout->GetSize());
		}
		inflateEnd(&stream);
		return err;
	}

	/*!
	\brief WS组发送帧,单帧,permessage_deflate支持
	*/
	inline bool MakeWsSend(const void* pdata, size_t sizes, unsigned char wsopt, tArray< char>* pout, int ncompress)
	{
		const char* pds = (const char*)pdata;
		size_t slen = sizes;
		tArray<char> tmp(2048 + sizes - sizes % 1024);
		unsigned char uc = 0x80 | (0x0F & wsopt);
		if (ncompress)
		{
			if (Z_OK != ec::wsencode_zlib(pdata, sizes, &tmp) || tmp.GetNum() < 6)
				return false;
			pds = tmp.GetBuf() + 2;
			slen = tmp.GetSize() - 6;
			uc |= 0x40;
		}

		pout->ClearData();
		pout->Add((char)uc);
		if (slen < 126)
		{
			uc = (unsigned char)slen;
			pout->Add((char)uc);
		}
		else if (uc < 65536)
		{
			uc = 126;
			pout->Add((char)uc);
			pout->Add((char)((slen & 0xFF00) >> 8)); //高字节
			pout->Add((char)(slen & 0xFF)); //低字节
		}
		else // < 4G
		{
			uc = 127;
			pout->Add((char)uc);
			pout->Add((char)0); pout->Add((char)0); pout->Add((char)0); pout->Add((char)0);//high 4 bytes 0
			pout->Add((char)((slen & 0xFF000000) >> 24));
			pout->Add((char)((slen & 0x00FF0000) >> 16));
			pout->Add((char)((slen & 0x0000FF00) >> 8));
			pout->Add((char)(slen & 0xFF));
		}
		pout->Add((const char*)pds, slen);
		return true;
	}

	/*!
	\brief WS组发送帧,多帧,permessage_deflate支持
	*/
	inline bool MakeWsSend_m(const void* pdata, size_t sizes, unsigned char wsopt, tArray< char>* pout, int ncompress, size_t framesize)
	{
		const char* pds = (const char*)pdata;
		size_t slen = sizes;
		tArray<char> tmp(2048 + sizes - sizes % 1024);
		unsigned char uc;
		if (ncompress)
		{
			if (Z_OK != ec::wsencode_zlib(pdata, sizes, &tmp) || tmp.GetNum() < 6)
				return false;
			pds = tmp.GetBuf() + 2;
			slen = tmp.GetSize() - 6;
		}
		size_t ss = 0, us;
		pout->ClearData();
		while (ss < slen)
		{
			uc = 0;
			if (0 == ss)//第一帧
			{
				uc = 0x0F & wsopt;
				if (ncompress)
					uc |= 0x40;
			}
			us = framesize;
			if (ss + framesize >= slen) //结束帧
			{
				uc |= 0x80;
				us = slen - ss;
			}
			pout->Add((char)uc);
			if (us < 126)
			{
				uc = (unsigned char)us;
				pout->Add((char)uc);
			}
			else if (uc < 65536)
			{
				uc = 126;
				pout->Add((char)uc);
				pout->Add((char)((us & 0xFF00) >> 8)); //高字节
				pout->Add((char)(us & 0xFF)); //低字节
			}
			else // < 4G
			{
				uc = 127;
				pout->Add((char)uc);
				pout->Add((char)0); pout->Add((char)0); pout->Add((char)0); pout->Add((char)0);//high 4 bytes 0
				pout->Add((char)((us & 0xFF000000) >> 24));
				pout->Add((char)((us & 0x00FF0000) >> 16));
				pout->Add((char)((us & 0x0000FF00) >> 8));
				pout->Add((char)(us & 0xFF));
			}
			pout->Add((const char*)(pds + ss), us);
			ss += us;
		}
		return true;
	}

	/*!
	\brief WS组发送帧,多帧,deflate-frame支持,适合ios safari
	*/
	inline bool MakeWsSend_mdf(const void* pdata, size_t sizes, unsigned char wsopt, tArray< char>* pout, size_t framesize)
	{
		const char* pds = (const char*)pdata;
		char* pf;
		size_t slen = sizes;
		tArray<char> tmp(2048 + framesize);
		unsigned char uc;
		size_t ss = 0, us, fl;
		pout->ClearData();
		while (ss < slen)
		{
			uc = 0;
			us = framesize;

			if (0 == ss)//第一帧
				uc = 0x0F & wsopt;
			if (us > 256)
				uc |= 0x40;
			if (ss + framesize >= slen) //结束帧
			{
				uc |= 0x80;
				us = slen - ss;
			}
			pout->Add((char)uc);
			if (uc & 0x40)
			{
				tmp.ClearData();
				if (Z_OK != ec::wsencode_zlib(pds + ss, us, &tmp) || tmp.GetNum() < 6)
					return false;
				pf = tmp.GetBuf() + 2;
				fl = tmp.GetSize() - 6;
			}
			else
			{
				pf = (char*)pds + ss;
				fl = us;
			}

			if (fl < 126)
			{
				uc = (unsigned char)fl;
				pout->Add((char)uc);
			}
			else if (uc < 65536)
			{
				uc = 126;
				pout->Add((char)uc);
				pout->Add((char)((fl & 0xFF00) >> 8)); //高字节
				pout->Add((char)(fl & 0xFF)); //低字节
			}
			else // < 4G
			{
				uc = 127;
				pout->Add((char)uc);
				pout->Add((char)0); pout->Add((char)0); pout->Add((char)0); pout->Add((char)0);//high 4 bytes 0
				pout->Add((char)((fl & 0xFF000000) >> 24));
				pout->Add((char)((fl & 0x00FF0000) >> 16));
				pout->Add((char)((fl & 0x0000FF00) >> 8));
				pout->Add((char)(fl & 0xFF));
			}
			pout->Add((const char*)pf, fl);
			ss += us;
		}
		return true;
	}
	/*!
	\brief 判断是否是目录
	*/
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
	\brief httpsrv配置
	*/
	class cHttpCfg : public cReadIni
	{
	public:

	public:
		cHttpCfg() :_mime(1024) {
			_wport = 0;
			_blogdetail = false;
			memset(_sroot, 0, sizeof(_sroot));
			memset(_slogpath, 0, sizeof(_slogpath));

			_wport_wss = 0;
			_blogdetail_wss = false;
			memset(_sroot_wss, 0, sizeof(_sroot_wss));
			memset(_slogpath_wss, 0, sizeof(_slogpath_wss));

			memset(_ca_server, 0, sizeof(_ca_server));
			memset(_ca_root, 0, sizeof(_ca_root));
			memset(_private_key, 0, sizeof(_private_key));


		};
		virtual ~cHttpCfg() {};
	public:
		//http and ws
		unsigned short _wport;//!< server port
		char _sroot[512];     //!< http root , utf8
		char _slogpath[512];
		bool _blogdetail;     //!< save detail log

		//https && wss
		unsigned short _wport_wss;//!< server port
		char _sroot_wss[512];     //!< http root , utf8
		char _slogpath_wss[512];
		bool _blogdetail_wss;     //!< save detail log

		char _ca_server[512];
		char _ca_root[512];
		char _private_key[512];

		tMap<const char*, t_mime> _mime;
	public:
		bool GetMime(const char* sext, char *sout, size_t outsize)
		{
			t_mime t;
			if (!_mime.Lookup(sext, t))
				return false;
			strncpy(sout, t.stype, outsize);
			return true;
		}
	protected:
		virtual void OnBlkName(const char* lpszBlkName) {};
		virtual void OnDoKeyVal(const char* lpszBlkName, const char* lpszKeyName, const char* lpszKeyVal)
		{
			if (!stricmp("http", lpszBlkName))
			{
				if (!stricmp("rootpath", lpszKeyName))
				{
					if (lpszKeyVal && *lpszKeyVal)
						ec::str_ncpy(_sroot, lpszKeyVal, sizeof(_sroot));
				}
				else if (!stricmp("logpath", lpszKeyName))
				{
					if (lpszKeyVal && *lpszKeyVal)
						ec::str_ncpy(_slogpath, lpszKeyVal, sizeof(_slogpath));
				}
				else if (!stricmp("port", lpszKeyName))
				{
					if (lpszKeyVal && *lpszKeyVal)
						_wport = (unsigned short)atoi(lpszKeyVal);
				}
				else if (!stricmp("logdetail", lpszKeyName))
				{
					if (lpszKeyVal && *lpszKeyVal && (!str_icmp("true", lpszKeyVal) || !str_icmp("yes", lpszKeyVal)))
						_blogdetail = true;
				}
			}
			if (!stricmp("https", lpszBlkName))
			{
				if (!stricmp("rootpath", lpszKeyName))
				{
					if (lpszKeyVal && *lpszKeyVal)
						ec::str_ncpy(_sroot_wss, lpszKeyVal, sizeof(_sroot_wss));
				}
				else if (!stricmp("logpath", lpszKeyName))
				{
					if (lpszKeyVal && *lpszKeyVal)
						ec::str_ncpy(_slogpath_wss, lpszKeyVal, sizeof(_slogpath_wss));
				}
				else if (!stricmp("port", lpszKeyName))
				{
					if (lpszKeyVal && *lpszKeyVal)
						_wport_wss = (unsigned short)atoi(lpszKeyVal);
				}
				else if (!stricmp("logdetail", lpszKeyName))
				{
					if (lpszKeyVal && *lpszKeyVal && (!str_icmp("true", lpszKeyVal) || !str_icmp("yes", lpszKeyVal)))
						_blogdetail_wss = true;
				}
				else if (!stricmp("ca_root", lpszKeyName))
				{
					if (lpszKeyVal && *lpszKeyVal)
						ec::str_ncpy(_ca_root, lpszKeyVal, sizeof(_ca_root));
				}
				else if (!stricmp("ca_server", lpszKeyName))
				{
					if (lpszKeyVal && *lpszKeyVal)
						ec::str_ncpy(_ca_server, lpszKeyVal, sizeof(_ca_server));
				}
				else if (!stricmp("private_key", lpszKeyName))
				{
					if (lpszKeyVal && *lpszKeyVal)
						ec::str_ncpy(_private_key, lpszKeyVal, sizeof(_private_key));
				}
			}
			else  if (!stricmp("mime", lpszBlkName))
			{
				if (lpszKeyName && *lpszKeyName && lpszKeyVal && *lpszKeyVal)
				{
					t_mime t;
					memset(&t, 0, sizeof(t));
					strncpy(t.sext, lpszKeyName, sizeof(t.sext) - 1);
					strncpy(t.stype, lpszKeyVal, sizeof(t.stype) - 1);
					_mime.SetAt(t.sext, t, false);
				}
			}
		}

		virtual void OnReadFile()
		{
			_wport = 0;
			_blogdetail = false;
			memset(_sroot, 0, sizeof(_sroot));
			memset(_slogpath, 0, sizeof(_slogpath));
		}
	};

	struct t_httpfileds
	{
		char name[48];
		char args[208];
	};

	/*!
	\bruef Parse text,\n as one word
	*/
	class cParseText
	{
	public:
		cParseText(const char* s, size_t usize)
		{
			_ps = s;
			_pe = s + usize;
			_pstr = s;
		}
		~cParseText() {}
	public:
		const char* _ps, *_pe, *_pstr;
	public:
		bool GetNextWord(char* sout, size_t outsize)
		{
			size_t pos = 0;
			sout[0] = '\0';
			while (_ps < _pe)
			{
				if (*_ps == '\x20' || *_ps == '\t' || *_ps == '\r' || *_ps == '\n')
				{
					if (pos > 0)
					{
						_ps++;
						break;
					}
				}
				sout[pos++] = *_ps++;
				if (pos >= outsize)
					return false;
			}
			sout[pos] = '\0';
			return (pos > 0);
		}
		/*!
		\return: -1 error,0:end ; >0 next line pos
		*/
		size_t GetNextLine(char* sout, size_t outsize, bool bfirstline = false) // include the end \n
		{
			size_t pos = 0;
			sout[0] = '\0';
			while (_ps < _pe)
			{
				if (*_ps == '\r')
				{
					_ps++;
					continue;
				}
				else if (*_ps == '\n')
				{
					sout[pos++] = *_ps++;
					sout[pos] = '\0';
					return pos;
				}
				sout[pos++] = *_ps++;
				if (pos >= outsize)
					return -1; //error
			}
			if (bfirstline && (_ps - _pstr) > 7)
			{
				char smothod[8] = { 0 };
				size_t pos = 0;
				if (!ec::str_getnextstring('\x20', _pstr, _ps - _pstr, pos, smothod, sizeof(smothod)))
					return -1;
				if (!ec::str_icmp("Get", smothod) || !ec::str_icmp("Head", smothod))
					return 0;
				return -1;//error
			}
			return 0;
		}
	};


	/*!
	\brief http packet from clinet

	*/
	class cHttpPacket
	{
	public:
		cHttpPacket() :_headers(8), _body(8192)
		{
			memset(_method, 0, sizeof(_method));
			memset(_request, 0, sizeof(_request));
			memset(_version, 0, sizeof(_version));
			_fin = 0;
			
		};
		~cHttpPacket() {};
	public:
		int  _nprotocol;   //!< HTTP_PROTOCOL or WEB_SOCKET
		char _method[32];  //!< get ,head
		char _request[512];//!< requet URL
		char _version[32];
		char _sline[1024];

		tArray<t_httpfileds> _headers;
		tArray<char> _body; //已解压的完整消息
		int _fin;   //!< end  已不用了  
		int _opcode;//!< operator code
	protected:
		bool checkreq()
		{
			char* pc = (char*)_request, *ps;
			ps = pc;
			while (*pc)
			{
				if (*pc == '?')
				{
					*pc = 0;
					break;
				}
				pc++;
			}
			return ((pc - ps) < 120);
		}

		int  ParseFirstLine(cParseText* pwp)
		{
			size_t ul = pwp->GetNextLine(_sline, sizeof(_sline), true);
			if (-1 == ul)
				return he_failed;
			if (!ul)
				return he_waitdata;

			cParseText wp(_sline, ul);
			if (!wp.GetNextWord(_method, sizeof(_method))) //method
				return he_waitdata;

			if (ec::str_icmp("Get", _method) && ec::str_icmp("Head", _method))
				return he_failed;

			if (!wp.GetNextWord(_request, sizeof(_request))) //request
				return he_waitdata;

			if (!checkreq()) // not suport ?
				return he_failed;

			if (!wp.GetNextWord(_version, sizeof(_version))) //version
				return he_waitdata;

			return he_ok;
		}

		/*!
		\brief Parse head fileds
		\breturn he_ok or he_failed
		*/
		int ParseHeadFiled(const char* s)
		{
			t_httpfileds ft;
			memset(&ft, 0, sizeof(ft));
			int nf = 0;
			size_t pos = 0;
			while (*s)
			{
				if (*s == '\x20' || *s == '\t' || *s == '\r' || *s == '\n')
				{
					s++;
					continue;
				}
				else if (*s == ':')
				{
					if (!nf)
					{
						s++;
						pos = 0;
						nf++;
					}
					else
					{
						if (pos < sizeof(ft.args) - 1)
						{
							ft.args[pos++] = *s++;
							ft.args[pos] = '\0';
						}
						else
							return he_failed;
					}
				}
				else
				{
					if (nf == 0)
					{
						if (pos < sizeof(ft.name) - 1)
						{
							ft.name[pos++] = *s++;
							ft.name[pos] = '\0';
						}
						else
							return he_failed;
					}
					else
					{
						if (pos < sizeof(ft.args) - 1)
						{
							ft.args[pos++] = *s++;
							ft.args[pos] = '\0';
						}
						else
							return he_failed;
					}
				}
			}
			if (nf != 1)
				return he_failed;
			_headers.Add(&ft, 1);
			return he_ok;
		}

		/*!
		\brief get Context-Length valuse
		\return >= 0
		*/
		int GetContextLength()
		{
			unsigned int i, n = _headers.GetSize();
			t_httpfileds* pf = _headers.GetBuf();
			for (i = 0; i < n; i++)
			{
				if (!stricmp(pf[i].name, "Context-Length"))
				{
					int nv = atoi(pf[i].args);
					if (nv < 0)
						return 0;
					return nv;
				}
			}
			return 0;
		}

	public:

		int  HttpParse(const char* stxt, size_t usize, size_t &sizedo)
		{
			if (usize < 1)
				return he_waitdata;

			cParseText wp(stxt, usize);
			int nret;

			_headers.ClearData();

			_method[0] = 0;
			_request[0] = 0;
			_version[0] = 0;
			_sline[0] = 0;

			_nprotocol = PROTOCOL_HTTP;

			nret = ParseFirstLine(&wp);
			if (nret != he_ok)
				return nret;

			size_t ul;
			while ((ul = wp.GetNextLine(_sline, sizeof(_sline))) > 0)
			{
				if (_sline[0] == '\n') //head end
					break;
				nret = ParseHeadFiled(_sline);
				if (nret != he_ok)
					return nret;
			}
			if (ul < 0)
				return he_failed;
			if (!ul)
				return he_waitdata;

			_body.ClearData();
			size_t bodylength = GetContextLength();
			if (!bodylength)
			{
				sizedo = wp._ps - stxt;
				return he_ok;
			}
			size_t szdo = wp._ps - stxt;

			if (szdo + bodylength > usize)
				return he_waitdata;
			_body.Add(wp._ps, bodylength);
			sizedo = szdo + bodylength;
			return he_ok;
		}
		void Resetwscomp()
		{
			_body.ClearAndFree(1024 * 512);
		}

		class CWsFrame
		{
		public:
			CWsFrame() : _f(1024 * 64){
			}
			int _opt;
			int _fin;
			int _comp;
			tArray<char> _f;
		public:
			int  parseonframe(const char* stxt, size_t usize, int ncomp)//分离原始帧
			{
				_opt = 0;
				_fin = 0;
				_comp = 0;
				_f.ClearData();
				if (usize < 2)
					return 0;
				int i;
				size_t datalen = 0, sizedo = 0;
				size_t datapos = 2;
				unsigned char* pu = (unsigned char*)stxt;

				_fin = pu[0] & 0x80;				
				_comp = (pu[0] & 0x40) ? ws_permessage_deflate : 0;
				_opt = (pu[0] & 0x0F);

				int bmask = pu[1] & 0x80;
				int payloadlen = pu[1] & 0x7F;

				//client can not use mask
				if (bmask)
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
				sizedo = datapos + datalen;

				_f.ClearData();
				int ns = 0;
				if (_comp)
				{
					_f.Add('\x78');
					_f.Add('\x9c');
					ns = 2;
				}
				_f.Add(stxt + datapos, datalen);
				if (bmask)
				{					
					unsigned char* p = (unsigned char*)_f.GetBuf() + ns;
					int n = _f.GetNum() - ns;
					for (i = 0; i < n; i++)
						p[i] = p[i] ^ pu[datapos - 4 + i % 4];					
				}
				if (ncomp == ws_x_webkit_deflate_frame && _comp) //帧解压 deflate_frame
				{
					_comp = 0;
					tArray<char> tmp(2048 + _f.GetSize() - _f.GetSize() % 1024);					
					tmp.Add(_f.GetBuf(), _f.GetSize());
					_f.ClearData();
					if (Z_OK != ec::wsdecode_zlib(tmp.GetBuf(), tmp.GetSize(), &_f))
						return -1;					
				}
				return (int)sizedo;
			}
		};

		int WebsocketParse(const char* stxt, size_t usize, size_t &sizedo, int ncomp)//支持多帧
		{
			CWsFrame f;
			const char *pd = stxt;
			int ndo = 0, msgcomp = 0;
			sizedo = 0;
			_body.ClearData();
			while(sizedo < usize && (ndo = f.parseonframe(pd, usize - sizedo, ncomp)) > 0)
			{				
				if (!sizedo)
				{
					_opcode = f._opt;
					msgcomp = f._comp;
				}
				sizedo += ndo;
				_body.Add(f._f.GetBuf(), f._f.GetSize());
				if (f._fin) //结束帧
				{			
					_fin = f._fin;
					if (msgcomp) // ws_permessage_deflate
					{
						tArray<char> tmp(1024);
						tmp.Add(_body.GetBuf(), _body.GetSize());
						_body.ClearData();
						if (Z_OK != ec::wsdecode_zlib(tmp.GetBuf(), tmp.GetSize(), &_body))
							return he_failed ;
					}					
					return he_ok;
				}	
				pd += ndo;
			}
			if(0 == ndo)
				return he_waitdata;
			return he_failed;
		}
		
		inline bool HasKeepAlive()
		{
			return CheckHeadFiled("Connection", "keep-alive");
		}

		/*!
		\brief get Sec-WebSocket-Key
		*/
		bool GetWebSocketKey(char sout[], int nsize)
		{
			if (!CheckHeadFiled("Connection", "Upgrade") || !CheckHeadFiled("Upgrade", "websocket"))
				return false;

			unsigned int i, n = _headers.GetSize();
			t_httpfileds* pf = _headers.GetBuf();
			for (i = 0; i < n; i++)
			{
				if (!stricmp(pf[i].name, "Sec-WebSocket-Key"))
				{
					strncpy(sout, pf[i].args, nsize);
					sout[nsize - 1] = '\0';
					return  true;
				}
			}
			return false;
		}

		bool GetHeadFiled(const char* sname, char sval[], size_t size)
		{
			unsigned int i, n = _headers.GetSize();
			t_httpfileds* pf = _headers.GetBuf();
			for (i = 0; i < n; i++)
			{
				if (!stricmp(pf[i].name, sname))
				{
					strncpy(sval, pf[i].args, size - 1);
					sval[size - 1] = '\0';
					return true;
				}
			}
			return false;
		}
		bool CheckHeadFiled(const char* sname, const char* sval)
		{
			char stmp[128];
			unsigned int i, n = _headers.GetSize();
			t_httpfileds* pf = _headers.GetBuf();
			size_t len, pos;
			for (i = 0; i < n; i++)
			{
				if (!stricmp(pf[i].name, sname))
				{
					len = strlen(pf[i].args);
					pos = 0;
					while (str_getnextstring(',', pf[i].args, len, pos, stmp, sizeof(stmp)))
					{
						if (!stricmp(stmp, sval))
							return true;
					}
				}
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
		cHttpClient(unsigned int ucid, const char* sip) : _txt(16384)
		{
			memset(_sip, 0, sizeof(_sip));
			_ucid = ucid;
			_protocol = PROTOCOL_HTTP;
			if (sip && *sip)
				strncpy(_sip, sip, sizeof(_sip) - 1);
			_wscompress = 0;
		};
		~cHttpClient() {};
	public:
		int  _wscompress; // ws_x_webkit_deflate_frame or ws_permessage_deflate
		int					_protocol;//!< HTTP_PROTOCOL:http; WEB_SOCKET:websocket        
		unsigned int        _ucid; //!<UCID
		char _sip[32];				//!<ip address
		tArray<char>   _txt;  //!< 未处理字符数组
	public:
		/*!
		\brief 处理接收数据
		\return 返回HTTPERROR, he_ok表示有解析好的报文存储于pout
		*/
		int OnReadData(unsigned int ucid, const char* pdata, unsigned int usize, cHttpPacket* pout)
		{
			if (!pdata || !usize || !pout)
				return he_failed;
			size_t sizedo = 0;
			pout->Resetwscomp();
			pout->_nprotocol = _protocol;
			_txt.Add(pdata, usize);//添加到待处理字符串
			if (_protocol == PROTOCOL_HTTP)
			{
				int nr = pout->HttpParse(_txt.GetBuf(), _txt.GetSize(), sizedo);
				if (nr == he_ok)
					_txt.LeftMove(sizedo);
				else
				{
					if (nr >= he_failed || _txt.GetSize() > SIZE_HTTPMAXREQUEST)
						_txt.ClearData();
				}
				_txt.ReduceMem(1024 * 16);
				return nr;
			}

			//下面按照websocket处理
			int nr = pout->WebsocketParse(_txt.GetBuf(), _txt.GetSize(), sizedo, _wscompress);
			if (nr == he_ok)
			{
				_txt.LeftMove(sizedo);
			}
			else
			{
				if (nr >= he_failed || _txt.GetSize() > SIZE_WSMAXREQUEST)
					_txt.ClearData();
			}
			_txt.ReduceMem(1024 * 16);
			return nr;
		}

		int DoNextData(unsigned int ucid, cHttpPacket* pout)
		{
			pout->Resetwscomp();
			size_t sizedo = 0;
			if (_protocol == PROTOCOL_HTTP)
			{
				int nr = pout->HttpParse(_txt.GetBuf(), _txt.GetSize(), sizedo);
				if (nr == he_ok)
					_txt.LeftMove(sizedo);
				else
				{
					if (nr >= he_failed || _txt.GetSize() > SIZE_HTTPMAXREQUEST)
						_txt.ClearData();
				}
				_txt.ReduceMem(1024 * 16);
				return nr;
			}

			//下面按照websocket处理
			int nr = pout->WebsocketParse(_txt.GetBuf(), _txt.GetSize(), sizedo, _wscompress);
			if (nr == he_ok)
			{
				_txt.LeftMove(sizedo);
			}
			else
			{
				if (nr >= he_failed || _txt.GetSize() > SIZE_WSMAXREQUEST)
					_txt.ClearData();
			}
			_txt.ReduceMem(1024 * 16);
			return nr;
		}
	};

	template<>
	inline bool	tMap<unsigned int, cHttpClient*>::ValueKey(unsigned int key, cHttpClient** pcls)
	{
		return key == (*pcls)->_ucid;
	}

	template<>
	inline void	tMap<unsigned int, cHttpClient*>::OnRemoveValue(cHttpClient** pcls)
	{
		if (*pcls)
		{
			delete *pcls;
			*pcls = NULL;
		}
	};


	/*!
	\brief http客户端连接集合
	*/
	class cHttpClientMap
	{
	public:
		cHttpClientMap() : _map(1024 * 8)
		{

		}
		~cHttpClientMap()
		{

		}
	private:
		cCritical _cs;           //!<临界区锁
		tMap<unsigned int, cHttpClient*> _map; //!<客户端MAP
	public:
		/*!
		\brief 处理接收到的数据
		\return 返回HTTPERROR, he_ok表示有解析好的报文存储于pout
		*/
		int OnReadData(unsigned int ucid, const char* pdata, unsigned int usize, cHttpPacket* pout)
		{
			cSafeLock lck(&_cs);
			cHttpClient* pcli = NULL;
			if (!_map.Lookup(ucid, pcli) || !pcli)
				return he_failed;
			return pcli->OnReadData(ucid, pdata, usize, pout);
		}

		/*!
		\brief 处理粘包数据
		*/
		int DoNextData(unsigned int ucid, cHttpPacket* pout)
		{
			cSafeLock lck(&_cs);
			cHttpClient* pcli = NULL;
			if (!_map.Lookup(ucid, pcli) || !pcli)
				return he_failed;
			return pcli->DoNextData(ucid, pout);
		}

		void Add(unsigned int ucid, const char* sip)
		{
			cSafeLock lck(&_cs);
			cHttpClient* pcli = new cHttpClient(ucid, sip);

			if (pcli)
				_map.SetAt(ucid, pcli);
		}
		bool Del(unsigned int ucid)
		{
			cSafeLock lck(&_cs);
			return _map.RemoveKey(ucid);
		}

		void UpgradeWebSocket(unsigned int ucid, int wscompress)//升级为websocket协议
		{
			cSafeLock lck(&_cs);
			cHttpClient* pcli = NULL;
			if (!_map.Lookup(ucid, pcli) || !pcli)
				return;
			pcli->_protocol = PROTOCOL_WS;
			pcli->_wscompress = wscompress;
			pcli->_txt.ClearData();
		}
		
		int GetCompress(unsigned int ucid)
		{
			cSafeLock lck(&_cs);
			cHttpClient* pcli = NULL;
			if (!_map.Lookup(ucid, pcli) || !pcli)
				return 0;
			return pcli->_wscompress;
		}
	};

	/*!
	\brief Http工作线程
	*/
	class cHttpWorkThread : public cTcpSvrWorkThread
	{
	public:
		cHttpWorkThread(cHttpClientMap* pclis, cHttpCfg*  pcfg, cLog*	plog) : _filetmp(32768), _answer(32768), _encodetmp(32768)
		{
			_pclis = pclis;
			_pcfg = pcfg;
			_plog = plog;
		};
		virtual ~cHttpWorkThread() {
		};

	protected:
		cHttpCfg*		_pcfg;		//!<配置
		cLog*			_plog;		//!<日志

		cHttpClientMap*	_pclis;		//!<连接客户MAP
		cHttpPacket		_httppkg;	//!<报文解析
		tArray<char>	_filetmp;	//!<文件临时区
		tArray<char>	_answer;	//!<应答       
		tArray<char>	_encodetmp;	//!<压缩  
	protected:
		/*!
		\brief 处理websocket接收到的数据
		\return 返回true表示成功，false表示失败，底层会断开这个连接
		\remark 派生类重载这个函数,处理接受到的数据，如果需要应答，直接使用SendToUcid方法应答
		*/
		virtual bool OnWebSocketData(unsigned int ucid, int bFinal, int wsopcode, const void* pdata, size_t size)//重载这个函数处理websocket接收数据
		{
			//简单回显，原样应答发送
			_answer.ClearData();
			MakeWsSend(pdata, size, (unsigned char)wsopcode, &_answer, _pclis->GetCompress(ucid));
			SendToUcid(ucid, _answer.GetBuf(), _answer.GetSize(), true);
			if (_pcfg->_blogdetail && _plog)
				_plog->AddLog("MSG:ws read:ucid=%d,Final=%d,opcode=%d,size=%d ", ucid, bFinal, wsopcode, size);
			return true;
		}
	private:
		/*!
		\brief websocket升级处理
		*/
		bool DoUpgradeWebSocket(int ucid, const char *skey)
		{
			const char* sc;
			char sProtocol[128] = { 0 }, sVersion[128] = { 0 }, tmp[256] = { 0 };
			_httppkg.GetHeadFiled("Sec-WebSocket-Protocol", sProtocol, sizeof(sProtocol));
			_httppkg.GetHeadFiled("Sec-WebSocket-Version", sVersion, sizeof(sVersion));

			if (atoi(sVersion) != 13)
			{
				if (_pcfg->_blogdetail && _plog)
					_plog->AddLog("MSG:ws sVersion(%s) error :ucid=%d, ", sVersion, ucid);
				DoBadRequest(ucid);
				return _httppkg.HasKeepAlive();
			}
			_answer.ClearData();
			sc = "HTTP/1.1 101 Switching Protocols\x0d\x0a"
				"Upgrade: websocket\x0d\x0a"
				"Connection: Upgrade\x0d\x0a";
			_answer.Add(sc, strlen(sc));

			char ss[256];
			strcpy(ss, skey);
			strcat(ss, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

			char sha1out[20] = { 0 }, base64out[32] = { 0 };
			encode_sha1(ss, (unsigned int)strlen(ss), sha1out); //SHA1
			encode_base64(base64out, sha1out, 20);    //BASE64

			sc = "Sec-WebSocket-Accept: ";
			_answer.Add(sc, strlen(sc));
			_answer.Add(base64out, strlen(base64out));
			_answer.Add("\x0d\x0a", 2);

			if (sProtocol[0])
			{
				sc = "Sec-WebSocket-Protocol: ";
				_answer.Add(sc, strlen(sc));
				_answer.Add(sProtocol, strlen(sProtocol));
				_answer.Add("\x0d\x0a", 2);
			}

			if (_httppkg.GetHeadFiled("Host", tmp, sizeof(tmp)))
			{
				sc = "Host: ";
				_answer.Add(sc, strlen(sc));
				_answer.Add(tmp, strlen(tmp));
				_answer.Add("\x0d\x0a", 2);
			}			

			int ncompress = 0;
			if (_httppkg.GetHeadFiled("Sec-WebSocket-Extensions", tmp, sizeof(tmp)))
			{
				char st[64] = { 0 };
				size_t pos = 0, len = strlen(tmp);
				while (ec::str_getnext(";,", tmp, len, pos, st, sizeof(st)))
				{
					if (!ec::str_icmp("permessage-deflate", st))
					{
						sc = "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover";
						_answer.Add(sc, strlen(sc));
						_answer.Add("\x0d\x0a", 2);
						ncompress = ws_permessage_deflate;
						break;
					}
					else if (!ec::str_icmp("x-webkit-deflate-frame", st))
					{
						sc = "Sec-WebSocket-Extensions: x-webkit-deflate-frame; no_context_takeover";
						_answer.Add(sc, strlen(sc));
						_answer.Add("\x0d\x0a", 2);
						ncompress = ws_x_webkit_deflate_frame;
						break;
					}
				}
			}
			_answer.Add("\x0d\x0a", 2);

			_pclis->UpgradeWebSocket(ucid, ncompress);//升级协议为websocket

			SendToUcid(ucid, _answer.GetBuf(), _answer.GetSize(), true);//发送

			if (_pcfg->_blogdetail && _plog) {
				_answer.Add((char)0);
				_plog->AddLog("MSG:Write ucid %d\r\n%s", ucid, _answer.GetBuf());
			}
			return true;
		}

	public:	
		
		protected:
		/*!
		\brief 响应ping,使用PONG回答
		*/
		void OnWsPing(unsigned int ucid, const void* pdata, size_t size)
		{
			_answer.ClearData();
			MakeWsSend(pdata, size, WS_OP_PONG, &_answer, _pclis->GetCompress(ucid));
			SendToUcid(ucid, _answer.GetBuf(), _answer.GetSize(), true);
		}

		/*!
		\brief 处理一个http请求报文,入口参数在_httppkg中
		\return 返回true表示成功，返回false会导致底层断开这个连接
		*/
		bool DoHttpRequest(unsigned int ucid)
		{
			if (_pcfg->_blogdetail && _plog)
			{
				_plog->AddLog("MSG:read from ucid %u:", ucid);
				_plog->AddLog2("   %s %s %s\r\n", _httppkg._method, _httppkg._request, _httppkg._version);
				int i, n = _httppkg._headers.GetNum();
				t_httpfileds* pa = _httppkg._headers.GetBuf();
				for (i = 0; i < n; i++)
					_plog->AddLog2("    %s:%s\r\n", pa[i].name, pa[i].args);
				_plog->AddLog2("\r\n");
			}
			else
			{
				_plog->AddLog("MSG:ucid %u:%s %s %s", ucid, _httppkg._method, _httppkg._request, _httppkg._version);
			}
			if (!stricmp("GET", _httppkg._method)) //GET
			{
				char skey[128];
				if (_httppkg.GetWebSocketKey(skey, sizeof(skey))) //web_socket升级
				{
					if (_plog)
						_plog->AddLog("MSG:ucid %u Upgrade websocket", ucid);
					return DoUpgradeWebSocket(ucid, skey); //处理Upgrade中的Get
				}
				else
					return DoGetAndHead(ucid);
			}
			else if (!stricmp("HEAD", _httppkg._method)) //HEAD
				return DoGetAndHead(ucid, false);

			DoBadRequest(ucid);//不支持其他方法
			return _httppkg.HasKeepAlive();
		}

		
		
		/*!
		\brief 处理GET和HEAD方法
		*/
		bool DoGetAndHead(unsigned int ucid, bool bGet = true)
		{
			char sfile[1024], tmp[4096];
			const char* sc;
			sfile[0] = '\0';
			tmp[0] = '\0';

			strcpy(sfile, _pcfg->_sroot);

			url2utf8(_httppkg._request, tmp, (int)sizeof(tmp));

			strcat(sfile, tmp);

			size_t n = strlen(sfile);
			if (n && (sfile[n - 1] == '/' || sfile[n - 1] == '\\')) //如果是目录在使用默认的index.html作为文件名
				strcat(sfile, "index.html");

			else if (IsDir(sfile))
			{
				DoNotFount(ucid);
				return _httppkg.HasKeepAlive();
			}
			if (!IO::LckRead(sfile, &_filetmp))
			{
				DoNotFount(ucid);
				return _httppkg.HasKeepAlive();
			}

			_answer.ClearData();
			sc = "HTTP/1.1 200 ok\r\n";
			_answer.Add(sc, strlen(sc));

			sc = "Server: rdb5 websocket server\r\n";
			_answer.Add(sc, strlen(sc));

			if (_httppkg.HasKeepAlive())
			{
				sc = "Connection: keep-alive\r\n";
				_answer.Add(sc, strlen(sc));
			}
			const char* sext = GetFileExtName(sfile);
			if (sext && *sext && _pcfg->GetMime(sext, tmp, sizeof(tmp)))
			{
				_answer.Add("Content-type: ", 13);
				_answer.Add(tmp, strlen(tmp));
				_answer.Add("\r\n", 2);
			}
			else
			{
				sc = "Content-type: application/octet-stream\r\n";
				_answer.Add(sc, strlen(sc));
			}

			int necnode = 0;
			if (_httppkg.GetHeadFiled("Accept-Encoding", tmp, sizeof(tmp)))
			{
				char sencode[16] = { 0 };
				size_t pos = 0;
				while (ec::str_getnext(";,", tmp, strlen(tmp), pos, sencode, sizeof(sencode)))
				{
					if (!ec::str_icmp("deflate", sencode))
					{
						sc = "Content-Encoding: deflate\r\n";
						_answer.Add(sc, strlen(sc));
						necnode = HTTPENCODE_DEFLATE;
						break;
					}
				}
			}
			_encodetmp.ClearData();
			if (HTTPENCODE_DEFLATE == necnode)
			{
				if (Z_OK != ec::wsencode_zlib(_filetmp.GetBuf(), _filetmp.GetSize(), &_encodetmp))
					return false;
				sprintf(tmp, "Content-Length: %d\r\n\r\n", _encodetmp.GetNum());
			}
			else
				sprintf(tmp, "Content-Length: %d\r\n\r\n", _filetmp.GetNum());
			_answer.Add(tmp, strlen(tmp));

			if (_pcfg->_blogdetail && _plog)
			{
				tArray<char> atmp(4096);
				atmp.Add(_answer.GetBuf(), _answer.GetSize());
				atmp.Add((char)0);
				_plog->AddLog("MSG:write ucid %u:", ucid);
				_plog->AddLog2("%s", atmp.GetBuf());
			}

			if (bGet) //get
			{
				if (HTTPENCODE_DEFLATE == necnode)
					_answer.Add(_encodetmp.GetBuf(), _encodetmp.GetSize());
				else
					_answer.Add(_filetmp.GetBuf(), _filetmp.GetSize());
			}

			SendToUcid(ucid, _answer.GetBuf(), _answer.GetSize(), true);
			_filetmp.ClearAndFree(0xFFFFF);
			_answer.ClearAndFree(0xFFFFF);
			_encodetmp.ClearAndFree(0xFFFFF);
			return true;
		}

		/*!
		\brief 应答404错误,资源未找到
		*/
		void DoNotFount(unsigned int ucid)
		{
			const char* sret = "http/1.1 404  not found!\r\nServer:rdb5 websocket server\r\nConnection: keep-alive\r\nContent-type:text/plain\r\nContent-Length:9\r\n\r\nnot found";
			SendToUcid(ucid, (void*)sret, (unsigned int)strlen(sret), true);
			if (_pcfg->_blogdetail && _plog)
				_plog->AddLog("MSG:write ucid %u:\r\n%s", ucid, sret);
		}

		/*!
		\brief 应答400错误,错误的方法
		*/
		void DoBadRequest(unsigned int ucid)
		{
			const char* sret = "http/1.1 400  Bad Request!\r\nServer:rdb5 websocket server\r\nConnection: keep-alive\r\nContent-type:text/plain\r\nContent-Length:11\r\n\r\nBad Request";
			SendToUcid(ucid, (void*)sret, (unsigned int)strlen(sret), true);
			if (_pcfg->_blogdetail && _plog)
				_plog->AddLog("MSG:write ucid %u:\r\n%s", ucid, sret);
		}

	protected:
		/*!
		\brief 重载客户端连接断开，删除ucid对应的应用层客户端对象
		*/
		virtual void	OnClientDisconnect(unsigned int  ucid, unsigned int uopt, int nerrorcode) //uopt = TCPIO_OPT_XXXX
		{
			if (_pclis->Del(ucid) && _plog)
				_plog->AddLog("MSG:ucid %u disconnected!", ucid);
		};

		/*!
		\brief 处理接受数据
		*/
		virtual bool	OnReadBytes(unsigned int ucid, const void* pdata, unsigned int usize) //返回false表示要服务端要断开连接
		{
			bool bret = true;
			int nr = _pclis->OnReadData(ucid, (const char*)pdata, usize, &_httppkg);//解析数据，结构存放在_httppkg中
			while (nr == he_ok)
			{
				if (_httppkg._nprotocol == PROTOCOL_HTTP)
				{
					bret = DoHttpRequest(ucid);
				}
				else if (_httppkg._nprotocol == PROTOCOL_WS)
				{
					if (_httppkg._opcode <= WS_OP_BIN)
						bret = OnWebSocketData(ucid, _httppkg._fin, _httppkg._opcode, _httppkg._body.GetBuf(), _httppkg._body.GetSize());
					else if (_httppkg._opcode == WS_OP_CLOSE)
					{
						if(_plog)
							_plog->AddLog("MSG:ucid %d WS_OP_CLOSE!", ucid);
						return false; //返回false后底层会断开连接
					}

					else if (_httppkg._opcode == WS_OP_PING)
					{
						OnWsPing(ucid, _httppkg._body.GetBuf(), _httppkg._body.GetSize());
						if (_pcfg->_blogdetail && _plog)
							_plog->AddLog("MSG:ucid %d WS_OP_PING!", ucid);
						bret = true;
					}
					_httppkg.Resetwscomp();
				}
				nr = _pclis->DoNextData(ucid, &_httppkg);
			}
			if (nr == he_failed)
			{
				DoBadRequest(ucid);
				return false;
			}
			return bret;
		};

		virtual	void	DoSelfMsg(unsigned int dwMsg) {};	// dwMsg = TCPIO_MSG_XXXX
		virtual	void	OnOptComplete(unsigned int ucid, unsigned int uopt) {};//uopt = TCPIO_OPT_XXXX
		virtual	void	OnOptError(unsigned int ucid, unsigned int uopt) {};	//uopt = TCPIO_OPT_XXXX        
	};

	/*!
	\brief httpserver
	*/
	class cHttpServer : public cTcpServer
	{
	public:
		cHttpServer() {};
		virtual ~cHttpServer() {};
	public:
		cHttpCfg        _cfg;    //!<配置
		cHttpClientMap	_clients;//!<连接客户端
		cLog		    _log;	 //!<日志
	protected:

		virtual void    OnConnected(unsigned int  ucid, const char* sip)
		{
			_log.AddLog("MSG:ucid %u TCP connected from IP:%s!", ucid, sip);
			_clients.Add(ucid, sip);
		};
		virtual void	OnRemovedUCID(unsigned int ucid)
		{
			if (_clients.Del(ucid))
				_log.AddLog("MSG:ucid %u disconnected!", ucid);
		};
		virtual void    CheckNotLogin() {};
	public:
		virtual ec::cTcpSvrWorkThread* CreateWorkThread()
		{
			return new cHttpWorkThread(&_clients, &_cfg, &_log);
		}
	public:

		bool StartServer(const char* cnffile, unsigned int uThreads, unsigned int  uMaxConnect)
		{
			if (!_cfg.ReadIniFile(cnffile))
				return false;
			if (!_log.Start(_cfg._slogpath))
				return false;
			return Start(_cfg._wport, uThreads, uMaxConnect);
		}
		void StopServer()
		{
			Stop();
			_log.AddLog("MSG:httpsrv stop success!");
			_log.Stop();
		}
	};
}
#endif //C_WEBSOCKET_H
