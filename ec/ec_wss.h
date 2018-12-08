/*!
\file ec_wss.h
\author kipway@outlook.com
\update 2018.12.6

eclib websocket secret class. easy to use, no thread , lock-free

eclib Copyright (c) 2017-2018, kipway
source repository : https://github.com/kipway/eclib

Licensed under the Apache License, Version 2.0 (the "License");
*/
#pragma once
#include "ec_tls12srv.h"
#include "c11_websocket.h"

#define EZ_PROTOC_WSS  (EZ_PROTOC_BASETLS12 + 1) // WSS
#define EZ_MAX_WSMSG_SIZE (1024 * 1024 * 100) //100MB
namespace ec {
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
			if (!stricmp("mime", lpszBlkName)) {
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
	namespace tls12 {
		class ws_session : public tls12_session {
		public:
			ws_session(SOCKET  fd, uint32_t ucid, const void* pcer, size_t cerlen,
				const void* pcerroot, size_t cerrootlen, std::mutex *pRsaLck, RSA* pRsaPrivate, ec::memory* pmem, ec::cLog* plog) :
				tls12_session(fd, ucid, pcer, cerlen, pcerroot, cerrootlen, pRsaLck, pRsaPrivate, pmem, plog, EZ_PROTOC_WSS),
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

			int WebsocketParse(const char* stxt, size_t usize, size_t &sizedo, cHttpPacket* pout)//support multi-frame
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
					return tls12_session::send(pdata, size, timeoutmsec);
				else if (_protocol == PROTOCOL_WS) {
					bool bsend;
					vector<uint8_t> vret(2048 + size - size % 1024, _pmem);
					if (_wscompress == ws_x_webkit_deflate_frame){ //deflate-frame					
						vret.set_grow(2048 + size / 2 - size % 1024);
						bsend = ws_make_perfrm(pdata, size, WS_OP_TXT, &vret);
					}
					else{ // ws_permessage_deflate					
						if (size > 128 && _wscompress)
							vret.set_grow(2048 + size / 2 - size % 1024);
						bsend = ws_make_permsg(pdata, size, WS_OP_TXT, &vret, size > 128 && _wscompress);
					}
					if (!bsend) {
						if (_plog)
							_plog->add(CLOG_DEFAULT_ERR, "send ucid %u make wsframe failed,size %u", _ucid, (unsigned int)size);
						return -1;
					}
					return tls12_session::send(vret.data(), vret.size(), timeoutmsec);
				}
				_plog->add(CLOG_DEFAULT_ERR, "wss send failed _protocol = %d", _protocol);
				return -1;
			}

			int OnReadData(const char* pdata, size_t usize, cHttpPacket* pout)
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

			int DoNextData(cHttpPacket* pout)
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

		class httpserver : public server {
		public:
			httpserver(ec::cLog* plog, ec::memory* pmem, ec::mimecfg* pmime) : server(plog, pmem), _httppkg(pmem), _pmime(pmime) {
			}
		protected:
			ec::mimecfg* _pmime;
			cHttpPacket _httppkg;
			virtual bool domessage(uint32_t ucid, const uint8_t*pmsg, size_t msgsize) {
				ptrbasession pi = nullptr;
				if (!_map.get(ucid, pi))
					return false;
				if (EZ_PROTOC_WSS != pi->_protoc)
					return onprotcomessage(pi, pmsg, msgsize);

				ws_session* pws = (ws_session*)pi; //处理WSS协议
				
				int nr = pws->OnReadData((const char*)pmsg, msgsize, &_httppkg);
				while (nr == he_ok)
				{
					if (_httppkg._nprotocol == PROTOCOL_HTTP) {
						if (!DoHttpRequest(pws)) {
							closeucid(ucid);
							return false;
						}
					}
					else if (_httppkg._nprotocol == PROTOCOL_WS) {
						if (_httppkg._opcode <= WS_OP_BIN) {
							pws->_wsappmsg.add(_httppkg._body.data(), _httppkg._body.size());
							if (pws->_wsappmsg.size() > EZ_MAX_WSMSG_SIZE) {
								closeucid(ucid);
								pws->_wsappmsg.clear((size_t)0);
								return false;
							}
							if (_httppkg._fin) {
								onwsmessage(ucid, pws->_wsappmsg.data(), pws->_wsappmsg.size());
								pws->_wsappmsg.clear((size_t)0);
							}
						}
						else if (_httppkg._opcode == WS_OP_CLOSE) {
							if (_plog)
								_plog->add(CLOG_DEFAULT_MSG, "ucid %d WS_OP_CLOSE!", ucid);
							closeucid(ucid);
							return false;
						}
						else if (_httppkg._opcode == WS_OP_PING) {
							if (ws_send(pws, _httppkg._body.data(), _httppkg._body.size(), WS_OP_PONG) < 0) {
								closeucid(ucid);
								return false;
							}
							if (_plog)
								_plog->add(CLOG_DEFAULT_MSG, "ucid %d WS_OP_PING!", ucid);
						}
					}
					nr = pws->DoNextData(&_httppkg);
				}
				if (nr == he_failed) {
					pws->send(http_sret400, strlen(http_sret400));
					closeucid(ucid);
					return false;
				}
				return true;
			}

			virtual void onconnect(uint32_t ucid) {
			}
			virtual void ondisconnect(uint32_t ucid) {
			}
			virtual base_session* createsession(SOCKET  fd, uint32_t ucid, const void* pcer, size_t cerlen,
				const void* pcerroot, size_t cerrootlen, std::mutex *pRsaLck, RSA* pRsaPrivate, ec::memory* pmem, ec::cLog* plog) {
				return new ws_session(fd, ucid, pcer, cerlen, pcerroot, cerrootlen, pRsaLck, pRsaPrivate, pmem, plog);
			}
		protected:
			virtual bool onhttprequest(uint32_t ucid, cHttpPacket* phttpmsg) = 0;
			virtual bool onwsmessage(uint32_t ucid, const void* pdata, size_t size) = 0;
			virtual bool onprotcomessage(ptrbasession pi, const void* pdata, size_t size) { //other protoc
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
						_plog->add(CLOG_DEFAULT_MSG, "ucid %u read: %s %s?%s %s", pws->ucid(), _httppkg._method, _httppkg._request, _httppkg._reqargs, _httppkg._version);
					else
						_plog->add(CLOG_DEFAULT_MSG, "ucid %u read: %s %s %s", pws->ucid(), _httppkg._method, _httppkg._request, _httppkg._version);
				}
				if (!stricmp("GET", _httppkg._method)) { //GET			
					char skey[128];
					if (_httppkg.GetWebSocketKey(skey, sizeof(skey))) { //websocket Upgrade
						if (DoUpgradeWebSocket(pws, skey)) {
							onupdatewss(pws->ucid());
							return true;
						}
						else
							return false;
					}
				}
				return onhttprequest(pws->ucid(), &_httppkg);
			}
			bool httprequest(const char* sroot, uint32_t ucid, cHttpPacket* pPkg) //default httprequest
			{
				if (!stricmp("GET", _httppkg._method))
					return  DoGetAndHead(sroot, ucid, pPkg);
				else if (!stricmp("HEAD", _httppkg._method))
					return  DoGetAndHead(sroot, ucid, pPkg, false);
				httpreterr(ucid, http_sret400);
				return _httppkg.HasKeepAlive();
			}

			bool DoGetAndHead(const char* sroot, uint32_t ucid, cHttpPacket* pPkg, bool bGet = true)
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
				if (sext && *sext && getmime(sext, tmp, sizeof(tmp))) {
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
				size_t poslen = answer.size(), sizehead;
				sprintf(tmp, "Content-Length: %9d\r\n\r\n", (int)filetmp.size());
				answer.add((const uint8_t*)tmp, strlen(tmp));
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
						answer.add((const uint8_t*)filetmp.data(), filetmp.size());
				}

				if (_plog)
					_plog->add(CLOG_DEFAULT_MSG, "write ucid %u size %zu", ucid, answer.size());
				return sendbyucid(ucid, answer.data(), answer.size()) > 0;
			}

			void httpreterr(unsigned int ucid, const char* sret)
			{
				int nret = sendbyucid(ucid, (const uint8_t*)sret, strlen(sret));
				if (_plog) {
					if (nret > 0)
						_plog->add(CLOG_DEFAULT_DBG, "http write ucid %u:\n%s", ucid, sret);
					else
						_plog->add(CLOG_DEFAULT_DBG, "http write ucid %u failed.\n%s", ucid, sret);
				}
			}

			bool DoUpgradeWebSocket(ws_session* pws, const char *skey)
			{
				if (_plog) {
					char stmp[128] = { 0 };
					_plog->add(CLOG_DEFAULT_MSG, "ucid %u upgrade websocket", pws->ucid());
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
						_plog->add(CLOG_DEFAULT_MSG, "ws sVersion(%s) error :ucid=%d, ", sVersion, pws->ucid());
					pws->send(http_sret400, strlen(http_sret400));
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
				pws->_txt.clear((size_t)0);

				int ns = 0;
				if (_plog) {
					vector<char> vlog(1024 * 4, _pmem);
					vlog.add((const char*)vret.data(), vret.size());
					vlog.add(char(0));
					ns = pws->send(vret.data(), vret.size());
					if (ns < 0) {
						_plog->add(CLOG_DEFAULT_MSG, "ucid %d upggrade WS failed", pws->ucid());
						_plog->append(CLOG_DEFAULT_DBG, "%s", vlog.data());
						return false;
					}
					vlog.for_each([](char &v) {
						if ('\r' == v)
							v = '\x20';
					});
					_plog->add(CLOG_DEFAULT_MSG, "ucid %d upggrade WS success\n%s", pws->ucid(), vlog.data());					
				}
				else
					ns = pws->send(vret.data(), vret.size());
				pws->_protocol = PROTOCOL_WS;
				pws->_wscompress = ncompress;
				pws->_status |= EZ_PROTOC_ST_WORK;
				return ns > 0;
			}

			int ws_send(unsigned int ucid, const void* pdata, size_t size, unsigned char wsopt, int waitmsec = 1000) //return -1 error, >0 is send bytes
			{
				ptrbasession pi = nullptr;
				if (!_map.get(ucid, pi))
					return -1;
				if (pi->_protoc != EZ_PROTOC_WSS)
					return -1;
				ws_session* pws = (ws_session*)pi;
				bool bsend;
				vector<uint8_t> vret(2048 + size - size % 1024, _pmem);
				if (pws->_wscompress == ws_x_webkit_deflate_frame) //deflate-frame
				{
					vret.set_grow(2048 + size / 2 - size % 1024);
					bsend = ws_make_perfrm(pdata, size, wsopt, &vret);
				}
				else // ws_permessage_deflate
				{
					if (size > 128 && pws->_wscompress)
						vret.set_grow(2048 + size / 2 - size % 1024);
					bsend = ws_make_permsg(pdata, size, wsopt, &vret, size > 128 && pws->_wscompress);
				}
				if (!bsend) {
					if (_plog)
						_plog->add(CLOG_DEFAULT_ERR, "send ucid %u make wsframe failed,size %u", ucid, (unsigned int)size);
					return -1;
				}
				return pws->send(vret.data(), vret.size(), waitmsec);
			}

			int ws_send(ws_session* pws, const void* pdata, size_t size, unsigned char wsopt, int waitmsec = 1000) //return -1 error, >0 is send bytes
			{
				bool bsend;
				vector<uint8_t> vret(2048 + size - size % 1024, _pmem);
				if (pws->_wscompress == ws_x_webkit_deflate_frame) //deflate-frame
				{
					vret.set_grow(2048 + size / 2 - size % 1024);
					bsend = ws_make_perfrm(pdata, size, wsopt, &vret);
				}
				else // ws_permessage_deflate
				{
					if (size > 128 && pws->_wscompress)
						vret.set_grow(2048 + size / 2 - size % 1024);
					bsend = ws_make_permsg(pdata, size, wsopt, &vret, size > 128 && pws->_wscompress);
				}
				if (!bsend) {
					if (_plog)
						_plog->add(CLOG_DEFAULT_ERR, "send ucid %u make wsframe failed,size %u", pws->ucid(), (unsigned int)size);
					return -1;
				}
				return pws->send(vret.data(), vret.size(), waitmsec);
			}
		};
	}
}// ec



