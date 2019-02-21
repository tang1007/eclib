/*!
\file c_wss.h
\author	kipway@outlook.com
\update 2018.2.7

eclib websocket protocol on TLS 1.2
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
#include "c_tls12.h"
#include "c_websocket.h"

namespace ec
{
	/*!
	\brief Https工作线程
	*/
	class cHttpsWorkThread : public cTlsSrvThread
	{
	public:
		cHttpsWorkThread(cTlsSession_srvMap* psss, cHttpClientMap* pclis, cHttpCfg*  pcfg, cLog*	plog) :
			cTlsSrvThread(psss),
			_filetmp(32768), _answer(32768), _encodetmp(32768)
		{
			_pclis = pclis;
			_pcfg = pcfg;
			_plog = plog;
		};
		virtual ~cHttpsWorkThread() {
		};

	protected:
		cHttpCfg*		_pcfg;		//!<配置
		cLog*			_plog;		//!<日志

		cHttpClientMap*	_pclis;		//!<连接客户MAP
	
		cHttpPacket		_httppkg;	//!<报文解析
		tArray<char>	_filetmp;	//!<文件临时区
		tArray<char>	_answer;	//!<http,https,ws,wss use     
		tArray<char>	_encodetmp;	//!<压缩     
	protected:
		/*!
		\brief 处理websocket接收到的数据
		\return 返回true表示成功，false表示失败，底层会断开这个连接
		\remark 派生类重载这个函数,处理接受到的数据，如果需要应答，直接使用ws_send_ucid方法应答
		*/
		virtual bool OnWebSocketData(unsigned int ucid, int bFinal, int wsopcode, const void* pdata, size_t size)//重载这个函数处理websocket接收数据
		{				
			if (_pcfg->_blogdetail_wss && _plog)
				_plog->AddLog("MSG:ws read:ucid=%d,Final=%d,opcode=%d,size=%d ", ucid, bFinal, wsopcode, size);
			return ws_send_ucid(ucid, pdata,size, WS_OP_TXT) > 0;//简单回显，原样应答发送								
		}
		int ws_send_ucid(unsigned int ucid, const void* pdata, size_t size, unsigned char wsopt, bool bAddCount = false, unsigned int uSendOpt = TCPIO_OPT_SEND) //返回-1表示错误,大于0表示发送的字节数
		{
			bool bsend;
			int ncomp = _pclis->GetCompress(ucid);
			if (ncomp == ws_x_webkit_deflate_frame) //deflate-frame压缩
				bsend = ec::MakeWsSend_mdf(pdata, size, wsopt, &_answer, EC_SIZE_WSS_FRAME,&_encodetmp);
			else
				bsend = ec::MakeWsSend_m(pdata, size, wsopt, &_answer, size > 256 && ncomp, EC_SIZE_WSS_FRAME,&_encodetmp);
			if (!bsend)	{
				if (_plog && _pcfg->_blogdetail_wss)
					_plog->AddLog("ERR: send ucid %u make wsframe failed,size %u", ucid, (unsigned int)size);
				return -1;
			}
			bsend = SendAppData(ucid, _answer.GetBuf(), _answer.GetSize(), bAddCount, uSendOpt);
			if (_plog && !bsend)
					_plog->AddLog("ERR: send ucid %u failed size(%u/%u)", ucid, (unsigned int)size, (unsigned int)_answer.GetSize());
			_answer.clear();
			_answer.shrink(0xFFFFF);
			_encodetmp.clear();
			_encodetmp.shrink(0xFFFFF);
			return (int)size;
		}
	private:
		/*!
		\brief websocket升级处理
		*/
		bool DoUpgradeWebSocket(int ucid, const char *skey)
		{
			if (_pcfg->_blogdetail_wss && _plog)
			{
				char stmp[128] = { 0 };
				_plog->AddLog("MSG: ucid %u upgrade websocket",ucid);				
				if (_httppkg.GetHeadFiled("Origin", stmp, sizeof(stmp)))
					_plog->AddLog2("\tOrigin: %s\n", stmp);
				if (_httppkg.GetHeadFiled("Sec-WebSocket-Extensions", stmp, sizeof(stmp)))
					_plog->AddLog2("\tSec-WebSocket-Extensions: %s\n", stmp);
			}
			const char* sc;
			char sProtocol[128] = { 0 }, sVersion[128] = { 0 }, tmp[256] = { 0 };
			_httppkg.GetHeadFiled("Sec-WebSocket-Protocol", sProtocol, sizeof(sProtocol));
			_httppkg.GetHeadFiled("Sec-WebSocket-Version", sVersion, sizeof(sVersion));

			if (atoi(sVersion) != 13)
			{
				if (_pcfg->_blogdetail_wss && _plog)
					_plog->AddLog("MSG:WSS sVersion(%s) error :ucid=%d, ", sVersion, ucid);
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
				while (ec::str_getnext(";", tmp, len, pos, st, sizeof(st)))
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
			_pclis->UpgradeWebSocket(ucid, ncompress);
			SendAppData(ucid, _answer.GetBuf(), _answer.GetSize(), true);
			if (_pcfg->_blogdetail_wss && _plog) {				
				_answer.Add((char)0);
				_plog->AddLog("MSG: ucid %u upggrade WSS success\r\n%s", ucid, _answer.GetBuf());
			}			
			return true;
		}
	protected:		
		/*!
		\brief 响应ping,使用PONG回答
		*/
		void OnWsPing(unsigned int ucid, const void* pdata, size_t size)
		{
			_answer.ClearData();
			MakeWsSend(pdata, size, WS_OP_PONG, &_answer, _pclis->GetCompress(ucid));
			SendAppData(ucid, _answer.GetBuf(), _answer.GetSize(), true);
		}

		/*!
		\brief 处理一个http请求报文,入口参数在_httppkg中
		\return 返回true表示成功，返回false会导致底层断开这个连接
		*/
		bool DoHttpRequest(unsigned int ucid)
		{			
			if (_pcfg->_blogdetail_wss && _plog)
				_plog->AddLog("MSG:ucid %u read:%s", ucid, _httppkg._sorgfirstline);
			if (!stricmp("GET", _httppkg._method)) //GET
			{
				char skey[128];
				if (_httppkg.GetWebSocketKey(skey, sizeof(skey))) //websocket upgrade
					return DoUpgradeWebSocket(ucid, skey);
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
		virtual bool DoGetAndHead(unsigned int ucid, bool bGet = true)
		{
			char sfile[1024], tmp[4096];
			const char* sc;
			sfile[0] = '\0';
			tmp[0] = '\0';

			strcpy(sfile, _pcfg->_sroot_wss);

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

			sc = "Server: kipway websocket server\r\n";
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

			if (_pcfg->_blogdetail_wss && _plog)
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
			SendAppData(ucid, _answer.GetBuf(), _answer.GetSize(), true);
			_filetmp.clear();
			_filetmp.shrink(0xFFFFF);
			_answer.clear();
			_answer.shrink(0xFFFFF);	
			_encodetmp.clear();
			_encodetmp.shrink(0xFFFFF);
			return true;
		}

		/*!
		\brief 应答404错误,资源未找到
		*/
		void DoNotFount(unsigned int ucid)
		{
			const char* sret = "http/1.1 404  not found!\r\nServer:kipway websocket server\r\nConnection: keep-alive\r\nContent-type:text/plain\r\nContent-Length:9\r\n\r\nnot found";
			SendAppData(ucid, (void*)sret, (unsigned int)strlen(sret), true);
			if (_pcfg->_blogdetail_wss && _plog)
				_plog->AddLog("MSG:write ucid %u:\r\n%s", ucid, sret);
			else if(_plog)
				_plog->AddLog("MSG:write ucid %u not found(404)", ucid);
		}

		/*!
		\brief 应答400错误,错误的方法
		*/
		void DoBadRequest(unsigned int ucid)
		{
			const char* sret = "http/1.1 400  Bad Request!\r\nServer:kipway websocket server\r\nConnection: keep-alive\r\nContent-type:text/plain\r\nContent-Length:11\r\n\r\nBad Request";
			SendAppData(ucid, (void*)sret, (unsigned int)strlen(sret), true);
			if (_pcfg->_blogdetail_wss && _plog)
				_plog->AddLog("MSG:write ucid %u:\r\n%s", ucid, sret);
			else if (_plog)
				_plog->AddLog("MSG:write ucid %u bad request(400)", ucid);
		}

	protected:
		/*!
		\brief 重载客户端连接断开，删除ucid对应的应用层客户端对象
		*/
		virtual void	OnDisconnect(unsigned int  ucid, unsigned int uopt, int nerrorcode) //uopt = TCPIO_OPT_XXXX
		{
			if (_pclis->Del(ucid) && _plog)
				_plog->AddLog("MSG:ucid %u disconnected!", ucid);
		};

		/*!
		\brief 处理接受数据
		*/
		virtual bool    OnAppData(unsigned int ucid, const void* pdata, unsigned int usize)//返回false表示要服务端要断开连接
		{
			bool bret = true;
			int nr = _pclis->OnReadData(ucid, (const char*)pdata, usize, &_httppkg);//解析数据，结构存放在_httppkg中
			_threadstcode = 2001;
			while (nr == he_ok)
			{
				if (_httppkg._nprotocol == PROTOCOL_HTTP)
				{
					_threadstcode = 2002;
					bret = DoHttpRequest(ucid);
				}
				else if (_httppkg._nprotocol == PROTOCOL_WS)
				{
					_threadstcode = 2003;
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
						if (_pcfg->_blogdetail_wss && _plog)
							_plog->AddLog("MSG:ucid %d WS_OP_PING!", ucid);
						bret = true;
					}
					_httppkg.Resetwscomp();
				}
				_threadstcode = 2004;
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
	\brief httpsserver
	*/
	class cHttpsServer : public cTlsServer
	{
	public:
		cHttpsServer(cLog* plog):_plog(plog){};
		virtual ~cHttpsServer() {};
	public:
		cHttpCfg        _cfg;    //!<配置
		cHttpClientMap	_clients;//!<连接客户端
		cLog*		    _plog;	 //!<日志
	protected:

		virtual void    OnConnected(unsigned int  ucid, const char* sip)
		{
			cTlsServer::OnConnected(ucid, sip);
			if(_cfg._blogdetail_wss)
				_plog->AddLog("MSG:ucid %u TCP connected from IP:%s!", ucid, sip);
			_clients.Add(ucid, sip);
		};
		virtual void	OnRemovedUCID(unsigned int ucid)
		{
			if (_clients.Del(ucid) && _cfg._blogdetail_wss)
				_plog->AddLog("MSG:ucid %u disconnected!", ucid);
			cTlsServer::OnRemovedUCID(ucid);
		};
		virtual void    CheckNotLogin() {};

		virtual ec::cTcpSvrWorkThread* CreateWorkThread()
		{
			cHttpsWorkThread* pthread = new cHttpsWorkThread(&_sss, &_clients, &_cfg, _plog);
			return pthread;
		}
	public:
		bool StartServer(const char* scfgfile, unsigned int uThreads, unsigned int  uMaxConnect)
		{
			if (!_cfg.ReadIniFile(scfgfile) || !InitCert(_cfg._ca_server, _cfg._ca_root, _cfg._private_key))
				return false;
			return Start(_cfg._wport_wss, uThreads, uMaxConnect);
		}
		void StopServer()
		{
			Stop();
			_plog->AddLog("MSG:HTTPS server stop success!");
		}
	};
}//ec
