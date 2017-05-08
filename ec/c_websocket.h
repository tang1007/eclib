/*!
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

#ifndef _WIN32
#ifndef stricmp
#define stricmp(a,b)    strcasecmp(a,b)
#endif // stricmp
#endif

#define SIZE_HTTPMAXREQUEST 16384
#define SIZE_WSMAXREQUEST   65535

#define PROTOCOL_HTTP   0
#define PROTOCOL_WS     1

#define WS_FINAL	  0x80
#define WS_OP_CONTINUE  0 
#define WS_OP_TXT		1
#define WS_OP_BIN		2
#define WS_OP_CLOSE	    8
#define WS_OP_PING		9
#define WS_OP_PONG		10



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
            _sroot[0] = 0;
            _slogpath[0] = 0;        
        };
        virtual ~cHttpCfg() {};
    public:
        unsigned short _wport;//!< server port
        char _sroot[512];     //!< http root , utf8
        char _slogpath[512];
        bool _blogdetail;     //!< save detail log
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
                    {
                        strncpy(_sroot, lpszKeyVal, sizeof(_sroot) - 1);
                        size_t n = strlen(_sroot);
                        if (n > 0 && (_sroot[n - 1] == '/' || _sroot[n - 1] == '\\'))
                            _sroot[n - 1] = 0;
                    }
                }
                else if (!stricmp("logpath", lpszKeyName))
                {
                    if (lpszKeyVal && *lpszKeyVal)
                        strncpy(_slogpath, lpszKeyVal, sizeof(_slogpath) - 1);
                }
                else if (!stricmp("port", lpszKeyName))
                {
                    if (lpszKeyVal && *lpszKeyVal)
                        _wport = (unsigned short)atoi(lpszKeyVal);
                }
                else if (!stricmp("logdetail", lpszKeyName))
                {
                    if (lpszKeyVal && *lpszKeyVal && (str_icmp("true", lpszKeyVal) || str_icmp("yes", lpszKeyVal)))
                        _blogdetail = true;
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
        }
        ~cParseText() {}
    public:
        const char* _ps, *_pe;
    public:

        bool GetNextWord(char* sout, size_t outsize) // \n as one word
        {
            size_t pos = 0;
            sout[0] = '\0';
            while (_ps < _pe)
            {
                if (*_ps == '\x20' || *_ps == '\t' || *_ps == '\r')
                {
                    if (pos > 0)
                    {
                        _ps++;
                        break;
                    }
                }
                else if (*_ps == '\n')
                {
                    if (pos > 0)
                        break;
                    sout[pos++] = *_ps++;
                    break;
                }
                sout[pos++] = *_ps++;
                if (pos >= outsize)
                    return false;
            }
            sout[pos] = '\0';
            return (pos > 0);
        }

        size_t GetNextLine(char* sout, size_t outsize) // include the end \n
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
                    break;
                }
                sout[pos++] = *_ps++;
                if (pos >= outsize)
                    return 0;
            }
            sout[pos] = '\0';
            return pos;
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
        };
        ~cHttpPacket() {};
    public:
        int  _nprotocol;   //!< HTTP_PROTOCOL or WEB_SOCKET
        char _method[32];  //!< get ,head
        char _request[512];//!< requet URL
        char _version[16];
        char _sline[512];

        tArray<t_httpfileds> _headers;
        tArray<char> _body;
        int  _fin;   //!< end
        int  _opcode;//!< operator code
    protected:

        int  ParseFirstLine(cParseText* pwp)
        {
            size_t ul = pwp->GetNextLine(_sline, sizeof(_sline));
            if (!ul)
                return he_waitdata;

            cParseText wp(_sline, ul);
            if (!wp.GetNextWord(_method, sizeof(_method))) //method
                return he_waitdata;

            if (!wp.GetNextWord(_request, sizeof(_request))) //request
                return he_waitdata;

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
                        ft.args[pos++] = *s++;
                        ft.args[pos] = '\0';
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
                    }
                    else if (nf == 1)
                    {
                        if (pos < sizeof(ft.args) - 1)
                        {
                            ft.args[pos++] = *s++;
                            ft.args[pos] = '\0';
                        }
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

            _nprotocol = PROTOCOL_HTTP;
            nret = ParseFirstLine(&wp);
            if (nret != he_ok)
                return nret;

            size_t ul = wp.GetNextLine(_sline, sizeof(_sline));
            while (ul && _sline[0] != '\n')
            {
                nret = ParseHeadFiled(_sline);
                if (nret != he_ok)
                    return nret;
                ul = wp.GetNextLine(_sline, sizeof(_sline));
            }

            _body.ClearData();
            if (!ul) //no body
            {
                sizedo = wp._ps - stxt;
                return he_ok;
            }

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
            sizedo = wp._ps - stxt + bodylength;
            return he_ok;
        }


        int WebsocketParse(const char* stxt, size_t usize, size_t &sizedo)
        {
            if (usize < 2)
                return he_waitdata;

            int i;
            size_t datalen = 0;
            size_t datapos = 2;
            unsigned char* pu = (unsigned char*)stxt;

            _nprotocol = PROTOCOL_WS;

            _fin = pu[0] & 0x80;
            _opcode = (pu[0] & 0x0F);

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
                return he_waitdata;

            _body.ClearData();
            _body.Add(stxt + datapos, datalen);
            if (bmask)
            {
                unsigned char* p = (unsigned char*)_body.GetBuf();
                int n = _body.GetNum();
                for (i = 0; i < n; i++)
                    p[i] = p[i] ^ pu[datapos - 4 + i % 4];
            }
            sizedo = datapos + datalen;
            return he_ok;
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
                    while (ec::str_getnextstring(',', pf[i].args, len, pos, stmp, sizeof(stmp)))
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
        };
        ~cHttpClient() {};
    public:
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
                return nr;
            }

            //下面按照websocket处理
            int nr = pout->WebsocketParse(_txt.GetBuf(), _txt.GetSize(), sizedo);
            if (nr == he_ok)
                _txt.LeftMove(sizedo);
            else
            {
                if (nr >= he_failed || _txt.GetSize() > SIZE_WSMAXREQUEST)
                    _txt.ClearData();
            }
            return nr;
        }

        int DoNextData(unsigned int ucid, cHttpPacket* pout)
        {
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
                return nr;
            }

            //下面按照websocket处理
            int nr = pout->WebsocketParse(_txt.GetBuf(), _txt.GetSize(), sizedo);
            if (nr == he_ok)
                _txt.LeftMove(sizedo);
            else
            {
                if (nr >= he_failed || _txt.GetSize() > SIZE_WSMAXREQUEST)
                    _txt.ClearData();
            }
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

        void UpgradeWebSocket(unsigned int ucid)//升级为websocket协议
        {
            cSafeLock lck(&_cs);
            cHttpClient* pcli = NULL;
            if (!_map.Lookup(ucid, pcli) || !pcli)
                return;
            pcli->_protocol = PROTOCOL_WS;
            pcli->_txt.ClearData();
        }
    };

    /*!
    \brief Http工作线程
    */
    class cHttpWorkThread : public cTcpSvrWorkThread
    {
    public:
        cHttpWorkThread(cHttpClientMap* pclis, cHttpCfg*  pcfg, cLog*	plog) : _filetmp(32768), _answer(32768)
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
            MakeWsSend(pdata, size, (unsigned char)wsopcode, &_answer);
            SendToUcid(ucid, _answer.GetBuf(), _answer.GetSize(), true);
            if (_pcfg->_blogdetail)
                _plog->AddLog("MSG:ws read:ucid=%d,Final=%d,opcode=%d,size=%d ", ucid, bFinal, wsopcode, size);
            return true;
        }
    private:
        /*!
        \brief websocket升级处理
        */
        bool DoUpgradeWebSocket(int ucid, const char *skey)
        {
            char sProtocol[128] = { 0 }, sVersion[128] = { 0 }, tmp[256] = { 0 };
            _httppkg.GetHeadFiled("Sec-WebSocket-Protocol", sProtocol, sizeof(sProtocol));
            _httppkg.GetHeadFiled("Sec-WebSocket-Version", sVersion, sizeof(sVersion));

            if (atoi(sVersion) < 13) //版本不支持小于13
            {
                DoBadRequest(ucid);
                return _httppkg.HasKeepAlive();
            }
            _answer.ClearData();
            strcpy(tmp, "http/1.1 101 Switching Protocols\r\n");
            _answer.Add(tmp, strlen(tmp));

            strcpy(tmp, "Upgrade: websocket\r\nConnection: Upgrade\r\n");
            _answer.Add(tmp, strlen(tmp));

            if (sProtocol[0])
            {
                strcpy(tmp, "Sec-WebSocket-Protocol:");
                strcat(tmp, sProtocol);
                strcat(tmp, "\r\n");
                _answer.Add(tmp, strlen(tmp));
            }

            char ss[256];
            strcpy(ss, skey);
            strcat(ss, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

            char sha1out[20] = { 0 }, base64out[32] = { 0 };
            encode_sha1(ss, (unsigned int)strlen(ss), sha1out); //SHA1
            encode_base64(base64out, sha1out, 20);    //BASE64

            strcpy(tmp, "Sec-WebSocket-Accept: ");
            strcat(tmp, base64out);
            strcat(tmp, "\r\n\r\n");
            _answer.Add(tmp, strlen(tmp));

            _pclis->UpgradeWebSocket(ucid);//升级协议为websocket

            SendToUcid(ucid, _answer.GetBuf(), _answer.GetSize(), true);//发送

            if (_pcfg->_blogdetail) {
                _answer.Add((char)0);
                _plog->AddLog("MSG:Write ucid %d\r\n%s", ucid, _answer.GetBuf());
            }
            return true;
        }

    protected:

        /*!
        \brief WS组发送帧 size < 65536
        */
        bool MakeWsSend(const void* pdata, size_t size, unsigned char wsopt, tArray< char>* pout)
        {
            unsigned char uc = 0x80 | (0x0F & wsopt);
            pout->ClearData();
            pout->Add((char)uc);
            if (size < 126)
            {
                uc = (unsigned char)size;
                pout->Add((char)uc);
            }
            else if (uc < 65536)
            {
                uc = 126;
                pout->Add((char)uc);
                pout->Add((char)((size & 0xFF00) >> 8)); //高字节
                pout->Add((char)(size & 0xFF)); //低字节
            }
            else // < 4G
            {
                uc = 127;
                pout->Add((char)uc);
                pout->Add((char)0); pout->Add((char)0); pout->Add((char)0); pout->Add((char)0);//high 4 bytes 0
                pout->Add((char)((size & 0xFF000000) >> 24));
                pout->Add((char)((size & 0x00FF0000) >> 16));
                pout->Add((char)((size & 0x0000FF00) >> 8));
                pout->Add((char)(size & 0xFF));
            }
            pout->Add((const char*)pdata, size);
            return true;
        }

        /*!
        \brief 响应ping,使用PONG回答
        */
        void OnWsPing(unsigned int ucid, const void* pdata, size_t size)
        {
            _answer.ClearData();
            MakeWsSend(pdata, size, WS_OP_PONG, &_answer);
            SendToUcid(ucid, _answer.GetBuf(), _answer.GetSize(), true);
        }

        /*!
        \brief 处理一个http请求报文,入口参数在_httppkg中
        \return 返回true表示成功，返回false会导致底层断开这个连接
        */
        bool DoHttpRequest(unsigned int ucid)
        {
            if (_pcfg->_blogdetail)
            {
                _plog->AddLog("MSG:read from ucid %u:", ucid);
                _plog->AddLog2("   %s %s %s\r\n", _httppkg._method, _httppkg._request, _httppkg._version);
                int i, n = _httppkg._headers.GetNum();
                t_httpfileds* pa = _httppkg._headers.GetBuf();
                for (i = 0; i < n; i++)
                    _plog->AddLog2("    %s:%s\r\n", pa[i].name, pa[i].args);
                _plog->AddLog2("\r\n");
            }
            if (!stricmp("GET", _httppkg._method)) //GET
            {
                char skey[128];
                if (_httppkg.GetWebSocketKey(skey, sizeof(skey))) //web_socket升级
                    return DoUpgradeWebSocket(ucid, skey); //处理Upgrade中的Get
                else
                    return DoGetAndHead(ucid);
            }
            else if (!stricmp("HEAD", _httppkg._method)) //HEAD
                return DoGetAndHead(ucid, false);

            DoBadRequest(ucid);//不支持其他方法
            return _httppkg.HasKeepAlive();
        }

        /*!
        \brief 判断是否是目录
        */
        bool IsDir(const char* s)
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

        /*!
        \brief 取文件扩展名
        */
        const char *GetFileExtName(const char*s)
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
        \brief 处理GET和HEAD方法
        */
        bool DoGetAndHead(unsigned int ucid, bool bGet = true)
        {
            char sfile[1024], tmp[4096];
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
            strcpy(tmp, "http/1.1 200 ok\r\n");
            _answer.Add(tmp, strlen(tmp));

            strcpy(tmp, "Server: httpsrv1.0\r\n");
            _answer.Add(tmp, strlen(tmp));

            if (_httppkg.HasKeepAlive())
            {
                strcpy(tmp, "Connection: keep-alive\r\n");
                _answer.Add(tmp, strlen(tmp));
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
                strcpy(tmp, "Content-type: application/octet-stream\r\n");
                _answer.Add(tmp, strlen(tmp));
            }

            sprintf(tmp, "Content-Length: %d\r\n\r\n", _filetmp.GetNum());
            _answer.Add(tmp, strlen(tmp));

            if (_pcfg->_blogdetail)
            {
                tArray<char> atmp(4096);
                atmp.Add(_answer.GetBuf(), _answer.GetSize());
                atmp.Add((char)0);
                _plog->AddLog("MSG:write ucid %u:", ucid);
                _plog->AddLog2("%s", atmp.GetBuf());
            }

            if (bGet) //get
                _answer.Add(_filetmp.GetBuf(), _filetmp.GetSize());

            SendToUcid(ucid, _answer.GetBuf(), _answer.GetSize(), true);
            _filetmp.ClearAndFree(0xFFFFF);
            _answer.ClearAndFree(0xFFFFF);
            return true;
        }

        /*!
        \brief 应答404错误,资源未找到
        */
        void DoNotFount(unsigned int ucid)
        {
            const char* sret = "http/1.1 404  not found!\r\nServer: httpsrv1.0\r\nConnection: keep-alive\r\nContent-type:text/plain\r\nContent-Length:9\r\n\r\nnot found";
            SendToUcid(ucid, (void*)sret, (unsigned int)strlen(sret), true);
            if (_pcfg->_blogdetail)
                _plog->AddLog("MSG:write ucid %u:%s", ucid, sret);
        }

        /*!
        \brief 应答400错误,错误的方法
        */
        void DoBadRequest(unsigned int ucid)
        {
            const char* sret = "http/1.1 400  Bad Request!\r\nServer: httpsrv1.0\r\nConnection: keep-alive\r\nContent-type:text/plain\r\nContent-Length:11\r\n\r\nBad Request";
            SendToUcid(ucid, (void*)sret, (unsigned int)strlen(sret), true);
            if (_pcfg->_blogdetail)
                _plog->AddLog("MSG:write ucid %u:%s", ucid, sret);
        }

    protected:
        /*!
        \brief 重载客户端连接断开，删除ucid对应的应用层客户端对象
        */
        virtual void	OnClientDisconnect(unsigned int  ucid, unsigned int uopt, int nerrorcode) //uopt = TCPIO_OPT_XXXX
        {
            if (_pclis->Del(ucid))
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
                        _plog->AddLog("MSG:ucid %d WS_OP_CLOSE!", ucid);
                        return false; //返回false后底层会断开连接
                    }

                    else if (_httppkg._opcode == WS_OP_PING)
                    {
                        OnWsPing(ucid, _httppkg._body.GetBuf(), _httppkg._body.GetSize());
                        if (_pcfg->_blogdetail)
                            _plog->AddLog("MSG:ucid %d WS_OP_PING!", ucid);
                        bret = true;
                    }
                }
                nr = _pclis->DoNextData(ucid, &_httppkg);
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

        bool StartServer(unsigned int uThreads, unsigned int  uMaxConnect)
        {
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
