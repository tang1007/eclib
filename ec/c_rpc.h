/*!
\file c_rpc.h
\brief 基于TCP的安全消息传输，支持request/reply和服务器publish发布推送

ec library is free C++ library.

\author	 jiangyong,
\email   13212314895@126.com

\remark  安全可靠传输应用层的消息,消息大小1字节到1G(1024 * 1024 * 1024)字节,为了处理效率和降低内存耗用，建议消息不超过1M字节，推荐小于256K字节。

1)登录验证采用动态摘要加密，不传输密码。
原理：
客户端登录后,服务端会随机产生一个40字节的信息(同时字节记住)发送给客户端,客户都收到这40字节后,在尾部拼接上自己的密码，然后使用SHA1计算出20字节的摘要再发送给服务器
服务器收到摘要后，按照客户端同样的方法计算摘要，两边计算摘要相同，这验证完成，继续下一步的应用层的login.

没有传输密码,保证密码不会被泄露。
随机信息计算摘要，防止重放攻击。

2)数据加密：
登录验证之后的数据采用密码的SHA1摘要信息(20字节)加密(循环掩码处理),加密解密算法完全相同。验证中并没有交换密码,也没有交换密码的SHA1摘要,因此只要密码不泄露,是无法解密的。

3)数据CRC32验证：
打包的用户消息数据在加密前采用CRC32验证。保证不会错误,报文被篡改将会导致解密后验证失败.

4)压缩
目前支持LZ4和ZLIB压缩,压缩后再校验和加密。

5)服务端采用多线程,双平台支持,数据传输和数据处理彻底分开。


数据组包：压缩->校验->加密->组包
数据解包: 解包->解密->校验->解压

*/

#ifndef C_RPC_H
#define C_RPC_H

#ifdef _WIN32
#pragma warning (disable : 4200)
#endif

#include "c_array.h"
#include "c_str.h"
#include "c_log.h"
#include "c_tcp_srv.h"
#include "c_tcp_cli.h"
#include "c_crc32.h"
#include "c_sha1.h"
#include "c_thread.h"
#include "c_trace.h"
#include "c_atomic.h"

#include "c_lz4s.h"   //LZ4 src

#ifdef RPC_USE_ZLIB
#include "c_zlibs.h"  //ZLIB src
#endif

/*!
\brief 消息类型
*/
enum RPCMSGTYPE
{
    rpcmsg_sys = 0, //!<系统信息
    rpcmsg_sh = 1, //!<握手消息,连接阶段

    //以下消息类型需要应用处理
    rpcmsg_request = 10, //!<客户端请求消息,服务端使用rpcmsg_reply回答。
    rpcmsg_send = 11, //!<客户端推送给服务器的消息,不要求应答,服务端也可以回答
    rpcmsg_reply = 12  //!<服务端的应答消息。
};

/*!
\brief 压缩方式
*/
enum RPCCOMPRESS
{
    rpccomp_none = 0, //!<不压缩
    rpccomp_lz4 = 1, //!<LZ4压缩,压缩率和LZO一样,但速度更快
#ifdef RPC_USE_ZLIB
    rpccomp_zlib = 2, //!<ZLIB压缩
#endif
};

/*!
\brief 客户端用户状态
*/
enum RPCUSRST
{
    rpcusr_connect = 0, //!<已连接
    rpcusr_sha1info = 1, //!<已发送随机信息
    rpcusr_pass = 2  //!<已验证通过
};

/*!
\brief 通知结构体
\remark 用于底层和应用层简单交互,比如用户登出,ucid发送完成等,输入输出参数为逗号分隔的字符串
其中in和out均为逗号分隔的0结束的字符串
预定义通知：

1)客户端连接
in:connect,usrname
status:0表示允许客户端连接,out中为用户密码用于验证和加密,否则为错误码，out清零
out:usrpass
应用层收到这个消息后，将用户密码填入out中,0结束

2)login
单向通知
in:login,usrname,ucid
out:清零
应用层收到这个消息后，加入在线信息

3)连接断开
单向通知
in:logout,ucid,opt,errcode
out:清零
无返回数据,应用层收到后做相应处理,从在线信息表中清除

*/
struct t_rpcnotify
{
    int  threadno;  //!<线程号>=0表示线程号，-1表示未知线程号
    char in[1020];  //!<通知数据
    int  status;    //!<处理状态，0表示已处理，其他为错误码
    char out[1020]; //!<处理结果
};//sizeof() = 2048

/*!
\brief 通知回调
\return 0:表示已处理，非0表示错误码
*/
typedef int(*rpc_OnNotify)(void* pParam, t_rpcnotify* pnotify); //通知回调

/*!
\breif 消息处理回调
\param pParam,回调函数自己的参数.
\param nthreadno 线程号,0-n(n=最大线程数-1),当前调用回调函数的线程号
\param type 消息类型,见RPCMSGTYPE订阅和注释
\param ucid 唯一的连接ID,用于区分从哪个客户端发来的消息
\param pmsg 消息
\param msglen 消息长度,字节数
\param presult [out] 回传消息内容，如果不回传，*presult置NULL
\param resultlen [out] 回传消息字节数，如果不回传，*resultlen置0
return 0表示成功,其他为应用层定义的错误码,返回值不为0时,底层会断开连接(如果有回答信息，会在发送应答信息后优雅的断开)
\remark 该回调函数在不同的线程中执行,注意多线程同步
*/
typedef int(*rpc_OnMsg)(void* pParam, int nthreadno, RPCMSGTYPE type, unsigned int ucid, const char* usr, const unsigned char *pmsg, size_t msglen, void** presult, size_t* resultlen); //消息处理回调

namespace ec
{
    /*!
    \brief  消息包装,头部的整数为(网络字节顺序)
    \remark 报文头只做报头信息和报头验证，不做分包机制，因为底层封装了发送接收，如果报头验证失败，则一般是发生了严重错误，服务器会断开连接。
    */
    struct t_rpcpkg
    {
        unsigned char sync;      //!<起始固定字符,0xA9
        char          type;      //!<msg类型,
        char          comp;      //!<压缩方式,0:不压缩;1:LZ4;2:ZLIB;
        unsigned char cflag;     //!< D0=1:没加密
        unsigned int  seqno;     //!<消息序列号(网络字节顺序),应答时使用请求的序列号

        unsigned int  size_en;   //!<压缩后的长度(网络字节顺序),用于消息重组,如果不压缩,则和size_dn相同
        unsigned int  size_dn;   //!<解压后的长度(网络字节顺序),用于辅助解压

        unsigned int  crc32msg;  //!<msg字段的CRC32(网络字节顺序),解密后数据的验证.传输中修改报文的任意字节将会使报文解密后验证失败.
        unsigned int  crc32head; //!<头部的CRC32(网络字节顺序),这个值之前的20字节的CRC32

        unsigned char msg[];     //!<应用层消息数据
    };//sizeof() = 24


    /*!
    \brief 网络字节顺序转换
    */
    class CNetInt
    {
    public:
        static bool IsNetBytesOrder()
        {
            unsigned a = 0x12345678;
            return *((unsigned char*)&a) == 0x12;
        }
        static unsigned int NetUInt(unsigned int v) //本地，网络互转，只有本地为小头时才转换
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

    /*!
    \brief 用户信息
    */
    struct t_rpcuserinfo
    {
        unsigned int    _ucid;	     //!<UCID
        int             _nstatus;    //!<状态;0:未登录; 1:已登录
        char            _susr[32];   //!<用户名
        char            _psw[40];    //!<密码
        unsigned char   _pswsha1[20];//!<密码摘要
        char			_sip[20];    //!<ip地址
    };//;sizeof() = 88

    /*!
    \brief 连接客户端
    */
    class cRpcCon
    {
    public:
        cRpcCon(unsigned int ucid, const char* sip) : _rbuf(16384)
        {
            _timeconnect = ::time(NULL);
            memset(_sip, 0, sizeof(_sip));
            memset(_susr, 0, sizeof(_susr));
            _ucid = ucid;
            if (sip && *sip)
                str_ncpy(_sip, sip, sizeof(_sip) - 1);
            _nstatus = 0;
            memset(_psw, 0, sizeof(_psw));
            memset(_pswsha1, 0, sizeof(_pswsha1));
            memset(_srandominfo, 0, sizeof(_srandominfo));
        };
        ~cRpcCon() {};
    public:
        unsigned int    _ucid;	     //!<UCID
        int             _nstatus;    //!<状态;0:未登录; 1:已登录
        time_t          _timeconnect;//!<连接时间
        char            _susr[32];   //!<用户名
        char            _psw[40];    //!<密码
        unsigned char   _pswsha1[20];//!<密码摘要
        char			_sip[20];    //!<ip地址
        char            _srandominfo[64];  //!<随机信息,前40字节有效，验证时使用
        tArray<unsigned char>	_rbuf;       //!<未处理字符数组
    public:

        /*!
        \brief 处理接收数据
        \return 返回-1:错误需要断开连接; 0:没有完整的消息,需要等待;1:有完整的消息存放在pout中
        */
        int DoReadData(const unsigned char* pdata, unsigned int usize, tArray<unsigned char>* pout)
        {
            pout->ClearData();
            if (!pdata || !usize || !pout)
                return -1;
            _rbuf.Add(pdata, usize);//添加到待处理字符串
            return DoLeftData(pout);
        }

        /*!
        \brief 处理缓冲中的数据
        \return 返回-1:错误需要断开连接; 0:没有完整的消息,需要等待;1:有完整的消息存放在pout中
        \remark 报文已经解密和校验
        */
        int DoLeftData(tArray<unsigned char>* pout)//处理生效的报文
        {
            pout->ClearData();
            unsigned int   ulen = _rbuf.GetSize();
            unsigned char* pu = _rbuf.GetBuf();
            if (ulen < sizeof(t_rpcpkg))
            {
                _rbuf.ReduceMem(1024 * 128);//回收多余的内存,防止高并发时内存不够
                return 0;
            }
            //验证
            t_rpcpkg* pkg = (t_rpcpkg*)pu;
            unsigned int c1 = crc32(pu, 20);
            if (pkg->sync != 0xA9 || c1 != CNetInt::NetUInt(pkg->crc32head))
                return -1;//报文错误

            unsigned int sizemsg = CNetInt::NetUInt(pkg->size_en);

            if (ulen < sizemsg + sizeof(t_rpcpkg))
                return 0;
            pout->Add(pu, sizemsg + sizeof(t_rpcpkg));
            _rbuf.LeftMove(sizemsg + sizeof(t_rpcpkg));
            unsigned char* puc = pout->GetBuf() + sizeof(t_rpcpkg);
            if (pkg->type >= rpcmsg_request) //应用层消息需要解密
            {
                register unsigned int i;
                if (!(pkg->cflag & 0x01))
                {
                    unsigned int *pu4 = (unsigned int*)puc, u4 = sizemsg / 4;//先解密
                    unsigned int *pmk4 = (unsigned int*)_pswsha1;
                    for (i = 0; i < u4; i++) //先按照4字节对齐解
                        pu4[i] ^= pmk4[i % 5];
                    for (i = u4 * 4; i < sizemsg; i++)//剩下的单字节解
                        puc[i] ^= _pswsha1[i % 20];
                }
                register unsigned int	crc = 0xffffffff;
                for (i = 0; i < sizemsg; i++) //计算CRC32
                    crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ puc[i]]; //解密后计算数据CRC32
                if (pkg->crc32msg != CNetInt::NetUInt(crc ^ 0xffffffff))
                    return -1;
            }
            else
            {
                if (pkg->crc32msg != CNetInt::NetUInt(crc32(puc, sizemsg)))
                    return -1;
            }
            return 1;
        }
    };

    template<>
    inline bool	tMap<unsigned int, cRpcCon*>::ValueKey(unsigned int key, cRpcCon** pcls)
    {
        return key == (*pcls)->_ucid;
    }

    template<>
    inline void	tMap<unsigned int, cRpcCon*>::OnRemoveValue(cRpcCon** pcls)
    {
        if (*pcls)
        {
            delete *pcls;
            *pcls = NULL;
        }
    };

    /*!
    \brief 连接客户端MAP
    */
    class cRpcClientMap
    {
    public:
        cRpcClientMap() : _map(1024 * 16)
        {
            _bEncryptData = true;
            _tks = ::time(NULL);
            _tks <<= 24;
            _lseqno = 1;
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
    protected:
        bool _bEncryptData;
        unsigned long long _tks;
        cCritical _cs;
        tMap<unsigned int, cRpcCon*> _map;
    public:
        void Add(unsigned int ucid, const char* sip)
        {
            cSafeLock lck(&_cs);
            cRpcCon* pcli = new cRpcCon(ucid, sip);
            if (pcli)
                _map.SetAt(ucid, pcli);
        }

        bool Del(unsigned int ucid)
        {
            cSafeLock lck(&_cs);
            return _map.RemoveKey(ucid);
        }

        int DoReadData(unsigned int ucid, const unsigned char* pdata, unsigned int usize, tArray<unsigned char>* pout)
        {
            cSafeLock lck(&_cs);
            cRpcCon* pcli = NULL;
            if (!_map.Lookup(ucid, pcli) || !pcli)
                return -1;
            return pcli->DoReadData(pdata, usize, pout);
        }
        int DoLeftData(unsigned int ucid, tArray<unsigned char>* pout)
        {
            cSafeLock lck(&_cs);
            cRpcCon* pcli = NULL;
            if (!_map.Lookup(ucid, pcli) || !pcli)
                return -1;
            return pcli->DoLeftData(pout);
        }

        bool GetUserInfo(t_rpcuserinfo* puser)
        {
            cSafeLock lck(&_cs);
            cRpcCon* pcli = NULL;
            if (!_map.Lookup(puser->_ucid, pcli) || !pcli)
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
            cSafeLock lck(&_cs);

            cRpcCon* pcli = NULL;
            if (!_map.Lookup(ucid, pcli) || !pcli)
                return false;
            if (!spsw || !(*spsw))
                strcpy(pcli->_psw, "123456");//
            else
                str_ncpy(pcli->_psw, spsw, sizeof(pcli->_psw));
            str_ncpy(pcli->_susr, susr, sizeof(pcli->_susr));
            pcli->_psw[sizeof(pcli->_psw) - 1] = 0;
            pcli->_nstatus = rpcusr_connect;
            encode_sha1(pcli->_psw, (unsigned int)strlen(pcli->_psw), pcli->_pswsha1);//计算密码的sha1摘要
            return true;
        }

        bool SetUserRandomInfo(unsigned int ucid, char* sout) //sout必须大于40字节
        {
            cSafeLock lck(&_cs);

            cRpcCon* pcli = NULL;
            if (!_map.Lookup(ucid, pcli) || !pcli)
                return false;
            _tks++;
            unsigned char usha1[20], uc;
            encode_sha1(&_tks, 8, usha1);//计算密码的sha1摘要
            int i;
            for (i = 0; i < 20; i++)
            {
                uc = usha1[i] >> 4;
                pcli->_srandominfo[i * 2] = (uc >= 0x0A) ? 'A' + (uc - 0x0A) : '0' + uc;
                uc = usha1[i] & 0x0F;
                pcli->_srandominfo[i * 2 + 1] = (uc >= 0x0A) ? 'A' + (uc - 0x0A) : '0' + uc;
            }
            memcpy(sout, pcli->_srandominfo, 40);
            sout[40] = 0;
            pcli->_nstatus = rpcusr_sha1info;//置已设置随机信息已发送
            return true;
        }

        bool GetUsrInfoSha1(unsigned int ucid, char* pout, char* outusr) //取随机信息的计算摘要,pout >40字节,outusr>=32字节
        {
            cSafeLock lck(&_cs);

            char sbuf[80] = { 0 };
            cRpcCon* pcli = NULL;
            if (!_map.Lookup(ucid, pcli) || !pcli)
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
            cSafeLock lck(&_cs);

            cRpcCon* pcli = NULL;
            if (!_map.Lookup(ucid, pcli) || !pcli)
                return;
            pcli->_nstatus = nst;
        }

        int GetTimeOutNoLogin(time_t ltime, time_t timeoutsec, ec::tArray<unsigned int>*pucids)
        {
            cSafeLock lck(&_cs);

            int npos = 0, nlist = 0;

            cRpcCon *p;
            pucids->ClearData();
            while (_map.GetNext(npos, nlist, p))
            {
                if (p->_nstatus == 0 && ltime - p->_timeconnect > timeoutsec)
                    pucids->Add(p->_ucid);
            }
            return pucids->GetNum();
        }
    };

    /*!
    \brief 重用内存
    */
    class cReUseMem
    {
    public:
        cReUseMem(size_t sizefree = 1024 * 1024 * 2)//默认2MB以下重用
        {
            _pbuf = 0;
            _size = 0;
            _sizefree = sizefree;
        }
        ~cReUseMem()
        {
            if (_pbuf)
                free(_pbuf);
            _pbuf = 0;
            _size = 0;
        }
        void* Alloc(size_t size)
        {
            if (_size >= size)
                return _pbuf;
            if (_pbuf)
                free(_pbuf);
            _pbuf = malloc(size);
            _size = _pbuf ? size : 0;
            return _pbuf;
        }
        void Free() //超过_sizefree则释放,否者不释放,下次重用
        {
            if (_pbuf && _size > _sizefree)
            {
                free(_pbuf);
                _pbuf = 0;
                _size = 0;
            }
        }
    private:
        void*  _pbuf;
        size_t _size;
        size_t _sizefree;
    };

    /*
    \brief 工作线程
    */
    class cRpcBaseThread :public cTcpSvrWorkThread
    {
    public:
        cRpcBaseThread(cRpcClientMap* pcli) : _msgr(256 * 1024), _msgs(256 * 1024), _putmsg(256 * 1024)
        {
            _pcli = pcli;
            _plog = NULL;
            memset(_srvname, 0, sizeof(_srvname));
        }
        virtual ~cRpcBaseThread()
        {
        }
        inline void SetLogSrv(ec::cLog* plog)
        {
            _plog = plog;
        }
        inline void SetSrvName(const char *srvname)
        {
            strncpy(_srvname, srvname, sizeof(_srvname));
        }
    protected:
        virtual int _OnNotify(t_rpcnotify* pnotify) = 0;//必须处理connect,login,logout;可选处理selfmsg,complete,opterr
        virtual int _OnMsg(RPCMSGTYPE type, unsigned int ucid, const char* usr, const unsigned char *pmsg, size_t msglen, void** presult, size_t* resultlen) = 0; //消息处理回调
    protected:
        char _srvname[32];
        ec::cLog* _plog;
        ec::cCritical _csmkbuf; //!<压缩缓冲公用
        cRpcClientMap* _pcli;//!<连接MAP,报文重组用
        tArray<unsigned char> _msgr;//!<报文接收缓冲区
        tArray<unsigned char> _msgs;//!<报文发送缓冲区
        cReUseMem _cpbufc; //压缩内存
        cReUseMem _cpbufu; //解压内存
        tArray<unsigned char> _putmsg;//!<报文推送缓冲区

    private:
        bool MakePkg(const void* pd, size_t size, RPCMSGTYPE msgtype, RPCCOMPRESS compress, unsigned int seqno, const unsigned char* pmask, tArray<unsigned char>* pPkg)
        {
            ec::cSafeLock lck(&_csmkbuf);

            unsigned char shead[sizeof(t_rpcpkg)] = { 0 };
            pPkg->ClearData();
            pPkg->Add(shead, sizeof(t_rpcpkg));
            t_rpcpkg* ph = (t_rpcpkg*)pPkg->GetBuf();

            ph->sync = 0xA9;
            ph->type = (char)msgtype;

            void* pdata;
            size_t ulen = size;
            if (compress == rpccomp_lz4)
            {
                ulen = size + (size / 1024) * 32 + 1024;
                pdata = _cpbufc.Alloc(ulen);
                if (pdata && encode_lz4(pd, size, pdata, &ulen))
                    ph->comp = rpccomp_lz4; //lz4压缩
                else //压缩失败
                {
                    pdata = (void*)pd;
                    ph->comp = rpccomp_none; //不压缩
                    ulen = size;
                }
            }
#ifdef RPC_USE_ZLIB
            else if (compress == rpccomp_zlib)
            {
                ulen = size + (size / 1024) * 32 + 1024;
                pdata = _cpbufc.Alloc(ulen);
                if (pdata && encode_zlib(pd, size, pdata, &ulen))
                    ph->comp = rpccomp_zlib; //zlib压缩
                else //压缩失败
                {
                    pdata = (void*)pd;
                    ph->comp = rpccomp_none; //不压缩
                    ulen = size;
                }
            }
#endif
            else
            {
                pdata = (void*)pd;
                ph->comp = rpccomp_none; //不压缩
                ulen = size;
            }
            if (_pcli->IsEncryptData())
                ph->cflag = 0;
            else
                ph->cflag = 1;

            ph->seqno = CNetInt::NetUInt(seqno);
            ph->size_en = CNetInt::NetUInt((unsigned int)ulen);
            ph->size_dn = CNetInt::NetUInt((unsigned int)size);

            if (!pPkg->Add((const unsigned char*)pdata, ulen))
                return false;

            ph = (t_rpcpkg*)pPkg->GetBuf();//重新读取头部

            _cpbufc.Free();//释放过大的内存
            unsigned char* puc = pPkg->GetBuf() + sizeof(t_rpcpkg);
            if (pmask && msgtype >= rpcmsg_request)//应用层消息需要加密
            {
                unsigned int ul = (unsigned int)ulen;
                register unsigned int	crc = 0xffffffff;
                register unsigned int i;

                for (i = 0; i < ul; i++) //加密同时计算CRC32
                    crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ puc[i]];//加密前验证数据
                ph->crc32msg = CNetInt::NetUInt(crc ^ 0xffffffff);
                if (_pcli->IsEncryptData())
                {
                    unsigned int *pu4 = (unsigned int *)puc, ul4 = ul / 4; //加密
                    unsigned int *pmk4 = (unsigned int*)pmask;
                    for (i = 0; i < ul4; i++)
                        pu4[i] ^= pmk4[i % 5];
                    for (i = ul4 * 4; i < ul; i++)
                        puc[i] ^= pmask[i % 20];
                }
            }
            else
                ph->crc32msg = CNetInt::NetUInt(crc32(puc, (unsigned int)ulen));
            ph->crc32head = CNetInt::NetUInt(crc32(ph, 20));
            return true;
        }
        inline void MakeSysMsg(const char* smsg, unsigned int seqno, tArray<unsigned char>* pout)
        {
            MakePkg(smsg, strlen(smsg), rpcmsg_sys, rpccomp_none, seqno, NULL, pout);
        }
        /*!
        \breif  处理msg
        \return 0:成功; 其他错误会断开连接,pout有数据则表示要先应答
        \remark pin中的数据包已经验证和解密,没有解压
        */
        int DoMsg(unsigned int ucid, tArray<unsigned char>* pin, tArray<unsigned char>* pout)
        {
            pout->ClearData();

            t_rpcpkg* pkg = (t_rpcpkg*)pin->GetBuf();
            void* pmsg = 0;
            size_t ulen = 0;

            if (pkg->comp == rpccomp_none)
            {
                pmsg = pkg->msg;
                ulen = CNetInt::NetUInt(pkg->size_en);
            }
            else if (pkg->comp == rpccomp_lz4)
            {
                size_t uen = CNetInt::NetUInt(pkg->size_en), udn = CNetInt::NetUInt(pkg->size_dn);
                void *pdes = _cpbufu.Alloc(udn);
                if (!decode_lz4(pkg->msg, uen, pdes, &udn))
                {
                    MakeSysMsg("msgsys,-1,decode lz4 error!", CNetInt::NetUInt(pkg->seqno), pout);
                    return -1;
                }
                pmsg = pdes;
                ulen = udn;
            }

#ifdef RPC_USE_ZLIB
            else if (pkg->comp == rpccomp_zlib)
            {
                size_t uen = CNetInt::NetUInt(pkg->size_en), udn = CNetInt::NetUInt(pkg->size_dn);
                void *pdes = _cpbufu.Alloc(udn);
                if (!decode_zlib(pkg->msg, uen, pdes, &udn))
                {
                    MakeSysMsg("msgsys,-1,decode lz4 error!", CNetInt::NetUInt(pkg->seqno), pout);
                    return -1;
                }
                pmsg = pdes;
                ulen = udn;
            }
#endif
            else
            {
                MakeSysMsg("msgsys,-1,unkown compress type!", CNetInt::NetUInt(pkg->seqno), pout);
                return -1;
            }

            if (pkg->type == rpcmsg_sh)
                return Do_shmsg(ucid, pmsg, (unsigned int)ulen, CNetInt::NetUInt(pkg->seqno), pout); //处理握手消息
            else if (pkg->type == rpcmsg_request || pkg->type == rpcmsg_send)
                return Do_appMsg(ucid, (RPCMSGTYPE)pkg->type, pmsg, (unsigned int)ulen, CNetInt::NetUInt(pkg->seqno), pout);
            else
            {
                const char* sr = "msgsys,-1,unkown msgtype!";
                MakePkg(sr, strlen(sr), rpcmsg_sys, rpccomp_none, CNetInt::NetUInt(pkg->seqno), NULL, pout);
                return -1;
            }
        }
        /*!
        \brief 处理开始握手消息
        请求数据：带0结束的字符串，用户名
        应答数据：状态码4字节(大头),40字节随机信息
        \return 返回0表示正确处理，非零为错误码，底层会断开连接
        */
        int Do_shmsg(unsigned int ucid, const void* pmsg, unsigned int msglen, unsigned int seqno, tArray<unsigned char>* pout)
        {
            const char* sd = (const char*)pmsg, *sret;
            char sod[16];

            t_rpcuserinfo usri;
            memset(&usri, 0, sizeof(usri));

            size_t pos = 0;
            if (!str_getnextstring(',', sd, msglen, pos, sod, sizeof(sod)))//读取命令
            {
                sret = "onconnect,-1,msg format error!";
                MakePkg(sret, strlen(sret), rpcmsg_sh, rpccomp_none, seqno, NULL, pout);
                return -1;
            }
            if (!strcmp(sod, "connect")) //连接后，客户端发来connect命令,服务端应答onconnect命令，发送随机信息要求客户端计算摘要
            {
                if (usri._nstatus != rpcusr_connect)
                {
                    sret = "onconnect,-1,usr status error!";
                    MakePkg(sret, strlen(sret), rpcmsg_sh, rpccomp_none, seqno, NULL, pout);
                    return -1;
                }

                //"connect,username"
                char susr[32];
                if (!str_getnextstring(',', sd, msglen, pos, susr, sizeof(susr))) //取用户名
                {
                    sret = "onconnect,-1,msg format error!";
                    MakePkg(sret, strlen(sret), rpcmsg_sh, rpccomp_none, seqno, NULL, pout);
                    return -1;
                }
                t_rpcnotify notfy;
                notfy.threadno = _nthreadno;
                sprintf(notfy.in, "connect,%s", susr);
                notfy.status = 0;
                notfy.out[0] = 0;
                int nr = _OnNotify(&notfy);
                if (nr != 0) //错误
                {
                    sret = "onconnect,%d,error!";
                    MakePkg(sret, strlen(sret), rpcmsg_sh, rpccomp_none, seqno, NULL, pout);
                    return nr;
                }
                char sinfo[44];

                if (!_pcli->SetUserPsw(susr, ucid, notfy.out) || !_pcli->SetUserRandomInfo(ucid, sinfo))
                {
                    sret = "onconnect,-1,system error!";
                    MakePkg(sret, strlen(sret), rpcmsg_sh, rpccomp_none, seqno, NULL, pout);
                    return -1;
                }
                char  sbuf[128];
                sprintf(sbuf, "onconnect,0,%s", sinfo);//发送摘要信息
                MakePkg(sbuf, strlen(sbuf), rpcmsg_sh, rpccomp_none, seqno, NULL, pout);
                return 0;
            }
            else if (!strcmp(sod, "sha1")) //客户端发来摘要信息，并附件登录信息
            {
                usri._ucid = ucid;
                if (!_pcli->GetUserInfo(&usri))
                {
                    sret = "msgsh,-1,no ucid!";
                    MakePkg(sret, strlen(sret), rpcmsg_sh, rpccomp_none, seqno, NULL, pout);
                    return -1;
                }

                if (usri._nstatus != rpcusr_sha1info)
                {
                    sret = "onconnect,-1,usr status error!";
                    MakePkg(sret, strlen(sret), rpcmsg_sh, rpccomp_none, seqno, NULL, pout);
                    return -1;
                }

                //"sha1,摘要信息,附件信息长度(整数字符模式),附件信息"
                char sha1usr[44], sha1srv[44], susr[32];
                if (!str_getnextstring(',', sd, msglen, pos, sha1usr, sizeof(sha1usr))) //摘要
                {
                    sret = "onsha1,-1,msg format error!";
                    MakePkg(sret, strlen(sret), rpcmsg_sh, rpccomp_none, seqno, NULL, pout);
                    return -1;
                }
                if (!_pcli->GetUsrInfoSha1(ucid, sha1srv, susr))
                {
                    sret = "onsha1,-1,system error!";
                    MakePkg(sret, strlen(sret), rpcmsg_sh, rpccomp_none, seqno, NULL, pout);
                    return -1;
                }

                if (strcmp(sha1usr, sha1srv)) //验证错误
                {
                    sret = "onsha1,-2,Authentication failed!";
                    MakePkg(sret, strlen(sret), rpcmsg_sh, rpccomp_none, seqno, NULL, pout);
                    return -2;
                }
                t_rpcnotify notfy;
                notfy.threadno = _nthreadno;
                sprintf(notfy.in, "login,%s,%u", susr, ucid);
                notfy.status = 0;
                notfy.out[0] = 0;
                _OnNotify(&notfy);

                sret = "onsha1,0";
                _pcli->SetUsrStatus(ucid, rpcusr_pass);//设置验证已通过

                MakePkg(sret, strlen(sret), rpcmsg_sh, rpccomp_none, seqno, NULL, pout);
                return 0;
            }
            sret = "msgsh,-1,msg format error!";
            MakePkg(sret, strlen(sret), rpcmsg_sh, rpccomp_none, seqno, NULL, pout);
            return -1;
        }

        int Do_appMsg(unsigned int ucid, RPCMSGTYPE type, const void* pmsg, unsigned int msglen, unsigned int seqno, tArray<unsigned char>* pout)//处理put和call消息
        {
            unsigned char* pus = (unsigned char*)pmsg;

            char sret[128];
            t_rpcuserinfo usrinfo;
            usrinfo._ucid = ucid;
            if (!_pcli->GetUserInfo(&usrinfo))//取用户信息
            {
                const char* sr = "msgsys,-1,no ucid!";
                MakePkg(sr, strlen(sr), rpcmsg_sys, rpccomp_none, seqno, NULL, pout);
                return -1;
            }
            if (usrinfo._nstatus != rpcusr_pass) //状态不是已验证
            {
                const char* sr = "msgsys,-1,please login!";
                MakePkg(sr, strlen(sr), rpcmsg_sys, rpccomp_none, seqno, NULL, pout);
                return -1;
            }

            void* presult = NULL;
            size_t sizeresult = 0;
            int nr = _OnMsg(type, ucid, usrinfo._susr, pus, msglen, &presult, &sizeresult);//交应用层处理
            if (nr)
            {
                sprintf(sret, "msgsys,%d,failed!", nr);
                MakePkg(sret, strlen(sret), rpcmsg_sys, rpccomp_none, seqno, NULL, pout);
                return -1;
            }
            if (presult && sizeresult) //有应答，自动按照发送数据长度选择压缩方式
            {
                RPCCOMPRESS cp = rpccomp_none;
                if (sizeresult > 1024)
                    cp = rpccomp_lz4;
                MakePkg(presult, sizeresult, rpcmsg_reply, cp, seqno, usrinfo._pswsha1, pout);//加密打包
            }
            else
            {
                if (type == rpcmsg_request)//如果是调用,应用层没有应答,这里代为应答一个处理成功消息.
                {
                    sprintf(sret, "msgsys,0,success!");
                    MakePkg(sret, strlen(sret), rpcmsg_sys, rpccomp_none, seqno, NULL, pout);
                }
            }
            return 0;
        }

    protected:
        virtual void	OnClientDisconnect(unsigned int ucid, unsigned int uopt, int uerrcode) //uopt = TCPIO_OPT_XXXX
        {
            t_rpcuserinfo usrinfo;
            usrinfo._ucid = ucid;
            if (!_pcli->GetUserInfo(&usrinfo))//取用户信息
                return;
            _pcli->Del(ucid);
            if (usrinfo._nstatus > rpcusr_connect)
            {
                t_rpcnotify ntf;
                ntf.threadno = _nthreadno;
                ntf.status = -1;
                sprintf(ntf.in, "logout,%u,%u,%u", ucid, uopt, uerrcode);
                ntf.out[0] = 0;
                _OnNotify(&ntf);
                if (_plog)
                    _plog->AddLog("MSG: Server(%s) UCID %u TCP disconnected from %s", _srvname, ucid, usrinfo._sip);
                return;
            }
            if (_plog)
                _plog->AddLog("MSG: Server(%s) UCID %u TCP disconnected from %s", _srvname, ucid, usrinfo._sip);
        }
        virtual bool	OnReadBytes(unsigned int ucid, const void* pdata, unsigned int usize) //返回false表示要断开客户端连接.
        {
            int nr = 0, ndo;
            nr = _pcli->DoReadData(ucid, (const unsigned char*)pdata, usize, &_msgr);//已经校验和解密
            while (nr == 1)
            {
                ndo = DoMsg(ucid, &_msgr, &_msgs);
                if (_msgs.GetSize() > 0)
                    SendToUcid(ucid, _msgs.GetBuf(), _msgs.GetSize(), true);

                if (ndo)
                    return false; //处理错误,返回false断开
                nr = _pcli->DoLeftData(ucid, &_msgr);//继续处理剩下的报文
            };
            _msgr.ClearAndFree(1024 * 1024 * 2);//2MB以上回收内存
            _msgs.ClearAndFree(1024 * 1024 * 2);//2MB以上回收内存
            _cpbufu.Free(); //释放大内存
            return nr >= 0; // < 0 解析错误,返回false断开
        }

        virtual	void	DoSelfMsg(unsigned int uevt) //执行自定义操作,uevt为PostSelfEvent时投递的消息,可用于服务端主动推送
        {
            t_rpcnotify ntf;
            ntf.threadno = _nthreadno;
            ntf.status = -1;
            sprintf(ntf.in, "selfmsg,%u", uevt);
            ntf.out[0] = 0;
            _OnNotify(&ntf);

        };	// dwMsg = TCPIO_MSG_XXXX
        virtual	void	OnOptComplete(unsigned int ucid, unsigned int uopt) //读或写完成,可用于服务端主动推送
        {
            t_rpcnotify ntf;
            ntf.threadno = _nthreadno;
            ntf.status = -1;
            sprintf(ntf.in, "complete,%u,%u", ucid, uopt);
            ntf.out[0] = 0;
            _OnNotify(&ntf);

        };//uopt = TCPIO_OPT_XXXX
        virtual	void	OnOptError(unsigned int ucid, unsigned int uopt) //读或写错误,可用于服务端主动推送
        {
            t_rpcnotify ntf;
            ntf.threadno = _nthreadno;
            ntf.status = -1;
            sprintf(ntf.in, "opterr,%u,%u", ucid, uopt);
            ntf.out[0] = 0;
            _OnNotify(&ntf);
        };	//uopt = TCPIO_OPT_XXXX

        /*!
        \brief 主动推送消息
        \return -1表示有错,>=0为发送的字节数
        */
        int PutMsg(unsigned int ucid, const void* pdata, size_t usize)
        {
            t_rpcuserinfo usrinfo;
            usrinfo._ucid = ucid;
            if (!_pcli->GetUserInfo(&usrinfo) || usrinfo._nstatus != rpcusr_pass)//取用户信息			
                return -1; //无此用户或该用户没有登录

            RPCCOMPRESS comp = rpccomp_none;
            if (usize > 512)
                comp = rpccomp_lz4;
            unsigned int seqno = (unsigned int)ec::atomic_addlong(&_pcli->_lseqno, 1);
            _putmsg.ClearData();
            MakePkg(pdata, usize, rpcmsg_send, comp, seqno, usrinfo._pswsha1, &_putmsg);
            int nret = SendToUcid(ucid, _putmsg.GetBuf(), _putmsg.GetSize(), true);
            _putmsg.ClearAndFree(2 * 1024 * 1024);
            return nret;
        }
    };

    /*!
    \brief 服务方,继承方式使用
    */
    class cRpcBaseServer : public cTcpServer
    {
    public:
        cRpcBaseServer() : _tmp(1024 * 256), _aucid(256)
        {
            _plog = NULL;
            memset(_sname, 0, sizeof(_sname));
        }
        cRpcClientMap _clients;
        cCritical _csbuf;
        tArray<unsigned char> _tmp;
    protected:
        char _sname[32];
        ec::cLog* _plog;
        ec::tArray<unsigned int> _aucid;
    public:
        inline void SetLogSrv(ec::cLog* plog)
        {
            _plog = plog;
        }
        inline void SetSrvName(const char* sname)
        {
            strncpy(_sname, sname, sizeof(_sname) - 1);
        }
        inline const char* GetSrvName() {
            return _sname;
        }
        inline void SetEncryptData(bool bEncrypt)
        {
            _clients.SetEncryptData(bEncrypt);
        }
        inline bool IsEncryptData()
        {
            return _clients.IsEncryptData();
        }
    protected:
        virtual int _OnNotify(t_rpcnotify* pnotify) = 0; //只处理logout
        virtual void    OnConnected(unsigned int ucid, const char* sip)
        {
            if (_plog)
                _plog->AddLog("MSG: Server(%s) UCID %u IP=%s TCP connected!", _sname, ucid, sip);
            _clients.Add(ucid, sip);
        };
        virtual void	OnRemovedUCID(unsigned int ucid)//继承的类先调用基类的实现
        {
            t_rpcuserinfo usrinfo;
            usrinfo._ucid = ucid;
            if (!_clients.GetUserInfo(&usrinfo))//取用户信息
                return;
            _clients.Del(ucid);
            if (usrinfo._nstatus > rpcusr_connect)
            {
                t_rpcnotify ntf;
                ntf.threadno = -1;
                ntf.status = -1;
                sprintf(ntf.in, "logout,%u,0,0", ucid);
                ntf.out[0] = 0;
                _OnNotify(&ntf);
                if (_plog)
                    _plog->AddLog("MSG: Server(%s) UCID %u TCP disconnected from %s", _sname, ucid, usrinfo._sip);
                return;
            }
            if (_plog)
                _plog->AddLog("MSG: Server(%s) UCID %u TCP disconnected from %s", _sname, ucid, usrinfo._sip);
        };

        virtual void    CheckNotLogin() //chech not login 
        {
            if (!_clients.GetTimeOutNoLogin(::time(NULL), 60, &_aucid))
                return;
            int i, n = _aucid.GetNum();
            unsigned int *pu = _aucid.GetBuf();
            t_rpcuserinfo usrinfo;
            memset(&usrinfo, 0, sizeof(usrinfo));

            for (i = 0; i < n; i++)
            {
                if (_plog)
                {
                    usrinfo._ucid = pu[i];
                    if (_clients.GetUserInfo(&usrinfo))//取用户信息
                        _plog->AddLog("MSG: Server(%s) Delete UCID %u IP=%s as long time no login!", _sname, pu[i], usrinfo._sip);
                    else
                        _plog->AddLog("MSG: Server(%s) Delete UCID %u as long time no login!", _sname, pu[i]);
                }
                DisconnectUser(pu[i]);
            }
        }
    };

    /*
    \brief 接收线程
    */
    class cRpcThread :public cRpcBaseThread
    {
    public:
        cRpcThread(cRpcClientMap* pcli,
            rpc_OnNotify OnNotify, void* pclsOnNotify,
            rpc_OnMsg		OnMsg, void* pclsOnMsg
        ) : cRpcBaseThread(pcli)
        {
            _pOnNotify = OnNotify;
            _pclsOnNotify = pclsOnNotify;

            _pOnMsg = OnMsg;
            _pclsOnMsg = pclsOnMsg;
        }
        virtual ~cRpcThread()
        {
        }
    private:
        rpc_OnNotify _pOnNotify;
        void* _pclsOnNotify;

        rpc_OnMsg	_pOnMsg;
        void* _pclsOnMsg;

    protected:
        virtual int _OnNotify(t_rpcnotify* pnotify)
        {
            return _pOnNotify(_pclsOnNotify, pnotify);
        }
        virtual int _OnMsg(RPCMSGTYPE type, unsigned int ucid, const char* usr, const unsigned char *pmsg, size_t msglen, void** presult, size_t* resultlen) //消息处理回调
        {
            return _pOnMsg(_pclsOnMsg, _nthreadno, type, ucid, usr, pmsg, msglen, presult, resultlen);
        }
    };

    /*!
    \brief 服务方,高度封装回调方式
    */
    class cRpc_S : public cRpcBaseServer
    {
    public:
        cRpc_S()
        {
            _pOnNotify = 0;
            _pclsOnNotify = 0;
            _pOnMsg = 0;
            _pclsOnMsg = 0;
        }
    private:
        rpc_OnNotify _pOnNotify;
        void* _pclsOnNotify;

        rpc_OnMsg	_pOnMsg;
        void* _pclsOnMsg;

    protected:
        virtual int _OnNotify(t_rpcnotify* pnotify)
        {
            return _pOnNotify(_pclsOnNotify, pnotify);
        }
        virtual cTcpSvrWorkThread* CreateWorkThread() {
            return new cRpcThread(&_clients, _pOnNotify, _pclsOnNotify, _pOnMsg, _pclsOnMsg);
        };
    public:
        bool StartServer(unsigned short wport, unsigned int uThreads, unsigned int  uMaxConnect,
            rpc_OnNotify OnNotify, void* pclsOnNotify,
            rpc_OnMsg		OnMsg, void* pclsOnMsg
        )
        {
            _pOnNotify = OnNotify;
            _pclsOnNotify = pclsOnNotify;
            _pOnMsg = OnMsg;
            _pclsOnMsg = pclsOnMsg;

            return Start(wport, uThreads, uMaxConnect);
        }
    };
}//ec

/*!
\brief rpc客户端通知事件
*/
enum RPC_CLINET_EVT
{
    rpc_c_connecting = 1, //!<正在连接
    rpc_c_login_ok = 0, //!<登录成功
    rpc_c_login_usrerr = -1, //!<登录用户无效,无此用户或者账号过期,未登录
    rpc_c_login_pswerr = -2, //!<登录密码错误,
    rpc_c_connect_tcperr = -3, //!<连接TCP错误
    roc_c_disconnected_tcp = -4, //!<TCP层连接断开
    roc_c_disconnected_msgerr = -5  //!<消息错误而断开
};

typedef void(*rpc_clientevt)(void* pParam, RPC_CLINET_EVT nevt); //客户端事件回调

/*!
\brief  客户端消息回调
\remark 接收消息处理,根据处理结果，如果需要向服务器发送消息，可以使用SendMsg直接在回调中发送
*/
typedef void(*rpc_clientMsg)(void* pParam, RPCMSGTYPE type, unsigned int seqno, const unsigned char *pmsg, size_t msglen); //消息处理回调
namespace ec
{
    /*!
    \brief 客户端对象,断线通知
    */
    class cRpc_C : public cThread
    {
    public:
        cRpc_C() : _rbuf(256 * 1024), _msgs(256 * 1024), _msgr(256 * 1024), _msgput(256 * 1024) {
            _bEncryptData = true;
            _wport = 0;
            _sip[0] = 0;
            _usr[0] = 0;
            _psw[0] = 0;

            _funevt = 0;
            _clsevt = 0;

            _funmsg = 0;
            _clsmsg = 0;

            _sock = INVALID_SOCKET;
            _nstatus = -1;
            _seqno = 0;
            _bdisconnect = 0;
        };

        virtual ~cRpc_C() {
        }

        inline void SetEncryptData(bool bEncrypt)
        {
            _bEncryptData = bEncrypt;
        }
        inline bool IsEncryptData()
        {
            return _bEncryptData;
        }
    protected:
        bool _bEncryptData;
    protected:
        unsigned short _wport;
        char _sip[16];
        char _usr[32];
        char _psw[40];
        unsigned char _pswsha1[20]; //密码的sha1摘要，用于解密

        rpc_clientevt _funevt;//事件通知函数
        void* _clsevt;//!<事件通知对象
        rpc_clientMsg _funmsg;
        void* _clsmsg;

        volatile  int    _bdisconnect;//!<主动断开标识
        volatile  SOCKET _sock;
        volatile  int   _nstatus;//!<状态,-1,未连接,0已连接,1已登录
        tArray<unsigned char> _rbuf;//!<未处理字符数组
        tArray<unsigned char> _msgs;//!<发送缓冲区
        tArray<unsigned char> _msgr;//!<接收到的完整消息

        tArray<unsigned char> _msgput;//!<发送缓冲区

        cReUseMem _cpbufc;//压缩内存
        cReUseMem _cpbufu;//解压内存

        char _msgsh[1024];//握手消息用
        unsigned char _readbuf[32768];//接收缓冲
        volatile unsigned int _seqno;

        cCritical _csmk, _cssend;
    private:
        bool MakePkg(const void* pd, size_t size, RPCMSGTYPE msgtype, RPCCOMPRESS compress, unsigned int seqno, const unsigned char* pmask, tArray<unsigned char>* pPkg)
        {
            ec::cSafeLock Lck(&_csmk);//打包公用,发送和应答公用

            unsigned char shead[sizeof(t_rpcpkg)] = { 0 };
            pPkg->ClearData();
            pPkg->Add(shead, sizeof(t_rpcpkg));
            t_rpcpkg* ph = (t_rpcpkg*)pPkg->GetBuf();

            ph->sync = 0xA9;
            ph->type = (char)msgtype;

            void* pdata;
            size_t ulen = size;
            if (compress == rpccomp_lz4)
            {
                ulen = size + (size / 1024) * 32 + 1024;
                pdata = _cpbufc.Alloc(ulen);
                if (pdata && encode_lz4(pd, size, pdata, &ulen))
                    ph->comp = rpccomp_lz4; //lz4压缩
                else //压缩失败
                {
                    pdata = (void*)pd;
                    ph->comp = rpccomp_none; //不压缩
                    ulen = size;
                }
            }
#ifdef RPC_USE_ZLIB
            else if (compress == rpccomp_zlib)
            {
                ulen = size + (size / 1024) * 32 + 1024;
                pdata = _cpbufc.Alloc(ulen);
                if (pdata && encode_zlib(pd, size, pdata, &ulen))
                    ph->comp = rpccomp_zlib; //zlib压缩
                else //压缩失败
                {
                    pdata = (void*)pd;
                    ph->comp = rpccomp_none; //不压缩
                    ulen = size;
                }
            }
#endif
            else
            {
                pdata = (void*)pd;
                ph->comp = rpccomp_none; //不压缩
                ulen = size;
            }
            if (_bEncryptData)
                ph->cflag = 0;
            else
                ph->cflag = 1;

            ph->seqno = CNetInt::NetUInt(seqno);
            ph->size_en = CNetInt::NetUInt((unsigned int)ulen);
            ph->size_dn = CNetInt::NetUInt((unsigned int)size);

            if (!pPkg->Add((const unsigned char*)pdata, ulen))
                return false;

            ph = (t_rpcpkg*)pPkg->GetBuf(); //必须重新读取头部

            _cpbufc.Free();//释放大内存
            unsigned char* puc = pPkg->GetBuf() + sizeof(t_rpcpkg);
            if (pmask && msgtype >= rpcmsg_request)//应用层消息需要加密
            {
                unsigned int ul = (unsigned int)ulen;
                register unsigned int	crc = 0xffffffff;
                register unsigned int i;

                for (i = 0; i < ul; i++) //先计算CRC32
                    crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ puc[i]];//加密前验证数据
                ph->crc32msg = CNetInt::NetUInt(crc ^ 0xffffffff);

                if (_bEncryptData)
                {
                    unsigned int *pu4 = (unsigned int *)puc, ul4 = ul / 4; //加密
                    unsigned int *pmk4 = (unsigned int*)pmask;
                    for (i = 0; i < ul4; i++)
                        pu4[i] ^= pmk4[i % 5];
                    for (i = ul4 * 4; i < ul; i++)
                        puc[i] ^= pmask[i % 20];
                }
            }
            else
                ph->crc32msg = CNetInt::NetUInt(crc32(puc, (unsigned int)ulen));
            ph->crc32head = CNetInt::NetUInt(crc32(ph, 20));
            return true;
        }
    protected:
        virtual void OnStop() {
            if (_sock != INVALID_SOCKET)
            {
                closesocket(_sock);
                _sock = INVALID_SOCKET;
            }
            _nstatus = -1;
            _bdisconnect = 0;
        };
        virtual	void dojob() {
            if (_sock == INVALID_SOCKET)
            {
                int nr = ConnectIn();
                if (nr < 0)
                {
                    ec::atomic_setlong(&_lKillTread, 1);
                    if (_funevt)
                        _funevt(_clsevt, (RPC_CLINET_EVT)nr);//通知                    
                    return;
                }
            }
            if (_bdisconnect) //主动断开
            {
                ec::atomic_setlong(&_lKillTread, 1);
                _bdisconnect = 0;
                if (_sock != INVALID_SOCKET)
                {
                    _nstatus = -1;
                    closesocket(_sock);
                    _sock = INVALID_SOCKET;
                }
                if (_funevt)
                    _funevt(_clsevt, roc_c_disconnected_tcp);//通知
                return;
            }

            int nr = tcp_read(_sock, _readbuf, sizeof(_readbuf), 100);
            while (nr > 0)
            {
                int nerrcode = OnReadByte(_readbuf, nr);
                if (nerrcode < 0)
                {
                    if (nerrcode != roc_c_disconnected_tcp && _funevt)
                        _funevt(_clsevt, (RPC_CLINET_EVT)nerrcode); //错误原因
                    nr = roc_c_disconnected_tcp;
                    break;
                }
                nr = tcp_read(_sock, _readbuf, sizeof(_readbuf), 0);
            }
            if (nr < 0)
            {
                ec::atomic_setlong(&_lKillTread, 1);
                if (_sock != INVALID_SOCKET)
                {
                    _nstatus = -1;
                    closesocket(_sock);
                    _sock = INVALID_SOCKET;
                }
                if (_funevt)
                    _funevt(_clsevt, roc_c_disconnected_tcp);//通知断开
            }
        };

        int  ConnectIn()//返回 0 连接成功,1已经连接，<0需要通知
        {
            if (_sock != INVALID_SOCKET)
                return 1;

            _rbuf.ClearData();//所有缓冲初始化
            _msgs.ClearData();
            _msgr.ClearData();

            SOCKET s = tcp_connect(_sip, _wport, 4);
            if (s == INVALID_SOCKET)
            {
                _nstatus = -1;
                return rpc_c_connect_tcperr;
            }

            SetSocketKeepAlive(s, false);
            sprintf(_msgsh, "connect,%s", _usr);//发送握手信息
            MakePkg(_msgsh, strlen(_msgsh), rpcmsg_sh, rpccomp_none, _seqno++, 0, &_msgs);
            if (tcp_send(s, _msgs.GetBuf(), _msgs.GetNum()) <= 0)
            {
                closesocket(s);
                _sock = INVALID_SOCKET;
                _nstatus = -1;
                return rpc_c_connect_tcperr;
            }
            _sock = s;
            _nstatus = 0;
            return 0;
        }

        int OnReadByte(const unsigned char* s, int n)
        {
            _rbuf.Add(s, n);
            int nr = DoLeftData(&_msgr);
            while (nr > 0)
            {
                nr = DoMsg();
                if (nr < 0)
                    return nr;
                nr = DoLeftData(&_msgr);
            };
            _cpbufu.Free();
            _msgs.ClearAndFree(1024 * 1024 * 2);
            _msgr.ClearAndFree(1024 * 1024 * 2);
            return nr;
        }

        int DoLeftData(tArray<unsigned char>* pout)//处理生效的报文
        {
            pout->ClearData();
            unsigned int   ulen = _rbuf.GetSize();
            unsigned char* pu = _rbuf.GetBuf();
            if (ulen < sizeof(t_rpcpkg))
            {
                _rbuf.ReduceMem(1024 * 128);//回收多余的内存
                return 0;
            }
            //验证
            t_rpcpkg* pkg = (t_rpcpkg*)pu;
            unsigned int c1 = crc32(pu, 20);
            if (pkg->sync != 0xA9 || c1 != CNetInt::NetUInt(pkg->crc32head))
                return roc_c_disconnected_msgerr;//报文错误
            unsigned int sizemsg = CNetInt::NetUInt(pkg->size_en);

            if (ulen < sizemsg + sizeof(t_rpcpkg))
                return 0;
            pout->Add(pu, sizemsg + sizeof(t_rpcpkg));
            _rbuf.LeftMove(sizemsg + sizeof(t_rpcpkg));
            unsigned char* puc = pout->GetBuf() + sizeof(t_rpcpkg);
            if (pkg->type >= rpcmsg_request) //应用层消息需要解密
            {
                register unsigned int i;
                if (!(pkg->cflag & 0x01))
                {
                    unsigned int *pu4 = (unsigned int*)puc, u4 = sizemsg / 4;//先解密
                    unsigned int *pmk4 = (unsigned int*)_pswsha1;
                    for (i = 0; i < u4; i++) //先按照4字节对齐解
                        pu4[i] ^= pmk4[i % 5];
                    for (i = u4 * 4; i < sizemsg; i++)//剩下的单字节解
                        puc[i] ^= _pswsha1[i % 20];
                }
                register unsigned int	crc = 0xffffffff;
                for (i = 0; i < sizemsg; i++) //计算CRC32
                    crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ puc[i]]; //解密后计算数据CRC32
                if (pkg->crc32msg != CNetInt::NetUInt(crc ^ 0xffffffff))
                    return -1;
            }
            else
            {
                if (pkg->crc32msg != CNetInt::NetUInt(crc32(puc, sizemsg)))
                    return roc_c_disconnected_msgerr;
            }
            return 1;
        }

        int DoMsg() //处理存放于_msgr中的消息,返回<0 为断开错误码,要断开连接
        {
            t_rpcpkg* pkg = (t_rpcpkg*)_msgr.GetBuf();
            void* pmsg;
            size_t ulen;

            if (pkg->comp == rpccomp_none)
            {
                pmsg = pkg->msg;
                ulen = CNetInt::NetUInt(pkg->size_en);
            }
            else if (pkg->comp == rpccomp_lz4)
            {
                size_t uen = CNetInt::NetUInt(pkg->size_en), udn = CNetInt::NetUInt(pkg->size_dn);
                void *pdes = _cpbufu.Alloc(udn);
                if (!decode_lz4(pkg->msg, uen, pdes, &udn))
                    return roc_c_disconnected_msgerr;
                pmsg = pdes;
                ulen = udn;
            }
#ifdef RPC_USE_ZLIB
            else if (pkg->comp == rpccomp_zlib)
            {
                size_t uen = CNetInt::NetUInt(pkg->size_en), udn = CNetInt::NetUInt(pkg->size_dn);
                void *pdes = _cpbufu.Alloc(udn);
                if (!decode_zlib(pkg->msg, uen, pdes, &udn))
                    return roc_c_disconnected_msgerr;
                pmsg = pdes;
                ulen = udn;
            }
#endif
            else
                return roc_c_disconnected_msgerr;

            if (pkg->type == rpcmsg_sh) //握手消息
                return  DoMsgSh((char*)pmsg, ulen);
            else if (pkg->type == rpcmsg_sys) //系统消息
                _msgr.Add((unsigned char)0);
            else
            {
                _funmsg(_clsmsg, (RPCMSGTYPE)pkg->type, CNetInt::NetUInt(pkg->seqno), (unsigned char*)pmsg, ulen);
                return 0;
            }
            return 0;
        }

        int DoMsgSh(char* ps, size_t len)//返回小于0表示要断开连接，并通知
        {
            char sod[32];
            size_t pos = 0;
            if (!str_getnextstring(',', ps, len, pos, sod, sizeof(sod)))
                return roc_c_disconnected_msgerr;
            if (!strcmp(sod, "onconnect"))
            {
                char sarg[128];
                if (!str_getnextstring(',', ps, len, pos, sarg, sizeof(sarg)))
                    return roc_c_disconnected_msgerr;
                if (atoi(sarg))
                    return rpc_c_login_usrerr;//用户无效
                if (!str_getnextstring(',', ps, len, pos, sarg, sizeof(sarg)))
                    return roc_c_disconnected_msgerr;

                unsigned char  hex[20], uc, sha[44];
                strcat(sarg, _psw);//附上自己的密码，然后sha1摘要

                encode_sha1(sarg, (unsigned int)strlen(sarg), hex);

                int i;
                for (i = 0; i < 20; i++)
                {
                    uc = hex[i] >> 4;
                    sha[i * 2] = (uc >= 0x0A) ? 'A' + (uc - 0x0A) : '0' + uc;
                    uc = hex[i] & 0x0F;
                    sha[i * 2 + 1] = (uc >= 0x0A) ? 'A' + (uc - 0x0A) : '0' + uc;
                }
                sha[40] = 0;
                sprintf(sarg, "sha1,%s", sha);

                MakePkg(sarg, strlen(sarg), rpcmsg_sh, rpccomp_none, _seqno++, _pswsha1, &_msgs);
                if (tcp_send(_sock, _msgs.GetBuf(), _msgs.GetNum()) <= 0)
                    return rpc_c_connect_tcperr;
            }
            else if (!strcmp(sod, "onsha1"))
            {
                char sarg[128];
                if (!str_getnextstring(',', ps, len, pos, sarg, sizeof(sarg)))
                    return roc_c_disconnected_msgerr;
                if (atoi(sarg))
                    return rpc_c_login_pswerr;
                _nstatus = 1;//已login成功
                if (_funevt)
                    _funevt(_clsevt, rpc_c_login_ok);//通知登录成功

            }
            return 0;
        }

    public:
        void Start(const char* sip, unsigned short wport, const char* usr, const char* password, rpc_clientevt pfce, void* pParamFce, rpc_clientMsg pfmsg, void* pParamFmsg)
        {
            _bdisconnect = 0;
            str_ncpy(_sip, sip, sizeof(_sip));
            _wport = wport;

            str_ncpy(_usr, usr, sizeof(_usr));
            str_ncpy(_psw, password, sizeof(_psw));
            if (!_psw[0])
                strcpy(_psw, "123456");//默认密码

            encode_sha1(_psw, (unsigned int)strlen(_psw), _pswsha1);

            _funevt = pfce;
            _clsevt = pParamFce;

            _funmsg = pfmsg;
            _clsmsg = pParamFmsg;

            StartThread(0);
        }
        inline void Stop()
        {
            StopThread();
        }

        /*!
        \brief 应用层发送
        \param pseqno [out] 当前发送的消息的序列号,如果是rpsmsg_call或rpcmsg_put，服务端会使用rpcmsg_ans以相同的seqno应答
        \return 0表示成功，其他为错误码,如果短线，则不会通知应用层,由线程的keepalive负责重连
        \remark 可以在回调中发送，也可以在应用层主动发送
        */
        int  SendMsg(const void* pd, size_t size, RPCMSGTYPE msgtype, RPCCOMPRESS compress, unsigned int seqno) //返回0表示成功，其他为错误码
        {
            if (_nstatus != 1 || _sock == INVALID_SOCKET)
                return rpc_c_login_usrerr; //未登录
            MakePkg(pd, size, msgtype, compress, seqno, _pswsha1, &_msgput);
            _cssend.Lock();
            int nr = tcp_send(_sock, _msgput.GetBuf(), _msgput.GetNum());
            _cssend.Unlock();
            if (nr <= 0)
                return roc_c_disconnected_tcp;
            return 0;
        }

        inline void SetDisConnect() //设置重连,由外部调用
        {
            _bdisconnect = 1;
        }

        /*!
        \brief 返回状态,-1:未连接; 0:握手中; 1:已连接
        */
        inline int GetStatus()
        {
            return _nstatus;
        }
        inline bool IsConnect()
        {
            return _nstatus == 1;
        }
    };

    /*!
    \breif RPC auto reconnect client
    */
    class cRpcAutoClient : public cTcpCli
    {
    public:
        cRpcAutoClient() : _rbuf(256 * 1024), _msgs(256 * 1024), _msgr(256 * 1024), _msgput(256 * 1024) {
            _bEncryptData = true;
            _wport = 0;
            _sip[0] = 0;
            _usr[0] = 0;
            _psw[0] = 0;

            _sock = INVALID_SOCKET;
            _nstatus = -1;
            _seqno = 0;
        };

        virtual ~cRpcAutoClient() {
            Close();
        }
        inline void SetEncryptData(bool bEncrypt)
        {
            _bEncryptData = bEncrypt;
        }
        inline bool IsEncryptData()
        {
            return _bEncryptData;
        }
    protected:
        bool _bEncryptData;
    protected:
        virtual void OnLoginEvent(RPC_CLINET_EVT nEvent) = 0;
        virtual void OnClientMsg(RPCMSGTYPE type, unsigned int seqno, const unsigned char *pmsg, size_t msglen) = 0;

        virtual void OnConnected()
        {
            _rbuf.ClearData();
            _msgs.ClearData();
            _msgr.ClearData();

            SetSocketKeepAlive(_sock, false);
            sprintf(_msgsh, "connect,%s", _usr);
            MakePkg(_msgsh, strlen(_msgsh), rpcmsg_sh, rpccomp_none, _seqno++, 0, &_msgs);
            Send(_msgs.GetBuf(), _msgs.GetNum());
            _nstatus = 0;
        }
        virtual void OnDisConnected(int where, int nerrcode) {
            _nstatus = -1;
            if (where > 0)
                OnLoginEvent(roc_c_disconnected_tcp);
            else if (where < 0)
                OnLoginEvent(rpc_c_connect_tcperr);
        };
        virtual void OnRead(const void* pd, int nsize)
        {
            const unsigned char* s = (const unsigned char*)pd;
            _rbuf.Add(s, nsize);
            int nr = DoLeftData(&_msgr);
            while (nr > 0)
            {
                DoMsg();
                nr = DoLeftData(&_msgr);
            };
            _cpbufu.Free();
            _msgs.ClearAndFree(1024 * 1024 * 2);
            _msgr.ClearAndFree(1024 * 1024 * 2);
        }
    protected:
        unsigned short _wport;
        char _sip[16];
        char _usr[32];
        char _psw[40];
        unsigned char _pswsha1[20]; //密码的sha1摘要，用于解密

        volatile  int   _nstatus;//!<状态,-1,未连接,0已连接,1已登录
        tArray<unsigned char> _rbuf;//!<未处理字符数组
        tArray<unsigned char> _msgs;//!<发送缓冲区
        tArray<unsigned char> _msgr;//!<接收到的完整消息

        tArray<unsigned char> _msgput;//!<发送缓冲区

        cReUseMem _cpbufc;//压缩内存
        cReUseMem _cpbufu;//解压内存

        char _msgsh[1024];//握手消息用
        volatile unsigned int _seqno;

        cCritical _csmk;
    private:
        bool MakePkg(const void* pd, size_t size, RPCMSGTYPE msgtype, RPCCOMPRESS compress, unsigned int seqno, const unsigned char* pmask, tArray<unsigned char>* pPkg)
        {
            ec::cSafeLock Lck(&_csmk);//打包公用,发送和应答公用

            unsigned char shead[sizeof(t_rpcpkg)] = { 0 };
            pPkg->ClearData();
            pPkg->Add(shead, sizeof(t_rpcpkg));
            t_rpcpkg* ph = (t_rpcpkg*)pPkg->GetBuf();

            ph->sync = 0xA9;
            ph->type = (char)msgtype;

            void* pdata;
            size_t ulen = size;
            if (compress == rpccomp_lz4)
            {
                ulen = size + (size / 1024) * 32 + 1024;
                pdata = _cpbufc.Alloc(ulen);
                if (pdata && encode_lz4(pd, size, pdata, &ulen))
                    ph->comp = rpccomp_lz4; //lz4压缩
                else //压缩失败
                {
                    pdata = (void*)pd;
                    ph->comp = rpccomp_none; //不压缩
                    ulen = size;
                }
            }
#ifdef RPC_USE_ZLIB
            else if (compress == rpccomp_zlib)
            {
                ulen = size + (size / 1024) * 32 + 1024;
                pdata = _cpbufc.Alloc(ulen);
                if (pdata && encode_zlib(pd, size, pdata, &ulen))
                    ph->comp = rpccomp_zlib; //zlib压缩
                else //压缩失败
                {
                    pdata = (void*)pd;
                    ph->comp = rpccomp_none; //不压缩
                    ulen = size;
                }
            }
#endif
            else
            {
                pdata = (void*)pd;
                ph->comp = rpccomp_none; //不压缩
                ulen = size;
            }
            if (_bEncryptData)
                ph->cflag = 0;
            else
                ph->cflag = 1;

            ph->seqno = CNetInt::NetUInt(seqno);
            ph->size_en = CNetInt::NetUInt((unsigned int)ulen);
            ph->size_dn = CNetInt::NetUInt((unsigned int)size);

            if (!pPkg->Add((const unsigned char*)pdata, ulen))
                return false;

            ph = (t_rpcpkg*)pPkg->GetBuf(); //必须重新读取头部

            _cpbufc.Free();//释放大内存
            unsigned char* puc = pPkg->GetBuf() + sizeof(t_rpcpkg);
            if (pmask && msgtype >= rpcmsg_request)//应用层消息需要加密
            {
                unsigned int ul = (unsigned int)ulen;
                register unsigned int	crc = 0xffffffff;
                register unsigned int i;

                for (i = 0; i < ul; i++) //先计算CRC32
                    crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ puc[i]];//加密前验证数据
                ph->crc32msg = CNetInt::NetUInt(crc ^ 0xffffffff);

                if (_bEncryptData)
                {
                    unsigned int *pu4 = (unsigned int *)puc, ul4 = ul / 4; //加密
                    unsigned int *pmk4 = (unsigned int*)pmask;
                    for (i = 0; i < ul4; i++)
                        pu4[i] ^= pmk4[i % 5];
                    for (i = ul4 * 4; i < ul; i++)
                        puc[i] ^= pmask[i % 20];
                }
            }
            else
                ph->crc32msg = CNetInt::NetUInt(crc32(puc, (unsigned int)ulen));
            ph->crc32head = CNetInt::NetUInt(crc32(ph, 20));
            return true;
        }
    protected:


        int DoLeftData(tArray<unsigned char>* pout)//处理生效的报文
        {
            pout->ClearData();
            unsigned int   ulen = _rbuf.GetSize();
            unsigned char* pu = _rbuf.GetBuf();
            if (ulen < sizeof(t_rpcpkg))
            {
                _rbuf.ReduceMem(1024 * 128);//回收多余的内存
                return 0;
            }
            //验证
            t_rpcpkg* pkg = (t_rpcpkg*)pu;
            unsigned int c1 = crc32(pu, 20);
            if (pkg->sync != 0xA9 || c1 != CNetInt::NetUInt(pkg->crc32head))
                return roc_c_disconnected_msgerr;//报文错误
            unsigned int sizemsg = CNetInt::NetUInt(pkg->size_en);

            if (ulen < sizemsg + sizeof(t_rpcpkg))
                return 0;
            pout->Add(pu, sizemsg + sizeof(t_rpcpkg));
            _rbuf.LeftMove(sizemsg + sizeof(t_rpcpkg));
            unsigned char* puc = pout->GetBuf() + sizeof(t_rpcpkg);
            if (pkg->type >= rpcmsg_request) //应用层消息需要解密
            {
                register unsigned int i;
                if (!(pkg->cflag & 0x01)) {
                    unsigned int *pu4 = (unsigned int*)puc, u4 = sizemsg / 4;//先解密
                    unsigned int *pmk4 = (unsigned int*)_pswsha1;
                    for (i = 0; i < u4; i++) //先按照4字节对齐解
                        pu4[i] ^= pmk4[i % 5];
                    for (i = u4 * 4; i < sizemsg; i++)//剩下的单字节解
                        puc[i] ^= _pswsha1[i % 20];
                }
                register unsigned int	crc = 0xffffffff;
                for (i = 0; i < sizemsg; i++) //计算CRC32
                    crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ puc[i]]; //解密后计算数据CRC32
                if (pkg->crc32msg != CNetInt::NetUInt(crc ^ 0xffffffff))
                    return -1;
            }
            else
            {
                if (pkg->crc32msg != CNetInt::NetUInt(crc32(puc, sizemsg)))
                    return roc_c_disconnected_msgerr;
            }
            return 1;
        }

        int DoMsg() //处理存放于_msgr中的消息,返回<0 为断开错误码,要断开连接
        {
            t_rpcpkg* pkg = (t_rpcpkg*)_msgr.GetBuf();
            void* pmsg;
            size_t ulen;

            if (pkg->comp == rpccomp_none)
            {
                pmsg = pkg->msg;
                ulen = CNetInt::NetUInt(pkg->size_en);
            }
            else if (pkg->comp == rpccomp_lz4)
            {
                size_t uen = CNetInt::NetUInt(pkg->size_en), udn = CNetInt::NetUInt(pkg->size_dn);
                void *pdes = _cpbufu.Alloc(udn);
                if (!decode_lz4(pkg->msg, uen, pdes, &udn))
                    return roc_c_disconnected_msgerr;
                pmsg = pdes;
                ulen = udn;
            }
#ifdef RPC_USE_ZLIB
            else if (pkg->comp == rpccomp_zlib)
            {
                size_t uen = CNetInt::NetUInt(pkg->size_en), udn = CNetInt::NetUInt(pkg->size_dn);
                void *pdes = _cpbufu.Alloc(udn);
                if (!decode_zlib(pkg->msg, uen, pdes, &udn))
                    return roc_c_disconnected_msgerr;
                pmsg = pdes;
                ulen = udn;
            }
#endif
            else
                return roc_c_disconnected_msgerr;

            if (pkg->type == rpcmsg_sh) //握手消息
                return  DoMsgSh((char*)pmsg, ulen);
            else if (pkg->type == rpcmsg_sys) //系统消息
                _msgr.Add((unsigned char)0);
            else
            {
                OnClientMsg((RPCMSGTYPE)pkg->type, CNetInt::NetUInt(pkg->seqno), (unsigned char*)pmsg, ulen);
                return 0;
            }
            return 0;
        }

        int DoMsgSh(char* ps, size_t len)//返回小于0表示要断开连接，并通知
        {
            char sod[32];
            size_t pos = 0;
            if (!str_getnextstring(',', ps, len, pos, sod, sizeof(sod)))
            {
                OnLoginEvent(roc_c_disconnected_msgerr);
                return roc_c_disconnected_msgerr;
            }
            if (!strcmp(sod, "onconnect"))
            {
                char sarg[128];
                if (!str_getnextstring(',', ps, len, pos, sarg, sizeof(sarg)))
                {
                    OnLoginEvent(roc_c_disconnected_msgerr);
                    return roc_c_disconnected_msgerr;
                }
                if (atoi(sarg))
                {
                    OnLoginEvent(rpc_c_login_usrerr);
                    return rpc_c_login_usrerr;
                }
                if (!str_getnextstring(',', ps, len, pos, sarg, sizeof(sarg)))
                {
                    OnLoginEvent(roc_c_disconnected_msgerr);
                    return roc_c_disconnected_msgerr;
                }

                unsigned char  hex[20], uc, sha[44];
                strcat(sarg, _psw);

                encode_sha1(sarg, (unsigned int)strlen(sarg), hex);

                int i;
                for (i = 0; i < 20; i++)
                {
                    uc = hex[i] >> 4;
                    sha[i * 2] = (uc >= 0x0A) ? 'A' + (uc - 0x0A) : '0' + uc;
                    uc = hex[i] & 0x0F;
                    sha[i * 2 + 1] = (uc >= 0x0A) ? 'A' + (uc - 0x0A) : '0' + uc;
                }
                sha[40] = 0;
                sprintf(sarg, "sha1,%s", sha);

                MakePkg(sarg, strlen(sarg), rpcmsg_sh, rpccomp_none, _seqno++, _pswsha1, &_msgs);
                Send(_msgs.GetBuf(), _msgs.GetNum());
            }
            else if (!strcmp(sod, "onsha1"))
            {
                char sarg[128];
                if (!str_getnextstring(',', ps, len, pos, sarg, sizeof(sarg)))
                    return roc_c_disconnected_msgerr;
                if (atoi(sarg))
                    return rpc_c_login_pswerr;
                _nstatus = 1;//已login成功
                OnLoginEvent(rpc_c_login_ok);
            }
            return 0;
        }

    public:
        bool Connect(const char* sip, unsigned short wport, const char* usr, const char* password)
        {
            if (!sip || !wport)
                return false;
            str_ncpy(_usr, usr, sizeof(_usr));
            str_ncpy(_psw, password, sizeof(_psw));
            if (!_psw[0])
                strcpy(_psw, "123456");//默认密码
            encode_sha1(_psw, (unsigned int)strlen(_psw), _pswsha1);
            return Open(sip, wport);

        }
        inline void Disconnect()
        {
            Close();
        }

        /*!
        \brief 应用层发送
        \param pseqno [out] 当前发送的消息的序列号,如果是rpsmsg_call或rpcmsg_put，服务端会使用rpcmsg_ans以相同的seqno应答
        \return 0表示成功，其他为错误码,如果短线，则不会通知应用层,由线程的keepalive负责重连
        \remark 可以在回调中发送，也可以在应用层主动发送
        */
        int  SendMsg(const void* pd, size_t size, RPCMSGTYPE msgtype, RPCCOMPRESS compress, unsigned int seqno) //返回0表示成功，其他为错误码
        {
            if (_nstatus != 1 || INVALID_SOCKET == _sock)
                return rpc_c_login_usrerr; //未登录
            MakePkg(pd, size, msgtype, compress, seqno, _pswsha1, &_msgput);
            int nw = Send(_msgput.GetBuf(), _msgput.GetNum());
            if (nw <= 0)
                return roc_c_disconnected_tcp;
            return 0;
        }

        /*!
        \brief 返回状态,-1:未连接; 0:握手中; 1:已连接
        */
        inline int GetStatus()
        {
            return _nstatus;
        }
        inline bool IsConnect()
        {
            return _nstatus == 1;
        }
    };
}//ec
#endif//C_RPC_H
