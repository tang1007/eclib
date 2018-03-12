/*!
\file c_tcpsrv.h
\brief tcp server windows use CPIO,Linux use Epoll

class ec::cTcpSvrWorkThread;
class ec::cTcpServer;

ec library is free C++ library.

\author	 kipway@outlook.com
*/

#ifndef C_TCPSRV_H
#define C_TCPSRV_H

#include <time.h>

#define TCPIO_OPT_NONE	 0			           // NONE
#define TCPIO_OPT_READ	 0x10000		       // read
#define TCPIO_OPT_SEND	 0x20000		       // write
#define TCPIO_OPT_PUT   (TCPIO_OPT_SEND + 12)  //server put

#define TCPIO_MSG_SELF	0XFF000000	// self
#define TCPIO_MSG_EXIT	0xFF00077F	// exit

#define MAX_TCPWORK_THREAD	16		//

#ifndef _WIN32
#include <unistd.h>
#include <pthread.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <errno.h>
#include <sys/epoll.h>
#include <fcntl.h>
#endif

#include "c_tcp_tl.h"
#include "c_tcp_cpl.h"
#include "c_critical.h"
#include "c_event.h"
#include "c_thread.h"
#include "c_fifobuf.h"

namespace ec
{

#ifdef _WIN32

#ifndef SIZE_READMENBLK
#define SIZE_READMENBLK    32768 //!< memsize for read bytes
#endif

#ifndef SIZE_SMLMEMBLK
#define SIZE_SMLMEMBLK      65536 //!< small memery block bytes for send
#endif

#ifndef ITEMS_MAX_SMLBLKMEM
#define ITEMS_MAX_SMLBLKMEM 512	 //!<number of small memert blocks
#endif

    /*£¡
    \brief CPIO memory block
    */
    struct t_cpioblk
    {
        OVERLAPPED	 Overlapped;
        WSABUF		 WSABuf;
        unsigned int uOperate; // operate code
    };

    /*!
    \brief small memery block statck
    */
    class cSmlBlkMemStack
    {
    public:
        cSmlBlkMemStack() : m_Lock(4000)
        {
            m_utop = 0;
            unsigned int i;
            for (i = 0; i < ITEMS_MAX_SMLBLKMEM; i++)
                m_ios[i] = NULL;
        };
        ~cSmlBlkMemStack() {
            unsigned int i;
            for (i = 0; i < m_utop; i++)
                delioblk(m_ios[i]);
        }
    protected:
        unsigned int		m_utop;
        cCritical m_Lock;
        t_cpioblk*	m_ios[ITEMS_MAX_SMLBLKMEM];

    public:
        static void delioblk(t_cpioblk* p)
        {
            if (!p)
                return;
            if (p->WSABuf.buf)
                free(p->WSABuf.buf);
            delete p;
        }

        static t_cpioblk* newioblk(size_t bufsize = SIZE_SMLMEMBLK)
        {
            t_cpioblk* p = new t_cpioblk;
            size_t sz = bufsize;
            if (sz <= SIZE_SMLMEMBLK)
                sz = SIZE_SMLMEMBLK;
            if (p)
            {
                p->WSABuf.buf = (char*)malloc(sz);
                if (p->WSABuf.buf)
                    memset(p->WSABuf.buf, 0, sz);
                else
                {
                    delete p;
                    p = NULL;
                }
            }
            return p;
        }

    public:
        void	Init(unsigned int uMaxConnect)
        {
            t_cpioblk* p;
            int i, pos = 0;
            for (i = 0; i < ITEMS_MAX_SMLBLKMEM / 4; i++) {
                p = newioblk();
                if (p)
                {
                    m_ios[pos] = p;
                    pos++;
                }
            }
            m_utop = pos;
        }

        t_cpioblk* Pop(unsigned int usize = SIZE_SMLMEMBLK)
        {
            cSafeLock lck(&m_Lock);
            if (usize > SIZE_SMLMEMBLK)
                return newioblk(usize);
            if (m_utop > 0)
            {
                m_utop--;
                return m_ios[m_utop];
            }
            return newioblk();
        };

        void Push(t_cpioblk* p)
        {
            cSafeLock lck(&m_Lock);

            if (p->WSABuf.len > SIZE_SMLMEMBLK)
            {
                delioblk(p);
                return;
            }
            if (m_utop < ITEMS_MAX_SMLBLKMEM)
            {
                m_ios[m_utop] = p;
                m_utop++;
                return;
            }
            delioblk(p);
        }
    };
#else
#define EPOLL_READBUFSIZE 32768
    /*!
    \brief Epoll Event FIFOBUF,designed for custom event
    */
    class cSocketEvents
    {
    public:
        cSocketEvents() :
            _buf(256)
        {
        };
        ~cSocketEvents() {
        }

        cEvent _evt;
    protected:
        cCritical _cs;
        tFifo<struct epoll_event> _buf;
    public:
        void Put(struct epoll_event &epollevt)
        {
            bool badd = false;
            while (!badd)
            {
                _cs.Lock();
                badd = _buf.Add(epollevt, false, 0);
                _cs.Unlock();
                _evt.SetEvent();
                if (!badd)
                    _evt.Wait(1);
            }
        }

        bool Get(struct epoll_event &epollevt)
        {
            bool bret;
            _cs.Lock();
            bret = _buf.Get(epollevt);
            _cs.Unlock();
            if (bret)
                _evt.SetEvent();
            return bret;
        }
    };

#define MAXEPOLLEVENTSIZE  8
    class cSocketEventThread : public cThread
    {
    public:
        cSocketEventThread() {
            _nfdr = -1;
            memset(_eplevt, 0, sizeof(_eplevt));
        };
        ~cSocketEventThread() {};
    protected:
        int  _nfdr;
        cTcpConnectPoll*    _pConPool;
        cSocketEvents*       _pEpollEvents;
        struct epoll_event  _eplevt[MAXEPOLLEVENTSIZE];
    protected:
        virtual	void dojob() // Login run
        {
            int i, n;
            n = epoll_wait(_nfdr, _eplevt, MAXEPOLLEVENTSIZE, 100);
            if (n <= 0)
                return;
            for (i = 0; i < n; i++)
                _pEpollEvents->Put(_eplevt[i]);
        };

    public:
        void Start(int nfdr, cTcpConnectPoll* pConPool, cSocketEvents* pEpollEvents)
        {
            _nfdr = nfdr;
            _pConPool = pConPool;
            _pEpollEvents = pEpollEvents;

            StartThread(NULL);
        }
        void Stop()
        {
            StopThread();
        }
    };
#endif

    /*!
    \brief work thread
    */
    class cTcpSvrWorkThread : public cThread
    {
    public:
        cTcpSvrWorkThread() {
            _nthreadno = -1;
            _wport = 0;
            m_pConPool = NULL;
#ifdef _WIN32
            m_hcpioPort = NULL;
            m_pMem = NULL;
#else
            memset(&_eplevt, 0, sizeof(_eplevt));
            memset(&_evtdel, 0, sizeof(_evtdel));

            _nfdr = -1;
            _pEpollEvents = NULL;
#endif
        };
        virtual ~cTcpSvrWorkThread() {
            Stop();
        };
    protected:
        unsigned short	_wport;
        int             _nthreadno;
        cTcpConnectPoll* m_pConPool;

#ifdef _WIN32
        HANDLE           m_hcpioPort;
        cSmlBlkMemStack* m_pMem;
#else
        int		            _nfdr;	 // epoll_wait fd
        cSocketEvents       *_pEpollEvents;
        struct epoll_event  _eplevt, _evtdel;
        char    _buf[EPOLL_READBUFSIZE];
#endif
    protected:
        virtual void	OnClientDisconnect(unsigned int  ucid, unsigned int uopt, int nerrorcode) = 0; //uopt = TCPIO_OPT_XXXX
        virtual bool	OnReadBytes(unsigned int ucid, const void* pdata, unsigned int usize) = 0; //return false will disconnect
        virtual	void	DoSelfMsg(unsigned int uevt) = 0;	// uevt = TCPIO_MSG_XXXX
        virtual	void	OnOptComplete(unsigned int ucid, unsigned int uopt) = 0;//uopt = TCPIO_OPT_XXXX
        virtual	void	OnOptError(unsigned int ucid, unsigned int uopt) = 0;   //uopt = TCPIO_OPT_XXXX
    public:
#ifdef _WIN32
        bool	Start(HANDLE hcpio, int nthreadno, unsigned short wport, cTcpConnectPoll* pconpool, cSmlBlkMemStack* pmem)
        {
            if (IsRun())
                return true;
            m_hcpioPort = hcpio;
            _nthreadno = nthreadno;
            _wport = wport;
            m_pConPool = pconpool;
            m_pMem = pmem;

            StartThread(NULL);
            return true;
        };
#else
        bool	Start(int nfdr, int nthreadno, unsigned short wport, cTcpConnectPoll* pconpool, cSocketEvents* pEpollEvents)
        {
            if (IsRun())
                return true;
            _nfdr = nfdr;
            _nthreadno = nthreadno;
            _wport = wport;

            m_pConPool = pconpool;
            _pEpollEvents = pEpollEvents;

            StartThread(&(_pEpollEvents->_evt));
            return true;
        }
#endif
        inline void Stop() {
            StopThread();
        };

        /*!
        \return return send bytes,
        0:memery error;
        -1: no ucid or IO error ,call OnClientDisconnect
        */
        int	SendToUcid(unsigned int ucid, const void* pbuf, unsigned int usize, bool bAddCount = false, unsigned int uSendOpt = TCPIO_OPT_SEND)
        {
            if (!pbuf || !usize)
                return 0;

#ifdef _WIN32
            DWORD	dwSend = 0;

            t_cpioblk* pol;
            pol = m_pMem->Pop(usize);

            if (!pol)
                return 0;

            memset(&pol->Overlapped, 0, sizeof(OVERLAPPED));
            pol->WSABuf.len = usize;
            memcpy(pol->WSABuf.buf, pbuf, usize);
            pol->uOperate = uSendOpt;

            if (SOCKET_ERROR == m_pConPool->ucid_WSASend(ucid, &(pol->WSABuf), 1, &dwSend, 0, &(pol->Overlapped), NULL, bAddCount))
            {
                m_pConPool->DelAndCloseSocket(ucid);
                OnClientDisconnect(ucid, uSendOpt, WSAGetLastError());
                m_pMem->Push(pol);
                return -1;
            }
            return (int)usize;
#else
            int nret = m_pConPool->ucid_Send(ucid, pbuf, usize);
            if (SOCKET_ERROR == nret)
            {
                m_pConPool->DelAndCloseSocket(ucid);
                OnClientDisconnect(ucid, uSendOpt, errno);
                OnOptError(ucid, uSendOpt);
                return -1;
            }
            m_pConPool->OnSend(ucid, usize, bAddCount);
            OnOptComplete(ucid, uSendOpt);
            return nret;
#endif
        };

        bool PostSelfEvent(unsigned int uevt)
        {
#ifdef _WIN32
            if (m_hcpioPort && PostQueuedCompletionStatus(m_hcpioPort, uevt, 0, NULL))
                return true;
            return false;
#else
            struct epoll_event e;
            e.data.u64 = 0;
            e.data.fd = -1;
            e.events = uevt;
            _pEpollEvents->Put(e);
            return true;
#endif
        };

    protected:
#ifdef _WIN32
        virtual	void dojob()
        {
            int				nErrCode = 0;
            unsigned long	BytesTransferred, dwRecv, dwFlags = 0;
            unsigned int	ucid, opt;
            LPOVERLAPPED	pOverlapped;
            ULONG_PTR		uKey;
            t_cpioblk*		piobuf;
            if (!GetQueuedCompletionStatus(m_hcpioPort, &BytesTransferred, &uKey, (LPOVERLAPPED *)&pOverlapped, 100))//io error
            {
                if (!pOverlapped)
                    return; // timeout,no completion packet

                nErrCode = GetLastError();

                // BytesTransferred, scoket closed or client error
                ucid = (unsigned int)uKey;
                piobuf = (t_cpioblk*)pOverlapped;

                m_pConPool->DelAndCloseSocket(ucid);
                OnClientDisconnect(ucid, piobuf->uOperate, nErrCode);

                opt = piobuf->uOperate;
                if ((piobuf->uOperate & TCPIO_OPT_SEND) == TCPIO_OPT_SEND)
                    m_pMem->Push(piobuf);
                else if (piobuf->uOperate == TCPIO_OPT_READ)
                    cSmlBlkMemStack::delioblk(piobuf);
                OnOptError(ucid, opt); // client close excpetion will make ERROR_NETNAME_DELETED  64L
                return;
            }

            if (uKey == 0 && pOverlapped == NULL) // self message
            {
                if (TCPIO_MSG_EXIT == BytesTransferred)
                {
                    setkill(1); // stop thread
                    return;
                }
                if (TCPIO_MSG_SELF == (TCPIO_MSG_SELF & BytesTransferred))
                    DoSelfMsg(BytesTransferred);
                return;
            }

            //IO Message
            ucid = (unsigned int)uKey;
            piobuf = (t_cpioblk*)pOverlapped;
            if (piobuf->uOperate == TCPIO_OPT_READ)// TCPIO_OPT_READ
            {
                if (BytesTransferred == 0) // client closed
                {
                    m_pConPool->DelAndCloseSocket(ucid);
                    OnClientDisconnect(ucid, TCPIO_OPT_READ, GetLastError());
                    cSmlBlkMemStack::delioblk(piobuf);
                    return;
                }
                if (!OnReadBytes(ucid, piobuf->WSABuf.buf, BytesTransferred))
                {
                    m_pConPool->DelAndCloseSocket(ucid);
                    OnClientDisconnect(ucid, TCPIO_OPT_READ, GetLastError());
                    cSmlBlkMemStack::delioblk(piobuf);
                    return;
                }
                m_pConPool->OnRead(ucid, BytesTransferred);
                OnOptComplete(ucid, TCPIO_OPT_READ);

                memset(&piobuf->Overlapped, 0, sizeof(OVERLAPPED));//continue read
                piobuf->WSABuf.len = SIZE_READMENBLK;
                piobuf->uOperate = TCPIO_OPT_READ;
                dwFlags = 0;
                if (SOCKET_ERROR == m_pConPool->ucid_WSARecv(ucid, &(piobuf->WSABuf), 1, &dwRecv, &dwFlags, &(piobuf->Overlapped), NULL))
                {
                    m_pConPool->DelAndCloseSocket(ucid);
                    OnClientDisconnect(ucid, TCPIO_OPT_READ, GetLastError());
                    cSmlBlkMemStack::delioblk(piobuf);
                }
            }
            else if ((piobuf->uOperate & TCPIO_OPT_SEND) == TCPIO_OPT_SEND) //TCPIO_OPT_SEND
            {
                if (BytesTransferred == 0) { // client closed
                    m_pConPool->DelAndCloseSocket(ucid);
                    OnClientDisconnect(ucid, piobuf->uOperate, GetLastError());
                    OnOptError(ucid, piobuf->uOperate);
                    m_pMem->Push(piobuf); //reuse memory
                }
                else // send complete
                {
                    m_pConPool->OnSend(ucid, BytesTransferred, piobuf->uOperate != TCPIO_OPT_SEND);
                    OnOptComplete(ucid, piobuf->uOperate);
                    m_pMem->Push(piobuf); //reuse memory
                }
            }
        }
#else
        virtual	void dojob()
        {
            int nfd, nerr;
            unsigned int ucid;
            if (!_pEpollEvents->Get(_eplevt))
                return;
            if (_eplevt.data.fd == -1) // selfmsg
            {
                DoSelfMsg(_eplevt.events);
                return;
            }
            nfd = (int)(_eplevt.data.u64 & 0xFFFFFFFF);
            ucid = (unsigned int)(_eplevt.data.u64 >> 32);
            if (_eplevt.events & EPOLLIN) // read
            {
                while (1)
                {
                    int nbytes = recv(nfd, _buf, sizeof(_buf), MSG_DONTWAIT);
                    if (nbytes < 0) // end or error
                    {
                        nerr = errno;
                        if (nerr == EAGAIN || nerr == EWOULDBLOCK)//read end
                        {
                            OnOptComplete(ucid, TCPIO_OPT_READ);
                            _eplevt.events = EPOLLIN | EPOLLONESHOT;
                            epoll_ctl(_nfdr, EPOLL_CTL_MOD, nfd, &_eplevt); // reset
                        }
                        else
                        {
                            epoll_ctl(_nfdr, EPOLL_CTL_DEL, nfd, &_evtdel);
                            m_pConPool->DelAndCloseSocket(ucid);
                            OnClientDisconnect(ucid, TCPIO_OPT_READ, errno);
                            OnOptError(ucid, TCPIO_OPT_READ);
                            return;
                        }
                        return;
                    }
                    else if (nbytes == 0) // close
                    {
                        epoll_ctl(_nfdr, EPOLL_CTL_DEL, nfd, &_evtdel);
                        m_pConPool->DelAndCloseSocket(ucid);
                        OnClientDisconnect(ucid, TCPIO_OPT_READ, errno);
                        OnOptError(ucid, TCPIO_OPT_READ);
                        return;
                    }
                    else
                    {
                        if (!OnReadBytes(ucid, _buf, nbytes))
                        {
                            epoll_ctl(_nfdr, EPOLL_CTL_DEL, nfd, &_evtdel);
                            m_pConPool->DelAndCloseSocket(ucid);
                            OnClientDisconnect(ucid, TCPIO_OPT_READ, errno);
                            OnOptError(ucid, TCPIO_OPT_READ);
                            return;
                        }
                        m_pConPool->OnRead(ucid, nbytes);
                    }
                };
            }
            else if (_eplevt.events & EPOLLERR || _eplevt.events & EPOLLHUP) // error
            {
                epoll_ctl(_nfdr, EPOLL_CTL_DEL, nfd, &_evtdel);
                m_pConPool->DelAndCloseSocket(ucid);
                OnClientDisconnect(ucid, TCPIO_OPT_READ, errno);
                OnOptError(ucid, TCPIO_OPT_READ);
            }
        }
#endif
    }; //cTcpSvrWorkThread

    /*!
    \brief TCP Server, accept
    */
    class cTcpServer : public cThread
    {
    public:
        cTcpServer(){
            unsigned int i;
            _bkeepalivefast = false;
            _busebnagle = true;
            m_wport = 0;
            m_uThreads = 0;
#ifdef _WIN32
            m_hcpioPort = NULL;
#endif
            m_sListen = INVALID_SOCKET;
            for (i = 0; i < MAX_TCPWORK_THREAD; i++)
                m_pThread[i] = NULL;
        };
        virtual ~cTcpServer() {};

    protected:
        unsigned short		m_wport;
        unsigned int		m_uThreads;
        SOCKET				m_sListen;
    protected:
        bool    _bkeepalivefast;
        bool    _busebnagle;
        cTcpSvrWorkThread*	m_pThread[MAX_TCPWORK_THREAD];
        cTcpConnectPoll	    m_ConPool;
#ifdef _WIN32
        HANDLE				m_hcpioPort;
        cSmlBlkMemStack		m_Mem;
#else
        int                 _epollfdr;
        cSocketEvents       _epollevents;
        cSocketEventThread  _threadevent;
#endif
    public:
        inline ec::cConnectPool* GetConnectPool() { return &m_ConPool; };
    protected:

        virtual	void dojob()
        {
            CheckNotLogin();
            int nRet;
            SOCKET	sAccept;
            struct  sockaddr_in		 addrClient;
            int		nClientAddrLen = sizeof(addrClient);

            TIMEVAL tv01 = { 1,0 };
            fd_set fdr;
            FD_ZERO(&fdr);
            FD_SET(m_sListen, &fdr);
#ifdef _WIN32
            nRet = ::select(0, &fdr, NULL, NULL, &tv01);
#else
            nRet = ::select(m_sListen + 1, &fdr, NULL, NULL, &tv01);
#endif
            if (!nRet || !FD_ISSET(m_sListen, &fdr))
                return;
#ifdef _WIN32
            if ((sAccept = ::accept(m_sListen, (struct sockaddr*)(&addrClient), &nClientAddrLen)) == INVALID_SOCKET)
                return;
#else
            if ((sAccept = ::accept(m_sListen, (struct sockaddr*)(&addrClient), (socklen_t*)&nClientAddrLen)) == INVALID_SOCKET)
                return;
            if (SetNoBlock(sAccept) < 0)
                return;
#endif
			if (m_ConPool.IsFull())
			{
				closesocket(sAccept);
				return;
			}
            DoConnected(sAccept, addrClient.sin_addr);
        };
    protected:
        void DoConnected(SOCKET sAccept, struct  in_addr	ipinaddr)
        {
            unsigned int ucid;
            char        sip[32] = { 0 };

            str_ncpy(sip, inet_ntoa(ipinaddr), sizeof(sip));
            sip[sizeof(sip) - 1] = 0;

            ucid = m_ConPool.AddItem(sAccept);
            if (!ucid)
            {
#ifdef _WIN32
                shutdown(sAccept, SD_BOTH);
#else
                shutdown(sAccept, SHUT_WR);
#endif
                closesocket(sAccept);
                return;
            }
            SetSocketKeepAlive(sAccept, _bkeepalivefast);
            if (!_busebnagle)
                SetTcpNoDelay(sAccept);

            OnConnected(ucid, sip);
            PostRead(sAccept, ucid);
        }
    protected:
        virtual void    OnConnected(unsigned int ucid, const char* sip) = 0;
        virtual void	OnRemovedUCID(unsigned int ucid) = 0;
        virtual ec::cTcpSvrWorkThread* CreateWorkThread() = 0;
        virtual void    CheckNotLogin() = 0; //chech not login 
    protected:
        void	StopAndDeleteThreads()
        {
            unsigned int i;
            for (i = 0; i < m_uThreads; i++)
            {
                m_pThread[i]->Stop();
                delete m_pThread[i];
                m_pThread[i] = NULL;
            }
            m_uThreads = 0;
        }
#ifdef _WIN32
        void    PostRead(SOCKET s, unsigned int ucid)
        {
            unsigned long	dwFlags, dwRecv;
            if (m_ConPool.ucid_CreateIoCompletionPort(ucid, m_hcpioPort, ucid, 0) == NULL)
            {
                OnRemovedUCID(ucid);
                m_ConPool.DelAndCloseSocket(ucid);
                return;
            }

            t_cpioblk* pio = cSmlBlkMemStack::newioblk(SIZE_READMENBLK);
            if (!pio)
            {
                OnRemovedUCID(ucid);
                m_ConPool.DelAndCloseSocket(ucid);
                return;
            }

            memset(&pio->Overlapped, 0, sizeof(OVERLAPPED));
            pio->WSABuf.len = SIZE_READMENBLK;
            pio->uOperate = TCPIO_OPT_READ;
            dwFlags = 0;

            bool bnoucid = false;
            int nErrCode = 0;

            if (SOCKET_ERROR == m_ConPool.ucid_WSARecv(ucid, &(pio->WSABuf), 1, &dwRecv, &dwFlags, &(pio->Overlapped), NULL))
            {
                OnRemovedUCID(ucid);
                m_ConPool.DelAndCloseSocket(ucid);
                cSmlBlkMemStack::delioblk(pio);
            }
        }
#else
        void    PostRead(SOCKET nfd, unsigned int ucid)
        {
            struct epoll_event event;

            event.data.u64 = ucid;
            event.data.u64 = (event.data.u64 << 32) + nfd;
            event.events = EPOLLIN | EPOLLONESHOT;
            if (-1 == epoll_ctl(_epollfdr, EPOLL_CTL_ADD, nfd, &event))
            {
                OnRemovedUCID(ucid);
                m_ConPool.DelAndCloseSocket(ucid);
                return;
            }
            return;
        }
#endif
    public:
        bool PostSelfEvent(unsigned int uevt)
        {
#ifdef _WIN32
            if (m_hcpioPort && PostQueuedCompletionStatus(m_hcpioPort, uevt, 0, NULL))
                return true;
            return false;
#else
            struct epoll_event e;
            e.data.u64 = 0;
            e.data.fd = -1;
            e.events = uevt;
            _epollevents.Put(e);
            return true;
#endif
        };

        void DisconnectUser(unsigned int ucid)
        {
#ifndef _WIN32

            T_CONITEM con;
            struct epoll_event  evtdel;
            if (!m_ConPool.GetVal(ucid, &con))
                return;
            memset(&evtdel, 0, sizeof(evtdel));
            epoll_ctl(_epollfdr, EPOLL_CTL_DEL, con.Socket, &evtdel);
#endif
            OnRemovedUCID(ucid);
            m_ConPool.DelAndCloseSocket(ucid);
        }

#ifndef _WIN32
        static int  SetNoBlock(int sfd)
        {
            int flags, s;

            flags = fcntl(sfd, F_GETFL, 0);
            if (flags == -1)
                return -1;

            flags |= O_NONBLOCK;
            s = fcntl(sfd, F_SETFL, flags);
            if (s == -1)
                return -1;
            return 0;
        }
#endif
        bool	Start(unsigned short wport, unsigned int uThreads, unsigned int uMaxConnect, bool bkeepalivefast = false, bool busenagle = true)
        {
            if (!wport)
                return false;

            if (m_sListen != INVALID_SOCKET)
                return true;

            _bkeepalivefast = bkeepalivefast;
            _busebnagle = busenagle;

#ifdef _WIN32
            SOCKADDR_IN		InternetAddr;
#else
            struct sockaddr_in	InternetAddr;
#endif
            m_uThreads = 0;
            m_wport = wport;

#ifdef _WIN32
            if ((m_sListen = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED)) == INVALID_SOCKET)
                return false;
#else
            if ((m_sListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
            {
                fprintf(stderr, "CEpollTcpSvr @port %u bind error!\n", m_wport);
                return false;
            }
#endif

            InternetAddr.sin_family = AF_INET;
            InternetAddr.sin_addr.s_addr = htonl(INADDR_ANY);
            InternetAddr.sin_port = htons(m_wport);

            if (bind(m_sListen, (const sockaddr *)&InternetAddr, sizeof(InternetAddr)) == SOCKET_ERROR)
            {
#ifdef _WIN32
                shutdown(m_sListen, SD_BOTH);
                closesocket(m_sListen);
#else
                fprintf(stderr, "ERR:SVR_PORT[%d] CEpollTcpSvr::Start\t bind failed with error %d\n", m_wport, errno);
                shutdown(m_sListen, SHUT_WR);
                close(m_sListen);
#endif
                m_sListen = INVALID_SOCKET;
                return false;
            }
            if (listen(m_sListen, SOMAXCONN) == SOCKET_ERROR)
            {
#ifdef _WIN32
                shutdown(m_sListen, SD_BOTH);
                closesocket(m_sListen);
#else
                fprintf(stderr, "ERR:SVR_PORT[%d] CEpollTcpSvr::Start\t listen failed with error %d\n", m_wport, errno);
                shutdown(m_sListen, SHUT_WR);
                close(m_sListen);
#endif
                m_sListen = INVALID_SOCKET;
                return false;
            }


#ifdef _WIN32
            m_Mem.Init(uMaxConnect);
            m_hcpioPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
            if (m_hcpioPort == NULL) {
                closesocket(m_sListen);
                m_sListen = INVALID_SOCKET;
                return false;
            }
#else
            _epollfdr = epoll_create(128);//Since Linux 2.6.8, the size argument is ignored, but must be  greater  than  zero;
            if (_epollfdr == SOCKET_ERROR)
            {
                shutdown(m_sListen, SHUT_WR);
                close(m_sListen);
                m_sListen = INVALID_SOCKET;
                return false;
            }
#endif
            m_ConPool.Init(uMaxConnect);

            unsigned int i, pos = 0;
            cTcpSvrWorkThread*	pt;
            m_uThreads = uThreads; // start work thread
            if (m_uThreads > MAX_TCPWORK_THREAD)
                m_uThreads = MAX_TCPWORK_THREAD;

            for (i = 0; i < m_uThreads; i++) {
                pt = CreateWorkThread();
                if (pt) {
#ifdef _WIN32
                    pt->Start(m_hcpioPort, (int)pos, m_wport, &m_ConPool, &m_Mem);
#else
                    pt->Start(_epollfdr, (int)pos, m_wport, &m_ConPool, &_epollevents);
#endif
                    m_pThread[pos] = pt;
                    pos++;
                }
            }
            m_uThreads = pos;
#ifndef _WIN32
            _threadevent.Start(_epollfdr, &m_ConPool, &_epollevents);
#endif
            StartThread(NULL);//start accpet thread
            return true;
        }

        void Stop()
        {
            if (m_sListen == INVALID_SOCKET)
                return;
            StopThread();//stop accpet thread
#ifdef _WIN32
            shutdown(m_sListen, SD_BOTH);
            closesocket(m_sListen);
            m_sListen = INVALID_SOCKET;

            tArray<unsigned int> ids(16384);
            m_ConPool.CloseAllSocket(&ids);

            unsigned int i, n = ids.GetSize();
            unsigned int *pids = ids.GetBuf();

            Sleep(500);
            for (i = 0; i < m_uThreads; i++)
                PostSelfEvent(TCPIO_MSG_EXIT);

            bool bend = false;
            int ntime = 100; //10 seconds
            while (!bend && ntime > 0)
            {
                bend = true;
                for (i = 0; i < m_uThreads; i++)
                {
                    if (m_pThread[i]->IsRun())
                        bend = false;
                }
                Sleep(100);
                ntime--;
            }
            StopAndDeleteThreads();
            CloseHandle(m_hcpioPort);
            m_hcpioPort = NULL;

            for (i = 0; i < n; i++)
                OnRemovedUCID(pids[i]);
#else
            _threadevent.Stop();//stop epoll event

            StopAndDeleteThreads();//stop work threads

            shutdown(m_sListen, SHUT_WR);
            close(m_sListen);
            m_sListen = INVALID_SOCKET;

            if (_epollfdr != INVALID_SOCKET)
            {
                close(_epollfdr);
                _epollfdr = INVALID_SOCKET;
            }

            //close all socket int con pool
            tArray<unsigned int> ids(16384);
            m_ConPool.CloseAllSocket(&ids);

            int i, n = ids.GetNum();
            unsigned int *pids = ids.GetBuf();
            for (i = 0; i < n; i++)
                OnRemovedUCID(pids[i]);
#endif
        }
		/*!
		\return return send bytes,
		0:memery error;
		-1: no ucid or IO error ,call OnRemovedUCID
		*/
		int	SendToUcid(unsigned int ucid, const void* pbuf, unsigned int usize, bool bAddCount = false, unsigned int uSendOpt = TCPIO_OPT_PUT)
		{
			if (!pbuf || !usize)
				return 0;

#ifdef _WIN32
			DWORD	dwSend = 0;

			t_cpioblk* pol;
			pol = m_Mem.Pop(usize);

			if (!pol)
				return 0;

			memset(&pol->Overlapped, 0, sizeof(OVERLAPPED));
			pol->WSABuf.len = usize;
			memcpy(pol->WSABuf.buf, pbuf, usize);
			pol->uOperate = uSendOpt;

			if (SOCKET_ERROR == m_ConPool.ucid_WSASend(ucid, &(pol->WSABuf), 1, &dwSend, 0, &(pol->Overlapped), NULL, bAddCount))
			{
				OnRemovedUCID(ucid);
				m_ConPool.DelAndCloseSocket(ucid);			
				m_Mem.Push(pol);
				return -1;
			}
			return (int)usize;
#else
			int nret = m_ConPool.ucid_Send(ucid, pbuf, usize);
			if (SOCKET_ERROR == nret)
			{
				OnRemovedUCID(ucid);
				m_ConPool.DelAndCloseSocket(ucid);				
				return -1;
			}
			m_ConPool.OnSend(ucid, usize, bAddCount);			
			return nret;
#endif
		};
    };
}// namespace ec

#endif //C_TCPSRV_H
