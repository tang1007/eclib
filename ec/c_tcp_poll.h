
/*!
\file c_tcp_poll.h

ec library is free C++ library.

\author	 kipway@outlook.com
*/
#pragma once
#ifndef _TCP_POLL_H
#define _TCP_POLL_H

#ifndef _WIN32
#    include <unistd.h>
#    include <pthread.h>
#    include <fcntl.h>

#    include <sys/time.h>
#    include <sys/types.h>
#    include <sys/socket.h>
#    include <sys/ioctl.h>

#    include <errno.h>
#    include <sys/epoll.h>
#    include <netdb.h>
#else
#    include <ws2tcpip.h>
#endif

#include "ec/c_tcp_tl.h"
#include "ec/c_map.h"
#include "ec/c_critical.h"
#include "ec/c_log.h"
#include "ec/c_str.h"
#include "ec/c_thread.h"
#include "ec/c_trace.h"
#include "ec/c_file.h"

namespace ec {
    namespace tcp_poll {
        struct t_item
        {
            unsigned int ucid;//ID key
            unsigned int st;  //status used for extend class
            unsigned int toip;//useed for extend class
            unsigned int toid;//useed for extend class
            SOCKET   s;
        };
    };
    template<>
    inline bool ec::tMap<unsigned int, tcp_poll::t_item>::ValueKey(unsigned int key, tcp_poll::t_item* pcls)
    {
        return key == pcls->ucid;
    }
    template<>
    void    ec::tMap<unsigned int, tcp_poll::t_item>::OnRemoveValue(tcp_poll::t_item* pcls) {}
};
namespace ec
{  
    namespace tcp_poll
    {
#define SIZE_READ_BLOCK  32768

#ifdef _WIN32
        struct t_wincpioblk
        {
            OVERLAPPED	 Overlapped;
            WSABUF		 WSABuf;
        };
#endif
        /*!
        \brife connect sockets
        */
        class CConPool
        {
        public:
            CConPool(ec::cLog* plog) :_map(8192)
            {
                m_uNextID = 0;
                _plog = plog;
                memset(_sidfile, 0, sizeof(_sidfile));
                
            };
            ~CConPool()
            {
                _fileid.Unlock(0, 0);
            }
            ec::cLog * _plog;
            ec::cCritical _cs;
            static unsigned int str2u(const char* s)
            {
                int n = 0;
                unsigned int u = 0, ut;
                while (*s && n < 8)
                {
                    if (*s >= '0' && *s <= '9')
                        ut = *s - '0';
                    else if (*s >= 'a' && *s <= 'f')
                        ut = 0x0A + *s - 'a';
                    else if (*s >= 'A' && *s <= 'F')
                        ut = 0x0A + *s - 'A';
                    else
                        return u;
                    u = (u << 4) | ut;
                    n++;
                    s++;
                }
                return u;
            }
        public:
            bool Loaducid(const char* sfile)
            {
                if (!_fileid.Open(sfile, ec::cFile::OF_RDWR | ec::cFile::OF_CREAT, ec::cFile::OF_SHARE_READ))
                {
                    if (!_fileid.Open(sfile, ec::cFile::OF_RDWR, ec::cFile::OF_SHARE_READ))
                        return false;
                }
                if (!_fileid.Lock(0, 0, true))
                    return false;
                char sbuf[64] = { 0 };
                int n = _fileid.ReadFrom(0, sbuf, sizeof(sbuf));
                if (n > 0)
                    m_uNextID = str2u(sbuf);                    
                return true;
            }
            unsigned int GetNextUcid()
            {
                m_uNextID++;
                while (!m_uNextID || _map.Lookup(m_uNextID))
                    m_uNextID++;
                char sbuf[64] = { 0 };
                sprintf(sbuf, "%X", m_uNextID);
                _fileid.WriteTo(0, sbuf, strlen(sbuf));
                return m_uNextID;
            }
        protected:
            unsigned int m_uNextID;
            ec::tMap<unsigned int, t_item> _map;
            ec::cFile _fileid;
            char _sidfile[512];
            bool _closesockets(SOCKET s)
            {
                if (s != INVALID_SOCKET)
                {
#ifdef _WIN32
                    shutdown(s, SD_BOTH);
#else
                    shutdown(s, SHUT_WR);
#endif
                    closesocket(s); // man 7 epoll ,closing a file descriptor cause it to be removed from all epoll sets automatically
                    return true;
                }
                return false;
            }
        public:
#ifdef _WIN32
            static void del_ioblk(t_wincpioblk* p)
            {
                if (!p)
                    return;
                if (p->WSABuf.buf)
                    free(p->WSABuf.buf);
                delete p;
            }

            static t_wincpioblk* new_ioblk()
            {
                t_wincpioblk* p = new t_wincpioblk;
                if (p)
                {
                    memset(&p->Overlapped, 0, sizeof(OVERLAPPED));
                    p->WSABuf.buf = (char*)malloc(SIZE_READ_BLOCK);
                    if (p->WSABuf.buf)
                    {
                        memset(p->WSABuf.buf, 0, SIZE_READ_BLOCK);
                        p->WSABuf.len = SIZE_READ_BLOCK;
                    }
                    else
                    {
                        delete p;
                        p = NULL;
                    }
                }
                return p;
            }
#endif
            bool Del(unsigned int ucid)
            {
                ec::cSafeLock lck(&_cs);
                t_item *p;
                p = _map.Lookup(ucid);
                if (p)
                {
                    if (_closesockets(p->s) && _plog)
                        _plog->AddLog("MSG:ucid %u(socket %u) closed", ucid, p->s);
                }
                return _map.RemoveKey(ucid);
            }

            unsigned Add(SOCKET s, unsigned int ip = 0,unsigned int id = 0)
            {
                ec::cSafeLock lck(&_cs);
                unsigned int ucid = GetNextUcid();                

                t_item u;
                memset(&u, 0, sizeof(u));
                u.ucid = ucid;
                u.s = s;
                u.toip = ip;
                u.toid = id;
                if (_map.SetAt(ucid, u, false))
                    return ucid;
                return 0;
            }
            bool Get(t_item* pinout)
            {
                ec::cSafeLock lck(&_cs);
                t_item *p;
                p = _map.Lookup(pinout->ucid);
                if (p) {
                    *pinout = *p;
                    return true;
                }
                return false;
            }
            bool GetNotLock(t_item* pinout)
            {
                t_item *p;
                p = _map.Lookup(pinout->ucid);
                if (p) {
                    *pinout = *p;
                    return true;
                }
                return false;
            }

            void SetSt(unsigned int ucid, unsigned int st,unsigned int ip = 0, unsigned int id = 0)
            {
                ec::cSafeLock lck(&_cs);
                t_item *p;
                p = _map.Lookup(ucid);
                if (p)
                {
                    p->st = st;
                    p->toip = ip;
                    p->toid = id;
                }
            }

            bool Send(unsigned int ucid, const void* pd, int nsize)
            {
                ec::cSafeLock lck(&_cs);
                t_item *p;
                p = _map.Lookup(ucid);
                if (!p)
                    return false;
                int ns = -1;

                if (p->s != INVALID_SOCKET)
                    ns = ec::tcp_send(p->s, pd, nsize);
                return ns == nsize;
            }

            void CloseAll() //全部关闭
            {
                ec::cSafeLock lck(&_cs);
                int npos = 0, nlist = 0;
                t_item *p;

                while (_map.GetNext(npos, nlist, p))
                {
                    if (_closesockets(p->s) && _plog)
                        _plog->AddLog("MSG:ucid %u(socket %u) closed", p->ucid,p->s);
                }
                _map.RemoveAll();
            }
        };
        /*!
        \brief
        */
        class CThreadPoll : public ec::cThread
        {
        public:
            CThreadPoll()
            {
                _plog = 0;
                _ppool = 0;
#ifndef _WIN32
                memset(_eplevtbuf, 0, sizeof(_eplevtbuf));
                memset(&_eplevt, 0, sizeof(_eplevt));
                memset(&_evtdel, 0, sizeof(_evtdel));
#endif
            }
            virtual ~CThreadPoll()
            {
            }
            ec::cLog*  _plog;
            CConPool*  _ppool;
        protected:
            virtual bool CheckJob() { return true; };
            virtual void OnDelUcid(unsigned int ucid) {}; //before delete ucid

        public:
#ifdef _WIN32
            bool   AddToPoll(SOCKET s, unsigned int ucid)
            {
                unsigned long	dwFlags, dwRecv;
                if (!CreateIoCompletionPort((HANDLE)s, _hio, ucid, 0))
                    return false;
                t_wincpioblk* pio = _ppool->new_ioblk();
                if (!pio)
                    return false;
                dwFlags = 0;
                int nret = WSARecv(s, &(pio->WSABuf), 1, &dwRecv, &dwFlags, &(pio->Overlapped), NULL);
                if (SOCKET_ERROR == nret)
                {
                    if (ERROR_IO_PENDING == WSAGetLastError())
                        return true;
                    _ppool->del_ioblk(pio);
                    return false;
                }

                return true;
            }
#else
            bool    AddToPoll(SOCKET nfd, unsigned int ucid)
            {
                struct epoll_event event;
                event.data.u64 = ucid;
                event.data.u64 = (event.data.u64 << 32) + nfd;
                event.events = EPOLLIN | EPOLLONESHOT;
                return -1 != epoll_ctl(_hio, EPOLL_CTL_ADD, nfd, &event);
            }
#endif

        protected:
#ifdef _WIN32
            HANDLE		_hio;
#else
            int         _hio;
#   define MAXEPOLLEVENTSIZE  16
            struct epoll_event  _eplevtbuf[MAXEPOLLEVENTSIZE];
            struct epoll_event  _eplevt, _evtdel;
            char    _buf[SIZE_READ_BLOCK];
#endif
        protected:
#ifdef _WIN32
            virtual	void dojob()
            {
                if (!CheckJob())
                    return;
                int				nErrCode = 0;
                unsigned long	BytesTransferred, dwRecv, dwFlags = 0;
                unsigned int	ucid;
                LPOVERLAPPED	pOverlapped;
                ULONG_PTR		uKey;
                t_wincpioblk*	piobuf;
                if (!GetQueuedCompletionStatus(_hio, &BytesTransferred, &uKey, (LPOVERLAPPED *)&pOverlapped, 100))//io error
                {
                    if (!pOverlapped)
                        return; // timeout,no completion packet

                    nErrCode = GetLastError();

                    // BytesTransferred, scoket closed or client error
                    ucid = (unsigned int)uKey;
                    piobuf = (t_wincpioblk*)pOverlapped;
                    OnDelUcid(ucid);
                    _ppool->Del(ucid);
                    _ppool->del_ioblk(piobuf);
                    return;
                }

                if (uKey == 0 && pOverlapped == NULL) // self message
                    return;

                //IO Message
                ucid = (unsigned int)uKey;
                piobuf = (t_wincpioblk*)pOverlapped;

                if (BytesTransferred == 0) // client closed
                {
                    OnDelUcid(ucid);
                    if (_ppool->Del(ucid) && _plog)
                        _plog->AddLog("MSG:ucid %u closed", ucid);
                    _ppool->del_ioblk(piobuf);
                    return;
                }
                if (!OnRead(ucid, piobuf->WSABuf.buf, (int)BytesTransferred))
                {
                    OnDelUcid(ucid);
                    _ppool->Del(ucid);
                    _ppool->del_ioblk(piobuf);
                    return;
                }
                bool bok = false;
                while (1)
                {
                    ec::cSafeLock lck(&_ppool->_cs);
                    t_item si;
                    si.ucid = ucid;
                    if (!_ppool->GetNotLock(&si))
                        break;
                    memset(&piobuf->Overlapped, 0, sizeof(OVERLAPPED));
                    piobuf->WSABuf.len = SIZE_READ_BLOCK;
                    dwFlags = 0;

                    if (si.s == INVALID_SOCKET)
                        break;
                    int nret = WSARecv(si.s, &(piobuf->WSABuf), 1, &dwRecv, &dwFlags, &(piobuf->Overlapped), NULL);
                    if (!nret || (SOCKET_ERROR == nret && ERROR_IO_PENDING == WSAGetLastError()))
                        bok = true;
                    break;
                }
                if (!bok)
                {
                    OnDelUcid(ucid);
                    if (_plog)
                        _plog->AddLog("ERR: ucid %u,WSARecv failed", ucid);
                    _ppool->Del(ucid);
                    _ppool->del_ioblk(piobuf);
                }
            }
#else
            void DoOnePollEvt()
            {
                int nfd, nerr;
                unsigned int ucid;
                if (_eplevt.data.fd == -1) // selfmsg
                    return;
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
                                _eplevt.events = EPOLLIN | EPOLLONESHOT;
                                epoll_ctl(_hio, EPOLL_CTL_MOD, nfd, &_eplevt); // reset
                            }
                            else
                            {
                                epoll_ctl(_hio, EPOLL_CTL_DEL, nfd, &_evtdel);
                                OnDelUcid(ucid);
                                _ppool->Del(ucid);
                                return;
                            }
                            return;
                        }
                        else if (nbytes == 0) // close
                        {
                            epoll_ctl(_hio, EPOLL_CTL_DEL, nfd, &_evtdel);
                            OnDelUcid(ucid);
                            _ppool->Del(ucid);
                            return;
                        }
                        else
                        {
                            if (!OnRead(ucid, _buf, nbytes))
                            {
                                epoll_ctl(_hio, EPOLL_CTL_DEL, nfd, &_evtdel);
                                OnDelUcid(ucid);
                                _ppool->Del(ucid);
                                return;
                            }
                        }
                    };
                }
                else if (_eplevt.events & EPOLLERR || _eplevt.events & EPOLLHUP) // error
                {
                    epoll_ctl(_hio, EPOLL_CTL_DEL, nfd, &_evtdel);
                    OnDelUcid(ucid);
                    _ppool->Del(ucid);
                }
            }
            virtual	void dojob()
            {
                if (!CheckJob())
                    return;
                int i, n;
                n = epoll_wait(_hio, _eplevtbuf, MAXEPOLLEVENTSIZE, 100);
                if (n <= 0)
                    return;
                for (i = 0; i < n; i++)
                {
                    _eplevt = _eplevtbuf[i];
                    DoOnePollEvt();
                }
            }
#endif
            virtual bool OnRead(unsigned int ucid, const void* pbuf, int size) = 0;// return false will close connection in CThreadPoll
        public:
            bool Start(CConPool* ppoll, ec::cLog* plog)
            {
#ifdef _WIN32
                _hio = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
                if (_hio == NULL)
                    return false;
#else
                _hio = epoll_create(128);//Since Linux 2.6.8, the size argument is ignored, but must be  greater  than  zero;
                if (_hio == -1)
                    return false;
#endif
                _ppool = ppoll;
                _plog = plog;

                StartThread(NULL);
                return true;
            }
            void Stop()
            {
                StopThread();
#ifdef _WIN32
                if (_hio)
                    CloseHandle(_hio);
                _hio = NULL;
#else
                if (_hio != -1)
                    close(_hio);
                _hio = -1;
#endif
            }     
            virtual void OnAsynConnectEvt(unsigned int ucid, SOCKET s, bool bsuccess) {}; //被异步连接处理线程调用
        };
        /*!
        \brief Accept thread
        */
        class CAcceptThread : public ec::cThread
        {
        public:
            CAcceptThread(CConPool* ppool)
            {
                _ppool = ppool;
                _bkeepalivefast = false;
                _busebnagle = true;
                _wport = 0;

                _plog = NULL;
                _slisten = INVALID_SOCKET;
                _pthread = 0;
            }
            virtual ~CAcceptThread()
            {

            }
            ec::cLog*  _plog;
            CConPool*  _ppool;
        protected:
            bool    _bkeepalivefast;
            bool    _busebnagle;
            unsigned short	_wport;

            SOCKET			_slisten;
            CThreadPoll*    _pthread;
        protected:
            virtual bool OnAddToPool(unsigned int ucid) { return true; };
            virtual	void dojob()
            {
                int nRet;
                SOCKET	sAccept;
                struct  sockaddr_in		 addrClient;
                int		nClientAddrLen = sizeof(addrClient);

                TIMEVAL tv01 = { 1,0 };
                fd_set fdr;
                FD_ZERO(&fdr);
                FD_SET(_slisten, &fdr);
#ifdef _WIN32
                nRet = ::select(0, &fdr, NULL, NULL, &tv01);
#else
                nRet = ::select(_slisten + 1, &fdr, NULL, NULL, &tv01);
#endif
                if (!nRet || !FD_ISSET(_slisten, &fdr))
                    return;
#ifdef _WIN32
                if ((sAccept = ::accept(_slisten, (struct sockaddr*)(&addrClient), &nClientAddrLen)) == INVALID_SOCKET)
                    return;
#else
                if ((sAccept = ::accept(_slisten, (struct sockaddr*)(&addrClient), (socklen_t*)&nClientAddrLen)) == INVALID_SOCKET)
                    return;
                if (SetNoBlock(sAccept) < 0)
                    return;
#endif                
                DoConnected(sAccept, addrClient.sin_addr);
            };
        protected:

            void DoConnected(SOCKET sAccept, struct  in_addr	ipinaddr)
            {
                unsigned int ucid;
                char        sip[32] = { 0 };

                ec::str_ncpy(sip, inet_ntoa(ipinaddr), sizeof(sip));
                sip[sizeof(sip) - 1] = 0;

                ec::SetSocketKeepAlive(sAccept, _bkeepalivefast);
                if (!_busebnagle)
                    ec::SetTcpNoDelay(sAccept);
#ifdef _WIN32
                ucid = _ppool->Add(sAccept, (unsigned int)ipinaddr.S_un.S_addr);
#else
                ucid = _ppool->Add(sAccept, (unsigned int)ipinaddr.s_addr);
#endif
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
                if (_plog)
                    _plog->AddLog("MSG:ucid %u(socket %u) connect in port %u from %s", ucid, sAccept,_wport, sip);

                if (!OnAddToPool(ucid) || !_pthread->AddToPoll(sAccept, ucid)) {
                    _ppool->Del(ucid);
                    return;
                }                
            }
        public:
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
            bool	Start(CThreadPoll* pthread, unsigned short wport, bool bkeepalivefast = false, bool busenagle = true)
            {
                if (!wport)
                    return false;

                if (_slisten != INVALID_SOCKET)
                    return true;

                _pthread = pthread;
                _bkeepalivefast = bkeepalivefast;
                _busebnagle = busenagle;

#ifdef _WIN32
                SOCKADDR_IN		InternetAddr;
#else
                struct sockaddr_in	InternetAddr;
#endif
                _wport = wport;

#ifdef _WIN32
                if ((_slisten = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED)) == INVALID_SOCKET)
                    return false;
#else
                if ((_slisten = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
                {
                    fprintf(stderr, "CEpollTcpSvr @port %u bind error!\n", wport);
                    return false;
                }
#endif

                InternetAddr.sin_family = AF_INET;
                InternetAddr.sin_addr.s_addr = htonl(INADDR_ANY);
                InternetAddr.sin_port = htons(_wport);

                if (bind(_slisten, (const sockaddr *)&InternetAddr, sizeof(InternetAddr)) == SOCKET_ERROR)
                {
#ifdef _WIN32
                    shutdown(_slisten, SD_BOTH);
                    closesocket(_slisten);
#else
                    fprintf(stderr, "ERR:SVR_PORT[%d] CEpollTcpSvr::Start\t bind failed with error %d\n", wport, errno);
                    shutdown(_slisten, SHUT_WR);
                    close(_slisten);
#endif
                    _slisten = INVALID_SOCKET;
                    return false;
                }
                if (listen(_slisten, SOMAXCONN) == SOCKET_ERROR)
                {
#ifdef _WIN32
                    shutdown(_slisten, SD_BOTH);
                    closesocket(_slisten);
#else
                    fprintf(stderr, "ERR:SVR_PORT[%d] CEpollTcpSvr::Start\t listen failed with error %d\n", wport, errno);
                    shutdown(_slisten, SHUT_WR);
                    close(_slisten);
#endif
                    _slisten = INVALID_SOCKET;
                    return false;
                }
                StartThread(NULL);//start accpet thread
                return true;
            }

            void Stop()
            {
                if (_slisten == INVALID_SOCKET)
                    return;
                StopThread();//stop accpet thread
#ifdef _WIN32
                shutdown(_slisten, SD_BOTH);
                closesocket(_slisten);
                _slisten = INVALID_SOCKET;
#else
                shutdown(_slisten, SHUT_WR);
                close(_slisten);
                _slisten = INVALID_SOCKET;
#endif
            }
        };
    };
};
#endif
