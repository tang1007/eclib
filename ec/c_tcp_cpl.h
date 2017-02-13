/*!
\file c_tcp_cpl.h
\brief tcp connect pool

struct ec::T_CONFLOW
struct ec::T_CONITEM
class ec::cConnectPool
class ec::cTcpConnectPoll

ec library is free C++ library.

\author	 kipway@outlook.com
*/
#ifndef C_TCP_CPL_H
#define C_TCP_CPL_H
#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif
#include "c_array.h"
#include "c_map.h"
#include "c_critical.h"
#include "c_event.h"

#define CPL_SOCKETST_IDLE    0  // idle
#define CPL_SOCKETST_SEND    1  // sending
#define CPL_SOCKETST_DEL     2  // deleteing

namespace ec
{
    struct T_CONFLOW
    {
        unsigned int srvid;
        unsigned int conid;
        unsigned int flow_r;
        unsigned int flow_s;
    };//sizeof() = 16

      /*!
      \brief connect client item
      */
    struct T_CONITEM
    {
        unsigned int	    uID;		 //connect ID,auto grown,not 0
        int		            nSendNoDone; // only for windows IOCP

        unsigned long long 	u64Send;	 //
        unsigned long long	u64Read;	 //
        long long		    llLoginTime; //time_t

        SOCKET		        Socket;		 //
        int                 sendst;      // only for linux,send status CPL_SOCKETST_IDLE:idle; CPL_SOCKETST_SEND:sending; CPL_SOCKETST_DEL:lock to delete;
        unsigned int		ubytes_s[2]; //send
        unsigned int		tick_s[2];   //

        unsigned int		ubytes_r[2]; //read
        unsigned int		tick_r[2];   //
    };

    template<>	inline bool	tMap< unsigned int, T_CONITEM>::ValueKey(unsigned int key, T_CONITEM* pcls)
    {
        return key == pcls->uID;
    }
    template<> inline void  tMap< unsigned int, T_CONITEM>::OnRemoveValue(T_CONITEM* pval) {};

    //connect pool
    class cConnectPool
    {
    public:
        cConnectPool() : m_Lock(4000), m_map(8192) {
            m_uNextID = 0;
            m_uMaxConnect = 128;
        };
        virtual ~cConnectPool() {
        };
    public:
        static unsigned int GetTicks()
        {
#ifdef _WIN32
            return ::GetTickCount();
#else
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            return (unsigned int)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
#endif
        }
    protected:
        unsigned int		m_uNextID;
        unsigned int		m_uMaxConnect;					//Max connect num

        cCritical       m_Lock;
        cEvent          _evtwait;
        tMap <unsigned int, T_CONITEM> m_map;

    protected:
        void SetBps(T_CONITEM* pi, unsigned int usize, bool bread)
        {
            unsigned int utk = GetTicks();
            unsigned int *ptk = pi->tick_s;
            unsigned int *pbps = pi->ubytes_s;
            if (bread)
            {
                ptk = pi->tick_r;
                pbps = pi->ubytes_r;
            }
            if (utk - ptk[1] > 1000)
            {
                ptk[0] = ptk[1];
                pbps[0] = pbps[1];
                ptk[1] = utk;
                pbps[1] = usize;
            }
            else
                pbps[1] += usize;
        }

        unsigned int GetCurBps(T_CONITEM* pi, bool bread)
        {
            unsigned int utk = GetTicks();
            unsigned int *ptk = pi->tick_s;
            unsigned int *pbps = pi->ubytes_s;
            if (bread)
            {
                ptk = pi->tick_r;
                pbps = pi->ubytes_r;
            }
            if ((utk - ptk[0]) < 2000)
                return pbps[0];
            return 0;
        }

        unsigned int AllocUcid()
        {
            m_uNextID++;
            while (!m_uNextID || m_map.Lookup(m_uNextID)) {
                m_uNextID++;
            }
            return m_uNextID;// not 0
        }
    public:
        void	Init(unsigned int uMaxConnect)
        {
            m_uMaxConnect = uMaxConnect;
            if (m_uMaxConnect < 2)
                m_uMaxConnect = 2;
        }

        bool GetReadAndSendBytes(unsigned int ucid, unsigned long long &llread, unsigned long long& llwrite)
        {
            llread = 0;
            llwrite = 0;
            cSafeLock	lock(&m_Lock);
            T_CONITEM* pi = m_map.Lookup(ucid);
            if (pi) {
                llread = pi->u64Read;
                llwrite = pi->u64Send;
                return true;
            }
            return false;
        }
        int GetConFlow(int &npos, int &nlist, T_CONFLOW item[], int nbufsize)
        {
            cSafeLock	lock(&m_Lock);

            if (npos == -1)
            {
                npos = 0;
                nlist = 0;
            }
            T_CONITEM* pi;
            int n = 0;
            while (n < nbufsize && m_map.GetNext(npos, nlist, pi))
            {
                if (pi)
                {
                    item[n].srvid = 0;
                    item[n].conid = pi->uID;
                    item[n].flow_r = GetCurBps(pi, true);
                    item[n].flow_s = GetCurBps(pi, false);
                    n++;
                }
            }
            return n;
        }

        bool	IsFull()
        {
            cSafeLock	lock(&m_Lock);
            return (m_map.GetCount() >= (int)m_uMaxConnect);
        }

        unsigned int Count()
        {
            cSafeLock	lock(&m_Lock);
            return m_map.GetCount();
        }

        unsigned int AddItem(SOCKET s)
        {
            cSafeLock	lock(&m_Lock);
            T_CONITEM it;

            memset(&it, 0, sizeof(it));
            it.uID = AllocUcid();
            it.llLoginTime = ::time(NULL);
            it.Socket = s;

            if (!m_map.SetAt(it.uID, it))
                return 0;
            return it.uID;
        }

        bool	DelItem(unsigned int uID, T_CONITEM* pitem = NULL)
        {
            cSafeLock	lock(&m_Lock);
            bool bDel = false;
            T_CONITEM* pi = m_map.Lookup(uID);
            if (pi)
            {
                if (pitem)
                    memcpy(pitem, pi, sizeof(T_CONITEM));
                bDel = true;
            }
            m_map.RemoveKey(uID);
            return  bDel;
        }

        bool DelAndCloseSocket(unsigned int uID)
        {
            cSafeLock	lock(&m_Lock);

            bool bDel = false;
            T_CONITEM* pi = m_map.Lookup(uID);
            if (pi)
            {
#ifdef _WIN32
                shutdown(pi->Socket, SD_BOTH);
#else
                shutdown(pi->Socket, SHUT_WR);
#endif
                closesocket(pi->Socket); // man 7 epoll ,closing a file descriptor cause it to be removed from all epoll sets automatically
                bDel = true;
            }
            m_map.RemoveKey(uID);
            return  bDel;
        }

        bool OnRead(unsigned int uID, unsigned int usize)
        {
            cSafeLock	lock(&m_Lock);
            T_CONITEM* pi = m_map.Lookup(uID);
            if (pi) {
                pi->u64Read += usize;
                SetBps(pi, usize, true);
                return true;
            }
            return false;
        }

        bool OnSend(unsigned int uID, unsigned int usize, bool bDecCount = false)
        {
            cSafeLock	lock(&m_Lock);
            T_CONITEM* pi = m_map.Lookup(uID);
            if (pi) {
                pi->u64Send += usize;
                if (bDecCount)
                    pi->nSendNoDone--;
                SetBps(pi, usize, false);
                return true;
            }
            return false;
        }

        int	CloseAllSocket(tArray<unsigned int>* pa)
        {
            cSafeLock	lock(&m_Lock);

            int npos = 0, nlist = 0;

            T_CONITEM* pi;

            while (m_map.GetNext(npos, nlist, pi)) {
                if (pa)
                    pa->Add(pi->uID);

#ifdef _WIN32
                shutdown(pi->Socket, SD_BOTH);
#else
                shutdown(pi->Socket, SHUT_WR);
#endif
                closesocket(pi->Socket);
            }
            m_map.RemoveAll();
            if (pa)
                return pa->GetNum();
            return 0;
        }

        int  GetSendNoDone(unsigned int uID)
        {
            cSafeLock	lock(&m_Lock);
            T_CONITEM* pi = m_map.Lookup(uID);
            if (pi)
                return pi->nSendNoDone;
            return 0;
        };

        bool SetSendNoDone(unsigned int ucid, int n)
        {
            cSafeLock	lock(&m_Lock);
            T_CONITEM* pi = m_map.Lookup(ucid);
            if (pi) {
                pi->nSendNoDone = n;
                return true;
            }
            return false;
        }

        bool	GetVal(unsigned int uID, T_CONITEM* pval)
        {
            cSafeLock	lock(&m_Lock);
            T_CONITEM* pi = m_map.Lookup(uID);
            if (pi) {
                *pval = *pi;
                return true;
            }
            return false;
        };

        unsigned int GetAll(tArray<T_CONITEM> *pa) // return records
        {
            cSafeLock	lock(&m_Lock);

            int npos = 0, nlist = 0;
            T_CONITEM* pi, t;

            pa->ClearData();
            while (m_map.GetNext(npos, nlist, pi)) {
                t = *pi;
                pa->Add(&t, 1);
            }
            return pa->GetSize();
        }
#ifndef _WIN32
        int LockSocket(unsigned int ucid, long lockst, SOCKET &s)// return 0: ok; -1 no ucid; 1:socekt is busy
        {
            cSafeLock	lock(&m_Lock);
            T_CONITEM* pi = m_map.Lookup(ucid);
            if (!pi)
                return -1;
            if (pi->sendst != CPL_SOCKETST_IDLE)
                return 1;
            pi->sendst = lockst;
            s = pi->Socket;
            return 0;
        }

        void UnlockSocket(unsigned int ucid)
        {
            cSafeLock	lock(&m_Lock);
            T_CONITEM* pi = m_map.Lookup(ucid);
            if (pi)
                pi->sendst = CPL_SOCKETST_IDLE;
        }
#endif
    };

    /*!
    \brief connect poll for windows CPIO
    */
    class cTcpConnectPoll : public cConnectPool
    {
    public:
        cTcpConnectPoll() {};
        virtual ~cTcpConnectPoll() {};
#ifdef _WIN32
        HANDLE  ucid_CreateIoCompletionPort(
            unsigned int uID,
            HANDLE ExistingCompletionPort,
            ULONG_PTR CompletionKey,
            DWORD NumberOfConcurrentThreads
        )
        {
            cSafeLock	lock(&m_Lock);
            T_CONITEM* pi = m_map.Lookup(uID);
            if (!pi)
                return NULL;
            return CreateIoCompletionPort((HANDLE)pi->Socket, ExistingCompletionPort, CompletionKey, NumberOfConcurrentThreads);
        }

        int	ucid_WSARecv(
            unsigned int uID,
            LPWSABUF lpBuffers,
            DWORD dwBufferCount,
            LPDWORD lpNumberOfBytesRecvd,
            LPDWORD lpFlags,
            LPWSAOVERLAPPED lpOverlapped,
            LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
        )// return 0 ok,-1error
        {
            cSafeLock	lock(&m_Lock);

            T_CONITEM* pi = m_map.Lookup(uID);
            if (!pi)
                return SOCKET_ERROR;
            int nret = WSARecv(pi->Socket, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
            if (SOCKET_ERROR == nret && ERROR_IO_PENDING == WSAGetLastError())
                return 0;
            return nret;
        }

        int ucid_WSASend(
            unsigned int uID,
            LPWSABUF lpBuffers,
            DWORD dwBufferCount,
            LPDWORD lpNumberOfBytesSent,
            DWORD dwFlags,
            LPWSAOVERLAPPED lpOverlapped,
            LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
            bool bSendCount = false
        )// return WSASend returns
        {
            cSafeLock	lock(&m_Lock);
            T_CONITEM* pi = m_map.Lookup(uID);
            if (!pi)
                return SOCKET_ERROR;
            if (bSendCount)
                pi->nSendNoDone++;
            int nret = WSASend(pi->Socket, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
            if (SOCKET_ERROR == nret && ERROR_IO_PENDING == WSAGetLastError())
                return 0;
            return nret;
        }
#else

        //return send bytes size or -1 for error
        int Socket_Send(SOCKET s, void* pbuf, unsigned int nsize)
        {
            char *ps = (char*)pbuf;
            unsigned int  nsend = 0;
            int nret;
            while (nsend < nsize)
            {
                nret = (int)send(s, ps + nsend, nsize - nsend, MSG_DONTWAIT | MSG_NOSIGNAL);
                if (SOCKET_ERROR == nret)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        TIMEVAL tv01 = { 0,1000 * 100 };
                        fd_set fdw;
                        FD_ZERO(&fdw);
                        FD_SET(s, &fdw);
                        if (-1 == ::select(s + 1, NULL, &fdw, NULL, &tv01))
                            return SOCKET_ERROR;
                        continue;
                    }
                    else
                        return SOCKET_ERROR;
                }
                else
                    nsend += nret;
            }
            return nsend;
        };

        //send as block ,return send bytes size or -1 for error
        int ucid_Send(unsigned int uID, void* pbuf, unsigned int nsize)
        {
            SOCKET s = INVALID_SOCKET;
            int rst = LockSocket(uID, CPL_SOCKETST_SEND, s);
            while (rst)
            {
                if (rst == -1)
                    return SOCKET_ERROR;
                rst = LockSocket(uID, CPL_SOCKETST_SEND, s);
            }
            int nsend = Socket_Send(s, pbuf, nsize);
            UnlockSocket(uID);
            if (SOCKET_ERROR == nsend)
                return SOCKET_ERROR;

            m_Lock.Lock();
            T_CONITEM* pi = m_map.Lookup(uID);
            if (pi)
            {
                pi->u64Send += nsend;
                SetBps(pi, nsend, false);
            }
            m_Lock.Unlock();
            UnlockSocket(uID);
            return nsend;
        };
#endif
    };
} // ec
#endif // C_TCP_CPL_H
