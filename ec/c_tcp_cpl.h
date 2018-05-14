/*!
\file c_tcp_cpl.h
\author	kipway@outlook.com
\update 2018.4.3 
add ucid_recv and ucid_epoll_ctl in linux 

class ec::cConnectPool
class ec::cTcpConnectPoll

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
#define CPL_SOCKET_GROUPS    4  //
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

	template<>	inline bool	tMap< unsigned int, unsigned int>::ValueKey(unsigned int key, unsigned int* pcls)
	{
		return key == *pcls;
	}
	template<> inline void  tMap< unsigned int, unsigned int>::OnRemoveValue(unsigned int* pval) {};

	class cConnectPool //connect pool
	{
	public:
		cConnectPool() : _csucid(4000), _mapucid(16384) {
			m_uNextID = 0;
			m_uMaxConnect = 1024;
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
		unsigned int m_uNextID;
		unsigned int m_uMaxConnect;					//Max connect num

		cEvent       _evtwait;

		cCritical    _Locks[CPL_SOCKET_GROUPS];
		tMap <unsigned int, T_CONITEM> _maps[CPL_SOCKET_GROUPS];

		cCritical  _csucid;
		tMap <unsigned int, unsigned int> _mapucid;
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
			cSafeLock	lock(&_csucid);
			m_uNextID++;
			while (m_uNextID < 100 || _mapucid.Lookup(m_uNextID)) {
				m_uNextID++;
			}
			_mapucid.SetAt(m_uNextID, m_uNextID, false);
			return m_uNextID;// not 0
		}

		inline void FreeUcid(unsigned int ucid)
		{
			_csucid.Lock();
			_mapucid.RemoveKey(ucid);
			_csucid.Unlock();
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
			cSafeLock	lck(&_Locks[ucid % CPL_SOCKET_GROUPS]);
			T_CONITEM* pi = _maps[ucid % CPL_SOCKET_GROUPS].Lookup(ucid);
			if (pi) {
				llread = pi->u64Read;
				llwrite = pi->u64Send;
				return true;
			}
			return false;
		}

		int GetConFlow(tArray<T_CONFLOW>*po)
		{
			po->ClearData();
			unsigned int i;
			int npos, nlist;
			T_CONITEM* pi;
			T_CONFLOW it;
			for (i = 0; i < CPL_SOCKET_GROUPS; i++)
			{
				cSafeLock	lock(&_Locks[i]);
				npos = 0;
				nlist = 0;
				while (_maps[i].GetNext(npos, nlist, pi))
				{
					if (pi)
					{
						it.srvid = 0;
						it.conid = pi->uID;
						it.flow_r = GetCurBps(pi, true);
						it.flow_s = GetCurBps(pi, false);
						po->Add(&it, 1);
					}
				}
			}
			return po->GetNum();
		}

		bool	IsFull()
		{
			cSafeLock	lock(&_csucid);
			return (_mapucid.GetCount() >= (int)m_uMaxConnect);
		}

		unsigned int Count()
		{
			cSafeLock	lock(&_csucid);
			return _mapucid.GetCount();
		}

		unsigned int AddItem(SOCKET s)
		{
			T_CONITEM it;
			memset(&it, 0, sizeof(it));
			it.uID = AllocUcid();
			it.llLoginTime = ::time(NULL);
			it.Socket = s;
			_Locks[it.uID % CPL_SOCKET_GROUPS].Lock();
			_maps[it.uID % CPL_SOCKET_GROUPS].SetAt(it.uID, it);
			_Locks[it.uID % CPL_SOCKET_GROUPS].Unlock();
			return it.uID;
		}

		bool DelAndCloseSocket(unsigned int uID)
		{
			bool bDel = false;
			T_CONITEM* pi = 0;
			_Locks[uID % CPL_SOCKET_GROUPS].Lock();
			pi = _maps[uID % CPL_SOCKET_GROUPS].Lookup(uID);
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
			_maps[uID % CPL_SOCKET_GROUPS].RemoveKey(uID);
			_Locks[uID % CPL_SOCKET_GROUPS].Unlock();

			FreeUcid(uID);
			return  bDel;
		}

		bool OnRead(unsigned int uID, unsigned int usize)
		{
			cSafeLock	lock(&_Locks[uID % CPL_SOCKET_GROUPS]);
			T_CONITEM* pi = _maps[uID % CPL_SOCKET_GROUPS].Lookup(uID);
			if (pi) {
				pi->u64Read += usize;
				SetBps(pi, usize, true);
				return true;
			}
			return false;
		}

		bool OnSend(unsigned int uID, unsigned int usize, bool bDecCount = false)
		{
			cSafeLock	lock(&_Locks[uID % CPL_SOCKET_GROUPS]);
			T_CONITEM* pi = _maps[uID % CPL_SOCKET_GROUPS].Lookup(uID);
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
			unsigned int i;
			int npos = 0, nlist = 0;
			T_CONITEM* pi;
			for (i = 0; i < CPL_SOCKET_GROUPS; i++)
			{
				_Locks[i].Lock();
				npos = 0;
				nlist = 0;
				while (_maps[i].GetNext(npos, nlist, pi)) {
					if (pa)
						pa->Add(pi->uID);
#ifdef _WIN32
					shutdown(pi->Socket, SD_BOTH);
#else
					shutdown(pi->Socket, SHUT_WR);
#endif
					closesocket(pi->Socket);
				}
				_maps[i].RemoveAll();
				_Locks[i].Unlock();
			}
			_csucid.Lock();
			_mapucid.RemoveAll();
			_csucid.Unlock();
			if (pa)
				return pa->GetNum();
			return 0;
		}
        void	shutdown_all()
		{
			unsigned int i;
			int npos = 0, nlist = 0;
			T_CONITEM* pi;
			for (i = 0; i < CPL_SOCKET_GROUPS; i++)
			{
				_Locks[i].Lock();
				npos = 0;
				nlist = 0;
				while (_maps[i].GetNext(npos, nlist, pi)) {
#ifdef _WIN32
					shutdown(pi->Socket, SD_BOTH);
#else
					shutdown(pi->Socket, SHUT_WR);
#endif
				}
				_Locks[i].Unlock();
			}
		}
		int  GetSendNoDone(unsigned int uID)
		{
			cSafeLock	lock(&_Locks[uID % CPL_SOCKET_GROUPS]);
			T_CONITEM* pi = _maps[uID % CPL_SOCKET_GROUPS].Lookup(uID);
			if (pi)
				return pi->nSendNoDone;
			return 0;
		};

		bool SetSendNoDone(unsigned int uID, int n)
		{
			cSafeLock	lock(&_Locks[uID % CPL_SOCKET_GROUPS]);
			T_CONITEM* pi = _maps[uID % CPL_SOCKET_GROUPS].Lookup(uID);
			if (pi) {
				pi->nSendNoDone = n;
				return true;
			}
			return false;
		}

		bool	GetVal(unsigned int uID, T_CONITEM* pval)
		{
			cSafeLock	lock(&_Locks[uID % CPL_SOCKET_GROUPS]);
			T_CONITEM* pi = _maps[uID % CPL_SOCKET_GROUPS].Lookup(uID);
			if (pi) {
				*pval = *pi;
				return true;
			}
			return false;
		};

		unsigned int GetAll(tArray<T_CONITEM> *pa) // return records
		{
			unsigned int i;
			int npos, nlist;
			T_CONITEM* pi, t;
			pa->ClearData();
			for (i = 0; i < CPL_SOCKET_GROUPS; i++)
			{
				_Locks[i].Lock();
				npos = 0;
				nlist = 0;
				while (_maps[i].GetNext(npos, nlist, pi)) {
					t = *pi;
					pa->Add(&t, 1);
				}
				_Locks[i].Unlock();
			}
			return pa->GetSize();
		}
	};

	/*!
	\brief connect poll for windows CPIO
	*/
	class cTcpConnectPoll : public cConnectPool
	{
	public:
		cTcpConnectPoll(){
			int i;
			for (i = 0; i < CPL_SOCKET_GROUPS; i++)
				_maps[i].InitHashSize(4096);
		};
		virtual ~cTcpConnectPoll() {};
#ifdef _WIN32
		HANDLE  ucid_CreateIoCompletionPort(
			unsigned int uID,
			HANDLE ExistingCompletionPort,
			ULONG_PTR CompletionKey,
			DWORD NumberOfConcurrentThreads
		)
		{
			cSafeLock	lock(&_Locks[uID % CPL_SOCKET_GROUPS]);
			T_CONITEM* pi = _maps[uID % CPL_SOCKET_GROUPS].Lookup(uID);
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
			cSafeLock	lock( &_Locks[uID % CPL_SOCKET_GROUPS]);
			T_CONITEM* pi = _maps[uID % CPL_SOCKET_GROUPS].Lookup(uID);
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
			cSafeLock	lock(&_Locks[uID % CPL_SOCKET_GROUPS]);
			T_CONITEM* pi = _maps[uID % CPL_SOCKET_GROUPS].Lookup(uID);
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
		int ucid_recv(unsigned int uID, void *buf, size_t len, int flags)//recv by ucid
		{
			cSafeLock	lock(&_Locks[uID % CPL_SOCKET_GROUPS]);
			T_CONITEM* pi = _maps[uID % CPL_SOCKET_GROUPS].Lookup(uID);
			if (!pi)
				return -2;
			return recv(pi->Socket, buf, len, flags);
		}
		int ucid_epoll_ctl(int epfd, int op, unsigned int uID, struct epoll_event *pevent)// if delete , delete from connect pool
		{
			cSafeLock	lock(&_Locks[uID % CPL_SOCKET_GROUPS]);
			T_CONITEM* pi = _maps[uID % CPL_SOCKET_GROUPS].Lookup(uID);
			if (!pi)
				return -1;
			int nret = epoll_ctl(epfd, op, pi->Socket, pevent);
			if (EPOLL_CTL_DEL == op)
			{
				shutdown(pi->Socket, SHUT_WR);
				close(pi->Socket); // man 7 epoll ,closing a file descriptor cause it to be removed from all epoll sets automatically
				_maps[uID % CPL_SOCKET_GROUPS].RemoveKey(uID);
				FreeUcid(uID);
			}
			return nret;
		}
		//return send bytes size or -1 for error
		int Socket_Send(SOCKET s, const void* pbuf, unsigned int nsize)
		{
			const char *ps = (const char*)pbuf;
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
		int ucid_Send(int epfd, unsigned int uID, const void* pbuf, unsigned int nsize)// send failed will delete from connect pool
		{
			cSafeLock	lock(&_Locks[uID % CPL_SOCKET_GROUPS]);
			T_CONITEM* pi = _maps[uID % CPL_SOCKET_GROUPS].Lookup(uID);
			if (!pi) 
				return SOCKET_ERROR;			
			int nsend = Socket_Send(pi->Socket, pbuf, nsize);
			if (SOCKET_ERROR == nsend) {				
				struct epoll_event  evtdel;
				epoll_ctl(epfd, EPOLL_CTL_DEL, pi->Socket, &evtdel);
				shutdown(pi->Socket, SHUT_WR);
				close(pi->Socket);
				_maps[uID % CPL_SOCKET_GROUPS].RemoveKey(uID);
				FreeUcid(uID);				
				return SOCKET_ERROR;
			}
			pi->u64Send += nsend;
			SetBps(pi, nsend, false);
			return nsend;
		};
#endif
	};
} // ec
#endif // C_TCP_CPL_H
