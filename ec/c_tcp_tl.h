/*!
\file c_tcp.h

\brief tcp functions for windows & linux

ec library is free C++ library.

\author	 jiangyong,
\email   13212314895@126.com
*/

#ifndef C_TCP_H
#define C_TCP_H

#ifdef _WIN32
#	pragma warning(disable : 4996)
#	include <winsock2.h>
#	include <mstcpip.h>
#else
#	include <unistd.h>
#	include <sys/time.h>
#	include <sys/types.h>
#	include <sys/socket.h>
#	include <sys/ioctl.h>
#	include <sys/select.h>
#	include <netinet/tcp.h>
#	include <arpa/inet.h>
#	include <errno.h>

#ifndef SOCKET
#	define SOCKET int
#endif 

#ifndef INVALID_SOCKET
#	define INVALID_SOCKET    (-1)
#endif

#ifndef SOCKET_ERROR
#	define SOCKET_ERROR      (-1)
#endif

#ifndef closesocket
#	define closesocket(a) close(a)
#endif 

#ifndef TIMEVAL
#	define TIMEVAL struct timeval
#endif 

#endif

namespace ec
{
    inline void SetTcpNoDelay(SOCKET s)
    {
        int bNodelay = 1;
        setsockopt(
            s,
            IPPROTO_TCP,
            TCP_NODELAY,
            (char *)&bNodelay,
            sizeof(bNodelay));
    }
#ifndef _WIN32
    inline bool SetSocketKeepAlive(SOCKET s, bool bfast = false)
    {
        int keepAlive = 1;
        int keepIdle = 30;
        int keepInterval = 1;
        int keepCount = 5;
        if (bfast)
        {
            keepIdle = 5;
            keepInterval = 1;
            keepCount = 3;
        }
        setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepAlive, sizeof(keepAlive));
        setsockopt(s, SOL_TCP, TCP_KEEPIDLE, (void*)&keepIdle, sizeof(keepIdle));
        setsockopt(s, SOL_TCP, TCP_KEEPINTVL, (void *)&keepInterval, sizeof(keepInterval));
        setsockopt(s, SOL_TCP, TCP_KEEPCNT, (void *)&keepCount, sizeof(keepCount));
        return true;
    }
#else
    inline bool SetSocketKeepAlive(SOCKET sock, bool bfast = false)
    {
        BOOL bKeepAlive = 1;
        int nRet = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE,
            (char*)&bKeepAlive, sizeof(bKeepAlive));
        if (nRet == SOCKET_ERROR)
            return false;
        tcp_keepalive alive_in;
        tcp_keepalive alive_out;
        if (bfast)
        {
            alive_in.keepalivetime = 5 * 1000;
            alive_in.keepaliveinterval = 500;
        }
        else
        {
            alive_in.keepalivetime = 30 * 1000;
            alive_in.keepaliveinterval = 1000;
        }
        alive_in.onoff = 1;
        unsigned long ulBytesReturn = 0;

        nRet = WSAIoctl(sock, SIO_KEEPALIVE_VALS, &alive_in, sizeof(alive_in),
            &alive_out, sizeof(alive_out), &ulBytesReturn, NULL, NULL);
        if (nRet == SOCKET_ERROR)
            return false;
        return true;
    }
#endif 

	inline  SOCKET	tcp_connect(const char* sip, unsigned short suport, int nTimeOutSec)
	{
		if (!sip || !*sip || !inet_addr(sip) || !suport)
			return INVALID_SOCKET;

		struct sockaddr_in ServerHostAddr = { 0 };
		ServerHostAddr.sin_family = AF_INET;
		ServerHostAddr.sin_port = htons(suport);
		ServerHostAddr.sin_addr.s_addr = inet_addr(sip);
		SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		if (s == INVALID_SOCKET)
			return INVALID_SOCKET;

		long ul = 1;
#ifdef _WIN32
		if (SOCKET_ERROR == ioctlsocket(s, FIONBIO, (unsigned long*)&ul)) {
			closesocket(s);
			return INVALID_SOCKET;
		}
#else
		if (ioctl(s, FIONBIO, &ul) == -1) {
			closesocket(s);
			return INVALID_SOCKET;
		}
#endif
		connect(s, (sockaddr *)(&ServerHostAddr), sizeof(ServerHostAddr));

		TIMEVAL tv01 = { nTimeOutSec,0 };
		fd_set fdw;
		FD_ZERO(&fdw);
		FD_SET(s, &fdw);
#ifdef _WIN32
		if (1 != ::select(0, NULL, &fdw, NULL, &tv01))
#else
		if (1 != ::select(s + 1, NULL, &fdw, NULL, &tv01))
#endif
		{
			closesocket(s);
			return  INVALID_SOCKET;
		}

		ul = 0;
#ifdef _WIN32
		if (SOCKET_ERROR == ioctlsocket(s, FIONBIO, (unsigned long*)&ul)) {
			::closesocket(s);
			return INVALID_SOCKET;
		}
#else
		if (ioctl(s, FIONBIO, &ul) == -1) {
			closesocket(s);
			return INVALID_SOCKET;
		}
#endif
		return s;
	}

    //return send bytes size or -1 for error,use for block or nonblocking  mode
    inline int tcp_send(SOCKET s, const void* pbuf,  int nsize)
    {
        char *ps = (char*)pbuf;
        int  nsend = 0;
        int  nret;        
        while (nsend < nsize)
        {
#ifdef _WIN32            
            nret = ::send(s, ps + nsend, nsize - nsend, 0);            
            if (SOCKET_ERROR == nret)
            {
                int nerr = WSAGetLastError();
                if (WSAEWOULDBLOCK == nerr || WSAENOBUFS == nerr)  // nonblocking  mode
                {
                    TIMEVAL tv01 = { 0,1000 * 100 };
                    fd_set fdw;
                    FD_ZERO(&fdw);
                    FD_SET(s, &fdw);
                    if (-1 == ::select(0, NULL, &fdw, NULL, &tv01))
                        return SOCKET_ERROR;
                    continue;
                }
                else
                    return SOCKET_ERROR;
            }            
            else
                nsend += nret;            
#else
            nret = ::send(s, ps + nsend, nsize - nsend, MSG_DONTWAIT | MSG_NOSIGNAL);
            if (SOCKET_ERROR == nret)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK) // nonblocking  mode
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
#endif
        }
        return nsend;
    };
    
	inline  int tcp_read(SOCKET s, void* pbuf, int nbufsize, int nTimeOutMsec)
	{
		if (s == INVALID_SOCKET)
			return SOCKET_ERROR;

		TIMEVAL tv01 = { nTimeOutMsec / 1000,1000 * (nTimeOutMsec % 1000) };
		fd_set fdr, fde;
		FD_ZERO(&fdr);
		FD_ZERO(&fde);
		FD_SET(s, &fdr);
		FD_SET(s, &fde);

#ifdef _WIN32
		int nRet = ::select(0, &fdr, NULL, &fde, &tv01);
#else
		int nRet = ::select(s + 1, &fdr, NULL, &fde, &tv01);
#endif

		if (SOCKET_ERROR == nRet)
			return SOCKET_ERROR;

		if (nRet == 0)
			return 0;
		if (FD_ISSET(s, &fde))
			return SOCKET_ERROR;

		nRet = ::recv(s, (char*)pbuf, nbufsize, 0);

		if (nRet <= 0)
			return SOCKET_ERROR;
		return nRet;
	}
} //namespace ec
#endif // C_TCP_H
