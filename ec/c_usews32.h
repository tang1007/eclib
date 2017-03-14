
/*
\file c_usews32.h
\brief Use winsocket 

ec library is free C++ library.

\author	 kipway@outlook.com
*/

#ifndef C_USEWS32_H
#define C_USEWS32_H
namespace ec{
	#ifdef _WIN32
	#include <windows.h>
	#include <winsock2.h>
	class cUseWS_32
	{
	public:
		cUseWS_32(){
			m_bInit = false;
			unsigned short wVersionRequested;
			WSADATA wsaData;
			int err;

			wVersionRequested = MAKEWORD( 2,2 );

			err = WSAStartup( wVersionRequested, &wsaData );
			if ( err != 0 )
				return;

			if ( LOBYTE( wsaData.wVersion ) != 2 ||
				HIBYTE( wsaData.wVersion ) != 2 )
				WSACleanup( );
			else
				m_bInit = true;
		};
		~cUseWS_32(){
			if(m_bInit)
				WSACleanup( );
		};
	protected:
		bool m_bInit;

	public:
		static bool Init()
		{
			unsigned short wVersionRequested;
			WSADATA wsaData;
			int err;

			wVersionRequested = MAKEWORD( 2,2 );

			err = WSAStartup( wVersionRequested, &wsaData );
			if ( err != 0 )
				return false;

			if ( LOBYTE( wsaData.wVersion ) != 2 ||
				HIBYTE( wsaData.wVersion ) != 2 )
			{
				WSACleanup( );
				return false;
			}
			return true;
		}
		static bool Exit()
		{
			WSACleanup( );
			return true;
		}
	};
	#endif
};
#endif

