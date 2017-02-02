/*!
\file c_system.h

ec library is free C++ library.

\author	 kipway@outlook.com
*/
#ifndef C_SYSTEM_H
#define C_SYSTEM_H

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#pragma warning (disable : 4996)
#pragma warning (disable : 4200)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0502	// 0x0502 windows2003
#endif
#include <process.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifndef _NOTUSE_WINSOCKET
#include <Winsock2.h>
#pragma comment(lib,"Ws2_32.lib")
#endif

#else
#include <termios.h>
#include <unistd.h>
#endif

#include <stdlib.h>
#include <stdio.h>

#endif //C_SYSTEM_H
