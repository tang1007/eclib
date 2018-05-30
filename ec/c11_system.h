/*!
\file c11_system.h
\author	kipway@outlook.com
\update 2018.5.27

eclib class with c++11.

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

#ifndef USE_ECLIB_C11
#	define USE_ECLIB_C11 1 // 1: use std::thread,std:mutex,std::condition_variable and c++11 style code. 0:normal
#endif

#ifdef _WIN32
#	define _CRT_SECURE_NO_WARNINGS
#	pragma warning (disable : 4996)
#	pragma warning (disable : 4200)
#	ifndef _WIN32_WINNT
#		define _WIN32_WINNT 0x0600	//0x600=win7/2008 ;  0x0502=windows2003/xp
#	endif
#	include <process.h>
#	define WIN32_LEAN_AND_MEAN
#	include <windows.h>

#	ifndef _NOTUSE_WINSOCKET
#		include <Winsock2.h>
#		pragma comment(lib,"Ws2_32.lib")
#	endif

#else
#	include <termios.h>
#	include <unistd.h>

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

#include <stdlib.h>
#include <stdio.h>
#include <cstdint>

#include "c11_array.h"
#include "c11_stack.h"
#include "c11_memory.h"
#include "c11_vector.h"
#include "c11_map.h"




