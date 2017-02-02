/*
\file tType.h
\brief base type define

  ec library is free C++ library.

\author kipway@outlook.com
*/

#ifndef C_TYPE_H_
#define C_TYPE_H_

typedef char					T_I8;
typedef unsigned char			T_U8;

typedef short int				T_I16;
typedef unsigned short int		T_U16;

typedef int						T_I32;
typedef unsigned int			T_U32;

typedef long long			    T_I64;
typedef unsigned long long	    T_U64;


typedef float					T_F32;
typedef double					T_F64;

#ifndef _WIN32

#ifndef NULL
#define	NULL			0
#endif // NULL	

#ifndef UNALIGNED
#define UNALIGNED
#endif // UNALIGNED

#ifndef __stdcall
#define	__stdcall
#endif // __stdcall

#ifndef __cdecl
#define	__cdecl
#endif // __cdecl

#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE (-1)
#endif

#ifndef max
#define max(a,b)    (((a) > (b)) ? (a) : (b))
#endif // max

#ifndef min
#define min(a,b)    (((a) < (b)) ? (a) : (b))
#endif // min

#ifndef stricmp
#define stricmp(a,b)    strcasecmp(a,b)
#endif // stricmp

#ifndef _snprintf
#define _snprintf		snprintf
#endif // _snprintf

#endif

#endif // C_TYPE_H_

