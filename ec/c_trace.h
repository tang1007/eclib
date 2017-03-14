/*
\file c_trace.h
\brief ECTRACE

ec library is free C++ library.

\author	 jiangyong,
\email   13212314895@126.com
*/

#ifndef C_TRACE_H
#define C_TRACE_H
	#ifdef _WIN32

		#pragma warning (disable : 4996)
		#include <stdio.h>
		class cDebug
		{
		public:
			static void trace(const char * format, ...)
			{
				int nbytes = 0;
				char stmp[4096];
				va_list arg_ptr;
				va_start(arg_ptr, format);
				nbytes = vsnprintf(stmp, 4096-8,format, arg_ptr);
				va_end(arg_ptr);

				if(nbytes <=0 )
					return;
				stmp[nbytes] = 0;
				OutputDebugStringA(stmp);
			}
		};

		#ifdef _DEBUG
			#define ECTRACE cDebug::trace
		#else
			#define ECTRACE __noop
		#endif
	#else
	#include <stdio.h>
	#include <stdarg.h>
        #ifdef _DEBUG
            inline void ECTRACE(const char * format, ...)
			{
				int nbytes = 0;
				char stmp[4096];
				va_list arg_ptr;
				va_start(arg_ptr, format);
				nbytes = vsnprintf(stmp, 4096-8,format, arg_ptr);
				va_end(arg_ptr);

				if(nbytes <=0 )
					return;
				stmp[nbytes] = 0;
				fprintf(stderr,"%s",stmp);
			}
			#else
                #define ECTRACE(fmt, ...)
		#endif
	#endif
#endif // C_TRACE_H

