
/*!
\file timecount.h
\author	kipway@outlook.com
\update 2018.10.31

InterProcess Communication with socket AF_UNIX(Linux), AF_INET(windows)

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
#ifndef C_TIMECOUNT_H
#define C_TIMECOUNT_H

#ifdef _WIN32
#	include <WinBase.h>
#else
#	include <sys/time.h>
#endif
namespace ec
{
#ifdef _WIN32

    class   cTimeCount
    {
    public:
        cTimeCount() {};
        ~cTimeCount() {};

        void		start()
        {
            QueryPerformanceFrequency(&litmp);
            dfFreq = (double)litmp.QuadPart;
            QueryPerformanceCounter(&litmp);
            QPart1 = litmp.QuadPart;
        };
        void		end()
        {
            QueryPerformanceCounter(&litmp);
            QPart2 = litmp.QuadPart;
            dfMinus = (double)(QPart2 - QPart1);
            dfTim = dfMinus / dfFreq;
        };

        inline double	time_milli() {
            return dfTim * 1000.0;
        };

		inline int	time_us() {
			return (int)(dfTim * 1000000);
		};

    private:
        LARGE_INTEGER   litmp;
        LONGLONG		QPart1, QPart2;
        double			dfMinus, dfFreq, dfTim;
    };
#else
    class   cTimeCount
    {
    public:
        cTimeCount() {};
        ~cTimeCount() {};

        void		start()
        {
            gettimeofday(&_tv1, &tz);
        };
        void		end()
        {
            gettimeofday(&_tv2, &tz);
        };

        double	time_milli() {
            return ((_tv2.tv_sec - _tv1.tv_sec) * 1000000 + ((long)_tv2.tv_usec - (long)_tv1.tv_usec)) / 1000.0;
        };

		inline int	time_us() {
			return (int)((_tv2.tv_sec - _tv1.tv_sec) * 1000000 + ((long)_tv2.tv_usec - (long)_tv1.tv_usec));
		};

    private:
        struct timeval    _tv1;
        struct timeval    _tv2;
        struct timezone tz;
    };
#endif
}
#endif //C_TIMECOUNT_H

