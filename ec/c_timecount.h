
/*!
\file timecount.h
\brief high Performance time Counter


\author kipway@outlook.com

*/
#ifndef C_TIMECOUNT_H
#define C_TIMECOUNT_H
namespace ec
{
#ifdef _WIN32
#include <WinBase.h>
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
#include <sys/time.h>
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

