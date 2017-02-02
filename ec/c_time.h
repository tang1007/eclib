/*
\file c_time.h
\brief time class

ec library is free C++ library.

\author	 kipway@outlook.com
*/

#ifndef C_TIME_H
#define C_TIME_H
#ifdef _WIN32
#pragma warning (disable : 4996)
#endif
#include <time.h>
#ifndef _WIN32
inline unsigned int GetTickCount()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned int)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
#endif
namespace ec
{
    class cTime
    {
    public:
        cTime(time_t gmt) {
            _gmt = gmt;
            struct tm *ptm = localtime(&_gmt);
            if (ptm) {
                _year = ptm->tm_year + 1900;
                _mon = ptm->tm_mon + 1;
                _day = ptm->tm_mday;
                _hour = ptm->tm_hour;
                _min = ptm->tm_min;
                _sec = ptm->tm_sec;
            }
            else
            {
                _year = 1900;
                _mon = 1;
                _day = 1;
                _hour = 0;
                _min = 0;
                _sec = 0;
            }
        };
        cTime(int nyear, int nmon, int nday) {
            SetTime(nyear, nmon, nday);
        };
        cTime(int nyear, int nmon, int nday, int nhour, int nmin, int nsec) {
            SetTime(nyear, nmon, nday, nhour, nmin, nsec);
        };
        ~cTime() {};
        void SetTime(int nyear, int nmon, int nday)
        {
            struct tm t;
            time_t tmp = ::time(NULL);
            t = *localtime(&tmp);
            t.tm_year = nyear - 1900;
            t.tm_mon = nmon - 1;
            t.tm_mday = nday;
            t.tm_hour = 0;
            t.tm_min = 0;
            t.tm_sec = 0;
            _gmt = mktime(&t);
            _year = nyear;
            _mon = nmon;
            _day = nday;
            _hour = 0;
            _min = 0;
            _sec = 0;
        }
        void SetTime(int nyear, int nmon, int nday, int nhour, int nmin, int nsec)
        {
            struct tm t;
            time_t tmp = ::time(NULL);
            t = *localtime(&tmp);
            t.tm_year = nyear - 1900;
            t.tm_mon = nmon - 1;
            t.tm_mday = nday;
            t.tm_hour = nhour;
            t.tm_min = nmin;
            t.tm_sec = nsec;
            _gmt = mktime(&t);

            _year = nyear;
            _mon = nmon;
            _day = nday;
            _hour = nhour;
            _min = nmin;
            _sec = nsec;
        }

        inline time_t GetTime() const
        {
            return _gmt;
        };
        cTime& operator = (time_t gmt)
        {
            _gmt = gmt;
            struct tm *ptm = localtime(&_gmt);
            if (ptm) {
                _year = ptm->tm_year + 1900;
                _mon = ptm->tm_mon + 1;
                _day = ptm->tm_mday;
                _hour = ptm->tm_hour;
                _min = ptm->tm_min;
                _sec = ptm->tm_sec;
            }
            return *this;
        }
    protected:
        time_t _gmt; // GMT time
    public:
        int _year, _mon, _day, _hour, _min, _sec; //local
    };

}; // ec
#endif // C_TIME_H

