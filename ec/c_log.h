/*!
 \file c_log.h
 \brief cLog

    Max File size 8MB
    20140414-0001.txt
    20140414-0002.txt
    20140414-0003.txt
    ... ...
    20140414-9999.txt

    Userage:
    Start
    // ...
    AddLog
    // ..
    Stop

    thread safe

  ec library is free C++ library.

  \author	 kipway@outlook.com
*/

#ifndef C_LOG_H
#define C_LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <malloc.h>
#include "c_time.h"
#include "c_critical.h"
#include "c_thread.h"
#include "c_diskio.h"

#ifdef _WIN32

#else
#include <dirent.h>
#include <sys/stat.h>
#endif

#ifndef LOG_SVAE_SEC        
#define LOG_SVAE_SEC    10
#endif

#define RUNLOG_BUFSIZE		(1024 * 512)   // 512Kbytes
#define MAX_LOG_SIZE		(1024 * 32)

#define MAX_LOGFILE_SIZE	(1024 * 1024 * 8)
namespace ec
{
    class cLog : public cThread
    {
    public:
        cLog() : _evt(false, true)
        {
            _blinestylewin = false;
            _pstr = (char*)malloc(RUNLOG_BUFSIZE);
            *_pstr = 0;
            _nsize = 0;
            _slogpath[0] = 0;
            _scurlogfile[0] = 0;
            _nFileNo = 1;

            _tk100 = 0;

            cTime ct(::time(NULL));
            _udate = ((unsigned int)ct._year) << 16 | ((unsigned int)ct._mon) << 8 | (unsigned int)ct._day;
            _lastlogtime = 0;
        }
        virtual ~cLog()
        {
            if (_pstr)
                free(_pstr);
        }
    protected:
        bool _blinestylewin; // true \r\a ,false \n
        unsigned int   _udate; // year << 16 + mon << 8 +day
        unsigned int	_tk100;
        char *_pstr;
        int  _nsize;

        char _slog[MAX_LOG_SIZE + 32]; //

        char _slogpath[384];
        char _scurlogfile[512];
        int	 _nFileNo;

        cCritical	_cs;
        cEvent _evt;
        time_t _lastlogtime;
    protected:
        virtual const char* GetClassName() { return "CLog"; };
        virtual	void dojob() {
            _evt.Wait(100);
            _tk100++;
            if (!(_tk100 % (LOG_SVAE_SEC * 10)))
                SaveLog();
        }
    public:
        bool	Start(const char* slogpath,bool bLineStyleWin = false)
        {
            _blinestylewin = bLineStyleWin;
            if (!slogpath || !*slogpath)
                return false;
            strcpy(_slogpath, slogpath);
            int n = (int)strlen(_slogpath);

            if ((_slogpath[n - 1] != '\\') && (_slogpath[n - 1] != '/'))
                strcat(_slogpath, "/");
            if (!IO::CreateDir(_slogpath))
                return false;

            char szFile[512] = { '\0', };
            bool bok;
            int i;
#ifdef _WIN32
            int bfind = 1;
            char szFilter[256];
            strcpy(szFilter, _slogpath);
            strcat(szFilter, "*.txt");

            WIN32_FIND_DATAA FindFileData;
            HANDLE hFind = INVALID_HANDLE_VALUE;

            hFind = FindFirstFileA(szFilter, &FindFileData);
            while (hFind != INVALID_HANDLE_VALUE && bfind)
            {
                char* pc = FindFileData.cFileName;
                bok = true;
                i = 0;
                while (*pc && i < 13) {
                    if ((*pc < '\0' || *pc > '9') && (*pc != '-')) {
                        bok = false;
                        break;
                    }
                    pc++;
                    i++;
                }
                if (bok) {
                    if (!szFile[0])
                        strcpy(szFile, (const char*)(FindFileData.cFileName));
                    else {
                        if (strcmp(szFile, FindFileData.cFileName) < 0)
                            strcpy(szFile, (const char*)(FindFileData.cFileName));
                    }
                }
                bfind = FindNextFileA(hFind, &FindFileData);
            }
            FindClose(hFind);
#else
            DIR * dir = opendir(_slogpath);
            if (dir)
            {
                struct dirent *d = readdir(dir);
                while (d != NULL) {
                    if (strstr(d->d_name, ".txt"))
                    {
                        char* pc = d->d_name;
                        bok = true;
                        i = 0;
                        while (*pc && i < 13) {
                            if ((*pc < '\0' || *pc > '9') && (*pc != '-')) {
                                bok = false;
                                break;
                            }
                            pc++;
                            i++;
                        }
                        if (bok) {
                            if (!szFile[0])
                                strcpy(szFile, (const char*)(d->d_name));
                            else {
                                if (strcmp(szFile, d->d_name) < 0)
                                    strcpy(szFile, (const char*)(d->d_name));
                            }
                        }
                    }
                    d = readdir(dir);
                }
                closedir(dir);
            }
#endif
            cTime local_t(time(NULL));
            if (!szFile[0]) {
                sprintf(_scurlogfile, "%04d%02d%02d-%04d.txt", local_t._year, local_t._mon, local_t._day, _nFileNo);
                StartThread(NULL);
                return true;
            }

            char szday[32];
            sprintf(szday, "%04d%02d%02d", local_t._year, local_t._mon, local_t._day);
            char st[32];
            strncpy(st, szFile, 9);
            st[8] = 0;
            if (strcmp(st, szday))
            {
                sprintf(_scurlogfile, "%04d%02d%02d-%04d.txt", local_t._year, local_t._mon, local_t._day, _nFileNo);
                StartThread(NULL);
                return true;
            }

            char *ps = szFile;
            while (*ps != '\0' && *ps != '-')
                ps++;
            if (*ps == '0')
                return false;
            ps++;
            _nFileNo = atoi(ps);
            if (_nFileNo <= 0)
                _nFileNo = 1;
            sprintf(_scurlogfile, "%04d%02d%02d-%04d.txt", local_t._year, local_t._mon, local_t._day, _nFileNo);

            StartThread(NULL);
            return true;
        }

        void Stop()
        {
            SaveLog();
            StopThread();
        }

        void	AddLog(const char * format, ...)
        {
            cSafeLock lock(&_cs);
            if (!_pstr)
                return;
            cTime ctm(time(NULL));
            unsigned int udate = ((unsigned int)ctm._year) << 16 | ((unsigned int)ctm._mon) << 8 | (unsigned int)ctm._day;
            if (udate != _udate)
            {
                Write2Disk();
                _udate = udate;
                _nFileNo = 1;
                sprintf(_scurlogfile, "%04d%02d%02d-%04d.txt", ctm._year, ctm._mon, ctm._day, _nFileNo);
                _lastlogtime = 0;
            }
            int npos = 0;
            if (ctm.GetTime() != _lastlogtime)
            {
                sprintf(_slog, "%02d:%02d:%02d ", ctm._hour, ctm._min, ctm._sec);
                npos = 9;
                _lastlogtime = ctm.GetTime();
            }
            else
            {
                _slog[0] = '\t';                
                _slog[1] = '\x20';
                npos = 2;
            }

            va_list arg_ptr;
            va_start(arg_ptr, format);
            int nbytes = vsnprintf(&_slog[npos], MAX_LOG_SIZE, format, arg_ptr);
            va_end(arg_ptr);
            if (nbytes <= 0)
                return;
            nbytes += npos;
            if(_blinestylewin)
                _slog[nbytes++] = '\r';
            _slog[nbytes++] = '\n';
            _slog[nbytes] = 0;

            if ((_nsize + nbytes) > (RUNLOG_BUFSIZE - 1)) {
                Write2Disk();
                _nsize = 0;
                *_pstr = 0;
            }
            memcpy(_pstr + _nsize, _slog, nbytes);
            _nsize += nbytes;
            _pstr[_nsize] = 0;
            OnNewLog(_slog);
        }

        void DebugLog(const char * format, ...)
        {
#ifdef _DEBUG
            cSafeLock lock(&_cs);

            if (!_pstr)
                return;
            cTime ctm(time(NULL));
            unsigned int udate = ((unsigned int)ctm._year) << 16 | ((unsigned int)ctm._mon) << 8 | (unsigned int)ctm._day;
            if (udate != _udate)
            {
                Write2Disk();
                _udate = udate;
                _nFileNo = 1;
                sprintf(_scurlogfile, "%04d%02d%02d-%04d.txt", ctm._year, ctm._mon, ctm._day, _nFileNo);
            }
            sprintf(_slog, "%02d:%02d:%02d ", ctm._hour, ctm._min, ctm._sec);

            va_list arg_ptr;
            va_start(arg_ptr, format);
            int nbytes = vsnprintf(&_slog[9], MAX_LOG_SIZE, format, arg_ptr);
            va_end(arg_ptr);
            if (nbytes <= 0)
                return;
            nbytes += 9;
            _slog[nbytes++] = 0x0D;
            _slog[nbytes++] = 0x0A;
            _slog[nbytes] = 0;

            if ((_nsize + nbytes) > (RUNLOG_BUFSIZE - 1)) {
                Write2Disk();
                _nsize = 0;
                *_pstr = 0;
            }
            memcpy(_pstr + _nsize, _slog, nbytes);
            _nsize += nbytes;
            _pstr[_nsize] = 0;

#endif
        }

        void		AddLog2(const char * format, ...)
        {
            cSafeLock lock(&_cs);
            if (!_pstr)
                return;
            va_list arg_ptr;
            va_start(arg_ptr, format);
            int nbytes = vsnprintf(_slog, MAX_LOG_SIZE, format, arg_ptr);

            va_end(arg_ptr);

            if (nbytes <= 0)
                return;
            _slog[nbytes] = 0;

            cTime ctm(time(NULL));

            unsigned int udate = ((unsigned int)ctm._year) << 16 | ((unsigned int)ctm._mon) << 8 | (unsigned int)ctm._day;
            if (udate != _udate)
            {
                Write2Disk();
                _udate = udate;
                _nFileNo = 1;
                sprintf(_scurlogfile, "%04d%02d%02d-%04d.txt", ctm._year, ctm._mon, ctm._day, _nFileNo);
            }

            nbytes = (int)strlen(_slog);
            if ((_nsize + nbytes) > (RUNLOG_BUFSIZE - 1)) {
                Write2Disk();
                _nsize = 0;
                *_pstr = 0;
            }
            strcat(_pstr, _slog);
            _nsize += nbytes;
            OnNewLog(_slog);
        }

    protected:

        virtual void OnNewLog(const char* slog) {};
        bool	Write2Disk() {
            if (!_pstr || !_nsize)
                return false;

            if (IO::GetDiskSpace(_slogpath) < 50)// disk left space 50MB
            {
                *_pstr = 0;
                _nsize = 0;
                return false;
            }

            char szfile[512];
            strcpy(szfile, _slogpath);
            strcat(szfile, _scurlogfile);

            FILE* pf;
            pf = fopen(szfile, "a+t");
            if (pf != NULL) {
                if (!fseek(pf, 0, SEEK_END))
                {
                    fwrite(_pstr, _nsize, 1, pf);
#ifdef _WIN32
                    fpos_t pos = 0;
                    if (!fgetpos(pf, &pos))
                    {
                        if (pos >= MAX_LOGFILE_SIZE)
                        {
                            cTime local_t(::time(NULL));
                            _nFileNo++;
                            sprintf(_scurlogfile, "%04d%02d%02d-%04d.txt", local_t._year, local_t._mon, local_t._day, _nFileNo);
                        }
                    }
#else
                    fpos_t pos;
                    memset(&pos, 0, sizeof(pos));
                    if (!fgetpos(pf, &pos))
                    {
                        if (pos.__pos >= MAX_LOGFILE_SIZE)
                        {
                            cTime local_t(::time(NULL));
                            _nFileNo++;
                            sprintf(_scurlogfile, "%04d%02d%02d-%04d.txt", local_t._year, local_t._mon, local_t._day, _nFileNo);

                        }
                    }
#endif
                }
                fclose(pf);
                *_pstr = 0;
                _nsize = 0;
                return false;
            }
            *_pstr = 0;
            _nsize = 0;
            return false;
        }
    public:
        bool	SaveLog()
        {
            cSafeLock lock(&_cs);

            if (!_nsize)
                return true;
            bool bret = Write2Disk();
            if (_pstr) {
                _nsize = 0;
                *_pstr = 0;
            }
            return bret;
        }
    };
};
#endif // C_LOG_H

