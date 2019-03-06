/*!
\file c_log.h
\author kipway@outlook.com
\update 2018.3.12

eclib class cLog

Max File size 8MB
20140414-0001.txt
20140414-0002.txt
20140414-0003.txt
... ...
20140414-9999.txt

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
#ifndef RUNLOG_BUFSIZE
#ifdef _ARM_LINUX
#define RUNLOG_BUFSIZE		(1024 * 128)
#else
#define RUNLOG_BUFSIZE		(1024 * 512)
#endif
#endif
#ifndef MAX_LOG_SIZE
#ifdef _ARM_LINUX
#define MAX_LOG_SIZE		(1024 * 32)
#else
#define MAX_LOG_SIZE		(1024 * 16)
#endif
#endif
#ifdef _ARM_LINUX
#define MAX_LOGFILE_SIZE	(1024 * 1024 * 1)
#else
#define MAX_LOGFILE_SIZE	(1024 * 1024 * 8)
#endif
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
		inline const char* getlogpath() {
			return _slogpath;
		}
#ifdef _WIN32
        void	AddLog(const char * format, ...)
#else
		void	AddLog(const char * format, ...) __attribute__((format(printf, 2, 3)))
#endif
        {
            cSafeLock lock(&_cs);
            if (!_pstr)
                return;
			int ns = 0;
			cTime ctm(nstime(&ns));            
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
			snprintf(_slog, sizeof(_slog), "[%02d:%02d:%02d.%06d] ", ctm._hour, ctm._min, ctm._sec, ns);
			npos = (int)strlen(_slog);
			
            va_list arg_ptr;
            va_start(arg_ptr, format);
            int nbytes = vsnprintf(&_slog[npos], MAX_LOG_SIZE, format, arg_ptr);
            va_end(arg_ptr);
            if (nbytes <= 0 || nbytes >= MAX_LOG_SIZE)
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
#ifdef _WIN32
        void DebugLog(const char * format, ...)
#else
		void DebugLog(const char * format, ...) __attribute__((format(printf, 2, 3)))
#endif
        {
#ifdef _DEBUG
            cSafeLock lock(&_cs);

            if (!_pstr)
                return;
			int ns = 0;
            cTime ctm(nstime(&ns));
            unsigned int udate = ((unsigned int)ctm._year) << 16 | ((unsigned int)ctm._mon) << 8 | (unsigned int)ctm._day;
            if (udate != _udate)
            {
                Write2Disk();
                _udate = udate;
                _nFileNo = 1;
                sprintf(_scurlogfile, "%04d%02d%02d-%04d.txt", ctm._year, ctm._mon, ctm._day, _nFileNo);
            }
            snprintf(_slog, sizeof(_slog),"[%02d:%02d:%02d.%06d] ", ctm._hour, ctm._min, ctm._sec, ns);
			int npos = (int)strlen(_slog);
            va_list arg_ptr;
            va_start(arg_ptr, format);
            int nbytes = vsnprintf(&_slog[npos], MAX_LOG_SIZE, format, arg_ptr);
            va_end(arg_ptr);
            if (nbytes <= 0 || nbytes >= MAX_LOG_SIZE)
                return;
            nbytes += npos;
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
#ifdef _WIN32
        void	AddLog2(const char * format, ...)
#else
		void	AddLog2(const char * format, ...) __attribute__((format(printf, 2, 3)))
#endif
        {
            cSafeLock lock(&_cs);
            if (!_pstr)
                return;
            va_list arg_ptr;
            va_start(arg_ptr, format);
            int nbytes = vsnprintf(_slog, MAX_LOG_SIZE, format, arg_ptr);

            va_end(arg_ptr);

            if (nbytes <= 0 || nbytes >= MAX_LOG_SIZE)
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

		void AddLogMem(const void* pm, size_t size)
		{
			size_t i;
			char o[1024];
			unsigned char ul, uh;
			const unsigned char* s = (const unsigned char*)pm;
			for (i = 0; i < size && i < 256; i++)
			{
				uh = (s[i] & 0xF0) >> 4;
				ul = (s[i] & 0x0F);
				if (uh < 10)
					o[i * 3] = '0' + uh;
				else
					o[i * 3] = 'A' + uh - 10;
				if (ul < 10)
					o[i * 3 + 1] = '0' + ul;
				else
					o[i * 3 + 1] = 'A' + ul - 10;
				o[i * 3 + 2] = '\x20';
			}
			o[i * 3] = '\0';
			AddLog2("%s\n", o);
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

