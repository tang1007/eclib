/*!
\file c11_log.h
\author	jiangyong
\email  kipway@outlook.com
\update 2018.8.2

eclibe log for windows & linux

class clog;

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


#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <malloc.h>
#include "c_time.h"
#include "c_str.h"
#include "c11_array.h"
#include "c11_config.h"
#include "c11_mutex.h"
#include "c11_thread.h"
#include "c_diskio.h"
#include "c11_vector.h"

#ifndef _WIN32
#include <dirent.h>
#include <sys/stat.h>
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
#define MAX_LOG_SIZE		(1024 * 16)
#else
#define MAX_LOG_SIZE		(1024 * 32)
#endif
#endif
#ifdef _ARM_LINUX
#define MAX_LOGFILE_SIZE	(1024 * 1024 * 1)
#else
#define MAX_LOGFILE_SIZE	(1024 * 1024 * 8)
#endif

#define CLOG_DEFAULT_ERR  10
#define CLOG_DEFAULT_WRN  20
#define CLOG_DEFAULT_MSG  30
#define CLOG_DEFAULT_DBG  40

namespace ec
{

	/*!
	\brief log for cpp

	#clog default config file

	[clog]
	logpath = /home/clog
	outlevel = 100    # out put level, message level <= this level will output
	savesecond  = 5   # seconds to force write buffer to file

	[level]
	10 = err    # error
	20 = wrn    # warning
	30 = msg    # message
	40 = dbg    # debug
	*/
	class cLog : public cThread
	{
	public:
		class cfg : public config {
			struct t_i {
				char name[16];
				int  level;
			};
		public:
			cfg() : _outleval(100), _savesec(5) {
				_logpath[0] = '\0';
			}
			
			int _outleval;
			int _savesec;
			char _logpath[512];
			Array<t_i, 16> _levels;
			void initdefault(const char* slogpath)
			{
				str_lcpy(_logpath, slogpath, sizeof(_logpath));
				_outleval = 100;
				_savesec = 5;
				t_i t;
				str_lcpy(t.name, "err", sizeof(t.name));
				t.level = 10;
				_levels.add(&t);

				str_lcpy(t.name, "wrn", sizeof(t.name));
				t.level = 20;
				_levels.add(&t);

				str_lcpy(t.name, "msg", sizeof(t.name));
				t.level = 30;
				_levels.add(&t);

				str_lcpy(t.name, "dbg", sizeof(t.name));
				t.level = 40;
				_levels.add(&t);
			}
		protected:
			virtual void OnBlkName(const char* sblk) {};
			virtual void OnDoKeyVal(const char* sblk, const char* skey, const char* sval)
			{
				if (str_ieq("clog", sblk)) {
					if (str_ieq("logpath", skey))
						str_ncpy(_logpath, sval, sizeof(_logpath) - 1);
					else if (str_ieq("outlevel", skey))
						_outleval = atoi(sval);
					else if (str_ieq("savesecond", skey)) {
						_savesec = atoi(sval);
						if (_savesec < 1)
							_savesec = 1;
					}
				}
				else if (str_ieq("level", sblk)) {
					if (*skey && *sval) {
						t_i t;
						str_ncpy(t.name, sval, sizeof(t.name) - 1);
						t.level = atoi(skey);
						_levels.add(t);
					}
				}
			}
			virtual void OnReadFile()
			{
				_levels.clear();
				_logpath[0] = '\0';
				_outleval = 100;
				_savesec = 5;
			};
		};// class cfg
	public:
		cLog() : _evt(false, true), _buf(RUNLOG_BUFSIZE)
		{
			_blinestylewin = false;

			_slogpath[0] = 0;
			_scurlogfile[0] = 0;
			_unkown[0] = 0;
			_nFileNo = 1;

			_tk100 = 0;

			cTime ct(::time(NULL));
			_udate = ((unsigned int)ct._year) << 16 | ((unsigned int)ct._mon) << 8 | (unsigned int)ct._day;
			_lastlogtime = 0;
			_buf.add('\0');
			_buf.clear();
		}
		virtual ~cLog()	{
		}
	protected:
		bool _blinestylewin; // true \r\a ,false \n
		unsigned int   _udate; // year << 16 + mon << 8 +day
		unsigned int	_tk100;
		
		char _slog[MAX_LOG_SIZE + 32]; //

		char _slogpath[384], _unkown[32];
		char _scurlogfile[512];
		int	 _nFileNo;

		spinlock	_cs;
		cEvent _evt;
		time_t _lastlogtime;
		cfg _cfg;
		vector<char> _buf;
	protected:
		virtual const char* GetClassName() { return "cLog"; };
		virtual	void dojob() {
			_evt.Wait(100);
			_tk100++;
			if (!(_tk100 % (_cfg._savesec * 10)))
				SaveLog();
		}
		const char* levelstr(int level)
		{
			size_t i, n = _cfg._levels.size();
			for (i = 0; i < n; i++) {
				if (level == _cfg._levels[i].level)
					return _cfg._levels[i].name;
			}
			snprintf(_unkown, sizeof(_unkown), "level%d", level);
			return _unkown;
		}
	public:
		bool opendefault(const char* logpath, bool bLineStyleWin = false)
		{
			_cfg.initdefault(logpath);
			return _open(bLineStyleWin);
		}
		
		bool open(const char* scfgfile, bool bLineStyleWin = false)
		{
			if (!_cfg.fromfile(scfgfile))
				return false;
			return _open(bLineStyleWin);
		}
		void close()
		{
			SaveLog();
			StopThread();
		}
		inline void set_outlevel(int nlevel) {
			_cfg._outleval = nlevel;
		}
		inline int get_outlevel() {
			return _cfg._outleval;
		}
		inline const char* getlogpath() {
			return _slogpath;
		}
#ifdef _WIN32
		void	add(int level, const char * format, ...)
#else
		void	add(int level, const char * format, ...) __attribute__((format(printf, 3, 4)))
#endif		
		{
			if (level > _cfg._outleval)
				return;
			unique_spinlock lock(&_cs);
			int ns = 0;			
			cTime ctm(nstime(&ns));
			unsigned int udate = ((unsigned int)ctm._year) << 16 | ((unsigned int)ctm._mon) << 8 | (unsigned int)ctm._day;
			if (udate != _udate) {
				Write2Disk();
				_udate = udate;
				_nFileNo = 1;
				sprintf(_scurlogfile, "%04d%02d%02d-%04d.txt", ctm._year, ctm._mon, ctm._day, _nFileNo);
				_lastlogtime = 0;
			}
			int npos = 0;
			snprintf(_slog, sizeof(_slog),"[%02d:%02d:%02d.%06d] [%s] ", ctm._hour, ctm._min, ctm._sec, ns,levelstr(level));
			npos = (int)strlen(_slog);			

			va_list arg_ptr;
			va_start(arg_ptr, format);
			int nbytes = vsnprintf(&_slog[npos], MAX_LOG_SIZE - npos, format, arg_ptr);
			va_end(arg_ptr);
			if (nbytes <= 0 || nbytes >= MAX_LOG_SIZE)
				return;
			nbytes += npos;
			if (_blinestylewin)
				_slog[nbytes++] = '\r';
			_slog[nbytes++] = '\n';
			_slog[nbytes] = 0;

			if ((_buf.size() + nbytes) > (RUNLOG_BUFSIZE - 1))
				Write2Disk();
			_buf.add(_slog, nbytes);
		}

#ifdef _WIN32
		void	append(int level, const char * format, ...)
#else		
		void	append(int level, const char * format, ...)  __attribute__((format(printf, 3, 4)))
#endif
		{
			if (level > _cfg._outleval)
				return;
			unique_spinlock lock(&_cs);
			va_list arg_ptr;
			va_start(arg_ptr, format);
			int nbytes = vsnprintf(_slog, MAX_LOG_SIZE, format, arg_ptr);

			va_end(arg_ptr);

			if (nbytes <= 0 || nbytes >= MAX_LOG_SIZE)
				return;
			_slog[nbytes] = 0;

			cTime ctm(time(NULL));

			unsigned int udate = ((unsigned int)ctm._year) << 16 | ((unsigned int)ctm._mon) << 8 | (unsigned int)ctm._day;
			if (udate != _udate) {
				Write2Disk();
				_udate = udate;
				_nFileNo = 1;
				sprintf(_scurlogfile, "%04d%02d%02d-%04d.txt", ctm._year, ctm._mon, ctm._day, _nFileNo);
			}

			if ((_buf.size() + nbytes) > (RUNLOG_BUFSIZE - 1))
				Write2Disk();
			_buf.add(_slog, nbytes);
		}

		void addbin(int level, const void* pm, size_t size)
		{
			if (level > _cfg._outleval)
				return;
			size_t i,ido = 0;
			char o[1024];
			unsigned char ul, uh;
			const unsigned char* s = (const unsigned char*)pm;
			while (ido < size) {
				for (i = 0; ido < size && i < 256; i++)
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
					ido++;
				}
				o[i * 3] = '\0';
				append(level,"%s", o);
			}
		}

		void addstr(int level, const char* pm, size_t size)
		{
			if (level > _cfg._outleval)
				return;
			unique_spinlock lock(&_cs);			
			cTime ctm(time(NULL));

			unsigned int udate = ((unsigned int)ctm._year) << 16 | ((unsigned int)ctm._mon) << 8 | (unsigned int)ctm._day;
			if (udate != _udate) {
				Write2Disk();
				_udate = udate;
				_nFileNo = 1;
				sprintf(_scurlogfile, "%04d%02d%02d-%04d.txt", ctm._year, ctm._mon, ctm._day, _nFileNo);
			}			
			_buf.add(pm, size);
			if (_buf.size() > RUNLOG_BUFSIZE / 2 )
				Write2Disk();
		}

	protected:		
		bool _open( bool bLineStyleWin = false)
		{
			_blinestylewin = bLineStyleWin;
			if (!_cfg._logpath[0])
				return false;
			str_ncpy(_slogpath, _cfg._logpath, sizeof(_slogpath) - 1);
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
		bool	Write2Disk() 
		{
			if (!_buf.size())
				return false;

			if (IO::GetDiskSpace(_slogpath) < 50) { // disk left space 50MB
				_buf.clear();
				return false;
			}

			char szfile[512];
			snprintf(szfile, sizeof(szfile), "%s%s", _slogpath, _scurlogfile);

			FILE* pf;
			pf = fopen(szfile, "a+t");
			if (pf != NULL) {
				if (!fseek(pf, 0, SEEK_END))
				{
					fwrite(_buf.data(), 1, _buf.size(), pf);
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
				_buf.clear();
				return false;
			}
			return false;
		}
	public:
		bool	SaveLog()
		{
			unique_spinlock lock(&_cs);
			if (!_buf.size())
				return true;
			return Write2Disk();			
		}
	};
};
	

