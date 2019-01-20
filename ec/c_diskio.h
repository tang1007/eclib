
/*!
\file c_diskio.h
\author	jiangyong
\email  kipway@outlook.com
\update 2019.1.20

disk io tools

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

#ifdef _WIN32
#include  <io.h>
#include <windows.h>
#include <sys/stat.h>
#else
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <fcntl.h>
#endif
#include "c_str.h"
#if (0 != USE_ECLIB_C11)
#include "c11_vector.h"
#endif

namespace ec
{
	struct t_stat {
		long long size;
		time_t mtime;
		time_t ctime;
	};
	class IO
	{
	public:
		static FILE *fopen_utf8(const char* utf8file, const char* utf8mode)
		{
#ifdef _WIN32
			wchar_t sfile[1024], smode[32];
			int n = MultiByteToWideChar(CP_UTF8, 0, utf8file, -1, sfile, sizeof(sfile) / sizeof(wchar_t));
			sfile[n] = 0;
			n = MultiByteToWideChar(CP_UTF8, 0, utf8mode, -1, smode, sizeof(smode) / sizeof(wchar_t));
			smode[n] = 0;
			return _wfopen(sfile, smode);
#else
			return fopen(utf8file, utf8mode);
#endif
		}

#ifdef _WIN32
		static bool IsExist(const char* sfile)
		{
			if (_access(sfile, 0))
				return false;
			return true;
		}
		static bool CreateDir(const char* lpszPath)
		{
			if (!lpszPath || !*lpszPath)
				return false;
			char cl = 0;
			char szt[512] = { '\0', }, *pct;

			pct = (char*)szt;
			while (*lpszPath) {
				if (*lpszPath == '\\' || *lpszPath == '/') {
					if (-1 == _access(szt, 0))
						if (!CreateDirectoryA(szt, NULL))
							return false;
					*pct = '/';
					cl = *pct;
					pct++;
					*pct = '\0';
				}
				else {
					*pct = *lpszPath;
					cl = *pct;
					pct++;
					*pct = '\0';
				}
				lpszPath++;
			}
			if (cl != '/' && -1 == _access(szt, 0))
				if (!CreateDirectoryA(szt, NULL))
					return false;
			return true;
		}

		static long long GetDiskSpace(const char* lpszDisk) // lpszDisk format is "c:\"
		{
			ULARGE_INTEGER ullFreeBytesAvailable, ullTotalNumberOfBytes, ullTotalNumberOfFreeBytes;
			ullFreeBytesAvailable.QuadPart = 0;
			ullTotalNumberOfBytes.QuadPart = 0;
			ullTotalNumberOfFreeBytes.QuadPart = 0;
			BOOL bret = GetDiskFreeSpaceExA(
				lpszDisk,      // directory name
				&ullFreeBytesAvailable,    // bytes available to caller
				&ullTotalNumberOfBytes,    // bytes on disk
				&ullTotalNumberOfFreeBytes // free bytes on disk
			);
			if (bret)
			{
				ULONGLONG lspace = ullFreeBytesAvailable.QuadPart >> 20; //MB
				return (long long)lspace;
			}
			return 0;
		}
		static bool GetExePath(char spath[512]) // last char is '/'
		{
			char sFilename[_MAX_PATH];
			char sDrive[_MAX_DRIVE];
			char sDir[_MAX_DIR];
			char sFname[_MAX_FNAME];
			char sExt[_MAX_EXT];
			*spath = '\0';
			GetModuleFileNameA(NULL, sFilename, _MAX_PATH);
			_splitpath(sFilename, sDrive, sDir, sFname, sExt);

			strcpy(spath, sDrive);
			strcat(spath, sDir);

			char *ps = spath;
			while (*ps != '\0')
			{
				if (*ps == '\\')
					*ps = '/';
				ps++;
			}
			size_t nlen = strlen(spath);
			if (nlen > 0 && spath[nlen - 1] != '/')
			{
				spath[nlen] = '/';
				spath[nlen + 1] = '\0';
			}
			return true;
		}
		static bool GetAppName(char sappname[256])
		{
			char sFilename[_MAX_PATH];
			char sDrive[_MAX_DRIVE];
			char sDir[_MAX_DIR];
			char sFname[_MAX_FNAME];
			char sExt[_MAX_EXT];
			*sappname = '\0';
			GetModuleFileNameA(NULL, sFilename, _MAX_PATH);
			_splitpath(sFilename, sDrive, sDir, sFname, sExt);
			strcpy(sappname, sFname);
			return true;
		}
		static bool filestat(const char* sfile,t_stat *pout) {
			struct __stat64 statbuf;
			if (!_stat64(sfile, &statbuf)) {
				pout->size = statbuf.st_size;
				pout->mtime = statbuf.st_mtime;
				pout->ctime = statbuf.st_ctime;
				return true;
			}
			return false;
		}
		static long long filesize(const char* sfile)
		{
			struct __stat64 statbuf;
			if (!_stat64(sfile, &statbuf))
				return statbuf.st_size;
			return -1;
		}

		static long long filesize(const wchar_t* wsfile)
		{
			struct __stat64 statbuf;
			if (!_wstat64(wsfile, &statbuf))
				return statbuf.st_size;
			return -1;
		}

		/*!
		\brief lock read whole file for windows
		*/
		static bool	LckRead(const char* utf8file, vector<char> *pout)
		{
			wchar_t sfile[1024];
			int n = MultiByteToWideChar(CP_UTF8, 0, utf8file, -1, sfile, sizeof(sfile) / sizeof(wchar_t));
			sfile[n] = 0;

			HANDLE hFile = CreateFileW(sfile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL); // 共享只读打开
			if (hFile == INVALID_HANDLE_VALUE)
				return false;

			long long size = filesize(sfile);
			if (size <= 0) {
				CloseHandle(hFile);
				pout->clear();
				return false;
			}

			OVERLAPPED	 op;
			memset(&op, 0, sizeof(op));
			op.Offset = 0;
			op.OffsetHigh = 0;
			if (!LockFileEx(hFile, 0, 0, (DWORD)-1, (DWORD)-1, &op))
			{
				CloseHandle(hFile);
				return false;
			}
			pout->clear();
			pout->set_grow((size_t)size);
			char tmp[1024 * 32];
			DWORD dwr = 0;
			do
			{
				if (!ReadFile(hFile, tmp, sizeof(tmp), &dwr, NULL))
					break;
				pout->add(tmp, dwr);
			} while (dwr == sizeof(tmp));

			UnlockFileEx(hFile, 0, (DWORD)-1, (DWORD)-1, &op);
			CloseHandle(hFile);
			return pout->size() > 0;
		}
#else
		static bool IsExist(const char* sfile)
		{
			if (access(sfile, F_OK))
				return false;
			return true;
		}
		static 	bool CreateDir(const char* lpszPath)
		{
			if (!lpszPath || !*lpszPath)
				return false;
			char cl = 0;
			char szt[512] = { '\0', }, *pct;

			pct = (char*)szt;
			while (*lpszPath) {
				if (*lpszPath == '\\' || *lpszPath == '/') {
					if (szt[0] && access(szt, F_OK))
						if (mkdir(szt, S_IROTH | S_IXOTH | S_IRWXU | S_IRWXG))
							return false;
					*pct = '/';
					pct++;
					*pct = '\0';
					cl = '/';
				}
				else {
					*pct = *lpszPath;
					cl = *pct;
					pct++;
					*pct = '\0';
				}
				lpszPath++;
			}
			if (cl != '/' && access(szt, F_OK))
				if (mkdir(szt, S_IROTH | S_IXOTH | S_IRWXU | S_IRWXG))
					return false;
			return true;
		}

		static long long GetDiskSpace(const char* sroot) //
		{
			struct statfs diskInfo;

			if (-1 == statfs(sroot, &diskInfo))
				return 0;

			long long blocksize = diskInfo.f_bsize;
			unsigned long long  freeDisk = diskInfo.f_bfree*blocksize;
			freeDisk >>= 20; //MB
			return (long long)freeDisk;
		}
		static bool GetExePath(char spath[512]) // last char is '/'
		{
			char sopath[1024] = { 0, };
			int n = readlink("/proc/self/exe", sopath, 511);
			while (n > 0 && sopath[n - 1] != '/')
			{
				n--;
				sopath[n] = 0;
			}
			if (n > 0 && sopath[n - 1] != '/')
				strcat(sopath, "/");
			return snprintf(spath, 512, "%s", sopath) > 0;
		}
		static bool GetAppName(char appname[256]) //
		{
			char sopath[1024] = { 0, };
			int n = readlink("/proc/self/exe", sopath, 511);
			while (n > 0 && sopath[n - 1] != '/')
				n--;
			if (n > 0 && sopath[n - 1] != '/') {
				strcpy(appname, &sopath[n]);
				return true;
			}
			return false;
		}
	private:
		static bool Lock(int nfd, long long offset, long long lsize, bool bwrite)
		{
			struct flock    lock;

			if (bwrite)
				lock.l_type = F_WRLCK;  /* F_RDLCK, F_WRLCK, F_UNLCK */
			else
				lock.l_type = F_RDLCK;

			lock.l_start = offset;    /* byte offset, relative to l_whence */
			lock.l_whence = SEEK_SET; /* SEEK_SET, SEEK_CUR, SEEK_END */
			lock.l_len = lsize;       /* #bytes (0 means to EOF) */
			lock.l_pid = getpid();
			return !(fcntl(nfd, F_SETLKW, &lock) < 0);
		}

		static bool Unlock(int nfd, long long offset, long long lsize)
		{
			struct flock    lock;

			lock.l_type = F_UNLCK;  /* F_RDLCK, F_WRLCK, F_UNLCK */
			lock.l_start = offset;    /* byte offset, relative to l_whence */
			lock.l_whence = SEEK_SET; /* SEEK_SET, SEEK_CUR, SEEK_END */
			lock.l_len = lsize;       /* #bytes (0 means to EOF) */
			lock.l_pid = getpid();

			return !(fcntl(nfd, F_SETLKW, &lock) < 0);

		}
	public:

		static long long filesize(const char* utf8file)
		{
			struct stat statbuf;
			if (!::stat(utf8file, &statbuf))
				return (long long)statbuf.st_size;
			return -1;
		}

		static bool filestat(const char* sfile, t_stat *pout) {
			struct stat statbuf;
			if (!::stat(sfile, &statbuf)) {
				pout->size = statbuf.st_size;
				pout->mtime = statbuf.st_mtim.tv_sec;
				pout->ctime = statbuf.st_ctim.tv_sec;
				return true;
			}
			return false;
		}

		/*!
		\brief lock read whole file for linux

		S_IRWXU  00700 user (file owner) has read, write and execute permission
		S_IRUSR  00400 user has read permission
		S_IWUSR  00200 user has write permission
		S_IXUSR  00100 user has execute permission
		S_IRWXG  00070 group has read, write and execute permission
		S_IRGRP  00040 group has read permission
		S_IWGRP  00020 group has write permission
		S_IXGRP  00010 group has execute permission
		S_IRWXO  00007 others have read, write and execute permission
		S_IROTH  00004 others have read permission
		S_IWOTH  00002 others have write permission
		S_IXOTH  00001 others have execute permission
		*/
		static bool	LckRead(const char* utf8file, vector<char> *pout)
		{
			int nfd = ::open(utf8file, O_RDONLY, S_IROTH | S_IRUSR | S_IRGRP);
			if (nfd == -1)
				return false;
			long long  size = filesize(utf8file);
			if (size <= 0) {
				::close(nfd);
				pout->clear();
				return false;
			}
			pout->clear();
			pout->set_grow((size_t)size);
			char tmp[1024 * 32];
			ssize_t nr;
			if (!Lock(nfd, 0, 0, false))
			{
				::close(nfd);
				return false;
			}
			while (1)
			{
				nr = ::read(nfd, tmp, sizeof(tmp));
				if (nr <= 0)
					break;
				pout->add(tmp, nr);
			}
			Unlock(nfd, 0, 0);
			::close(nfd);
			return pout->size() > 0;
		}
#endif
	};
	class cdir
	{
	public:
		cdir(const char* spath)//spath with'/'
		{
#ifdef _WIN32
			char szFilter[512];
			snprintf(szFilter, sizeof(szFilter), "%s*.*", spath);
			hFind = FindFirstFileA(szFilter, &FindFileData);
#else
			dir = opendir(spath);
#endif
		}
		~cdir() {
#ifdef _WIN32
			if (hFind != INVALID_HANDLE_VALUE)
			{
				FindClose(hFind);
				hFind = INVALID_HANDLE_VALUE;
			}
#else
			if (dir) {
				closedir(dir);
				dir = nullptr;
			}
#endif
		}
	protected:
#ifdef _WIN32
		WIN32_FIND_DATAA FindFileData;
		HANDLE hFind;// = INVALID_HANDLE_VALUE;
		bool bfind;
#else
		DIR * dir;
#endif
	public:
		bool next(char *sout, size_t sizeout) {
#ifdef _WIN32

			if (hFind != INVALID_HANDLE_VALUE)
			{
				char* pc = FindFileData.cFileName;
				ec::str_lcpy(sout, pc, sizeout);
				if (!FindNextFileA(hFind, &FindFileData)) {
					FindClose(hFind);
					hFind = INVALID_HANDLE_VALUE;
				}				
				return true;
			}
			return false;
#else
			if (!dir)
				return false;
			struct dirent *d = readdir(dir);
			if (d) {
				ec::str_lcpy(sout, d->d_name, sizeout);
				return true;
			}
			closedir(dir);
			dir = nullptr;
			return false;
#endif
		}
	};
}; // ec


