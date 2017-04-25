/*!
\file   c_file.h

class cFile

ec library is free C++ library.

\author	 kipway@outlook.com
*/
#ifndef C_FILE_H
#define C_FILE_H

#ifdef _WIN32
#pragma warning(disable:4996)
#include <Windows.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include<sys/types.h>
#include<fcntl.h>
#include<sys/statfs.h>
#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE (-1)
#endif
#endif

namespace ec
{
    class cFile
    {
    public:
        cFile() {
            m_hFile = INVALID_HANDLE_VALUE;
            _sharemode = 0;
        };
        virtual ~cFile()
        {
            Close();
        }
        enum OFlags
        {
            OF_RDONLY = 0x00,
            OF_WRONLY = 0x01,
            OF_RDWR = 0x02,
            OF_CREAT = 0x04,
            OF_SYNC = 0x08,        // wirte througt
            OF_TRUNC = 0x10,       // create file,if exits create it
            OF_SHARE_READ = 0x20,  // only for windows,other open handle can read
            OF_SHARE_WRITE = 0x40  // only for windows,other open handle can write
        };
        enum SeekPosition { seek_set = 0, seek_cur = 1, seek_end = 2 };
    protected:
#ifdef _WIN32
        HANDLE		m_hFile;
#else
        int			m_hFile;
#endif
        int         _sharemode;
    public:
        inline bool IsOpen() { return m_hFile != INVALID_HANDLE_VALUE; };
#ifdef _WIN32

        union UV {
            struct {
                unsigned int  l;
                unsigned int  h;
            };
            long long v;
        };

        bool	 Open(const char* sfile, unsigned int nOpenFlags, unsigned int sharemode = 0) //Open File
        {
            if (!sfile)
                return false;
            _sharemode = sharemode;
            unsigned int dwAccess = 0;
            switch (nOpenFlags & 3)
            {
            case OF_RDONLY:
                dwAccess = GENERIC_READ;
                break;
            case OF_WRONLY:
                dwAccess = GENERIC_WRITE;
                break;
            case OF_RDWR:
                dwAccess = GENERIC_READ | GENERIC_WRITE;
                break;
            default:
                dwAccess = GENERIC_READ;
                break;
            }
            unsigned int dwShareMode = 0;
            if (OF_SHARE_READ & sharemode)
                dwShareMode |= FILE_SHARE_READ;
            if (OF_SHARE_WRITE & sharemode)
                dwShareMode |= FILE_SHARE_WRITE;

            // map modeNoInherit flag
            SECURITY_ATTRIBUTES sa;
            sa.nLength = sizeof(sa);
            sa.lpSecurityDescriptor = NULL;
            sa.bInheritHandle = true;

            unsigned int dwCreateFlag;
            if (nOpenFlags & OF_CREAT)
            {
                if (nOpenFlags & OF_TRUNC)
                    dwCreateFlag = CREATE_ALWAYS;// create file,if exits create it
                else
                    dwCreateFlag = CREATE_NEW;// Creates a new file, only if it does not already exist.
            }
            else
                dwCreateFlag = OPEN_EXISTING;

            unsigned int dwFlags = 0;
            if (nOpenFlags & OF_SYNC)
                dwFlags = FILE_FLAG_WRITE_THROUGH;
            HANDLE hFile = ::CreateFileA(sfile, dwAccess, dwShareMode, &sa,
                dwCreateFlag, dwFlags, NULL);

            if (hFile == INVALID_HANDLE_VALUE)
                return false;

            m_hFile = hFile;
            return true;
        };

        void	 Close() {

            if (m_hFile != INVALID_HANDLE_VALUE)
                ::CloseHandle(m_hFile);
            m_hFile = INVALID_HANDLE_VALUE;
        };

        ///\breif return filepos or -1 with error
        long long	Seek(long long lOff, int nFrom)
        {
            if (m_hFile == INVALID_HANDLE_VALUE)
                return -1;

            LARGE_INTEGER liOff;

            liOff.QuadPart = lOff;
            liOff.LowPart = ::SetFilePointer(m_hFile, liOff.LowPart, &liOff.HighPart,
                nFrom);
            if (liOff.LowPart == 0xFFFFFFFF)
                if (::GetLastError() != NO_ERROR)
                    return -1;
            return liOff.QuadPart;
        };

        ///\breif return number of readbytes or -1 with error
        int Read(void *buf, unsigned int ucount)
        {
            if (m_hFile == INVALID_HANDLE_VALUE)
                return -1;
            DWORD dwRead = 0;
            if (!::ReadFile(m_hFile, buf, ucount, &dwRead, NULL))
                return -1;
            return (int)dwRead;
        }

        ///\breif return number of writebytes or -1 with error
        int Write(const void *buf, unsigned int ucount)
        {
            if (m_hFile == INVALID_HANDLE_VALUE)
                return -1;
            DWORD dwRead = 0;
            if (!::WriteFile(m_hFile, buf, ucount, &dwRead, NULL))
                return -1;
            return (int)dwRead;
        }

        bool Lock(long long offset, long long lsize, bool bExc) // lsize 0 means to EOF
        {
            UV pos, sz;
            pos.v = offset;
            if (!lsize) {
                sz.h = 0xffffffff;
                sz.l = 0xffffffff;
            }
            else
                sz.v = lsize;

            OVERLAPPED	op;
            memset(&op, 0, sizeof(op));
            op.Offset = pos.l;
            op.OffsetHigh = pos.h;

            unsigned int uf = 0;
            if (bExc)
                uf = LOCKFILE_EXCLUSIVE_LOCK;
            return LockFileEx(m_hFile, uf, 0, sz.l, sz.h, &op) != 0;
        }
        bool Unlock(long long offset, long long lsize) // lsize 0 means to EOF
        {
            UV pos, sz;
            pos.v = offset;
            if (!lsize) {
                sz.h = 0xffffffff;
                sz.l = 0xffffffff;
            }
            else
                sz.v = lsize;

            OVERLAPPED	op;
            memset(&op, 0, sizeof(op));
            op.Offset = pos.l;
            op.OffsetHigh = pos.h;

            return UnlockFileEx(m_hFile, 0, sz.l, sz.h, &op) != 0;
        }
#else
        /*!
        \brief open file
        \remark  sharemode no use for linux
        */
        bool Open(const char* sfile, unsigned int nOpenFlags, unsigned int sharemode = 0)
        {
            if (!sfile)
                return false;
            _sharemode = OF_SHARE_READ | OF_SHARE_WRITE;
            int oflags = 0;
            switch (nOpenFlags & 3)
            {
            case OF_RDONLY:
                oflags = O_RDONLY;
                break;
            case OF_WRONLY:
                oflags = O_WRONLY;
                break;
            case OF_RDWR:
                oflags = O_RDWR;
                break;
            default:
                oflags = O_RDONLY;
                break;
            }
            if (nOpenFlags & OF_CREAT)
                oflags |= O_CREAT | O_EXCL;

            if (nOpenFlags & OF_TRUNC)
                oflags |= O_TRUNC;

            unsigned int dwFlag = 0;
            if (nOpenFlags & OF_SYNC)
                dwFlag = O_SYNC | O_RSYNC;

            // 创建文件
            int hFile = ::open64(sfile, oflags, S_IROTH | S_IXOTH | S_IRWXU | S_IRWXG | dwFlag);//must add S_IRWXG usergroup can R&W

            if (hFile == INVALID_HANDLE_VALUE)
                return false;

            m_hFile = hFile;
            return true;
        };

        bool	 Close() {
            if (m_hFile != INVALID_HANDLE_VALUE)
                ::close(m_hFile);
            m_hFile = INVALID_HANDLE_VALUE;
            return true;
        };

        ///\breif return filepos or -1 with error
        long long	Seek(long long lOff, int nFrom)
        {
            if (m_hFile == INVALID_HANDLE_VALUE)
                return -1;
            return ::lseek64(m_hFile, lOff, nFrom);
        };

        ///\breif return number of readbytes or -1 with error
        int Read(void *buf, unsigned int ucount)
        {
            if (m_hFile == INVALID_HANDLE_VALUE)
                return -1;
            ssize_t nr = ::read(m_hFile, buf, ucount);
            return (int)nr;
        }

        ///\breif return number of writebytes or -1 with error
        int Write(const void *buf, unsigned int ucount)
        {
            if (m_hFile == INVALID_HANDLE_VALUE)
                return -1;
            ssize_t nr = ::write(m_hFile, buf, ucount);
            return (int)nr;
        }

        bool Lock(long long offset, long long lsize, bool bExc) // lsize 0 means to EOF
        {
            struct flock    lock;

            if (bExc)
                lock.l_type = F_WRLCK;  /* F_RDLCK, F_WRLCK, F_UNLCK */
            else
                lock.l_type = F_RDLCK;

            lock.l_start = offset;    /* byte offset, relative to l_whence */
            lock.l_whence = SEEK_SET; /* SEEK_SET, SEEK_CUR, SEEK_END */
            lock.l_len = lsize;       /* #bytes (0 means to EOF) */
            lock.l_pid = getpid();
            return !(fcntl(m_hFile, F_SETLKW, &lock) < 0);
        }

        bool Unlock(long long offset, long long lsize) // lsize 0 means to EOF
        {
            struct flock    lock;

            lock.l_type = F_UNLCK;  /* F_RDLCK, F_WRLCK, F_UNLCK */
            lock.l_start = offset;    /* byte offset, relative to l_whence */
            lock.l_whence = SEEK_SET; /* SEEK_SET, SEEK_CUR, SEEK_END */
            lock.l_len = lsize;       /* #bytes (0 means to EOF) */
            lock.l_pid = getpid();

            return !(fcntl(m_hFile, F_SETLKW, &lock) < 0);

        }
#endif
        inline int ReadFrom(long long loff, void *buf, unsigned int ucount)
        {
            if (Seek(loff, seek_set) < 0)
                return -1;
            return Read(buf, ucount);
        };
        inline int WriteTo(long long loff, const void *buf, unsigned int ucount)
        {
            if (Seek(loff, seek_set) < 0)
                return -1;
            return Write(buf, ucount);
        };

#ifdef FILE_GROWN_FILLZERO
        bool FastGrown(int nsize)
        {
            char stmp[32768];
            if (nsize < 0 || Seek(0, seek_end) < 0)
                return false;
            memset(stmp, 0, sizeof(stmp));
            int n = nsize;
            while (n > 0)
            {
                if (n >= (int)sizeof(stmp))
                {
                    if (Write(stmp, (unsigned int)sizeof(stmp)) != (int)sizeof(stmp))
                        return false;
                }
                else
                {
                    if (Write(stmp, (unsigned int)n) != n)
                        return false;
                }
                n -= (int)sizeof(stmp);
            }
#ifdef _WIN32
            if (!::SetEndOfFile(m_hFile))
                return false;
#else            
            fsync(m_hFile);
#endif
            return true;
        }
#else
        bool FastGrown(int nsize)
        {
            if (nsize < 0 || Seek(nsize - 1, seek_end) < 0)
                return false;
            char c = 0;
            if (1 != Write(&c, 1))
                return false;
#ifdef _WIN32
            if (!::SetEndOfFile(m_hFile))
                return false;
#else
            fsync(m_hFile);
#endif
            return true;
            }
#endif
        };//CFile

        /*!
        \brief safe use file lock
        */
    class cSafeFileLock
    {
    public:
        cSafeFileLock(cFile* pf, long long offset, long long lsize, bool bExc)
        {
            _pf = pf;
            _offset = offset;
            _lsize = lsize;
            _bExc = bExc;
            if (_pf)
                _pf->Lock(_offset, _lsize, _bExc);
        }
        ~cSafeFileLock()
        {
            if (_pf)
                _pf->Unlock(_offset, _lsize);
        }
    private:
        cFile* _pf;
        long long _offset;
        long long _lsize;
        bool _bExc;
    };

    };//ec


#endif // C_FILE_H

