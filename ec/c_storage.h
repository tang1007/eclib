/*!
\file c_storage.h
simple storage

ec library is free C++ library.

\author	 kipway@outlook.com

*/
#pragma once
#ifndef C_STORAGE_H
#define C_STORAGE_H

#ifndef _WIN32
#include <errno.h>
#endif

#include "c_file.h"
#include "c_str.h"
#include "c_crc32.h"
#define VERSION_MINS 0xa1c70100 //version

#define MINS_ERR_FAILED        (-1) //failed
#define MINS_ERR_HEAD          (-2) //head error
#define MINS_ERR_DIRFULL       (-3) //directory is full
#define MINS_ERR_OVERSIZE      (-4) //over size
#define MINS_ERR_EXIST         (-5) //alreay exist
#define MINS_ERR_NOTEXIST      (-6) //not exist
#define MINS_ERR_BADDIR        (-7) //bad directory
#define MINS_ERR_ISOPEN        (-8) //already open
#define MINS_ERR_NOTOPEN       (-9) //not open
#define MINS_ERR_STRAEM        (-10)//stream error

#define MINS_PAGE_INVALIDATE  0xFFFFFFFF   // invalidte page no

namespace ec
{
    /*!
    \brief sample storage
    */
    class cStorage : public cFile
    {
    public:
        struct t_head //save in first page pos 0 Little Endian
        {
            char sappid[48]; // application save string,can't change
            unsigned int version;     //0xa1c70100
            unsigned int size_page;   //size of page
            unsigned int size_dir;    //sizeof one directory
            unsigned int pgs_dir;     //directory page number       
            unsigned int pgpos_pat;   //positon of page alloc,1 + pgs_dir;
            unsigned int pgs_pat;     //page alloc page number
            unsigned int pgpos_data;  //data page start position pgpos_pat + pgs_pat            

            unsigned int crc32;       //from version to pgpos_data CRC32
        };//sizeof() = 80

        struct t_dir //directory item, Little Endian
        {
            unsigned int    flag;       //0:empty,D0 = 1 use
            unsigned int    datasize;   //
            char            name[32];   //
            char            cres[4];    //
            unsigned int    pagenum;    //
            unsigned int    pagenos[];  //
        };//sizeof() = 48

        struct t_dirinfo //directory infomation
        {
            unsigned int    datasize;   //
            char            name[32];   //
            char            cres[4];    //
        };
        cStorage()
        {
            _lasterror = 0;
            _nextpageno = 0;
            memset(&_head, 0, sizeof(_head));
            _head.size_dir = 512;
        }
        virtual ~cStorage()
        {
        }
        inline unsigned int swapu(unsigned int v)
        {
            return  (v << 24) | (v >> 24) | ((v & 0xff00) << 8) | ((v & 0xff0000) >> 8);
        }
    protected:
        static const int    _appargspos = 512; //app args postion
        static const size_t _appargslen = 512; //app args length

        t_head  _head;
        int     _lasterror;
        unsigned int _nextpageno; //position for next alloc pages, optimize for speed
    protected:
        bool IsLe() // is Little endian
        {
            union {
                unsigned int uv;
                char cv[4];
            }v;
            v.uv = 0x04030201;
            return (v.cv[0] == 1);
        }
        void LeSwap(unsigned int *pu)
        {
            if (IsLe())
                return;
            *pu = swapu(*pu);
        }
        void LeSwap(t_dir* p)
        {
            if (IsLe())
                return;
            p->flag = swapu(p->flag);
            p->datasize = swapu(p->datasize);
            p->pagenum = swapu(p->pagenum);
            unsigned int i;
            for (i = 0; i < p->pagenum && i < MaxStreamPageNum(); i++)
                p->pagenos[i] = swapu(p->pagenos[i]);
        }
        void LeSwap(t_head* p)
        {
            if (IsLe())
                return;
            p->version = swapu(p->version);
            p->size_page = swapu(p->size_page);
            p->size_dir = swapu(p->size_dir);
            p->pgs_dir = swapu(p->pgs_dir);
            p->pgpos_pat = swapu(p->pgpos_pat);
            p->pgs_pat = swapu(p->pgs_pat);
            p->pgpos_data = swapu(p->pgpos_data);
            p->crc32 = swapu(p->crc32);
        }
        void SetSystemLastError()
        {
#ifdef _WIN32
            _lasterror = ::GetLastError();
#else
            _lasterror = errno;
#endif
        }
        bool CheckStream(void* pf)
        {
            if (!IsOpen()) {
                _lasterror = MINS_ERR_NOTOPEN;
                return false;
            }
            _lasterror = MINS_ERR_STRAEM;
            if (!pf)
                return false;
            t_dir* pdir = (t_dir*)pf;
            if (pdir->datasize > MaxStreamSize()
                || pdir->pagenum > MaxStreamPageNum()
                || !pdir->name[0]
                || !(pdir->flag & 0x01)
                )
                return false;
            _lasterror = 0;
            return true;
        }

        bool CreateHead(const char* sappid, unsigned int sizepage, unsigned int sizedir, unsigned int pagesdir, unsigned pagespat)
        {
            if (sizepage < 10 || sizepage > 16 || sizedir < 6 || sizedir > 15)
                return false;
            if (!pagesdir || !pagespat)
                return false;

            memset(&_head, 0, sizeof(_head));
            ec::str_ncpy(_head.sappid, sappid, sizeof(_head.sappid)-1);
            _head.version = VERSION_MINS;
            _head.size_page = 0x01 << sizepage;
            _head.size_dir = 0x01 << sizedir;
            _head.pgs_dir = pagesdir;
            _head.pgs_pat = pagespat;
            _head.pgpos_pat = 1 + _head.pgs_dir;
            _head.pgpos_data = _head.pgpos_pat + _head.pgs_pat;
            _head.crc32 = ec::crc32(&_head, sizeof(_head) - 4);
            return true;
        }

        void*  FindDirIdx(const char* sname, int &idx) //return >= 0 index; -1: no dir
        {
            idx = -1;
            if (Seek(_head.size_page, seek_set) < 0) {
                SetSystemLastError();
                return 0;
            }
            t_dir* pdir = (t_dir*)malloc(_head.size_dir);
            if (!pdir) {
                _lasterror = MINS_ERR_HEAD;
                return 0;
            }
            int i, n = (int)MaxDirNum();
            for (i = 0; i < n; i++)
            {
                if (Read(pdir, _head.size_dir) != (int)_head.size_dir) {
                    SetSystemLastError();
                    break;
                }
                LeSwap(pdir);
                if (pdir->flag && !strncmp(sname, pdir->name, sizeof(pdir->name))) {
                    idx = i;
                    break;
                }
            }
            if (idx >= 0) {
                _lasterror = 0;
                return pdir;
            }
            _lasterror = MINS_ERR_NOTEXIST;
            free(pdir);
            return 0;
        }

        int WriteDir(t_dir* pdirw)
        {
            t_dir th;
            int i, n = (int)MaxDirNum();
            for (i = 0; i < n; i++)
            {
                if (ReadFrom(_head.size_page + i * _head.size_dir, &th, sizeof(th)) < 0)
                {
                    SetSystemLastError();
                    return -1;
                }
                LeSwap(&th); // memery
                if (th.flag && !strncmp(th.name, pdirw->name, sizeof(pdirw->name)))
                {
                    LeSwap(pdirw); // to disk
                    if (WriteTo(_head.size_page + _head.size_dir * i, pdirw, _head.size_dir) < 0)
                    {
                        SetSystemLastError();
                        LeSwap(pdirw); // to memery
                        return -1;
                    }
                    LeSwap(pdirw);//  to memery
                    return 0;
                }
            }
            _lasterror = MINS_ERR_NOTEXIST;
            return -1;
        }

        unsigned int AllocPage() //alloc one data page,success return pgaeno; failed return MINS_PAGE_INVALIDATE
        {
            unsigned char uzero = 0, uct;
            unsigned int i, j, ubytes = MaxDataPageNum() / 8, pgno, ucpos = _nextpageno / 8;
            if (Seek(_head.size_page * _head.pgpos_pat + ucpos, seek_set) < 0) {
                SetSystemLastError();
                return MINS_PAGE_INVALIDATE;
            }
            for (i = ucpos; i < ubytes; i++)
            {
                if (1 != Read(&uct, 1)) {
                    SetSystemLastError();
                    return MINS_PAGE_INVALIDATE;
                }
                if (uct == 0xFF)
                    continue;
                for (j = 0; j < 8; j++)
                {
                    if (!(uct & (0x01 << j)))
                    {
                        pgno = i * 8 + j;
                        uct |= 0x01 << j;
                        if (WriteTo(_head.size_page * _head.pgpos_pat + i, &uct, 1) < 0)
                        {
                            SetSystemLastError();
                            return MINS_PAGE_INVALIDATE;
                        }
                        if (Seek((pgno + _head.pgpos_data)* _head.size_page + _head.size_page - 1, seek_set) < 0 || Write(&uzero, 1) < 0)
                        {
                            SetSystemLastError();
                            FreePage(pgno);
                            return MINS_PAGE_INVALIDATE;
                        }
                        _nextpageno = i * 8;
                        return pgno;
                    }
                }
            }
            _lasterror = MINS_ERR_OVERSIZE;
            return MINS_PAGE_INVALIDATE;
        }

        int FreePage(unsigned int pgno)
        {
            if (pgno >= MaxDataPageNum()) {
                _lasterror = MINS_PAGE_INVALIDATE;
                return -1;
            }
            unsigned char uc = 0;
            if (ReadFrom(_head.size_page * _head.pgpos_pat + pgno / 8, &uc, 1) < 0) {
                SetSystemLastError();
                return -1;
            }
            uc &= ~(0x01 << (pgno % 8));
            if (WriteTo(_head.size_page * _head.pgpos_pat + pgno / 8, &uc, 1) < 0) {
                SetSystemLastError();
                return -1;
            }
            if (_nextpageno > pgno)
                _nextpageno = pgno;
            return 0;
        }



    public:
        inline int GetLastErr() {
            return _lasterror;
        }

        inline unsigned int MaxDirNum()
        {
            return (_head.pgs_dir * _head.size_page) / _head.size_dir;
        }

        inline unsigned int MaxStreamPageNum()
        {
            return (_head.size_dir - sizeof(t_dir)) / 4;
        }

        inline unsigned int MaxStreamSize()
        {
            return _head.size_page * MaxStreamPageNum();
        }
        inline unsigned int MaxDataPageNum()
        {
            return _head.pgs_pat * _head.size_page * 8;
        }
        inline const char* GetAppId()
        {
            return _head.sappid;
        }
        inline unsigned int StreamSize(void* pf) {
            return ((t_dir*)pf)->datasize;
        }

        void printfstreaminfo(void*pf)
        {
            t_dir* pdir = (t_dir*)pf;
            printf("name:%s\n", pdir->name);
            printf("size:%u\n", pdir->datasize);
            printf("pagenum:%u\n", pdir->pagenum);
            unsigned int i;
            for (i = 0; i < pdir->pagenum; i++)
            {
                printf("%u\t", pdir->pagenos[i]);
                if (!(i % 8))
                    printf("\n");
            }
        }

        /*!
        \brief create mini storage
        \param sfile [in] file name,full path
        \param sappid [in] appid,< 48 bytes
        \param sizepage [in] page size[10,16]; 0x01 << sizepage,10=1024,12=4096,13=8192,14=16384,15=32768,16=65536
        \param sizedir [in] dir item size[6,15]; 0x01 << sizedir, 6=64,10=1024,12=4096,15=32768;
        \param pgsdir [in] dir pages
        \param patpags [in] page alloc pages
        return 0:success; -1 failed , error code int _lasterror
        \remark can't change args ofter create
        */
        int CreateStorage(const char *sfile, const char* sappid, unsigned int sizepage, unsigned int sizedir, unsigned int pgsdir, unsigned patpgs,bool writethrough = true)
        {
            _lasterror = 0;
            if (IsOpen()) {
                _lasterror = MINS_ERR_ISOPEN;
                return -1;
            }
            if (!CreateHead(sappid, sizepage, sizedir, pgsdir, patpgs)) {
                _lasterror = MINS_ERR_FAILED;
                return -1;
            }
            unsigned int uflag = OF_CREAT | OF_RDWR;
            if (writethrough)
                uflag |= OF_SYNC;

            if (!Open(sfile, uflag, OF_SHARE_READ | OF_SHARE_WRITE)) {
                SetSystemLastError();
                return -1;
            }
            Lock(0, (long long)(_head.pgpos_data * _head.size_page), true);
            char *page = (char*)malloc(_head.size_page);
            while (1)
            {
                unsigned int i;
                memset(page, 0, _head.size_page);
                for (i = 0; i < _head.pgpos_data; i++)
                {
                    if (Write(page, _head.size_page) < 0)
                    {
                        SetSystemLastError();
                        break;
                    }
                }
                if (!_lasterror)
                {
                    LeSwap(&_head); // to disk format
                    if (WriteTo(0, &_head, (unsigned int)sizeof(_head)) < 0)
                        SetSystemLastError();
                    LeSwap(&_head);// restore memery format
                }
                break;
            }
            Unlock(0, (long long)(_head.pgpos_data * _head.size_page));
            free(page);
            return _lasterror == 0 ? 0 : -1;
        }

        /*!
        \brief open storage
        \return 0:ok; -1 error and _lasterror set error code
        */
        int OpenStorage(const char *sfile,bool writethrough = true)
        {
            _lasterror = 0;
            if (IsOpen()) {
                _lasterror = MINS_ERR_ISOPEN;
                return -1;
            }
            unsigned int uflag = OF_RDWR;
            if (writethrough)
                uflag |= OF_SYNC;
            if (!Open(sfile, uflag, OF_SHARE_READ | OF_SHARE_WRITE)) {
                SetSystemLastError();
                return -1;
            }
            Lock(0, (long long)sizeof(_head), true);
            while (1)
            {
                if (!ReadFrom(0, &_head, (unsigned int)sizeof(_head)))
                {
                    SetSystemLastError();
                    break;
                }
                LeSwap(&_head); // to memery format
                if (_head.crc32 != ec::crc32(&_head, sizeof(_head) - 4))
                    _lasterror = -1;
                break;
            }
            Unlock(0, (long long)sizeof(_head));
            return _lasterror == 0 ? 0 : -1;;
        }

        /*!
        \brief write user args,max 512 bytes
        \return return write bytes; -1 failed _lasterror
        */
        int WriteAppArgs(const void* pdata, size_t len)
        {
            _lasterror = 0;
            if (!IsOpen()) {
                _lasterror = MINS_ERR_ISOPEN;
                return -1;
            }
            if (len > _appargslen) {
                _lasterror = MINS_ERR_OVERSIZE;
                return -1;
            }
            int nw = WriteTo(_appargspos, pdata, (unsigned int)len);
            if (nw < 0) {
                SetSystemLastError();
                return -1;
            }
            return nw;
        }

        /*!
        \brief read App Args
        \return return >=0:read bytes, -1:failed
        */
        int ReadAppArgs(void* pdata, size_t len)
        {
            _lasterror = 0;
            if (!IsOpen()) {
                _lasterror = MINS_ERR_ISOPEN;
                return -1;
            }
            int nr;
            size_t n = len;
            if (len > _appargslen)
                n = _appargslen;
            nr = ReadFrom(_appargspos, pdata, (unsigned int)n);
            if (nr < 0) {
                SetSystemLastError();
                return -1;
            }
            return nr;
        }

        /*!
        \brief close stream
        */
        int CloseStream(void* pf)
        {
            if (!CheckStream(pf))
                return -1;
            memset(pf, 0, (sizeof(t_dir)));
            free(pf);
            return 0;
        }
        /*!
        \brief create one stream
        \param sname [in] 
        \param nidx [in] create at nidx,-1 is any where
        \return return void* ; 0:failed and set _lasterror
        \remark When you no longer use, use CloseStream release flow
        */
        void* CreateStream(const char* sname, int nidx = -1)
        {
            _lasterror = 0;
            if (!IsOpen()) {
                _lasterror = MINS_ERR_NOTOPEN;
                return 0;
            }
            int i, n = (int)MaxDirNum(), npos = -1;
            if (Seek(_head.size_page, seek_set) < 0) {
                SetSystemLastError();
                return 0;
            }
            t_dir* pdir = (t_dir*)malloc(_head.size_dir);
            for (i = 0; i < n; i++)
            {
                if (Read(pdir, _head.size_dir) != (int)_head.size_dir)
                {
                    SetSystemLastError();
                    free(pdir);
                    return 0;
                }
                LeSwap(pdir);
                if (!pdir->flag)
                {
                    if ((npos < 0) && (nidx == -1 || nidx == i))
                        npos = i;
                    continue;
                }
                if (!strncmp(sname, pdir->name, sizeof(pdir->name))) {
                    _lasterror = MINS_ERR_EXIST;
                    free(pdir);
                    return 0;
                }
            }
            if (npos < 0)
            {
                _lasterror = MINS_ERR_DIRFULL;
                free(pdir);
                return 0;
            }
            memset(pdir, 0, _head.size_dir);
            pdir->flag = 1;
            ec::str_ncpy(pdir->name, sname, sizeof(pdir->name)-1);
            LeSwap(pdir);// to disk
            if (WriteTo(_head.size_page + npos * _head.size_dir, pdir, _head.size_dir) < 0)
            {
                SetSystemLastError();
                free(pdir);
                return 0;
            }
            LeSwap(pdir);// back to memery
            return pdir;
        }

        /*!
        \brief open onr stream
        \param sname [in] stream name
        \param nidx [in] open at nidx,-1 is not use
        \return return void* ; 0:failed and set _lasterror
        \remark When you no longer use, use CloseStream release flow
        */
        void* OpenStream(const char* sname,int nidx = -1)
        {
            _lasterror = 0;
            if (!IsOpen()) {
                _lasterror = MINS_ERR_NOTOPEN;
                return 0;
            }
            unsigned int upos = _head.size_page;
            int i = 0, n = (int)MaxDirNum();                
            if (nidx >= 0)
            {
                upos += nidx * _head.size_dir;
                i = nidx;
            }
            if (Seek(upos, seek_set) < 0) {
                SetSystemLastError();
                return 0;
            }
            t_dir* pdir = (t_dir*)malloc(_head.size_dir);            
            for (; i < n; i++)
            {
                if (Read(pdir, _head.size_dir) != (int)_head.size_dir)
                {
                    SetSystemLastError();
                    free(pdir);
                    return 0;
                }
                LeSwap(pdir);
                if (pdir->flag && !strncmp(sname, pdir->name, sizeof(pdir->name)))
                    return pdir;
            }
            _lasterror = MINS_ERR_NOTEXIST;
            return 0;
        }

        bool GetNextDir(int &npos, t_dirinfo *pinfo)// npos start form 0
        {
            if (npos < 0)
                npos = 0;
            _lasterror = 0;
            if (!IsOpen()) {
                _lasterror = MINS_ERR_NOTOPEN;
                return 0;
            }
            if (Seek(_head.size_page + npos * _head.size_dir, seek_set) < 0) {
                SetSystemLastError();
                return 0;
            }
            t_dir* pdir = (t_dir*)malloc(_head.size_dir);
            int n = (int)MaxDirNum();
            for (; npos < n; npos++)
            {
                if (Read(pdir, _head.size_dir) != (int)_head.size_dir)
                {
                    SetSystemLastError();
                    free(pdir);
                    return 0;
                }
                LeSwap(pdir);
                if (pdir->flag)
                {
                    pinfo->datasize = pdir->datasize;
                    memcpy(pinfo->name, pdir->name, sizeof(pinfo->name));
                    free(pdir);
                    npos++;
                    return true;
                }
            }
            return false;
        }

        unsigned int GetStreamSize(void* pf)
        {
            t_dir* pdir = (t_dir*)pf;
            return pdir->datasize;
        }

        /*!
        \brief read  data from stream
        \return return read bytes;-1:failed and set _lasterror error code
        */
        int ReadStream(void* pf, unsigned int pos, void* pout, unsigned int sizebuf)
        {
            if (!CheckStream(pf))
                return -1;

            int nr;
            unsigned int pg, upos = pos, upgoff, uread = 0, upgr;
            unsigned char* pd = (unsigned char*)pout;
            long long loff;

            t_dir* pdir = (t_dir*)pf;
            pg = upos / _head.size_page;
            while (uread < sizebuf && upos < pdir->datasize && pg < pdir->pagenum && pg < MaxStreamPageNum())
            {
                upgoff = upos % _head.size_page;
                upgr = _head.size_page - upgoff; //<= page size
                if (upgr + upos > pdir->datasize)//<= datasize
                    upgr = pdir->datasize - upos;
                if (upgr + uread > sizebuf)      //<= sizebuf
                    upgr = sizebuf - uread;
                if (!upgr)
                    break;
                if (pdir->pagenos[pg] > MaxDataPageNum())
                {
                    _lasterror = MINS_ERR_BADDIR;
                    return -1;
                }
                loff = (long long)_head.size_page * (_head.pgpos_data + pdir->pagenos[pg]) + upgoff;
                nr = ReadFrom(loff, pd + uread, upgr);
                if (nr < 0)
                {
                    SetSystemLastError();
                    return -1;
                }
                uread += (unsigned int)nr;
                upos += (unsigned int)nr;
                pg = upos / _head.size_page;
            }
            return (int)uread;
        }

        /*
        \brief write data to stream
        \param pos [in] write position
        \return >=0:write bytes 。-1:failed and set errocode to _lasterror
        \remark write position can > data size, max bytes<MaxStreamSize()
        */
        int WriteStream(void* pf, unsigned int pos, const void* pinbuf, unsigned int sizebuf)
        {
            if (!pinbuf || !sizebuf)
                return 0;
            if (!CheckStream(pf))
                return -1;

            if (pos + sizebuf > MaxStreamSize()) {
                _lasterror = MINS_ERR_OVERSIZE;
                return -1;
            }

            t_dir* pdir = (t_dir*)pf;
            unsigned int pgnumold = pdir->pagenum, uap, i;
            unsigned int usepgnum = (pos + sizebuf) / _head.size_page;

            if ((pos + sizebuf) % _head.size_page)
                usepgnum++;
            while (pdir->pagenum < usepgnum)//add pages
            {
                uap = AllocPage();
                if (uap == MINS_PAGE_INVALIDATE)
                {
                    for (i = pgnumold; i < pdir->pagenum; i++)  //restore pdir
                    {
                        FreePage(pdir->pagenos[i]);
                        pdir->pagenos[i] = MINS_PAGE_INVALIDATE;
                    }
                    pdir->pagenum = pgnumold;
                    return -1;
                }
                pdir->pagenos[pdir->pagenum++] = uap;
            }

            if (pdir->pagenum != pgnumold) //need write dir item
            {
                if (WriteDir(pdir) < 0)
                {
                    for (i = pgnumold; i < pdir->pagenum; i++) //restore pdir
                    {
                        FreePage(pdir->pagenos[i]);
                        pdir->pagenos[i] = MINS_PAGE_INVALIDATE;
                    }
                    pdir->pagenum = pgnumold;
                    return -1;
                }
            }

            //write data
            int nwr;
            unsigned int pg, upos = pos, upgoff, uw = 0, upgw;
            const unsigned char* pd = (const unsigned char*)pinbuf;
            long long loff;
            pg = upos / _head.size_page;
            while (uw < sizebuf && pg < pdir->pagenum && pg < MaxStreamPageNum())
            {
                upgoff = upos % _head.size_page;
                upgw = _head.size_page - upgoff; // <= page size
                if (upgw + uw > sizebuf)         // <= sizebuf
                    upgw = sizebuf - uw;
                if (!upgw)
                    break;
                if (pdir->pagenos[pg] > MaxDataPageNum())
                {
                    _lasterror = MINS_ERR_BADDIR;
                    return -1;
                }
                loff = (long long)_head.size_page * (_head.pgpos_data + pdir->pagenos[pg]) + upgoff;
                nwr = WriteTo(loff, pd + uw, upgw);
                if (nwr < 0)
                {
                    SetSystemLastError();
                    return -1;
                }
                uw += (unsigned int)nwr;
                upos += (unsigned int)nwr;
                pg = upos / _head.size_page;
            }
            if (pos + uw > pdir->datasize)
            {
                pdir->datasize = pos + uw;
                if (WriteDir(pdir) < 0)
                    return -1;
            }
            return (int)uw;
        }

        /*!
        \brief delete stream
        \return 0:success; -1:failed and set _lasterror
        */
        int DeleteStream(const char* sname)
        {
            _lasterror = 0;
            if (!IsOpen()) {
                _lasterror = MINS_ERR_NOTOPEN;
                return -1;
            }
            int idx = -1;
            void* pf = FindDirIdx(sname, idx);
            if (!pf || idx < 0)
                return -1;

            t_dir* pdir = (t_dir*)pf;
            unsigned int uz = 0;
            if (WriteTo(_head.size_page + idx * _head.size_dir, &uz, sizeof(uz)) < 0) {
                SetSystemLastError();
                return -1;
            }
            unsigned int i;
            for (i = 0; i < pdir->pagenum; i++) //free data page
                FreePage(pdir->pagenos[i]);
            free(pf);
            return 0;
        }
        /*!
        \brief compact stream pages,free not use pages
        \return 0:success; -1:failed and set errocode to _lasterror
        */
        int CompactStream(void* pf) //compact stream pages,free not use pages
        {
            t_dir* pdir = (t_dir*)pf;
            unsigned int i, ubk, u = (pdir->datasize % _head.size_page) ? (pdir->datasize / _head.size_page + 1) : (pdir->datasize / _head.size_page);
            if (pdir->pagenum > u)
            {
                ubk = pdir->pagenum;
                pdir->pagenum = u;
                if (WriteDir(pdir) < 0) {
                    pdir->pagenum = ubk;
                    return -1;
                }
                for (i = u; i < ubk; i++) //free data pages
                    FreePage(pdir->pagenos[i]);
            }
            return 0;
        }

        /*!
        \brief set stream size,add or delete page
        \return 0:success; -1:failed and set error code to _lasterror
        */
        int SetStreamSize(void* pf, unsigned int usize)
        {
            char cz = 0;
            unsigned int i;
            t_dir* pdir = (t_dir*)pf;
            if (!CheckStream(pf))
                return -1;
            if (usize > MaxStreamSize()) {
                _lasterror = MINS_ERR_OVERSIZE;
                return -1;
            }
            if (pdir->datasize == usize) {
                CompactStream(pf);
                return 0;
            }
            if (pdir->datasize < usize) //add pages
                return WriteStream(pdir, usize - 1, &cz, 1);

            unsigned int pgnumbk = pdir->pagenum, usizebk = pdir->datasize;
            pdir->datasize = usize;
            pdir->pagenum = (usize % _head.size_page) ? (usize / _head.size_page + 1) : (usize / _head.size_page);
            if (WriteDir(pdir) < 0) {
                pdir->datasize = usizebk;// write dir failed ,restore
                pdir->pagenum = pgnumbk;
                return -1;
            }
            for (i = pdir->pagenum; i < pgnumbk; i++) //free not use pages
                FreePage(pdir->pagenos[i]);
            return 0;
        }
    };
};

#endif //C_STORAGE_H

