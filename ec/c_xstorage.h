
/*!
\file c_xstorage.h
\author	kipway@outlook.com
\update 2018.5.16

eclib class extend storage

class ec::cXStorage

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

#ifndef _WIN32
#include <errno.h>
#endif
#include "c_trace.h"
#include "c_file.h"
#include "c_str.h"
#include "c_crc32.h"
#include "c_stream.h"
#include "c_array.h"
#define ECSTG_VERSION            0xa1c90200 //version

#define ECSTG_ERR_FAILED        (-1) //failed
#define ECSTG_ERR_HEAD          (-2) //head error
#define ECSTG_ERR_DIRFULL       (-3) //directory is full
#define ECSTG_ERR_OVERSIZE      (-4) //over size
#define ECSTG_ERR_EXIST         (-5) //alreay exist
#define ECSTG_ERR_NOTEXIST      (-6) //not exist
#define ECSTG_ERR_BADDIR        (-7) //bad directory
#define ECSTG_ERR_ISOPEN        (-8) //already open
#define ECSTG_ERR_NOTOPEN       (-9) //not open
#define ECSTG_ERR_STRAEM        (-10)//stream error
#define ECSTG_ERR_MEMERY        (-11)//memery failed
#define ECSTG_ERR_NAME          (-12)//文件名重复

#define ECSTG_PAGE_INVALIDATE  0xFFFFFFFF   // invalidte page no

#define ECSTG_PAGE_SIZE         4096 //固定页面大小4K
#define ECSTG_APPDATA_POS       2048 //APP全局数据位置,位于头部的位置，用于存储应用层小量识别信息。
#define ECSTG_APPDATA_MAXSIZE   2048 //APP全局数据大小,

#define ECSTG_ENTRY_EMPTY       0x00
#define ECSTG_ENTRY_FILE        0x46   //'F'
#define ECSTG_ENTRY_DIR         0x44   //'D'

#define ECSTG_PAGE_DIR          0xF1444952  //目录页面
#define ECSTG_PAGE_FAT          0xF346494C  //文件分配表页面

#define ECSTG_PG_ENTRYS         63  //每页面条目数
#define ECSTG_PG_FATPGS         1022//每个FAT页面数据页面存放数
namespace ec
{
    /*!
    \brief 存储磁盘的非应用数据均为big_endian，读入和写入需要转换
    第一个页面存储文件头和用户概要信息。
    接下来的连续页面为创建是定义了页面分配表页面。
    内部每个文件小于4G,文件名和子目录名小于48字符.子目录级数不限制。
    */
    class cXStorage : public cFile
    {
    public:
        struct t_file
        {
            unsigned int entrypgno; //条目所在页面
            int          entrypos;//条目所在页面的的条目位置,[0,62]。
            unsigned int fatpg;   //文件分配表入口页面。
            unsigned int fileppos;//当前文件读写位置。
            unsigned int filesize;//当前文件大小。
            char     sname[48];//文件名
        };
        struct dirent {
            unsigned char  d_type;
            unsigned char  res[3]; //0,0,0
            unsigned int   pgno_in;//入口页面
            unsigned int   size;
            unsigned int   ures;   //保留
            char           d_name[48];
        };
        struct DIR {
            unsigned int pgno_p; //条目所在页面
            int          pos_p;  //条目所在页面的的条目位置,[0,62]。
            unsigned int pgno_in;//目录入口页面。
            char     sname[48];  //文件名
            unsigned int pgno_e; //扫描用页面,当前扫描的页面,ECSTG_PAGE_INVALIDATE表示结束
            int           pos_e; //扫描位置,-1结束
            dirent   entry;
        };
    private:
        int  _lasterror;
        unsigned int _nextpageno; //position for next alloc pages, optimize for speed

        struct t_entry //条目
        {
            unsigned char type;   //ECSTG_ENTRY_EMPTY,ECSTG_ENTRY_FILE,ECSTG_ENTRY_DIRECTORY
            unsigned char res[3]; //0,0,0
            unsigned int  pageno; //入口页面，如果是文件，则为STORAGE_PAGE_FAT页面,如果是目录则为STORAGE_PAGE_DIR页面
            unsigned int  size;   //文件大小
            unsigned int  ures;   //保留
            char name[48];        //条目名    
        };//sizeof() = 64

        struct t_dirpghead
        {
            unsigned int type;   //类型
            unsigned int pgnext; // ECSTG_PAGE_INVALIDATE表示没有;
            unsigned char res[56];//0
        };
        struct t_pg_dir //目录页面是链式的.
        {
            t_dirpghead head;
            t_entry  items[ECSTG_PG_ENTRYS];   //目录入口
        };//sizeof() = 4096
        struct t_pg_fat //文件页面分配表
        {
            unsigned int type;   //类型
            unsigned int pgnext; // STORAGE_PAGE_INVALIDATE表示没有;
            unsigned int pages[1022];//页面分配表,遇到0xFFFFFFFF表示结束
        };
        struct t_head //头部，位于第一个页面的前128字节处
        {
            unsigned int version;   //0xa1c90200
            unsigned int allocpages;//页面分配页面数;1页面=32768个页面(128M), 16页面=2G,32页面=4G,64页面=8G,128页面=16G,256页面=32G,
            char sappid[48];        // application save string,can't change                        
            char res[68];
            unsigned int crc32;     //from version to pgpos_data CRC32
        } _head; //sizeof() = 128
        struct t_pg
        {
            unsigned int upgno;
            char pg[ECSTG_PAGE_SIZE];
        };

    public:
        cXStorage() {
            _lasterror = 0;
            _nextpageno = 0;
            memset(&_head, 0, sizeof(_head));
        }

        /*!
        \brief create mini storage
        \param sfile [in] file name,full path
        \param sappid [in] appid,< 48 bytes
        \param allocpages [in] [1,1024]

        return 0:success; -1 failed , error code int _lasterror
        \remark can't change args ofter create
        */
        int CreateStorage(const char *sfile, const char* sappid, unsigned int allocpages, bool writethrough = true)
        {
            _lasterror = 0;
            if (IsOpen()) {
                _lasterror = ECSTG_ERR_ISOPEN;
                return -1;
            }
            unsigned char tmphead[sizeof(_head)];
            ec::cStream ss(tmphead, sizeof(_head));

            if (!CreateHead(sappid, allocpages, ss)) {
                _lasterror = ECSTG_ERR_FAILED;
                return -1;
            }
            unsigned int uflag = OF_CREAT | OF_RDWR;
            if (writethrough)
                uflag |= OF_SYNC;

            if (!Open(sfile, uflag, OF_SHARE_READ | OF_SHARE_WRITE)) {
                SetSystemLastError();
                return -1;
            }
            Lock(0, 0, true);
            char page[ECSTG_PAGE_SIZE];
            memset(page, 0, ECSTG_PAGE_SIZE);
            while (1)
            {
                unsigned int i;
                for (i = 0; i < _head.allocpages + 1; i++)
                {
                    if (Write(page, ECSTG_PAGE_SIZE) < 0)
                    {
                        SetSystemLastError();
                        break;
                    }
                }
                if (!_lasterror)
                {
                    if (WriteTo(0, tmphead, (unsigned int)sizeof(_head)) < 0)
                        SetSystemLastError();
                }
                break;
            }

            char pg[ECSTG_PAGE_SIZE];
            memset(pg, 0, sizeof(pg));
            unsigned int utype = ECSTG_PAGE_DIR, pgnext = ECSTG_PAGE_INVALIDATE;
            ss.attach(pg, sizeof(pg));
            ss < utype < pgnext;
            if (ECSTG_PAGE_SIZE != WriteTo(static_cast<long long>(GetRootPgno()) * ECSTG_PAGE_SIZE, pg, ECSTG_PAGE_SIZE))
            {
                SetSystemLastError();
                //return -1; // debug 201711/15
            }
            Unlock(0, 0);
            return _lasterror == 0 ? 0 : -1;
        }

        /*!
        \brief open storage
        \return 0:ok; -1 error and _lasterror set error code
        */
        int OpenStorage(const char *sfile, bool writethrough = true)
        {
            _lasterror = 0;
            if (IsOpen()) {
                _lasterror = ECSTG_ERR_ISOPEN;
                return -1;
            }
            unsigned int uflag = OF_RDWR;
            if (writethrough)
                uflag |= OF_SYNC;
            if (!Open(sfile, uflag, OF_SHARE_READ | OF_SHARE_WRITE)) {
                SetSystemLastError();
                return -1;
            }
            unsigned char tmp[sizeof(_head)];
            Lock(0, (long long)sizeof(_head), true);
            while (1)
            {
                if (!ReadFrom(0, tmp, (unsigned int)sizeof(_head)))
                {
                    SetSystemLastError();
                    break;
                }
                ec::cStream ss(tmp, sizeof(_head));
                memset(&_head, 0, sizeof(_head));
                try
                {
                    ss > &_head.version > &_head.allocpages;
                    ss.read(_head.sappid, sizeof(_head.sappid)).read(_head.res, sizeof(_head.res));
                    ss > &_head.crc32;
                }
                catch (int)
                {
                    _lasterror = ECSTG_ERR_MEMERY;
                    break;// return -1; //debug 2017//11/15
                }
                if (_head.crc32 != ec::crc32(tmp, sizeof(_head) - 4))
                    _lasterror = -1;
                break;
            }
            Unlock(0, (long long)sizeof(_head));
            return _lasterror == 0 ? 0 : -1;
        }
                
        bool DelFile(const char* sfile)
        {
            t_file* pf = fOpen(sfile, false);
            if (!pf)
                return true;
            ec::tArray<unsigned int> fat(4096);
            bool bret = false;                        
            if (LoadFat(pf, &fat) && DelFileEntry(pf->entrypgno, pf->entrypos))
            {
                int i;
                for (i = 0; i < fat.GetNum(); i++)
                    FreePage(fat[i]);
                FreePage(pf->fatpg);
                bret = true;
            }
            fClose(pf);
            return bret;            
        }

        ec::cXStorage::t_file* fOpen(const char* sname, bool bCreate)
        {
            _lasterror = 0;
            if (!IsOpen()) {
                _lasterror = ECSTG_ERR_NOTOPEN;
                return 0;
            }

            t_file f;
            ec::tArray<t_file> fs(4);
            size_t namesize = strlen(sname), sizeitem;
            if (!namesize)
                return 0;
            if (*(sname + namesize - 1) == '/' || *(sname + namesize - 1) == '\\')
                return 0;
            char stmp[512];
            ec::cStrSplit sp(sname);

            while (sp.next("/\\", stmp, sizeof(stmp), &sizeitem))
            {
                if (sizeitem >= sizeof(f.sname) - 1)
                    return 0;
                memset(&f, 0, sizeof(f));
                strcpy(f.sname, stmp);
                fs.Add(&f, 1);
            }

            int i;
            unsigned int upg_pre = GetRootPgno();
            t_file *pf = fs.GetBuf();
            for (i = 0; i < fs.GetNum(); i++)
            {
                if (i != fs.GetNum() - 1) //dir
                {
                    pf[i].fatpg = OpenOneEntry(upg_pre, ECSTG_ENTRY_DIR, pf[i].sname, bCreate, &pf[i].entrypgno, &pf[i].entrypos, &pf[i].filesize);
                    if (pf[i].fatpg == ECSTG_PAGE_INVALIDATE)
                        return 0;
                    upg_pre = pf[i].fatpg;
                }
                else
                {
                    pf[i].fatpg = OpenOneEntry(upg_pre, ECSTG_ENTRY_FILE, pf[i].sname, bCreate, &pf[i].entrypgno, &pf[i].entrypos, &pf[i].filesize);
                    if (pf[i].fatpg == ECSTG_PAGE_INVALIDATE)
                        return 0;
                    t_file* pfile = new t_file;
                    memcpy(pfile, &pf[i], sizeof(t_file));
                    return pfile;
                }
            }
            return 0;
        }

        void fClose(ec::cXStorage::t_file* pf)
        {
            if (!IsOpen())
                return;
            if (pf)
                delete pf;
        }
        inline void fSeek(ec::cXStorage::t_file* pf, unsigned int upos)
        {
            pf->fileppos = upos;
        }

        inline unsigned int GetSeek(ec::cXStorage::t_file* pf)
        {
            return pf->fileppos;
        }
        inline void fSeektoEnd(ec::cXStorage::t_file* pf)
        {
            pf->fileppos = pf->filesize;
        }

        int fWrite(ec::cXStorage::t_file* pf, const void* pdate, int nsize)
        {
            _lasterror = 0;
            if (!IsOpen()) {
                _lasterror = ECSTG_ERR_NOTOPEN;
                return -1;
            }
            if (!pf)
                return -1;
            bool bext = false;
            unsigned int upg;
            ec::tArray<unsigned int> fat(4096);
            if (!LoadFat(pf, &fat))
                return -1;
            while (pf->fileppos + nsize > fat.GetSize() * ECSTG_PAGE_SIZE) //扩展页面
            {
                upg = AllocPage();
                if (upg == ECSTG_PAGE_INVALIDATE)
                    return -1;
                fat.Add(upg);
                bext = true;
            }
            if (bext)
            {
                if (!writeFat(pf, &fat))
                    return -1;
            }
            int nw = 0, nwp;
            const char* ps = (const char*)pdate;
            while (nw < nsize)
            {
                upg = pf->fileppos / ECSTG_PAGE_SIZE;
                nwp = ECSTG_PAGE_SIZE - (int)(pf->fileppos % ECSTG_PAGE_SIZE);
                if (nwp > nsize - nw)
                    nwp = nsize - nw;
                if (nwp != WriteTo(fat[upg] * ECSTG_PAGE_SIZE + pf->fileppos % ECSTG_PAGE_SIZE, ps + nw, nwp))
                    return -1;
                pf->fileppos += nwp;
                nw += nwp;
            }
            if (pf->fileppos > pf->filesize) //更改文件字节数
            {
                pf->filesize = pf->fileppos;
                WriteFileEntrySize(pf, pf->filesize);
            }
            return nsize;
        }

        int fRead(ec::cXStorage::t_file* pf, void* pbuf, int nbufsize)
        {
            _lasterror = 0;
            if (!IsOpen()) {
                _lasterror = ECSTG_ERR_NOTOPEN;
                return -1;
            }

            if (!pf)
                return -1;
            if (pf->fileppos >= pf->filesize)
                return 0;

            unsigned int upgpos;
            int nr = 0, nrp;
            int nsize = nbufsize;
            char* ps = (char*)pbuf;
            if (pf->fileppos + nsize > pf->filesize)
                nsize = (int)(pf->filesize - pf->fileppos);

            ec::tArray<unsigned int> fat(4096);
            if (!LoadFat(pf, &fat))
                return -1;
            upgpos = pf->fileppos / ECSTG_PAGE_SIZE;
            while (nr < nsize && pf->fileppos < pf->filesize && upgpos < fat.GetSize())
            {
                nrp = ECSTG_PAGE_SIZE - (int)(pf->fileppos % ECSTG_PAGE_SIZE);
                if (nrp > nsize - nr)
                    nrp = nsize - nr;
                if (nrp != ReadFrom(fat[upgpos] * ECSTG_PAGE_SIZE + pf->fileppos % ECSTG_PAGE_SIZE, ps + nr, nrp))
                    return -1;
                pf->fileppos += nrp;
                nr += nrp;
                upgpos = pf->fileppos / ECSTG_PAGE_SIZE;
            }
            return nr;
        }

        bool fSetEndFile(ec::cXStorage::t_file* pf) //设置当前文件位置为结束文件位置。
        {
            _lasterror = 0;
            if (!IsOpen()) {
                _lasterror = ECSTG_ERR_NOTOPEN;
                return false;
            }
            if (!pf)
                return false;
            if (pf->fileppos == pf->filesize)
                return true;
            int bfatmod = 0;
            unsigned int upg;
            ec::tArray<unsigned int> fat(4096);
            if (!LoadFat(pf, &fat))
                return false;
            if (pf->fileppos > pf->filesize) //扩展
            {
                while (fat.GetSize() * ECSTG_PAGE_SIZE < pf->fileppos)
                {
                    upg = AllocPage();
                    if (upg == ECSTG_PAGE_INVALIDATE)
                        return false;
                    fat.Add(upg);
                    bfatmod = 1;
                }
            }
            else // 收缩
            {
                if (fat.GetNum() > 1)
                {
                    while (fat.GetSize()  * ECSTG_PAGE_SIZE - ECSTG_PAGE_SIZE > pf->fileppos)
                    {
                        fat.DeleteAt(fat.GetSize() - 1, upg);
                        FreePage(upg);
                        bfatmod = 1;
                    }
                }
            }
            if (bfatmod && !writeFat(pf, &fat))
                return false;
            if (!WriteFileEntrySize(pf, pf->fileppos))
                return false;
            pf->filesize = pf->fileppos;
            return true;
        }

        
        ec::cXStorage::DIR* OpenDir(const char* sname)
        {
            _lasterror = 0;
            if (!IsOpen()) {
                _lasterror = ECSTG_ERR_NOTOPEN;
                return 0;
            }

            ec::cXStorage::DIR f;
            ec::tArray<ec::cXStorage::DIR> fs(4);
            size_t namesize = strlen(sname), sizeitem;
            if (!namesize)
                return 0;

            char stmp[512];
            ec::cStrSplit sp(sname);

            while (sp.next("/\\", stmp, sizeof(stmp), &sizeitem))
            {
                if (sizeitem >= sizeof(f.sname) - 1)
                    return 0;
                memset(&f, 0, sizeof(f));
                strcpy(f.sname, stmp);
                fs.Add(&f, 1);
            }

            int i;
            unsigned int upg_pre = GetRootPgno();
            if (fs.GetNum() == 0) // '/'
            {
                ec::cXStorage::DIR* pdir = new ec::cXStorage::DIR;
                memset(pdir, 0, sizeof(ec::cXStorage::DIR));
                pdir->sname[0] = '/';
                pdir->pgno_p = ECSTG_PAGE_INVALIDATE;
                pdir->pos_p = -1;
                pdir->pgno_in = GetRootPgno();
                pdir->pgno_e = GetRootPgno();
                pdir->pos_e = 0;
                return pdir;
            }
            ec::cXStorage::DIR *pf = fs.GetBuf();
            for (i = 0; i < fs.GetNum(); i++)
            {
                if (i != fs.GetNum() - 1) //dir
                {
                    pf[i].pgno_in = OpenOneEntry(upg_pre, ECSTG_ENTRY_DIR, pf[i].sname, false, 0, 0, 0);
                    if (pf[i].pgno_in == ECSTG_PAGE_INVALIDATE)
                        return 0;
                    upg_pre = pf[i].pgno_in;
                }
                else
                {
                    pf[i].pgno_in = OpenOneEntry(upg_pre, ECSTG_ENTRY_DIR, pf[i].sname, false, &pf[i].pgno_p, &pf[i].pos_p, 0);
                    if (pf[i].pgno_in == ECSTG_PAGE_INVALIDATE)
                        return 0;
                    ec::cXStorage::DIR* pdir = new ec::cXStorage::DIR;
                    memcpy(pdir, &pf[i], sizeof(ec::cXStorage::DIR));
                    pdir->pgno_e = pdir->pgno_in;
                    pdir->pos_e = 0;
                    return pdir;
                }
            }
            return 0;
        }
        void CloseDir(ec::cXStorage::DIR* pdir)
        {
            if (pdir)
                delete pdir;
        }
        /*!
        \brief same as linux , On  success,  ReadDir() returns a pointer to a dirent structure.  (This
       structure is be statically allocated; do not attempt to  free  it.)
       If  the  end  of  the directory stream is reached, NULL is returned
        */
        ec::cXStorage::dirent* ReadDir(ec::cXStorage::DIR* pdir) //do not free the return dirent*;
        {
            _lasterror = 0;
            if (!IsOpen()) {
                _lasterror = ECSTG_ERR_NOTOPEN;
                return 0;
            }

            if (pdir->pgno_e == ECSTG_PAGE_INVALIDATE || pdir->pos_e < 0)
                return 0;
            char page[ECSTG_PAGE_SIZE], cres = 0;
            ec::cStream ss(page, ECSTG_PAGE_SIZE);
            while (pdir->pgno_e != ECSTG_PAGE_INVALIDATE)
            {
                if (ECSTG_PAGE_SIZE != ReadFrom(static_cast<long long>(pdir->pgno_e) * ECSTG_PAGE_SIZE, page, ECSTG_PAGE_SIZE))
                    return 0;
                while (pdir->pos_e < ECSTG_PG_ENTRYS)
                {
                    ss.setpos((1 + pdir->pos_e) * sizeof(t_entry));

                    ss > &pdir->entry.d_type;
                    if (pdir->entry.d_type == ECSTG_ENTRY_FILE || pdir->entry.d_type == ECSTG_ENTRY_DIR)
                    {
                        ss > &pdir->entry.res[0] > &pdir->entry.res[1] > &pdir->entry.res[2];
                        ss > &pdir->entry.pgno_in;
                        ss > &pdir->entry.size;
                        ss > &pdir->entry.ures;
                        ss.read(pdir->entry.d_name, sizeof(pdir->entry.d_name));
                        pdir->pos_e++;
                        if (pdir->pos_e >= ECSTG_PG_ENTRYS) {
                            ss.setpos(4);
                            ss > &pdir->pgno_e;
                            pdir->pos_e = 0;
                        }
                        return &pdir->entry;
                    }
                    pdir->pos_e++;
                }
                ss.setpos(4);
                ss > &pdir->pgno_e;
                pdir->pos_e = 0;
            }
            pdir->pos_e = -1;
            return 0;
        }

        int WriteAppData(const void* pd, int nsize) //写app全局数据，小于2048，返回写入的字节数
        {
            _lasterror = 0;
            if (!IsOpen()) {
                _lasterror = ECSTG_ERR_NOTOPEN;
                return -1;
            }

            if (nsize <= 0 || nsize > ECSTG_APPDATA_MAXSIZE)
                return -1;
            return WriteTo(ECSTG_APPDATA_POS, pd, nsize);
        }
        int ReadAppData(void *pbuf, int nsize)//读app全局数据，小于2048,返回读取到的数据
        {
            _lasterror = 0;
            if (!IsOpen()) {
                _lasterror = ECSTG_ERR_NOTOPEN;
                return -1;
            }
            int n = nsize > ECSTG_APPDATA_MAXSIZE ? ECSTG_APPDATA_MAXSIZE : nsize;
            if (n <= 0)
                return -1;
            return ReadFrom(ECSTG_APPDATA_POS, pbuf, n);

        }
    private:
        inline unsigned int GetRootPgno()
        {
            return 1 + _head.allocpages;
        }

        bool DelFileEntry(unsigned int upg, unsigned int upos)
        {
            char pg[ECSTG_PAGE_SIZE];
            ec::cStream ss(pg, ECSTG_PAGE_SIZE);
            if (ECSTG_PAGE_SIZE != ReadFrom(static_cast<long long>(upg) * ECSTG_PAGE_SIZE, pg, ECSTG_PAGE_SIZE))
                return false;
            ss.setpos((upos + 1) * sizeof(t_entry));
            ss << int(0);
            return 4 == WriteTo(static_cast<long long>(upg) * ECSTG_PAGE_SIZE + (upos + 1) * sizeof(t_entry), &pg[(upos + 1) * sizeof(t_entry)], 4);
        }

        bool LoadFat(ec::cXStorage::t_file* pf, ec::tArray<unsigned int> *pout) //读取文件分配表
        {
            int i;
            unsigned int upgnext = pf->fatpg, utype, upg;
            char pg[ECSTG_PAGE_SIZE];
            ec::cStream ss(pg, ECSTG_PAGE_SIZE);
            pout->ClearData();
            while (upgnext != ECSTG_PAGE_INVALIDATE)
            {
                if (ECSTG_PAGE_SIZE != ReadFrom(static_cast<long long>(upgnext) * ECSTG_PAGE_SIZE, pg, ECSTG_PAGE_SIZE))
                    return false;
                ss.setpos(0);
                ss > &utype > &upgnext;
                if (utype != ECSTG_PAGE_FAT)
                    return false;
                for (i = 0; i < ECSTG_PG_FATPGS; i++)
                {
                    ss > &upg;
                    if (upg == ECSTG_PAGE_INVALIDATE)
                        return true;
                    pout->Add(upg);
                }
            }
            if (pout->GetSize() * ECSTG_PAGE_SIZE < pf->filesize) //error
                return false;
            return true;
        }

        bool writeFat(ec::cXStorage::t_file* pf, ec::tArray<unsigned int> *pin)
        {
            int i, isend = 0;
            unsigned int upgnext = pf->fatpg, utype, upg, uw = 0, *p = pin->GetBuf();
            char pg[ECSTG_PAGE_SIZE];
            ec::cStream ss(pg, ECSTG_PAGE_SIZE);

            while (upgnext != ECSTG_PAGE_INVALIDATE && !isend)
            {
                upg = upgnext;
                if (ECSTG_PAGE_SIZE != ReadFrom(static_cast<long long>(upgnext) * ECSTG_PAGE_SIZE, pg, ECSTG_PAGE_SIZE))
                    return false;
                ss.setpos(0);
                ss > &utype > &upgnext;
                if (utype != ECSTG_PAGE_FAT)
                    return false;

                if (upgnext == ECSTG_PAGE_INVALIDATE && pin->GetSize() - uw >= ECSTG_PG_FATPGS) //扩展一个FAT页面
                {
                    upgnext = AllocOneListPage(ECSTG_PAGE_FAT);
                    if (upgnext == ECSTG_PAGE_INVALIDATE)
                        return false;
                    ss.setpos(4);
                    ss < upgnext;
                }
                for (i = 0; i < ECSTG_PG_FATPGS; i++)
                {
                    if (uw < pin->GetSize()) {
                        ss < p[uw];
                        uw++;
                    }
                    else
                    {
                        ss < (unsigned int)0xffffffff;
                        isend = 1;
                        break;
                    }
                }
                if (ECSTG_PAGE_SIZE != WriteTo(static_cast<long long>(upg) * ECSTG_PAGE_SIZE, pg, ECSTG_PAGE_SIZE)) //写回
                    return false;
            }
            return true;
        }


        unsigned int AllocOneListPage(unsigned int type) //分配一个链式页面
        {
            unsigned int pgno = AllocPage();
            if (pgno == ECSTG_PAGE_INVALIDATE)
                return ECSTG_PAGE_INVALIDATE;
            char pg[ECSTG_PAGE_SIZE];
            memset(pg, 0, sizeof(pg));
            unsigned int  pgnext = ECSTG_PAGE_INVALIDATE;
            ec::cStream ss(pg, sizeof(pg));
            ss < type < pgnext;
            if (type == ECSTG_PAGE_FAT)
                ss < (unsigned int)ECSTG_PAGE_INVALIDATE;
            if (ECSTG_PAGE_SIZE != WriteTo(static_cast<long long>(pgno) * ECSTG_PAGE_SIZE, pg, ECSTG_PAGE_SIZE))
            {
                FreePage(pgno);
                return ECSTG_PAGE_INVALIDATE;
            }
            return pgno;
        }

        /*!
        \param uparent Entry所在目录的入口页面
        \param sname 子目录名或文件名
        \param pentrypgno成功后回填Entry所在目录页面pgno
        \param pentrypos成功后回填Entry所在页面的位置[0,62]。
        \return 返回子目录或文件分配表的入口页面,ECSTG_PAGE_INVALIDATE表示失败
        \remark 目录创建时包含创建一个目录页面
        */
        unsigned int OpenOneEntry(unsigned int uparent, unsigned char entrytype, const char* sname, bool bCreate, unsigned int *pentrypgno, int *pentrypos, unsigned int *psize)
        {
            unsigned int type, pgnext;
            t_pg pgtmp;//读入父目录下全部entry项
            ec::tArray<t_pg> pgs(4);
            ec::cStream ss(pgtmp.pg, ECSTG_PAGE_SIZE);
            pgnext = uparent;
            while (pgnext != ECSTG_PAGE_INVALIDATE)
            {
                pgtmp.upgno = pgnext;
                if (ECSTG_PAGE_SIZE != ReadFrom(static_cast<long long>(pgnext) * ECSTG_PAGE_SIZE, pgtmp.pg, ECSTG_PAGE_SIZE))
                    return ECSTG_PAGE_INVALIDATE;
                ss.setpos(0);
                ss > &type > &pgnext;
                if (type != ECSTG_PAGE_DIR)
                    return ECSTG_PAGE_INVALIDATE;
                pgs.Add(&pgtmp, 1);
            }

            t_pg *p = pgs.GetBuf();//检查是否存在
            int i, nfirstempty_pg = -1, nfirstempty_pos = -1, j;
            t_entry di;
            for (i = 0; i < pgs.GetNum(); i++)
            {
                ss.attach(p[i].pg, ECSTG_PAGE_SIZE);

                for (j = 0; j < ECSTG_PG_ENTRYS; j++)
                {
                    ss.setpos((j + 1) * sizeof(t_entry));
                    ss >> di.type >> di.res[0] >> di.res[1] >> di.res[2];
                    ss > &di.pageno > &di.size > &di.ures;
                    ss.read(di.name, sizeof(di.name));
                    if (di.type == ECSTG_ENTRY_EMPTY)
                    {
                        if (nfirstempty_pg == -1)
                        {
                            nfirstempty_pg = i;
                            nfirstempty_pos = j;
                        }
                    }
                    else
                    {
                        di.name[sizeof(di.name) - 1] = 0;
                        if (!ec::str_icmp(sname, di.name))
                        {
                            if (di.type != entrytype)
                            {
                                _nextpageno = ECSTG_ERR_NAME;
                                return ECSTG_PAGE_INVALIDATE;
                            }
                            if (pentrypgno)
                                *pentrypgno = p[i].upgno;
                            if (pentrypos)
                                *pentrypos = j;
                            if (psize)
                                *psize = di.size;
                            return di.pageno; //已经存在
                        }
                    }
                }
            }
            if (!bCreate)
                return ECSTG_PAGE_INVALIDATE;

            if (nfirstempty_pg == -1) //满，需要新分配一个父目录的链式页面
            {
                unsigned int upgno = AllocOneListPage(ECSTG_PAGE_DIR);//扩展一个目录页面
                if (upgno == ECSTG_PAGE_INVALIDATE)
                    return ECSTG_PAGE_INVALIDATE;

                ss.attach(p[pgs.GetNum() - 1].pg, ECSTG_PAGE_SIZE); //连接到末尾
                ss.setpos(4);
                ss < upgno; //t_pg_dir.pgnext
                if (4 != WriteTo(static_cast<long long>(p[pgs.GetNum() - 1].upgno) * ECSTG_PAGE_SIZE + 4, (char*)p[pgs.GetNum() - 1].pg + 4, 4))
                {
                    FreePage(upgno);
                    return ECSTG_PAGE_INVALIDATE;
                }

                pgtmp.upgno = upgno; //读回新页面
                if (ECSTG_PAGE_SIZE != ReadFrom(static_cast<long long>(upgno) * ECSTG_PAGE_SIZE, pgtmp.pg, ECSTG_PAGE_SIZE))
                    return ECSTG_PAGE_INVALIDATE;
                ss.attach(pgtmp.pg, ECSTG_PAGE_SIZE);
                ss.setpos(0);
                ss > &type > &pgnext;
                if (type != ECSTG_PAGE_DIR)
                    return ECSTG_PAGE_INVALIDATE;
                pgs.Add(&pgtmp, 1);
                nfirstempty_pg = pgs.GetNum() - 1;
                nfirstempty_pos = 0;
                p = pgs.GetBuf();
            }

            t_entry it; //分配入口页面
            memset(&it, 0, sizeof(it));
            it.type = entrytype;
            ec::str_ncpy(it.name, sname, sizeof(it.name)-1);
            if (entrytype == ECSTG_ENTRY_DIR)
                it.pageno = AllocOneListPage(ECSTG_PAGE_DIR);
            else
                it.pageno = AllocOneListPage(ECSTG_PAGE_FAT);
            if (it.pageno == ECSTG_PAGE_INVALIDATE)
                return ECSTG_PAGE_INVALIDATE;
            ss.attach(p[nfirstempty_pg].pg, ECSTG_PAGE_SIZE);//写新建条目
            ss.setpos((1 + nfirstempty_pos) * sizeof(t_entry));
            ss < it.type < it.res[0] < it.res[1] < it.res[2] < it.pageno < it.size < it.ures;
            ss.write(it.name, sizeof(it.name));
            WriteTo(static_cast<long long>(p[nfirstempty_pg].upgno) * ECSTG_PAGE_SIZE + (1 + nfirstempty_pos) * sizeof(t_entry),
                &p[nfirstempty_pg].pg[(1 + nfirstempty_pos) * sizeof(t_entry)], sizeof(t_entry));
            if (pentrypgno)
                *pentrypgno = p[nfirstempty_pg].upgno;
            if (pentrypos)
                *pentrypos = nfirstempty_pos;
            if (psize)
                *psize = 0;
            return it.pageno;
        }

        bool WriteFileEntrySize(ec::cXStorage::t_file* pf, unsigned int size)
        {
            char pg[ECSTG_PAGE_SIZE];
            ec::cStream ss(pg, ECSTG_PAGE_SIZE);
            if (ECSTG_PAGE_SIZE != ReadFrom(static_cast<long long>(pf->entrypgno) * ECSTG_PAGE_SIZE, pg, ECSTG_PAGE_SIZE))
                return false;
            ss.setpos((pf->entrypos + 1) * sizeof(t_entry) + 8);
            ss < size;
            return 4 == WriteTo(static_cast<long long>(pf->entrypgno) * ECSTG_PAGE_SIZE + (pf->entrypos + 1) * sizeof(t_entry) + 8, &pg[(pf->entrypos + 1) * sizeof(t_entry) + 8], 4);
        }

        bool CreateHead(const char* sappid, unsigned int allocpages, ec::cStream &ss)
        {
            if (allocpages > 1024)
                return false;
            memset(&_head, 0, sizeof(_head));
            ec::str_ncpy(_head.sappid, sappid, sizeof(_head.sappid)-1);
            _head.version = ECSTG_VERSION;
            _head.allocpages = allocpages;
            try
            {
                ss.setpos(0) < _head.version < _head.allocpages;
                ss.write(_head.sappid, sizeof(_head.sappid)).write(_head.res, sizeof(_head.res));
                _head.crc32 = ec::crc32(ss.getp(), sizeof(_head) - 4);
                ss < _head.crc32;
            }
            catch (int) { return false; }
            return true;
        }

        void SetSystemLastError()
        {
#ifdef _WIN32
            _lasterror = ::GetLastError();
#else
            _lasterror = errno;
#endif
        }

        unsigned int AllocPage() //alloc one data page,success return pgaeno; failed return MINS_PAGE_INVALIDATE
        {
            unsigned char uzero = 0, uct;
            unsigned int i, j, pgno, ucpos = _nextpageno / 8, ubytes = _head.allocpages * ECSTG_PAGE_SIZE, uret;
            if (Seek(ECSTG_PAGE_SIZE + ucpos, seek_set) < 0) {
                SetSystemLastError();
                return ECSTG_PAGE_INVALIDATE;
            }
            for (i = ucpos; i < ubytes; i++)
            {
                if (1 != Read(&uct, 1)) {
                    SetSystemLastError();
                    return ECSTG_PAGE_INVALIDATE;
                }
                if (uct == 0xFF)
                    continue;
                for (j = 0; j < 8; j++)
                {
                    if (!(uct & (0x01 << j)))
                    {
                        pgno = i * 8 + j;
                        uct |= 0x01 << j;
                        if (WriteTo(ECSTG_PAGE_SIZE + i, &uct, 1) < 0)
                        {
                            SetSystemLastError();
                            return ECSTG_PAGE_INVALIDATE;
                        }
                        uret = pgno + _head.allocpages + 2;
                        if (Seek(static_cast<long long>(uret) * ECSTG_PAGE_SIZE + ECSTG_PAGE_SIZE - 1, seek_set) < 0 || Write(&uzero, 1) < 0)
                        {
                            SetSystemLastError();
                            FreePage(pgno);
                            return ECSTG_PAGE_INVALIDATE;
                        }
                        _nextpageno = i * 8;
                        ECTRACE("- malloc page %u\n", uret);
                        return uret;
                    }
                }
            }
            _lasterror = ECSTG_ERR_OVERSIZE;
            return ECSTG_PAGE_INVALIDATE;
        }

        int FreePage(unsigned int pageno)
        {
            if (pageno == ECSTG_PAGE_INVALIDATE || pageno >= _head.allocpages * ECSTG_PAGE_SIZE * 8 || pageno < _head.allocpages + 2) {
                _lasterror = ECSTG_PAGE_INVALIDATE;
                return -1;
            }
            unsigned int pgno = pageno - _head.allocpages - 2;
            unsigned char uc = 0;
            if (ReadFrom(ECSTG_PAGE_SIZE + pgno / 8, &uc, 1) < 0) {
                SetSystemLastError();
                return -1;
            }
            uc &= ~(0x01 << (pgno % 8));
            if (WriteTo(ECSTG_PAGE_SIZE + pgno / 8, &uc, 1) < 0) {
                SetSystemLastError();
                return -1;
            }
            if (_nextpageno > pgno)
                _nextpageno = pgno;
            ECTRACE("+ free page %u\n", pageno);
            return 0;
        }
    public: //tst
        static  void tst_sizeof()
        {
            printf("sizeof(t_entry) = %d\n", (int)sizeof(ec::cXStorage::t_entry));
            printf("sizeof(t_pg_dir) = %d\n", (int)sizeof(ec::cXStorage::t_pg_dir));
            printf("sizeof(t_pg_fat) = %d\n", (int)sizeof(ec::cXStorage::t_pg_fat));
            printf("sizeof(t_head) = %d\n", (int)sizeof(ec::cXStorage::t_head));
        }
        /*
        void tst_OpenOneEntry()
        {
            char sfile[32] = { 0 };
            int i;
            unsigned int upgno, uroot = GetRootPgno();
            for (i = 0; i < 64; i++)
            {
                sprintf(sfile, "file%d", i);
                if (i == 63)
                    printf("\n");
                upgno = OpenOneEntry(uroot, ECSTG_ENTRY_FILE, sfile, true, 0, 0, 0);
                if (upgno == ECSTG_PAGE_INVALIDATE)
                {
                    printf("OpenOneEntry(create) %s failed\n", sfile);
                    return;
                }
                printf("OpenOneEntry(create) %s success\n", sfile);
                upgno = OpenOneEntry(uroot, ECSTG_ENTRY_FILE, sfile, false, 0, 0, 0);
                if (upgno == ECSTG_PAGE_INVALIDATE)
                {
                    printf("OpenOneEntry(open) %s failed\n", sfile);
                    return;;
                }
                printf("OpenOneEntry(open) %s success\n", sfile);
            }
            ec::cXStorage::DIR* pdir = OpenDir("/");
            if (pdir)
            {
                ec::cXStorage::dirent* d = ReadDir(pdir);
                while (d)
                {
                    printf("Type:%c ; name:%s\n", d->d_type, d->d_name);
                    d = ReadDir(pdir);
                }
                CloseDir(pdir);
            }
            pdir = OpenDir("/dir1/");
            if (pdir)
            {
                ec::cXStorage::dirent* d = ReadDir(pdir);
                while (d)
                {
                    printf("Type:%c ; name:/dir1/%s\n", d->d_type, d->d_name);
                    d = ReadDir(pdir);
                }
                CloseDir(pdir);
            }
            pdir = OpenDir("/dir1/dir2");
            if (pdir)
            {
                ec::cXStorage::dirent* d = ReadDir(pdir);
                while (d)
                {
                    printf("Type:%c ; name:/dir1/dir2/%s\n", d->d_type, d->d_name);
                    d = ReadDir(pdir);
                }
                CloseDir(pdir);
            }
        }
        void tst_fat()
        {
            int i;
            ec::cXStorage::t_file* pf = fOpen("file1", true);
            ec::tArray<unsigned int> fat(2048);
            if (LoadFat(pf, &fat)) //读取文件分配表
            {
                fat.ClearData();
                for (i = 0; i < ECSTG_PG_FATPGS; i++)
                {
                    fat.Add(500 + i);
                }
                writeFat(pf, &fat);
            }
            fClose(pf);

        }
        void tst_filewr()
        {
            ec::cXStorage::t_file* pf = fOpen("file1", true);
            int n = fWrite(pf, "1234", 4);
            char s[16] = { 0 };
            fClose(pf);
            pf = fOpen("file1", false);
            n = fRead(pf, s, 16);
            printf("read n= %d,s=%s\n", n, s);

            fSeek(pf, 4098);
            n = fWrite(pf, "5678", 4);
            fSeek(pf, 4098);
            n = fRead(pf, s, 16);
            printf("read n= %d,s=%s\n", n, s);
        }

        void tst_filewr2()
        {
            ec::cXStorage::t_file* pf = fOpen("file2", true);
            ec::cAp pb(1024 * 1024 * 4);
            unsigned int *pn = (unsigned int*)pb.getbuf();
            int i;
            for (i = 0; i < pb.getsize() / 4; i++)
            {
                pn[i] = i;
            }

            int n = fWrite(pf, pb, (int)pb.getsize());
            fClose(pf);

            for (i = 0; i < pb.getsize() / 4; i++)
            {
                pn[i] = 0;
            }

            pf = fOpen("file2", false);

            n = fRead(pf, pb, (int)pb.getsize());
            if (n == pb.getsize())
            {
                for (i = 0; i < pb.getsize() / 4; i++)
                {
                    if (pn[i] != i)
                    {
                        printf("error!\n");
                        break;
                    }
                }
            }
            printf("read n= %d\n", n);
            fClose(pf);
        }
        void tst_file3()
        {
            int n;
            char sbuf[32] = { 0 };
            ec::cXStorage::t_file* pf = fOpen("/dir1/file2", true);
            if (!pf)
                return;
            n = fRead(pf, sbuf, 32);
            printf("read %d,%s\n", n, sbuf);

            fSeek(pf, 1024*1024);
            if (fSetEndFile(pf))
                printf("fSetEndFile 1024*1024 OK!\n");
            else
                printf("fSetEndFile 1024*1024 failed!\n");
            fSeek(pf, 0);
            n = fWrite(pf, "1234", 4);
            fSeek(pf, 0);
            char sbuf[32] = { 0 };
            n = fRead(pf, sbuf, 32);
            printf("read %d,%s\n", n, sbuf);

            fSeek(pf, 4);
            if (!fSetEndFile(pf))
                printf("fSetEndFile 4 OK!\n");
            else
                printf("fSetEndFile 4 failed!\n");
            fSeek(pf, 0);
            n = fRead(pf, sbuf, 32);
            printf("read %d,%s\n", n, sbuf);
            fClose(pf);
        }
        
        void tst_file4()
        {
            int n;
            char sbuf[32] = { 0 };
            ec::cXStorage::t_file* pf = fOpen("/dir1/dir2/file1", true);
            if (!pf)
                return;

            fSeek(pf, 1024 * 5);
            if (fSetEndFile(pf))
                printf("fSetEndFile 1024*1024 OK!\n");
            else
                printf("fSetEndFile 1024*1024 failed!\n");

            n = fWrite(pf, "1234", 4);
            fSeek(pf, 1024 * 5);
            n = fRead(pf, sbuf, 32);
            printf("read %d,%s\n", n, sbuf);

            fClose(pf);
        }*/
    };
};