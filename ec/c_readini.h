/*!
\file c_readini.h
\brief parse local ini file

  ec library is free C++ library.

 \author	 kipway@outlook.com

*/


#ifndef C_READINI_H
#define C_READINI_H

#define MAX_INI_LINE_W		1024
#define MAX_INI_BLOCK_W		80
#define MAX_INI_KEYNAME_W	80
#define MAX_INI_KEYVAL_W	256

#ifdef _WIN32
#pragma warning (disable : 4996)
#endif // _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
namespace ec
{
    /*!
    \brief load and parse CSV
    \param sfile [in] filename full path
    \param onfiled [in] callback do filed，returnn 0 success，else error and stop pasre cs file
    \param ponfiledparam [in] onfiled param
    */
    inline  int csv_loadfile(const char* sfile, int(*onfiled)(int nrow, int ncol, const char* stxt, void*param), void *ponfiledparam)
    {
        FILE* pf = NULL;
        pf = fopen(sfile, "rt");
        if (pf == NULL)
            return -1;

        char stmp[4096];
        int nr = 0, nc = 0, nstr = 0, nerr = 0;

        char c, cnext;
        unsigned int np = 0;

        while ((c = fgetc(pf)) != EOF)
        {
            if (c == ',')
            {
                if (!nstr)
                {
                    stmp[np] = 0;
                    nerr = onfiled(nr, nc, stmp, ponfiledparam);
                    if (nerr)
                        break;
                    nc++;   np = 0;
                }
                else
                {
                    if (np < sizeof(stmp) - 1)
                        stmp[np++] = c;
                }
            }
            else if (c == '\n')
            {
                stmp[np] = 0;
                nerr = onfiled(nr, nc, stmp, ponfiledparam);
                if (nerr)
                    break;
                nr++; nc = 0; np = 0;
            }
            else if (c == '"')
            {
                cnext = fgetc(pf);
                if (cnext == EOF)
                    break;
                if (cnext == '"')
                {
                    if (np < sizeof(stmp) - 1)
                        stmp[np++] = c;
                }
                else
                {
                    fseek(pf, -1, SEEK_CUR);
                    if (nstr)
                        nstr = 0;
                    else
                        nstr++;
                }
            }
            else
            {
                if (c != '\r' && c != '\t' && np < sizeof(stmp) - 1)
                    stmp[np++] = c;
            }

        }
        if (nerr && np > 0)
        {
            stmp[np] = 0;
            nerr = onfiled(nr, nc, stmp, ponfiledparam);
        }
        fclose(pf);
        return nerr;
    };

    inline  int csv_loadfile2(const char* sfile, int(*onfiled)(int nrow, int ncol, const char* stxt, bool bendline, void*param), void *ponfiledparam)
    {
        FILE* pf = NULL;
        pf = fopen(sfile, "rt");
        if (pf == NULL)
            return -1;

        char stmp[4096];
        int nr = 0, nc = 0, nstr = 0, nerr = 0;

        char c, cnext;
        unsigned int np = 0;

        while ((c = fgetc(pf)) != EOF)
        {
            if (c == ',')
            {
                if (!nstr)
                {
                    stmp[np] = 0;
                    nerr = onfiled(nr, nc, stmp, false, ponfiledparam);
                    if (nerr)
                        break;
                    nc++;   np = 0;
                }
                else
                {
                    if (np < sizeof(stmp) - 1)
                        stmp[np++] = c;
                }
            }
            else if (c == '\n')
            {
                stmp[np] = 0;
                nerr = onfiled(nr, nc, stmp, true, ponfiledparam);
                if (nerr)
                    break;
                nr++; nc = 0; np = 0;
            }
            else if (c == '"')
            {
                cnext = fgetc(pf);
                if (cnext == EOF)
                    break;
                if (cnext == '"')
                {
                    if (np < sizeof(stmp) - 1)
                        stmp[np++] = c;
                }
                else
                {
                    fseek(pf, -1, SEEK_CUR);
                    if (nstr)
                        nstr = 0;
                    else
                        nstr++;
                }
            }
            else
            {
                if (c != '\r' && c != '\t' && np < sizeof(stmp) - 1)
                    stmp[np++] = c;
            }

        }
        if (nerr && np > 0)
        {
            stmp[np] = 0;
            nerr = onfiled(nr, nc, stmp, false, ponfiledparam);
        }
        fclose(pf);
        return nerr;
    };

    class cReadIni
    {
    public:
        cReadIni() {
            m_szLine[0] = '\0';
            m_szBlkName[0] = '\0';
        };
        virtual ~cReadIni() {};
    public:
        bool ReadIniFile(const char* lpszFile)
        {
            FILE* pf = NULL;
            pf = fopen(lpszFile, "rt");
            if (pf == NULL)
                return false;

            OnReadFile();

            char c, *pc = m_szLine;
            int npos = 0;
            *pc = '\0';
            while ((c = (char)fgetc(pf)) != EOF)
            {
                if (c != '\n' && c != '\r')
                {
                    if (npos < MAX_INI_LINE_W - 1)
                    {
                        *pc = c;
                        pc++;
                    }
                }
                else
                {
                    if (m_szLine[0])
                        DoLine();
                    pc = m_szLine;
                }
                *pc = '\0';
            }
            if (m_szLine[0])
                DoLine();
            fclose(pf);
            return true;
        }
        bool ReadIniString(const char* stxt)
        {
            if (!stxt)
                return false;
            OnReadFile();

            char c, *pc = m_szLine;
            int npos = 0;
            *pc = '\0';
            while ((c = *stxt++) != 0)
            {
                if (c != '\n' && c != '\r')
                {
                    if (npos < MAX_INI_LINE_W - 1)
                    {
                        *pc = c;
                        pc++;
                    }
                }
                else
                {
                    if (m_szLine[0])
                        DoLine();
                    pc = m_szLine;
                }
                *pc = '\0';
            }
            if (m_szLine[0])
                DoLine();
            return true;
        }
    protected:
        char m_szLine[MAX_INI_LINE_W];
        char m_szBlkName[MAX_INI_BLOCK_W];

    protected:
        void	DoLine()
        {
            m_szLine[MAX_INI_LINE_W - 1] = '\0';

            char *pline = m_szLine, *pt;
            while ((*pline == ' ' || *pline == '\t') && *pline != '\0')
                pline++;
            if (*pline == '\0' || *pline == ';')
                return;

            pt = pline;
            while (*pt != '\0' && *pt != ';')
                pt++;
            *pt = '\0';
            while (pt > m_szLine)
            {
                pt--;
                if (*pt == ' ' || *pt == '\t')
                    *pt = '\0';
                else
                    break;
            }
            int npos = 0;
            char *pblk = m_szBlkName;
            pt = pline;
            if (*pt == '[')
            {
                pt++;
                pblk = m_szBlkName;
                while (*pt != '\0' && npos < MAX_INI_BLOCK_W - 1)
                {
                    if (*pt == ']')
                        break;
                    else if (*pt != ' ' && *pt != '\t')
                    {
                        *pblk = *pt;
                        pblk++;
                        *pblk = '\0';
                        npos++;
                    }
                    pt++;
                }
                if (*pt != ']')
                    m_szBlkName[0] = '\0';
                if (m_szBlkName[0])
                    OnBlkName(m_szBlkName);
                return;
            }

            npos = 0;
            char szKeyName[MAX_INI_KEYNAME_W] = { 0, };
            char szKeyVal[MAX_INI_KEYVAL_W] = { 0, };
            int nk = 0, nv = 0;
            pt = pline;
            while (*pt != '\0')
            {
                if (!npos && *pt == '=')
                {
                    npos++;
                    pt++;
                    while (*pt == ' ' || *pt == '\t')
                        pt++;
                    continue;
                }
                else
                {
                    if (npos == 0)
                    {
                        if ((*pt != ' ' && *pt != '\t') && nk < MAX_INI_KEYNAME_W - 1)
                        {
                            szKeyName[nk] = *pt;
                            nk++;
                            szKeyName[nk] = '\0';
                        }
                    }
                    else
                    {
                        if (nv < MAX_INI_KEYVAL_W - 1)
                        {
                            szKeyVal[nv] = *pt;
                            nv++;
                            szKeyVal[nv] = '\0';
                        }
                    }
                }
                pt++;
            }

            if (npos > 0 && m_szBlkName[0])
            {
                OnDoKeyVal(m_szBlkName, szKeyName, szKeyVal);
            }
        };
        virtual void OnBlkName(const char* sblk) = 0;
        virtual void OnDoKeyVal(const char* sblk, const char* skey, const char* sval) = 0;
        virtual void OnReadFile() = 0;
    };
}; // ec
#endif // C_READINI_H


