﻿/*!
\file c11_config.h
\author	jiangyong
\email  kipway@outlook.com
\update 2018.12.20

eclibe config for windows & linux

class config;

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

#define MAX_INI_LINE_W		1280
#define MAX_INI_BLOCK_W		80
#define MAX_INI_KEYNAME_W	80
#define MAX_INI_KEYVAL_W	1024

#ifdef _WIN32
#pragma warning (disable : 4996)
#endif // _WIN32

#include <functional>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
namespace ec
{
	inline  int loadcsv(const char* sfile, std::function<int(int nrow, int ncol, const char* stxt, bool bendline)>fun)
	{
		FILE* pf = NULL;
		pf = fopen(sfile, "rt");
		if (pf == NULL)
			return -1;

		int c = fgetc(pf), c2 = fgetc(pf), c3 = fgetc(pf);
		if (!(c == 0xef && c2 == 0xbb && c3 == 0xbf)) // not utf8 with bom            
			fseek(pf, 0, SEEK_SET);

		char stmp[4096];
		int nr = 0, nc = 0, nstr = 0, nerr = 0;

		int cnext;
		unsigned int np = 0;

		while ((c = fgetc(pf)) != EOF) {
			if (c == ',') {
				if (!nstr) {
					stmp[np] = 0;
					if (0 != (nerr = fun(nr, nc, stmp, false)))
						break;
					nc++;   np = 0;
				}
				else {
					if (np < sizeof(stmp) - 1)
						stmp[np++] = c;
				}
			}
			else if (c == '\n') {
				stmp[np] = 0;
				if (0 != (nerr = fun(nr, nc, stmp, true)))
					break;
				nr++; nc = 0; np = 0;
			}
			else if (c == '"') {
				cnext = fgetc(pf);
				if (cnext == EOF)
					break;
				if (cnext == '"') {
					if (np < sizeof(stmp) - 1)
						stmp[np++] = c;
				}
				else {
					fseek(pf, -1, SEEK_CUR);
					if (nstr)
						nstr = 0;
					else
						nstr++;
				}
			}
			else {
				if (c != '\r' && c != '\t' && np < sizeof(stmp) - 1)
					stmp[np++] = c;
			}

		}
		if (nerr && np > 0) {
			stmp[np] = 0;
			nerr = fun(nr, nc, stmp, false);
		}
		fclose(pf);
		return nerr;
	};

	class config
	{
	public:
		config() {
			m_szLine[0] = '\0';
			m_szBlkName[0] = '\0';
		};
		virtual ~config() {};
	public:
		bool fromfile(const char* lpszFile)
		{
			FILE* pf = NULL;
			pf = fopen(lpszFile, "rt");
			if (pf == NULL)
				return false;
			OnReadFile();
			int c = fgetc(pf), c2 = fgetc(pf), c3 = fgetc(pf);
			if (!(c == 0xef && c2 == 0xbb && c3 == 0xbf)) // not utf8 with bom
				fseek(pf, 0, SEEK_SET);

			char *pc = m_szLine;
			int npos = 0;
			*pc = '\0';
			while ((c = fgetc(pf)) != EOF) {
				if (c != '\n' && c != '\r') {
					if (npos < MAX_INI_LINE_W - 1) {
						*pc = c;
						pc++;
						npos++;
					}
				}
				else {
					if (m_szLine[0])
						DoLine();
					pc = m_szLine;
					npos = 0;
				}
				*pc = '\0';
			}
			if (m_szLine[0])
				DoLine();
			fclose(pf);
			return true;
		}
		bool fromstring(const char* stxt)
		{
			if (!stxt)
				return false;
			OnReadFile();

			char c, *pc = m_szLine;
			int npos = 0;
			*pc = '\0';
			while ((c = *stxt++) != 0) {
				if (c != '\n' && c != '\r') {
					if (npos < MAX_INI_LINE_W - 1) {
						*pc = c;
						pc++;
						npos++;
					}
				}
				else {
					if (m_szLine[0])
						DoLine();
					pc = m_szLine;
					npos = 0;
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
			if (*pline == '\0' || *pline == ';' || *pline == '#')
				return;

			pt = pline;
			while (*pt != '\0' && *pt != ';' && *pt != '#')
				pt++;
			*pt = '\0';
			while (pt > m_szLine) {
				pt--;
				if (*pt == ' ' || *pt == '\t')
					*pt = '\0';
				else
					break;
			}
			int npos = 0;
			char *pblk = m_szBlkName;
			pt = pline;
			if (*pt == '[') {
				pt++;
				pblk = m_szBlkName;
				while (*pt != '\0' && npos < MAX_INI_BLOCK_W - 1) {
					if (*pt == ']')
						break;
					else if (*pt != ' ' && *pt != '\t') {
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
			while (*pt != '\0') {
				if (!npos && *pt == '=') {
					npos++;
					pt++;
					while (*pt == ' ' || *pt == '\t')
						pt++;
					continue;
				}
				else {
					if (npos == 0) {
						if ((*pt != ' ' && *pt != '\t') && nk < MAX_INI_KEYNAME_W - 1) {
							szKeyName[nk] = *pt;
							nk++;
							szKeyName[nk] = '\0';
						}
					}
					else {
						if (nv < MAX_INI_KEYVAL_W - 1) {
							szKeyVal[nv] = *pt;
							nv++;
							szKeyVal[nv] = '\0';
						}
					}
				}
				pt++;
			}
			if (npos > 0 && m_szBlkName[0])
				OnDoKeyVal(m_szBlkName, szKeyName, szKeyVal);
		};
		virtual void OnBlkName(const char* sblk) = 0;
		virtual void OnDoKeyVal(const char* sblk, const char* skey, const char* sval) = 0;
		virtual void OnReadFile() = 0;
	};
}; // ec