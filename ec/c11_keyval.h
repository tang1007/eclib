/*!
\file c11_keyval.h
\author	kipway@outlook.com
\update 2018.5.26  add fast memory allocator

eclib class text key-value

class txtkeyval;


key1:value1\n
key2:value2\n
key3:value3\n


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
#include <ctype.h>
#include <string.h>
#include "c11_array.h"

#ifndef KEYV_KEY_MAXSIZE
#define KEYV_KEY_MAXSIZE 48 // max key characters
#endif
#ifndef KEYV_VAL_MAXSIZE
#define KEYV_VAL_MAXSIZE 512 // max value characters
#endif

#ifndef KEYV_MAX_ITEMS
#define KEYV_MAX_ITEMS  512 // max key-value items
#endif
namespace ec {
	inline bool strieq(const char* s1, const char* s2)
	{		
		while (*s1 && *s2)
		{
			if (*s1 != *s2 && tolower(*s1) != tolower(*s2))
				return false;
			s1++;
			s2++;
		}
		return *s1 == 0 && *s2 == 0;
	}

	inline void strtrim(char *s,const char* sfliter = "\x20\t\n\r")
	{
		if (!*s)
			return;
		char *sp = s, *s1 = s;
		while (strchr(sfliter,*sp)) // trimleft
			sp++;
		if (sp != s) {
			while (*sp)
				*s1++ = *sp++;
			*s1 = '\0';
		}
		while (s1 > s) //trimright
		{
			s1--;
			if (strchr(sfliter, *s1))
				*s1 = '\0';
			else
				break;
		}
	}

	class txtkeyval
	{
	public:
		txtkeyval():_r(nullptr), _size(0){

		}
		txtkeyval(const char* s, size_t len) {
			init(s, len);
		}
	protected:
		Array<unsigned int, KEYV_MAX_ITEMS> _idx;  const char* _r;   size_t _size;
	public:
		int init(const char* srecs, size_t size)
		{
			_r = srecs;
			_size = size;
			_idx.clear();
			if (!_r || !size)
				return 0;
			size_t upre = 0, u = 0;
			while (u < _size)
			{
				if (_r[u] == '\n')
				{
					_idx.add((unsigned int)upre);
					if (_r[u + 1] == '\r')
						u++;
					upre = u + 1;
				}
				u++;
			}
			if (u > upre + 1)
				_idx.add((unsigned int)upre);
			return (int)_idx.size();
		}
		inline int countrecs() {
			return  (int)_idx.size();
		}
		bool get(size_t nr, char* field, size_t fieldbuflen, char *val, size_t valbuflen)
		{
			if (nr >= _idx.size() || !_r)
				return false;
			size_t pos = _idx[nr], poss = 0;
			while (pos < _size)
			{
				if (_r[pos] == ':' && !poss) {
					if (pos - _idx[nr] >= fieldbuflen)
						return false;
					memcpy(field, _r + _idx[nr], pos - _idx[nr]);
					field[pos - _idx[nr]] = 0;
					poss = pos + 1;
				}
				else if (_r[pos] == '\n')
				{
					if (poss)
					{
					lpend:
						if (valbuflen <= pos - poss)
							return false;
						if (pos > poss)
							memcpy(val, _r + poss, pos - poss);
						val[pos - poss] = 0;
						return true;
					}
					return false;
				}
				pos++;
			}
			if (poss)
				goto lpend;
			return false;
		}

		bool get(const char* sname, char *val, size_t valbuflen,const char* strim = "\x20\t\n\r")
		{
			if (!_r)
				return false;
			size_t i, n = _idx.size();
			size_t pos, poss = 0;
			char skey[KEYV_KEY_MAXSIZE];
			for (i = 0; i < n; i++)
			{
				pos = _idx[i];
				poss = 0;
				while (pos < _size)
				{
					if (_r[pos] == ':' && !poss) {
						if (pos == _idx[i])
							break;
						if (pos - _idx[i] >= KEYV_KEY_MAXSIZE)
							break;
						memcpy(skey, _r + _idx[i], pos - _idx[i]);
						skey[pos - _idx[i]] = 0;
						strtrim(skey);
						if (!strieq(sname, skey)) // not equal
							break;
						poss = pos + 1;
					}
					else if (_r[pos] == '\n')
					{
						if (poss)
						{
						lpend:
							if (valbuflen <= pos - poss)
								return false;
							if (pos > poss)
								memcpy(val, _r + poss, pos - poss);
							if(strim)
								strtrim(skey, strim);
							val[pos - poss] = 0;
							return true;
						}
						break;
					}
					pos++;
				}
			}
			if (poss)
				goto lpend;
			return false;
		}

		int getpos(const char* sname)
		{
			if (!_r)
				return -1;
			size_t i, n = _idx.size();
			size_t pos;
			char skey[KEYV_KEY_MAXSIZE];
			for (i = 0; i < n; i++)
			{
				pos = _idx[i];
				while (pos < _size)
				{
					if (_r[pos] == ':') {
						if (pos == _idx[i])
							break;
						if (pos - _idx[i] >= KEYV_KEY_MAXSIZE)
							break;
						memcpy(skey, _r + _idx[i], pos - _idx[i]);
						skey[pos - _idx[i]] = 0;
						strtrim(skey);
						if (strieq(sname, skey))
							return (int)_idx[i];
						break;
					}
					pos++;
				}
			}
			return -1;
		}
	};
}
