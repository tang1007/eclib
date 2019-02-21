/*!
\file c11_cmdline.h
\author kipway@outlook.com
\update 2018.10.25

eclib class cCmdLine ,parse command line

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

#include "ec/c11_vector.h"
#include "ec/c_str.h"

namespace ec
{
	/*!
	\brief Command Line parse

	cmd [--arg1 arg1val] [--arg2 arg2val] ...

	example:
	open --ip 127.0.0.1 --port 9501 --usr user1 --psw pass1
	*/
	class cCmdLine
	{
	public:
		cCmdLine(const char* s) : _scmd{ 0 }, _a(8, true), _serr{ 0 }{
			parse(s);
		}
	protected:
		class t_i
		{
		public:
			t_i() : key{ 0 }, val{ 0 } {
			}
			t_i(const char* k, const char* v) {
				ec::str_lcpy(key, k, sizeof(key));
				ec::str_lcpy(val, v, sizeof(val));
			}
			char key[16];
			char val[80];			
		};
		char _scmd[32];
		ec::vector<t_i> _a;
		const char* tonext(const char*s) {
			while (*s) {
				if (*s == '-' && *(s - 1) == '-' && (*(s - 2) == '\x20' || *(s - 2) == '\t'))
					return s - 1;
				s++;
			}
			return s;
		}
		bool  addarg(const char*s,char *serr,size_t errsize) {
			size_t pos = 0, len = strlen(s);
			t_i t;
			bool badd = false;
			if (ec::str_getnext("\x20\t\n\r", s, len, pos, t.key, sizeof(t.key))) {
				if (pos < len) {
					memcpy(t.val, s + pos, len - pos);
					t.val[len - pos] = '\0';
					_a.push_back(t);
					badd = true;
					return true;
				}
				else {
					snprintf(serr, errsize, "%s has no parameter", t.key);
					return false;
				}
			}			
			snprintf(serr, errsize, "%s error format", s);
			return false;			
		}
	private:
		char _serr[256];
	public:
		bool parse(const char *s) {
			_scmd[0] = 0;
			_a.clear();
			if (!s || !(*s))
				return false;
			size_t pos = 0, len = strlen(s);
			char z[80] = { 0 };

			if (ec::str_getnext("\x20\t\n\r", s, len, pos, z, sizeof(z)))
				ec::str_lcpy(_scmd, z, sizeof(_scmd));
			else
				return false;
			const char *ps = tonext(s + pos);
			const char* pe, *pend = s + len;
			while (ps < pend) {
				pe = tonext(ps + 2);
				memcpy(z, ps, pe - ps);
				z[pe - ps] = 0;
				ec::str_trim(z);
				if(!addarg(z,_serr,sizeof(_serr)))
					return false;
				ps = pe;
			}
			return true;
		}
		const char* lasterr() {
			return _serr;
		}
		inline const char* cmd() {
			if (_scmd[0])
				return _scmd;
			return nullptr;
		}

		const char* operator[](const char* key) {
			for (auto i = _a.begin(); i != _a.end(); i++) {
				if (!ec::str_icmp(key, (*i).key))
					return (*i).val;
			}
			return nullptr;
		}

		const char* arg(size_t pos) {
			if (pos >= _a.size())
				return nullptr;
			return _a[pos].val;
		}

		inline size_t size() {
			return _a.size();
		}

		inline bool ok() {
			return _scmd[0] != '\0';
		}

		void print() {
			printf("%s", _scmd);
			_a.for_each([&](t_i &v) {
				printf(" %s %s", v.key, v.val);
			});
			printf("\n");
		}
	};
}
