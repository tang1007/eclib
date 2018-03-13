/*!
\file c_command.h
\author kipway@outlook.com
\update 2018.3.4

eclib class cCommandLine ,parse command line as linux

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

#include "ec/c_array.h"
#include "ec/c_str.h"

namespace ec
{
	/*!
	\brief Command parse
	example:
	open --ip 127.0.0.1 --port 9501 --usr user1 --psw pass1
	*/
	class cCommandLine
	{
	public:
		cCommandLine(const char* s) :_a(8) {
			parse(s);
		}
	protected:
		class t_i
		{
		public:
			t_i() :key{ 0 }, val{ 0 } {
			}
			t_i(const char* k, const char* v) {
				ec::str_ncpy(key, k, sizeof(key));
				ec::str_ncpy(val, v, sizeof(val));
			}
			char key[16];
			char val[80];
		};
		ec::tArray<t_i> _a;
		const char* tonext(const char*s) {
			while (*s) {
				if (*s == '-' && *(s - 1) == '-' && (*(s - 2) == '\x20' || *(s - 2) == '\t'))
					return s - 1;
				s++;
			}
			return s;
		}
		void Add(const char*s) {
			size_t pos = 0, len = strlen(s);
			t_i t;
			if (ec::str_getnext("\x20\t\n\r", s, len, pos, t.key, sizeof(t.key))) {
				if (pos < len) {
					memcpy(t.val, s + pos, len - pos);
					t.val[len - pos] = '\0';
					_a.push_back(t);
				}
			}
		}
	public:
		size_t parse(const char *s) {
			_a.clear();
			size_t pos = 0, len = strlen(s);
			char z[80] = { 0 };
			if (ec::str_getnext("\x20\t\n\r", s, len, pos, z, sizeof(z)))
				_a.push_back(t_i("command", z));
			const char *ps = tonext(s + pos);
			const char* pe, *pend = s + len;
			while (ps < pend) {
				pe = tonext(ps + 2);
				memcpy(z, ps, pe - ps);
				z[pe - ps] = 0;
				ec::str_trim(z);
				Add(z);
				ps = pe;
			}
			return _a.size();
		}
		const char* operator[](const char* key) {
			for (auto i = _a.begin(); i != _a.end(); i++) {
				if (!ec::str_icmp(key, (*i).key))
					return (*i).val;
			}
			return 0;
		}
		inline size_t size() {
			return _a.size();
		}
	};
}
