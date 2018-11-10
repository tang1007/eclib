/*!
\file json.h
\brief parse json from string or file
\author	jiangyong
\email  kipway@outlook.com
\update 2018.11.10

eclibe parse json for windows & linux

class jsn::json;

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

#include "c_str.h"
#include "c11_vector.h"
#include "c11_array.h"

#ifndef SIZE_JSON_KVS_GROWN
#	define SIZE_JSON_KVS_GROWN 64 //json kv向量增长量
#endif
namespace ec {
	namespace jsn //json tools
	{
		enum KVTYPE {  //key-val对中的 val 类型
			jsv_null = 0, //未知，或值为空
			jsv_val = 1,  //值或字符串
			jsv_obj = 2,  //对象
			jsv_array = 3 //数组
		};
		inline bool ps_tochar(const char* &ps, const char* pe, char c)//ps移动到c的位置
		{
			if (*ps != c) {
				ps++;
				while (ps < pe) {
					if (*ps == c && *(ps - 1) != '\\')
						return true;
					ps++;
				}
				return false;
			}
			return true;
		}
		inline bool ps_tochar(const char* &ps, const char* pe, const char* cs)//ps移动到cs中任何一个字符的位置
		{
			if (!strchr(cs, *ps)) {
				ps++;
				while (ps < pe) {
					if (strchr(cs, *ps) && *(ps - 1) != '\\')
						return true;
					ps++;
				}
				return false;
			}
			return true;
		}
		inline bool ps_skip(const char* &ps, const char* pe)//跳过空白字符
		{
			while (ps < pe) {
				if (*ps != '\x20' && *ps != '\n' && *ps != '\r' && *ps != '\b' && *ps != '\t' && *ps != '\f')
					return true;
				ps++;
			}
			return false;
		}
		inline bool ps_objend(const char* &ps, const char* pe, char cs, char ce) //ps指向cs开始,移动到对象结束,ps会指向ce之后的一个字符
		{
			int nk = 1;
			ps++;
			while (ps < pe && nk)
			{
				if ((*ps == cs) && *(ps - 1) != '\\')
					nk++;
				else if ((*ps == ce) && *(ps - 1) != '\\')
					nk--;
				ps++;
			}
			return !nk;
		}

		inline KVTYPE vtype(const char* s) {
			if (!s || !*s)
				return jsv_null;
			if ('{' == *s)
				return  jsv_obj;
			else if ('[' == *s)
				return  jsv_array;
			else
				return jsv_val;
		}

		class json // json对象解析
		{
		public:
			class t_i {
			public:
				t_i(char *k = nullptr, char *v = nullptr) {
					key = k;
					val = v;
				}
				char *key; // nullptr表示是数组成员
				char *val;
			};
		private:
			ec::memory *_pmem;
			ec::vector<t_i> _kvs;
			void clear() {
				_kvs.for_each([&](t_i &v) {
					_pmem->mem_free(v.key);
					_pmem->mem_free(v.val);
					v.key = nullptr;
					v.val = nullptr;
				});
				_kvs.clear(true);
			}			
		public:
			json(ec::memory *pmem) : _pmem(pmem), _kvs(SIZE_JSON_KVS_GROWN, pmem) {
			}
			~json() {
				clear();
			}
			inline size_t size() {
				return _kvs.size();
			}
			inline ec::memory* mem() {
				return _pmem;
			}
			const t_i* at(size_t i) {
				if (i < _kvs.size())
					return &_kvs[i];
				return nullptr;
			}
			const char* getval(const char* key, KVTYPE* pvt = nullptr) {
				size_t i, n = _kvs.size();
				for (i = 0; i < n; i++) {
					if (ec::str_ieq(_kvs[i].key, key)) {
						if (pvt)
							*pvt = vtype(_kvs[i].val);
						return _kvs[i].val;
					}
				}
				return nullptr;
			}
			bool exist(const char* key, size_t keysize) {
				size_t i, n = _kvs.size();
				for (i = 0; i < n; i++) {
					if (ec::str_ineq(_kvs[i].key, key, keysize))
						return true;
				}
				return false;
			}
			bool from_str(const char* ps, size_t size) {
				if (!ps || !size)
					return false;
				clear();
				const char *pe = ps + size;
				if (!ps_skip(ps, pe)) //跳过中间的空格换行等到值的起点
					return false;
				if (*ps == '[')
					return from_array(ps, pe);
				else if (*ps == '{')
					return from_obj(ps, pe);
				return false;
			}
			static void del_comment(ec::vector<char>* pin, ec::vector<char>* pout) {
				pout->clear();
				size_t size = pin->size();
				const char* s = pin->data(), *sp = s, *se = s + size;
				while (s < se) {
					if (*s == '/') {
						if (s != pin->data() && *(s - 1) == '*' && !sp)  // */
							sp = s + 1;
					}
					else if (*s == '*') {
						if (s != pin->data() && *(s - 1) == '/') { // /*
							if (sp && s > sp + 1)
								pout->add(sp, s - sp - 1);
							sp = nullptr;
						}
					}
					s++;
				}
				if (sp && s > sp + 1)
					pout->add(sp, s - sp - 1);
			}
			bool from_file(const char *sfile) {
				if (!sfile)
					return false;
				FILE *pf = fopen(sfile, "rt");
				if (!pf)
					return false;
				int c = fgetc(pf), c2 = fgetc(pf), c3 = fgetc(pf);
				if (!(c == 0xef && c2 == 0xbb && c3 == 0xbf)) // not utf8 with bom
					fseek(pf, 0, SEEK_SET);
				char s[1024 * 8];
				
				ec::vector<char> v(1024 * 8, true, _pmem);
				size_t sz;
				while ((sz = fread(s, 1, sizeof(s), pf)) > 0)
					v.add(s, sz);
				fclose(pf);
				if (!v.size())
					return false;
				ec::vector<char> vjstr(1024 * 8, true, _pmem);
				del_comment(&v,&vjstr);
				return from_str(vjstr.data(), vjstr.size());
			}
			inline void prt(int nspace) {
				while (nspace > 0) {
					printf("\x20");
					nspace--;
				}
			}
			void print(int nspace = 0) { //递归打印json对象
				int i = 0;
				_kvs.for_each([&](t_i &v) {
					KVTYPE vt = vtype(v.val);
					if (vt == jsv_val) {
						prt(nspace);
						if (v.key)
							printf("%s:%s\n", v.key, v.val);
						else
							printf("[%d]  %s\n", i++, v.val);
					}
					else {
						json js(_pmem);
						if (!js.from_str(v.val, strlen(v.val))) {
							prt(nspace);
							printf("err-> %s:%s\n", v.key, v.val);
						}
						else {
							prt(nspace);
							if (v.key) {
								if (vt == jsv_array)
									printf("%s:[\n", v.key);
								else
									printf("%s:{\n", v.key);
							}
							else {
								if (vt == jsv_array)
									printf("[%d] [\n ", i++);
								else
									printf("[%d] {\n ", i++);
							}
							js.print(nspace + 4);
							prt(nspace);
							if (vt == jsv_array)
								printf("]\n");
							else
								printf("}\n");
						}
					}
				});
			}
		private:
			bool from_obj(const char* ps, const char* pe) { // 从 json对象解析
				bool bend = false;
				int  nf = 0, nv = 0;
				const char *pf = nullptr, *pv = nullptr;
				if (*ps != '{')
					return false;
				ps++;
				while (ps < pe) {
					if (!ps_tochar(ps, pe, "\"}")) // to key start
						return false;
					if (*ps == '}')
						return true;
					ps++;	pf = ps;
					if (!ps_tochar(ps, pe, '"'))  //to key end
						return false;
					nf = (int)(ps - pf);
					if (!ps_tochar(ps, pe, ':'))
						return false;
					ps++;
					if (!ps_skip(ps, pe))
						return false;
					if (*ps == '"') { //字符串
						ps++;	pv = ps;
						if (!ps_tochar(ps, pe, '\"'))
							return false;
						nv = (int)(ps - pv);	ps++;
					}
					else if (*ps == '{' || *ps == '[') { //JSON对象
						pv = ps;
						if (!ps_objend(ps, pe, *ps, *ps == '{' ? '}' : ']'))
							return false;
						nv = (int)(ps - pv);
					}
					else { //立即数
						pv = ps;
						if (!ps_tochar(ps, pe, ",}"))
							return false;
						nv = (int)(ps - pv);
						if (*ps == '}')
							bend = true;
						ps++;
					}
					if (pf && nf && pv && nv)
					{
						if (nf > 40)
							return false;
						if (exist(pf, nf))
							return false; //有重复key
						t_i t;
						t.key = (char*)_pmem->mem_malloc(nf + 1);
						if (!t.key)
							return false;
						t.val = (char*)_pmem->mem_malloc(nv + 1);
						if (!t.val) {
							_pmem->mem_free(t.key);
							return false;
						}
						memcpy(t.key, pf, nf);
						t.key[nf] = '\0';
						memcpy(t.val, pv, nv);
						t.val[nv] = '\0';
						if (!_kvs.add(t))
							return false;
					}
					if (bend)
						return true;
					nv = 0; nf = 0;	pf = nullptr;	pv = nullptr;
				}
				return false;
			}
			bool from_array(const char* ps, const char*pe) {//从json数组数组解析
				int  nv = 0;
				const char *pv = nullptr;
				if (*ps != '[')
					return false;
				ps++;
				pv = ps;
				char *s;
				while (ps < pe)
				{
					if (!ps_skip(ps, pe))
						return false;
					if (*ps == '{' || *ps == '[') { //JSON数组对象成员
						pv = ps;
						if (!ps_objend(ps, pe, *ps, *ps == '{' ? '}' : ']'))
							return false;
						nv = (int)(ps - pv);
						s = (char*)_pmem->mem_malloc(nv + 1);
						if (!s)
							return false;
						memcpy(s, pv, nv);
						s[nv] = '\0';
						_kvs.add(t_i(nullptr, s));
						pv = ps;
					}
					else if (*ps == '\"') { //JSON数组字符串成员
						ps++;	pv = ps;
						if (!ps_tochar(ps, pe, '\"'))
							return false;
						nv = (int)(ps - pv);
						s = (char*)_pmem->mem_malloc(nv + 1);
						if (!s)
							return false;
						memcpy(s, pv, nv);
						s[nv] = '\0';
						_kvs.add(t_i(nullptr, s));
						ps++;
						pv = ps;
					}
					else if (*ps == ',') {
						if (pv) {
							ps_skip(pv, ps);
							if (pv != ps) {
								nv = (int)(ps - pv);
								s = (char*)_pmem->mem_malloc(nv + 1);
								if (!s)
									return false;
								memcpy(s, pv, nv);
								s[nv] = '\0';
								_kvs.add(t_i(nullptr, s));								
							}
						}
						ps++;
						pv = ps;
					}
					else if (*ps == ']') {
						if (pv) {
							ps_skip(pv, ps);
							if (pv != ps) {
								nv = (int)(ps - pv);
								s = (char*)_pmem->mem_malloc(nv + 1);
								if (!s)
									return false;
								memcpy(s, pv, nv);
								s[nv] = '\0';
								_kvs.add(t_i(nullptr, s));
							}
						}
						return true; //结束
					}
					else
						ps++;
				}
				return false;
			}
		};
	}//json
}// ec

/*
#include "ec/c11_system.h"
#include "ec/c11_json.h"

ec::memory _jsonmem(32, 1024, 80, 512, 1024 * 16, 16); //json解析用的内存池
int main(int argc, char * argv[])
{
	ec::jsn::json  j1(&_jsonmem);
	printf("\ntest val is string array\n");
	const char * sj1 = "{\"req\":\"get\",\"tags\":[\"ta\\\"g1\",\"tag2\",\"tag3\"]}";
	printf("%s\n", sj1);
	if (j1.from_str(sj1, strlen(sj1)))
		j1.print();
	else
		printf("from_str failed!\n");
	printf("\ntest val is object array\n");
	sj1 = "{\"req\":\"put\",\"val\":[{\"tag1\":1},{\"tag2\":2},{\"tag3\":\"str3\"}]}";
	printf("%s\n", sj1);
	if (j1.from_str(sj1, strlen(sj1)))
		j1.print();
	else
		printf("from_str failed!\n");
	printf("\ntest val is object\n");
	sj1 = "{\"req\":\"putval\",\"val\":{\"tag1\":1}}";
	printf("%s\n", sj1);
	if (j1.from_str(sj1, strlen(sj1))) {
		j1.print();
	}
	else
		printf("from_str failed!\n");
	printf("test from file\n");
#ifdef _WIN32
	if (j1.from_file("e:/json01.txt"))
#else
	if (j1.from_file("/home/json01.txt"))
#endif
		j1.print();
	else
		printf("from_file failed!\n");
}
*/