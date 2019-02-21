/*!
\file c11_handle.h
\author	jiangyong
\email  kipway@outlook.com
\update 2018.8.18

eclib for handle template class 

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

#define ERR_ECHANDLE		(-1)

#ifndef SIZE_MAXECHANDLES 
#define SIZE_MAXECHANDLES	1024	
#endif

#include "c11_map.h"
#include "c11_mutex.h"

#ifndef EC_HANDLE_UVSIZE
#define EC_HANDLE_UVSIZE 4  // user data
#endif

namespace ec
{
	template<class _Ty>
	class Handle
	{
		typedef _Ty value_type;
	private:
		struct t_i {
			int key;
			value_type *pcls;
			union {
				void* pv;
				int32_t iv;
				int64_t lv;
			}uv[EC_HANDLE_UVSIZE];//app data
		};	
		int _next;
		std::mutex _cs;
		memory _mem;
		map<int, t_i> _map;
		void nexthv() {
			_next++;
			if (_next > 2 * SIZE_MAXECHANDLES)
				_next = 1;
		}
	public:
		Handle() :_next(0), _mem(map<int, t_i>::size_node(), SIZE_MAXECHANDLES), _map(SIZE_MAXECHANDLES, &_mem) {
		};
		~Handle() {
			_map.for_each([](t_i &v) {
				if (v.pcls) {
					delete v.pcls;
					v.pcls = nullptr;
				}
			});
			_map.clear();
		}

		int  CreateHandle()
		{
			unique_lock lck(&_cs);
			if (_map.size() >= SIZE_MAXECHANDLES)
				return ERR_ECHANDLE;
			nexthv();
			while (_map.get(_next))
				nexthv();
			t_i tmp;
			memset(&tmp, 0, sizeof(tmp));
			tmp.key = _next;			
			tmp.pcls = new value_type();
			_map.set(tmp.key, tmp);
			return tmp.key;
		}

		void DelHandle(int h)
		{
			unique_lock lck(&_cs);
			t_i* pv = _map.get(h);
			if (pv && pv->pcls) {
				delete pv->pcls;				
				pv->pcls = nullptr;				
			}
			_map.erase(h);
		}

		value_type* GetClsByHandle(int h)
		{
			unique_lock lck(&_cs);
			t_i* p = _map.get(h);
			if (p)
				return p->pcls;
			return nullptr;
		}

		inline value_type* GetClass(int h)
		{
			return GetClsByHandle(h);
		}

		void *getpv(int h, int nindex) {
			unique_lock lck(&_cs);
			t_i* p = _map.get(h);
			if (p) {
				if (nindex < 0 || nindex >= EC_HANDLE_UVSIZE)
					return nullptr;
				return p->uv[nindex].pv;
			}				
			return nullptr;			
		}

		int32_t getiv(int h, int nindex) {
			unique_lock lck(&_cs);
			t_i* p = _map.get(h);
			if (p) {
				if (nindex < 0 || nindex >= EC_HANDLE_UVSIZE)
					return 0;
				return p->uv[nindex].iv;
			}
			return 0;
		}

		int64_t getlv(int h, int nindex) {
			unique_lock lck(&_cs);
			t_i* p = _map.get(h);
			if (p) {
				if (nindex < 0 || nindex >= EC_HANDLE_UVSIZE)
					return 0;
				return p->uv[nindex].lv;
			}
			return 0;
		}

		bool setpv(int h, int nindex,void *v) {
			unique_lock lck(&_cs);
			t_i* p = _map.get(h);
			if (p) {
				if (nindex < 0 || nindex >= EC_HANDLE_UVSIZE)
					return false;
				p->uv[nindex].pv = v;
				return true;
			}
			return false;
		}

		bool setiv(int h, int nindex, int32_t v) {
			unique_lock lck(&_cs);
			t_i* p = _map.get(h);
			if (p) {
				if (nindex < 0 || nindex >= EC_HANDLE_UVSIZE)
					return false;
				p->uv[nindex].iv = v;
				return true;
			}
			return false;
		}
		bool setlv(int h, int nindex, int64_t v) {
			unique_lock lck(&_cs);
			t_i* p = _map.get(h);
			if (p) {
				if (nindex < 0 || nindex >= EC_HANDLE_UVSIZE)
					return false;
				p->uv[nindex].lv = v;
				return true;
			}
			return false;
		}		
	};	
};