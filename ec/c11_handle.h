/*!
\file c11_handle.h
\author kipway@outlook.com
\update 2018.7.19

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
	};	
};