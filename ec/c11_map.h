/*!
\file c11_map.h
\author	jiangyong
\email  kipway@outlook.com
\update 2018.12.6

eclib class map with c++11. fast noexcept unordered hashmap with safety iterator

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
#include <functional>
#include "c11_memory.h"
#include "c11_hash.h"

namespace ec
{
	template<class _Kty, class _Ty> // is _Kty is equal to the key in class _Ty
	struct key_equal
	{
		bool operator()(_Kty key, const _Ty& val)
		{
			return key == val.key;
		}
	};

	template<class _Ty> // on del mao node
	struct del_node
	{
		void operator()(_Ty& val)
		{
		}
	};
	template<class _Kty,
		class _Ty,
		class _Keyeq = key_equal<_Kty, _Ty>,
		class _DelVal = del_node<_Ty>,
		class _Hasher = hash<_Kty> >
		class map
	{
	public:
		typedef uint64_t iterator;  // safety iterator 
		typedef _Ty		value_type;
		typedef _Kty	key_type;
		typedef size_t	size_type;
		struct t_node
		{
			t_node*		pNext;
			value_type  value;
		};

	protected:
		t_node * *	_ppv;
		size_type   _uhashsize;
		size_type	_usize;
	private:
		ec::memory* _pmem;
		spinlock* _pmutex;
		inline t_node* new_node() {
			t_node* pnode = nullptr;
			if (_pmem)
				pnode = (t_node*)_pmem->mem_malloc(sizeof(t_node));
			else
				pnode = (t_node*)malloc(sizeof(t_node));
			if (pnode)
				new(&pnode->value)value_type();
			return pnode;
		}
		inline void free_node(t_node* p) {
			if (p)
				p->value.~value_type();
			if (_pmem)
				_pmem->mem_free(p);
			else
				free(p);
		}
	public:
		map(unsigned int uhashsize = 1024, ec::memory* pmem = nullptr, spinlock* pmutex = nullptr)
			: _ppv(nullptr), _uhashsize(uhashsize), _usize(0), _pmem(pmem), _pmutex(pmutex)
		{
			_ppv = new t_node*[_uhashsize];
			if (nullptr == _ppv)
				return;
			memset(_ppv, 0, sizeof(t_node*) * _uhashsize);
		};
		~map()
		{
			clear();
		};
		inline static size_t size_node() {
			return sizeof(t_node);
		}
		inline size_type size() const noexcept
		{
			return _usize;
		};
		inline bool empty() const noexcept
		{
			return !_ppv || !_usize;
		}
		iterator begin() noexcept //Multi-thread safe if _pmutex not null
		{
			unique_spinlock lck(_pmutex);
			iterator ir = 0;
			if (nullptr == _ppv || !_usize)
				return ~ir;
			for (size_type i = 0; i < _uhashsize; i++)
			{
				if (_ppv[i])
				{
					ir = i;
					return (ir << 32);
				}
			}
			return ~ir;
		}
		inline iterator end() const noexcept
		{
			return ~0;
		}
		bool set(key_type key, value_type& Value) noexcept //Multi-thread safe if _pmutex not null
		{
			unique_spinlock lck(_pmutex);
			if (nullptr == _ppv)
			{
				_ppv = new t_node*[_uhashsize];
				if (nullptr == _ppv)
					return false;
				memset(_ppv, 0, sizeof(t_node*) * _uhashsize);
			}
			size_type upos = _Hasher()(key) % _uhashsize;
			t_node* pnode;
			for (pnode = _ppv[upos]; pnode != nullptr; pnode = pnode->pNext)
			{
				if (_Keyeq()(key, pnode->value))
				{
					_DelVal()(pnode->value);
					pnode->value = Value;
					return true;
				}
			}
			pnode = new_node();
			if (pnode == nullptr)
				return false;
			pnode->value = Value;
			pnode->pNext = _ppv[upos];
			_ppv[upos] = pnode;
			_usize++;
			return true;
		};
		bool set(key_type key, value_type&& Value) noexcept //Multi-thread safe if _pmutex not null
		{
			unique_spinlock lck(_pmutex);
			if (nullptr == _ppv)
			{
				_ppv = new t_node*[_uhashsize];
				if (nullptr == _ppv)
					return false;
				memset(_ppv, 0, sizeof(t_node*) * _uhashsize);
			}
			size_type upos = _Hasher()(key) % _uhashsize;
			t_node* pnode;
			for (pnode = _ppv[upos]; pnode != nullptr; pnode = pnode->pNext)
			{
				if (_Keyeq()(key, pnode->value))
				{
					_DelVal()(pnode->value);
					pnode->value = std::move(Value);
					return true;
				}
			}
			pnode = new_node();
			if (pnode == nullptr)
				return false;
			pnode->value = std::move(Value);
			pnode->pNext = _ppv[upos];
			_ppv[upos] = pnode;
			_usize++;
			return true;
		};
		value_type* get(key_type key) noexcept
		{
			if (nullptr == _ppv || !_usize)
				return nullptr;
			size_type upos = _Hasher()(key) % _uhashsize;
			t_node* pnode;
			for (pnode = _ppv[upos]; pnode != nullptr; pnode = pnode->pNext) {
				if (_Keyeq()(key, pnode->value))
					return &pnode->value;
			}
			return nullptr;
		}
		bool get(key_type key, value_type& Value) noexcept //Multi-thread safe if _pmutex not null
		{
			unique_spinlock lck(_pmutex);
			value_type* pv = get(key);
			if (nullptr == pv)
				return false;
			Value = *pv;
			return true;
		}
		void clear() noexcept //Multi-thread safe if _pmutex not null
		{
			unique_spinlock lck(_pmutex);
			if (!_ppv)
				return;
			if (_usize)
			{
				t_node* ppre, *pNode;
				for (size_type i = 0; i < _uhashsize; i++)
				{
					pNode = _ppv[i];
					while (pNode)
					{
						ppre = pNode;
						pNode = pNode->pNext;
						_DelVal()(ppre->value);
						free_node(ppre);
					}
				}
			}
			delete[] _ppv;
			_ppv = nullptr;
			_usize = 0;
		};
		bool erase(key_type key) noexcept //Multi-thread safe if _pmutex not null
		{
			unique_spinlock lck(_pmutex);
			if (nullptr == _ppv || !_usize)
				return false;
			size_type upos = _Hasher()(key) % _uhashsize;
			t_node** ppNodePrev;
			ppNodePrev = &_ppv[upos];
			t_node* pNode;
			for (pNode = *ppNodePrev; pNode != nullptr; pNode = pNode->pNext)
			{
				if (_Keyeq()(key, pNode->value))
				{
					*ppNodePrev = pNode->pNext;
					_DelVal()(pNode->value);
					free_node(pNode);
					_usize--;
					return true;
				}
				ppNodePrev = &pNode->pNext;
			}
			return false;
		};
		value_type* next(iterator& i) noexcept
		{
			value_type* pv = nullptr;
			if (nullptr == _ppv || (i >> 32) >= _uhashsize || !_usize) {
				i = end();
				return pv;
			}
			t_node* pNode = nullptr;
			unsigned int ih = (unsigned int)(i >> 32), il = (unsigned)(i & 0xffffffff);
			unsigned int ul;
			while (ih < _uhashsize) {
				pNode = _ppv[ih];
				ul = 0;
				while (ul < il && pNode) {
					pNode = pNode->pNext;
					ul++;
				}
				if (pNode) {
					pv = &pNode->value;
					if (!pNode->pNext)
						i = _nexti(ih + 1, 0);
					else
						i = _nexti(ih, ul + 1);
					return pv;
				}
				ih++;
				il = 0;
			}
			i = ~0;
			return nullptr;
		}
		inline bool next(iterator& i, value_type* &pv) noexcept
		{
			pv = next(i);
			return pv != nullptr;
		}
		bool next(iterator& i, value_type &rValue) noexcept //Multi-thread safe if _pmutex not null
		{
			if (_pmutex)
				_pmutex->lock();
			value_type* pv = nullptr;
			bool bret = next(i, pv);
			if (bret)
				rValue = *pv;
			if (_pmutex)
				_pmutex->unlock();
			return bret;
		};
		void for_each(std::function<void(value_type& val)> fun) noexcept //Multi-thread safe if _pmutex not null
		{			
			iterator i = begin();
			if (_pmutex)
				_pmutex->lock();
			value_type* pv = next(i);
			while (pv)
			{
				fun(*pv);
				pv = next(i);
			}
			if (_pmutex)
				_pmutex->unlock();
		}
	private:
		iterator _nexti(unsigned int ih, unsigned int il) noexcept
		{
			iterator ir = 0;
			unsigned int ul;
			t_node* pNode;
			while (ih < _uhashsize) {
				pNode = _ppv[ih];
				ul = 0;
				while (ul < il && pNode) {
					pNode = pNode->pNext;
					ul++;
				}
				if (pNode) {
					ir = ih;
					ir <<= 32;
					ir += ul;
					return ir;
				}
				ih++;
				il = 0;
			}
			return ~0;
		}
	};
}


/* // ec::map examples

#include "ec/c11_system.h"
#include "ec/c_command.h"

class ctst
{
public:
	ctst() {
		_nid = 0;
		printf("construct\n");
	}
	ctst(int n) {
		_nid = n;
	}
	~ctst() {
		printf("destruct %d\n", _nid);
	}
	int _nid;
};

namespace ec {
	template<>
	struct key_equal<int, ctst>
	{
		bool operator()(int key, const ctst& val)
		{
			return key == val._nid;
		}
	};
	template<>
	struct del_node<ctst>
	{
		void operator()(ctst& val)
		{
			printf("del_node delete %d\n", val._nid);
		}
	};
}


struct t_item {
	int nid;
};

namespace ec {
	template<>
	struct key_equal<int, t_item>
	{
		bool operator()(int key, const t_item& val)
		{
			return key == val.nid;
		}
	};

	template<>
	struct del_node<t_item>
	{
		void operator()(t_item& val)
		{
			printf("del_node delete %d\n", val.nid);
		}
	};
}

void testclsmap()
{
	printf("test class map-----------------\n");
	ec::map<int, ctst> map;
	ctst cls1(1), cls2(2);

	map.set(cls1._nid, cls1);
	map.set(cls2._nid, cls2);

	printf("for each\n");
	map.for_each([](ctst& v) {
		printf("nid=%d\n", v._nid);
	});
	printf("clear,remove all items\n");
	map.clear();
	printf("clear,complete\n");
}

void teststructmap()
{
	printf("test struct map-----------------\n");
	ec::map<int, t_item> map;
	t_item it;

	it.nid = 1;
	map.set(it.nid, it);

	it.nid = 2;
	map.set(it.nid, it);

	it.nid = 3;
	map.set(it.nid, it);

	map.for_each([](t_item& v) {
		printf("nid=%d\n", v.nid);
	});
}

typedef int* intptr;
namespace ec {
	template<>
	struct key_equal<int, intptr>
	{
		bool operator()(int key, const intptr &val)
		{
			return key == *val;
		}
	};
	template<>
	struct del_node<intptr>
	{
		void operator()(intptr& val)
		{
			if (val)
			{
				printf("del_node delete %d\n", *val);
				delete val;
				val = nullptr;
			}
		}
	};
}

void testptrmap()
{
	printf("test pointer map-----------------\n");
	int *p;
	ec::map<int, int*> map;

	p = new int(1);
	map.set(*p, p);

	p = new int(2);
	map.set(*p, p);

	p = new int(3);
	map.set(*p, p);

	map.for_each([](int*& v) {
		printf("nid=%d\n", *v);
	});
}

namespace ec {
	template<>
	struct key_equal<const char*, std::string>
	{
		bool operator()(const char* key, const std::string &val)
		{
			return !strcmp(key, val.c_str());
		}
	};
	template<>
	struct del_node<std::string>
	{
		void operator()(std::string& val)
		{
			printf("del_node delete %s\n", val.c_str());
		}
	};
}
#include <string>
void tststdstrmap()
{
	printf("test std::string map-----------------\n");
	ec::map<const char*, std::string> map;

	std::string str1("str1"), str2("str2"), str3("str3");
	map.set("str1", str1);
	map.set("str2", str2);
	map.set("str3", str3);

	map.for_each([](std::string & v) {
		printf("%s\n", v.c_str());
	});
}
#define CMDOD_LEN 1024
int main(int argc, char* argv[])
{
	char sod[CMDOD_LEN];
	memset(sod, 0, sizeof(sod));
	testclsmap();
	teststructmap();
	testptrmap();
	tststdstrmap();
	printf("type 'exit' to exit\n");
	while (1) {
		if (fgets(sod, CMDOD_LEN - 1, stdin)) {
			ec::cCommandLine cmd(sod);
			if (!strcmp(cmd["command"], "exit"))
				break;
			else
				printf("error cmd\n");
		}
	}
	return 0;
}
*/