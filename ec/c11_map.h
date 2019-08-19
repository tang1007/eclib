/*!
\file c11_map.h
\author	jiangyong
\email  kipway@outlook.com
\update 2019.8.19

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
		typedef _Ty	value_type;
		void operator()(_Ty& val)
		{
			val.~value_type();
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
			if (!p)
				return;
			_DelVal()(p->value);
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
		bool has(key_type key) noexcept
		{
			unique_spinlock lck(_pmutex);
			if (nullptr == _ppv || !_usize)
				return false;
			size_type upos = _Hasher()(key) % _uhashsize;
			t_node* pnode;
			for (pnode = _ppv[upos]; pnode != nullptr; pnode = pnode->pNext) {
				if (_Keyeq()(key, pnode->value))
					return true;
			}
			return false;
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


/* ec::map examples

class ctst
{
public:
	ctst()
	{
		_id = 0;
		_sid[0] = 0;
		printf("construct ctst default\n");
	}
	ctst(int nid, const char* sid)
	{
		_id = nid;
		ec::str::lcpy(_sid, sid, sizeof(_sid));
		printf("construct ctst args(%d,%s)\n", _id, _sid);
	}
	ctst(const ctst &v)
	{
		_id = v._id;
		memcpy(_sid, v._sid, sizeof(_sid));
		printf("construct ctst cls(%d,%s)\n", _id, _sid);
	}

	void operator=(const ctst &v)
	{
		printf("=\n");
		_id = v._id;
		memcpy(_sid, v._sid, sizeof(_sid));
	}

	~ctst()
	{
		printf("destruct ctst(%d,%s)\n", _id, _sid);
	}
	int _id;
	char _sid[12];
};

typedef ctst* PTST;

namespace ec
{
	template<>
	struct key_equal<int, ctst>
	{
		bool operator()(int key, const ctst& val)
		{
			return key == val._id;
		}
	};

	template<>
	struct key_equal<int, PTST>
	{
		bool operator()(int key, const PTST& val)
		{
			return key == val->_id;
		}
	};

	template<>
	struct del_node<PTST>
	{
		void operator()(PTST& val)
		{
			if (val) {
				printf("del_node delete %d\n", val->_id);
				delete val;
				val = nullptr;
			}
		}
	};
}

void tstmap1()
{
	ec::memory _mem(ec::map<int, ctst>::size_node(), 40);
	ec::map<int, ctst> map(1024, &_mem);
	map.set(1, ctst(1, "s1"));
	map.set(2, ctst(2, "s2"));
	map.set(3, ctst(3, "s3"));
	map.set(4, ctst(4, "s4"));
	ctst ti(5, "s5");
	map.set(5, ti);

	printf("for_each:\n");
	map.for_each([](ctst &i) {
		printf("%d,%s\n", i._id, i._sid);
		});

	map.erase(3);
	printf("erase 3:\n");
	map.for_each([](ctst &i) {
		printf("%d,%s\n", i._id, i._sid);
		});

	ctst tr;
	if (map.get(5, tr)) {
		printf("get key == 5 success!(%d,%s)\n", tr._id, tr._sid);
	}
}

void tstmap2()
{
	ec::memory _mem(ec::map<int, PTST>::size_node(), 40);
	ec::map<int, PTST> map(1024, &_mem);
	map.set(1, new ctst(1, "s1"));
	map.set(2, new ctst(2, "s2"));
	map.set(3, new ctst(3, "s3"));
	map.set(4, new ctst(4, "s4"));
	ctst* p = new ctst(5, "s5");
	map.set(5, p);
	printf("for_each:\n");
	map.for_each([](PTST &i) {
		printf("%d,%s\n", i->_id, i->_sid);
		});

	map.erase(3);
	printf("erase 3:\n");
	map.for_each([](PTST &i) {
		printf("%d,%s\n", i->_id, i->_sid);
		});

	if (map.get(5, p)) {
		printf("get key == 5 success! (%d,%s)\n", p->_id, p->_sid);
	}
}
*/
