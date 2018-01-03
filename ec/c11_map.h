/*!
\file c11_map.h
\author	kipway@outlook.com
\update 2018.1.3

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
#include <cstdint>
namespace ec
{
	template<class _Kty> // hash class
	struct hash
	{
		size_t operator()(_Kty key)
		{
			if (sizeof(size_t) == 8)
				return (((size_t)key) * 11400714819323198485ULL);
			return (((size_t)key) * 2654435769U);
		}
	};
	template<>
	struct hash<const char*>
	{
		size_t  operator()(const char*  key)
		{
			register unsigned int uHash = 0;
			while (char ch = *key++)
				uHash = uHash * 31 + ch;
			return uHash;
		}
	};
	template<>
	struct hash<char*>
	{
		size_t operator()(char*  key)
		{
			register unsigned int uHash = 0;
			while (char ch = *key++)
				uHash = uHash * 31 + ch;
			return uHash;
		}
	};

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
		t_node**	_ppv;
		size_type   _uhashsize;
		size_type	_usize;
	public:
		map(unsigned int uhashsize = 1024) : _ppv(nullptr), _uhashsize(uhashsize), _usize(0)
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
		inline size_type size() const noexcept
		{
			return _usize;
		};
		inline bool empty() const noexcept
		{
			return !(_pbuf && _usize);
		}
		iterator begin() noexcept
		{
			iterator ir = 0;
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
		bool set(key_type key, value_type& Value) noexcept
		{
			if (nullptr == _ppv)
				return false;
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
			pnode = new t_node;
			if (pnode == nullptr)
				return false;
			pnode->value = Value;
			pnode->pNext = _ppv[upos];
			_ppv[upos] = pnode;
			_usize++;
			return true;
		};
		value_type* get(key_type key) noexcept
		{
			if (nullptr == _ppv)
				return nullptr;
			size_type upos = _Hasher()(key) % _uhashsize;
			t_node* pnode;
			for (pnode = _ppv[upos]; pnode != nullptr; pnode = pnode->pNext) {
				if (_Keyeq()(key, pnode->value))
					return &pnode->value;
			}
			return nullptr;
		}
		bool get(key_type key, value_type& Value) noexcept
		{
			value_type* pv = get(key);
			if (nullptr == _ppv)
				return false;
			Value = *pv;
			return true;
		}
		void clear() noexcept
		{
			if (!_ppv || !_usize)
				return;
			t_node* ppre, *pNode;
			for (size_type i = 0; i < _uhashsize; i++)
			{
				pNode = _ppv[i];
				while (pNode)
				{
					ppre = pNode;
					pNode = pNode->pNext;
					_DelVal()(ppre->value);
					delete ppre;
				}
			}
			delete[] _ppv;
			_ppv = nullptr;
			_usize = 0;
		};
		bool erase(key_type key) noexcept
		{
			if (nullptr == _ppv)
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
					delete pNode;
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
			if (nullptr == _ppv || (i >> 32) >= _uhashsize) {
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
		bool next(iterator& i, value_type &rValue) noexcept
		{
			value_type* pv = nullptr;
			bool bret = next(i, pv);
			if (bret)
				rValue = *pv;
			return bret;
		};
		void for_each(void(*fun)(value_type& val)) noexcept
		{
			iterator i = begin();
			value_type* pv = next(i);
			while (pv)
			{
				fun(*pv);
				pv = next(i);
			}
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
/*
//usage and test

struct t_item
{
	char name[32];
	int v;
	int *pv;
};

namespace ec
{
	template<>
	struct key_equal<const char*, t_item>
	{
		bool operator()(const char* key, const t_item& val)
		{
			return !strcmp(key, val.name);
		}
	};

	template<>
	struct del_node<t_item>
	{
		void operator()(t_item& val)
		{
			if (val.pv)
			{
				printf("delete %s.pv,*pv = %d\n", val.name, *(val.pv));
				delete val.pv;
				val.pv = nullptr;
			}
		}
	};
}
void tstecmap()
{
	ec::map<const char*, t_item> map1;

	t_item it;
	strcpy(it.name, "1");
	it.v = 1;
	it.pv = new int;
	*it.pv = 1;
	map1.set(it.name, it);

	strcpy(it.name, "2");
	it.v = 2;
	it.pv = new int;
	*it.pv = 2;
	map1.set(it.name, it);

	map1.for_each([](t_item& v)
	{
		printf("key=%s:v=%d,*pv=%d\n", v.name, v.v, *v.pv);
	});

	if (map1.get("1", it))
		printf("key=%s:v=%d,*pv=%d\n", it.name, it.v, *it.pv);

	if (map1.get("2", it))
		printf("key=%s:v=%d,*pv=%d\n", it.name, it.v, *it.pv);

	ec::map<const char*, t_item, ec::key_equal<const char*, t_item>>::iterator i;
	i = map1.begin();
	while (i != map1.end())
	{
		t_item* pit = 0;
		if (map1.next(i, pit))
			printf("key=%s:v=%d,*pv=%d\n", pit->name, pit->v, *(pit->pv));
	}

	i = map1.begin();
	while (i != map1.end())
	{
		if (map1.next(i, it))
			printf("key=%s:v=%d,*pv=%d\n", it.name, it.v, *(it.pv));
	}

	strcpy(it.name, "1");//replace old
	it.v = 1;
	it.pv = new int;
	*it.pv = 11;
	map1.set(it.name, it); // first del_node ,then replace
}

int main(int argc, char*argv[])
{
	tstecmap();
	return 0;
}
*/