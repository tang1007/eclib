/*!
\file c11_vector.h
\author	jiangyong
\email  kipway@outlook.com
\update 2018.7.27

eclib class vector with c++11. fast noexcept simple vector. members of a vector can only be simple types, pointers and structures

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
#include <algorithm> // std::sort
#include <functional>
#include "c11_memory.h"
namespace ec
{
	template<typename _Tp>
	class vector
	{
	public:
		typedef _Tp		value_type;
		typedef size_t	size_type;
		typedef _Tp*	iterator;
		vector(size_type ugrownsize, ec::memory* pmem = nullptr) : _pbuf(nullptr), _usize(0), _ubufsize(0), _pmem(pmem), _doublegrown(false)
		{
			set_grow(ugrownsize);
		};
		vector(size_type ugrownsize, const value_type& val, ec::memory* pmem = nullptr) : _pbuf(nullptr), _usize(0), _ubufsize(0), _pmem(pmem), _doublegrown(false)
		{
			set_grow(ugrownsize);
			push_back(val);
		};
		vector(size_type ugrownsize, const value_type* pval, size_type size, ec::memory* pmem = nullptr) : _pbuf(nullptr), _usize(0), _ubufsize(0), _pmem(pmem), _doublegrown(false)
		{
			set_grow(ugrownsize);
			add(pval, size);
		};
		vector(size_type initsize, bool doublegrown, ec::memory* pmem = nullptr) : _pbuf(nullptr), _usize(0), _ubufsize(0), _pmem(pmem), _doublegrown(doublegrown)
		{
			set_grow(initsize);
		}
		vector(vector &&v)
		{
			_pbuf = v._pbuf;
			_usize = v._usize;
			_ubufsize = v._ubufsize;
			_ugrown = v._ugrown;
			_pmem = v._pmem;
			_doublegrown = v._doublegrown;
			v._pbuf = nullptr;
			v._usize = 0;
			v._ubufsize = 0;
		}
		~vector()
		{
			if (_pbuf != nullptr) {
				mem_free(_pbuf);
				_pbuf = nullptr;
				_usize = 0;
				_ubufsize = 0;
				_pmem = nullptr;
			}
		};
		vector& operator = (vector&& v)
		{
			this->~vector();
			_pbuf = v._pbuf;
			_usize = v._usize;
			_ubufsize = v._ubufsize;
			_ugrown = v._ugrown;
			_pmem = v._pmem;
			v._pbuf = nullptr;
			v._usize = 0;
			v._ubufsize = 0;
			return *this;
		}
		inline ec::memory* get_mem_allocator() {
			return _pmem;
		}
	protected:
		value_type * _pbuf;
		size_type	_usize;
		size_type	_ubufsize;
		size_type	_ugrown;
		bool		_doublegrown; //auto double grown
	private:
		ec::memory *_pmem;
		inline void *mem_malloc(size_t size, size_t &sizeout) {
			if (_pmem)
				return _pmem->malloc(size, sizeout);
			sizeout = size;
			return malloc(size);
		}
		inline void mem_free(void* p) {
			if (_pmem)
				_pmem->mem_free(p);
			else
				free(p);
		}
		inline void* mem_realloc(size_t size, size_t &sizeout) {
			if (_pmem) {
				void *pnew = _pmem->malloc(size, sizeout);
				if (!pnew)
					return nullptr;
				if (_pbuf) {
					if (_usize)
						memcpy(pnew, _pbuf, ((_usize < size) ? _usize : size) * sizeof(value_type));
					_pmem->mem_free(_pbuf);
				}
				return pnew;
			}
			sizeout = size;
			return realloc(_pbuf, size);
		}
	public:
		inline size_type max_size() const noexcept
		{
			return SIZE_MAX / sizeof(value_type);
		}
		void set_grow(size_type ugrowsize) noexcept
		{
			_ugrown = ugrowsize;
			if (!_ugrown)
				_ugrown = 4;
			if (_ugrown % 4)
				_ugrown += 4 - (_ugrown % 4);
			if (_ugrown > max_size())
				_ugrown = max_size();
		};
		bool set_size(size_t size)
		{
			if (_ubufsize < size)
				return false;
			_usize = size;
			return true;
		}
		inline size_type size() const noexcept
		{
			return _usize;
		}
		inline void clear(bool bfreemem = false) noexcept
		{
			_usize = 0;
			if (bfreemem && _pbuf) {
				mem_free(_pbuf);
				_pbuf = nullptr;
				_ubufsize = 0;
			}
		}
		inline void clear(size_type shrinksize) noexcept
		{
			_usize = 0;
			shrink(shrinksize);
		}
		inline size_type capacity() const noexcept
		{
			return _ubufsize;
		}
		bool add(const value_type &obj) noexcept
		{
			if (!_grown())
				return false;
			*(_pbuf + _usize) = obj;
			_usize += 1;
			return true;
		}
		bool add(const value_type &obj, size_type size) noexcept
		{
			if (!_grown(size))
				return false;
			for (size_type i = 0; i < size; i++)
			{
				*(_pbuf + _usize) = obj;
				_usize++;
			}
			return true;
		}
		bool add(const value_type *pbuf, size_type usize = 1) noexcept
		{
			if (!usize || !pbuf)
				return true;
			if (!_grown(usize))
				return false;
			memcpy(_pbuf + _usize, pbuf, usize * sizeof(value_type));
			_usize += usize;
			return true;
		};
		inline bool push_back(const value_type& val) noexcept
		{
			return add(val);
		}
		inline void pop_back() noexcept
		{
			if (_usize > 0)
				_usize--;
		}
		inline bool push(const value_type& val) noexcept
		{
			return add(val);
		}
		inline bool pop(value_type& val) noexcept
		{
			if (_usize > 0) {
				_usize--;
				val = _pbuf[_usize];
				return true;
			}
			return false;
		}
		inline value_type& operator [](size_type pos)
		{
			return _pbuf[pos];
		}
		inline iterator begin() noexcept
		{
			return _pbuf;
		}
		inline iterator end() noexcept
		{
			return _pbuf + _usize;
		}
		inline bool empty() const noexcept
		{
			return !(_pbuf && _usize);
		}
		void for_each(std::function<void(value_type& val)> fun) noexcept
		{
			for (size_type i = 0; i < _usize; i++)
				fun(_pbuf[i]);
		}
		void for_each(iterator first, iterator last, std::function<void(value_type& val)> fun) noexcept
		{
			while (first != last)
				fun(*first++);
		}
		inline value_type* data() noexcept
		{
			return _pbuf;
		}
		inline const value_type* data() const noexcept
		{
			return _pbuf;
		}
		bool insert(size_type pos, const value_type *pbuf, size_type usize) noexcept // insert before
		{
			if (!pbuf || !usize)
				return false;
			if (pos >= _usize)
				return add(pbuf, usize);
			if (!_grown(usize))
				return false;
			memmove(_pbuf + pos + usize, _pbuf + pos, (_usize - pos) * sizeof(value_type));
			memcpy(_pbuf + pos, pbuf, usize * sizeof(value_type));
			_usize += usize;
			return true;
		}
		bool replace(size_type pos, size_type rsize, const value_type *pbuf, size_type usize) noexcept
		{
			if (!rsize)
				return insert(pos, pbuf, usize);  // insert
			if (!pbuf || !usize) //delete
			{
				if (pos + rsize >= _usize) {
					_usize = pos;
					return true;
				}
				memmove(_pbuf + pos, _pbuf + pos + rsize, (_usize - (pos + rsize)) * sizeof(value_type));
				_usize = _usize - rsize;
				return true;
			}
			if (pos >= _usize) // add
				return add(pbuf, usize);
			if (pos + rsize >= _usize)//outof end
			{
				_usize = pos;
				return add(pbuf, usize);
			}
			if (usize > rsize) {
				if (!_grown(usize - rsize))
					return false;
			}
			if (rsize != usize)
				memmove(_pbuf + pos + usize, _pbuf + pos + rsize, (_usize - (pos + rsize)) * sizeof(value_type));
			memcpy(_pbuf + pos, pbuf, usize * sizeof(value_type));
			_usize = _usize + usize - rsize;
			return true;
		}
		void erase(size_type pos, size_type size = 1) noexcept
		{
			if (!_pbuf || pos >= _usize)
				return;
			if (pos + size >= _usize)
				_usize = pos;
			else {
				memmove(_pbuf + pos, _pbuf + pos + size, (_usize - (pos + size)) * sizeof(value_type));
				_usize -= size;
			}
		}
		inline void sort(bool(*cmp)(const value_type& v1, const value_type& v2))
		{
			std::sort(begin(), end(), cmp);
		}
		void shrink(size_type size) noexcept
		{
			if (!_pbuf || _ubufsize <= size)
				return;
			if (!size && !_usize)
			{
				mem_free(_pbuf);
				_pbuf = 0;
				_ubufsize = 0;
				return;
			}
			if (_usize >= size)
				return;
			size_t sizeout = 0;
			value_type* pnew = (value_type*)mem_malloc(size * sizeof(value_type), sizeout);
			if (!pnew)
				return;
			if (_usize)
				memcpy(pnew, _pbuf, _usize * sizeof(value_type));
			mem_free(_pbuf);
			_pbuf = pnew;
			_ubufsize = sizeout / sizeof(value_type);
		}
		bool expand(size_type size) noexcept
		{
			if (_ubufsize >= size)
				return true;
			size_t sizeout = 0;
			value_type* pnew = (value_type*)mem_malloc(size * sizeof(value_type), sizeout);
			if (!pnew)
				return false;
			if (_pbuf)
			{
				if (_usize)
					memcpy(pnew, _pbuf, _usize * sizeof(value_type));
				mem_free(_pbuf);
			}
			_pbuf = pnew;
			_ubufsize = sizeout / sizeof(value_type);
			return true;
		}
		void* detach_buf() {
			void* p = (void*)_pbuf;
			_usize = 0;
			_ubufsize = 0;
			_pbuf = nullptr;
			return p;
		}
	private:
		bool _grown(size_type usize = 1) noexcept
		{
			if (_usize + usize <= _ubufsize || !usize)
				return true;
			size_type usizet;
			if (_doublegrown) {
				usizet = _ubufsize;
				if (!usizet)
					usizet = _ugrown;
				while (usizet < _usize + usize)
					usizet *= 2;
			}
			else
				usizet = _usize + usize;
			if (usizet > max_size())
				return false;
			usizet += _ugrown - (usizet % _ugrown);
			size_t sizeout = 0;
			value_type	*pt = (value_type*)mem_realloc(usizet * sizeof(value_type), sizeout);
			if (!pt)
				return false;
			_pbuf = pt;			
			_ubufsize = sizeout / sizeof(value_type);
			return true;
		}
	};
}
