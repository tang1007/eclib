/*!
\file c11_array.h
\author	jiangyong
\email  kipway@outlook.com
\update 2019.1.22

eclib class stack array with c++11.

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
#include <memory.h>
#include <algorithm> // std::sort
#include <functional>
namespace ec {
	template<typename _Tp, size_t _Num>
	class Array {
	public:
		typedef _Tp		value_type;
		typedef size_t	size_type;
		typedef _Tp*	iterator;
		Array() :_bufsize(_Num), _size(0) {
		}
	protected:
		size_type _bufsize;
		size_type _size;
		value_type _data[_Num];
	public:
		inline size_type size() const noexcept
		{
			return _size;
		}
		inline void clear() noexcept
		{
			_size = 0;
		}
		inline size_type capacity() const noexcept
		{
			return _bufsize;
		}
		bool add(const value_type &obj) noexcept
		{
			if (_size >= _bufsize)
				return false;
			_data[_size++] = obj;
			return true;
		}
		bool add(const value_type &obj, size_type size) noexcept
		{
			if (_size + size > _bufsize)
				return false;
			for (size_type i = 0; i < size; i++)
				_data[_size++] = obj;
			return true;
		}
		bool add(const value_type *pbuf, size_type usize = 1) noexcept
		{
			if (!usize || !pbuf)
				return true;
			if (_size + usize > _bufsize)
				return false;
			memcpy(&_data[_size], pbuf, usize * sizeof(value_type));
			_size += usize;
			return true;
		};
		inline bool push_back(const value_type& val) noexcept
		{
			return add(val);
		}
		inline void pop_back() noexcept
		{
			if (_size > 0)
				_size--;
		}
		inline bool push(const value_type& val) noexcept
		{
			return add(val);
		}
		inline bool pop(value_type& val) noexcept
		{
			if (_size > 0) {
				_size--;
				val = _data[_size];
				return true;
			}
			return false;
		}
		inline value_type& operator [](size_type pos)
		{
			return _data[pos];
		}
		inline iterator begin() noexcept
		{
			return &_data[0];
		}
		inline iterator end() noexcept
		{
			return &_data[_size];
		}
		inline bool empty() const noexcept
		{
			return !_size;
		}
		inline bool full() const noexcept
		{
			return _size >= _bufsize;
		}		
		void for_each(std::function<void (value_type& val)> fun) noexcept
		{
			for (size_type i = 0; i < _size; i++)
				fun(_data[i]);
		}
		void for_each(iterator first, iterator last, std::function<void(value_type& val)> fun) noexcept
		{
			while (first != last)
				fun(*first++);
		}		
		inline value_type* data() noexcept
		{
			return &_data[0];
		}
		inline const value_type* data() const noexcept
		{
			return &_data[0];
		}
		bool erase(value_type &val) noexcept
		{
			for (size_type i = 0; i < _size; i++) {
				if (val == _data[i]) {
					while (i + 1 < _size) {
						_data[i] = _data[i + 1];
						i++;
					}
					_size--;
					return true;
				}
			}
			return false;
		}

		bool erase(size_type pos) noexcept
		{
			if (pos >= _size)
				return false;
			while (pos + 1 < _size) {
				_data[pos] = _data[pos + 1];
				pos++;
			}
			_size--;
			return true;
		}

		void erase(size_type pos, size_type size) noexcept
		{
			if ( pos >= _size)
				return;
			if (pos + size >= _size)
				_size = pos;
			else {
				memmove(&_data[pos], &_data[pos + size], (_size - (pos + size)) * sizeof(value_type));
				_size -= size;
			}
		}

		value_type* find(std::function <bool(value_type& val)> fun) {
			for (size_type i = 0; i < _size; i++) {
				if (fun(_data[i]))
					return &_data[i];
			}
			return nullptr;
		}		
		inline value_type& at(size_type pos)
		{
			return _data[pos];
		}
		inline bool at(size_type pos, value_type& v) noexcept
		{
			if (pos < _size) {
				v = _data[pos];
				return true;
			}
			return false;
		}
		inline value_type* atptr(size_type pos) noexcept
		{
			if (pos < _size)
				return &_data[pos];
			return nullptr;
		}
		inline void sort(std::function<bool(const value_type& v1, const value_type& v2)> cmp)
		{
			std::sort(begin(), end(), cmp);
		}
		inline void sort(iterator istart, iterator iend, std::function<bool(const value_type& v1, const value_type& v2)> cmp)
		{
			std::sort(istart, iend, cmp);
		}
		void setsize(size_t size)
		{
			if (size <= _bufsize)
				_size = size;
		}
		bool insert(size_type pos, const value_type *pval, size_t insize = 1) noexcept // insert before
		{
			if (_size + insize > _bufsize || !insize || !pval)
				return false;
			if (_size >= _size)
				return add(pval, insize);
			memmove(&_data[pos] + insize, &_data[pos], (_size - pos) * sizeof(value_type));
			memcpy(&_data[pos], pval, insize * sizeof(value_type));
			_size += insize;
			return true;
		}
	};
}
