/*!
\file c11_array.h
\author	kipway@outlook.com
\update 2018.3.9

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
				memcpy(&_data[_size], pbuf, usize * sizeof(value_type));
			_size += usize;
			return true;
		};
		inline bool push_back(const value_type& val) noexcept
		{
			return add(val);
		}
		inline void pop_back()
		{
			if (_size > 0)
				_size--;
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
		void for_each(void(*fun)(value_type& val)) noexcept
		{
			for (size_type i = 0; i < _size; i++)
				fun(_data[i]);
		}
		void for_each(iterator first, iterator last, void(*fun)(value_type& val)) noexcept
		{
			while (first != last)
				fun(*first++);
		}
		void for_each(void*param, void(*fun)(value_type& val, void* param)) noexcept
		{
			for (size_type i = 0; i < _size; i++)
				fun(_data[i], param);
		}
		void for_each(void*param, iterator first, iterator last, void(*fun)(value_type& val, void* param)) noexcept
		{
			while (first != last)
				fun(*first++, param);
		}
		inline value_type* data() noexcept
		{
			return &_data[0];
		}
		inline const value_type* data() const noexcept
		{
			return &_data[0];
		}
	};
}
