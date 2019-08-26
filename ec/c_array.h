/*!
\file c_array.h
\author kipway@outlook.com
\update 2018.1.4

eclib class tArray ,fast noexcept simple array. members of a array can only be simple types, pointers and structures

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

#ifndef C_ARRAY_H
#define C_ARRAY_H

#include <stdlib.h>
#include <memory.h>
#if (0 != USE_ECLIB_C11)
#undef max
#undef min
#include <cstdint>
#include <algorithm>
#include <functional>
#endif
namespace ec
{
	template<class _Ty>
	class tArray
	{
	public:
		typedef size_t	size_type;
		typedef _Ty	 value_type;
		typedef _Ty* iterator;
		tArray(size_type ugrownsize)
		{
			_pbuf = 0;
			_usize = 0;
			_ubufsize = 0;
			set_grow(ugrownsize);
		};
		tArray(size_type ugrownsize, const value_type& val) : _pbuf(0), _usize(0), _ubufsize(0)
		{
			set_grow(ugrownsize);
			push_back(val);
		};
		tArray(size_type ugrownsize, const value_type* pval, size_type size) : _pbuf(0), _usize(0), _ubufsize(0)
		{
			set_grow(ugrownsize);
			add(pval, size);
		};
		~tArray()
		{
			if (_pbuf) {
				free(_pbuf);
				_pbuf = 0;
				_usize = 0;
				_ubufsize = 0;
			}
		};
	protected:
		value_type*	_pbuf;
		size_type	_usize;
		size_type	_ubufsize;
		size_type	_ugrown;
	protected:
		bool _grown(size_type usize = 1)
		{
			value_type	*pt = 0;
			size_type	usizet = _usize + usize;
			if (!usize)
				return true;
			if (usizet > max_size())
				return false;
			if (usizet > _ubufsize) {
				usizet += _ugrown - (usizet%_ugrown);
				pt = (value_type*)realloc(_pbuf, usizet * sizeof(value_type));
				if (!pt)
					return false;
				_pbuf = pt;
				_ubufsize = usizet;
			}
			return true;
		}
	public: // c++11 style
		inline size_type max_size() const
		{
			return SIZE_MAX / sizeof(value_type);
		}
		inline value_type& operator [](size_type pos)
		{
			return _pbuf[pos];
		}
		inline value_type valat(size_type pos)
		{
			return _pbuf[pos];
		}
		inline value_type* data()
		{
			return _pbuf;
		}
		inline size_type size()
		{
			return _usize;
		}
		inline void clear()
		{
			_usize = 0;
		}
		inline void clear(size_type shrinksize)
		{
			_usize = 0;
			shrink(shrinksize);
		}
		void shrink(size_type size)
		{
			if (!_pbuf || _ubufsize <= size)
				return;
			if (!size && !_usize) {
				free(_pbuf);
				_pbuf = 0;
				_ubufsize = 0;
				return;
			}
			if (_usize >= size)
				return;
			value_type* pnew = (value_type*)malloc(size * sizeof(value_type));
			if (!pnew)
				return;
			if (_usize)
				memcpy(pnew, _pbuf, _usize * sizeof(value_type));
			free(_pbuf);
			_pbuf = pnew;
			_ubufsize = size;
		}
		inline size_type capacity()
		{
			return _ubufsize;
		}
		bool add(const value_type &obj)
		{
			if (!_grown())
				return false;
			*(_pbuf + _usize) = obj;
			_usize += 1;
			return true;
		}
		bool add(const value_type &obj, size_type size)
		{
			if (!_grown(size))
				return false;
			for (size_type i = 0; i < size; i++) {
				*(_pbuf + _usize) = obj;
				_usize++;
			}
			return true;
		}
		bool add(const value_type *pbuf, size_type usize = 1)
		{
			if (!usize || !pbuf)
				return true;
			if (!_grown(usize))
				return false;
			memcpy(_pbuf + _usize, pbuf, usize * sizeof(value_type));
			_usize += usize;
			return true;
		};
		inline bool push_back(const value_type& val)
		{
			return add(val);
		}
		inline void pop_back()
		{
			if (_usize > 0)
				_usize--;
		}
		inline iterator begin()
		{
			return _pbuf;
		}
		inline iterator end()
		{
			return _pbuf + _usize;
		}
		inline bool empty() const
		{
			return !(_pbuf && _usize);
		}
#if (USE_ECLIB_C11 == 0)
		void for_each(void(*fun)(value_type& val))
		{
			for (size_type i = 0; i < _usize; i++)
				fun(_pbuf[i]);
		}
		void for_each(iterator first, iterator last, void(*fun)(value_type& val))
		{
			while (first != last)
				fun(*first++);
		}
		void for_each(void*param, void(*fun)(value_type& val, void* param))
		{
			for (size_type i = 0; i < _usize; i++)
				fun(_pbuf[i], param);
		}
		void for_each(void*param, iterator first, iterator last, void(*fun)(value_type& val, void* param))
		{
			while (first != last)
				fun(*first++, param);
		}
#endif
		bool insert(size_type pos, const value_type *pbuf, size_type usize)  // insert before
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
		bool replace(size_type pos, size_type rsize, const value_type *pbuf, size_type usize)
		{
			if (!rsize)
				return insert(pos, pbuf, usize);  // insert
			if (!pbuf || !usize) { //delete
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
			if (pos + rsize >= _usize) { //outof end
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
		void erase(size_type pos, size_type size = 1)
		{
			if (!_pbuf || pos >= _usize || !size)
				return;
			if (pos + size >= _usize)
				_usize = pos;
			else {
				memmove(_pbuf + pos, _pbuf + pos + size, (_usize - (pos + size)) * sizeof(value_type));
				_usize -= size;
			}
		}
#if (0 != USE_ECLIB_C11)
		inline void sort(bool(*cmp)(const value_type& v1, const value_type& v2)) noexcept
		{
			if (_usize > 1)
				std::sort(begin(), end(), cmp);
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
#endif
	public: // Adapt for old version
		inline value_type* GetBuf() const
		{
			return _pbuf;
		};
		inline unsigned int GetSize() const
		{
			return (unsigned int)_usize;
		};
		inline int	GetNum() const
		{
			return (int)_usize;
		};
		inline unsigned int GetBufSize()
		{
			return (unsigned int)_ubufsize;
		};
		inline void SetDataSize(size_type n)
		{
			_usize = n;
		};
		inline bool Add(value_type obj)
		{
			return add(obj);
		}
		inline bool Add(const value_type *pbuf, size_type usize = 1)
		{
			return add(pbuf, usize);
		};
		value_type*	GetAt(size_type pos)
		{
			if (pos < _usize)
				return &_pbuf[pos];
			return 0;
		}
		void SetGrowSize(size_type ugrowsize)
		{
			_ugrown = ugrowsize;
			if (_ugrown % 4)
				_ugrown += 4 - (_ugrown % 4);
			if (_ugrown > max_size())
				_ugrown = max_size();
		};
		inline void set_grow(size_type ugrowsize)
		{
			SetGrowSize(ugrowsize);
		}
		inline void	ClearData()
		{
			_usize = 0;
		};
		bool DeleteAt(size_type pos, value_type& item)
		{
			if (!_pbuf || pos >= _usize)
				return false;
			item = _pbuf[pos];
			if (pos + 1 < _usize)
				memmove(_pbuf + pos, _pbuf + pos + 1, sizeof(value_type) * (_usize - pos - 1));
			_usize--;
			return true;
		}
		inline void LeftMove(size_type  n)
		{
			erase(0, n);
		};
		inline void  ClearAndFree(size_type sizemin)//clear data, if _ubufsize > sizemin free _pbuf
		{
			clear();
			if (capacity() > sizemin)
				shrink(0);
		}
		inline void ReduceMem(size_type itemsize)//shrink buffer to itemsize,keep data
		{
			shrink(itemsize);
		}
		inline bool InsertAt(size_type pos, const value_type *pbuf, size_type usize)
		{
			return insert(pos, pbuf, usize);
		}
		inline bool Replace(size_type pos, size_type rsize, const value_type *pbuf, size_type usize)
		{
			return replace(pos, rsize, pbuf, usize);
		}
		inline bool Delete(size_type pos, size_type rsize)
		{
			erase(pos, rsize);
			return true;
		}
		inline void reduceto(size_type size)
		{
			if (_usize > size)
				_usize = size;
		}
#ifdef _WIN32
		static int  compare(void* pParam, const void *p1, const void* p2);
#else
		static int  compare(const void *p1, const void* p2, void* pParam);
#endif

#ifdef _WIN32
		void Sort(void* pCompareParam)
		{
			if (_usize > 1)
				qsort_s(_pbuf, _usize, sizeof(value_type), compare, pCompareParam);
		}
#else
		void Sort(void* pCompareParam)
		{
			if (_usize > 1)
				qsort_r(_pbuf, _usize, sizeof(value_type), &compare, pCompareParam);
		}
#endif // _WIN32
	};
}; //ec

#endif // C_ARRAY_H

