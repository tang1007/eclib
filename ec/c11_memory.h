/*!
\file c11_memory.h
\author	jiangyong
\email  kipway@outlook.com
\update 2018.11.3

eclib class fast memory allocator with c++11.

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
#include <memory.h>
#include "c11_mutex.h"
#include "c11_stack.h"
namespace ec {
	class memory
	{
	public:
		memory(size_t sblksize, size_t sblknum,
			size_t mblksize = 0, size_t mblknum = 0,
			size_t lblksize = 0, size_t lblknum = 0,
			spinlock* pmutex = nullptr
		) : _ps(nullptr), _pm(nullptr), _pl(nullptr), _pmutex(pmutex), _stks(sblknum), _stkm(mblknum), _stkl(lblknum)
		{
			_sz_s = sblksize;// small memory blocks,Pre-allocation
			if (_sz_s % (sizeof(size_t) * 2))
				_sz_s += (sizeof(size_t) * 2) - sblksize % (sizeof(size_t) * 2);
			_blk_s = sblknum;
			malloc_block(_sz_s, _blk_s, _ps, _stks);

			_sz_m = mblksize; // medium memory blocks, malloc at the time of use
			if (_sz_m % (sizeof(size_t) * 2))
				_sz_m += (sizeof(size_t) * 2) - mblksize % (sizeof(size_t) * 2);
			_blk_m = mblknum;

			_sz_l = lblksize; // large memory blocks, malloc at the time of use
			if (_sz_l % (sizeof(size_t) * 2))
				_sz_l += (sizeof(size_t) * 2) - lblksize % (sizeof(size_t) * 2);
			_blk_l = lblknum;
			_nsys_malloc = 0;
		}
		~memory()
		{
			_stks.clear();
			_stkm.clear();
			_stkl.clear();
			if (_ps)
				::free(_ps);
			if (_pm)
				::free(_pm);
			if (_pl)
				::free(_pl);
		}
		void *mem_malloc(size_t size)
		{
			unique_spinlock lck(_pmutex);
			return _malloc(size);
		}
		void mem_free(void *pmem)
		{
			if (!pmem)
				return;
			unique_spinlock lck(_pmutex);
			size_t pa = (size_t)pmem;
			if (_ps && pa >= (size_t)_ps  && pa < (size_t)_ps + _sz_s * _blk_s)
				_stks.push(pmem);
			else if (_pm &&  pa >= (size_t)_pm  && pa < (size_t)_pm + _sz_m * _blk_m)
				_stkm.push(pmem);
			else if (_pl &&  pa >= (size_t)_pl  && pa < (size_t)_pl + _sz_l * _blk_l)
				_stkl.push(pmem);
			else {
				free(pmem);
				_nsys_malloc--;
			}
		}

		void *malloc(size_t size, size_t &outsize)
		{
			unique_spinlock lck(_pmutex);
			void* pr = nullptr;
			if (size <= _sz_s) {
				if (_stks.pop(pr)) {
					outsize = _sz_s;
					return pr;
				}
			}
			if (size <= _sz_m) {
				if (!_pm)
					malloc_block(_sz_m, _blk_m, _pm, _stkm);
				if (_stkm.pop(pr)) {
					outsize = _sz_m;
					return pr;
				}
				if (!_pl)
					malloc_block(_sz_l, _blk_l, _pl, _stkl);
				if (_pl && _stkl.size() > _stkl.capacity() / 2u) {
					if (_stkl.pop(pr)) {
						outsize = _sz_l;
						return pr;
					}
				}
			}
			else if (size <= _sz_l) {
				if (!_pl)
					malloc_block(_sz_l, _blk_l, _pl, _stkl);
				if (_stkl.pop(pr)) {
					outsize = _sz_l;
					return pr;
				}
			}
			outsize = size;
			pr = ::malloc(size);
			if (!pr)
				outsize = 0;
			else
				_nsys_malloc++;
			return pr;
		}

		void* mem_realloc(void *pmem, size_t size)
		{
			if (!pmem)
				return mem_malloc(size);
			if (!size) {
				mem_free(pmem);
				return nullptr;
			}
			if (1) {
				unique_spinlock lck(_pmutex);
				size_t pa = (size_t)pmem;
				if (_ps && pa >= (size_t)_ps  && pa < (size_t)_ps + _sz_s * _blk_s) {
					if (size <= _sz_s)
						return pmem;
					void* p = _malloc(size);
					if (!p)
						return nullptr;
					memcpy(p, pmem, _sz_s);
					_stks.push(pmem);
					return p;
				}
				else if (_pm &&  pa >= (size_t)_pm  && pa < (size_t)_pm + _sz_m * _blk_m) {
					if (size <= _sz_m)
						return pmem;
					void* p = _malloc(size);
					if (!p)
						return nullptr;
					memcpy(p, pmem, _sz_m);
					_stkm.push(pmem);
					return p;
				}
				else if (_pl &&  pa >= (size_t)_pl  && pa < (size_t)_pl + _sz_l * _blk_l) {
					if (size <= _sz_l)
						return pmem;
					void* p = _malloc(size);
					if (!p)
						return nullptr;
					memcpy(p, pmem, _sz_l);
					_stkl.push(pmem);
					return p;
				}
				else
					return ::realloc(pmem, size);
			}
			return nullptr;
		}

		void* mem_calloc(size_t count, size_t size) {
			void* p = mem_malloc(count * size);
			if (p)
				memset(p, 0, count * size);
			return p;
		}
		bool info(int idx, size_t *left, size_t *bufsize) {
			switch (idx) {
			case 0:*left = _stks.size(); *bufsize = _ps ? _stks.capacity() : 0; break;
			case 1:*left = _stkm.size(); *bufsize = _pm ? _stkm.capacity() : 0; break;
			case 2:*left = _stkl.size(); *bufsize = _pl ? _stkl.capacity() : 0; break;
			default:
				*left = 0;
				*bufsize = 0;
				return false;
			}
			return true;
		}
		inline int get_sys_mlloc() {
			return _nsys_malloc;
		}
	private:
		void *_ps, *_pm, *_pl;
		spinlock* _pmutex;
		size_t _sz_s, _sz_m, _sz_l;  //blocks size
		size_t _blk_s, _blk_m, _blk_l; // blocks number
		ec::stack<void*> _stks;     // small memory blocks
		ec::stack<void*> _stkm; // medium memory blocks
		ec::stack<void*> _stkl; // large memory blocks		
		int _nsys_malloc; //malloc memery blocks

		bool malloc_block(size_t blksize, size_t blknum, void * &ph, ec::stack<void*> &stk)
		{
			if (!blknum || !blksize)
				return false;
			size_t i;
			ph = ::malloc(blksize * blknum);
			if (ph) {
				uint8_t *p = (uint8_t *)ph;
				for (i = 0; i < blknum; i++)
					stk.add(p + (blknum - 1 - i) * blksize);
			}
			return ph != nullptr;
		}
		void *_malloc(size_t size)
		{
			void* pr = nullptr;
			if (size <= _sz_s) {
				if (_stks.pop(pr))
					return pr;
			}
			if (size <= _sz_m) {
				if (!_pm)
					malloc_block(_sz_m, _blk_m, _pm, _stkm);
				if (_stkm.pop(pr))
					return pr;
				if (!_pl)
					malloc_block(_sz_l, _blk_l, _pl, _stkl);
				if (_pl && _stkl.size() > _stkl.capacity() / 2u) {
					if (_stkl.pop(pr))
						return pr;
				}
			}
			else if (size <= _sz_l) {
				if (!_pl)
					malloc_block(_sz_l, _blk_l, _pl, _stkl);
				if (_stkl.pop(pr))
					return pr;
			}

			pr = ::malloc(size);
			if (pr)
				_nsys_malloc++;
			return pr;
		}
	};

	class auto_buffer
	{
	public:
		auto_buffer(memory* pmem = nullptr) :_pmem(pmem), _pbuf(0), _size(0), _sizebuf(0) {
		}
		~auto_buffer() {
			clear();
		}
	private:
		memory* _pmem;
		void*   _pbuf;
		size_t  _size;
		size_t  _sizebuf;
	public:
		inline void *data() {
			return _pbuf;
		}
		inline size_t size() {
			return _size;
		}
		inline void clear() {
			if (_pbuf) {
				if (_pmem)
					_pmem->mem_free(_pbuf);
				else
					::free(_pbuf);
				_pbuf = nullptr;
				_size = 0;
				_sizebuf = 0;
			}
		}
		inline void* resize(size_t rsz) {
			_size = rsz;
			if (_size > _sizebuf) {
				clear();
				if (_pmem)
					_pbuf = _pmem->malloc(rsz, _sizebuf);
				else {
					_pbuf = ::malloc(_size);
					_sizebuf = _size;
				}
				if (!_pbuf) {
					_pbuf = nullptr;
					_size = 0;
					_sizebuf = 0;
				}
			}
			return _pbuf;
		}
	};
}