/*!
\file c11_memory.h
\author	jiangyong
\email  kipway@outlook.com
\update 2019.1.22

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
		) : _ps(nullptr), _pm(nullptr), _pl(nullptr), _pmutex(pmutex), _stks(sblknum), _stkm(mblknum), _stkl(lblknum),
			_uerr_s(0), _uerr_m(0), _uerr_l(0)
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
			_ps = nullptr;
			if (_pm)
				::free(_pm);
			_pm = nullptr;
			if (_pl)
				::free(_pl);
			_pl = nullptr;
		}
		void *mem_malloc(size_t size)
		{
			unique_spinlock lck(_pmutex);
			size_t sizeout = 0;
			return _malloc(size, sizeout);
		}
		void mem_free(void *pmem, bool bsafe = false)
		{
			unique_spinlock lck(_pmutex);
			return _free(pmem, bsafe);
		}

		void *malloc(size_t size, size_t &outsize)
		{
			unique_spinlock lck(_pmutex);
			return _malloc(size, outsize);
		}

		void* mem_calloc(size_t count, size_t size) {
			void* p = mem_malloc(count * size);
			if (p)
				memset(p, 0, count * size);
			return p;
		}

		struct t_mem_info {
			int sysblks, err_s, err_m, err_l;
			int sz_s, sz_m, sz_l;    // blocks size
			int blk_s, blk_m, blk_l; // blocks number
			int stk_s, stk_m, stk_l; // not use in stacks
		};

		void getinfo(t_mem_info *pinfo) {
			pinfo->sysblks = _nsys_malloc;
			pinfo->err_s = _uerr_s;
			pinfo->err_m = _uerr_m;
			pinfo->err_l = _uerr_l;
			pinfo->sz_s = (int)_sz_s;
			pinfo->sz_m = (int)_sz_m;
			pinfo->sz_l = (int)_sz_l;
			pinfo->blk_s = (int)_blk_s;
			pinfo->blk_m = (int)_blk_m;
			pinfo->blk_l = (int)_blk_l;
			pinfo->stk_s = (int)_stks.size();
			pinfo->stk_m = (int)_stkm.size();
			pinfo->stk_l = (int)_stkl.size();
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
		int _uerr_s, _uerr_m, _uerr_l;// free error

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

		void *_malloc(size_t size, size_t &outsize)
		{
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

		void _free(void *pmem, bool bsafe = false)
		{
			if (!pmem)
				return;
			size_t pa = (size_t)pmem;
			if (_ps && pa >= (size_t)_ps  && pa < (size_t)_ps + _sz_s * _blk_s) {
				if (!bsafe || !isExist(&_stks, pmem))
					_stks.push(pmem);
				else _uerr_s++;
			}
			else if (_pm &&  pa >= (size_t)_pm  && pa < (size_t)_pm + _sz_m * _blk_m) {
				if (!bsafe || !isExist(&_stkm, pmem))
					_stkm.push(pmem);
				else _uerr_m++;
			}
			else if (_pl &&  pa >= (size_t)_pl  && pa < (size_t)_pl + _sz_l * _blk_l) {
				if (!bsafe || !isExist(&_stkl, pmem))
					_stkl.push(pmem);
				else _uerr_l++;
			}
			else {
				::free(pmem);
				_nsys_malloc--;
			}
		}
		bool isExist(ec::stack<void*> *pstk, void* p) {
			size_t i, n = pstk->size();
			for (i = 0u; i < n; i++) {
				if (pstk->at(i) == p)
					return true;
			}
			return false;
		}
	};

	class auto_buffer
	{
	public:
		auto_buffer(memory* pmem = nullptr) :_pmem(pmem), _pbuf(0), _size(0) {
		}
		auto_buffer(size_t size, memory* pmem = nullptr) :_pmem(pmem), _size(size) {
			if (_pmem)
				_pbuf = _pmem->mem_malloc(_size);
			else
				_pbuf = ::malloc(_size);
			if (!_pbuf)				
				_size = 0;			
		}
		~auto_buffer() {
			clear();
		}
	private:
		memory* _pmem;
		void*   _pbuf;
		size_t  _size;
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
			}
		}
		inline void* resize(size_t rsz) {
			clear();
			if (!rsz) 
				return nullptr;			
			void* pt = nullptr;
			if (_pmem)
				pt = _pmem->mem_malloc(rsz);
			else
				pt = ::malloc(rsz);
			if (!pt)
				return nullptr;
			_pbuf = pt;
			_size = rsz;
			return _pbuf;
		}
	};
}