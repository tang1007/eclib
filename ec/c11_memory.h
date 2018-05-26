/*!
\file c11_memory.h
\author	kipway@outlook.com
\update 2018.5.26

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
#include "c11_stack.h"
#include "c11_array.h"
#ifndef MEM_ML_BLKNUM 
#define MEM_ML_BLKNUM 512 //medium/large memory blocks
#endif
namespace ec {
	class memory
	{
	public:
		memory(size_t sblksize, size_t sblknum,
			size_t mblksize = 0, size_t mblknum = 0,
			size_t lblksize = 0, size_t lblknum = 0
		) : _pm(nullptr), _pl(nullptr), _stks(sblknum)
		{
			size_t i;
			_sz_s = sblksize;
			if (_sz_s % 8)
				_sz_s += sblksize - sblksize % 8;
			_blk_s = sblknum;
			_ps = malloc(_sz_s * sblknum);
			if (_ps)
			{
				uint8_t *p = (uint8_t *)_ps;
				for (i = 0; i < sblknum; i++)
					_stks.add(p + i * _sz_s);
			}

			_sz_m = mblksize;
			if (_sz_m % 16)
				_sz_m += mblksize - mblksize % 16;
			_blk_m = mblknum;
			if (_blk_m > MEM_ML_BLKNUM)
				_blk_m = MEM_ML_BLKNUM;

			_sz_l = lblksize;
			if (_sz_l % 16)
				_sz_l += lblksize - lblksize % 16;
			_blk_l = lblknum;
			if (_blk_l > MEM_ML_BLKNUM)
				_blk_l = MEM_ML_BLKNUM;
		}
		~memory()
		{
			_stks.clear();
			_stkm.clear();
			_stkl.clear();
			if (_ps)
				free(_ps);
			if (_pm)
				free(_pm);
			if (_pl)
				free(_pl);
		}
		void *mem_malloc(size_t size)
		{
			void* pr = nullptr;
			if (size <= _sz_s)
				_stks.pop(pr);
			else if (size <= _sz_m)
			{
				if (!_pm)
					malloc_block(_sz_m, _blk_m, _pm, _stkm);
				_stkm.pop(pr);
			}
			else if (size <= _sz_l)
			{
				if (!_pl)
					malloc_block(_sz_l, _blk_l, _pl, _stkl);
				_stkl.pop(pr);
			}
			if (!pr)
				pr = malloc(size);
			return pr;
		}
		void mem_free(void *pmem)
		{
			size_t pa = (size_t)pmem;
			if (_ps && pa >= (size_t)_ps  && pa < (size_t)_ps + _sz_s * _blk_s)
				_stks.push(pmem);
			else if (_pm &&  pa >= (size_t)_pm  && pa < (size_t)_pm + _sz_m * _blk_m)
				_stkm.push(pmem);
			else if (_pl &&  pa >= (size_t)_pl  && pa < (size_t)_pl + _sz_l* _blk_l)
				_stkl.push(pmem);
			else
				free(pmem);
		}
	private:
		void *_ps, *_pm, *_pl;
		size_t _sz_s, _sz_m, _sz_l;  //blocks size
		size_t _blk_s, _blk_m, _blk_l; // blocks number
		ec::stack<void*> _stks;     // small memory blocks
		ec::Array<void*, MEM_ML_BLKNUM> _stkm; // medium memory blocks
		ec::Array<void*, MEM_ML_BLKNUM> _stkl; // large memory blocks

		bool malloc_block(size_t blksize, size_t blknum, void * &ph, ec::Array<void*, MEM_ML_BLKNUM> &stk)
		{
			if (!blknum || !blksize)
				return false;
			size_t i;
			ph = malloc(blksize * blknum);
			if (ph)
			{
				uint8_t *p = (uint8_t *)ph;
				for (i = 0; i < blknum; i++)
					stk.add(p + i * blksize);
			}
			return ph != nullptr;
		}
	};
}