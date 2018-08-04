/*!
\file c11_fifo.h
\author	jiangyong
\email  kipway@outlook.com
\update 2018.8.4

FIFO class for windows & linux

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
#include "c11_mutex.h"

namespace ec
{
	template<class _Ty>
	class fifo
	{
	public:
		typedef _Ty	value_type;
		fifo(size_t usize, std::mutex *pmutex = nullptr) :_pmutex(pmutex) {
			_pbuf = new value_type[usize];
			if (_pbuf)
				_usize = usize;
			else
				_usize = 0;
			_uhead = 0;
			_utail = 0;
		};
		~fifo() {
			if (_pbuf) {
				delete[]_pbuf;
				_pbuf = nullptr;
			}
		};
	private:
		value_type * _pbuf;
		std::mutex* _pmutex;
		size_t	_usize; //bufsize
		size_t	_uhead;	//out
		size_t	_utail;	//in,point empty
	public:
		bool empty() const noexcept {
			unique_lock lck(_pmutex);
			return _uhead == _utail;
		};
		bool full() const noexcept {
			unique_lock lck(_pmutex);
			return  (_utail + 1) % _usize == _uhead;
		};
		int add(value_type &item, bool *pbfull = nullptr) noexcept // -1:error;  0: full ;  1:success
		{
			unique_lock lck(_pmutex);
			if (!_pbuf)
				return -1; // error
			if ((_utail + 1) % _usize == _uhead) {
				if (pbfull)
					*pbfull = true;
				return 0; //full
			}
			_pbuf[_utail] = item;
			_utail = (_utail + 1) % _usize;
			if(pbfull)
				*pbfull = ((_utail + 1) % _usize == _uhead);
			return 1; //success
		};
		void add_overflow(value_type &item) {
			unique_lock lck(_pmutex);
			if (!_pbuf)
				return; // error
			if ((_utail + 1) % _usize == _uhead) { // full
				_pbuf[_uhead].~value_type();
				_uhead = (_uhead + 1) % _usize;				
			}
			_pbuf[_utail] = item;
			_utail = (_utail + 1) % _usize;			
		}
		bool get(value_type& item) noexcept
		{
			unique_lock lck(_pmutex);
			if (!_pbuf || _uhead == _utail)
				return false;
			item = _pbuf[_uhead];
			_pbuf[_uhead].~value_type();
			_uhead = (_uhead + 1) % _usize;
			return true;
		}
		void clear() noexcept
		{
			unique_lock lck(_pmutex);
			if (!_pbuf || _uhead == _utail)
				return;
			while (_uhead != _utail) {
				_pbuf[_uhead].~value_type();
				_uhead = (_uhead + 1) % _usize;
			}
			_uhead = 0;
			_utail = 0;
		}
		size_t count() noexcept
		{
			unique_lock lck(_pmutex);
			size_t uh = _uhead;
			size_t n = 0;
			while (uh != _utail)
			{
				n++;
				uh = (uh + 1) % _usize;
			}
			return n;
		}
		void for_each(std::function<void(value_type& val)> fun) noexcept
		{
			unique_lock lck(_pmutex);
			if (!_pbuf)
				return;
			size_t h = _uhead, t = _utail;
			while (h != t) {
				fun(_pbuf[h]);
				h = (h + 1) % _usize;
			}			
		}
	};
}