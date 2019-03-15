/*!
\file c_stream.h
\author kipway@outlook.com
\update 2019.3.15

eclib class memery stream

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
#ifdef _MSC_VER
#define bswap_16(x) _byteswap_ushort(x)
#define bswap_32(x) _byteswap_ulong(x)
#define bswap_64(x) _byteswap_uint64(x)
#else
#include <byteswap.h>
#endif
namespace ec
{
	/*!
	*Note: overloaded "<,>" and "<<, >>" do not mix in one line because the priority is different
	*/
	class cStream
	{
	public:
		cStream()
		{
			_ps = 0;
			_size = 0;
			_pos = 0;
		};
		cStream(void* p, size_t size)
		{
			attach(p, size);
		};
		~cStream() {};

		inline bool isbig()
		{
			union {
				uint32_t u32;
				uint8_t u8;
			}ua;
			ua.u32 = 0x01020304;
			return ua.u8 == 0x01;
		}
	public:
		void attach(void* p, size_t size)
		{
			_ps = (uint8_t*)p;
			_size = size;
			_pos = 0;
		}
		template < typename T > cStream & operator >> (T& v) // read as little_endian
		{
			if (_pos + sizeof(T) > _size)
				throw (int)1;
			memcpy(&v, _ps + _pos, sizeof(T)); // Let the compiler optimize unaligned memory
			_pos += sizeof(T);
			if (isbig()) { // big_endian, swap
				int c = sizeof(T);
				switch (c) {
				case 1:
					break;
				case 2:
					v = (T)bswap_16((uint16_t)v);
					break;
				case 4:
					v = (T)bswap_32((uint32_t)v);
					break;
				case 8:
					v = (T)bswap_64((uint64_t)v);
					break;
				default:
					throw (int)2;
				}
			}
			return *this;
		};

		template < typename T > cStream & operator << (T v) // write as little_endian
		{
			if (_pos + sizeof(T) > _size)
				throw (int)1;
			if (isbig()) { // big_endian, swap
				int c = sizeof(T);
				switch (c) {
				case 1:
					break;
				case 2:
					v = (T)bswap_16((uint16_t)v);
					break;
				case 4:
					v = (T)bswap_32((uint32_t)v);
					break;
				case 8:
					v = (T)bswap_64((uint64_t)v);
					break;
				default:
					throw (int)2;
				}
			}
			memcpy(_ps + _pos, &v, sizeof(T)); // Let the compiler optimize unaligned memory
			_pos += sizeof(T);
			return *this;
		};

		template < typename T > cStream & operator > (T& v) // read as big_endian
		{
			if (_pos + sizeof(T) > _size)
				throw (int)1;
			memcpy(&v, _ps + _pos, sizeof(T)); // Let the compiler optimize unaligned memory
			_pos += sizeof(T);
			if (!isbig()) { // little_endian,swap
				int c = sizeof(T);
				switch (c) {
				case 1:
					break;
				case 2:
					v = (T)bswap_16((uint16_t)v);
					break;
				case 4:
					v = (T)bswap_32((uint32_t)v);
					break;
				case 8:
					v = (T)bswap_64((uint64_t)v);
					break;
				default:
					throw (int)2;
				}
			}
			return *this;
		};

		template < typename T > cStream & operator < (T v)  // write as big_endian
		{
			if (_pos + sizeof(T) > _size)
				throw (int)1;
			if (!isbig()) { // little_endian,swap
				int c = sizeof(T);
				switch (c) {
				case 1:
					break;
				case 2:
					v = (T)bswap_16((uint16_t)v);
					break;
				case 4:
					v = (T)bswap_32((uint32_t)v);
					break;
				case 8:
					v = (T)bswap_64((uint64_t)v);
					break;
				default:
					throw (int)2;
				}
			}
			memcpy(_ps + _pos, &v, sizeof(T)); // Let the compiler optimize unaligned memory
			_pos += sizeof(T);
			return *this;
		};

		cStream & read(void* pbuf, size_t size)
		{
			if (_pos + size > _size)
				throw (int)1;
			memcpy(pbuf, _ps + _pos, size);
			_pos += size;
			return *this;
		};

		cStream & write(const void* pbuf, size_t size)
		{
			if (_pos + size > _size)
				throw (int)1;
			memcpy(_ps + _pos, pbuf, size);
			_pos += size;
			return *this;
		};

		cStream & readstr(char* pbuf, size_t size)
		{
			if (!size)
				throw (int)2;
			size_t n = 0;
			while (_pos < _size && _ps[_pos]) {
				if (n + 1 < size) {
					pbuf[n] = _ps[_pos];
					n++;
				}
				_pos++;
			}
			pbuf[n] = 0;
			_pos++;
			return *this;
		};

		cStream & writestr(const char* pbuf)
		{
			size_t n = 0;
			if (pbuf)
				n = strlen(pbuf);
			if (_pos + n + 1 >= _size)
				throw (int)1;
			if (pbuf && n > 0) {
				memcpy(_ps + _pos, pbuf, n);
				_pos += n;
			}
			_ps[_pos] = 0;
			_pos++;
			return *this;
		};

		cStream & setpos(size_t pos)
		{
			if (pos > _size)
				throw (int)1;
			_pos = pos;
			return *this;
		};

		inline size_t getpos() const { return _pos; };
		inline size_t leftsize() { return _size - _pos; }
		inline void* getp() { return _ps; };
		inline bool iseof()
		{
			return _pos == _size;
		}
		inline size_t size() const
		{
			return _size;
		}
	protected:
		size_t	_pos;
		size_t	_size;
		uint8_t* _ps;
	};
};
