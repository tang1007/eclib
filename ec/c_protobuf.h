/*!
\file c_protobuf.h
\author kipway@outlook.com
\update 2018.1.29 

eclib class base_protobuf ,parse google protocol buffer

not support start_group and end_group 

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
#include <stdint.h>
#include <memory.h>
#include "c11_vector.h"
#include "c11_array.h"
#define pb_varint  0  // Varint
#define pb_fixed64 1  // 64-bit
#define pb_length_delimited  2  // Length-delimited
#define pb_start_group  3 // deprecated not support
#define pb_end_group  4   //deprecated not support
#define pb_fixed32 5  // 32-bit
namespace ec
{	
	/*!
	\brief encode and decode 
	see https://developers.google.com/protocol-buffers/docs/encoding
	*/
	class base_protobuf //base class for encode and decode protobuf
	{
	public:
		inline uint32_t en_zigzag32(int32_t v) const
		{
			return ((v << 1) ^ (v >> 31));
		}
		inline uint64_t en_zigzag64(int64_t v) const
		{
			return ((v << 1) ^ (v >> 63));
		}
		inline int32_t de_zigzag32(uint32_t v) const
		{
			return (int)((v >> 1) ^ (-(int32_t)(v & 1)));
		}
		inline int64_t de_zigzag64(uint64_t v) const
		{
			return (int)((v >> 1) ^ (-(int64_t)(v & 1)));
		}
		template<class _Tp>
		inline bool get_varint(const uint8_t* &pd, size_t &len, _Tp &out) const  //get Varint (Base 128 Varints)
		{
			int nbit = 0;
			out = 0;
			do{
				out |= (*pd & 0x7F) << nbit;
				nbit += 7;
				pd++;
				len--;
			} while (*(pd - 1) & 0x80 && len > 0 && nbit < 8 * sizeof(_Tp));
			return nbit <= 8 * sizeof(_Tp);
		}
		template<class _Tp>
		bool out_varint(_Tp v, ec::vector<uint8_t>* pout) const //out Varint (Base 128 Varints)
		{
			int nbit = 0;
			uint8_t out = 0;
			do{
				out = (v >> nbit) & 0x7F;
				nbit += 7;
				if (v >> nbit) {
					out |= 0x80;
					pout->add(out);
				}
				else {
					pout->add(out);
					break;
				}
			} while (nbit < 8 * sizeof(_Tp));
			return nbit <= 8 * sizeof(_Tp);
		}
		template<class _Tp>
		inline bool get_fixed(const uint8_t* &pd, size_t &len, _Tp &out) const  //get 32-bit and 64-bit (fixed32,sfixed32,fixed64,sfixed64,float,double)
		{
			if (len < sizeof(_Tp) || (sizeof(_Tp) != 4 && sizeof(_Tp) != 8))
				return false;
			memcpy(&out, pd, sizeof(_Tp));
			pd += sizeof(_Tp);
			len -= sizeof(_Tp);
			return true;
		}
		template<class _Tp>
		inline bool out_fixed(_Tp v, ec::vector<uint8_t>* pout) const  //out 32-bit and 64-bit (fixed32,sfixed32,fixed64,sfixed64,float,double)
		{
			if ((sizeof(_Tp) != 4 && sizeof(_Tp) != 8))
				return false;
			pout->add((uint8_t*)&v, sizeof(_Tp));
			return true;
		}
		inline bool get_key(const uint8_t* &pd, size_t &len, uint32_t &field_number, uint32_t &wire_type) const //get field_number and  wire_type
		{
			uint32_t key;
			if (!get_varint(pd, len, key))
				return false;
			wire_type = key & 0x07;
			field_number = key >> 3;
			return true;
		}
		inline bool get_length_delimited(const uint8_t* &pd, size_t &len, ec::vector<uint8_t>* pout) const //get string, bytes
		{
			pout->clear();
			uint32_t ul = 0;
			if (!get_varint(pd, len, ul))
				return false;
			if (len < ul)
				return false;
			pout->add(pd, ul);
			pd += ul;
			len -= ul;
			return true;
		}
		inline bool get_length_delimited(const uint8_t* &pd, size_t &len, void* pout, size_t &outlen) const //get string, bytes
		{
			uint32_t ul = 0;
			if (!get_varint(pd, len, ul))
				return false;
			if (len < ul || outlen < ul)
				return false;
			memcpy(pout, pd, ul);
			pd += ul;
			len -= ul;
			outlen = ul;
			return true;
		}
		inline bool get_length_delimited(const uint8_t* &pd, size_t &len, const uint8_t** pout, size_t &outlen) const //get string, bytes,no copy
		{
			uint32_t ul = 0;
			if (!get_varint(pd, len, ul))
				return false;
			if (len < ul || outlen < ul)
				return false;
			*pout = pd;
			pd += ul;
			len -= ul;
			outlen = ul;
			return true;
		}

		inline bool get_string(const uint8_t* &pd, size_t &len, char* pout, size_t outlen) const 
		{
			uint32_t ul = 0;
			size_t lv;
			if (!get_varint(pd, len, ul))
				return false;
			if (outlen <= ul) // Truncated
				lv = outlen - 1; 
			else
				lv = ul;			
			memcpy(pout, pd, lv);
			pout[lv] = '\0';
			pd += ul;
			len -= ul;
			outlen = ul;
			return true;
		}
		inline bool jump_over(const uint8_t* &pd, size_t &len, uint32_t wire_type) const //jump over unkown field_number
		{
			switch (wire_type)
			{
			case 0: // Varint
			{
				uint64_t v;
				return get_varint(pd, len, v);
			}
			break;
			case 1: // 64-bit
			{
				if (len < 8)
					return false;
				pd += 8;
				len -= 8;				
				break;
			}
			case 2: //Length - delimited
			{
				size_t datalen;
				if (!get_varint(pd, len, datalen))
					return false;
				if (len < datalen)
					return false;
				pd += datalen;
				len -= datalen;				
				break;
			}
			case 5: //32 bit
			{
				if (len < 4)
					return false;
				pd += 4;
				len -= 4;				
				break;
			}
			default:
				return false;// unkown wire_type
			}
			return true;
		}
		inline bool out_length_delimited(const uint8_t* pd, size_t len, ec::vector<uint8_t>* pout) const // out string, bytes
		{
			if (!out_varint(len, pout))
				return false;
			pout->add(pd, len);
			return true;
		}
		inline bool out_key(uint32_t field_number, uint32_t wire_type, ec::vector<uint8_t>* pout) const // out field_number and  wire_type
		{
			uint32_t v = (field_number << 3) | (wire_type & 0x07);
			return out_varint(v, pout);
		}

		template<class _Tp,size_t _N>
		bool out_varint(_Tp v, ec::Array<uint8_t, _N>* pout) const //out Varint (Base 128 Varints)
		{
			int nbit = 0;
			uint8_t out = 0;
			do {
				out = (v >> nbit) & 0x7F;
				nbit += 7;
				if (v >> nbit) {
					out |= 0x80;
					pout->add(out);
				}
				else {
					pout->add(out);
					break;
				}
			} while (nbit < 8 * sizeof(_Tp));
			return nbit <= 8 * sizeof(_Tp);
		}
		
		template<class _Tp, size_t _N>
		inline bool out_fixed(_Tp v, ec::Array<uint8_t,_N>* pout) const  //out 32-bit and 64-bit (fixed32,sfixed32,fixed64,sfixed64,float,double)
		{
			if ((sizeof(_Tp) != 4 && sizeof(_Tp) != 8))
				return false;
			return pout->add((uint8_t*)&v, sizeof(_Tp));
		}

		template<size_t _N>
		inline bool out_length_delimited(const uint8_t* pd, size_t len, ec::Array<uint8_t,_N>* pout) const // out string, bytes
		{
			if (!out_varint(len, pout))
				return false;
			return pout->add(pd, len);
		}

		template<size_t _N>
		inline bool out_key(uint32_t field_number, uint32_t wire_type, ec::Array<uint8_t,_N>* pout) const // out field_number and  wire_type
		{
			uint32_t v = (field_number << 3) | (wire_type & 0x07);
			return out_varint(v, pout);
		}
	};
	class msg_protoc :public base_protobuf
	{
	public:
		msg_protoc() {
			_uflag = 0;
		}
		inline void set_flag(int id) {
			_uflag |= 0x01 << id;
		}
		inline bool has(int id) {
			return 0 != (_uflag & (0x01 << id));
		}
		template<class _Tp>
		void set_var(int id, _Tp& d, _Tp src)
		{
			d = src;
			set_flag(id);
		}
		void set_str(int id, char* sd, size_t sized, const char* src)
		{
			snprintf(sd, sized, "%s", src);
			set_flag(id);
		}
		void set_bin(int id, void *dst, size_t sizedst, const void* src, size_t sizesrc)
		{
			size_t sz = sizesrc;
			if (sz > sizedst)
				sz = sizedst;
			memcpy(dst, src, sz);
			set_flag(id);
		}
		void set_cls(int id, ec::vector<uint8_t> *pcls, const void* src,size_t sizesrc)
		{
			pcls->clear();
			pcls->add((uint8_t*)src, sizesrc);
			set_flag(id);
		}
		bool p_str(int id, uint32_t wire_type, const uint8_t* &pd, size_t &len, char* pout, size_t outlen)
		{
			if (wire_type != pb_length_delimited || !get_string(pd, len, pout, outlen))
				return false;
			set_flag(id);
			return true;
		}
		bool p_cls(int id, uint32_t wire_type, const uint8_t* &pd, size_t &len, ec::vector<uint8_t>* pout)
		{
			if (wire_type != pb_length_delimited || !get_length_delimited(pd, len, pout))
				return false;
			set_flag(id);
			return true;
		}
		template< size_t _N>
		bool p_cls(int id, uint32_t wire_type, const uint8_t* &pd, size_t &len, ec::Array<uint8_t, _N>* pout)
		{
			const uint8_t* p;
			size_t sz = 0;
			if (wire_type != pb_length_delimited || !get_length_delimited(pd, len, &p, sz))
				return false;
			if (!pout->add(p, sz))
				return false;
			set_flag(id);
			return true;
		}
		template<class _Tp>
		bool p_var(int id, uint32_t wire_type, const uint8_t* &pd, size_t &len, _Tp &out, bool zigzag = false)
		{
			if (wire_type != pb_varint)
				return false;
			if (sizeof(_Tp) == 4) {
				uint32_t v;
				if (!get_varint(pd, len, v))
					return false;
				if (zigzag)
					out = (_Tp)de_zigzag32(v);
				else
					out = (_Tp)v;
			}
			else {
				uint64_t v;
				if (!get_varint(pd, len, v))
					return false;
				if (zigzag)
					out = (_Tp)de_zigzag64(v);
				else
					out = (_Tp)v;
			}
			set_flag(id);
			return true;
		}
		template<class _Tp>
		bool out_var(ec::vector<uint8_t>* po, int id, _Tp v, bool zigzag = false)
		{
			if (sizeof(_Tp) == 4) {
				if (zigzag) {
					if (has(id) && (!out_key(id, pb_varint, po) || !out_varint((uint32_t)(en_zigzag32(v)), po)))
						return false;
				}
				else {
					if (has(id) && (!out_key(id, pb_varint, po) || !out_varint((uint32_t)v, po)))
						return false;
				}
			}
			else {
				if (zigzag) {
					if (has(id) && (!out_key(id, pb_varint, po) || !out_varint((uint64_t)(en_zigzag64(v)), po)))
						return false;
				}
				else {
					if (has(id) && (!out_key(id, pb_varint, po) || !out_varint((uint64_t)v, po)))
						return false;
				}
			}
			return true;
		}
		bool out_str(ec::vector<uint8_t>* po, int id, const char* s)
		{
			if (has(id) && (!out_key(id, pb_length_delimited, po) || !out_length_delimited((uint8_t*)s, strlen(s), po)))
				return false;
			return true;
		}
		bool out_cls(ec::vector<uint8_t>* po, int id, const void* pcls, size_t size)
		{
			if (has(id) && (!out_key(id, pb_length_delimited, po) || !out_length_delimited((uint8_t*)pcls, size, po)))
				return false;
			return true;
		}
		template<class _Tp, size_t _N>
		bool out_var(ec::Array<uint8_t, _N>* po, int id, _Tp v, bool zigzag = false)
		{
			if (sizeof(_Tp) == 4) {
				if (zigzag) {
					if (has(id) && (!out_key(id, pb_varint, po) || !out_varint((uint32_t)(en_zigzag32(v)), po)))
						return false;
				}
				else {
					if (has(id) && (!out_key(id, pb_varint, po) || !out_varint((uint32_t)v, po)))
						return false;
				}
			}
			else {
				if (zigzag) {
					if (has(id) && (!out_key(id, pb_varint, po) || !out_varint((uint64_t)(en_zigzag64(v)), po)))
						return false;
				}
				else {
					if (has(id) && (!out_key(id, pb_varint, po) || !out_varint((uint64_t)v, po)))
						return false;
				}
			}
			return true;
		}
		template< size_t _N>
		bool out_str(ec::Array<uint8_t, _N>* po, int id, const char* s)
		{
			if (has(id) && (!out_key(id, pb_length_delimited, po) || !out_length_delimited((uint8_t*)s, strlen(s), po)))
				return false;
			return true;
		}
		template<size_t _N>
		bool out_cls(ec::Array<uint8_t, _N>* po, int id, const void* pcls, size_t size)
		{
			if (has(id) && (!out_key(id, pb_length_delimited, po) || !out_length_delimited((uint8_t*)pcls, size, po)))
				return false;
			return true;
		}
	protected:
		uint32_t _uflag;
	};
}
