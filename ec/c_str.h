/*!
\file c_str.h
\author	jiangyong
\email  kipway@outlook.com
\update 2019.1.9

eclib  string

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
#ifndef C_STR_H
#define C_STR_H
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#ifndef _WIN32
#include <iconv.h>
#include <ctype.h>
#endif
namespace ec
{
	inline void str_rightzero(char* s, size_t nsize)
	{
		size_t i = 0;
		if (!nsize || !s)
			return;
		s[nsize - 1] = '\0';
		while (s[i++]);
		while (i < nsize)
			s[i++] = '\0';
	}

	inline void str_trimright(char* s, size_t count, const char* flt = "\x20\t\n\r")
	{
		if (!count || !s)
			return;
		count--;
		while (count >= 0 && strchr(flt, s[count]))
			s[count--] = '\0';
	}

	inline void str_trim(char *s, const char* flt = "\x20\t\n\r")
	{
		if (!*s)
			return;
		char *sp = s, *s1 = s;
		while (*sp && strchr(flt, *sp))
			sp++;
		if (sp != s) {
			while (*sp)
				*s1++ = *sp++;
			*s1 = '\0';
		}
		else
			while (*s1++);
		while (s1 > s)
		{
			s1--;
			if (strchr(flt, *s1))
				*s1 = '\0';
			else
				break;
		}
	}

	inline char* str_ncpy(char* sd, const char* ss, size_t count)//like strncpy,add null to the end of sd, buffer size of sd must > count
	{
		if (!sd)
			return (char*)0;
		if (!ss || !(*ss) || !count) {
			*sd = '\0';
			return (char*)0;
		}
		char* sr = sd;
		while (count && (*sd++ = *ss++) != '\0')
			count--;
		if(!count)
			*sd = '\0';
		return sr;
	};

	inline size_t str_lcpy(char* sd, const char* ss, size_t count)// like strlcpy for linux,add null to the end of sd
	{		
		size_t n = count;
		if (!sd)
			return 0;
		if (!ss || !(*ss) || !count){
			if(sd)
				*sd = '\0';
			return 0;
		}
		while (count && (*sd++ = *ss++) != '\0')
			count--;
		if (!count){
			count = 1;
			*--sd = '\0';
		}
		return n - count;
	};

	inline bool str_eq(const char* s1, const char* s2)
	{
		if (!s1 || !s2)
			return false;
		while (*s1 && *s2) {
			if (*s1++ != *s2++)
				return false;
		}
		return *s1 == '\0' && *s2 == '\0';
	}

	inline bool str_ieq(const char* s1, const char* s2)
	{
		if (!s1 || !s2)
			return false;
		while (*s1 && *s2) {
			if (*s1 != *s2 && tolower(*s1) != tolower(*s2))
				return false;
			s1++;
			s2++;
		}
		return *s1 == '\0' && *s2 == '\0';
	}

	inline bool str_neq(const char* s1, const char* s2, size_t n)
	{
		if (!s1 || !s2)
			return false;
		size_t i = 0;
		while (i < n && *s1 && *s2) {
			if (*s1++ != *s2++)
				return false;
			i++;
		}
		return i == n;
	}

	inline bool str_ineq(const char* s1, const char* s2, size_t n)
	{
		if (!s1 || !s2)
			return false;
		size_t i = 0;
		while (i < n && *s1 && *s2) {
			if (*s1 != *s2 && tolower(*s1) != tolower(*s2))
				return false;
			s1++;
			s2++;
			i++;
		}
		return i == n;
	}

	///\brief filter string
	///
	///sfliter support *?
	///\param ssrc [in] src
	///\param sfliter [in] filter str
	///\return true success
	inline bool str_filter(const char *ssrc, const char *sfliter)
	{
		char ssub[512], cp = 0;
		char *ps = ssub, *ss = (char *)ssrc, *sf = (char *)sfliter;
		if (!ss || !sf || *sf == 0)
			return true;
		if ((*sf == '*') && (*(sf + 1) == 0))
			return true;
		while ((*sf) && (*ss))
		{
			if (*sf == '*') {
				if (ps != ssub) {
					*ps = 0;
					ss = strstr(ss, ssub);
					if (!ss)
						return false;
					ss += (ps - ssub);
					ps = ssub;
				}
				cp = '*';	sf++;
			}
			else if (*sf == '?') {
				if (ps != ssub) {
					*ps = 0;
					ss = strstr(ss, ssub);
					if (!ss)
						return false;
					ss += (ps - ssub);
					ps = ssub;
				}
				ps = ssub;
				cp = '?';		ss++;		sf++;
			}
			else
			{
				if (cp == '*')
					*ps++ = *sf++;
				else {
					if (*sf != *ss)
						return false;
					sf++;		ss++;
				}
			}
		}//while
		if (cp != '*')
		{
			if (*ss == *sf)
				return true;
			if (*sf == '*') {
				sf++;
				if (*sf == 0)
					return true;
			}
			return false;
		}
		if (ps != ssub) {
			*ps = 0;
			ss = strstr(ss, ssub);
			if (!ss)
				return false;
			ss += (ps - ssub);
			if (!*ss)
				return true;
			return false;
		}
		return true;
	}

	/*!
	\brief get next string
	\param cp separate character
	\param src source string
	\param srcsize source string length
	\param pos [in/out] current position
	\param sout [out] output buffer
	\param outsize output buffer length
	*/
	inline const char* str_getnextstring(const char cp, const char* src, size_t srcsize, size_t &pos, char *sout, size_t outsize)
	{
		char c;
		size_t i = 0;
		while (pos < srcsize)
		{
			c = src[pos++];
			if (c == cp)
			{
				while (i > 0)// delete tail space char
				{
					if (sout[i - 1] != '\t' && sout[i - 1] != ' ')
						break;
					i--;
				}
				sout[i] = '\0';
				if (i > 0)
					return sout;
			}
			else if (c != '\n' && c != '\r')
			{
				if (i == 0 && (c == '\t' || c == ' ')) //delete head space char
					continue;
				sout[i++] = c;
				if (i >= outsize)
					return 0;
			}
		}
		if (i && i < outsize && pos == srcsize)
		{
			while (i > 0) //delete tail space char
			{
				if (sout[i - 1] != '\t' && sout[i - 1] != ' ')
					break;
				i--;
			}
			sout[i] = '\0';
			if (i > 0)
				return sout;
		}
		return 0;
	}


	/*!
	\brief get next string
	\param split separate characters
	\param src source string
	\param srcsize source string length
	\param pos [in/out] current position
	\param sout [out] output buffer
	\param outsize output buffer length
	*/
	inline const char* str_getnext(const char* split, const char* src, size_t srcsize, size_t &pos, char *sout, size_t outsize)
	{
		char c;
		size_t i = 0;
		while (pos < srcsize)
		{
			c = src[pos++];
			if (strchr(split, c))
			{
				while (i > 0)// delete tail space char
				{
					if (sout[i - 1] != '\t' && sout[i - 1] != ' ')
						break;
					i--;
				}
				sout[i] = '\0';
				if (i > 0)
					return sout;
			}
			else if (c != '\n' && c != '\r')
			{
				if (i == 0 && (c == '\t' || c == ' ')) //delete head space char
					continue;
				sout[i++] = c;
				if (i >= outsize)
					return 0;
			}
		}
		if (i && i < outsize && pos == srcsize)
		{
			while (i > 0) //delete tail space char
			{
				if (sout[i - 1] != '\t' && sout[i - 1] != ' ')
					break;
				i--;
			}
			sout[i] = '\0';
			if (i > 0)
				return sout;
		}
		return 0;
	}

	inline bool char2hex(char c, unsigned char *pout)
	{
		if (c >= 'a' && c <= 'f')
			*pout = 0x0a + (c - 'a');
		else if (c >= 'A' && c <= 'F')
			*pout = 0x0a + (c - 'A');
		else if (c >= '0' && c <= '9')
			*pout = c - '0';
		else
			return false;
		return true;
	}

	/*!
	\brief utf8 fomat url translate to utf8 string,add 0 at end
	*/
	inline  int url2utf8(const char* url, char sout[], int noutsize)
	{
		int n = 0;
		unsigned char h, l;
		while (*url && n < noutsize - 1)
		{
			if (*url == '%')
			{
				url++;
				if (!char2hex(*url++, &h))
					break;
				if (!char2hex(*url++, &l))
					break;
				sout[n++] = (char)((h << 4) | l);
			}
			else
				sout[n++] = *url++;
		}
		sout[n] = 0;
		return n;
	}

	inline void hex2string(const void* psrc, size_t sizesrc, char *sout, size_t outsize)
	{
		unsigned char uc;
		size_t i;
		const unsigned char* pu = (const unsigned char*)psrc;
		for (i = 0; i < sizesrc && 2 * i + 1 < outsize; i++)
		{
			uc = pu[i] >> 4;
			sout[i * 2] = (uc >= 0x0A) ? 'A' + (uc - 0x0A) : '0' + uc;
			uc = pu[i] & 0x0F;
			sout[i * 2 + 1] = (uc >= 0x0A) ? 'A' + (uc - 0x0A) : '0' + uc;
		}
		sout[2 * i] = 0;
	}

	inline int str_icmp(const char* a, const char* b)
	{
#ifdef _WIN32
		return stricmp(a, b);
#else
		return strcasecmp(a, b);
#endif
	}

	inline   char chr_upr(char c)
	{
		if (c >= 'a' && c <= 'z')
			return c - 'a' + 'A';
		return c;
	}

	inline char *str_upr(char *str)
	{
#ifdef _WIN32
		return _strupr(str);
#else
		char *ptr = str;
		while (*ptr) {
			if (*ptr >= 'a' && *ptr <= 'z')
				*ptr -= 'a' - 'A';
			ptr++;
		}
		return str;
#endif
	}

	inline char *str_lwr(char *str)
	{
#ifdef _WIN32
		return _strlwr(str);
#else
		char *ptr = str;
		while (*ptr) {
			if (*ptr >= 'A' && *ptr <= 'Z')
				*ptr += 'a' - 'A';
			ptr++;
		}
		return str;
#endif
	}

	inline char *formatpath(char* spath, size_t size)
	{
		if (strlen(spath) + 2 > size || !(*spath))
			return spath;
		char *s = spath;
		while (*s)
		{
			if (*s == '\\')
				*s = '/';
			s++;
		}
		if (*(s - 1) != '/')
		{
			*s++ = '/';
			*s = '\0';
		}
		return spath;
	}
	/*!
	\brief GB2312 to utf-8
	\param sizeout [in/out] , in outbufsize, out strlen(out)
	*/
	inline bool gb2utf8(const char* in, size_t sizein, char *out, size_t &sizeout)
	{
		*out = 0;
		if (!in || !(*in))
			return true;
#ifdef _WIN32
		int i = MultiByteToWideChar(CP_ACP, 0, in, (int)sizein, NULL, 0);
		if (!i)
		{
			str_ncpy(out, in, sizeout - 1);
			return false;
		}
		wchar_t* sUnicode = new wchar_t[i + 1];
		MultiByteToWideChar(CP_ACP, 0, in, (int)sizein, sUnicode, i); //to unicode

		int nout = WideCharToMultiByte(CP_UTF8, 0, sUnicode, i, out, (int)sizeout - 1, NULL, NULL); //to utf-8
		sizeout = nout;
		if (sizeout > 0)
			out[sizeout] = 0;
		else
			str_ncpy(out, in, sizeout - 1);
		delete[]sUnicode;
		return nout > 0;
#else
		iconv_t cd;
		char **pin = (char**)&in;
		char **pout = &out;

		cd = iconv_open("UTF-8//IGNORE", "GBK");
		if (cd == (iconv_t)-1)
		{
			str_ncpy(out, in, sizeout - 1);
			sizeout = strlen(out);
			return false;
		}
		size_t inlen = sizein;
		size_t outlen = sizeout - 1;
		if (iconv(cd, pin, &inlen, pout, &outlen) == (size_t)(-1))
		{
			iconv_close(cd);
			str_ncpy(out, in, sizeout - 1);
			sizeout = strlen(out);
			return false;
		}
		iconv_close(cd);
		sizeout = sizeout - outlen;
		if (outlen >= 0)
			*out = 0;
		return true;
#endif
	}

	inline bool gb2utf8_s(const char* sgb, size_t sizegb, char *sutf8, size_t sizeout)
	{
		size_t sz = sizeout;
		return gb2utf8(sgb, sizegb, sutf8, sz);
	}

	/*!
	\brief utf8 - gbk
	\param sizeout [in/out] , in outbufsize, out strlen(out)
	*/
	inline bool utf82gbk(const char* in, size_t sizein, char *out, size_t &sizeout)
	{
		*out = 0;
		if (!in || !(*in))
			return true;
#ifdef _WIN32
		int i = MultiByteToWideChar(CP_UTF8, 0, in, (int)sizein, NULL, 0);
		if (!i)
		{
			str_ncpy(out, in, sizeout - 1);
			sizeout = strlen(out);
			return false;
		}
		wchar_t* sUnicode = new wchar_t[i + 1];
		MultiByteToWideChar(CP_UTF8, 0, in, (int)sizein, sUnicode, i); //to unicode

		int nout = WideCharToMultiByte(CP_ACP, 0, sUnicode, i, out, (int)sizeout - 1, NULL, NULL); //to utf-8
		sizeout = nout;
		if (sizeout > 0)
			out[sizeout] = 0;
		else
		{
			str_ncpy(out, in, sizeout - 1);
			sizeout = strlen(out);
		}
		delete[]sUnicode;
		return nout > 0;
#else
		iconv_t cd;
		char **pin = (char**)&in;
		char **pout = &out;

		cd = iconv_open("GBK//IGNORE", "UTF-8");
		if (cd == (iconv_t)-1)
		{
			str_ncpy(out, in, sizeout - 1);
			sizeout = strlen(out);
			return false;
		}
		size_t inlen = sizein;
		size_t outlen = sizeout - 1;
		if (iconv(cd, pin, &inlen, pout, &outlen) == (size_t)(-1))
		{
			iconv_close(cd);
			str_ncpy(out, in, sizeout - 1);
			sizeout = strlen(out);
			return false;
		}
		iconv_close(cd);
		sizeout = sizeout - outlen;
		if (outlen >= 0)
			*out = 0;
		return true;
#endif
	}

	inline bool utf82gbk_s(const char* utf8, size_t sizeutf8, char *sgbk, size_t sizeout)
	{
		size_t sz = sizeout;
		return utf82gbk(utf8, sizeutf8, sgbk, sz);
	}


	/*!
	\brief 快速小字符串转换,in 小于4096 unicode字符,转换不成功则原样拷贝,sizeout必须足够，否则会截断
	*/
	inline bool str_gbk2utf8(const char* in, size_t sizein, char *out, size_t sizeout)
	{
		*out = 0;
		if (!in || !(*in))
			return true;
#ifdef _WIN32
		wchar_t tmp[4096];
		int i = MultiByteToWideChar(CP_ACP, 0, in, (int)sizein, tmp, (int)sizeof(tmp) / sizeof(wchar_t));
		if (!i)
		{
			str_ncpy(out, in, sizeout - 1);
			return false;
		}
		i = WideCharToMultiByte(CP_UTF8, 0, tmp, i, out, (int)sizeout - 1, NULL, NULL); //to utf-8
		if (!i)
		{
			str_ncpy(out, in, sizeout - 1);
			return false;
		}

		if (i > 0)
			out[i] = 0;
		else
			str_ncpy(out, in, sizeout - 1);
		return i > 0;
#else
		iconv_t cd;
		char **pin = (char**)&in;
		char **pout = &out;

		cd = iconv_open("UTF-8//IGNORE", "GBK");
		if (cd == (iconv_t)-1)
		{
			str_ncpy(out, in, sizeout - 1);
			sizeout = strlen(out);
			return false;
		}
		size_t inlen = sizein;
		size_t outlen = sizeout - 1;
		if (iconv(cd, pin, &inlen, pout, &outlen) == (size_t)(-1))
		{
			iconv_close(cd);
			str_ncpy(out, in, sizeout - 1);
			return false;
		}
		iconv_close(cd);
		*out = 0;
		return true;
#endif
	}

	/*!
	\brief 快速小字符串转换,in小于4096 unicode字符,转换不成功则原样拷贝,sizeout必须足够，否则会截断
	*/
	inline bool str_utf82gbk(const char* in, size_t sizein, char *out, size_t sizeout)
	{
		*out = 0;
		if (!in || !(*in))
			return true;
#ifdef _WIN32
		wchar_t tmp[4096];
		int i = MultiByteToWideChar(CP_UTF8, 0, in, (int)sizein, tmp, (int)sizeof(tmp) / sizeof(wchar_t));
		if (!i)
		{
			str_ncpy(out, in, sizeout - 1);
			return false;
		}
		i = WideCharToMultiByte(CP_ACP, 0, tmp, i, out, (int)sizeout - 1, NULL, NULL); //to utf-8
		if (!i)
		{
			str_ncpy(out, in, sizeout - 1);
			return false;
		}

		if (i > 0)
			out[i] = 0;
		else
			str_ncpy(out, in, sizeout - 1);
		return i > 0;
#else
		iconv_t cd;
		char **pin = (char**)&in;
		char **pout = &out;

		cd = iconv_open("GBK", "UTF-8//IGNORE");
		if (cd == (iconv_t)-1)
		{
			str_ncpy(out, in, sizeout - 1);
			sizeout = strlen(out);
			return false;
		}
		size_t inlen = sizein;
		size_t outlen = sizeout - 1;
		if (iconv(cd, pin, &inlen, pout, &outlen) == (size_t)(-1))
		{
			iconv_close(cd);
			str_ncpy(out, in, sizeout - 1);
			return false;
		}
		iconv_close(cd);
		*out = 0;
		return true;
#endif
	}

	class cAp // auto free pointer
	{
	public:
		cAp(size_t size) {
			_p = malloc(size);
			if (_p)
				_size = size;
		}
		~cAp() {
			if (_p)
				free(_p);
		}
		template<typename T>
		inline operator T*() {
			return (T*)_p;
		}
		inline bool isempty() {
			return !_p;
		}
		inline size_t getsize() {
			return _size;
		};
		inline size_t size() {
			return _size;
		};
		inline void* getbuf() { return _p; };
		inline void* data() { return _p; };
		bool resize(size_t newsize, bool bkeepdata = false)
		{
			if (bkeepdata)
			{
				void* p = malloc(newsize);
				if (!p)
					return false;
				if (_p && _size) {
					memcpy(p, _p, _size);
					free(_p);
				}
				_p = p;
			}
			else
			{
				if (_p && _size)
					free(_p);
				_p = malloc(newsize);
			}
			_size = _p ? newsize : 0;
			return _p != 0;
		}
		bool upsizeto(size_t newsize, bool bkeepdata = false)
		{
			if (_size >= newsize)
				return true;
			return resize(newsize, bkeepdata);
		}
	protected:
		size_t _size;
		void* _p;
	};

	class cStrSplit
	{
	public:
		cStrSplit(const char* s, const char* sfilter = "\t\x20\f\r\n", size_t sizes = 0)
		{
			reset(s, sfilter, sizes);
		}
	private:
		const char* _s, *_sfilter;
		size_t _sizes, _pos;
		char _sfiled[4096]; //current filed
	public:
		void reset(const char* s, const char* sfilter = "\t\x20\f\r\n", size_t sizes = 0)
		{
			if (s && *s)
			{
				_s = s;
				if (sizes)
					_sizes = sizes;
				else
					_sizes = strlen(s);
			}
			else
			{
				_s = 0;
				_sizes = 0;
			}
			_pos = 0;
			_sfiled[0] = 0;
			_sfilter = sfilter;
		}
		inline void Reset() {
			_pos = 0;
			_sfiled[0] = 0;
		}
		char* next(const char *split, char * sout = 0, size_t sizeout = 0, size_t *psize = NULL)
		{
			if (psize)
				*psize = 0;
			char c;
			size_t i = 0, lout = sizeout;
			char *so = sout;

			if (!sout || !sizeout)
			{
				so = _sfiled;
				lout = sizeof(_sfiled);
			}
			if (!_s)
				return 0;
			while (_pos < _sizes)
			{
				c = _s[_pos++];
				if (strchr(split, c))
				{
					while (i > 0)// delete tail space char
					{
						if (!_sfilter || !strchr(_sfilter, so[i - 1])) //filter out  
							break;
						i--;
					}
					so[i] = '\0';
					if (i > 0)
					{
						if (psize)
							*psize = i;
						return so;
					}
				}
				else
				{
					if (_sfilter && strchr(_sfilter, c)) //filter out  
						continue; //delete head space char                    
					so[i++] = c;
					if (i >= lout)
						return 0;
				}
			}

			while (i > 0) //delete tail space char
			{
				if (!_sfilter || !strchr(_sfilter, so[i - 1])) //filter out  
					break;
				i--;
			}
			so[i] = '\0';
			if (i > 0)
			{
				if (psize)
					*psize = i;
				return so;
			}
			return 0;
		}
	};

	inline long long ato_ll(const char* s)
	{
#ifdef _WIN32
		return _atoi64(s);
#else
		return atoll(s);
#endif
	}

	/*!
	little endian fast XOR,8x faster than byte-by-byte XOR
	*/
	inline void fast_xor_le(unsigned char* pd, int size, unsigned int umask)//little endian fast XOR
	{
		int i, nl = 4 - ((size_t)pd % 4), nu = (size - nl) / 4;
		for (i = 0; i < nl && i < size; i++)
			pd[i] ^= (umask >> ((i % 4) * 8)) & 0xFF;

		unsigned int *puint = (unsigned int*)(pd + i), um;
		um = umask >> nl * 8;
		um |= umask << (4 - nl) * 8;
		for (i = 0; i < nu; i++)
			puint[i] ^= um;

		for (i = nl + nu * 4; i < size; i++)
			pd[i] ^= (umask >> ((i % 4) * 8)) & 0xFF;
	}

};//namespace ec
#endif //C_STR_H

