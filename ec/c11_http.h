/*!
\file c11_http.h
\author	jiangyong
\email  kipway@outlook.com
\update 2019.3.23
2019.3.23 add new http tips

eclib class for parse http package

class ec::http::package

eclib 2.0 Copyright (c) 2017-2019, kipway
source repository : https://github.com/kipway/eclib

Licensed under the Apache License, Version 2.0 (the "License");
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
*/
#pragma once
#include <string.h>
#include <ctype.h>
#include "c11_array.h"
namespace ec
{
	enum HTTPERROR
	{
		he_ok = 0,
		he_waitdata,
		he_failed
	};

	static const char* http_sret404 = "http/1.1 404  not found!\r\nConnection:keep-alive\r\nContent-type:text/html\r\nContent-Length:60\r\n\r\n"\
		"<!DOCTYPE html><html><body><p>404 not fund</p></body></html>";
	static const char* http_sret400 = "http/1.1 400  Bad Request!\r\nConnection:keep-alive\r\nContent-type:text/html\r\nContent-Length:63\r\n\r\n"\
		"<!DOCTYPE html><html><body><p>400 Bad Request</p></body></html>";
	static const char* http_sret413 = "http/1.1 413  Payload Too Large!\r\nConnection:keep-alive\r\nContent-type:text/html\r\nContent-Length:76\r\n\r\n"\
		"<!DOCTYPE html><html><body><p>413 Request Entity Too Large</p></body></html>";
	
	namespace http
	{
		constexpr int e_wait = 0;  // waiting more data
		constexpr int e_err = -1;  // normal error
		constexpr int e_line = -2; // line not \r\n  end
		constexpr int e_linesize = -3;  // line length over 512
		constexpr int e_method = -4; // method error   
		constexpr int e_url = -5;  // URL error
		constexpr int e_ver = -6;  // version error not "http/1.1."
		constexpr int e_head = -7; // head item error		
		constexpr int e_bodysize = -8; // body size "Content-Length" error 		

		static bool isdir(const char* s)
		{
#ifdef _WIN32
			struct _stat st;
			if (_stat(s, &st))
				return false;
			if (st.st_mode & S_IFDIR)
				return true;
			return false;
#else
			struct stat st;
			if (stat(s, &st))
				return false;
			if (st.st_mode & S_IFDIR)
				return true;
			return false;
#endif
		}
		static const char *file_extname(const char*s)
		{
			const char *pr = NULL;
			while (*s) {
				if (*s == '.')
					pr = s;
				s++;
			}
			return pr;
		}

		class txt // text with length
		{
		public:
			const char* _s;
			size_t _size;
		public:
			txt(const char* s = nullptr, size_t size = 0) :_s(s), _size(size)
			{
			}
			inline void clear()
			{
				_s = nullptr;
				_size = 0;
			}
			inline bool empty()
			{
				return !_size || !_s;
			}
			inline bool is_endline()
			{
				return (_s && _size == 2 && _s[0] == '\r' && _s[1] == '\n');
			}
			inline bool is_multiline()
			{
				return (_s && _size > 0 && (_s[0] == '\x20' || _s[0] == '\t'));
			}
			void trim()
			{
				char c;
				while (_size > 0) { // left
					c = *_s;
					if (c != '\x20' && c != '\t')
						break;
					_s++;
					_size--;
				}
				while (_size > 0) { // right
					c = *(_s + _size - 1);
					if (c != '\r' && c != '\n' && c != '\x20' && c != '\t')
						break;
					_size--;
				}
			}
			bool ieq(const char* s) // Case insensitive equal
			{
				if (!s || !_s || !_size)
					return false;
				const char* sr = _s;
				size_t i = 0;
				while (i < _size && *s) {
					if (*s != *sr && tolower(*s) != tolower(*sr))
						return false;
					s++;
					sr++;
					i++;
				}
				return !*s;
			}
			bool get2c(txt* pout, const char c) // get to c and skip c
			{
				pout->_s = _s;
				pout->_size = 0;
				while (_size > 0) {
					if (*_s == c) {
						_s++;
						_size--;
						return pout->_size > 0;
					}
					_s++;
					_size--;
					pout->_size++;
				}
				return false;
			}
			bool get2sp(txt* pout) // get to space '\x20' or '\t'
			{
				pout->_s = _s;
				pout->_size = 0;
				while (_size > 0) {
					if (*_s == '\x20' || *_s == '\t')
						return pout->_size > 0;
					_s++;
					_size--;
					pout->_size++;
				}
				return pout->_size > 0;
			}
			int getline(txt* pout) //return <0 : error ; 0 : e_wait; >0 : line size include line end "\r\n"
			{
				pout->_s = _s;
				pout->_size = 0;
				while (_size > 1) {
					if (*_s == '\r') {
						if (*(_s + 1) != '\n')
							return e_head;
						_s += 2;
						_size -= 2u;
						pout->_size += 2u;
						return (pout->_size > 1024) ? e_linesize : (int)pout->_size;
					}
					_s++;
					_size--;
					pout->_size++;
				}
				return (pout->_size > 1024) ? e_linesize : e_wait;
			}
			int skip()// skip char \x20 , \t , \r, \n
			{
				int n = 0;
				while (_size > 0) {
					if (*_s == '\n')
						n++;
					else if (*_s != '\x20' && *_s != '\t' && *_s != '\r')
						break;
					_s++;
					_size--;
				}
				return n;
			};
			bool headitem(txt* key, txt *val)//parse to key and value
			{
				if (!get2c(key, ':'))
					return false;
				skip();
				val->_s = _s;
				val->_size = _size;
				key->trim();
				return !(key->empty() || val->empty());
			}
		};

		/*!
		\brief parse request_line
		*/
		class req_line
		{
		public:
			req_line()
			{
			}
			txt _method, _url, _ver;
		public:
			inline void clear()
			{
				_method.clear();
				_url.clear();
				_ver.clear();
			}
			int parse(const char* sl, size_t size)// return <0 : error ; >0 : line size
			{
				if (!sl || !size)
					return e_err;
				txt _s(sl, size);
				if (!_s.get2sp(&_method) || (!_method.ieq("get") && !_method.ieq("head")))
					return e_method;
				_s.skip();
				if (!_s.get2sp(&_url))
					return e_url;
				_s.skip();
				if (!_s.get2sp(&_ver) || !_ver.ieq("http/1.1")) {
					if (_ver.empty() && _url.ieq("http/1.1"))
						return e_url;
					return e_ver;
				}
				if (!_url._size || !_url._s)
					return e_url;
				return (int)size;
			}
		};

		/*!
		\brief parse http package
		*/
		class package
		{
		public:
			package()
			{
			}
			struct t_i {
				txt _key;
				txt _val;
			};
			req_line _req; // start line
			ec::Array<t_i, 24> _head;//head items
			txt _body; // body
		public:
			inline void clear()
			{
				_req.clear();
				_body.clear();
				_head.clear();
			}
			int parse(const char* s, size_t size)// return <0 : error ; 0 : e_wait; >0 : package size
			{
				clear();
				if (!s || !size)
					return e_err;
				txt _s(s, size);
				int ne;
				txt l;
				ne = _s.getline(&l); // start line
				if (ne <= 0)
					return ne;
				l.trim();
				ne = _req.parse(l._s, l._size);
				if (ne <= 0)
					return ne;
				t_i i;
				ne = _s.getline(&l);
				while (ne > 0) {
					if (l.is_multiline()) { // multiline continue
						if (!_head.size())
							return e_head;
						_head[_head.size() - 1]._val._size += l._size;
					}
					else if (l.is_endline()) { // only "\r\n"
						if (_s._size >= _body._size) { // head end
							_body._s = _s._s;
							_head.for_each([&](t_i& v) { // head item value trim space
								v._val.trim();
							});
							return (int)((_body._s - s) + _body._size);
						}
						return e_wait;
					}
					else {
						if (!l.headitem(&i._key, &i._val))
							return e_head;
						if (!_head.add(i))// add failed ,head item too much
							return e_head;
						if (i._key.ieq("Content-Length")) {
							if (i._val._size > 15)
								return e_head;
							char stmp[16] = { 0 };
							memcpy(stmp, i._val._s, i._val._size);
							long long len = atoll(stmp);
							if (len <= 0 || len > INT32_MAX)
								return e_bodysize;
							_body._size = (int)len;
						}
					}
					ne = _s.getline(&l);
				}
				return ne;
			}
			txt* getattr(const char* key)
			{
				size_t i;
				for (i = 0; i < _head.size(); i++) {
					if (_head[i]._key.ieq(key))
						return &_head[i]._val;
				}
				return nullptr;
			}
			inline t_i* getattr(size_t i)
			{
				return _head.atptr(i);
			}
			static const char* serr(int nerr)
			{
				const char* s[] = { "wait","failed","line end space","line size","method","url","ver","head","body size" };
				int n = nerr * (-1);
				if (n < 0 || n >= (int)(sizeof(s) / sizeof(void*)))
					return "none";
				return s[n];
			}
			
			bool GetHeadFiled(const char* skey, char sval[], size_t size)
			{
				txt* pt = getattr(skey);
				if (!pt || pt->_size >= size)
					return false;
				memcpy(sval, pt->_s, pt->_size);
				sval[pt->_size] = 0;
				return true;
			}
			bool CheckHeadFiled(const char* skey, const char* sval)
			{
				char sv[80];
				txt* pt = getattr(skey);
				if (!pt)
					return false;
				size_t pos = 0;
				while (str_getnext(",", pt->_s, pt->_size, pos, sv, sizeof(sv))) {
					if (!str_icmp(sv, sval))
						return true;
				}
				return false;
			}
			inline bool HasKeepAlive()
			{
				return CheckHeadFiled("Connection", "keep-alive");
			}
			inline bool GetWebSocketKey(char sout[], size_t size)
			{
				return (CheckHeadFiled("Connection", "Upgrade") && CheckHeadFiled("Upgrade", "websocket")
					&& GetHeadFiled("Sec-WebSocket-Key", sout, size));
			}
			inline bool ismethod(const char* key)
			{
				return _req._method.ieq(key);
			}
			bool GetUrl(char sout[], size_t size)
			{
				size_t i = 0u;
				while (i + 1 < size && i < _req._url._size) {
					if (_req._url._s[i] == '?')
						break;
					sout[i] = _req._url._s[i];
					i++;
				}
				sout[i] = 0;
				return i > 0;
			}
			bool GetMethod(char sout[], size_t size)
			{
				if (size + 1 < _req._method._size)
					return false;
				memcpy(sout, _req._method._s, _req._method._size);
				sout[_req._method._size] = 0;
				return true;
			}
		};
	}// http
}//ec