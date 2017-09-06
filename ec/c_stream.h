/*!
    \file tStream.h
    \brief simple stream

    simple stream

    \author jiangyong
    \email 13212314895%126.com
    */
#ifndef C_STREAM_H
#define C_STREAM_H
#include <memory.h>
namespace ec
{
    class cStream
    {
    public:
        cStream() {
            _ps = 0;
            _size = 0;
            _pos = 0;
        };
        cStream(void* p, size_t size) {
            attach(p, size);
        };
        ~cStream() {};
    public:
        void attach(void* p, size_t size)
        {
            _ps = (char*)p;
            _size = size;
            _pos = 0;
        }
        template < typename T > cStream & operator >> (T& v)
        {
            if (_pos + sizeof(T) > _size)
                throw (int)1;
            v = *((T*)(_ps + _pos));
            _pos += sizeof(T);
            return *this;
        };

        template < typename T > cStream & operator << (T v)
        {
            if (_pos + sizeof(T) > _size)
                throw (int)1;
            *((T*)(_ps + _pos)) = v;
            _pos += sizeof(T);
            return *this;
        };

        template < typename T > cStream & operator < (T v)  // write as big_endian
        {
            if (_pos + sizeof(T) > _size)
                throw (int)1;
            if (sizeof(T) == 1)
            {
                *((T*)(_ps + _pos)) = v;
            }
            else if (sizeof(T) == 2)
            {
                unsigned short uv = *((unsigned short*)&v);
                unsigned char *pu = (unsigned char*)(_ps + _pos);
                *pu++ = (uv >> 8) & 0xFF;
                *pu++ = uv & 0xFF;
            }
            else if (sizeof(T) == 4)
            {
                unsigned int uv = *((unsigned int *)&v);
                unsigned char *pu = (unsigned char*)(_ps + _pos);
                *pu++ = (uv >> 24) & 0xFF;
                *pu++ = (uv >> 16) & 0xFF;
                *pu++ = (uv >> 8) & 0xFF;
                *pu++ = uv & 0xFF;
            }
            else if (sizeof(T) == 8)
            {
                unsigned long long  uv = *((unsigned long long*)&v);
                unsigned char *pu = (unsigned char*)(_ps + _pos);
                *pu++ = (uv >> 56) & 0xFF;
                *pu++ = (uv >> 48) & 0xFF;
                *pu++ = (uv >> 40) & 0xFF;
                *pu++ = (uv >> 32) & 0xFF;
                *pu++ = (uv >> 24) & 0xFF;
                *pu++ = (uv >> 16) & 0xFF;
                *pu++ = (uv >> 8) & 0xFF;
                *pu++ = uv & 0xFF;
            }
            else
                throw (int)2;
            _pos += sizeof(T);
            return *this;
        };

        template < typename T > cStream & operator > (T* pv) // read as big_endian
        {
            if (_pos + sizeof(T) > _size)
                throw (int)1;
            if (sizeof(T) == 1)
            {
                *pv = *((T*)(_ps + _pos));
            }
            else if (sizeof(T) == 2)
            {
                unsigned short uv;
                unsigned char *pu = (unsigned char*)(_ps + _pos);
                uv = *pu++;
                uv = (uv << 8) | *pu++;
                *pv = *((T*)&uv);
            }
            else if (sizeof(T) == 4)
            {
                unsigned int uv;
                unsigned char *pu = (unsigned char*)(_ps + _pos);
                uv = *pu++;
                uv = (uv << 8) | *pu++;
                uv = (uv << 8) | *pu++;
                uv = (uv << 8) | *pu++;
                *pv = *((T*)&uv);
            }
            else if (sizeof(T) == 8)
            {
                unsigned long long  uv;
                unsigned char *pu = (unsigned char*)(_ps + _pos);
                uv = *pu++;
                uv = (uv << 8) | *pu++;
                uv = (uv << 8) | *pu++;
                uv = (uv << 8) | *pu++;
                uv = (uv << 8) | *pu++;
                uv = (uv << 8) | *pu++;
                uv = (uv << 8) | *pu++;
                uv = (uv << 8) | *pu++;
                *pv = *((T*)&uv);
            }
            else
                throw (int)2;
            _pos += sizeof(T);
            return *this;
        };

        cStream & read(void* pbuf, size_t size)
        {
            if (_pos + sizeof(size) > _size)
                throw (int)1;
            memcpy(pbuf, _ps + _pos, size);
            _pos += size;
            return *this;
        };

        cStream & write(const void* pbuf, size_t size)
        {
            if (_pos + sizeof(size) > _size)
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

        inline size_t getpos() { return _pos; };
        inline size_t leftsize() { return _size - _pos; }
        inline void* getp() { return _ps; };
    protected:
        size_t	_pos;
        size_t	_size;
        char*	_ps;
    };
};

#endif