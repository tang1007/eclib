/*!
\file c_array.h
\brief dynamic template array

Elements of the tArray can only be simple types and structures

ec library is free C++ library.
\author	 kipway@outlook.com
*/

#ifndef C_ARRAY_H
#define C_ARRAY_H

#include <stdlib.h>
#include <memory.h>

#ifndef MAX_CARRAY_SIZE
#define MAX_CARRAY_SIZE		(1024 * 1024 * 1024) //max items 1G
#endif

namespace ec {
    template<class T>
    class tArray
    {
    public:
        tArray(size_t ugrownsize) {
            _pbuf = NULL;
            _usize = 0;
            _ubufsize = 0;
            SetGrowSize(ugrownsize);
        };
        ~tArray() {
            if (_pbuf != NULL)
            {
                free(_pbuf);
            }
        };
    protected:
        T*		_pbuf;
        size_t	_usize;
        size_t	_ubufsize;
        size_t	_ugrown;
    protected:
        bool Grown(size_t usize = 1)
        {
            T	*pt;
            size_t	usizet = _usize + usize;
            if (!usize)
                return true;
            if (usizet > MAX_CARRAY_SIZE)
                return false;
            if (usizet > _ubufsize) {
                usizet += _ugrown - (usizet%_ugrown);
                pt = (T*)realloc(_pbuf, usizet * sizeof(T));
                if (!pt)
                    return false;
                _pbuf = pt;
                _ubufsize = usizet;
            }
            return true;
        }
    public:
        inline T& operator [](int nindex)
        {
            return _pbuf[nindex];
        }
        inline T* GetBuf() const { return _pbuf; };
        inline unsigned int GetSize() const { return (unsigned int)_usize; };
        inline int	GetNum() const { return (int)_usize; };
        inline unsigned int GetBufSize() { return (unsigned int)_ubufsize; };
        inline void SetDataSize(unsigned int n) { _usize = n; };
        bool Add(T obj)
        {
            if (!Grown(1))
                return false;
            memcpy(_pbuf + _usize, &obj, sizeof(T));
            _usize += 1;
            return true;
        }
        bool Add(const T *pbuf, size_t usize = 1)
        {
            if (!usize || !Grown(usize))
                return false;
            memcpy(_pbuf + _usize, pbuf, usize * sizeof(T));
            _usize += usize;
            return true;
        };
        T*	GetAt(size_t pos)
        {
            if (pos < _usize)
                return &_pbuf[pos];
            return NULL;
        }
        void SetGrowSize(size_t ugrowsize) {
            _ugrown = ugrowsize;
            if (_ugrown % 4)
                _ugrown += 8 - (_ugrown % 8);
            if (_ugrown > MAX_CARRAY_SIZE)
                _ugrown = MAX_CARRAY_SIZE;
        };

        inline void	ClearData() {
            _usize = 0;
        };
        bool DeleteAt(size_t pos, T& item) {
            if (!_pbuf || pos >= _usize)
                return false;
            item = _pbuf[pos];
            if (pos + 1 < _usize)
                memmove(_pbuf + pos, _pbuf + pos + 1, sizeof(T) * (_usize - pos - 1));
            _usize--;
            return true;
        }
        void LeftMove(size_t  n) {
            if (!_pbuf || !n)
                return;
            if (n >= _usize) {
                _usize = 0;
                return;
            }
            memmove(_pbuf, _pbuf + n, (_usize - n) * sizeof(T));
            _usize -= n;
        };

        /*!
        \breif clear and free buffer
        */
        void  ClearAndFree(size_t sizemin)//clear data if _ubufsize > sizemin free _pbuf
        {
            _usize = 0;
            if (_pbuf && _ubufsize > sizemin)
            {
                free(_pbuf);
                _pbuf = NULL;
                _ubufsize = 0;
            }
        }

        /*!
        \brief reduce buffer to itemsize,keep data
        */
        void ReduceMem(size_t itemsize)
        {
            if (!_pbuf || _ubufsize <= itemsize || _usize >= itemsize)
                return;
            T* pnew = (T*)malloc(itemsize * sizeof(T));
            if (!pnew)
                return;
            memcpy(pnew, _pbuf, _usize * sizeof(T));
            free(_pbuf);
            _pbuf = pnew;
            _ubufsize = itemsize;
        }

        bool InsertAt(size_t pos, const T *pbuf, size_t usize)// insert before
        {
            if (!pbuf || !usize)
                return false;
            if (pos >= _usize)
                return Add(pbuf, usize);
            if (!Grown(usize))
                return false;                        
            memmove(_pbuf + pos + usize, _pbuf + pos, (_usize - pos) * sizeof(T));
            memcpy(_pbuf + pos, pbuf, usize * sizeof(T));
            _usize += usize;
            return true;            
        }
        bool Replace(size_t pos, size_t rsize, const T *pbuf, size_t usize)
        {                       
            if (!rsize)
                return InsertAt(pos, pbuf, usize);  // insert
                
            if (!pbuf || !usize) //delete
            {
                if (pos + rsize >= _usize) {
                    _usize = pos;
                    return true;
                }
                memmove(_pbuf + pos, _pbuf + pos + rsize, (_usize - (pos + rsize)) * sizeof(T));
                _usize = _usize - rsize;
                return true;
            }
            if (pos >= _usize) // add
                return Add(pbuf, usize);
           
            if (pos + rsize >= _usize)//outof end
            {
                _usize = pos;
                return Add(pbuf, usize);
            }
           
            if (usize > rsize) {
                if (!Grown(usize - rsize))
                    return false;
            }
            if(rsize != usize)
                memmove(_pbuf + pos + usize, _pbuf + pos + rsize, (_usize - (pos + rsize)) * sizeof(T));
            memcpy(_pbuf + pos, pbuf, usize * sizeof(T));
            _usize = _usize + usize - rsize;
            return true;
        }

        inline bool Delete(size_t pos, size_t rsize)
        {
            return Replace(pos,rsize,0,0);
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
                qsort_s(_pbuf, _usize, sizeof(T), compare, pCompareParam);
        }
#else
        void Sort(void* pCompareParam)
        {
            if (_usize > 1)
                qsort_r(_pbuf, _usize, sizeof(T), &compare, pCompareParam);
        }
#endif // _WIN32
    };
}; //ec

#endif // C_ARRAY_H

