/*!
\file c_map.h
\brief hash map

ec library is free C++ library.

\author	 kipway@outlook.com
*/


#ifndef C_MAP_H
#define C_MAP_H

#include <memory.h>
namespace ec
{
    template <class KEY>
    inline unsigned int	tMapHashKey(KEY key)
    {
        return (((unsigned int)key) * 2654435769);
    };

    template <>
    inline unsigned int	tMapHashKey(const char* key)
    {
        //Brian Kernighan与Dennis Ritchie
        register unsigned int uHash = 0;
        while (char ch = *key++)
            uHash = uHash * 31 + ch;
        return uHash;
    };

    template <>
    inline unsigned int	tMapHashKey(char* key)
    {
        //Brian Kernighan与Dennis Ritchie
        register unsigned int uHash = 0;
        while (char ch = *key++)
            uHash = uHash * 31 + ch;
        return uHash;
    };

    template<class KEY, class VALUE>
    class tMap
    {
    protected:
        struct CAssoc
        {
            CAssoc* pNext;
            VALUE	value;
        };
    public:
        tMap(unsigned int uhashsize = 1024) {
            _ppv = NULL;
            _usize = uhashsize;
            _ncount = 0;
        };
        ~tMap()
        {
            RemoveAll();
        };
    protected:
        CAssoc**	 _ppv;
        unsigned int _usize;
        int			 _ncount;
    protected:
        bool	ValueKey(KEY key, VALUE* pcls);
        void    OnRemoveValue(VALUE* pcls);
    public:
        void InitHashSize(unsigned int size)
        {
            if (_ppv || _ncount || size <= _usize)
                return;
            _usize = size;            
        }
        inline int GetCount() const { return _ncount; };

        VALUE* SetAt(KEY key, VALUE& newValue, bool bRemoveOld = true)
        {
            if (_ppv == NULL)
            {
                _ppv = new CAssoc*[_usize];
                if (_ppv == NULL)
                    return NULL;
                memset(_ppv, 0, sizeof(CAssoc*) * _usize);
            }
            unsigned int upos = tMapHashKey(key) % _usize;
            CAssoc* pAssoc;
            for (pAssoc = _ppv[upos]; pAssoc != NULL; pAssoc = pAssoc->pNext)
            {
                if (ValueKey(key, &pAssoc->value))
                {
                    if (bRemoveOld)
                        OnRemoveValue(&pAssoc->value);
                    pAssoc->value = newValue;
                    return &pAssoc->value;
                }
            }
            pAssoc = new CAssoc;
            if (pAssoc == NULL)
                return NULL;
            pAssoc->value = newValue;
            pAssoc->pNext = _ppv[upos];
            _ppv[upos] = pAssoc;
            _ncount++;
            return &pAssoc->value;
        };

        VALUE* Lookup(KEY key)
        {
            if (_ppv == NULL)
                return NULL;
            unsigned int upos = tMapHashKey(key) % _usize;
            CAssoc* pAssoc;
            for (pAssoc = _ppv[upos]; pAssoc != NULL; pAssoc = pAssoc->pNext) {
                if (ValueKey(key, &pAssoc->value))
                    return &pAssoc->value;
            }
            return NULL;
        };
        bool Lookup(KEY key, VALUE& val)
        {
            if (_ppv == NULL)
                return NULL;
            unsigned int upos = tMapHashKey(key) % _usize;
            CAssoc* pAssoc;
            for (pAssoc = _ppv[upos]; pAssoc != NULL; pAssoc = pAssoc->pNext) {
                if (ValueKey(key, &pAssoc->value)) {
                    val = pAssoc->value;
                    return true;
                }
            }
            return false;
        };

        void RemoveAll()
        {
            if (_ppv != NULL)
            {
                for (unsigned int i = 0; i < _usize; i++)
                {
                    CAssoc* ppre;
                    CAssoc* pAssoc = _ppv[i];
                    while (pAssoc)
                    {
                        ppre = pAssoc;
                        pAssoc = pAssoc->pNext;
                        OnRemoveValue(&ppre->value);
                        delete ppre;
                    }
                }
                delete[] _ppv;
            }
            _ppv = NULL;
            _ncount = 0;
        };

        bool RemoveKey(KEY key)
        {
            if (_ppv == NULL)
                return false;
            unsigned int upos = tMapHashKey(key) % _usize;
            CAssoc** ppAssocPrev;
            ppAssocPrev = &_ppv[upos];
            CAssoc* pAssoc;
            for (pAssoc = *ppAssocPrev; pAssoc != NULL; pAssoc = pAssoc->pNext)
            {
                if (ValueKey(key, &pAssoc->value))
                {
                    *ppAssocPrev = pAssoc->pNext;
                    OnRemoveValue(&pAssoc->value);
                    delete pAssoc;
                    _ncount--;
                    return true;
                }
                ppAssocPrev = &pAssoc->pNext;
            }
            return false;
        };

        bool GetNext(int &npos, int &nlist, VALUE* &pValue)
        {
            if (_ppv == NULL || npos >= (int)_usize || npos < 0) {
                npos = -1;
                return false;
            }
            CAssoc* pAssoc = NULL;
            int nl = 0;
            while (npos < (int)_usize) {
                pAssoc = _ppv[npos];
                nl = 0;
                while (nl < nlist && pAssoc) {
                    pAssoc = pAssoc->pNext;
                    nl++;
                }
                if (pAssoc) {
                    pValue = &pAssoc->value;
                    if (!pAssoc->pNext) {
                        npos++;
                        nlist = 0;
                    }
                    else
                        nlist++;
                    return true;
                }
                npos++;
                nlist = 0;
            }
            npos = -1;
            return false;
        };

        bool GetNext(int &npos, int &nlist, VALUE &rValue)
        {
            if (_ppv == NULL || npos >= (int)_usize || npos < 0) {
                npos = -1;
                return false;
            }
            CAssoc* pAssoc = NULL;
            int nl = 0;
            while (npos < (int)_usize) {
                pAssoc = _ppv[npos];
                nl = 0;
                while (nl < nlist && pAssoc) {
                    pAssoc = pAssoc->pNext;
                    nl++;
                }
                if (pAssoc) {
                    rValue = pAssoc->value;
                    if (!pAssoc->pNext) {
                        npos++;
                        nlist = 0;
                    }
                    else
                        nlist++;
                    return true;
                }
                npos++;
                nlist = 0;
            }
            npos = -1;
            return false;
        };
    };//tMap	

};//ec
#endif //C_MAP_H

