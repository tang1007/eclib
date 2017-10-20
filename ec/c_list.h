/*!
\file c_list.h
ec library is free C++ library.

\author	 kipway@outlook.com
*/
#pragma once

namespace ec
{
    template<class KEY, class VALUE>
    class cList
    {
    protected:
        struct t_i
        {
            t_i* next;
            t_i* prior;
            VALUE v;
        };
        t_i* _ph;
        t_i* _pt;
        int _nsize;
    public:
        cList()
        {
            _ph = 0;
            _pt = 0;
            _nsize = 0;
        }
        ~cList()
        {
            clear();
        }
        inline int size()
        {
            return _nsize;
        }
        void clear()
        {
            t_i* p = _ph, *pp;
            while (p)
            {
                pp = p;
                if (p->next)
                    pp = p;
                p = p->next;                
                delete pp;
            }
            _ph = 0;
            _pt = 0;
            _nsize = 0;
        }

        bool put_head(VALUE val)
        {
            t_i* p = new t_i;
            if (!p)
                return false;
            if(_ph)
                _ph->prior = p;

            p->next = _ph;
            p->prior = 0;
            p->v = val;
            _ph = p;

            if (!_pt)
                _pt = p;
            _nsize++;
            return true;
        }        

        bool pop_end(VALUE &val)
        {
            if (!_pt)
                return false;
            t_i* p = _pt->prior;
            if (_pt == _ph)
                _ph = 0;
            val = _pt->v;
            delete _pt;
            _pt = p;            
            if (_pt)
                _pt->next = 0;
            _nsize--;
            return true;
        }        

        bool remove_at(KEY key, VALUE &v)
        {
            t_i* p = _ph;
            while (p)
            {
                if (KeyEqual(key, &p->v))
                {       
                    v = p->v;
                    Remove(p);
                    delete p;
                    return true;
                }
                p = p->next;
            }
            return false;
        }

        void* put_head2(VALUE &val)
        {
            t_i* p = new t_i;
            if (!p)
                return 0;
            if (_ph)
                _ph->prior = p;

            p->next = _ph;
            p->prior = 0;
            p->v = val;
            _ph = p;

            if (!_pt)
                _pt = p;
            _nsize++;
            return p;
        }
        bool remove_at2(KEY key, VALUE &v, void* pnode)
        {
            t_i* p = (t_i*)pnode;
            if (KeyEqual(key, &p->v))
            {
                v = p->v;
                Remove(p);
                delete p;
                return true;
            }
            return false;
        }
    protected:
        void Remove(t_i* p)
        {
            if (p == _ph)
            {
                if (_ph == _pt)
                {
                    _ph = 0;
                    _pt = 0;
                    _nsize = 0;
                    return;
                }
                else
                {
                    _ph = p->next;
                    _ph->prior = 0;
                }                
            }
            else if (p == _pt)
            {
                _pt = p->prior;
                _pt->next = 0;
            }
            else
            {
                p->next->prior = p->prior;
                p->prior->next = p->next;
            }
            _nsize--;
        }

        bool	KeyEqual(KEY key, VALUE* pcls);        
    };
};
