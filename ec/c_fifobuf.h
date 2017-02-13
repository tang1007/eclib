/*! 
\file c_cifobuf.h
\brief 	class FIFO

  FIFO buffer

  ec library is free C++ library.

 \author kipway@outlook.com
*/

#ifndef C_FIFOBUF_H
#define C_FIFOBUF_H

#include <stdlib.h>
namespace ec{
	template<class T>
	class tFifo
	{
	public:
		tFifo(){
			_pbuf = NULL;
			_usize = 0;
			_uhead = 0;
			_utail = 0;
		};
		tFifo(size_t usize){
			_pbuf = new T[usize];
			_usize = usize;
			_uhead = 0;
			_utail = 0;
		};
		~tFifo(){
			if(_pbuf != NULL)
				delete []_pbuf;
		};
	protected:
		T*		_pbuf;		
		size_t	_usize;		
		size_t	_uhead;		// out
		size_t	_utail;		// in
	public:
		bool SetBufSize(size_t usize)
		{
			if(_pbuf && usize== _usize)
				return true;
			if(_pbuf)
				delete [] _pbuf;
			
			_pbuf = new T[usize];
			if(_pbuf)
				_usize = usize;
			else
				_usize = 0;
			_uhead = 0;
			_utail = 0;
			return (_pbuf != NULL);
		};
		inline bool IsEmpty() const	{
			return _uhead == _utail;
		};
		inline bool IsFull() const{
			return  (_utail + 1)%_usize == _uhead;
		};
		inline bool	IsBufOk() const{
			return _pbuf != NULL;
		}
		bool DoFind(T* pin ,void* parg ,T* pout);//if find return true and cpoy pin to pout,otherwise return false

		bool Add(T &item,bool breplace,int nleft = 0) //nleft is res size
		{
			if(!_pbuf)			
				return false;

			if(!breplace && nleft && GetLeft() < nleft)
				return false;

			if((_utail + 1)%_usize == _uhead){
				if(!breplace)
					return false;
				_uhead = (_uhead + 1)%_usize;
			}
			_pbuf[_utail] = item;
			_utail = (_utail + 1) % _usize;
			return true;
		};
		bool Get( T& item)
		{
			if(!_pbuf || _uhead == _utail)
				return false;
			item  = _pbuf[_uhead];
			_uhead = (_uhead + 1)%_usize;
			return true;
		}
		
		T*	ViewTail(void)
		{
			if(!_pbuf || _uhead == _utail)
				return NULL;
			return &_pbuf[(_utail + _usize - 1)%_usize];			
		}

		T*	ViewHead(void)
		{
			if(!_pbuf || _uhead == _utail)
				return NULL;
			return &_pbuf[_uhead];
		}
		void RemoveHead(){
			if(!_pbuf || _uhead == _utail)
				return ;
			_uhead = (_uhead + 1)%_usize;
		}
		void RemoveAll()
		{
			_uhead = 0;
			_utail = 0;
		}
		int GetItems()
		{
			size_t uh = _uhead;
			int n = 0;
			while(uh != _utail)
			{
				n++;
				uh = (uh + 1)%_usize;
			}
			return n;
		}
        inline int Count() {
            return GetItems();
        }
		int GetLeft()
		{
			return (int)_usize - GetItems();
		}

		/// \brief from older
		bool Find(void* pArgs,T* pOut)
		{
			size_t  h = _uhead;
			if(!_pbuf)
				return false;
			while( h != _utail)
			{
				if(DoFind(&_pbuf[h],pArgs,pOut))
					return true;
				h = (h +1)%_usize;
			}
			return false;
		}

		/// \brief from new
		bool Find2(void* pArgs,T* pOut)
		{
			size_t  t = _utail;
			if(!_pbuf)
				return false;			
			while( t != _uhead)
			{
				t = (t + _usize - 1) % _usize;
				if(DoFind(&_pbuf[t],pArgs,pOut))
					return true;				
			}
			return false;
		}
	};
}; // namespace

#endif // C_FIFOBUF_H

