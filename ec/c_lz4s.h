/*!
\file c_lz4.h

LZ4 - Fast LZ compression algorithm
Header File
Copyright (C) 2011-2015, Yann Collet.

BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

You can contact the author at :
- LZ4 source repository : https://github.com/Cyan4973/lz4
- LZ4 public forum : https://groups.google.com/forum/#!forum/lz4c

*/


#ifndef C_LZ4_H
#define C_LZ4_H

#ifdef __cplusplus
extern "C" {
#endif
	int LZ4_compress_default(const char* source, char* dest, int sourceSize, int maxDestSize);
	int LZ4_decompress_safe(const char* source, char* dest, int compressedSize, int maxDecompressedSize);
#ifdef __cplusplus
} /* extern "C" */
#endif

namespace ec
{
	inline  bool encode_lz4(const void *pSrc, size_t size_src, void* pDes, size_t* psize_des)
	{
		int noutsize = LZ4_compress_default((const char*)pSrc, (char*)pDes, static_cast<int>(size_src), static_cast<int>(*psize_des));
		if (noutsize > 0) {
			*psize_des = (size_t)noutsize;
			return true;
		}
		else {
			*psize_des = 0;
			return false;
		}
	}
	inline  bool decode_lz4(const void *pSrc, size_t size_src, void* pDes, size_t* psize_des)
	{
		int noutsize = LZ4_decompress_safe((const char*)pSrc, (char*)pDes, static_cast<int>(size_src), static_cast<int>(*psize_des));
		if (noutsize > 0) {
			*psize_des = (size_t)noutsize;
			return true;
		}
		else {
			*psize_des = 0;
			return false;
		}
	}
}//namespace ec

#endif //C_LZ4_H
