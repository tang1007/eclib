/*!
\file c11_hash.h
\author	kipway@outlook.com
\update 2018.4.6

eclib class hash with c++11. Separated from c11_map.h

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
namespace ec
{
	template<class _Kty> // hash class
	struct hash
	{
		size_t operator()(_Kty key)
		{
			if (sizeof(size_t) == 8)
				return static_cast<size_t>(static_cast<size_t>(key) * 11400714819323198485ULL);
			return (((size_t)key) * 2654435769U);
		}
	};
	template<>
	struct hash<const char*>
	{
		size_t  operator()(const char*  key)
		{
			register unsigned int uHash = 0;
			while (char ch = *key++)
				uHash = uHash * 31 + ch;
			return uHash;
		}
	};
	template<>
	struct hash<char*>
	{
		size_t operator()(char*  key)
		{
			register unsigned int uHash = 0;
			while (char ch = *key++)
				uHash = uHash * 31 + ch;
			return uHash;
		}
	};	
}

