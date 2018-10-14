/*!
\file c11_console.cpp
\author kipway@outlook.com
\update 2018.10.14

eclib Console application framework

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

#include "ec/c11_system.h"
#include "ec/c11_cmdline.h"

#define CMDOD_LEN 4096

const char* g_help = "\nwelcom to console!";//todo: your help string

inline void prt_prompt() {
	printf("\n>>");
}

int main(int argc, char* argv[])
{
	char sod[CMDOD_LEN];
	const char* scmd = nullptr;
	ec::cCmdLine cmdline(nullptr);

	printf("%s", g_help);
	prt_prompt();
	while (1) {
		if (!fgets(sod, CMDOD_LEN - 1, stdin))
			continue;

		if (!cmdline.parse(sod)) {
			prt_prompt();
			continue;
		}
		scmd = cmdline.cmd();
		if (!scmd)
			continue;

		if (ec::str_ieq(scmd, "help")) {

			printf("%s", g_help);
			prt_prompt();
		}
		else if (ec::str_ieq(scmd, "exit"))
			break;
		
		//todo your command

		else {
			cmdline.print();
			printf("unkown command!");
			prt_prompt();
		}
	}
	return 0;
}
