#pragma once
#ifndef _C_MEMINFO_H
#define _C_MEMINFO_H

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/sysinfo.h>
#endif
namespace ec
{
    inline unsigned long GetFreeMem()
    {
#ifdef _WIN32
        MEMORYSTATUSEX statex;
        statex.dwLength = sizeof(statex);
        if (GlobalMemoryStatusEx(&statex))
        {
            unsigned long long lfrPhys = statex.ullAvailPhys / (1024 * 1024); //MB
            unsigned long long lfrVir = statex.ullAvailVirtual / (1024 * 1024); //MB
            return (unsigned long)(lfrPhys < lfrVir ? lfrPhys : lfrVir);
        }
#else
        struct sysinfo info;
        if (!sysinfo(&info))
            return info.freeram / (1024 * 1024);
#endif
            return 0;
    }
}
#endif 
