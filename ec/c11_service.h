/*!
\file c11_service.h
\author kipway@outlook.com
\update 2018.11.30

service frame for windows and Linux

eclib Copyright (c) 2017-2018, kipway
source repository : https://github.com/kipway/eclib

Licensed under the Apache License, Version 2.0 (the "License");
*/
#pragma once

#include <stdio.h>
#include <stdarg.h>
#include "c_usews32.h"
#include "c_str.h"

#ifdef _WIN32
#include "tchar.h"
#include <Windows.h>

namespace ec {
	class CNtService
	{
	public:
		CNtService() {};
		virtual ~CNtService() {};
		void Init(LPCTSTR sName, LPCTSTR sDispName, LPCTSTR sDescription)
		{
			m_bShutDown = FALSE;
			_tcscpy(m_szServiceName, sName);
			_tcscpy(m_szServiceDispName, sDispName);
			_tcscpy(m_szServiceDes, sDescription);

			m_hServiceStatus = NULL;
			m_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
			m_status.dwCurrentState = SERVICE_STOPPED;
			m_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
			m_status.dwWin32ExitCode = 0;
			m_status.dwServiceSpecificExitCode = 0;
			m_status.dwCheckPoint = 0;
			m_status.dwWaitHint = 0;
		}
	public:
		static CNtService* _pobj;
		TCHAR m_szServiceName[256];
		TCHAR m_szServiceDispName[256];
		TCHAR m_szServiceDes[256];

		SERVICE_STATUS_HANDLE	m_hServiceStatus;
		SERVICE_STATUS			m_status;
		DWORD					m_dwThreadID;

		bool					m_bShutDown;

		void ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv)
		{
			m_status.dwCurrentState = SERVICE_START_PENDING;
			m_hServiceStatus = RegisterServiceCtrlHandler(m_szServiceName, _Handler);
			if (m_hServiceStatus == NULL)
				return;
			SetServiceStatus(SERVICE_START_PENDING);

			m_status.dwWin32ExitCode = S_OK;
			m_status.dwCheckPoint = 0;
			m_status.dwWaitHint = 0;

			Run();
			SetServiceStatus(SERVICE_STOPPED);
		}

		void Handler(DWORD dwOpcode)
		{
			switch (dwOpcode)
			{
			case SERVICE_CONTROL_STOP:
				SetServiceStatus(SERVICE_STOP_PENDING);
				PostThreadMessage(m_dwThreadID, WM_QUIT, 0, 0);
				break;
			case SERVICE_CONTROL_PAUSE:
				break;
			case SERVICE_CONTROL_CONTINUE:
				break;
			case SERVICE_CONTROL_INTERROGATE:
				break;
			case SERVICE_CONTROL_SHUTDOWN:
				m_bShutDown = TRUE;
				SetServiceStatus(SERVICE_STOP_PENDING);
				PostThreadMessage(m_dwThreadID, WM_QUIT, 0, 0);
				break;
			default:
				break;
			}
		}

		void Start()
		{
			SERVICE_TABLE_ENTRY st[] =
			{
				{ m_szServiceName, _ServiceMain },
				{ NULL, NULL }
			};
			if (!::StartServiceCtrlDispatcher(st))
				Run();
		};

		BOOL IsInstalled()
		{
			BOOL bResult = FALSE;

			SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

			if (hSCM != NULL)
			{
				SC_HANDLE hService = ::OpenService(hSCM, m_szServiceName, SERVICE_QUERY_CONFIG);
				if (hService != NULL)
				{
					bResult = TRUE;
					::CloseServiceHandle(hService);
				}
				::CloseServiceHandle(hSCM);
			}
			return bResult;
		}

		BOOL Install()
		{
			if (IsInstalled())
				return TRUE;

			SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
			if (hSCM == NULL) {
				MessageBox(NULL, _T("Couldn't open service manager"), m_szServiceName, MB_OK);
				return FALSE;
			}

			TCHAR szFilePath[_MAX_PATH];
			::GetModuleFileName(NULL, szFilePath, _MAX_PATH);

			TCHAR szBinfile[_MAX_PATH];
			_tcscpy(szBinfile, szFilePath);
			_tcscat(szBinfile, _T(" -service"));

			SC_HANDLE hService = ::CreateService(
				hSCM, m_szServiceName, m_szServiceDispName,
				GENERIC_ALL, SERVICE_WIN32_OWN_PROCESS,
				SERVICE_AUTO_START,
				SERVICE_ERROR_IGNORE,
				szBinfile, NULL, NULL, NULL, NULL, NULL);

			if (hService == NULL) {
				::CloseServiceHandle(hSCM);
				MessageBox(NULL, _T("Couldn't create service"), m_szServiceName, MB_OK);
				return FALSE;
			}

			{
				SC_ACTION  Actions;
				Actions.Type = SC_ACTION_RESTART;
				Actions.Delay = 60 * 1000; //1 minute

				SERVICE_FAILURE_ACTIONS act;
				memset(&act, 0, sizeof(act));
				act.dwResetPeriod = 0;
				act.lpRebootMsg = nullptr;
				act.lpCommand = nullptr;
				act.cActions = 1;
				act.lpsaActions = &Actions;

				if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &act))
					MessageBox(NULL, _T("Configuration failure recovery failed!\nplease manually configure service failure recovery!\n"), m_szServiceName, MB_OK);
			}

			TCHAR sKey[_MAX_PATH];
			_tcscpy(sKey, _T("SYSTEM\\CurrentControlSet\\Services\\"));
			_tcscat(sKey, m_szServiceName);

			HKEY hkey;
			if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, sKey, 0, KEY_WRITE | KEY_READ, &hkey) == ERROR_SUCCESS) {
				RegSetValueEx(hkey, _T("Description"), NULL, REG_SZ, (LPBYTE)(m_szServiceDes), (lstrlen(m_szServiceDes) + 1) * sizeof(TCHAR));
				RegCloseKey(hkey);
			}

			::CloseServiceHandle(hService);
			::CloseServiceHandle(hSCM);

			MessageBox(NULL, _T("install service success!"), m_szServiceName, MB_OK);
			return TRUE;
		}
		BOOL Uninstall()
		{
			if (!IsInstalled())
				return TRUE;

			SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

			if (hSCM == NULL) {
				MessageBox(NULL, _T("Couldn't open service manager"), m_szServiceName, MB_OK);
				return FALSE;
			}

			SC_HANDLE hService = ::OpenService(hSCM, m_szServiceName, SERVICE_STOP | DELETE);

			if (hService == NULL) {
				::CloseServiceHandle(hSCM);
				MessageBox(NULL, _T("Couldn't open service"), m_szServiceName, MB_OK);
				return FALSE;
			}
			SERVICE_STATUS status;
			::ControlService(hService, SERVICE_CONTROL_STOP, &status);

			BOOL bDelete = ::DeleteService(hService);
			::CloseServiceHandle(hService);
			::CloseServiceHandle(hSCM);

			if (bDelete) {
				MessageBox(NULL, _T("delete service success!"), m_szServiceName, MB_OK);
				return TRUE;
			}

			MessageBox(NULL, _T("Service could not be deleted"), m_szServiceName, MB_OK);
			return FALSE;
		}
		void LogEvent(UINT ueventid, LPCTSTR pszFormat, ...)
		{
			TCHAR    chMsg[256];
			HANDLE  hEventSource;
			LPTSTR  lpszStrings[1];
			va_list pArg;

			va_start(pArg, pszFormat);
			_vstprintf(chMsg, pszFormat, pArg);
			va_end(pArg);

			lpszStrings[0] = chMsg;

			hEventSource = RegisterEventSource(NULL, m_szServiceName);
			if (hEventSource != NULL) {
				ReportEvent(hEventSource, EVENTLOG_INFORMATION_TYPE, 0, ueventid, NULL, 1, 0, (LPCTSTR*)&lpszStrings[0], NULL);
				DeregisterEventSource(hEventSource);
			}

		}
		void SetServiceStatus(DWORD dwState)
		{
			m_status.dwCurrentState = dwState;
			::SetServiceStatus(m_hServiceStatus, &m_status);
		}

		BOOL RegisterServer()
		{
			Uninstall();
			return Install();
		}
		inline BOOL UnregisterServer()
		{
			return Uninstall();
		}

	private:
		static void WINAPI _ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv)
		{
			CNtService::_pobj->ServiceMain(dwArgc, lpszArgv);
		};
		static void WINAPI _Handler(DWORD dwOpcode)
		{
			CNtService::_pobj->Handler(dwOpcode);
		}
	protected:
		virtual void Run()
		{
			m_dwThreadID = GetCurrentThreadId();
			SetServiceStatus(SERVICE_RUNNING);

			MSG msg;
			while (GetMessage(&msg, NULL, 0, 0)) {
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
			m_dwThreadID = 0;
		};
	public:

		virtual void Debug()
		{
			m_dwThreadID = GetCurrentThreadId();
			MSG msg;
			while (GetMessage(&msg, NULL, 0, 0)) {
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
			m_dwThreadID = 0;
		};
	};
}//ec

#endif

#ifdef _DEBUG
#ifdef _WIN32
#define EC_SERVICE_FRAME(SSERVICE,SPID,MSGKEY,SBUILD,SVER) int main(int argc, char* argv[])\
{\
	ec::cUseWS_32 usews32;\
	char sod[1024] = { 0 }, sw[64] = { 0 };\
	memset(sod, 0, sizeof(sod));\
	CRuncls srv;\
	if (!srv.start()){\
		printf("srv.Start failed!\n");\
		return 0;\
	}\
	printf("start success\n");\
	while (1){\
		if (fgets(sod, (int)sizeof(sod) - 1, stdin)){\
			size_t n = strlen(sod), pos = 0;\
			if (!ec::str_getnextstring(' ', sod, n, pos, sw, sizeof(sw)))\
				continue;\
			if (!strcmp(sw, "exit"))\
				break;\
			else\
				printf("error command!\n");\
		}\
	}\
	srv.stop();\
}\

#else
#define EC_SERVICE_FRAME(SSERVICE,SPID,MSGKEY,SBUILD,SVER) int main(int argc, char* argv[])\
{\	
char sod[1024] = { 0 }, sw[64] = { 0 }; \
memset(sod, 0, sizeof(sod)); \
CRuncls srv; \
if (!srv.start()) {
	\
		printf("srv.Start failed!\n"); \
		return 0; \
}\
printf("start success\n"); \
while (1) {
	\
		if (fgets(sod, (int)sizeof(sod) - 1, stdin)) {
			\
				size_t n = strlen(sod), pos = 0; \
				if (!ec::str_getnextstring(' ', sod, n, pos, sw, sizeof(sw)))\
					continue; \
					if (!strcmp(sw, "exit"))\
						break; \
					else\
						printf("error command!\n"); \
		}\
}\
srv.stop(); \
}\

#endif

#else
#ifdef _WIN32
#define EC_SERVICE_FRAME(SSERVICE,SPID,MSGKEY,SBUILD,SVER)  class CAppService : public ec::CNtService\
{\
protected:\
	void Run()\
	{\
		CRuncls* psvr = new CRuncls();\
		if (!psvr)\
			return;\
		if (!psvr->start()){\
			psvr->stop();\
			delete psvr;\
			exit(-1);\
		    return;\
		}\
		ec::CNtService::Run();\
		psvr->stop();\
		delete psvr;\
	};\
}_server;\
\
ec::CNtService* ec::CNtService::_pobj = &_server;\
LPCTSTR FindOneOf(LPCTSTR p1, LPCTSTR p2){\
	while (p1 != NULL && *p1 != NULL){\
		LPCTSTR p = p2;\
		while (p != NULL && *p != NULL){\
			if (*p1 == *p)\
				return CharNext(p1);\
			p = CharNext(p);\
		}\
		p1 = CharNext(p1);\
	}\
	return NULL;\
}\
\
void ShowMsg()\
{\
	TCHAR smsg[1024]={0};\
	_tcscpy(smsg, _T("please install first \n"));\
	_tcscat(smsg, SSERVICE);\
	_tcscat(smsg, _T(" -install\n"));\
	_tcscat(smsg, SBUILD);\
	MessageBox(0, smsg, SSERVICE, MB_OK);\
}\
\
int APIENTRY _tWinMain(HINSTANCE hInstance,\
	HINSTANCE hPrevInstance,\
	LPTSTR     lpCmdLine,\
	int       nCmdShow)\
{\
	ec::cUseWS_32 usews32;\
	_server.Init(SSERVICE, SSERVICE, SBUILD);\
	TCHAR szTokens[] = _T("-/");\
	LPCTSTR lpszToken = FindOneOf(lpCmdLine, szTokens);\
	if (lpszToken == NULL) {\
		ShowMsg();\
		return 0;\
	}\
	else {\
		if (!lstrcmpi(lpszToken, _T("uninstall")))\
			_server.UnregisterServer();\
		else if (!lstrcmpi(lpszToken, _T("install"))) {\
			if (!_server.RegisterServer())\
				MessageBox(NULL, _T("install failed,Please make sure you have admin rights!"), SSERVICE, MB_OK);\
		}\
		else if (!lstrcmpi(lpszToken, _T("service"))) {\
			_server.Start();\
			return 0;\
		}\
		else\
			ShowMsg();\
	}\
	return 0;\
}\

#else

#include "ec/c11_daemon.h"
#define EC_SERVICE_FRAME(SSERVICE,SPID,MSGKEY,SBUILD,SVER)\
ec::daemon<CRuncls>_server;\
template<>\
CRuncls * ec::daemon<CRuncls>::_pcls = nullptr;\
int main(int argc, char** argv)\
{\
	printf("\n");\
	_server.Init(SPID, SSERVICE, SVER, MSGKEY);\
	if (argc == 2){\
		if (!strcasecmp(argv[1], "-start"))\
			_server.start();\
		else if (!strcasecmp(argv[1], "-stop"))\
			_server.stop();\
		else if (!strcasecmp(argv[1], "-status"))\
			_server.status();\
		else if (!strcasecmp(argv[1], "-ver") || !strcasecmp(argv[1], "-version"))\
			printf("%s %s %s\n", SSERVICE, SVER, SBUILD); \
		else\
			_server.usage();\
	}\
	else\
	_server.usage();\
	return 0;\
}\

#endif  //_WIN32

#endif  //_DEBUG