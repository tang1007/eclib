/*
\file tOdbc.h
\brief ODBC class

   TOM library is free C++ library.
\author jiangyong,13212314895@126.com
*/

#ifndef _TODBC_H
#define _TODBC_H


#include <stdlib.h>
#include <string.h>
#include <sql.h>
#include <sqlext.h>
#ifdef _WIN32
#pragma comment(lib, "odbc32.lib")
#endif
#include "c_log.h"
#include "c_trace.h"
#include "c_str.h"
typedef int						DBRET;
#define DBDSNSTR_LEN			1024

#define DBE_OK					0	///< SUCCESS 
#define DBE_ERR					(-1)	///< error
#define DBE_HWK					(-2)	///< CreateWorkspace error
#define DBE_HDB					(-3)	///< db handle error
#define DBE_CON					(-4)	///< db connect error
#define DBE_EVNATTR				(-5)	///< SQLSetEnvAttr错误
#define DBE_CONATTR_TIMEOUT		(-6)	///< 
#define DBE_CONATTR_AUTOCOMMIT	(-7)	///< 

#define DBE_HSTMT				(-8)	
#define DBE_HSTMTATTR			(-9)	///< SQLSetStmtAttr error
#define DBE_EXEC				(-10)	///< SQLExecDirect error
#define DBE_COLNUM				(-11) 
#define DBE_NODATA				(-12)

#pragma warning (disable : 4312)

namespace ec
{
	class CODBC_WKS  // workspace
	{
	public:
		CODBC_WKS()
		{
			_hwk = NULL;
		}
		virtual ~CODBC_WKS()
		{
			if(_hwk){
				SQLFreeHandle(SQL_HANDLE_ENV,_hwk);
				_hwk = NULL;
			}
		}
	protected:
		SQLHANDLE	_hwk; // workspace handle
	public:
		DBRET  CreateWorkspace()
		{
			SQLRETURN ret = DBE_OK;
			if(!_hwk)
			{
				ret = SQLAllocHandle(SQL_HANDLE_ENV,NULL,&_hwk);
				if(ret != SQL_SUCCESS)
					return DBE_HWK;

				ret = SQLSetEnvAttr(_hwk, SQL_ATTR_ODBC_VERSION,(SQLPOINTER) SQL_OV_ODBC3, SQL_IS_INTEGER);
				if(ret == SQL_SUCCESS)
					return DBE_OK;
				
				Close();
				return DBE_EVNATTR;								
			}
			return ret;
		}
		int Close()
		{
			if(_hwk){
				SQLFreeHandle(SQL_HANDLE_ENV,_hwk);
				_hwk = NULL;
			}
			return DBE_OK;
		}
	public:
		inline SQLHANDLE GetHandle(){ return _hwk;}
		
		// errocode from
		// 08S01 Communication link failure
		// https://msdn.microsoft.com/en-us/library/ms714687(v=vs.85).aspx
		static int LogDbErr(ec::cLog* plog,const char* smsg,SQLSMALLINT     HandleType,  SQLHANDLE       Handle)
		{
			SQLSMALLINT i=1;
			SQLRETURN	rc2;
			SQLCHAR		SQLState[32];
			SQLINTEGER  NativeError;
			SQLCHAR     MessageText[512];
				
			SQLSMALLINT TextLength = 0;
			SQLState[0] = 0;
			MessageText[0] = 0;
			int ndberr = DBE_OK;
			while(SQL_NO_DATA != (rc2 = ::SQLGetDiagRec(HandleType,Handle,i,SQLState,&NativeError,MessageText,sizeof(MessageText),&TextLength)))
			{
				if(rc2 != SQL_SUCCESS && rc2 != SQL_SUCCESS_WITH_INFO)
					break;
				SQLState[5] = 0;
				MessageText[511] = 0;
				if(plog)
					plog->AddLog("ERR:%s(%d:%d)SQLState = %s,Msg = %s",smsg,HandleType,i,SQLState,MessageText);
				i++;
				if(!strcmp("08S01",(const char*)SQLState))
					ndberr = DBE_CON;
				else
				{
					if(!ndberr)
						ndberr = DBE_ERR;
				}
			}
			return ndberr;
		};
	};


	class CODBC_DB // DB
	{
	public:
		CODBC_DB(CODBC_WKS* pwks)
		{
			_hdb = NULL;
			_pwks = pwks;
			memset(_sdsn,0,sizeof(DBDSNSTR_LEN));
		}
		virtual ~CODBC_DB()
		{
			Close();
		}
	protected:
		SQLHANDLE	_hdb;
		CODBC_WKS*	_pwks;
		char		_sdsn[DBDSNSTR_LEN];
	public:
		static bool IsConnectErr(const char* sqlst){
			return !strcmp("08S01",sqlst);
		}
		inline bool	IsConnected() {return _hdb != NULL;}
		inline SQLHANDLE	GetHandle(){return _hdb;}
		DBRET Connect(const char* sdsn,int ntimeoutsec = 8,bool bAutoCommit = true) //use DSN connect
		{
			SQLRETURN ret;			
			if(!_pwks->GetHandle())
				return DBE_HWK;
			Close();
			ret = ::SQLAllocHandle(SQL_HANDLE_DBC,_pwks->GetHandle(),&_hdb);
			if(ret != SQL_SUCCESS)
				return DBE_HDB;
			
			ec::str_ncpy(_sdsn,sdsn,DBDSNSTR_LEN);
			ret = ::SQLSetConnectAttr(_hdb,SQL_ATTR_CONNECTION_TIMEOUT,(SQLPOINTER)ntimeoutsec,SQL_IS_INTEGER); 
			if(ret != SQL_SUCCESS)
				return DBE_CONATTR_TIMEOUT;

			if(bAutoCommit){
				ret = ::SQLSetConnectAttr(_hdb,SQL_ATTR_AUTOCOMMIT,(SQLPOINTER)true,SQL_IS_INTEGER); 
				if(ret != SQL_SUCCESS)
				return DBE_CONATTR_AUTOCOMMIT;
			}

			ret = ::SQLConnect(_hdb,(SQLCHAR*)_sdsn,SQL_NTS,NULL,0,NULL,0);			
			if(ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO)
				return DBE_CON;			
			return DBE_OK;
			
		}
		DBRET Connect(const char* sdsn,const char* user,const char* pass,int ntimeoutsec = 8,bool bAutoCommit = true) //use DSN connect
		{
			SQLRETURN ret;			
			if(!_pwks->GetHandle())
				return DBE_HWK;
			Close();

			ret = ::SQLAllocHandle(SQL_HANDLE_DBC,_pwks->GetHandle(),&_hdb);
			if(ret != SQL_SUCCESS)
				return DBE_HDB;
			
			ec::str_ncpy(_sdsn,sdsn,DBDSNSTR_LEN);
			ret = ::SQLSetConnectAttr(_hdb,SQL_ATTR_CONNECTION_TIMEOUT,(SQLPOINTER)ntimeoutsec,SQL_IS_INTEGER); 
			if(ret != SQL_SUCCESS)
				return DBE_CONATTR_TIMEOUT;

			if(bAutoCommit){
				ret = ::SQLSetConnectAttr(_hdb,SQL_ATTR_AUTOCOMMIT,(SQLPOINTER)true,SQL_IS_INTEGER); 
				if(ret != SQL_SUCCESS)
				return DBE_CONATTR_AUTOCOMMIT;
			}
			ret = ::SQLConnect(_hdb,(SQLCHAR*)_sdsn,SQL_NTS,(SQLCHAR*)user,SQL_NTS,(SQLCHAR*)pass,SQL_NTS);						
			if(ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO)
				return DBE_CON;

			return DBE_OK;
			
		}
		DBRET ConnectEx(const char* sConnectStr,int ntimeoutsec = 8,bool bAutoCommit = true) //use connect string connect
		{
			SQLRETURN ret;

			if(!_pwks->GetHandle())
				return DBE_HWK;
			Close();
			ret = ::SQLAllocHandle(SQL_HANDLE_DBC,_pwks->GetHandle(),&_hdb);
			if(ret != SQL_SUCCESS)
				return DBE_HDB;

			ec::str_ncpy(_sdsn,sConnectStr,DBDSNSTR_LEN);
			ret = ::SQLSetConnectAttr(_hdb,SQL_ATTR_CONNECTION_TIMEOUT,(SQLPOINTER)ntimeoutsec,SQL_IS_INTEGER); 
			if(ret != SQL_SUCCESS)
				return DBE_CONATTR_TIMEOUT;

			if(bAutoCommit){
				ret = ::SQLSetConnectAttr(_hdb,SQL_ATTR_AUTOCOMMIT,(SQLPOINTER)true,SQL_IS_INTEGER); 
				if(ret != SQL_SUCCESS)
				return DBE_CONATTR_AUTOCOMMIT;
			}
			SQLCHAR sOut[1024];
			SQLSMALLINT nsLen = 0;
			ret = ::SQLDriverConnect(_hdb,NULL,(SQLCHAR*)sConnectStr,SQL_NTS,sOut,sizeof(sOut),&nsLen,SQL_DRIVER_NOPROMPT);
			if(ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO)
				return DBE_CON;

			return DBE_OK;
		}

		void DisConnect()
		{
			if(_hdb){
				::SQLDisconnect(_hdb);
				::SQLFreeHandle(SQL_HANDLE_DBC,_hdb);
				_hdb = NULL;
			}
		}
		DBRET Close()
		{
			if(_hdb){
				::SQLDisconnect(_hdb);
				::SQLFreeHandle(SQL_HANDLE_DBC,_hdb);
				_hdb = NULL;
			}
			return DBE_OK;
		}
	};

	#define ODBCFDNAMELEN  128
	#define ODBCFD_MAXCOLS 64
	struct ODBC_FDINFO
	{
		SQLUSMALLINT ColNum;				
		SQLCHAR      ColName[ODBCFDNAMELEN];
		SQLSMALLINT  NameLength;
		SQLSMALLINT  DataType;
        SQLULEN      ColumnSize;
        SQLSMALLINT  DecimalDigits;
        SQLSMALLINT  Nullable;				//  SQL_NO_NULLS; SQL_NULLABLE ; SQL_NULLABLE_UNKNOWN
	};
#define SQL_ROW_ARRAY_SIZE 256
	class CODBC_RD // recordset
	{
	public:
		CODBC_RD(CODBC_DB* pdb)
		{
			_pdb = pdb;
			_hrd = NULL;
			_ucols = 0;
		}
		virtual ~CODBC_RD()
		{
			Close();
		}
	protected:
		SQLHSTMT	_hrd;
		CODBC_DB*	_pdb;
	
		unsigned int	_ucols;
		ODBC_FDINFO _fds[ODBCFD_MAXCOLS];
	public:
		DBRET Open(bool bScrollable = true, int nCursorType = SQL_CURSOR_STATIC)
		{
			if(!_pdb->GetHandle())
				return DBE_HDB;			
			Close(); 
			SQLRETURN ret;
			ret = ::SQLAllocHandle(SQL_HANDLE_STMT,_pdb->GetHandle(),&_hrd);
			if(ret != SQL_SUCCESS)
				return DBE_HSTMT;

			if(bScrollable)
				ret = ::SQLSetStmtAttr(_hrd,SQL_ATTR_CURSOR_SCROLLABLE ,(SQLPOINTER)SQL_SCROLLABLE ,SQL_IS_INTEGER);
			else
				ret = ::SQLSetStmtAttr(_hrd,SQL_ATTR_CURSOR_SCROLLABLE ,(SQLPOINTER)SQL_NONSCROLLABLE ,SQL_IS_INTEGER);
			
			if(ret != SQL_SUCCESS)
				return DBE_HSTMTATTR;
			
			ret = ::SQLSetStmtAttr(_hrd,SQL_ATTR_CURSOR_TYPE  ,(SQLPOINTER)nCursorType ,SQL_IS_INTEGER);
			if(ret != SQL_SUCCESS)
				return DBE_HSTMTATTR;
			return DBE_OK;
		}

		DBRET ExecSql(const char* sSql)
		{
			if(!_hrd)
				return DBE_HSTMT;
			SQLRETURN ret;
			ret = ::SQLExecDirect(_hrd,(SQLCHAR*)sSql,SQL_NTS);
			if(ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO)
				return DBE_EXEC;		
			return DBE_OK;
		}

		DBRET	Close()
		{
			if(_hrd)
			{
				::SQLFreeHandle(SQL_HANDLE_STMT,_hrd);
				_hrd = NULL;
			}
			return DBE_OK;
		}
		bool GetFieldInfo()
		{
			SQLRETURN	ret;
			SQLSMALLINT snNum = 0,i;
			if(!_hrd)
				return false;
			ret = ::SQLNumResultCols(_hrd,&snNum);
			if(ret != SQL_SUCCESS)
				return false;
			for(i = 0;i < snNum && i< ODBCFD_MAXCOLS;i++)
			{
				memset(&_fds[i],0,sizeof(ODBC_FDINFO));
				ret = ::SQLDescribeCol(_hrd,i+1,(SQLCHAR*)_fds[i].ColName,ODBCFDNAMELEN,&_fds[i].NameLength,&_fds[i].DataType,&_fds[i].ColumnSize,&_fds[i].DecimalDigits,&_fds[i].Nullable);
				if(ret != SQL_SUCCESS)
					return false;
				_fds[i].ColNum = i+1;
			}
			_ucols = i;
			return true;
		}
		inline unsigned int GetColNum(){return _ucols;}
		bool   GetColInfo(unsigned int uIndex,ODBC_FDINFO* p)
		{
			if(uIndex < _ucols){
				memcpy(p,&_fds[uIndex],sizeof(ODBC_FDINFO));
				return true;
			}
			return false;
		}

		//执行查询SQL语句,和sqlite3_exec 类似
		int Exec_SelSql(const char* sql, int(*OnRead)(void* pobj, int nargc, char** data, char** columns), void* pParam, ec::cLog* plog = 0)
		{
			DBRET dbr = Open();
			if (dbr != DBE_OK)
				return dbr;
			SQLRETURN		rc;
			ec::tArray<size_t> fs(32);
			rc = SQLExecDirect(_hrd, (SQLCHAR*)sql, SQL_NTS);
			if (SQL_SUCCESS != rc)
			{
				if (DBE_CON == ec::CODBC_WKS::LogDbErr(plog, "ERR: SQLExecDirect  @ Exec_SelSql", SQL_HANDLE_STMT, _hrd))
					return DBE_CON;
				return DBE_EXEC;
			}
			if (!GetFieldInfo())
				return -1;
			for (unsigned int i = 0; i < _ucols; i++)
				fs.Add(_fds[i].ColumnSize + 4 - _fds[i].ColumnSize % 4);
			size_t sizerd = 0;
			for (int i = 0; i < fs.GetNum(); i++)
				sizerd += fs[i] + sizeof(SQLINTEGER);

			ec::cAp bufs(sizerd * SQL_ROW_ARRAY_SIZE);

			SQLINTEGER		NumRowsFetched;
			SQLUSMALLINT	RowStatusArray[SQL_ROW_ARRAY_SIZE];

			SQLSetStmtAttr(_hrd, SQL_ATTR_ROW_BIND_TYPE, (SQLPOINTER)sizerd, SQL_IS_UINTEGER);
			SQLSetStmtAttr(_hrd, SQL_ATTR_ROW_ARRAY_SIZE, (SQLPOINTER)SQL_ROW_ARRAY_SIZE, SQL_IS_UINTEGER);
			SQLSetStmtAttr(_hrd, SQL_ATTR_ROW_STATUS_PTR, RowStatusArray, 0);
			SQLSetStmtAttr(_hrd, SQL_ATTR_ROWS_FETCHED_PTR, &NumRowsFetched, 0);

			char *pb = (char *)bufs.getbuf();
			for (int i = 0; i < fs.GetNum(); i++)
			{
				SQLBindCol(_hrd, i + 1, SQL_C_CHAR, pb, fs[i], (SQLINTEGER*)(pb + fs[i]));
				pb += fs[i] + sizeof(SQLINTEGER);
			}
			SQLINTEGER len;
			ec::tArray<char*> keys(32);
			ec::tArray<char*> datas(32);
			while ((rc = SQLFetchScroll(_hrd, SQL_FETCH_NEXT, 0)) != SQL_NO_DATA)
			{
				if (rc != SQL_SUCCESS && rc != SQL_SUCCESS_WITH_INFO)//SQL_SUCCESS_WITH_INFO一般是字符串右截断或类型转换丢失精度
				{
					if (DBE_CON == ec::CODBC_WKS::LogDbErr(plog, "ERR: SQLFetchScroll @ Exec_SelSql ", SQL_HANDLE_STMT, _hrd))
						return DBE_CON;
					return DBE_EXEC;
				}

				for (SQLINTEGER i = 0; i < NumRowsFetched; i++)
				{
					if (RowStatusArray[i] == SQL_ROW_SUCCESS || RowStatusArray[i] == SQL_ROW_SUCCESS_WITH_INFO)
					{
						keys.ClearData();
						datas.ClearData();

						pb = (char *)bufs.getbuf();
						pb += i * sizerd;
						for (int j = 0; j < fs.GetNum(); j++)
						{
							len = *((SQLINTEGER*)(pb + fs[j]));
							if (len < 0)
								*pb = '\0';
							else
							{
								if (len >(int)fs[j])
									len = (int)fs[j];
								ec::str_trimright(pb, len);
							}
							keys.Add((char*)_fds[j].ColName);
							datas.Add(pb);
							pb += fs[j] + sizeof(SQLINTEGER);
						}
						if (keys.GetNum() > 0)
							OnRead(pParam, keys.GetNum(), datas.GetBuf(), keys.GetBuf());
					}
				}
			}
			return DBE_OK;
		}
	};	
}; // namespace TOM

/*
#include "ec/c_system.h"
#include "ec/c_odbc.h"

int OnReadRow(void* pParam, int argc, char** datas, char** columns)
{
	int i;
	for (i = 0; i<argc; i++)
		printf("%s:%s; ", columns[i], datas[i]);
	printf("\n");
	return 0;
}

int main(int argc, char*argv[])
{
	ec::CODBC_WKS wks;
	if (DBE_OK != wks.CreateWorkspace())
	{
		printf("create ODBC Workspace failed!\n");
		return -1;
	}
	ec::CODBC_DB db(&wks);
	if (DBE_OK != db.Connect("dsn", "name", "passwd"))
	{
		printf("connect failed!\n");
		return -1;
	}
	ec::CODBC_RD rd(&db);
	if (DBE_OK != rd.Exec_SelSql("select mkcode,sccode,sctype,name,autoid from T_SC", OnReadRow, 0))
		printf("Failed\n");
	return 0;
}
*/
#pragma warning (default : 4312)
#endif // _TODBC_H

