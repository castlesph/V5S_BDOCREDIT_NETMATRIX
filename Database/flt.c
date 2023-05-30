#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctosapi.h>
#include <sqlite3.h>

#include "../Database/DatabaseFunc.h"
#include "../Includes/POSTypedef.h"
#include "../FileModule/myFileFunc.h"

extern sqlite3 * db;
extern sqlite3_stmt *stmt;
extern int inStmtSeq;

extern void vdDebug_LogPrintf(const char * fmt,...);

int inFLTRead(int inSeekCnt)
{     
	int result = 0;
	char *sql = "SELECT szDescriptorCode, szDescription FROM FLT WHERE FLTid = ?";

	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 1;
	}
	
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 2;
	}

	sqlite3_bind_int(stmt, 1, inSeekCnt);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do 
	{
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) /* can read data */
		{ 
			inStmtSeq = 0;
			strcpy((char *)strFLT.szDescriptorCode, (char *)sqlite3_column_text(stmt, inStmtSeq ));
			strcpy((char *)strFLT.szDescription, (char *)sqlite3_column_text(stmt, inStmtSeq +=1 ));
		}
	} 
	while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	
	return(d_OK);
}


int inFLTSave(int inSeekCnt)
{
	int result = 0;
	char *sql = "UPDATE FLT SET szDescriptorCode = ?, szDescription = ? WHERE FLTid=?";

 	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 1;
	}
	
	/* prepare the sql, leave stmt ready for loop */
	sqlite3_exec( db, "begin", 0, 0, NULL );
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 2;
	}
	
	inStmtSeq = 0;
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strFLT.szDescriptorCode, strlen((char*)strFLT.szDescriptorCode), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strFLT.szDescription, strlen((char*)strFLT.szDescription), SQLITE_STATIC);
	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE )
	{
		sqlite3_close(db);
		return 3;
	}  
	
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	CTOS_Delay(300);
	
	return(d_OK);
}


int inFLTNumRecord(void)
{
	int len = 0;
	int result = 0;
	char *sql = "SELECT COUNT(*) FROM FLT";
	int inCount = 0;
	
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 1;
	}
	
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 2;
	}

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do 
	{
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) /* can read data */
		{ 
			inStmtSeq = 0;

			/* count */
			inCount = sqlite3_column_int(stmt,inStmtSeq);
		}
	} 
	while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	
	return(inCount);
}


