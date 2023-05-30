/** 
**    A Template for developing new terminal shared application
**/

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

#include<eft.h>

// start for cup REF ID mfl
int inEFTNumRecord(void)
{
	int len = 0;
	int result = 0;
	char *sql = "SELECT COUNT(*) FROM EFT";
	int inCount = 0;

	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 1;
	}
	sqlite3_exec( db, "begin", 0, 0, NULL );
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 2;
	}

	do 
	{
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) 
		{
			inStmtSeq = 0;
			inCount = sqlite3_column_int(stmt,inStmtSeq);
		}
	} 
	while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inCount);
}

int inEFTRead(int inSeekCnt)
{
	int result = 0;
	int inResult = d_NO;
	char *sql = "SELECT HDTid, fEFTSec, usKeySet, usKeyIndex, szSecureNII FROM EFT WHERE HDTid = ?";

    memset(&strEFT, 0, sizeof(strEFT));
	
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK)
	{
		sqlite3_close(db);
		return 1;
	}

	sqlite3_exec( db, "begin", 0, 0, NULL );
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 2;
	}

	sqlite3_bind_int(stmt, 1, inSeekCnt);

	do 
	{
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) 
		{ 
			inResult = d_OK;
			inStmtSeq = 0;
			/* HDTid */
			strEFT.HDTid = sqlite3_column_int(stmt, inStmtSeq);   

            strEFT.fEFTSec = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 )); 

            memcpy((BYTE *)&strEFT.usKeySet, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);
            
            memcpy((BYTE *)&strEFT.usKeyIndex, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);

			memcpy(strEFT.szSecureNII, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);
		}
	}
	while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inResult);
}


int inEFTSave(int inSeekCnt)
{
	int result = 0;
	char *sql = "UPDATE EFT SET fEFTSec = ?, usKeySet = ?, usKeyIndex = ?, szSecureNII = ? WHERE HDTid = ?";

	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 1;
	}
	
	sqlite3_exec( db, "begin", 0, 0, NULL );
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEFT.fEFTSec);

	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, (BYTE *)&strEFT.usKeySet, 2, SQLITE_STATIC);

	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, (BYTE *)&strEFT.usKeyIndex, 2, SQLITE_STATIC);	

	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strEFT.szSecureNII, 2, SQLITE_STATIC);
	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
	result = sqlite3_step(stmt);
	
	if( result != SQLITE_DONE )
	{
		sqlite3_close(db);
		return 1;
	}

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(d_OK);
}

// end
