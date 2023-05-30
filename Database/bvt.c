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

extern void vdDebug_LogPrintf(const char * fmt,...);

int inBVTRead(int inSeekCnt)
{     
	int result;
	char *sql = "SELECT BVTid, szBINVerTPDU, szBINVerNII, szBINVerTID, szBINVerMID, szBINVerPriNum, szBINVerSecNum, szBINVerSTAN FROM BVT WHERE BVTid = ?";

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

	result = sqlite3_step(stmt);
	if (result == SQLITE_ROW) /* can read data */
	{
		strBVT.BVTid= sqlite3_column_int(stmt,inStmtSeq +=1);	
		inStmtSeq = 0;
		memcpy(strBVT.szBINVerTPDU, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);
		memcpy(strBVT.szBINVerNII, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);
		strcpy((char*)strBVT.szBINVerTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		strcpy((char*)strBVT.szBINVerMID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*BDO: Separate dialing number for BIN Ver - start -- jzg */
		strcpy((char*)strBVT.szBINVerPriNum, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		strcpy((char*)strBVT.szBINVerSecNum, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		/*BDO: Separate dialing number for BIN Ver - end -- jzg */	
		
		memcpy(strBVT.szBINVerSTAN, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);
	}

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	
	return(d_OK);
}

int inBVTSave(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE BVT SET szBINVerTPDU=?, szBINVerNII=?, szBINVerTID=?, szBINVerMID=?, szBINVerPriNum=?, szBINVerSecNum=?, szBINVerSTAN=? WHERE BVTid = ?";

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

	inStmtSeq = 0;

	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strBVT.szBINVerTPDU, 5, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strBVT.szBINVerNII, 2, SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strBVT.szBINVerTID, strlen((char*)strBVT.szBINVerTID), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strBVT.szBINVerMID, strlen((char*)strBVT.szBINVerMID), SQLITE_STATIC);

	/*BDO: Separate dialing number for BIN Ver - start -- jzg */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strBVT.szBINVerPriNum, strlen((char*)strBVT.szBINVerPriNum), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strBVT.szBINVerSecNum, strlen((char*)strBVT.szBINVerSecNum), SQLITE_STATIC);
	/*BDO: Separate dialing number for BIN Ver - end -- jzg */

	
	//vdDebug_LogPrintf("**GET BINVER STAN	%x %x %x**", strBVT.szBINVerSTAN[0],strBVT.szBINVerSTAN[1],strBVT.szBINVerSTAN[2]);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strBVT.szBINVerSTAN, 3, SQLITE_STATIC);


	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
    

	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE )
	{
		sqlite3_close(db);
		return 3;
	}  

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(d_OK);
}

int inBVTNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM BVT";
	int inCount = 0;
	
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;

			/* count */
			inCount = sqlite3_column_int(stmt,inStmtSeq);
		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return(inCount);
}
