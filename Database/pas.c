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
#include "..\Debug\Debug.h"

extern sqlite3 * db;
extern sqlite3_stmt *stmt;
extern int inStmtSeq;

//extern void vdDebug_LogPrintf(const char * fmt,...);

int inPASRead(int inSeekCnt)
{     
	int result = 0;
	char *sql = "SELECT inEnable, szSTLTime1, szSTLTime2, szSTLTime3, inRetryTime, inOnGoing, szWaitTime, fFirstBootUp, szlastSettleDate FROM PAS WHERE inPASid = ?";

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
			strPAS.fEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq ));
			strcpy((char *)strPAS.szSTLTime1,  (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strcpy((char *)strPAS.szSTLTime2,  (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strcpy((char *)strPAS.szSTLTime3,  (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strPAS.inRetryTime = sqlite3_column_int(stmt,inStmtSeq +=1 );
			strPAS.fOnGoing = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strcpy((char *)strPAS.szWaitTime,  (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
			strPAS.fFirstBootUp = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq+=1));
			
			strcpy((char *)strPAS.szlastSettleDate,(char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		}
	} 
	while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

/*	vdDebug_LogPrintf("inPASRead");
	vdDebug_LogPrintf("strPAS.fEnable %d", strPAS.fEnable);
	vdDebug_LogPrintf("strPAS.szSTLTime1 %s", strPAS.szSTLTime1);
	vdDebug_LogPrintf("strPAS.szSTLTime2 %s", strPAS.szSTLTime2);
	vdDebug_LogPrintf("strPAS.szSTLTime3 %s", strPAS.szSTLTime3);
	vdDebug_LogPrintf("strPAS.inRetryTime %d", strPAS.inRetryTime);
	vdDebug_LogPrintf("strPAS.fOnGoing %d", strPAS.fOnGoing);
	vdDebug_LogPrintf("strPAS.szWaitTime %d", strPAS.szWaitTime);
	vdDebug_LogPrintf("strPAS.fFirstBootUp %d", strPAS.fFirstBootUp);
	vdDebug_LogPrintf("strPAS.szlastSettleDate %s", strPAS.szlastSettleDate);
*/
	return(d_OK);
}

int inPASSave(int inSeekCnt)
{
	int result = 0;
	char *sql = "UPDATE PAS SET inEnable=?,szSTLTime1=?,szSTLTime2=?,szSTLTime3=?,inRetryTime=?,inOnGoing=?,szWaitTime=?, fFirstBootUp=?, szlastSettleDate=? WHERE inPASid=?";



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
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strPAS.fEnable);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPAS.szSTLTime1, strlen((char*)strPAS.szSTLTime1), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPAS.szSTLTime2, strlen((char*)strPAS.szSTLTime2), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPAS.szSTLTime3, strlen((char*)strPAS.szSTLTime3), SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strPAS.inRetryTime);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strPAS.fOnGoing);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPAS.szWaitTime, strlen((char*)strPAS.szWaitTime), SQLITE_STATIC);	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strPAS.fFirstBootUp);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPAS.szlastSettleDate, strlen((char*)strPAS.szlastSettleDate), SQLITE_STATIC);	
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

	CTOS_Delay(300);

/*	vdDebug_LogPrintf("inPASSave");
	vdDebug_LogPrintf("strPAS.fEnable %d", strPAS.fEnable);
	vdDebug_LogPrintf("strPAS.szSTLTime1 %s", strPAS.szSTLTime1);
	vdDebug_LogPrintf("strPAS.szSTLTime2 %s", strPAS.szSTLTime2);
	vdDebug_LogPrintf("strPAS.szSTLTime3 %s", strPAS.szSTLTime3);
	vdDebug_LogPrintf("strPAS.inRetryTime %d", strPAS.inRetryTime);
	vdDebug_LogPrintf("strPAS.fOnGoing %d", strPAS.fOnGoing);
	vdDebug_LogPrintf("strPAS.szWaitTime %d", strPAS.szWaitTime);
	vdDebug_LogPrintf("strPAS.fFirstBootUp %d", strPAS.fFirstBootUp);
	vdDebug_LogPrintf("strPAS.szlastSettleDate %s", strPAS.szlastSettleDate);
*/
	
	return(d_OK);
}

int inPASNumRecord(void)
{
	int len = 0;
	int result = 0;
	char *sql = "SELECT COUNT(*) FROM PAS";
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


