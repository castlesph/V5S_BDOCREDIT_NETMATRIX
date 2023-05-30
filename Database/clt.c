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

int inCLTRead(int inHDTid)
{     
	int result;
	char *sql = "SELECT CLTid, HDTid, fCashLoyaltyEnable, szCashLoyaltyTPDU, szCashLoyaltyNII, szCashLoyaltyTID, szCashLoyaltyMID FROM CLT WHERE HDTid = ? AND fCashLoyaltyEnable = ?";



	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	//sqlite3_bind_int(stmt, 1, inSeekCnt);




	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inHDTid);
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);
	

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			result = d_OK;

			strCLT.CLTid= sqlite3_column_int(stmt,inStmtSeq +=1);	

			inStmtSeq = 0;
			//strCLT.CLTid= sqlite3_column_int(stmt,inStmtSeq +=1);	

			strCLT.HDTid= sqlite3_column_int(stmt,inStmtSeq +=1);	
			strCLT.fCashLoyaltyEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));


			memcpy(strCLT.szCashLoyaltyTPDU, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);
			memcpy(strCLT.szCashLoyaltyNII, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);
			strcpy((char*)strCLT.szCashLoyaltyTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strcpy((char*)strCLT.szCashLoyaltyMID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));


		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);



	return(result);
}

int inCLTSave(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE CLT SET szCashLoyaltyTPDU=?, szCashLoyaltyNII=?, szCashLoyaltyTID=?, szCashLoyaltyMID=? WHERE CLTid = ?";

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
	inStmtSeq = 0;
        
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strCLT.szCashLoyaltyTPDU, 5, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strCLT.szCashLoyaltyNII, 2, SQLITE_STATIC);

	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCLT.szCashLoyaltyTID, strlen((char*)strCLT.szCashLoyaltyTID), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCLT.szCashLoyaltyMID, strlen((char*)strCLT.szCashLoyaltyMID), SQLITE_STATIC);


	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}  
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return(d_OK);
}

int inCLTNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM CLT";
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
