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

int inGPTRead(int inSeekCnt)
{
	int result;
	char *sql = "SELECT GPTid, szGPTAPN, szGPTUserName, szGPTPassword, szGPTPriTxnHostIP, szGPTSecTxnHostIP, szGPTPriSettlementHostIP, szGPTSecSettlementHostIP, inGPTPriTxnHostPortNum, inGPTSecTxnHostPortNum, inGPTPriSettlementHostPort, inGPTSecSettlementHostPort FROM GPT WHERE GPTid = ?";



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

	sqlite3_bind_int(stmt, 1, inSeekCnt);




	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */

			strGPT.GPTid= sqlite3_column_int(stmt,inStmtSeq +=1);
			inStmtSeq = 0;
			/*szAPN*/
			strcpy((char*)strGPT.szGPTAPN, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szGPTUserName*/
			strcpy((char*)strGPT.szGPTUserName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szGPTPassword*/
			strcpy((char*)strGPT.szGPTPassword, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szGPTPriTxnHostIP*/
			strcpy((char*)strGPT.szGPTPriTxnHostIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szGPTSecTxnHostIP*/
			strcpy((char*)strGPT.szGPTSecTxnHostIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szGPTPriSettlementHostIP*/
			strcpy((char*)strGPT.szGPTPriSettlementHostIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szGPTSecSettlementHostIP*/
			strcpy((char*)strGPT.szGPTSecSettlementHostIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* inGPTPriTxnHostPortNum*/
			strGPT.inGPTPriTxnHostPortNum = sqlite3_column_int(stmt, inStmtSeq +=1 );

			/* inGPTSecTxnHostPortNum*/
			strGPT.inGPTSecTxnHostPortNum = sqlite3_column_int(stmt, inStmtSeq +=1 );

			/* inGPTPriSettlementHostPort*/
			strGPT.inGPTPriSettlementHostPort = sqlite3_column_int(stmt, inStmtSeq +=1 );

			/* inGPTSecSettlementHostPort*/
			strGPT.inGPTSecSettlementHostPort = sqlite3_column_int(stmt, inStmtSeq +=1 );


		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return(d_OK);
}

int inGPTSave(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE GPT SET szGPTAPN=?, szGPTUserName=?, szGPTPassword=?, szGPTPriTxnHostIP=?, szGPTSecTxnHostIP=?, szGPTPriSettlementHostIP=?, szGPTSecSettlementHostIP=?, inGPTPriTxnHostPortNum=?, inGPTSecTxnHostPortNum=?, inGPTPriSettlementHostPort=?, inGPTSecSettlementHostPort=? WHERE GPTid = ?";

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

	/* szGPTAPN*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strGPT.szGPTAPN, strlen((char*)strGPT.szGPTAPN), SQLITE_STATIC);

	/* szGPTUserName*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strGPT.szGPTUserName, strlen((char*)strGPT.szGPTUserName), SQLITE_STATIC);

	/* szGPTPassword*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strGPT.szGPTPassword, strlen((char*)strGPT.szGPTPassword), SQLITE_STATIC);

	/* szPriTxnHostIP*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strGPT.szGPTPriTxnHostIP, strlen((char*)strGPT.szGPTPriTxnHostIP), SQLITE_STATIC);

	/* szSecTxnHostIP*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strGPT.szGPTSecTxnHostIP, strlen((char*)strGPT.szGPTSecTxnHostIP), SQLITE_STATIC);

	/*szPriSettlementHostIP*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strGPT.szGPTPriSettlementHostIP, strlen((char*)strGPT.szGPTPriSettlementHostIP), SQLITE_STATIC);

	/*szSecSettlementHostIP*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strGPT.szGPTSecSettlementHostIP, strlen((char*)strGPT.szGPTSecSettlementHostIP), SQLITE_STATIC);

	/* inPriTxnHostPortNum*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strGPT.inGPTPriTxnHostPortNum);

	/* inSecTxnHostPortNum*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strGPT.inGPTSecTxnHostPortNum);

	/* inPriSettlementHostPort*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strGPT.inGPTPriSettlementHostPort);

	/* inSecSettlementHostPort*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strGPT.inGPTSecSettlementHostPort);

	result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);

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

int inGPTNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM GPT";
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
