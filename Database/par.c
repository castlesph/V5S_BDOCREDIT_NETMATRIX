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

//extern void vdDebug_LogPrintf(const char * fmt,...);

int inPARRead(int inSeekCnt)
{     
	int result;

	//POS auto report: added last logon date -- jzg
	char *sql = "SELECT PARID, PARTPDU,PARNII,PARTID,PARMID,PARTelNum1,PARTelNum1,PAREnable,PARVersion,PARSerialNumber,PARLastLogonDate FROM PAR WHERE PARid = ?";



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

			strPAR.inPARid= sqlite3_column_int(stmt,inStmtSeq +=1);	
			inStmtSeq = 0;
			memcpy(strPAR.szPARTPDU, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);
			//vdDebug_LogPrintf("gladytest szPARTPDU - %s", strPAR.szPARTPDU);

			memcpy(strPAR.szPARNII, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);
			strcpy((char*)strPAR.szPARTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strcpy((char*)strPAR.szPARMID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strcpy((char*)strPAR.szPARTelNum1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strcpy((char*)strPAR.szPARTelNum2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strPAR.fPAREnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strcpy((char*)strPAR.szPARVersion, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strcpy((char*)strPAR.szPARSerialNumber, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strcpy((char*)strPAR.szPARLastLogonDate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));  //POS auto report: added last logon date -- jzg
		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return(d_OK);
}

int inPARSave(int inSeekCnt)
{
	int result;

	//POS auto report: added last logon date -- jzg
	char *sql = "UPDATE PAR SET PARTPDU=?, PARNII=?, PARTID=?, PARMID=?, PARTelNum1=?, PARTelNum2=?, PAREnable=?, PARVersion=?, PARSerialNumber=?, PARLastLogonDate=? WHERE PARID=?";

 	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	
	/* prepare the sql, leave stmt ready for loop */
	sqlite3_exec( db, "begin", 0, 0, NULL );
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}
	inStmtSeq = 0;

	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strPAR.szPARTPDU, 5, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strPAR.szPARNII, 2, SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPAR.szPARTID, strlen((char*)strPAR.szPARTID), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPAR.szPARMID, strlen((char*)strPAR.szPARMID), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPAR.szPARTelNum1, strlen((char*)strPAR.szPARTelNum1), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPAR.szPARTelNum2, strlen((char*)strPAR.szPARTelNum2), SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strPAR.fPAREnable);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPAR.szPARVersion, strlen((char*)strPAR.szPARVersion), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPAR.szPARSerialNumber, strlen((char*)strPAR.szPARSerialNumber), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPAR.szPARLastLogonDate, strlen((char*)strPAR.szPARLastLogonDate), SQLITE_STATIC); //POS auto report: added last logon date -- jzg

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

int inPARNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM PAR";
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


