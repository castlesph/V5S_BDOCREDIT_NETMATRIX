/** 
**    A Template for developing new terminal shared application
**/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctosapi.h>
#include <sqlite3.h>

#include "../Includes/myEZLib.h"
#include "../Includes/wub_lib.h"
#include "../Includes/POSTypedef.h"

#include "../Includes/Trans.h"

#include "DatabaseFunc.h"
#include "../FileModule/myFileFunc.h"
#include "../Debug/Debug.h"
#include "../Database/DatabaseFunc.h"
#include "../Includes/POSSetting.h"

extern sqlite3 * db;
extern sqlite3_stmt *stmt;
extern int inStmtSeq;

int inDatabase_TransLogSave(TRANS_DATA_TABLE *transData)
{
	int result;	
 	char *sql = "INSERT INTO TransLog (TransDataid, HDTid, MITid, szInvoiceNo, ulBatchIndex, byTransType, byPackType) VALUES (NULL, ?, ?, ?, ?, ?, ?)";

	transData->byPackType=DCC_LOGGING;

	/* open the database */
	result = sqlite3_open(DB_BATCH,&db);
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

	inStmtSeq = 0;
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->HDTid);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->MITid);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szInvoiceNo, 4, SQLITE_STATIC);
    result = sqlite3_bind_double(stmt, inStmtSeq +=1, transData->ulSavedIndex);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byTransType);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byPackType);
	
	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

    //vdDebug_LogPrintf("inDatabase_TransLogSave");
	//vdDebug_LogPrintf("transData->HDTid: %d", transData->HDTid);
	//vdDebug_LogPrintf("transData->MITid: %d", transData->MITid);
	//DebugAddHEX("transData->szInvoiceNo", transData->szInvoiceNo, 3);
	//vdDebug_LogPrintf("transData->ulSavedIndex: %d", transData->ulSavedIndex);
	//vdDebug_LogPrintf("transData->byTransType: %d", transData->byTransType);
	//vdDebug_LogPrintf("transData->byPackType: %d", transData->byPackType);
	//vdDebug_LogPrintf("**********************************************************");

	return(ST_SUCCESS);
}

int inDatabase_TransLogNumRecord(int inMode)
{
	int len;
	int result;
	char *sql; // = "SELECT COUNT (*) FROM TransLog WHERE HDTid = ? AND MITid = ? AND byTransType != ?";
	int inCount = 0;
    char szTempSQL[512+1];

    memset(szTempSQL, 0, sizeof(szTempSQL));
	sql=&szTempSQL;
	
    if(inMode == GET_ALL_EXCEPT_TIP)
        strcpy(szTempSQL, "SELECT COUNT (*) FROM TransLog WHERE HDTid = ? AND MITid = ? AND byTransType != 109");
    else if(inMode == GET_TIP_ONLY)        
        strcpy(szTempSQL, "SELECT COUNT (*) FROM TransLog WHERE HDTid = ? AND MITid = ? AND byTransType == 109");
    else if(inMode == GET_ALL)
        strcpy(szTempSQL, "SELECT COUNT (*) FROM TransLog WHERE HDTid = ? AND MITid = ?");

	/* open the database */
	result = sqlite3_open(DB_BATCH,&db);
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

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].HDTid);
	sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].MITid);
	//sqlite3_bind_int(stmt, inStmtSeq +=1, BALANCE_INQUIRY);

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

/*inMode 1-Delete using HDTid and MITid, 2-Delete using HDTid, MITid, szInvoiceNo, and byTransType*/
int inDatabase_TransLogDelete(TRANS_DATA_TABLE *transData, int inMode)
{
	int result;
 	char *sql; 
 	int inDBResult =0 ;
    char szTempSQL[512+1];

	vdDebug_LogPrintf("****inDatabase_TransLogDelete");
	
    memset(szTempSQL, 0, sizeof(szTempSQL));
	sql=&szTempSQL;
 
    if(inMode == DELETE_BY_TRANSTYPE_INVOICE) /*delete by trans type and invoice number*/
        strcpy(szTempSQL, "DELETE FROM TransLog WHERE HDTid = ? and MITid = ? and szInvoiceNo = ? and byTransType = ?");
    else if(inMode == DELETE_BY_HOSTID_MERCHID) /*delete by hostid and merchant Id*/
        strcpy(szTempSQL, "DELETE FROM TransLog WHERE HDTid = ? and MITid = ?");
	else
		strcpy(szTempSQL, "DELETE FROM TransLog WHERE HDTid = ? and MITid = ? and szInvoiceNo = ?");

    //vdDebug_LogPrintf("inDatabase_TransLogDelete");
	//vdDebug_LogPrintf("transData->HDTid: %d", transData->HDTid);
	//vdDebug_LogPrintf("transData->MITid: %d", transData->MITid);
	//DebugAddHEX("transData->szInvoiceNo", transData->szInvoiceNo, 3);
	//vdDebug_LogPrintf("transData->ulSavedIndex: %d", transData->ulSavedIndex);
	//vdDebug_LogPrintf("transData->byTransType: %d", transData->byTransType);
	//vdDebug_LogPrintf("transData->byPackType: %d", transData->byPackType);
	//vdDebug_LogPrintf("**********************************************************");
	
	/* open the database */
	result = sqlite3_open(DB_BATCH,&db);
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

	inStmtSeq = 0;
    sqlite3_bind_int(stmt, inStmtSeq +=1, transData->HDTid);
	sqlite3_bind_int(stmt, inStmtSeq +=1, transData->MITid);
	if(inMode == 1)
	{
		result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szInvoiceNo, 4, SQLITE_STATIC);
		result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byTransType);
	}
	else if(inMode == 3)
	{
		result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szInvoiceNo, 4, SQLITE_STATIC);
	}
	
	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

	inDBResult = sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	
	//vdDebug_LogPrintf("Batch delet,sqlite3_exec[%d]",inDBResult);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(ST_SUCCESS);
}

int inDatabase_TransLogRead(int inTransDataid, STRUCT_ADVICE *strAdvice, TRANS_DATA_TABLE *transData)
{
    int inResult=0;

    //vdDebug_LogPrintf("1. inDatabase_TransLogRead");
	
    inResult = inDatabase_TransLogReadByTransId(strAdvice, inTransDataid); 
    if(inResult != d_OK)
        return ST_ERROR;

    //vdDebug_LogPrintf("2. inDatabase_TransLogRead");
    
    inResult = inDatabase_BatchRead(transData, strAdvice->ulBatchIndex);
    if(inResult != d_OK)
        return ST_ERROR;

    transData->byDCCTransType=strAdvice->byTransType; /*for dcc logging DE61 transtype*/
		
    //vdDebug_LogPrintf("3. inDatabase_TransLogRead");

	//DebugAddHEX("inDatabase_TransLogRead transData->szInvoiceNo", transData->szInvoiceNo, 3);
    //DebugAddHEX("inDatabase_TransLogRead strAdvice->szInvoiceNo", strAdvice->szInvoiceNo, 3);
	//DebugAddHEX("inDatabase_TransLogRead srTransRec.szAdviceInvoiceNo", srTransRec.szAdviceInvoiceNo, 3);
    if(memcmp(transData->szInvoiceNo, strAdvice->szInvoiceNo, INVOICE_BCD_SIZE) != 0)
    {
        return ST_ERROR;		
    }

    //vdDebug_LogPrintf("4. inDatabase_TransLogRead");

    return ST_SUCCESS;	
}

int inDatabase_TransLogGetTransId(TRANS_DATA_TABLE *transData, int inTranID[], int inMode)
{
	int result;
  	char *sql; // = "SELECT TransDataid FROM TransLog WHERE HDTid = ? AND MITid = ? AND szBatchNo = ? AND byTransType != ? AND byTransType != ? AND byTransType != ?";
	int count = 0;
    char szTempSQL[512+1];
    
    memset(szTempSQL, 0, sizeof(szTempSQL));
    sql=&szTempSQL;

    if(inMode == GET_ALL_EXCEPT_TIP) /*get all TransId except SALE_TIP*/
        strcpy(szTempSQL, "SELECT TransDataid FROM TransLog WHERE HDTid = ? AND MITid = ? AND byTransType != 109 ORDER BY TransDataid DESC");
	else if(inMode == GET_TIP_ONLY) /*get SALE_TIP only*/
        strcpy(szTempSQL, "SELECT TransDataid FROM TransLog WHERE HDTid = ? AND MITid = ? AND szInvoiceNo = ? AND byTransType == 109 ORDER BY TransDataid DESC");
	else if(inMode == GET_ALL)
		strcpy(szTempSQL, "SELECT TransDataid FROM TransLog WHERE HDTid = ? AND MITid = ? ORDER BY TransDataid DESC");

    //vdDebug_LogPrintf("inDatabase_TransLogGetTransId szTempSQL: %s", szTempSQL);
	
	/* open the database */
	result = sqlite3_open(DB_BATCH,&db);
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

    inStmtSeq = 0;
    sqlite3_bind_int(stmt, inStmtSeq +=1, transData->HDTid);
    sqlite3_bind_int(stmt, inStmtSeq +=1, transData->MITid);
    if(inMode == 2)
    {
        result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szAdviceInvoiceNo, 4, SQLITE_STATIC);
		DebugAddHEX("transData->szAdviceInvoiceNo", transData->szAdviceInvoiceNo, 3);
    }
	inStmtSeq = 0;
	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */		
             inStmtSeq = 0;
			 inTranID[count] = sqlite3_column_int(stmt,inStmtSeq);
             DebugAddINT("***inTranID", inTranID[count]);
			 count++;

   		}
	} while (result == SQLITE_ROW);	   

	result = sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	//vdDebug_LogPrintf("inDBResult[%d]",result);
	//vdDebug_LogPrintf("inCount[%d]",count);

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	
	//sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	//sqlite3_finalize(stmt);
	//sqlite3_close(db);

    return(d_OK);
}

int inDatabase_TransLogReadByTransId(STRUCT_ADVICE *strAdvice, int inTransDataid)
{
	int result;
	int inResult = d_NO;

	//char *sql = "SELECT HDTid, MITid, szInvoiceNo, ulBatchIndex, byTransType, byPackType from TransLog WHERE TransDataid = ?";
	char *sql = "SELECT szInvoiceNo, ulBatchIndex, byTransType, byPackType, ulTraceNum from TransLog WHERE TransDataid = ?";

    //vdDebug_LogPrintf("inDatabase_TransLogReadByTransId");
	
	/* open the database */
	result = sqlite3_open(DB_BATCH,&db);
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

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inTransDataid);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			//strAdvice->HDTid = sqlite3_column_int(stmt,inStmtSeq);
			//strAdvice->MITid = sqlite3_column_int(stmt,inStmtSeq +=1 );
            memcpy(strAdvice->szInvoiceNo, sqlite3_column_blob(stmt,inStmtSeq), 4); 
            strAdvice->ulBatchIndex= sqlite3_column_double(stmt, inStmtSeq +=1 );	
			strAdvice->byTransType = sqlite3_column_int(stmt,inStmtSeq +=1 );
			strAdvice->inPacketType = sqlite3_column_int(stmt,inStmtSeq +=1 );
            strAdvice->ulTraceNo = sqlite3_column_double(stmt,inStmtSeq +=1 );
			//DebugAddHEX("strAdvice->szInvoiceNo", strAdvice->szInvoiceNo, 3);
			//vdDebug_LogPrintf("strAdvice->ulBatchIndex: %d", strAdvice->ulBatchIndex);
			//vdDebug_LogPrintf("strAdvice->byTransType: %d", strAdvice->byTransType);
			//vdDebug_LogPrintf("strAdvice->byPackType: %d", strAdvice->inPacketType);
			//vdDebug_LogPrintf("**********************************************************");
		}
	} while (result == SQLITE_ROW);

    //inDatabase_BatchRead(transData, strAdvice->ulBatchIndex)

	
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inResult);
}

int inDatabase_TransLogReadAll(TRANS_DATA_TABLE *transData)
{
	int result;
	int inResult = d_NO;

	/* Issue# 000096: BIN VER Checking -- jzg*/
	char *sql = "SELECT HDTid, MITid, szInvoiceNo, ulBatchIndex, byTransType, byPackType from TransLog DESC";

    //vdDebug_LogPrintf("inDatabase_TransLogReadAll");
	
	/* open the database */
	result = sqlite3_open(DB_BATCH,&db);
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

	inStmtSeq = 0;
	///sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			transData->HDTid = sqlite3_column_int(stmt,inStmtSeq);
			transData->MITid = sqlite3_column_int(stmt,inStmtSeq +=1 );
            memcpy(transData->szInvoiceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4); 
            transData->ulSavedIndex = sqlite3_column_double(stmt, inStmtSeq +=1 );	
			transData->byTransType = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->byPackType = sqlite3_column_int(stmt,inStmtSeq +=1 );

			//vdDebug_LogPrintf("transData->HDTid: %d", transData->HDTid);
			//vdDebug_LogPrintf("transData->MITid: %d", transData->MITid);
			//DebugAddHEX("transData->szInvoiceNo", transData->szInvoiceNo, 3);
			//vdDebug_LogPrintf("transData->ulSavedIndex: %d", transData->ulSavedIndex);
			//vdDebug_LogPrintf("transData->byTransType: %d", transData->byTransType);
			//vdDebug_LogPrintf("transData->byPackType: %d", transData->byPackType);
			//vdDebug_LogPrintf("**********************************************************");
		}
	} while (result == SQLITE_ROW);

    //inDatabase_BatchRead(transData, strAdvice->ulBatchIndex)

	
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inResult);
}

int inDatabase_TransLogUpdatePackType(TRANS_DATA_TABLE *transData)
{
	int result;	
 	char *sql = "UPDATE TransLog SET byPackType=145, ulTraceNum = ? WHERE HDTid = ? and MITid = ? and szInvoiceNo = ? and byTransType = ?";

	//transData->byPackType=DCC_LOGGING;

	/* open the database */
	result = sqlite3_open(DB_BATCH,&db);
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

	inStmtSeq = 0;
    result = sqlite3_bind_double(stmt, inStmtSeq +=1, transData->ulTraceNum);	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->HDTid);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->MITid);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szInvoiceNo, 4, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byTransType);
	
	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

    //vdDebug_LogPrintf("inDatabase_TransLogUpdatePackType");
	//vdDebug_LogPrintf("transData->ulTraceNum: %06ld", transData->ulTraceNum);
	//vdDebug_LogPrintf("transData->HDTid: %d", transData->HDTid);
	//vdDebug_LogPrintf("transData->MITid: %d", transData->MITid);
	//DebugAddHEX("transData->szInvoiceNo", transData->szInvoiceNo, 3);
	//vdDebug_LogPrintf("transData->ulSavedIndex: %d", transData->ulSavedIndex);
	//vdDebug_LogPrintf("transData->byTransType: %d", transData->byTransType);
	//vdDebug_LogPrintf("transData->byPackType: %d", transData->byPackType);
	//vdDebug_LogPrintf("**********************************************************");

	return(ST_SUCCESS);
}

