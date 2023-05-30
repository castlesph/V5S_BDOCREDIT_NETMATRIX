/** 
**    A Template for developing change transaction type application
**/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctosapi.h>
#include <sqlite3.h>



//#include "../Library/Include/sqlite3.h"

#include "../Includes/myEZLib.h"
#include "../Includes/wub_lib.h"
#include "../Includes/POSTypedef.h"

#include "../Includes/Trans.h"

#include "../includes/LocalFunc.h"
#include "../FileModule/myFileFunc.h"
#include "../Debug/Debug.h"
#include "../Database/DatabaseFunc.h"
#include "../Includes/POSSetting.h"

extern sqlite3 * db;
extern sqlite3_stmt *stmt;
extern int inStmtSeq;

int inLocalAP_Database_BatchRead(TRANS_DATA_TABLE *transData)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT MITid, HDTid, CDTid, IITid, byTransType, byPanLen, szExpireDate, byEntryMode, szTotalAmount, szBaseAmount, szTipAmount, byOrgTransType, szMacBlock, szYear, szDate, szTime, szOrgDate, szOrgTime, szAuthCode, szRRN, szInvoiceNo, szOrgInvoiceNo, byPrintType, byVoided, byAdjusted, byUploaded, byTCuploaded, szCardholderName, szzAMEX4DBC, szStoreID, szRespCode, szServiceCode, byContinueTrans, byOffline, byReversal, byEMVFallBack, shTransResult, szTpdu, szIsoField03, szMassageType, szPAN, szCardLable, usTrack1Len, usTrack2Len, usTrack3Len, szTrack1Data, szTrack2Data, szTrack3Data, ulTraceNum, ulOrgTraceNum, usTerminalCommunicationMode, ulSavedIndex, byPINEntryCapability, byPackType, szOrgAmount, szCVV2, inCardType, byTCFailUpCnt, byCardTypeNum, byEMVTransStatus, T5A_len, T5A, T5F2A, T5F30, T5F34, T5F34_len, T82, T84_len, T84, T8A, T91, T91Len, T95, T9A, T9C, T9F02, T9F03, T9F09, T9F10_len, T9F10, T9F1A, T9F26, T9F27, T9F33, T9F34, T9F35, T9F36_len, T9F36, T9F37, T9F41, T9F53, ISR, ISRLen, T9B, T5F24, T71Len, T71, T72Len, T72, T9F06, T9F1E, T9F28, T9F29, szChipLabel, szTID, szMID, szHostLabel, szBatchNo, T9F6E, T9F6E_len FROM TransData WHERE TransDataid = ?";

	/* open the database */
	result = sqlite3_open(DB_LOCALAP,&db);
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
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			transData->MITid = sqlite3_column_int(stmt,inStmtSeq);
			transData->HDTid = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->CDTid = sqlite3_column_int(stmt,inStmtSeq +=1 );
            transData->IITid = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->byTransType = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->byPanLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->szExpireDate, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			transData->byEntryMode = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->szTotalAmount, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);						
			memcpy(transData->szBaseAmount, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);						
			memcpy(transData->szTipAmount, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);						
			transData->byOrgTransType = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->szMacBlock, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 8);						
			memcpy(transData->szYear, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);						
			memcpy(transData->szDate, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			memcpy(transData->szTime, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);						
			memcpy(transData->szOrgDate, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			memcpy(transData->szOrgTime, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);						
			memcpy(transData->szAuthCode, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);						
			memcpy(transData->szRRN, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 13);						
			memcpy(transData->szInvoiceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);						
			memcpy(transData->szOrgInvoiceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);						
			transData->byPrintType = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->byVoided = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->byAdjusted = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->byUploaded = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->byTCuploaded = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->szCardholderName, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 31);						
			memcpy(transData->szzAMEX4DBC, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);						
			memcpy(transData->szStoreID, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 19);						
			memcpy(transData->szRespCode, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			memcpy(transData->szServiceCode, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);						
			transData->byContinueTrans = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->byOffline = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->byReversal = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->byEMVFallBack = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->shTransResult = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->szTpdu, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);						
			memcpy(transData->szIsoField03, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);						
			memcpy(transData->szMassageType, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			memcpy(transData->szPAN, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 20);	
            memcpy(transData->szCardLable, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 20);	
			transData->usTrack1Len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->usTrack2Len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->usTrack3Len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->szTrack1Data, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 86);						
			memcpy(transData->szTrack2Data, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 42);						
			memcpy(transData->szTrack3Data, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 65);						
			transData->ulTraceNum = sqlite3_column_double(stmt, inStmtSeq +=1 );
			transData->ulOrgTraceNum = sqlite3_column_double(stmt, inStmtSeq +=1 );			
			transData->usTerminalCommunicationMode = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->ulSavedIndex = sqlite3_column_double(stmt, inStmtSeq +=1 );			
			transData->byPINEntryCapability = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->byPackType = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->szOrgAmount, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);						
			memcpy(transData->szCVV2, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);
			transData->inCardType = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->byTCFailUpCnt = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->stEMVinfo.byCardTypeNum = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->stEMVinfo.byEMVTransStatus = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->stEMVinfo.T5A_len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->stEMVinfo.T5A, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 10);						
			memcpy(transData->stEMVinfo.T5F2A, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);						
			memcpy(transData->stEMVinfo.T5F30, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			transData->stEMVinfo.T5F34 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->stEMVinfo.T5F34_len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->stEMVinfo.T82, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);						
			transData->stEMVinfo.T84_len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->stEMVinfo.T84, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 16);						
			memcpy(transData->stEMVinfo.T8A, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);						
			memcpy(transData->stEMVinfo.T91, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 16);						
			transData->stEMVinfo.T91Len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->stEMVinfo.T95, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);						
			memcpy(transData->stEMVinfo.T9A, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			transData->stEMVinfo.T9C = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->stEMVinfo.T9F02, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 6);						
			memcpy(transData->stEMVinfo.T9F03, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 6);						
			memcpy(transData->stEMVinfo.T9F09, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);						
			transData->stEMVinfo.T9F10_len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->stEMVinfo.T9F10, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 32);						
			memcpy(transData->stEMVinfo.T9F1A, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);						
			memcpy(transData->stEMVinfo.T9F26, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 8);						
			transData->stEMVinfo.T9F27 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->stEMVinfo.T9F33, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			memcpy(transData->stEMVinfo.T9F34, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			transData->stEMVinfo.T9F35 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->stEMVinfo.T9F36_len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->stEMVinfo.T9F36, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);						
			memcpy(transData->stEMVinfo.T9F37, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);						
			memcpy(transData->stEMVinfo.T9F41, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			transData->stEMVinfo.T9F53 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->stEMVinfo.ISR, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 16);						
			transData->stEMVinfo.ISRLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->stEMVinfo.T9B, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);						
			memcpy(transData->stEMVinfo.T5F24, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			transData->stEMVinfo.T71Len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->stEMVinfo.T71, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 258);						
			transData->stEMVinfo.T72Len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->stEMVinfo.T72, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 258);						
			memcpy(transData->stEMVinfo.T9F06, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			memcpy(transData->stEMVinfo.T9F1E, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 8);						
			memcpy(transData->stEMVinfo.T9F28, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 8);						
			memcpy(transData->stEMVinfo.T9F29, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 8);						
			memcpy(transData->stEMVinfo.szChipLabel, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 32);
			strcpy((char*)transData->szTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)transData->szMID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)transData->szHostLabel, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            memcpy(transData->szBatchNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);
			memcpy(transData->stEMVinfo.T9F6E, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);
			transData->stEMVinfo.T9F6E_len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			
		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inResult);
}

int inLocalAP_Database_BatchUpdate(TRANS_DATA_TABLE *transData)
{
	int result;
	char *sql = "UPDATE TransData SET HDTid = ?, MITid = ?, CDTid = ?, IITid = ?, szHostLabel = ?, szBatchNo = ?, byTransType = ?, byPanLen = ?, szExpireDate = ?, byEntryMode = ?, szTotalAmount = ?, szBaseAmount = ?, szTipAmount = ?, byOrgTransType = ?, szMacBlock = ?, szYear = ?, szDate = ?, szTime = ?, szOrgDate = ?, szOrgTime = ?, szAuthCode = ?, szRRN = ?, szInvoiceNo = ?, szOrgInvoiceNo = ?, byPrintType = ?, byVoided = ?, byAdjusted = ?, byUploaded = ?, byTCuploaded = ?, szCardholderName = ?, szzAMEX4DBC = ?, szStoreID = ?, szRespCode = ?, szServiceCode = ?, byContinueTrans = ?, byOffline = ?, byReversal = ?, byEMVFallBack = ?, shTransResult = ?, szTpdu = ?, szIsoField03 = ?, szMassageType = ?, szPAN = ?, szCardLable = ?, usTrack1Len = ?, usTrack2Len = ?, usTrack3Len = ?, szTrack1Data = ?, szTrack2Data = ?, szTrack3Data = ?, ulTraceNum = ?, ulOrgTraceNum = ?, usTerminalCommunicationMode = ?, ulSavedIndex = ?, byPINEntryCapability = ?, byPackType = ?, szOrgAmount = ?, szCVV2 = ?, inCardType = ?, byTCFailUpCnt = ?, byCardTypeNum = ?, byEMVTransStatus = ?, T5A_len = ?, T5A = ?, T5F2A = ?, T5F30 = ?, T5F34 = ?, T5F34_len = ?, T82 = ?, T84_len = ?, T84 = ?, T8A = ?, T91 = ?, T91Len = ?, T95 = ?, T9A = ?, T9C = ?, T9F02 = ?, T9F03 = ?, T9F09 = ?, T9F10_len = ?, T9F10 = ?, T9F1A = ?, T9F26 = ?, T9F27 = ?, T9F33 = ?, T9F34 = ?, T9F35 = ?, T9F36_len = ?, T9F36 = ?, T9F37 = ?, T9F41 = ?, T9F53 = ?, ISR = ?, ISRLen = ?, T9B = ?, T5F24 = ?, T71Len = ?, T71 = ?, T72Len = ?, T72 = ?, T9F06 = ?, T9F1E = ?, T9F28 = ?, T9F29 = ?, szChipLabel = ?, szTID = ?, szMID = ?, T9F6E = ?, T9F6E_len = ? WHERE TransDataid = ?";

	/* open the database */
	result = sqlite3_open(DB_LOCALAP,&db);
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
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->CDTid);
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->IITid);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szHostLabel, strlen((char*)transData->szHostLabel), SQLITE_STATIC); 
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szBatchNo, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byTransType);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byPanLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szExpireDate, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byEntryMode);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szTotalAmount, 7, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szBaseAmount, 7, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szTipAmount, 7, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byOrgTransType);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szMacBlock, 8, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szYear, 2, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szDate, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szTime, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szOrgDate, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szOrgTime, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szAuthCode, 7, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szRRN, 13, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szInvoiceNo, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szOrgInvoiceNo, 4, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byPrintType);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byVoided);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byAdjusted);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byUploaded);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byTCuploaded);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szCardholderName, 31, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szzAMEX4DBC, 5, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szStoreID, 19, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szRespCode, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szServiceCode, 4, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byContinueTrans);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byOffline);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byReversal);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byEMVFallBack);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->shTransResult);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szTpdu, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szIsoField03, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szMassageType, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szPAN, 20, SQLITE_STATIC);
    result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szCardLable, 20, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usTrack1Len);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usTrack2Len);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usTrack3Len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szTrack1Data, 86, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szTrack2Data, 42, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szTrack3Data, 65, SQLITE_STATIC);
	result = sqlite3_bind_double(stmt, inStmtSeq +=1, transData->ulTraceNum);
	result = sqlite3_bind_double(stmt, inStmtSeq +=1, transData->ulOrgTraceNum);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usTerminalCommunicationMode);
	result = sqlite3_bind_double(stmt, inStmtSeq +=1, transData->ulSavedIndex);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byPINEntryCapability);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byPackType);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szOrgAmount, 7, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szCVV2, 4, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->inCardType);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byTCFailUpCnt);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.byCardTypeNum);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.byEMVTransStatus);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T5A_len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T5A, 10, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T5F2A, 2, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T5F30, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T5F34);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T5F34_len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T82, 2, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T84_len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T84, 16, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T8A, 2, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T91, 16, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T91Len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T95, 5, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9A, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T9C);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F02, 6, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F03, 6, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F09, 2, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F10_len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F10, 32, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F1A, 2, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F26, 8, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F27);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F33, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F34, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F35);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F36_len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F36, 2, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F37, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F41, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F53);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.ISR, 16, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.ISRLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9B, 2, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T5F24, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T71Len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T71, 258, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T72Len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T72, 258, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F06, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F1E, 8, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F28, 8, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F29, 8, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.szChipLabel, 32, SQLITE_STATIC);
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szTID, strlen((char*)transData->szTID), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szMID, strlen((char*)transData->szMID), SQLITE_STATIC); 
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F6E, 4, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F6E_len);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, 1);

	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(ST_SUCCESS);
}



int inLocalAP_Database_BatchInsert(TRANS_DATA_TABLE *transData)
{
	int result;	
	char *sql1 = "SELECT MAX(TransDataid) FROM TransData";
 	char *sql = "INSERT INTO TransData (TransDataid, HDTid, MITid, CDTid, IITid, szHostLabel, szBatchNo, byTransType, byPanLen, szExpireDate, byEntryMode, szTotalAmount, szBaseAmount, szTipAmount, byOrgTransType, szMacBlock, szYear, szDate, szTime, szOrgDate, szOrgTime, szAuthCode, szRRN, szInvoiceNo, szOrgInvoiceNo, byPrintType, byVoided, byAdjusted, byUploaded, byTCuploaded, szCardholderName, szzAMEX4DBC, szStoreID, szRespCode, szServiceCode, byContinueTrans, byOffline, byReversal, byEMVFallBack, shTransResult, szTpdu, szIsoField03, szMassageType, szPAN, szCardLable, usTrack1Len, usTrack2Len, usTrack3Len, szTrack1Data, szTrack2Data, szTrack3Data, ulTraceNum, ulOrgTraceNum, usTerminalCommunicationMode, ulSavedIndex, byPINEntryCapability, byPackType, szOrgAmount, szCVV2, inCardType, byTCFailUpCnt, byCardTypeNum, byEMVTransStatus, T5A_len, T5A, T5F2A, T5F30, T5F34, T5F34_len, T82, T84_len, T84, T8A, T91, T91Len, T95, T9A, T9C, T9F02, T9F03, T9F09, T9F10_len, T9F10, T9F1A, T9F26, T9F27, T9F33, T9F34, T9F35, T9F36_len, T9F36, T9F37, T9F41, T9F53, ISR, ISRLen, T9B, T5F24, T71Len, T71, T72Len, T72, T9F06, T9F1E, T9F28, T9F29, szChipLabel, szTID, szMID, szHostLabel, szBatchNo, T9F6E, T9F6E_len) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

	/* open the database */
	result = sqlite3_open(DB_LOCALAP,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	sqlite3_exec( db, "begin", 0, 0, NULL );

	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql1, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;

			transData->ulSavedIndex = sqlite3_column_int(stmt,inStmtSeq);
			transData->ulSavedIndex += 1;
		}
	} while (result == SQLITE_ROW);
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	   
	/* open the database */
	result = sqlite3_open(DB_LOCALAP,&db);
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
	//vdCTOSS_GetMemoryStatus("bagin Database");

	inStmtSeq = 0;
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->HDTid);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->MITid);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->CDTid);
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->IITid);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szHostLabel, strlen((char*)transData->szHostLabel), SQLITE_STATIC); 
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szBatchNo, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byTransType);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byPanLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szExpireDate, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byEntryMode);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szTotalAmount, 7, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szBaseAmount, 7, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szTipAmount, 7, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byOrgTransType);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szMacBlock, 8, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szYear, 2, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szDate, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szTime, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szOrgDate, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szOrgTime, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szAuthCode, 7, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szRRN, 13, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szInvoiceNo, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szOrgInvoiceNo, 4, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byPrintType);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byVoided);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byAdjusted);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byUploaded);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byTCuploaded);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szCardholderName, 31, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szzAMEX4DBC, 5, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szStoreID, 19, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szRespCode, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szServiceCode, 4, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byContinueTrans);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byOffline);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byReversal);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byEMVFallBack);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->shTransResult);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szTpdu, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szIsoField03, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szMassageType, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szPAN, 20, SQLITE_STATIC);
    result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szCardLable, 20, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usTrack1Len);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usTrack2Len);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usTrack3Len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szTrack1Data, 86, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szTrack2Data, 42, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szTrack3Data, 65, SQLITE_STATIC);
	result = sqlite3_bind_double(stmt, inStmtSeq +=1, transData->ulTraceNum);
	result = sqlite3_bind_double(stmt, inStmtSeq +=1, transData->ulOrgTraceNum);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usTerminalCommunicationMode);
	result = sqlite3_bind_double(stmt, inStmtSeq +=1, transData->ulSavedIndex);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byPINEntryCapability);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byPackType);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szOrgAmount, 7, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szCVV2, 4, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->inCardType);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byTCFailUpCnt);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.byCardTypeNum);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.byEMVTransStatus);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T5A_len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T5A, 10, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T5F2A, 2, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T5F30, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T5F34);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T5F34_len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T82, 2, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T84_len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T84, 16, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T8A, 2, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T91, 16, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T91Len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T95, 5, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9A, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T9C);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F02, 6, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F03, 6, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F09, 2, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F10_len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F10, 32, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F1A, 2, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F26, 8, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F27);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F33, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F34, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F35);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F36_len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F36, 2, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F37, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F41, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F53);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.ISR, 16, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.ISRLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9B, 2, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T5F24, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T71Len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T71, 258, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T72Len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T72, 258, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F06, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F1E, 8, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F28, 8, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F29, 8, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.szChipLabel, 32, SQLITE_STATIC);
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szTID, strlen((char*)transData->szTID), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szMID, strlen((char*)transData->szMID), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szHostLabel, strlen((char*)transData->szHostLabel), SQLITE_STATIC); 
    result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szBatchNo, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F6E, 4, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F6E_len);

	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(ST_SUCCESS);
}



int inLocalAP_Database_BatchDelete(void)
{
	int result;
	char *sql = "DELETE FROM TransData";	
	int inDBResult =0 ;

	/* open the database */
	result = sqlite3_open(DB_LOCALAP,&db);
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
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srTransRec.szHostLabel, strlen((char*)srTransRec.szHostLabel), SQLITE_STATIC); 
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, srTransRec.szBatchNo, 3, SQLITE_STATIC);

	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

    
	inDBResult = sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	
	vdDebug_LogPrintf("Batch delet,sqlite3_exec[%d]",inDBResult);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(ST_SUCCESS);
}

