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

extern char szGlobalAPName[25];

sqlite3 * db;
//version16
sqlite3 * walletdb;

sqlite3_stmt *stmt;
int inStmtSeq = 0;

extern BOOL fInstApp;

void vdSetJournalModeOff(void)
{
	int result;
	char *sql2 = "PRAGMA journal_mode=OFF";
	
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql2, -1, &stmt, NULL);
	//vdDebug_LogPrintf("sqlite3_prepare_v2 sql2=[%d]",result);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return;
	}

	do
	{
		result = sqlite3_step(stmt);
		//vdDebug_LogPrintf("sqlite3_step sql2=[%d]",result);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;
			//vdDebug_LogPrintf("sqlite3_step sql2=[%s]",sqlite3_column_text(stmt,inStmtSeq));
		}
	}while (result == SQLITE_ROW);
	
	result = sqlite3_finalize(stmt);
	//vdDebug_LogPrintf("sqlite3_finalize sql2=[%d]",result);
}


int inHDTReadHostName(char szHostName[][400], int inCPTID[])
{    
	int result;	
	char *sql = "SELECT HDTid, szHostLabel FROM HDT WHERE fHostEnable = ? order by inSequence";
	int inCount = 0;
	int inDBResult = 0;
	
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

	
	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);//fHostEnable = 1

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;
			/* HDTid */
			inCPTID[inCount] = sqlite3_column_int(stmt,inStmtSeq);

            /* szHostName */
			strcpy((char*)szHostName[inCount], (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			vdDebug_LogPrintf("szHostName[%s] %d",szHostName[inCount], inCount);

			inCount++;
		}
	} while (result == SQLITE_ROW);

    
	inDBResult = sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	vdDebug_LogPrintf("inDBResult[%d]",inDBResult);
	vdDebug_LogPrintf("inCount[%d]",inCount);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(d_OK);
}

int inCPTRead(int inSeekCnt)
{     
	int result;
	char *sql = "SELECT HDTid, szHostName,inCommunicationMode, szPriTxnPhoneNumber, szSecTxnPhoneNumber, szPriSettlePhoneNumber, szSecSettlePhoneNumber, fFastConnect, fDialMode, inDialHandShake, szATCommand, inMCarrierTimeOut, inMRespTimeOut, fPreDial, szPriTxnHostIP, szSecTxnHostIP, szPriSettlementHostIP, szSecSettlementHostIP, inPriTxnHostPortNum, inSecTxnHostPortNum, inPriSettlementHostPort, inSecSettlementHostPort, fTCPFallbackDial, fSSLEnable, inTCPConnectTimeout, inTCPResponseTimeout, inCountryCode, inHandShake, inParaMode, inIPHeader, fCommBackUpMode, inCommunicationBackUpMode FROM CPT WHERE CPTid = ?";
		
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

	result = sqlite3_bind_int(stmt, 1, inSeekCnt);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;

                        /* HDTid */
                        strCPT.HDTid = sqlite3_column_int(stmt, inStmtSeq );   
                        
                        /* szHostName*/
			strcpy((char*)strCPT.szHostName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
           
            /* inCommunicationMode */
            strCPT.inCommunicationMode = sqlite3_column_int(stmt, inStmtSeq +=1 );   

			/* szPriTxnPhoneNumber; */
                        strcpy((char*)strCPT.szPriTxnPhoneNumber, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szSecTxnPhoneNumber*/
                        strcpy((char*)strCPT.szSecTxnPhoneNumber, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szPriSettlePhoneNumber*/			 //5
			strcpy((char*)strCPT.szPriSettlePhoneNumber, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
                        
                        
			/* szSecSettlePhoneNumber*/
			strcpy((char*)strCPT.szSecSettlePhoneNumber, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fFastConnect*/
                        strCPT.fFastConnect = fGetBoolean((BYTE *)sqlite3_column_text(stmt, inStmtSeq +=1 ));   

			/* fDialMode*/
			strCPT.fDialMode = fGetBoolean((BYTE *)sqlite3_column_text(stmt, inStmtSeq +=1 ));
                        
			/* inDialHandShake*/
			strCPT.inDialHandShake = sqlite3_column_int(stmt, inStmtSeq +=1 );
			/* szATCommand*/
			strcpy((char*)strCPT.szATCommand, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* inMCarrierTimeOut*/
			strCPT.inMCarrierTimeOut = sqlite3_column_int(stmt, inStmtSeq +=1 );

			/* inMRespTimeOut*/
			strCPT.inMRespTimeOut = sqlite3_column_int(stmt, inStmtSeq +=1 );
                        
            /* fPreDial*/
			strCPT.fPreDial = fGetBoolean((BYTE *)sqlite3_column_text(stmt, inStmtSeq +=1 ));

			/* szPriTxnHostIP*/
			strcpy((char*)strCPT.szPriTxnHostIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
						
                        /* szSecTxnHostIP*/
			strcpy((char*)strCPT.szSecTxnHostIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
                        /* szPriSettlementHostIP*/
			strcpy((char*)strCPT.szPriSettlementHostIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	                
                        /* szSecSettlementHostIP*/
			strcpy((char*)strCPT.szSecSettlementHostIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		        
                        /* inPriTxnHostPortNum*/
			strCPT.inPriTxnHostPortNum = sqlite3_column_int(stmt, inStmtSeq +=1 );
                          
                        /* inSecTxnHostPortNum*/
			strCPT.inSecTxnHostPortNum = sqlite3_column_int(stmt, inStmtSeq +=1 );
                        
                        /* inPriSettlementHostPort*/
			strCPT.inPriSettlementHostPort = sqlite3_column_int(stmt, inStmtSeq +=1 );
                         
                        /* inSecSettlementHostPort*/
			strCPT.inSecSettlementHostPort = sqlite3_column_int(stmt, inStmtSeq +=1 );
                        
			/*fTCPFallbackDial*/
			strCPT.fTCPFallbackDial = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
                        			
                        /*fSSLEnable*/
			strCPT.fSSLEnable =fGetBoolean((BYTE *) sqlite3_column_text(stmt,inStmtSeq +=1 ));
                       
                        /*inTCPConnectTimeout*/
			strCPT.inTCPConnectTimeout = sqlite3_column_int(stmt, inStmtSeq +=1 );
                            
                        /*inTCPResponseTimeout*/
			strCPT.inTCPResponseTimeout = sqlite3_column_int(stmt, inStmtSeq +=1 );

			/*inCountryCode*/
			strCPT.inCountryCode = sqlite3_column_int(stmt, inStmtSeq +=1 );
			/*inHandShake*/
			strCPT.inHandShake = sqlite3_column_int(stmt, inStmtSeq +=1 );
			/*inParaMode*/
			strCPT.inParaMode = sqlite3_column_int(stmt, inStmtSeq +=1 );

            /*inIPHeader*/
			strCPT.inIPHeader = sqlite3_column_int(stmt, inStmtSeq +=1 );

			/*fCommBackUpMode*/
			strCPT.fCommBackUpMode =fGetBoolean((BYTE *) sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
			/* inCommunicationBackUpMode */
			strCPT.inCommunicationBackUpMode = sqlite3_column_int(stmt, inStmtSeq +=1 );	 
                        
   
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(d_OK);
}

int inCPTReadEx(int inSeekCnt)
{     
	int result;
	char *sql = "SELECT HDTid, szHostName,inCommunicationMode, szPriTxnPhoneNumber, szSecTxnPhoneNumber, szPriSettlePhoneNumber, szSecSettlePhoneNumber, fFastConnect, fDialMode, inDialHandShake, szATCommand, inMCarrierTimeOut, inMRespTimeOut, fPreDial, szPriTxnHostIP, szSecTxnHostIP, szPriSettlementHostIP, szSecSettlementHostIP, inPriTxnHostPortNum, inSecTxnHostPortNum, inPriSettlementHostPort, inSecSettlementHostPort, fTCPFallbackDial, fSSLEnable, inTCPConnectTimeout, inTCPResponseTimeout, inCountryCode, inHandShake, inParaMode, inIPHeader, fCommBackUpMode, inCommunicationBackUpMode FROM CPT WHERE CPTid = ?";

	#if 0
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	#endif
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	result = sqlite3_bind_int(stmt, 1, inSeekCnt);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;

                        /* HDTid */
                        strCPT.HDTid = sqlite3_column_int(stmt, inStmtSeq );   
                        
                        /* szHostName*/
			strcpy((char*)strCPT.szHostName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
           
            /* inCommunicationMode */
            strCPT.inCommunicationMode = sqlite3_column_int(stmt, inStmtSeq +=1 );   

			/* szPriTxnPhoneNumber; */
                        strcpy((char*)strCPT.szPriTxnPhoneNumber, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szSecTxnPhoneNumber*/
                        strcpy((char*)strCPT.szSecTxnPhoneNumber, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szPriSettlePhoneNumber*/			 //5
			strcpy((char*)strCPT.szPriSettlePhoneNumber, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
                        
                        
			/* szSecSettlePhoneNumber*/
			strcpy((char*)strCPT.szSecSettlePhoneNumber, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fFastConnect*/
                        strCPT.fFastConnect = fGetBoolean((BYTE *)sqlite3_column_text(stmt, inStmtSeq +=1 ));   

			/* fDialMode*/
			strCPT.fDialMode = fGetBoolean((BYTE *)sqlite3_column_text(stmt, inStmtSeq +=1 ));
                        
			/* inDialHandShake*/
			strCPT.inDialHandShake = sqlite3_column_int(stmt, inStmtSeq +=1 );
			/* szATCommand*/
			strcpy((char*)strCPT.szATCommand, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* inMCarrierTimeOut*/
			strCPT.inMCarrierTimeOut = sqlite3_column_int(stmt, inStmtSeq +=1 );

			/* inMRespTimeOut*/
			strCPT.inMRespTimeOut = sqlite3_column_int(stmt, inStmtSeq +=1 );
                        
            /* fPreDial*/
			strCPT.fPreDial = fGetBoolean((BYTE *)sqlite3_column_text(stmt, inStmtSeq +=1 ));

			/* szPriTxnHostIP*/
			strcpy((char*)strCPT.szPriTxnHostIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
						
                        /* szSecTxnHostIP*/
			strcpy((char*)strCPT.szSecTxnHostIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
                        /* szPriSettlementHostIP*/
			strcpy((char*)strCPT.szPriSettlementHostIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	                
                        /* szSecSettlementHostIP*/
			strcpy((char*)strCPT.szSecSettlementHostIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		        
                        /* inPriTxnHostPortNum*/
			strCPT.inPriTxnHostPortNum = sqlite3_column_int(stmt, inStmtSeq +=1 );
                          
                        /* inSecTxnHostPortNum*/
			strCPT.inSecTxnHostPortNum = sqlite3_column_int(stmt, inStmtSeq +=1 );
                        
                        /* inPriSettlementHostPort*/
			strCPT.inPriSettlementHostPort = sqlite3_column_int(stmt, inStmtSeq +=1 );
                         
                        /* inSecSettlementHostPort*/
			strCPT.inSecSettlementHostPort = sqlite3_column_int(stmt, inStmtSeq +=1 );
                        
			/*fTCPFallbackDial*/
			strCPT.fTCPFallbackDial = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
                        			
                        /*fSSLEnable*/
			strCPT.fSSLEnable =fGetBoolean((BYTE *) sqlite3_column_text(stmt,inStmtSeq +=1 ));
                       
                        /*inTCPConnectTimeout*/
			strCPT.inTCPConnectTimeout = sqlite3_column_int(stmt, inStmtSeq +=1 );
                            
                        /*inTCPResponseTimeout*/
			strCPT.inTCPResponseTimeout = sqlite3_column_int(stmt, inStmtSeq +=1 );

			/*inCountryCode*/
			strCPT.inCountryCode = sqlite3_column_int(stmt, inStmtSeq +=1 );
			/*inHandShake*/
			strCPT.inHandShake = sqlite3_column_int(stmt, inStmtSeq +=1 );
			/*inParaMode*/
			strCPT.inParaMode = sqlite3_column_int(stmt, inStmtSeq +=1 );

            /*inIPHeader*/
			strCPT.inIPHeader = sqlite3_column_int(stmt, inStmtSeq +=1 );

			/*fCommBackUpMode*/
			strCPT.fCommBackUpMode =fGetBoolean((BYTE *) sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
			/* inCommunicationBackUpMode */
			strCPT.inCommunicationBackUpMode = sqlite3_column_int(stmt, inStmtSeq +=1 );	 
                        
   
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	#if 0
	sqlite3_close(db);
	#endif

    return(d_OK);
}

int inCPTSave(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE CPT SET HDTid = ?, szHostName = ?,inCommunicationMode = ?, szPriTxnPhoneNumber = ?, szSecTxnPhoneNumber = ?, szPriSettlePhoneNumber = ?, szSecSettlePhoneNumber = ?, fFastConnect = ?, fDialMode = ?, inDialHandShake = ?, szATCommand = ?, inMCarrierTimeOut = ?, inMRespTimeOut = ?, fPreDial = ?, szPriTxnHostIP = ?, szSecTxnHostIP = ?, szPriSettlementHostIP = ?, szSecSettlementHostIP = ?, inPriTxnHostPortNum = ?, inSecTxnHostPortNum = ?, inPriSettlementHostPort = ?, inSecSettlementHostPort = ?, fTCPFallbackDial = ?, fSSLEnable = ?, inTCPConnectTimeout = ?, inTCPResponseTimeout = ?, inCountryCode = ?, inHandShake = ?, inParaMode = ?, inIPHeader= ?, fCommBackUpMode=?, inCommunicationBackUpMode=? WHERE  CPTid = ?";
	
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
	inStmtSeq = 0;
        
        /* HDTid*/
        result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.HDTid);
	/* szHostName*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCPT.szHostName, strlen((char*)strCPT.szHostName), SQLITE_STATIC);
	/* inCommunicationMode*/	
		result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.inCommunicationMode);
	/* szPriTxnPhoneNumber*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCPT.szPriTxnPhoneNumber, strlen((char*)strCPT.szPriTxnPhoneNumber), SQLITE_STATIC);
        /* szSecTxnPhoneNumber*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCPT.szSecTxnPhoneNumber, strlen((char*)strCPT.szSecTxnPhoneNumber), SQLITE_STATIC);
        /* szPriSettlePhoneNumber*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCPT.szPriSettlePhoneNumber, strlen((char*)strCPT.szPriSettlePhoneNumber), SQLITE_STATIC);
        /* szSecSettlePhoneNumber*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCPT.szSecSettlePhoneNumber, strlen((char*)strCPT.szSecSettlePhoneNumber), SQLITE_STATIC);
        
        /* fFastConnect*/
        result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.fFastConnect);
        
        /* fDialMode*/
        result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.fDialMode);
         /* inDialHandShake*/
        result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.inDialHandShake);       
        
        /* szATCommand*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCPT.szATCommand, strlen((char*)strCPT.szATCommand), SQLITE_STATIC);   
        
        /* inMCarrierTimeOut*/
        result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.inMCarrierTimeOut);       
               
        /* inMRespTimeOut*/
        result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.inMRespTimeOut);    
   
        /* fPreDial*/
        result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.fPreDial);
        
	/* szPriTxnHostIP*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCPT.szPriTxnHostIP, strlen((char*)strCPT.szPriTxnHostIP), SQLITE_STATIC);
	/* szSecTxnHostIP*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCPT.szSecTxnHostIP, strlen((char*)strCPT.szSecTxnHostIP), SQLITE_STATIC);
	/*szPriSettlementHostIP*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCPT.szPriSettlementHostIP, strlen((char*)strCPT.szPriSettlementHostIP), SQLITE_STATIC);
	/*szSecSettlementHostIP*/	
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCPT.szSecSettlementHostIP, strlen((char*)strCPT.szSecSettlementHostIP), SQLITE_STATIC);
	/* inPriTxnHostPortNum*/
        result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.inPriTxnHostPortNum);
       /* inSecTxnHostPortNum*/
        result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.inSecTxnHostPortNum); 
        /* inPriSettlementHostPort*/
        result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.inPriSettlementHostPort);          
        /* inSecSettlementHostPort*/
        result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.inSecSettlementHostPort);   
        /* fTCPFallbackDial*/
        result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.fTCPFallbackDial);        
        /* fSSLEnable*/
        result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.fSSLEnable);           
          /* inTCPConnectTimeout*/	  
		result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.inTCPConnectTimeout);	
        /* inTCPResponseTimeout*/
		result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.inTCPResponseTimeout);
		/* inCountryCode*/
		result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.inCountryCode);
		/* inHandShake*/
		result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.inHandShake);
		/* inParaMode*/
		result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.inParaMode);
         /* inIPHeader*/
		result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.inIPHeader);	 

    	/* fCommBackUpMode*/
    	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.fCommBackUpMode); 		  
    
    	/* inCommunicationBackUpMode*/	 
    	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCPT.inCommunicationBackUpMode);
        
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



int inHDTNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM HDT";
	int inCount = 0;
	
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


/* BDO: Make sure we use the BDO Credit host details first - start -- jzg */
int inGetCreditHostIndex(void)
{
	int result = d_OK;
	char *sql = "SELECT inHostIndex FROM HDT WHERE szHostLabel LIKE 'BDO'";
	int inCreditHostIndex = 0;

	result = sqlite3_open(DB_TERMINAL,&db);
	if(result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 1;
	}
	sqlite3_exec(db, "begin", 0, 0, NULL);
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if(result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 2;
	}

	result = sqlite3_step(stmt);
	if(result == SQLITE_ROW) 
	{ 
		inStmtSeq = 0;
		inCreditHostIndex = sqlite3_column_int(stmt,inStmtSeq);
	}

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inCreditHostIndex);
}
/* BDO: Make sure we use the BDO Credit host details first - end -- jzg */


/* BDO: Make sure we use the BDO Credit host details first - start -- jzg */
int inGetCreditHostIndexEx(void)
{
	int result = d_OK;
	char *sql = "SELECT inHostIndex FROM HDT WHERE szHostLabel LIKE 'BDO'";
	int inCreditHostIndex = 0;

	#if 0
	result = sqlite3_open(DB_TERMINAL,&db);
	if(result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 1;
	}
	#endif
	sqlite3_exec(db, "begin", 0, 0, NULL);
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if(result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 2;
	}

	result = sqlite3_step(stmt);
	if(result == SQLITE_ROW) 
	{ 
		inStmtSeq = 0;
		inCreditHostIndex = sqlite3_column_int(stmt,inStmtSeq);
	}

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	#if 0
	sqlite3_close(db);
	#endif
	
	return(inCreditHostIndex);
}


int inTCTNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM TCT";
	int inCount = 0;
	
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

int inCDTNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM CDT";
	int inCount = 0;
	
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


int inIITNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM IIT";
	int inCount = 0;
	
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

int inMMTNumAlbertRecord(int HDTid)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM MMT WHERE fMMTEnable = 1 AND HDTid = ?";
	int inCount = 0;
	
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

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, HDTid);
	
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


int inMMTNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM MMT";
	int inCount = 0;
	
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

int inPITNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM PIT";
	int inCount = 0;
	
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

int inRDTNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM RDT";
	int inCount = 0;
	
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

int inEMVNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM EMV";
	int inCount = 0;
	
	/* open the database */
	result = sqlite3_open(DB_EMV,&db);
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

int inAIDNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM AID";
	int inCount = 0;
	
	/* open the database */
	//result = sqlite3_open(DB_TERMINAL,&db);
	result = sqlite3_open(DB_EMV,&db);
	
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

int inMSGNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM MSG";
	int inCount = 0;
	
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

int inTLENumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM TLE";
	int inCount = 0;
	
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


int inWaveAIDNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM AID";
	int inCount = 0;
	
	/* open the database */
	//result = sqlite3_open(DB_TERMINAL,&db);
	result = sqlite3_open(DB_WAVE,&db);
	
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
	//�ر�sqlite����
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inCount);
}

int inWaveEMVNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM EMV";
	int inCount = 0;
	
	/* open the database */
	result = sqlite3_open(DB_WAVE,&db);
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
	//�ر�sqlite����
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inCount);
}


int inHDTRead(int inSeekCnt)
{
	int len;
	CTOS_RTC SetRTC;     
	int result;
	int inResult = d_NO;
	char *sql = "SELECT inHostIndex, szHostLabel, szTPDU, szNII, fReversalEnable, fHostEnable, szTraceNo, fSignOn, ulLastTransSavedIndex, inCurrencyIdx, szAPName, inFailedREV, inDeleteREV, inNumAdv, fPrintFooterLogo, fPrintBankReceipt, fPrintCustReceipt, fPrintMercReceipt, fPrintVoidBankReceipt, fPrintVoidCustReceipt, fPrintVoidMercReceipt, fHDTTipAllow, fAutoDelReversal, inReversalTries, fBinVerEnable, szDCCRateandLogTraceNo, fTapAndGo, szDetailReportMask, inIssuerID, fSendPosSerial FROM HDT WHERE HDTid = ? AND fHostEnable = ?";
	//

    vdDebug_LogPrintf("inHDTREAD 1");
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	vdDebug_LogPrintf("inHDTREAD 2");

	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

    vdDebug_LogPrintf("inHDTREAD 3");

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);//fHostEnable = 1

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

            /*inHostIndex*/
			strHDT.inHostIndex = sqlite3_column_int(stmt, inStmtSeq );

            /* szHostLabel */
			strcpy((char*)strHDT.szHostLabel, (char *)sqlite3_column_text(stmt, inStmtSeq +=1));
            

			/*szTPDU*/
			memcpy(strHDT.szTPDU, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);

			/* szNII*/
			memcpy(strHDT.szNII, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);

			/* fReversalEnable*/
			strHDT.fReversalEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fHostEnable*/
			strHDT.fHostEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

	
			/* szTraceNo*/
			memcpy(strHDT.szTraceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);

			/* fSignOn */
			strHDT.fSignOn = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*ulLastTransSavedIndex*/
			strHDT.ulLastTransSavedIndex = sqlite3_column_double(stmt, inStmtSeq +=1 );

 			/* inCurrencyIdx */	
			strHDT.inCurrencyIdx = sqlite3_column_int(stmt, inStmtSeq +=1 );
            
			/* szAPName */			
			strcpy((char*)strHDT.szAPName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* inFailedREV */
			strHDT.inFailedREV = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* inDeleteREV */
			strHDT.inDeleteREV = sqlite3_column_int(stmt,inStmtSeq +=1);

            /* inNumAdv */
			strHDT.inNumAdv = sqlite3_column_int(stmt,inStmtSeq +=1);
			
			//sidumili: Issue#: 000135
			/*fPrintFooterLogo*/
			strHDT.fPrintFooterLogo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));


			/*BDO: Parameterized receipt printing - start*/
			/*fPrintBankReceipt*/
			strHDT.fPrintBankReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintCustReceipt*/
			strHDT.fPrintCustReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintMercReceipt*/
			strHDT.fPrintMercReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintVoidBankReceipt*/
			strHDT.fPrintVoidBankReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintVoidCustReceipt*/
			strHDT.fPrintVoidCustReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintVoidMercReceipt*/
			strHDT.fPrintVoidMercReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/*BDO: Parameterized receipt printing - end*/

			/* BDO: Tip Allow flag moved to HDT - start -- jzg */
			/*fHDTTipAllow*/
			strHDT.fHDTTipAllow = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO: Tip Allow flag moved to HDT - end -- jzg */

			/* BDO PHASE 2:[Flag for auto delete reversal file if host does not respond] -- sidumili */
			/*fAutoDelReversal*/
				strHDT.fAutoDelReversal = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO PHASE 2:[Flag for auto delete reversal file if host does not respond] -- sidumili */

			/* BDO PHASE 2:[Reversal Tries] -- sidumili */
				strHDT.inReversalTries = sqlite3_column_int(stmt,inStmtSeq +=1);
			/* BDO PHASE 2:[Reversal Tries] -- sidumili */

			/*fHDTTipAllow*/
			strHDT.fBinVerEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
				
			/* szDCCRateandLogTraceNo */
			memcpy(strHDT.szDCCRateandLogTraceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);

			/*fTapAndGo*/
			strHDT.fTapAndGo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szDetailReportMask */
			strcpy((char*)strHDT.szDetailReportMask, (char *)sqlite3_column_text(stmt, inStmtSeq +=1));

			/*inIssuerID*/
			strHDT.inIssuerID = sqlite3_column_int(stmt,inStmtSeq +=1);

            //version16
			//fSendPosSerial
			strHDT.fSendPosSerial = sqlite3_column_int(stmt,inStmtSeq +=1);

					
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	//vdDebug_LogPrintf("HDTREAD %d", inResult);

    memset(szGlobalAPName, 0x00, sizeof(szGlobalAPName));
	strcpy(szGlobalAPName, strHDT.szAPName);

    vdDebug_LogPrintf("inHDTREAD RESULT %d", inResult);

    return(inResult);
}

int inHDTReadEx(int inSeekCnt)
{
	int len;
	CTOS_RTC SetRTC;     
	int result;
	int inResult = d_NO;
	char *sql = "SELECT inHostIndex, szHostLabel, szTPDU, szNII, fReversalEnable, fHostEnable, szTraceNo, fSignOn, ulLastTransSavedIndex, inCurrencyIdx, szAPName, inFailedREV, inDeleteREV, inNumAdv, fPrintFooterLogo, fPrintBankReceipt, fPrintCustReceipt, fPrintMercReceipt, fPrintVoidBankReceipt, fPrintVoidCustReceipt, fPrintVoidMercReceipt, fHDTTipAllow, fAutoDelReversal, inReversalTries, fBinVerEnable, szDCCRateandLogTraceNo, fTapAndGo, szDetailReportMask, inIssuerID, fSendPosSerial FROM HDT WHERE HDTid = ? AND fHostEnable = ?";
	//

	#if 0
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	#endif
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);//fHostEnable = 1

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

            /*inHostIndex*/
			strHDT.inHostIndex = sqlite3_column_int(stmt, inStmtSeq );

            /* szHostLabel */
			strcpy((char*)strHDT.szHostLabel, (char *)sqlite3_column_text(stmt, inStmtSeq +=1));
            

			/*szTPDU*/
			memcpy(strHDT.szTPDU, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);

			/* szNII*/
			memcpy(strHDT.szNII, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);

			/* fReversalEnable*/
			strHDT.fReversalEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fHostEnable*/
			strHDT.fHostEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

	
			/* szTraceNo*/
			memcpy(strHDT.szTraceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);

			/* fSignOn */
			strHDT.fSignOn = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*ulLastTransSavedIndex*/
			strHDT.ulLastTransSavedIndex = sqlite3_column_double(stmt, inStmtSeq +=1 );

 			/* inCurrencyIdx */	
			strHDT.inCurrencyIdx = sqlite3_column_int(stmt, inStmtSeq +=1 );
            
			/* szAPName */			
			strcpy((char*)strHDT.szAPName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* inFailedREV */
			strHDT.inFailedREV = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* inDeleteREV */
			strHDT.inDeleteREV = sqlite3_column_int(stmt,inStmtSeq +=1);

            /* inNumAdv */
			strHDT.inNumAdv = sqlite3_column_int(stmt,inStmtSeq +=1);
			
			//sidumili: Issue#: 000135
			/*fPrintFooterLogo*/
			strHDT.fPrintFooterLogo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));


			/*BDO: Parameterized receipt printing - start*/
			/*fPrintBankReceipt*/
			strHDT.fPrintBankReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintCustReceipt*/
			strHDT.fPrintCustReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintMercReceipt*/
			strHDT.fPrintMercReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintVoidBankReceipt*/
			strHDT.fPrintVoidBankReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintVoidCustReceipt*/
			strHDT.fPrintVoidCustReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintVoidMercReceipt*/
			strHDT.fPrintVoidMercReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/*BDO: Parameterized receipt printing - end*/

			/* BDO: Tip Allow flag moved to HDT - start -- jzg */
			/*fHDTTipAllow*/
			strHDT.fHDTTipAllow = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO: Tip Allow flag moved to HDT - end -- jzg */

			/* BDO PHASE 2:[Flag for auto delete reversal file if host does not respond] -- sidumili */
			/*fAutoDelReversal*/
				strHDT.fAutoDelReversal = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO PHASE 2:[Flag for auto delete reversal file if host does not respond] -- sidumili */

			/* BDO PHASE 2:[Reversal Tries] -- sidumili */
				strHDT.inReversalTries = sqlite3_column_int(stmt,inStmtSeq +=1);
			/* BDO PHASE 2:[Reversal Tries] -- sidumili */

			/*fHDTTipAllow*/
			strHDT.fBinVerEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
				
			/* szDCCRateandLogTraceNo */
			memcpy(strHDT.szDCCRateandLogTraceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);

			/*fTapAndGo*/
			strHDT.fTapAndGo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szDetailReportMask */
			strcpy((char*)strHDT.szDetailReportMask, (char *)sqlite3_column_text(stmt, inStmtSeq +=1));

			/*inIssuerID*/
			strHDT.inIssuerID = sqlite3_column_int(stmt,inStmtSeq +=1);

			//version16
			strHDT.fSendPosSerial = sqlite3_column_int(stmt,inStmtSeq +=1);

			
			
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	#if 0
	sqlite3_close(db);
	#endif
	
	//vdDebug_LogPrintf("HDTREAD %d", inResult);

    memset(szGlobalAPName, 0x00, sizeof(szGlobalAPName));
	strcpy(szGlobalAPName, strHDT.szAPName);

    return(inResult);
}

int inHDTSave(int inSeekCnt)
{
	int result;
	//char *sql = "UPDATE HDT SET inHostIndex = ? , szTPDU = ? ,szNII = ? ,fHostEnable = ? ,szTraceNo = ? ,fSignOn = ?,inFailedREV = ?,inNumAdv = ?, fPrintFooterLogo = ?, fPrintBankReceipt = ?, fPrintCustReceipt = ?, fPrintMercReceipt = ?, fPrintVoidBankReceipt = ?, fPrintVoidCustReceipt = ?, fPrintVoidMercReceipt = ? WHERE  HDTid = ?";
	char *sql = "UPDATE HDT SET inHostIndex = ? , szNII = ? ,fHostEnable = ? ,szTraceNo = ? ,fSignOn = ?,inFailedREV = ?,inNumAdv = ?, fPrintFooterLogo = ?, fPrintBankReceipt = ?, fPrintCustReceipt = ?, fPrintMercReceipt = ?, fPrintVoidBankReceipt = ?, fPrintVoidCustReceipt = ?, fPrintVoidMercReceipt = ?, fTapAndGo = ?, fSendPosSerial = ?, inReversalTries = ?  WHERE  HDTid = ?";

	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

	vdSetJournalModeOff();

	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}
	inStmtSeq = 0;
    /*inHostIndex*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.inHostIndex);
	/*szTPDU*/
	//result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strHDT.szTPDU, 5, SQLITE_STATIC);
	/* szNII*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strHDT.szNII, 2, SQLITE_STATIC);
	/* fHostEnable*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fHostEnable);

	/* szTraceNo*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strHDT.szTraceNo, 3, SQLITE_STATIC);
	/* fSignOn */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fSignOn);

	/*inFailedREV*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.inFailedREV);

    /*inNumAdv*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.inNumAdv);
			
	//sidumili: Issue#: 000135
	/* fPrintFooterLogo */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintFooterLogo);	

	/*BDO: Parameterized receipt printing - start*/
	/* fPrintBankReceipt */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintBankReceipt);
	 
	/* fPrintCustReceipt */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintCustReceipt);
	 
	/* fPrintMercReceipt */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintMercReceipt);
	 	
	/* fPrintVoidBankReceipt */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintVoidBankReceipt);
	 
	/* fPrintVoidCustReceipt */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintVoidCustReceipt);
	 
	/* fPrintVoidMercReceipt */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintVoidMercReceipt);
	/*BDO: Parameterized receipt printing - end*/

	/*fTapAndGo*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fTapAndGo);

	//version16
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fSendPosSerial);

	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.inReversalTries);


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

int inHDTSaveEx(int inSeekCnt)
{
	int result;
	//char *sql = "UPDATE HDT SET inHostIndex = ? , szTPDU = ? ,szNII = ? ,fHostEnable = ? ,szTraceNo = ? ,fSignOn = ?,inFailedREV = ?,inNumAdv = ?, fPrintFooterLogo = ?, fPrintBankReceipt = ?, fPrintCustReceipt = ?, fPrintMercReceipt = ?, fPrintVoidBankReceipt = ?, fPrintVoidCustReceipt = ?, fPrintVoidMercReceipt = ? WHERE  HDTid = ?";
	char *sql = "UPDATE HDT SET inHostIndex = ? , szNII = ? ,fHostEnable = ? ,szTraceNo = ? ,fSignOn = ?,inFailedREV = ?,inNumAdv = ?, fPrintFooterLogo = ?, fPrintBankReceipt = ?, fPrintCustReceipt = ?, fPrintMercReceipt = ?, fPrintVoidBankReceipt = ?, fPrintVoidCustReceipt = ?, fPrintVoidMercReceipt = ?, fTapAndGo = ?, fSendPosSerial = ? WHERE  HDTid = ?";
#if 0
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
#endif
	vdSetJournalModeOff();

	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}
	inStmtSeq = 0;
    /*inHostIndex*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.inHostIndex);
	/*szTPDU*/
	//result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strHDT.szTPDU, 5, SQLITE_STATIC);
	/* szNII*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strHDT.szNII, 2, SQLITE_STATIC);
	/* fHostEnable*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fHostEnable);

	/* szTraceNo*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strHDT.szTraceNo, 3, SQLITE_STATIC);
	/* fSignOn */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fSignOn);

	/*inFailedREV*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.inFailedREV);

    /*inNumAdv*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.inNumAdv);
			
	//sidumili: Issue#: 000135
	/* fPrintFooterLogo */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintFooterLogo);	

	/*BDO: Parameterized receipt printing - start*/
	/* fPrintBankReceipt */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintBankReceipt);
	 
	/* fPrintCustReceipt */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintCustReceipt);
	 
	/* fPrintMercReceipt */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintMercReceipt);
	 	
	/* fPrintVoidBankReceipt */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintVoidBankReceipt);
	 
	/* fPrintVoidCustReceipt */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintVoidCustReceipt);
	 
	/* fPrintVoidMercReceipt */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintVoidMercReceipt);
	/*BDO: Parameterized receipt printing - end*/

	/*fTapAndGo*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fTapAndGo);

	//version16
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fSendPosSerial);

	result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);

	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
#if 0
	sqlite3_close(db);
#endif

	return(d_OK);
}

int inHDTSaveFailedRev(int inSeekCnt)
{
	int result;
	//char *sql = "UPDATE HDT SET inHostIndex = ? , szNII = ? ,fHostEnable = ? ,szTraceNo = ? ,fSignOn = ?,inFailedREV = ?,inNumAdv = ?, fPrintFooterLogo = ?, fPrintBankReceipt = ?, fPrintCustReceipt = ?, fPrintMercReceipt = ?, fPrintVoidBankReceipt = ?, fPrintVoidCustReceipt = ?, fPrintVoidMercReceipt = ?, fTapAndGo = ? WHERE  HDTid = ?";
    char *sql = "UPDATE HDT SET inFailedREV = ? WHERE  HDTid = ?";
    #if 0
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
    #endif
	vdSetJournalModeOff();

	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}
	inStmtSeq = 0;

	/*inFailedREV*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.inFailedREV);

	result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);

	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	#if 0
	sqlite3_close(db);
    #endif
	return(d_OK);
}

//REMOVE FOR SM PARTNER
//#define TRUNC_PAN_READING
int inCDTReadMulti(char *szPAN, int *inFindRecordNum)
{
	int result;
	int inResult = d_NO;
	char *sql; 
	int inDBResult = 0;
	char szTemp[16];
	int inPAN, inCount=0, inIndex=0;
    char szTempSQL[512+1];

    memset(szTempSQL, 0, sizeof(szTempSQL));
	sql=&szTempSQL;
	
    if(strTCT.fATPBinRoute == TRUE)
	    strcpy(szTempSQL, "SELECT szPANLo, szPANHi, szCardLabel, inType, inMinPANDigit, inMaxPANDigit, inCVV_II, InFloorLimitAmount, fExpDtReqd,  fPinpadRequired, fManEntry, fCardPresent, fChkServiceCode, fluhnCheck, fCDTEnable, IITid, HDTid, CDTid, fInstallmentEnable, inInstGroup, fDualCurrencyEnable, fFleetCard, fPANCatchAll, fDCCEnable FROM CDT WHERE ? BETWEEN szPANLo AND szPANHi AND fCDTATPEnable= ?");
    else
	    strcpy(szTempSQL, "SELECT szPANLo, szPANHi, szCardLabel, inType, inMinPANDigit, inMaxPANDigit, inCVV_II, InFloorLimitAmount, fExpDtReqd,  fPinpadRequired, fManEntry, fCardPresent, fChkServiceCode, fluhnCheck, fCDTEnable, IITid, HDTid, CDTid, fInstallmentEnable, inInstGroup, fDualCurrencyEnable, fFleetCard, fPANCatchAll, fDCCEnable FROM CDT WHERE ? BETWEEN szPANLo AND szPANHi AND fCDTEnable= ?");

	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	inDBResult = sqlite3_exec( db, "begin", 0, 0, NULL );
	vdDebug_LogPrintf("inCDTRead,sqlite3_exec[%d]",inDBResult);
	
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}
#ifdef TRUNC_PAN_READING
	memcpy(szTemp, szPAN, 8);
	szTemp[8]=0;
	inPAN = atoi(szTemp);
	vdDebug_LogPrintf("inPAN = %d",inPAN);
#else
	memcpy(szTemp, szPAN, 12);
	szTemp[12]=0;
#endif

	inStmtSeq = 0;

#ifdef TRUNC_PAN_READING
	sqlite3_bind_int(stmt, inStmtSeq +=1, inPAN);
#else
	sqlite3_bind_text(stmt, inStmtSeq +=1, szTemp, strlen(szTemp), SQLITE_STATIC);
#endif

	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);//fCDTEnable = 1

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		vdDebug_LogPrintf("inCDTRead,result[%d]SQLITE_ROW[%d]",result,SQLITE_ROW);
		
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

		    /*szPANLo*/
		     strcpy(strMCDT[inCount].szPANLo, sqlite3_column_text(stmt,inStmtSeq));

		    /*szPANHi*/
		     strcpy(strMCDT[inCount].szPANHi, sqlite3_column_text(stmt,inStmtSeq +=1));

		    /*szCardLabel*/
		    strcpy(strMCDT[inCount].szCardLabel, sqlite3_column_text(stmt,inStmtSeq +=1));

		    /*inType*/
			strMCDT[inCount].inType = sqlite3_column_int(stmt,inStmtSeq +=1);
			
			/*inMinPANDigit*/
		    strMCDT[inCount].inMinPANDigit = sqlite3_column_int(stmt,inStmtSeq +=1);
			
			/*inMaxPANDigit*/
		    strMCDT[inCount].inMaxPANDigit = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*inCVV_II*/
		    strMCDT[inCount].inCVV_II = sqlite3_column_int(stmt,inStmtSeq +=1);

            
			/*InFloorLimitAmount*/
			strMCDT[inCount].InFloorLimitAmount = sqlite3_column_double(stmt,inStmtSeq +=1 );

			
			/*fExpDtReqd*/
		    strMCDT[inCount].fExpDtReqd = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			
			
			/*fPinpadRequired*/
		    strMCDT[inCount].fPinpadRequired = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

				
			/*fManEntry*/
		    strMCDT[inCount].fManEntry = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		    /*fCardPresent*/
		    strMCDT[inCount].fCardPresent = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			
		    /*fChkServiceCode*/
		    strMCDT[inCount].fChkServiceCode =fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fluhnCheck */
			strMCDT[inCount].fluhnCheck = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fCDTEnable*/
			strMCDT[inCount].fCDTEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));		

            /*IITid*/
		    strMCDT[inCount].IITid = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* HDTid*/
			strMCDT[inCount].HDTid = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* CDTid*/
			strMCDT[inCount].CDTid = sqlite3_column_int(stmt,inStmtSeq +=1);


			//gcitra
			/*fInstallmentEnable*/
			strMCDT[inCount].fInstallmentEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));		

			/*inInstGroup*/
			strMCDT[inCount].inInstGroup = sqlite3_column_double(stmt,inStmtSeq +=1 );
			//gcitra		

			//1026
            /*fDualCurrencyEnable*/
			strMCDT[inCount].fDualCurrencyEnable = sqlite3_column_double(stmt,inStmtSeq +=1 );

			/* BDO CLG: Fleet card support - start -- jzg */
			/*fFleetCard*/
			strMCDT[inCount].fFleetCard = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO CLG: Fleet card support - end -- jzg */

			
			/*fPANCatchAll - add to check if BIN is CATCH all - will be used for DEBIT Paypass*/
			strMCDT[inCount].fPANCatchAll = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
			/*fDCCEnable*/
					strMCDT[inCount].fDCCEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			inCount ++;
			if(inCount >=10)
				break;
		}
	} while (result == SQLITE_ROW);
  
  *inFindRecordNum = inCount;
  vdDebug_LogPrintf("inCDTReadMulti Record=%d",*inFindRecordNum);
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inResult);
}

int inCDTRead(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql; 
	int inDBResult = 0;	

    char szTempSQL[512+1];

    memset(szTempSQL, 0, sizeof(szTempSQL));
	sql=&szTempSQL;
	
    if(strTCT.fATPBinRoute == TRUE)
	    strcpy(szTempSQL, "SELECT szPANLo, szPANHi, szCardLabel, inType, inMinPANDigit, inMaxPANDigit, inCVV_II, InFloorLimitAmount, fExpDtReqd,  fPinpadRequired, fManEntry, fCardPresent, fChkServiceCode, fluhnCheck, fCDTEnable, IITid, HDTid, fInstallmentEnable, inInstGroup, fDualCurrencyEnable, inDualCurrencyHost, fFleetCard, fPANCatchAll, fBalInqAllowed, fDCCEnable FROM CDT WHERE CDTid = ? AND fCDTATPEnable= ?");
    else
	    strcpy(szTempSQL, "SELECT szPANLo, szPANHi, szCardLabel, inType, inMinPANDigit, inMaxPANDigit, inCVV_II, InFloorLimitAmount, fExpDtReqd,  fPinpadRequired, fManEntry, fCardPresent, fChkServiceCode, fluhnCheck, fCDTEnable, IITid, HDTid, fInstallmentEnable, inInstGroup, fDualCurrencyEnable, inDualCurrencyHost, fFleetCard, fPANCatchAll, fBalInqAllowed, fDCCEnable FROM CDT WHERE CDTid = ? AND fCDTEnable= ?");
	
	if (fInstApp == TRUE){
		result = inInstallmentCDTRead(inSeekCnt);
		return result;
	}

	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	
	inDBResult = sqlite3_exec( db, "begin", 0, 0, NULL );
	vdDebug_LogPrintf("inCDTRead,sqlite3_exec[%d]",inDBResult);

	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);//fCDTEnable = 1

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		vdDebug_LogPrintf("inCDTRead,result[%d]SQLITE_ROW[%d]",result,SQLITE_ROW);

		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			/*szPANLo*/
			strcpy(strCDT.szPANLo, sqlite3_column_text(stmt,inStmtSeq));

			/*szPANHi*/
			strcpy(strCDT.szPANHi, sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szCardLabel*/
			strcpy(strCDT.szCardLabel, sqlite3_column_text(stmt,inStmtSeq +=1));

			/*inType*/
			strCDT.inType = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*inMinPANDigit*/
			strCDT.inMinPANDigit = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*inMaxPANDigit*/
			strCDT.inMaxPANDigit = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*inCVV_II*/
			strCDT.inCVV_II = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*InFloorLimitAmount*/
			strCDT.InFloorLimitAmount = sqlite3_column_double(stmt,inStmtSeq +=1 );

			/*fExpDtReqd*/
			strCDT.fExpDtReqd = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPinpadRequired*/
			strCDT.fPinpadRequired = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fManEntry*/
			strCDT.fManEntry = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fCardPresent*/
			strCDT.fCardPresent = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fChkServiceCode*/
			strCDT.fChkServiceCode =fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fluhnCheck */
			strCDT.fluhnCheck = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fCDTEnable*/
			strCDT.fCDTEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));		

			/*IITid*/
			strCDT.IITid = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* HDTid*/
			strCDT.HDTid = sqlite3_column_int(stmt,inStmtSeq +=1);	

			//gcitra
			/*fInstallmentEnable*/
			strCDT.fInstallmentEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));		

			/*inInstGroup*/
			strCDT.inInstGroup = sqlite3_column_double(stmt,inStmtSeq +=1 );
			//gcitra

			//1026
			/*fDualCurrencyEnable*/
			strCDT.fDualCurrencyEnable = sqlite3_column_double(stmt,inStmtSeq +=1 );

			/* BDO: Added dual currency to CDT -- jzg */
			strCDT.inDualCurrencyHost = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* BDO CLG: Fleet card support - start -- jzg */
			/*fFleetCard*/
			strCDT.fFleetCard = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO CLG: Fleet card support - end -- jzg */

			/*fPANCatchAll - add to check if BIN is CATCH all - will be used for DEBIT Paypass*/
			strCDT.fPANCatchAll = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fBalInqAllowed*/
			strCDT.fBalInqAllowed = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fDCCEnable*/
			strCDT.fDCCEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inResult);
}

int inCDTMAX(void)
{
	int result;	
	char *sql = "SELECT MAX(CDTid) FROM CDT";
	int inMaxValue = 0;
	int inDBResult = 0;
	
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

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;

			inMaxValue = sqlite3_column_int(stmt,inStmtSeq);
		}
	} while (result == SQLITE_ROW);
    
	inDBResult = sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	
	vdDebug_LogPrintf("inCDTRead,inDBResult[%d]result[%d]",inDBResult,result);
	inDBResult = sqlite3_finalize(stmt);
	
	vdDebug_LogPrintf("inCDTRead,sqlite3_finalize[%d]",inDBResult);
	inDBResult = sqlite3_close(db);
	vdDebug_LogPrintf("inCDTRead,sqlite3_close[%d]",inDBResult);

	return(inMaxValue);
}

int inEnableDCTBIN(int fBINEnable, int inSeekCount)
{
    int result;
    //char *sql = "UPDATE HDT set fHostEnable=? where inHostIndex=1 or inHostIndex=2 or inHostIndex=3 or inHostIndex=4 or inHostIndex=10 or inHostIndex=12";
    char *sql = "UPDATE CDT set fCDTEnable=? where CDTid=?";
    
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
    
    inStmtSeq = 0;    
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, fBINEnable);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCount);
	
    
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


int inIITRead(int inSeekCnt)
{
	int result;
	int inResult = d_NO;

	char *sql = "SELECT inIssuerNumber, szIssuerAbbrev, szIssuerLabel, szPANFormat, szMaskBankCopy, szMaskMerchantCopy, szMaskCustomerCopy, szMaskExpireDate, szMaskDisplay, fMerchExpDate, fCustExpDate, fMerchPANFormat, inCheckHost, ulTransSeqCounter, fPolicyNumber, inPolicyNumMaxChar, szIssuerLogo, fLast4Digits, fQuasiCash, fGetPolicyNumber, fNSR, szNSRLimit, fNSRCustCopy, fBalInqAllowed, fMaskPanDisplay, szPrintOption, inIssuerID, fSMErrorRC86, fSMPrintFooterMsg, fEMVFallbackEnable, szInstCVMLimit, szDCCCVMLimit FROM IIT WHERE IITid = ?";
		
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
		vdDebug_LogPrintf("IIT read result[%d]", result); 
		vdDebug_LogPrintf("SQLITE_ROW[%d]", SQLITE_ROW); 
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			/*inIssuerNumber*/
			strIIT.inIssuerNumber = sqlite3_column_int(stmt, inStmtSeq );
			vdDebug_LogPrintf("inIssuerNumber [%d]", strIIT.inIssuerNumber);
			/* szIssuerAbbrev */			
			strcpy((char*)strIIT.szIssuerAbbrev, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
				
			/* szIssuerLabel */			
			strcpy((char*)strIIT.szIssuerLabel, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szPANFormat*/
			strcpy((char*)strIIT.szPANFormat, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szMaskBankCopy*/
			strcpy((char*)strIIT.szMaskBankCopy, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 )); //BDO: Enable PAN Masking for each receipt -- jzg

			/*szMaskMerchantCopy*/
			strcpy((char*)strIIT.szMaskMerchantCopy, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szMaskCustomerCopy*/
			strcpy((char*)strIIT.szMaskCustomerCopy, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szMaskExpireDate*/
			strcpy((char*)strIIT.szMaskExpireDate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szMaskDisplay*/
			strcpy((char*)strIIT.szMaskDisplay, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fMerchExpDate */
			strIIT.fMerchExpDate = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fCustExpDate //5*/
			strIIT.fCustExpDate = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fMerchPANFormat*/
			strIIT.fMerchPANFormat = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));	

            /*inCheckHost*/
		    strIIT.inCheckHost = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*ulTransSeqCounter*/
			strIIT.ulTransSeqCounter = sqlite3_column_double(stmt,inStmtSeq +=1);

			//gcitra
			/*fPolicyNumber*/
			strIIT.fPolicyNumber = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/*inPolicyNumMaxChar*/
			strIIT.inPolicyNumMaxChar = sqlite3_column_int(stmt,inStmtSeq +=1 );
			//gcitra

			//Display Issuer logo: get issuer logo filename -- jzg
			strcpy((char*)strIIT.szIssuerLogo, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* BDO: Last 4 PAN digit checking - start -- jzg */
			/* fLast4Digits */
			strIIT.fLast4Digits = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO: Last 4 PAN digit checking - end -- jzg */

			/* BDO: Quasi should be parametrized per issuer - start -- jzg */
			/* fQuasiCash */
      strIIT.fQuasiCash = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO: Quasi should be parametrized per issuer - end -- jzg */


			/* BDO-00060: Policy number should be per issuer -- jzg */
			/* fGetPolicyNumber */
			strIIT.fGetPolicyNumber = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /*fNSR*/
            strIIT.fNSR = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            
            /* szNSRLimit*/
            strcpy((char*)strIIT.szNSRLimit, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* fNSRCustCopy*/
			strIIT.fNSRCustCopy = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* fBalInqAllowed*/
			strIIT.fBalInqAllowed = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/*fMaskPanDisplay*/

			strIIT.fMaskPanDisplay = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			strcpy((char*)strIIT.szPrintOption, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inIssuerID*/
		    strIIT.inIssuerID = sqlite3_column_int(stmt,inStmtSeq +=1);

			strIIT.fSMErrorRC86 = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fSMPrintFooterMsg*/
			strIIT.fSMPrintFooterMsg = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fEMVFallbackEnable*/
			strIIT.fEMVFallbackEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));


			/* szInstCVMLimit*/
            strcpy((char*)strIIT.szInstCVMLimit, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szDCCCVMLimit*/
            strcpy((char*)strIIT.szDCCCVMLimit, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));


			
        }	
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inResult);
}

int inIITSave(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE IIT SET szIssuerAbbrev = ?, szIssuerLabel = ?, szPANFormat = ?, szMaskBankCopy = ?, szMaskMerchantCopy = ?, szMaskCustomerCopy = ?, szMaskExpireDate = ?, szMaskDisplay = ?, fMerchExpDate = ?, fCustExpDate = ?, fMerchPANFormat = ?, ulTransSeqCounter = ?, fPolicyNumber = ?, inPolicyNumMaxChar = ?, szIssuerLogo = ?, fSMPrintFooterMsg = ?, fEMVFallbackEnable = ? WHERE  IITid = ?";
		
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

	vdSetJournalModeOff();

	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
	/* szIssuerAbbrev */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strIIT.szIssuerAbbrev, strlen((char*)strIIT.szIssuerAbbrev), SQLITE_STATIC);
	/* szIssuerLabel */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strIIT.szIssuerLabel, strlen((char*)strIIT.szIssuerLabel), SQLITE_STATIC);
	/* szPANFormat*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strIIT.szPANFormat, strlen((char*)strIIT.szPANFormat), SQLITE_STATIC);
	/* szMaskBankCopy*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strIIT.szMaskBankCopy, strlen((char*)strIIT.szMaskBankCopy), SQLITE_STATIC); //BDO: Enable PAN Masking for each receipt -- jzg
	/* szMaskMerchantCopy*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strIIT.szMaskMerchantCopy, strlen((char*)strIIT.szMaskMerchantCopy), SQLITE_STATIC);
	/* szMaskCustomerCopy*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strIIT.szMaskCustomerCopy, strlen((char*)strIIT.szMaskCustomerCopy), SQLITE_STATIC);
	/* szMaskExpireDate*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strIIT.szMaskExpireDate, strlen((char*)strIIT.szMaskExpireDate), SQLITE_STATIC);
	/* szMaskDisplay*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strIIT.szMaskDisplay, strlen((char*)strIIT.szMaskDisplay), SQLITE_STATIC);
	/*fMerchExpDate*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strIIT.fMerchExpDate);
	/* fCustExpDate */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strIIT.fCustExpDate);
	/* fMerchPANFormat */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strIIT.fMerchPANFormat);
	/* ulTransSeqCounter */
    if(strIIT.ulTransSeqCounter >= 0xFFFFFE)
       strIIT.ulTransSeqCounter = 1;
	result = sqlite3_bind_double(stmt, inStmtSeq +=1, strIIT.ulTransSeqCounter);
    vdDebug_LogPrintf(" strIIT.ulTransSeqCounter[%d] result[%d]",strIIT.ulTransSeqCounter, result);

	//gcitra
	/*fPolicyNumber*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strIIT.fPolicyNumber);

	/*inPolicyNumMaxChar*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strIIT.inPolicyNumMaxChar);
	//gcitra

	//Display Issuer logo: save issuer logo filename -- jzg
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strIIT.szIssuerLogo, strlen((char*)strIIT.szIssuerLogo), SQLITE_STATIC);

	/*fSMPrintFooterMsg*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strIIT.fSMPrintFooterMsg);

	/*fEMVFallbackEnable*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strIIT.fEMVFallbackEnable);

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


int inPCTNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM PCT";
	int inCount = 0;
	
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


int inPCTRead(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT szRctHdr1, szRctHdr2, szRctHdr3, szRctHdr4, szRctHdr5, szRctFoot1, szRctFoot2, szRctFoot3, inPrinterType, inPrintOption, inCustCopyOption, fPrintDisclaimer, fEnablePrinter FROM PCT WHERE PCTid = ?";
		
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
			inResult = d_OK;
			inStmtSeq = 0;

			/* szRctHdr1 */			
			strcpy((char*)strPCT.szRctHdr1, (char *)sqlite3_column_text(stmt,inStmtSeq ));
			
			/* szRctHdr2 */			
			strcpy((char*)strPCT.szRctHdr2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szRctHdr3*/
			strcpy((char*)strPCT.szRctHdr3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctHdr4 */			
			strcpy((char*)strPCT.szRctHdr4, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szRctHdr5*/
			strcpy((char*)strPCT.szRctHdr5, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctFoot1 */			
			strcpy((char*)strPCT.szRctFoot1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szRctFoot2*/
			strcpy((char*)strPCT.szRctFoot2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctFoot3 */			
			strcpy((char*)strPCT.szRctFoot3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inPrinterType*/
			strPCT.inPrinterType = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*inPrintOption*/
			strPCT.inPrintOption = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*inCustCopyOption*/
			strPCT.inCustCopyOption = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/* fPrintDisclaimer*/
			strPCT.fPrintDisclaimer = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fEnablePrinter*/
			strPCT.fEnablePrinter = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inResult);
}


int inPCTSave(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE PCT SET szRctHdr1 = ?, szRctHdr2 = ?, szRctHdr3 = ?, szRctHdr4 = ?, szRctHdr5 = ?, szRctFoot1 = ?, szRctFoot2 = ?, szRctFoot3 = ?, inPrinterType = ?, inPrintOption = ?, inCustCopyOption = ?, fPrintDisclaimer = ?, fEnablePrinter = ? WHERE  PCTid = ?";
		
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

	inStmtSeq = 0;
	
	/* szRctHdr1 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPCT.szRctHdr1, strlen((char*)strPCT.szRctHdr1), SQLITE_STATIC);
	/* szRctHdr2 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPCT.szRctHdr2, strlen((char*)strPCT.szRctHdr2), SQLITE_STATIC);
	/* szRctHdr3 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPCT.szRctHdr3, strlen((char*)strPCT.szRctHdr3), SQLITE_STATIC);
	/* szRctHdr4 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPCT.szRctHdr4, strlen((char*)strPCT.szRctHdr4), SQLITE_STATIC);
	/* szRctHdr5 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPCT.szRctHdr5, strlen((char*)strPCT.szRctHdr5), SQLITE_STATIC);
	/* szRctFoot1 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPCT.szRctFoot1, strlen((char*)strPCT.szRctFoot1), SQLITE_STATIC);
	/* szRctFoot2 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPCT.szRctFoot2, strlen((char*)strPCT.szRctFoot2), SQLITE_STATIC);
	/* szRctFoot3 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPCT.szRctFoot3, strlen((char*)strPCT.szRctFoot3), SQLITE_STATIC);
	/*inPrinterType*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strPCT.inPrinterType);
	/*inPrintOption*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strPCT.inPrintOption);
	/*inCustCopyOption*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strPCT.inCustCopyOption);
	/* fPrintDisclaimer */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strPCT.fPrintDisclaimer);
	/* fEnablePrinter */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strPCT.fEnablePrinter);
	
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



int inCSTNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM CST";
	int inCount = 0;
	
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


int inCSTRead(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT inCurrencyIndex, szCurSymbol, szCurCode, szAmountFormat, inMinorUnit FROM CST WHERE CSTid = ?";
		
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
			inResult = d_OK;
			inStmtSeq = 0;

			/* inCurrencyIndex */
			strCST.inCurrencyIndex = sqlite3_column_int(stmt,inStmtSeq);
				
			/* szCurSymbol */			
			strcpy((char*)strCST.szCurSymbol, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szCurCode*/
			strcpy((char*)strCST.szCurCode, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			strcpy((char*)strCST.szAmountFormat, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));	

			/* inMinorUnit */
			strCST.inMinorUnit = sqlite3_column_int(stmt,inStmtSeq +=1);
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inResult);
}

int inCSTReadEx(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT inCurrencyIndex, szCurSymbol, szCurCode, szAmountFormat, inMinorUnit FROM CST WHERE CSTid = ?";

	#if 0
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	#endif
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
			inResult = d_OK;
			inStmtSeq = 0;

			/* inCurrencyIndex */
			strCST.inCurrencyIndex = sqlite3_column_int(stmt,inStmtSeq);
				
			/* szCurSymbol */			
			strcpy((char*)strCST.szCurSymbol, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szCurCode*/
			strcpy((char*)strCST.szCurCode, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			strcpy((char*)strCST.szAmountFormat, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));	

			/* inMinorUnit */
			strCST.inMinorUnit = sqlite3_column_int(stmt,inStmtSeq +=1);
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	#if 0
	sqlite3_close(db);
	#endif

    return(inResult);
}


int inCSTSave(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE CST SET inCurrencyIndex = ?, szCurSymbol = ?, szCurCode = ? WHERE  CSTid = ?";
		
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

	inStmtSeq = 0;
	/* inCurrencyIndex */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCST.inCurrencyIndex);
	/* szCurSymbol */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCST.szCurSymbol, strlen((char*)strCST.szCurSymbol), SQLITE_STATIC);
	/* szCurCode */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCST.szCurCode, strlen((char*)strCST.szCurCode), SQLITE_STATIC);

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

int inMMTReadRecord_SettleAll(int inHDTid,int inMITid)
{
	int result;
	int inResult = d_NO;
	/* aaronnino for BDOCLG ver 9.0 fix on issue #00241 added  fManualMMTSettleTrigger, inOnlineMMTSettleTries, inOnlineMMTSettleLimit*/
	char *sql = "SELECT MMTid, szHostName, HDTid, szMerchantName, MITid, szTID, szMID, szATCMD1, szATCMD2, szATCMD3, szATCMD4, szATCMD5, fMustSettFlag, szBatchNo, szRctHdr1,szRctHdr2, szRctHdr3, szRctHdr4, szRctHdr5, szRctFoot1, szRctFoot2, szRctFoot3, fMMTEnable, fEnablePSWD, szPassWord, inSettleStatus,  fManualMMTSettleTrigger, inOnlineMMTSettleTries, inOnlineMMTSettleLimit, fBatchNotEmpty, fPendingReversal FROM MMT WHERE HDTid = ? AND MITid = ? AND fMMTEnable = ? ORDER BY MMTid";
	int incount = 0;
	
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

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inHDTid);
	sqlite3_bind_int(stmt, inStmtSeq +=1, inMITid);
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);
	
	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			/* MMTid */
			strMMT[incount].MMTid = sqlite3_column_int(stmt, inStmtSeq);
			
			/*szHostName*/
			strcpy((char*)strMMT[incount].szHostName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
            
			/* HDTid */
			strMMT[incount].HDTid = sqlite3_column_int(stmt,inStmtSeq +=1 );
				
			/* szMerchantName */			
			strcpy((char*)strMMT[incount].szMerchantName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* MITid */
			strMMT[incount].MITid = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*szTID*/
			strcpy((char*)strMMT[incount].szTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szMID*/
			strcpy((char*)strMMT[incount].szMID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            
			/*szATCMD1*/
			strcpy((char*)strMMT[incount].szATCMD1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD2*/
			strcpy((char*)strMMT[incount].szATCMD2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD3*/
			strcpy((char*)strMMT[incount].szATCMD3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD4*/
			strcpy((char*)strMMT[incount].szATCMD4, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD5*/
			strcpy((char*)strMMT[incount].szATCMD5, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
	
            /* fMustSettFlag */
			strMMT[incount].fMustSettFlag = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
			/*szBatchNo*/
			memcpy(strMMT[incount].szBatchNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);

			/* szRctHdr1 */			
			strcpy((char*)strMMT[incount].szRctHdr1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctHdr2 */			
			strcpy((char*)strMMT[incount].szRctHdr2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctHdr3 */ 		
			strcpy((char*)strMMT[incount].szRctHdr3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctHdr4 */ 		
			strcpy((char*)strMMT[incount].szRctHdr4, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctHdr5 */ 		
			strcpy((char*)strMMT[incount].szRctHdr5, (char *)sqlite3_column_text(stmt,inStmtSeq +=1  ));

			/* szRctFoot1 */ 		
			strcpy((char*)strMMT[incount].szRctFoot1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1  ));

			/* szRctFoot2 */		
			strcpy((char*)strMMT[incount].szRctFoot2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctFoot3 */		
			strcpy((char*)strMMT[incount].szRctFoot3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
      /* fMMTEnable */
			strMMT[incount].fMMTEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
						
			/* fEnablePSWD */
			strMMT[incount].fEnablePSWD = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
						
			/*szPassWord*/
			strcpy((char*)strMMT[incount].szPassWord, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
						
			/* inSettleStatus */
			strMMT[incount].inSettleStatus = sqlite3_column_int(stmt,inStmtSeq +=1 );

			 //aaronnino for BDOCLG ver 9.0 fix on issue #00241 No Manual Settle/Clear Batch prompt after 3 failed start
			/* fManualMMTSettleTrigger */
			strMMT[incount].fManualMMTSettleTrigger = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* inOnlineMMTSettleTries */
			strMMT[incount].inOnlineMMTSettleTries = sqlite3_column_int(stmt,inStmtSeq +=1 );
				/*inOnlineMMTSettleLimit*/
      strMMT[incount].inOnlineMMTSettleLimit = sqlite3_column_int(stmt,inStmtSeq +=1 );
			//aaronnino for BDOCLG ver 9.0 fix on issue #00241 No Manual Settle/Clear Batch prompt after 3 failed end

			/*fBatchNotEmpty*/	
			strMMT[incount].fBatchNotEmpty = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPendingReversal*/
			strMMT[incount].fPendingReversal = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));


		}
	} while (result == SQLITE_ROW);

		sqlite3_exec(db,"commit;",NULL,NULL,NULL);

		sqlite3_finalize(stmt);
		sqlite3_close(db);

		srTransRec.MITid = strMMT[incount].MITid;
		strcpy(srTransRec.szTID, strMMT[incount].szTID);
		strcpy(srTransRec.szMID, strMMT[incount].szMID);
		memcpy(srTransRec.szBatchNo, strMMT[incount].szBatchNo, 4);
		strcpy(srTransRec.szHostLabel, strHDT.szHostLabel);

		return(inResult);
}


int inMMTReadRecord(int inHDTid,int inMITid)
{
	int result;
	int inResult = d_NO;
	/* aaronnino for BDOCLG ver 9.0 fix on issue #00241 added  fManualMMTSettleTrigger, inOnlineMMTSettleTries, inOnlineMMTSettleLimit*/
	char *sql = "SELECT MMTid, szHostName, HDTid, szMerchantName, MITid, szTID, szMID, szATCMD1, szATCMD2, szATCMD3, szATCMD4, szATCMD5, fMustSettFlag, szBatchNo, szRctHdr1,szRctHdr2, szRctHdr3, szRctHdr4, szRctHdr5, szRctFoot1, szRctFoot2, szRctFoot3, fMMTEnable, fEnablePSWD, szPassWord, inSettleStatus, fManualMMTSettleTrigger, inOnlineMMTSettleTries, inOnlineMMTSettleLimit, szSettleDate, inMustSettleNumOfDays, fBatchNotEmpty, fPendingReversal  FROM MMT WHERE HDTid = ? AND MITid = ? AND fMMTEnable = ? ORDER BY MMTid";
	int incount = 0;
	
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

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inHDTid);
	sqlite3_bind_int(stmt, inStmtSeq +=1, inMITid);
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);
	
	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			/* MMTid */
			strMMT[incount].MMTid = sqlite3_column_int(stmt, inStmtSeq);
			
			/*szHostName*/
			strcpy((char*)strMMT[incount].szHostName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
            
			/* HDTid */
			strMMT[incount].HDTid = sqlite3_column_int(stmt,inStmtSeq +=1 );
				
			/* szMerchantName */			
			strcpy((char*)strMMT[incount].szMerchantName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* MITid */
			strMMT[incount].MITid = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*szTID*/
			strcpy((char*)strMMT[incount].szTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szMID*/
			strcpy((char*)strMMT[incount].szMID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            
			/*szATCMD1*/
			strcpy((char*)strMMT[incount].szATCMD1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD2*/
			strcpy((char*)strMMT[incount].szATCMD2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD3*/
			strcpy((char*)strMMT[incount].szATCMD3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD4*/
			strcpy((char*)strMMT[incount].szATCMD4, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD5*/
			strcpy((char*)strMMT[incount].szATCMD5, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
	
            /* fMustSettFlag */
			strMMT[incount].fMustSettFlag = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
			/*szBatchNo*/
			memcpy(strMMT[incount].szBatchNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);

			/* szRctHdr1 */			
			strcpy((char*)strMMT[incount].szRctHdr1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctHdr2 */			
			strcpy((char*)strMMT[incount].szRctHdr2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctHdr3 */ 		
			strcpy((char*)strMMT[incount].szRctHdr3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctHdr4 */ 		
			strcpy((char*)strMMT[incount].szRctHdr4, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctHdr5 */ 		
			strcpy((char*)strMMT[incount].szRctHdr5, (char *)sqlite3_column_text(stmt,inStmtSeq +=1  ));

			/* szRctFoot1 */ 		
			strcpy((char*)strMMT[incount].szRctFoot1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1  ));

			/* szRctFoot2 */		
			strcpy((char*)strMMT[incount].szRctFoot2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctFoot3 */		
			strcpy((char*)strMMT[incount].szRctFoot3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
            /* fMMTEnable */
			strMMT[incount].fMMTEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fEnablePSWD */
			strMMT[incount].fEnablePSWD = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
			/*szPassWord*/
			strcpy((char*)strMMT[incount].szPassWord, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/* inSettleStatus */
			strMMT[incount].inSettleStatus = sqlite3_column_int(stmt,inStmtSeq +=1 );

      //aaronnino for BDOCLG ver 9.0 fix on issue #00241 No Manual Settle/Clear Batch prompt after 3 failed start
			/* fManualMMTSettleTrigger */
			strMMT[incount].fManualMMTSettleTrigger = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* inOnlineMMTSettleTries */
			strMMT[incount].inOnlineMMTSettleTries = sqlite3_column_int(stmt,inStmtSeq +=1 );
				/*inOnlineMMTSettleLimit*/
      strMMT[incount].inOnlineMMTSettleLimit = sqlite3_column_int(stmt,inStmtSeq +=1 );
			//aaronnino for BDOCLG ver 9.0 fix on issue #00241 No Manual Settle/Clear Batch prompt after 3 failed end

#if 0
			//BDO: Added settlement status to settlement report -- jzg
			/* inSettleStatus */
			strMMT[incount].inSettleStatus = sqlite3_column_int(stmt,inStmtSeq +=1 );
#endif
            /*szSettleDate*/
			strcpy((char*)strMMT[incount].szSettleDate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inMustSettleNumOfDays*/
			strMMT[incount].inMustSettleNumOfDays = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*fBatchNotEmpty*/
			strMMT[incount].fBatchNotEmpty = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPendingReversal*/
			strMMT[incount].fPendingReversal = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	
	// patrick add code 20141207
	memcpy(&strMMT[0],&strMMT[incount],sizeof(STRUCT_MMT));
	
	srTransRec.MITid = strMMT[incount].MITid;
	strcpy(srTransRec.szTID, strMMT[incount].szTID);
	strcpy(srTransRec.szMID, strMMT[incount].szMID);
	memcpy(srTransRec.szBatchNo, strMMT[incount].szBatchNo, 4);
	strcpy(srTransRec.szHostLabel, strHDT.szHostLabel);
    
    return(inResult);
}

int inMMTReadRecordEx(int inHDTid,int inMITid)
{
	int result;
	int inResult = d_NO;
	/* aaronnino for BDOCLG ver 9.0 fix on issue #00241 added  fManualMMTSettleTrigger, inOnlineMMTSettleTries, inOnlineMMTSettleLimit*/
	char *sql = "SELECT MMTid, szHostName, HDTid, szMerchantName, MITid, szTID, szMID, szATCMD1, szATCMD2, szATCMD3, szATCMD4, szATCMD5, fMustSettFlag, szBatchNo, szRctHdr1,szRctHdr2, szRctHdr3, szRctHdr4, szRctHdr5, szRctFoot1, szRctFoot2, szRctFoot3, fMMTEnable, fEnablePSWD, szPassWord, inSettleStatus, fManualMMTSettleTrigger, inOnlineMMTSettleTries, inOnlineMMTSettleLimit, szSettleDate, inMustSettleNumOfDays, fBatchNotEmpty, fPendingReversal  FROM MMT WHERE HDTid = ? AND MITid = ? AND fMMTEnable = ? ORDER BY MMTid";
	int incount = 0;

	#if 0
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	#endif
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inHDTid);
	sqlite3_bind_int(stmt, inStmtSeq +=1, inMITid);
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);
	
	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			/* MMTid */
			strMMT[incount].MMTid = sqlite3_column_int(stmt, inStmtSeq);
			
			/*szHostName*/
			strcpy((char*)strMMT[incount].szHostName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
            
			/* HDTid */
			strMMT[incount].HDTid = sqlite3_column_int(stmt,inStmtSeq +=1 );
				
			/* szMerchantName */			
			strcpy((char*)strMMT[incount].szMerchantName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* MITid */
			strMMT[incount].MITid = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*szTID*/
			strcpy((char*)strMMT[incount].szTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szMID*/
			strcpy((char*)strMMT[incount].szMID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            
			/*szATCMD1*/
			strcpy((char*)strMMT[incount].szATCMD1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD2*/
			strcpy((char*)strMMT[incount].szATCMD2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD3*/
			strcpy((char*)strMMT[incount].szATCMD3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD4*/
			strcpy((char*)strMMT[incount].szATCMD4, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD5*/
			strcpy((char*)strMMT[incount].szATCMD5, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
	
            /* fMustSettFlag */
			strMMT[incount].fMustSettFlag = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
			/*szBatchNo*/
			memcpy(strMMT[incount].szBatchNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);

			/* szRctHdr1 */			
			strcpy((char*)strMMT[incount].szRctHdr1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctHdr2 */			
			strcpy((char*)strMMT[incount].szRctHdr2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctHdr3 */ 		
			strcpy((char*)strMMT[incount].szRctHdr3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctHdr4 */ 		
			strcpy((char*)strMMT[incount].szRctHdr4, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctHdr5 */ 		
			strcpy((char*)strMMT[incount].szRctHdr5, (char *)sqlite3_column_text(stmt,inStmtSeq +=1  ));

			/* szRctFoot1 */ 		
			strcpy((char*)strMMT[incount].szRctFoot1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1  ));

			/* szRctFoot2 */		
			strcpy((char*)strMMT[incount].szRctFoot2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctFoot3 */		
			strcpy((char*)strMMT[incount].szRctFoot3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
            /* fMMTEnable */
			strMMT[incount].fMMTEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fEnablePSWD */
			strMMT[incount].fEnablePSWD = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
			/*szPassWord*/
			strcpy((char*)strMMT[incount].szPassWord, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/* inSettleStatus */
			strMMT[incount].inSettleStatus = sqlite3_column_int(stmt,inStmtSeq +=1 );

      //aaronnino for BDOCLG ver 9.0 fix on issue #00241 No Manual Settle/Clear Batch prompt after 3 failed start
			/* fManualMMTSettleTrigger */
			strMMT[incount].fManualMMTSettleTrigger = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* inOnlineMMTSettleTries */
			strMMT[incount].inOnlineMMTSettleTries = sqlite3_column_int(stmt,inStmtSeq +=1 );
				/*inOnlineMMTSettleLimit*/
      strMMT[incount].inOnlineMMTSettleLimit = sqlite3_column_int(stmt,inStmtSeq +=1 );
			//aaronnino for BDOCLG ver 9.0 fix on issue #00241 No Manual Settle/Clear Batch prompt after 3 failed end

#if 0
			//BDO: Added settlement status to settlement report -- jzg
			/* inSettleStatus */
			strMMT[incount].inSettleStatus = sqlite3_column_int(stmt,inStmtSeq +=1 );
#endif
            /*szSettleDate*/
			strcpy((char*)strMMT[incount].szSettleDate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inMustSettleNumOfDays*/
			strMMT[incount].inMustSettleNumOfDays = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*fBatchNotEmpty*/
			strMMT[incount].fBatchNotEmpty = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPendingReversal*/
			strMMT[incount].fPendingReversal = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	#if 0
	sqlite3_close(db);
	#endif
	
	// patrick add code 20141207
	memcpy(&strMMT[0],&strMMT[incount],sizeof(STRUCT_MMT));
	
	srTransRec.MITid = strMMT[incount].MITid;
	strcpy(srTransRec.szTID, strMMT[incount].szTID);
	strcpy(srTransRec.szMID, strMMT[incount].szMID);
	memcpy(srTransRec.szBatchNo, strMMT[incount].szBatchNo, 4);
	strcpy(srTransRec.szHostLabel, strHDT.szHostLabel);
    
    return(inResult);
}

int inMMTReadNumofRecords(int inSeekCnt,int *inFindRecordNum)
{
	int result;
	/* aaronnino for BDOCLG ver 9.0 fix on issue #00241 added  fManualMMTSettleTrigger, inOnlineMMTSettleTries, inOnlineMMTSettleLimit*/
	char *sql = "SELECT MMTid, szHostName, HDTid, szMerchantName, MITid, szTID, szMID, szATCMD1, szATCMD2, szATCMD3, szATCMD4, szATCMD5, fMustSettFlag, szBatchNo, szRctHdr1,szRctHdr2, szRctHdr3, szRctHdr4, szRctHdr5, szRctFoot1, szRctFoot2, szRctFoot3, fMMTEnable,fEnablePSWD, szPassWord,inSettleStatus, fManualMMTSettleTrigger, inOnlineMMTSettleTries, inOnlineMMTSettleLimit, szSettleDate, inMustSettleNumOfDays, fBatchNotEmpty, fPendingReversal  FROM MMT WHERE HDTid = ? AND fMMTEnable = ? ORDER BY MMTid";
	//char *sql = "SELECT MMTid, szHostName, HDTid, szMerchantName, MITid, szTID, szMID, szATCMD1, szATCMD2, szATCMD3, szATCMD4, szATCMD5, fMustSettFlag, szBatchNo, szRctHdr1,szRctHdr2, szRctHdr3, szRctHdr4, szRctHdr5, szRctFoot1, szRctFoot2, szRctFoot3, fMMTEnable,fEnablePSWD, szPassWord,inSettleStatus FROM MMT WHERE fMMTEnable = ? ORDER BY MMTid";
	int incount = 0;
	
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

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		vdDebug_LogPrintf("inMMTReadNumofRecords=[%d]",result);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;

			/* MMTid */
			strMMT[incount].MMTid = sqlite3_column_int(stmt, inStmtSeq);

			/*szHostName*/
			strcpy((char*)strMMT[incount].szHostName, (char *)sqlite3_column_text(stmt, inStmtSeq +=1 ));
            
			/* HDTid */
			strMMT[incount].HDTid = sqlite3_column_int(stmt,inStmtSeq +=1 );
				
			/* szMerchantName */			
			strcpy((char*)strMMT[incount].szMerchantName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* MITid */
			strMMT[incount].MITid = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*szTID*/
			strcpy((char*)strMMT[incount].szTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szMID*/
			strcpy((char*)strMMT[incount].szMID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szATCMD1*/
			strcpy((char*)strMMT[incount].szATCMD1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD2*/
			strcpy((char*)strMMT[incount].szATCMD2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD3*/
			strcpy((char*)strMMT[incount].szATCMD3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD4*/
			strcpy((char*)strMMT[incount].szATCMD4, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD5*/
			strcpy((char*)strMMT[incount].szATCMD5, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
	
            /* fMustSettFlag */
			strMMT[incount].fMustSettFlag = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
            /*szBatchNo*/
            memcpy(strMMT[incount].szBatchNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);

			/*szRctHdr1*/
			strcpy((char*)strMMT[incount].szRctHdr1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			
			/*szRctHdr2*/
			strcpy((char*)strMMT[incount].szRctHdr2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szRctHdr3*/
			strcpy((char*)strMMT[incount].szRctHdr3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szRctHdr4*/
			strcpy((char*)strMMT[incount].szRctHdr4, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szRctHdr5*/
			strcpy((char*)strMMT[incount].szRctHdr5, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szRctFoot1*/
			strcpy((char*)strMMT[incount].szRctFoot1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szRctFoot2*/
			strcpy((char*)strMMT[incount].szRctFoot2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szRctFoot3*/
			strcpy((char*)strMMT[incount].szRctFoot3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			
            /* fMMTEnable */
			strMMT[incount].fMMTEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fEnablePSWD */
			strMMT[incount].fEnablePSWD = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
			/*szPassWord*/
			strcpy((char*)strMMT[incount].szPassWord, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/* inSettleStatus */
			strMMT[incount].inSettleStatus = sqlite3_column_int(stmt,inStmtSeq +=1 );

			 //aaronnino for BDOCLG ver 9.0 fix on issue #00241 No Manual Settle/Clear Batch prompt after 3 failed start
			/* fManualMMTSettleTrigger */
			strMMT[incount].fManualMMTSettleTrigger = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* inOnlineMMTSettleTries */
			strMMT[incount].inOnlineMMTSettleTries = sqlite3_column_int(stmt,inStmtSeq +=1 );
				/*inOnlineMMTSettleLimit*/
      strMMT[incount].inOnlineMMTSettleLimit = sqlite3_column_int(stmt,inStmtSeq +=1 );
			//aaronnino for BDOCLG ver 9.0 fix on issue #00241 No Manual Settle/Clear Batch prompt after 3 failed end

            /*szSettleDate*/
			strcpy((char*)strMMT[incount].szSettleDate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*inMustSettleNumOfDays*/
			strMMT[incount].inMustSettleNumOfDays = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*fBatchNotEmpty*/		
			strMMT[incount].fBatchNotEmpty = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPendingReversal*/
			strMMT[incount].fPendingReversal = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
			incount ++;

		}
	} while (result == SQLITE_ROW);

	   *inFindRecordNum = incount;

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);
    
    return(d_OK);
}

int inMMTSave(int inSeekCnt)
{
	int result;
	/* aaronnino for BDOCLG ver 9.0 fix on issue #00241 added  fManualMMTSettleTrigger, inOnlineMMTSettleTries, inOnlineMMTSettleLimit*/
	char *sql = "UPDATE MMT SET MMTid = ? , szHostName = ? ,HDTid = ? ,szMerchantName = ? ,MITid = ? ,szTID = ? ,szMID = ? , szATCMD1 = ? , szATCMD2 = ? , szATCMD3 = ? , szATCMD4 = ? , szATCMD5 = ?, fMustSettFlag = ?, szBatchNo = ?, szRctHdr1 = ?, szRctHdr2 = ?, szRctHdr3 = ?, szRctHdr4 = ?, szRctHdr5 = ?, szRctFoot1 =?, szRctFoot2 =?, szRctFoot3 =?, fMMTEnable =?, fEnablePSWD=?, szPassWord=?, inSettleStatus=?, fManualMMTSettleTrigger=?, inOnlineMMTSettleTries=?, inOnlineMMTSettleLimit=?, szSettleDate=?, inMustSettleNumOfDays=?, fBatchNotEmpty=?, fPendingReversal=?, fPreAuthExisting = ?  WHERE  MMTid = ?";
		
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

	vdSetJournalModeOff();

	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
    /* MMMTid */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].MMTid);
    /* szHostName */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szHostName, strlen((char*)strMMT[0].szHostName), SQLITE_STATIC);
	/* HDTid */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].HDTid);
	/* szMerchantName */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szMerchantName, strlen((char*)strMMT[0].szMerchantName), SQLITE_STATIC);
    /* MITid */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].MITid);
    /* szTID*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szTID, strlen((char*)strMMT[0].szTID), SQLITE_STATIC);
	/* szMID*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szMID, strlen((char*)strMMT[0].szMID), SQLITE_STATIC);
	/* szATCMD1 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szATCMD1, strlen((char*)strMMT[0].szATCMD1), SQLITE_STATIC);
	/* szATCMD2 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szATCMD2, strlen((char*)strMMT[0].szATCMD2), SQLITE_STATIC);
	/* szATCMD3 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szATCMD3, strlen((char*)strMMT[0].szATCMD3), SQLITE_STATIC);
	/* szATCMD4 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szATCMD4, strlen((char*)strMMT[0].szATCMD4), SQLITE_STATIC);
	/* szATCMD5 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szATCMD5, strlen((char*)strMMT[0].szATCMD5), SQLITE_STATIC);   
    /* fMustSettFlag */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].fMustSettFlag);
    /* szBatchNo*/
    result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strMMT[0].szBatchNo, 3, SQLITE_STATIC);

	/* szRctHdr1 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szRctHdr1, strlen((char*)strMMT[0].szRctHdr1), SQLITE_STATIC);   

	/* szRctHdr2 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szRctHdr2, strlen((char*)strMMT[0].szRctHdr2), SQLITE_STATIC);   

	/* szRctHdr3 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szRctHdr3, strlen((char*)strMMT[0].szRctHdr3), SQLITE_STATIC);   

	/* szRctHdr4 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szRctHdr4, strlen((char*)strMMT[0].szRctHdr4), SQLITE_STATIC);   

	/* szRctHdr5 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szRctHdr5, strlen((char*)strMMT[0].szRctHdr5), SQLITE_STATIC);   

	/* szRctFoot1 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szRctFoot1, strlen((char*)strMMT[0].szRctFoot1), SQLITE_STATIC);   

	/* szRctFoot2 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szRctFoot2, strlen((char*)strMMT[0].szRctFoot2), SQLITE_STATIC);   

	/* szRctFoot3 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szRctFoot3, strlen((char*)strMMT[0].szRctFoot2), SQLITE_STATIC);
	/* fMMTEnable */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].fMMTEnable);

	/* fEnablePSWD */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].fEnablePSWD);

	/* szPassWord */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szPassWord, strlen((char*)strMMT[0].szPassWord), SQLITE_STATIC); 	

	/* inSettleStatus */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].inSettleStatus);

  //aaronnino for BDOCLG ver 9.0 fix on issue #00241 No Manual Settle/Clear Batch prompt after 3 failed start
	/* fManualMMTSettleTrigger */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].fManualMMTSettleTrigger);
	/* inOnlineMMTSettleTries */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].inOnlineMMTSettleTries);
	/*inOnlineMMTSettleLimit*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].inOnlineMMTSettleLimit);
  //aaronnino for BDOCLG ver 9.0 fix on issue #00241 No Manual Settle/Clear Batch prompt after 3 failed end

#if 0
	//BDO: Added settlement status to settlement report -- jzg
	/* fEnablePSWD */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].inSettleStatus);
#endif

    /*szSettleDate*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szSettleDate, strlen((char*)strMMT[0].szSettleDate), SQLITE_STATIC); 	

	/*inMustSettleNumOfDays*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].inMustSettleNumOfDays);

	/*fBatchNotEmpty*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].fBatchNotEmpty);

	/*fPendingReversal*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].fPendingReversal);
	
	/*fPreAuthExisting*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].fPreAuthExisting);
	
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

int inMMTSaveEx(int inSeekCnt)
{
	int result;
	/* aaronnino for BDOCLG ver 9.0 fix on issue #00241 added  fManualMMTSettleTrigger, inOnlineMMTSettleTries, inOnlineMMTSettleLimit*/
	char *sql = "UPDATE MMT SET MMTid = ? , szHostName = ? ,HDTid = ? ,szMerchantName = ? ,MITid = ? ,szTID = ? ,szMID = ? , szATCMD1 = ? , szATCMD2 = ? , szATCMD3 = ? , szATCMD4 = ? , szATCMD5 = ?, fMustSettFlag = ?, szBatchNo = ?, szRctHdr1 = ?, szRctHdr2 = ?, szRctHdr3 = ?, szRctHdr4 = ?, szRctHdr5 = ?, szRctFoot1 =?, szRctFoot2 =?, szRctFoot3 =?, fMMTEnable =?, fEnablePSWD=?, szPassWord=?, inSettleStatus=?, fManualMMTSettleTrigger=?, inOnlineMMTSettleTries=?, inOnlineMMTSettleLimit=?, szSettleDate=?, inMustSettleNumOfDays=?, fBatchNotEmpty=?, fPendingReversal=?, fPreAuthExisting = ? WHERE  MMTid = ?";

	#if 0	
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
    #endif
	
	vdSetJournalModeOff();

	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
    /* MMMTid */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].MMTid);
    /* szHostName */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szHostName, strlen((char*)strMMT[0].szHostName), SQLITE_STATIC);
	/* HDTid */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].HDTid);
	/* szMerchantName */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szMerchantName, strlen((char*)strMMT[0].szMerchantName), SQLITE_STATIC);
    /* MITid */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].MITid);
    /* szTID*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szTID, strlen((char*)strMMT[0].szTID), SQLITE_STATIC);
	/* szMID*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szMID, strlen((char*)strMMT[0].szMID), SQLITE_STATIC);
	/* szATCMD1 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szATCMD1, strlen((char*)strMMT[0].szATCMD1), SQLITE_STATIC);
	/* szATCMD2 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szATCMD2, strlen((char*)strMMT[0].szATCMD2), SQLITE_STATIC);
	/* szATCMD3 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szATCMD3, strlen((char*)strMMT[0].szATCMD3), SQLITE_STATIC);
	/* szATCMD4 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szATCMD4, strlen((char*)strMMT[0].szATCMD4), SQLITE_STATIC);
	/* szATCMD5 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szATCMD5, strlen((char*)strMMT[0].szATCMD5), SQLITE_STATIC);   
    /* fMustSettFlag */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].fMustSettFlag);
    /* szBatchNo*/
    result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strMMT[0].szBatchNo, 3, SQLITE_STATIC);

	/* szRctHdr1 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szRctHdr1, strlen((char*)strMMT[0].szRctHdr1), SQLITE_STATIC);   

	/* szRctHdr2 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szRctHdr2, strlen((char*)strMMT[0].szRctHdr2), SQLITE_STATIC);   

	/* szRctHdr3 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szRctHdr3, strlen((char*)strMMT[0].szRctHdr3), SQLITE_STATIC);   

	/* szRctHdr4 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szRctHdr4, strlen((char*)strMMT[0].szRctHdr4), SQLITE_STATIC);   

	/* szRctHdr5 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szRctHdr5, strlen((char*)strMMT[0].szRctHdr5), SQLITE_STATIC);   

	/* szRctFoot1 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szRctFoot1, strlen((char*)strMMT[0].szRctFoot1), SQLITE_STATIC);   

	/* szRctFoot2 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szRctFoot2, strlen((char*)strMMT[0].szRctFoot2), SQLITE_STATIC);   

	/* szRctFoot3 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szRctFoot3, strlen((char*)strMMT[0].szRctFoot2), SQLITE_STATIC);
	/* fMMTEnable */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].fMMTEnable);

	/* fEnablePSWD */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].fEnablePSWD);

	/* szPassWord */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szPassWord, strlen((char*)strMMT[0].szPassWord), SQLITE_STATIC); 	

	/* inSettleStatus */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].inSettleStatus);

  //aaronnino for BDOCLG ver 9.0 fix on issue #00241 No Manual Settle/Clear Batch prompt after 3 failed start
	/* fManualMMTSettleTrigger */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].fManualMMTSettleTrigger);
	/* inOnlineMMTSettleTries */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].inOnlineMMTSettleTries);
	/*inOnlineMMTSettleLimit*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].inOnlineMMTSettleLimit);
  //aaronnino for BDOCLG ver 9.0 fix on issue #00241 No Manual Settle/Clear Batch prompt after 3 failed end

#if 0
	//BDO: Added settlement status to settlement report -- jzg
	/* fEnablePSWD */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].inSettleStatus);
#endif

    /*szSettleDate*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strMMT[0].szSettleDate, strlen((char*)strMMT[0].szSettleDate), SQLITE_STATIC); 	

	/*inMustSettleNumOfDays*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].inMustSettleNumOfDays);

	/*fBatchNotEmpty*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].fBatchNotEmpty);

	/*fPendingReversal*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].fPendingReversal);
	
	/*fPreAuthExisting*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].fPreAuthExisting);
	
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
    
	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}
	
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	#if 0
	sqlite3_close(db);
    #endif

    return(d_OK);
}

int inPITRead(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT szTransactionTypeName, inTxnTypeID, fTxnEnable, inPasswordLevel FROM PIT WHERE inTxnTypeID = ?";
		
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
			inResult = d_OK;
			inStmtSeq = 0;

			/*szTransactionTypeName*/
			strcpy((char*)strPIT.szTransactionTypeName, (char *)sqlite3_column_text(stmt,inStmtSeq));
            
			/* inTxnTypeID */
			strPIT.inTxnTypeID = sqlite3_column_int(stmt,inStmtSeq +=1 );
		    
            /* fTxnEnable */
			strPIT.fTxnEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            
            /* inPasswordLevel */
			strPIT.inPasswordLevel = sqlite3_column_int(stmt,inStmtSeq +=1 );
		}
	} while (result == SQLITE_ROW);
    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	   
    return(inResult);
}

int inPITSave(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE PIT SET szTransactionTypeName = ? ,inTxnTypeID = ? ,fTxnEnable = ? ,inPasswordLevel = ? WHERE  PITid = ?";
		
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

	inStmtSeq = 0;
    /* szTransactionTypeName */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPIT.szTransactionTypeName, strlen((char*)strPIT.szTransactionTypeName), SQLITE_STATIC);
	/* inTxnTypeID */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strPIT.inTxnTypeID);
	/* fTxnEnable*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strPIT.fTxnEnable);
    /* inPasswordLevel */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strPIT.inPasswordLevel);

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

int inEMVRead(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT inSchemeReference, inIssuerReference, inTRMDataPresent, lnEMVFloorLimit, lnEMVRSThreshold, inEMVTargetRSPercent, inEMVMaxTargetRSPercent, inMerchantForcedOnlineFlag, inBlackListedCardSupportFlag, szEMVTACDefault, szEMVTACDenial, szEMVTACOnline, szDefaultTDOL, szDefaultDDOL, inEMVFallbackAllowed, inNextRecord, ulEMVCounter, inEMVAutoSelectAppln, szEMVTermCountryCode, szEMVTermCurrencyCode, inEMVTermCurExp, szEMVTermCapabilities, szEMVTermAddCapabilities, szEMVTermType, szEMVMerchantCategoryCode, szEMVTerminalCategoryCode, inModifyCandListFlag, shRFU1, shRFU2, shRFU3, szRFU1, szRFU2, szRFU3, szCardScheme FROM EMV WHERE EMVid = ?";

	/* open the database */
	result = sqlite3_open(DB_EMV,&db);
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
		
		//Debug_LogPrintf("EMV read[%d]",result);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

      /*inSchemeReference;*/
			strEMVT.inSchemeReference = sqlite3_column_int(stmt,inStmtSeq);
    
      /*inIssuerReference*/
			strEMVT.inIssuerReference = sqlite3_column_int(stmt,inStmtSeq +=1 );
                
      /*inTRMDataPresent*/
			strEMVT.inTRMDataPresent = sqlite3_column_int(stmt,inStmtSeq +=1 );
                            
      /*lnEMVFloorLimit*/
			strEMVT.lnEMVFloorLimit = sqlite3_column_double(stmt,inStmtSeq +=1 );
                
      /*lnEMVRSThreshold*/            //5
			strEMVT.lnEMVRSThreshold = sqlite3_column_double(stmt,inStmtSeq +=1 );
                
      /*inEMVTargetRSPercent*/
			strEMVT.inEMVTargetRSPercent = sqlite3_column_int(stmt,inStmtSeq +=1 );
                
      /*inEMVMaxTargetRSPercent*/
			strEMVT.inEMVMaxTargetRSPercent = sqlite3_column_int(stmt,inStmtSeq +=1 );
                
      /*inMerchantForcedOnlineFlag*/
			strEMVT.inMerchantForcedOnlineFlag = sqlite3_column_int(stmt,inStmtSeq +=1 );
                
      /*inBlackListedCardSupportFlag*/
			strEMVT.inBlackListedCardSupportFlag = sqlite3_column_int(stmt,inStmtSeq +=1 );
            
      /* szEMVTACDefault */            //10
			memcpy(strEMVT.szEMVTACDefault, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);
           
      /* szEMVTACDenial */            
			memcpy(strEMVT.szEMVTACDenial, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);
            
      /* szEMVTACOnline */
			memcpy(strEMVT.szEMVTACOnline, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);
            
      /* szDefaultTDOL */
			strcpy((char*)strEMVT.szDefaultTDOL, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            
      /* szDefaultDDOL */
			strcpy((char*)strEMVT.szDefaultDDOL, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

      /*inEMVFallbackAllowed*/        //15
			strEMVT.inEMVFallbackAllowed = sqlite3_column_int(stmt,inStmtSeq +=1 );

      /*inNextRecord*/
			strEMVT.inNextRecord = sqlite3_column_int(stmt,inStmtSeq +=1 );

      /*ulEMVCounter*/
			strEMVT.ulEMVCounter = sqlite3_column_double(stmt, inStmtSeq +=1 );

      /*inEMVAutoSelectAppln*/
			strEMVT.inEMVAutoSelectAppln = sqlite3_column_int(stmt,inStmtSeq +=1 );
    
      /* szEMVTermCountryCode */
			memcpy(strEMVT.szEMVTermCountryCode, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);
			
      /* szEMVTermCurrencyCode */        //20
			memcpy(strEMVT.szEMVTermCurrencyCode, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);
            
      /*inEMVTermCurExp*/
			strEMVT.inEMVTermCurExp = sqlite3_column_int(stmt,inStmtSeq +=1 );
    
      /* szEMVTermCapabilities*/
			memcpy(strEMVT.szEMVTermCapabilities, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);
               
      /* szEMVTermAddCapabilities */
			memcpy(strEMVT.szEMVTermAddCapabilities, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);
    
      /* szEMVTermType */
			memcpy(strEMVT.szEMVTermType, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 1);
            
      /* szEMVMerchantCategoryCode */        //25
			memcpy(strEMVT.szEMVMerchantCategoryCode, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 1);

      /* szEMVTerminalCategoryCode */
			memcpy(strEMVT.szEMVTerminalCategoryCode, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 1);

      /*inModifyCandListFlag*/
			strEMVT.inModifyCandListFlag = sqlite3_column_int(stmt,inStmtSeq +=1 );
                
      /*shRFU1*/
			strEMVT.shRFU1 = sqlite3_column_int(stmt,inStmtSeq +=1 );
                
      /*shRFU2*/
			strEMVT.shRFU2 = sqlite3_column_int(stmt,inStmtSeq +=1 );
                
      /*shRFU3*/                            //30
			strEMVT.shRFU3 = sqlite3_column_int(stmt,inStmtSeq +=1 );
    
      /* szRFU1*/
			strcpy((char*)strEMVT.szRFU1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
    
      /* szRFU2 */
			strcpy((char*)strEMVT.szRFU2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            
      /* szRFU3 */
			strcpy((char*)strEMVT.szRFU3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szCardScheme*/
			strcpy((char*)strEMVT.szCardScheme, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

  return(inResult);
}


int inEMVSave(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE EMV SET inSchemeReference=?, inIssuerReference=?, inTRMDataPresent=?, lnEMVFloorLimit=?, lnEMVRSThreshold=?, inEMVTargetRSPercent=?, inEMVMaxTargetRSPercent=?, inMerchantForcedOnlineFlag=?, inBlackListedCardSupportFlag=?, szEMVTACDefault=?, szEMVTACDenial=?, szEMVTACOnline=?, szDefaultTDOL=?, szDefaultDDOL=?, inEMVFallbackAllowed=?, inNextRecord=?, ulEMVCounter=?, inEMVAutoSelectAppln=?, szEMVTermCountryCode=?, szEMVTermCurrencyCode=?, inEMVTermCurExp=?, szEMVTermCapabilities=?, szEMVTermAddCapabilities=?, szEMVTermType=?, szEMVMerchantCategoryCode=?, szEMVTerminalCategoryCode=?, inModifyCandListFlag=?, shRFU1=?, shRFU2=?, shRFU3=?, szRFU1=?, szRFU2=?, szRFU3=? WHERE EMVid = ?";
		
	/* open the database */
	result = sqlite3_open(DB_EMV,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	
	sqlite3_exec(db, "begin", 0, 0, NULL);
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;

	/*inSchemeReference;*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEMVT.inSchemeReference);
	
	/*inIssuerReference*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEMVT.inIssuerReference);
						
	/*inTRMDataPresent*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEMVT.inTRMDataPresent);
												
	/*lnEMVFloorLimit*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEMVT.lnEMVFloorLimit);
						
	/*lnEMVRSThreshold*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEMVT.lnEMVRSThreshold);
						
	/*inEMVTargetRSPercent*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEMVT.inEMVTargetRSPercent);
						
	/*inEMVMaxTargetRSPercent*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEMVT.inEMVMaxTargetRSPercent);
						
	/*inMerchantForcedOnlineFlag*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEMVT.inMerchantForcedOnlineFlag);
						
	/*inBlackListedCardSupportFlag*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEMVT.inBlackListedCardSupportFlag);
				
	/*szEMVTACDefault*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strEMVT.szEMVTACDefault, 5, SQLITE_STATIC);
			 
	/*szEMVTACDenial*/						
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strEMVT.szEMVTACDenial, 5, SQLITE_STATIC);
				
	/*szEMVTACOnline*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strEMVT.szEMVTACOnline, 5, SQLITE_STATIC);
				
	/*szDefaultTDOL*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strEMVT.szDefaultTDOL, strlen((char*)strEMVT.szDefaultTDOL), SQLITE_STATIC);
				
	/*szDefaultDDOL*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strEMVT.szDefaultDDOL, strlen((char*)strEMVT.szDefaultDDOL), SQLITE_STATIC);
	
	/*inEMVFallbackAllowed*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEMVT.inEMVFallbackAllowed);
	
	/*inNextRecord*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEMVT.inNextRecord);
	
	/*ulEMVCounter*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEMVT.ulEMVCounter);
	
	/*inEMVAutoSelectAppln*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEMVT.inEMVAutoSelectAppln);
	
	/*szEMVTermCountryCode*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strEMVT.szEMVTermCountryCode, 2, SQLITE_STATIC);
	
	/*szEMVTermCurrencyCode*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strEMVT.szEMVTermCurrencyCode, 2, SQLITE_STATIC);
				
	/*inEMVTermCurExp*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEMVT.inEMVTermCurExp);
	
	/*szEMVTermCapabilities*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strEMVT.szEMVTermCapabilities, 3, SQLITE_STATIC);
					 
	/*szEMVTermAddCapabilities*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strEMVT.szEMVTermAddCapabilities, 5, SQLITE_STATIC);
	
	/*szEMVTermType*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strEMVT.szEMVTermType, 1, SQLITE_STATIC);
				
	/*szEMVMerchantCategoryCode*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strEMVT.szEMVMerchantCategoryCode, 1, SQLITE_STATIC);
	
	/*szEMVTerminalCategoryCode*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strEMVT.szEMVTerminalCategoryCode, 1, SQLITE_STATIC);
	
	/*inModifyCandListFlag*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEMVT.inModifyCandListFlag);
						
	/*shRFU1*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEMVT.shRFU1);
						
	/*shRFU2*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEMVT.shRFU2);
						
	/*shRFU3*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEMVT.shRFU3);
	
	/* szRFU1*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strEMVT.szRFU1, strlen((char*)strEMVT.szRFU1), SQLITE_STATIC);
	
	/* szRFU2 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strEMVT.szRFU2, strlen((char*)strEMVT.szRFU2), SQLITE_STATIC);
				
	/* szRFU3 */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strEMVT.szRFU3, strlen((char*)strEMVT.szRFU3), SQLITE_STATIC);

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


#if 0
int inAIDReadbyRID(int inSeekCnt, char * PRid)
{
	int result;
	int inResult = d_NO;
	char *sql = "select ulRef, bAIDLen, pbAID, bApplication_Selection_Indicator, inEMVid, inCAPKindex1, pbExpireDate1, inCAPKindex2, pbExpireDate2, inCAPKindex3, pbExpireDate3, inCAPKindex4, pbExpireDate4, inCAPKindex5, pbExpireDate5, inCAPKindex6, pbExpireDate6, inCAPKindex7, pbExpireDate7, inCAPKindex8, pbExpireDate8, inCAPKindex9, pbExpireDate9, inCAPKindex10, pbExpireDate10, pbTerminalAVN, pb2ndTerminalAVN from AID where AIDid = ?";
	BOOL fRIDMatchFlag = FALSE;


	/* open the database */
	result = sqlite3_open(DB_EMV,&db);
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
		
		//vdDebug_LogPrintf("strAIDT.result[%d]AIDid[%d]",result,inSeekCnt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;
			
			/*ulRef*/
			strAIDT.ulRef = sqlite3_column_double(stmt, inStmtSeq);

			/*bAIDLen*/
			strAIDT.bAIDLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			//Debug_LogPrintf("strAIDT.bAIDLen[%d]",strAIDT.bAIDLen);

			/* pbAID */
			memcpy(strAIDT.pbAID, sqlite3_column_blob(stmt,inStmtSeq +=1 ), strAIDT.bAIDLen);
			vdDebug_LogPrintf("strAIDT.bAIDLen[%d]",strAIDT.bAIDLen);
			DebugAddHEX("read AID =",strAIDT.pbAID,strAIDT.bAIDLen);
			if((memcmp(strAIDT.pbAID, PRid, 5) == 0))
			{
				fRIDMatchFlag = TRUE;
			}
			
			/*bApplication_Selection_Indicator*/
			strAIDT.bApplication_Selection_Indicator = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*inEMVid*/
			strAIDT.inEMVid = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*inCAPKindex1*/
			strAIDT.inCAPKindex1 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate1*/
			strcpy((char*)strAIDT.pbExpireDate1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex2*/
			strAIDT.inCAPKindex2 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate2*/
			strcpy((char*)strAIDT.pbExpireDate2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex3*/
			strAIDT.inCAPKindex3 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate3*/
			strcpy((char*)strAIDT.pbExpireDate3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex4*/
			strAIDT.inCAPKindex4 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate4*/
			strcpy((char*)strAIDT.pbExpireDate4, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		
			/*inCAPKindex5*/
			strAIDT.inCAPKindex5 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate5*/
			strcpy((char*)strAIDT.pbExpireDate5, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/*inCAPKindex6*/
			strAIDT.inCAPKindex6 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate6*/
			strcpy((char*)strAIDT.pbExpireDate6, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

					
			/*inCAPKindex7*/
			strAIDT.inCAPKindex7 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate7*/
			strcpy((char*)strAIDT.pbExpireDate7, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex8*/
			strAIDT.inCAPKindex8 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate8*/
			strcpy((char*)strAIDT.pbExpireDate8, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex9*/
			strAIDT.inCAPKindex9 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate9*/
			strcpy((char*)strAIDT.pbExpireDate9, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex10*/
			strAIDT.inCAPKindex4 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate10*/
			strcpy((char*)strAIDT.pbExpireDate10, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* pbTerminalAVN */
			memcpy(strAIDT.pbTerminalAVN, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);
			/* pb2ndTerminalAVN */
			memcpy(strAIDT.pb2ndTerminalAVN, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);


		}
	} while (result == SQLITE_ROW);    

	
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	if(fRIDMatchFlag == TRUE)
		return(99);
	else
		return(inResult);
}
#endif
#if 0
int inAIDRead(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql = "select ulRef, bAIDLen, pbAID, bApplication_Selection_Indicator, inEMVid, inCAPKindex1, pbExpireDate1, inCAPKindex2, pbExpireDate2, inCAPKindex3, pbExpireDate3, inCAPKindex4, pbExpireDate4, inCAPKindex5, pbExpireDate5, inCAPKindex6, pbExpireDate6, inCAPKindex7, pbExpireDate7, inCAPKindex8, pbExpireDate8, inCAPKindex9, pbExpireDate9, inCAPKindex10, pbExpireDate10, pbTerminalAVN, pb2ndTerminalAVN from AID where AIDid = ?";



	/* open the database */
	result = sqlite3_open(DB_EMV,&db);
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
		
		//vdDebug_LogPrintf("strAIDT.result[%d]AIDid[%d]",result,inSeekCnt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;
			
            /*ulRef*/
			strAIDT.ulRef = sqlite3_column_double(stmt, inStmtSeq);

            /*bAIDLen*/
			strAIDT.bAIDLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			//Debug_LogPrintf("strAIDT.bAIDLen[%d]",strAIDT.bAIDLen);

			/* pbAID */
			memcpy(strAIDT.pbAID, sqlite3_column_blob(stmt,inStmtSeq +=1 ), strAIDT.bAIDLen);
			vdDebug_LogPrintf("strAIDT.bAIDLen[%d]",strAIDT.bAIDLen);
            DebugAddHEX("AID =",strAIDT.pbAID,strAIDT.bAIDLen);
                 
            /*bApplication_Selection_Indicator*/
			strAIDT.bApplication_Selection_Indicator = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*inEMVid*/
			strAIDT.inEMVid = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*inCAPKindex1*/
			strAIDT.inCAPKindex1 = sqlite3_column_int(stmt,inStmtSeq +=1 );
            /* pbExpireDate1*/
			strcpy((char*)strAIDT.pbExpireDate1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex2*/
			strAIDT.inCAPKindex2 = sqlite3_column_int(stmt,inStmtSeq +=1 );
            /* pbExpireDate2*/
			strcpy((char*)strAIDT.pbExpireDate2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex3*/
			strAIDT.inCAPKindex3 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate3*/
			strcpy((char*)strAIDT.pbExpireDate3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex4*/
			strAIDT.inCAPKindex4 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate4*/
			strcpy((char*)strAIDT.pbExpireDate4, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		
			/*inCAPKindex5*/
			strAIDT.inCAPKindex5 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate5*/
			strcpy((char*)strAIDT.pbExpireDate5, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/*inCAPKindex6*/
			strAIDT.inCAPKindex6 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate6*/
			strcpy((char*)strAIDT.pbExpireDate6, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

					
			/*inCAPKindex7*/
			strAIDT.inCAPKindex7 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate7*/
			strcpy((char*)strAIDT.pbExpireDate7, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex8*/
			strAIDT.inCAPKindex8 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate8*/
			strcpy((char*)strAIDT.pbExpireDate8, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex9*/
			strAIDT.inCAPKindex9 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate9*/
			strcpy((char*)strAIDT.pbExpireDate9, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex10*/
			strAIDT.inCAPKindex4 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate10*/
			strcpy((char*)strAIDT.pbExpireDate10, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* pbTerminalAVN */
			memcpy(strAIDT.pbTerminalAVN, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);
			/* pb2ndTerminalAVN */
			memcpy(strAIDT.pb2ndTerminalAVN, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);


		}
	} while (result == SQLITE_ROW);	   

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inResult);
}
#else
int inAIDRead(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT AIDid, EMVid, ulRef, fAIDEnable, inAIDLen, pbAID,  inApplication_Selection_Indicator, inCAPKindex1, pbExpireDate1, inCAPKindex2, pbExpireDate2, inCAPKindex3, pbExpireDate3, inCAPKindex4, pbExpireDate4, inCAPKindex5, pbExpireDate5, inCAPKindex6, pbExpireDate6, inCAPKindex7, pbExpireDate7, inCAPKindex8, pbExpireDate8, inCAPKindex9, pbExpireDate9, inCAPKindex10, pbExpireDate10, pbTerminalAVN, pb2ndTerminalAVN from AID where AIDid = ?";



	/* open the database */
	result = sqlite3_open(DB_EMV,&db);
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
		
		//vdDebug_LogPrintf("strAIDT.result[%d]AIDid[%d]",result,inSeekCnt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			/*inAIDid*/
			strAIDT.AIDid = sqlite3_column_int(stmt,inStmtSeq );

			/*inEMVid*/
			strAIDT.EMVid = sqlite3_column_int(stmt,inStmtSeq +=1 );
			
      /*ulRef*/
			strAIDT.ulRef = sqlite3_column_double(stmt, inStmtSeq +=1 );

			 /* fAIDEnable */
			strAIDT.fAIDEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inAIDLen*/   
			strAIDT.inAIDLen = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* pbAID */
			memcpy(strAIDT.pbAID, sqlite3_column_blob(stmt,inStmtSeq +=1 ), strAIDT.inAIDLen);
			vdDebug_LogPrintf("strAIDT.inAIDLen[%d]",strAIDT.inAIDLen);
            DebugAddHEX("AID =",strAIDT.pbAID,strAIDT.inAIDLen);
						
			
      /*bApplication_Selection_Indicator*/
			strAIDT.bApplication_Selection_Indicator = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*inCAPKindex1*/
			strAIDT.inCAPKindex1 = sqlite3_column_int(stmt,inStmtSeq +=1 );
            /* pbExpireDate1*/
			strcpy((char*)strAIDT.pbExpireDate1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex2*/
			strAIDT.inCAPKindex2 = sqlite3_column_int(stmt,inStmtSeq +=1 );
            /* pbExpireDate2*/
			strcpy((char*)strAIDT.pbExpireDate2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex3*/
			strAIDT.inCAPKindex3 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate3*/
			strcpy((char*)strAIDT.pbExpireDate3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex4*/
			strAIDT.inCAPKindex4 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate4*/
			strcpy((char*)strAIDT.pbExpireDate4, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		
			/*inCAPKindex5*/
			strAIDT.inCAPKindex5 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate5*/
			strcpy((char*)strAIDT.pbExpireDate5, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/*inCAPKindex6*/
			strAIDT.inCAPKindex6 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate6*/
			strcpy((char*)strAIDT.pbExpireDate6, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

					
			/*inCAPKindex7*/
			strAIDT.inCAPKindex7 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate7*/
			strcpy((char*)strAIDT.pbExpireDate7, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex8*/
			strAIDT.inCAPKindex8 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate8*/
			strcpy((char*)strAIDT.pbExpireDate8, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex9*/
			strAIDT.inCAPKindex9 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate9*/
			strcpy((char*)strAIDT.pbExpireDate9, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex10*/
			strAIDT.inCAPKindex4 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate10*/
			strcpy((char*)strAIDT.pbExpireDate10, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* pbTerminalAVN */
			memcpy(strAIDT.pbTerminalAVN, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);
			/* pb2ndTerminalAVN */
			memcpy(strAIDT.pb2ndTerminalAVN, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);


		}
	} while (result == SQLITE_ROW);	   

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);
  
    return(inResult);
}
#endif

int inTCTRead(int inSeekCnt)
{
	int result;
	int len = 0;
	int inResult = -1;
	BYTE szBuffer [50];
	
	/* CTLS: Added szMaxCTLSAmount to check CTLS max txn amount during runtime -- jzg */
	/* aaronnino for BDOCLG ver 9.0 fix on issue #0061 changed fEnableInstMKE to fEnableManualKeyEntry 1 of 7*/
	/* aaronnino for BDOCLG ver 9.0 fix on issue #0066 added fDutyFreeMode 1 of  8*/
  /*aaronnino for BDOCLG ver 9.0 fix on issue#00078 added inBankCopy, inCustomerCopy, inMerchantCopy*/
	/*aaronnino for BDOCLG ver 9.0 fix on issue#00032 added szCurrentDate and fNextDayMustSettle*/	

	char *sql = "SELECT inMainLine, fHandsetPresent, fDemo, fCVVEnable, szSuperPW, szSystemPW, szEngineerPW, szFunKeyPW, szPMpassword, szBInRoutePW,  byRS232DebugPort, inPrinterHeatLevel, inWaitTime, byCtlsMode, fTipAllowFlag, fDebitFlag, szFallbackTime, inFallbackTimeGap, fManualEntryInv, szInvoiceNo, szPabx, szLastInvoiceNo, inMenuid, fECR, fDebugOpenedFlag,fShareComEnable, inReversalCount, inTipAdjustCount, fPrintISOMessage, fConfirmPAN, szMinInstAmt, fFirstInit, fTrickleFeedEMVUpload,	fDualCurrency, fPrintExpiryDate, inMaxAdjust, fMaskPanDisplay, DisplayPANFormat, szMaxTrxnAmt, fPrintTipReceipt, byTerminalType, szMaxCTLSAmount, lnTipPercent, byPinPadPort, fPrintWarningSound, fOfflinePinbypass, fEnableInstMKE, fEnableManualKeyEntry, fPrintSettleDetailReport, fDutyFreeMode, fScreenLocked, fMOTO, SMACRATE, DEACTDATE, SMACENABLE, SMZ, inBankCopy, inCustomerCopy, inMerchantCopy, fAutoDownloadEnable, usTMSGap, inTMSComMode, usTMSRemotePort, szTMSRemoteIP, szTMSRemotePhone, szTMSRemoteID, szTMSRemotePW, szLockPassword, szCurrentDate, fFleetGetLiters, fGetDescriptorCode, fSelectECRTrxn, szAppVersionHeader, fNextDayMustSettle, fEnableBinVerMKE, fDefaultCashAdvance, fNSRCustCopy, inSMACMode, ATPNII, ATPTPDU, szPrintOption, inIdleTimeOut, fPrintSummaryAll, fPrintDetailAll, fInclude_DEBIT_SETTLEALL, fInclude_INST_SETTLEALL, fInclude_CUP_SETTLEALL, szCTLSLimit, inModemReceivingTime, fCheckout, fATPBinRoute, byTerminalModel, byRS232ECRPort, fECRBaudRate, szMinTrxnAmt, fHotelSetup, szMaxInstAmt, fSMMode, fSMReceipt, fSMLogo, fEnableBalInqMKE, szSMReceiptLogo, szBDOReceiptLogo, fEnablePrintBalanceInq, fSingleComms, inECRTrxnMenu, fECRISOLogging, byERMMode, fDCC, szIdleLogo1, szIdleLogo2, szIdleLogo3, inSMCardRetryCount, fPrintReceiptPrompt, fISOLogging, inTxnLogLimit, fReprintSettleStatus, fPrintIssuerID, fDisplayPrintBitmap, fSignatureFlag, inERMMaximum, byERMInit, inPrintISOOption, fFormatDCCAmount, fChangeDateMustSettle, fDebitInsertEnable, inECRMode, fDisplayBattery, fTapAndGo, fPrintFooterLogo, szTMSNACProtocol, szTMSNACSourceAddr, szTMSNACDestAddr, szMobileWalletLabel, inBackupSettNumDays, fDisplayAPPROVED, fInsertAndGo, inDCCMode, inSetMobileWalletLabel FROM TCT WHERE TCTid = ?";
	//char *sql = "SELECT inMainLine, fHandsetPresent, fDemo, fCVVEnable, szSuperPW, szSystemPW, szEngineerPW, szFunKeyPW, szPMpassword, szBInRoutePW,  byRS232DebugPort, inPrinterHeatLevel, inWaitTime, byCtlsMode, fTipAllowFlag, fDebitFlag, szFallbackTime, inFallbackTimeGap, fManualEntryInv, szInvoiceNo, szPabx, szLastInvoiceNo, inMenuid, fECR, fDebugOpenedFlag,fShareComEnable, inReversalCount, inTipAdjustCount, fPrintISOMessage, fConfirmPAN, szMinInstAmt, fFirstInit, fTrickleFeedEMVUpload,	fDualCurrency, fPrintExpiryDate, inMaxAdjust, fMaskPanDisplay, DisplayPANFormat, szMaxTrxnAmt, fPrintTipReceipt, byTerminalType, szMaxCTLSAmount, lnTipPercent, byPinPadPort, fPrintWarningSound, fOfflinePinbypass, fEnableInstMKE, fEnableManualKeyEntry, fPrintSettleDetailReport, fDutyFreeMode, fScreenLocked, fMOTO, SMACRATE, DEACTDATE, SMACENABLE, SMZ, inBankCopy, inCustomerCopy, inMerchantCopy, fAutoDownloadEnable, usTMSGap, inTMSComMode, usTMSRemotePort, szTMSRemoteIP, szTMSRemotePhone, szTMSRemoteID, szTMSRemotePW, szLockPassword, szCurrentDate, fFleetGetLiters, fGetDescriptorCode, fSelectECRTrxn, szAppVersionHeader, fNextDayMustSettle, fEnableBinVerMKE, fDefaultCashAdvance, fNSRCustCopy, inSMACMode, ATPNII, ATPTPDU, szPrintOption, inIdleTimeOut, fPrintSummaryAll, fPrintDetailAll, fInclude_DEBIT_SETTLEALL, fInclude_INST_SETTLEALL, fInclude_CUP_SETTLEALL, szCTLSLimit, inModemReceivingTime, fCheckout, fATPBinRoute, byTerminalModel, byRS232ECRPort, fECRBaudRate, szMinTrxnAmt, fHotelSetup, szMaxInstAmt, fSMMode, fSMReceipt, fSMLogo, fEnableBalInqMKE, szSMReceiptLogo, szBDOReceiptLogo, fEnablePrintBalanceInq, fSingleComms, inECRTrxnMenu, fECRISOLogging, byERMMode, fDCC, szIdleLogo1, szIdleLogo2, szIdleLogo3, inSMCardRetryCount, fPrintReceiptPrompt, fISOLogging, inTxnLogLimit, fReprintSettleStatus, fPrintIssuerID, fDisplayPrintBitmap, fSignatureFlag, inERMMaximum, byERMInit, inPrintISOOption, fFormatDCCAmount FROM TCT WHERE TCTid = ?";
	//char *sql = "SELECT inMainLine, fHandsetPresent, fDemo, fCVVEnable, szSuperPW, szSystemPW, szEngineerPW, szFunKeyPW, szPMpassword, byRS232DebugPort, inPrinterHeatLevel, inWaitTime, byCtlsMode, fTipAllowFlag, fDebitFlag, szFallbackTime, inFallbackTimeGap, fManualEntryInv, szInvoiceNo, szPabx, szLastInvoiceNo, inMenuid, fECR, fDebugOpenedFlag,fShareComEnable, inReversalCount, inTipAdjustCount, fPrintISOMessage, fConfirmPAN, szMinInstAmt, fFirstInit, fTrickleFeedEMVUpload,	fDualCurrency, fPrintExpiryDate, inMaxAdjust, fMaskPanDisplay, DisplayPANFormat, szMaxTrxnAmt, fPrintTipReceipt, byTerminalType, szMaxCTLSAmount, lnTipPercent, byPinPadPort, fPrintWarningSound, fOfflinePinbypass, fEnableManualKeyEntry, fPrintSettleDetailReport, inOnlineSettleTries, fDutyFreeMode, inManualSettleTrigger, fScreenLocked, fMOTO, SMACRATE, DEACTDATE, SMACENABLE, SMZ, inBankCopy, inCustomerCopy, inMerchantCopy,  usTMSGap, inTMSComMode, usTMSRemotePort, szTMSRemoteIP, szTMSRemotePhone, szTMSRemoteID, szTMSRemotePW, szLockPassword, szCurrentDate FROM TCT WHERE TCTid = ?";

	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

	vdSetJournalModeOff();

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
			inResult = d_OK;
			inStmtSeq = 0;
			
    
            /* inMainLine */
			strTCT.inMainLine = sqlite3_column_int(stmt,inStmtSeq  );

            /* fHandsetPresent */
			strTCT.fHandsetPresent = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
    
             /* fDemo //5*/
			strTCT.fDemo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            
            /* fCVVEnable */
			strTCT.fCVVEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
                        
            /* szSuperPW*/
			strcpy((char*)strTCT.szSuperPW, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* szSystemPW */
			strcpy((char*)strTCT.szSystemPW, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* szEngineerPW */
			strcpy((char*)strTCT.szEngineerPW, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* szFunKeyPW */
			strcpy((char*)strTCT.szFunKeyPW, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* szPMpassword */
			strcpy((char*)strTCT.szPMpassword, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /*szBInRoutePW*/
			strcpy((char*)strTCT.szBInRoutePW, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			   
            /*byRS232DebugPort*/
			strTCT.byRS232DebugPort = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/*inPrinterHeatLevel*/
			strTCT.inPrinterHeatLevel = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/*inWaitTime*/
			strTCT.inWaitTime = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/*byCtlsMode*/
			strTCT.byCtlsMode = sqlite3_column_int(stmt,inStmtSeq +=1 );
            
 			/* fTipAllowFlag */
			strTCT.fTipAllowFlag = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            
            /* fDebitFlag */
            strTCT.fDebitFlag = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* szFallbackTime*/
			strcpy((char*)strTCT.szFallbackTime, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

             /* inFallbackTimeGap */
			strTCT.inFallbackTimeGap = sqlite3_column_int(stmt,inStmtSeq +=1 );

             /* fManualEntryInv */
            strTCT.fManualEntryInv = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			 
			/* szInvoiceNo*/
			memcpy(strTCT.szInvoiceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);

            /* szPabx */
			strcpy((char*)strTCT.szPabx, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			DelCharInStr(strTCT.szPabx,',',2);
			len = strlen((char*)strTCT.szPabx);
			if(len > 0)
				strTCT.szPabx[len]=',';

			/* szLastInvoiceNo */
			memcpy(strTCT.szLastInvoiceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);

			/* BDO CLG: Revised menu functions - start -- jzg */
			/* inMenuid */
			strTCT.inMenuid = sqlite3_column_int(stmt,inStmtSeq +=1);
			/* BDO CLG: Revised menu functions - end -- jzg */
			
			/* fECR */
			strTCT.fECR = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* fDebugOpenedFlag */
            strTCT.fDebugOpenedFlag = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* fShareComEnable */
            strTCT.fShareComEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* inReversalCount */
			strTCT.inReversalCount = sqlite3_column_int(stmt,inStmtSeq +=1 );

            /* inTipAdjustCount */
			strTCT.inTipAdjustCount = sqlite3_column_int(stmt,inStmtSeq +=1 );

		//gcitra
		/*fPrintISOMessage*/
		strTCT.fPrintISOMessage = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
		/*fConfirmPAN*/
		strTCT.fConfirmPAN = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		//gcitra

			/* szMinInstAmt */
			memcpy(strTCT.szMinInstAmt, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 6);

		/* fFirstInit */
		strTCT.fFirstInit = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fTrickleFeedEMVUpload*/	
		strTCT.fTrickleFeedEMVUpload = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fDualCurrency*/
		strTCT.fDualCurrency = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fPrintExpiryDate*/
		strTCT.fPrintExpiryDate = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*inMaxAdjust*/	
		strTCT.inMaxAdjust = sqlite3_column_int(stmt,inStmtSeq +=1 );

		/*fMaskPanDisplay*/	
		strTCT.fMaskPanDisplay = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*DisplayPANFormat*/
		strcpy((char*)strTCT.DisplayPANFormat, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

        //sidumili: Issue#:000076 [OUT OF RANGE]
        /* szMaxTrxnAmt */
//        memcpy(strTCT.szMaxTrxnAmt, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 12);
				strcpy((char*)strTCT.szMaxTrxnAmt, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		//vdDebug_LogPrintf("JEFF::TCT MAX TXN AMT: [%s]", strTCT.szMaxTrxnAmt);

		/*sidumili: Fix on Issue#: 000181*/
		/*fPrintTipReceipt*/
		strTCT.fPrintTipReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fInstTCUpload */
        //Issue# 000166 - start -- jzg
        /* fInstTCUpload */
        //strTCT.fInstTCUpload = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
        //Issue# 000166 - end -- jzg

		/*byTerminalType*/
		strTCT.byTerminalType = sqlite3_column_int(stmt,inStmtSeq +=1 );

		/* CTLS: Added szMaxCTLSAmount to check CTLS max txn amount during runtime -- jzg */
		strcpy((char*)strTCT.szMaxCTLSAmount, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*lnTipPercent*/
		strTCT.lnTipPercent = sqlite3_column_int(stmt, inStmtSeq +=1 );

		strTCT.byPinPadPort = sqlite3_column_int(stmt, inStmtSeq +=1 );

		/*BDO PHASE 2: [Warning sound for printing flag] -- sidumili*/
		/*fPrintWarningSound*/
		strTCT.fPrintWarningSound = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/* fOfflinePinbypass */
		strTCT.fOfflinePinbypass = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));


		 //BDO: Parameterized manual key entry for installment --jzg
		strTCT.fEnableInstMKE = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		 /*fEnableManualKeyEntry*/
		strTCT.fEnableManualKeyEntry = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 )); //aaronnino for BDOCLG ver 9.0 fix on issue #0061 Manual Entry should not be allowed for BIN Check transactions 2 of 7

		/* BDO: Include detailed report to settlement receipt - start -- jzg */
		/* fPrintSettleDetailReport */
		strTCT.fPrintSettleDetailReport = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		/* BDO: Include detailed report to settlement receipt - end -- jzg */

		/*fDutyFreeMode*/
		strTCT.fDutyFreeMode = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 )); //aaronnino for BDOCLG ver 9.0 fix on issue #0066 "APPR.CODE" single width printed on transaction receipt 2 of 8
		
		/* BDO CLG: Terminal lock screen - start -- jzg */
		/* fScreenLocked */
		strTCT.fScreenLocked = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		/* BDO CLG: Terminal lock screen - end -- jzg */

		/* BDO CLG: MOTO setup - start -- jzg */
		/* fMOTO */
		strTCT.fMOTO = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		/* BDO CLG: MOTO setup - end -- jzg */
//smac
		strTCT.SMACRATE = sqlite3_column_double(stmt,inStmtSeq +=1);
		memcpy(strTCT.DEACTDATE, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 20);
		strTCT.SMACENABLE = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		strTCT.SMZ = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
//smac
   //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable start 1 of 21
   /*inBankCopy*/
   strTCT.inBankCopy = sqlite3_column_int(stmt,inStmtSeq +=1 );
   
   /*inCustomerCopy*/
   strTCT.inCustomerCopy = sqlite3_column_int(stmt,inStmtSeq +=1 );
   
   /*inMerchantCopy*/
   strTCT.inMerchantCopy = sqlite3_column_int(stmt,inStmtSeq +=1 );
   //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable end 1 of 21

       //add param for auto DL enable/disable
       //fAutoDownloadEnable
   		strTCT.fAutoDownloadEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
   
	   //aaronnino for remote download setup 2 of 12 start
	   /* usTMSGap */
	   strTCT.usTMSGap = sqlite3_column_int(stmt,inStmtSeq +=1 );
	   /* inTMSComMode */
	   strTCT.inTMSComMode = sqlite3_column_int(stmt,inStmtSeq +=1 );
   
	   /* usTMSRemotePort */
	   strTCT.usTMSRemotePort = sqlite3_column_int(stmt,inStmtSeq +=1 );
   
	   /* szTMSRemoteIP */
	   //memcpy(strTCT.szTMSRemoteIP, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 30);
   		strcpy((char*)strTCT.szTMSRemoteIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	   
	   /* szTMSRemotePhone */
	   //memcpy(strTCT.szTMSRemotePhone, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 30);
	   strcpy((char*)strTCT.szTMSRemotePhone, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
   
	   /* szTMSRemoteID */
	   //memcpy(strTCT.szTMSRemoteID, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 32);
	   strcpy((char*)strTCT.szTMSRemoteID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
   
	   /* szTMSRemotePW */
	   //memcpy(strTCT.szTMSRemotePW, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 32);
	   strcpy((char*)strTCT.szTMSRemotePW, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	   //aaronnino for remote download setup 2 of 12 end

		/* szLockPassword */
		strcpy((char*)strTCT.szLockPassword, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 )); /* BDO: Terminal screen lock -- jzg */

		 /* szCurrentDate */	 //aaronnino for BDOCLG ver 9.0 fix on issue#00032 "must settle" response on transactions per host after 1 day if batch is not empty 1 of 9 		
		strcpy((char*)strTCT.szCurrentDate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 )); 


		/*fFleetGetLiters*/
		strTCT.fFleetGetLiters = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
		/*fGetDescriptorCode*/
		strTCT.fGetDescriptorCode = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fSelectECRTrxn*/
		strTCT.fSelectECRTrxn = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		//ad header for Version - issue 00420
		strcpy((char*)strTCT.szAppVersionHeader, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

		/*fNextDayMustSettle*/ //aaronnino for BDOCLG ver 9.0 fix on issue#00032 "must settle" response on transactions per host after 1 day if batch is not empty 2 of 9
		strTCT.fNextDayMustSettle = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

        /*fEnableBinVerMKE*/
		strTCT.fEnableBinVerMKE = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fDefaultCashAdvance*/
		strTCT.fDefaultCashAdvance = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	

        /*fNSRCustCopy*/
        strTCT.fNSRCustCopy = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

	
		/* inSMACMode */
		strTCT.inSMACMode = sqlite3_column_int(stmt,inStmtSeq +=1 );

		
		/* ATPNII*/
		memcpy(strTCT.ATPNII, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);

		/*ATPTPDU*/
		memcpy(strTCT.ATPTPDU, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);

        //szPrintOption
        strcpy((char*)strTCT.szPrintOption, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

		/*inIdleTimeOut*/
		strTCT.inIdleTimeOut = sqlite3_column_int(stmt,inStmtSeq +=1 );
		
		strTCT.fPrintSummaryAll = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		strTCT.fPrintDetailAll = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
		
		strTCT.fInclude_DEBIT_SETTLEALL = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		strTCT.fInclude_INST_SETTLEALL = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		strTCT.fInclude_CUP_SETTLEALL = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
		/*szCTLSLimit */
		strcpy((char*)strTCT.szCTLSLimit, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
		/* inModemReceivingTime*/
		strTCT.inModemReceivingTime = sqlite3_column_int(stmt, inStmtSeq +=1 );

        strTCT.fCheckout = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fATPBinRoute*/
		strTCT.fATPBinRoute = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*byTerminalModel*/
		strTCT.byTerminalModel = sqlite3_column_int(stmt,inStmtSeq +=1 );

		/*byRS232ECRPort*/
		strTCT.byRS232ECRPort = sqlite3_column_int(stmt,inStmtSeq +=1 );
		
		/*fECRBaudRate*/
		strTCT.fECRBaudRate = sqlite3_column_int(stmt,inStmtSeq +=1 );
		
    	/*szMinTrxnAmt*/
		strcpy((char*)strTCT.szMinTrxnAmt, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fHotelSetup*/
		strTCT.fHotelSetup = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szMaxInstAmt*/
		strcpy((char*)strTCT.szMaxInstAmt, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

        strTCT.fSMMode = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
        strTCT.fSMReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
        strTCT.fSMLogo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 )); 

        strTCT.fEnableBalInqMKE = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 )); 

		strcpy((char*)strTCT.szSMReceiptLogo, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		strcpy((char*)strTCT.szBDOReceiptLogo, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		strTCT.fEnablePrintBalanceInq = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fSingleComms*/
        strTCT.fSingleComms = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*inECRTrxnMenu*/
		strTCT.inECRTrxnMenu = sqlite3_column_int(stmt,inStmtSeq +=1 );

		/*fECRISOLogging*/
		strTCT.fECRISOLogging = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*byERMMode*/
			strTCT.byERMMode = sqlite3_column_int(stmt,inStmtSeq +=1 );

        /*fDCC*/
        strTCT.fDCC = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*szIdleLogo1*/
		strcpy((char*)strTCT.szIdleLogo1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*szIdleLogo2*/
		strcpy((char*)strTCT.szIdleLogo2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*szIdleLogo3*/
		strcpy((char*)strTCT.szIdleLogo3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*inSMCardRetryCount*/
		strTCT.inSMCardRetryCount = sqlite3_column_int(stmt,inStmtSeq +=1 );

		/*fPrintReceiptPrompt*/
		strTCT.fPrintReceiptPrompt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

   		/* fISOLogging */
   		strTCT.fISOLogging = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
   
   		/* inTxnLogLimit */
   		strTCT.inTxnLogLimit = sqlite3_column_int(stmt,inStmtSeq +=1 );	

        strTCT.fReprintSettleStatus = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		strTCT.fPrintIssuerID = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fPrintDisplayBitmap*/
		strTCT.fDisplayPrintBitmap = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

        /*fSignatureFlag*/
		strTCT.fSignatureFlag = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/* inERMMaximum */
		strTCT.inERMMaximum = sqlite3_column_int(stmt,inStmtSeq +=1 );
		/* byERMInit */
		strTCT.byERMInit = sqlite3_column_int(stmt,inStmtSeq +=1 );		

		strTCT.inPrintISOOption = sqlite3_column_int(stmt,inStmtSeq +=1 );	

		/*fFormatDCCAmount*/
		strTCT.fFormatDCCAmount = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fFormatDCCAmount*/
		strTCT.fChangeDateMustSettle = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fDebitInsertEnable*/
		strTCT.fDebitInsertEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*inECRMode*/
		strTCT.inECRMode = sqlite3_column_int(stmt,inStmtSeq +=1 );

		/*fDisplayBattery */
		strTCT.fDisplayBattery = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fTapAndGo*/
		strTCT.fTapAndGo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
		/*fPrintFooterLogo*/
		strTCT.fPrintFooterLogo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*szTMSNACProtocol*/
		strcpy((char*)strTCT.szTMSNACProtocol, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*szTMSNACSourceAddr*/
		strcpy((char*)strTCT.szTMSNACSourceAddr, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*szTMSNACDestAddr*/
		strcpy((char*)strTCT.szTMSNACDestAddr, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*szMobileWalletLabel*/
		strcpy((char*)strTCT.szMobileWalletLabel, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*inBackupSettNumDays*/
		strTCT.inBackupSettNumDays = sqlite3_column_int(stmt,inStmtSeq +=1 );

		/*fDisplayAPPROVED*/
		strTCT.fDisplayAPPROVED = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fInsertAndGo*/
		strTCT.fInsertAndGo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*inDCCMode*/
		strTCT.inDCCMode = sqlite3_column_int(stmt,inStmtSeq +=1 );

		/*inSetMobileWalletLabel*/
		strTCT.inSetMobileWalletLabel = sqlite3_column_int(stmt,inStmtSeq +=1 );
		
        }
	} while (result == SQLITE_ROW);	

			wub_hex_2_str(strTCT.szInvoiceNo, szBuffer, 3);
			vdDebug_LogPrintf("inTCTRead szBuffer %s", szBuffer);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inResult);
}


int inTCTSave(int inSeekCnt)
{
	int result;
	
	/* CTLS: Added szMaxCTLSAmount to check CTLS max txn amount during runtime -- jzg */
   /* aaronnino for BDOCLG ver 9.0 fix on issue #0061 added fEnableManualKeyEntry 3 of 7*/
	/* aaronnino for BDOCLG ver 9.0 fix on issue #0066 added fDutyFreeMode 3 of 8*/
	/*aaronnino for BDOCLG ver 9.0 fix on issue#00078 added inBankCopy, inCustomerCopy, inMerchantCopy*/
	/*aaronnino for BDOCLG ver 9.0 fix on issue#00032 added szCurrentDate and fNextDayMustSettle*/	
	char *sql = "UPDATE TCT SET inMainLine = ?, fHandsetPresent = ?, fDemo = ?, fCVVEnable = ?, szSuperPW = ?, szSystemPW = ?, szEngineerPW = ?, szFunKeyPW = ?, szPMpassword = ?, szBInRoutePW=?, byRS232DebugPort = ?, inPrinterHeatLevel = ?, inWaitTime = ?, byCtlsMode = ?, fTipAllowFlag = ?, fDebitFlag = ?, inFallbackTimeGap = ?, fManualEntryInv = ?, szInvoiceNo = ?, szPabx = ?, szLastInvoiceNo = ?, inMenuid = ?, fDebugOpenedFlag = ?, fShareComEnable = ?, inReversalCount = ?, inTipAdjustCount = ?, fPrintISOMessage = ?, fConfirmPAN = ?, szMinInstAmt = ?, fFirstInit = ?,	fTrickleFeedEMVUpload=?,	fDualCurrency=?, fPrintExpiryDate=?, inMaxAdjust=?, fMaskPanDisplay=?, DisplayPANFormat=?, szMaxTrxnAmt=?, fPrintTipReceipt=?, byTerminalType=?, szMaxCTLSAmount=?, lnTipPercent=?, byPinPadPort=?, fEnableManualKeyEntry=?, fPrintSettleDetailReport=?, fDutyFreeMode=?, fScreenLocked=?, fMOTO=?, SMACRATE=?, DEACTDATE=?, SMACENABLE=?, SMZ=?, inBankCopy=?, inCustomerCopy=?, inMerchantCopy=?, fAutoDownloadEnable = ?, usTMSGap = ?, inTMSComMode = ?, usTMSRemotePort = ?, szTMSRemoteIP = ?, szTMSRemotePhone = ?, szTMSRemoteID = ?, szTMSRemotePW = ?, szLockPassword = ?,  szCurrentDate = ?, fFleetGetLiters=?, fGetDescriptorCode=?, fSelectECRTrxn=?, fNextDayMustSettle=?, fNSRCustCopy = ?, inSMACMode = ?, ATPNII=?, ATPTPDU=?, inModemReceivingTime=?, fATPBinRoute=?, fECR=?, byRS232ECRPort=?, fECRBaudRate=?, szMinTrxnAmt=?, fSingleComms=?, inECRTrxnMenu=?, fECRISOLogging = ?, byERMMode = ?, fISOLogging=?, inTxnLogLimit=?, fReprintSettleStatus=?, inERMMaximum = ?, byERMInit = ?, fChangeDateMustSettle = ?, fDebitInsertEnable = ?, inECRMode = ?, fDisplayBattery = ?, fTapAndGo =?,  fPrintFooterLogo =?,  inBackupSettNumDays = ?,  fDisplayAPPROVED = ?, fInsertAndGo = ? , inDCCMode = ?, inSetMobileWalletLabel = ? WHERE TCTid = ?"; 			

	//char *sql = "UPDATE TCT SET inMainLine = ?, fHandsetPresent = ?, fDemo = ?, fCVVEnable = ?, szSuperPW = ?, szSystemPW = ?, szEngineerPW = ?, szFunKeyPW = ?, szPMpassword = ?, byRS232DebugPort = ?, inPrinterHeatLevel = ?, inWaitTime = ?, byCtlsMode = ?, fTipAllowFlag = ?, fDebitFlag = ?, inFallbackTimeGap = ?, fManualEntryInv = ?, szInvoiceNo = ?, szPabx = ?, szLastInvoiceNo = ?, inMenuid = ?, fDebugOpenedFlag = ?, fShareComEnable = ?, inReversalCount = ?, inTipAdjustCount = ?, fPrintISOMessage = ?, fConfirmPAN = ?, szMinInstAmt = ?, fFirstInit = ?,	fTrickleFeedEMVUpload=?,	fDualCurrency=?, fPrintExpiryDate=?, inMaxAdjust=?, fMaskPanDisplay=?, DisplayPANFormat=?, szMaxTrxnAmt=?, fPrintTipReceipt=?, byTerminalType=?, szMaxCTLSAmount=?, lnTipPercent=?, byPinPadPort=?, fEnableManualKeyEntry=?, fPrintSettleDetailReport=?, inOnlineSettleTries=?, fDutyFreeMode=?, inManualSettleTrigger=?, fScreenLocked=?, fMOTO=?, SMACRATE=?, DEACTDATE=?, SMACENABLE=?, SMZ=?, inBankCopy=?, inCustomerCopy=?, inMerchantCopy=?,  usTMSGap = ?, inTMSComMode = ?, usTMSRemotePort = ?, szTMSRemoteIP = ?, szTMSRemotePhone = ?, szTMSRemoteID = ?, szTMSRemotePW = ?, szLockPassword = ?,  szCurrentDate = ?  WHERE	TCTid = ?"; 			


	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

		/* 07 JAn 2021
		CTOS_Delay(300);
		*/
		
		vdSetJournalModeOff();

    vdDebug_LogPrintf("[inTCTSave]-fDemo[%d]",strTCT.fDemo);
	//sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);   
    vdDebug_LogPrintf("[inTCTSave]-sqlite3_prepare_v2[%d]",result);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;

	/* inMainLine */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inMainLine);
	/* fHandsetPresent */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fHandsetPresent);
    /* fDemo */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fDemo);
	/* fCVVEnable */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fCVVEnable);
	/* szSuperPW */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCT.szSuperPW, strlen((char*)strTCT.szSuperPW), SQLITE_STATIC);
	/* szSystemPW */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCT.szSystemPW, strlen((char*)strTCT.szSystemPW), SQLITE_STATIC);
	/* szEngineerPW */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCT.szEngineerPW, strlen((char*)strTCT.szEngineerPW), SQLITE_STATIC);
	
	/* szFunKeyPW */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCT.szFunKeyPW, strlen((char*)strTCT.szFunKeyPW), SQLITE_STATIC);
	/* szPMpassword */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCT.szPMpassword, strlen((char*)strTCT.szPMpassword), SQLITE_STATIC);

	/*szBInRoutePW*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCT.szBInRoutePW, strlen((char*)strTCT.szBInRoutePW), SQLITE_STATIC);
	
	/* byRS232DebugPort */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.byRS232DebugPort);
	/* inPrinterHeatLevel */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inPrinterHeatLevel);
	/* inWaitTime */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inWaitTime);
	/* byCtlsMode */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.byCtlsMode);

	/* fTipAllowFlag */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fTipAllowFlag);

    /* fDebitFlag */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fDebitFlag);

    /*inFallbackTimeGap*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inFallbackTimeGap);

    /* fManualEntryInv */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fManualEntryInv);

	/* szInvoiceNo*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strTCT.szInvoiceNo, 3, SQLITE_STATIC);

    /* szPabx*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCT.szPabx, strlen((char*)strTCT.szPabx), SQLITE_STATIC);
	/* szLastInvoiceNo*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strTCT.szLastInvoiceNo, 3, SQLITE_STATIC);

	/* BDO CLG: Revised menu functions - start -- jzg */
	/* inMenuid */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inMenuid);
	/* BDO CLG: Revised menu functions - end -- jzg */

    /* fDebugOpenedFlag*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fDebugOpenedFlag);

    /* fShareComEnable*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fShareComEnable);

    /*inReversalCount*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inReversalCount);

    /*inTipAdjustCount*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inTipAdjustCount);

	//gcitra
	/*fPrintISOMessage*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fPrintISOMessage);

	/*fConfirmPAN*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fConfirmPAN);
	//gcitra

	/* szMinInstAmt*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strTCT.szMinInstAmt, 6, SQLITE_STATIC);

	/* fFirstInit */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fFirstInit);

	/*fTrickleFeedEMVUpload*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fTrickleFeedEMVUpload);
	
	/*fDualCurrency*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fDualCurrency);

	/*fPrintExpiryDate*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fPrintExpiryDate);

	/*inMaxAdjust*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inMaxAdjust);

        /*fMaskPanDisplay*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fMaskPanDisplay);

        /*DisplayPANFormat*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCT.DisplayPANFormat, strlen((char*)strTCT.DisplayPANFormat), SQLITE_STATIC);        
        
        //sidumili: Issue#:000076 [OUT OF RANGE]
        /* szMaxTrxnAmt*/
//        result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strTCT.szMaxTrxnAmt, 12, SQLITE_STATIC);

vdDebug_LogPrintf("JEFF::TCT SAVE MAX TXN AMT = [%s]", strTCT.szMaxTrxnAmt);

				result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCT.szMaxTrxnAmt, 13, SQLITE_STATIC);
		
		/*sidumili: Fix on Issue#: 000181*/
		/*fPrintTipReceipt*/
		result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fPrintTipReceipt);

	//Issue# 000166 - start -- jzg
	  /*fInstTCUpload*/
	  //result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fInstTCUpload);
	  //Issue# 000166 - end - jzg

	/*byTerminalType*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.byTerminalType);
	

	/* CTLS: Added szMaxCTLSAmount to check CTLS max txn amount during runtime -- jzg */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCT.szMaxCTLSAmount, strlen((char*)strTCT.szMaxCTLSAmount), SQLITE_STATIC);

  /*lnTipPercent*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.lnTipPercent);

	/*byPinPadPort*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.byPinPadPort);

	/*fEnableManualKeyEntry*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fEnableManualKeyEntry); //aaronnino for BDOCLG ver 9.0 fix on issue #0061 Manual Entry should not be allowed for BIN Check transactions 4 of 7

	/* BDO: Include detailed report to settlement receipt - start -- jzg */
	/* fPrintSettleDetailReport */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fPrintSettleDetailReport);
	/* BDO: Include detailed report to settlement receipt - end -- jzg */

	/* fDutyFreeMode */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fDutyFreeMode); //aaronnino for BDOCLG ver 9.0 fix on issue #00066 "APPR.CODE" single width printed on transaction receipt 4 of 8
	
		/* BDO CLG: Terminal lock screen - start -- jzg */
	/* fScreenLocked */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fScreenLocked);
	/* BDO CLG: Terminal lock screen - end -- jzg */


	/* BDO CLG: MOTO setup - start -- jzg */
	/* fMOTO */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fMOTO);
	/* BDO CLG: MOTO setup - end -- jzg */

//smac
	result = sqlite3_bind_double(stmt, inStmtSeq +=1, strTCT.SMACRATE);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strTCT.DEACTDATE, 20, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.SMACENABLE);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.SMZ);
//smac 

  //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable start 2 of 21
  /* inBankCopy */
  result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inBankCopy);
  
  /* inCustomerCopy */
  result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inCustomerCopy);
  
  /* inMerchantCopy */
  result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inMerchantCopy);
  //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable end 2 of 21


    //fAutoDownloadEnable  
  	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fAutoDownloadEnable);
    
	//aaronnino for remote download setup 4 of 12 start
		 /*usTMSGap*/
		result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.usTMSGap);
		
		/*inTMSComMode*/
		result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inTMSComMode);
	
			/*usTMSRemotePort*/
		result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.usTMSRemotePort);
	
			/* szTMSRemoteIP*/
		//result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strTCT.szTMSRemoteIP, 30, SQLITE_STATIC);
		result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCT.szTMSRemoteIP, strlen((char*)strTCT.szTMSRemoteIP), SQLITE_STATIC); 
	
			/* szTMSRemotePhone*/
		//result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strTCT.szTMSRemotePhone, 30, SQLITE_STATIC);
		result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCT.szTMSRemotePhone, strlen((char*)strTCT.szTMSRemotePhone), SQLITE_STATIC);
			
		/* szTMSRemoteID*/
		//result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strTCT.szTMSRemoteID, 32, SQLITE_STATIC);
		result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCT.szTMSRemoteID, strlen((char*)strTCT.szTMSRemoteID), SQLITE_STATIC);
		
		/* szTMSRemotePW*/
		//result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strTCT.szTMSRemotePW, 32, SQLITE_STATIC);
		result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCT.szTMSRemotePW, strlen((char*)strTCT.szTMSRemotePW), SQLITE_STATIC);
		
		//aaronnino for remote download setup 4 of 12 end	 


		/* szSystemPW */
		result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCT.szLockPassword, strlen((char*)strTCT.szLockPassword), SQLITE_STATIC); /* BDO: Terminal screen lock -- jzg */


    /*szCurrentDate*/ //aaronnino for BDOCLG ver 9.0 fix on issue#00032 "must settle" response on transactions per host after 1 day if batch is not empty 3 of 9
		result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCT.szCurrentDate, strlen((char*)strTCT.szCurrentDate), SQLITE_STATIC);

	/*fFleetGetLiters*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fFleetGetLiters);
	
	/*fGetDescriptorCode*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fGetDescriptorCode);

	/*fSelectECRTrxn*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fSelectECRTrxn);

	/*fNextDayMustSettle*/ //aaronnino for BDOCLG ver 9.0 fix on issue#00032 "must settle" response on transactions per host after 1 day if batch is not empty 4 of 9
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fNextDayMustSettle);
	
	/*fNSRCustCopy*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fNSRCustCopy);	
 
	/* inSMACMode */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inSMACMode);

	
	/* ATPNII*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strTCT.ATPNII, 2, SQLITE_STATIC);

	/*ATPTPDU*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strTCT.ATPTPDU, 5, SQLITE_STATIC);

	/*inModemReceivingTime*/
	  result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inModemReceivingTime); 

	/*fATPBinRoute*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fATPBinRoute);	

	/*fECR*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fECR);

	/*byRS232ECRPort*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.byRS232ECRPort);
	
	/*fECRBaudRate*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fECRBaudRate); 
	
  /*szMinTrxnAmt*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCT.szMinTrxnAmt, 13, SQLITE_STATIC);

  /*fSingleComms*/
  result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fSingleComms);	  

  /*inECRTrxnMenu*/
  result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inECRTrxnMenu);

  /*fECRISOLogging*/
  result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fECRISOLogging);	

	/* byERMMode */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.byERMMode);

	/* fISOLogging */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fISOLogging);
	
	/* inTxnLogLimit */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inTxnLogLimit);

	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fReprintSettleStatus);

	/*inERMMaximum*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inERMMaximum);
	
	/*byERMInit*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.byERMInit);

	/*fChangeDateMustSettle*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fChangeDateMustSettle);	

	/*fDebitInsertEnable*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fDebitInsertEnable);	

	/*inECRMode*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inECRMode);	
	/*fDisplayBattery*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fDisplayBattery);	
	/*fTapAndGo*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fTapAndGo);

	/*fPrintFooterLogo*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fPrintFooterLogo);	
	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inBackupSettNumDays);

	/*fDisplayAPPROVED*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fDisplayAPPROVED);

	/*fInsertAndGo*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.fInsertAndGo);

	/*inDCCMode*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inDCCMode);

	/*inSetMobileWalletLabel*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCT.inSetMobileWalletLabel);
	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
	
	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}
    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);
    vdDebug_LogPrintf("[inTCTSave]-end ");

    return(d_OK);
}


int inTCPRead(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT szTerminalIP, szGetWay, szSubNetMask, szHostDNS1, szHostDNS2, fDHCPEnable, szAPN, szUserName, szPassword, szWifiSSID, szWifiPassword, szWifiProtocal, szWifiPairwise, szWifiGroup, inSIMSlot FROM TCP WHERE TCPid = ?";
		
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
			inResult = d_OK;
			inStmtSeq = 0;

			/*szTerminalIP*/
			strcpy((char*)strTCP.szTerminalIP, (char *)sqlite3_column_text(stmt,inStmtSeq));
            				
			/* szGetWay */			
			strcpy((char*)strTCP.szGetWay, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szSubNetMask*/
			strcpy((char*)strTCP.szSubNetMask, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szHostDNS1*/
			strcpy((char*)strTCP.szHostDNS1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szHostDNS2*/
			strcpy((char*)strTCP.szHostDNS2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* fDHCPEnable */
			strTCP.fDHCPEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szAPN*/
			strcpy((char*)strTCP.szAPN, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /*szUserName*/
			strcpy((char*)strTCP.szUserName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /*szPassword*/
			strcpy((char*)strTCP.szPassword, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

						 /*szWifiSSID*/
			strcpy((char*)strTCP.szWifiSSID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

						  /*szWifiPassword*/
			strcpy((char*)strTCP.szWifiPassword, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

							 /*szWifiProtocal*/
			strcpy((char*)strTCP.szWifiProtocal, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

							  /*szWifiPairwise*/
			strcpy((char*)strTCP.szWifiPairwise, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

								/*szWifiGroup*/
			strcpy((char*)strTCP.szWifiGroup, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

								/* inSIMSlot */
		  strTCP.inSIMSlot = sqlite3_column_int(stmt,inStmtSeq +=1 );

		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inResult);
}

int inTCPSave(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE TCP SET szTerminalIP = ? ,szGetWay = ? ,szSubNetMask = ? ,szHostDNS1 = ? ,szHostDNS2 = ? ,fDHCPEnable = ? ,szAPN = ? ,szUserName = ? ,szPassword = ? WHERE  TCPid = ?";
		
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

	vdSetJournalModeOff();

	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
    /* szTerminalIP */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCP.szTerminalIP, strlen((char*)strTCP.szTerminalIP), SQLITE_STATIC);
	/* szGetWay */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCP.szGetWay, strlen((char*)strTCP.szGetWay), SQLITE_STATIC);
    /* szSubNetMask*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCP.szSubNetMask, strlen((char*)strTCP.szSubNetMask), SQLITE_STATIC);
	/* szHostDNS1*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCP.szHostDNS1, strlen((char*)strTCP.szHostDNS1), SQLITE_STATIC);
	/* szHostDNS2*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCP.szHostDNS2, strlen((char*)strTCP.szHostDNS2), SQLITE_STATIC);
    /* fDHCPEnable*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strTCP.fDHCPEnable);
    /* szAPN*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCP.szAPN, strlen((char*)strTCP.szAPN), SQLITE_STATIC);
    /* szUserName*/
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCP.szUserName, strlen((char*)strTCP.szUserName), SQLITE_STATIC);
    /* szPassword*/
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strTCP.szPassword, strlen((char*)strTCP.szPassword), SQLITE_STATIC);


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


int inMSGRead(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
  	char *sql = "select usMsgIndex, szMsg, szResponseCode, inHostIndex, szHostName from MSG where MSGid = ?";

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
			inResult = d_OK;
			inStmtSeq = 0;

            /*usMsgIndex*/
			strMSG.usMsgIndex = sqlite3_column_int(stmt,inStmtSeq);
    
            /* szMeg */
			strcpy((char*)strMSG.szMsg, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));


			/* szResponseCode */
			strcpy((char*)strMSG.szResponseCode, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));


			
			/* inHostIndex */
			strMSG.inHostIndex, sqlite3_column_int(stmt,inStmtSeq +=1 );


						
			/* szHostName */
			strcpy((char*)strMSG.szHostName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
   		}
	} while (result == SQLITE_ROW);	   

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inResult);
}

int inTLERead(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
   	char *sql = "select szVERSION, szTMKRefNum, szZMK, szTMK, szTAK, szTermPinEncryuptKey, szMACKey, szLineEncryptKey from TLE where TLEid = ?";
	
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
			inResult = d_OK;
			inStmtSeq = 0;

			/* szVERSION */
			memcpy(strTLE.szVERSION, sqlite3_column_blob(stmt,inStmtSeq), 2);

			/* szTMKRefNum*/
			strcpy((char*)strTLE.szTMKRefNum, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* Zone Master key*/
			memcpy(strTLE.szZMK, sqlite3_column_blob(stmt,inStmtSeq +=1), 16);
				
			/* Terminal Master key*/
			memcpy(strTLE.szTMK, sqlite3_column_blob(stmt,inStmtSeq +=1), 16);

			/* Terminal A key*/
			memcpy(strTLE.szTAK, sqlite3_column_blob(stmt,inStmtSeq +=1), 16);
				
			/* szTermPinEncryuptKey*/
			memcpy(strTLE.szTermPinEncryuptKey, sqlite3_column_blob(stmt,inStmtSeq +=1), 16);

			/* szMACKey*/
			memcpy(strTLE.szMACKey, sqlite3_column_blob(stmt,inStmtSeq +=1), 16);

			/* szLineEncryptKey*/
			memcpy(strTLE.szLineEncryptKey, sqlite3_column_blob(stmt,inStmtSeq +=1), 16);
   		}
	} while (result == SQLITE_ROW);	

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inResult);
}

int inTLESave(int inSeekCnt)
{   
    return d_OK;
}


int inWaveAIDRead(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql = "select ulRef, fAIDEnable, inAIDLen, pbAID, inApplication_Selection_Indicator, EMVid, inCAPKindex1, pbExpireDate1, pbCAPKExponent1, inCAPKindex2, pbExpireDate2, pbCAPKExponent2, inCAPKindex3, pbExpireDate3, pbCAPKExponent3, inCAPKindex4, pbExpireDate4, pbCAPKExponent4, inCAPKindex5, pbExpireDate5, pbCAPKExponent5, inCAPKindex6, pbExpireDate6, pbCAPKExponent6, inCAPKindex7, pbExpireDate7, pbCAPKExponent7, inCAPKindex8, pbExpireDate8, pbCAPKExponent8, inCAPKindex9, pbExpireDate9, pbCAPKExponent9, inCAPKindex10, pbExpireDate10, pbCAPKExponent10, pbTerminalAVN, pb2ndTerminalAVN from AID where AIDid = ? AND fAIDEnable = ?";

	/* open the database */
	result = sqlite3_open(DB_WAVE,&db);
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
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		
		//vdDebug_LogPrintf("strAIDT.result[%d]AIDid[%d]",result,inSeekCnt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;
			
            /*ulRef*/
			strWaveAIDT.ulRef = sqlite3_column_double(stmt, inStmtSeq);

            /* fAIDEnable */
			strWaveAIDT.fAIDEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /*inAIDLen*/
			strWaveAIDT.inAIDLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			//Debug_LogPrintf("strAIDT.inAIDLen[%d]",strAIDT.inAIDLen);

			/* pbAID */
			memcpy(strWaveAIDT.pbAID, sqlite3_column_blob(stmt,inStmtSeq +=1 ), strWaveAIDT.inAIDLen);
			vdDebug_LogPrintf("strAIDT.inAIDLen[%d]",strWaveAIDT.inAIDLen);
            DebugAddHEX("AID =",strWaveAIDT.pbAID,strWaveAIDT.inAIDLen);
                 
            /*inApplication_Selection_Indicator*/
			strWaveAIDT.inApplication_Selection_Indicator = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*EMVid*/
			strWaveAIDT.EMVid = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*inCAPKindex1*/
			strWaveAIDT.inCAPKindex1 = sqlite3_column_int(stmt,inStmtSeq +=1 );
            /* pbExpireDate1*/
			strcpy((char*)strWaveAIDT.pbExpireDate1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* pbCAPKExponent1*/
			strcpy((char*)strWaveAIDT.pbCAPKExponent1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
			/*inCAPKindex2*/
			strWaveAIDT.inCAPKindex2 = sqlite3_column_int(stmt,inStmtSeq +=1 );
            /* pbExpireDate2*/
			strcpy((char*)strWaveAIDT.pbExpireDate2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* pbCAPKExponent2*/
			strcpy((char*)strWaveAIDT.pbCAPKExponent2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex3*/
			strWaveAIDT.inCAPKindex3 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate3*/
			strcpy((char*)strWaveAIDT.pbExpireDate3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* pbCAPKExponent3*/
			strcpy((char*)strWaveAIDT.pbCAPKExponent3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex4*/
			strWaveAIDT.inCAPKindex4 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate4*/
			strcpy((char*)strWaveAIDT.pbExpireDate4, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* pbCAPKExponent4*/
			strcpy((char*)strWaveAIDT.pbCAPKExponent4, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		
			/*inCAPKindex5*/
			strWaveAIDT.inCAPKindex5 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate5*/
			strcpy((char*)strWaveAIDT.pbExpireDate5, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* pbCAPKExponent5*/
			strcpy((char*)strWaveAIDT.pbCAPKExponent5, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex6*/
			strWaveAIDT.inCAPKindex6 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate6*/
			strcpy((char*)strWaveAIDT.pbExpireDate6, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* pbCAPKExponent6*/
			strcpy((char*)strWaveAIDT.pbCAPKExponent6, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

					
			/*inCAPKindex7*/
			strWaveAIDT.inCAPKindex7 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate7*/
			strcpy((char*)strWaveAIDT.pbExpireDate7, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* pbCAPKExponent7*/
			strcpy((char*)strWaveAIDT.pbCAPKExponent7, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex8*/
			strWaveAIDT.inCAPKindex8 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate8*/
			strcpy((char*)strWaveAIDT.pbExpireDate8, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* pbCAPKExponent8*/
			strcpy((char*)strWaveAIDT.pbCAPKExponent8, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex9*/
			strWaveAIDT.inCAPKindex9 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate9*/
			strcpy((char*)strWaveAIDT.pbExpireDate9, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* pbCAPKExponent9*/
			strcpy((char*)strWaveAIDT.pbCAPKExponent9, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inCAPKindex10*/
			strWaveAIDT.inCAPKindex10 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/* pbExpireDate10*/
			strcpy((char*)strWaveAIDT.pbExpireDate10, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* pbCAPKExponent10*/
			strcpy((char*)strWaveAIDT.pbCAPKExponent10, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* pbTerminalAVN */
			memcpy(strWaveAIDT.pbTerminalAVN, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);
			/* pb2ndTerminalAVN */
			memcpy(strWaveAIDT.pb2ndTerminalAVN, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);


		}
	} while (result == SQLITE_ROW);	   

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	//�ر�sqlite����
	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inResult);
}


int inWaveEMVRead(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
 	char *sql = "SELECT szASI, szSchemeID,szActivate,szTerminalType,szEMVTermCapabilities,szEMVTermAddCapabilities,szAppVerNo,szEMVTermCountryCode,szEMVTermCurrencyCode,szTransactionType,lnEMVFloorLimit,szVisaWaveVLPIndicator,szVisaWaveTTQ,szDefaultTDOL,szDefaultDDOL,inEMVTargetRSPercent,inEMVMaxTargetRSPercent,lnEMVRSThreshold,szEMVTACDefault,szEMVTACDenial,szEMVTACOnline,szUploadDOL,szAEPara,szTransactionResult,szVisMSDCVN17Enable,szTerminalIdentification,szIFDSerialNumber,szMerchantIdentifier,inVisaMSDTrack1Enable,inVisaMSDTrack2Enable,inDisplayOfflineIndicator,szStatusCheck,szAmount0Check,szCLTranslimit,szCLCVMlimit,szCLFloorlimit, szCVN17UploadDOL, szAdditionalDataUploadDOL FROM EMV WHERE EMVid = ?";

	/* open the database */
	result = sqlite3_open(DB_WAVE,&db);
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
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		
		//Debug_LogPrintf("EMV read[%d]",result);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;
	
			/* szASI */
		   strcpy((char*)strWaveEMVT.szASI, (char *)sqlite3_column_text(stmt,inStmtSeq));
//			vdDebug_LogPrintf("szASI=[%s]",strWaveEMVT.szASI);
	   
		    /* szSchemeID */
		   strcpy((char*)strWaveEMVT.szSchemeID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
//			vdDebug_LogPrintf("szSchemeID=[%s]",strWaveEMVT.szSchemeID);
            /*szActivate;*/
			strWaveEMVT.szActivate = sqlite3_column_int(stmt,inStmtSeq +=1 );
//			vdDebug_LogPrintf("szActivate=[%d]",strWaveEMVT.szActivate);
			/* szSchemeID */
			strcpy((char*)strWaveEMVT.szTerminalType, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
//			vdDebug_LogPrintf("szTerminalType=[%s]",strWaveEMVT.szTerminalType);
			 /* szEMVTermCapabilities*/
			memcpy(strWaveEMVT.szEMVTermCapabilities, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);
            DebugAddHEX("szEMVTermCapabilities",strWaveEMVT.szEMVTermCapabilities,4);  
            /* szEMVTermAddCapabilities */
			memcpy(strWaveEMVT.szEMVTermAddCapabilities, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 6);
    		DebugAddHEX("szEMVTermAddCapabilities",strWaveEMVT.szEMVTermAddCapabilities,6); 
			/* szAppVerNo */
		    memcpy((char*)strWaveEMVT.szAppVerNo, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),3);
			DebugAddHEX("szAppVerNo",strWaveEMVT.szAppVerNo,3);
			/* szEMVTermCountryCode */
		   memcpy(strWaveEMVT.szEMVTermCountryCode, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);
		   DebugAddHEX("szEMVTermCountryCode",strWaveEMVT.szEMVTermCountryCode,3); 
		   /* szEMVTermCurrencyCode */		  //20
		   memcpy(strWaveEMVT.szEMVTermCurrencyCode, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);
			DebugAddHEX("szEMVTermCurrencyCode",strWaveEMVT.szEMVTermCurrencyCode,3); 
		   /* szAppVerNo */
		   memcpy((char*)strWaveEMVT.szTransactionType, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),2);
			DebugAddHEX("szTransactionType=",strWaveEMVT.szTransactionType,2);
            /*lnEMVFloorLimit*/
			memcpy((char*)strWaveEMVT.lnEMVFloorLimit, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),5);
			DebugAddHEX("lnEMVFloorLimit=",strWaveEMVT.lnEMVFloorLimit,5);
			/* szVisaWaveVLPIndicator */
			memcpy((char*)strWaveEMVT.szVisaWaveVLPIndicator, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),2);
			DebugAddHEX("szVisaWaveVLPIndicator=",strWaveEMVT.szVisaWaveVLPIndicator,2);
			/* szVisaWaveTTQ */
			memcpy((char*)strWaveEMVT.szVisaWaveTTQ, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),5);
			DebugAddHEX("szVisaWaveTTQ=",strWaveEMVT.szVisaWaveTTQ,5);
            /* szDefaultTDOL */
			memcpy((char*)strWaveEMVT.szDefaultTDOL, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),4);
           DebugAddHEX("szDefaultTDOL=",strWaveEMVT.szDefaultTDOL,4);
            /* szDefaultDDOL */
			memcpy((char*)strWaveEMVT.szDefaultDDOL, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),4);
			DebugAddHEX("szDefaultDDOL=",strWaveEMVT.szDefaultDDOL,4);
            /*inEMVTargetRSPercent*/
			memcpy((char*)strWaveEMVT.inEMVTargetRSPercent, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),2);
           DebugAddHEX("inEMVTargetRSPercent=",strWaveEMVT.inEMVTargetRSPercent,2);    
            /*inEMVMaxTargetRSPercent*/
			memcpy((char*)strWaveEMVT.inEMVMaxTargetRSPercent, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),2);
			DebugAddHEX("inEMVMaxTargetRSPercent=",strWaveEMVT.inEMVMaxTargetRSPercent,2);    
			/*lnEMVRSThreshold*/			//5
			memcpy((char*)strWaveEMVT.lnEMVRSThreshold, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),5);
			DebugAddHEX("lnEMVRSThreshold=",strWaveEMVT.lnEMVRSThreshold,5);
			/* szEMVTACDefault */			 //10
		   memcpy(strWaveEMVT.szEMVTACDefault, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);
		  DebugAddHEX("szEMVTACDefault",strWaveEMVT.szEMVTACDefault,5); 
		   /* szEMVTACDenial */ 		   
		   memcpy(strWaveEMVT.szEMVTACDenial, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);
		   DebugAddHEX("szEMVTACDenial",strWaveEMVT.szEMVTACDenial,5); 
		   /* szEMVTACOnline */
		   memcpy(strWaveEMVT.szEMVTACOnline, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);
  			DebugAddHEX("szEMVTACOnline",strWaveEMVT.szEMVTACOnline,5);
		   /* szUploadDOL */
		   memcpy((char*)strWaveEMVT.szUploadDOL, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),16);
			DebugAddHEX("szUploadDOL",strWaveEMVT.szUploadDOL,16);
			/* szAEPara */
			memcpy((char*)strWaveEMVT.szAEPara, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),7);
			DebugAddHEX("szAEPara",strWaveEMVT.szAEPara,7);
			/* szTransactionResult */
		   memcpy((char*)strWaveEMVT.szTransactionResult, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),2);
			DebugAddHEX("szTransactionResult=",strWaveEMVT.szTransactionResult,2);
			/* szVisMSDCVN17Enable */
			memcpy((char*)strWaveEMVT.szVisMSDCVN17Enable, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),2);
			DebugAddHEX("szVisMSDCVN17Enable=",strWaveEMVT.szVisMSDCVN17Enable,2);
			/* szTerminalIdentification */
		   memcpy((char*)strWaveEMVT.szTerminalIdentification, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),9);
			DebugAddHEX("szTerminalIdentification=",strWaveEMVT.szTerminalIdentification,9);
			/* szIFDSerialNumber */
			memcpy((char*)strWaveEMVT.szIFDSerialNumber, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),9);
			DebugAddHEX("szIFDSerialNumber=",strWaveEMVT.szIFDSerialNumber,9);
			/* szMerchantIdentifier */
			memcpy((char*)strWaveEMVT.szMerchantIdentifier, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),16);
			DebugAddHEX("szMerchantIdentifier",strWaveEMVT.szMerchantIdentifier,16);
			/*inVisaMSDTrack1Enable*/
			memcpy((char*)strWaveEMVT.inVisaMSDTrack1Enable, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),2);
           DebugAddHEX("inVisaMSDTrack1Enable=",strWaveEMVT.inVisaMSDTrack1Enable,2);    
            /*inEMVMaxTargetRSPercent*/
 			memcpy((char*)strWaveEMVT.inVisaMSDTrack2Enable, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),2);
			DebugAddHEX("inVisaMSDTrack2Enable=",strWaveEMVT.inVisaMSDTrack2Enable,2);
			/*inDisplayOfflineIndicator*/
 			memcpy((char*)strWaveEMVT.inDisplayOfflineIndicator, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),2);
			DebugAddHEX("inDisplayOfflineIndicator=",strWaveEMVT.inDisplayOfflineIndicator,2);

			 /* szStatusCheck */
		   memcpy((char*)strWaveEMVT.szStatusCheck, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),2);
			DebugAddHEX("szStatusCheck=",strWaveEMVT.szStatusCheck,2);
			/* szAmount0Check */
			memcpy((char*)strWaveEMVT.szAmount0Check, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),2);
			DebugAddHEX("szAmount0Check=",strWaveEMVT.szAmount0Check,2);
			/* szCLTranslimit */
		   memcpy((char*)strWaveEMVT.szCLTranslimit, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),7);
			DebugAddHEX("szCLTranslimit",strWaveEMVT.szCLTranslimit,7);
			/* szCLCVMlimit */
			memcpy((char*)strWaveEMVT.szCLCVMlimit, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),7);
			DebugAddHEX("szCLCVMlimit=",strWaveEMVT.szCLCVMlimit,7);
			/* szCLFloorlimit */
		   memcpy((char*)strWaveEMVT.szCLFloorlimit, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),7);
			DebugAddHEX("szCLFloorlimit=",strWaveEMVT.szCLFloorlimit,7);
			/* szCVN17UploadDOL */
			memcpy((char*)strWaveEMVT.szCVN17UploadDOL, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),70);
			DebugAddHEX("szCVN17UploadDOL=",strWaveEMVT.szCVN17UploadDOL,70);
			/* szAdditionalDataUploadDOL */
			memcpy((char*)strWaveEMVT.szAdditionalDataUploadDOL, (char *)sqlite3_column_blob(stmt,inStmtSeq +=1 ),7);
			DebugAddHEX("szAdditionalDataUploadDOL=",strWaveEMVT.szAdditionalDataUploadDOL,7);
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	//�ر�sqlite����
	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inResult);
}


int inDatabase_BatchDeleteHDTidMITid(void)
{
	int result;
	char *sql = "DELETE FROM TransData WHERE HDTid = ? AND MITid = ?";	
	int inDBResult = 0;
	
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

	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

	inDBResult = sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	
	vdDebug_LogPrintf("Batch delete,sqlite3_exec[%d]",inDBResult);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(ST_SUCCESS);
}

int inDatabase_BatchDelete(void)
{
	int result;
	char *sql = "DELETE FROM TransData WHERE (szHostLabel = ? AND szBatchNo = ? AND MITid = ?)";	
	int inDBResult = 0;
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
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srTransRec.szHostLabel, strlen((char*)srTransRec.szHostLabel), SQLITE_STATIC); 
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, srTransRec.szBatchNo, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, srTransRec.MITid);


	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

    
	inDBResult = sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	
	vdDebug_LogPrintf("Batch dele,sqlite3_exec[%d]MITid[%d]",inDBResult,srTransRec.MITid);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(ST_SUCCESS);
}

int inDatabase_BatchRead(TRANS_DATA_TABLE *transData, int inSeekCnt)
{
	int result;
	int inResult = d_NO;

	/* Issue# 000096: BIN VER Checking -- jzg*/
	char *sql = "SELECT MITid, HDTid, CDTid, IITid, byTransType, byPanLen, szExpireDate, byEntryMode, szTotalAmount, szBaseAmount, szTipAmount, byOrgTransType, szMacBlock, szYear, szDate, szTime, szOrgDate, szOrgTime, szAuthCode, szRRN, szInvoiceNo, szOrgInvoiceNo, byPrintType, byVoided, byAdjusted, byUploaded, byTCuploaded, szCardholderName, szzAMEX4DBC, szStoreID, szRespCode, szServiceCode, byContinueTrans, byOffline, byReversal, byEMVFallBack, shTransResult, szTpdu, szIsoField03, szMassageType, szPAN, szCardLable, usTrack1Len, usTrack2Len, usTrack3Len, szTrack1Data, szTrack2Data, szTrack3Data, usChipDataLen, baChipData, usAdditionalDataLen, baAdditionalData, bWaveSID,usWaveSTransResult,bWaveSCVMAnalysis,ulTraceNum, ulOrgTraceNum, usTerminalCommunicationMode, ulSavedIndex, byPINEntryCapability, byPackType, szOrgAmount, szCVV2, inCardType, byTCFailUpCnt, byCardTypeNum, byEMVTransStatus, T5A_len, T5A, T5F2A, T5F30, T5F34, T5F34_len, T82, T84_len, T84, T8A, T91, T91Len, T95, T9A, T9C, T9F02, T9F03, T9F09, T9F10_len, T9F10, T9F1A, T9F26, T9F27, T9F33, T9F34, T9F35, T9F36_len, T9F36, T9F37, T9F41, T9F53, ISR, ISRLen, T9B, T5F24, T71Len, T71, T72Len, T72, T9F06, T9F1E, T9F28, T9F29, szChipLabel, szTID, szMID, szHostLabel, szBatchNo, inNumOfAdjust, fTIPAllow, fBINVer, szBINVerSTAN, szPolicyNumber, inSavedCurrencyIdx, fFooterLogo, fOnlineSALE, fCompletion, fVoidOffline, SmacPoints, SmacBalance, inSmacTender, fFleetCard, inFleetNumofLiters, szFleetProductCode, szFleetProductDesc, szSMACAmount, fECRTriggerTran, szPOSTID, szDCCCur, szDCCCurAmt, inDCCCurMU, szDCCFXRate, inDCCFXRateMU, szDCCFXRateRefID, szDCCCardType, szDCCFXMID, szDCCFXTID, szDCCMerchPOS, szDCCMarkupPer, inDCCMarkupPerMU, fDCC, szDCCCurSymbol, szDCCLocalAmount, szDCCLocalCur, szDCCLocalSymbol, fPrintSMCardHolder, fPrintCardHolderBal, fSMACFooter, fPrintExpFlag, byPreviouslyUploaded, szOrgRRN, szDCCLocalTipAmount, szSMACBDORewardsBalance, szLocalStoreID, fDualBrandedCredit, fDCCAuth, fBINRouteApproved, T9F6E, T9F6E_len, szBarcodeText FROM TransData WHERE ulSavedIndex = ?";

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
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);

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
			transData->usChipDataLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->baChipData, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 1024);
			transData->usAdditionalDataLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->baAdditionalData, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 1024);
			transData->bWaveSID = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->usWaveSTransResult = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->bWaveSCVMAnalysis = sqlite3_column_int(stmt,inStmtSeq +=1 );
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
			/*inNumOfAdjust*/	
			transData->inNumOfAdjust = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/*fTIPAllow*/
			transData->fTIPAllow = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/* Issue# 000096: BIN VER Checking - start -- jzg*/
			/* fBINVer */
			transData->fBINVer = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szBINVerSTAN */
			strcpy((char*)transData->szBINVerSTAN, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* Issue# 000096: BIN VER Checking - end -- jzg*/

			/*sidumili: Issue#: 00026*/
			/*szPolicyNumber*/
			strcpy((char*)transData->szPolicyNumber, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*Issue#: 000299 -- sidumili*/
			transData->inSavedCurrencyIdx = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*sidumili -- checking to print footer logo*/
			/*fFooterLogo*/
			transData->fFooterLogo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
			/*fOnlineSALE*/
			transData->fOnlineSALE = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fCompletion*/	
			transData->fCompletion = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fVoidOffline*/
			transData->fVoidOffline = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
//smac
			memcpy(transData->SmacPoints, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);
			memcpy(transData->SmacBalance, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);
			transData->inSmacTender = sqlite3_column_int(stmt,inStmtSeq +=1 );
//smac			


			/* BDOCLG-00321: Print fleet details also for duplicate receipts - start -- jzg */
			transData->fFleetCard = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1));
			transData->inFleetNumofLiters = sqlite3_column_int(stmt,inStmtSeq +=1);
			strcpy((char*)transData->szFleetProductCode, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			strcpy((char*)transData->szFleetProductDesc, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/* BDOCLG-00321: Print fleet details also for duplicate receipts - end -- jzg */

			/*BDO: For SMAC -- sidumili*/
			memcpy(transData->szSMACAmount, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);

			/*fECRTriggerTran*/
			transData->fECRTriggerTran = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szPOSTID*/
			strcpy((char*)transData->szPOSTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

      /*DCC - start*/
      strcpy((char*)transData->szDCCCur, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
      strcpy((char*)transData->szDCCCurAmt, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
      transData->inDCCCurMU = sqlite3_column_int(stmt,inStmtSeq +=1);
      strcpy((char*)transData->szDCCFXRate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
      transData->inDCCFXRateMU = sqlite3_column_int(stmt,inStmtSeq +=1);
      strcpy((char*)transData->szDCCFXRateRefID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
      strcpy((char*)transData->szDCCCardType, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
      strcpy((char*)transData->szDCCFXMID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
      strcpy((char*)transData->szDCCFXTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
      strcpy((char*)transData->szDCCMerchPOS, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
      strcpy((char*)transData->szDCCMarkupPer, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
      transData->inDCCMarkupPerMU = sqlite3_column_int(stmt,inStmtSeq +=1);		
      transData->fDCC = sqlite3_column_int(stmt,inStmtSeq +=1 );			
      strcpy((char*)transData->szDCCCurSymbol, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
      memcpy(transData->szDCCLocalAmount, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);
      strcpy((char*)transData->szDCCLocalCur, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
      strcpy((char*)transData->szDCCLocalSymbol, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
      /*DCC - end*/

      /*fPrintSMCardHolder*/
	  transData->fPrintSMCardHolder = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	  transData->fPrintCardHolderBal = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	  transData->fSMACFooter = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	  transData->fPrintExpFlag = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	  transData->byPreviouslyUploaded = sqlite3_column_int(stmt,inStmtSeq +=1 );
	  memcpy(transData->szOrgRRN, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 13);

        memcpy(transData->szDCCLocalTipAmount, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);
		strcpy((char*)transData->szSMACBDORewardsBalance, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
		memcpy(transData->szLocalStoreID, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 19);						
		transData->fDualBrandedCredit = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));	
		transData->fDCCAuth = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		transData->fBINRouteApproved = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		memcpy(transData->stEMVinfo.T9F6E, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);
		transData->stEMVinfo.T9F6E_len = sqlite3_column_int(stmt,inStmtSeq +=1 );
		//version16
		strcpy((char*)transData->szBarcodeText, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	

		
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inResult);
}

int inDatabase_BatchReadByHostidAndMITid(TRANS_DATA_TABLE *transData,int inHDTid,int inMITid)
{
	int result;
	int inResult = d_NO;
	
	/* Issue# 000096: BIN VER Checking -- jzg*/
	char *sql = "SELECT MITid, HDTid, CDTid, IITid, byTransType, byPanLen, szExpireDate, byEntryMode, szTotalAmount, szBaseAmount, szTipAmount, byOrgTransType, szMacBlock, szYear, szDate, szTime, szOrgDate, szOrgTime, szAuthCode, szRRN, szInvoiceNo, szOrgInvoiceNo, byPrintType, byVoided, byAdjusted, byUploaded, byTCuploaded, szCardholderName, szzAMEX4DBC, szStoreID, szRespCode, szServiceCode, byContinueTrans, byOffline, byReversal, byEMVFallBack, shTransResult, szTpdu, szIsoField03, szMassageType, szPAN, szCardLable, usTrack1Len, usTrack2Len, usTrack3Len, szTrack1Data, szTrack2Data, szTrack3Data, usChipDataLen, baChipData, usAdditionalDataLen, baAdditionalData, bWaveSID,usWaveSTransResult,bWaveSCVMAnalysis, ulTraceNum, ulOrgTraceNum, usTerminalCommunicationMode, ulSavedIndex, byPINEntryCapability, byPackType, szOrgAmount, szCVV2, inCardType, byTCFailUpCnt, byCardTypeNum, byEMVTransStatus, T5A_len, T5A, T5F2A, T5F30, T5F34, T5F34_len, T82, T84_len, T84, T8A, T91, T91Len, T95, T9A, T9C, T9F02, T9F03, T9F09, T9F10_len, T9F10, T9F1A, T9F26, T9F27, T9F33, T9F34, T9F35, T9F36_len, T9F36, T9F37, T9F41, T9F53, ISR, ISRLen, T9B, T5F24, T71Len, T71, T72Len, T72, T9F06, T9F1E, T9F28, T9F29, szChipLabel, fBINVer, szBINVerSTAN, szPolicyNumber, inSavedCurrencyIdx, fFooterLogo, fECRTriggerTran, T9F6E, T9F6E_len, szBarcodeText FROM TransData WHERE HDTid = ? AND MITid = ?";

	int incount = 0;
	
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
	
	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inHDTid);
	sqlite3_bind_int(stmt, inStmtSeq +=1, inMITid);
	
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
			transData->usChipDataLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->baChipData, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 1024);
			transData->usAdditionalDataLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->baAdditionalData, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 1024);			
			transData->bWaveSID = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->usWaveSTransResult = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->bWaveSCVMAnalysis = sqlite3_column_int(stmt,inStmtSeq +=1 );
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

			/* Issue# 000096: BIN VER Checking - start -- jzg*/
			/* fBINVer */
			transData->fBINVer = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
			/* szBINVerSTAN */
			strcpy((char*)transData->szBINVerSTAN, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* Issue# 000096: BIN VER Checking - end -- jzg*/

			/*sidumili: Issue#: 000269*/
			/*szPolicyNumber*/
			strcpy((char*)transData->szPolicyNumber, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*Issue# 000299 -- sidumili*/
			/*inSavedCurrencyIdx*/
			transData->inSavedCurrencyIdx = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*fFooterLogo -- sidumili*/
			transData->fFooterLogo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fECRTriggerTran*/
			transData->fECRTriggerTran = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	       /*T9F6E*/
		   memcpy(transData->stEMVinfo.T9F6E, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);
			transData->stEMVinfo.T9F6E_len = sqlite3_column_int(stmt,inStmtSeq +=1 );

			//version16
			strcpy((char*)transData->szBarcodeText, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			
		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);
    
    return(inResult);
}


int inDatabase_BatchInsert(TRANS_DATA_TABLE *transData)
{
	int result;	
	char *sql1 = "SELECT MAX(TransDataid) FROM TransData";

	/* Issue# 000096: BIN VER Checking -- jzg*/
 	char *sql = "INSERT INTO TransData (TransDataid, HDTid, MITid, CDTid, IITid, szHostLabel, szBatchNo, byTransType, byPanLen, szExpireDate, byEntryMode, szTotalAmount, szBaseAmount, szTipAmount, byOrgTransType, szMacBlock, szYear, szDate, szTime, szOrgDate, szOrgTime, szAuthCode, szRRN, szInvoiceNo, szOrgInvoiceNo, byPrintType, byVoided, byAdjusted, byUploaded, byTCuploaded, szCardholderName, szzAMEX4DBC, szStoreID, szRespCode, szServiceCode, byContinueTrans, byOffline, byReversal, byEMVFallBack, shTransResult, szTpdu, szIsoField03, szMassageType, szPAN, szCardLable, usTrack1Len, usTrack2Len, usTrack3Len, szTrack1Data, szTrack2Data, szTrack3Data, usChipDataLen, baChipData, usAdditionalDataLen, baAdditionalData, bWaveSID,usWaveSTransResult,bWaveSCVMAnalysis, ulTraceNum, ulOrgTraceNum, usTerminalCommunicationMode, ulSavedIndex, byPINEntryCapability, byPackType, szOrgAmount, szCVV2, inCardType, byTCFailUpCnt, byCardTypeNum, byEMVTransStatus, T5A_len, T5A, T5F2A, T5F30, T5F34, T5F34_len, T82, T84_len, T84, T8A, T91, T91Len, T95, T9A, T9C, T9F02, T9F03, T9F09, T9F10_len, T9F10, T9F1A, T9F26, T9F27, T9F33, T9F34, T9F35, T9F36_len, T9F36, T9F37, T9F41, T9F53, ISR, ISRLen, T9B, T5F24, T71Len, T71, T72Len, T72, T9F06, T9F1E, T9F28, T9F29, szChipLabel, szTID, szMID, szHostLabel, szBatchNo, inNumOfAdjust, fTIPAllow, fBINVer, szBINVerSTAN, szPolicyNumber, inSavedCurrencyIdx, fFooterLogo, fOnlineSALE, fCompletion, fVoidOffline, SmacPoints, SmacBalance, inSmacTender, fFleetCard, inFleetNumofLiters, szFleetProductCode, szFleetProductDesc, szSMACAmount, fECRTriggerTran, szPOSTID, szDCCCur, szDCCCurAmt, inDCCCurMU, szDCCFXRate, inDCCFXRateMU, szDCCFXRateRefID, szDCCCardType, szDCCFXMID, szDCCFXTID, szDCCMerchPOS, szDCCMarkupPer, inDCCMarkupPerMU, fDCC, szDCCCurSymbol, szDCCLocalAmount, szDCCLocalCur, szDCCLocalSymbol, fPrintSMCardHolder, fPrintCardHolderBal, fSMACFooter, fPrintExpFlag, byPreviouslyUploaded, szOrgRRN, szDCCLocalTipAmount, szSMACBDORewardsBalance, szLocalStoreID, fDualBrandedCredit, fDCCAuth, fBINRouteApproved, T9F6E, T9F6E_len, fOptOutComplete, fQuasiCash, bySMACPay_CardSeqNo, bySMACPay_CardStatus, bySMACPay_CardPerDate, bySMACPay_LastDataSync, bySMACPay_ExpiryDate, bySMACPay_MemberSince, fVirtualCard, fSignPadBypassSignature, szBarcodeText, fSMACPrintscan) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";


	/* open the database */
	result = sqlite3_open(DB_BATCH,&db);
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
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usChipDataLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->baChipData, 1024, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usAdditionalDataLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->baAdditionalData, 1024, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->bWaveSID);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usWaveSTransResult);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->bWaveSCVMAnalysis);
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
		
	/*inNumOfAdjust*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->inNumOfAdjust);
	/*fTIPAllow*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fTIPAllow);


	/* Issue# 000096: BIN VER Checking - start -- jzg*/
	/* BIN Ver */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fBINVer);

	/* BIN Ver STAN */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szBINVerSTAN, strlen((char*)transData->szBINVerSTAN), SQLITE_STATIC);
	/* Issue# 000096: BIN VER Checking - end -- jzg*/

	/*sidumili: Issue#: 000269*/
	/*szPolicyNumber*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szPolicyNumber, strlen((char*)transData->szPolicyNumber), SQLITE_STATIC);
	
	/*Issue# 000299 -- sidumili*/
	/*inSavedCurrencyIdx*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->inSavedCurrencyIdx);

	/*fFooterLogo -- sidumili*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fFooterLogo);
	
	/*fOnlineSALE*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fOnlineSALE);

	/*fCompletion*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fCompletion);
	

  /*fVoidOffline*/	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fVoidOffline);

//smac
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->SmacPoints, 7, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->SmacBalance, 7, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->inSmacTender);	
//smac


	/* BDOCLG-00321: Print fleet details also for duplicate receipts - start -- jzg */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fFleetCard);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->inFleetNumofLiters);
  result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szFleetProductCode, strlen((char*)transData->szFleetProductCode), SQLITE_STATIC); 
  result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szFleetProductDesc, strlen((char*)transData->szFleetProductDesc), SQLITE_STATIC); 
	/* BDOCLG-00321: Print fleet details also for duplicate receipts - end -- jzg */

	/*BDO: For SMAC -- sidumili*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szSMACAmount, 7, SQLITE_STATIC);

	/*fECRTriggerTran*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fECRTriggerTran);

	/*szPOSTID*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szPOSTID, strlen((char*)transData->szPOSTID), SQLITE_STATIC); 

	/*DCC - start*/
  result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szDCCCur, strlen((char*)transData->szDCCCur), SQLITE_STATIC); 
  result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szDCCCurAmt, strlen((char*)transData->szDCCCurAmt), SQLITE_STATIC); 
  result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->inDCCCurMU);
  result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szDCCFXRate, strlen((char*)transData->szDCCFXRate), SQLITE_STATIC); 
  result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->inDCCFXRateMU);
  result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szDCCFXRateRefID, strlen((char*)transData->szDCCFXRateRefID), SQLITE_STATIC); 
  result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szDCCCardType, strlen((char*)transData->szDCCCardType), SQLITE_STATIC); 
  result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szDCCFXMID, strlen((char*)transData->szDCCFXMID), SQLITE_STATIC); 
  result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szDCCFXTID, strlen((char*)transData->szDCCFXTID), SQLITE_STATIC); 
  result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szDCCMerchPOS, strlen((char*)transData->szDCCMerchPOS), SQLITE_STATIC); 
  result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szDCCMarkupPer, strlen((char*)transData->szDCCMarkupPer), SQLITE_STATIC); 
  result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->inDCCMarkupPerMU);
  result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fDCC);
  result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szDCCCurSymbol, strlen((char*)transData->szDCCCurSymbol), SQLITE_STATIC); //szDCCCurSymbol
  result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szDCCLocalAmount, 7, SQLITE_STATIC);//szDCCLocalAmount
  result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szDCCLocalCur, strlen((char*)transData->szDCCLocalCur), SQLITE_STATIC); //szDCCLocalCur
  result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szDCCLocalSymbol, strlen((char*)transData->szDCCLocalSymbol), SQLITE_STATIC); //szDCCLocalSymbol
	/*DCC - end*/
  result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fPrintSMCardHolder);
  result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fPrintCardHolderBal);	
  result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fSMACFooter);	
  result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fPrintExpFlag);	
  result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byPreviouslyUploaded);
  result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szOrgRRN, 13, SQLITE_STATIC);
	
    result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szDCCLocalTipAmount, 7, SQLITE_STATIC);//szDCCLocalAmount
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szSMACBDORewardsBalance, strlen((char*)transData->szSMACBDORewardsBalance), SQLITE_STATIC); 	
		result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szLocalStoreID, 19, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fDualBrandedCredit);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fDCCAuth);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fBINRouteApproved);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F6E, 4, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F6E_len);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fOptOutComplete);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fQuasiCash);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->bySMACPay_CardSeqNo, 3, SQLITE_STATIC);//szDCCLocalAmount
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->bySMACPay_CardStatus, strlen((char*)transData->bySMACPay_CardStatus), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->bySMACPay_CardPerDate, strlen((char*)transData->bySMACPay_CardPerDate), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->bySMACPay_LastDataSync, strlen((char*)transData->bySMACPay_LastDataSync), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->bySMACPay_ExpiryDate, strlen((char*)transData->bySMACPay_ExpiryDate), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->bySMACPay_MemberSince, strlen((char*)transData->bySMACPay_MemberSince), SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fVirtualCard);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fSignPadBypassSignature);
	//version6
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szBarcodeText, strlen((char*)transData->szBarcodeText), SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fSMACPrintscan);////00160 - No SCAN label printed in Smac QR void receipt

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

int inDatabase_BatchUpdate(TRANS_DATA_TABLE *transData)
{
	int result;

	/* Issue# 000096: BIN VER Checking -- jzg*/
	char *sql = "UPDATE TransData SET HDTid = ?, MITid = ?, CDTid = ?, IITid = ?, szHostLabel = ?, szBatchNo = ?, byTransType = ?, byPanLen = ?, szExpireDate = ?, byEntryMode = ?, szTotalAmount = ?, szBaseAmount = ?, szTipAmount = ?, byOrgTransType = ?, szMacBlock = ?, szYear = ?, szDate = ?, szTime = ?, szOrgDate = ?, szOrgTime = ?, szAuthCode = ?, szRRN = ?, szInvoiceNo = ?, szOrgInvoiceNo = ?, byPrintType = ?, byVoided = ?, byAdjusted = ?, byUploaded = ?, byTCuploaded = ?, szCardholderName = ?, szzAMEX4DBC = ?, szStoreID = ?, szRespCode = ?, szServiceCode = ?, byContinueTrans = ?, byOffline = ?, byReversal = ?, byEMVFallBack = ?, shTransResult = ?, szTpdu = ?, szIsoField03 = ?, szMassageType = ?, szPAN = ?, szCardLable = ?, usTrack1Len = ?, usTrack2Len = ?, usTrack3Len = ?, szTrack1Data = ?, szTrack2Data = ?, szTrack3Data = ?, usChipDataLen = ?, baChipData = ?, usAdditionalDataLen = ?, baAdditionalData = ?, bWaveSID = ?,usWaveSTransResult = ?,bWaveSCVMAnalysis = ?, ulTraceNum = ?, ulOrgTraceNum = ?, usTerminalCommunicationMode = ?, ulSavedIndex = ?, byPINEntryCapability = ?, byPackType = ?, szOrgAmount = ?, szCVV2 = ?, inCardType = ?, byTCFailUpCnt = ?, byCardTypeNum = ?, byEMVTransStatus = ?, T5A_len = ?, T5A = ?, T5F2A = ?, T5F30 = ?, T5F34 = ?, T5F34_len = ?, T82 = ?, T84_len = ?, T84 = ?, T8A = ?, T91 = ?, T91Len = ?, T95 = ?, T9A = ?, T9C = ?, T9F02 = ?, T9F03 = ?, T9F09 = ?, T9F10_len = ?, T9F10 = ?, T9F1A = ?, T9F26 = ?, T9F27 = ?, T9F33 = ?, T9F34 = ?, T9F35 = ?, T9F36_len = ?, T9F36 = ?, T9F37 = ?, T9F41 = ?, T9F53 = ?, ISR = ?, ISRLen = ?, T9B = ?, T5F24 = ?, T71Len = ?, T71 = ?, T72Len = ?, T72 = ?, T9F06 = ?, T9F1E = ?, T9F28 = ?, T9F29 = ?, szChipLabel = ?, szTID = ?, szMID = ?, inNumOfAdjust=?, fTIPAllow=?, fBINVer=?, szBINVerSTAN=?, szPolicyNumber=?, inSavedCurrencyIdx=?, fFooterLogo=?, SmacPoints=?, SmacBalance=?,inSmacTender=?, fFleetCard=?, inFleetNumofLiters=?, szFleetProductCode=?, szFleetProductDesc=?, szSMACAmount=?, fECRTriggerTran=?, szPOSTID = ?, byPreviouslyUploaded = ?, szOrgRRN = ?, szDCCLocalTipAmount = ?, szSMACBDORewardsBalance = ?, szLocalStoreID = ?, fDualBrandedCredit = ?, fDCCAuth = ?, fBINRouteApproved = ?, T9F6E = ?, T9F6E_len = ?, fOptOut = ?, fOptOutVoided = ?, fOptOutComplete = ?, bySMACPay_CardSeqNo = ?, bySMACPay_CardStatus = ?, bySMACPay_CardPerDate = ?, bySMACPay_LastDataSync = ?, bySMACPay_ExpiryDate = ?, szBarcodeText = ? WHERE ulSavedIndex = ?";

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
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usChipDataLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->baChipData, 1024, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usAdditionalDataLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->baAdditionalData, 1024, SQLITE_STATIC);	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->bWaveSID);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usWaveSTransResult);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->bWaveSCVMAnalysis);
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
	/*inNumOfAdjust*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->inNumOfAdjust);
	/*fTIPAllow*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fTIPAllow);

	/* Issue# 000096: BIN VER Checking - start -- jzg*/
	/* BIN Ver */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fBINVer);

	/* BIN Ver STAN */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szBINVerSTAN, strlen((char*)transData->szBINVerSTAN), SQLITE_STATIC); 
	/* Issue# 000096: BIN VER Checking - end -- jzg*/

	/*sidumili: Issue#: 000269*/
	/*szPolicyNumber*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szPolicyNumber, strlen((char*)transData->szPolicyNumber), SQLITE_STATIC); 

	/*Issue# 000299 -- sidumili*/
	/*inSavedCurrencyIdx*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->inSavedCurrencyIdx);

	/*fFooterLogo -- sidumili*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fFooterLogo);


	/*fOnlineSALE*/
	//result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fOnlineSALE);

//smac
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->SmacPoints, 7, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->SmacBalance, 7, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->inSmacTender);	
//smac		


	/* BDOCLG-00321: Print fleet details also for duplicate receipts - start -- jzg */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fFleetCard);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->inFleetNumofLiters);
  result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szFleetProductCode, strlen((char*)transData->szFleetProductCode), SQLITE_STATIC); 
  result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szFleetProductDesc, strlen((char*)transData->szFleetProductDesc), SQLITE_STATIC); 
	/* BDOCLG-00321: Print fleet details also for duplicate receipts - end -- jzg */

	/*BDO: For SMAC*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szSMACAmount, 7, SQLITE_STATIC);
	

	/*fECRTriggerTran*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fECRTriggerTran);

	/*szPOSTID*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szPOSTID, strlen((char*)transData->szPOSTID), SQLITE_STATIC); 

	/*byPreviouslyUploaded*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->byPreviouslyUploaded);

	/*szOrgRRN*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szOrgRRN, 13, SQLITE_STATIC);

	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szDCCLocalTipAmount, 7, SQLITE_STATIC);
	
	/*szSMACBDORewardsBalance*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szSMACBDORewardsBalance, strlen((char*)transData->szSMACBDORewardsBalance), SQLITE_STATIC); 
	/*szLocalStoreID*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szLocalStoreID, 19, SQLITE_STATIC);
	/*fDualBrandedCredit*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fDualBrandedCredit);

	/*fDCCAuth*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fDCCAuth);

	/*fBINRouteApproved*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fBINRouteApproved);

	/*T9F6E*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F6E, 4, SQLITE_STATIC);

	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F6E_len);

	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fOptOut); 
	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fOptOutVoided); 

	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fOptOutComplete); 
	
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->bySMACPay_CardSeqNo, 3, SQLITE_STATIC);

	/*bySMACPay_CardStatus*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->bySMACPay_CardStatus, strlen((char*)transData->bySMACPay_CardStatus), SQLITE_STATIC); 

	/*bySMACPay_CardPerDate*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->bySMACPay_CardPerDate, strlen((char*)transData->bySMACPay_CardPerDate), SQLITE_STATIC); 

	/*bySMACPay_LastDataSync*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->bySMACPay_LastDataSync, strlen((char*)transData->bySMACPay_LastDataSync), SQLITE_STATIC); 

	/*bySMACPay_ExpiryDate*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->bySMACPay_ExpiryDate, strlen((char*)transData->bySMACPay_ExpiryDate), SQLITE_STATIC); 

	//version16
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szBarcodeText, strlen((char*)transData->szBarcodeText), SQLITE_STATIC); 



	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->ulSavedIndex);
	
	
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

int inDatabase_BatchSave(TRANS_DATA_TABLE *transData, int inStoredType)
{
	int inResult;
    TRANS_DATA_TABLE temptransData;
		
	vdDebug_LogPrintf("inDatabase_BatchSave inStoredType= %d", inStoredType);
	

    if (inStoredType == DF_BATCH_APPEND)
    {
		if(transData->IITid == 23)//change issuer from CITI VISA to VISA
			transData->IITid=2;
		else if(transData->IITid == 24)//change issuer from CITI MC to MC
			transData->IITid=4;
		
		inResult = inDatabase_BatchInsert(transData);
		if (inResult != ST_SUCCESS)
		{
			return ST_ERROR;
		}
		memset(&temptransData, 0x00, sizeof(temptransData));
        memcpy(&temptransData, transData, sizeof(temptransData));
		inDatabase_InvoiceNumInsert(&temptransData);

        if(strTCT.fDCC && transData->fDCC && (transData->byTransType == SALE || transData->byTransType == SALE_OFFLINE))
        {			
            memset(&temptransData, 0x00, sizeof(temptransData));
            memcpy(&temptransData, transData, sizeof(temptransData));
            //inMyFile_TransLogSave(&temptransData, DCC_LOGGING);
            inDatabase_TransLogSave(&temptransData);
        }		
    }
    else if(inStoredType == DF_BATCH_UPDATE)//default for tip or adjust txn
    {		
		inResult = inDatabase_BatchUpdate(transData);
		if (inResult != ST_SUCCESS)
		{
			return ST_ERROR;
		}

        //if(transData->fDCC && transData->byTransType == VOID)
        //{			
          //  memset(&temptransData, 0x00, sizeof(temptransData));
            //memcpy(&temptransData, transData, sizeof(temptransData));
            //inMyFile_TransLogSave(&temptransData, DCC_LOGGING);
        //}		
    }
    else
    {
        return ST_ERROR;
    }

    strHDT.ulLastTransSavedIndex = transData->ulSavedIndex;
    


    return ST_SUCCESS;
}

int inDatabase_BatchSearch(TRANS_DATA_TABLE *transData, char *hexInvoiceNo)
{
	int result,i = 0;
	int inResult = d_NO;

	/* Issue# 000096: BIN VER Checking -- jzg*/
	char *sql = "SELECT HDTid, MITid, CDTid, IITid, byTransType, byPanLen, szExpireDate, byEntryMode, szTotalAmount, szBaseAmount, szTipAmount, byOrgTransType, szMacBlock, szYear, szDate, szTime, szOrgDate, szOrgTime, szAuthCode, szRRN, szInvoiceNo, szOrgInvoiceNo, byPrintType, byVoided, byAdjusted, byUploaded, byTCuploaded, szCardholderName, szzAMEX4DBC, szStoreID, szRespCode, szServiceCode, byContinueTrans, byOffline, byReversal, byEMVFallBack, shTransResult, szTpdu, szIsoField03, szMassageType, szPAN, szCardLable, usTrack1Len, usTrack2Len, usTrack3Len, szTrack1Data, szTrack2Data, szTrack3Data, usChipDataLen, baChipData, usAdditionalDataLen, baAdditionalData, bWaveSID,usWaveSTransResult,bWaveSCVMAnalysis,ulTraceNum, ulOrgTraceNum, usTerminalCommunicationMode, ulSavedIndex, byPINEntryCapability, byPackType, szOrgAmount, szCVV2, inCardType, byTCFailUpCnt, byCardTypeNum, byEMVTransStatus, T5A_len, T5A, T5F2A, T5F30, T5F34, T5F34_len, T82, T84_len, T84, T8A, T91, T91Len, T95, T9A, T9C, T9F02, T9F03, T9F09, T9F10_len, T9F10, T9F1A, T9F26, T9F27, T9F33, T9F34, T9F35, T9F36_len, T9F36, T9F37, T9F41, T9F53, ISR, ISRLen, T9B, T5F24, T71Len, T71, T72Len, T72, T9F06, T9F1E, T9F28, T9F29, szChipLabel, szTID, szMID, szHostLabel, szBatchNo, inNumOfAdjust, fTIPAllow, fBINVer, szBINVerSTAN, szPolicyNumber, inSavedCurrencyIdx, fFooterLogo, fOnlineSALE, fCompletion, fVoidOffline, SmacPoints,SmacBalance, inSmacTender, fFleetCard, inFleetNumofLiters, szFleetProductCode, szFleetProductDesc, szSMACAmount, fECRTriggerTran, szPOSTID, szDCCCur, szDCCCurAmt, inDCCCurMU, szDCCFXRate, inDCCFXRateMU, szDCCFXRateRefID, szDCCCardType, szDCCFXMID, szDCCFXTID, szDCCMerchPOS, szDCCMarkupPer, inDCCMarkupPerMU, fDCC, szDCCCurSymbol, szDCCLocalAmount, szDCCLocalCur, szDCCLocalSymbol, fPrintSMCardHolder, fPrintCardHolderBal, fSMACFooter, fPrintExpFlag, byPreviouslyUploaded, szOrgRRN, szDCCLocalTipAmount, szSMACBDORewardsBalance, szLocalStoreID, fDualBrandedCredit, fDCCAuth, fBINRouteApproved, T9F6E, T9F6E_len, fOptOut, fOptOutVoided, fOptOutComplete, byOptOutOrigTransType, bySMACPay_CardSeqNo, bySMACPay_CardStatus, bySMACPay_CardPerDate, bySMACPay_LastDataSync, bySMACPay_ExpiryDate, bySMACPay_MemberSince, fVirtualCard, fSignPadBypassSignature, szBarcodeText, fSMACPrintscan FROM TransData WHERE szInvoiceNo = ?";

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
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, hexInvoiceNo, 4, SQLITE_STATIC);

	DebugAddINT("inDatabase_BatchSearch sqlite3_bind_blob", result);
	DebugAddHEX("hexInvoiceNo", hexInvoiceNo, 3);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		i++;
		DebugAddINT("if(100)=Find", result);
		DebugAddINT("Loop Count", i);

		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			transData->HDTid = sqlite3_column_int(stmt,inStmtSeq);
			transData->MITid = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->CDTid = sqlite3_column_int(stmt,inStmtSeq +=1 );
            transData->IITid = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->byTransType = sqlite3_column_int(stmt,inStmtSeq+=1 );
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
			transData->usChipDataLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->baChipData, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 1024);
			transData->usAdditionalDataLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->baAdditionalData, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 1024);			
			transData->bWaveSID = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->usWaveSTransResult = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->bWaveSCVMAnalysis = sqlite3_column_int(stmt,inStmtSeq +=1 );
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
			
			/*inNumOfAdjust*/
			transData->inNumOfAdjust = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/*fTIPAllow*/
			transData->fTIPAllow = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/* Issue# 000096: BIN VER Checking - start -- jzg*/
			/* fBINVer */
			transData->fBINVer = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szBINVerSTAN */
			strcpy((char*)transData->szBINVerSTAN, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* Issue# 000096: BIN VER Checking - end -- jzg*/

			/*sidumili: Issue#: 000269*/
			/*szPolicyNumber*/
			strcpy((char*)transData->szPolicyNumber, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*Issue# 000299 -- sidumili*/
			/*inSavedCurrencyIdx*/
			transData->inSavedCurrencyIdx = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*fFooterLogo -- sidumili*/
			transData->fFooterLogo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fOnlineSALE*/
		transData->fOnlineSALE = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fCompletion*/
		transData->fCompletion = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fVoidOffline*/
		transData->fVoidOffline = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

//smac
		memcpy(transData->SmacPoints, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);	
		memcpy(transData->SmacBalance, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7); 
		transData->inSmacTender = sqlite3_column_int(stmt,inStmtSeq +=1 );
//smac			


		/* BDOCLG-00321: Print fleet details also for duplicate receipts - start -- jzg */
		transData->fFleetCard = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1));
		transData->inFleetNumofLiters = sqlite3_column_int(stmt,inStmtSeq +=1);
		strcpy((char*)transData->szFleetProductCode, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
		strcpy((char*)transData->szFleetProductDesc, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
		/* BDOCLG-00321: Print fleet details also for duplicate receipts - end -- jzg */

		/*BDO: For SMAC*/
		memcpy(transData->szSMACAmount, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);

		/*fECRTriggerTran*/
		transData->fECRTriggerTran = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*szPOSTID*/
		strcpy((char*)transData->szPOSTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*DCC - start*/
    strcpy((char*)transData->szDCCCur, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
    strcpy((char*)transData->szDCCCurAmt, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
    transData->inDCCCurMU = sqlite3_column_int(stmt,inStmtSeq +=1);
    strcpy((char*)transData->szDCCFXRate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
    transData->inDCCFXRateMU = sqlite3_column_int(stmt,inStmtSeq +=1);
    strcpy((char*)transData->szDCCFXRateRefID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
    strcpy((char*)transData->szDCCCardType, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
    strcpy((char*)transData->szDCCFXMID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
    strcpy((char*)transData->szDCCFXTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
    strcpy((char*)transData->szDCCMerchPOS, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
    strcpy((char*)transData->szDCCMarkupPer, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
    transData->inDCCMarkupPerMU = sqlite3_column_int(stmt,inStmtSeq +=1);		
    transData->fDCC = sqlite3_column_int(stmt,inStmtSeq +=1 );			
    strcpy((char*)transData->szDCCCurSymbol, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
    memcpy(transData->szDCCLocalAmount, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);
    strcpy((char*)transData->szDCCLocalCur, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
    strcpy((char*)transData->szDCCLocalSymbol, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
		/*DCC - end*/
	transData->fPrintSMCardHolder = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));	
	transData->fPrintCardHolderBal = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));		
	transData->fSMACFooter = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));	
	transData->fPrintExpFlag = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));	
	transData->byPreviouslyUploaded = sqlite3_column_int(stmt,inStmtSeq +=1 );
	memcpy(transData->szOrgRRN, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 13);		
    memcpy(transData->szDCCLocalTipAmount, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);
	strcpy((char*)transData->szSMACBDORewardsBalance, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));						
	memcpy(transData->szLocalStoreID, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 19);						
	transData->fDualBrandedCredit = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

	transData->fDCCAuth = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	transData->fBINRouteApproved = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	memcpy(transData->stEMVinfo.T9F6E, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);
	transData->stEMVinfo.T9F6E_len = sqlite3_column_int(stmt,inStmtSeq +=1 );
	transData->fOptOut = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	transData->fOptOutVoided = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	transData->fOptOutComplete = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	transData->byOptOutOrigTransType = sqlite3_column_int(stmt,inStmtSeq+=1 );
	memcpy(transData->bySMACPay_CardSeqNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);
	strcpy((char*)transData->bySMACPay_CardStatus, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
	strcpy((char*)transData->bySMACPay_CardPerDate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
	strcpy((char*)transData->bySMACPay_LastDataSync, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
	strcpy((char*)transData->bySMACPay_ExpiryDate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
	strcpy((char*)transData->bySMACPay_MemberSince, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
	transData->fVirtualCard = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	transData->fSignPadBypassSignature = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

	//version16
	strcpy((char*)transData->szBarcodeText, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
	transData->fSMACPrintscan = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));//00160 - No SCAN label printed in Smac QR void receipt
	
	
	}
	} while (result == SQLITE_ROW);

    DebugAddSTR("batch serPAN", transData->szPAN, 10);
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inResult);
}

int inDatabase_BatchCheckDuplicateInvoice(char *hexInvoiceNo)
{
	int result;
	char *sql = "SELECT * FROM TransData WHERE szInvoiceNo = ?";

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
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, hexInvoiceNo, 4, SQLITE_STATIC);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;
			
			sqlite3_exec(db,"commit;",NULL,NULL,NULL);

			sqlite3_finalize(stmt);
			sqlite3_close(db);
			return 0x0080;
		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(ST_SUCCESS);
}

//aaronnino for BDOCLG ver 9.0 fix on issue #00124 Terminal display according to response codes was not updated  start 1 of 5
#if 0
int inMSGResponseCodeRead(char* szMsg, int inMsgIndex, int inHostIndex)
{
	int result;
  	char *sql = "SELECT szMsg FROM MSG WHERE usMsgIndex = ? AND inHostIndex = ?";

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

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inMsgIndex);
	sqlite3_bind_int(stmt, inStmtSeq +=1, inHostIndex);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */		
			inStmtSeq = 0;

			 /* szMsg */
			 strcpy((char*)szMsg, (char *)sqlite3_column_text(stmt,inStmtSeq ));
   		}
	} while (result == SQLITE_ROW);	   

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(d_OK);
}
#else
int inMSGResponseCodeRead(char* szMsg, char* szMsg2, char* szMsg3, int inMsgIndex, int inHostIndex)
{
	int result;
  	char *sql = "SELECT szMsg, szMsg2, szMsg3 FROM MSG WHERE usMsgIndex = ? AND inHostIndex = ?";

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

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inMsgIndex);
	sqlite3_bind_int(stmt, inStmtSeq +=1, inHostIndex);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */		
			inStmtSeq = 0;

			 /* szMsg */
			 strcpy((char*)szMsg, (char *)sqlite3_column_text(stmt,inStmtSeq ));

			 /* szMsg2 */
			 strcpy((char*)szMsg2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			 /* szMsg3 */
			 strcpy((char*)szMsg3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
   		}
	} while (result == SQLITE_ROW);	   

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(d_OK);
}
#endif
//aaronnino for BDOCLG ver 9.0 fix on issue #00124 Terminal display according to response codes was not updated end 1 of 5


int inBatchNumRecord(void)
{
	int len;
	int result;
	//char *sql = "SELECT COUNT(*) FROM TransData WHERE HDTid = ? AND MITid = ? AND szBatchNo = ?";
	char *sql = "SELECT COUNT(*) FROM TransData WHERE HDTid = ? AND MITid = ? AND szBatchNo = ? AND byTransType <> 102 AND byTransType <> 139 AND byTransType <> 131"; /*BDO: Do not include PRE_AUTH, SMAC BALANCE and BALANCE INQUIRY in count -- sidumili*/
	int inCount = 0;
	
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
	sqlite3_bind_blob(stmt, inStmtSeq +=1, strMMT[0].szBatchNo, 3, SQLITE_STATIC);

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



int inBatchByMerchandHost(int inNumber, int inHostIndex, int inMerchIndex, char *szBatchNo, int *inTranID)
{
	int result;
  	char *sql = "SELECT TransDataid FROM TransData WHERE HDTid = ? AND MITid = ? AND szBatchNo = ?";
	int count = 0;

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
	sqlite3_bind_int(stmt, inStmtSeq +=1, inHostIndex);
	sqlite3_bind_int(stmt, inStmtSeq +=1, inMerchIndex);
	sqlite3_bind_blob(stmt, inStmtSeq +=1, szBatchNo, 3, SQLITE_STATIC);

	inStmtSeq = 0;
	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */		

			 inTranID[count] = sqlite3_column_int(stmt,inStmtSeq);
             DebugAddINT("inTranID", inTranID[count]);
			 count++;

   		}
	} while (result == SQLITE_ROW);	   

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(d_OK);
}

int inDatabase_BatchReadByTransId(TRANS_DATA_TABLE *transData, int inTransDataid)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT MITid, HDTid, CDTid, IITid, byTransType, byPanLen, szExpireDate, byEntryMode, szTotalAmount, szBaseAmount, szTipAmount, byOrgTransType, szMacBlock, szYear, szDate, szTime, szOrgDate, szOrgTime, szAuthCode, szRRN, szInvoiceNo, szOrgInvoiceNo, byPrintType, byVoided, byAdjusted, byUploaded, byTCuploaded, szCardholderName, szzAMEX4DBC, szStoreID, szRespCode, szServiceCode, byContinueTrans, byOffline, byReversal, byEMVFallBack, shTransResult, szTpdu, szIsoField03, szMassageType, szPAN, szCardLable, usTrack1Len, usTrack2Len, usTrack3Len, szTrack1Data, szTrack2Data, szTrack3Data, usChipDataLen, baChipData, usAdditionalDataLen, baAdditionalData, bWaveSID,usWaveSTransResult,bWaveSCVMAnalysis, ulTraceNum, ulOrgTraceNum, usTerminalCommunicationMode, ulSavedIndex, byPINEntryCapability, byPackType, szOrgAmount, szCVV2, inCardType, byTCFailUpCnt, byCardTypeNum, byEMVTransStatus, T5A_len, T5A, T5F2A, T5F30, T5F34, T5F34_len, T82, T84_len, T84, T8A, T91, T91Len, T95, T9A, T9C, T9F02, T9F03, T9F09, T9F10_len, T9F10, T9F1A, T9F26, T9F27, T9F33, T9F34, T9F35, T9F36_len, T9F36, T9F37, T9F41, T9F53, ISR, ISRLen, T9B, T5F24, T71Len, T71, T72Len, T72, T9F06, T9F1E, T9F28, T9F29, szChipLabel, szTID, szMID, szHostLabel, szBatchNo, inNumOfAdjust, fTIPAllow, fBINVer, szBINVerSTAN, szPolicyNumber, inSavedCurrencyIdx, fFooterLogo,fOnlineSALE, fCompletion, fVoidOffline, fFleetCard, inFleetNumofLiters, szFleetProductCode, szFleetProductDesc, szSMACAmount, szPOSTID, szDCCCur, szDCCCurAmt, inDCCCurMU, szDCCFXRate, inDCCFXRateMU, szDCCFXRateRefID, szDCCCardType, szDCCFXMID, szDCCFXMID, szDCCMerchPOS, szDCCMarkupPer, inDCCMarkupPerMU, fDCC, szDCCCurSymbol, szDCCLocalAmount, szDCCLocalCur, szDCCLocalSymbol, fPrintSMCardHolder, fPrintCardHolderBal, fSMACFooter, fPrintExpFlag, byPreviouslyUploaded, szOrgRRN, szSMACBDORewardsBalance, szLocalStoreID, szDCCLocalTipAmount, fDualBrandedCredit, fDCCAuth, fBINRouteApproved, T9F6E, T9F6E_len, fQuasiCash, bySMACPay_CardSeqNo, bySMACPay_CardStatus, bySMACPay_CardPerDate, bySMACPay_LastDataSync, bySMACPay_ExpiryDate FROM TransData WHERE TransDataid = ?";

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

	inStmtSeq = 0;
	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
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
			transData->usChipDataLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->baChipData, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 1024);
			transData->usAdditionalDataLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->baAdditionalData, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 1024);			
			transData->bWaveSID = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->usWaveSTransResult = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->bWaveSCVMAnalysis = sqlite3_column_int(stmt,inStmtSeq +=1 );
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
			/*inNumOfAdjust*/ 
			transData->inNumOfAdjust = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/*fTIPAllow*/
			transData->fTIPAllow = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/* Issue# 000096: BIN VER Checking - start -- jzg*/
			/* fBINVer */
			transData->fBINVer = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szBINVerSTAN */
			strcpy((char*)transData->szBINVerSTAN, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* Issue# 000096: BIN VER Checking - end -- jzg*/

			/*sidumili: Issue#: 00026*/
			/*szPolicyNumber*/
			strcpy((char*)transData->szPolicyNumber, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*Issue# 000299 -- sidumili*/
			/*inSavedCurrencyIdx*/
			transData->inSavedCurrencyIdx = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*fFooterLogo  -- sidumili*/
			transData->fFooterLogo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/*fOnlineSALE*/
			transData->fOnlineSALE = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fCompletion*/
			transData->fCompletion = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			

			/*fVoidOffline*/		
			transData->fVoidOffline = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*BDO: Added -- sidumili*/
			transData->fFleetCard = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			transData->inFleetNumofLiters = sqlite3_column_int(stmt,inStmtSeq +=1);
			strcpy((char*)transData->szFleetProductCode, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			strcpy((char*)transData->szFleetProductDesc, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			
			memcpy(transData->szSMACAmount, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);
			/*BDO: Added -- sidumili*/

			/*szPOSTID*/
			strcpy((char*)transData->szPOSTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*DCC - start*/
		    strcpy((char*)transData->szDCCCur, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		    strcpy((char*)transData->szDCCCurAmt, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		    transData->inDCCCurMU = sqlite3_column_int(stmt,inStmtSeq +=1);
		    strcpy((char*)transData->szDCCFXRate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		    transData->inDCCFXRateMU = sqlite3_column_int(stmt,inStmtSeq +=1);
		    strcpy((char*)transData->szDCCFXRateRefID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		    strcpy((char*)transData->szDCCCardType, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		    strcpy((char*)transData->szDCCFXMID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		    strcpy((char*)transData->szDCCFXTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		    strcpy((char*)transData->szDCCMerchPOS, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		    strcpy((char*)transData->szDCCMarkupPer, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		    transData->inDCCMarkupPerMU = sqlite3_column_int(stmt,inStmtSeq +=1);		
		    transData->fDCC = sqlite3_column_int(stmt,inStmtSeq +=1 );			
		    strcpy((char*)transData->szDCCCurSymbol, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
		    memcpy(transData->szDCCLocalAmount, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);
		    strcpy((char*)transData->szDCCLocalCur, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
		    strcpy((char*)transData->szDCCLocalSymbol, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*DCC - end*/
			transData->fPrintSMCardHolder = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			transData->fPrintCardHolderBal = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			transData->fSMACFooter = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			transData->fPrintExpFlag = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			transData->byPreviouslyUploaded = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->szOrgRRN, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 13);						
			strcpy((char*)transData->szSMACBDORewardsBalance, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			memcpy(transData->szLocalStoreID, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 19);
			memcpy(transData->szDCCLocalTipAmount, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);
			transData->fDualBrandedCredit = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			transData->fDCCAuth = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			transData->fBINRouteApproved = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			memcpy(transData->stEMVinfo.T9F6E, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);
			transData->stEMVinfo.T9F6E_len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->fQuasiCash = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			memcpy(transData->bySMACPay_CardSeqNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);
			strcpy((char*)transData->bySMACPay_CardStatus, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			strcpy((char*)transData->bySMACPay_CardPerDate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			strcpy((char*)transData->bySMACPay_LastDataSync, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			strcpy((char*)transData->bySMACPay_ExpiryDate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
//1123

		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inResult);
}

int inMultiAP_Database_BatchRead(TRANS_DATA_TABLE *transData)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT MITid, HDTid, CDTid, IITid, byTransType, byPanLen, szExpireDate, byEntryMode, szTotalAmount, szBaseAmount, szTipAmount, byOrgTransType, szMacBlock, szYear, szDate, szTime, szOrgDate, szOrgTime, szAuthCode, szRRN, szInvoiceNo, szOrgInvoiceNo, byPrintType, byVoided, byAdjusted, byUploaded, byTCuploaded, szCardholderName, szzAMEX4DBC, szStoreID, szRespCode, szServiceCode, byContinueTrans, byOffline, byReversal, byEMVFallBack, shTransResult, szTpdu, szIsoField03, szMassageType, szPAN, szCardLable, usTrack1Len, usTrack2Len, usTrack3Len, szTrack1Data, szTrack2Data, szTrack3Data, usChipDataLen, baChipData, usAdditionalDataLen, baAdditionalData, bWaveSID,usWaveSTransResult,bWaveSCVMAnalysis, ulTraceNum, ulOrgTraceNum, usTerminalCommunicationMode, ulSavedIndex, byPINEntryCapability, byPackType, szOrgAmount, szCVV2, inCardType, byTCFailUpCnt, byCardTypeNum, byEMVTransStatus, T5A_len, T5A, T5F2A, T5F30, T5F34, T5F34_len, T82, T84_len, T84, T8A, T91, T91Len, T95, T9A, T9C, T9F02, T9F03, T9F09, T9F10_len, T9F10, T9F1A, T9F26, T9F27, T9F33, T9F34, T9F35, T9F36_len, T9F36, T9F37, T9F41, T9F53, ISR, ISRLen, T9B, T5F24, T71Len, T71, T72Len, T72, T9F06, T9F1E, T9F28, T9F29, szChipLabel, szTID, szMID, szHostLabel, szBatchNo, fBINVer, szBINVerSTAN, szECRPANFormatted, szECRRespText, szECRMerchantName, szECRRespCode, fECRTrxFlg, T9F6E, T9F6E_len, PRMid, szTerms FROM TransData WHERE TransDataid = ?";

	/* open the database */
	result = sqlite3_open(DB_MULTIAP,&db);
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
			transData->usChipDataLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->baChipData, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 1024);
			transData->usAdditionalDataLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->baAdditionalData, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 1024);			
			transData->bWaveSID = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->usWaveSTransResult = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->bWaveSCVMAnalysis = sqlite3_column_int(stmt,inStmtSeq +=1 );
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
			/* fBINVer */
			transData->fBINVer = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));				
			/* szBINVerSTAN */
			strcpy((char*)transData->szBINVerSTAN, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
			/* BDO: Read field for SHARLS_ECR -- sidumili */
			strcpy((char*)transData->szECRPANFormatted, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strcpy((char*)transData->szECRRespText, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strcpy((char*)transData->szECRMerchantName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strcpy((char*)transData->szECRRespCode, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO: Read field for SHARLS_ECR -- sidumili */

			/*fECRTrxFlg*/
			transData->fECRTrxFlg = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));	
			/*T9F29*/
			memcpy(transData->stEMVinfo.T9F6E, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);
			transData->stEMVinfo.T9F6E_len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			
			/*PRMid*/
			transData->PRMid= sqlite3_column_int(stmt,inStmtSeq +=1 );
			
			/*szTerms*/			
			strcpy((char*)transData->szTerms, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inResult);
}

int inMultiAP_Database_BatchUpdate(TRANS_DATA_TABLE *transData)
{
	int result;
	char *sql = "UPDATE TransData SET HDTid = ?, MITid = ?, CDTid = ?, IITid = ?, szHostLabel = ?, szBatchNo = ?, byTransType = ?, byPanLen = ?, szExpireDate = ?, byEntryMode = ?, szTotalAmount = ?, szBaseAmount = ?, szTipAmount = ?, byOrgTransType = ?, szMacBlock = ?, szYear = ?, szDate = ?, szTime = ?, szOrgDate = ?, szOrgTime = ?, szAuthCode = ?, szRRN = ?, szInvoiceNo = ?, szOrgInvoiceNo = ?, byPrintType = ?, byVoided = ?, byAdjusted = ?, byUploaded = ?, byTCuploaded = ?, szCardholderName = ?, szzAMEX4DBC = ?, szStoreID = ?, szRespCode = ?, szServiceCode = ?, byContinueTrans = ?, byOffline = ?, byReversal = ?, byEMVFallBack = ?, shTransResult = ?, szTpdu = ?, szIsoField03 = ?, szMassageType = ?, szPAN = ?, szCardLable = ?, usTrack1Len = ?, usTrack2Len = ?, usTrack3Len = ?, szTrack1Data = ?, szTrack2Data = ?, szTrack3Data = ?, usChipDataLen = ?, baChipData = ?, usAdditionalDataLen = ?, baAdditionalData = ?, bWaveSID = ?,usWaveSTransResult = ?,bWaveSCVMAnalysis = ?, ulTraceNum = ?, ulOrgTraceNum = ?, usTerminalCommunicationMode = ?, ulSavedIndex = ?, byPINEntryCapability = ?, byPackType = ?, szOrgAmount = ?, szCVV2 = ?, inCardType = ?, byTCFailUpCnt = ?, byCardTypeNum = ?, byEMVTransStatus = ?, T5A_len = ?, T5A = ?, T5F2A = ?, T5F30 = ?, T5F34 = ?, T5F34_len = ?, T82 = ?, T84_len = ?, T84 = ?, T8A = ?, T91 = ?, T91Len = ?, T95 = ?, T9A = ?, T9C = ?, T9F02 = ?, T9F03 = ?, T9F09 = ?, T9F10_len = ?, T9F10 = ?, T9F1A = ?, T9F26 = ?, T9F27 = ?, T9F33 = ?, T9F34 = ?, T9F35 = ?, T9F36_len = ?, T9F36 = ?, T9F37 = ?, T9F41 = ?, T9F53 = ?, ISR = ?, ISRLen = ?, T9B = ?, T5F24 = ?, T71Len = ?, T71 = ?, T72Len = ?, T72 = ?, T9F06 = ?, T9F1E = ?, T9F28 = ?, T9F29 = ?, szChipLabel = ?, szTID = ?, szMID = ?, fBINVer=?, szBINVerSTAN=? szECRPANFormatted=? szECRRespText=?, szECRMerchantName=?  szECRRespCode=?, fECRTrxFlg = ?, T9F6E = ?, T9F6E_len = ? WHERE TransDataid = ?";

	/* open the database */
	result = sqlite3_open(DB_MULTIAP,&db);
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
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usChipDataLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->baChipData, 1024, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usAdditionalDataLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->baAdditionalData, 1024, SQLITE_STATIC);	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->bWaveSID);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usWaveSTransResult);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->bWaveSCVMAnalysis);
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
	/* fBINVer */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fBINVer);
	/* szBINVerSTAN */
  	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szBINVerSTAN, strlen((char*)transData->szBINVerSTAN), SQLITE_STATIC); 

	/* BDO: Save fields for SHARLS_ECR -- sidumili */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szECRPANFormatted, strlen((char*)transData->szECRPANFormatted), SQLITE_STATIC); 
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szECRRespText, strlen((char*)transData->szECRRespText), SQLITE_STATIC); 
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szECRMerchantName, strlen((char*)transData->szECRMerchantName), SQLITE_STATIC); 
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szECRRespCode, strlen((char*)transData->szECRRespCode), SQLITE_STATIC); 
	/* BDO: Save fields for SHARLS_ECR -- sidumili */	

	/*fECRTrxFlg*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fECRTrxFlg);
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



int inMultiAP_Database_BatchInsert(TRANS_DATA_TABLE *transData)
{
	int result;	
	char *sql1 = "SELECT MAX(TransDataid) FROM TransData";
 	char *sql = "INSERT INTO TransData (TransDataid, HDTid, MITid, CDTid, IITid, szHostLabel, szBatchNo, byTransType, byPanLen, szExpireDate, byEntryMode, szTotalAmount, szBaseAmount, szTipAmount, byOrgTransType, szMacBlock, szYear, szDate, szTime, szOrgDate, szOrgTime, szAuthCode, szRRN, szInvoiceNo, szOrgInvoiceNo, byPrintType, byVoided, byAdjusted, byUploaded, byTCuploaded, szCardholderName, szzAMEX4DBC, szStoreID, szRespCode, szServiceCode, byContinueTrans, byOffline, byReversal, byEMVFallBack, shTransResult, szTpdu, szIsoField03, szMassageType, szPAN, szCardLable, usTrack1Len, usTrack2Len, usTrack3Len, szTrack1Data, szTrack2Data, szTrack3Data, usChipDataLen, baChipData, usAdditionalDataLen, baAdditionalData, bWaveSID,usWaveSTransResult,bWaveSCVMAnalysis, ulTraceNum, ulOrgTraceNum, usTerminalCommunicationMode, ulSavedIndex, byPINEntryCapability, byPackType, szOrgAmount, szCVV2, inCardType, byTCFailUpCnt, byCardTypeNum, byEMVTransStatus, T5A_len, T5A, T5F2A, T5F30, T5F34, T5F34_len, T82, T84_len, T84, T8A, T91, T91Len, T95, T9A, T9C, T9F02, T9F03, T9F09, T9F10_len, T9F10, T9F1A, T9F26, T9F27, T9F33, T9F34, T9F35, T9F36_len, T9F36, T9F37, T9F41, T9F53, ISR, ISRLen, T9B, T5F24, T71Len, T71, T72Len, T72, T9F06, T9F1E, T9F28, T9F29, szChipLabel, szTID, szMID, fBINVer, szBINVerSTAN, szECRPANFormatted, szECRRespText, szECRMerchantName, szECRRespCode, PRMid, szPolicyNumber, fECRTrxFlg, T9F6E, T9F6E_len, bySMACPay_CardSeqNo,szTerms) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

	/* open the database */
	result = sqlite3_open(DB_MULTIAP,&db);
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
	result = sqlite3_open(DB_MULTIAP,&db);
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
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usChipDataLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->baChipData, 1024, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usAdditionalDataLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->baAdditionalData, 1024, SQLITE_STATIC);	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->bWaveSID);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usWaveSTransResult);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->bWaveSCVMAnalysis);
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
  //result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szHostLabel, strlen((char*)transData->szHostLabel), SQLITE_STATIC); 
  //result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szBatchNo, 3, SQLITE_STATIC);
	/* fBINVer */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fBINVer);
	/* szBINVerSTAN */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szBINVerSTAN, strlen((char*)transData->szBINVerSTAN), SQLITE_STATIC); 

	/* BDO: Save fields for SHARLS_ECR -- sidumili */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szECRPANFormatted, strlen((char*)transData->szECRPANFormatted), SQLITE_STATIC); 
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szECRRespText, strlen((char*)transData->szECRRespText), SQLITE_STATIC); 
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szECRMerchantName, strlen((char*)transData->szECRMerchantName), SQLITE_STATIC); 
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szECRRespCode, strlen((char*)transData->szECRRespCode), SQLITE_STATIC);
	/* BDO: Save fields for SHARLS_ECR -- sidumili */

	/*promo id - installment*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->PRMid);

    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szPolicyNumber, strlen((char*)transData->szPolicyNumber), SQLITE_STATIC); 

	/*fECRTrxFlg*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fECRTrxFlg);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F6E, 4, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F6E_len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->bySMACPay_CardSeqNo, 3, SQLITE_STATIC);//bySMACPay_CardSeqNo
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szTerms, strlen((char*)transData->szTerms), SQLITE_STATIC); 
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



int inMultiAP_Database_BatchDelete(void)
{
	int result;
	char *sql = "DELETE FROM TransData";	
	int inDBResult =0 ;
	
	//1205
	remove(DB_MULTIAP_JOURNAL);
	//1205

	/* open the database */
	result = sqlite3_open(DB_MULTIAP,&db);
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

//	inStmtSeq = 0;
//	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srTransRec.szHostLabel, strlen((char*)srTransRec.szHostLabel), SQLITE_STATIC); 
//	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, srTransRec.szBatchNo, 3, SQLITE_STATIC);

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


int inMultiAP_Database_EMVTransferDataInit(void)
{
    int inSeekCnt = 1;
    USHORT usDataLen = 0;
    BYTE bEMVData[4];
    int result;
    char *sql = "UPDATE ETD SET inEMVDataLen = ? ,szEMVTransferData = ? WHERE  ETDid = ?";          
   
    /* open the database */
    result = sqlite3_open(DB_EMV,&db);
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

    memset(bEMVData, 0x00, sizeof(bEMVData));
    inStmtSeq = 0;

    /* inEMVDataLen */
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, usDataLen);
    
    /* szEMVTransferData */    
    result = sqlite3_bind_blob(stmt, inStmtSeq +=1, bEMVData, 1, SQLITE_STATIC);


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



int inMultiAP_Database_EMVTransferDataWrite(USHORT usDataLen, BYTE *bEMVData)
{
    int inSeekCnt = 1;
    int result;
    char *sql = "UPDATE ETD SET inEMVDataLen = ? ,szEMVTransferData = ? WHERE  ETDid = ?";          
  
    /* open the database */
    result = sqlite3_open(DB_EMV,&db);
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

    /* inEMVDataLen */
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, usDataLen);
    
    /* szEMVTransferData */    
    result = sqlite3_bind_blob(stmt, inStmtSeq +=1, bEMVData, usDataLen, SQLITE_STATIC);


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


int inMultiAP_Database_EMVTransferDataRead(USHORT *usDataLen, BYTE *bEMVData)
{
    int inSeekCnt = 1;
    int result;
    int inResult = d_NO;
    char *sql = "SELECT inEMVDataLen, szEMVTransferData FROM ETD WHERE ETDid = ?";
        
    /* open the database */
    result = sqlite3_open(DB_EMV,&db);
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
            inResult = d_OK;
            inStmtSeq = 0;

            /*inEMVDataLen*/
            *usDataLen = sqlite3_column_int(stmt,inStmtSeq  );
            
            /*szEMVTransferData*/
            memcpy(bEMVData, sqlite3_column_blob(stmt,inStmtSeq +=1 ), *usDataLen);

        }
    } while (result == SQLITE_ROW);

    
    sqlite3_exec(db,"commit;",NULL,NULL,NULL);

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return(inResult);
}

/*BDO PHASE 2: [Unused function] -- sidumili */ 
#if 0
int inMultiAP_Database_COM_Read(void)
{
    int result;
    int inSeekCnt = 1;
    int len = 0;
    int inResult = -1;
    char *sql = "SELECT inCommMode, inHeaderFormat,bSSLFlag, szCAFileName, szClientFileName, szClientKeyFileName, szPriPhoneNum, szSecPhoneNum, szPriHostIP, ulPriHostPort, szSecHostIP, ulSecHostPort, inSendLen, szSendData, inReceiveLen, szReceiveData FROM COM WHERE COMid = ?";

    /* open the database */
    result = sqlite3_open(DB_COM,&db);
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
            inResult = d_OK;
            inStmtSeq = 0;

           /* inCommMode */
           strCOM.inCommMode = sqlite3_column_int(stmt, inStmtSeq );

           
           /* inCommMode */
           strCOM.inHeaderFormat = sqlite3_column_int(stmt, inStmtSeq +=1 );

           /* fDialMode*/
           strCOM.bSSLFlag = fGetBoolean((BYTE *)sqlite3_column_text(stmt, inStmtSeq +=1 ));

           /* szCAFileName*/
			strcpy((char*)strCOM.szCAFileName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* szClientFileName*/
             strcpy((char*)strCOM.szClientFileName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* szClientKeyFileName*/
             strcpy((char*)strCOM.szClientKeyFileName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* szPriPhoneNum*/
             strcpy((char*)strCOM.szPriPhoneNum, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            /* szSecPhoneNum*/
             strcpy((char*)strCOM.szSecPhoneNum, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* szPriHostIP*/
             strcpy((char*)strCOM.szPriHostIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            /* szPriHostIP*/
			strCOM.ulPriHostPort = sqlite3_column_double(stmt,inStmtSeq +=1);

            /* szSecHostIP*/
             strcpy((char*)strCOM.szSecHostIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            /* szPriHostIP*/
			strCOM.ulSecHostPort = sqlite3_column_double(stmt,inStmtSeq +=1);

            /* inSendLen*/
            strCOM.inSendLen = sqlite3_column_int(stmt, inStmtSeq +=1 );
			/*szSendData*/
			memcpy(strCOM.szSendData, sqlite3_column_blob(stmt,inStmtSeq +=1 ), strCOM.inSendLen);

            /* inReceiveLen*/
            strCOM.inReceiveLen = sqlite3_column_int(stmt, inStmtSeq +=1 );
			/*szReceiveData*/
			memcpy(strCOM.szReceiveData, sqlite3_column_blob(stmt,inStmtSeq +=1 ), strCOM.inReceiveLen);

        }
    } while (result == SQLITE_ROW); 

    
    sqlite3_exec(db,"commit;",NULL,NULL,NULL);
    //�ر�sqlite����
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return(inResult);
}


int inMultiAP_Database_COM_Save(void)
{
    int inSeekCnt = 1;
    int result;
    char *sql = "UPDATE COM SET inCommMode = ? ,inHeaderFormat = ? ,bSSLFlag = ? ,szCAFileName = ? ,szClientFileName = ? ,szClientKeyFileName = ? ,szPriPhoneNum = ? ,szSecPhoneNum = ? ,szPriHostIP = ? ,ulPriHostPort = ? ,szSecHostIP = ? ,ulSecHostPort = ? ,inSendLen = ? ,szSendData = ? ,inReceiveLen = ?,szReceiveData = ? WHERE  COMid = ?";          
 
    /* open the database */
    result = sqlite3_open(DB_COM,&db);
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
        
    /* inCommMode*/
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCOM.inCommMode);
    /* inHeaderFormat*/
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCOM.inHeaderFormat);
    /* bSSLFlag*/
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCOM.bSSLFlag);
    /* szCAFileName*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCOM.szCAFileName, strlen((char*)strCOM.szCAFileName), SQLITE_STATIC);
    /* szClientFileName*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCOM.szClientFileName, strlen((char*)strCOM.szClientFileName), SQLITE_STATIC);
    /* szClientKeyFileName*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCOM.szClientKeyFileName, strlen((char*)strCOM.szClientKeyFileName), SQLITE_STATIC);
    /* szPriPhoneNum*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCOM.szPriPhoneNum, strlen((char*)strCOM.szPriPhoneNum), SQLITE_STATIC);
    /* szSecPhoneNum*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCOM.szSecPhoneNum, strlen((char*)strCOM.szSecPhoneNum), SQLITE_STATIC);
    /* szPriHostIP*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCOM.szPriHostIP, strlen((char*)strCOM.szPriHostIP), SQLITE_STATIC);
    /* ulPriHostPort*/
    result = sqlite3_bind_double(stmt, inStmtSeq +=1, strCOM.ulPriHostPort);
    /* szSecHostIP*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCOM.szSecHostIP, strlen((char*)strCOM.szSecHostIP), SQLITE_STATIC);
    /* ulSecHostPort*/
    result = sqlite3_bind_double(stmt, inStmtSeq +=1, strCOM.ulSecHostPort);

    /* inSendLen*/
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCOM.inSendLen);
	/* szSendData*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strCOM.szSendData, strCOM.inSendLen, SQLITE_STATIC);

    /* inReceiveLen*/
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCOM.inReceiveLen);
	/* szReceiveData*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strCOM.szReceiveData, strCOM.inReceiveLen, SQLITE_STATIC);


    result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
    result = sqlite3_step(stmt);
    if( result != SQLITE_DONE ){
        sqlite3_close(db);
        return 3;
    }
    
    sqlite3_exec(db,"commit;",NULL,NULL,NULL);
    //�ر�sqlite����
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    vdDebug_LogPrintf("---usCTOSS_COMM_SAVE");

    return(d_OK);
}



int inMultiAP_Database_COM_Clear(void)
{
    int inSeekCnt = 1;
    int result;
    char *sql = "UPDATE COM SET inCommMode = ? ,inHeaderFormat = ? ,bSSLFlag = ? ,szCAFileName = ? ,szClientFileName = ? ,szClientKeyFileName = ? ,szPriPhoneNum = ? ,szSecPhoneNum = ? ,szPriHostIP = ? ,ulPriHostPort = ? ,szSecHostIP = ? ,ulSecHostPort = ? ,inSendLen = ? ,szSendData = ? ,inReceiveLen = ?,szReceiveData = ? WHERE  COMid = ?";          
 
    /* open the database */
    result = sqlite3_open(DB_COM,&db);
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

    memset(&strCOM,0,sizeof(strCOM));
    
    /* inCommMode*/
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCOM.inCommMode);
    /* inHeaderFormat*/
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCOM.inHeaderFormat);
    /* bSSLFlag*/
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCOM.bSSLFlag);
    /* szCAFileName*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCOM.szCAFileName, strlen((char*)strCOM.szCAFileName), SQLITE_STATIC);
    /* szClientFileName*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCOM.szClientFileName, strlen((char*)strCOM.szClientFileName), SQLITE_STATIC);
    /* szClientKeyFileName*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCOM.szClientKeyFileName, strlen((char*)strCOM.szClientKeyFileName), SQLITE_STATIC);
    /* szPriPhoneNum*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCOM.szPriPhoneNum, strlen((char*)strCOM.szPriPhoneNum), SQLITE_STATIC);
    /* szSecPhoneNum*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCOM.szSecPhoneNum, strlen((char*)strCOM.szSecPhoneNum), SQLITE_STATIC);
    /* szPriHostIP*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCOM.szPriHostIP, strlen((char*)strCOM.szPriHostIP), SQLITE_STATIC);
    /* ulPriHostPort*/
    result = sqlite3_bind_double(stmt, inStmtSeq +=1, strCOM.ulPriHostPort);
    /* szSecHostIP*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCOM.szSecHostIP, strlen((char*)strCOM.szSecHostIP), SQLITE_STATIC);
    /* ulSecHostPort*/
    result = sqlite3_bind_double(stmt, inStmtSeq +=1, strCOM.ulSecHostPort);

    /* inSendLen*/
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCOM.inSendLen);
	/* szSendData*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strCOM.szSendData, strCOM.inSendLen, SQLITE_STATIC);

    /* inReceiveLen*/
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCOM.inReceiveLen);
	/* szReceiveData*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strCOM.szReceiveData, strCOM.inReceiveLen, SQLITE_STATIC);


    result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
    result = sqlite3_step(stmt);
    if( result != SQLITE_DONE ){
        sqlite3_close(db);
        return 3;
    }
    
    sqlite3_exec(db,"commit;",NULL,NULL,NULL);
    //�ر�sqlite����
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    vdDebug_LogPrintf("---usCTOSS_COMM_CLEAR");

    return(d_OK);
}

#endif
/*BDO PHASE 2: [Unused function] -- sidumili */ 

int inCRCRead(int inSeekCnt)
{     
	int result;
	char *sql = "SELECT CRCTid, szAppname, ulSize  FROM RNT WHERE CRCTid = ?";
		
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

	result = sqlite3_bind_int(stmt, 1, inSeekCnt);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;
			
            strCRC.CRCTid = sqlite3_column_int(stmt, inStmtSeq);   
			strcpy((char*)strCRC.szAppname, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strCRC.ulSize = sqlite3_column_double(stmt, inStmtSeq +=1 );
			
			if (strcmp (strCRC.szAppname, "DIGITAL WALLET") == 0)
				{
					if(strTCT.inSetMobileWalletLabel == 1)
						{
							strcpy(strCRC.szAppname, strTCT.szMobileWalletLabel);
						}
					else
						{
							strcat(strCRC.szAppname, "MOBILE WALLET");
						}
				}

                        
		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return(d_OK);
}
//1027

//BDO: Added settlement status to settlement report - start -- jzg
int inMMTReadRecord_Footer(void)
{
	int result = 0;
	int inResult = d_NO;
	char *sql = "SELECT a.[HDTid], a.[szHostName], a.[szMerchantName], a.[MITid], b.[szNII], a.[inSettleStatus] FROM MMT a, HDT b WHERE a.[HDTid] = b.[HDTid] AND b.[fHostEnable] = 1 AND a.[fMMTEnable] = 1 ORDER BY a.[inSequence]";
	int incount = 0;

	memset(strMMT_Ft, 0, sizeof(strMMT_Ft));

	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return -1;
	}

	sqlite3_exec( db, "begin", 0, 0, NULL );
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return -1;
	}

	inStmtSeq = 0;

	do 
	{
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) 
		{ 
			inResult = d_OK;
			inStmtSeq = 0;

			/* HDTid */
			strMMT_Ft[incount].HDTid = sqlite3_column_int(stmt,inStmtSeq);

			/* szHostName */
			strcpy((char*)strMMT_Ft[incount].szHostName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/* szMerchantName */
			strcpy((char*)strMMT_Ft[incount].szMerchantName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/* MITid */
			strMMT_Ft[incount].MITid = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/* szNII */
			memcpy(strMMT_Ft[incount].szNII, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);

			/* inSettleStatus */
			strMMT_Ft[incount].inSettleStatus = sqlite3_column_int(stmt,inStmtSeq +=1 );

			incount++;
		}
	} 
	while(result == SQLITE_ROW);

	vdDebug_LogPrintf("MMT_FT Rec Count [%d]", incount);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inResult);
}

//BDO: Added settlement status to settlement report - end -- jzg

/*BDO PHASE 2: [Function to get the total record of CPT table, use for "Change Comm"] -- sidumili */ 
int inCPTNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM CPT";
	int inCount = 0;
	
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
/*BDO PHASE 2: [Function to get the total record of CPT table, use for "Change Comm"] -- sidumili */ 



/* BDO: Removed CARD VER from batch review - start -- jzg */
int inBatchReviewNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM TransData WHERE HDTid = ? AND MITid = ? AND szBatchNo = ? AND byTransType != ? AND byTransType != ? AND byTransType != ? AND byTransType != ? AND byTransType != ? AND byTransType != ?";
	int inCount = 0;
	
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
	sqlite3_bind_blob(stmt, inStmtSeq +=1, strMMT[0].szBatchNo, 3, SQLITE_STATIC);
	sqlite3_bind_int(stmt, inStmtSeq +=1, PRE_AUTH);
	sqlite3_bind_int(stmt, inStmtSeq +=1, SMAC_BALANCE);
	sqlite3_bind_int(stmt, inStmtSeq +=1, BALANCE_INQUIRY);
	sqlite3_bind_int(stmt, inStmtSeq +=1, KIT_SALE);
	sqlite3_bind_int(stmt, inStmtSeq +=1, RENEWAL);
	sqlite3_bind_int(stmt, inStmtSeq +=1, PTS_AWARDING);

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


int inBatchReviewByMerchandHostAlbert(int *inTranID, int HDTid)
{
	int result;
  	char *sql = "SELECT MMTid FROM MMT WHERE fMMTEnable = 1  AND HDTid = ?";
	int count = 0;

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

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, HDTid);
	
	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */		

			 inTranID[count] = sqlite3_column_int(stmt,inStmtSeq);
             DebugAddINT("inTranID", inTranID[count]);
			 count++;

   		}
	} while (result == SQLITE_ROW);	   

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(d_OK);
}
/* BDO: Removed CARD VER from batch review - end -- jzg */


/* BDO CLG: Revised menu functions - start -- jzg */
int inReadDynamicMenu()
{
	int inMenuIndex = 0,
		inResult = 0,
		inCtr = 0;

	char szMenuFilename[FILENAME_SIZE] = {0},
		*szSQL = "SELECT szButtonItemLabel, szButtonItemFunc, szSubMenuName FROM DMTerminalSettingMenu ORDER BY usButtonID";

	inTCTRead(1);
	sprintf(szMenuFilename, "./fs_data/DYNAMICMENU%02d.S3DB", strTCT.inMenuid);

	
	inResult = sqlite3_open(szMenuFilename, &db);
	if(inResult != SQLITE_OK) 
	{
		sqlite3_close(db);
		return ST_ERROR;
	}

	sqlite3_exec( db, "begin", 0, 0, NULL );
	inResult = sqlite3_prepare_v2(db, szSQL  , -1, &stmt, NULL);
	if (inResult != SQLITE_OK) 
	{
		sqlite3_close(db);
		return ST_ERROR;
	}

	do 
	{
		inResult = sqlite3_step(stmt);
		if(inResult == SQLITE_ROW) 
		{ 
			inStmtSeq = 0;
		
			/* szButtonTitleLabel */			
			strcpy((char*)strDynamicMenu[inCtr].szButtonItemLabel, (char *)sqlite3_column_text(stmt, inStmtSeq));

			/* szButtonItemFunc */			
			strcpy((char*)strDynamicMenu[inCtr].szButtonItemFunc, (char *)sqlite3_column_text(stmt, inStmtSeq += 1));

			/* szSubMenuName */			
			strcpy((char*)strDynamicMenu[inCtr].szSubMenuName, (char *)sqlite3_column_text(stmt, inStmtSeq += 1));

			++inCtr;
		}
	} 
	while(inResult == SQLITE_ROW);
		
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inCtr);
}
/* BDO CLG: Revised menu functions - end -- jzg */


int inMultiAP_Database_CTLS_Delete(void)
{
	int result;
	char *sql = "DELETE FROM TransData";	
	int inDBResult =0 ;

	/* open the database */
	result = sqlite3_open(DB_CTLS,&db);
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

int inMultiAP_Database_CTLS_Read(CTLS_TransData *strCTLSTransData)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT szAmount, szOtherAmt, szTransType, szCatgCode, szCurrCode, status, bSID, baDateTime, bTrack1Len, baTrack1Data, bTrack2Len, baTrack2Data, usChipDataLen, baChipData, usAdditionalDataLen, baAdditionalData, usTransResult, bCVMAnalysis, baCVMResults, bVisaAOSAPresent, baVisaAOSA, bODAFail, inReserved1, inReserved2, inReserved3, szReserved1, szReserved2, szReserved3 FROM TransData WHERE TransDataid = ?";

	/* open the database */
	result = sqlite3_open(DB_CTLS,&db);
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

			strcpy((char*)strCTLSTransData->szAmount, (char *)sqlite3_column_text(stmt,inStmtSeq));
			strcpy((char*)strCTLSTransData->szOtherAmt, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strcpy((char*)strCTLSTransData->szTransType, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 )); 
			strcpy((char*)strCTLSTransData->szCatgCode, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strcpy((char*)strCTLSTransData->szCurrCode, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strCTLSTransData->status = sqlite3_column_int(stmt,inStmtSeq +=1 );
			strCTLSTransData->bSID = sqlite3_column_int(stmt,inStmtSeq +=1 );
			strcpy((char*)strCTLSTransData->baDateTime, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strCTLSTransData->bTrack1Len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(strCTLSTransData->baTrack1Data, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 100);
			strCTLSTransData->bTrack2Len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(strCTLSTransData->baTrack2Data, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 100);
			strCTLSTransData->usChipDataLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(strCTLSTransData->baChipData, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 1024);
			strCTLSTransData->usAdditionalDataLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(strCTLSTransData->baAdditionalData, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 1024);
			strCTLSTransData->usTransResult = sqlite3_column_int(stmt,inStmtSeq +=1 );
			strCTLSTransData->bCVMAnalysis = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(strCTLSTransData->baCVMResults, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);
			strCTLSTransData->bVisaAOSAPresent = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(strCTLSTransData->baVisaAOSA, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);
			strCTLSTransData->bODAFail = sqlite3_column_int(stmt,inStmtSeq +=1 );
			strCTLSTransData->inReserved1 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			strCTLSTransData->inReserved2 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			strCTLSTransData->inReserved3 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(strCTLSTransData->szReserved1, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 100);
			memcpy(strCTLSTransData->szReserved2, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 100);
			memcpy(strCTLSTransData->szReserved3, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 100);
		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inResult);
}


int inMultiAP_Database_CTLS_Insert(CTLS_TransData *strCTLSTransData)
{
	int result; 
	char *sql = "INSERT INTO TransData (TransDataid, szAmount, szOtherAmt, szTransType, szCatgCode, szCurrCode, status, bSID, baDateTime, bTrack1Len, baTrack1Data, bTrack2Len, baTrack2Data, usChipDataLen, baChipData, usAdditionalDataLen, baAdditionalData, usTransResult, bCVMAnalysis, baCVMResults, bVisaAOSAPresent, baVisaAOSA, bODAFail, inReserved1, inReserved2, inReserved3, szReserved1, szReserved2, szReserved3) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
	   
	/* open the database */
	result = sqlite3_open(DB_CTLS,&db);
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
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCTLSTransData->szAmount, strlen((char*)strCTLSTransData->szAmount), SQLITE_STATIC); 
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCTLSTransData->szOtherAmt, strlen((char*)strCTLSTransData->szOtherAmt), SQLITE_STATIC); 
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCTLSTransData->szTransType, strlen((char*)strCTLSTransData->szTransType), SQLITE_STATIC); 
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCTLSTransData->szCatgCode, strlen((char*)strCTLSTransData->szCatgCode), SQLITE_STATIC); 
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCTLSTransData->szCurrCode, strlen((char*)strCTLSTransData->szCurrCode), SQLITE_STATIC); 
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCTLSTransData->status);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCTLSTransData->bSID);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strCTLSTransData->baDateTime, strlen((char*)strCTLSTransData->baDateTime), SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCTLSTransData->bTrack1Len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strCTLSTransData->baTrack1Data, 100, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCTLSTransData->bTrack2Len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strCTLSTransData->baTrack2Data, 100, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCTLSTransData->usChipDataLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strCTLSTransData->baChipData, 1024, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCTLSTransData->usAdditionalDataLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strCTLSTransData->baAdditionalData, 1024, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCTLSTransData->usTransResult);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCTLSTransData->bCVMAnalysis);	
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strCTLSTransData->baCVMResults, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCTLSTransData->bVisaAOSAPresent);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strCTLSTransData->baVisaAOSA, 6, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCTLSTransData->bODAFail);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCTLSTransData->inReserved1);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCTLSTransData->inReserved2);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strCTLSTransData->inReserved3);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strCTLSTransData->szReserved1, 100, SQLITE_STATIC); 
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strCTLSTransData->szReserved2, 100, SQLITE_STATIC); 
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strCTLSTransData->szReserved3, 100, SQLITE_STATIC); 
	
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

//SMAC
#if 0
int inSMTRead(int inSeekCnt)
{     
	int result;
	char *sql = "SELECT SMTTid, SMACRATE, DEACTDATE, SMACENABLE, SMZ FROM SMT WHERE SMTTid = ?";

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
	
		inStmtSeq = 0;
		strSMT.SMTTid= sqlite3_column_int(stmt,inStmtSeq +=1);	
		strSMT.SMACRATE = sqlite3_column_double(stmt,inStmtSeq +=1);
		memcpy(strSMT.DEACTDATE, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 20);
		strSMT.SMACENABLE = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		strSMT.SMZ = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	}

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	
	return(d_OK);
}

int inSMTSave(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE SMT SET SMACRATE=?, DEACTDATE=?, SMACENABLE=?, SMZ=? WHERE SMTTid = ?";

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

	result = sqlite3_bind_double(stmt, inStmtSeq +=1, strSMT.SMACRATE);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strSMT.DEACTDATE, 20, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strSMT.SMACENABLE);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strSMT.SMZ);
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
#endif



int inNMTReadNumofRecords(int *inFindRecordNum)
{
	int result;
	char *sql = "SELECT NMTID, szMerchName, fNMTEnable, szMercPassword, fMerchEnablePassword  FROM NMT WHERE  fNMTEnable = ? ORDER BY NMTID";

	int incount = 0;
	
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

	inStmtSeq = 0;
	//sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		vdDebug_LogPrintf("inMMTReadNumofRecords=[%d]",result);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;

            strNMT[incount].NMTID= sqlite3_column_int(stmt, inStmtSeq);   
			strcpy((char*)strNMT[incount].szMerchName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strNMT[incount].fNMTEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strcpy((char*)strNMT[incount].szMercPassword, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strNMT[incount].fMerchEnablePassword = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			incount ++;

		}
	} while (result == SQLITE_ROW);

	*inFindRecordNum = incount;

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);
    
    return(d_OK);
}


int inBatchReviewByMerchandHost(int inNumber, int inHostIndex, int inMerchIndex, char *szBatchNo, int *inTranID)
{
	int result;
  	char *sql = "SELECT TransDataid FROM TransData WHERE HDTid = ? AND MITid = ? AND szBatchNo = ? AND byTransType != ? AND byTransType != ? AND byTransType != ? AND byTransType != ? AND byTransType != ? AND byTransType != ?";
	int count = 0;

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
	sqlite3_bind_int(stmt, inStmtSeq +=1, inHostIndex);
	sqlite3_bind_int(stmt, inStmtSeq +=1, inMerchIndex);
	sqlite3_bind_blob(stmt, inStmtSeq +=1, szBatchNo, 3, SQLITE_STATIC);
	sqlite3_bind_int(stmt, inStmtSeq +=1, PRE_AUTH);
	sqlite3_bind_int(stmt, inStmtSeq +=1, SMAC_BALANCE);
	sqlite3_bind_int(stmt, inStmtSeq +=1, BALANCE_INQUIRY);
	sqlite3_bind_int(stmt, inStmtSeq +=1, KIT_SALE);
	sqlite3_bind_int(stmt, inStmtSeq +=1, RENEWAL);
	sqlite3_bind_int(stmt, inStmtSeq +=1, PTS_AWARDING);

	inStmtSeq = 0;
	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */		

			 inTranID[count] = sqlite3_column_int(stmt,inStmtSeq);
             DebugAddINT("inTranID", inTranID[count]);
			 count++;

   		}
	} while (result == SQLITE_ROW);	   

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(d_OK);
}

int inMustSettleNumRecord(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM MMT WHERE fMustSettFlag = 1 AND fMMTEnable = 1";
	int inCount = 0;
	
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


int inCheckHostEnable_Per_APPLICATION(char *szAPPNAME)
{
	int len,inCount;
	CTOS_RTC SetRTC;     
	int result;
	int inResult = d_NO;
	char *sql = "SELECT COUNT(*) FROM HDT WHERE szAPName = ? AND fHostEnable = 1";

	char test[20];
	memset(test,0x00,20);
		
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

	inStmtSeq = 0;
	
	sqlite3_bind_text(stmt, inStmtSeq +=1, szAPPNAME, strlen(szAPPNAME), SQLITE_STATIC);
	//sqlite3_bind_int(stmt, inStmtSeq +=1, 1);//fHostEnable = 1

	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;

			/* count */
			inCount = sqlite3_column_int(stmt,inStmtSeq);
		}
	} while (result == SQLITE_ROW);

    return 	inCount;

}

int inSetOfflineLabel(char *szButtonItemLabel)
{
	int result;
	char szMenuFilename[FILENAME_SIZE] = {0};
		
	char *sql = "UPDATE DMHotelMenu SET szButtonItemLabel=? WHERE szButtonItemLabel='OFFLINE' or szButtonItemLabel='COMPLETION' or szButtonItemLabel='CHECKOUT'"; 			

	inTCTRead(1);
	sprintf(szMenuFilename, "./fs_data/DYNAMICMENU%02d.S3DB", strTCT.inMenuid);

	/* open the database */
	result = sqlite3_open(szMenuFilename,&db);
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
    //sqlite3_bind_int(stmt, inStmtSeq +=1, inHostIndex);
    sqlite3_bind_text(stmt, inStmtSeq +=1, szButtonItemLabel, strlen(szButtonItemLabel), SQLITE_STATIC);
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

int inNMTReadRecord(int NMTID)
{     
	int result = 0,
		inCount = 0;
	char *sql = "SELECT NMTID, szMerchName, fNMTEnable, szMercPassword, fMerchEnablePassword, szRctHdr1, szRctHdr2, szRctHdr3, szRctHdr4, szRctHdr5, szRctFoot1, szRctFoot2, szRctFoot3  FROM NMT WHERE fNMTEnable = 1 AND NMTID = ? ORDER BY NMTID";

    memset(&strSingleNMT, 0x00, sizeof(strSingleNMT));
	
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

	sqlite3_bind_int(stmt, 1, NMTID);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do 
	{
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) /* can read data */
		{ 
			inStmtSeq = 0;
            
            strSingleNMT.NMTID= sqlite3_column_int(stmt, inStmtSeq);   
            strcpy((char*)strSingleNMT.szMerchName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strSingleNMT.fNMTEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strSingleNMT.szMercPassword, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strSingleNMT.fMerchEnablePassword = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            strcpy((char*)strSingleNMT.szRctHdr1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strSingleNMT.szRctHdr2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strSingleNMT.szRctHdr3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strSingleNMT.szRctHdr4, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strSingleNMT.szRctHdr5, (char *)sqlite3_column_text(stmt,inStmtSeq +=1  ));
            strcpy((char*)strSingleNMT.szRctFoot1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1  ));
            strcpy((char*)strSingleNMT.szRctFoot2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strSingleNMT.szRctFoot3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			inCount++;
		}
	} 
	while (result == SQLITE_ROW);
	
	//*inNumRecs = inCount;
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	
	return(d_OK);
}



int inBatchNumALLRecord(void)
{
	int len;
	int result;
	//char *sql = "SELECT COUNT(*) FROM TransData WHERE HDTid = ? AND MITid = ? AND szBatchNo = ?";
	char *sql = "SELECT COUNT(*) FROM TransData WHERE HDTid = ? AND MITid = ? AND szBatchNo = ?"; 
	int inCount = 0;
	
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
	sqlite3_bind_blob(stmt, inStmtSeq +=1, strMMT[0].szBatchNo, 3, SQLITE_STATIC);

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

int inDatabase_InvoiceNumInsert(TRANS_DATA_TABLE *transData)
{
	int result;	
	char *sql1 = "SELECT MAX(TransDataid) FROM TransData";

 	char *sql = "INSERT INTO TransData (TransDataid, HDTid, MITid, szInvoiceNo, ulSavedIndex, byTransType) VALUES (NULL, ?, ?, ?, ?, ?)";


	/* open the database */
	result = sqlite3_open(DB_INVOICE,&db);
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
	result = sqlite3_open(DB_INVOICE,&db);
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

int inDatabase_InvoiceNumSearch(TRANS_DATA_TABLE *transData, char *hexInvoiceNo)
{
	int result,i = 0;
	int inResult = d_NO;

	/* Issue# 000096: BIN VER Checking -- jzg*/
	char *sql = "SELECT HDTid FROM TransData WHERE szInvoiceNo = ?";

	/* open the database */
	result = sqlite3_open(DB_INVOICE,&db);
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
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, hexInvoiceNo, 4, SQLITE_STATIC);

	DebugAddINT("inDatabase_BatchSearch sqlite3_bind_blob", result);
	DebugAddHEX("hexInvoiceNo", hexInvoiceNo, 3);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		i++;
		DebugAddINT("if(100)=Find", result);
		DebugAddINT("Loop Count", i);

		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			transData->HDTid = sqlite3_column_int(stmt,inStmtSeq);
		}
	} while (result == SQLITE_ROW);

    DebugAddSTR("batch serPAN", transData->szPAN, 10);
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inResult);
}

int inDatabase_InvoiceNumDelete(int HDTid, int MITid)
{
	int result;
	char *sql = "DELETE FROM TransData WHERE HDTid = ? and MITid = ?";	
	int inDBResult =0 ;
	
	//1205
	//remove(DB_INVOICE);
	//1205

	/* open the database */
	result = sqlite3_open(DB_INVOICE,&db);
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
//	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srTransRec.szHostLabel, strlen((char*)srTransRec.szHostLabel), SQLITE_STATIC); 
//	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, srTransRec.szBatchNo, 3, SQLITE_STATIC);

//    result = sqlite3_bind_int(stmt, 1, inSeekCnt);
    sqlite3_bind_int(stmt, inStmtSeq +=1, HDTid);
	sqlite3_bind_int(stmt, inStmtSeq +=1, MITid);
	
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

int inCheckBatchEmtpy(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM TransData where byTransType <> 102 AND byTransType <> 139";
	int inCount = 0;
	
	/* open the database */
	result = sqlite3_open(DB_INVOICE,&db);
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

int inHDTSaveEDCSETTTING(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE HDT SET inHostIndex = ? , szTPDU = ? ,szNII = ? ,fHostEnable = ? ,szTraceNo = ? ,fSignOn = ?,inFailedREV = ?,inNumAdv = ?, fPrintFooterLogo = ?, fPrintBankReceipt = ?, fPrintCustReceipt = ?, fPrintMercReceipt = ?, fPrintVoidBankReceipt = ?, fPrintVoidCustReceipt = ?, fPrintVoidMercReceipt = ? WHERE  HDTid = ?";

	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

	vdSetJournalModeOff();

	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}
	inStmtSeq = 0;
    /*inHostIndex*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.inHostIndex);
	/*szTPDU*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strHDT.szTPDU, 5, SQLITE_STATIC);
	/* szNII*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strHDT.szNII, 2, SQLITE_STATIC);
	/* fHostEnable*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fHostEnable);

	/* szTraceNo*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strHDT.szTraceNo, 3, SQLITE_STATIC);
	/* fSignOn */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fSignOn);

	/*inFailedREV*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.inFailedREV);

    /*inNumAdv*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.inNumAdv);
			
	//sidumili: Issue#: 000135
	/* fPrintFooterLogo */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintFooterLogo);	

	/*BDO: Parameterized receipt printing - start*/
	/* fPrintBankReceipt */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintBankReceipt);
	 
	/* fPrintCustReceipt */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintCustReceipt);
	 
	/* fPrintMercReceipt */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintMercReceipt);
	 	
	/* fPrintVoidBankReceipt */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintVoidBankReceipt);
	 
	/* fPrintVoidCustReceipt */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintVoidCustReceipt);
	 
	/* fPrintVoidMercReceipt */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strHDT.fPrintVoidMercReceipt);
	/*BDO: Parameterized receipt printing - end*/

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


int inInstallmentCDTReadMulti(char *szPAN, int *inFindRecordNum)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT szPANLo, szPANHi, szCardLabel, inType, inMinPANDigit, inMaxPANDigit, inCVV_II, InFloorLimitAmount, fExpDtReqd,  fPinpadRequired, fManEntry, fCardPresent, fChkServiceCode, fluhnCheck, fCDTEnable, IITid, HDTid, CDTid, fInstallmentEnable, inInstGroup, fDualCurrencyEnable, fFleetCard,fPANCatchAll FROM CDT WHERE ? BETWEEN szPANLo AND szPANHi AND fInstallmentEnable = ?";
	int inDBResult = 0;
	char szTemp[16];
	int inPAN, inCount=0;
		
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	inDBResult = sqlite3_exec( db, "begin", 0, 0, NULL );
	vdDebug_LogPrintf("inCDTRead,sqlite3_exec[%d]",inDBResult);
	
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}
#ifdef TRUNC_PAN_READING
	memcpy(szTemp, szPAN, 8);
	szTemp[8]=0;
	inPAN = atoi(szTemp);
	vdDebug_LogPrintf("inPAN = %d",inPAN);
#else
	memcpy(szTemp, szPAN, 12);
	szTemp[12]=0;
#endif

	inStmtSeq = 0;

#ifdef TRUNC_PAN_READING
	sqlite3_bind_int(stmt, inStmtSeq +=1, inPAN);
#else
	sqlite3_bind_text(stmt, inStmtSeq +=1, szTemp, strlen(szTemp), SQLITE_STATIC);
#endif

	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);//fCDTEnable = 1


	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		vdDebug_LogPrintf("inCDTRead,result[%d]SQLITE_ROW[%d]",result,SQLITE_ROW);
		
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

		    /*szPANLo*/
		     strcpy(strMCDT[inCount].szPANLo, sqlite3_column_text(stmt,inStmtSeq));

		    /*szPANHi*/
		     strcpy(strMCDT[inCount].szPANHi, sqlite3_column_text(stmt,inStmtSeq +=1));

		    /*szCardLabel*/
		    strcpy(strMCDT[inCount].szCardLabel, sqlite3_column_text(stmt,inStmtSeq +=1));

		    /*inType*/
			strMCDT[inCount].inType = sqlite3_column_int(stmt,inStmtSeq +=1);
			
			/*inMinPANDigit*/
		    strMCDT[inCount].inMinPANDigit = sqlite3_column_int(stmt,inStmtSeq +=1);
			
			/*inMaxPANDigit*/
		    strMCDT[inCount].inMaxPANDigit = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*inCVV_II*/
		    strMCDT[inCount].inCVV_II = sqlite3_column_int(stmt,inStmtSeq +=1);

            
			/*InFloorLimitAmount*/
			strMCDT[inCount].InFloorLimitAmount = sqlite3_column_double(stmt,inStmtSeq +=1 );

			
			/*fExpDtReqd*/
		    strMCDT[inCount].fExpDtReqd = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			
			
			/*fPinpadRequired*/
		    strMCDT[inCount].fPinpadRequired = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

				
			/*fManEntry*/
		    strMCDT[inCount].fManEntry = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		    /*fCardPresent*/
		    strMCDT[inCount].fCardPresent = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			
		    /*fChkServiceCode*/
		    strMCDT[inCount].fChkServiceCode =fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fluhnCheck */
			strMCDT[inCount].fluhnCheck = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fCDTEnable*/
			strMCDT[inCount].fCDTEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));		

            /*IITid*/
		    strMCDT[inCount].IITid = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* HDTid*/
			strMCDT[inCount].HDTid = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* CDTid*/
			strMCDT[inCount].CDTid = sqlite3_column_int(stmt,inStmtSeq +=1);


			//gcitra
			/*fInstallmentEnable*/
			strMCDT[inCount].fInstallmentEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));		

			/*inInstGroup*/
			strMCDT[inCount].inInstGroup = sqlite3_column_double(stmt,inStmtSeq +=1 );
			//gcitra		

			//1026
            /*fDualCurrencyEnable*/
			strMCDT[inCount].fDualCurrencyEnable = sqlite3_column_double(stmt,inStmtSeq +=1 );

			/* BDO CLG: Fleet card support - start -- jzg */
			/*fFleetCard*/
			strMCDT[inCount].fFleetCard = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO CLG: Fleet card support - end -- jzg */

			
			/*fPANCatchAll - add to check if BIN is CATCH all - will be used for DEBIT Paypass*/
			strMCDT[inCount].fPANCatchAll = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			inCount ++;
			if(inCount >=10)
				break;
		}
	} while (result == SQLITE_ROW);
  
  *inFindRecordNum = inCount;
  vdDebug_LogPrintf("inCDTReadMulti Record=%d",*inFindRecordNum);
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inResult);
}



int inInstallmentCDTRead(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT szPANLo, szPANHi, szCardLabel, inType, inMinPANDigit, inMaxPANDigit, inCVV_II, InFloorLimitAmount, fExpDtReqd,  fPinpadRequired, fManEntry, fCardPresent, fChkServiceCode, fluhnCheck, fCDTEnable, IITid, HDTid, fInstallmentEnable, inInstGroup, fDualCurrencyEnable, inDualCurrencyHost, fFleetCard, fPANCatchAll FROM CDT WHERE CDTid = ? AND fInstallmentEnable = ?";
	//char sql[1000+1];

	int inDBResult = 0;	
		
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	
	inDBResult = sqlite3_exec( db, "begin", 0, 0, NULL );
	vdDebug_LogPrintf("inCDTRead,sqlite3_exec[%d]",inDBResult);

	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);//fCDTEnable = 1

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		vdDebug_LogPrintf("inCDTRead,result[%d]SQLITE_ROW[%d]",result,SQLITE_ROW);

		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			/*szPANLo*/
			strcpy(strCDT.szPANLo, sqlite3_column_text(stmt,inStmtSeq));

			/*szPANHi*/
			strcpy(strCDT.szPANHi, sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szCardLabel*/
			strcpy(strCDT.szCardLabel, sqlite3_column_text(stmt,inStmtSeq +=1));

			/*inType*/
			strCDT.inType = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*inMinPANDigit*/
			strCDT.inMinPANDigit = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*inMaxPANDigit*/
			strCDT.inMaxPANDigit = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*inCVV_II*/
			strCDT.inCVV_II = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*InFloorLimitAmount*/
			strCDT.InFloorLimitAmount = sqlite3_column_double(stmt,inStmtSeq +=1 );

			/*fExpDtReqd*/
			strCDT.fExpDtReqd = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPinpadRequired*/
			strCDT.fPinpadRequired = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fManEntry*/
			strCDT.fManEntry = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fCardPresent*/
			strCDT.fCardPresent = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fChkServiceCode*/
			strCDT.fChkServiceCode =fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fluhnCheck */
			strCDT.fluhnCheck = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fCDTEnable*/
			strCDT.fCDTEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));		

			/*IITid*/
			strCDT.IITid = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* HDTid*/
			strCDT.HDTid = sqlite3_column_int(stmt,inStmtSeq +=1);	

			//gcitra
			/*fInstallmentEnable*/
			strCDT.fInstallmentEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));		

			/*inInstGroup*/
			strCDT.inInstGroup = sqlite3_column_double(stmt,inStmtSeq +=1 );
			//gcitra

			//1026
			/*fDualCurrencyEnable*/
			strCDT.fDualCurrencyEnable = sqlite3_column_double(stmt,inStmtSeq +=1 );

			/* BDO: Added dual currency to CDT -- jzg */
			strCDT.inDualCurrencyHost = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* BDO CLG: Fleet card support - start -- jzg */
			/*fFleetCard*/
			strCDT.fFleetCard = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO CLG: Fleet card support - end -- jzg */

			/*fPANCatchAll - add to check if BIN is CATCH all - will be used for DEBIT Paypass*/
			strCDT.fPANCatchAll = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			
		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inResult);
}

int inInstallmentCDTReadEx(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT szPANLo, szPANHi, szCardLabel, inType, inMinPANDigit, inMaxPANDigit, inCVV_II, InFloorLimitAmount, fExpDtReqd,  fPinpadRequired, fManEntry, fCardPresent, fChkServiceCode, fluhnCheck, fCDTEnable, IITid, HDTid, fInstallmentEnable, inInstGroup, fDualCurrencyEnable, inDualCurrencyHost, fFleetCard, fPANCatchAll FROM CDT WHERE CDTid = ? AND fInstallmentEnable = ?";
	//char sql[1000+1];

	int inDBResult = 0;	
	#if 0	
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	#endif
	
	inDBResult = sqlite3_exec( db, "begin", 0, 0, NULL );
	vdDebug_LogPrintf("inCDTRead,sqlite3_exec[%d]",inDBResult);

	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);//fCDTEnable = 1

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		vdDebug_LogPrintf("inCDTRead,result[%d]SQLITE_ROW[%d]",result,SQLITE_ROW);

		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			/*szPANLo*/
			strcpy(strCDT.szPANLo, sqlite3_column_text(stmt,inStmtSeq));

			/*szPANHi*/
			strcpy(strCDT.szPANHi, sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szCardLabel*/
			strcpy(strCDT.szCardLabel, sqlite3_column_text(stmt,inStmtSeq +=1));

			/*inType*/
			strCDT.inType = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*inMinPANDigit*/
			strCDT.inMinPANDigit = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*inMaxPANDigit*/
			strCDT.inMaxPANDigit = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*inCVV_II*/
			strCDT.inCVV_II = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*InFloorLimitAmount*/
			strCDT.InFloorLimitAmount = sqlite3_column_double(stmt,inStmtSeq +=1 );

			/*fExpDtReqd*/
			strCDT.fExpDtReqd = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPinpadRequired*/
			strCDT.fPinpadRequired = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fManEntry*/
			strCDT.fManEntry = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fCardPresent*/
			strCDT.fCardPresent = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fChkServiceCode*/
			strCDT.fChkServiceCode =fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fluhnCheck */
			strCDT.fluhnCheck = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fCDTEnable*/
			strCDT.fCDTEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));		

			/*IITid*/
			strCDT.IITid = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* HDTid*/
			strCDT.HDTid = sqlite3_column_int(stmt,inStmtSeq +=1);	

			//gcitra
			/*fInstallmentEnable*/
			strCDT.fInstallmentEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));		

			/*inInstGroup*/
			strCDT.inInstGroup = sqlite3_column_double(stmt,inStmtSeq +=1 );
			//gcitra

			//1026
			/*fDualCurrencyEnable*/
			strCDT.fDualCurrencyEnable = sqlite3_column_double(stmt,inStmtSeq +=1 );

			/* BDO: Added dual currency to CDT -- jzg */
			strCDT.inDualCurrencyHost = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* BDO CLG: Fleet card support - start -- jzg */
			/*fFleetCard*/
			strCDT.fFleetCard = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO CLG: Fleet card support - end -- jzg */

			/*fPANCatchAll - add to check if BIN is CATCH all - will be used for DEBIT Paypass*/
			strCDT.fPANCatchAll = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			
		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	
	#if 0
	sqlite3_close(db);
    #endif
	
	return(inResult);
}

int inHDTReadData(int inSeekCnt)
{
	int len;
	CTOS_RTC SetRTC;     
	int result;
	int inResult = d_NO;
	char *sql = "SELECT szHostLabel, fHostEnable, inCurrencyIdx, szDCCRateandLogTraceNo, fTapAndGo FROM HDT WHERE HDTid = ?";

    memset(&strHDT_Temp,0x00, sizeof(STRUCT_HDT));
		
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

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);

    /* loop reading each row until step returns anything other than SQLITE_ROW */
    do 
    {
        result = sqlite3_step(stmt);
        if (result == SQLITE_ROW)  /* can read data */
        {
            inResult = d_OK;
            inStmtSeq = 0;
           
            /* szHostLabel */
            strcpy((char*)strHDT_Temp.szHostLabel, (char *)sqlite3_column_text(stmt, inStmtSeq));
            
            /* fHostEnable*/
            strHDT_Temp.fHostEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			 /* inCurrencyIdx*/
			strHDT_Temp.inCurrencyIdx = sqlite3_column_int(stmt, inStmtSeq +=1 );

 			/* szDCCRateandLogTraceNo */
			memcpy(strHDT_Temp.szDCCRateandLogTraceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);

			/*fTapAndGo*/
			strHDT_Temp.fTapAndGo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
        }
    } while (result == SQLITE_ROW);

    sqlite3_exec(db,"commit;",NULL,NULL,NULL);
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return(inResult);
}

int inHDTReadDataEx(int inSeekCnt)
{
	int len;
	CTOS_RTC SetRTC;     
	int result;
	int inResult = d_NO;
	char *sql = "SELECT szHostLabel, fHostEnable, inCurrencyIdx, szDCCRateandLogTraceNo FROM HDT WHERE HDTid = ?";

    memset(&strHDT_Temp,0x00, sizeof(STRUCT_HDT));

	#if 0
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	#endif
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);

    /* loop reading each row until step returns anything other than SQLITE_ROW */
    do 
    {
        result = sqlite3_step(stmt);
        if (result == SQLITE_ROW)  /* can read data */
        {
            inResult = d_OK;
            inStmtSeq = 0;
           
            /* szHostLabel */
            strcpy((char*)strHDT_Temp.szHostLabel, (char *)sqlite3_column_text(stmt, inStmtSeq));
            
            /* fHostEnable*/
            strHDT_Temp.fHostEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			 /* inCurrencyIdx*/
			strHDT_Temp.inCurrencyIdx = sqlite3_column_int(stmt, inStmtSeq +=1 );

 			/* szDCCRateandLogTraceNo */
			memcpy(strHDT_Temp.szDCCRateandLogTraceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);
        }
    } while (result == SQLITE_ROW);

    sqlite3_exec(db,"commit;",NULL,NULL,NULL);
    
    sqlite3_finalize(stmt);
	#if 0
    sqlite3_close(db);
	#endif
    
    return(inResult);
}

int inSetTipAllowedLabel(char *szButtonItemLabel)
{
	int result;
	char szMenuFilename[FILENAME_SIZE] = {0};
		
	char *sql = "UPDATE DMTerminalSettingMenu SET szButtonItemLabel=? WHERE szButtonItemLabel='TIP ALLOWD'"; 			

	inTCTRead(1);
	sprintf(szMenuFilename, "./fs_data/DYNAMICMENU%02d.S3DB", strTCT.inMenuid);

	/* open the database */
	result = sqlite3_open(szMenuFilename,&db);
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
    //sqlite3_bind_int(stmt, inStmtSeq +=1, inHostIndex);
    sqlite3_bind_text(stmt, inStmtSeq +=1, szButtonItemLabel, strlen(szButtonItemLabel), SQLITE_STATIC);
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

int inDatabase_IPReportInsert(void)
{
	int result;	
	char szMenuFilename[FILENAME_SIZE] = {0};
 	char *sql = "INSERT INTO DMReportMenu (DMReportMenuid, fButtonIDEnable, usButtonID, szButtonItemImage, szButtonItemLabel, szButtonTitleLabel, szButtonItemFunc, szSubMenuName) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    char *sql1 = "SELECT COUNT(*) FROM DMReportMenu";
	char *sql2 = "SELECT COUNT(*) FROM DMReportMenu WHERE szButtonItemLabel = 'IP'";
	int inCount=0;
	
	inTCTRead(1);
	sprintf(szMenuFilename, "./fs_data/DYNAMICMENU%02d.S3DB", strTCT.inMenuid);

	/* open the database */
	result = sqlite3_open(szMenuFilename,&db);
	if (result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 1;
	}

    /*start - get number of records for szButtonItemLabel = IP*/
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql2, -1, &stmt, NULL);
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
    //inCount++;
    if(inCount > 0)
    {
		sqlite3_close(db);
		return(ST_SUCCESS);
    }
    /*end - get number of records for szButtonItemLabel = IP*/
	
    /*start - get number of records*/
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

			/* count */
			inCount = sqlite3_column_int(stmt,inStmtSeq);
		}
	} while (result == SQLITE_ROW);
    inCount++;
    /*end - get number of records*/
	
    vdDebug_LogPrintf("inDatabase_IPReportInsert inCount:%d", inCount);
	
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, inCount);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, 1);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, inCount);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, " ", strlen(" "), SQLITE_STATIC);
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, "IP", strlen("IP"), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, "REPORT", strlen("REPORT"), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, "vdCTOS_PrintIP", strlen("vdCTOS_PrintIP"), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, " ", strlen(" "), SQLITE_STATIC); 
	
	
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

#if 0
int inDatabase_IPReportInsert2(void)
{
	int result;	
	char szMenuFilename[FILENAME_SIZE] = {0};
 	char *sql = "INSERT INTO DMTrxMenu (DMTrxMenuid, fButtonIDEnable, usButtonID, szButtonItemImage, szButtonItemLabel, szButtonTitleLabel, szButtonItemFunc, szSubMenuName) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    char *sql1 = "SELECT COUNT(*) FROM DMTrxMenu";
	char *sql2 = "SELECT COUNT(*) FROM DMTrxMenu WHERE szButtonItemLabel = 'BDO LOYALTY'";
	int inCount=0;
	
	inTCTRead(1);
	sprintf(szMenuFilename, "./fs_data/DYNAMICMENU%02d.S3DB", strTCT.inMenuid);

	vdDebug_LogPrintf("inDatabase_IPReportInsert2 - start");

	vdDebug_LogPrintf("szMenuFilename[%s]",szMenuFilename);

	/* open the database */
	result = sqlite3_open(szMenuFilename,&db);
	if (result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 1;
	}

    /*start - get number of records for szButtonItemLabel = IP*/
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql2, -1, &stmt, NULL);
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
    //inCount++;
    if(inCount > 0)
    {
		sqlite3_close(db);
		return(ST_SUCCESS);
    }
    /*end - get number of records for szButtonItemLabel = IP*/
	
    /*start - get number of records*/
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

			/* count */
			inCount = sqlite3_column_int(stmt,inStmtSeq);
		}
	} while (result == SQLITE_ROW);
    inCount++;
    /*end - get number of records*/
	
    vdDebug_LogPrintf("inDatabase_IPReportInsert inCount:%d", inCount);
	
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
	

	vdDebug_LogPrintf("inDatabase_IPReportInsert2 - 5");
	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, inCount);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, 1);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, inCount);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, " ", strlen(" "), SQLITE_STATIC);
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, "BDO LOYALTY", strlen("BDO LOYALTY"), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, "FUNCTION", strlen("FUNCTION"), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, "inBDOLoyaltyMenu", strlen("inBDOLoyaltyMenu"), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, " ", strlen(" "), SQLITE_STATIC); 
	
	
	result = sqlite3_step(stmt);

    vdDebug_LogPrintf("inDatabase_IPReportInsert result2:%d", result);
	
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	vdDebug_LogPrintf("inDatabase_IPReportInsert2 - SUCCESS!!!");

	return(ST_SUCCESS);
}
#endif

int inFXTRead(int inSeekCnt)
{     
	int result;
	char *sql = "SELECT FXTid, szFXTTPDU, szFXTNII, szFXTTID, szFXTMID, szDCCAuthTPDU, szDCCAuthNII, szACQID FROM FXT WHERE FXTid = ?";

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
	if (result == SQLITE_ROW)
	{
		strFXT.FXTid= sqlite3_column_int(stmt,inStmtSeq +=1);	
		inStmtSeq = 0;
		memcpy(strFXT.szFXTTPDU, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);
		memcpy(strFXT.szFXTNII, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);
		strcpy((char*)strFXT.szFXTTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		strcpy((char*)strFXT.szFXTMID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
        memcpy(strFXT.szDCCAuthTPDU, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);
		memcpy(strFXT.szDCCAuthNII, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);
		strcpy((char*)strFXT.szACQID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	}

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	
	return(d_OK);
}

int inCSTReadHostID(char *szCurCode)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT inCurrencyIndex, szCurSymbol, szCurCode, HDTid, szAmountFormat, inMinorUnit FROM CST WHERE szCurCode = ?";

	memset(&strCST,0x00,sizeof(strCST));
	
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
	inStmtSeq = 0;
    sqlite3_bind_text(stmt, inStmtSeq +=1, szCurCode, strlen(szCurCode), SQLITE_STATIC);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;
		
			/* inCurrencyIndex */
			strCST.inCurrencyIndex = sqlite3_column_int(stmt,inStmtSeq);
				
			/* szCurSymbol */			
			strcpy((char*)strCST.szCurSymbol, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szCurCode*/
			strcpy((char*)strCST.szCurCode, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* inCurrencyIndex */
			strCST.HDTid = sqlite3_column_int(stmt,inStmtSeq +=1);

			strcpy((char*)strCST.szAmountFormat, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));	

			/* inMinorUnit */
			strCST.inMinorUnit = sqlite3_column_int(stmt,inStmtSeq +=1);
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inResult);
}


int inERMAP_Database_BatchDelete(void)
{
	int result;
	char *sql = "DELETE FROM TransData";	
	int inDBResult =0 ;

	/* open the database */
	result = sqlite3_open(DB_ERM,&db);
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

int inERMAP_Database_BatchRead(ERM_TransData *strERMTransData)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT shType, szTPDU, szPAN, szAmt, szSTAN, szTime, szDate, szExpDate, szRefNum, szApprCode, szTID, szMID, szTerminalSerialNO, szBankCode, szMerchantCode, szStoreCode, szPaymentType, szPaymentMedia, szBatchNum, szReceiptImageFileName, szInvNum, szLogoFileName, szSingatureStatus, szRSAKEKVersion, szReceiptLogoIndex, fGzipReceiptImage, fSettle, fReserved1, fReserved2, fReserved3, szReserved1, szReserved2, szReserved3 FROM TransData WHERE TransDataid = ?";

	/* open the database */
	result = sqlite3_open(DB_ERM,&db);
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

			strERMTransData->shType = sqlite3_column_int(stmt,inStmtSeq);
			strcpy((char*)strERMTransData->szTPDU, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strERMTransData->szPAN, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strERMTransData->szAmt, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));	
			strcpy((char*)strERMTransData->szSTAN, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strERMTransData->szTime, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strERMTransData->szDate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));	
			strcpy((char*)strERMTransData->szExpDate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strERMTransData->szRefNum, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strERMTransData->szApprCode, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));	
			strcpy((char*)strERMTransData->szTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strERMTransData->szMID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strERMTransData->szTerminalSerialNO, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));			
			strcpy((char*)strERMTransData->szBankCode, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strERMTransData->szMerchantCode, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strERMTransData->szStoreCode, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));	
			strcpy((char*)strERMTransData->szPaymentType, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strERMTransData->szPaymentMedia, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strERMTransData->szBatchNum, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));	
			strcpy((char*)strERMTransData->szReceiptImageFileName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strERMTransData->szInvNum, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strERMTransData->szLogoFileName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));	
			strcpy((char*)strERMTransData->szSingatureStatus, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strERMTransData->szRSAKEKVersion, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strERMTransData->szReceiptLogoIndex, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strERMTransData->fGzipReceiptImage = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strERMTransData->fSettle = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strERMTransData->fReserved1 = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strERMTransData->fReserved2 = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strERMTransData->fReserved3 = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));			
			strcpy((char*)strERMTransData->szReserved1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strERMTransData->szReserved2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)strERMTransData->szReserved3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inResult);
}

//INSERT INTO TransData (TransDataid, shType, szTPDU, szPAN, szAmt, szSTAN, szTime, szDate, szExpDate, szRefNum, szApprCode, szTID, szMID, szTerminalSerialNO, szBankCode, szMerchantCode, szStoreCode, szPaymentType, szPaymentMedia, szBatchNum, szReceiptImageFileName, szInvNum, szLogoFileName, szSingatureStatus, szRSAKEKVersion, szReceiptLogoIndex, fGzipReceiptImage, fSettle, fReserved1, fReserved2, fReserved3, szReserved1, szReserved2, szReserved3) VALUES (1, 3, 3, 3, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
int inERMAP_Database_BatchInsert(ERM_TransData *strERMTransData)
{
	int result;	
 	char *sql = "INSERT INTO TransData (TransDataid, shType, szTPDU, szPAN, szAmt, szSTAN, szTime, szDate, szExpDate, szRefNum, szApprCode, szTID, szMID, szTerminalSerialNO, szBankCode, szMerchantCode, szStoreCode, szPaymentType, szPaymentMedia, szBatchNum, szReceiptImageFileName, szInvNum, szLogoFileName, szSingatureStatus, szRSAKEKVersion, szReceiptLogoIndex, fGzipReceiptImage, fSettle, fReserved1, fReserved2, fReserved3, szReserved1, szReserved2, szReserved3) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
	   
	/* open the database */
	result = sqlite3_open(DB_ERM,&db);
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
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strERMTransData->shType);
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szTPDU, strlen((char*)strERMTransData->szTPDU), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szPAN, strlen((char*)strERMTransData->szPAN), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szAmt, strlen((char*)strERMTransData->szAmt), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szSTAN, strlen((char*)strERMTransData->szSTAN), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szTime, strlen((char*)strERMTransData->szTime), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szDate, strlen((char*)strERMTransData->szDate), SQLITE_STATIC);
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szExpDate, strlen((char*)strERMTransData->szExpDate), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szRefNum, strlen((char*)strERMTransData->szRefNum), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szApprCode, strlen((char*)strERMTransData->szApprCode), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szTID, strlen((char*)strERMTransData->szTID), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szMID, strlen((char*)strERMTransData->szMID), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szTerminalSerialNO, strlen((char*)strERMTransData->szTerminalSerialNO), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szBankCode, strlen((char*)strERMTransData->szBankCode), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szMerchantCode, strlen((char*)strERMTransData->szMerchantCode), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szStoreCode, strlen((char*)strERMTransData->szStoreCode), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szPaymentType, strlen((char*)strERMTransData->szPaymentType), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szPaymentMedia, strlen((char*)strERMTransData->szPaymentMedia), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szBatchNum, strlen((char*)strERMTransData->szBatchNum), SQLITE_STATIC);
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szReceiptImageFileName, strlen((char*)strERMTransData->szReceiptImageFileName), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szInvNum, strlen((char*)strERMTransData->szInvNum), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szLogoFileName, strlen((char*)strERMTransData->szLogoFileName), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szSingatureStatus, strlen((char*)strERMTransData->szSingatureStatus), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szRSAKEKVersion, strlen((char*)strERMTransData->szRSAKEKVersion), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szReceiptLogoIndex, strlen((char*)strERMTransData->szReceiptLogoIndex), SQLITE_STATIC); 
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strERMTransData->fGzipReceiptImage);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strERMTransData->fSettle);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strERMTransData->fReserved1);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strERMTransData->fReserved3);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strERMTransData->fReserved3);
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szReserved1, strlen((char*)strERMTransData->szReserved1), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szReserved2, strlen((char*)strERMTransData->szReserved2), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strERMTransData->szReserved3, strlen((char*)strERMTransData->szReserved3), SQLITE_STATIC); 
	
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


int inERMCommSet(char *szFlag, int fValue)
{
	int result;
	char *sql;
	char szTempSQL[512+1];
	
	memset(szTempSQL, 0, sizeof(szTempSQL));
	sql=&szTempSQL;
	
	sprintf(szTempSQL, "UPDATE ERMTct SET %s = ?",szFlag);
	
 	/* open the database */
	result = sqlite3_open(DB_ERMTCT,&db);
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
        
	/* fCommBackUpMode*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, fValue); 		  

	//result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);

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


int inHDTReadByApname(char *szAPName)
{
	int len;
	CTOS_RTC SetRTC;     
	int result;
	int inResult = d_NO;
	int inHostIndex = 0;
	char *sql = "SELECT inHostIndex FROM HDT WHERE szAPName = ?";
		
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

	inStmtSeq = 0;
	sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)szAPName, strlen(szAPName), SQLITE_STATIC);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

            /*inHostIndex*/
			inHostIndex = sqlite3_column_int(stmt, inStmtSeq );

		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inHostIndex);
}


int inMMTReadHostName(char szHostName[][400], int inCPTID[], int inMITid, int inIndicator)
{    
	int result;
	char *sql = "SELECT HDTid, fBatchNotEmpty, fPendingReversal, fReprintSettleStatus, szHostName FROM MMT WHERE fMMTEnable = ? AND MITid = ? order by inSequence";
	int inCount = 0;
	int inDBResult = 0;
	BOOL fBatchNotEmpty;
	BOOL fPendingReversal;
	BOOL fReprintSettleStatus;
	BOOL isExist = FALSE;
	char szFileName[d_BUFF_SIZE] = {0};
	
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

	
	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);//fHostEnable = 1
	sqlite3_bind_int(stmt, inStmtSeq +=1, inMITid);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;
			/* HDTid */
			inCPTID[inCount] = sqlite3_column_int(stmt,inStmtSeq);

			fBatchNotEmpty = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            fPendingReversal = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	
            fReprintSettleStatus = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* szHostName */
			strcpy((char*)szHostName[inCount], (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			
			// for 00144 - Asterisk �*� is missing in Clear Reversal
			// check file exist
			isExist = FALSE;
			memset(szFileName, 0x00, sizeof(szFileName));
			sprintf(szFileName, "%s%02d%02d.rev"
                                , szHostName[inCount]
                                , inCPTID[inCount]
                                , inMITid);
			isExist = isReversalFileExist(szFileName);
			// for 00144 - Asterisk �*� is missing in Clear Reversal


			vdDebug_LogPrintf("szHostName[%s], isExist[%d]",szHostName[inCount], isExist);

			if (inIndicator == 1){			
				if (fBatchNotEmpty == TRUE)
					strcat((char*)szHostName[inCount],"*");
			}else if(inIndicator == 2) {
				if (fPendingReversal == TRUE || isExist == TRUE)
					strcat((char*)szHostName[inCount],"*");
			}else if(inIndicator == 3) {
				if (fReprintSettleStatus == TRUE)
					strcat((char*)szHostName[inCount],"*");
			}
			
			vdDebug_LogPrintf("szHostName[%s] %d",szHostName[inCount], inCount);

			inCount++;
		}
	} while (result == SQLITE_ROW);

    
	inDBResult = sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	vdDebug_LogPrintf("inDBResult[%d]",inDBResult);
	vdDebug_LogPrintf("inCount[%d]",inCount);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(d_OK);
}

//update CPT set szPriTxnHostIP="192.168.0.111", szSecTxnHostIP="192.168.0.111", szPriSettlementHostIP="192.168.0.111", 
//inPriTxnHostPortNum=5010,  inSecTxnHostPortNum=5010, inPriSettlementHostPort=5010,  inSecSettlementHostPort=5010;

//update CPT set szPriTxnHostIP=?, szSecTxnHostIP=?, szPriSettlementHostIP=?, szSecSettlementHostIP=?, inPriTxnHostPortNum=?,  inSecTxnHostPortNum=?, inPriSettlementHostPort=?,  inSecSettlementHostPort=?

int inSetPriSecConnection(char *szPriTxnHostIP, char *szSecTxnHostIP, int inPriPort, int inSecPort)
{
	int result;
	char szMenuFilename[FILENAME_SIZE] = {0};
		
	char *sql = "update CPT set szPriTxnHostIP=?, szSecTxnHostIP=?, szPriSettlementHostIP=?, szSecSettlementHostIP=?, inPriTxnHostPortNum=?,  inSecTxnHostPortNum=?, inPriSettlementHostPort=?,  inSecSettlementHostPort=?"; 			

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

    inStmtSeq = 0;
    //sqlite3_bind_int(stmt, inStmtSeq +=1, inHostIndex);
    sqlite3_bind_text(stmt, inStmtSeq +=1, szPriTxnHostIP, strlen(szSecTxnHostIP), SQLITE_STATIC);
	sqlite3_bind_text(stmt, inStmtSeq +=1, szSecTxnHostIP, strlen(szSecTxnHostIP), SQLITE_STATIC);
	sqlite3_bind_int(stmt, inStmtSeq +=1, inPriPort);
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSecPort);
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

int inMMTResetReprintSettle(int inMITid)
{
	int result;
	/* aaronnino for BDOCLG ver 9.0 fix on issue #00241 added  fManualMMTSettleTrigger, inOnlineMMTSettleTries, inOnlineMMTSettleLimit*/
	char *sql = "UPDATE MMT SET fReprintSettleStatus = 0 WHERE  MITid = ?";
		
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

	vdSetJournalModeOff();

	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
	
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, inMITid);
    
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

int inMMTSetReprintSettle(int inMMTid)
{
	int result;
	/* aaronnino for BDOCLG ver 9.0 fix on issue #00241 added  fManualMMTSettleTrigger, inOnlineMMTSettleTries, inOnlineMMTSettleLimit*/
	char *sql = "UPDATE MMT SET fReprintSettleStatus = 1 WHERE  MMTid = ?";
		
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

	vdSetJournalModeOff();

	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
	
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, inMMTid);
    
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

int inMMTNumRecordwithBatch(int inMITid, int inHDTid[])
{
	int len;
	int result;
	char *sql = "SELECT HDTid FROM MMT where fMMTEnable=1 and fBatchNotEmpty=1 and MITid=? order by inSequence";
	int inCount = 0;
	
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

	sqlite3_bind_int(stmt, 1, inMITid);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;

            /*inHostIndex*/
            inHDTid[inCount] = sqlite3_column_int(stmt, inStmtSeq );
						
			/* count */
			//inCount = sqlite3_column_int(stmt,inStmtSeq);
			inCount++;
			
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inCount);
}

int inSetMMTSettleStatusEmpty(int inMITid)
{
	int result;
	char szMenuFilename[FILENAME_SIZE] = {0};
		
	char *sql = "update MMT set inSettleStatus=0 where fMMTEnable=1 and fBatchNotEmpty=0 and MITid=?"; 			

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

	result = sqlite3_bind_int(stmt, 1, inMITid);
	
	//result = sqlite3_bind_int(stmt, inStmtSeq +=1, inMITid);

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

int inMMTNumRecordwithSettleStatusSuccess(int inMITid, int inHDTid[])
{
	int len;
	int result;
	char *sql = "SELECT HDTid FROM MMT where fMMTEnable=1 and inSettleStatus=1 and MITid=? order by inSequence";
	int inCount = 0;
	
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

	sqlite3_bind_int(stmt, 1, inMITid);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;

            /*inHostIndex*/
            inHDTid[inCount] = sqlite3_column_int(stmt, inStmtSeq );
						
			/* count */
			//inCount = sqlite3_column_int(stmt,inStmtSeq);
			inCount++;
			
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inCount);
}


int inUpdateInstallmentMenu(int usButtonID)
{
	int result;
	char szMenuFilename[FILENAME_SIZE] = {0};
		
	//char *sql = "UPDATE DMTrxMenu SET szButtonItemLabel=? WHERE szButtonItemLabel='OFFLINE' or szButtonItemLabel='COMPLETION' or szButtonItemLabel='CHECKOUT'"; 			
    char *sql = "UPDATE DMInstallmentMenu SET usButtonID = ? WHERE szButtonItemLabel = 'BIN CHECK'";
	
	inTCTRead(1);
	sprintf(szMenuFilename, "./fs_data/DYNAMICMENU%02d.S3DB", strTCT.inMenuid);

	/* open the database */
	result = sqlite3_open(szMenuFilename,&db);
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
    result=sqlite3_bind_int(stmt, inStmtSeq +=1, usButtonID);

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

int inHDTReadOrderBySequence(int inHDTid[])
{
	int len;
	int result;
		
	char *sql = "SELECT HDTid FROM HDT WHERE fHostEnable=1 order by inSequence";
	int inCount = 0;
	
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

	//sqlite3_bind_int(stmt, 1, inMITid);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;

            /*inHostIndex*/
            inHDTid[inCount] = sqlite3_column_int(stmt, inStmtSeq );
						
			/* count */
			//inCount = sqlite3_column_int(stmt,inStmtSeq);
			inCount++;
			
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inCount);
}

int inHDTReadHostID(char *szHostName, int inHDTid[])
{    
	int result;	
	char *sql = "SELECT inSequence FROM HDT WHERE fHostEnable = 1 and szAPName = ? ORDER BY inSequence";
	int inCount = 0;
	int inDBResult = 0;
	
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

	
    inStmtSeq = 0;
    sqlite3_bind_text(stmt, inStmtSeq +=1, szHostName, strlen(szHostName), SQLITE_STATIC);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;
			/* HDTid */
			inHDTid[inCount] = sqlite3_column_int(stmt,inStmtSeq);

            /* szHostName */
			//strcpy((char*)szHostName[inCount], (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			//vdDebug_LogPrintf("szHostName[%s] %d",szHostName[inCount], inCount);

			inCount++;
		}
	} while (result == SQLITE_ROW);

    
	inDBResult = sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	vdDebug_LogPrintf("inDBResult[%d]",inDBResult);
	vdDebug_LogPrintf("inCount[%d]",inCount);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inCount);
}

/*albert - start - 20161202 - Reprint of Detail Report for Last Settlement Report*/
int inDatabase_BackupDetailReport(int HDTid, int MITid)
{
	int result;
	char *sql = "Insert into TransDataBackup (TransDataid, HDTid, MITid, CDTid, IITid, byTransType, szExpireDate, byEntryMode, szTotalAmount, byOrgTransType, szAuthCode, szInvoiceNo, szPAN, inCardType) Select TransDataid, HDTid, MITid, CDTid, IITid, byTransType, szExpireDate, byEntryMode, szTotalAmount, byOrgTransType, szAuthCode, szInvoiceNo, szPAN, inCardType from TransData WHERE HDTid = ? and MITid = ?";	
	int inDBResult =0 ;

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
//	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srTransRec.szHostLabel, strlen((char*)srTransRec.szHostLabel), SQLITE_STATIC); 
//	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, srTransRec.szBatchNo, 3, SQLITE_STATIC);

//    result = sqlite3_bind_int(stmt, 1, inSeekCnt);
    sqlite3_bind_int(stmt, inStmtSeq +=1, HDTid);
	sqlite3_bind_int(stmt, inStmtSeq +=1, MITid);
	
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
/*albert - end - 20161202 - Reprint of Detail Report for Last Settlement Report*/

/*albert - start - 20161202 - Reprint of Detail Report for Last Settlement Report*/
int inDatabase_DeleteDetailReport(int HDTid, int MITid)
{
	int result;
	char *sql = "DELETE FROM TransDataBackup WHERE HDTid = ? and MITid = ?";	
	int inDBResult =0 ;
	
	//1205
	//remove(DB_INVOICE);
	//1205

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
//	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srTransRec.szHostLabel, strlen((char*)srTransRec.szHostLabel), SQLITE_STATIC); 
//	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, srTransRec.szBatchNo, 3, SQLITE_STATIC);

//    result = sqlite3_bind_int(stmt, 1, inSeekCnt);
    sqlite3_bind_int(stmt, inStmtSeq +=1, HDTid);
	sqlite3_bind_int(stmt, inStmtSeq +=1, MITid);
	
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
/*albert - end - 20161202 - Reprint of Detail Report for Last Settlement Report*/

/*albert - start - 20161202 - Reprint of Detail Report for Last Settlement Report*/
int inBatchByDetailReport(int inNumber, int inHostIndex, int inMerchIndex, int *inTranID)
{
	int result;
  	char *sql = "SELECT TransDataid FROM TransDataBackup WHERE HDTid = ? AND MITid = ?";
	int count = 0;

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
	sqlite3_bind_int(stmt, inStmtSeq +=1, inHostIndex);
	sqlite3_bind_int(stmt, inStmtSeq +=1, inMerchIndex);
	//sqlite3_bind_blob(stmt, inStmtSeq +=1, szBatchNo, 3, SQLITE_STATIC);

	inStmtSeq = 0;
	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */		

			 inTranID[count] = sqlite3_column_int(stmt,inStmtSeq);
             DebugAddINT("inTranID", inTranID[count]);
			 count++;

   		}
	} while (result == SQLITE_ROW);	   

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(d_OK);
}
/*albert - end - 20161202 - Reprint of Detail Report for Last Settlement Report*/

/*albert - start - 20161202 - Reprint of Detail Report for Last Settlement Report*/
int inDatabase_ReadDetailReport(TRANS_DATA_TABLE *transData, int inTransDataid)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT MITid, HDTid, CDTid, IITid, byTransType, szExpireDate, byEntryMode, szTotalAmount, byOrgTransType, szAuthCode, szInvoiceNo, szPAN, inCardType FROM TransDataBackup WHERE TransDataid = ?";

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

	inStmtSeq = 0;
	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			transData->MITid = sqlite3_column_int(stmt,inStmtSeq);
			transData->HDTid = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->CDTid = sqlite3_column_int(stmt,inStmtSeq +=1 );
            transData->IITid = sqlite3_column_int(stmt,inStmtSeq +=1 );
			transData->byTransType = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->szExpireDate, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			transData->byEntryMode = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->szTotalAmount, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);						
			transData->byOrgTransType = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(transData->szAuthCode, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);						
			memcpy(transData->szInvoiceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);						
			memcpy(transData->szPAN, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 20);	
			transData->inCardType = sqlite3_column_int(stmt,inStmtSeq +=1 );
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inResult);
}
/*albert - end - 20161202 - Reprint of Detail Report for Last Settlement Report*/

/*albert - start - 20161202 - Reprint of Detail Report for Last Settlement Report*/
int inBackupDetailReportNumRecord(void)
{
	int len;
	int result;
	//char *sql = "SELECT COUNT(*) FROM TransData WHERE HDTid = ? AND MITid = ? AND szBatchNo = ?";
	char *sql = "SELECT COUNT(*) FROM TransDataBackup WHERE HDTid = ? AND MITid = ?"; 
	int inCount = 0;
	
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
	//sqlite3_bind_blob(stmt, inStmtSeq +=1, strMMT[0].szBatchNo, 3, SQLITE_STATIC);

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
/*albert - end - 20161202 - Reprint of Detail Report for Last Settlement Report*/

int inEFTPubRead(int inSeekCnt)
{
	int len;
	CTOS_RTC SetRTC;     
	int result;
	int inResult = d_NO;
	char *sql = "SELECT EFTid, inEFTEnable FROM EFT WHERE HDTid = ?";
		
	/* open the database */
	result = sqlite3_open(DB_EFTSEC,&db);
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
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

            /*inHostIndex*/
			strEFTPub.EFTid = sqlite3_column_int(stmt, inStmtSeq );

			/*inHostIndex*/
			strEFTPub.HDTid = sqlite3_column_int(stmt, inStmtSeq);
			
			/* inEFTEnable*/
			strEFTPub.inEFTEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));			
		
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	//vdDebug_LogPrintf("HDTREAD %d", inResult);

    //memset(szGlobalAPName, 0x00, sizeof(szGlobalAPName));
	//strcpy(szGlobalAPName, strHDT.szAPName);

    return(inResult);
}

int inEFTPubSave(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE EFT SET inEFTEnable = ? WHERE  HDTid = ?";
	
 	/* open the database */
	result = sqlite3_open(DB_EFTSEC,&db);
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
        
    /* HDTid*/
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, strEFTPub.inEFTEnable);
        
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

int inHDTReadinSequence(int inSeekCnt)
{
	int len;
	CTOS_RTC SetRTC;     
	int result;
	int inResult = d_NO;
	char *sql = "SELECT inHostIndex, szHostLabel, szTPDU, szNII, fReversalEnable, fHostEnable, szTraceNo, fSignOn, ulLastTransSavedIndex, inCurrencyIdx, szAPName, inFailedREV, inDeleteREV, inNumAdv, fPrintFooterLogo, fPrintBankReceipt, fPrintCustReceipt, fPrintMercReceipt, fPrintVoidBankReceipt, fPrintVoidCustReceipt, fPrintVoidMercReceipt, fHDTTipAllow, fAutoDelReversal, inReversalTries, fBinVerEnable FROM HDT WHERE inSequence = ? AND fHostEnable = ?";
		
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

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);//fHostEnable = 1

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

            /*inHostIndex*/
			strHDT.inHostIndex = sqlite3_column_int(stmt, inStmtSeq );

            /* szHostLabel */
			strcpy((char*)strHDT.szHostLabel, (char *)sqlite3_column_text(stmt, inStmtSeq +=1));
            

			/*szTPDU*/
			memcpy(strHDT.szTPDU, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);

			/* szNII*/
			memcpy(strHDT.szNII, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);

			/* fReversalEnable*/
			strHDT.fReversalEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fHostEnable*/
			strHDT.fHostEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

	
			/* szTraceNo*/
			memcpy(strHDT.szTraceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);

			/* fSignOn */
			strHDT.fSignOn = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*ulLastTransSavedIndex*/
			strHDT.ulLastTransSavedIndex = sqlite3_column_double(stmt, inStmtSeq +=1 );

 			/* inCurrencyIdx */	
			strHDT.inCurrencyIdx = sqlite3_column_int(stmt, inStmtSeq +=1 );
            
			/* szAPName */			
			strcpy((char*)strHDT.szAPName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* inFailedREV */
			strHDT.inFailedREV = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* inDeleteREV */
			strHDT.inDeleteREV = sqlite3_column_int(stmt,inStmtSeq +=1);

            /* inNumAdv */
			strHDT.inNumAdv = sqlite3_column_int(stmt,inStmtSeq +=1);
			
			//sidumili: Issue#: 000135
			/*fPrintFooterLogo*/
			strHDT.fPrintFooterLogo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));


			/*BDO: Parameterized receipt printing - start*/
			/*fPrintBankReceipt*/
			strHDT.fPrintBankReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintCustReceipt*/
			strHDT.fPrintCustReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintMercReceipt*/
			strHDT.fPrintMercReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintVoidBankReceipt*/
			strHDT.fPrintVoidBankReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintVoidCustReceipt*/
			strHDT.fPrintVoidCustReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintVoidMercReceipt*/
			strHDT.fPrintVoidMercReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/*BDO: Parameterized receipt printing - end*/

			/* BDO: Tip Allow flag moved to HDT - start -- jzg */
			/*fHDTTipAllow*/
			strHDT.fHDTTipAllow = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO: Tip Allow flag moved to HDT - end -- jzg */

			/* BDO PHASE 2:[Flag for auto delete reversal file if host does not respond] -- sidumili */
			/*fAutoDelReversal*/
				strHDT.fAutoDelReversal = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO PHASE 2:[Flag for auto delete reversal file if host does not respond] -- sidumili */

			/* BDO PHASE 2:[Reversal Tries] -- sidumili */
				strHDT.inReversalTries = sqlite3_column_int(stmt,inStmtSeq +=1);
			/* BDO PHASE 2:[Reversal Tries] -- sidumili */

			/*fHDTTipAllow*/
			strHDT.fBinVerEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	//vdDebug_LogPrintf("HDTREAD %d", inResult);

    memset(szGlobalAPName, 0x00, sizeof(szGlobalAPName));
	strcpy(szGlobalAPName, strHDT.szAPName);

    return(inResult);
}

int inHDTDCCSave(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE HDT SET szDCCRateandLogTraceNo = ? WHERE  HDTid = ?";

	
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

	vdSetJournalModeOff();

	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}
	inStmtSeq = 0;

	/* szDCCRateandLogTraceNo*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strHDT_Temp.szDCCRateandLogTraceNo, 3, SQLITE_STATIC);

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

int inCSTReadData(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT inCurrencyIndex, szCurSymbol, szCurCode, szAmountFormat, inMinorUnit FROM CST WHERE CSTid = ?";

	memset(&strCST_Temp,0x00, sizeof(STRUCT_CST));
		
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
			inResult = d_OK;
			inStmtSeq = 0;

			/* inCurrencyIndex */
			strCST_Temp.inCurrencyIndex = sqlite3_column_int(stmt,inStmtSeq);
				
			/* szCurSymbol */			
			strcpy((char*)strCST_Temp.szCurSymbol, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szCurCode*/
			strcpy((char*)strCST_Temp.szCurCode, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			strcpy((char*)strCST_Temp.szAmountFormat, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));	

			/* inMinorUnit */
			strCST_Temp.inMinorUnit = sqlite3_column_int(stmt,inStmtSeq +=1);
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inResult);
}


int inDatabase_BatchDeleteTransType(BYTE *byTransType)
{
	int result;
	char *sql = "DELETE FROM TransData WHERE byTransType = ?";	
	int inDBResult = 0;
	
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

	sqlite3_bind_int(stmt, inStmtSeq +=1, byTransType);

	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

	inDBResult = sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	
	vdDebug_LogPrintf("Batch delete,sqlite3_exec[%d]",inDBResult);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(ST_SUCCESS);
}


int inDCCMMTUpdate(void)
{
	int result;

	inFXTRead(1);//Get FXTTID and FXTMID

	char *sql = "UPDATE MMT SET szTID = ?, szMID = ? WHERE fDCCMerchant = 1";
	
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
	inStmtSeq = 0;
        
    /* szTID*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strFXT.szFXTTID, strlen((char*)strFXT.szFXTTID), SQLITE_STATIC);
	/* szMID*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strFXT.szFXTMID, strlen((char*)strFXT.szFXTMID), SQLITE_STATIC);
        
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

int inDatabase_inSMACFooterSave(char *szBuff, TRANS_DATA_TABLE *transData)
{
	int result;

	char *sql = "INSERT INTO SMACFooter (szFooterMsg, ulTraceNum, szInvoiceNo, HDTid, MITid) VALUES (?, ?, ?, ?, ?)";
	//char *sql = "INSERT INTO SMACFooter (szFooterMsg) VALUES (?)";
		
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

	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)szBuff, strlen((char*)szBuff), SQLITE_STATIC); 

	result = sqlite3_bind_double(stmt, inStmtSeq +=1, transData->ulTraceNum);

	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szInvoiceNo, 4, SQLITE_STATIC);

	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->HDTid);

	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->MITid);
	
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

int inDatabase_SMACFooterDeleteAll(void)
{
	int result;
	char *sql = "DELETE FROM SMACFooter";	
	int inDBResult =0 ;

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


int inDatabase_SMACFooterDeletebyTraceNum(TRANS_DATA_TABLE *transData)
{
	int result;
	char *sql = "DELETE FROM SMACFooter WHERE szInvoiceNo = ?";	
	int inDBResult =0 ;

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

	//result = sqlite3_bind_double(stmt, inStmtSeq +=1, transData->ulTraceNum);
    result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szInvoiceNo, 4, SQLITE_STATIC);
	
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

int inDatabase_inSMACFooterRead(char *szBuff, TRANS_DATA_TABLE *transData)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT szFooterMsg FROM SMACFooter WHERE szInvoiceNo = ?";

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

		//result = sqlite3_bind_double(stmt, inStmtSeq +=1, transData->ulTraceNum);
		result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szInvoiceNo, 4, SQLITE_STATIC);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;
			strcpy((char*)szBuff, (char *)sqlite3_column_text(stmt,inStmtSeq));
			vdDebug_LogPrintf("szBuff[%s]",szBuff);
		}
	} while (result == SQLITE_ROW);
    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	   
    return(inResult);
}


int inDatabase_SMACFooterDelete(int HDTid, int MITid)
{
	int result;
	char *sql = "DELETE FROM SMACFooter WHERE HDTid = ? and MITid = ?";	
	int inDBResult =0 ;
	
	//1205
	//remove(DB_INVOICE);
	//1205

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
//	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srTransRec.szHostLabel, strlen((char*)srTransRec.szHostLabel), SQLITE_STATIC); 
//	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, srTransRec.szBatchNo, 3, SQLITE_STATIC);

//    result = sqlite3_bind_int(stmt, 1, inSeekCnt);
    sqlite3_bind_int(stmt, inStmtSeq +=1, HDTid);
	sqlite3_bind_int(stmt, inStmtSeq +=1, MITid);
	
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

int inDatabase_TerminalOpenDatabase(void)
{
	int result;
	
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

	return d_OK;
}

int inDatabase_TerminalCloseDatabase(void)
{
	int result;
	
	if (db != NULL) sqlite3_close(db);
	db = NULL;

	return d_OK;
}

int inDatabase_TerminalOpenDatabaseEx(const char *szDBName)
{
    int result;
    
    /* open the database */
    result = sqlite3_open(szDBName,&db);
    if (result != SQLITE_OK) {
        sqlite3_close(db);
        vdDebug_LogPrintf("DB Open %s Fail",szDBName);
        return 1;
    }
    vdDebug_LogPrintf("DB Open %s Successful",szDBName);
    return d_OK;
}

int inCDTReadEx(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql; 
	int inDBResult = 0;	

    char szTempSQL[512+1];

    memset(szTempSQL, 0, sizeof(szTempSQL));
	sql=&szTempSQL;
	
    if(strTCT.fATPBinRoute == TRUE)
	    strcpy(szTempSQL, "SELECT szPANLo, szPANHi, szCardLabel, inType, inMinPANDigit, inMaxPANDigit, inCVV_II, InFloorLimitAmount, fExpDtReqd,  fPinpadRequired, fManEntry, fCardPresent, fChkServiceCode, fluhnCheck, fCDTEnable, IITid, HDTid, fInstallmentEnable, inInstGroup, fDualCurrencyEnable, inDualCurrencyHost, fFleetCard, fPANCatchAll, fBalInqAllowed, fDCCEnable FROM CDT WHERE CDTid = ? AND fCDTATPEnable= ?");
    else
	    strcpy(szTempSQL, "SELECT szPANLo, szPANHi, szCardLabel, inType, inMinPANDigit, inMaxPANDigit, inCVV_II, InFloorLimitAmount, fExpDtReqd,  fPinpadRequired, fManEntry, fCardPresent, fChkServiceCode, fluhnCheck, fCDTEnable, IITid, HDTid, fInstallmentEnable, inInstGroup, fDualCurrencyEnable, inDualCurrencyHost, fFleetCard, fPANCatchAll, fBalInqAllowed, fDCCEnable FROM CDT WHERE CDTid = ? AND fCDTEnable= ?");
	
	if (fInstApp == TRUE){
		result = inInstallmentCDTReadEx(inSeekCnt);
		return result;
	}
	
#if 0
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
#endif

	inDBResult = sqlite3_exec( db, "begin", 0, 0, NULL );
	vdDebug_LogPrintf("inCDTRead,sqlite3_exec[%d]",inDBResult);

	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);//fCDTEnable = 1

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		vdDebug_LogPrintf("inCDTRead,result[%d]SQLITE_ROW[%d]",result,SQLITE_ROW);

		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			/*szPANLo*/
			strcpy(strCDT.szPANLo, sqlite3_column_text(stmt,inStmtSeq));

			/*szPANHi*/
			strcpy(strCDT.szPANHi, sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szCardLabel*/
			strcpy(strCDT.szCardLabel, sqlite3_column_text(stmt,inStmtSeq +=1));

			/*inType*/
			strCDT.inType = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*inMinPANDigit*/
			strCDT.inMinPANDigit = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*inMaxPANDigit*/
			strCDT.inMaxPANDigit = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*inCVV_II*/
			strCDT.inCVV_II = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*InFloorLimitAmount*/
			strCDT.InFloorLimitAmount = sqlite3_column_double(stmt,inStmtSeq +=1 );

			/*fExpDtReqd*/
			strCDT.fExpDtReqd = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPinpadRequired*/
			strCDT.fPinpadRequired = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fManEntry*/
			strCDT.fManEntry = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fCardPresent*/
			strCDT.fCardPresent = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fChkServiceCode*/
			strCDT.fChkServiceCode =fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fluhnCheck */
			strCDT.fluhnCheck = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fCDTEnable*/
			strCDT.fCDTEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));		

			/*IITid*/
			strCDT.IITid = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* HDTid*/
			strCDT.HDTid = sqlite3_column_int(stmt,inStmtSeq +=1);	

			//gcitra
			/*fInstallmentEnable*/
			strCDT.fInstallmentEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));		

			/*inInstGroup*/
			strCDT.inInstGroup = sqlite3_column_double(stmt,inStmtSeq +=1 );
			//gcitra

			//1026
			/*fDualCurrencyEnable*/
			strCDT.fDualCurrencyEnable = sqlite3_column_double(stmt,inStmtSeq +=1 );

			/* BDO: Added dual currency to CDT -- jzg */
			strCDT.inDualCurrencyHost = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* BDO CLG: Fleet card support - start -- jzg */
			/*fFleetCard*/
			strCDT.fFleetCard = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO CLG: Fleet card support - end -- jzg */

			/*fPANCatchAll - add to check if BIN is CATCH all - will be used for DEBIT Paypass*/
			strCDT.fPANCatchAll = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fBalInqAllowed*/
			strCDT.fBalInqAllowed = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fDCCEnable*/
			strCDT.fDCCEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	
	#if 0
	sqlite3_close(db);
    #endif
	
	return(inResult);
}

int inIITReadEx(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT inIssuerNumber, szIssuerAbbrev, szIssuerLabel, szPANFormat, szMaskBankCopy, szMaskMerchantCopy, szMaskCustomerCopy, szMaskExpireDate, szMaskDisplay, fMerchExpDate, fCustExpDate, fMerchPANFormat, inCheckHost, ulTransSeqCounter, fPolicyNumber, inPolicyNumMaxChar, szIssuerLogo, fLast4Digits, fQuasiCash, fGetPolicyNumber, fNSR, szNSRLimit, fNSRCustCopy, fBalInqAllowed, fMaskPanDisplay, szPrintOption, inIssuerID, fSMErrorRC86, fSMPrintFooterMsg, fEMVFallbackEnable,  szInstCVMLimit, szDCCCVMLimit FROM IIT WHERE IITid = ?";

#if 0	
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
#endif
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
		vdDebug_LogPrintf("IIT read result[%d]", result); 
		vdDebug_LogPrintf("SQLITE_ROW[%d]", SQLITE_ROW); 
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			/*inIssuerNumber*/
			strIIT.inIssuerNumber = sqlite3_column_int(stmt, inStmtSeq );
			vdDebug_LogPrintf("inIssuerNumber [%d]", strIIT.inIssuerNumber);
			/* szIssuerAbbrev */			
			strcpy((char*)strIIT.szIssuerAbbrev, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
				
			/* szIssuerLabel */			
			strcpy((char*)strIIT.szIssuerLabel, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szPANFormat*/
			strcpy((char*)strIIT.szPANFormat, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szMaskBankCopy*/
			strcpy((char*)strIIT.szMaskBankCopy, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 )); //BDO: Enable PAN Masking for each receipt -- jzg

			/*szMaskMerchantCopy*/
			strcpy((char*)strIIT.szMaskMerchantCopy, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szMaskCustomerCopy*/
			strcpy((char*)strIIT.szMaskCustomerCopy, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szMaskExpireDate*/
			strcpy((char*)strIIT.szMaskExpireDate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szMaskDisplay*/
			strcpy((char*)strIIT.szMaskDisplay, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fMerchExpDate */
			strIIT.fMerchExpDate = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fCustExpDate //5*/
			strIIT.fCustExpDate = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fMerchPANFormat*/
			strIIT.fMerchPANFormat = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));	

            /*inCheckHost*/
		    strIIT.inCheckHost = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*ulTransSeqCounter*/
			strIIT.ulTransSeqCounter = sqlite3_column_double(stmt,inStmtSeq +=1);

			//gcitra
			/*fPolicyNumber*/
			strIIT.fPolicyNumber = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/*inPolicyNumMaxChar*/
			strIIT.inPolicyNumMaxChar = sqlite3_column_int(stmt,inStmtSeq +=1 );
			//gcitra

			//Display Issuer logo: get issuer logo filename -- jzg
			strcpy((char*)strIIT.szIssuerLogo, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* BDO: Last 4 PAN digit checking - start -- jzg */
			/* fLast4Digits */
			strIIT.fLast4Digits = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO: Last 4 PAN digit checking - end -- jzg */

			/* BDO: Quasi should be parametrized per issuer - start -- jzg */
			/* fQuasiCash */
      strIIT.fQuasiCash = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO: Quasi should be parametrized per issuer - end -- jzg */


			/* BDO-00060: Policy number should be per issuer -- jzg */
			/* fGetPolicyNumber */
			strIIT.fGetPolicyNumber = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /*fNSR*/
            strIIT.fNSR = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            
            /* szNSRLimit*/
            strcpy((char*)strIIT.szNSRLimit, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* fNSRCustCopy*/
			strIIT.fNSRCustCopy = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* fBalInqAllowed*/
			strIIT.fBalInqAllowed = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/*fMaskPanDisplay*/

			strIIT.fMaskPanDisplay = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			strcpy((char*)strIIT.szPrintOption, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inIssuerID*/
		    strIIT.inIssuerID = sqlite3_column_int(stmt,inStmtSeq +=1);

			strIIT.fSMErrorRC86 = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fSMPrintFooterMsg*/
			strIIT.fSMPrintFooterMsg = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fEMVFallbackEnable*/
			strIIT.fEMVFallbackEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));


			//version16
			/* szInstCVMLimit*/
            strcpy((char*)strIIT.szInstCVMLimit, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strcpy((char*)strIIT.szDCCCVMLimit, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			//version16


        }	
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
#if 0
	sqlite3_close(db);
#endif
    return(inResult);
}

int inCSTReadHostIDEx(char *szCurCode)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT inCurrencyIndex, szCurSymbol, szCurCode, HDTid, szAmountFormat, inMinorUnit FROM CST WHERE szCurCode = ?";

	memset(&strCST,0x00,sizeof(strCST));

	#if 0
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	#endif
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}
	inStmtSeq = 0;
    sqlite3_bind_text(stmt, inStmtSeq +=1, szCurCode, strlen(szCurCode), SQLITE_STATIC);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;
		
			/* inCurrencyIndex */
			strCST.inCurrencyIndex = sqlite3_column_int(stmt,inStmtSeq);
				
			/* szCurSymbol */			
			strcpy((char*)strCST.szCurSymbol, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szCurCode*/
			strcpy((char*)strCST.szCurCode, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* inCurrencyIndex */
			strCST.HDTid = sqlite3_column_int(stmt,inStmtSeq +=1);

			strcpy((char*)strCST.szAmountFormat, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));	

			/* inMinorUnit */
			strCST.inMinorUnit = sqlite3_column_int(stmt,inStmtSeq +=1);
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	#if 0
	sqlite3_close(db);
    #endif
    return(inResult);
}

int inTCTReadEx(int inSeekCnt)
{
	int result;
	int len = 0;
	int inResult = -1;
	/* CTLS: Added szMaxCTLSAmount to check CTLS max txn amount during runtime -- jzg */
	/* aaronnino for BDOCLG ver 9.0 fix on issue #0061 changed fEnableInstMKE to fEnableManualKeyEntry 1 of 7*/
	/* aaronnino for BDOCLG ver 9.0 fix on issue #0066 added fDutyFreeMode 1 of  8*/
  /*aaronnino for BDOCLG ver 9.0 fix on issue#00078 added inBankCopy, inCustomerCopy, inMerchantCopy*/
	/*aaronnino for BDOCLG ver 9.0 fix on issue#00032 added szCurrentDate and fNextDayMustSettle*/	

	char *sql = "SELECT inMainLine, fHandsetPresent, fDemo, fCVVEnable, szSuperPW, szSystemPW, szEngineerPW, szFunKeyPW, szPMpassword, szBInRoutePW,  byRS232DebugPort, inPrinterHeatLevel, inWaitTime, byCtlsMode, fTipAllowFlag, fDebitFlag, szFallbackTime, inFallbackTimeGap, fManualEntryInv, szInvoiceNo, szPabx, szLastInvoiceNo, inMenuid, fECR, fDebugOpenedFlag,fShareComEnable, inReversalCount, inTipAdjustCount, fPrintISOMessage, fConfirmPAN, szMinInstAmt, fFirstInit, fTrickleFeedEMVUpload,	fDualCurrency, fPrintExpiryDate, inMaxAdjust, fMaskPanDisplay, DisplayPANFormat, szMaxTrxnAmt, fPrintTipReceipt, byTerminalType, szMaxCTLSAmount, lnTipPercent, byPinPadPort, fPrintWarningSound, fOfflinePinbypass, fEnableInstMKE, fEnableManualKeyEntry, fPrintSettleDetailReport, fDutyFreeMode, fScreenLocked, fMOTO, SMACRATE, DEACTDATE, SMACENABLE, SMZ, inBankCopy, inCustomerCopy, inMerchantCopy, fAutoDownloadEnable, usTMSGap, inTMSComMode, usTMSRemotePort, szTMSRemoteIP, szTMSRemotePhone, szTMSRemoteID, szTMSRemotePW, szLockPassword, szCurrentDate, fFleetGetLiters, fGetDescriptorCode, fSelectECRTrxn, szAppVersionHeader, fNextDayMustSettle, fEnableBinVerMKE, fDefaultCashAdvance, fNSRCustCopy, inSMACMode, ATPNII, ATPTPDU, szPrintOption, inIdleTimeOut, fPrintSummaryAll, fPrintDetailAll, fInclude_DEBIT_SETTLEALL, fInclude_INST_SETTLEALL, fInclude_CUP_SETTLEALL, szCTLSLimit, inModemReceivingTime, fCheckout, fATPBinRoute, byTerminalModel, byRS232ECRPort, fECRBaudRate, szMinTrxnAmt, fHotelSetup, szMaxInstAmt, fSMMode, fSMReceipt, fSMLogo, fEnableBalInqMKE, szSMReceiptLogo, szBDOReceiptLogo, fEnablePrintBalanceInq, fSingleComms, inECRTrxnMenu, fECRISOLogging, byERMMode, fDCC, szIdleLogo1, szIdleLogo2, szIdleLogo3, inSMCardRetryCount, fPrintReceiptPrompt, fISOLogging, inTxnLogLimit, fReprintSettleStatus, fPrintIssuerID, fDisplayPrintBitmap, fSignatureFlag, inERMMaximum, byERMInit, inPrintISOOption, fFormatDCCAmount, fChangeDateMustSettle, fDebitInsertEnable, inECRMode, fDisplayBattery, fTapAndGo, fPrintFooterLogo, szTMSNACProtocol, szTMSNACSourceAddr, szTMSNACDestAddr, szMobileWalletLabel, inBackupSettNumDays, fDisplayAPPROVED, fInsertAndGo, inDCCMode, inSetMobileWalletLabel FROM TCT WHERE TCTid = ?";
	//char *sql = "SELECT inMainLine, fHandsetPresent, fDemo, fCVVEnable, szSuperPW, szSystemPW, szEngineerPW, szFunKeyPW, szPMpassword, szBInRoutePW,  byRS232DebugPort, inPrinterHeatLevel, inWaitTime, byCtlsMode, fTipAllowFlag, fDebitFlag, szFallbackTime, inFallbackTimeGap, fManualEntryInv, szInvoiceNo, szPabx, szLastInvoiceNo, inMenuid, fECR, fDebugOpenedFlag,fShareComEnable, inReversalCount, inTipAdjustCount, fPrintISOMessage, fConfirmPAN, szMinInstAmt, fFirstInit, fTrickleFeedEMVUpload,	fDualCurrency, fPrintExpiryDate, inMaxAdjust, fMaskPanDisplay, DisplayPANFormat, szMaxTrxnAmt, fPrintTipReceipt, byTerminalType, szMaxCTLSAmount, lnTipPercent, byPinPadPort, fPrintWarningSound, fOfflinePinbypass, fEnableInstMKE, fEnableManualKeyEntry, fPrintSettleDetailReport, fDutyFreeMode, fScreenLocked, fMOTO, SMACRATE, DEACTDATE, SMACENABLE, SMZ, inBankCopy, inCustomerCopy, inMerchantCopy, fAutoDownloadEnable, usTMSGap, inTMSComMode, usTMSRemotePort, szTMSRemoteIP, szTMSRemotePhone, szTMSRemoteID, szTMSRemotePW, szLockPassword, szCurrentDate, fFleetGetLiters, fGetDescriptorCode, fSelectECRTrxn, szAppVersionHeader, fNextDayMustSettle, fEnableBinVerMKE, fDefaultCashAdvance, fNSRCustCopy, inSMACMode, ATPNII, ATPTPDU, szPrintOption, inIdleTimeOut, fPrintSummaryAll, fPrintDetailAll, fInclude_DEBIT_SETTLEALL, fInclude_INST_SETTLEALL, fInclude_CUP_SETTLEALL, szCTLSLimit, inModemReceivingTime, fCheckout, fATPBinRoute, byTerminalModel, byRS232ECRPort, fECRBaudRate, szMinTrxnAmt, fHotelSetup, szMaxInstAmt, fSMMode, fSMReceipt, fSMLogo, fEnableBalInqMKE, szSMReceiptLogo, szBDOReceiptLogo, fEnablePrintBalanceInq, fSingleComms, inECRTrxnMenu, fECRISOLogging, byERMMode, fDCC, szIdleLogo1, szIdleLogo2, szIdleLogo3, inSMCardRetryCount, fPrintReceiptPrompt, fISOLogging, inTxnLogLimit, fReprintSettleStatus, fPrintIssuerID, fDisplayPrintBitmap, fSignatureFlag, inERMMaximum, byERMInit, inPrintISOOption, fFormatDCCAmount FROM TCT WHERE TCTid = ?";
	//char *sql = "SELECT inMainLine, fHandsetPresent, fDemo, fCVVEnable, szSuperPW, szSystemPW, szEngineerPW, szFunKeyPW, szPMpassword, byRS232DebugPort, inPrinterHeatLevel, inWaitTime, byCtlsMode, fTipAllowFlag, fDebitFlag, szFallbackTime, inFallbackTimeGap, fManualEntryInv, szInvoiceNo, szPabx, szLastInvoiceNo, inMenuid, fECR, fDebugOpenedFlag,fShareComEnable, inReversalCount, inTipAdjustCount, fPrintISOMessage, fConfirmPAN, szMinInstAmt, fFirstInit, fTrickleFeedEMVUpload,	fDualCurrency, fPrintExpiryDate, inMaxAdjust, fMaskPanDisplay, DisplayPANFormat, szMaxTrxnAmt, fPrintTipReceipt, byTerminalType, szMaxCTLSAmount, lnTipPercent, byPinPadPort, fPrintWarningSound, fOfflinePinbypass, fEnableManualKeyEntry, fPrintSettleDetailReport, inOnlineSettleTries, fDutyFreeMode, inManualSettleTrigger, fScreenLocked, fMOTO, SMACRATE, DEACTDATE, SMACENABLE, SMZ, inBankCopy, inCustomerCopy, inMerchantCopy,  usTMSGap, inTMSComMode, usTMSRemotePort, szTMSRemoteIP, szTMSRemotePhone, szTMSRemoteID, szTMSRemotePW, szLockPassword, szCurrentDate FROM TCT WHERE TCTid = ?";

    #if 0
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
    #endif
	
	vdSetJournalModeOff();

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
			inResult = d_OK;
			inStmtSeq = 0;
			
    
            /* inMainLine */
			strTCT.inMainLine = sqlite3_column_int(stmt,inStmtSeq  );

            /* fHandsetPresent */
			strTCT.fHandsetPresent = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
    
             /* fDemo //5*/
			strTCT.fDemo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            
            /* fCVVEnable */
			strTCT.fCVVEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
                        
            /* szSuperPW*/
			strcpy((char*)strTCT.szSuperPW, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* szSystemPW */
			strcpy((char*)strTCT.szSystemPW, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* szEngineerPW */
			strcpy((char*)strTCT.szEngineerPW, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* szFunKeyPW */
			strcpy((char*)strTCT.szFunKeyPW, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* szPMpassword */
			strcpy((char*)strTCT.szPMpassword, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /*szBInRoutePW*/
			strcpy((char*)strTCT.szBInRoutePW, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			   
            /*byRS232DebugPort*/
			strTCT.byRS232DebugPort = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/*inPrinterHeatLevel*/
			strTCT.inPrinterHeatLevel = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/*inWaitTime*/
			strTCT.inWaitTime = sqlite3_column_int(stmt,inStmtSeq +=1 );
			/*byCtlsMode*/
			strTCT.byCtlsMode = sqlite3_column_int(stmt,inStmtSeq +=1 );
            
 			/* fTipAllowFlag */
			strTCT.fTipAllowFlag = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            
            /* fDebitFlag */
            strTCT.fDebitFlag = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* szFallbackTime*/
			strcpy((char*)strTCT.szFallbackTime, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

             /* inFallbackTimeGap */
			strTCT.inFallbackTimeGap = sqlite3_column_int(stmt,inStmtSeq +=1 );

             /* fManualEntryInv */
            strTCT.fManualEntryInv = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			 
			/* szInvoiceNo*/
			memcpy(strTCT.szInvoiceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);

            /* szPabx */
			strcpy((char*)strTCT.szPabx, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			DelCharInStr(strTCT.szPabx,',',2);
			len = strlen((char*)strTCT.szPabx);
			if(len > 0)
				strTCT.szPabx[len]=',';

			/* szLastInvoiceNo */
			memcpy(strTCT.szLastInvoiceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);

			/* BDO CLG: Revised menu functions - start -- jzg */
			/* inMenuid */
			strTCT.inMenuid = sqlite3_column_int(stmt,inStmtSeq +=1);
			/* BDO CLG: Revised menu functions - end -- jzg */
			
			/* fECR */
			strTCT.fECR = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* fDebugOpenedFlag */
            strTCT.fDebugOpenedFlag = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* fShareComEnable */
            strTCT.fShareComEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* inReversalCount */
			strTCT.inReversalCount = sqlite3_column_int(stmt,inStmtSeq +=1 );

            /* inTipAdjustCount */
			strTCT.inTipAdjustCount = sqlite3_column_int(stmt,inStmtSeq +=1 );

		//gcitra
		/*fPrintISOMessage*/
		strTCT.fPrintISOMessage = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
		/*fConfirmPAN*/
		strTCT.fConfirmPAN = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		//gcitra

			/* szMinInstAmt */
			memcpy(strTCT.szMinInstAmt, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 6);

		/* fFirstInit */
		strTCT.fFirstInit = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fTrickleFeedEMVUpload*/	
		strTCT.fTrickleFeedEMVUpload = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fDualCurrency*/
		strTCT.fDualCurrency = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fPrintExpiryDate*/
		strTCT.fPrintExpiryDate = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*inMaxAdjust*/	
		strTCT.inMaxAdjust = sqlite3_column_int(stmt,inStmtSeq +=1 );

		/*fMaskPanDisplay*/	
		strTCT.fMaskPanDisplay = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*DisplayPANFormat*/
		strcpy((char*)strTCT.DisplayPANFormat, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

        //sidumili: Issue#:000076 [OUT OF RANGE]
        /* szMaxTrxnAmt */
//        memcpy(strTCT.szMaxTrxnAmt, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 12);
				strcpy((char*)strTCT.szMaxTrxnAmt, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		//vdDebug_LogPrintf("JEFF::TCT MAX TXN AMT: [%s]", strTCT.szMaxTrxnAmt);

		/*sidumili: Fix on Issue#: 000181*/
		/*fPrintTipReceipt*/
		strTCT.fPrintTipReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fInstTCUpload */
        //Issue# 000166 - start -- jzg
        /* fInstTCUpload */
        //strTCT.fInstTCUpload = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
        //Issue# 000166 - end -- jzg

		/*byTerminalType*/
		strTCT.byTerminalType = sqlite3_column_int(stmt,inStmtSeq +=1 );

		/* CTLS: Added szMaxCTLSAmount to check CTLS max txn amount during runtime -- jzg */
		strcpy((char*)strTCT.szMaxCTLSAmount, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*lnTipPercent*/
		strTCT.lnTipPercent = sqlite3_column_int(stmt, inStmtSeq +=1 );

		strTCT.byPinPadPort = sqlite3_column_int(stmt, inStmtSeq +=1 );

		/*BDO PHASE 2: [Warning sound for printing flag] -- sidumili*/
		/*fPrintWarningSound*/
		strTCT.fPrintWarningSound = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/* fOfflinePinbypass */
		strTCT.fOfflinePinbypass = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));


		 //BDO: Parameterized manual key entry for installment --jzg
		strTCT.fEnableInstMKE = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		 /*fEnableManualKeyEntry*/
		strTCT.fEnableManualKeyEntry = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 )); //aaronnino for BDOCLG ver 9.0 fix on issue #0061 Manual Entry should not be allowed for BIN Check transactions 2 of 7

		/* BDO: Include detailed report to settlement receipt - start -- jzg */
		/* fPrintSettleDetailReport */
		strTCT.fPrintSettleDetailReport = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		/* BDO: Include detailed report to settlement receipt - end -- jzg */

		/*fDutyFreeMode*/
		strTCT.fDutyFreeMode = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 )); //aaronnino for BDOCLG ver 9.0 fix on issue #0066 "APPR.CODE" single width printed on transaction receipt 2 of 8
		
		/* BDO CLG: Terminal lock screen - start -- jzg */
		/* fScreenLocked */
		strTCT.fScreenLocked = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		/* BDO CLG: Terminal lock screen - end -- jzg */

		/* BDO CLG: MOTO setup - start -- jzg */
		/* fMOTO */
		strTCT.fMOTO = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		/* BDO CLG: MOTO setup - end -- jzg */
//smac
		strTCT.SMACRATE = sqlite3_column_double(stmt,inStmtSeq +=1);
		memcpy(strTCT.DEACTDATE, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 20);
		strTCT.SMACENABLE = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		strTCT.SMZ = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
//smac
   //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable start 1 of 21
   /*inBankCopy*/
   strTCT.inBankCopy = sqlite3_column_int(stmt,inStmtSeq +=1 );
   
   /*inCustomerCopy*/
   strTCT.inCustomerCopy = sqlite3_column_int(stmt,inStmtSeq +=1 );
   
   /*inMerchantCopy*/
   strTCT.inMerchantCopy = sqlite3_column_int(stmt,inStmtSeq +=1 );
   //aaronnino for BDOCLG ver 9.0 fix on issue #00078 Printing of copies should be configurable end 1 of 21

       //add param for auto DL enable/disable
       //fAutoDownloadEnable
   		strTCT.fAutoDownloadEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
   
	   //aaronnino for remote download setup 2 of 12 start
	   /* usTMSGap */
	   strTCT.usTMSGap = sqlite3_column_int(stmt,inStmtSeq +=1 );
	   /* inTMSComMode */
	   strTCT.inTMSComMode = sqlite3_column_int(stmt,inStmtSeq +=1 );
   
	   /* usTMSRemotePort */
	   strTCT.usTMSRemotePort = sqlite3_column_int(stmt,inStmtSeq +=1 );
   
	   /* szTMSRemoteIP */
	   //memcpy(strTCT.szTMSRemoteIP, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 30);
   		strcpy((char*)strTCT.szTMSRemoteIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	   
	   /* szTMSRemotePhone */
	   //memcpy(strTCT.szTMSRemotePhone, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 30);
	   strcpy((char*)strTCT.szTMSRemotePhone, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
   
	   /* szTMSRemoteID */
	   //memcpy(strTCT.szTMSRemoteID, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 32);
	   strcpy((char*)strTCT.szTMSRemoteID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
   
	   /* szTMSRemotePW */
	   //memcpy(strTCT.szTMSRemotePW, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 32);
	   strcpy((char*)strTCT.szTMSRemotePW, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	   //aaronnino for remote download setup 2 of 12 end

		/* szLockPassword */
		strcpy((char*)strTCT.szLockPassword, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 )); /* BDO: Terminal screen lock -- jzg */

		 /* szCurrentDate */	 //aaronnino for BDOCLG ver 9.0 fix on issue#00032 "must settle" response on transactions per host after 1 day if batch is not empty 1 of 9 		
		strcpy((char*)strTCT.szCurrentDate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 )); 


		/*fFleetGetLiters*/
		strTCT.fFleetGetLiters = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
		/*fGetDescriptorCode*/
		strTCT.fGetDescriptorCode = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fSelectECRTrxn*/
		strTCT.fSelectECRTrxn = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		//ad header for Version - issue 00420
		strcpy((char*)strTCT.szAppVersionHeader, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

		/*fNextDayMustSettle*/ //aaronnino for BDOCLG ver 9.0 fix on issue#00032 "must settle" response on transactions per host after 1 day if batch is not empty 2 of 9
		strTCT.fNextDayMustSettle = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

        /*fEnableBinVerMKE*/
		strTCT.fEnableBinVerMKE = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fDefaultCashAdvance*/
		strTCT.fDefaultCashAdvance = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	

        /*fNSRCustCopy*/
        strTCT.fNSRCustCopy = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

	
		/* inSMACMode */
		strTCT.inSMACMode = sqlite3_column_int(stmt,inStmtSeq +=1 );

		
		/* ATPNII*/
		memcpy(strTCT.ATPNII, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);

		/*ATPTPDU*/
		memcpy(strTCT.ATPTPDU, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);

        //szPrintOption
        strcpy((char*)strTCT.szPrintOption, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

		/*inIdleTimeOut*/
		strTCT.inIdleTimeOut = sqlite3_column_int(stmt,inStmtSeq +=1 );
		
		strTCT.fPrintSummaryAll = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		strTCT.fPrintDetailAll = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
		
		strTCT.fInclude_DEBIT_SETTLEALL = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		strTCT.fInclude_INST_SETTLEALL = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		strTCT.fInclude_CUP_SETTLEALL = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
		/*szCTLSLimit */
		strcpy((char*)strTCT.szCTLSLimit, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
		/* inModemReceivingTime*/
		strTCT.inModemReceivingTime = sqlite3_column_int(stmt, inStmtSeq +=1 );

        strTCT.fCheckout = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fATPBinRoute*/
		strTCT.fATPBinRoute = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*byTerminalModel*/
		strTCT.byTerminalModel = sqlite3_column_int(stmt,inStmtSeq +=1 );

		/*byRS232ECRPort*/
		strTCT.byRS232ECRPort = sqlite3_column_int(stmt,inStmtSeq +=1 );
		
		/*fECRBaudRate*/
		strTCT.fECRBaudRate = sqlite3_column_int(stmt,inStmtSeq +=1 );
		
    	/*szMinTrxnAmt*/
		strcpy((char*)strTCT.szMinTrxnAmt, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fHotelSetup*/
		strTCT.fHotelSetup = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szMaxInstAmt*/
		strcpy((char*)strTCT.szMaxInstAmt, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

        strTCT.fSMMode = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
        strTCT.fSMReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
        strTCT.fSMLogo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 )); 

        strTCT.fEnableBalInqMKE = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 )); 

		strcpy((char*)strTCT.szSMReceiptLogo, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		strcpy((char*)strTCT.szBDOReceiptLogo, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		strTCT.fEnablePrintBalanceInq = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fSingleComms*/
        strTCT.fSingleComms = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*inECRTrxnMenu*/
		strTCT.inECRTrxnMenu = sqlite3_column_int(stmt,inStmtSeq +=1 );

		/*fECRISOLogging*/
		strTCT.fECRISOLogging = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*byERMMode*/
			strTCT.byERMMode = sqlite3_column_int(stmt,inStmtSeq +=1 );

        /*fDCC*/
        strTCT.fDCC = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*szIdleLogo1*/
		strcpy((char*)strTCT.szIdleLogo1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*szIdleLogo2*/
		strcpy((char*)strTCT.szIdleLogo2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*szIdleLogo3*/
		strcpy((char*)strTCT.szIdleLogo3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*inSMCardRetryCount*/
		strTCT.inSMCardRetryCount = sqlite3_column_int(stmt,inStmtSeq +=1 );

		/*fPrintReceiptPrompt*/
		strTCT.fPrintReceiptPrompt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

   		/* fISOLogging */
   		strTCT.fISOLogging = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
   
   		/* inTxnLogLimit */
   		strTCT.inTxnLogLimit = sqlite3_column_int(stmt,inStmtSeq +=1 );	

        strTCT.fReprintSettleStatus = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		strTCT.fPrintIssuerID = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fPrintDisplayBitmap*/
		strTCT.fDisplayPrintBitmap = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

        /*fSignatureFlag*/
		strTCT.fSignatureFlag = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/* inERMMaximum */
		strTCT.inERMMaximum = sqlite3_column_int(stmt,inStmtSeq +=1 );
		/* byERMInit */
		strTCT.byERMInit = sqlite3_column_int(stmt,inStmtSeq +=1 );		

		strTCT.inPrintISOOption = sqlite3_column_int(stmt,inStmtSeq +=1 );	

		/*fFormatDCCAmount*/
		strTCT.fFormatDCCAmount = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fFormatDCCAmount*/
		strTCT.fChangeDateMustSettle = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fDebitInsertEnable*/
		strTCT.fDebitInsertEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*inECRMode*/
		strTCT.inECRMode = sqlite3_column_int(stmt,inStmtSeq +=1 );

		/*fDisplayBattery */
		strTCT.fDisplayBattery = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fTapAndGo*/
		strTCT.fTapAndGo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
		/*fPrintFooterLogo*/
		strTCT.fPrintFooterLogo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*szTMSNACProtocol*/
		strcpy((char*)strTCT.szTMSNACProtocol, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*szTMSNACSourceAddr*/
		strcpy((char*)strTCT.szTMSNACSourceAddr, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*szTMSNACDestAddr*/
		strcpy((char*)strTCT.szTMSNACDestAddr, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*szMobileWalletLabel*/		
		strcpy((char*)strTCT.szMobileWalletLabel, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*inBackupSettNumDays*/
		strTCT.inBackupSettNumDays = sqlite3_column_int(stmt,inStmtSeq +=1 );

		/*fDisplayAPPROVED*/
		strTCT.fDisplayAPPROVED = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*fInsertAndGo*/
		strTCT.fInsertAndGo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		/*inDCCMode*/
		strTCT.inDCCMode = sqlite3_column_int(stmt,inStmtSeq +=1 );

		/*inSetMobileWalletLabel*/	
		strTCT.inSetMobileWalletLabel = sqlite3_column_int(stmt,inStmtSeq +=1 );
				
        }
	} while (result == SQLITE_ROW);	

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	#if 0
	sqlite3_close(db);
    #endif
    return(inResult);
}

int inPCTReadEx(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT szRctHdr1, szRctHdr2, szRctHdr3, szRctHdr4, szRctHdr5, szRctFoot1, szRctFoot2, szRctFoot3, inPrinterType, inPrintOption, inCustCopyOption, fPrintDisclaimer, fEnablePrinter FROM PCT WHERE PCTid = ?";

    #if 0
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	#endif
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
			inResult = d_OK;
			inStmtSeq = 0;

			/* szRctHdr1 */			
			strcpy((char*)strPCT.szRctHdr1, (char *)sqlite3_column_text(stmt,inStmtSeq ));
			
			/* szRctHdr2 */			
			strcpy((char*)strPCT.szRctHdr2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szRctHdr3*/
			strcpy((char*)strPCT.szRctHdr3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctHdr4 */			
			strcpy((char*)strPCT.szRctHdr4, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szRctHdr5*/
			strcpy((char*)strPCT.szRctHdr5, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctFoot1 */			
			strcpy((char*)strPCT.szRctFoot1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szRctFoot2*/
			strcpy((char*)strPCT.szRctFoot2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctFoot3 */			
			strcpy((char*)strPCT.szRctFoot3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inPrinterType*/
			strPCT.inPrinterType = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*inPrintOption*/
			strPCT.inPrintOption = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*inCustCopyOption*/
			strPCT.inCustCopyOption = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/* fPrintDisclaimer*/
			strPCT.fPrintDisclaimer = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fEnablePrinter*/
			strPCT.fEnablePrinter = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	#if 0
	sqlite3_close(db);
    #endif
    return(inResult);
}

int inTCPReadEx(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT szTerminalIP, szGetWay, szSubNetMask, szHostDNS1, szHostDNS2, fDHCPEnable, szAPN, szUserName, szPassword, szWifiSSID, szWifiPassword, szWifiProtocal, szWifiPairwise, szWifiGroup, inSIMSlot FROM TCP WHERE TCPid = ?";

	#if 0	
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	#endif
	
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
			inResult = d_OK;
			inStmtSeq = 0;

			/*szTerminalIP*/
			strcpy((char*)strTCP.szTerminalIP, (char *)sqlite3_column_text(stmt,inStmtSeq));
            				
			/* szGetWay */			
			strcpy((char*)strTCP.szGetWay, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szSubNetMask*/
			strcpy((char*)strTCP.szSubNetMask, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szHostDNS1*/
			strcpy((char*)strTCP.szHostDNS1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szHostDNS2*/
			strcpy((char*)strTCP.szHostDNS2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /* fDHCPEnable */
			strTCP.fDHCPEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szAPN*/
			strcpy((char*)strTCP.szAPN, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /*szUserName*/
			strcpy((char*)strTCP.szUserName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /*szPassword*/
			strcpy((char*)strTCP.szPassword, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

						 /*szWifiSSID*/
			strcpy((char*)strTCP.szWifiSSID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

						  /*szWifiPassword*/
			strcpy((char*)strTCP.szWifiPassword, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

							 /*szWifiProtocal*/
			strcpy((char*)strTCP.szWifiProtocal, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

							  /*szWifiPairwise*/
			strcpy((char*)strTCP.szWifiPairwise, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

								/*szWifiGroup*/
			strcpy((char*)strTCP.szWifiGroup, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

								/* inSIMSlot */
		  strTCP.inSIMSlot = sqlite3_column_int(stmt,inStmtSeq +=1 );

		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	#if 0
	sqlite3_close(db);
    #endif
    return(inResult);
}

int inMultiAP_Database_EMVTransferDataInitEx(void)
{
    int inSeekCnt = 1;
    USHORT usDataLen = 0;
    BYTE bEMVData[4];
    int result;
    char *sql = "UPDATE ETD SET inEMVDataLen = ? ,szEMVTransferData = ? WHERE  ETDid = ?";          

    #if 0
    /* open the database */
    result = sqlite3_open(DB_EMV,&db);
    if (result != SQLITE_OK) {
        sqlite3_close(db);
        return 1;
    }
    #endif
	
	sqlite3_exec( db, "begin", 0, 0, NULL );
    /* prepare the sql, leave stmt ready for loop */
    result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (result != SQLITE_OK) {
        sqlite3_close(db);
        return 2;
    }

    memset(bEMVData, 0x00, sizeof(bEMVData));
    inStmtSeq = 0;

    /* inEMVDataLen */
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, usDataLen);
    
    /* szEMVTransferData */    
    result = sqlite3_bind_blob(stmt, inStmtSeq +=1, bEMVData, 1, SQLITE_STATIC);


    result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
    result = sqlite3_step(stmt);
    if( result != SQLITE_DONE ){
        sqlite3_close(db);
        return 3;
    }
    
    sqlite3_exec(db,"commit;",NULL,NULL,NULL);

    sqlite3_finalize(stmt);
	#if 0
    sqlite3_close(db);
    #endif
    return(d_OK);
}



int inMultiAP_Database_EMVTransferDataWriteEx(USHORT usDataLen, BYTE *bEMVData)
{
    int inSeekCnt = 1;
    int result;
    char *sql = "UPDATE ETD SET inEMVDataLen = ? ,szEMVTransferData = ? WHERE  ETDid = ?";          

    #if 0
    /* open the database */
    result = sqlite3_open(DB_EMV,&db);
    if (result != SQLITE_OK) {
        sqlite3_close(db);
        return 1;
    }
    #endif
	
	sqlite3_exec( db, "begin", 0, 0, NULL );
    /* prepare the sql, leave stmt ready for loop */
    result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (result != SQLITE_OK) {
        sqlite3_close(db);
        return 2;
    }

    inStmtSeq = 0;

    /* inEMVDataLen */
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, usDataLen);
    
    /* szEMVTransferData */    
    result = sqlite3_bind_blob(stmt, inStmtSeq +=1, bEMVData, usDataLen, SQLITE_STATIC);


    result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
    result = sqlite3_step(stmt);
    if( result != SQLITE_DONE ){
        sqlite3_close(db);
        return 3;
    }
    
    sqlite3_exec(db,"commit;",NULL,NULL,NULL);

    sqlite3_finalize(stmt);
	#if 0
    sqlite3_close(db);
    #endif
    return(d_OK);
}


int inMultiAP_Database_EMVTransferDataReadEx(USHORT *usDataLen, BYTE *bEMVData)
{
    int inSeekCnt = 1;
    int result;
    int inResult = d_NO;
    char *sql = "SELECT inEMVDataLen, szEMVTransferData FROM ETD WHERE ETDid = ?";

	#if 0	
    /* open the database */
    result = sqlite3_open(DB_EMV,&db);
    if (result != SQLITE_OK) {
        sqlite3_close(db);
        return 1;
    }
    #endif
	
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
            inResult = d_OK;
            inStmtSeq = 0;

            /*inEMVDataLen*/
            *usDataLen = sqlite3_column_int(stmt,inStmtSeq  );
            
            /*szEMVTransferData*/
            memcpy(bEMVData, sqlite3_column_blob(stmt,inStmtSeq +=1 ), *usDataLen);

        }
    } while (result == SQLITE_ROW);

    
    sqlite3_exec(db,"commit;",NULL,NULL,NULL);

    sqlite3_finalize(stmt);
	#if 0
    sqlite3_close(db);
    #endif
    return(inResult);
}

int inIITSaveEx(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE IIT SET szIssuerAbbrev = ?, szIssuerLabel = ?, szPANFormat = ?, szMaskBankCopy = ?, szMaskMerchantCopy = ?, szMaskCustomerCopy = ?, szMaskExpireDate = ?, szMaskDisplay = ?, fMerchExpDate = ?, fCustExpDate = ?, fMerchPANFormat = ?, ulTransSeqCounter = ?, fPolicyNumber = ?, inPolicyNumMaxChar = ?, szIssuerLogo = ?, fSMPrintFooterMsg = ?, fEMVFallbackEnable = ? WHERE  IITid = ?";

	#if 0
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
    #endif
	
	vdSetJournalModeOff();

	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
	/* szIssuerAbbrev */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strIIT.szIssuerAbbrev, strlen((char*)strIIT.szIssuerAbbrev), SQLITE_STATIC);
	/* szIssuerLabel */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strIIT.szIssuerLabel, strlen((char*)strIIT.szIssuerLabel), SQLITE_STATIC);
	/* szPANFormat*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strIIT.szPANFormat, strlen((char*)strIIT.szPANFormat), SQLITE_STATIC);
	/* szMaskBankCopy*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strIIT.szMaskBankCopy, strlen((char*)strIIT.szMaskBankCopy), SQLITE_STATIC); //BDO: Enable PAN Masking for each receipt -- jzg
	/* szMaskMerchantCopy*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strIIT.szMaskMerchantCopy, strlen((char*)strIIT.szMaskMerchantCopy), SQLITE_STATIC);
	/* szMaskCustomerCopy*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strIIT.szMaskCustomerCopy, strlen((char*)strIIT.szMaskCustomerCopy), SQLITE_STATIC);
	/* szMaskExpireDate*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strIIT.szMaskExpireDate, strlen((char*)strIIT.szMaskExpireDate), SQLITE_STATIC);
	/* szMaskDisplay*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strIIT.szMaskDisplay, strlen((char*)strIIT.szMaskDisplay), SQLITE_STATIC);
	/*fMerchExpDate*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strIIT.fMerchExpDate);
	/* fCustExpDate */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strIIT.fCustExpDate);
	/* fMerchPANFormat */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strIIT.fMerchPANFormat);
	/* ulTransSeqCounter */
    if(strIIT.ulTransSeqCounter >= 0xFFFFFE)
       strIIT.ulTransSeqCounter = 1;
	result = sqlite3_bind_double(stmt, inStmtSeq +=1, strIIT.ulTransSeqCounter);
    vdDebug_LogPrintf(" strIIT.ulTransSeqCounter[%d] result[%d]",strIIT.ulTransSeqCounter, result);

	//gcitra
	/*fPolicyNumber*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strIIT.fPolicyNumber);

	/*inPolicyNumMaxChar*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strIIT.inPolicyNumMaxChar);
	//gcitra

	//Display Issuer logo: save issuer logo filename -- jzg
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strIIT.szIssuerLogo, strlen((char*)strIIT.szIssuerLogo), SQLITE_STATIC);

	/*fSMPrintFooterMsg*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strIIT.fSMPrintFooterMsg);

	/*fEMVFallbackEnable*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strIIT.fEMVFallbackEnable);

	result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);

	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	#if 0
	sqlite3_close(db);
    #endif
    return(d_OK);
}

int inMultiAP_Database_BatchDeleteEx(void)
{
	int result;
	char *sql = "DELETE FROM TransData";	
	int inDBResult =0 ;
	
	//1205
	remove(DB_MULTIAP_JOURNAL);
	//1205
    #if 0
	/* open the database */
	result = sqlite3_open(DB_MULTIAP,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	#endif
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

//	inStmtSeq = 0;
//	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srTransRec.szHostLabel, strlen((char*)srTransRec.szHostLabel), SQLITE_STATIC); 
//	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, srTransRec.szBatchNo, 3, SQLITE_STATIC);

	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

    
	inDBResult = sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	
	vdDebug_LogPrintf("Batch delet,sqlite3_exec[%d]",inDBResult);

	sqlite3_finalize(stmt);
	#if 0
	sqlite3_close(db);
    #endif
	return(ST_SUCCESS);
}

int inMultiAP_Database_BatchInsertEx(TRANS_DATA_TABLE *transData)
{
	int result;	
	//char *sql1 = "SELECT MAX(TransDataid) FROM TransData";
 	char *sql = "INSERT INTO TransData (TransDataid, HDTid, MITid, CDTid, IITid, szHostLabel, szBatchNo, byTransType, byPanLen, szExpireDate, byEntryMode, szTotalAmount, szBaseAmount, szTipAmount, byOrgTransType, szMacBlock, szYear, szDate, szTime, szOrgDate, szOrgTime, szAuthCode, szRRN, szInvoiceNo, szOrgInvoiceNo, byPrintType, byVoided, byAdjusted, byUploaded, byTCuploaded, szCardholderName, szzAMEX4DBC, szStoreID, szRespCode, szServiceCode, byContinueTrans, byOffline, byReversal, byEMVFallBack, shTransResult, szTpdu, szIsoField03, szMassageType, szPAN, szCardLable, usTrack1Len, usTrack2Len, usTrack3Len, szTrack1Data, szTrack2Data, szTrack3Data, usChipDataLen, baChipData, usAdditionalDataLen, baAdditionalData, bWaveSID,usWaveSTransResult,bWaveSCVMAnalysis, ulTraceNum, ulOrgTraceNum, usTerminalCommunicationMode, ulSavedIndex, byPINEntryCapability, byPackType, szOrgAmount, szCVV2, inCardType, byTCFailUpCnt, byCardTypeNum, byEMVTransStatus, T5A_len, T5A, T5F2A, T5F30, T5F34, T5F34_len, T82, T84_len, T84, T8A, T91, T91Len, T95, T9A, T9C, T9F02, T9F03, T9F09, T9F10_len, T9F10, T9F1A, T9F26, T9F27, T9F33, T9F34, T9F35, T9F36_len, T9F36, T9F37, T9F41, T9F53, ISR, ISRLen, T9B, T5F24, T71Len, T71, T72Len, T72, T9F06, T9F1E, T9F28, T9F29, szChipLabel, szTID, szMID, fBINVer, szBINVerSTAN, szECRPANFormatted, szECRRespText, szECRMerchantName, szECRRespCode, PRMid, szPolicyNumber, fECRTrxFlg, T9F6E, T9F6E_len,szTerms) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    #if 0
	/* open the database */
	result = sqlite3_open(DB_MULTIAP,&db);
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
    #endif
	
    transData->ulSavedIndex=1;

	#if 0   
	/* open the database */
	result = sqlite3_open(DB_MULTIAP,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	#endif
	
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
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usChipDataLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->baChipData, 1024, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usAdditionalDataLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->baAdditionalData, 1024, SQLITE_STATIC);	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->bWaveSID);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->usWaveSTransResult);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->bWaveSCVMAnalysis);
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
  //result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szHostLabel, strlen((char*)transData->szHostLabel), SQLITE_STATIC); 
  //result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->szBatchNo, 3, SQLITE_STATIC);
	/* fBINVer */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fBINVer);
	/* szBINVerSTAN */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szBINVerSTAN, strlen((char*)transData->szBINVerSTAN), SQLITE_STATIC); 

	/* BDO: Save fields for SHARLS_ECR -- sidumili */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szECRPANFormatted, strlen((char*)transData->szECRPANFormatted), SQLITE_STATIC); 
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szECRRespText, strlen((char*)transData->szECRRespText), SQLITE_STATIC); 
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szECRMerchantName, strlen((char*)transData->szECRMerchantName), SQLITE_STATIC); 
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szECRRespCode, strlen((char*)transData->szECRRespCode), SQLITE_STATIC);
	/* BDO: Save fields for SHARLS_ECR -- sidumili */

	/*promo id - installment*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->PRMid);

    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szPolicyNumber, strlen((char*)transData->szPolicyNumber), SQLITE_STATIC); 
	
	/*fECRTrxFlg*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->fECRTrxFlg);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F6E, 4, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, transData->stEMVinfo.T9F6E_len);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)transData->szTerms, strlen((char*)transData->szTerms), SQLITE_STATIC); 
	
	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	#if 0
	sqlite3_close(db);
    #endif
	return(ST_SUCCESS);
}

int inHDTReadinSequenceEx(int inSeekCnt)
{
	int len;
	CTOS_RTC SetRTC;     
	int result;
	int inResult = d_NO;
	char *sql = "SELECT inHostIndex, szHostLabel, szTPDU, szNII, fReversalEnable, fHostEnable, szTraceNo, fSignOn, ulLastTransSavedIndex, inCurrencyIdx, szAPName, inFailedREV, inDeleteREV, inNumAdv, fPrintFooterLogo, fPrintBankReceipt, fPrintCustReceipt, fPrintMercReceipt, fPrintVoidBankReceipt, fPrintVoidCustReceipt, fPrintVoidMercReceipt, fHDTTipAllow, fAutoDelReversal, inReversalTries, fBinVerEnable FROM HDT WHERE inSequence = ? AND fHostEnable = ?";
#if 0		
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
#endif	
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);//fHostEnable = 1

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

            /*inHostIndex*/
			strHDT.inHostIndex = sqlite3_column_int(stmt, inStmtSeq );

            /* szHostLabel */
			strcpy((char*)strHDT.szHostLabel, (char *)sqlite3_column_text(stmt, inStmtSeq +=1));
            

			/*szTPDU*/
			memcpy(strHDT.szTPDU, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);

			/* szNII*/
			memcpy(strHDT.szNII, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);

			/* fReversalEnable*/
			strHDT.fReversalEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fHostEnable*/
			strHDT.fHostEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

	
			/* szTraceNo*/
			memcpy(strHDT.szTraceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);

			/* fSignOn */
			strHDT.fSignOn = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*ulLastTransSavedIndex*/
			strHDT.ulLastTransSavedIndex = sqlite3_column_double(stmt, inStmtSeq +=1 );

 			/* inCurrencyIdx */	
			strHDT.inCurrencyIdx = sqlite3_column_int(stmt, inStmtSeq +=1 );
            
			/* szAPName */			
			strcpy((char*)strHDT.szAPName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* inFailedREV */
			strHDT.inFailedREV = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* inDeleteREV */
			strHDT.inDeleteREV = sqlite3_column_int(stmt,inStmtSeq +=1);

            /* inNumAdv */
			strHDT.inNumAdv = sqlite3_column_int(stmt,inStmtSeq +=1);
			
			//sidumili: Issue#: 000135
			/*fPrintFooterLogo*/
			strHDT.fPrintFooterLogo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));


			/*BDO: Parameterized receipt printing - start*/
			/*fPrintBankReceipt*/
			strHDT.fPrintBankReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintCustReceipt*/
			strHDT.fPrintCustReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintMercReceipt*/
			strHDT.fPrintMercReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintVoidBankReceipt*/
			strHDT.fPrintVoidBankReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintVoidCustReceipt*/
			strHDT.fPrintVoidCustReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPrintVoidMercReceipt*/
			strHDT.fPrintVoidMercReceipt = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/*BDO: Parameterized receipt printing - end*/

			/* BDO: Tip Allow flag moved to HDT - start -- jzg */
			/*fHDTTipAllow*/
			strHDT.fHDTTipAllow = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO: Tip Allow flag moved to HDT - end -- jzg */

			/* BDO PHASE 2:[Flag for auto delete reversal file if host does not respond] -- sidumili */
			/*fAutoDelReversal*/
				strHDT.fAutoDelReversal = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO PHASE 2:[Flag for auto delete reversal file if host does not respond] -- sidumili */

			/* BDO PHASE 2:[Reversal Tries] -- sidumili */
				strHDT.inReversalTries = sqlite3_column_int(stmt,inStmtSeq +=1);
			/* BDO PHASE 2:[Reversal Tries] -- sidumili */

			/*fHDTTipAllow*/
			strHDT.fBinVerEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	//sqlite3_close(db);

	//vdDebug_LogPrintf("HDTREAD %d", inResult);

    memset(szGlobalAPName, 0x00, sizeof(szGlobalAPName));
	strcpy(szGlobalAPName, strHDT.szAPName);

    return(inResult);
}

int inCPT_Update(int inCommMode, int inIPHeader)
{
	int result;
    char *sql = "UPDATE CPT SET inCommunicationMode = ?, inIPHeader = ?";
               
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
 
    inStmtSeq = 0;
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, inCommMode);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, inIPHeader);
               
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

int inFLGGet(char *szFlag)
{
	int result;
	int inResult = d_NO;
	char *sql;
  	char szTempSQL[512+1];
	BOOL fValue = FALSE;

	vdDebug_LogPrintf("*****inFLGGet*****");
	memset(szTempSQL, 0, sizeof(szTempSQL));
	sql=&szTempSQL;
	

	sprintf(szTempSQL, "select %s from FLG",szFlag);
	
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return -1;
	}
	
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return -1;
	}

	//sqlite3_bind_int(stmt, 1, inSeekCnt);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			/*fPrintMercReceipt*/
			fValue = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq));    
            
   		}
	} while (result == SQLITE_ROW);	   

    vdDebug_LogPrintf("inFLGGet Flag[%s] value[%d]",szFlag,fValue);
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	
    return(fValue);
}

int inFLGRead(int inSeekCnt)
{
	int result;
	int len = 0;
	int inResult = -1;
	
	char *sql = "SELECT fLargeInvoice FROM FLG WHERE FLGid = ?";
	
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

	vdSetJournalModeOff();

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
			inResult = d_OK;
			inStmtSeq = 0;			
    
            /* inMainLine */
			strFLG.fLargeInvoice = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq));              
		
        }
	} while (result == SQLITE_ROW);	

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inResult);
}

int inFLGSet(char *szFlag, BOOL fValue)
{
	int result;
	char *sql;
	char szTempSQL[512+1];
	
	memset(szTempSQL, 0, sizeof(szTempSQL));
	sql=&szTempSQL;
	
	sprintf(szTempSQL, "UPDATE FLG SET %s = ?",szFlag);
	
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
	inStmtSeq = 0;
        
	/* fCommBackUpMode*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, fValue); 		  

	//result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);

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


int inCheckHostBatchEmtpy(int inHDTid,int inMITid)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM TransData where byTransType <> 102 AND byTransType <> 139 AND HDTid = ? AND MITid = ?";
	int inCount = 0;
	
	/* open the database */
	result = sqlite3_open(DB_INVOICE,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return -1;
	}
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return -2;
	}

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inHDTid);
	sqlite3_bind_int(stmt, inStmtSeq +=1, inMITid);
	//sqlite3_bind_int(stmt, inStmtSeq +=1, 1);
	vdDebug_LogPrintf("inHDTid[%d] :: inMITid[%d]",inHDTid,inMITid);
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

int inDatabase_OptOutInsert(void)
{
	int result;	
	char szMenuFilename[FILENAME_SIZE] = {0};
	char *sql = "INSERT INTO DMTrxMenu (DMTrxMenuid, fButtonIDEnable, usButtonID, szButtonItemImage, szButtonItemLabel, szButtonTitleLabel, szButtonItemFunc, szSubMenuName) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    char *sql1 = "SELECT MAX(usButtonID) FROM DMTrxMenu";
	char *sql2 = "SELECT COUNT(*) FROM DMTrxMenu WHERE szButtonItemLabel = 'OPT OUT'";

	int inCount=0;
	
	inTCTRead(1);
	sprintf(szMenuFilename, "./fs_data/DYNAMICMENU%02d.S3DB", strTCT.inMenuid);

	/* open the database */
	result = sqlite3_open(szMenuFilename,&db);
	if (result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 1;
	}

    /*start - get number of records for szButtonItemLabel = IP*/
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql2, -1, &stmt, NULL);
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
	vdDebug_LogPrintf("inCount [%d]",inCount);
    if(inCount > 0)
    {
		sqlite3_close(db);
		return(ST_SUCCESS);
    }
    /*end - get number of records for szButtonItemLabel = IP*/


/*********************************************************************************************/
	
#if 0
	/* open the database */
	result = sqlite3_open(szMenuFilename,&db);
	if (result != SQLITE_OK) 
	{
		sqlite3_close(db);
		return 1;
	}
#endif

    /*start - get number of records*/
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

			/* count */
			inCount = sqlite3_column_int(stmt,inStmtSeq);
		}
	} while (result == SQLITE_ROW);
    inCount++;
    /*end - get number of records*/
	
    vdDebug_LogPrintf("inDatabase_OptOutInsert inCount:%d", inCount);
	
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, inCount);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, 1);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, inCount);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, " ", strlen(" "), SQLITE_STATIC);
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, "OPT OUT", strlen("OPT OUT"), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, "FUNCTION", strlen("FUNCTION"), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, "inCTOS_DCCOptOut", strlen("inCTOS_DCCOptOut"), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, " ", strlen(" "), SQLITE_STATIC); 
	
	
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


int inDatabase_OptOutCompleteBatchUpdate(char *hexInvoiceNo)
{
	int result;

	/* Issue# 000096: BIN VER Checking -- jzg*/
	char *sql = "UPDATE TransData SET fOptOutComplete = ? WHERE szInvoiceNo = ?";

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
	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, 1); 
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, hexInvoiceNo, 4, SQLITE_STATIC);
	
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

int inMMTReadBDOHost(int inHDTid,int inMITid)
{
	int result;
	int inResult = d_NO;
	/* aaronnino for BDOCLG ver 9.0 fix on issue #00241 added  fManualMMTSettleTrigger, inOnlineMMTSettleTries, inOnlineMMTSettleLimit*/
	char *sql = "SELECT MMTid, szHostName, HDTid, szMerchantName, MITid, szTID, szMID, szATCMD1, szATCMD2, szATCMD3, szATCMD4, szATCMD5, fMustSettFlag, szBatchNo, szRctHdr1,szRctHdr2, szRctHdr3, szRctHdr4, szRctHdr5, szRctFoot1, szRctFoot2, szRctFoot3, fMMTEnable, fEnablePSWD, szPassWord, inSettleStatus, fManualMMTSettleTrigger, inOnlineMMTSettleTries, inOnlineMMTSettleLimit, szSettleDate, inMustSettleNumOfDays, fBatchNotEmpty, fPendingReversal  FROM MMT WHERE HDTid = ? AND MITid = ? AND fMMTEnable = ? ORDER BY MMTid";
	int incount = 0;
	
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

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inHDTid);
	sqlite3_bind_int(stmt, inStmtSeq +=1, inMITid);
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);
	
	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			/* MMTid */
			strMMT_Temp[incount].MMTid = sqlite3_column_int(stmt, inStmtSeq);
			
			/*szHostName*/
			strcpy((char*)strMMT_Temp[incount].szHostName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			
			/* HDTid */
			strMMT_Temp[incount].HDTid = sqlite3_column_int(stmt,inStmtSeq +=1 );
				
			/* szMerchantName */			
			strcpy((char*)strMMT_Temp[incount].szMerchantName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* MITid */
			strMMT_Temp[incount].MITid = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*szTID*/
			strcpy((char*)strMMT_Temp[incount].szTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szMID*/
			strcpy((char*)strMMT_Temp[incount].szMID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
			/*szATCMD1*/
			strcpy((char*)strMMT_Temp[incount].szATCMD1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD2*/
			strcpy((char*)strMMT_Temp[incount].szATCMD2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD3*/
			strcpy((char*)strMMT_Temp[incount].szATCMD3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD4*/
			strcpy((char*)strMMT_Temp[incount].szATCMD4, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szATCMD5*/
			strcpy((char*)strMMT_Temp[incount].szATCMD5, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
	
			/* fMustSettFlag */
			strMMT_Temp[incount].fMustSettFlag = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
			/*szBatchNo*/
			memcpy(strMMT_Temp[incount].szBatchNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);

			/* szRctHdr1 */ 		
			strcpy((char*)strMMT_Temp[incount].szRctHdr1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctHdr2 */ 		
			strcpy((char*)strMMT_Temp[incount].szRctHdr2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctHdr3 */ 		
			strcpy((char*)strMMT_Temp[incount].szRctHdr3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctHdr4 */ 		
			strcpy((char*)strMMT_Temp[incount].szRctHdr4, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctHdr5 */ 		
			strcpy((char*)strMMT_Temp[incount].szRctHdr5, (char *)sqlite3_column_text(stmt,inStmtSeq +=1  ));

			/* szRctFoot1 */		
			strcpy((char*)strMMT_Temp[incount].szRctFoot1, (char *)sqlite3_column_text(stmt,inStmtSeq +=1  ));

			/* szRctFoot2 */		
			strcpy((char*)strMMT_Temp[incount].szRctFoot2, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szRctFoot3 */		
			strcpy((char*)strMMT_Temp[incount].szRctFoot3, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
			/* fMMTEnable */
			strMMT_Temp[incount].fMMTEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fEnablePSWD */
			strMMT_Temp[incount].fEnablePSWD = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
		
			/*szPassWord*/
			strcpy((char*)strMMT_Temp[incount].szPassWord, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/* inSettleStatus */
			strMMT_Temp[incount].inSettleStatus = sqlite3_column_int(stmt,inStmtSeq +=1 );

	  //aaronnino for BDOCLG ver 9.0 fix on issue #00241 No Manual Settle/Clear Batch prompt after 3 failed start
			/* fManualMMTSettleTrigger */
			strMMT_Temp[incount].fManualMMTSettleTrigger = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* inOnlineMMTSettleTries */
			strMMT_Temp[incount].inOnlineMMTSettleTries = sqlite3_column_int(stmt,inStmtSeq +=1 );
				/*inOnlineMMTSettleLimit*/
	  strMMT_Temp[incount].inOnlineMMTSettleLimit = sqlite3_column_int(stmt,inStmtSeq +=1 );
			//aaronnino for BDOCLG ver 9.0 fix on issue #00241 No Manual Settle/Clear Batch prompt after 3 failed end

#if 0
			//BDO: Added settlement status to settlement report -- jzg
			/* inSettleStatus */
			strMMT[incount].inSettleStatus = sqlite3_column_int(stmt,inStmtSeq +=1 );
#endif
			/*szSettleDate*/
			strcpy((char*)strMMT_Temp[incount].szSettleDate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*inMustSettleNumOfDays*/
			strMMT_Temp[incount].inMustSettleNumOfDays = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*fBatchNotEmpty*/
			strMMT_Temp[incount].fBatchNotEmpty = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPendingReversal*/
			strMMT_Temp[incount].fPendingReversal = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	
	// patrick add code 20141207
	memcpy(&strMMT_Temp[0],&strMMT_Temp[incount],sizeof(STRUCT_MMT));
	
	//srTransRec.MITid = strMMT[incount].MITid;
	//strcpy(srTransRec.szTID, strMMT[incount].szTID);
	//strcpy(srTransRec.szMID, strMMT[incount].szMID);
	//memcpy(srTransRec.szBatchNo, strMMT[incount].szBatchNo, 4);
	//strcpy(srTransRec.szHostLabel, strHDT.szHostLabel);
	
	return(inResult);
}



int inMMTBDOMustSettleSave(int inSeekCnt)
{
	int result;
	/* aaronnino for BDOCLG ver 9.0 fix on issue #00241 added  fManualMMTSettleTrigger, inOnlineMMTSettleTries, inOnlineMMTSettleLimit*/
	char *sql = "UPDATE MMT SET fMustSettFlag = ? WHERE  MMTid = ?";
		
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

	vdSetJournalModeOff();

	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
      
    /* fMustSettFlag */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT_Temp[0].fMustSettFlag);
    	
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

int inDCCMMTNumRecordwithBatch(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM MMT where HDTid BETWEEN 6 AND 35 AND fBatchNotEmpty = 1";
	int inCount = 0;
	
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return -1;
	}
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return -2;
	}

	inStmtSeq = 0;
	
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
	vdDebug_LogPrintf("inCount[%d]",inCount);
	return(inCount);
}


int inDatabase_OptOutbyTransTypeBatchUpdate(BYTE byTransType, char *hexInvoiceNo)
{
	int result;

	/* Issue# 000096: BIN VER Checking -- jzg*/
	char *sql = "UPDATE TransData SET byOptOutOrigTransType = ? WHERE szInvoiceNo = ?";

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
	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, byTransType);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, hexInvoiceNo, 4, SQLITE_STATIC);
	
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

int inTCTReadLastInvoiceNo(int inSeekCnt)
{
	int result;
	int len = 0;
	int inResult = -1;
 	char *sql = "SELECT inMainLine, szInvoiceNo, szLastInvoiceNo FROM TCT WHERE TCTid = ?";

	vdDebug_LogPrintf("--inTCTReadLastInvoiceNo--");
	
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

	vdSetJournalModeOff();

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
			inResult = d_OK;
			inStmtSeq = 0;

			/* inMainLine */
			strTCT.inMainLine = sqlite3_column_int(stmt,inStmtSeq  );
			
			/* szInvoiceNo */
			memcpy(strTCT.szInvoiceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);
			   
            /* szLastInvoiceNo */
			memcpy(strTCT.szLastInvoiceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);
			
        }
	} while (result == SQLITE_ROW);	

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	vdDebug_LogPrintf("inResult[%d]", inResult);
	
    return(inResult);
}


int inMMTReadPreAuthHostName(char szHostName[][400], int inCPTID[], int inMITid, int inIndicator)
{    
	int result;
	char *sql = "SELECT HDTid, fBatchNotEmpty, fPendingReversal, fReprintSettleStatus, szHostName, fPreAuthEnable, fPreAuthExisting FROM MMT WHERE fMMTEnable = ? AND MITid = ? order by inSequence";
	int inCount = 0;
	int inDBResult = 0;
	BOOL fBatchNotEmpty;
	BOOL fPendingReversal;
	BOOL fReprintSettleStatus;
	BOOL fPreAuthEnable;
	BOOL fPreAuthExisting = FALSE;
	char szAPName[20+1];
	char szHostNameBuff[30+1];
	
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

	//memset(szAPName,0x00,sizeof(szAPName));
	//memset(szHostNameBuff,0x00,sizeof(szHostNameBuff));
	
	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);//fHostEnable = 1
	sqlite3_bind_int(stmt, inStmtSeq +=1, inMITid);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;
			/* HDTid */
			inCPTID[inCount] = sqlite3_column_int(stmt,inStmtSeq);

			fBatchNotEmpty = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            fPendingReversal = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
	
            fReprintSettleStatus = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* szHostName */
			//strcpy((char*)szHostName[inCount], (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			strcpy((char*)szHostNameBuff, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			fPreAuthEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPreAuthExisting*/
			fPreAuthExisting = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
			if(fPreAuthEnable == TRUE)
			{
				strcpy(szHostName[inCount],szHostNameBuff);
				if (fPreAuthExisting == TRUE)
					strcat((char*)szHostName[inCount],"*");

				inCount++;
			}			

			
		}
	} while (result == SQLITE_ROW);

    
	inDBResult = sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	vdDebug_LogPrintf("inDBResult[%d]",inDBResult);
	vdDebug_LogPrintf("inCount[%d]",inCount);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(d_OK);
}

int inBatchPreAuthNumRecord(void)
{
	int len;
	int result;
	//char *sql = "SELECT COUNT(*) FROM TransData WHERE HDTid = ? AND MITid = ? AND szBatchNo = ?";
	char *sql = "SELECT COUNT(*) FROM TransData WHERE HDTid = ? AND MITid = ? AND szBatchNo = ? AND (byTransType = 102 OR byTransType = 154)"; /*BDO: Do not include PRE_AUTH, SMAC BALANCE and BALANCE INQUIRY in count -- sidumili*/
	int inCount = 0;
	
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
	sqlite3_bind_blob(stmt, inStmtSeq +=1, strMMT[0].szBatchNo, 3, SQLITE_STATIC);

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


int inDetailReportHeader(void)
{
	int result;
	char szMenuFilename[FILENAME_SIZE] = {0};
		
	char *sql = "UPDATE DMDetailReportMenu SET szButtonTitleLabel='DETAIL REPORT'"; 			

	inTCTRead(1);
	sprintf(szMenuFilename, "./fs_data/DYNAMICMENU%02d.S3DB", strTCT.inMenuid);

	/* open the database */
	result = sqlite3_open(szMenuFilename,&db);
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
    //sqlite3_bind_int(stmt, inStmtSeq +=1, inHostIndex);
    //sqlite3_bind_text(stmt, inStmtSeq +=1, szButtonItemLabel, strlen(szButtonItemLabel), SQLITE_STATIC);
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

int inHDTSaveTraceNo(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE HDT SET szTraceNo = ? WHERE  HDTid = ?";

	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

	vdSetJournalModeOff();

	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}
	inStmtSeq = 0;
    /* szTraceNo*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strHDT.szTraceNo, 3, SQLITE_STATIC);
	
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


int inHDTReadQRMenu(char *szHostName, int inHDTid[])
{    
	int result;	
	char *sql = "SELECT HDTid FROM HDT WHERE fHostEnable = 1 and szAPName = ? order by inSequence";
	int inCount = 0;
	int inDBResult = 0;
	
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

	
    inStmtSeq = 0;
    sqlite3_bind_text(stmt, inStmtSeq +=1, szHostName, strlen(szHostName), SQLITE_STATIC);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;
			/* HDTid */
			inHDTid[inCount] = sqlite3_column_int(stmt,inStmtSeq);

            /* szHostName */
			//strcpy((char*)szHostName[inCount], (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			//vdDebug_LogPrintf("szHostName[%s] %d",szHostName[inCount], inCount);

			inCount++;
		}
	} while (result == SQLITE_ROW);

    
	inDBResult = sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	vdDebug_LogPrintf("inDBResult[%d]",inDBResult);
	vdDebug_LogPrintf("inCount[%d]",inCount);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inCount);
}


int inCDTReadMulti_2(char *szPAN, int *inFindRecordNum)
{
	int result;
	int inResult = d_NO;
	char *sql; 
	int inDBResult = 0;
	char szTemp[16];
	int inPAN, inCount=0, inIndex=0;
    char szTempSQL[512+1];

    memset(szTempSQL, 0, sizeof(szTempSQL));
	sql=&szTempSQL;
	
     //if(strTCT.fATPBinRoute == TRUE)
    //	    strcpy(szTempSQL, "SELECT szPANLo, szPANHi, szCardLabel, inType, inMinPANDigit, inMaxPANDigit, inCVV_II, InFloorLimitAmount, fExpDtReqd,  fPinpadRequired, fManEntry, fCardPresent, fChkServiceCode, fluhnCheck, fCDTEnable, IITid, HDTid, CDTid, fInstallmentEnable, inInstGroup, fDualCurrencyEnable, fFleetCard, fPANCatchAll, fDCCEnable FROM CDT WHERE ? BETWEEN szPANLo AND szPANHi AND fCDTATPEnable= ?");
    //else
	    strcpy(szTempSQL, "SELECT szPANLo, szPANHi, szCardLabel, inType, inMinPANDigit, inMaxPANDigit, inCVV_II, InFloorLimitAmount, fExpDtReqd,  fPinpadRequired, fManEntry, fCardPresent, fChkServiceCode, fluhnCheck, fCDTEnable, IITid, HDTid, CDTid, fInstallmentEnable, inInstGroup, fDualCurrencyEnable, fFleetCard, fPANCatchAll, fDCCEnable FROM CDT WHERE ? BETWEEN szPANLo AND szPANHi AND fCDTEnable= ?");

	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	inDBResult = sqlite3_exec( db, "begin", 0, 0, NULL );
	vdDebug_LogPrintf("inCDTRead,sqlite3_exec[%d]",inDBResult);
	
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}
#ifdef TRUNC_PAN_READING
	memcpy(szTemp, szPAN, 8);
	szTemp[8]=0;
	inPAN = atoi(szTemp);
	vdDebug_LogPrintf("inPAN = %d",inPAN);
#else
	memcpy(szTemp, szPAN, 12);
	szTemp[12]=0;
#endif

	inStmtSeq = 0;

#ifdef TRUNC_PAN_READING
	sqlite3_bind_int(stmt, inStmtSeq +=1, inPAN);
#else
	sqlite3_bind_text(stmt, inStmtSeq +=1, szTemp, strlen(szTemp), SQLITE_STATIC);
#endif

	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);//fCDTEnable = 1

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		vdDebug_LogPrintf("inCDTRead,result[%d]SQLITE_ROW[%d]",result,SQLITE_ROW);
		
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

		    /*szPANLo*/
		     strcpy(strMCDT[inCount].szPANLo, sqlite3_column_text(stmt,inStmtSeq));

		    /*szPANHi*/
		     strcpy(strMCDT[inCount].szPANHi, sqlite3_column_text(stmt,inStmtSeq +=1));

		    /*szCardLabel*/
		    strcpy(strMCDT[inCount].szCardLabel, sqlite3_column_text(stmt,inStmtSeq +=1));

		    /*inType*/
			strMCDT[inCount].inType = sqlite3_column_int(stmt,inStmtSeq +=1);
			
			/*inMinPANDigit*/
		    strMCDT[inCount].inMinPANDigit = sqlite3_column_int(stmt,inStmtSeq +=1);
			
			/*inMaxPANDigit*/
		    strMCDT[inCount].inMaxPANDigit = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*inCVV_II*/
		    strMCDT[inCount].inCVV_II = sqlite3_column_int(stmt,inStmtSeq +=1);

            
			/*InFloorLimitAmount*/
			strMCDT[inCount].InFloorLimitAmount = sqlite3_column_double(stmt,inStmtSeq +=1 );

			
			/*fExpDtReqd*/
		    strMCDT[inCount].fExpDtReqd = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			
			
			/*fPinpadRequired*/
		    strMCDT[inCount].fPinpadRequired = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

				
			/*fManEntry*/
		    strMCDT[inCount].fManEntry = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

		    /*fCardPresent*/
		    strMCDT[inCount].fCardPresent = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			
		    /*fChkServiceCode*/
		    strMCDT[inCount].fChkServiceCode =fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fluhnCheck */
			strMCDT[inCount].fluhnCheck = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fCDTEnable*/
			strMCDT[inCount].fCDTEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));		

            /*IITid*/
		    strMCDT[inCount].IITid = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* HDTid*/
			strMCDT[inCount].HDTid = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* CDTid*/
			strMCDT[inCount].CDTid = sqlite3_column_int(stmt,inStmtSeq +=1);


			//gcitra
			/*fInstallmentEnable*/
			strMCDT[inCount].fInstallmentEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));		

			/*inInstGroup*/
			strMCDT[inCount].inInstGroup = sqlite3_column_double(stmt,inStmtSeq +=1 );
			//gcitra		

			//1026
            /*fDualCurrencyEnable*/
			strMCDT[inCount].fDualCurrencyEnable = sqlite3_column_double(stmt,inStmtSeq +=1 );

			/* BDO CLG: Fleet card support - start -- jzg */
			/*fFleetCard*/
			strMCDT[inCount].fFleetCard = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO CLG: Fleet card support - end -- jzg */

			
			/*fPANCatchAll - add to check if BIN is CATCH all - will be used for DEBIT Paypass*/
			strMCDT[inCount].fPANCatchAll = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
			/*fDCCEnable*/
					strMCDT[inCount].fDCCEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			inCount ++;
			if(inCount >=10)
				break;
		}
	} while (result == SQLITE_ROW);
  
  *inFindRecordNum = inCount;
  vdDebug_LogPrintf("inCDTReadMulti Record=%d",*inFindRecordNum);
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inResult);
}



int inCDTReadEx_2(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql; 
	int inDBResult = 0;	

    char szTempSQL[512+1];

    memset(szTempSQL, 0, sizeof(szTempSQL));
	sql=&szTempSQL;
	
   // if(strTCT.fATPBinRoute == TRUE)
  //	    strcpy(szTempSQL, "SELECT szPANLo, szPANHi, szCardLabel, inType, inMinPANDigit, inMaxPANDigit, inCVV_II, InFloorLimitAmount, fExpDtReqd,  fPinpadRequired, fManEntry, fCardPresent, fChkServiceCode, fluhnCheck, fCDTEnable, IITid, HDTid, fInstallmentEnable, inInstGroup, fDualCurrencyEnable, inDualCurrencyHost, fFleetCard, fPANCatchAll, fBalInqAllowed, fDCCEnable FROM CDT WHERE CDTid = ? AND fCDTATPEnable= ?");
   // else
	    strcpy(szTempSQL, "SELECT szPANLo, szPANHi, szCardLabel, inType, inMinPANDigit, inMaxPANDigit, inCVV_II, InFloorLimitAmount, fExpDtReqd,  fPinpadRequired, fManEntry, fCardPresent, fChkServiceCode, fluhnCheck, fCDTEnable, IITid, HDTid, fInstallmentEnable, inInstGroup, fDualCurrencyEnable, inDualCurrencyHost, fFleetCard, fPANCatchAll, fBalInqAllowed, fDCCEnable FROM CDT WHERE CDTid = ? AND fCDTEnable= ?");
	
	if (fInstApp == TRUE){
		result = inInstallmentCDTReadEx(inSeekCnt);
		return result;
	}
	
#if 0
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
#endif

	inDBResult = sqlite3_exec( db, "begin", 0, 0, NULL );
	vdDebug_LogPrintf("inCDTRead,sqlite3_exec[%d]",inDBResult);

	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);//fCDTEnable = 1

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		vdDebug_LogPrintf("inCDTRead,result[%d]SQLITE_ROW[%d]",result,SQLITE_ROW);

		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			/*szPANLo*/
			strcpy(strCDT.szPANLo, sqlite3_column_text(stmt,inStmtSeq));

			/*szPANHi*/
			strcpy(strCDT.szPANHi, sqlite3_column_text(stmt,inStmtSeq +=1));

			/*szCardLabel*/
			strcpy(strCDT.szCardLabel, sqlite3_column_text(stmt,inStmtSeq +=1));

			/*inType*/
			strCDT.inType = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*inMinPANDigit*/
			strCDT.inMinPANDigit = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*inMaxPANDigit*/
			strCDT.inMaxPANDigit = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*inCVV_II*/
			strCDT.inCVV_II = sqlite3_column_int(stmt,inStmtSeq +=1);

			/*InFloorLimitAmount*/
			strCDT.InFloorLimitAmount = sqlite3_column_double(stmt,inStmtSeq +=1 );

			/*fExpDtReqd*/
			strCDT.fExpDtReqd = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fPinpadRequired*/
			strCDT.fPinpadRequired = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fManEntry*/
			strCDT.fManEntry = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fCardPresent*/
			strCDT.fCardPresent = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fChkServiceCode*/
			strCDT.fChkServiceCode =fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fluhnCheck */
			strCDT.fluhnCheck = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/* fCDTEnable*/
			strCDT.fCDTEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));		

			/*IITid*/
			strCDT.IITid = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* HDTid*/
			strCDT.HDTid = sqlite3_column_int(stmt,inStmtSeq +=1);	

			//gcitra
			/*fInstallmentEnable*/
			strCDT.fInstallmentEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));		

			/*inInstGroup*/
			strCDT.inInstGroup = sqlite3_column_double(stmt,inStmtSeq +=1 );
			//gcitra

			//1026
			/*fDualCurrencyEnable*/
			strCDT.fDualCurrencyEnable = sqlite3_column_double(stmt,inStmtSeq +=1 );

			/* BDO: Added dual currency to CDT -- jzg */
			strCDT.inDualCurrencyHost = sqlite3_column_int(stmt,inStmtSeq +=1);

			/* BDO CLG: Fleet card support - start -- jzg */
			/*fFleetCard*/
			strCDT.fFleetCard = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			/* BDO CLG: Fleet card support - end -- jzg */

			/*fPANCatchAll - add to check if BIN is CATCH all - will be used for DEBIT Paypass*/
			strCDT.fPANCatchAll = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fBalInqAllowed*/
			strCDT.fBalInqAllowed = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fDCCEnable*/
			strCDT.fDCCEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	
	#if 0
	sqlite3_close(db);
    #endif
	
	return(inResult);
}


int inCountBatchesWithTxn(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM MMT WHERE fBatchNotEmpty = 1";
	int inCount = 0;

	
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return -1;
	}
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return -2;
	}

	inStmtSeq = 0;
	
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
	vdDebug_LogPrintf("inCount[%d]",inCount);
	return(inCount);
}

/*For TMS, read all MMT records but only need few data*/
int inMMTReadSelectedData(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT MITid, HDTid, szHostName, szMerchantName, szTID, szMID, szBatchNo, fMMTEnable FROM MMT WHERE MMTid = ?";
	int incount = 0;
#if 0	
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
#endif
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}
    
	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
	
	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;
			
            /* MITid */
			strMMTRec.MITid = sqlite3_column_int(stmt,inStmtSeq);
			
			/* HDTid */
			strMMTRec.HDTid = sqlite3_column_int(stmt,inStmtSeq +=1 );
			
			/*szHostName*/
			strcpy((char*)strMMTRec.szHostName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			
			/* szMerchantName */			
			strcpy((char*)strMMTRec.szMerchantName, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
			/*szTID*/
			strcpy((char*)strMMTRec.szTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
			/*szMID*/
			strcpy((char*)strMMTRec.szMID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            
			/*szBatchNo*/
			memcpy(strMMTRec.szBatchNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);
			
            /* fMMTEnable */
			strMMTRec.fMMTEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			//incount++;
		}
	} while (result == SQLITE_ROW);

	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	
	//sqlite3_close(db);
    
    return(inResult);
}


int inMMTEnabledMerchants(int inMerchID[])
{    
	int result;	
	char *sql = "SELECT MMTid FROM MMT WHERE fMMTEnable = ? order by inSequence";
	int inCount = 0;
	int inDBResult = 0;
#if 0	
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
#endif
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return -2;
	}

	
	inStmtSeq = 0;
	sqlite3_bind_int(stmt, inStmtSeq +=1, 1);//fMMTEnable = 1

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inStmtSeq = 0;
			/* MMTid */
			inMerchID[inCount] = sqlite3_column_int(stmt,inStmtSeq);
           	vdDebug_LogPrintf("inMerchID[%d] = %d",inCount,inMerchID[inCount]);
			inCount++;
		}
	} while (result == SQLITE_ROW);

    
	inDBResult = sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	vdDebug_LogPrintf("inDBResult[%d]",inDBResult);
	vdDebug_LogPrintf("inMMTEnabledMerchants inCount[%d]",inCount);

	sqlite3_finalize(stmt);
#if 0
	sqlite3_close(db);
#endif

    return(inCount);
}

int inTCTInvoiceNoSave(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE TCT SET szInvoiceNo = ?, szLastInvoiceNo = ? WHERE TCTid = ?";    		

#if 0
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
#endif	
    vdDebug_LogPrintf("[inTCTInvoiceNoSave]");
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);   
    vdDebug_LogPrintf("[inTCTSave]-sqlite3_prepare_v2[%d]",result);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;

	/* szInvoiceNo*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strTCT.szInvoiceNo, 3, SQLITE_STATIC);

	/* szLastInvoiceNo*/
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strTCT.szLastInvoiceNo, 3, SQLITE_STATIC);
	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}
    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
#if 0
	sqlite3_close(db);
#endif
    vdDebug_LogPrintf("[inTCTSave]-end ");

    return(d_OK);
}


int inTMSMMTSave(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE MMT SET MMTid = ? ,HDTid = ? ,MITid = ?, szBatchNo = ? WHERE  MMTid = ?";
#if 0		
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
#endif
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	inStmtSeq = 0;
    /* MMMTid */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].MMTid);    
	/* HDTid */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].HDTid);	
    /* MITid */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, strMMT[0].MITid);    
    /* szBatchNo*/
    result = sqlite3_bind_blob(stmt, inStmtSeq +=1, strMMT[0].szBatchNo, 3, SQLITE_STATIC);

    result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);
    
	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}
	
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
#if 0
	sqlite3_close(db);
#endif


    return(d_OK);
}

int inEFTTempRead(int inSeekCnt)
{
	int len;
	CTOS_RTC SetRTC;     
	int result;
	int inResult = d_NO;
	char *sql = "SELECT EFTid, inEFTEnable FROM EFT WHERE HDTid = ?";
		
	/* open the database */
	result = sqlite3_open(DB_EFTSEC,&db);
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
	sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

            /*inHostIndex*/
			strEFT_Temp.EFTid = sqlite3_column_int(stmt, inStmtSeq );

			/*inHostIndex*/
			strEFT_Temp.HDTid = sqlite3_column_int(stmt, inStmtSeq);
			
			/* inEFTEnable*/
			strEFT_Temp.inEFTEnable = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));			
		
		}
	} while (result == SQLITE_ROW);

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	//vdDebug_LogPrintf("HDTREAD %d", inResult);

    //memset(szGlobalAPName, 0x00, sizeof(szGlobalAPName));
	//strcpy(szGlobalAPName, strHDT.szAPName);

    return(inResult);
}

int inSetBinCheck(int inValue)
{
	int result;
	char szMenuFilename[FILENAME_SIZE] = {0};
		
    char *sql = "UPDATE DMTrxMenu SET fButtonIDEnable=? WHERE szButtonItemLabel='BIN CHECK'";

	vdDebug_LogPrintf("*** inSetBinCheck ***");
	inTCTRead(1);
	sprintf(szMenuFilename, "./fs_data/DYNAMICMENU%02d.S3DB", strTCT.inMenuid);

	/* open the database */
	result = sqlite3_open(szMenuFilename,&db);
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
    result=sqlite3_bind_int(stmt, inStmtSeq +=1, inValue);

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

int inSetMobileWalletLabel(char *szButtonItemLabel)
{
	int result;
	char szMenuFilename[FILENAME_SIZE] = {0};
		
	char *sql = "UPDATE DMTrxMenu SET szButtonItemLabel=? WHERE szButtonItemFunc='inQRPAY'"; 			

	inTCTRead(1);
	sprintf(szMenuFilename, "./fs_data/DYNAMICMENU%02d.S3DB", strTCT.inMenuid);

	/* open the database */
	result = sqlite3_open(szMenuFilename,&db);
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
    //sqlite3_bind_int(stmt, inStmtSeq +=1, inHostIndex);
    sqlite3_bind_text(stmt, inStmtSeq +=1, szButtonItemLabel, strlen(szButtonItemLabel), SQLITE_STATIC);
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

int inCountBatchesWithPendingReversal(void)
{
	int len;
	int result;
	char *sql = "SELECT COUNT(*) FROM MMT where fPendingReversal = 1";
	int inCount = 0;

	
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return -1;
	}
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return -2;
	}

	inStmtSeq = 0;
	
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
	vdDebug_LogPrintf("inCount[%d]",inCount);
	return(inCount);
}


int inPHQRRead(int inSeekCnt)
{
	int len;
	CTOS_RTC SetRTC;     
	int result;
	int inResult = d_NO;
	char *sql = "SELECT MerchantID, ScanQRURL, GenerateQRURL, GetStatusURL, VoidURL, inCurlRequestTimeout, inCurlRetries, SSLEnable, szPAN, szFailureMsg1, szFailureMsg2, szFailureMsg3, szProxyURL, szAppKey, szAppSecret, szMerchantAPIUser, szMerchantAPIKey, fSignatureLine, fDisclaimer, fThankYouLine, fPrintTimeLine, fPartnerCode, szTranStatusAppkey, szTranStatusSecret, szGetStatusPriIP, szGetStatusSecIP, inGetStatusPriPort, inGetStatusSecPort FROM PHT WHERE PHTID = ? ";
	//


	vdDebug_LogPrintf("inPHQRRead");

	//vdDebug_LogPrintf("inBDOPayRead OPEN");
	/* open the database */
	result = sqlite3_open(DB_BDOPAY,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

	//vdDebug_LogPrintf("inBDOPayRead BEGIN");

	vdSetJournalModeOff();
	
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	sqlite3_bind_int(stmt, 1, inSeekCnt);

	//vdDebug_LogPrintf("inBDOPayRead BEFORE DO");

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;
			
			strcpy((char*)strPHQR.MerchantID, (char *)sqlite3_column_text(stmt, inStmtSeq));
			
			strcpy((char*)strPHQR.ScanQRURL, (char *)sqlite3_column_text(stmt, inStmtSeq +=1));
			
			strcpy((char*)strPHQR.GenerateQRURL, (char *)sqlite3_column_text(stmt, inStmtSeq +=1));	

			strcpy((char*)strPHQR.GetStatusURL, (char *)sqlite3_column_text(stmt, inStmtSeq +=1));	

			strcpy((char*)strPHQR.VoidURL, (char *)sqlite3_column_text(stmt, inStmtSeq +=1));	
			
			strPHQR.inCurlRequestTimeout = sqlite3_column_int(stmt,inStmtSeq +=1 );

			strPHQR.inCurlRetries = sqlite3_column_int(stmt,inStmtSeq +=1 );
			
			strPHQR.SSLEnable = sqlite3_column_int(stmt,inStmtSeq +=1 );

			strcpy(strPHQR.szPAN, sqlite3_column_text(stmt,inStmtSeq +=1));

			strcpy(strPHQR.szFailureMsg1, sqlite3_column_text(stmt,inStmtSeq +=1));

			strcpy(strPHQR.szFailureMsg2, sqlite3_column_text(stmt,inStmtSeq +=1));

			strcpy(strPHQR.szFailureMsg3, sqlite3_column_text(stmt,inStmtSeq +=1));			

			strcpy(strPHQR.szProxyURL, sqlite3_column_text(stmt,inStmtSeq +=1));
			
			strcpy(strPHQR.szAppKey, sqlite3_column_text(stmt,inStmtSeq +=1));

			strcpy(strPHQR.szAppSecret, sqlite3_column_text(stmt,inStmtSeq +=1));

			strcpy(strPHQR.szMerchantAPIUser, sqlite3_column_text(stmt,inStmtSeq +=1));

			strcpy(strPHQR.szMerchantAPIKey, sqlite3_column_text(stmt,inStmtSeq +=1));
			
			strPHQR.fSignatureLine = sqlite3_column_int(stmt,inStmtSeq +=1 );
			
			strPHQR.fDisclaimer = sqlite3_column_int(stmt,inStmtSeq +=1 );
			
			strPHQR.fThankYouLine = sqlite3_column_int(stmt,inStmtSeq +=1 );
			
			strPHQR.fPrintTimeLine = sqlite3_column_int(stmt,inStmtSeq +=1 );
			
			strPHQR.fPartnerCode = sqlite3_column_int(stmt,inStmtSeq +=1 );
			
			strcpy(strPHQR.szTranStatusAppkey, sqlite3_column_text(stmt,inStmtSeq +=1));

			strcpy(strPHQR.szTranStatusSecret, sqlite3_column_text(stmt,inStmtSeq +=1));

			strcpy((char*)strPHQR.szGetStatusPriIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
			strcpy((char*)strPHQR.szGetStatusSecIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
			strPHQR.inGetStatusPriPort = sqlite3_column_int(stmt, inStmtSeq +=1 );
			
			strPHQR.inGetStatusSecPort = sqlite3_column_int(stmt, inStmtSeq +=1 );

	
		}
	} while (result == SQLITE_ROW);
  
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	//srTransRec.fDisclaimer = strPHQR.fDisclaimer;
	//srTransRec.fThankYouLine = strPHQR.fThankYouLine;
	//srTransRec.fPrintTimeLine = strPHQR.fPrintTimeLine;
	//srTransRec.fSignatureLine = strPHQR.fSignatureLine;


	vdDebug_LogPrintf("return inPHQRRead");
    return(inResult);
}

int readWaveTable(char* szTableName, char* szUniqueID, int inSeekCnt)
{
	char *sql = "";
	char szTempSQL[512+1];
	int inResult = d_NO;
	int result;

	vdDebug_LogPrintf("--readWaveTable--");
	vdDebug_LogPrintf("szTableName=[%s]", szTableName);
	vdDebug_LogPrintf("szUniqueID=[%s]", szUniqueID);
	vdDebug_LogPrintf("inSeekCnt=[%d]", inSeekCnt);
	
	memset(szTempSQL, 0, sizeof(szTempSQL));
	sql=&szTempSQL;

	sprintf(szTempSQL, "SELECT %s, szName, szTag, szValue FROM %s WHERE %s = %d;", szUniqueID, szTableName, szUniqueID, inSeekCnt);
	vdDebug_LogPrintf("szTempSQL=[%s]", szTempSQL);

	result = sqlite3_open(DB_WAVE,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

	vdSetJournalModeOff();
	
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
			inResult = d_OK;
			inStmtSeq = 0;
			
			/*inHostIndex*/
			strTableWave.WaveID = sqlite3_column_int(stmt, inStmtSeq );			
			strcpy((char*)strTableWave.szName, (char *)sqlite3_column_text(stmt, inStmtSeq +=1));			
			strcpy((char*)strTableWave.szTag, (char *)sqlite3_column_text(stmt, inStmtSeq +=1));
			strcpy((char*)strTableWave.szValue, (char *)sqlite3_column_text(stmt, inStmtSeq +=1));
		}
	} while (result == SQLITE_ROW);
  
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	vdDebug_LogPrintf("strTableWave.WaveID=[%d]", strTableWave.WaveID);
	vdDebug_LogPrintf("strTableWave.szName=[%s]", strTableWave.szName);
	vdDebug_LogPrintf("strTableWave.szTag=[%s]", strTableWave.szTag);
	vdDebug_LogPrintf("strTableWave.szValue=[%s]", strTableWave.szValue);
	
    return(inResult);
}

int inBLTRead(int inSeekCnt)
{
	int len;
	CTOS_RTC SetRTC;     
	int result;
	int inResult = d_NO;
	char *sql = "SELECT BaseURL, AccessTokenURL, RedemptionURL, PtsInquiryURL, ReversalURL, inCurlRequestTimeout, inCurlRetries, SSLEnable,szProxyURL, szAuthUserName, szAuthPassword, szGetStatusPriIP, szGetStatusSecIP, inGetStatusPriPort, inGetStatusSecPort FROM BLT WHERE BLTID = ? ";
	//


	vdDebug_LogPrintf("inBLTRead");

	//vdDebug_LogPrintf("inBDOPayRead OPEN");
	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

	//vdDebug_LogPrintf("inBDOPayRead BEGIN");

	vdSetJournalModeOff();
	
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	sqlite3_bind_int(stmt, 1, inSeekCnt);

	//vdDebug_LogPrintf("inBDOPayRead BEFORE DO");

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			strcpy((char*)strLoyalty.BaseURL, (char *)sqlite3_column_text(stmt, inStmtSeq));

			strcpy((char*)strLoyalty.AccessTokenURL, (char *)sqlite3_column_text(stmt, inStmtSeq+=1));
			
			strcpy((char*)strLoyalty.RedemptionURL, (char *)sqlite3_column_text(stmt, inStmtSeq +=1));

			strcpy((char*)strLoyalty.PtsInquiryURL, (char *)sqlite3_column_text(stmt, inStmtSeq +=1));	

			strcpy((char*)strLoyalty.ReversalURL, (char *)sqlite3_column_text(stmt, inStmtSeq +=1));	

			strLoyalty.inCurlRequestTimeout = sqlite3_column_int(stmt,inStmtSeq +=1 );

			strLoyalty.inCurlRetries = sqlite3_column_int(stmt,inStmtSeq +=1 );
			
			strLoyalty.SSLEnable = sqlite3_column_int(stmt,inStmtSeq +=1 );

			strcpy(strLoyalty.szProxyURL, sqlite3_column_text(stmt,inStmtSeq +=1));
			
			strcpy(strLoyalty.szAuthUserName, sqlite3_column_text(stmt,inStmtSeq +=1));

			strcpy(strLoyalty.szAuthPassword, sqlite3_column_text(stmt,inStmtSeq +=1));

			strcpy((char*)strLoyalty.szGetStatusPriIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
			strcpy((char*)strLoyalty.szGetStatusSecIP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
			strLoyalty.inGetStatusPriPort = sqlite3_column_int(stmt, inStmtSeq +=1 );
			
			strLoyalty.inGetStatusSecPort = sqlite3_column_int(stmt, inStmtSeq +=1 );

	
		}
	} while (result == SQLITE_ROW);
  
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);



	vdDebug_LogPrintf("return inBLTRead");
    return(inResult);
}

//version16
int inPHQRSave(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE PHT SET szGetStatusPriIP = ?, szGetStatusSecIP = ? WHERE PHTID = ?";


   vdDebug_LogPrintf("inPHQRSave 1 ");
	/* open the database */
	result = sqlite3_open(DB_BDOPAY,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}

   vdDebug_LogPrintf("inPHQRSave 2");

	vdSetJournalModeOff();

	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}
	inStmtSeq = 0;

	inStmtSeq = 0;
   vdDebug_LogPrintf("inPHQRSave 3");

	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPHQR.szGetStatusPriIP, strlen((char*)strPHQR.szGetStatusPriIP), SQLITE_STATIC);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)strPHQR.szGetStatusSecIP, strlen((char*)strPHQR.szGetStatusSecIP), SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);

	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}
   
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);
   vdDebug_LogPrintf("inPHQRSave 4");

	return(d_OK);
}


int inBDOWechatRead(int inSeekCnt)
{
	int result = 0;
	char *sql = "SELECT BWTid, szBDOMID FROM BDOWECHAT WHERE BWTid=?";

	/* open the database */
	result = sqlite3_open(DB_BDOPAY,&walletdb);
	if (result != SQLITE_OK)
	{
		sqlite3_close(walletdb);
		return 1;
	}

	sqlite3_exec( walletdb, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(walletdb, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK)
	{
		sqlite3_close(walletdb);
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
			strDigitalWallet.BWTid = sqlite3_column_int(stmt, inStmtSeq);
			strcpy((char *)strDigitalWallet.szBDOMID,  (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

		}
	}
	while (result == SQLITE_ROW);

	sqlite3_exec(walletdb,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(walletdb);


	
	return(d_OK);
}

int inBDOAlipayRead(int inSeekCnt)
{
	int result = 0;
	char *sql = "SELECT BWTid, szBDOMID FROM BDOALIPAY WHERE BWTid=?";

	/* open the database */
	result = sqlite3_open(DB_BDOPAY,&walletdb);
	if (result != SQLITE_OK)
	{
		sqlite3_close(walletdb);
		return 1;
	}

	sqlite3_exec( walletdb, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(walletdb, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK)
	{
		sqlite3_close(walletdb);
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
			strDigitalWallet.BWTid = sqlite3_column_int(stmt, inStmtSeq);
			strcpy((char *)strDigitalWallet.szBDOMID,  (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

		}
	}
	while (result == SQLITE_ROW);

	sqlite3_exec(walletdb,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(walletdb);

	
	return(d_OK);
}



#if 0
int inCheckQRPH_Exist(void)
{
	int result = 0,
			inCount = 0;
	int inMenuIndex = 0,
		inResult = 0,
		inCtr = 0x0000;
	char szMenuFilename[FILENAME_SIZE] = {0};
	char *sql = "SELECT DMTrxMenuid, usButtonID, szButtonItemImage, szButtonItemLabel, szButtonTitleLabel, szButtonItemFunc, szSubMenuName FROM DMTrxMenu WHERE szButtonItemLabel = 'BDO LOYALTY'";

	vdDebug_LogPrintf("--inReadBaseDMTrxMenu--");

	//vdDebug_LogPrintf("DB_APPSELECTMENU[%s]", DB_APPSELECTMENU);

	memset(szMenuFilename, 0x00, sizeof(szMenuFilename));
	if (strTCT.inMenuid > 99)
		sprintf(szMenuFilename, "./fs_data/DYNAMICMENU%03d.S3DB", strTCT.inMenuid);
	else
		sprintf(szMenuFilename, "./fs_data/DYNAMICMENU%02d.S3DB", strTCT.inMenuid);

	vdDebug_LogPrintf("szMenuFilename[%s]", szMenuFilename);
	
	inResult = sqlite3_open(szMenuFilename, &db);
	if(inResult != SQLITE_OK) 
	{
		sqlite3_close(db);
		return ST_ERROR;
	}

	sqlite3_exec( db, "begin", 0, 0, NULL );
	inResult = sqlite3_prepare_v2(db, sql  , -1, &stmt, NULL);
	if (inResult != SQLITE_OK) 
	{
		sqlite3_close(db);
		return ST_ERROR;
	}

	//do 
	//{
		inResult = sqlite3_step(stmt);

		vdDebug_LogPrintf("TESTLANG STEP RESULT %d", inResult);
		if(inResult == SQLITE_ROW) 
		{ 
			inStmtSeq = 0;
			strTrxMenu[inCount].DMTrxMenuid = sqlite3_column_int(stmt, inStmtSeq);
			strTrxMenu[inCount].usButtonID = sqlite3_column_int(stmt, inStmtSeq+=1);
			strcpy((char *)strTrxMenu[inCount].szButtonItemImage,  (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			strcpy((char *)strTrxMenu[inCount].szButtonItemLabel,  (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			strcpy((char *)strTrxMenu[inCount].szButtonTitleLabel,  (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			strcpy((char *)strTrxMenu[inCount].szButtonItemFunc,  (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			strcpy((char *)strTrxMenu[inCount].szSubMenuName,  (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			vdDebug_LogPrintf("inCount[%d].szButtonItemImage[%s]", inCount, (char *)strTrxMenu[inCount].szButtonItemImage);
			vdDebug_LogPrintf("inCount[%d].szButtonItemLabel[%s]", inCount, (char *)strTrxMenu[inCount].szButtonItemLabel);
			vdDebug_LogPrintf("inCount[%d].szButtonTitleLabel[%s]", inCount, (char *)strTrxMenu[inCount].szButtonTitleLabel);
			vdDebug_LogPrintf("inCount[%d].szButtonItemFunc[%s]", inCount, (char *)strTrxMenu[inCount].szButtonItemFunc);
			vdDebug_LogPrintf("inCount[%d].szSubMenuName[%s]", inCount, (char *)strTrxMenu[inCount].szSubMenuName);

			inResult = TRUE;
			
			//inCount++;
			//if (inCount>20)
			//	break;
		}else
		 inResult = FALSE;
	//} 
	//while(inResult == SQLITE_ROW);

	//*inNumRecs = inCount;		
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inResult);
}



int inInsertQRPH2Menu(int DMTrxMenuid, int usButtonID, char* szButtonItemImage, char* szButtonItemLabel, char* szButtonTitleLabel, char* szButtonItemFunc, char* szSubMenuName)
{
	int result; 
	char *sql = "INSERT INTO DMTrxMenu (DMTrxMenuid, usButtonID, szButtonItemImage, szButtonItemLabel, szButtonTitleLabel, szButtonItemFunc, szSubMenuName) VALUES (?, ?, ?, ?, ?, ?, ?)";
	char szMenuFilename[FILENAME_SIZE] = {0};

	vdDebug_LogPrintf("--inInsertSelectionMenu--");
	
	vdDebug_LogPrintf("DMTrxMenuid[%d]", DMTrxMenuid);
	vdDebug_LogPrintf("usButtonID[%d]", usButtonID);
	vdDebug_LogPrintf("szButtonItemImage[%s]", szButtonItemImage);
	vdDebug_LogPrintf("szButtonItemLabel[%s]", szButtonItemLabel);
	vdDebug_LogPrintf("szButtonTitleLabel[%s]", szButtonTitleLabel);
	vdDebug_LogPrintf("szButtonItemFunc[%s]", szButtonItemFunc);
	vdDebug_LogPrintf("szSubMenuName[%s]", szSubMenuName);


	memset(szMenuFilename, 0x00, sizeof(szMenuFilename));
	if (strTCT.inMenuid > 99)
		sprintf(szMenuFilename, "./fs_data/DYNAMICMENU%03d.S3DB", strTCT.inMenuid);
	else
		sprintf(szMenuFilename, "./fs_data/DYNAMICMENU%02d.S3DB", strTCT.inMenuid);

	/* open the database */
	result = sqlite3_open(szMenuFilename,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		vdDebug_LogPrintf("error return 1");
		return 1;
	}

	vdDebug_LogPrintf("--inInsertSelectionMenu-1-");
	
	
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		vdDebug_LogPrintf("error return 2");
		return 2;
	}

	vdDebug_LogPrintf("--inInsertSelectionMenu-2-");
	

	inStmtSeq = 0;
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, DMTrxMenuid);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, usButtonID);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)szButtonItemImage, strlen((char*)szButtonItemImage), SQLITE_STATIC); 
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)szButtonItemLabel, strlen((char*)szButtonItemLabel), SQLITE_STATIC); 
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)szButtonTitleLabel, strlen((char*)szButtonTitleLabel), SQLITE_STATIC); 
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)szButtonItemFunc, strlen((char*)szButtonItemFunc), SQLITE_STATIC); 
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)szSubMenuName, strlen((char*)szSubMenuName), SQLITE_STATIC); 
			
	result = sqlite3_step(stmt);

	vdDebug_LogPrintf("--inInsertSelectionMenu-result-[%d]", result);
	
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		vdDebug_LogPrintf("error return 3");
		return 3;
	}
	
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	vdDebug_LogPrintf("--inInsertSelectionMenu [success]");
	
	return(ST_SUCCESS);
}



int inDeleteQRPH_FromMenu(void)
{
	int result;
	char *sql = "DELETE FROM DMTrxMenu WHERE  szButtonItemLabel='BDO LOYALTY'";	
	int inDBResult =0 ;
	
	char szMenuFilename[FILENAME_SIZE] = {0};


	memset(szMenuFilename, 0x00, sizeof(szMenuFilename));
	if (strTCT.inMenuid > 99)
		sprintf(szMenuFilename, "./fs_data/DYNAMICMENU%03d.S3DB", strTCT.inMenuid);
	else
		sprintf(szMenuFilename, "./fs_data/DYNAMICMENU%02d.S3DB", strTCT.inMenuid);

	/* open the database */
	result = sqlite3_open(szMenuFilename,&db);
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

	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

    
	inDBResult = sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	
	vdDebug_LogPrintf("selectmenu delet,sqlite3_exec[%d]",inDBResult);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(ST_SUCCESS);
}
#endif


#ifdef BLT_REV_PFR
int inDatabase_BatchSaveRrtrieveDataPHQR(RTRV_BPT_TRANS_DATA_TABLE  *RtrvTransData, int inStoredType)
{
	int inResult;
    //TRANS_DATA_TABLE temptransData;
		
	vdDebug_LogPrintf("inDatabase_BatchSave inStoredType= %d", inStoredType);
	

    if (inStoredType == DF_BATCH_APPEND)
    {
		inResult = inDatabase_PHQRBatchInsertRetrieveData(RtrvTransData);
		if (inResult != ST_SUCCESS)
		{
			vdDebug_LogPrintf("inDatabase_BatchSaveRrtrieveDataBPT -- ERROR saving");
			return ST_ERROR;
		}

		
    }
    else
    {
       
	   vdDebug_LogPrintf("test retreive batch st error");
        return ST_ERROR;
    }




    
	vdDebug_LogPrintf("test retreive batch success");
    return ST_SUCCESS;
}



int inDatabase_PHQRBatchInsertRetrieveData(RTRV_BPT_TRANS_DATA_TABLE  *RtrvTransData)
{
	int result;	
	char *sql1 = "SELECT MAX(TransDataid) FROM PHQRRetrieveData";
 	char *sql = "INSERT INTO PHQRRetrieveData (TransDataid, HDTid, MITid, CDTid, IITid, szHostLabel, szBatchNo, byTransType, byPanLen, szExpireDate, byEntryMode, szTotalAmount, szBaseAmount, szTipAmount, byOrgTransType, szMacBlock, szYear, szDate, szTime, szOrgDate, szOrgTime, szAuthCode, szRRN, szInvoiceNo, szOrgInvoiceNo, byPrintType, byVoided, byAdjusted, byUploaded, byTCuploaded, szCardholderName, szzAMEX4DBC, szStoreID, szRespCode, szServiceCode, byContinueTrans, byOffline, byReversal, byEMVFallBack, shTransResult, szTpdu, szIsoField03, szMassageType, szPAN, szCardLable, usTrack1Len, usTrack2Len, usTrack3Len, szTrack1Data, szTrack2Data, szTrack3Data, usChipDataLen, baChipData, usAdditionalDataLen, baAdditionalData, bWaveSID,usWaveSTransResult,bWaveSCVMAnalysis, ulTraceNum, ulOrgTraceNum, usTerminalCommunicationMode, ulSavedIndex, byPINEntryCapability, byPackType, szOrgAmount, szCVV2, inCardType, byTCFailUpCnt, byCardTypeNum, byEMVTransStatus, T5A_len, T5A, T5F2A, T5F30, T5F34, T5F34_len, T82, T84_len, T84, T8A, T91, T91Len, T95, T9A, T9C, T9F02, T9F03, T9F09, T9F10_len, T9F10, T9F1A, T9F26, T9F27, T9F33, T9F34, T9F35, T9F36_len, T9F36, T9F37, T9F41, T9F53, ISR, ISRLen, T9B, T5F24, T71Len, T71, T72Len, T72, T9F06, T9F1E, T9F28, T9F29, szChipLabel, szTID, szMID, szHostLabel, szBatchNo, fFooterLogo, szDestCardNo, fECRTriggerTran, szPOSTID, byEMVReversal, inAccountType, szXMLbank_type, szXMLcash_fee, szXMLcash_fee_type, szXMLfee_type, szXMLlocal_fee_type, szXMLorder_fee, szXMLout_trade_no, szXMLout_transaction_id, szXMLplatform_rate, szXMLtime_start, szXMLtime_end, szXMLtotal_fee, szXMLlocal_total_fee, szXMLtransaction_id, szXMLcode_url, szTransactionID, szPartnerTxnID, szSodexo_TransID, fDisclaimer, fThankYouLine, fPrintTimeLine, fSignatureLine, szacquirementId, szMerchantTransId, szCorrelationID, inQrVersion) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";


	/* open the database */
	result = sqlite3_open(DB_BATCH,&db);
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

			RtrvTransData->ulSavedIndex = sqlite3_column_int(stmt,inStmtSeq);
			RtrvTransData->ulSavedIndex += 1;
		}
	} while (result == SQLITE_ROW);
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	
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
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->HDTid);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->MITid);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->CDTid);
    result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->IITid);
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szHostLabel, strlen((char*)RtrvTransData->szHostLabel), SQLITE_STATIC); 
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szBatchNo, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->byTransType);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->byPanLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szExpireDate, 10, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->byEntryMode, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szTotalAmount, 7, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szBaseAmount, 7, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szTipAmount, 7, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->byOrgTransType);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szMacBlock, 8, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szYear, 2, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szDate, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szTime, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szOrgDate, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szOrgTime, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szAuthCode, 7, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szRRN, 13, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szInvoiceNo, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szOrgInvoiceNo, 4, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->byPrintType);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->byVoided);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->byAdjusted);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->byUploaded);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->byTCuploaded);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szCardholderName, 31, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szzAMEX4DBC, 5, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szStoreID, 19, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szRespCode, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szServiceCode, 4, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->byContinueTrans);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->byOffline);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->byReversal);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->byEMVFallBack);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->shTransResult);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szTpdu, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szIsoField03, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szMassageType, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szPAN, 20, SQLITE_STATIC);
    result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szCardLable, 20, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->usTrack1Len);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->usTrack2Len);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->usTrack3Len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szTrack1Data, 86, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szTrack2Data, 42, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szTrack3Data, 65, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->usChipDataLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->baChipData, 1024, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->usAdditionalDataLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->baAdditionalData, 1024, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->bWaveSID);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->usWaveSTransResult);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->bWaveSCVMAnalysis);
	result = sqlite3_bind_double(stmt, inStmtSeq +=1, RtrvTransData->ulTraceNum);
	result = sqlite3_bind_double(stmt, inStmtSeq +=1, RtrvTransData->ulOrgTraceNum);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->usTerminalCommunicationMode);
	result = sqlite3_bind_double(stmt, inStmtSeq +=1, RtrvTransData->ulSavedIndex);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->byPINEntryCapability);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->byPackType);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szOrgAmount, 7, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szCVV2, 4, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->inCardType);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->byTCFailUpCnt);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.byCardTypeNum);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.byEMVTransStatus);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T5A_len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T5A, 10, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T5F2A, 2, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T5F30, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T5F34);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T5F34_len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T82, 2, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T84_len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T84, 16, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T8A, 2, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T91, 16, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T91Len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T95, 5, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9A, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9C);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F02, 6, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F03, 6, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F09, 2, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F10_len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F10, 32, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F1A, 2, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F26, 8, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F27);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F33, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F34, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F35);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F36_len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F36, 2, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F37, 4, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F41, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F53);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.ISR, 16, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.ISRLen);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9B, 2, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T5F24, 3, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T71Len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T71, 258, SQLITE_STATIC);
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T72Len);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T72, 258, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F06, 3, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F1E, 8, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F28, 8, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.T9F29, 8, SQLITE_STATIC);
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->stEMVinfo.szChipLabel, 32, SQLITE_STATIC);
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szTID, strlen((char*)RtrvTransData->szTID), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szMID, strlen((char*)RtrvTransData->szMID), SQLITE_STATIC); 
    result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szHostLabel, strlen((char*)RtrvTransData->szHostLabel), SQLITE_STATIC); 
    result = sqlite3_bind_blob(stmt, inStmtSeq +=1, RtrvTransData->szBatchNo, 3, SQLITE_STATIC);

		/*fFooterLogo -- sidumili*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->fFooterLogo);

	/*BDO: For Reload trxn -- sidumili */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szDestCardNo, strlen((char*)RtrvTransData->szDestCardNo), SQLITE_STATIC); 

	/*fECRTriggerTran*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->fECRTriggerTran);
	
	/*szPOSTID*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szPOSTID, strlen((char*)RtrvTransData->szPOSTID), SQLITE_STATIC); 

	/*byEMVReversal*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->byEMVReversal);

	/*inAccountType*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->inAccountType);

	// For Wechat -- sidumili
	/*szXMLbank_type*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szXMLbank_type, strlen((char*)RtrvTransData->szXMLbank_type), SQLITE_STATIC); 	
	/*szXMLcash_fee*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szXMLcash_fee, strlen((char*)RtrvTransData->szXMLcash_fee), SQLITE_STATIC); 	
	/*szXMLcash_fee_type*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szXMLcash_fee_type, strlen((char*)RtrvTransData->szXMLcash_fee_type), SQLITE_STATIC); 	
	/*szXMLfee_type*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szXMLfee_type, strlen((char*)RtrvTransData->szXMLfee_type), SQLITE_STATIC); 	
	/*szXMLlocal_fee_type*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szXMLlocal_fee_type, strlen((char*)RtrvTransData->szXMLlocal_fee_type), SQLITE_STATIC); 	
	/*szXMLorder_fee*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szXMLorder_fee, strlen((char*)RtrvTransData->szXMLorder_fee), SQLITE_STATIC); 	
	/*szXMLout_trade_no*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szXMLout_trade_no, strlen((char*)RtrvTransData->szXMLout_trade_no), SQLITE_STATIC); 	
	/*szXMLout_transaction_id*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szXMLout_transaction_id, strlen((char*)RtrvTransData->szXMLout_transaction_id), SQLITE_STATIC); 	
	/*szXMLplatform_rate*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szXMLplatform_rate, strlen((char*)RtrvTransData->szXMLplatform_rate), SQLITE_STATIC); 
	/*szXMLtime_start*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szXMLtime_start, strlen((char*)RtrvTransData->szXMLtime_start), SQLITE_STATIC); 	
	/*szXMLtime_end*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szXMLtime_end, strlen((char*)RtrvTransData->szXMLtime_end), SQLITE_STATIC); 	
	/*szXMLtotal_fee*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szXMLtotal_fee, strlen((char*)RtrvTransData->szXMLtotal_fee), SQLITE_STATIC);
	/*szXMLlocal_total_fee*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szXMLlocal_total_fee, strlen((char*)RtrvTransData->szXMLlocal_total_fee), SQLITE_STATIC);
	/*szXMLtransaction_id*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szXMLtransaction_id, strlen((char*)RtrvTransData->szXMLtransaction_id), SQLITE_STATIC); 
	/*szXMLcode_url*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szXMLcode_url, strlen((char*)RtrvTransData->szXMLcode_url), SQLITE_STATIC); 
	/*szTransactionID*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szTransactionID, strlen((char*)RtrvTransData->szTransactionID), SQLITE_STATIC); 
	/*szPartnerTxnID*/
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szPartnerTxnID, strlen((char*)RtrvTransData->szPartnerTxnID), SQLITE_STATIC); 
	//SODEXO 
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szSodexo_TransID, strlen((char*)RtrvTransData->szSodexo_TransID), SQLITE_STATIC); 
	//fDisclaimer
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->fDisclaimer);
	//fThankYouLine
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->fThankYouLine);
	//fPrintTimeLine
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->fPrintTimeLine);
	//fSignatureLine
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->fSignatureLine);
	//szacquirementId
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szacquirementId, strlen((char*)RtrvTransData->szacquirementId), SQLITE_STATIC);
	//szMerchantTransId
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szMerchantTransId, strlen((char*)RtrvTransData->szMerchantTransId), SQLITE_STATIC);
	//szCorrelationID
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)RtrvTransData->szCorrelationID, strlen((char*)RtrvTransData->szCorrelationID), SQLITE_STATIC);
	/*inQrVersion*/
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, RtrvTransData->inQrVersion);
		
	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

{
	
	BYTE szTemp[30+10];
	memset(szTemp,0x00,sizeof(szTemp));
	//wub_hex_2_str(srPHQRRtrvTransRec.szExpireDate, szTemp,EXPIRY_DATE_BCD_SIZE);	
	vdDebug_LogPrintf("inDatabase_PHQRBatchInsertRetrieveData SAVE TO RTRV szExpireDate[%s]",srPHQRRtrvTransRec.szExpireDate);
}
    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(ST_SUCCESS);
}




int inDatabase_PHQRBatchSearchRetrieveData(RTRV_BPT_TRANS_DATA_TABLE  *RtrvTransData, char *hexInvoiceNo)
{
	int result,i = 0;
	int inResult = d_NO;
	#if 1
	char *sql = "SELECT HDTid, MITid, CDTid, IITid, byTransType, byPanLen, szExpireDate, byEntryMode, szTotalAmount, szBaseAmount, szTipAmount, byOrgTransType, szMacBlock, szYear, szDate, szTime, szOrgDate, szOrgTime, szAuthCode, szRRN, szInvoiceNo, szOrgInvoiceNo, byPrintType, byVoided, byAdjusted, byUploaded, byTCuploaded, szCardholderName, szzAMEX4DBC, szStoreID, szRespCode, szServiceCode, byContinueTrans, byOffline, byReversal, byEMVFallBack, shTransResult, szTpdu, szIsoField03, szMassageType, szPAN, szCardLable, usTrack1Len, usTrack2Len, usTrack3Len, szTrack1Data, szTrack2Data, szTrack3Data, usChipDataLen, baChipData, usAdditionalDataLen, baAdditionalData, bWaveSID,usWaveSTransResult,bWaveSCVMAnalysis,ulTraceNum, ulOrgTraceNum, usTerminalCommunicationMode, ulSavedIndex, byPINEntryCapability, byPackType, szOrgAmount, szCVV2, inCardType, byTCFailUpCnt, byCardTypeNum, byEMVTransStatus, T5A_len, T5A, T5F2A, T5F30, T5F34, T5F34_len, T82, T84_len, T84, T8A, T91, T91Len, T95, T9A, T9C, T9F02, T9F03, T9F09, T9F10_len, T9F10, T9F1A, T9F26, T9F27, T9F33, T9F34, T9F35, T9F36_len, T9F36, T9F37, T9F41, T9F53, ISR, ISRLen, T9B, T5F24, T71Len, T71, T72Len, T72, T9F06, T9F1E, T9F28, T9F29, szChipLabel, szTID, szMID, szHostLabel, szBatchNo, fFooterLogo, szDestCardNo, fECRTriggerTran, szPOSTID,  byEMVReversal, inAccountType, szXMLbank_type, szXMLcash_fee, szXMLcash_fee_type, szXMLfee_type, szXMLlocal_fee_type, szXMLorder_fee, szXMLout_trade_no, szXMLout_transaction_id, szXMLplatform_rate, szXMLtime_start, szXMLtime_end, szXMLtotal_fee, szXMLlocal_total_fee, szXMLtransaction_id, szXMLcode_url, szRefundID, szTransactionID, szPartnerTxnID, szSodexo_TransID, fDisclaimer, fThankYouLine, fPrintTimeLine, fSignatureLine, szacquirementId, szMerchantTransId, szCorrelationID, inQrVersion FROM PHQRRetrieveData WHERE szInvoiceNo = ?";
	#else
	char *sql = "SELECT HDTid, MITid, CDTid, IITid, byTransType, byPanLen, szExpireDate, byEntryMode, szTotalAmount, szBaseAmount, szTipAmount, byOrgTransType, szMacBlock, szYear, szDate, szTime, szOrgDate, szOrgTime, szAuthCode, szRRN, szInvoiceNo, szOrgInvoiceNo, byPrintType, byVoided, byAdjusted, byUploaded, byTCuploaded, szCardholderName, szzAMEX4DBC, szStoreID, szRespCode, szServiceCode, byContinueTrans, byOffline, byReversal, byEMVFallBack, shTransResult, szTpdu, szIsoField03, szMassageType, szPAN, szCardLable, usTrack1Len, usTrack2Len, usTrack3Len, szTrack1Data, szTrack2Data, szTrack3Data, usChipDataLen, baChipData, usAdditionalDataLen, baAdditionalData, bWaveSID,usWaveSTransResult,bWaveSCVMAnalysis,ulTraceNum, ulOrgTraceNum, usTerminalCommunicationMode, ulSavedIndex, byPINEntryCapability, byPackType, szOrgAmount, szCVV2, inCardType, byTCFailUpCnt, byCardTypeNum, byEMVTransStatus, T5A_len, T5A, T5F2A, T5F30, T5F34, T5F34_len, T82, T84_len, T84, T8A, T91, T91Len, T95, T9A, T9C, T9F02, T9F03, T9F09, T9F10_len, T9F10, T9F1A, T9F26, T9F27, T9F33, T9F34, T9F35, T9F36_len, T9F36, T9F37, T9F41, T9F53, ISR, ISRLen, T9B, T5F24, T71Len, T71, T72Len, T72, T9F06, T9F1E, T9F28, T9F29, szChipLabel, szTID, szMID, szHostLabel, szBatchNo, fFooterLogo, szDestCardNo, fECRTriggerTran, szPOSTID,	byEMVReversal, inAccountType, szXMLbank_type, szXMLcash_fee, szXMLcash_fee_type, szXMLfee_type, szXMLlocal_fee_type, szXMLorder_fee, szXMLout_trade_no, szXMLout_transaction_id, szXMLplatform_rate, szXMLtime_start, szXMLtime_end, szXMLtotal_fee, szXMLlocal_total_fee, szXMLtransaction_id, szXMLcode_url, szRefundID, szTransactionID, szPartnerTxnID, szSodexo_TransID, fDisclaimer, fThankYouLine, fPrintTimeLine, fSignatureLine, szacquirementId, szMerchantTransId FROM TransData WHERE szInvoiceNo = ?";
		

	#endif

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
	result = sqlite3_bind_blob(stmt, inStmtSeq +=1, hexInvoiceNo, 4, SQLITE_STATIC);

	DebugAddINT("inDatabase_BatchSearch sqlite3_bind_blob", result);
	DebugAddHEX("hexInvoiceNo", hexInvoiceNo, 3);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		i++;
		DebugAddINT("if(100)=Find", result);
		DebugAddINT("Loop Count", i);

		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;

			RtrvTransData->HDTid = sqlite3_column_int(stmt,inStmtSeq);
			RtrvTransData->MITid = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->CDTid = sqlite3_column_int(stmt,inStmtSeq +=1 );
            RtrvTransData->IITid = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->byTransType = sqlite3_column_int(stmt,inStmtSeq+=1 );
			RtrvTransData->byPanLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->szExpireDate, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);	
			memcpy(RtrvTransData->byEntryMode, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);
			memcpy(RtrvTransData->szTotalAmount, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);						
			memcpy(RtrvTransData->szBaseAmount, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);						
			memcpy(RtrvTransData->szTipAmount, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);						
			RtrvTransData->byOrgTransType = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->szMacBlock, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 8);						
			memcpy(RtrvTransData->szYear, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);						
			memcpy(RtrvTransData->szDate, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			memcpy(RtrvTransData->szTime, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);						
			memcpy(RtrvTransData->szOrgDate, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			memcpy(RtrvTransData->szOrgTime, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);						
			memcpy(RtrvTransData->szAuthCode, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);						
			memcpy(RtrvTransData->szRRN, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 13);						
			memcpy(RtrvTransData->szInvoiceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);						
			memcpy(RtrvTransData->szOrgInvoiceNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);						
			RtrvTransData->byPrintType = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->byVoided = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->byAdjusted = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->byUploaded = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->byTCuploaded = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->szCardholderName, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 31);						
			memcpy(RtrvTransData->szzAMEX4DBC, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);						
			memcpy(RtrvTransData->szStoreID, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 19);						
			memcpy(RtrvTransData->szRespCode, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			memcpy(RtrvTransData->szServiceCode, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);						
			RtrvTransData->byContinueTrans = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->byOffline = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->byReversal = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->byEMVFallBack = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->shTransResult = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->szTpdu, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);						
			memcpy(RtrvTransData->szIsoField03, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);						
			memcpy(RtrvTransData->szMassageType, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			memcpy(RtrvTransData->szPAN, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 20);	
            memcpy(RtrvTransData->szCardLable, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 20);
			RtrvTransData->usTrack1Len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->usTrack2Len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->usTrack3Len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->szTrack1Data, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 86);						
			memcpy(RtrvTransData->szTrack2Data, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 42);						
			memcpy(RtrvTransData->szTrack3Data, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 65);						
			RtrvTransData->usChipDataLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->baChipData, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 1024);
			RtrvTransData->usAdditionalDataLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->baAdditionalData, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 1024);			
			RtrvTransData->bWaveSID = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->usWaveSTransResult = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->bWaveSCVMAnalysis = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->ulTraceNum = sqlite3_column_double(stmt, inStmtSeq +=1 );
			RtrvTransData->ulOrgTraceNum = sqlite3_column_double(stmt, inStmtSeq +=1 );			
			RtrvTransData->usTerminalCommunicationMode = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->ulSavedIndex = sqlite3_column_double(stmt, inStmtSeq +=1 );			
			RtrvTransData->byPINEntryCapability = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->byPackType = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->szOrgAmount, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 7);						
			memcpy(RtrvTransData->szCVV2, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);
			RtrvTransData->inCardType = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->byTCFailUpCnt = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->stEMVinfo.byCardTypeNum = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->stEMVinfo.byEMVTransStatus = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->stEMVinfo.T5A_len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->stEMVinfo.T5A, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 10);						
			memcpy(RtrvTransData->stEMVinfo.T5F2A, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);						
			memcpy(RtrvTransData->stEMVinfo.T5F30, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			RtrvTransData->stEMVinfo.T5F34 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->stEMVinfo.T5F34_len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->stEMVinfo.T82, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);						
			RtrvTransData->stEMVinfo.T84_len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->stEMVinfo.T84, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 16);						
			memcpy(RtrvTransData->stEMVinfo.T8A, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);						
			memcpy(RtrvTransData->stEMVinfo.T91, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 16);						
			RtrvTransData->stEMVinfo.T91Len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->stEMVinfo.T95, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 5);						
			memcpy(RtrvTransData->stEMVinfo.T9A, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			RtrvTransData->stEMVinfo.T9C = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->stEMVinfo.T9F02, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 6);						
			memcpy(RtrvTransData->stEMVinfo.T9F03, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 6);						
			memcpy(RtrvTransData->stEMVinfo.T9F09, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);						
			RtrvTransData->stEMVinfo.T9F10_len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->stEMVinfo.T9F10, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 32);						
			memcpy(RtrvTransData->stEMVinfo.T9F1A, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);						
			memcpy(RtrvTransData->stEMVinfo.T9F26, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 8);						
			RtrvTransData->stEMVinfo.T9F27 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->stEMVinfo.T9F33, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			memcpy(RtrvTransData->stEMVinfo.T9F34, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			RtrvTransData->stEMVinfo.T9F35 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			RtrvTransData->stEMVinfo.T9F36_len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->stEMVinfo.T9F36, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);						
			memcpy(RtrvTransData->stEMVinfo.T9F37, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 4);						
			memcpy(RtrvTransData->stEMVinfo.T9F41, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			RtrvTransData->stEMVinfo.T9F53 = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->stEMVinfo.ISR, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 16);						
			RtrvTransData->stEMVinfo.ISRLen = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->stEMVinfo.T9B, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 2);						
			memcpy(RtrvTransData->stEMVinfo.T5F24, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			RtrvTransData->stEMVinfo.T71Len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->stEMVinfo.T71, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 258);						
			RtrvTransData->stEMVinfo.T72Len = sqlite3_column_int(stmt,inStmtSeq +=1 );
			memcpy(RtrvTransData->stEMVinfo.T72, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 258);						
			memcpy(RtrvTransData->stEMVinfo.T9F06, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);						
			memcpy(RtrvTransData->stEMVinfo.T9F1E, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 8);						
			memcpy(RtrvTransData->stEMVinfo.T9F28, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 8);						
			memcpy(RtrvTransData->stEMVinfo.T9F29, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 8);						
			memcpy(RtrvTransData->stEMVinfo.szChipLabel, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 32);
            strcpy((char*)RtrvTransData->szTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)RtrvTransData->szMID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            strcpy((char*)RtrvTransData->szHostLabel, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            memcpy(RtrvTransData->szBatchNo, sqlite3_column_blob(stmt,inStmtSeq +=1 ), 3);

			/*fFooterLogo -- sidumili*/
			RtrvTransData->fFooterLogo = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*BDO: For Reload trxn -- sidumili*/
			strcpy((char*)RtrvTransData->szDestCardNo, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*fECRTriggerTran*/
			RtrvTransData->fECRTriggerTran = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szPOSTID*/
			strcpy((char*)RtrvTransData->szPOSTID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			/*byEMVReversal*/
			RtrvTransData->byEMVReversal = sqlite3_column_int(stmt,inStmtSeq +=1 );

			/*inAccountType*/	
			RtrvTransData->inAccountType = sqlite3_column_int(stmt,inStmtSeq +=1 );

			// For Wechat -- sidumili
			/*szXMLbank_type*/
			strcpy((char*)RtrvTransData->szXMLbank_type, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*szXMLcash_fee*/
			strcpy((char*)RtrvTransData->szXMLcash_fee, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*szXMLcash_fee_type*/
			strcpy((char*)RtrvTransData->szXMLcash_fee_type, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*szXMLfee_type*/
			strcpy((char*)RtrvTransData->szXMLfee_type, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*szXMLlocal_fee_type*/
			strcpy((char*)RtrvTransData->szXMLlocal_fee_type, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*szXMLorder_fee*/
			strcpy((char*)RtrvTransData->szXMLorder_fee, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*szXMLout_trade_no*/
			strcpy((char*)RtrvTransData->szXMLout_trade_no, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*szXMLout_transaction_id*/
			strcpy((char*)RtrvTransData->szXMLout_transaction_id, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*szXMLplatform_rate*/
			strcpy((char*)RtrvTransData->szXMLplatform_rate, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*szXMLtime_start*/
			strcpy((char*)RtrvTransData->szXMLtime_start, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*szXMLtime_end*/
			strcpy((char*)RtrvTransData->szXMLtime_end, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*szXMLtotal_fee*/
			strcpy((char*)RtrvTransData->szXMLtotal_fee, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*szXMLlocal_total_fee*/
			strcpy((char*)RtrvTransData->szXMLlocal_total_fee, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*szXMLtransaction_id*/
			strcpy((char*)RtrvTransData->szXMLtransaction_id, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*szXMLcode_url*/
			strcpy((char*)RtrvTransData->szXMLcode_url, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*szRefundID*/
			strcpy((char*)RtrvTransData->szRefundID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*szTransactionID*/
			strcpy((char*)RtrvTransData->szTransactionID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*szPartnerTxnID*/
			strcpy((char*)RtrvTransData->szPartnerTxnID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			//SODEXO 
			strcpy((char*)RtrvTransData->szSodexo_TransID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			//fDisclaimer
			RtrvTransData->fDisclaimer = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			//fThankYouLine
			RtrvTransData->fThankYouLine = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			//fPrintTimeLine
			RtrvTransData->fPrintTimeLine = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			//fSignatureLine
			RtrvTransData->fSignatureLine = fGetBoolean((BYTE *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			//szacquirementId
			strcpy((char*)RtrvTransData->szacquirementId, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			//szMerchantTransId
			strcpy((char*)RtrvTransData->szMerchantTransId, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));

			#if 1 //for testing
			//szCorrelationID
			strcpy((char*)RtrvTransData->szCorrelationID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1));
			/*inQrVersion*/	
			RtrvTransData->inQrVersion= sqlite3_column_int(stmt,inStmtSeq +=1 );
			#endif
		}
	} while (result == SQLITE_ROW);

    DebugAddSTR("batch serPAN", RtrvTransData->szPAN, 10);
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(inResult);
}


int inDatabase_PHQRBatchDeleteRetrieveData(void)
{
	int result;
	char *sql = "DELETE FROM PHQRRetrieveData";	
	int inDBResult = 0;
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
	//result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srTransRec.szHostLabel, strlen((char*)srTransRec.szHostLabel), SQLITE_STATIC); 
	//result = sqlite3_bind_blob(stmt, inStmtSeq +=1, srTransRec.szBatchNo, 3, SQLITE_STATIC);
	//result = sqlite3_bind_int(stmt, inStmtSeq +=1, srTransRec.MITid);


	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

    
	inDBResult = sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	
	vdDebug_LogPrintf("Batch dele,sqlite3_exec[%d]MITid[%d]",inDBResult,srTransRec.MITid);
	vdDebug_LogPrintf("inDatabase_PHQRBatchDeleteRetrieveData, SUCCESFUL!!!");

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return(ST_SUCCESS);
}


#endif

