#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctosapi.h>
#include <vwdleapi.h>
#include <sqlite3.h>

#include "..\Includes\POSTypedef.h"
#include "..\Debug\Debug.h"

#include "..\Includes\POSMain.h"
#include "..\Includes\POSTrans.h"
#include "..\Includes\POSHost.h"
#include "..\Includes\POSSale.h"
#include "..\Includes\POSbatch.h"
#include "..\ui\Display.h"
#include "..\Includes\V5IsoFunc.h"
#include "..\Accum\Accum.h"
#include "..\print\Print.h"
#include "..\Comm\V5Comm.h"
#include "..\Includes\MultiApLib.h"
#include "..\Aptrans\MultiAptrans.h"
#include "..\Includes\Wub_lib.h"
#include "..\Database\DatabaseFunc.h"
#include "..\ApTrans\MultiShareEMV.h"
#include "..\Includes\CardUtil.h"
#include "..\Includes\POSSetting.h"
#include "..\PCI100\COMMS.h"

#include "..\POWRFAIL\POSPOWRFAIL.h"
#include "../Ctls/POSCtls.h"
#include "..\Includes\POSDCC.h"

extern int isPredial;

extern VS_BOOL fPreConnectEx;
extern BOOL fSmacScan;


extern BOOL fSkipBINRoutingForDebit;

#include "POSCtls.h"
#include "POSWave.h"

int inWaveTransType = 0;
extern BOOL fIdleSwipe;

/*sidumili: added */
extern BOOL fBINVer;

extern BOOL fRouteToSpecificHost;

BOOL fUSDSelected;

extern BOOL fDualBrandedCard;
extern BOOL fMagStripeDebit;
extern BOOL fBinRouteDCC;

//version 16
extern BYTE szBarcodeText[50];


/* BDO: Last 4 PAN digit checking - start -- jzg */
extern int inBDOEnterLast4Digits(BOOL fInstallment);

/* For ECR -- sidumili */
extern BOOL fECRBuildSendOK; 
extern BOOL fTimeOutFlag; /*BDO: Flag for timeout --sidumili*/
/* For ECR -- sidumili */

extern BOOL fEntryCardfromIDLE;
extern BOOL fIdleInsert;
extern BOOL fIdleSwipe;

BOOL fAutoSMACLogon=FALSE;

extern BOOL fBINVerPreConnectEx;
extern BOOL fNoCTLSSupportforBinRoute;
extern BOOL fMagStripeCUP;
BOOL fReEnterOfflinePIN;
BOOL fNoEMVProcess = FALSE;
extern int inGblCtlsErr;
extern BOOL fAMEXHostEnable;
extern BOOL fCommsFallback;
extern int inCommsFallbackMode;
//extern BOOL fOptOutFlag;
extern BOOL fBDOOptOutHostEnabled;
extern int inReversalType;

extern BOOL fCTLSfromECR;
extern BOOL fAmountFromIdle;
extern BOOL fPANEntryFromECR;

void vdCTOSS_SetWaveTransType(int type)
{
	inWaveTransType = type;
}

int inCTOSS_GetWaveTransType(void)
{
	return inWaveTransType;
}
int inCTOSS_CLMSetCustomEMVTags(void)
{
	sqlite3 * dbWave;
	sqlite3_stmt *stmtWave;
	int inStmtSeqWave = 0;
	BYTE baBuf[16+1];

	BYTE buf[100];
	UINT len;
	ULONG rtn;
 	char setbuf[100];
	int inlen=0;

	char szName[100+1];
	char szTag[10+1];
	char szValue[200+1];
	char szTagHex[10+1];
	char szValueHex[200+1];
	char inbuf[1024];
	int inBufLen = 0;	
	int inTaglen = 0;
	int inValuelen = 0;

	int result;
	int inResult = d_NO;
	char *sql = "SELECT szName, szTag, szValue FROM TAGS";

	vdDebug_LogPrintf("inCTOSS_CLMSetCustomEMVTags"); 
	inCTOSS_CLMOpenAndGetVersion();
	if (CTLS_EXTERNAL == inCTOSS_GetCtlsMode())
	{
		rtn = MsessionAuthenAdmin();
		vdDebug_LogPrintf("rtn =[%x]........",rtn);
		if (rtn != d_NO_ERROR) 
		{
			vdDisplayErrorMsg(1, 8, "Authen Fail");
			return ;
		}
		
		rtn = VW_SwitchToAdministrativeMode(d_VW_MODE_ADMIN,baBuf);
		vdDebug_LogPrintf("rtn =[%x],baBuf=[%s].....",rtn,baBuf);
	}

	/* open the database */
	result = sqlite3_open(DB_WAVE,&dbWave);
	if (result != SQLITE_OK) {
		sqlite3_close(dbWave);
		return 1;
	}
	
	sqlite3_exec( dbWave, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(dbWave, sql, -1, &stmtWave, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(dbWave);
		return 2;
	}
	
	inStmtSeqWave = 0;

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmtWave);
		
		//vdDebug_LogPrintf("strAIDT.result[%d]AIDid[%d]",result,inSeekCnt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeqWave = 0;
			
			/* szName*/
			strcpy((char*)szName, (char *)sqlite3_column_text(stmtWave,inStmtSeqWave));
			/* szTag*/
			strcpy((char*)szTag, (char *)sqlite3_column_text(stmtWave,inStmtSeqWave +=1 ));
			/* szValue*/
			strcpy((char*)szValue, (char *)sqlite3_column_text(stmtWave,inStmtSeqWave +=1 ));

			vdDebug_LogPrintf("szName=[%s].szTag=[%s].szValue=[%s]",szName, szTag, szValue);

			wub_str_2_hex((unsigned char *)szTag, (unsigned char *)szTagHex, strlen((char *)szTag));
			wub_str_2_hex((unsigned char *)szValue, (unsigned char *)szValueHex, strlen((char *)szValue));

			inTaglen = strlen((char *)szTag)/2;
			inValuelen = strlen((char *)szValue)/2;
			
			DebugAddHEX("szTagHex", szTagHex, inTaglen);
			DebugAddHEX("szValueHex", szValueHex, inValuelen);

			inBufLen = 0;
			memset(inbuf, 0x00, sizeof(inbuf));

			inbuf[inBufLen++] = 0x01;

			if (inTaglen == 1)
            {
                inbuf[inBufLen++] = szTag[0];                            
            }
            else
            {
				memcpy(&inbuf[inBufLen], szTagHex, inTaglen);
				inBufLen = inBufLen + inTaglen;
            }

			inbuf[inBufLen++] = inValuelen;
			
            if (inValuelen == 1)
            {
                    inbuf[inBufLen++] = szValueHex[0];                            
                    inlen =  inBufLen;
            }
            else
            {
                    memcpy(&inbuf[inBufLen], szValueHex, inValuelen);                        
                    inlen =  inBufLen + inValuelen;
            }

			DebugAddHEX("Set Tag Data1", inbuf, inlen);
			
			if (CTLS_INTERNAL == inCTOSS_GetCtlsMode())
				rtn = EMVCL_SetEMVTags(inbuf, inlen, buf, &len);
			if (CTLS_EXTERNAL == inCTOSS_GetCtlsMode())
				rtn = VW_SetEMVTags(inbuf, inlen, buf, &len);
		
			DebugAddHEX("Set Tag Data2", inbuf, inlen);
			vdDebug_LogPrintf("rtn =[%x].inlen=[%d].len=[%d]...",rtn,inlen,len);
			if(rtn != d_EMVCL_NO_ERROR)
			{
				return rtn;
			}
			
 			if(inlen != len)
			{
				return 0xD0000001;
			}
			DebugAddHEX("Set Tag Data Resopnse", buf, len);
		//	if(memcmp(d_SET_TAG, buf, len) != 0)
			if(memcmp(inbuf, buf, len) != 0)
			{
				return 0xD0000002;
			}
		}
	} while (result == SQLITE_ROW);    

	if (CTLS_EXTERNAL == inCTOSS_GetCtlsMode())
	rtn = VW_SwitchToAdministrativeMode(d_VW_MODE_NORMAL,baBuf);
	vdDebug_LogPrintf("rtn =[%x],baBuf=[%s].....",rtn,baBuf);
	
	vdCTOSS_CLMClose();
	
	sqlite3_exec(dbWave,"commit;",NULL,NULL,NULL);
	//�ر�sqlite����
	sqlite3_finalize(stmtWave);
	sqlite3_close(dbWave);

	return(inResult);
}

/*
void vdCTOS_InitWaveData(void)
{
	vdCTOSS_CLMSetALLCAPK();
	vdCTOSS_CLMSetAIDAndEMVTag();	
	inCTOSS_CLMSetCustomEMVTags();
}
*/

void vdCTOSS_GetALLWaveSetting(void)
{
	BYTE OutRBuf[2048];
	UINT outLen,rtn;
	EMVCL_SCHEME_DATA stScheme;
	EMVCL_CA_PUBLIC_KEY stCAPubKey;

	inCTOSS_CLMOpenAndGetVersion();

	if (CTLS_EXTERNAL == inCTOSS_GetCtlsMode())
	{
		rtn = MsessionAuthenAdmin();
		vdDebug_LogPrintf("rtn =[%x]........",rtn);
        if (rtn != d_NO_ERROR) 
		{
			vdDisplayErrorMsg(1, 8, "Authen Fail");
			return ;
        }
		
		rtn = VW_SwitchToAdministrativeMode(d_VW_MODE_ADMIN,OutRBuf);
		vdDebug_LogPrintf("rtn =[%x],baBuf=[%s].....",rtn,OutRBuf);
	}
		
	inCTOSS_CLMGetEMVTag(OutRBuf,&outLen);
	inCTOSS_CLMVisaGetCapability(&stScheme);

	if (CTLS_EXTERNAL == inCTOSS_GetCtlsMode())
		rtn = VW_SwitchToAdministrativeMode(d_VW_MODE_NORMAL,OutRBuf);
		vdDebug_LogPrintf("rtn =[%x],baBuf=[%s].....",rtn,OutRBuf);
		
	vdCTOSS_CLMClose();
		
	inCTOSS_CLMListAllCAPKID(OutRBuf,&outLen);

	inCTOSS_CLMGetACAPK("\xA0\x00\x00\x00\x03",0x08,&stCAPubKey);
}



int inCTOS_MultiAPReloadWaveData(void)
{
	if (srTransRec.usChipDataLen > 0)
	{			
		vdCTOSS_WaveGetEMVData(srTransRec.baChipData, srTransRec.usChipDataLen);
	}
		
	if (srTransRec.usAdditionalDataLen > 0)
	{			
		vdCTOSS_WaveGetEMVData(srTransRec.baAdditionalData, srTransRec.usAdditionalDataLen);
	}
	
	return (d_OK);
}

#if 0

int inCTOS_WaveFlowProcess(void)

{
    int inRet = d_NO;
	int inRetVal = d_NO;
    USHORT ushEMVtagLen;
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];
	int inEVENT_ID = 0;
    BOOL fBinRoute=TRUE;
	int inSMCardRetryCount=0;
	char szTemp1[d_LINE_SIZE + 1];
	fECRBuildSendOK = FALSE; /* BDO: For ECR -- sidumili */
	fTimeOutFlag = FALSE; /*BDO: Flag for timeout --sidumili*/
	put_env_int("SMCARDRETRY",0);
	put_env_int("SMCARDRETRYCOUNT",0);
	vdCTOS_SetTransType(SALE);

	memset(&stRCDataAnalyze,0x00,sizeof(EMVCL_RC_DATA_ANALYZE));

	
/*	inRet = inCTOS_PreConnectEx();
	if(d_OK != inRet)
		return inRet;
*/

   if(srTransRec.usTerminalCommunicationMode == DIAL_UP_MODE && srTransRec.fBINVer == TRUE)
   {
	   if (strTCT.fSingleComms && (fPreConnectEx == FALSE || fBINVerPreConnectEx == FALSE)){
			   inRet = inCTOS_PreConnectEx();
	   
			   if (inRet != d_OK)
				   return inRet;
		   }
   }

    if(fEntryCardfromIDLE == TRUE && (srTransRec.byEntryMode == CARD_ENTRY_ICC || srTransRec.byEntryMode == CARD_ENTRY_MSR)){		
		
	    //if (strTCT.byCtlsMode == 0)
				inRet = inCTOS_GetCardFields();
			//else
	    	//inRet = inCTOS_WaveGetCardFields();
		
	
    	if(d_OK != inRet)
        	return inRet;

		inRet=inCTOS_SelectCurrencyfromIDLE();
		if(d_OK != inRet)
			return inRet;

		if(inFLGGet("fDebitDualCurrency") == FALSE)
		{
			if((strcmp(strHDT.szAPName,"V5S_BDODEBIT") == 0) && strCST.inCurrencyIndex != CURRENCY_PHP)
			{
				vdDisplayErrorMsgResp2("DEBIT", "NOT ALLOWED", "FOR USD");
				return d_NO;
			}
		}
	}

    #if 0
	if (fIdleSwipe == TRUE){
		inRet=inReadIDLEMSD();
		if (inRet == USER_ABORT || inRet == INVALID_CARD){ 	
			clearLine(1);
			return d_NO;
		}


    	if(d_OK != inRet)
        	return inRet;
		
	    if (strTCT.byCtlsMode == 0)
				inRet = inCTOS_GetCardFields();
			else
	    	inRet = inCTOS_WaveGetCardFields();
		
	
    	if(d_OK != inRet)
        	return inRet;
	}
	#endif
	
	vdDebug_LogPrintf("fDebitInsertEnable[%d] :: srTransRec.byEntryMode[%d] :: strCDT.HDTid[%d]",strTCT.fDebitInsertEnable,srTransRec.byEntryMode,strCDT.HDTid);
	if (strTCT.fDebitInsertEnable == FALSE && srTransRec.byEntryMode == CARD_ENTRY_ICC && 
		(strCDT.HDTid == DEBIT_HDT_INDEX || strCDT.HDTid == DEBIT2_HDT_INDEX))
	{	
		vdInstallmentPromptToSwipe();
        vdCTOS_ResetMagstripCardData();
        inRet = inCTOS_GetCardFieldsSwipeOnly();
        if(d_OK != inRet)
            return inRet;	
	}
    
    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;

#if 0
//for enhance the treansaction speed
	vdDebug_LogPrintf("GOC 3 = [%d]", strCDT.HDTid);

    //inRet = inCTOS_SelectHost(); // Check if Host is enabled
    inRet = inCTOS_SelectHostEx2();
    if(d_OK != inRet)
        return inRet;

    //if (inMMTReadRecord(strCDT.HDTid,srTransRec.MITid) != d_OK) // Also check if Merchant using host is enabled
    if (inMMTReadRecordEx(strCDT.HDTid,srTransRec.MITid) != d_OK) // Also check if Merchant using host is enabled
    {
        vdDisplayErrorMsgResp2(" ", "TRANSACTION", "NOT ALLOWED");
		inDatabase_TerminalCloseDatabase();
        return(d_NO);
    }	
	inDatabase_TerminalCloseDatabase();

	inRet = inCTOS_PreConnectAndInit();
		if(d_OK != inRet)
			return inRet;
#else
    //inRet = inCTOS_PreConnectAndInit();
    //if(d_OK != inRet)
    //    return inRet;
#endif	

    //SIT-start
    if (inCTOS_ValidFirstIdleKey() == d_OK){
        
		inRet = inCTOS_GetTxnBaseAmount();
		if(d_OK != inRet)
			return inRet;

    	if (!fBINVer){
			inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
			if(d_OK != inRet)
				return inRet;
    	}
    }else{
	
    	if (!fBINVer){
			inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
			if(d_OK != inRet)
				return inRet;
	   	}

		if(fIdleSwipe == TRUE || fIdleInsert == TRUE)//If sale is accessed via menu, dual currency menu should be prompted.
		{		
		}
		else
		{
			inRet=inCTOS_SelectCurrencyEx();
			if(d_OK != inRet)
				return inRet;
		}
	
		inRet = inCTOS_GetTxnBaseAmount();
    	if(d_OK != inRet)
        	return inRet;
    }


    inRet = inCTOS_PreConnectAndInit();
    if(d_OK != inRet)
        return inRet;
	else if((srTransRec.usTerminalCommunicationMode == GPRS_MODE || srTransRec.usTerminalCommunicationMode == WIFI_MODE) 
		&& (fIdleSwipe == TRUE || fIdleInsert == TRUE))// Added delay to fix issue where terminal does not react to keypress after preconnect using SHARLS_COM
	{
		vdClearBelowLine(2);
		vdCTOS_DispStatusMessage("PROCESSING...");  
		WaitKey(1);
	}
	

/*
    if (strTCT.fSingleComms){	
		inRet = inCTOS_PreConnectEx();

		if (inRet != d_OK)
			return inRet;
	}
*/

//SIT-end
SWIPE_AGAIN:
		fBinRoute = TRUE;
		if (fBINVer){
			inRet = inCTOS_GetCardFields();
		}
		else{    
	    if (strTCT.byCtlsMode == 0)
				inRet = inCTOS_GetCardFields();
			else
	    	inRet = inCTOS_WaveGetCardFields();
		}
    if (USER_ABORT == inRet || READ_CARD_TIMEOUT == inRet || INVALID_CARD == inRet || LOGON_FAILED == inRet)
        return inRet;
    else if(inRet == CTLS_ANALYZE_ERROR || inRet == CTLS_EXPIRED_CARD)//Prompt user to Swipe/Insert card on Analyze error or Expired card on CTLS.
	{
		inGblCtlsErr=2;
		vdResetAllCardData();
		inRet = inCTOS_GetCardFieldsFailedCtlsFallbackEx();
		if(d_OK != inRet)
        	return inRet;
	}
	else if (d_OK != inRet)
        goto SWIPE_AGAIN;


	if(inFLGGet("fDebitDualCurrency") == FALSE)
	{
		if((strcmp(strHDT.szAPName,"V5S_BDODEBIT") == 0) && strCST.inCurrencyIndex != CURRENCY_PHP)
		{
			vdDisplayErrorMsgResp2("DEBIT", "NOT ALLOWED", "FOR USD");
			return d_NO;
		}
	}
				
	vdDebug_LogPrintf("fDebitInsertEnable[%d] :: srTransRec.byEntryMode[%d] :: strCDT.HDTid[%d]",strTCT.fDebitInsertEnable,srTransRec.byEntryMode,strCDT.HDTid);
	if (fIdleInsert != TRUE && strTCT.fDebitInsertEnable == FALSE && srTransRec.byEntryMode == CARD_ENTRY_ICC && 
		(strCDT.HDTid == DEBIT_HDT_INDEX || strCDT.HDTid == DEBIT2_HDT_INDEX))
	{	
		vdInstallmentPromptToSwipe();
        vdCTOS_ResetMagstripCardData();
        inRet = inCTOS_GetCardFieldsSwipeOnly();
        if(d_OK != inRet)
            return inRet;	
	}
	
	if(strTCT.fSMMode == FALSE)
	{
		if (strCDT.HDTid == SMAC_HDT_INDEX)
		{
			vdDisplayErrorMsgResp2(" ", "TRANSACTION", "NOT ALLOWED");
			return d_OK;
		}
	}
	else
	{
		if(strCDT.HDTid== SMAC_HDT_INDEX) // Check if SMAC is logged on. If not, do SMAC logon.
		{	
			inRet = CheckIfSmacEnableonIdleSale();
			if(inRet != d_OK)
			{
				inRet = inCTOS_SMACLogonFlowProcess(NO_SELECT);
				if(d_OK != inRet)
				{
					vdSetECRResponse(ECR_OPER_CANCEL_RESP);
        			return inRet;
				}
				vdCTOS_SetTransType(SALE); // Set TransType back to Sale
				fAutoSMACLogon = TRUE;
			}	
		}
	
	}

	inRet=inEMVCheckCUPEnable(); /*check CUP PHP*/
	if(d_OK != inRet)
		return inRet;

	/* BDO: Last 4 PAN digit checking - start -- jzg */
	if (!fBINVer){
		inRet = inBDOEnterLast4Digits(FALSE);
		if(inRet != d_OK)
				return inRet;
	}

	//gcitra - put display here not in amount entry

	inSETIssuerForCatchAll();
#if 1
	if(strTCT.fATPBinRoute == TRUE && srTransRec.byEntryMode == CARD_ENTRY_WAVE && srTransRec.IITid == 9 )//Check if CUP CTLS. Terminal should be able to identify CUP CTLS right away since it does not support bin routing.
	{
		if (fUSDSelected)
			inHDTReadData(37);
		else
	    	inHDTReadData(36);
		vdDebug_LogPrintf("strHDT_Temp.fTapAndGo[%d]",strHDT_Temp.fTapAndGo);
		vdDebug_LogPrintf("strHDT.fTapAndGo[%d] :: srTransRec.byEntryMode[%d]",strHDT.fTapAndGo,srTransRec.byEntryMode);
		strHDT.fTapAndGo = strHDT_Temp.fTapAndGo;
	}
#endif	
	vdDebug_LogPrintf("strHDT.fTapAndGo[%d] :: srTransRec.byEntryMode[%d]",strHDT.fTapAndGo,srTransRec.byEntryMode);

	if((strHDT.fTapAndGo == TRUE && srTransRec.byEntryMode == CARD_ENTRY_WAVE) || (strTCT.fInsertAndGo == TRUE && srTransRec.byEntryMode == CARD_ENTRY_ICC))
	{	
	}
	else
	{
		inRet=inCTOS_DisplayCardTitle(6, 7); //Display Issuer logo: re-aligned Issuer label and PAN lines -- jzg
		if(d_OK != inRet)
			return inRet;
	}
	
	inRet = inCTOS_UpdateTxnTotalAmount();
	if(d_OK != inRet)
			return inRet;
	
	if((strHDT.fTapAndGo == TRUE && srTransRec.byEntryMode == CARD_ENTRY_WAVE) || (strTCT.fInsertAndGo == TRUE && srTransRec.byEntryMode == CARD_ENTRY_ICC))
	{
	}
	else
	{
		inRet = inConfirmPAN();
		if(d_OK != inRet)
			return inRet;
	}


    if ((strTCT.fSingleComms == FALSE) && (fPreConnectEx == FALSE)){
		inRet = inCTOS_PreConnectEx();

		if (inRet != d_OK)
			return inRet;
	}


	inRet = inCTOS_GetCVV2();
	if(d_OK != inRet)
		  return inRet;
#if 0
	inRet=inCTOS_SelectCurrency();
	if(d_OK != inRet)
		return inRet;
#else
	inRet=inCTOS_SetCurrency();
	if(d_OK != inRet)
		return inRet;
#endif

	inRet=inEMVCheckCUPEnable(); /*check CUP USD*/
	if(d_OK != inRet)
		return inRet;

	inRet = inGetPolicyNumber();
	if(d_OK != inRet)
		return inRet;	

BINROUTE_AGAIN:

	fDualBrandedCard = FALSE;
    fBinRouteDCC = FALSE;
#if 0	
    if(inCTLSEMVCheck() == d_OK)
        fBinRoute=FALSE;	
#endif
	if(fCUPBinRoute() == d_OK)
		fBinRoute=FALSE;

	if(fAmexBinRoute() == d_OK)
	{
		fBinRoute=FALSE;
		
		if (inCheckIfHostEnable(2) != 0 )
		{
			if (fUSDSelected)
		       	strHDT.inHostIndex=srTransRec.HDTid=strCDT.HDTid=4;
		    else
		       	strHDT.inHostIndex=srTransRec.HDTid=strCDT.HDTid=2;
		}
	}

	if(fDinersBinRoute() == d_OK)
	{
		fBinRoute=FALSE;
		if (inCheckIfHostEnable(59) != 0 )
		{
			if (fUSDSelected)
	        	strHDT.inHostIndex=srTransRec.HDTid=strCDT.HDTid=106;
	        else
	        	strHDT.inHostIndex=srTransRec.HDTid=strCDT.HDTid=59;
		}
	}
	
	vdDebug_LogPrintf("srTransRec.stEMVinfo.T84 %x %x %x %x %x",srTransRec.stEMVinfo.T84[0], srTransRec.stEMVinfo.T84[1], srTransRec.stEMVinfo.T84[2],srTransRec.stEMVinfo.T84[3],srTransRec.stEMVinfo.T84[4] );
	if(memcmp(srTransRec.stEMVinfo.T84,"\xA0\x00\x00\x06\x35",5) == 0 || memcmp(srTransRec.stEMVinfo.T84,"\xa0\x00\x00\x06\x35",5) == 0)//Bancnet AID
	{
		vdDebug_LogPrintf("AID IS BANCNET");
		fBinRoute=FALSE;		
		srTransRec.HDTid = strCDT.HDTid = 53;
		srTransRec.inCardType = DEBIT_CARD;
		srTransRec.IITid = 1;
	}

	if(srTransRec.fOptOut == TRUE)
	{
		if(fBDOOptOutHostEnabled == TRUE)
			srTransRec.HDTid = strCDT.HDTid = BDO_OPTOUT_HDT_INDEX;
	}

	
 
	if ((strTCT.fATPBinRoute == TRUE) && (strCDT.fPANCatchAll == TRUE) && (fBinRoute == TRUE) && srTransRec.fOptOut != TRUE){
	
		#define ATPBINROUTE
		#ifdef ATPBINROUTE
			    //do not do ATP routing if USD selected
			 //if (fUSDSelected == FALSE){
				vdSetATPBinRouteFlag(1);
				fRouteToSpecificHost = 0;
				fMagStripeDebit=FALSE;
				fMagStripeCUP=FALSE;
				fNoCTLSSupportforBinRoute=FALSE;
				inRet = inCTOSS_ATPBinRoutingProcess();
				vdDebug_LogPrintf("inCTOSS_ATPBinRoutingProcess inRet=[%d]",inRet);
				vdDebug_LogPrintf("szRespCode_Temp[%d]",atoi(srTransRec.szRespCode_Temp));
				if(inRet == VS_CONTINUE && srTransRec.byEntryMode == CARD_ENTRY_WAVE 
					&& atoi(srTransRec.szRespCode_Temp) != 72 && atoi(srTransRec.szRespCode_Temp) != 79/*not AMEX*/ && srTransRec.fDualBrandedCredit != TRUE)
				{
ENTER_AGAIN:	
					vdResetAllCardData();		
					fNoCTLSSupportforBinRoute = TRUE;
				
					inRetVal = inCTOS_GetCardFieldsFailedCtlsFallbackEx();
					if(d_OK != inRetVal)
					{
						if(inRetVal == ST_ERROR || inRetVal == INVALID_CARD)//
							goto ENTER_AGAIN;
						else
						{
							vdSetECRResponse(ECR_OPER_CANCEL_RESP);
							return inRetVal;
						}
					}
					else
						goto BINROUTE_AGAIN;
				}
				
				vdSetATPBinRouteFlag(0);
				if(VS_CONTINUE != inRet)
					return inRet;

				vdDebug_LogPrintf("strCDT.HDTid[%d]",strCDT.HDTid);
				vdDebug_LogPrintf("srTransRec.inCardType[%d]",srTransRec.inCardType);
				vdDebug_LogPrintf("srTransRec.IIT[%d]",srTransRec.IITid);
					                   
				//memset( &srTransRec, 0x00, sizeof(TRANS_DATA_TABLE));

				if (fSkipBINRoutingForDebit == FALSE){
					if (strCDT.HDTid == 53 && srTransRec.byEntryMode == CARD_ENTRY_ICC) {
						vdDebug_LogPrintf("inside fSkipBINRoutingForDebit == FALSE");
						//vdCTOS_ResetMagstripCardData();
						//memset(&stRCDataAnalyze,0x00,sizeof(EMVCL_RC_DATA_ANALYZE));
						//memset(&strEMVT,0x00, sizeof(STRUCT_EMVT));

                        //fix for RC: 05 response from host
                        //add code
                        #if 1
						//inCTOSS_CLMCancelTransaction();
						vdResetAllCardData();
						vdCTOS_SetTransEntryMode(CARD_ENTRY_ICC);//Fix where byEntryMode is set to 0 by vdCTOS_ResetMagstripCardData().
						inRet = inCTOS_EMVCardReadProcess();
						
						if(d_OK != inRet)
							return inRet;
						
						#else
						//removed- fix for RC: 05 response from host
						if (strTCT.byCtlsMode == 0)
							inRet = inCTOS_GetCardFields();
						else
							inRet = inCTOS_WaveGetCardFields();

						if(d_OK != inRet)
							return inRet;
						//reemoved
						#endif
						
                        //srTransRec.byEntryMode = CARD_ENTRY_ICC;//Fix where byEntryMode is set to 0 by vdCTOS_ResetMagstripCardData().
                        strCDT.HDTid = 53;
						srTransRec.inCardType = DEBIT_CARD;				
						srTransRec.IITid = 1;						
						inIITRead(srTransRec.IITid);
						strcpy(srTransRec.szCardLable, strIIT.szIssuerLabel);
					}
				}

                if(fMagStripeDebit==TRUE)
                {
                   if (strCDT.HDTid == 53 && srTransRec.byEntryMode == CARD_ENTRY_ICC)
                   {
						vdRemoveCard();
								
                        vdCTOS_ResetMagstripCardData(); 
                        inRet = inCTOS_GetCardFieldsSwipeOnly();
                        if(d_OK != inRet)
                            return inRet;	
                            
                        strCDT.HDTid = 53;
                        srTransRec.inCardType = DEBIT_CARD;
						srTransRec.IITid = 1;						
						inIITRead(srTransRec.IITid);
						strcpy(srTransRec.szCardLable, strIIT.szIssuerLabel);
                    }
                }

				if(fMagStripeCUP==TRUE)
                {
                   if ((strCDT.HDTid == 36 || strCDT.HDTid == 37) && srTransRec.byEntryMode == CARD_ENTRY_ICC)
                   {
						vdRemoveCard();
								
                        vdCTOS_ResetMagstripCardData(); 
                        inRet = inCTOS_GetCardFieldsSwipeOnly();
                        if(d_OK != inRet)
                            return inRet;	

						if (fUSDSelected)
							strCDT.HDTid = 37;
						else
					    	strCDT.HDTid = 36;

						srTransRec.IITid = 9;
                        inIITRead(srTransRec.IITid);
						strcpy(srTransRec.szCardLable, strIIT.szIssuerLabel);
                    }
                }

			    if (strCDT.HDTid == 56){		
					//add fleet card processing
					srTransRec.fFleetCard = TRUE;
					inRet = inFleetGetLiters();
					if(d_OK != inRet)
						return inRet;
					
					inRet = inFleetSelectProductCode();
					if(d_OK != inRet)
						return inRet;
						//end fleet modifications
			    }
				
				vdDebug_LogPrintf("strCDT.HDTid[%d] :: srTransRec.byEntryMode[%d] :: fBinRouteDCC[%d]",strCDT.HDTid,srTransRec.byEntryMode,fBinRouteDCC);
				vdDebug_LogPrintf("fAMEXHostEnable[%d] :: srTransRec.byEntryMode[%d] :: strCDT.HDTid[%d]",fAMEXHostEnable,srTransRec.byEntryMode,strCDT.HDTid);
				if( (srTransRec.byEntryMode == CARD_ENTRY_ICC && fBinRouteDCC== FALSE) && fRouteToSpecificHost == TRUE)
#if 0					
				 ( (strCDT.HDTid == 56 || strCDT.HDTid == 59 || strCDT.HDTid == 2 || strCDT.HDTid == 4) || // Do not perform inCTOS_EMVProcessing() for Diners, Fleet, AMEX and AMEX USD. inCTOS_EMVProcessing() was already called inside inCTOSS_ATPBinRoutingProcess()
				   (fAMEXHostEnable == FALSE && strCDT.HDTid == 1)) ) // If AMEX is disabled and AMEX transactions will be saved to BDO host, do not perform inCTOS_EMVProcessing() again. inCTOS_EMVProcessing() was already called inside inCTOSS_ATPBinRoutingProcess()
#endif	
				{
					fNoEMVProcess = TRUE; 
				} 
					
			//}		
		#endif
			if(strIIT.fGetPolicyNumber == TRUE && strlen(srTransRec.szPolicyNumber) == 0)
			{
				inRet = inGetPolicyNumber();
				if(d_OK != inRet)
					return inRet;
			}
	}
	else{
		
		vdSetATPBinRouteFlag(0);

		if (strCDT.HDTid == 56){		
			//add fleet card processing
			srTransRec.fFleetCard = TRUE;
			inRet = inFleetGetLiters();
			if(d_OK != inRet)
				return inRet;

			inRet = inFleetSelectProductCode();
			if(d_OK != inRet)
				return inRet;
			//end fleet modifications
		}

		vdDebug_LogPrintf("GOC 1 = [%d]", strCDT.HDTid);
#if 0		
		if (strCDT.HDTid == DEBIT_HDT_INDEX && srTransRec.byEntryMode == CARD_ENTRY_WAVE)
		{
		    
			vdDebug_LogPrintf("GOC 2  = [%d]", strCDT.HDTid);
			strCDT.HDTid = 1;	
			srTransRec.inCardType = CREDIT_CARD;
			srTransRec.IITid = 21;	
			inIITRead(srTransRec.IITid);
			strcpy(srTransRec.szCardLable, strIIT.szIssuerLabel);
		}
#endif		 
	}

    //inRet = inCTOS_PreConnectAndInit();
    //if(d_OK != inRet)
        //return inRet;

//if (chGetInit_Connect() != 1)
{
	vdDebug_LogPrintf("GOC 3 = [%d]", strCDT.HDTid);

    //inRet = inCTOS_SelectHost(); // Check if Host is enabled
    inRet = inCTOS_SelectHostEx2();
    if(d_OK != inRet)
        return inRet;

    //if (inMMTReadRecord(strCDT.HDTid,srTransRec.MITid) != d_OK) // Also check if Merchant using host is enabled
    if (inMMTReadRecordEx(strCDT.HDTid,srTransRec.MITid) != d_OK) // Also check if Merchant using host is enabled
    {
        vdDisplayErrorMsgResp2(" ", "TRANSACTION", "NOT ALLOWED");
		inDatabase_TerminalCloseDatabase();
        return(d_NO);
    }	
	inDatabase_TerminalCloseDatabase();
}
    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
    	if (srTransRec.byTransType == REFUND)
				inEVENT_ID = d_IPC_CMD_WAVE_REFUND;
			else
				inEVENT_ID = d_IPC_CMD_WAVE_SALE;

		if(srTransRec.usTerminalCommunicationMode == DIAL_UP_MODE || srTransRec.usTerminalCommunicationMode == ETHERNET_MODE)
		{	
			char szAPName[25];
			int inAPPID;
			inMultiAP_CurrentAPNamePID(szAPName, &inAPPID);
			if (strcmp (strHDT.szAPName,szAPName) != 0)
				inCTOS_inDisconnect();
		}
		
        inRet = inCTOS_MultiAPSaveData(inEVENT_ID);
		if(strTCT.fSMMode == 1)
		{
			if(get_env_int("SMCARDRETRY") == 1 && (get_env_int("SMCARDRETRYCOUNT")<=strTCT.inSMCardRetryCount) && (!fGetECRTransactionFlg()))
			{
				vdRemoveCard();
				vdSMReEnterCardDetails();
				goto SWIPE_AGAIN;
			}
		}
		if(d_OK != inRet)
            return inRet;
    }
    else
    {
        if (inMultiAP_CheckSubAPStatus() == d_OK)
        {
            inRet = inCTOS_MultiAPGetData();
            if(d_OK != inRet)
                return inRet;
            
            inRet = inCTOS_MultiAPReloadTable();
            if(d_OK != inRet)
                return inRet;

			inRet = inCTOS_MultiAPReloadWaveData();
            if(d_OK != inRet)
                return inRet;
        }
        inRet = inCTOS_MultiAPCheckAllowd();
        if(d_OK != inRet)
            return inRet;
    }
	
	if(strTCT.fDCC	&& srTransRec.byEntryMode != CARD_ENTRY_WAVE && srTransRec.fOptOut != TRUE)
    {
		if((strTCT.fATPBinRoute == FALSE && strCDT.fDCCEnable == TRUE) || 
		   (strTCT.fATPBinRoute == TRUE && fBinRouteDCC && inSetIssuerforBINRouteDCC() == TRUE) )
		{
	       inRet = inCTOS_ProcessDCCRate();
	       if(d_OK != inRet)
	           return inRet;
		   memset(srTransRec.szRespCode,0x00,sizeof(srTransRec.szRespCode));
		   
		   //if(fNoCTLSSupportforBinRoute == TRUE)
		   		//fBinRouteDCC=FALSE;//Set to FALSE to perform inCTOS_EMVProcessing()
		   	if(fBinRouteDCC == TRUE && srTransRec.fDCC == TRUE && srTransRec.byEntryMode == CARD_ENTRY_ICC)
			{
				vdDebug_LogPrintf("Resetting EMV Structure");
				memset(&stRCDataAnalyze,0x00,sizeof(EMVCL_RC_DATA_ANALYZE));
				memset(&strEMVT,0x00, sizeof(STRUCT_EMVT));
				inCTOS_EMVCardReadProcess();
			}
			else if(fBinRouteDCC == TRUE && srTransRec.fDCC == FALSE)
				fNoEMVProcess = TRUE;
			
			inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);
		}
    }
	
	//

    inRet = inCTOS_CheckMustSettle();
    if(d_OK != inRet)
    {
		//vdSetECRResponse(ECR_OPER_CANCEL_RESP);
		return inRet;
    }
    inRet = inCTOS_CheckIssuerEnable();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_CheckTranAllowd();
    if(d_OK != inRet)
        return inRet;

	if(fNoCTLSSupportforBinRoute == TRUE && fDualBrandedCard == TRUE)
   		fDualBrandedCard=FALSE;//Set to FALSE to perform inCTOS_EMVProcessing()

    if (fDualBrandedCard == FALSE && fNoEMVProcess == FALSE)
	{
    	inRet = inCTOS_EMVProcessing();
    	if(d_OK != inRet)
        	return inRet;  
    }
		//EMV: Online PIN enchancement - start -- jzg
#ifdef ONLINE_PIN_SUPPORT
		srTransRec.fEMVPIN = FALSE;
		vdDebug_LogPrintf("JEFF::inCTOS_WaveFlowProcess 9F34 = [%02X %02X %02X]", srTransRec.stEMVinfo.T9F34[0], srTransRec.stEMVinfo.T9F34[1], srTransRec.stEMVinfo.T9F34[2]);
		if((srTransRec.stEMVinfo.T9F34[0] & 0x0F) == 0x02)
		{
			inRet = inGetIPPPin();
			if(d_OK != inRet)
				 return inRet;
			else
				srTransRec.fEMVPIN = TRUE;		
		}
#endif
		//EMV: Online PIN enchancement - end -- jzg


   if(srTransRec.usTerminalCommunicationMode == GPRS_MODE || (srTransRec.usTerminalCommunicationMode == WIFI_MODE && fAutoSMACLogon == FALSE))
   {
   		if (chGetInit_Connect() != 1)
   		{
            inRet = inCTOS_PreConnect();
            if(d_OK != inRet)
                return inRet;
   		}
   }else{

		if (strTCT.fSingleComms){	
			if(inCPTRead(1) != d_OK)
			{
				vdSetErrorMessage("LOAD CPT ERR");
				return(d_NO);
			}
		//}else
		//{
		//	inRet = inCTOS_PreConnect();
		//	if(d_OK != inRet)
		//		return inRet;
		}

		if(fCommsFallback == TRUE && srTransRec.fDCC == TRUE)//Comms fallback already done during DCC rate request. inCPTRead will overwrite value of inCommunicationMode set in inCTOS_CommsFallback() and needs to be set again.
		{
			srTransRec.usTerminalCommunicationMode = strCPT.inCommunicationMode = inCommsFallbackMode; 
			fCommsFallback = FALSE;
			inCommsFallbackMode = -1;
			
		}	
		
   }


	if(get_env_int("BINROUTE") != TRUE)//Fix to invoice number incrementing twice on Bin Routing setup.
	{
	    inRet = inCTOS_GetInvoice();
	    if(d_OK != inRet)
	        return inRet;
	}



	//inCTOSS_GetRAMMemorySize("BUILD&SEND START");
    inRet = inBuildAndSendIsoData();
	//inCTOSS_GetRAMMemorySize("BUILD&SEND END");
    if(d_OK != inRet)
	{

		/*BDO: Set ECR response code to EN - COMM ERROR -- sidumili*/
		if (strlen(srTransRec.szRespCode) <= 0)
		{
			strcpy(srTransRec.szECRRespCode, ECR_COMMS_ERR);
		}
		else
		{
			inSMCardRetryCount = get_env_int("SMCARDRETRYCOUNT");
			inSMCardRetryCount++;
			put_env_int("SMCARDRETRYCOUNT",inSMCardRetryCount);
			if(strTCT.fSMMode == 1 && get_env_int("SMCARDRETRYCOUNT")<=strTCT.inSMCardRetryCount && (!fGetECRTransactionFlg()) )
			{
				vdRemoveCard();
				if(srTransRec.fDCC == TRUE)//copy local amount to the szTotalAmount
				{
					memset(srTransRec.szBaseAmount,0x00,sizeof(srTransRec.szBaseAmount));
					memcpy(srTransRec.szBaseAmount, srTransRec.szDCCLocalAmount,sizeof(srTransRec.szTotalAmount));
					srTransRec.fDCC = FALSE;
				}
				vdSMReEnterCardDetails();
				fBINVer = FALSE; // SET fBINVer to false for SMCARDRETRY scenario
				if(srTransRec.usTerminalCommunicationMode == DIAL_UP_MODE)
				{
					inRet = inCTOS_PreConnectEx();
					if (inRet != d_OK)
						return inRet;
				}
				goto SWIPE_AGAIN;
			}
		}

        return inRet;
    }
#ifdef DCC_SIGNPAD
	if(inFLGGet("fSignPad") && strTCT.fDCC && (srTransRec.fDCC || inNSRFlag() != TRUE) && srTransRec.fDCCInitiatedTxn && inIsEMVTxnWithPIN() != TRUE)
	{
		inRet = inSignPadSendReceive(d_COM2, GET_PAYMENT_SIGNATURE);		
		if(inRet != d_OK)
			srTransRec.fSignPadBypassSignature = TRUE;
	}
#endif	
    inRet = inCTOS_SaveBatchTxn();
    if(d_OK != inRet)
        return inRet;

    vdDebug_LogPrintf("inCTOS_UpdateAccumTotal");
	
    inRet = inCTOS_UpdateAccumTotal();
    if(d_OK != inRet)
        return inRet;

	vdDebug_LogPrintf("inDisconnectIfNoPendingADVICEandUPLOAD");


	/*  FOR TESTING 06 jan 2021	
	inRet=inDisconnectIfNoPendingADVICEandUPLOAD(&srTransRec, strHDT.inNumAdv);
    if(d_OK != inRet)
        return inRet;
	*/
	
	// patrick add code 20141205 start, modified -- sidumili
	fECRBuildSendOK = TRUE;	
	if (fECRBuildSendOK){	
	    inRet = inMultiAP_ECRSendSuccessResponse();
	}

	if(inCheckSMACPayRedemption(&srTransRec) == TRUE)
	{
		inRet = inWriteMifareCardFields();
		if(d_OK != inRet)
			vdDisplayErrorMsgResp2("","CARD NOT","UPDATED");
	}
	
	vdDebug_LogPrintf("ushCTOS_ePadSignature");
	
    inRet = ushCTOS_ePadSignature();
    if(d_OK != inRet)
        return inRet;

	vdDebug_LogPrintf("ushCTOS_printReceipt");
	
    inRet = ushCTOS_printReceipt();
    if(d_OK != inRet)
        return inRet;

		
    inCTLOS_Updatepowrfail(PFR_IDLE_STATE);

		CTOS_LCDTClearDisplay(); //BDO UAT 0012: Merchant copy still being displayed during TC Upload -- jzg
		
    inRet = inCTOS_EMVTCUpload();
    if(d_OK != inRet)
        return inRet;
    else
        vdSetErrorMessage("");

	CTOS_LCDTClearDisplay(); //BDO UAT 0012: Merchant copy still being displayed during Advice Upload -- sidumili

	
	if(strTCT.fSMMode == TRUE)
	{
		if (srTransRec.byTransType == SALE && srTransRec.HDTid == SMAC_HDT_INDEX)
		{
			if (srTransRec.fPrintCardHolderBal == TRUE)
				InSMACDisplayBalance();
		}
		else if(inCheckIfSMCardTransRec() == TRUE)
		{
			wub_hex_2_str(srTransRec.SmacBalance, szTemp1, AMT_BCD_SIZE);
			if(atol(szTemp1)>=0)
				if(srTransRec.HDTid != SMECARD_HDT_INDEX)
					InSMACDisplayBalance();
		}
	}
#if 0
	if(srTransRec.fOptOut == TRUE)
	{
		DebugAddHEX("szInvoiceNo",srTransRec.szInvoiceNo,INVOICE_BCD_SIZE);
		DebugAddHEX("szOptOutVoidInvoiceNo",srTransRec.szOptOutVoidInvoiceNo,INVOICE_BCD_SIZE);
	
		inRet = inDatabase_OptOutCompleteBatchUpdate(srTransRec.szOptOutVoidInvoiceNo);
		if(d_OK != inRet)
		{
			vdDisplayErrorMsgResp2("OPT OUT", "BATCH UPDATE", "FAILED");
			return inRet;
		}
	}
#endif		
    if(strTCT.fDCC && srTransRec.fDCC)
    {
        inRet=inProcessTransLogTrans(&srTransRec, 1, 2, GET_ALL_EXCEPT_TIP);
        if(d_OK != inRet)
            return TRANSLOG_FAILED;
        else
            vdSetErrorMessage("");
    }
	
    if (srTransRec.byTransType != SALE_OFFLINE)	
    {
       inRet=inProcessAdviceTrans(&srTransRec, strHDT.inNumAdv);
       if(d_OK != inRet)
          return ADVICE_FAILED;
       else
          vdSetErrorMessage("");
    }

		
    if(strTCT.fDCC && srTransRec.fDCC)
    {
#if 0
        inRet=inProcessTransLogTrans(&srTransRec, 1, 2, GET_ALL_EXCEPT_TIP);
        if(d_OK != inRet)
            return inRet;
        else
            vdSetErrorMessage("");
#endif        
        inRet=inProcessTransLogTrans(&srTransRec, 1, 2, GET_TIP_ONLY);
        if(d_OK != inRet)
            return TRANSLOG_FAILED;
        else
            vdSetErrorMessage("");
    }
	
    return d_OK;
}

#else

int inCTOS_WaveFlowProcess(void)

{
    int inRet = d_NO;
	int inRetVal = d_NO;
    USHORT ushEMVtagLen;
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];
	int inEVENT_ID = 0;
    BOOL fBinRoute=TRUE;
	int inSMCardRetryCount=0;
	char szTemp1[d_LINE_SIZE + 1];

	int inRetFromWaveGetCardFields = 0;

	//version16
    BYTE szQrCodeText[200];
	BYTE szBuffer [50];
	char szBcd[INVOICE_BCD_SIZE+1];
	//version16
	char szAmtBuff[AMT_ASC_SIZE+1];

	int inResult = d_NO;
	
	fECRBuildSendOK = FALSE; /* BDO: For ECR -- sidumili */
	fTimeOutFlag = FALSE; /*BDO: Flag for timeout --sidumili*/
	put_env_int("SMCARDRETRY",0);
	put_env_int("SMCARDRETRYCOUNT",0);
	vdCTOS_SetTransType(SALE);

	memset(&stRCDataAnalyze,0x00,sizeof(EMVCL_RC_DATA_ANALYZE));


	wub_hex_2_str(srTransRec.szBaseAmount,szAmtBuff,AMT_BCD_SIZE);
	vdDebug_LogPrintf("inCTOS_WaveFlowProcess DIGITAL WALLET AMOUT IS %s",szAmtBuff);

	vdDebug_LogPrintf("inCTOS_WaveFlowProcess START");

	
/*	inRet = inCTOS_PreConnectEx();
	if(d_OK != inRet)
		return inRet;
*/

   if(srTransRec.usTerminalCommunicationMode == DIAL_UP_MODE && srTransRec.fBINVer == TRUE)
   {
	   if (strTCT.fSingleComms && (fPreConnectEx == FALSE || fBINVerPreConnectEx == FALSE)){
			   inRet = inCTOS_PreConnectEx();
	   
			   if (inRet != d_OK)
				   return inRet;
		   }
   }

    if(fEntryCardfromIDLE == TRUE && (srTransRec.byEntryMode == CARD_ENTRY_ICC || srTransRec.byEntryMode == CARD_ENTRY_MSR)){		
		
	    //if (strTCT.byCtlsMode == 0)

			inRet = inCTOS_GetCardFields();
			//else
	    	//inRet = inCTOS_WaveGetCardFields();
		
    		if(d_OK != inRet)
        		return inRet;

		inRet=inCTOS_SelectCurrencyfromIDLE();
		if(d_OK != inRet)
			return inRet;

		if(inFLGGet("fDebitDualCurrency") == FALSE)
		{
			if((strcmp(strHDT.szAPName,"V5S_BDODEBIT") == 0) && strCST.inCurrencyIndex != CURRENCY_PHP)
			{
				vdDisplayErrorMsgResp2("DEBIT", "NOT ALLOWED", "FOR USD");
				return d_NO;
			}
		}
	}

	wub_hex_2_str(srTransRec.szBaseAmount,szAmtBuff,AMT_BCD_SIZE);
	vdDebug_LogPrintf("inCTOS_WaveFlowProcess2 DIGITAL WALLET AMOUT IS %s",szAmtBuff);

    #if 0
	if (fIdleSwipe == TRUE){
		inRet=inReadIDLEMSD();
		if (inRet == USER_ABORT || inRet == INVALID_CARD){ 	
			clearLine(1);
			return d_NO;
		}


    	if(d_OK != inRet)
        	return inRet;
		
	    if (strTCT.byCtlsMode == 0)
				inRet = inCTOS_GetCardFields();
			else
	    	inRet = inCTOS_WaveGetCardFields();
		
	
    	if(d_OK != inRet)
        	return inRet;
	}
	#endif

	vdDebug_LogPrintf("inCTOS_WaveFlowProcess XXX invoice num %x%x%x",srTransRec.szInvoiceNo[0], srTransRec.szInvoiceNo[1],srTransRec.szInvoiceNo[2]);
	
	vdDebug_LogPrintf("fDebitInsertEnable[%d] :: srTransRec.byEntryMode[%d] :: strCDT.HDTid[%d]",strTCT.fDebitInsertEnable,srTransRec.byEntryMode,strCDT.HDTid);
	if (strTCT.fDebitInsertEnable == FALSE && srTransRec.byEntryMode == CARD_ENTRY_ICC && 
		(strCDT.HDTid == DEBIT_HDT_INDEX || strCDT.HDTid == DEBIT2_HDT_INDEX))
	{	
		vdInstallmentPromptToSwipe();
        vdCTOS_ResetMagstripCardData();
        inRet = inCTOS_GetCardFieldsSwipeOnly();
        if(d_OK != inRet)
            return inRet;	
	}
    
    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;

#if 0
//for enhance the treansaction speed
	vdDebug_LogPrintf("GOC 3 = [%d]", strCDT.HDTid);

    //inRet = inCTOS_SelectHost(); // Check if Host is enabled
    inRet = inCTOS_SelectHostEx2();
    if(d_OK != inRet)
        return inRet;

    //if (inMMTReadRecord(strCDT.HDTid,srTransRec.MITid) != d_OK) // Also check if Merchant using host is enabled
    if (inMMTReadRecordEx(strCDT.HDTid,srTransRec.MITid) != d_OK) // Also check if Merchant using host is enabled
    {
        vdDisplayErrorMsgResp2(" ", "TRANSACTION", "NOT ALLOWED");
		inDatabase_TerminalCloseDatabase();
        return(d_NO);
    }	
	inDatabase_TerminalCloseDatabase();

	inRet = inCTOS_PreConnectAndInit();
		if(d_OK != inRet)
			return inRet;
#else
    //inRet = inCTOS_PreConnectAndInit();
    //if(d_OK != inRet)
    //    return inRet;
#endif	

    //SIT-start
    if (inCTOS_ValidFirstIdleKey() == d_OK){
        
		inRet = inCTOS_GetTxnBaseAmount();
		if(d_OK != inRet)
			return inRet;

    	if (!fBINVer){
			inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
			if(d_OK != inRet)
				return inRet;
    	}
    }else{
	
    	if (!fBINVer){
			inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
			if(d_OK != inRet)
				return inRet;
	   	}

		if(fIdleSwipe == TRUE || fIdleInsert == TRUE)//If sale is accessed via menu, dual currency menu should be prompted.
		{		
		}
		else
		{
			inRet=inCTOS_SelectCurrencyEx();
			if(d_OK != inRet)
				return inRet;
		}
	
		inRet = inCTOS_GetTxnBaseAmount();
    	if(d_OK != inRet)
        	return inRet;
    }


    inRet = inCTOS_PreConnectAndInit();
    if(d_OK != inRet)
        return inRet;
	else if((srTransRec.usTerminalCommunicationMode == GPRS_MODE || srTransRec.usTerminalCommunicationMode == WIFI_MODE) 
		&& (fIdleSwipe == TRUE || fIdleInsert == TRUE))// Added delay to fix issue where terminal does not react to keypress after preconnect using SHARLS_COM
	{
		vdClearBelowLine(2);
		vdCTOS_DispStatusMessage("PROCESSING...");  
		WaitKey(1);
	}


	
	vdDebug_LogPrintf("inCTOS_WaveFlowProcess YYY invoice num %x%x%x",srTransRec.szInvoiceNo[0], srTransRec.szInvoiceNo[1],srTransRec.szInvoiceNo[2]);

/*
    if (strTCT.fSingleComms){	
		inRet = inCTOS_PreConnectEx();

		if (inRet != d_OK)
			return inRet;
	}
*/

//SIT-end
SWIPE_AGAIN:

		fBinRoute = TRUE;
		//version16
		if (fSmacScan == TRUE){

            vdDebug_LogPrintf("testlang smacsacn");
           	srTransRec.HDTid = SMAC_HDT_INDEX;
			strCDT.HDTid = SMAC_HDT_INDEX;
			srTransRec.IITid = 15;

			inIITRead(srTransRec.IITid);
			inCPTRead(srTransRec.HDTid);
			strcpy(srTransRec.szCardLable, strIIT.szIssuerLabel);
			vdDebug_LogPrintf("testlang hdtid %d", srTransRec.HDTid);
			vdCTOS_SetTransEntryMode(SMAC_SCAN);
			vdDebug_LogPrintf("smac srTransRec.byEntryMode %d", srTransRec.byEntryMode);


		}else{


			if (fBINVer){
				
				inRet = inCTOS_GetCardFields();
			}
			else{    
	    		if (strTCT.byCtlsMode == 0)
					inRet = inCTOS_GetCardFields();
				else{
	    			inRet = inCTOS_WaveGetCardFields();					
					fCTLSfromECR = FALSE;
					fAmountFromIdle = FALSE;
					fPANEntryFromECR = FALSE;
					vdDebug_LogPrintf("inRet  --[%d]", inRet);		
				}
			}
		
    		if (USER_ABORT == inRet || READ_CARD_TIMEOUT == inRet || INVALID_CARD == inRet || LOGON_FAILED == inRet)
        		return inRet;
    		else if(inRet == CTLS_ANALYZE_ERROR || inRet == CTLS_EXPIRED_CARD)//Prompt user to Swipe/Insert card on Analyze error or Expired card on CTLS.
			{
				inGblCtlsErr=2;
				vdResetAllCardData();
				inRet = inCTOS_GetCardFieldsFailedCtlsFallbackEx();
				if(d_OK != inRet)
        			return inRet;
			}else if (d_OK != inRet)
        		goto SWIPE_AGAIN;
		}


	if(inFLGGet("fDebitDualCurrency") == FALSE)
	{
		if((strcmp(strHDT.szAPName,"V5S_BDODEBIT") == 0) && strCST.inCurrencyIndex != CURRENCY_PHP)
		{
			vdDisplayErrorMsgResp2("DEBIT", "NOT ALLOWED", "FOR USD");
			return d_NO;
		}
	}

	vdDebug_LogPrintf("inCTOS_WaveFlowProcess YYY invoice num %x%x%x",srTransRec.szInvoiceNo[0], srTransRec.szInvoiceNo[1],srTransRec.szInvoiceNo[2]);
				
	vdDebug_LogPrintf("fDebitInsertEnable[%d] :: srTransRec.byEntryMode[%d] :: strCDT.HDTid[%d]",strTCT.fDebitInsertEnable,srTransRec.byEntryMode,strCDT.HDTid);
	if (fIdleInsert != TRUE && strTCT.fDebitInsertEnable == FALSE && srTransRec.byEntryMode == CARD_ENTRY_ICC && 
		(strCDT.HDTid == DEBIT_HDT_INDEX || strCDT.HDTid == DEBIT2_HDT_INDEX))
	{	
		vdInstallmentPromptToSwipe();
        vdCTOS_ResetMagstripCardData();
        inRet = inCTOS_GetCardFieldsSwipeOnly();
        if(d_OK != inRet)
            return inRet;	
	}
	
	if(strTCT.fSMMode == FALSE)
	{
		if (strCDT.HDTid == SMAC_HDT_INDEX)
		{
			vdDisplayErrorMsgResp2(" ", "TRANSACTION", "NOT ALLOWED");
			return d_OK;
		}
	}
	else
	{
		if(strCDT.HDTid== SMAC_HDT_INDEX) // Check if SMAC is logged on. If not, do SMAC logon.
		{	
#if 1
			inRet = CheckIfSmacEnableonIdleSale();
			if(inRet != d_OK)
			{
				inRet = inCTOS_SMACLogonFlowProcess(NO_SELECT);
				if(d_OK != inRet)
				{
					vdSetECRResponse(ECR_OPER_CANCEL_RESP);
        			return inRet;
				}
				vdCTOS_SetTransType(SALE); // Set TransType back to Sale
				fAutoSMACLogon = TRUE;
			}	
#endif
		}
	
	}

	inRet=inEMVCheckCUPEnable(); /*check CUP PHP*/
	if(d_OK != inRet)
		return inRet;

	/* BDO: Last 4 PAN digit checking - start -- jzg */

	//version16
	if (fSmacScan != TRUE){
		if (!fBINVer){
			inRet = inBDOEnterLast4Digits(FALSE);
			if(inRet != d_OK)
				return inRet;
		}
	}
	
	//gcitra - put display here not in amount entry

	inSETIssuerForCatchAll();
#if 1
	if(strTCT.fATPBinRoute == TRUE && srTransRec.byEntryMode == CARD_ENTRY_WAVE && srTransRec.IITid == 9 )//Check if CUP CTLS. Terminal should be able to identify CUP CTLS right away since it does not support bin routing.
	{
		if (fUSDSelected)
			inHDTReadData(37);
		else
	    	inHDTReadData(36);
		vdDebug_LogPrintf("strHDT_Temp.fTapAndGo[%d]",strHDT_Temp.fTapAndGo);
		vdDebug_LogPrintf("strHDT.fTapAndGo[%d] :: srTransRec.byEntryMode[%d]",strHDT.fTapAndGo,srTransRec.byEntryMode);
		strHDT.fTapAndGo = strHDT_Temp.fTapAndGo;
	}
#endif	
	vdDebug_LogPrintf("strHDT.fTapAndGo[%d] :: srTransRec.byEntryMode[%d]",strHDT.fTapAndGo,srTransRec.byEntryMode);

	if((strHDT.fTapAndGo == TRUE && srTransRec.byEntryMode == CARD_ENTRY_WAVE) || (strTCT.fInsertAndGo == TRUE && srTransRec.byEntryMode == CARD_ENTRY_ICC))
	{	
	}
	else
	{
	   	if (fSmacScan != TRUE){//version16
			inRet=inCTOS_DisplayCardTitle(6, 7); //Display Issuer logo: re-aligned Issuer label and PAN lines -- jzg
			if(d_OK != inRet)
				return inRet;
	    }
	}
	
	inRet = inCTOS_UpdateTxnTotalAmount();
	if(d_OK != inRet)
			return inRet;
	
	if((strHDT.fTapAndGo == TRUE && srTransRec.byEntryMode == CARD_ENTRY_WAVE) || (strTCT.fInsertAndGo == TRUE && srTransRec.byEntryMode == CARD_ENTRY_ICC))
	{
	}
	else
	{
	   	if (fSmacScan != TRUE){//version16
			inRet = inConfirmPAN();
			if(d_OK != inRet)
				return inRet;
	    }
	}


    if ((strTCT.fSingleComms == FALSE) && (fPreConnectEx == FALSE)){
		inRet = inCTOS_PreConnectEx();

		if (inRet != d_OK)
			return inRet;
	}

	if (fSmacScan != TRUE){
		inRet = inCTOS_GetCVV2();
		if(d_OK != inRet)
		  return inRet;
	}
#if 0
	inRet=inCTOS_SelectCurrency();
	if(d_OK != inRet)
		return inRet;
#else
	inRet=inCTOS_SetCurrency();
	if(d_OK != inRet)
		return inRet;
#endif

	inRet=inEMVCheckCUPEnable(); /*check CUP USD*/
	if(d_OK != inRet)
		return inRet;

	inRet = inGetPolicyNumber();
	if(d_OK != inRet)
		return inRet;	

BINROUTE_AGAIN:

	fDualBrandedCard = FALSE;
    fBinRouteDCC = FALSE;
#if 0	
    if(inCTLSEMVCheck() == d_OK)
        fBinRoute=FALSE;	
#endif
	if(fCUPBinRoute() == d_OK)
		fBinRoute=FALSE;

	if(fAmexBinRoute() == d_OK)
	{
		fBinRoute=FALSE;
		
		if (inCheckIfHostEnable(2) != 0 )
		{
			if (fUSDSelected)
		       	strHDT.inHostIndex=srTransRec.HDTid=strCDT.HDTid=4;
		    else
		       	strHDT.inHostIndex=srTransRec.HDTid=strCDT.HDTid=2;
		}
	}

	if(fDinersBinRoute() == d_OK)
	{
		fBinRoute=FALSE;
		if (inCheckIfHostEnable(59) != 0 )
		{
			if (fUSDSelected)
	        	strHDT.inHostIndex=srTransRec.HDTid=strCDT.HDTid=106;
	        else
	        	strHDT.inHostIndex=srTransRec.HDTid=strCDT.HDTid=59;
		}
	}
	
	vdDebug_LogPrintf("srTransRec.stEMVinfo.T84 %x %x %x %x %x",srTransRec.stEMVinfo.T84[0], srTransRec.stEMVinfo.T84[1], srTransRec.stEMVinfo.T84[2],srTransRec.stEMVinfo.T84[3],srTransRec.stEMVinfo.T84[4] );
	if(memcmp(srTransRec.stEMVinfo.T84,"\xA0\x00\x00\x06\x35",5) == 0 || memcmp(srTransRec.stEMVinfo.T84,"\xa0\x00\x00\x06\x35",5) == 0)//Bancnet AID
	{
		vdDebug_LogPrintf("AID IS BANCNET");
		fBinRoute=FALSE;		
		srTransRec.HDTid = strCDT.HDTid = 53;
		srTransRec.inCardType = DEBIT_CARD;
		srTransRec.IITid = 1;
	}

	if(srTransRec.fOptOut == TRUE)
	{
		if(fBDOOptOutHostEnabled == TRUE)
			srTransRec.HDTid = strCDT.HDTid = BDO_OPTOUT_HDT_INDEX;
	}

	
 
	if ((strTCT.fATPBinRoute == TRUE) && (strCDT.fPANCatchAll == TRUE) && (fBinRoute == TRUE) && srTransRec.fOptOut != TRUE){
	
		#define ATPBINROUTE
		#ifdef ATPBINROUTE
			    //do not do ATP routing if USD selected
			 //if (fUSDSelected == FALSE){
				vdSetATPBinRouteFlag(1);
				fRouteToSpecificHost = 0;
				fMagStripeDebit=FALSE;
				fMagStripeCUP=FALSE;
				fNoCTLSSupportforBinRoute=FALSE;
				inRet = inCTOSS_ATPBinRoutingProcess();
				vdDebug_LogPrintf("inCTOSS_ATPBinRoutingProcess inRet=[%d]",inRet);
				vdDebug_LogPrintf("szRespCode_Temp[%d]",atoi(srTransRec.szRespCode_Temp));
				if(inRet == VS_CONTINUE && srTransRec.byEntryMode == CARD_ENTRY_WAVE 
					&& atoi(srTransRec.szRespCode_Temp) != 72 && atoi(srTransRec.szRespCode_Temp) != 79/*not AMEX*/ && srTransRec.fDualBrandedCredit != TRUE)
				{
ENTER_AGAIN:	
					vdResetAllCardData();		
					fNoCTLSSupportforBinRoute = TRUE;
				
					inRetVal = inCTOS_GetCardFieldsFailedCtlsFallbackEx();
					if(d_OK != inRetVal)
					{
						if(inRetVal == ST_ERROR || inRetVal == INVALID_CARD)//
							goto ENTER_AGAIN;
						else
						{
							vdSetECRResponse(ECR_OPER_CANCEL_RESP);
							return inRetVal;
						}
					}
					else
						goto BINROUTE_AGAIN;
				}
				
				vdSetATPBinRouteFlag(0);
				if(VS_CONTINUE != inRet)
					return inRet;

				vdDebug_LogPrintf("strCDT.HDTid[%d]",strCDT.HDTid);
				vdDebug_LogPrintf("srTransRec.inCardType[%d]",srTransRec.inCardType);
				vdDebug_LogPrintf("srTransRec.IIT[%d]",srTransRec.IITid);
					                   
				//memset( &srTransRec, 0x00, sizeof(TRANS_DATA_TABLE));

				if (fSkipBINRoutingForDebit == FALSE){
					if (strCDT.HDTid == 53 && srTransRec.byEntryMode == CARD_ENTRY_ICC) {
						vdDebug_LogPrintf("inside fSkipBINRoutingForDebit == FALSE");
						//vdCTOS_ResetMagstripCardData();
						//memset(&stRCDataAnalyze,0x00,sizeof(EMVCL_RC_DATA_ANALYZE));
						//memset(&strEMVT,0x00, sizeof(STRUCT_EMVT));

                        //fix for RC: 05 response from host
                        //add code
                        #if 1
						//inCTOSS_CLMCancelTransaction();
						vdResetAllCardData();
						vdCTOS_SetTransEntryMode(CARD_ENTRY_ICC);//Fix where byEntryMode is set to 0 by vdCTOS_ResetMagstripCardData().
						inRet = inCTOS_EMVCardReadProcess();
						
						if(d_OK != inRet)
							return inRet;
						
						#else
						//removed- fix for RC: 05 response from host
						if (strTCT.byCtlsMode == 0)
							inRet = inCTOS_GetCardFields();
						else
							inRet = inCTOS_WaveGetCardFields();

						if(d_OK != inRet)
							return inRet;
						//reemoved
						#endif
						
                        //srTransRec.byEntryMode = CARD_ENTRY_ICC;//Fix where byEntryMode is set to 0 by vdCTOS_ResetMagstripCardData().
                        strCDT.HDTid = 53;
						srTransRec.inCardType = DEBIT_CARD;				
						srTransRec.IITid = 1;						
						inIITRead(srTransRec.IITid);
						strcpy(srTransRec.szCardLable, strIIT.szIssuerLabel);
					}
				}

                if(fMagStripeDebit==TRUE)
                {
                   if (strCDT.HDTid == 53 && srTransRec.byEntryMode == CARD_ENTRY_ICC)
                   {
						vdRemoveCard();
								
                        vdCTOS_ResetMagstripCardData(); 
                        inRet = inCTOS_GetCardFieldsSwipeOnly();
                        if(d_OK != inRet)
                            return inRet;	
                            
                        strCDT.HDTid = 53;
                        srTransRec.inCardType = DEBIT_CARD;
						srTransRec.IITid = 1;						
						inIITRead(srTransRec.IITid);
						strcpy(srTransRec.szCardLable, strIIT.szIssuerLabel);
                    }
                }

				if(fMagStripeCUP==TRUE)
                {
                   if ((strCDT.HDTid == 36 || strCDT.HDTid == 37) && srTransRec.byEntryMode == CARD_ENTRY_ICC)
                   {
						vdRemoveCard();
								
                        vdCTOS_ResetMagstripCardData(); 
                        inRet = inCTOS_GetCardFieldsSwipeOnly();
                        if(d_OK != inRet)
                            return inRet;	

						if (fUSDSelected)
							strCDT.HDTid = 37;
						else
					    	strCDT.HDTid = 36;

						srTransRec.IITid = 9;
                        inIITRead(srTransRec.IITid);
						strcpy(srTransRec.szCardLable, strIIT.szIssuerLabel);
                    }
                }

			    if (strCDT.HDTid == 56){		
					//add fleet card processing
					srTransRec.fFleetCard = TRUE;
					inRet = inFleetGetLiters();
					if(d_OK != inRet)
						return inRet;
					
					inRet = inFleetSelectProductCode();
					if(d_OK != inRet)
						return inRet;
						//end fleet modifications
			    }
				
				vdDebug_LogPrintf("strCDT.HDTid[%d] :: srTransRec.byEntryMode[%d] :: fBinRouteDCC[%d]",strCDT.HDTid,srTransRec.byEntryMode,fBinRouteDCC);
				vdDebug_LogPrintf("fAMEXHostEnable[%d] :: srTransRec.byEntryMode[%d] :: strCDT.HDTid[%d]",fAMEXHostEnable,srTransRec.byEntryMode,strCDT.HDTid);
				if( (srTransRec.byEntryMode == CARD_ENTRY_ICC && fBinRouteDCC== FALSE) && fRouteToSpecificHost == TRUE)
#if 0					
				 ( (strCDT.HDTid == 56 || strCDT.HDTid == 59 || strCDT.HDTid == 2 || strCDT.HDTid == 4) || // Do not perform inCTOS_EMVProcessing() for Diners, Fleet, AMEX and AMEX USD. inCTOS_EMVProcessing() was already called inside inCTOSS_ATPBinRoutingProcess()
				   (fAMEXHostEnable == FALSE && strCDT.HDTid == 1)) ) // If AMEX is disabled and AMEX transactions will be saved to BDO host, do not perform inCTOS_EMVProcessing() again. inCTOS_EMVProcessing() was already called inside inCTOSS_ATPBinRoutingProcess()
#endif	
				{
					fNoEMVProcess = TRUE; 
				} 
					
			//}		
		#endif
			if(strIIT.fGetPolicyNumber == TRUE && strlen(srTransRec.szPolicyNumber) == 0)
			{
				inRet = inGetPolicyNumber();
				if(d_OK != inRet)
					return inRet;
			}
	}
	else{
		
		vdSetATPBinRouteFlag(0);

		if (strCDT.HDTid == 56){		
			//add fleet card processing
			srTransRec.fFleetCard = TRUE;
			inRet = inFleetGetLiters();
			if(d_OK != inRet)
				return inRet;

			inRet = inFleetSelectProductCode();
			if(d_OK != inRet)
				return inRet;
			//end fleet modifications
		}
		vdDebug_LogPrintf("inCTOS_WaveFlowProcess ZZZ invoice num %x%x%x",srTransRec.szInvoiceNo[0], srTransRec.szInvoiceNo[1],srTransRec.szInvoiceNo[2]);

		vdDebug_LogPrintf("GOC 1 = [%d]", strCDT.HDTid);
#if 0		
		if (strCDT.HDTid == DEBIT_HDT_INDEX && srTransRec.byEntryMode == CARD_ENTRY_WAVE)
		{
		    
			vdDebug_LogPrintf("GOC 2  = [%d]", strCDT.HDTid);
			strCDT.HDTid = 1;	
			srTransRec.inCardType = CREDIT_CARD;
			srTransRec.IITid = 21;	
			inIITRead(srTransRec.IITid);
			strcpy(srTransRec.szCardLable, strIIT.szIssuerLabel);
		}
#endif		 
	}

    //inRet = inCTOS_PreConnectAndInit();
    //if(d_OK != inRet)
        //return inRet;


//if (chGetInit_Connect() != 1)
{
	vdDebug_LogPrintf("inCTOS_WaveFlowProcess GOC 3 = [%d][%d]", strCDT.HDTid, srTransRec.MITid);

    //inRet = inCTOS_SelectHost(); // Check if Host is enabled
    inRet = inCTOS_SelectHostEx2();
    if(d_OK != inRet)
        return inRet;

	#if 1
    //if (inMMTReadRecord(strCDT.HDTid,srTransRec.MITid) != d_OK) // Also check if Merchant using host is enabled
    if (inMMTReadRecordEx(strCDT.HDTid,srTransRec.MITid) != d_OK) // Also check if Merchant using host is enabled
    {
        vdDisplayErrorMsgResp2(" ", "TRANSACTION", "NOT ALLOWED");
		vdDebug_LogPrintf("inCTOS_WaveFlowProcess TRANSACTION NOT ALLOWED");
		
		inDatabase_TerminalCloseDatabase();
        return(d_NO);
    }	
	inDatabase_TerminalCloseDatabase();
	#endif
}


#if 0
	//version16
	if (fSmacScan == TRUE){
		memset(szQrCodeText, 0x00, sizeof(szQrCodeText));
		//sprintf(szQrCodeText,"D01%s%d%s%s%s%s%s%s",srTransRec.szBaseAmount,
		//srTransRec.ulTraceNum,srTransRec.szTID, 
		//srTransRec.szMID, srTransRec.szInvoiceNo,
		//strMMT[0].szMerchantName,strMMT[0].szRctHdr1);
		strcpy(szQrCodeText,"D01");

		memset(szBuffer, 0x00, sizeof(szBuffer));
		wub_hex_2_str(srTransRec.szBaseAmount, szBuffer, 6);
		vdDebug_LogPrintf("testlang amount %s", szBuffer);
		strcat(szQrCodeText, szBuffer);

        //increment trace number
		memcpy(szBcd, strHDT.szTraceNo, INVOICE_BCD_SIZE);
		inBcdAddOne(szBcd, strHDT.szTraceNo, INVOICE_BCD_SIZE);	
		inHDTSave(strHDT.inHostIndex);
  		//srTransRec.ulTraceNum = wub_bcd_2_long(strHDT.szTraceNo,3);
		//end incremrnt

		memset(szBuffer, 0x00, sizeof(szBuffer));
		wub_hex_2_str(strHDT.szTraceNo, szBuffer, 3);
		vdDebug_LogPrintf("testlang stan %s", szBuffer);
		strcat(szQrCodeText, szBuffer);

			
		strcat(szQrCodeText, srTransRec.szTID);
		vdDebug_LogPrintf("testlang TID %s", srTransRec.szTID);
		strcat(szQrCodeText, srTransRec.szMID);
		vdDebug_LogPrintf("testlang MID %s", srTransRec.szMID);
		

		memset(szBuffer, 0x00, sizeof(szBuffer));
		wub_hex_2_str(strTCT.szInvoiceNo, szBuffer, 3);
		vdDebug_LogPrintf("testlang invoice %s", szBuffer);
		strcat(szQrCodeText, szBuffer);

		strcat(szQrCodeText, strMMT[0].szMerchantName);
		vdDebug_LogPrintf("testlang Merchant name  %s", strMMT[0].szMerchantName);
		
		strcat(szQrCodeText, strMMT[0].szRctHdr1);
		vdDebug_LogPrintf("testlang Merchant header %s", strMMT[0].szRctHdr1);

		strcat(szQrCodeText, strMMT[0].szRctHdr2);
		vdDebug_LogPrintf("testlang Merchant header %s", strMMT[0].szRctHdr2);

		strcat(szQrCodeText, strMMT[0].szRctHdr3);
		vdDebug_LogPrintf("testlang Merchant header %s", strMMT[0].szRctHdr3);

		strcat(szQrCodeText, strMMT[0].szRctHdr4);

		vdDebug_LogPrintf("testlang szQrCodeText %s", szQrCodeText);


		inRet = inCTOSS_DisplayQRCodeAndConfirm(szQrCodeText);
		if(d_OK != inRet)
			return inRet;



	}
#else
		vdDebug_LogPrintf("inCTOS_WaveFlowProcess AAA invoice num %x%x%x",srTransRec.szInvoiceNo[0], srTransRec.szInvoiceNo[1],srTransRec.szInvoiceNo[2]);

		if (fSmacScan == TRUE){

			//00160 - No SCAN label printed in Smac QR void receipt
			srTransRec.fSMACPrintscan = TRUE;
			
			memset(szQrCodeText, 0x00, sizeof(szQrCodeText));
			//sprintf(szQrCodeText,"D01%s%d%s%s%s%s%s%s",srTransRec.szBaseAmount,
			//srTransRec.ulTraceNum,srTransRec.szTID, 
			//srTransRec.szMID, srTransRec.szInvoiceNo,
			//strMMT[0].szMerchantName,strMMT[0].szRctHdr1);
			strcpy(szQrCodeText,"D01|");

			memset(szBuffer, 0x00, sizeof(szBuffer));
			wub_hex_2_str(srTransRec.szBaseAmount, szBuffer, 6);
			vdDebug_LogPrintf("inCTOS_WaveFlowProcess testlang amount %s", szBuffer);
			strcat(szQrCodeText, szBuffer);
			strcat(szQrCodeText,"|");

            //increment trace number
			memcpy(szBcd, strHDT.szTraceNo, INVOICE_BCD_SIZE);
			inBcdAddOne(szBcd, strHDT.szTraceNo, INVOICE_BCD_SIZE);	
			inHDTSave(strHDT.inHostIndex);
  			//srTransRec.ulTraceNum = wub_bcd_2_long(strHDT.szTraceNo,3);
			//end incremrnt

			//trace number
			memset(szBuffer, 0x00, sizeof(szBuffer));
			wub_hex_2_str(strHDT.szTraceNo, szBuffer, 3);
			vdDebug_LogPrintf("inCTOS_WaveFlowProcess testlang stan %s", szBuffer);			
			
			strcat(szQrCodeText, szBuffer);
			strcat(szQrCodeText,"|");

			//TID
			strcat(szQrCodeText, srTransRec.szTID);
			strcat(szQrCodeText,"|");			
			vdDebug_LogPrintf("inCTOS_WaveFlowProcess testlang TID %s", srTransRec.szTID);
			

			//MID
			strcat(szQrCodeText, srTransRec.szMID);
			strcat(szQrCodeText,"|");			
			vdDebug_LogPrintf("inCTOS_WaveFlowProcess testlang MID %s", srTransRec.szMID);

			
			//Invoice number
			memset(szBuffer, 0x00, sizeof(szBuffer));			
			memset(szBcd, 0x00, sizeof(szBcd));
			
#if 0			
			wub_hex_2_str(srTransRec.szInvoiceNo, szBcd, INVOICE_BCD_SIZE);

			vdDebug_LogPrintf("testlang invoice %s", szBcd);
			strcat(szQrCodeText, szBcd);
			strcat(szQrCodeText,"|");			
			

#else		
			// for testing only - 03012023 - 00136 - SM: No delimiter pipe ( I ) on smac qrcode #2
			vdDebug_LogPrintf("#00136 inCTOS_WaveFlowProcess - BBB %s", szBuffer);

			//00125 - SM: Different stan # / invoice # in SMAC QR data and	MTI 200 sale request #2
			//00158 - Same invoice # in MTI  200 request for SMAC transaction
			#if 1 // - 
			inTCTRead(1);
		    inRet = inCTOS_GetInvoice();
		    if(d_OK != inRet)
		        return inRet;
			#endif

			vdDebug_LogPrintf("#00136 inCTOS_WaveFlowProcess - CCC %s", szBuffer);
			
			wub_hex_2_str(strTCT.szInvoiceNo, szBuffer, 3);
			vdDebug_LogPrintf("inCTOS_WaveFlowProcess testlang invoice %s", szBuffer);
			strcat(szQrCodeText, szBuffer);
			strcat(szQrCodeText,"|");
			
#endif


#if 0
			strcat(szQrCodeText, strMMT[0].szMerchantName);			
			strcat(szQrCodeText,"|");
			vdDebug_LogPrintf("inCTOS_WaveFlowProcess testlang Merchant name  %s", strMMT[0].szMerchantName);

			strcat(szQrCodeText, strMMT[0].szRctHdr1);			
			strcat(szQrCodeText,"|");
			vdDebug_LogPrintf("inCTOS_WaveFlowProcess testlang Merchant header %s", strMMT[0].szRctHdr1);
#else
			vdDebug_LogPrintf("inCTOS_WaveFlowProcess srTransRec.MITid %d", srTransRec.MITid);
			vdDebug_LogPrintf("#00136 inCTOS_WaveFlowProcess FOOTER FROM NMT TABLE");
			
			inNMTReadRecord(srTransRec.MITid);		

			strcat(szQrCodeText, strSingleNMT.szMerchName);
			strcat(szQrCodeText,"|");
			vdDebug_LogPrintf("testlang Merchant name  %s", strSingleNMT.szMerchName);

			strcat(szQrCodeText, strSingleNMT.szRctHdr1);
			//strcat(szQrCodeText,"|");			
			vdDebug_LogPrintf("testlang Merchant header1 %s", strSingleNMT.szRctHdr1);

			strcat(szQrCodeText, strSingleNMT.szRctHdr2);
			//strcat(szQrCodeText,"|");			
			vdDebug_LogPrintf("testlang Merchant header2 %s", strSingleNMT.szRctHdr2);

			strcat(szQrCodeText, strSingleNMT.szRctHdr3);
			//strcat(szQrCodeText,"|");			
			vdDebug_LogPrintf("testlang Merchant header3 %s", strSingleNMT.szRctHdr3);

			strcat(szQrCodeText, strSingleNMT.szRctHdr4);
			//strcat(szQrCodeText,"|");
			vdDebug_LogPrintf("testlang Merchant header4 %s", strSingleNMT.szRctHdr4);			

			strcat(szQrCodeText, strSingleNMT.szRctHdr5);
			vdDebug_LogPrintf("testlang Merchant header5 %s", strSingleNMT.szRctHdr5);			

#endif
			vdDebug_LogPrintf("inCTOS_WaveFlowProcess testlang szQrCodeText %s", szQrCodeText);
			vdDebug_LogPrintf("inCTOS_WaveFlowProcess srTransRec.fSMACPrintscan %d", srTransRec.fSMACPrintscan);		


			inRet = inCTOSS_DisplayQRCodeAndConfirm(szQrCodeText);

			if(d_OK != inRet)
				return inRet;


		}

#endif

    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
    	if (srTransRec.byTransType == REFUND)
				inEVENT_ID = d_IPC_CMD_WAVE_REFUND;
			else
				inEVENT_ID = d_IPC_CMD_WAVE_SALE;

		if(srTransRec.usTerminalCommunicationMode == DIAL_UP_MODE || srTransRec.usTerminalCommunicationMode == ETHERNET_MODE)
		{	
			char szAPName[25];
			int inAPPID;
			inMultiAP_CurrentAPNamePID(szAPName, &inAPPID);
			if (strcmp (strHDT.szAPName,szAPName) != 0)
				inCTOS_inDisconnect();
		}
		
        inRet = inCTOS_MultiAPSaveData(inEVENT_ID);
		if(strTCT.fSMMode == 1)
		{
			if(get_env_int("SMCARDRETRY") == 1 && (get_env_int("SMCARDRETRYCOUNT")<=strTCT.inSMCardRetryCount) && (!fGetECRTransactionFlg()))
			{
				vdRemoveCard();
				vdSMReEnterCardDetails();
				goto SWIPE_AGAIN;
			}
		}
		if(d_OK != inRet)
            return inRet;
    }
    else
    {
        if (inMultiAP_CheckSubAPStatus() == d_OK)
        {
            inRet = inCTOS_MultiAPGetData();
            if(d_OK != inRet)
                return inRet;
            
            inRet = inCTOS_MultiAPReloadTable();
            if(d_OK != inRet)
                return inRet;

			inRet = inCTOS_MultiAPReloadWaveData();
            if(d_OK != inRet)
                return inRet;
        }
        inRet = inCTOS_MultiAPCheckAllowd();
        if(d_OK != inRet)
            return inRet;
    }
	
	if(strTCT.fDCC	&& srTransRec.byEntryMode != CARD_ENTRY_WAVE && srTransRec.fOptOut != TRUE)
    {
		if((strTCT.fATPBinRoute == FALSE && strCDT.fDCCEnable == TRUE) || 
		   (strTCT.fATPBinRoute == TRUE && fBinRouteDCC && inSetIssuerforBINRouteDCC() == TRUE) )
		{
	       inRet = inCTOS_ProcessDCCRate();
	       if(d_OK != inRet)
	           return inRet;
		   memset(srTransRec.szRespCode,0x00,sizeof(srTransRec.szRespCode));
		   
		   //if(fNoCTLSSupportforBinRoute == TRUE)
		   		//fBinRouteDCC=FALSE;//Set to FALSE to perform inCTOS_EMVProcessing()
		   	if(fBinRouteDCC == TRUE && srTransRec.fDCC == TRUE && srTransRec.byEntryMode == CARD_ENTRY_ICC)
			{
				vdDebug_LogPrintf("Resetting EMV Structure");
				memset(&stRCDataAnalyze,0x00,sizeof(EMVCL_RC_DATA_ANALYZE));
				memset(&strEMVT,0x00, sizeof(STRUCT_EMVT));
				inCTOS_EMVCardReadProcess();
			}
			else if(fBinRouteDCC == TRUE && srTransRec.fDCC == FALSE)
				fNoEMVProcess = TRUE;
			
			inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);
		}
    }
	
	//

    inRet = inCTOS_CheckMustSettle();
    if(d_OK != inRet)
    {
		//vdSetECRResponse(ECR_OPER_CANCEL_RESP);
		return inRet;
    }
    inRet = inCTOS_CheckIssuerEnable();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_CheckTranAllowd();
    if(d_OK != inRet)
        return inRet;

	if(fNoCTLSSupportforBinRoute == TRUE && fDualBrandedCard == TRUE)
   		fDualBrandedCard=FALSE;//Set to FALSE to perform inCTOS_EMVProcessing()

    if (fDualBrandedCard == FALSE && fNoEMVProcess == FALSE)
	{
    	inRet = inCTOS_EMVProcessing();
    	if(d_OK != inRet)
        	return inRet;  
    }
		//EMV: Online PIN enchancement - start -- jzg
#ifdef ONLINE_PIN_SUPPORT
		srTransRec.fEMVPIN = FALSE;
		vdDebug_LogPrintf("JEFF::inCTOS_WaveFlowProcess 9F34 = [%02X %02X %02X]", srTransRec.stEMVinfo.T9F34[0], srTransRec.stEMVinfo.T9F34[1], srTransRec.stEMVinfo.T9F34[2]);
		if((srTransRec.stEMVinfo.T9F34[0] & 0x0F) == 0x02)
		{
			inRet = inGetIPPPin();
			if(d_OK != inRet)
				 return inRet;
			else
				srTransRec.fEMVPIN = TRUE;		
		}
#endif
		//EMV: Online PIN enchancement - end -- jzg


   if(srTransRec.usTerminalCommunicationMode == GPRS_MODE || (srTransRec.usTerminalCommunicationMode == WIFI_MODE && fAutoSMACLogon == FALSE))
   {
   		if (chGetInit_Connect() != 1)
   		{
            inRet = inCTOS_PreConnect();
            if(d_OK != inRet)
                return inRet;
   		}
   }else{

		if (strTCT.fSingleComms){	
			if(inCPTRead(1) != d_OK)
			{
				vdSetErrorMessage("LOAD CPT ERR");
				return(d_NO);
			}
		//}else
		//{
		//	inRet = inCTOS_PreConnect();
		//	if(d_OK != inRet)
		//		return inRet;
		}

		if(fCommsFallback == TRUE && srTransRec.fDCC == TRUE)//Comms fallback already done during DCC rate request. inCPTRead will overwrite value of inCommunicationMode set in inCTOS_CommsFallback() and needs to be set again.
		{
			srTransRec.usTerminalCommunicationMode = strCPT.inCommunicationMode = inCommsFallbackMode; 
			fCommsFallback = FALSE;
			inCommsFallbackMode = -1;
			
		}	
		
   }
   vdDebug_LogPrintf("inCTOS_WaveFlowProcess BBB1 fSmacScan [%d]", fSmacScan);


	//00125 - SM: Different stan # / invoice # in SMAC QR data and  MTI 200 sale request #1
	if(fSmacScan != TRUE)
	{
		if(get_env_int("BINROUTE") != TRUE)//Fix to invoice number incrementing twice on Bin Routing setup.
		{
		    inRet = inCTOS_GetInvoice();
		    if(d_OK != inRet)
		        return inRet;
		}
	}
	else
	{
        memcpy(srTransRec.szInvoiceNo,strTCT.szInvoiceNo, 3);
		vdDebug_LogPrintf("inCTOS_WaveFlowProcess BBBa invoice num %x%x%x",srTransRec.szInvoiceNo[0], srTransRec.szInvoiceNo[1],srTransRec.szInvoiceNo[2]);
	}
		



	vdDebug_LogPrintf("inBuildAndSendIsoData -- START");

	//inCTOSS_GetRAMMemorySize("BUILD&SEND START");
    inRet = inBuildAndSendIsoData();
	//inCTOSS_GetRAMMemorySize("BUILD&SEND END");
	vdDebug_LogPrintf("inBuildAndSendIsoData -- END");
	vdDebug_LogPrintf("testlang 4 barcodetext %s", srTransRec.szBarcodeText);


	vdDebug_LogPrintf("inCTOS_WaveFlowProcess CCC invoice num %x%x%x",srTransRec.szInvoiceNo[0], srTransRec.szInvoiceNo[1],srTransRec.szInvoiceNo[2]);
	
    vdDebug_LogPrintf("inCTOS_WaveFlowProcess KIKO srTransPara->szPAN:%s", srTransRec.szPAN);
	
    if(d_OK != inRet)
	{

		/*BDO: Set ECR response code to EN - COMM ERROR -- sidumili*/
		if (strlen(srTransRec.szRespCode) <= 0)
		{
			strcpy(srTransRec.szECRRespCode, ECR_COMMS_ERR);
		}
		else
		{
			inSMCardRetryCount = get_env_int("SMCARDRETRYCOUNT");
			inSMCardRetryCount++;
			put_env_int("SMCARDRETRYCOUNT",inSMCardRetryCount);
			if(strTCT.fSMMode == 1 && get_env_int("SMCARDRETRYCOUNT")<=strTCT.inSMCardRetryCount && (!fGetECRTransactionFlg()) )
			{
				vdRemoveCard();
				if(srTransRec.fDCC == TRUE)//copy local amount to the szTotalAmount
				{
					memset(srTransRec.szBaseAmount,0x00,sizeof(srTransRec.szBaseAmount));
					memcpy(srTransRec.szBaseAmount, srTransRec.szDCCLocalAmount,sizeof(srTransRec.szTotalAmount));
					srTransRec.fDCC = FALSE;
				}
				vdSMReEnterCardDetails();
				fBINVer = FALSE; // SET fBINVer to false for SMCARDRETRY scenario
				if(srTransRec.usTerminalCommunicationMode == DIAL_UP_MODE)
				{
					inRet = inCTOS_PreConnectEx();
					if (inRet != d_OK)
						return inRet;
				}
				goto SWIPE_AGAIN;
			}
		}

        return inRet;
    }



//VETSION 16

    inRet = inCTOSS_CheckCVMAmount();
    if (inRet == d_OK) {

	    vdDebug_LogPrintf("test nsr %d", inNSRFlag());
#ifdef DCC_SIGNPAD
		if(inFLGGet("fSignPad") && strTCT.fDCC && (srTransRec.fDCC || inNSRFlag() != TRUE) && srTransRec.fDCCInitiatedTxn && inIsEMVTxnWithPIN() != TRUE)
		{
			inRet = inSignPadSendReceive(d_COM2, GET_PAYMENT_SIGNATURE);		
			if(inRet != d_OK)
				srTransRec.fSignPadBypassSignature = TRUE;
		}
#endif	
    }else
       srTransRec.fSignPadBypassSignature = TRUE;
//version16



		
    inCTLOS_Updatepowrfail(PFR_IDLE_STATE);

	vdDebug_LogPrintf("testlang 2 barcodetext %s", srTransRec.szBarcodeText);
	//version16
	if (fSmacScan == TRUE){
		vdDebug_LogPrintf("szBarcodeText %s", szBarcodeText);
		if (strlen(szBarcodeText) > 0){
			memset(srTransRec.szBarcodeText, 0x00, sizeof(srTransRec));
			strcpy(srTransRec.szBarcodeText, szBarcodeText);

		}
				vdDebug_LogPrintf("srTransRec.szBarcodeText %s", srTransRec.szBarcodeText);

	}

    inRet = inCTOS_SaveBatchTxn();
    if(d_OK != inRet)
        return inRet;

    vdDebug_LogPrintf("inCTOS_UpdateAccumTotal");
	
    inRet = inCTOS_UpdateAccumTotal();
    if(d_OK != inRet)
        return inRet;

	
	inRet=inDisconnectIfNoPendingADVICEandUPLOAD(&srTransRec, strHDT.inNumAdv);
    if(d_OK != inRet)
        return inRet;
	
	
	// patrick add code 20141205 start, modified -- sidumili
	fECRBuildSendOK = TRUE;	
	if (fECRBuildSendOK){	
	    inRet = inMultiAP_ECRSendSuccessResponse();
	}

	if(inCheckSMACPayRedemption(&srTransRec) == TRUE)
	{
		inRet = inWriteMifareCardFields();
		if(d_OK != inRet)
			vdDisplayErrorMsgResp2("","CARD NOT","UPDATED");
	}
	
	vdDebug_LogPrintf("ushCTOS_ePadSignature");
	
    inRet = ushCTOS_ePadSignature();
    if(d_OK != inRet)
        return inRet;


	vdDebug_LogPrintf("ushCTOS_printReceipt");
	vdDebug_LogPrintf("testlang 3 barcodetext %s", srTransRec.szBarcodeText);
    vdDebug_LogPrintf("inCTOS_WaveFlowProcess KIKO1 srTransPara->szPAN:%s", srTransRec.szPAN);

	inRet = ushCTOS_printReceipt();
	vdDebug_LogPrintf("ushCTOS_printReceipt inRet [%d]", inRet);
	
	if(d_OK != inRet)
		return inRet;

	vdDebug_LogPrintf("inCTOS_WaveFlowProcess DDD invoice num %x%x%x",srTransRec.szInvoiceNo[0], srTransRec.szInvoiceNo[1],srTransRec.szInvoiceNo[2]);

#if 0
	//00125 - SM: Different stan # / invoice # in SMAC QR data and  MTI 200 sale request #2
	// need to increment for next SMAC QR transaction.
	//QR WAS scanned
	if(fSmacScan == TRUE)
	{
	    inRet = inCTOS_GetInvoice();
	    if(d_OK != inRet)
	        return inRet;
	}
#endif

	vdDebug_LogPrintf("inCTOS_WaveFlowProcess EEE invoice num %x%x%x",srTransRec.szInvoiceNo[0], srTransRec.szInvoiceNo[1],srTransRec.szInvoiceNo[2]);

	CTOS_LCDTClearDisplay(); //BDO UAT 0012: Merchant copy still being displayed during TC Upload -- jzg

	vdDebug_LogPrintf("inDisconnectIfNoPendingADVICEandUPLOAD");

    inCTLOS_Updatepowrfail(PFR_IDLE_STATE);

	CTOS_LCDTClearDisplay(); //BDO UAT 0012: Merchant copy still being displayed during TC Upload -- jzg
	
    inRet = inCTOS_EMVTCUpload();
    if(d_OK != inRet)
        return inRet;
    else
        vdSetErrorMessage("");

	CTOS_LCDTClearDisplay(); //BDO UAT 0012: Merchant copy still being displayed during Advice Upload -- sidumili

	
	if(strTCT.fSMMode == TRUE)
	{
		if (srTransRec.byTransType == SALE && srTransRec.HDTid == SMAC_HDT_INDEX)
		{
			if (srTransRec.fPrintCardHolderBal == TRUE)
				InSMACDisplayBalance();
		}
		else if(inCheckIfSMCardTransRec() == TRUE)
		{
			wub_hex_2_str(srTransRec.SmacBalance, szTemp1, AMT_BCD_SIZE);
			if(atol(szTemp1)>=0)
				if(srTransRec.HDTid != SMECARD_HDT_INDEX)
					InSMACDisplayBalance();
		}
	}
#if 0
	if(srTransRec.fOptOut == TRUE)
	{
		DebugAddHEX("szInvoiceNo",srTransRec.szInvoiceNo,INVOICE_BCD_SIZE);
		DebugAddHEX("szOptOutVoidInvoiceNo",srTransRec.szOptOutVoidInvoiceNo,INVOICE_BCD_SIZE);
	
		inRet = inDatabase_OptOutCompleteBatchUpdate(srTransRec.szOptOutVoidInvoiceNo);
		if(d_OK != inRet)
		{
			vdDisplayErrorMsgResp2("OPT OUT", "BATCH UPDATE", "FAILED");
			return inRet;
		}
	}
#endif		
    if(strTCT.fDCC && srTransRec.fDCC)
    {
        inRet=inProcessTransLogTrans(&srTransRec, 1, 2, GET_ALL_EXCEPT_TIP);
        if(d_OK != inRet)
            return TRANSLOG_FAILED;
        else
            vdSetErrorMessage("");
    }
	
    if (srTransRec.byTransType != SALE_OFFLINE)	
    {
       inRet=inProcessAdviceTrans(&srTransRec, strHDT.inNumAdv);
       if(d_OK != inRet)
          return ADVICE_FAILED;
       else
          vdSetErrorMessage("");
    }

		
    if(strTCT.fDCC && srTransRec.fDCC)
    {
#if 0
        inRet=inProcessTransLogTrans(&srTransRec, 1, 2, GET_ALL_EXCEPT_TIP);
        if(d_OK != inRet)
            return inRet;
        else
            vdSetErrorMessage("");
#endif        
        inRet=inProcessTransLogTrans(&srTransRec, 1, 2, GET_TIP_ONLY);
        if(d_OK != inRet)
            return TRANSLOG_FAILED;
        else
            vdSetErrorMessage("");
    }
	
    return d_OK;
}

#endif





int inCTOS_WAVE_SALE(void)
{
	int inRet = d_NO;
	unsigned char bTC2ndbyte = 0,
		bTC3rdbyte = 0;
	char szAmtBuff[AMT_ASC_SIZE+1];
	BYTE szTempBaseAmount[AMT_BCD_SIZE+1]; // 00126 - SM: Can't process SMAC QR any amount via ECR triggered


    vdDebug_LogPrintf("inCTOS_WAVE_SALE fAmountFromIdle:[%d]", fAmountFromIdle);
	DebugAddHEX("inCTOS_WAVE_SALE BASE AMOUNT",srTransRec.szBaseAmount,AMT_BCD_SIZE);	
	//memset(szTempBaseAmount,0x00,sizeof(szTempBaseAmount));
	//wub_hex_2_str(srTransRec.szBaseAmount,szTempBaseAmount,AMT_BCD_SIZE);

    inSetColorMenuMode();		
	CTOS_LCDTClearDisplay();
	vdCTOS_SetTransType(SALE);
	vdDispTransTitle(srTransRec.byTransType);
	vdCTOS_DispStatusMessage("PROCESSING...");  //NER

	if(fAmountFromIdle != TRUE) //00159 - Incorrect transaction flow in SMAC QR via amount entry
    vdCTOS_TxnsBeginInit();

	//if(fAmountFromIdle)		
	//	memcpy(srTransRec.szBaseAmount, szTempBaseAmount, 6); // 00126

	wub_hex_2_str(srTransRec.szBaseAmount,szAmtBuff,AMT_BCD_SIZE);
	vdDebug_LogPrintf("inCTOS_WAVE_SALE DIGITAL WALLET AMOUT IS %s",szAmtBuff);
	
    if ((strTCT.fSingleComms) && (fPreConnectEx == FALSE)){
		inRet = inCTOS_PreConnectEx();

		if (inRet != d_OK)
			return inRet;
	}

	srTransRec.fVoidOffline = CN_FALSE;

	//vdDispTransTitle(SALE);
    vdDebug_LogPrintf("fEntryCardfromIDLE:%d", fEntryCardfromIDLE);
    if(fEntryCardfromIDLE == FALSE)
    {
		vdDebug_LogPrintf("enable CTLS");
        if(strTCT.byCtlsMode != NO_CTLS)
        {
            vdCTOSS_SetWaveTransType(1);
            inRet = inCTOSS_CLMOpenAndGetVersion();
            if(d_OK != inRet)
                return inRet;
        }
    }
	
	vdDebug_LogPrintf("fGetECRTransactionFlg=[%d]",fGetECRTransactionFlg());
    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiStopResumeAP("SHARLS_ECRBDO");

	inRet = inCTOS_WaveFlowProcess();

    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiResumeContinueAP("SHARLS_ECRBDO");

	
    if(fEntryCardfromIDLE == FALSE)
    {
		vdDebug_LogPrintf("disale CTLS");
		vdDebug_LogPrintf("");
        if(strTCT.byCtlsMode != NO_CTLS)
            vdCTOSS_CLMClose();
    }
	
	/* Send response to ECR -- sidumili */
	if (!fECRBuildSendOK){	
		inMultiAP_ECRSendSuccessResponse();
	}	
	fECRBuildSendOK = FALSE;
	/* Send response to ECR -- sidumili */

	inCTOS_inDisconnect();
	vdCTOS_TransEndReset();
	//vdCTOSS_MainAPMemoryRecover();
	
	return inRet;
}



int inCTOS_WAVE_REFUND(void)
{
    int inRet = d_NO;

    CTOS_LCDTClearDisplay();

    vdCTOS_TxnsBeginInit();

	vdCTOS_SetTransType(REFUND);
	vdCTOSS_SetWaveTransType(1);

	vdCTOSS_GetAmt();

	inRet = inCTOSS_CLMOpenAndGetVersion();
	if(d_OK != inRet)
        return inRet;
	//display title
    vdDispTransTitle(REFUND);

    inRet = inCTOS_WaveFlowProcess();

	vdCTOSS_CLMClose();

    inCTOS_inDisconnect();

    vdCTOS_TransEndReset();

    return inRet;
}



void vdCTOS_InitWaveData(void)
{
	BYTE bInBuf[250];
	BYTE bOutBuf[250];
	BYTE *ptr = NULL;
	USHORT usInLen = 0;
	USHORT usOutLen = 0;
	USHORT usResult;
	int inCTLSmode = 0;
	
	inCTLSmode = inCTOSS_GetCtlsMode();
	if (NO_CTLS == inCTLSmode)
		return;

	//Open the Back Light in the LCD Display //
	vduiKeyboardBackLight(VS_TRUE);
	vduiLightOn();
	CTOS_LCDTClearDisplay();
    vdDispTitleString((BYTE *)"CONTACTLESS");
	setLCDPrint(5, DISPLAY_POSITION_LEFT, "CONFIGURE READER...");
	
	memset(bOutBuf, 0x00, sizeof(bOutBuf));
	memset(bInBuf, 0x00, sizeof(bInBuf));
	
	vdDebug_LogPrintf("d_IPC_CMD_EMV_WAVESETTAGS usInLen[%d],inCTLSmode=[%d],GetCtlsMode=[%d] ",usInLen,inCTLSmode,inCTOSS_GetCtlsMode());
/*
	if(strTCT.byPinPadMode == 0)
	{
		if(strTCT.byPinPadType == 3 && CTLS_V3_SHARECTLS == inCTLSmode)
		{
			char szV3PSendBuf[1024+1];
			int inOffSet = 0;
			int status;
			char szRecvBuf[1024+1];
			int inRecvlen = 0;
			unsigned char *pszPtr;
			
			vdCTOSS_SetV3PRS232Port(strTCT.byPinPadPort);
			inCTOSS_V3PRS232Open(strTCT.inPPBaudRate, 'N', 8, 1);

			// send STX INJECT_KEY ETX LRC
			memset(szV3PSendBuf, 0x00, sizeof(szV3PSendBuf));
			inOffSet = 0;
			szV3PSendBuf[inOffSet] = STX;
			inOffSet += 1;
			memcpy(&szV3PSendBuf[inOffSet], "INIT_WAVE", strlen("INIT_WAVE"));
			inOffSet += strlen("INIT_WAVE");
			szV3PSendBuf[inOffSet] = ETX;
			inOffSet += 1;			
			szV3PSendBuf[inOffSet] = (char) wub_lrc(&(szV3PSendBuf[1]), inOffSet-1);
			inOffSet += 1;
			inCTOSS_V3PRS232SendBuf(szV3PSendBuf, inOffSet);	
			status = inCTOSS_V3PRS232RecvACK(szRecvBuf, &inRecvlen, (d_CEPAS_READ_BALANCE_CARD_PRESENT_TIMEOUT));						

			//inCTOSS_USBHostCloseEx();
			inCTOSS_V3PRS232Close();
			return ;
		}
	}
*/
	if (CTLS_INTERNAL == inCTLSmode || CTLS_EXTERNAL == inCTLSmode)
	{
		usResult = inMultiAP_RunIPCCmdTypes("SHARLS_EMV", d_IPC_CMD_EMV_WAVESETTAGS, bInBuf, usInLen, bOutBuf, &usOutLen);
	}

	if (CTLS_V3_SHARECTLS == inCTLSmode || CTLS_V3_INT_SHARECTLS == inCTLSmode)
	{
		usResult = inMultiAP_RunIPCCmdTypes("SHARLS_CTLS", d_IPC_CMD_EMV_WAVESETTAGS, bInBuf, usInLen, bOutBuf, &usOutLen);
	}	

}

void vdSMReEnterCardDetails(void)
{	
	char szTemp[MAX_CHAR_PER_LINE+1];
	char szTemp1[MAX_CHAR_PER_LINE+1];
	char szTemp2[MAX_CHAR_PER_LINE+1];

#if 0
	wub_hex_2_str(srTransRec.szTotalAmount, szTemp, AMT_BCD_SIZE);
	vdCTOS_FormatAmount(strCST.szAmountFormat, szTemp,szTemp1);
	sprintf(szTemp2,"%s %s",strCST.szCurSymbol,szTemp1);
	setLCDPrint27(3,DISPLAY_POSITION_LEFT,"REM TXN AMT:");
	setLCDPrint27(4,DISPLAY_POSITION_LEFT,szTemp2);
#endif

	memset(srTransRec.szRespCode,0x00,sizeof(srTransRec.szRespCode));
	memset(&stRCDataAnalyze,0x00,sizeof(EMVCL_RC_DATA_ANALYZE));
	memset(&strEMVT,0x00, sizeof(STRUCT_EMVT));
	
	vdCTOS_ResetMagstripCardData();
	put_env_int("SMCARDRETRY",0);
	fIdleInsert=0;
	fIdleSwipe=0;
	fEntryCardfromIDLE=0;
	CTOS_Beep();
	//CTOS_Delay(2500);
	
}



