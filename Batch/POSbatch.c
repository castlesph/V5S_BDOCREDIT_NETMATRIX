#include <string.h>
#include <stdio.h>
#include <stdlib.h>
/** These two files are necessary for calling CTOS API **/
#include <ctosapi.h>
#include "../Includes/POSbatch.h"
#include "../Includes/POSTypedef.h"

#include "../FileModule/myFileFunc.h"
#include "../POWRFAIL/POSPOWRFAIL.h"
#include "..\debug\debug.h"
#include "..\Database\DatabaseFunc.h"
#include "..\Includes\myEZLib.h"
#include "..\ui\Display.h"
#include "..\Includes\POSHost.h"
#include "..\debug\debug.h"
#include "../Ctls/POSCtls.h"

#include "..\Includes\date.h"
/* Issue# 000096: BIN VER Checking - start -- jzg*/
extern BOOL fBINVer;
extern char szBINVerSTAN[8];
/* Issue# 000096: BIN VER Checking - end -- jzg*/
BYTE byPackTypeBeforeDCCLog;
extern BOOL fRouteToSpecificHost;

int inCTOS_SaveBatchTxn(void)
{
	int inResult ;
	int inSaveType;

//save first transaction date in MMT
  	//BYTE szCurrDate[8+1] = {0};
  	CTOS_RTC SetRTC;
	myDate newdate;
	myDate szCurrDate;

	BYTE szPOSTID[10] = {0};

	BYTE szBaseAmount[12+1] = {0};
	BYTE szTipAmount[12+1] = {0};
	BYTE szLocalTotalAmount[12+1] = {0};

	vdDebug_LogPrintf("inCTOS_SaveBatchTxn");

	vdSaveLastInvoiceNo();
		
	inDatabase_BatchDeleteTransType(SMAC_BALANCE);//Delete any existing SMAC_BALANCE from the Batch
	inDatabase_BatchDeleteTransType(BALANCE_INQUIRY);//Delete any existing BALANCE_INQUIRY from the Batch

	
	vdDebug_LogPrintf("inCTOS_SaveBatchTxn ** TEST **szTID[%s]..szMID=[%s]..",srTransRec.szTID,srTransRec.szMID);
	
	if (wub_str_2_long(strMMT[0].szSettleDate) <= 0){	

		vdDebug_LogPrintf("inCTOS_SaveBatchTxn 2");

		//memset(szCurrDate, 0x00, sizeof(szCurrDate));
		CTOS_RTCGet(&SetRTC);
		//sprintf(szCurrDate,"%02d%02d%02d", SetRTC.bYear, SetRTC.bMonth, SetRTC.bDay);

        szCurrDate.year = SetRTC.bYear;
		szCurrDate.month = SetRTC.bMonth;
	    szCurrDate.day = SetRTC.bDay;

		//newdate = getNewDate(&szCurrDate, strMMT[0].inMustSettleNumOfDays);
		
		newdate = getNewDate(&szCurrDate, strMMT[0].inMustSettleNumOfDays>0?strMMT[0].inMustSettleNumOfDays:strTCT.inBackupSettNumDays);
		sprintf(strMMT[0].szSettleDate, "%04d%02d%02d" ,newdate.year, newdate.month, newdate.day);  
		
		vdDebug_LogPrintf("settle days %s :: inMustSettleNumOfDays %d strTCT.inBackupSettNumDays %d", strMMT[0].szSettleDate, strMMT[0].inMustSettleNumOfDays, strTCT.inBackupSettNumDays); 	
		inMMTSave(strMMT[0].MMTid);
	}
//end save
	vdDebug_LogPrintf("inCTOS_SaveBatchTxn");
	inCTLOS_Updatepowrfail(PFR_BEGIN_BATCH_UPDATE);

	/* Issue# 000096: BIN VER Checking - start -- jzg*/
	if (fBINVer)
	{
		srTransRec.fBINVer = CN_TRUE;
		strcpy(srTransRec.szBINVerSTAN, szBINVerSTAN);
	}
	/* Issue# 000096: BIN VER Checking - end -- jzg*/

	/*Issue# 000299 -- sidumili*/
	srTransRec.inSavedCurrencyIdx = strCST.inCurrencyIndex;

	/*Saved flag for footer logo -- sidumili*/
	srTransRec.fFooterLogo = strHDT.fPrintFooterLogo && strTCT.fPrintFooterLogo;
	vdDebug_LogPrintf("srTransRec.fFooterLogo[%d]",srTransRec.fFooterLogo);

	if ((srTransRec.fECRTriggerTran == TRUE) && (strTCT.fSMMode == TRUE) && (srTransRec.byTransType != VOID)){
		inCTOSS_GetEnvDB("PTID", szPOSTID);
		strcpy(srTransRec.szPOSTID, szPOSTID);
	}
	
	vdDebug_LogPrintf("inCTOS_SaveBatchTxn byTransType[%d].byOffline[%d].byUploaded[%d].szPOSTID[%s].fECRTriggerTran[%d].fSMMode[%d]", srTransRec.byTransType, srTransRec.byOffline, srTransRec.byUploaded, srTransRec.szPOSTID, srTransRec.fECRTriggerTran, strTCT.fSMMode);
	if(srTransRec.byTransType == VOID && srTransRec.byOffline == CN_TRUE)
	{
		//OFFLINE SALE, then VOID it, the VOID is offline, should delete the OFFLINE SALE Advice
		if(srTransRec.byUploaded == CN_FALSE)
		{
			inCTOSS_DeleteAdviceByINV(srTransRec.szInvoiceNo);
		}
	}

	//1102   
	//if((srTransRec.byTransType == SALE) || (srTransRec.byTransType == REFUND) || (srTransRec.byTransType == SALE_OFFLINE) || (srTransRec.byTransType == PRE_AUTH))
	if((srTransRec.byTransType == SALE) || (srTransRec.byTransType == REFUND) || (srTransRec.byTransType == SALE_OFFLINE) || (srTransRec.byTransType == PRE_AUTH) 
		|| (srTransRec.byTransType == CASH_ADVANCE) || (srTransRec.byTransType == SMAC_BALANCE) || (srTransRec.byTransType == BALANCE_INQUIRY) 
		|| (srTransRec.byTransType == KIT_SALE) || (srTransRec.byTransType == RENEWAL) || (srTransRec.byTransType == PTS_AWARDING))
	//1102
	{

        if (srTransRec.byTransType != PRE_AUTH && srTransRec.byTransType != SMAC_BALANCE && srTransRec.byTransType != BALANCE_INQUIRY && 
			srTransRec.byTransType != KIT_SALE && srTransRec.byTransType != RENEWAL && srTransRec.byTransType != PTS_AWARDING){
	    	strMMT[0].fBatchNotEmpty = TRUE;
			inMMTSave(strMMT[0].MMTid);
        }
		else if(srTransRec.byTransType == PRE_AUTH)
		{
			strMMT[0].fPreAuthExisting = TRUE;
			inMMTSave(strMMT[0].MMTid);
		}
		
		inSaveType = DF_BATCH_APPEND;

		//Should be Online void the Intial SALE amount.
		if(srTransRec.byOffline == CN_FALSE)
		{
			//use szStoreID to store how much amount fill up in DE4 for VOID
			//either enter tip or not enter tip are ok
			memcpy(srTransRec.szStoreID, srTransRec.szTotalAmount, 6);

			if(srTransRec.fDCC)
			{
				memset(szBaseAmount,0x00,sizeof(szBaseAmount));
				memset(szTipAmount,0x00,sizeof(szTipAmount));
				memset(szLocalTotalAmount,0x00,sizeof(szLocalTotalAmount));
				memset(srTransRec.szLocalStoreID,0x00,sizeof(srTransRec.szLocalStoreID));
				
				wub_hex_2_str(srTransRec.szDCCLocalTipAmount, szTipAmount, 6);
				wub_hex_2_str(srTransRec.szDCCLocalAmount, szBaseAmount, 6); 
				sprintf(szLocalTotalAmount, "%012.0f", atof(szBaseAmount) + atof(szTipAmount));
				vdDebug_LogPrintf("szLocalTotalAmount [%s]",szBaseAmount);
				wub_str_2_hex(szLocalTotalAmount,srTransRec.szLocalStoreID,12);
				//memcpy(srTransRec.szLocalStoreID, srTransRec.szDCCLocalAmount, 6);
			}

		}
	}
	else
	{
		inSaveType = DF_BATCH_UPDATE;
	}

	if(srTransRec.byTransType == VOID)
		srTransRec.byVoided = TRUE;
	
	inResult = inDatabase_BatchSave(&srTransRec, inSaveType);

	if(inResult != ST_SUCCESS)
	{
		vdSetErrorMessage("Batch Save Error");
		return ST_ERROR;
	}

	if((memcmp(srTransRec.szAuthCode, "Y3",2))  && 
		(srTransRec.byTransType != SALE_OFFLINE) && 
		(srTransRec.byTransType != SALE_ADJUST)  &&
		(srTransRec.byTransType != SALE_TIP) &&		
	  ( srTransRec.byOffline != VS_TRUE))
	{
		inMyFile_ReversalDelete();
	}

	vdDebug_LogPrintf("Create Advice !!!!!!! test 1 - %x %d %d", srTransRec.bWaveSID, srTransRec.byEntryMode, srTransRec.byTransType);
	
	if((srTransRec.byTransType == SALE_TIP) || (srTransRec.byTransType == SALE_ADJUST) || (srTransRec.byTransType == SALE_OFFLINE && memcmp(srTransRec.szAuthCode, "Y1",2)==0)) 
	{
		
		vdDebug_LogPrintf("inMyFile_AdviceSave");
		//fix send tip adjust advie two times issue
		inCTOSS_DeleteAdviceByINV(srTransRec.szInvoiceNo);
		inMyFile_AdviceSave(&srTransRec, srTransRec.byPackType);
	}
	//if original txn is offline, then do a online txn piggy back the offline advice, the offline advice been deleted, then void it, the void is offline, need to create advice for this offline void
	else if(srTransRec.byTransType == VOID && srTransRec.byOffline == CN_TRUE && srTransRec.byUploaded == CN_TRUE)
	//else if(srTransRec.byTransType == VOID && srTransRec.byOffline == CN_TRUE && srTransRec.byUploaded == CN_FALSE)
	{
		vdDebug_LogPrintf("Create Advice for offline VOID");
		//fix send tip adjust advie two times issue
		inCTOSS_DeleteAdviceByINV(srTransRec.szInvoiceNo);
		inMyFile_AdviceSave(&srTransRec, OFFLINE_VOID);
	}
	//    else if((srTransRec.byTransType == SALE) && (srTransRec.byEntryMode == CARD_ENTRY_ICC))
	else if (((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||
		/* EMV: Revised EMV details printing - start -- jzg */
		//(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
		(srTransRec.bWaveSID == 0x65) ||
		(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
		(srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
		(srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
		//(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_2) ||
		(srTransRec.bWaveSID == 0x63) ||
		(srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS) ||		
		(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC)) && (srTransRec.byTransType == SALE))
		/* EMV: Revised EMV details printing - end -- jzg */ // patrick fix contactless 20140828
	{

	    
		vdDebug_LogPrintf(" !!!!!!! test 2 %s", srTransRec.szAuthCode);
		if((srTransRec.byTCuploaded == 0) ||
			(!memcmp(srTransRec.szAuthCode, "Y1",2)) || 
			(!memcmp(srTransRec.szAuthCode, "Y3",2)))
		{
			if((memcmp(srTransRec.szAuthCode, "Y1",2)) && 
			(memcmp(srTransRec.szAuthCode, "Y3",2)))
			{
				vdDebug_LogPrintf("Create Advice - TC UPLOAD");
				srTransRec.byPackType = TC_UPLOAD;
				inMyFile_TCUploadFileSave(&srTransRec, srTransRec.byPackType);
			}
			else
			{
				vdDebug_LogPrintf("Create Advice - OFFLINE");
				srTransRec.byPackType = SEND_ADVICE;
				inMyFile_AdviceSave(&srTransRec, srTransRec.byPackType);
			}
		}
	}
//issue-00369- add tc upload in cash advance
	else if((srTransRec.byTransType == REFUND || srTransRec.byTransType == PRE_AUTH || srTransRec.byTransType == CASH_ADVANCE) && (srTransRec.byEntryMode == CARD_ENTRY_ICC))
	{

        //Fix for Pre-auth DCC TC Upload - Get th FX TID and MID if TC Upload was resent (once failed or before settlement)
		if (srTransRec.byTransType == PRE_AUTH && strTCT.fDCC == TRUE && strCDT.fDCCEnable == TRUE 
					&& inGetATPBinRouteFlag() != TRUE && (srTransRec.HDTid != 2 && srTransRec.HDTid != 4/*Not AMEX and AMEX USD host*/) && inCheckIssuerforBINRoute() == TRUE/*&& fRouteToSpecificHost == FALSE*/){
			memcpy(srTransRec.szTID, strFXT.szFXTTID, strlen(strFXT.szFXTTID));	
			memcpy(srTransRec.szMID,"00000",5);
			memcpy(&srTransRec.szMID[5], strFXT.szFXTMID, strlen(strFXT.szFXTMID));
			//memcpy(srTransRec.szMID, strFXT.szFXTMID, strlen(strFXT.szFXTMID));
			srTransRec.fDCCAuth = TRUE;
		}
		
		srTransRec.byPackType = TC_UPLOAD;
		inMyFile_TCUploadFileSave(&srTransRec, srTransRec.byPackType);
		
	}

	
	if(strTCT.fDCC && srTransRec.fDCC && (srTransRec.byTransType == SALE_TIP || srTransRec.byTransType == VOID))				
	{
		byPackTypeBeforeDCCLog = srTransRec.byPackType;//Added before being overwriten by inDatabase_TransLogSave. Will be used for Receipt printing.
		if(srTransRec.byTransType == SALE_TIP)
			inDatabase_TransLogDelete(&srTransRec, DELETE_BY_TRANSTYPE_INVOICE);
		else
			inDatabase_TransLogDelete(&srTransRec, DELETE_BY_INVOICE);

		inDatabase_TransLogSave(&srTransRec);
	}

	return d_OK;
}



/* BDO: Removed CARD VER from batch review - start -- jzg */
int inCTOS_BatchReviewFlow(void)
{
	int inResult = d_OK;
	int inCount = 0;
	int inBatchRecordNum = 0;
	BYTE key = 0;
	int  *pinTransDataid = NULL;

	inBatchRecordNum = inBatchReviewNumRecord();

	pinTransDataid = (int*)malloc(inBatchRecordNum * sizeof(int));

	inBatchReviewByMerchandHost(inBatchRecordNum, srTransRec.HDTid, srTransRec.MITid, srTransRec.szBatchNo, pinTransDataid);

	inResult = inDatabase_BatchReadByTransId(&srTransRec, pinTransDataid[inCount]);

	if(inResult == d_NO)
	{
		vdDisplayErrorMsg(1, 8, "EMPTY BATCH");
		free(pinTransDataid);
		return d_OK;
	}

	inCTOS_DisplayBatchRecordDetail(BATCH_REVIEW);

	while(1)
	{ 
		CTOS_KBDHit(&key); 
		if(key == d_KBD_CANCEL) 
		{ 
			free(pinTransDataid);
			return; 
		} 
		else if((key == d_KBD_DOWN)||(key == d_KBD_DOT))
		{
			inCount++;     
			DebugAddIntX("inCount", inCount);

			if(inCount > inBatchRecordNum - 1)
			{
				vdDisplayErrorMsg(1, 8, "END OF BATCH");
				inCount = inBatchRecordNum - 1;			  		  			  
			}
			else
			{
				inResult = inDatabase_BatchReadByTransId(&srTransRec, pinTransDataid[inCount]);
				inCTOS_DisplayBatchRecordDetail(BATCH_REVIEW);	
			}
		} 
		else if((key == d_KBD_UP)||(key == d_KBD_00))
		{ 
			inCount--;
			DebugAddIntX("inCount", inCount);

			if(inCount >= 0)
			{
				inResult = inDatabase_BatchReadByTransId(&srTransRec, pinTransDataid[inCount]);
				inCTOS_DisplayBatchRecordDetail(BATCH_REVIEW);
				
			}
			else
            {
                if(inCount < 0)
                {
                    vdDisplayErrorMsg(1, 8, "END OF BATCH");
                    inCount = 0;				
                }
            }
		} 
	} 	

	free(pinTransDataid);
	return d_OK;

}
/* BDO: Removed CARD VER from batch review - end -- jzg */


