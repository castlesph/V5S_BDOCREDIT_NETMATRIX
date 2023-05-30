/*******************************************************************************

*******************************************************************************/

#include <string.h>
#include <stdio.h>
#include <ctosapi.h>
#include <stdlib.h>
#include <stdarg.h>
#include <typedef.h>
#include <EMVAPLib.h>
#include <EMVLib.h>


#include "..\Includes\POSTypedef.h"


#include "..\Includes\POSMain.h"
#include "..\Includes\POSTrans.h"
#include "..\Includes\POSHost.h"
#include "..\Includes\POSSale.h"
#include "..\Includes\POSbatch.h"
#include "..\ui\Display.h"
#include "..\Includes\V5IsoFunc.h"
#include "..\print\Print.h"
#include "..\Includes\POSHost.h"
#include "..\Comm\V5Comm.h"
#include "..\Includes\POSSetting.h"
#include "..\Includes\MultiApLib.h"
#include "..\Aptrans\MultiAptrans.h"
#include "..\FileModule\myFileFunc.h"
#include "..\Database\DatabaseFunc.h"
#include "../Debug/Debug.h"
#include "..\Includes\Wub_lib.h"
#include "..\Includes\myEZLib.h"
#include "..\Debug\Debug.h"

//smac
#include "..\Includes\posSmac.h"
//smac

//tms
#include "..\TMS\TMS.h"
//tms

extern char szGlobalAPName[25];

#define HOST_ONE_BY_ONE

int gvSettleType; //aaa fix on issue #000210 Terminal displays "Batch empty, skip" on all hosts when trying to settle hosts with no transactions 3 of 6

extern char szFuncTitleName [21 + 1]; //aaronnino for BDOCLG ver 9.0 fix on issue #0081 No Manual settle prompt upon 3 failed settlements 7 of 8

extern BOOL gblfBatchEmpty; //aaronnino for BDOCLG ver 9.0 fix on issue #0033 and #0034 "settle failed" error response after "comm error" 3 of 8

extern BOOL fAUTOManualSettle;

extern BOOL fAutoSettle;

extern BOOL fECRBuildSendOK;

BOOL inRevSettFlag = FALSE; //for inRequestAccessToken fxn. wont request/send if  no reversal file found.
int inCTOS_SettlementFlowProcess(void)
{
    int inRet = d_NO;

    vdCTOS_SetTransType(SETTLE);

	vdDebug_LogPrintf("inCTOS_SettlementFlowProcess START");
	
    //display title
    //vdDispTransTitle(SETTLE);
    inDatabase_BatchDeleteTransType(SMAC_BALANCE);
	inDatabase_BatchDeleteTransType(BALANCE_INQUIRY);//Delete any existing BALANCE_INQUIRY from the Batch
	
    vdCTOS_DispStatusMessage("PROCESSING...");// Replace SETTLE header with PROCESSING... message.

   /* inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;

	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;*/

   srTransRec.MITid = strNMT[0].NMTID; 

    inRet = inCTOS_SettlementSelectAndLoadHost();
    if(d_OK != inRet)
        return inRet;

	//srTransRec.MITid = strNMT[0].NMTID; //aaronnino for BDOCLG ver 10 fix on issue #00099 MULTI MERCHANT: Batch Empty displayed when process settlement on merchant 1 for Credit, Installment & CUP

    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_SETTLEMENT);
		inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);
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

            inRet = inCTOS_MultiAPReloadHost();
            if(d_OK != inRet)
                return inRet;
        }
    }


	//remove prompt fro selection-Merchant selection is done by inCTOS_TEMPCheckAndSelectMutipleMID
	//	  inRet = inCTOS_CheckAndSelectMutipleMID();
	//	  if(d_OK != inRet)
	//		  return inRet;
	inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);



	inRet = inCTOS_ChkBatchEmpty();


	//BDO: Added settlement status to settlement report - start -- jzg
	if(inRet != d_OK)
		strMMT[0].inSettleStatus = 0;
	else
		strMMT[0].inSettleStatus = 2;

	
	inMMTSave(strMMT[0].MMTid);
	//BDO: Added settlement status to settlement report - end -- jzg

#if 0
		//BDO: Added settlement status to settlement report - start -- jzg
		if(inRet != d_OK)
			strMMT[0].inSettleStatus = 0;
		else
			strMMT[0].inSettleStatus = 2;
		inMMTSave(strMMT[0].MMTid);
		//BDO: Added settlement status to settlement report - end -- jzg

		vdDebug_LogPrintf("JEFF::1>> Merch[%d] Settle Status[%d]", strMMT[0].MITid, strMMT[0].inSettleStatus); //remove later -- jzg
#endif

    if(d_OK != inRet)
    {
		inMMTSave(strMMT[0].MMTid);
        return inRet;
    }
	//set must settle flag once settlement wsa triggered
	strMMT[0].fMustSettFlag = CN_TRUE;
	inMMTSave(strMMT[0].MMTid);

    //version16
    if (srTransRec.HDTid != BDO_LOYALTY_HDT_INDEX){
    	inRet = inCTOS_PreConnect();
    	if(d_OK != inRet)
        	return inRet;
    }

    inGetDateAndTime(); /*set date and time*/

    // version16
	if (srTransRec.HDTid == BDO_LOYALTY_HDT_INDEX)
	{	
		int inResult, inHostIndex;
		int inBDOLoyRevReturn;
		
		vdCTOS_DispStatusMessage("PROCESSING...");// 04042023

		vdDebug_LogPrintf("inCTOS_SettlementFlowProcess (srTransRec.HDTid == BDO_LOYALTY_HDT_INDEX)");
		
//to send redemption reversal before settlement	
		//00208 - SM: 20 to 25 secnods Processing & White screen displayed during settlement  
		inBDOLoyRevReturn = vdChecksReversalFile();		
		vdDebug_LogPrintf("inCTLOS_Getpowrfail xxx inBDOLoyRevReturn[%d] srTransRec.HDTid [%d]", inBDOLoyRevReturn, srTransRec.HDTid);		

		if(inBDOLoyRevReturn)
		{
			//00167 (No reversal is sent before processing BDO Loyalty settlement) 
			inResult = inSendReversalOnSettle();
			vdDebug_LogPrintf("inCTOS_SettlementFlowProcess inSendReversalOnSettle inResult [%d]", inResult);
		}

		//00207 - SM: Can't settle other host if the terminal with pending reversal
		//if(d_OK != inResult)
		//	return inResult;

		inRet = d_OK;
	}
	else
    inRet = inBuildAndSendIsoData();
    if(d_OK != inRet)
    {

       if(ST_REVERSAL_SETTLE_ERR == inRet) //aaronnino for BDOCLG ver 9.0 fix on issue #00500 and #00501 
	   	      return ST_ERROR;  
		
       //aaronnino for BDOCLG ver 9.0 fix on issue #00241 No Manual Settle/Clear Batch prompt after 3 failed start
       	//vdSetErrorMessage("SETTLE FAILED"); //aaronnino for BDOCLG ver 9.0 fix on issue #0033 and #0034 "settle failed" error response after "comm error" 4 of 8
        vdDisplayErrorMsgResp2(" ", " ", "SETTLE FAILED");
		vdSetErrorMessage("");
        
       if(inRet == ST_NO_CONNECT_ERR)
           return ST_ERROR; //aaronnino for BDOCLG ver 9.0 fix on issue #00460 Settle failed retries should not count terminal level connection error
    int inOnlineMMTSettleLimitVal = strMMT[0].inOnlineMMTSettleLimit; 
		if ((inOnlineMMTSettleLimitVal > 98) || (inOnlineMMTSettleLimitVal == 0))
	 	     inOnlineMMTSettleLimitVal = 99;
			 
		if (strMMT[0].fManualMMTSettleTrigger != FALSE)
		{
			strMMT[0].inOnlineMMTSettleTries+=1;
			inMMTSave(strMMT[0].MMTid);
			vdDebug_LogPrintf("TEST SETTLE tries=%d  limit=%d inOnlineMMTSettleLimitVal[%d]", strMMT[0].inOnlineMMTSettleTries, strMMT[0].inOnlineMMTSettleLimit, inOnlineMMTSettleLimitVal);
			if (strMMT[0].inOnlineMMTSettleTries >= inOnlineMMTSettleLimitVal)
			{
				fAUTOManualSettle = TRUE;
				inRet = inAutoManualSettle();
			 
				if (inRet != d_OK)    
				{
					strMMT[0].inSettleStatus = 2;
					inMMTSave(strMMT[0].MMTid);
					return inRet;
				}else{
					strMMT[0].inSettleStatus = 1;
					strMMT[0].inOnlineMMTSettleTries = 0;
					inMMTSave(strMMT[0].MMTid);				  
					vdSetErrorMessage("");
					//inMMTResetReprintSettle(strMMT[0].MITid);
					inMMTSetReprintSettle(strMMT[0].MMTid);
					return inRet;
				}
			}
		}
			 
		return inRet;
    }


//smac
	inCheckNewSMACRateFromSettlement();
//smac

	//inMMTResetReprintSettle(strMMT[0].MITid);
	inMMTSetReprintSettle(strMMT[0].MMTid);

    inRet = inCTOS_PrintSettleReport(FALSE);
    if(d_OK != inRet)
        return inRet; 

    inRet = inCTOS_SettlementClearBathAndAccum(FALSE);

		//BDO: Added settlement status to settlement report - start -- jzg
		if(inRet != d_OK)
			strMMT[0].inSettleStatus = 2;
		else
			strMMT[0].inSettleStatus = 1;
			inMMTSave(strMMT[0].MMTid);
		//BDO: Added settlement status to settlement report - end -- jzg

#if 0

		//BDO: Added settlement status to settlement report - start -- jzg
		if(inRet != d_OK)
			strMMT[0].inSettleStatus = 2;
		else
			strMMT[0].inSettleStatus = 1;
		inMMTSave(strMMT[0].MMTid);
		//BDO: Added settlement status to settlement report - end -- jzg

		vdDebug_LogPrintf("JEFF::2>> Merch[%d] Settle Status[%d]", strMMT[0].MITid, strMMT[0].inSettleStatus); //remove later -- jzg
#endif
		
    if(d_OK != inRet)
        return inRet;

//transfer to inCTOS_SETTLEMENT - to solve settlement retry COMM INIT ERROR if cable was removed on settlement
    //inRet = inCTOS_inDisconnect();
    //if(d_OK != inRet)
    //    return inRet;
    //else
    //    vdSetErrorMessage("");
    

		//vdBDO_PrintSettlementReportFooter();


    return ST_SUCCESS;
}

int inCTOS_SETTLEMENT(void)
{
    int inRet;

		gvSettleType = SINGLE_SETTLE; //aaa fix on issue #000210 Terminal displays "Batch empty, skip" on all hosts when trying to settle hosts with no transactions 4 of 6
    
    CTOS_LCDTClearDisplay();
    
    vdCTOS_TxnsBeginInit();

    vdCTOS_DispStatusMessage("PROCESSING...");// 04042023
	
    inRet = inCTOS_SettlementFlowProcess();

    if(strMMT[0].inSettleStatus == 0){	
//    if(d_OK == inRet){
		
		if (strTCT.fAutoDownloadEnable == TRUE)
        	inCTOSS_SettlementCheckTMSDownloadRequest();
    }

//fix for settlement retry
		//if (inRet != ST_SUCCESS)

    if(inRet == d_OK)
			vdSetErrorMessage("");

	//version16
	if (srTransRec.HDTid != BDO_LOYALTY_HDT_INDEX)
		inCTOS_inDisconnect();
    //if(d_OK != inRet)
    //    return inRet;
    //else
    //    vdSetErrorMessage("");
//fix for settlement retry

    vdCTOS_TransEndReset();

    //temporary removed
    //vdDebug_LogPrintf("Call TMS %d", inRet);
    //if(d_OK == inRet)
    //    inCTOSS_SettlementCheckTMSDownloadRequest();

    return inRet;
}



int inCTOS_SettleAMerchant(void)
{
	int inRet = d_NO;
	char szDisplayMsg[50];

	memset(szDisplayMsg,0x00,sizeof(szDisplayMsg));
#if 0
        sprintf(szDisplayMsg,"%s",strMMT[0].szMerchantName);
#else
        sprintf(szDisplayMsg,"SETTLE-%s",strHDT.szHostLabel); // sidumili: Issue#:000109 [Display hostname during settle all]
#endif
	CTOS_LCDTPrintXY(1, 8, "                   ");
	CTOS_LCDTPrintXY(1, 8, szDisplayMsg);
	vdDebug_LogPrintf("inCTOS_SettleAMerchant--hostname=[%s]-merchant=[%s]--",strHDT.szHostLabel,strMMT[0].szMerchantName);

	
	inRet = inCTOS_ChkBatchEmpty();
	
	//BDO: Added settlement status to settlement report - start -- jzg
	if(inRet != d_OK)
		strMMT[0].inSettleStatus = 0;
	else
		strMMT[0].inSettleStatus = 2;
		
	//BDO: Added settlement status to settlement report - end -- jzg

    if(d_OK != inRet)
    {
		inMMTSave(strMMT[0].MMTid);
        return inRet;
    }
	
	//set must settle flag once settlement wsa triggered
	strMMT[0].fMustSettFlag = CN_TRUE;
	inMMTSave(strMMT[0].MMTid);
	
    inRet = inCTOS_PreConnect();
    if(d_OK != inRet)
        return inRet;

    // version16
	if (srTransRec.HDTid == BDO_LOYALTY_HDT_INDEX){
//for testing - send first if there's  a pending reversal
		int inResult, inHostIndex;
		int inBDOLoyRevReturn;
		
		vdCTOS_DispStatusMessage("PROCESSING...");

		vdDebug_LogPrintf("inCTOS_SettlementFlowProcess (srTransRec.HDTid == BDO_LOYALTY_HDT_INDEX)");
		
		inBDOLoyRevReturn = vdChecksReversalFile();		
		vdDebug_LogPrintf("inCTLOS_Getpowrfail xxx inBDOLoyRevReturn[%d] srTransRec.HDTid [%d]", inBDOLoyRevReturn, srTransRec.HDTid);		

		if(inBDOLoyRevReturn)
		{
			inResult = inSendReversalOnSettle();
			vdDebug_LogPrintf("inCTOS_SettlementFlowProcess inSendReversalOnSettle inResult [%d]", inResult);
			inRet = inCTOS_inDisconnect();
		}
//end of testing
		inRet = d_OK;
    }else 
    	inRet = inBuildAndSendIsoData();
    if(d_OK != inRet)
    	{

			  if(ST_REVERSAL_SETTLE_ERR == inRet)//aaronnino for BDOCLG ver 9.0 fix on issue #00500 and #00501 
	   	       return ST_ERROR; 
					
    	  //aaronnino for BDOCLG ver 9.0 fix on issue #00241 No Manual Settle/Clear Batch prompt after 3 failed start
        vdDisplayErrorMsgResp2(" ", " ", "SETTLE FAILED");
		vdSetErrorMessage("");

       if(inRet == ST_NO_CONNECT_ERR)
         return ST_ERROR; //aaronnino for BDOCLG ver 9.0 fix on issue #00460 Settle failed retries should not count terminal level connection error
				
			if (strMMT[0].fManualMMTSettleTrigger != FALSE)
			{
				strMMT[0].inOnlineMMTSettleTries+=1;
				inMMTSave(strMMT[0].MMTid);
				vdDebug_LogPrintf("TEST SETTLE tries=%d  limit=%d", strMMT[0].inOnlineMMTSettleTries, strMMT[0].inOnlineMMTSettleLimit);
        int inOnlineMMTSettleLimitVal = strMMT[0].inOnlineMMTSettleLimit;
        if ((inOnlineMMTSettleLimitVal > 98) || (inOnlineMMTSettleLimitVal == 0))
            inOnlineMMTSettleLimitVal = 99;
				if (strMMT[0].inOnlineMMTSettleTries >= inOnlineMMTSettleLimitVal)
				{
					fAUTOManualSettle = TRUE;
					inRet = inAutoManualSettle();
				
					if (inRet != d_OK)	  
					{
						strMMT[0].inSettleStatus = 2;
						inMMTSave(strMMT[0].MMTid);
						return inRet;
					}else{
						strMMT[0].inSettleStatus = 1;
						strMMT[0].inOnlineMMTSettleTries = 0;
						inMMTSave(strMMT[0].MMTid);	
                         if(strTCT.fReprintSettleStatus == 0)
                         {
                             inMMTResetReprintSettle(strMMT[0].MITid);
                             strTCT.fReprintSettleStatus=1;
                             inTCTSave(1);
                         }
                         inMMTSetReprintSettle(strMMT[0].MMTid);
						vdSetErrorMessage("");
						return inRet;
					}
				}
			}
				
		return inRet;

    }

    vdDebug_LogPrintf("1. strTCT.fReprintSettleStatus:(%d)", strTCT.fReprintSettleStatus);
	
    if(strTCT.fReprintSettleStatus == 0)
    {
        inMMTResetReprintSettle(strMMT[0].MITid);
		strTCT.fReprintSettleStatus=1;
		inTCTSave(1);
    }
    inMMTSetReprintSettle(strMMT[0].MMTid);

    vdDebug_LogPrintf("2. strTCT.fReprintSettleStatus:(%d)", strTCT.fReprintSettleStatus);

	fECRBuildSendOK = TRUE;//Set to True for ECR purposes	
		
    inRet = inCTOS_PrintSettleReport(FALSE);
    if(d_OK != inRet)
        return inRet; 

    inRet = inCTOS_SettlementClearBathAndAccum(FALSE);
				//BDO: Added settlement status to settlement report - start -- jzg
				if(inRet != d_OK)
					strMMT[0].inSettleStatus = 2;
				else
					strMMT[0].inSettleStatus = 1;
					inMMTSave(strMMT[0].MMTid);
		//BDO: Added settlement status to settlement report - end -- jzg

    if(d_OK != inRet)
        return inRet;

    //version16
	if (srTransRec.HDTid == BDO_LOYALTY_HDT_INDEX)
		inRet = d_OK;
    else
    	inRet = inCTOS_inDisconnect();
    if(d_OK != inRet)
        return inRet;
    else
        vdSetErrorMessage("");

	return ST_SUCCESS;
}



int inCTOS_SettleAHost(void)
{
	int inRet = d_NO;
	int inNumOfMit = 0,inNum;
	char szErrMsg[30+1];

	memset(szErrMsg,0x00,sizeof(szErrMsg));
	sprintf(szErrMsg,"SETTLE %s",strHDT.szHostLabel);
	CTOS_LCDTPrintXY(1, 8, "                   ");
	CTOS_LCDTPrintXY(1, 8, szErrMsg);
	inMMTReadNumofRecords(strHDT.inHostIndex,&inNumOfMit);
	vdDebug_LogPrintf("inNumOfMit=[%d]-----",inNumOfMit);
	//	inMMTReadNumofRecords(strHDT.inHostIndex,&inNumOfMit);
	//	vdDebug_LogPrintf("inNumOfMit=[%d]-----",inNumOfMit);
	//	for(inNum =0 ;inNum < inNumOfMit; inNum++)
	{
		//		memcpy(&strMMT[0],&strMMT[inNum],sizeof(STRUCT_MMT));
		//		srTransRec.MITid = strMMT[0].MITid;
		//		strcpy(srTransRec.szTID, strMMT[0].szTID);
		//		strcpy(srTransRec.szMID, strMMT[0].szMID);
		//		memcpy(srTransRec.szBatchNo, strMMT[0].szBatchNo, 4);
		//		strcpy(srTransRec.szHostLabel, strHDT.szHostLabel);
		/*
		if ( inMMTReadRecord_SettleAll(srTransRec.HDTid , srTransRec.MITid) != d_OK)
		{
		vdSetErrorMessage("LOAD MMT ERR");
		return(d_NO);
		}
		*/

		
		vdDebug_LogPrintf("HDTid=[%d]-MITid=[%d]----",srTransRec.HDTid,srTransRec.MITid);
		inMMTReadRecord(srTransRec.HDTid , srTransRec.MITid) ;
		inRet = inCTOS_SettleAMerchant();

		if (d_OK != inRet)
		{			
			inCTOS_inDisconnect();//FIX for COMM INIT ERROR ON settlement retry
			memset(szErrMsg,0x00,sizeof(szErrMsg));
			if (inGetErrorMessage(szErrMsg) > 0)
			{
				vdDisplayErrorMsg(1, 8, szErrMsg);
			}
			vdSetErrorMessage("");

			if (!fECRBuildSendOK){	
				put_env_int("SETTLEOK",0);		
			}	
			fECRBuildSendOK = FALSE;
			
			return(ST_ERROR); //Auto-settlement: return settlement status for each merchant -- jzg
		}
	}

	return ST_SUCCESS;
}

int inCTOS_SettleAMerchantHost(void)
{
    int inRet = d_NO;
    int inNumOfMit = 0,inNum;
    char szErrMsg[30+1];

		vdDebug_LogPrintf("inCTOS_SettleAMerchantHost inHostIndex=[%d], szAPName=[%s]", strHDT.inHostIndex, strHDT.szAPName);
		
    memset(szErrMsg,0x00,sizeof(szErrMsg));
    sprintf(szErrMsg,"SETTLE %s",strHDT.szHostLabel);
    CTOS_LCDTPrintXY(1, 8, "									 ");
    CTOS_LCDTPrintXY(1, 8, szErrMsg);
    inMMTReadNumofRecords(strHDT.inHostIndex,&inNumOfMit);
    vdDebug_LogPrintf("inNumOfMit=[%d]-----",inNumOfMit);
    for(inNum =0 ;inNum < inNumOfMit; inNum++)
    {
        memcpy(&strMMT[0],&strMMT[inNum],sizeof(STRUCT_MMT));
        srTransRec.MITid = strMMT[0].MITid;
        strcpy(srTransRec.szTID, strMMT[0].szTID);
        strcpy(srTransRec.szMID, strMMT[0].szMID);
        memcpy(srTransRec.szBatchNo, strMMT[0].szBatchNo, 4);
        strcpy(srTransRec.szHostLabel, strHDT.szHostLabel);
        
        vdCTOS_SetTransType(SETTLE);
        
        inRet = inCTOS_SettleAMerchant();
        if (d_OK != inRet)
        {
            memset(szErrMsg,0x00,sizeof(szErrMsg));
            if (inGetErrorMessage(szErrMsg) > 0)
            {
                vdDisplayErrorMsg(1, 8, szErrMsg);
            }
            vdSetErrorMessage("");
        }
    }

    return ST_SUCCESS;
}


#ifdef HOST_ONE_BY_ONE
int inCTOS_SettleAllHosts(void)
{
    int inRet = d_NO;
	int inNumOfHost = 0,inNum;
	char szBcd[INVOICE_BCD_SIZE+1];
	char szErrMsg[30+1];
    int inHDTid[150];
	int inHDTIndex=0;
	
    vdCTOS_SetTransType(SETTLE);
    
    //display title
    //vdDispTransTitle(SETTLE);

    /*inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;*/

	if (inMultiAP_CheckSubAPStatus() != d_OK)//only 1 APP or main APP
	{	
		inNumOfHost=inMMTNumRecordwithBatch(srTransRec.MITid, inHDTid);
		inSetMMTSettleStatusEmpty(srTransRec.MITid);
	    //inNumOfHost = inHDTNumRecord();
		vdDebug_LogPrintf("inNumOfHost=[%d]-----",inNumOfHost);

		put_env_int("SETTLEOK",1);//Set to 1 by default to indicate success. If any one of the host fails. This will be set to zero and ERROR will be sent to ECR.
		
		for(inNum =1 ;inNum <= inNumOfHost; inNum++)
		{
			//vdDispTransTitle(SETTLE);
			vduiClearBelow(2);
			vdCTOS_DispStatusMessage("PROCESSING...");
		
			//if(inHDTRead(inNum) == d_OK)
			inHDTIndex=inHDTid[inNum-1];
			if(inHDTRead(inHDTIndex) == d_OK)
			{
		        vdDebug_LogPrintf("Settle Host: (%s)", strHDT.szHostLabel);		
				inCPTRead(inHDTIndex);
				srTransRec.HDTid = inHDTIndex;
        		strcpy(srTransRec.szHostLabel, strHDT.szHostLabel);
				memset(szBcd, 0x00, sizeof(szBcd));
			    memcpy(szBcd, strHDT.szTraceNo, INVOICE_BCD_SIZE);    
			    inBcdAddOne(szBcd, strHDT.szTraceNo, INVOICE_BCD_SIZE);
			    srTransRec.ulTraceNum = wub_bcd_2_long(strHDT.szTraceNo,3);
				
				if (inMultiAP_CheckMainAPStatus() == d_OK)
				{
					//multi AP
			        //inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_SETTLE_ALL);
			        put_env_int("BDOMMTID",srTransRec.MITid);
					put_env_int("BDOHDTID",srTransRec.HDTid);
					inMMTReadRecord(srTransRec.HDTid , srTransRec.MITid) ;//ner
					vdDebug_LogPrintf("MMTid [%d] :: szHostName [%s] :: HDTid [%d] :: fBatchNotEmpty [%d]",strMMT[0].MMTid,strMMT[0].szHostName,strMMT[0].HDTid,strMMT[0].fBatchNotEmpty);
					if(strMMT[0].fBatchNotEmpty == FALSE)
					{
						strMMT[0].inSettleStatus = 0;
						inMMTSave(strMMT[0].MMTid);
						continue;
					}	
					
					if(fAutoSettle == TRUE)
						inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_SETTLE_MERCHANT_ALL);
					else
		        		inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_SETTLE_ALL);


					vdDebug_LogPrintf("inCTOS_MultiAPSaveData %d", inRet);
				
			        if (d_OK == inRet)//Current AP
					{
						inRet = inCTOS_SettleAHost();

						vdDebug_LogPrintf("szGlobalAPName app name %s", szGlobalAPName);
						
						vdDebug_LogPrintf("do not refork");
						  		
						//}else{
						//	vdDebug_LogPrintf("refork subapp");
						//	inReforkSubAPP();
					}
					
					memset(szErrMsg,0x00,sizeof(szErrMsg));
				    if (inGetErrorMessage(szErrMsg) > 0)
				    {
				        vdDisplayErrorMsg(1, 8, szErrMsg);
				    }
					vdSetErrorMessage("");

                    //report sub-app after settlement					
					vdDebug_LogPrintf("refork subapp");
					inReforkSubAPP();
					
				}
				else
				{
					// only one AP
					inRet = inCTOS_SettleAHost();
		                return inRet;
				}
			}
		}
	}
	else// Sub APP
    {
    	srTransRec.MITid = get_env_int("BDOMMTID");
		srTransRec.HDTid = get_env_int("BDOHDTID");
        inRet = inCTOS_MultiAPGetData();
        if(d_OK != inRet)
            return inRet;
		
		inRet = inCTOS_MultiAPReloadHost();
        if(d_OK != inRet)
            return inRet;
		
		inRet = inCTOS_SettleAHost();
            return inRet;
    }

    return ST_SUCCESS;
}
#else
// for AP name settle All host
int inCTOS_SettleAllHosts(void)
{
	int inRet = d_NO;
	int inNumOfHost = 0, inNum = 0;
	char szBcd[INVOICE_BCD_SIZE+1] = {0};
	char szErrMsg[31] = {0};
	char szAPName[25] = {0};
	int inAPPID = 0;

	//Auto-settlement: return result if a settlement failed or not -- jzg
	int inResult = ST_SUCCESS;
	BOOL fSTLFailed = FALSE;

	memset(szAPName,0x00,sizeof(szAPName));
	inMultiAP_CurrentAPNamePID(szAPName, &inAPPID);

	inNumOfHost = inHDTNumRecord();
	vdDebug_LogPrintf("inNumOfHost=[%d]-----",inNumOfHost);
	for(inNum =1 ;inNum <= inNumOfHost; inNum++)
	{
		if(inHDTRead(inNum) == d_OK)
		{
			vdDebug_LogPrintf("szAPName=[%s]-[%s]----",szAPName,strHDT.szAPName);
			if (strcmp(szAPName, strHDT.szAPName)!=0)
			{
				continue;
			}

			inCPTRead(inNum);
			srTransRec.HDTid = inNum;
			strcpy(srTransRec.szHostLabel, strHDT.szHostLabel);
			memset(szBcd, 0x00, sizeof(szBcd));
			memcpy(szBcd, strHDT.szTraceNo, INVOICE_BCD_SIZE);    
			inBcdAddOne(szBcd, strHDT.szTraceNo, INVOICE_BCD_SIZE);
			srTransRec.ulTraceNum = wub_bcd_2_long(strHDT.szTraceNo,3);

			// only one AP
			//if(fAutoSettle == TRUE)
			//	inResult = inCTOS_SettleAMerchantHost();
			//else	
			  inResult = inCTOS_SettleAHost();
			//aaronnino for BDOCLG ver 9.0 fix on issue #0033 and #0034 "settle failed" error response after "comm error" 5 of 8 start
			if (inResult != ST_SUCCESS) 
				{
        //if (gblfBatchEmpty != TRUE)
        	//{
					    //CTOS_LCDTClearDisplay();
              //CTOS_Sound(1000, 50);
             // CTOS_LCDTPrintXY(1,8,"SETTLE FAILED");
              //CTOS_Delay(1000);
        	//}
           fSTLFailed = TRUE;
				}
			//aaronnino for BDOCLG ver 9.0 fix on issue #0033 and #0034 "settle failed" error response after "comm error" 2 of 8 end
		}
	}

	vdDebug_LogPrintf("end inCTOS_SettleAllHosts-----");
	//Auto-settlement: return result if a settlement failed or not -- jzg
	if (fSTLFailed == TRUE)
	       inResult = ST_ERROR;

  

	return(inResult); 
}
#endif

int inCTOS_SettleAllOperation(void)
{
	int inRet = d_NO;
	int inNumOfHost = 0,inNum;
	char szBcd[INVOICE_BCD_SIZE+1];
	char szErrMsg[30+1];
	char szAPName[25];
	int inAPPID;

	int inResult = ST_SUCCESS; //Auto-settlement: return result if a settlement failed or not -- jzg
	int inBDOLoyRevReturn;

	vdCTOS_SetTransType(SETTLE);

	vdDebug_LogPrintf("inCTOS_SettleAllOperation START");
	vdCTOS_DispStatusMessage("PROCESSING..."); //04042023
	

	//display title
	//vdDispTransTitle(SETTLE);

    if(fAutoSettle == FALSE) /* do not prompt for password if auto-settle -- jzg */
    {
       /* inRet = inCTOS_GetTxnPassword();
        if(d_OK != inRet)
            return inRet;
        
        inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
        if(d_OK != inRet)
            return inRet;
        */
        //inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);
    }

#ifdef BLT_REV_PFR
//for testing - remove here, transfer to before  settlement of BDO Loyalty
#if 0
		//00208 - SM: 20 to 25 secnods Processing & White screen displayed during settlement  
		inBDOLoyRevReturn = vdChecksReversalFile(); 	
		vdDebug_LogPrintf("inCTLOS_Getpowrfail xxx inBDOLoyRevReturn[%d] srTransRec.HDTid [%d]", inBDOLoyRevReturn, srTransRec.HDTid);	

		if(inBDOLoyRevReturn)
		{
			//00167 (No reversal is sent before processing BDO Loyalty settlement) 
	  		inResult = inSendReversalOnSettle();
			vdDebug_LogPrintf("inCTOS_SettleAllOperation inSendReversalOnSettle inResult [%d]", inResult);
		}

		//00207 - SM: Can't settle other host if the terminal with pending reversal 
		//if(d_OK != inResult)
		//	return inResult;
#endif
#endif
		
    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
			inResult = inCTOS_SettleAllHosts();
			#if VERSION9
			if(fAutoSettle == TRUE)
				inCTOS_MultiAPALLAppEventID(d_IPC_CMD_SETTLE_MERCHANT_ALL);
			else
        		inCTOS_MultiAPALLAppEventID(d_IPC_CMD_SETTLE_ALL);
			#endif
    }
    else
    {
        inCTOS_SettleAllHosts();
    }

	//smac
		inCheckNewSMACRateFromSettlement();
	//smac

	//Auto-settlement: return result if a settlement failed or not -- jzg
	//if (inResult == ST_SUCCESS)
	//{
		//strPAS.fOnGoing = FALSE;
		//inPASSave(1);
	//}

	vdBDO_PrintSettlementReportFooter();
	CTOS_LCDTClearDisplay();

	return ST_SUCCESS;
}



int inCTOS_SETTLE_ALL(void)
{
	BOOL fECRTxn = FALSE;
    int inRet = d_NO;
    int inMITid;

	
	gvSettleType = MULTI_SETTLE; //aaa fix on issue #000210 Terminal displays "Batch empty, skip" on all hosts when trying to settle hosts with no transactions 5 of 6

	fECRBuildSendOK = FALSE;
	
    CTOS_LCDTClearDisplay();

	inMITid=srTransRec.MITid;
		
    vdCTOS_TxnsBeginInit();

	fECRTxn = srTransRec.fECRTrxFlg;
		
	srTransRec.MITid=inMITid;
		
    inRet = inCTOS_SettleAllOperation();

	if(fECRTxn)
	{
		if(get_env_int("SETTLEOK") == TRUE)
			strcpy(srTransRec.szRespCode,"00");			
		else
		{
			strcpy(srTransRec.szRespCode,"103");//Set to 103 to set message to SETTLE FAILED to ECR		
		}

		inMultiAP_ECRSendSuccessResponse();
		
	}
	
    if(d_OK == inRet)
    {
        if (strTCT.fAutoDownloadEnable == TRUE)
            inCTOSS_SettlementCheckTMSDownloadRequest();	

		
		//resend all penfing ERM receipts
		inHDTRead(1);
		inMMTReadRecord(1, 1);

	
		if(inFLGGet("fUploadADCReport"))
			vdReUploadERMReceipt(1);
    }

    vdCTOS_TransEndReset();

    return inRet;
}


int inCTOS_BATCH_TOTAL_Process(void)
{
    int inRet;

    
    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
       return inRet;

	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;


    //inRet = inCTOS_SelectHostSetting();
    inRet = inCTOS_SelectHostSettingWithIndicator(1);
    if (inRet == -1)
        return;

    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_BATCH_TOTAL);
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

            inRet = inCTOS_MultiAPReloadHost();
            if(d_OK != inRet)
                return inRet;
        }
    }


	//remove prompt fro selection-Merchant selection is done by inCTOS_TEMPCheckAndSelectMutipleMID
	//	  inRet = inCTOS_CheckAndSelectMutipleMID();
	//	  if(d_OK != inRet)
	//		  return inRet;
	inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);

    inRet = inCTOS_ChkBatchEmpty();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_DisplayBatchTotal();
    if(d_OK != inRet)
        return inRet;

    vdSetErrorMessage("");

    return d_OK;
    
}

int inCTOS_BATCH_REVIEW_Process(void)
{
    int inRet;


    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
       return inRet;

	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;

    //inRet = inCTOS_SelectHostSetting();
    inRet = inCTOS_SelectHostSettingWithIndicator(1);
    if (inRet == -1)
        return;

    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_BATCH_REVIEW);
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

            inRet = inCTOS_MultiAPReloadHost();
            if(d_OK != inRet)
                return inRet;
        }
    }


	//remove prompt fro selection-Merchant selection is done by inCTOS_TEMPCheckAndSelectMutipleMID
	//	  inRet = inCTOS_CheckAndSelectMutipleMID();
	//	  if(d_OK != inRet)
	//		  return inRet;
	inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);

    inRet = inCTOS_ChkBatchEmpty();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_BatchReviewFlow();    
    if(d_OK != inRet)
        return inRet;

    vdSetErrorMessage("");
    
    return d_OK;
    
}

int inCTOS_BATCH_TOTAL(void)
{
    int inRet;
    
    CTOS_LCDTClearDisplay();
    
    vdCTOS_TxnsBeginInit(); 

    vdDispTransTitle(BATCH_TOTAL);

    inCTOS_BATCH_TOTAL_Process();
    
    vdCTOS_TransEndReset();

    return d_OK;
    
}

int inCTOS_BATCH_REVIEW(void)
{
    int inRet;
    
    CTOS_LCDTClearDisplay();
    
    vdCTOS_TxnsBeginInit(); 

		vdCTOS_SetTransType(BATCH_REVIEW);

    vdDispTransTitle(BATCH_REVIEW);
    
    inCTOS_BATCH_REVIEW_Process();
    
    vdCTOS_TransEndReset();
    
    return d_OK;
    
}

//settle ALL merchants
int inCTOS_SETTLE_ALL_MERCHANT(void)
{
    int inRet = d_NO;
	int inNumOfRecords;
	int inLoop;
	CTOS_RTC SetRTC;
	BYTE szCurrDate[8] = {0};

	vdCTOS_TxnsBeginInit();


	gvSettleType = MULTI_SETTLE; //aaa fix on issue #000210 Terminal displays "Batch empty, skip" on all hosts when trying to settle hosts with no transactions 5 of 6

    fAutoSettle = VS_TRUE;

    inNMTReadNumofRecords(&inNumOfRecords);
    CTOS_KBDBufFlush();//cleare key buffer

    if(inNumOfRecords >= 1)
    {    

        for (inLoop = 0; inLoop < inNumOfRecords; inLoop++){

		   
    		CTOS_LCDTClearDisplay();
			srTransRec.MITid = strNMT[inLoop].NMTID;    
    		inRet = inCTOS_SettleAllOperation();
        }

    }
	
    if((strPAS.fEnable==TRUE) && (strPAS.fOnGoing == TRUE))
    {
        if(inMustSettleNumRecord() <= 0) 	
        {
            memset(szCurrDate, 0x00, sizeof(szCurrDate));
            CTOS_RTCGet(&SetRTC);
            sprintf(szCurrDate,"%02d%02d%02d", SetRTC.bYear, SetRTC.bMonth, SetRTC.bDay);
            memcpy(strPAS.szlastSettleDate,szCurrDate, 6); 
        }	
        strPAS.fOnGoing=FALSE;
				inPASSave(1);
    }
	
    //if(d_OK == inRet)
    //{
    //    if (strTCT.fAutoDownloadEnable == TRUE)
    //        inCTOSS_SettlementCheckTMSDownloadRequest();					
    //}

    vdCTOS_TransEndReset();

    return inRet;
}

//00167 (No reversal is sent before processing BDO Loyalty settlement) 
int inSendReversalOnSettle(void){

		int inResult, inHostIndex, inRet;
		vdDebug_LogPrintf("inSendReversalOnSettle START");
		
		inRevSettFlag = 1;

		// host index
		srTransRec.HDTid = BDO_LOYALTY_HDT_INDEX;
		strCDT.HDTid = BDO_LOYALTY_HDT_INDEX;
		
		// issuer index
		srTransRec.IITid = BDO_LOYALTY_ISSUER_INDEX;
		strIIT.inIssuerNumber = BDO_LOYALTY_ISSUER_INDEX;
		strCDT.IITid = BDO_LOYALTY_ISSUER_INDEX;

		inRet = inCTOS_SelectHost();
		if(d_OK != inRet)
			return inRet;

		
		#if 1

		vdDebug_LogPrintf("strCPT.inCommunicationMode %d",strCPT.inCommunicationMode);
		vdDebug_LogPrintf("strCPT.inCommunicationMode %s",strCPT.szPriTxnHostIP);

		
		inCTOSS_GPRSPing(strCPT.szPriTxnHostIP);
		//sprintf(strCPT.szPriTxnHostIP, "%s", "api25.apigateway.uat.bdo.com.ph");
		//inCTOSS_GPRSPing(strCPT.szPriTxnHostIP);

		#endif

    	inRet = inCTOS_PreConnect();
    	if(d_OK != inRet)
        	return inRet;
		
		inBLTRead(1);

		#if 0
		// Request Access Token
		inRet = inRequestAccessToken();
		
		if(d_OK != inRet)
			return inRet;	
		#endif

		//START OF Reversal Routine
		
		vdCTOS_DispStatusMessage("PROCESSING..."); //04042023
		inResult = inReversalRoutine();
		
		vdDebug_LogPrintf("inSendReversalOnSettle inResult [%d]", inResult);
		
		if(d_OK != inResult)
			return inResult;	

		
		vdDebug_LogPrintf("inSendReversalOnSettle END");


return d_OK;
}

