/*******************************************************************************

*******************************************************************************/

#include <string.h>
#include <stdio.h>
#include <ctosapi.h>
#include <stdlib.h>
#include <stdarg.h>
#include <typedef.h>


#include "..\Includes\POSTypedef.h"
#include "..\Includes\POSMain.h"
#include "..\Includes\POSTrans.h"
#include "..\Includes\POSHost.h"
#include "..\Includes\POSSale.h"
#include "..\Includes\POSbatch.h"
#include "..\ui\Display.h"
#include "..\Includes\V5IsoFunc.h"
#include "..\includes\POSbatch.h"
#include "..\Accum\Accum.h"
#include "..\print\Print.h"
#include "..\Comm\V5Comm.h"
#include "..\Includes\MultiApLib.h"
#include "..\Aptrans\MultiAptrans.h"
#include "../Ctls/POSCtls.h"
#include "..\debug\debug.h"
#include "..\Includes\POSDCC.h"


extern BOOL fRouteToSpecificHost;
extern BOOL fBinRouteDCC;
extern BOOL fNoEMVProcess;
extern BOOL fAMEXHostEnable;
extern BOOL fDinersHostEnable;
extern BOOL fUSDSelected;
extern BOOL fBDOOptOutHostEnabled;
extern BOOL fECRBuildSendOK;

int inCTOS_SaleOffLineFlowProcess(void)
{
    int inRet = d_NO;
    BOOL fBinRoute=TRUE;


    vdCTOS_SetTransType(SALE_OFFLINE);
    
    //display title
    vdDispTransTitle(SALE_OFFLINE);
		
	//srTransRec.fVoidOffline = CN_TRUE;
    srTransRec.fVoidOffline = CN_FALSE; // Set to FALSE since COMPLETION/CHECKOUT is already online.
	
    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;

	if(srTransRec.fOptOut == FALSE)
	{
	    inRet = inCTOS_GetTxnPassword();
	    if(d_OK != inRet)
	        return inRet;
	}

	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;

       //inRet = inCTOS_PreConnectAndInit();
       //if(d_OK != inRet)
       //    return inRet;

    if (strTCT.fSingleComms){	
		inRet = inCTOS_PreConnectEx();

		if (inRet != d_OK)
			return inRet;
	}
	
	inRet=inCTOS_SelectCurrencyEx();
	if(d_OK != inRet)
		return inRet;
			
	//gcitra
	inRet = inCTOS_GetTxnBaseAmount();
	if(d_OK != inRet)
		return inRet;
		
	inRet = inCTOS_PreConnectAndInit();
	if(d_OK != inRet)
		return inRet;
	
/*		inRet = inCTOS_GetTxnTipAmount();
		if(d_OK != inRet)
			return inRet;
*/
	//gcitra

	if( strlen(srTransRec.szPAN) > 0 && strlen(srTransRec.szExpireDate) > 0 && fGetECRTransactionFlg() == TRUE)
	{
		srTransRec.byEntryMode = CARD_ENTRY_MANUAL;//Card number from ECR. Card Entry is set to Manual
		inRet = inCTOS_LoadCDTIndex();
		if (d_OK != inRet)
           return inRet;
	}
	else
	{
	    inRet = inCTOS_GetCardFields();
	    if(d_OK != inRet)
	        return inRet;
	}
	
	inRet = inBDOEnterLast4Digits(FALSE);
	if(inRet != d_OK)
		return inRet;


//gcitra - put display here not in amount entry
	inSETIssuerForCatchAll();

	inRet=inCTOS_DisplayCardTitle(6, 7); //Display Issuer logo: re-aligned Issuer label and PAN lines -- jzg
	if(d_OK != inRet)
		return inRet;

	inRet = inCTOS_UpdateTxnTotalAmount();
	if(d_OK != inRet)
		return inRet;

	
	inRet = inConfirmPAN();
	if(d_OK != inRet)
		return inRet;

	if (strTCT.fSingleComms == FALSE) {
		inRet = inCTOS_PreConnectEx();

		if (inRet != d_OK)
			return inRet;
	}

//gcitra

#if 0
	inRet=inCTOS_SelectCurrency();
	if(d_OK != inRet)
		return inRet;
#else
	inRet=inCTOS_SetCurrency();
	if(d_OK != inRet)
		return inRet;
#endif

	fBinRouteDCC = FALSE;
		
    if(inCTLSEMVCheck() == d_OK)
        fBinRoute=FALSE;		

    if(inCTLSCUPCheck() == d_OK)
        fBinRoute=FALSE; 

	if(fCUPBinRoute() == d_OK)
	{
		fBinRoute=FALSE;
		if (fUSDSelected)
	       	strHDT.inHostIndex=srTransRec.HDTid=strCDT.HDTid=37;
	    else
	       	strHDT.inHostIndex=srTransRec.HDTid=strCDT.HDTid=36;
	}

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

	if(srTransRec.fOptOut == TRUE)
	{
		if(fBDOOptOutHostEnabled == TRUE)
			srTransRec.HDTid = strCDT.HDTid = BDO_COMPLETION_OPTOUT_HDT_INDEX;
	}
	
	if ((strTCT.fATPBinRoute == TRUE) && (strCDT.fPANCatchAll == TRUE) && (fBinRoute == TRUE) && srTransRec.fOptOut != TRUE){


//#ifdef ATPBINROUTE
		vdSetATPBinRouteFlag(1);
		fRouteToSpecificHost = 0;
		inRet = inCTOSS_ATPBinRoutingProcessCompCheck();
		vdSetATPBinRouteFlag(0);
		if(VS_CONTINUE != inRet)
			return inRet;

		if( ((strCDT.HDTid == 56 || strCDT.HDTid == 59 || strCDT.HDTid == 2 || strCDT.HDTid == 4) && srTransRec.byEntryMode == CARD_ENTRY_ICC) || // Do not perform inCTOS_EMVProcessing() for Diners, Fleet, AMEX and AMEX USD. inCTOS_EMVProcessing() was already called inside inCTOSS_ATPBinRoutingProcessCompCheck()
			(fAMEXHostEnable == FALSE && srTransRec.byEntryMode == CARD_ENTRY_ICC && strCDT.HDTid == 1) || // If AMEX is disabled and AMEX transactions will be saved to BDO host, do not perform inCTOS_EMVProcessing() again. inCTOS_EMVProcessing() was already called inside inCTOSS_ATPBinRoutingProcess()
			(fDinersHostEnable == FALSE && srTransRec.byEntryMode == CARD_ENTRY_ICC && strCDT.HDTid == 1))
			fNoEMVProcess = TRUE; 
	}

	if (strCDT.HDTid == 53){
	  vdDisplayErrorMsgResp2(" ", "TRANSACTION", "NOT ALLOWED");
	  vdSetErrorMessage("");
      return d_NO;
	}
	
	//if (strCDT.HDTid == 53 && srTransRec.byEntryMode == CARD_ENTRY_ICC) {
		//vdCTOS_ResetMagstripCardData();
		//memset(&stRCDataAnalyze,0x00,sizeof(EMVCL_RC_DATA_ANALYZE));
		//memset(&strEMVT,0x00, sizeof(STRUCT_EMVT));
		//inCTOS_WaveGetCardFields();
		//strCDT.HDTid = 53;
	//}
//#endif
	
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

    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        
		if(srTransRec.usTerminalCommunicationMode == DIAL_UP_MODE){	
			char szAPName[25];
			int inAPPID;
			inMultiAP_CurrentAPNamePID(szAPName, &inAPPID);
			if (strcmp (strHDT.szAPName,szAPName) != 0)
				inCTOS_inDisconnect();
		}
		
        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_OFFLINE_SALE);
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
        }
        inRet = inCTOS_MultiAPCheckAllowd();
        if(d_OK != inRet)
            return inRet;
    }

#if 0
    if(strTCT.fDCC)
    {
        inRet = inCTOS_ProcessDCCRate();
        if(d_OK != inRet)
            return inRet;
    }
#endif

	if(strTCT.fDCC	&& srTransRec.byEntryMode != CARD_ENTRY_WAVE && srTransRec.fOptOut != TRUE)
	{
		if((strTCT.fATPBinRoute == FALSE && strCDT.fDCCEnable == TRUE) || 
		   (strTCT.fATPBinRoute == TRUE && fBinRouteDCC && inSetIssuerforBINRouteDCC() == TRUE))
	    {
				inRet = inCTOS_ProcessDCCRate();
				if(d_OK != inRet)
				   return inRet;
				memset(srTransRec.szRespCode,0x00,sizeof(srTransRec.szRespCode));

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
    
    //inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid); - only for DCC condition
    
	
/* BDO: Remove from offline txn -- jzg */
#if 0
    inRet = inCTOS_PreConnect();
    if(d_OK != inRet)
        return inRet;
#endif

    inRet = inCTOS_CheckIssuerEnable();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_CheckTranAllowd();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_CheckMustSettle();
    if(d_OK != inRet)
        return inRet;

//gcitra
/*
    inRet = inCTOS_GetTxnBaseAmount();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_UpdateTxnTotalAmount();
    if(d_OK != inRet)
        return inRet;
*/
//gcitra

   /* inRet = inCTOS_PreConnect();
    if(d_OK != inRet)
        return inRet;*/

    inRet = inCTOS_GetCVV2();
    if(d_OK != inRet)
        return inRet;

	if(strlen(srTransRec.szAuthCode) <= 0)//Skip prompt if szAuthCode already has value from ATPBinRoute Setup.
	{
		inRet = inCTOS_GetOffApproveNO();
	    if(d_OK != inRet)
	        return inRet;
	}
	
	if(fNoEMVProcess == FALSE)
	{
	    inRet = inCTOS_EMVProcessing();
	    if(d_OK != inRet)
	        return inRet;   
	}

	if((srTransRec.usTerminalCommunicationMode == GPRS_MODE) || (srTransRec.usTerminalCommunicationMode == WIFI_MODE)){
	 
		 inRet = inCTOS_PreConnect();
		 if(d_OK != inRet)
			 return inRet;
	}else{
	
		 if (strTCT.fSingleComms){	 
			 if(inCPTRead(1) != d_OK)
			 {
				 vdSetErrorMessage("LOAD CPT ERR");
				 return(d_NO);
			 }
		 }
	}

	if(get_env_int("BINROUTE") != TRUE)//Fix to invoice number incrementing twice on Bin Routing setup.
	{
	    inRet = inCTOS_GetInvoice();
	    if(d_OK != inRet)
	        return inRet;
	}

	vdGetTimeDate(&srTransRec);// get time and date used in COMPLETION
	
    inRet = inBuildAndSendIsoData();
    if(d_OK != inRet)
    {
    	vdSetECRResponse(ECR_COMMS_ERR);
        return inRet;
    }


//VETSION 16

    inRet = inCTOSS_CheckCVMAmount();
    if (inRet == d_OK) {
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


    inRet = inCTOS_SaveBatchTxn();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_UpdateAccumTotal();
    if(d_OK != inRet)
        return inRet;

	fECRBuildSendOK = TRUE;	
	if (fECRBuildSendOK){	
	    inRet = inMultiAP_ECRSendSuccessResponse();
	}
	
    inRet = ushCTOS_printReceipt();
    if(d_OK != inRet)
        return inRet;
    else
        vdSetErrorMessage("");

	// Send pending advice on completion/checkout
	CTOS_LCDTClearDisplay();

	if(strTCT.fDCC && srTransRec.fDCC)
    {
        inRet=inProcessTransLogTrans(&srTransRec, 1, 2, GET_ALL_EXCEPT_TIP);
        if(d_OK != inRet)
            return inRet;
        else
            vdSetErrorMessage("");
	}
	   
   	inRet=inProcessAdviceTrans(&srTransRec, strHDT.inNumAdv);
	if(d_OK != inRet)
	  return inRet;
	else
	  vdSetErrorMessage("");

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
            return inRet;
        else
            vdSetErrorMessage("");
    }

	    return d_OK;
}

int inCTOS_SALE_OFFLINE(void)
{
    int inRet = d_NO;
    
    CTOS_LCDTClearDisplay();
    
    vdCTOS_TxnsBeginInit();

    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiStopResumeAP("SHARLS_ECRBDO");
    
    inRet = inCTOS_SaleOffLineFlowProcess();
    
    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiResumeContinueAP("SHARLS_ECRBDO");

	/* Send response to ECR -- sidumili */
	if (!fECRBuildSendOK){	
		inMultiAP_ECRSendSuccessResponse();
	}
	
    inCTOS_inDisconnect();
	
    vdCTOS_TransEndReset();

    return inRet;
}
