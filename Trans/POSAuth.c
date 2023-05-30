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
#include "..\Includes\POSAuth.h"
#include "..\ui\Display.h"
#include "..\Includes\V5IsoFunc.h"
#include "..\comm\V5comm.h"
#include "..\print\print.h"
#include "..\Includes\MultiApLib.h"
#include "..\Aptrans\MultiAptrans.h"
#include "..\POWRFAIL\POSPOWRFAIL.h"
#include "..\debug\debug.h"
#include "../Database/DatabaseFunc.h"


//#include "..\Includes\POSSale.h"

extern BOOL fRouteToSpecificHost;
extern BOOL fBinRouteDCC;
extern BOOL fUSDSelected;
extern BOOL fECRBuildSendOK;


int inCTOS_PreAuthFlowProcess(void)
{
    int inRet = d_NO;
    BOOL fBinRoute=TRUE;
	
    vdCTOS_SetTransType(PRE_AUTH);
    
    vdDispTransTitle(PRE_AUTH);
    
    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;
  
    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;

	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();	
	if(d_OK != inRet)
		return inRet;

    //inRet = inCTOS_PreConnectAndInit(); /*for GPRS and WIFI only*/
    //if(d_OK != inRet)
    //    return inRet;

    if (strTCT.fSingleComms){	
		inRet = inCTOS_PreConnectEx();

		if (inRet != d_OK)
		{
	    	vdSetECRResponse(ECR_COMMS_ERR);
	        return inRet;
	    }
	}

	inRet=inCTOS_SelectCurrencyEx();
	if(d_OK != inRet)
		return inRet;

//gcitra
	inRet = inCTOS_GetTxnBaseAmount();
	if(d_OK != inRet)
		return inRet;

	
    inRet = inCTOS_PreConnectAndInit(); /*for GPRS and WIFI only*/
    if(d_OK != inRet)
    {
    	vdSetECRResponse(ECR_COMMS_ERR);
        return inRet;
    }

/*	inRet = inCTOS_GetTxnTipAmount();
	if(d_OK != inRet)
		return inRet;
*/


//gcitra

#if 0
    if (strTCT.byCtlsMode == 0)
		inRet = inCTOS_GetCardFields();
	else
    	inRet = inCTOS_WaveGetCardFields();

    if(d_OK != inRet)
        return inRet;
#else
	if( strlen(srTransRec.szPAN) > 0 && strlen(srTransRec.szExpireDate) > 0 && fGetECRTransactionFlg() == TRUE)
	{
		srTransRec.byEntryMode = CARD_ENTRY_MANUAL;//Card number from ECR. Card Entry is set to Manual
		inRet = inCTOS_LoadCDTIndex();
		if (d_OK != inRet)
        {
	    	vdSetECRResponse(ECR_OPER_CANCEL_RESP);
	        return inRet;
    	}
	}
	else
	{
		inRet = inCTOS_GetCardFields();
		if(d_OK != inRet)
			return inRet;
	}
#endif


	inRet = inBDOEnterLast4Digits(FALSE);
	if(inRet != d_OK)
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


//gcitra


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
			{
		    	vdSetECRResponse(ECR_COMMS_ERR);
		        return inRet;
		    }
		}

	//gcitra
	
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

	if ((strTCT.fATPBinRoute == TRUE) && (strCDT.fPANCatchAll == TRUE) && (fBinRoute == TRUE)){

//#ifdef ATPBINROUTE
		vdSetATPBinRouteFlag(1);
		fRouteToSpecificHost = 0;
		inRet = inCTOSS_ATPBinRoutingProcess();
		vdSetATPBinRouteFlag(0);
		if(VS_CONTINUE != inRet)
			return inRet;

		if (strCDT.HDTid == 53){
			vdDisplayErrorMsgResp2(" ", " ", "TRANSACTION NOT ALLOWED");
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
	}
	
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
		
        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_PRE_AUTH);
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

//remove prompt fro selection-Merchant selection is done by inCTOS_TEMPCheckAndSelectMutipleMID
//    inRet = inCTOS_CheckAndSelectMutipleMID();
//    if(d_OK != inRet)
//        return inRet;
	 //inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);


    inRet = inCTOS_CheckMustSettle();
    if(d_OK != inRet)
        return inRet;

/*    inRet = inCTOS_PreConnect();
    if(d_OK != inRet)
        return inRet;
*/
    inRet = inCTOS_CheckIssuerEnable();
    if(d_OK != inRet)
    {
    	vdSetECRResponse(ECR_OPER_CANCEL_RESP);
        return inRet;
	}

    inRet = inCTOS_CheckTranAllowd();
    if(d_OK != inRet)
    {
    	vdSetECRResponse(ECR_OPER_CANCEL_RESP);
        return inRet;
	}


//gcitra
/*    inRet = inCTOS_GetTxnBaseAmount();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_UpdateTxnTotalAmount();
    if(d_OK != inRet)
        return inRet;
*/
//gcitra

    inRet = inCTOS_GetCVV2();
    if(d_OK != inRet)
        return inRet;


    //inRet = inCTOS_CustComputeAndDispTotal();
    //if(d_OK != inRet)
    //    return inRet;

	//gcitra
    if(fBinRouteDCC == FALSE && fRouteToSpecificHost == FALSE)//If Bin Routing host replies with 71 (DCC) and 79 (AMEX), do not perform EMV Processing again since amount and currency is still the same. 
    {
	    inRet = inCTOS_EMVProcessing();
	    if(d_OK != inRet)
	        return inRet;  
    }

	if((srTransRec.usTerminalCommunicationMode == GPRS_MODE) || (srTransRec.usTerminalCommunicationMode == WIFI_MODE)){
	 
		 inRet = inCTOS_PreConnect();
		 if(d_OK != inRet)
		 {
			vdSetECRResponse(ECR_COMMS_ERR);
		    return inRet;
		 }
	}else{
	
		 if (strTCT.fSingleComms){	 
			 if(inCPTRead(1) != d_OK)
			 {
				 vdSetErrorMessage("LOAD CPT ERR");
				 vdSetECRResponse(ECR_COMMS_ERR);
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

    inRet = inBuildAndSendIsoData();
    if(d_OK != inRet)
    {
    	vdSetECRResponse(ECR_COMMS_ERR);
        return inRet;
    }

    inModifyTIDMID_DCC();

    inRet = inCTOS_SaveBatchTxn();
    if(d_OK != inRet)
        return inRet;


	inRet = inCTOS_UpdatePreAuthAccumTotal();
    if(d_OK != inRet)
        return inRet;

		/* BDO: Terminal should disconnect if there no pending TC or advise - start -- jzg */
		inRet = inDisconnectIfNoPendingADVICEandUPLOAD(&srTransRec, strHDT.inNumAdv);
		if(d_OK != inRet)
			return inRet;
		/* BDO: Terminal should disconnect if there no pending TC or advise - end -- jzg */


	fECRBuildSendOK = TRUE;	
	if (fECRBuildSendOK){	
	    inRet = inMultiAP_ECRSendSuccessResponse();
	}
	
    inRet = ushCTOS_printReceipt();
    if(d_OK != inRet)
        return inRet;

    inCTLOS_Updatepowrfail(PFR_IDLE_STATE);


		CTOS_LCDTClearDisplay(); //BDO UAT 0012: Merchant copy still being displayed during TC Upload -- jzg

	if(srTransRec.fDCCAuth == TRUE)
		inRet = inProcessEMVTCUpload_PreAuthDCC(&srTransRec, 1);
	else	
	    inRet = inCTOS_EMVTCUpload();
	
    if(d_OK != inRet)
        return inRet;
    else
        vdSetErrorMessage("");   

		CTOS_LCDTClearDisplay(); //BDO UAT 0012: Merchant copy still being displayed during Advice Upload -- sidumili
		
		inRet=inProcessAdviceTrans(&srTransRec, strHDT.inNumAdv);
			if(d_OK != inRet)
					return inRet;
			else
					vdSetErrorMessage("");


    return d_OK;
}

int inCTOS_PREAUTH(void)
{
    int inRet = d_NO;
    
    CTOS_LCDTClearDisplay();
    
    vdCTOS_TxnsBeginInit();

	vdCTOS_SetTransType(PRE_AUTH);
	vdCTOSS_SetWaveTransType(1);

	inRet = inCTOSS_CLMOpenAndGetVersion();
	if(d_OK != inRet)
        return inRet;

    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiStopResumeAP("SHARLS_ECRBDO");
    
    inRet = inCTOS_PreAuthFlowProcess();
    
    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiResumeContinueAP("SHARLS_ECRBDO");

	/* Send response to ECR -- sidumili */
	if (!fECRBuildSendOK){	
		inMultiAP_ECRSendSuccessResponse();
	}
	
	vdCTOSS_CLMClose();

    inCTOS_inDisconnect();

    vdCTOS_TransEndReset();

    return inRet;
}


int inModifyTIDMID_DCC(void){

		
		if (srTransRec.byTransType == PRE_AUTH && strTCT.fDCC == TRUE && strCDT.fDCCEnable == TRUE 
				&& inGetATPBinRouteFlag() != TRUE && (srTransRec.HDTid != 2 && srTransRec.HDTid != 4/*Not AMEX and AMEX USD host*/) && inCheckIssuerforBINRoute() == TRUE /*&& fRouteToSpecificHost == FALSE*/){
			
			memset(srTransRec.szTID, 0x00, sizeof(srTransRec.szTID));
			memset(srTransRec.szMID, 0x00, sizeof(srTransRec.szMID));
			
			memcpy(srTransRec.szTID, strFXT.szFXTTID, strlen(strFXT.szFXTTID));

			//memcpy(srTransRec.szMID, strFXT.szFXTMID, strlen(strFXT.szFXTMID));
			memcpy(srTransRec.szMID,"00000",5);	
			memcpy(&srTransRec.szMID[5], strFXT.szFXTMID, strlen(strFXT.szFXTMID));		
			

			srTransRec.fDCCAuth = 1;
		}


	vdDebug_LogPrintf("inModifyTIDMID_DCC ** TEST **szTID[%s]..szMID=[%s]..",srTransRec.szTID,srTransRec.szMID);

}

