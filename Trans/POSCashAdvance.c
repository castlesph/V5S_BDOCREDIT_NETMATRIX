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
#include "..\Debug\Debug.h"

#include "..\Includes\POSMain.h"
#include "..\Includes\POSTrans.h"
#include "..\Includes\POSHost.h"
#include "..\Includes\POSCashAdvance.h"
#include "..\Includes\POSbatch.h"
#include "..\ui\Display.h"
#include "..\Includes\V5IsoFunc.h"
#include "..\Accum\Accum.h"
#include "..\print\Print.h"
#include "..\Comm\V5Comm.h"
#include "..\Includes\MultiApLib.h"
#include "..\Aptrans\MultiAptrans.h"

extern BOOL fRouteToSpecificHost;
extern BOOL fEntryCardfromIDLE;
extern BOOL fUSDSelected;

int inCTOS_CashAdvanceFlowProcess(void)
{
    int inRet = d_NO;

    USHORT ushEMVtagLen;
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];
    BOOL fBinRoute=TRUE;
	
    vdCTOS_SetTransType(CASH_ADVANCE);
    
    //display title
    vdDispTransTitle(CASH_ADVANCE);
    
    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;

    if(fEntryCardfromIDLE == TRUE && (srTransRec.byEntryMode == CARD_ENTRY_ICC || srTransRec.byEntryMode == CARD_ENTRY_MSR))
    {
        inRet = inCTOS_GetCardFields();
        
        if(d_OK != inRet)
            return inRet;
    }

	
	if (inCTOS_ValidFirstIdleKey() == d_OK){

		inRet = inCTOS_GetTxnBaseAmount();
		if(d_OK != inRet)
			return inRet;
		
		inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
		if(d_OK != inRet)
			return inRet;

	}else{
	
		inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
		if(d_OK != inRet)
			return inRet;
		
		inRet = inCTOS_GetTxnBaseAmount();
		if(d_OK != inRet)
		return inRet;
	}

    inRet = inCTOS_PreConnectAndInit();
    if(d_OK != inRet)
        return inRet;
	


    if (strTCT.fSingleComms){	
		inRet = inCTOS_PreConnectEx();

		if (inRet != d_OK)
			return inRet;
	}

		
    inRet = inCTOS_GetCardFields(); 
    if(d_OK != inRet)
         return inRet;

    if(strCDT.inType == DEBIT_CARD)
    {
        vdDisplayErrorMsgResp2(" ", "TRANSACTION", "NOT ALLOWED");
        return d_OK;
    }

	inRet=inEMVCheckCUPEnable(); /*check CUP PHP*/
	if(d_OK != inRet)
		return inRet;

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

    if(inCTLSEMVCheck() == d_OK)
        fBinRoute=FALSE;		

    if(fCUPBinRoute() == d_OK)
        fBinRoute=FALSE;

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
  
    if ((strTCT.fATPBinRoute == TRUE) && (strCDT.fPANCatchAll == TRUE) && (fBinRoute == TRUE))
    {
        vdSetATPBinRouteFlag(1);
        fRouteToSpecificHost = 0;
        inRet = inCTOSS_ATPBinRoutingProcess();
        vdDebug_LogPrintf("inCTOSS_ATPBinRoutingProcess inRet=[%d]",inRet);
        vdSetATPBinRouteFlag(0);
        if(VS_CONTINUE != inRet)
            return inRet;
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

    //aaronnino for BDOCLG ver 9.0 fix on issue#00146 Debit is accepting on CASH ADVANCE start 1 of 3
    inRet = inCTOS_CardNotSuppoted(HDT_DEBIT_CARD);
    if(d_OK != inRet)
         return inRet;
	//aaronnino for BDOCLG ver 9.0 fix on issue#00146 Debit is accepting on CASH ADVANCE end 1 of 3



    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {

		if(srTransRec.usTerminalCommunicationMode == DIAL_UP_MODE){	
			char szAPName[25];
			int inAPPID;
			inMultiAP_CurrentAPNamePID(szAPName, &inAPPID);
			if (strcmp (strHDT.szAPName,szAPName) != 0)
				inCTOS_inDisconnect();
		}

        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_CASH_ADVANCE);
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
	//	  inRet = inCTOS_CheckAndSelectMutipleMID();
	//	  if(d_OK != inRet)
	//		  return inRet;
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
        return inRet;

    inRet = inCTOS_CheckTranAllowd();
    if(d_OK != inRet)
        return inRet;


    //gcitra
    //inRet = inCTOS_SelectAccountType();
    //if(d_OK != inRet)
    //    return inRet;
	//gcitra

    //inRet = inGetIPPPin();
    //if(d_OK != inRet)
    //    return inRet;

	
    inRet = inCTOS_EMVProcessing();
    if(d_OK != inRet)
        return inRet;  

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


    inRet = inCTOS_GetInvoice();
    if(d_OK != inRet)
        return inRet;

    inRet = inBuildAndSendIsoData();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_SaveBatchTxn();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_UpdateAccumTotal();
    if(d_OK != inRet)
        return inRet;

	/* BDO: Terminal should disconnect if there no pending TC or advise - start -- jzg */
	inRet = inDisconnectIfNoPendingADVICEandUPLOAD(&srTransRec, strHDT.inNumAdv);
	if(d_OK != inRet)
		return inRet;
	/* BDO: Terminal should disconnect if there no pending TC or advise - end -- jzg */

    inRet = ushCTOS_printReceipt();
    if(d_OK != inRet)
        return inRet;

	CTOS_LCDTClearDisplay(); 
		
    inRet = inCTOS_EMVTCUpload();
    if(d_OK != inRet)
        return inRet;
    else
        vdSetErrorMessage("");


    return d_OK;
}

int inCTOS_CASH_ADVANCE(void)
{
    int inRet = d_NO;
    
    CTOS_LCDTClearDisplay();
    
    vdCTOS_TxnsBeginInit();

    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiStopResumeAP("SHARLS_ECRBDO");
    
    inRet = inCTOS_CashAdvanceFlowProcess();
    
    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiResumeContinueAP("SHARLS_ECRBDO");

    inCTOS_inDisconnect();

    vdCTOS_TransEndReset();

    return inRet;
}

