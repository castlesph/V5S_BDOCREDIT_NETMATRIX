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
#include "..\Includes\POSSale.h"
#include "..\Includes\POSbatch.h"
#include "..\Includes\POSInstallment.h"
#include "..\ui\Display.h"
#include "..\Includes\V5IsoFunc.h"
#include "..\Accum\Accum.h"
#include "..\print\Print.h"
#include "..\Comm\V5Comm.h"
#include "..\Includes\MultiApLib.h"
#include "..\Aptrans\MultiAptrans.h"

//gcitra
#include "..\Includes\CTOSInput.h"
#include "..\Includes\ISOEnginee.h"
//gcitra

#include "..\Database\prm.h"

extern BOOL fInstApp; //BDO: Parameterized manual key entry for installment --jzg
extern BOOL fBINVer;;
extern BOOL fECRBuildSendOK;

int inCTOS_InstallmentFlowProcess(void)
{
    int inRet = d_NO;
	int inNumRecs = 0;
    USHORT ushEMVtagLen;
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];
	BOOL fWaveCardEntry;

    vdCTOS_SetTransType(SALE);

		fInstApp = TRUE; //BDO: Parameterized manual key entry for installment --jzg
    
    //display title
    //vdDispTransTitle();
    //vdDispTitleString("INSTALLMENT");//aaronnino for BDOCLG ver 9.0 fix on issue #00072 Installment title flickering twice before amount display
    
    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;

    if (!fBINVer){
		inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
		if(d_OK != inRet)
			return inRet;
    }

    //inRet = inCTOS_PreConnectAndInit();
    //if(d_OK != inRet)
    //    return inRet;
	
//gcitra
    inRet = inCTOS_INSTGetTxnBaseAmount();
    if(d_OK != inRet)
        return inRet;

	if(srTransRec.PRMid > 0 && fGetECRTransactionFlg())//Fix for blank screen before card confirmation screen.
		vdCTOS_DispStatusMessage("PROCESSING..."); 

    inRet = inCTOS_PreConnectAndInit();
    if(d_OK != inRet)
        return inRet;

/*    inRet = inCTOS_GetTxnTipAmount();
    if(d_OK != inRet)
        return inRet;
*/


    //remove - BDO does not require display and Floor limit cheking is not applicable to BDO (Except for EMV) 
	//inRet = inCTOS_CustComputeAndDispTotal();
	//if(d_OK != inRet)
	//	return inRet;
//gcitra
	
   // if (strTCT.byCtlsMode == 0)
//		inRet = inCTOS_GetCardFields();
	//else
//CTOS_LCDTClearDisplay();
//vdClearBelowLine(2);

/* BDO: CTLS not allowed for installment -- jzg */
#if 0
    	inRet = inCTOS_WaveGetCardFields();
    if(d_OK != inRet)
        return inRet;
#else
 		//version16
 		fWaveCardEntry = TRUE;
SWIPE_AGAIN:
		if (fWaveCardEntry == TRUE){
			inRet = inCTOS_WaveGetCardFields(); //enable CTLS for installment
            if (strTCT.fSMMode == TRUE){
            	if (srTransRec.byEntryMode == CARD_ENTRY_WAVE){
					if (inCheckBDO_Off_Us() != d_OK){
						vdClearBelowLine(2);
						vdDisplayErrorMsg(1, 8, "CTLS NOT DETECTED");
						vdResetAllCardData();
						fWaveCardEntry = FALSE;
						goto SWIPE_AGAIN;
					}
            	}
            }
		}else
			inRet = inCTOS_GetCardFields();


		//version16-end

		
		
		if ((USER_ABORT == inRet) || (READ_CARD_TIMEOUT == inRet || INVALID_CARD == inRet))
		   	return inRet;
		else if (d_OK != inRet)
        	goto SWIPE_AGAIN;
#endif

	memset(strMultiPRM, 0, sizeof(strMultiPRM));
	
	inRet = inPRMReadbyinInstGroupEx(strCDT.inInstGroup, &inNumRecs);
	
	if(strlen(strMultiPRM[0].szPrintPromoLabel) <= 0)//check if no records found
	{
		CTOS_LCDTClearDisplay();
		vdDisplayErrorMsgResp2(" ", "TRANSACTION", "NOT ALLOWED");
		return inRet;	
	}

	
	
	if (srTransRec.byEntryMode == CARD_ENTRY_ICC && strMultiPRM[inNumRecs - 1].fInstEMVEnable == FALSE)
	{	
		vdInstallmentPromptToSwipe();
        vdCTOS_ResetMagstripCardData();
        inRet = inCTOS_GetCardFieldsSwipeOnly();
        if(d_OK != inRet)
            return inRet;	
	}

	if (srTransRec.byEntryMode == CARD_ENTRY_FALLBACK && strMultiPRM[inNumRecs - 1].fInstEMVEnable == FALSE)//Terminal should not support FALLBACK if fInstEMVEnable is FALSE.
		srTransRec.byEntryMode = CARD_ENTRY_MSR;
		
	/* BDOCLG-00325: Installment should not accept fleet cards - start -- jzg */
	if(strCDT.fFleetCard == TRUE)
	{
		vdDisplayErrorMsgResp2(" ", "TRANSACTION", "NOT ALLOWED");
		return(d_OK);
	}
	/* BDOCLG-00325: Installment should not accept fleet cards - end -- jzg */

    if (!fBINVer){
		inRet = inBDOEnterLast4Digits(TRUE);
		if(inRet != d_OK)
			return inRet;
    }

	//gcitra - put display here not in amount entry
		inRet=inCTOS_DisplayCardTitle(6, 7); //Display Issuer logo: re-aligned Issuer label and PAN lines -- jzg
		if(d_OK != inRet)
			return inRet;

		inRet = inCTOS_UpdateTxnTotalAmount();
		if(d_OK != inRet)
			return inRet;

	
		inRet = inConfirmPAN();
		if(d_OK != inRet)
			return inRet;
		
	//gcitra


	
	if(srTransRec.PRMid > 0 && fGetECRTransactionFlg())
	{
		//Do not prompt for Promo selection if Installment request is directly sent by ECR.
		inRet = inCTOS_SelectECRInstallmentPromo();
	    if(d_OK != inRet)
	    	return inRet;
	}
	else
	{
		//Installment: Promo selection function -- jzg
	    inRet = inCTOS_SelectInstallmentPromo();
	    if(d_OK != inRet)
	    	return inRet;
	}

   
    //inRet = inCTOS_SelectHost();
    inRet = inCTOS_SelectHostEx2();
	inDatabase_TerminalCloseDatabase();
    if(d_OK != inRet)
        return inRet;

	inRet = 0;
	inRet = inMultiAP_CheckMainAPStatus();
    if (inRet == d_OK)
    {
        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_ONLINES_SALE);
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
    inRet = inCTOS_CheckAndSelectMutipleMID();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_PreConnect();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_CheckIssuerEnable();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_CheckTranAllowd();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_CheckMustSettle();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_GetInvoice();
    if(d_OK != inRet)
        return inRet;

/*
    inRet = inCTOS_GetTxnBaseAmount();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_GetTxnTipAmount();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_UpdateTxnTotalAmount();
    if(d_OK != inRet)
        return inRet;
*/

//gcitra - put display here not in amount entry
	inRet=inCTOS_DisplayCardTitle(4, 5);
    if(d_OK != inRet)
        return inRet;

	inRet = inConfirmPAN();
    if(d_OK != inRet)
        return inRet;
//gcitra

    inRet = inCTOS_GetCVV2();
    if(d_OK != inRet)
        return inRet;

/*
    	inRet = inCTOS_CustComputeAndDispTotal();
    	if(d_OK != inRet)
        	return inRet;
*/
	//gcitra
	//inRet = inGetPolicyNumber();
	//if(d_OK != inRet)
	//	return inRet;	
	//gcitra

 
    inRet = inCTOS_EMVProcessing();
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
    
    inRet = ushCTOS_printReceipt();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_EMVTCUpload();
    if(d_OK != inRet)
        return inRet;
    else
        vdSetErrorMessage("");

	//gcitra
	inCTOS_CashierLoyalty();
		if(d_OK != inRet)
		return inRet;
	//gcitra

#endif
    return d_OK;
}



int inCTOS_INSTALLMENT(void)
{
    int inRet = d_NO;
    
    CTOS_LCDTClearDisplay();
    
    vdCTOS_TxnsBeginInit();

//	vdCTOSS_GetAmt();

	inRet = inCTOSS_CLMOpenAndGetVersion();
	if(d_OK != inRet)
		return inRet;

    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiStopResumeAP("SHARLS_ECRBDO");

	inRet = inCTOS_InstallmentFlowProcess();

    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiResumeContinueAP("SHARLS_ECRBDO");

	vdCTOSS_CLMClose();

	/* Send response to ECR -- sidumili */
	if (!fECRBuildSendOK){	
		inMultiAP_ECRSendSuccessResponse();
	}	
	fECRBuildSendOK = FALSE;
	/* Send response to ECR -- sidumili */
	
    inCTOS_inDisconnect();

    vdCTOS_TransEndReset();

    return inRet;


	
}


int inCheckInstallmentEMVEnable(void)
{
	if(strCDT.inInstGroup == BDO_INST_GROUP || strCDT.inInstGroup == AMEX_INST_GROUP || strCDT.inInstGroup == BRANCH_INST_GROUP || 
		strCDT.inInstGroup == BANKARD_INST_GROUP || strCDT.inInstGroup == CITIBANK_INST_GROUP)
		return TRUE;

	return FALSE;

}

void vdInstallmentPromptToSwipe(void)
{
	CTOS_LCDTPrintXY(1, 3, "CHIP NOT SUPPORTED");
	CTOS_Beep();
	WaitKey(2);
	vduiClearBelow(2);
	vdRemoveCard();
	vduiClearBelow(2);
	CTOS_LCDTPrintXY(1, 3, "Please Swipe");
	CTOS_LCDTPrintXY(1, 4, "Customer Card");

}


