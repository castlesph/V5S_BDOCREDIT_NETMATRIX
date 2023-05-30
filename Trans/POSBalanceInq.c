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
#include "..\Includes\POSBalanceInq.h"
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

extern BOOL fAutoSMACLogon;
BYTE szSMACBalPAN[PAN_SIZE+1];


int inCTOS_BalanceInquiryFlowProcess(void)
{
    int inRet = d_NO;

    USHORT ushEMVtagLen;
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];

    vdCTOS_SetTransType(BALANCE_INQUIRY);
    
    //display title
    //vdDispTransTitle(BALANCE_INQUIRY);
    
    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_PreConnectAndInit();
    if(d_OK != inRet)
        return inRet;
	
	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();	
	if(d_OK != inRet)
		return inRet;

    if(strTCT.fSMMode == TRUE)
    {	
		inRet = inCTOS_WaveGetCardFields();
	    if(d_OK != inRet)
	        return inRet;
	}
	else
    {
		inRet = inCTOS_GetCardFields();
	    if(d_OK != inRet)
	        return inRet;
    }


	//00188 - [BALANCE INQUIRY] DE02 - PAN is not present in 0100 Request during Balance Inquiry #1
	memset(szSMACBalPAN,0x00,sizeof(szSMACBalPAN));
	strcpy(szSMACBalPAN, srTransRec.szPAN);

	vdDebug_LogPrintf("inCTOS_BalanceInquiryFlowProcess szSMACBalPAN=%s", szSMACBalPAN);	
	vdDebug_LogPrintf("inCTOS_BalanceInquiryFlowProcess fDebitInsertEnable[%d] :: srTransRec.byEntryMode[%d] :: strCDT.HDTid[%d]",strTCT.fDebitInsertEnable,srTransRec.byEntryMode,strCDT.HDTid);


	if (strTCT.fDebitInsertEnable == FALSE && srTransRec.byEntryMode == CARD_ENTRY_ICC && 
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
				vdCTOS_SetTransType(BALANCE_INQUIRY); // Set TransType back to Sale
				fAutoSMACLogon = TRUE;
			}	
		}
	}
	inRet=inCTOS_DisplayCardTitle(6, 7); //Display Issuer logo: re-aligned Issuer label and PAN lines -- jzg
	if(d_OK != inRet)
		return inRet;

	inRet = inConfirmPAN();
	if(d_OK != inRet)
		return inRet; 										

    /*do not allow emv cup to process balance inquiry*/
	//if(strCDT.HDTid == CUP_HDT_INDEX || strCDT.HDTid == CUPUSD_HDT_INDEX || strCDT.HDTid == SMECARD_HDT_INDEX || srTransRec.HDTid == SM_CREDIT_CARD || (memcmp(srTransRec.stEMVinfo.T84,"\xA0\x00\x00\x03\x33",5) == 0))
	if(strTCT.fATPBinRoute == TRUE)
	{
	/*do not allow emv cup to process balance inquiry*/
		//if(strCDT.HDTid == SMECARD_HDT_INDEX || srTransRec.HDTid == SM_CREDIT_CARD || (memcmp(srTransRec.stEMVinfo.T84,"\xA0\x00\x00\x03\x33",5) == 0))
		if(strIIT.fBalInqAllowed == FALSE || (memcmp(srTransRec.stEMVinfo.T84,"\xA0\x00\x00\x03\x33",5) == 0))
		{
	        vdDisplayErrorMsgResp2(" ","BALANCE INQUIRY","NOT ALLOWED");
	        return d_OK;
		}

		if (strCDT.HDTid == BDO_HDT_INDEX)
			{
				if(inCheckIfSMCardInq() == FALSE)
					strCDT.HDTid = DEBIT_HDT_INDEX;

				if(strTCT.fSMMode == FALSE)
					strCDT.HDTid = DEBIT_HDT_INDEX;

			}
		
	}
	else 
	{
		inIITRead(strCDT.IITid);
		if (strIIT.fBalInqAllowed == 0 || (memcmp(srTransRec.stEMVinfo.T84,"\xA0\x00\x00\x03\x33",5) == 0))
		{
	        vdDisplayErrorMsgResp2(" ","BALANCE INQUIRY","NOT ALLOWED");
	        return d_OK;
		}
	}

    inRet = inCTOS_SelectHost();
    if(d_OK != inRet)
        return inRet;

    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {

	    
		if(srTransRec.usTerminalCommunicationMode == DIAL_UP_MODE)		
			inCTOS_inDisconnect();
		
        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_BALANCE_INQUIRY);
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

	
	if(srTransRec.HDTid == SMAC_HDT_INDEX)
	{
		vdCTOS_SetTransType(SMAC_BALANCE);
	    //display title
	    //vdDispTransTitle(SMAC_BALANCE);
	}
	else
	{
		vdCTOS_SetTransType(BALANCE_INQUIRY);
		//vdDispTransTitle(BALANCE_INQUIRY);
	}
	
	inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);

    inRet = inCTOS_CheckMustSettle();
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

	/*sidumili: [CHECK TRANS FOR DEBIT BALANCE INQUIRY]*/

    if ((strTCT.fATPBinRoute == TRUE) && (srTransRec.inCardType == CREDIT_CARD))
    {
    }
    else
    {
        inRet = inCTOS_CheckCardTypeAllowd();
        if(d_OK != inRet)
        return inRet;
    }

    inRet = inCTOS_GetInvoice();
    if(d_OK != inRet)
        return inRet;

    inRet = inBuildAndSendIsoData();
    if(d_OK != inRet){

				// sidumili: delete created reversal for unsuccessfull balance inquiry
			  //inMyFile_ReversalDelete(); //REMOVED to fix issue on reversal being deleted.
		
        return inRet;
    }

	 inRet = InSMACDisplayBalance();
	 if(d_OK != inRet)
		 return inRet;

	 if(srTransRec.fSMACFooter == TRUE)
	 {
		 inRet = inCTOS_SaveBatchTxn();
	     if(d_OK != inRet)
	         return inRet;
	 }

	if(inCheckSMACPayBalanceInq(&srTransRec) == TRUE)
	{
		inRet = inWriteMifareCardFields();
		if(d_OK != inRet)
			vdDisplayErrorMsgResp2("","CARD NOT","UPDATED");
		
	}
		
	 inRet = ushCTOS_printReceipt();
	 if(d_OK != inRet)
		 return inRet;

	 inRet = InDisplayBalance();


   vdSetErrorMessage("");  

    return d_OK;
	
}



int inUnPackIsoFunc04(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{
	if(srTransPara->byTransType == SMAC_BALANCE || (srTransPara->byTransType == BALANCE_INQUIRY && (srTransPara->HDTid == SM_CREDIT_CARD || srTransPara->HDTid == SMSHOPCARD_HDT_INDEX)) )
    	memcpy(srTransRec.szTotalAmount,(char *)uszUnPackBuf,12);
	
	return ST_SUCCESS;	
}



int InDisplayBalance(void){

	char szAmount[12+1];
	char szStr[12+1];

	vdDebug_LogPrintf("-->>InDisplayBalance[START]");

  CTOS_LCDTClearDisplay();
	//display title
  //vdDispTransTitle(BALANCE_INQUIRY);

	CTOS_LCDTPrintXY(1, 4, "BALANCE:");

    wub_hex_2_str(srTransRec.szTotalAmount, szAmount, AMT_BCD_SIZE);      
    memset(szStr, 0x00, sizeof(szStr));
    sprintf(szStr, "%lu.%02lu", atol(szAmount)/100, atol(szAmount)%100);
    setLCDPrint(6, DISPLAY_POSITION_LEFT, strCST.szCurSymbol);
    CTOS_LCDTPrintXY(MAX_CHAR_PER_LINE-(strlen(szStr)+1)*2,  6, szStr);

	WaitKey(10);

	vdDebug_LogPrintf("-->>InDisplayBalance[END]");
	
	return d_OK;



}


int inCTOS_BALANCE_INQUIRY(void)
{
    int inRet = d_NO;
    
    CTOS_LCDTClearDisplay();
    
    vdCTOS_TxnsBeginInit();

	if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiStopResumeAP("SHARLS_ECRBDO");
    
    inRet = inCTOS_BalanceInquiryFlowProcess();
    
    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiResumeContinueAP("SHARLS_ECRBDO");

    inCTOS_inDisconnect();

    vdCTOS_TransEndReset();

    return inRet;
}


/*sidumili: [CHECK TRANS FOR DEBIT BALANCE INQUIRY]*/
int inCTOS_CheckCardTypeAllowd(void){
//if ((srTransRec.byTransType == BALANCE_INQUIRY) && (srTransRec.inCardType != DEBIT_CARD) && (inCheckIfSMCardInq() == FALSE))
if ((srTransRec.byTransType == BALANCE_INQUIRY) && (srTransRec.inCardType != DEBIT_CARD) && (strIIT.fBalInqAllowed == FALSE))

{
	//vdDispTransTitle(srTransRec.byTransType);
	//vdSetErrorMessage("TRANS NOT ALLOWED");
	CTOS_LCDTClearDisplay();
	vdDisplayErrorMsgResp2(" ", "TRANSACTION", "NOT ALLOWED");
	return(d_NO);
}

return(d_OK);
}
/*sidumili: [CHECK TRANS FOR DEBIT BALANCE INQUIRY]*/

/*BDO: Display SM Guarantor Balance -- sidumili*/
int inSMGuarantorDisplayBalance(void){

	char szAmount[30+1],sTemp[30+1];
	char szStr[12+1];
	char szDisplayBuf[30] = {0};

  	CTOS_LCDTClearDisplay();
  	vdDispTransTitle(srTransRec.byTransType);

	CTOS_LCDTPrintXY(1, 4, "NEW BALANCE:");

	if (srTransRec.byTransType == BALANCE_INQUIRY)
		wub_hex_2_str(srTransRec.szTotalAmount, sTemp, AMT_BCD_SIZE);    
	else	
    	wub_hex_2_str(srTransRec.SmacBalance, sTemp, AMT_BCD_SIZE);      
	
	vdCTOS_FormatAmount(strCST.szAmountFormat, sTemp,szAmount);
	sprintf(szDisplayBuf, "%s %s", strCST.szCurSymbol, szAmount);
    CTOS_LCDTPrintXY(1, 6, szDisplayBuf);
	
	WaitKey(10);
	
	return d_OK;

}
/*BDO: Display SM Guarantor Balance -- sidumili*/

