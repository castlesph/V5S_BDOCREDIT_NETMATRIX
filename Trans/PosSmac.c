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
#include "..\ui\Display.h"
#include "..\Includes\V5IsoFunc.h"
#include "..\Accum\Accum.h"
#include "..\print\Print.h"
#include "..\Comm\V5Comm.h"
#include "..\Includes\MultiApLib.h"
#include "..\Aptrans\MultiAptrans.h"
#include "..\POWRFAIL\POSPOWRFAIL.h"


//gcitra
#include "..\Includes\CTOSInput.h"
#include "..\Includes\ISOEnginee.h"
//gcitra

#include "..\Includes\posSmac.h"
#include "..\Includes\POSBinVer.h"


/* BDO: Last 4 PAN digit checking - start -- jzg */
extern int inBDOEnterLast4Digits(BOOL fInstallment);


extern int inCTOS_CashierLoyalty(void);
extern BOOL fBINVer;
extern BOOL fAutoSMACLogon;
extern int inReversalType;



extern BOOL fECRBuildSendOK; 
extern BOOL fTimeOutFlag; 


#if 0
int inCTOS_SaleFlowProcess(void)
{
    int inRet = d_NO;

    USHORT ushEMVtagLen;
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];

    vdCTOS_SetTransType(SALE);
    
    //display title
    vdDispTransTitle(SALE);
		
		srTransRec.fVoidOffline = CN_FALSE;
    
    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;
//gcitra
    inRet = inCTOS_GetTxnBaseAmount();
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
	
    inRet = inCTOS_GetCardFields(); 
    //inRet = inCTOS_WaveGetCardFields();
    if(d_OK != inRet)
        return inRet;

	/* BDO: Last 4 PAN digit checking - start -- jzg */
	inRet = inBDOEnterLast4Digits();
	if(inRet != d_OK)
			return inRet;
	/* BDO: Last 4 PAN digit checking - end -- jzg */

	inRet = inCTOS_SelectHost();
	if(d_OK != inRet)
		return inRet;


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


	
    if (inMultiAP_CheckMainAPStatus() == d_OK)
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


    inRet = inCTOS_CheckAndSelectMutipleMID();
    if(d_OK != inRet)
        return inRet;

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

		//EMV: Online PIN enchancement - start -- jzg
#ifdef ONLINE_PIN_SUPPORT
		srTransRec.fEMVPIN = FALSE;
		vdDebug_LogPrintf("JEFF::inCTOS_SaleFlowProcess 9F34 = [%02X %02X %02X]", srTransRec.stEMVinfo.T9F34[0], srTransRec.stEMVinfo.T9F34[1], srTransRec.stEMVinfo.T9F34[2]);
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

		inRet = inCTOS_PreConnect();
				if(d_OK != inRet)
						return inRet;


    inRet = inCTOS_GetInvoice();
    if(d_OK != inRet)
        return inRet;

    inRet = inBuildAndSendIsoData();
    if(d_OK != inRet)
        return inRet;

		vdDebug_LogPrintf("JEFF::strHDT.szTraceNo 2 = [%s]", strHDT.szTraceNo);

    inRet = inCTOS_SaveBatchTxn();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_UpdateAccumTotal();
    if(d_OK != inRet)
        return inRet;
		// patrick add code 20141205 start
    inRet = inMultiAP_ECRSendSuccessResponse();
    if(d_OK != inRet)
        return inRet;
		// patrick add code 20141205 end
    
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
	
	inRet=inProcessAdviceTrans(&srTransRec, strHDT.inNumAdv);
    if(d_OK != inRet)
        return inRet;
    else
        vdSetErrorMessage("");


	//gcitra
	inCTOS_CashierLoyalty();
		if(d_OK != inRet)
		return inRet;
	//gcitra


    return d_OK;
}


/* Issuer# 000163 - start -- jzg */
int inGetPolicyNumber(void)
{
                USHORT usRet = 0;
    USHORT usLens;
                USHORT usMinLen = 1;
                USHORT usMaxLen = 0;
                USHORT usInputLine = 6;
                BYTE baBuf[21+1] = {0};

								if ((srTransRec.HDTid != 1) && (srTransRec.HDTid != 2) && (srTransRec.HDTid != 23) && (srTransRec.HDTid != 24))
										return d_OK;

                if (strTCT.fGetPolicyNumber == 0)
                    return d_OK;

                CTOS_LCDTClearDisplay();
                vdDispTransTitle(SALE);

                memset(srTransRec.szPolicyNumber, 0x00, sizeof(srTransRec.szPolicyNumber));

                CTOS_KBDBufFlush();

                usMaxLen = strIIT.inPolicyNumMaxChar;

                if (usMaxLen >19)
                                usMaxLen = 19;

                setLCDPrint(4, DISPLAY_POSITION_LEFT, "POLICY NO: ");
                memset(baBuf, 0x00, sizeof(baBuf));     

                while(1)
                {
                                vduiClearBelow(5);
                                memset(baBuf,0x00, sizeof(baBuf));

                                usRet = InputStringAlpha2(1, usInputLine, 0x00, 0x02, baBuf, &usMaxLen, usMinLen, d_INPUT_TIMEOUT);
                                if(usRet == d_KBD_ENTER)
                                {
                                                if(strlen(baBuf) > 0)
                                                {
                                                                memset(srTransRec.szPolicyNumber, 0, strlen(srTransRec.szPolicyNumber));
                                                                memcpy(srTransRec.szPolicyNumber, baBuf, strlen(baBuf));
                                                                break;
                                                }
                                }
                                if(usRet == d_KBD_CANCEL)
                                                return d_USER_CANCEL;
                }

                return d_OK;
}
/* Issuer# 000163 - end -- jzg */







int inCTOS_SALE(void)
{
	int inRet = d_NO;
	unsigned char bTC2ndbyte = 0,
		bTC3rdbyte = 0;

#ifdef ONLINE_PIN_SUPPORT
	/* POC: 2 dip online pin - start -- jzg*/
	inEMVRead(2);
	bTC2ndbyte = strEMVT.szEMVTermCapabilities[1];
	bTC3rdbyte = strEMVT.szEMVTermCapabilities[2];

	do
	{
		CTOS_LCDTClearDisplay();
		vdCTOS_TxnsBeginInit();
		
		inRet = inCTOS_SaleFlowProcess();
		vdDebug_LogPrintf("JEFF::inCTOS_SaleFlowProcess = [%d]", inRet);
		if(inRet == ST_RESP_DO_ONLINE_PIN)
		{
			inEMVRead(2);
			strEMVT.szEMVTermCapabilities[1] = 0xF0;
			strEMVT.szEMVTermCapabilities[2] = 0xC8;
			inEMVSave(2);
		}
		else
		{
			inEMVRead(2);
			strEMVT.szEMVTermCapabilities[1] = bTC2ndbyte;
			strEMVT.szEMVTermCapabilities[2] = bTC3rdbyte;
			inEMVSave(2);
		}
		vdDebug_LogPrintf("JEFF::szEMVTermCapabilities = [%02X %02X %02X]", strEMVT.szEMVTermCapabilities[0], strEMVT.szEMVTermCapabilities[1], strEMVT.szEMVTermCapabilities[2]);
		
		inCTOS_inDisconnect();
		vdCTOS_TransEndReset();
	}
	while(inRet == ST_RESP_DO_ONLINE_PIN);

	strEMVT.szEMVTermCapabilities[1] = bTC2ndbyte;
	strEMVT.szEMVTermCapabilities[2] = bTC3rdbyte;
	inEMVSave(2);
	/* POC: 2 dip online pin - start -- jzg*/
#else
	CTOS_LCDTClearDisplay();
	
	vdCTOS_TxnsBeginInit();
	
	inRet = inCTOS_SaleFlowProcess();
	
	inCTOS_inDisconnect();
	
	vdCTOS_TransEndReset();
#endif

	

	return inRet;
}
#endif

int inCTOS_SMACLogonFlowProcess(int inSelectMerchant )
{
    int inRet = d_NO;

    USHORT ushEMVtagLen;
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];


    vdCTOS_SetTransType(SMAC_ACTIVATION);
    
    //display title
    //vdDispTransTitle(SMAC_ACTIVATION);
    
    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;

	#if 0
	if (strTCT.SMACENABLE == TRUE){
		vdDisplayMessage("ALREADY LOGGED ON", "", "");
		CTOS_Delay(3000);

		return d_NO;
		
	}
	#endif
	if(inSelectMerchant == SELECT) // Will not prompt for Merchant selection if auto SMAC Logon occurs before SMAC Sale from Idle Menu.
	{
		inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
		if(d_OK != inRet)
			return inRet;
	}
	//inRet = inCTOS_SelectLogonIIT();
	//if(d_OK != inRet)
    //    return inRet;

	//	inRet = inCTOS_SeletLogonPIT();
	//		if(d_OK != inRet)
    //    return inRet;

		
    inRet = inCTOS_PreConnectAndInit();
    if(d_OK != inRet)
        return inRet;
	
    inRet = inCTOS_SelectSMACHost();
    if(d_OK != inRet)
        return inRet;


	
    //if (strTCT.fSingleComms)	
	//	inCTOS_PreConnectEx();

	//inGetIssuerRecord(15); /*BDO: Ver9.0 = 23, Ver10.0 = 27 -- sidumili*/ /*moved inside inCTOS_SelectSMACHost*/

	/*BDO: Check if SMAC already logged on -- sidumili*/
	inRet = CheckIfSmacAlreadyLogOn();
	if(d_OK != inRet)
    return inRet;
		
    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_SMAC_LOGON);
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
	//inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid); moved inside inCTOS_SelectSMACHost

	//if(fBINVer != TRUE)
		//inFirstInitConnectFuncPoint();
		
	//if (strTCT.fSingleComms != TRUE){
		inRet = inCTOS_PreConnect();
		if(d_OK != inRet)
			return inRet;
	//}
		
    inRet = inCTOS_CheckIssuerEnable();
    if(d_OK != inRet)
        return inRet;

/*    inRet = inCTOS_CheckTranAllowd();
    if(d_OK != inRet)
        return inRet;
*/
    inRet = inBuildAndSendIsoData();
    if(d_OK != inRet){
		//inMyFile_ReversalDelete();		
        return inRet;
    }

	inRet = inCheckLogonResponse();
    if(d_OK != inRet)
        return inRet;

    return d_OK;
}

int inCTOS_SMACLOGON(void)
{
    int inRet = d_NO;
		int result;

	fSMACTRAN = TRUE;
	
    CTOS_LCDTClearDisplay();

    vdCTOS_TxnsBeginInit();

    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiStopResumeAP("SHARLS_ECRBDO");
    
    inRet = inCTOS_SMACLogonFlowProcess(SELECT);
    
    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiResumeContinueAP("SHARLS_ECRBDO");

    inCTOS_inDisconnect();

    vdCTOS_TransEndReset();

    return inRet;
}


int inCTOS_SelectSMACHost(void) 
{
    short shGroupId ;
    int inHostIndex;
    short shCommLink;
    int inCurrencyIdx=0;
	char szDebug[40]={0};
	char szStr[16+1]={0};



    inHostIndex =  SMAC_HDT_INDEX;
    //inHostIndex = (short) srTransRec.HDTid;
    
     vdDebug_LogPrintf("inCTOS_SelectHost =[%d]",inHostIndex);
    
    if (inMultiAP_CheckSubAPStatus() == d_OK)
        return d_OK;

	inDatabase_TerminalOpenDatabase(); 
    if ( inHDTReadEx(inHostIndex) != d_OK)
    {
        //vdSetErrorMessage("HOST SELECTION ERR");
		inHDTReadDataEx(inHostIndex);
		strcpy(szStr,strHDT_Temp.szHostLabel);
		memset(strHDT_Temp.szHostLabel,0x00,16+1);
		sprintf(strHDT_Temp.szHostLabel," %s ",szStr);
		vdDisplayErrorMsgResp2(strHDT_Temp.szHostLabel, "TRANSACTION", "NOT ALLOWED");
		inDatabase_TerminalCloseDatabase(); 
        return(d_NO);
    } 
    else 
    {
        srTransRec.HDTid = inHostIndex;

        inCurrencyIdx = strHDT.inCurrencyIdx;

        if (inCSTReadEx(inCurrencyIdx) != d_OK) 
        {
            inDatabase_TerminalCloseDatabase();
            vdSetErrorMessage("LOAD CST ERR");
            return(d_NO);
        }

        if(strTCT.fSingleComms == TRUE)
		    inHostIndex=1;
		
        if ( inCPTReadEx(inHostIndex) != d_OK)
        {
            inDatabase_TerminalCloseDatabase();
            vdSetErrorMessage("LOAD CPT ERR");
            return(d_NO);
        }

        inIITReadEx(15);
		
        inMMTReadRecordEx(srTransRec.HDTid,srTransRec.MITid);
		
        inDatabase_TerminalCloseDatabase();
        return (d_OK);
    }
}



int inCTOS_SMACAward(void)
{
    int inRet = d_NO;
		int result;

	
	fSMACTRAN = TRUE;
	
    CTOS_LCDTClearDisplay();

    vdCTOS_TxnsBeginInit();

    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiStopResumeAP("SHARLS_ECRBDO");
    
    inRet = inCTOS_SMACAwardFlowProcess();
    
    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiResumeContinueAP("SHARLS_ECRBDO");

    inCTOS_inDisconnect();

    vdCTOS_TransEndReset();

    return inRet;
}



int inCTOS_SMACAwardFlowProcess(void)
{
		int inRet = d_NO;
	
		USHORT ushEMVtagLen;
		BYTE   EMVtagVal[64];
		BYTE   szStr[64];
	
		vdCTOS_SetTransType(SALE_OFFLINE);
		
		vdDispTransTitle(SALE_OFFLINE);
			
		
		inRet = inCTOSS_CheckMemoryStatus();
		if(d_OK != inRet)
			return inRet;
	
		//inRet = inCTOS_GetTxnPassword();
		//if(d_OK != inRet)
		//	return inRet;

		inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
		if(d_OK != inRet)
			return inRet;

        inRet = inCTOS_PreConnectAndInit();
        if(d_OK != inRet)
            return inRet;
	
		//inRet = inCTOS_GetTxnBaseAmount();
		inRet=inSMACSelectTender();
		if(d_OK != inRet)
			return inRet;
	
		
		inRet = inCTOS_GetCardFields(); 
		if(d_OK != inRet)
			return inRet;
	
		/* BDO: Last 4 PAN digit checking - start -- jzg */
		inRet = inBDOEnterLast4Digits(FALSE);
		if(inRet != d_OK)
				return inRet;
		/* BDO: Last 4 PAN digit checking - end -- jzg */
	
		inRet = inCTOS_SelectHost();
		if(d_OK != inRet)
			return inRet;
	
	
		inRet=inCTOS_DisplayCardTitle(6, 7); //Display Issuer logo: re-aligned Issuer label and PAN lines -- jzg
		if(d_OK != inRet)
			return inRet;
	
	
		inRet = inCTOS_UpdateTxnTotalAmount();
		if(d_OK != inRet)
			return inRet;
		
		inRet = inConfirmPAN();
		if(d_OK != inRet)
			return inRet;		


		inRet = CheckIfSmacCard();	
		if(d_OK != inRet)
			return inRet;		

		inRet=CheckIfSmacEnable();
		if(d_OK != inRet)
			return inRet;		

	
		if (inMultiAP_CheckMainAPStatus() == d_OK)
		{
			
			inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_AWARD_POINTS);
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
		inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);
	
		inRet = inCTOS_CheckMustSettle();
		if(d_OK != inRet)
			return inRet;
	
	
		inRet = inCTOS_CheckIssuerEnable();
		if(d_OK != inRet)
			return inRet;
	
//		inRet = inCTOS_CheckTranAllowd();
//		if(d_OK != inRet)
//			return inRet;
	
	
		inRet = inCTOS_GetCVV2();
		if(d_OK != inRet)
			return inRet;
	
	
	 
		inRet = inCTOS_EMVProcessing();
		if(d_OK != inRet)
			return inRet;	
	
	
		inRet = inCTOS_PreConnect();
		if(d_OK != inRet)
			return inRet;
	
	
		inRet = inCTOS_GetInvoice();
		if(d_OK != inRet)
			return inRet;
	
		inRet = inBuildAndSendIsoData();
		if(d_OK != inRet)
			return inRet;
	
		vdDebug_LogPrintf("JEFF::strHDT.szTraceNo 2 = [%s]", strHDT.szTraceNo);
	
		inRet = inCTOS_SaveBatchTxn();
		if(d_OK != inRet)
			return inRet;
	
		inRet = inCTOS_UpdateAccumTotal();
		if(d_OK != inRet)
			return inRet;
			// patrick add code 20141205 start
		inRet = inMultiAP_ECRSendSuccessResponse();
		if(d_OK != inRet)
			return inRet;
			// patrick add code 20141205 end
		
		inRet = ushCTOS_printReceipt();
		if(d_OK != inRet)
			return inRet;
	
		
		inCTLOS_Updatepowrfail(PFR_IDLE_STATE);
		
		CTOS_LCDTClearDisplay(); //BDO UAT 0012: Merchant copy still being displayed during TC Upload -- jzg
	
#if 0
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
#endif

		vdSetErrorMessage("");
	
	
		//gcitra
		//inCTOS_CashierLoyalty();
		//	if(d_OK != inRet)
		//	return inRet;
		//gcitra
	
	
		return d_OK;
}

#if 1

char* szCalculatePoints(void){
 
	DOUBLE lnAmount = 0.00, lnPoints = 0.00;
	char szTemp[20+1], szPoints[6+1];
	char* ptr = NULL;
	char szDecimal[2+1];
	int i;

	int inDecimal=0;
    BYTE szBaseAmount[20];

    memset(szBaseAmount, 0x00, sizeof(szBaseAmount));
    //wub_hex_2_str(srTransRec.szBaseAmount, szBaseAmount, 6);
	
	wub_hex_2_str(srTransRec.szBaseAmount, szBaseAmount, AMT_BCD_SIZE);

	lnAmount = (atof(szBaseAmount)  * 0.01) / 100;

	lnPoints = (strTCT.SMACRATE * 0.01) * lnAmount;

	memset(szTemp, 0x00, sizeof(szTemp));
	memset(szPoints, 0x00, sizeof(szPoints));
	memset(szDecimal, 0x00, sizeof(szDecimal));

	sprintf(szTemp,"%.3f",lnPoints);
	

	ptr = strchr(szTemp, '.');

	strncpy(szPoints, szTemp, ptr - szTemp);

	memcpy(szDecimal, ptr+1, 2);

	i = atoi(&ptr[3]);


	if (i>0){
		inDecimal = atoi(szDecimal);
		inDecimal = inDecimal + 1;

		if (inDecimal < 10)
            sprintf(szDecimal, "0%d", inDecimal);
        else
            sprintf(szDecimal, "%d", inDecimal);

	}

	if (inDecimal > 99){
		memset(szTemp, 0x00, sizeof(szTemp));

		lnPoints = atof(szPoints) + 1;
		sprintf(szTemp,"%.3f",lnPoints);
		ptr = strchr(szTemp, '.');

		memset(szPoints, 0x00, sizeof(szPoints));

		strncpy(szPoints, szTemp, ptr - szTemp);
		strcpy(szDecimal, "00");
		
	}


	strncat(szPoints, szDecimal, 2);

	sprintf(szTemp, "%012.0f", atof(szPoints));
	wub_str_2_hex(szTemp,srTransRec.SmacPoints,12);

	return (szPoints);
	
}


int inSMACSelectTender(void){

	int inRet;
	char szTemp[7+1], szTemp2[6+1];
	char 	*chNull = 0;
	int inTender=4;
	BYTE key;

	BYTE byItmesNum = 3;
	BYTE bHeaderAttr = 0x01+0x04, iCol = 1;
	BYTE  x = 1;
	char szHeaderString[50] = "SELECT TENDER";
	char szTenderMenu[1024];
	int inLoop = 0;

	BYTE szTenderList[3][32] = 
		{	"CASH",
			"CREDIT",
			"OTHERS"
		};



	CTOS_LCDTClearDisplay();
	vdDispTransTitle(srTransRec.byTransType);

	#if 0

	do
	{
		//setLCDPrint27(3,DISPLAY_POSITION_LEFT, "SELECT TENDER:"); 	
		
		CTOS_LCDTPrintXY(1, 3, "SELECT TENDER");
		CTOS_LCDTPrintXY(1, 5, "[1]CASH");
		CTOS_LCDTPrintXY(1, 6, "[2]CREDIT");		
		CTOS_LCDTPrintXY(1, 7, "[3]OTHERS");

		key = WaitKey(60);
		if (key == d_KBD_1)
		{
			inRet = d_OK;
			inTender = 0;
			break;
		}
		else if (key == d_KBD_2)
		{
			inRet = d_OK;	
			inTender = 1;
			break;
		}
		else if (key == d_KBD_3)
		{
			inRet = d_OK;	
			inTender = 2;
			break;
		}

		else if (key == d_KBD_CANCEL)
		{
			inRet = d_NO;
			break;
		}
		else
			vduiWarningSound();

	}
	while(1);
	#endif

	CTOS_KBDBufFlush();//cleare key buffer

    if(byItmesNum > 1)
    {
        
        //issue-00436: clear the buffer first to avoid garbage display
		memset(szTenderMenu, 0x00, sizeof(szTenderMenu));
		
        for (inLoop = 0; inLoop < byItmesNum; inLoop++)
        {
            strcat((char *)szTenderMenu, &szTenderList[inLoop]);
            if(inLoop + 1 != byItmesNum)
                strcat((char *)szTenderMenu, (char *)" \n");
        }

		if((strTCT.byTerminalType % 2) == 0)
		{
			CTOS_LCDForeGndColor(RGB(13, 43, 112));
			CTOS_LCDBackGndColor(RGB(255, 255, 255));
		}
			
        key = MenuDisplay(szHeaderString, strlen(szHeaderString), bHeaderAttr, iCol, x, szTenderMenu, TRUE);
		vdDebug_LogPrintf("MenuDisplay select[%d]", key);

		
        inSetTextMode(); 
				 
        if (key == 1)
		{
			inRet = d_OK;
			inTender = 0;
			//break;
		}
		else if (key == 2)
		{
			inRet = d_OK;	
			inTender = 1;
			//break;
		}
		else if (key == 3)
		{
			inRet = d_OK;	
			inTender = 2;
			//break;
		}
		else if (key == d_KBD_CANCEL)
		{
			inRet = d_NO;
			//break;
			return inRet;
		}
		else
			vduiWarningSound();
		
    }


	if ((inTender == 0) ||(inTender == 1) ||(inTender == 2)){
		
		inRet = inCTOS_GetTxnBaseAmount();
		if(d_OK != inRet)
			return inRet;
		
		memset(szTemp, 0x00, sizeof(szTemp));
		memset(szTemp2, 0x00, sizeof(szTemp2));

		sprintf(szTemp,"%d", inTender);

		strcpy(szTemp2,szCalculatePoints());

	
		srTransRec.inSmacTender = inTender;
		//vdCTOS_Pad_String(szTemp2, 6, '0', POSITION_RIGHT);	
		
		//strcpy(&szTemp[1],szTemp2);
		//inStoreBatchFieldData((BATCH_REC *)&pobTran->srBRec, SMAC_AWARD_POINTS_FIELD63, (unsigned char*)szTemp, 7);
		inRet = d_OK;
	}
	
	return inRet;

}


int inCTOS_SMACRedeem(void)
{
    int inRet = d_NO;
		int result;

	fSMACTRAN = TRUE;
	
    CTOS_LCDTClearDisplay();

    vdCTOS_TxnsBeginInit();

    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiStopResumeAP("SHARLS_ECRBDO");
    
    inRet = inCTOS_SMACRedeemFlowProcess();
    
    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiResumeContinueAP("SHARLS_ECRBDO");

    inCTOS_inDisconnect();

    vdCTOS_TransEndReset();

    return inRet;
}


extern BOOL fSmacScan;

int inCTOS_SMACRedeemFlowProcess(void)
{
		int inRet = d_NO;
	
		USHORT ushEMVtagLen;
		BYTE   EMVtagVal[64];
		BYTE   szStr[64];

		//version16
        BYTE szQrCodeText[200];
		BYTE szBuffer [50];
		char szBcd[INVOICE_BCD_SIZE+1];
		int  inResult;

		//version16
	
		vdCTOS_SetTransType(SALE);
		
		vdDispTransTitle(SALE);

		//vdDebug_LogPrintf("inCTOS_SMACRedeemFlowProcess");
			
		
		inRet = inCTOSS_CheckMemoryStatus();
		if(d_OK != inRet)
			return inRet;

		inRet = inCTOS_GetTxnPassword();
		if(d_OK != inRet)
			return inRet;

		inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
		if(d_OK != inRet)
			return inRet;

        //inRet = inCTOS_PreConnectAndInit();
        //if(d_OK != inRet)
        //    return inRet;
	
		inRet = inCTOS_GetTxnBaseAmount();
		if(d_OK != inRet)
			return inRet;
	
		inRet = inCTOS_PreConnectAndInit();
		if(d_OK != inRet)
			return inRet;

		//version16
		if (fSmacScan == TRUE){

           	srTransRec.HDTid = SMAC_HDT_INDEX;
			strCDT.HDTid = SMAC_HDT_INDEX;
			srTransRec.IITid = 15;

			inIITRead(srTransRec.IITid);
			inCPTRead(srTransRec.HDTid);
			strcpy(srTransRec.szCardLable, strIIT.szIssuerLabel);
        	vdCTOS_SetTransEntryMode(SMAC_SCAN);
			//vdDebug_LogPrintf("inCTOS_SMACRedeemFlowProcess smac srTransRec.byEntryMode %d", srTransRec.byEntryMode);

			//srTransRec.fSMACPrintscan = TRUE;//00160 - No SCAN label printed in Smac QR void receipt
		}else{
			//inRet = inCTOS_GetCardFields(); 
			inRet = inCTOS_WaveGetCardFields();
			if(d_OK != inRet)
				return inRet;
	
			/* BDO: Last 4 PAN digit checking - start -- jzg */
			inRet = inBDOEnterLast4Digits(FALSE);
			if(inRet != d_OK)
				return inRet;
			/* BDO: Last 4 PAN digit checking - end -- jzg */
	
			inRet = inCTOS_SelectHostEx2();
			inDatabase_TerminalCloseDatabase();
			if(d_OK != inRet)
				return inRet;

		}

		//version16
		if (fSmacScan == TRUE){
			inRet=inCTOS_DisplayCardTitle(6, 7); //Display Issuer logo: re-aligned Issuer label and PAN lines -- jzg
			if(d_OK != inRet)
				return inRet;
		}
	
	
		inRet = inCTOS_UpdateTxnTotalAmount();
		if(d_OK != inRet)
			return inRet;

		if (fSmacScan != TRUE){

			inRet = inConfirmPAN();
			if(d_OK != inRet)
				return inRet;	

			inRet = CheckIfSmacCard();	
			if(d_OK != inRet)
				return inRet;		
	
		}

		inRet=CheckIfSmacEnable();
		if(d_OK != inRet)
			return inRet;		

		if (inMultiAP_CheckMainAPStatus() == d_OK)
		{
			
			inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_REDEEM);
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


		// for testing only - 03012023 - 00136 - SM: No delimiter pipe ( I ) on smac qrcode #1
		#if 0
	    inRet = inCTOS_GetInvoice();
		vdDebug_LogPrintf("#00136 - AAA %s", szBuffer);
		
		if(d_OK != inRet)
			return inRet;
		#endif
	
		//remove prompt fro selection-Merchant selection is done by inCTOS_TEMPCheckAndSelectMutipleMID
		//	  inRet = inCTOS_CheckAndSelectMutipleMID();
		//	  if(d_OK != inRet)
		//		  return inRet;
		inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);

		if (fSmacScan == TRUE){
			memset(szQrCodeText, 0x00, sizeof(szQrCodeText));
			//sprintf(szQrCodeText,"D01%s%d%s%s%s%s%s%s",srTransRec.szBaseAmount,
			//srTransRec.ulTraceNum,srTransRec.szTID, 
			//srTransRec.szMID, srTransRec.szInvoiceNo,
			//strMMT[0].szMerchantName,strMMT[0].szRctHdr1);
			strcpy(szQrCodeText,"D01|");

			memset(szBuffer, 0x00, sizeof(szBuffer));
			wub_hex_2_str(srTransRec.szBaseAmount, szBuffer, 6);
			vdDebug_LogPrintf("testlang amount %s", szBuffer);
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
			vdDebug_LogPrintf("testlang stan %s", szBuffer);			
			strcat(szQrCodeText, szBuffer);
			strcat(szQrCodeText,"|");

			//TID
			strcat(szQrCodeText, srTransRec.szTID);
			strcat(szQrCodeText,"|");			
			vdDebug_LogPrintf("testlang TID %s", srTransRec.szTID);

			//MID
			strcat(szQrCodeText, srTransRec.szMID);
			strcat(szQrCodeText,"|");			
			vdDebug_LogPrintf("testlang MID %s", srTransRec.szMID);

			
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
			vdDebug_LogPrintf("#00136 - BBB %s", szBuffer);
			
			inTCTRead(1);

			vdDebug_LogPrintf("#00136 - CCC %s", szBuffer);
			
			wub_hex_2_str(strTCT.szInvoiceNo, szBuffer, 3);
			vdDebug_LogPrintf("testlang invoice %s", szBuffer);
			strcat(szQrCodeText, szBuffer);
			strcat(szQrCodeText,"|");
			
#endif

#if 0
			strcat(szQrCodeText, strMMT[0].szMerchantName);			
			strcat(szQrCodeText,"|");
			vdDebug_LogPrintf("testlang Merchant name  %s", strMMT[0].szMerchantName);

			strcat(szQrCodeText, strMMT[0].szRctHdr1);			
			strcat(szQrCodeText,"|");
			vdDebug_LogPrintf("testlang Merchant header %s", strMMT[0].szRctHdr1);
#else
						vdDebug_LogPrintf("inCTOS_WaveFlowProcess srTransRec.MITid %d", srTransRec.MITid);
			
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
			vdDebug_LogPrintf("testlang szQrCodeText %s", szQrCodeText);


			inRet = inCTOSS_DisplayQRCodeAndConfirm(szQrCodeText);

			if(d_OK != inRet)
				return inRet;


		}


		vdDebug_LogPrintf("inCTOS_SMACRedeemFlowProcess CCC");

		inRet = inCTOS_CheckMustSettle();
		if(d_OK != inRet)
			return inRet;
	
	
		inRet = inCTOS_CheckIssuerEnable();
		if(d_OK != inRet)
			return inRet;
	
		inRet = inCTOS_CheckTranAllowd();
		if(d_OK != inRet)
			return inRet;
	
	
		inRet = inCTOS_GetCVV2();
		if(d_OK != inRet)
			return inRet;
	
	
	 
		//inRet = inCTOS_EMVProcessing();
		//if(d_OK != inRet)
		//	return inRet;	
	
	
		inRet = inCTOS_PreConnect();
		if(d_OK != inRet)
			return inRet;
	
	
	vdDebug_LogPrintf("inCTOS_SMACRedeemFlowProcess DDD");


		inRet = inCTOS_GetInvoice();
		if(d_OK != inRet)
			return inRet;


		vdDebug_LogPrintf("inCTOS_SMACRedeemFlowProcess EEE");
		
	
		inRet = inBuildAndSendIsoData();
		if(d_OK != inRet)
			return inRet;
	
		vdDebug_LogPrintf("JEFF::strHDT.szTraceNo 2 = [%s]", strHDT.szTraceNo);
		inRet = inCTOS_SaveBatchTxn();
		if(d_OK != inRet)
			return inRet;
	
		inRet = inCTOS_UpdateAccumTotal();
		if(d_OK != inRet)
			return inRet;
			// patrick add code 20141205 start
		inRet = inMultiAP_ECRSendSuccessResponse();
		if(d_OK != inRet)
			return inRet;
			// patrick add code 20141205 end

        //version16
        if (fSmacScan != TRUE){
			inRet = inWriteMifareCardFields();
			if(d_OK != inRet)
				vdDisplayErrorMsgResp2("","CARD NOT","UPDATED");
		}
		
		inRet = ushCTOS_printReceipt();
		if(d_OK != inRet)
			return inRet;
	
		
		inCTLOS_Updatepowrfail(PFR_IDLE_STATE);
		
			CTOS_LCDTClearDisplay(); //BDO UAT 0012: Merchant copy still being displayed during TC Upload -- jzg
	
		//inRet = inCTOS_EMVTCUpload();
		//if(d_OK != inRet)
		//	return inRet;
		//else
		//	vdSetErrorMessage("");
	
		//CTOS_LCDTClearDisplay(); //BDO UAT 0012: Merchant copy still being displayed during Advice Upload -- sidumili
		
		//inRet=inProcessAdviceTrans(&srTransRec, strHDT.inNumAdv);
		//if(d_OK != inRet)
		//	return inRet;
		//else
		vdSetErrorMessage("");
	


		InSMACDisplayBalance();
		//gcitra
		//inCTOS_CashierLoyalty();
		//	if(d_OK != inRet)
		//	return inRet;
		//gcitra
	
	
		return d_OK;
}


int inSMACAnalyzeField63(void)
{
	//char szMsgBuff[MESSAGE_SIZE+1];
	char *pszMsgBuff;
	char *pszNewBal;
	int inPeriod=0, inNewAmt=0;
	char szNewBalance[100+1];
	char szMsgBuff[29+1];
	int Len;
	char TempBuf[32+1];
	char szCardExpiry[16+1]; //SMAC Footer Modification

	//fSMCHGiftCard = VS_FALSE;   // Privelege or Guarantor Card
	vdDebug_LogPrintf("SMAC szField63 = [%s]", szField63);
	memset(szNewBalance, 0x00, sizeof(szNewBalance));
	memset(szMsgBuff, 0x00, sizeof(szMsgBuff));
	//added extra braces for porting

	if(	(pszNewBal = strstr((char *)&szField63[2], "NEW BAL") !=NULL) || (pszNewBal = (strstr((char *)&szField63[2], "New Bal"))) !=NULL ||
		(pszNewBal = strstr((char *)&szField63[2], "NEWBAL") !=NULL) || (pszNewBal = (strstr((char *)&szField63[2], "NewBal"))) !=NULL)
		srTransRec.fPrintSMCardHolder = TRUE;
	
	pszMsgBuff=strchr((char *)&szField63[2], '=');


	if (pszMsgBuff)
	{
		int inPos=0;
		// get name from field 63
		//srRcpt.unFrm.srDet.srMid.szAmt
		while (1)
		{
			if(szField63[inPos] == '=')
			{
				memcpy(srTransRec.szCardholderName,(char *)&szField63[2],inPos-9);
				srTransRec.szCardholderName[inPos-9] = 0x00;


				break;
			}
			inPos++;
		}


		//SMAC Footer Modification - get the card expiry added in Field 63
		
		strcpy(TempBuf, pszMsgBuff+1);
		vdTrimSpaces(TempBuf);

		Len=strlen(TempBuf);
		
		if(Len>0)
			srTransRec.fPrintCardHolderBal = TRUE;
		//get the remaining balance from the remaining data
		vdDebug_LogPrintf("TempBuf[%s] :: inPos+1[%c]:: Len[%d] :: fPrintCardHolderBal[%d]",TempBuf,szField63[inPos+1],Len,srTransRec.fPrintCardHolderBal);
		
		inPos=0;

		memset(szCardExpiry,'\0',sizeof(szCardExpiry));
		while(1)
		{
			if(TempBuf[inPos]==',')
			{
				int inLen;
				char s[8+1];
				
				inLen=strlen(strstr(TempBuf,","));
				
				memcpy(szMsgBuff,TempBuf,12); //get the remaining balance
				strcpy(szCardExpiry,&TempBuf[(strlen(szMsgBuff)+1)]);
				break;
			}

			if(inPos>=Len+1)
			{			
				strcpy(szMsgBuff,TempBuf);
				break;
			}
			inPos++;
		}
	}
	//added extra braces for porting
	else if (((pszMsgBuff = (strstr((char *)&szField63[2], "NEW BAL"))) !=NULL) || 
		    ((pszMsgBuff = (strstr((char *)&szField63[2], "New Bal"))) !=NULL))
	{

		strcpy(szMsgBuff, pszMsgBuff+7 );
		vdTrimLeadSpaces(szMsgBuff);
		//fSMCHGiftCard = VS_TRUE;   // Gift Card
		//szNewBalance[19] = VS_TRUE;
	}
	else if (((pszMsgBuff = (strstr((char *)&szField63[2], "NEWBAL"))) !=NULL) || 
		    ((pszMsgBuff = (strstr((char *)&szField63[2], "NewBal"))) !=NULL))
	{

		strcpy(szMsgBuff, pszMsgBuff+6 );
		vdTrimLeadSpaces(szMsgBuff);
		//fSMCHGiftCard = VS_TRUE;   // Gift Card
		//szNewBalance[19] = VS_TRUE;
	}

	// remove the period for amount format
	while (inPeriod < strlen(szMsgBuff))
	{
		if (szMsgBuff[inPeriod] == '.')
			inPeriod++;
		szNewBalance[inNewAmt] = szMsgBuff[inPeriod];
		inPeriod++;
		inNewAmt++;
	}

	/*BDO: Save SMAC Balance -- sidumili*/
	vdTrimLeadSpaces(szNewBalance);
	vdTrimSpaces(szNewBalance);
	vdCTOS_Pad_String(szNewBalance, 12, IS_ZERO, POSITION_LEFT);
	/*BDO: Save SMAC Balance -- sidumili*/
	
    vdDebug_LogPrintf("SMAC szNewBalance = [%s]", szNewBalance);

	memset(srTransRec.SmacBalance, 0x00, sizeof(srTransRec.SmacBalance));
	wub_str_2_hex(szNewBalance,srTransRec.SmacBalance,12);
	
#if 0
	if(strlen(srRcpt.szErrorMessage))
	{

		szNewBalance[18] = '1';   // if '1' there is card name from of field63 host reponse 
		strcpy(&szNewBalance[21],srRcpt.szErrorMessage);   // copy card name 
	}	
	szNewBalance[19] = fSMCHGiftCard;
#endif


	  
	return d_OK;
}


void vdTrimLeadSpaces(char* pchString) {
    int inIndex;
    
    inIndex = 0;
    while (pchString[inIndex] == 0x20)
        inIndex++;
    if (inIndex != 0)
        strcpy(pchString, &(pchString[inIndex]));
}
#if 0
int InSMACDisplayBalance(void){

	char szAmount[30+1],sTemp[30+1];
	char szStr[12+1];
	char szDisplayBuf[30] = {0};

	vdDebug_LogPrintf("-->>InDisplayBalance[START]");

  	CTOS_LCDTClearDisplay();
  	vdDispTransTitle(srTransRec.byTransType);

	CTOS_LCDTPrintXY(1, 4, "NEW BALANCE:");

	if (srTransRec.byTransType == SMAC_BALANCE)
		wub_hex_2_str(srTransRec.szTotalAmount, sTemp, AMT_BCD_SIZE);    
	else	
    	wub_hex_2_str(srTransRec.SmacBalance, sTemp, AMT_BCD_SIZE);      

	vdDebug_LogPrintf("::sTemp[%s]::srTransRec.SmacBalance[%s]", sTemp, srTransRec.SmacBalance);
	
	vdCTOS_FormatAmount(strCST.szAmountFormat, sTemp,szAmount);
	sprintf(szDisplayBuf, "%s %s", strCST.szCurSymbol, szAmount);
    CTOS_LCDTPrintXY(1, 6, szDisplayBuf);
	
	WaitKey(10);

	vdDebug_LogPrintf("-->>InDisplayBalance[END]");
	
	return d_OK;



}
#else
int InSMACDisplayBalance(void)
{

   char szAmount[30+1],sTemp[30+1];
   char szStr[12+1];
   char szDisplayBuf[30] = {0};
   
   char szTemp[20+1];
   char szSMACCTRID[6+1]; 
   char szSMACCBatchNo[4+1]; 
   char szSMACCExpDate[8+1]; 
   int inCount=0;
   
   vdDebug_LogPrintf("-->>InDisplayBalance[START]");
	if(srTransRec.HDTid == SMECARD_HDT_INDEX || srTransRec.HDTid == SMPARTNER_HDT_INDEX)
		return d_OK;

	if (srTransRec.byTransType == SALE && srTransRec.fPrintCardHolderBal == FALSE)
	  	return d_OK;

   if (srTransRec.byTransType == SMAC_BALANCE || srTransRec.byTransType == BALANCE_INQUIRY)
   		vdHandPinPadtoCustomer();
   	
   CTOS_LCDTClearDisplay();
   vdDispTransTitle(srTransRec.byTransType);
   if (srTransRec.byTransType == SALE && srTransRec.HDTid == SMAC_HDT_INDEX )
   {
	  vdDebug_LogPrintf("srTransRec.szSMACBDORewardsBalance[%s]", srTransRec.szSMACBDORewardsBalance);

	  //if (srTransRec.fPrintCardHolderBal == FALSE)
	  	//return d_OK;

	  
       CTOS_LCDTPrintXY(1, 4, "NEW BALANCE:");
	   
	   vdDebug_LogPrintf("srTransRec.szSMACBDORewardsBalance[%s]", srTransRec.szSMACBDORewardsBalance);

	   sprintf(szDisplayBuf, "%s %s", strCST.szCurSymbol, srTransRec.szSMACBDORewardsBalance);
	   
       //if(inCheckifAllSpaces((char*)srTransRec.SmacBalance) == TRUE)
	   		//memset(szDisplayBuf,0x00,sizeof(szDisplayBuf));
	   
	   CTOS_LCDTPrintXY(1, 5, szDisplayBuf);
	   WaitKey(10);
   
	   vdDebug_LogPrintf("-->>InDisplayBalance[END]");
	   
	   return d_OK;
	  
   }
   else
   {
	   if (srTransRec.byTransType == SMAC_BALANCE || srTransRec.byTransType == BALANCE_INQUIRY)
	   {
   	  
	      CTOS_LCDTPrintXY(1, 4, "BALANCE:");

		  if(srTransRec.byTransType == SMAC_BALANCE || ( srTransRec.byTransType == BALANCE_INQUIRY && (srTransRec.HDTid == SM_CREDIT_CARD || srTransRec.HDTid == SMSHOPCARD_HDT_INDEX)))
	      	wub_hex_2_str(srTransRec.szTotalAmount, sTemp, AMT_BCD_SIZE);
		  else
		  	wub_hex_2_str(srTransRec.SmacBalance, sTemp, AMT_BCD_SIZE);

		  if(srTransRec.byTransType == SMAC_BALANCE)
		  {
			  memset(szTemp,0,sizeof(szTemp));
		      memset(szSMACCTRID,0,sizeof(szSMACCTRID));
		      strcpy(szTemp, "CTR ID:");
		      memcpy(szSMACCTRID, &szField63[0], 6);
		      strcat(szTemp, szSMACCTRID);
		      CTOS_LCDTPrintXY(1, 6, szTemp);
	      
		      memset(szTemp,0,sizeof(szTemp));
		      memset(szSMACCBatchNo,0,sizeof(szSMACCBatchNo));
		      strcpy(szTemp, "BATCH#:");
		      memcpy(szSMACCBatchNo, &szField63[7], 4);
		      strcat(szTemp, szSMACCBatchNo);
		      CTOS_LCDTPrintXY(1, 7, szTemp);
	      
		      memset(szTemp,0,sizeof(szTemp));
		      memset(szSMACCExpDate,0x00,sizeof(szSMACCExpDate));
		      strcpy(szTemp, "EXPIRES:");
		      memcpy(szSMACCExpDate, &szField63[12], 8);
			  while(1)//check if expiry date contains numbers to display
			  {
			  	vdDebug_LogPrintf("szSMACCExpDate[%d][%c]",inCount, szSMACCExpDate[inCount]);
				if( (szSMACCExpDate[inCount] > '0' && szSMACCExpDate[inCount] < '9') )	
				{
					srTransRec.fPrintExpFlag = TRUE;
					break;
				}

				if(szSMACCExpDate[inCount] == 0X00)
					break;
				
				inCount++;
			  }

			  if(srTransRec.fPrintExpFlag == TRUE)
			  {
			      strcat(szTemp, szSMACCExpDate);
			      CTOS_LCDTPrintXY(1, 8, szTemp);
			  }
		  }
   
	   }
   
	   else	if (srTransRec.byTransType == SALE)
	   {
	      wub_hex_2_str(srTransRec.SmacBalance, sTemp, AMT_BCD_SIZE);      
		  vdDebug_LogPrintf("::sTemp[%s]::srTransRec.SmacBalance[%s] %ld", sTemp, srTransRec.SmacBalance, atol(sTemp));

		  if (atol(sTemp) < 0)
		  	return d_OK;

	  
	      CTOS_LCDTPrintXY(1, 4, "NEW BALANCE:");
	   }
   }
#if 0
   else	
   {
      CTOS_LCDTPrintXY(1, 4, "NEW BALANCE:");
      //wub_hex_2_str(srTransRec.SmacBalance, sTemp, AMT_BCD_SIZE);      
	  wub_hex_2_str(srTransRec.szTotalAmount, sTemp, AMT_BCD_SIZE); 
	  vdDebug_LogPrintf("::sTemp[%s]::srTransRec.szTotalAmount[%s]", sTemp, srTransRec.szTotalAmount);
   }
#endif

   vdCTOS_FormatAmount(strCST.szAmountFormat, sTemp,szAmount);
   sprintf(szDisplayBuf, "%s %s", strCST.szCurSymbol, szAmount);
   CTOS_LCDTPrintXY(1, 5, szDisplayBuf);
   
   
   
   WaitKey(10);
   
   vdDebug_LogPrintf("-->>InDisplayBalance[END]");
   
   return d_OK;



}

#endif

int inCTOS_SMACBalanceInq(void)
{
    int inRet = d_NO;

	fSMACTRAN = TRUE;
    
    CTOS_LCDTClearDisplay();
    
    vdCTOS_TxnsBeginInit();

    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiStopResumeAP("SHARLS_ECRBDO");
    
    inRet = inCTOS_SMACBalanceInquiryFlowProcess();
    
    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiResumeContinueAP("SHARLS_ECRBDO");

    inCTOS_inDisconnect();

    vdCTOS_TransEndReset();

    return inRet;
}

int inCTOS_SMACBalanceInquiryFlowProcess(void)
{
    int inRet = d_NO;

    USHORT ushEMVtagLen;
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];

    vdCTOS_SetTransType(SMAC_BALANCE);
    
    //display title
    vdDispTransTitle(SMAC_BALANCE);
    
    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;

	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;

    inRet = inCTOS_PreConnectAndInit();
    if(d_OK != inRet)
        return inRet;
	
    //inRet = inCTOS_GetCardFields();
    inRet = inCTOS_WaveGetCardFields();
    if(d_OK != inRet)
        return inRet;

	inRet=inCTOS_DisplayCardTitle(6, 7); //Display Issuer logo: re-aligned Issuer label and PAN lines -- jzg
		if(d_OK != inRet)
											return inRet;
		
	inRet = inConfirmPAN();
		if(d_OK != inRet)
			return inRet; 										

	inRet = CheckIfSmacCard();	
	if(d_OK != inRet)
		return inRet;		

	inRet=CheckIfSmacEnable();
	if(d_OK != inRet)
		return inRet;		

    inRet = inCTOS_SelectHostEx2();
	inDatabase_TerminalCloseDatabase();
    if(d_OK != inRet)
        return inRet;

    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_SMAC_INQ);
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
	inRet = inCTOS_CheckCardTypeAllowd();
	if(d_OK != inRet)
			return inRet;


    inRet = inCTOS_GetInvoice();
    if(d_OK != inRet)
        return inRet;

    inRet = inBuildAndSendIsoData();
    if(d_OK != inRet){

				// sidumili: delete created reversal for unsuccessfull balance inquiry
			  //inMyFile_ReversalDelete(); ////REMOVED to fix issue on reversal being deleted.
		
        return inRet;
    }

	//inRet = InDisplayBalance();
	 inRet = InSMACDisplayBalance();
	 if(d_OK != inRet)
		 return inRet;

	 if(srTransRec.fSMACFooter == TRUE)
	 {
		 inRet = inCTOS_SaveBatchTxn();
	     if(d_OK != inRet)
	         return inRet;
	 }
	inRet = inWriteMifareCardFields();
	if(d_OK != inRet)
		vdDisplayErrorMsgResp2("","CARD NOT","UPDATED");

	 inRet = ushCTOS_printReceipt();
	 if(d_OK != inRet)
		 return inRet;

   vdSetErrorMessage("");  

    return d_OK;
}


int inCheckLogonResponse(void){

	char szTemp[5+1];
	BYTE szCurrDate[8+1];
	char szActivationDate[8+1];
	char szMessage[21];
	char szTempDate[8+1];
	
    CTOS_RTC SetRTC;
    //BYTE szCurrentTime[20];

	   
	memset(szCurrDate, 0x00, sizeof(szCurrDate));
	memset(szActivationDate, 0x00, sizeof(szActivationDate));
	memset(szTemp, 0x00, sizeof(szTemp));

	
	//vdGetDate((char*)szCurrDate, YYYYMMDD);
	

    memset(szCurrDate, 0x00, sizeof(szCurrDate));
    CTOS_RTCGet(&SetRTC);
	sprintf(szCurrDate,"%02d%02d%02d",SetRTC.bYear, SetRTC.bMonth, SetRTC.bDay, SetRTC.bHour,SetRTC.bMinute);


	if (strTCT.SMZ == 1){
		memcpy(szActivationDate,&szField63[6],4);  
		memcpy(&szActivationDate[4],&szField63[2],2);  
		memcpy(&szActivationDate[6],&szField63[4],2);  
	}else{
		memcpy(szActivationDate,&szField63[4],4);  
		memcpy(&szActivationDate[4],&szField63[0],2);  
		memcpy(&szActivationDate[6],&szField63[2],2);  
	}

	/*BDO: Remove "20" in year -- sidumili*/
	memset(szTempDate, 0x00, sizeof(szTempDate));
	memcpy(szTempDate, &szActivationDate[2],6);
	memset(szActivationDate, 0x00, sizeof(szActivationDate));
	strcpy(szActivationDate, szTempDate);
	/*BDO: Remove "20" in year -- sidumili*/

	vdDebug_LogPrintf("strTCT.SMZ[%d]", strTCT.SMZ);
	vdDebug_LogPrintf("Activation Date [%s]::Current Date[%s]", szActivationDate, szCurrDate);
	vdDebug_LogPrintf("FIELD63 LEN[%d]::szField63[%s]", strlen(szField63), szField63);
	
	//if (strcmp(szActivationDate, szCurrDate) <= 0){
	if(strTCT.inSMACMode == 1)//Activation date is greater than current date
	{
		if (atol(szActivationDate) > atol(szCurrDate))
		{
				if (strTCT.SMZ == 1)
					memcpy(szTemp, &szField63[10], 5);
				else
					memcpy(szTemp, &szField63[8], 5);	
				
				strTCT.SMACRATE= atoi(szTemp);
				strTCT.SMACENABLE = TRUE;
				strcpy(strTCT.DEACTDATE,"");

				vdDebug_LogPrintf("strTCT.SMACRATE[%d]", strTCT.SMACRATE);
				
				inTCTSave(1);
				//vdDisplayMessage("SMAC LOGON", "SUCCESSFULL", "");
				vduiClearBelow(2);
				setLCDPrint27(3, DISPLAY_POSITION_CENTER, "  SMAC LOGON  ");
				setLCDPrint27(4, DISPLAY_POSITION_CENTER, "SUCCESSFUL");
				CTOS_Delay(3000);
				CTOS_LCDTClearDisplay();
				inTCTRead(1);
		}else{
				vdDisplayErrorMsg(1, 8, "LOGON FAILED");
			    return d_NO;
		}
	}
	else
	{//Activation date is less than current date
		if (atol(szActivationDate) < atol(szCurrDate))
		{
				if (strTCT.SMZ == 1)
					memcpy(szTemp, &szField63[10], 5);
				else
					memcpy(szTemp, &szField63[8], 5);	
				
				strTCT.SMACRATE= atoi(szTemp);
				strTCT.SMACENABLE = TRUE;
				strcpy(strTCT.DEACTDATE,"");

				vdDebug_LogPrintf("strTCT.SMACRATE[%d]", strTCT.SMACRATE);
				
				inTCTSave(1);
				//vdDisplayMessage("SMAC LOGON", "SUCCESSFULL", "");
				setLCDPrint27(3, DISPLAY_POSITION_CENTER, "  SMAC LOGON  ");
				setLCDPrint27(4, DISPLAY_POSITION_CENTER, "SUCCESSFUL");
				CTOS_Delay(3000);
				inTCTRead(1);
		}else{
				vdDisplayErrorMsg(1, 8, "LOGON FAILED");
			    return d_NO;
		}
	}
	return d_OK;

}


int inCheckNewSMACRateFromSettlement(void){

	char szTemp[5+1];
	//char szCurrDate[8+1];
	char szDecctivationDate[8];
	//char szMessage[21];


	vdDebug_LogPrintf("*************************inCheckNewSMACRateFromSettlement*********************************");

	if (srTransRec.HDTid != SMAC_HDT_INDEX)
		return d_OK;

	if (inCTOSS_CheckBitmapSetBit(63) == CN_TRUE){
		vdDebug_LogPrintf("SMAC = %s", szField63);

		memset(szDecctivationDate, 0x00, sizeof(szDecctivationDate));
		memcpy(szDecctivationDate, szField63, 8);		
		strcpy(strTCT.DEACTDATE,szDecctivationDate);
		
		inTCTSave(1);
		
		memset(szTemp, 0x00, sizeof(szTemp));
		memcpy(szTemp, &szField63[8], 5);	

		if (atoi(szTemp) <= 0)
			return d_OK;
		else
			strTCT.SMACRATE= atoi(szTemp);

		
		vdDebug_LogPrintf("SMACRATE = %d", strTCT.SMACRATE);
			
		inTCTSave(1);
	}

	strTCT.SMACENABLE = FALSE; /*BDO: Added to force disable SMACENABLE for settlement -- sidumili*/
	inTCTSave(1);
	inTCTRead(1);
	
	return d_OK;

}

int inCheckSMAC(void){

	char szTime[6 + 1];
	char szHour[2+1];
	char szCurrDate[8+1];
	char szActivationDate[8+1];
	char szTempActivationDate[8+1];
    CTOS_RTC SetRTC;


	fSMACTRAN = FALSE;
	if (strTCT.SMACENABLE == 0)
		return d_OK;


	memset(szCurrDate, 0x00, sizeof(szCurrDate));
	memset(szActivationDate, 0x00, sizeof(szActivationDate));
	memset(szTempActivationDate, 0x00, sizeof(szTempActivationDate));

    memset(szCurrDate, 0x00, sizeof(szCurrDate));
    CTOS_RTCGet(&SetRTC);
	sprintf(szCurrDate,"%02d-%02d-%02d",SetRTC.bYear, SetRTC.bMonth, SetRTC.bDay);

	strcpy(szTempActivationDate,strTCT.DEACTDATE);

	memcpy(szActivationDate, &szTempActivationDate[4], 4);
	memcpy(&szActivationDate[4], &szTempActivationDate[0], 4);


	if ((strcmp(szActivationDate, "") != 0) && (strlen(szActivationDate) == 8 )){
		if (strcmp(szActivationDate, szCurrDate) <= 0) {		
			strTCT.SMACRATE= 0;
			strTCT.SMACENABLE = FALSE;
			strcpy(strTCT.DEACTDATE,"");
			inTCTSave(1);

			
			inTCTRead(1);
		}
	}


	return d_OK;

}


int CheckIfSmacEnable(void){
	
  	CTOS_LCDTClearDisplay();

	if (strTCT.SMACENABLE == 1)
		return d_OK;
	else{
		
		vdDisplayErrorMsg(1, 8, "PLEASE LOGON FIRST");
		//vduiWarningSound();
		//CTOS_Beep();
		//CTOS_Delay(2000);
		//CTOS_Delay(500);
		return d_NO;
	}
}

int CheckIfSmacCard(void){
	vdDebug_LogPrintf("CheckIfSmacCard strCDT.HDTid=%d", strCDT.HDTid);
	if (strCDT.HDTid == SMAC_HDT_INDEX)
		return d_OK;
	else{
		CTOS_LCDTClearDisplay();
		
		vdDisplayErrorMsg(1, 8, "CARD NOT SUPPORTED");
		//vduiWarningSound();
		//CTOS_Beep();
		//CTOS_Delay(2000);
		//CTOS_Delay(500);
		return d_NO;
	}
}

int CheckIfSmacAlreadyLogOn(void){
	
	if (strTCT.SMACENABLE == 0)
		return d_OK;
	else{
		CTOS_LCDTClearDisplay();	
		vdDisplayErrorMsg(1, 8, "ALREADY LOGGED ON");
		//vduiWarningSound();
		//CTOS_Beep();
		//CTOS_Delay(2000);
		//CTOS_Delay(500);
		return d_NO;
	}	
}

/*BDO: For SMAC which during void DE04 is the balance amount -- sidumili*/
void vdUpdateSMACAmount(void)
{
	vdDebug_LogPrintf("vdUpdateSMACAmount::byTransType[%d]:byOrgTransType[%d]:fSMACTRAN[%d]::srTransRec.HDTid[%d]", srTransRec.byTransType, srTransRec.byOrgTransType, fSMACTRAN, srTransRec.HDTid);

	if ((srTransRec.byTransType == VOID) && (srTransRec.byOrgTransType == SALE) && inCheckIfSMCardTransRec() == TRUE){
		// save balance
		//memcpy(srTransRec.SmacBalance, srTransRec.szTotalAmount, 12);
		
		// get value of smac amount
		memcpy(srTransRec.szTotalAmount, srTransRec.szSMACAmount, 12);
}		
}

int inCheckIfSMCardCDT(void)
{
	if(strCDT.HDTid == SMAC_HDT_INDEX || strCDT.HDTid == SMGUARANTOR_HDT_INDEX || strCDT.HDTid == SMPARTNER_HDT_INDEX ||
		strCDT.HDTid == SMGIFTCARD_HDT_INDEX || strCDT.HDTid == SMSHOPCARD_HDT_INDEX || strCDT.HDTid == SMECARD_HDT_INDEX 
		|| strCDT.HDTid == SM_CREDIT_CARD || strCDT.HDTid == SMSHOPCRD)
		return TRUE;

	return FALSE;
}

int inCheckIfSMCardTransPara(TRANS_DATA_TABLE *srTransPara)
{
	if(srTransPara->HDTid == SMAC_HDT_INDEX || srTransPara->HDTid == SMGUARANTOR_HDT_INDEX || srTransPara->HDTid == SMPARTNER_HDT_INDEX ||
		srTransPara->HDTid == SMGIFTCARD_HDT_INDEX || srTransPara->HDTid == SMSHOPCARD_HDT_INDEX || srTransPara->HDTid == SMECARD_HDT_INDEX 
		|| srTransPara->HDTid == SM_CREDIT_CARD || srTransPara->HDTid == SMSHOPCRD)
		return TRUE;

	return FALSE;
}

int inCheckIfSMCardTransRec(void)
{
	if(srTransRec.HDTid == SMAC_HDT_INDEX || srTransRec.HDTid == SMGUARANTOR_HDT_INDEX || srTransRec.HDTid == SMPARTNER_HDT_INDEX ||
		srTransRec.HDTid == SMGIFTCARD_HDT_INDEX || srTransRec.HDTid == SMSHOPCARD_HDT_INDEX || srTransRec.HDTid == SMECARD_HDT_INDEX 
		|| srTransRec.HDTid == SM_CREDIT_CARD || srTransRec.HDTid == SMSHOPCRD)
		return TRUE;

	return FALSE;
}



int inCheckIfSMCardInq(void)//SM E-Card not included in Balance Inquiry
{
	if(strCDT.HDTid == SMAC_HDT_INDEX || strCDT.HDTid == SMPARTNER_HDT_INDEX || srTransRec.HDTid == SMGUARANTOR_HDT_INDEX ||
		strCDT.HDTid == SMGIFTCARD_HDT_INDEX || strCDT.HDTid == SMSHOPCARD_HDT_INDEX  || strCDT.HDTid == SM_CREDIT_CARD)
		return TRUE;

	return FALSE;
}

int CheckIfSmacEnableonIdleSale(void)
{
	
  	CTOS_LCDTClearDisplay();

	if (strTCT.SMACENABLE == 1)
		return d_OK;
	else{
		
		//vdDisplayErrorMsg(1, 8, "PLS. LOGON FIRST");
		vduiDisplayStringCenter(7,"PERFORMING AUTO");
		vduiDisplayStringCenter(8,"SMAC LOGON");
		CTOS_Beep();
		WaitKey(1);
		//vduiWarningSound();
		//CTOS_Delay(2000);
		//CTOS_Delay(500);
		return d_NO;
}
}

int inSMACBDORewardsAnalyzeField63(void)
{
	//char szMsgBuff[MESSAGE_SIZE+1];
	char *pszMsgBuff;
	char *pszNewBal;
	int inPeriod=0, inNewAmt=0, inComma=0;;
	char szNewBalance[100+1];
	char szMsgBuff[29+1];
	int Len;
	char TempBuf[32+1];
	char szCardExpiry[16+1]; //SMAC Footer Modification

	//fSMCHGiftCard = VS_FALSE;   // Privelege or Guarantor Card
	vdDebug_LogPrintf("SMAC szField63 = [%s]", szField63);
	memset(szNewBalance, 0x00, sizeof(szNewBalance));
	memset(szMsgBuff, 0x00, sizeof(szMsgBuff));
	//added extra braces for porting

	if(	(pszNewBal = strstr((char *)&szField63[2], "NEW BAL") !=NULL) || (pszNewBal = (strstr((char *)&szField63[2], "New Bal"))) !=NULL ||
		(pszNewBal = strstr((char *)&szField63[2], "NEWBAL") !=NULL) || (pszNewBal = (strstr((char *)&szField63[2], "NewBal"))) !=NULL)
		srTransRec.fPrintSMCardHolder = TRUE;
	
	pszMsgBuff=strchr((char *)&szField63[2], '=');


	if (pszMsgBuff)
	{
		int inPos=0;
		// get name from field 63
		//srRcpt.unFrm.srDet.srMid.szAmt
		while (1)
		{
			if(szField63[inPos] == '=')
			{
				memcpy(srTransRec.szCardholderName,(char *)&szField63[2],inPos-9);
				srTransRec.szCardholderName[inPos-9] = 0x00;


				break;
			}
			inPos++;
		}


		//SMAC Footer Modification - get the card expiry added in Field 63
		
		strcpy(TempBuf, pszMsgBuff+1);
		vdTrimSpaces(TempBuf);

		Len=strlen(TempBuf);
		
		if(Len>0)
		{
			if(szField63[inPos+1] == ',')		/*If 
"NEW BAL=" is followed by ',', amount is NULL or Empty.*/
				srTransRec.fPrintCardHolderBal = FALSE;
			else
				srTransRec.fPrintCardHolderBal = TRUE;
		}
		//get the remaining balance from the remaining data
		vdDebug_LogPrintf("TempBuf[%s] :: inPos+1[%c]:: Len[%d] :: fPrintCardHolderBal[%d]",TempBuf,szField63[inPos+1],Len,srTransRec.fPrintCardHolderBal);
		
		inPos=Len;

		memset(szCardExpiry,'\0',sizeof(szCardExpiry));
		while(1)
		{
			if(TempBuf[inPos]==',')
			{
				if(srTransRec.fPrintCardHolderBal == TRUE)
				{
					memcpy(szMsgBuff,TempBuf,12); 					//get the remaining balance
					vdDebug_LogPrintf("szMsgBuff [%s]",szMsgBuff);
					szMsgBuff[12] == 0x00;
					
				}
					
					
				//strcpy(szCardExpiry,&TempBuf[(strlen(szMsgBuff)+1)]);
				strcpy(szCardExpiry,&TempBuf[inPos+1]);
				vdDebug_LogPrintf("szCardExpiry[%s]",szCardExpiry);
				break;
			}

			//if(inPos>=Len+1)
			if(inPos == 0)
			{			
				strcpy(szMsgBuff,TempBuf);
				break;
			}
			inPos--;
		}
	}
	//added extra braces for porting
	else if (((pszMsgBuff = (strstr((char *)&szField63[2], "NEW BAL"))) !=NULL) || 
		    ((pszMsgBuff = (strstr((char *)&szField63[2], "New Bal"))) !=NULL))
	{

		strcpy(szMsgBuff, pszMsgBuff+7 );
		vdTrimLeadSpaces(szMsgBuff);
		//fSMCHGiftCard = VS_TRUE;   // Gift Card
		//szNewBalance[19] = VS_TRUE;
	}
	else if (((pszMsgBuff = (strstr((char *)&szField63[2], "NEWBAL"))) !=NULL) || 
		    ((pszMsgBuff = (strstr((char *)&szField63[2], "NewBal"))) !=NULL))
	{

		strcpy(szMsgBuff, pszMsgBuff+6 );
		vdTrimLeadSpaces(szMsgBuff);
		//fSMCHGiftCard = VS_TRUE;   // Gift Card
		//szNewBalance[19] = VS_TRUE;
	}
#if 0
	// remove the period for amount format
	while (inPeriod < strlen(szMsgBuff))
	{
		if (szMsgBuff[inPeriod] == '.' || szMsgBuff[inPeriod] == ',')
			inPeriod++;
		szNewBalance[inNewAmt] = szMsgBuff[inPeriod];
		inPeriod++;
		inNewAmt++;
	}
#endif
	/*BDO: Save SMAC Balance -- sidumili*/
	//vdTrimLeadSpaces(szMsgBuff);
	
	if(inCheckifAllSpaces(szMsgBuff) == FALSE)/*Only remove trailing spaces if remaining balance contains value other than SPACES*/
	{
		vdTrimLeadSpaces(szMsgBuff);
		vdTrimSpaces(szMsgBuff);
	}
	//vdCTOS_Pad_String(szNewBalance, 12, IS_ZERO, POSITION_LEFT);
	/*BDO: Save SMAC Balance -- sidumili*/
	
    vdDebug_LogPrintf("SMAC szNewBalance = [%s]", szMsgBuff);

	memset(srTransRec.szSMACBDORewardsBalance, 0x00, sizeof(srTransRec.szSMACBDORewardsBalance));
	//wub_str_2_hex(szMsgBuff,srTransRec.SmacBalance,12);
	memcpy(srTransRec.szSMACBDORewardsBalance,szMsgBuff,12);
		
#if 0
	if(strlen(srRcpt.szErrorMessage))
	{

		szNewBalance[18] = '1';   // if '1' there is card name from of field63 host reponse 
		strcpy(&szNewBalance[21],srRcpt.szErrorMessage);   // copy card name 
	}	
	szNewBalance[19] = fSMCHGiftCard;
#endif


	  
	return d_OK;
}



#endif


int inCTOS_SMACKitSale(void)
{
    int inRet = d_NO;

	fSMACTRAN = TRUE;
    
    CTOS_LCDTClearDisplay();
    
    vdCTOS_TxnsBeginInit();

    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiStopResumeAP("SHARLS_ECRBDO");
    
    inRet = inCTOS_SMACKitSaleFlowProcess();
    
    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiResumeContinueAP("SHARLS_ECRBDO");


//FOR TEST
	/* Send response to ECR -- sidumili */
	if (!fECRBuildSendOK){	
		inMultiAP_ECRSendSuccessResponse();
	}	
	fECRBuildSendOK = FALSE;
	/* Send response to ECR -- sidumili */

//FOR TEST

    inCTOS_inDisconnect();

    vdCTOS_TransEndReset();

    return inRet;
}

int inCTOS_SMACKitSaleFlowProcess(void)
{
    int inRet = d_NO;

    USHORT ushEMVtagLen;
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];

	fECRBuildSendOK = FALSE; /* BDO: For ECR -- sidumili */
	fTimeOutFlag = FALSE; /*BDO: Flag for timeout --sidumili*/

    vdCTOS_SetTransType(KIT_SALE);
    
    //display title
    //vdDispTransTitle(KIT_SALE);
    
    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;
	
	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;
	#if 0
	inRet = inCTOS_GetTxnBaseAmount();
	if(d_OK != inRet)
		return inRet;
	#endif	
    inRet = inCTOS_PreConnectAndInit();
    if(d_OK != inRet)
    {
    	vdSetECRResponse(ECR_COMMS_ERR);
        return inRet;
    }
	
    //inRet = inCTOS_GetCardFields();
    inRet = inCTOS_WaveGetCardFields();
	   {
	   		vdDebug_LogPrintf("inRet [%d]", inRet);  //remove this. debug
			if(d_OK != inRet)
	        		return inRet;
    	}

	inRet = CheckIfSmacEnableonIdleSale();
	if(inRet != d_OK)
	{
		inRet = inCTOS_SMACLogonFlowProcess(NO_SELECT);
		if(d_OK != inRet)
		{
			vdSetECRResponse(ECR_OPER_CANCEL_RESP);
			return inRet;
		}
		vdCTOS_SetTransType(KIT_SALE); // Set TransType back to Sale
		fAutoSMACLogon = TRUE;
	}
	
	inRet=inCTOS_DisplayCardTitle(6, 7); //Display Issuer logo: re-aligned Issuer label and PAN lines -- jzg
	if(d_OK != inRet)
		return inRet;
		
	inRet = inConfirmPAN();
		if(d_OK != inRet)
			return inRet; 										

	inRet = CheckIfSmacCard();	
	if(d_OK != inRet)
		return inRet;		

	inRet=CheckIfSmacEnable();
	if(d_OK != inRet)
		return inRet;		

    inRet = inCTOS_SelectHostEx2();
	inDatabase_TerminalCloseDatabase();
    if(d_OK != inRet)
        return inRet;

    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_SMAC_KIT_SALE);
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

	inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);

    inRet = inCTOS_CheckMustSettle();
    if(d_OK != inRet)
        return inRet;
	vdDebug_LogPrintf("REINER :: BEFORE inCTOS_PreConnect");
    inRet = inCTOS_PreConnect();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_CheckIssuerEnable();
    if(d_OK != inRet)
        return inRet;

    //inRet = inCTOS_CheckTranAllowd();
    //if(d_OK != inRet)
    //   return inRet;


	/*sidumili: [CHECK TRANS FOR DEBIT BALANCE INQUIRY]*/
	inRet = inCTOS_CheckCardTypeAllowd();
	if(d_OK != inRet)
			return inRet;


    inRet = inCTOS_GetInvoice();
    if(d_OK != inRet)
        return inRet;

    inRet = inBuildAndSendIsoData();
    if(d_OK != inRet){			

		if (strlen(srTransRec.szRespCode) <= 0)
		{
			strcpy(srTransRec.szECRRespCode, ECR_COMMS_ERR);
		}
		
        return inRet;
    }

	 inRet = inCTOS_SaveBatchTxn();
     if(d_OK != inRet)
         return inRet;

 	inRet = inCTOS_UpdateAccumTotal();
	if(d_OK != inRet)
		return inRet;

	inRet = inMultiAP_ECRSendSuccessResponse();
	if(d_OK != inRet)
		return inRet;

	inRet = inWriteMifareCardFields();
	if(d_OK != inRet)
		vdDisplayErrorMsgResp2("","CARD NOT","UPDATED");
	
	inRet = ushCTOS_printReceipt();
	 if(d_OK != inRet)
		 return inRet;

   vdSetErrorMessage("");  

    return d_OK;
}

int inCTOS_SMACRenewal(void)
{
    int inRet = d_NO;

	fSMACTRAN = TRUE;
    
    CTOS_LCDTClearDisplay();
    
    vdCTOS_TxnsBeginInit();

    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiStopResumeAP("SHARLS_ECRBDO");
    
    inRet = inCTOS_SMACRenewalFlowProcess();
    
    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiResumeContinueAP("SHARLS_ECRBDO");


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

int inCTOS_SMACRenewalFlowProcess(void)
{
    int inRet = d_NO;

    USHORT ushEMVtagLen;
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];

	fECRBuildSendOK = FALSE; /* BDO: For ECR -- sidumili */
	fTimeOutFlag = FALSE; /*BDO: Flag for timeout --sidumili*/


    vdCTOS_SetTransType(RENEWAL);
    
    //display title
    //vdDispTransTitle(RENEWAL);
    
    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;
	
	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;
	#if 0
	inRet = inCTOS_GetTxnBaseAmount();
	if(d_OK != inRet)
		return inRet;
	#endif	
    inRet = inCTOS_PreConnectAndInit();
    if(d_OK != inRet)
        return inRet;
	
    //inRet = inCTOS_GetCardFields();
    inRet = inCTOS_WaveGetCardFields();
    if(d_OK != inRet)
        return inRet;

	inRet = CheckIfSmacEnableonIdleSale();
	if(inRet != d_OK)
	{
		inRet = inCTOS_SMACLogonFlowProcess(NO_SELECT);
		if(d_OK != inRet)
		{
			vdSetECRResponse(ECR_OPER_CANCEL_RESP);
			return inRet;
		}
		vdCTOS_SetTransType(RENEWAL); // Set TransType back to Sale
		fAutoSMACLogon = TRUE;
	}
	
	inRet=inCTOS_DisplayCardTitle(6, 7); //Display Issuer logo: re-aligned Issuer label and PAN lines -- jzg
	if(d_OK != inRet)
		return inRet;
		
	inRet = inConfirmPAN();
		if(d_OK != inRet)
			return inRet; 										

	inRet = CheckIfSmacCard();	
	if(d_OK != inRet)
		return inRet;		

	inRet=CheckIfSmacEnable();
	if(d_OK != inRet)
		return inRet;		

    inRet = inCTOS_SelectHostEx2();
	inDatabase_TerminalCloseDatabase();
    if(d_OK != inRet)
        return inRet;

    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_SMAC_RENEWAL);
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

	inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);

    inRet = inCTOS_CheckMustSettle();
    if(d_OK != inRet)
        return inRet;
	vdDebug_LogPrintf("REINER :: BEFORE inCTOS_PreConnect");
    inRet = inCTOS_PreConnect();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_CheckIssuerEnable();
    if(d_OK != inRet)
        return inRet;

    //inRet = inCTOS_CheckTranAllowd();
    //if(d_OK != inRet)
    //   return inRet;


	inRet = inCTOS_CheckCardTypeAllowd();
	if(d_OK != inRet)
			return inRet;


    inRet = inCTOS_GetInvoice();
    if(d_OK != inRet)
        return inRet;

    inRet = inBuildAndSendIsoData();
    if(d_OK != inRet){
	if (strlen(srTransRec.szRespCode) <= 0)
		{
			strcpy(srTransRec.szECRRespCode, ECR_COMMS_ERR);
		}
		
        return inRet;
    }

	 inRet = inCTOS_SaveBatchTxn();
     if(d_OK != inRet)
         return inRet;

 	inRet = inCTOS_UpdateAccumTotal();
	if(d_OK != inRet)
		return inRet;

	inRet = inMultiAP_ECRSendSuccessResponse();
	if(d_OK != inRet)
		return inRet;

	inRet = inWriteMifareCardFields();
	if(d_OK != inRet)
		vdDisplayErrorMsgResp2("","CARD NOT","UPDATED");
			
	inRet = ushCTOS_printReceipt();
	 if(d_OK != inRet)
		 return inRet;

   vdSetErrorMessage("");  

    return d_OK;
}

int inCTOS_SMACPtsAwarding(void)
{
    int inRet = d_NO;

	fSMACTRAN = TRUE;
    
    CTOS_LCDTClearDisplay();
    
    vdCTOS_TxnsBeginInit();

	vdDebug_LogPrintf("inCTOS_SMACPtsAwarding");

    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiStopResumeAP("SHARLS_ECRBDO");
    
    inRet = inCTOS_SMACPtsAwardingFlowProcess();
    
    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiResumeContinueAP("SHARLS_ECRBDO");

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


int inCTOS_SMACPtsAwardingFlowProcess(void)
{
    int inRet = d_NO;

    USHORT ushEMVtagLen;
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];
	char szAmtBuff[AMT_ASC_SIZE+1];

	fECRBuildSendOK = FALSE; /* BDO: For ECR -- sidumili */
	fTimeOutFlag = FALSE; /*BDO: Flag for timeout --sidumili*/

    vdCTOS_SetTransType(PTS_AWARDING);
    
    //display title
    //vdDispTransTitle(PTS_AWARDING);
    
    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;
	
	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;


	wub_hex_2_str(srTransRec.szBaseAmount,szAmtBuff,AMT_BCD_SIZE);
	vdDebug_LogPrintf("inCTOS_WaveFlowProcess DIGITAL WALLET AMOUT IS %s",szAmtBuff);

	inRet = inCTOS_GetTxnBaseAmount();
	if(d_OK != inRet)
		return inRet;
		
    inRet = inCTOS_PreConnectAndInit();
    if(d_OK != inRet)
        return inRet;
	
    //inRet = inCTOS_GetCardFields();
    DebugAddHEX("1. BASE AMOUNT",srTransRec.szBaseAmount,AMT_BCD_SIZE);
	
    inRet = inCTOS_WaveGetCardFields();
	if(d_OK != inRet)
		return inRet;

	if(srTransRec.fOffline_PtsAwarding == TRUE)
	{
		inRet = inCTOS_SMACOfflinePtsAwardingFlowProcess();
		return inRet;
	}
	
	DebugAddHEX("2. BASE AMOUNT",srTransRec.szBaseAmount,AMT_BCD_SIZE);
	
	inRet = CheckIfSmacEnableonIdleSale();
	if(inRet != d_OK)
	{
		inRet = inCTOS_SMACLogonFlowProcess(NO_SELECT);
		if(d_OK != inRet)
		{
			vdSetECRResponse(ECR_OPER_CANCEL_RESP);
			return inRet;
		}
		vdCTOS_SetTransType(PTS_AWARDING); // Set TransType back to Sale
		fAutoSMACLogon = TRUE;
	}
	
	inRet=inCTOS_DisplayCardTitle(6, 7); //Display Issuer logo: re-aligned Issuer label and PAN lines -- jzg
	if(d_OK != inRet)
		return inRet;
		
	inRet = inConfirmPAN();
		if(d_OK != inRet)
			return inRet; 										

	inRet = CheckIfSmacCard();	
	if(d_OK != inRet)
		return inRet;		

	inRet=CheckIfSmacEnable();
	if(d_OK != inRet)
		return inRet;		

    inRet = inCTOS_SelectHostEx2();
	inDatabase_TerminalCloseDatabase();
    if(d_OK != inRet)
        return inRet;

    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_SMAC_RENEWAL);
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

	inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);

    inRet = inCTOS_CheckMustSettle();
    if(d_OK != inRet)
        return inRet;
	vdDebug_LogPrintf("REINER :: BEFORE inCTOS_PreConnect");
    inRet = inCTOS_PreConnect();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_CheckIssuerEnable();
    if(d_OK != inRet)
        return inRet;

    //inRet = inCTOS_CheckTranAllowd();
    //if(d_OK != inRet)
    //   return inRet;


	inRet = inCTOS_CheckCardTypeAllowd();
	if(d_OK != inRet)
			return inRet;


    inRet = inCTOS_GetInvoice();
    if(d_OK != inRet)
        return inRet;

    inRet = inBuildAndSendIsoData();
    if(d_OK != inRet){			
	if (strlen(srTransRec.szRespCode) <= 0)
		{
			strcpy(srTransRec.szECRRespCode, ECR_COMMS_ERR);
		}
        return inRet;
    }

	 inRet = inCTOS_SaveBatchTxn();
     if(d_OK != inRet)
         return inRet;

 	inRet = inCTOS_UpdateAccumTotal();
	if(d_OK != inRet)
		return inRet;

	inRet = inMultiAP_ECRSendSuccessResponse();
	if(d_OK != inRet)
		return inRet;

	inRet = inWriteMifareCardFields();
	if(d_OK != inRet)
	{	
		vdDisplayErrorMsgResp2("","CARD NOT","UPDATED");
	}	

	inRet = ushCTOS_printReceipt();
	 if(d_OK != inRet)
		 return inRet;

   vdSetErrorMessage("");  

    return d_OK;
}


int inCTOS_SMACOfflinePtsAwardingFlowProcess(void)
{
	int inRet = -1;

		
	vdDebug_LogPrintf("<=== inCTOS_SMACOfflinePtsAwardingFlowProcess ===>");

	inRet=CheckIfSmacEnable();
	if(d_OK != inRet)
		return inRet;		
	
    inRet = inCTOS_SelectHostEx2();
	inDatabase_TerminalCloseDatabase();

	inRet = inCTOS_CheckIssuerEnable();
    if(d_OK != inRet)
        return inRet;

	vdDispTransTitle(PTS_AWARDING);
	setLCDPrint27(4, DISPLAY_POSITION_CENTER, "SENDING");
	setLCDPrint27(5, DISPLAY_POSITION_CENTER, "CARD NUMBER");
	
    inRet = inCTOS_GetInvoice();
    if(d_OK != inRet)
        return inRet;
	
	vdSaveLastInvoiceNo();
	
	memcpy(srTransRec.szRespCode,"00",2);
	inRet = inMultiAP_ECRSendSuccessResponse();

    CTOS_Beep();
    CTOS_Delay(300);

	return inRet;
	
}

void vdSetMonthToText(char *szInput, char *szMonth)
{
	//char szTemp[d_LINE_SIZE + 1];
	//char sMonth[4];
	char szTempMonth[3];
	char szMonthNames[40];

	memset(szMonth,0x00,4);
	memset(szMonthNames,0x00,40);
	strcpy(szMonthNames,"JANFEBMARAPRMAYJUNJULAUGSEPOCTNOVDEC");
	memset(szTempMonth, 0x00, 3);

	memcpy(szTempMonth,&szInput[0],2);
	memcpy(szMonth, &szMonthNames[(atoi(szTempMonth) - 1)* 3], 3);
	
    return;
     
}



int inCTOS_SMACLogonFlowProcessEx(void)
{
    int inRet = d_NO;

    USHORT ushEMVtagLen;
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];


    vdCTOS_SetTransType(SMAC_ACTIVATION);
    
    //display title
    //vdDispTransTitle(SMAC_ACTIVATION);
    
    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;

	#if 0
	if (strTCT.SMACENABLE == TRUE){
		vdDisplayMessage("ALREADY LOGGED ON", "", "");
		CTOS_Delay(3000);

		return d_NO;
		
	}
	#endif
	
	//inRet = inCTOS_SelectLogonIIT();
	//if(d_OK != inRet)
    //    return inRet;

	//	inRet = inCTOS_SeletLogonPIT();
	//		if(d_OK != inRet)
    //    return inRet;

		
    inRet = inCTOS_PreConnectAndInit();
    if(d_OK != inRet)
        return inRet;
	
    inRet = inCTOS_SelectSMACHost();
    if(d_OK != inRet)
        return inRet;


	
    //if (strTCT.fSingleComms)	
	//	inCTOS_PreConnectEx();

	//inGetIssuerRecord(15); /*BDO: Ver9.0 = 23, Ver10.0 = 27 -- sidumili*/ /*moved inside inCTOS_SelectSMACHost*/

	/*BDO: Check if SMAC already logged on -- sidumili*/
	//inRet = CheckIfSmacAlreadyLogOn();
	//if(d_OK != inRet)
    //return inRet;
		
    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_SMAC_LOGON);
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
	//inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid); moved inside inCTOS_SelectSMACHost

	//if(fBINVer != TRUE)
		//inFirstInitConnectFuncPoint();
		
	//if (strTCT.fSingleComms != TRUE){
		inRet = inCTOS_PreConnect();
		if(d_OK != inRet)
			return inRet;
	//}
		
    inRet = inCTOS_CheckIssuerEnable();
    if(d_OK != inRet)
        return inRet;

/*    inRet = inCTOS_CheckTranAllowd();
    if(d_OK != inRet)
        return inRet;
*/
    inRet = inBuildAndSendIsoData();
    if(d_OK != inRet){
		//inMyFile_ReversalDelete();		
        return inRet;
    }

	inRet = inCheckLogonResponse();
    if(d_OK != inRet)
        return inRet;

    return d_OK;
}


//versio16-trim extra spaces - for giftcard error response
void vdRemoveExtraSpaces(char* pchString) {
    int inIndex;
	int inLen;


	inLen = strlen(pchString);
	inIndex = inLen - 1;
	DebugAddHEX("pchString =",pchString,strlen(pchString));

	vdDebug_LogPrintf("intial value inIndex %d", inIndex);


    while (pchString[inIndex] == 0x20){
		vdDebug_LogPrintf("pchString[inIndex] %x", pchString[inIndex]);

		vdDebug_LogPrintf("inIndex %d", inIndex);
		pchString[inIndex] = 0x00;

		inIndex--;

    }

	DebugAddHEX("pchString =",pchString,strlen(pchString));

  
 }
