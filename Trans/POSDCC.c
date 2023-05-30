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
#include "..\Includes\POSLogon.h"
#include "..\Includes\POSbatch.h"
#include "..\ui\Display.h"
#include "..\Includes\V5IsoFunc.h"
#include "..\Accum\Accum.h"
#include "..\print\Print.h"
#include "..\Comm\V5Comm.h"
//#include "..\Includes\MultiApLib.h"
#include "..\Aptrans\MultiAptrans.h"
#include "../Database/dct.h"
#include "..\Includes\LocalAptrans.h"
#include "..\Includes\LocalFunc.h"
#include "../POWRFAIL/POSPOWRFAIL.h"
#include "..\Includes\POSDCC.h"

//BOOL fOptOutFlag = 0;
extern BOOL fECRBuildSendOK; 
extern BOOL fTimeOutFlag; /*BDO: Flag for timeout --sidumili*/
extern VS_BOOL fPreConnectEx;
char szFuncTitleName [21 + 1]; //aaronnino for BDOCLG ver 9.0 fix on issue #0093 Have a function title for function keys shorcut 1 of  6
BOOL fBDOOptOutHostEnabled = FALSE;

int inCTOS_ProcessDCCRate(void)
{
    int inRet = d_NO, inRet2 = d_NO;
    int result;
    char szTemp[15+1];
	int inHostIndex=0, inLen=0;
	char szStr[16+1]={0};

	VS_BOOL fOptOut = FALSE;

	BYTE chKey;

	memcpy(srTransRec.szDCCLocalCur, strCST.szCurCode,3);
    memcpy(srTransRec.szDCCLocalSymbol, strCST.szCurSymbol,3);

#ifdef DCC_SIGNPAD
	srTransRec.fDCCInitiatedTxn = TRUE;
#endif

    inRet=inCTOS_LocalAPSaveData();
    if(d_OK != inRet)
        return inRet;
    
    strCDT.HDTid=6; //Dcc default host
    
    inRet = inCTOS_SelectHost();
    if(d_OK != inRet)
        return inRet;
    
    srTransRec.byPackType=DCC_RATEREQUEST;
    
    if(strTCT.fSingleComms != TRUE)
    {
        inRet = inCTOS_PreConnect();
        if(d_OK != inRet)
            return inRet;
    }

    /*commented - improve performance*/
	#if 0
	if(inCPTRead(1) != d_OK)
	{
		vdSetErrorMessage("LOAD CPT ERR");
		return(d_NO);
	} 
    #endif
	
    inRet = inProcessRequestDCC();
	vdDebug_LogPrintf("inProcessRequestDCC: (%d)", inRet);
    if(d_OK != inRet)
    {
		if(inRet == ST_CONNECT_FAILED)
		{
			vdSetECRResponse(ECR_COMMS_ERR);//Set the response to ECR to COMM ERROR 
            return inRet;
		}

		if(inRet == ST_COMMS_DISCONNECT)
		{
			vdSetECRResponse(ECR_COMMS_ERR);//Set the response to ECR to COMM ERROR 
			vdDisplayErrorMsgResp2(" Connection ","Terminated","Please Try Again");
			return inRet;
		}
		inRet2 = inCTOS_LocalAPGetData();
		if(d_OK != inRet2)
			return inRet2;
		
		inRet2 = inCTOS_LocalAPReloadTable();
		if(d_OK != inRet2)
			return inRet2;

		srTransRec.usTerminalCommunicationMode=strCPT.inCommunicationMode;
			
        if(inRet == ST_SEND_DATA_ERR || (inRet == ST_RECEIVE_TIMEOUT_ERR && strCPT.inCommunicationMode != DIAL_UP_MODE))
        {
			inCTOS_inDisconnect();
			vdCTOS_DispStatusMessage("PROCESSING...");
            //inRet = inCTOS_PreConnect();
            if(strCPT.inCommunicationMode == GPRS_MODE)
            	put_env_int("CONNECTED",0);
			
            inRet = inCTOS_PreConnectAndInit();
            if(d_OK != inRet)
                return inRet;
        }
        else if(inRet == TRANS_REJECT_APPROVED)
			inRet = d_OK;

		return inRet;
    }

	//strFLG.fNewDCCMode = inFLGGet("fNewDCCMode");
	
	if( (srTransRec.byTransType == SALE || srTransRec.byTransType == SALE_OFFLINE) 
		&&  (strTCT.inDCCMode == AUTO_OPTOUT_MODE || strTCT.inDCCMode == MANUAL_OPTOUT_MODE))
	{
		srTransRec.fDCC = VS_TRUE;			
		memset(srTransRec.szDCCLocalAmount,0x00,sizeof(srTransRec.szDCCLocalAmount));
		memcpy(srTransRec.szDCCLocalAmount, srTransRec.szTotalAmount,sizeof(srTransRec.szTotalAmount));
	}
	else
	{
		vdDebug_LogPrintf("strTCT.inDCCMode[%d]",strTCT.inDCCMode);
		if(strTCT.inDCCMode == PRINT_DCC_RATES)
		{
			vdCTOSS_PrinterStart(100);
		    CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);
		    if( printCheckPaper()==-1)
		    	return ;

			ushCTOS_PrintHeader(MERCHANT_COPY_RECEIPT);
  			ushCTOS_PrintDCCRateBody(MERCHANT_COPY_RECEIPT);
			ushCTOS_PrintDCCRateFooterEx(MERCHANT_COPY_RECEIPT);
			
			vdCTOSS_PrinterEnd();
			
		}

//versio16 - add:merchant to show and ask the customer to select the preferred currency for the transaction
		if(strTCT.inDCCMode == NORMAL_MODE){
			CTOS_LCDTClearDisplay();
        	while(1)
        	{ 
        		if (strTCT.fPrintWarningSound == TRUE) 
                    vduiWarningSound();

				setLCDPrint(2, DISPLAY_POSITION_CENTER, "Ask customer to");
				setLCDPrint(3, DISPLAY_POSITION_CENTER, "select currency");

				setLCDPrint(7, DISPLAY_POSITION_CENTER, "Press any key");
				setLCDPrint(8, DISPLAY_POSITION_CENTER, "to proceed");

				//CTOS_KBDHit(&chKey);
				//CTOS_KBDInKey(&chKey);
				chKey=WaitKey(inGetIdleTimeOut(TRUE));

        		if (chKey)
				{ 
					CTOS_Beep();
					CTOS_Delay(300);
            		CTOS_KBDBufFlush();
                	break;
            	}
        	}

		 	//if (chKey == d_KBD_CANCEL)
			//	return(d_NO); 

		}
		
//end

		if(inFLGGet("fSignPad") == TRUE)
		{
			inRet = inSignPadSendReceive(d_COM2, DCC_RATE);
			if(inRet == SIGNPAD_NOT_DETECTED)
			{
				inRet = inDisplayDCCRateScreen();
			    if(d_OK != inRet)
			    {
					vdSetECRResponse(ECR_OPER_CANCEL_RESP);
			        return inRet;
			    }
			}
			else if(inRet == d_KBD_CANCEL || inRet == d_NO)
				return inRet;
		}
		else
		{
		    inRet = inDisplayDCCRateScreen();
		    if(d_OK != inRet)
		    {
				vdSetECRResponse(ECR_OPER_CANCEL_RESP);
		        return inRet;
		    }
		}
	}

#if 1
	if(strCPT.inCommunicationMode == ETHERNET_MODE)
	{
		inRet = inCheckEthernetConnected();
		vdDebug_LogPrintf("*** inCheckEthernetConnected END ***");
		//else if(strCPT.inCommunicationMode == DIAL_UP_MODE)
			//inRet = inModem_InitModem(&srTransRec,1);
			
		if(SUCCESS != inRet)
		{
			vdDisplayErrorMsgResp2(" Connection ","Terminated","Please Try Again");
			vdSetECRResponse(ECR_COMMS_ERR);
			return inRet;
		}
	}
#endif
    //vdCTOS_SetTransType(SALE);						   
    //vdDispTransTitle(SALE);
    
    //dcc selection
    if(srTransRec.fDCC == CN_TRUE)
    {
        memset(szTemp,0x00,sizeof(szTemp));
        wub_str_2_hex(srTransRec.szDCCCurAmt, szTemp, 12);
        
        memset(srTransRec.szBaseAmount, 0x00, sizeof(srTransRec.szBaseAmount));
        memcpy(srTransRec.szBaseAmount, szTemp, sizeof(szTemp));
        
        memset(srTransRec.szTotalAmount, 0x00, sizeof(srTransRec.szTotalAmount));
        memcpy(srTransRec.szTotalAmount, srTransRec.szBaseAmount, sizeof(srTransRec.szBaseAmount));

	    inDatabase_TerminalOpenDatabase();
        //vdDebug_LogPrintf("srTransRec.szDCCCur: (%s)", srTransRec.szDCCCur); 
        inCSTReadHostIDEx(srTransRec.szDCCCur);

        //vdDebug_LogPrintf("1. strCST.HDTid: (%d)", strCST.HDTid);
        //vdDebug_LogPrintf("1. srTransRec.HDTid: (%d)", srTransRec.HDTid);
        
        inHostIndex = (short)strCST.HDTid;
        strCDT.HDTid=inHostIndex; 

		vdDebug_LogPrintf("1. inHostIndex: (%d)", inHostIndex);
		
        if(inHDTReadEx(inHostIndex) != d_OK)
        {
            //vdSetErrorMessage("HOST SELECTION ERR");
			inHDTReadDataEx(inHostIndex);
			strcpy(szStr,strHDT_Temp.szHostLabel);
			memset(strHDT_Temp.szHostLabel,0x00,16+1);
			sprintf(strHDT_Temp.szHostLabel," %s ",szStr);
			inDatabase_TerminalCloseDatabase();
			vdDisplayErrorMsgResp2(strHDT_Temp.szHostLabel, "TRANSACTION", "NOT ALLOWED");
            return(d_NO);
        } 
        else 
        {
			srTransRec.HDTid=inHostIndex;

			if(strTCT.fSingleComms == TRUE)
				inHostIndex = 1;
			
			if(inCPTReadEx(inHostIndex) != d_OK)
			{
				inDatabase_TerminalCloseDatabase();
				vdSetErrorMessage("LOAD CPT ERR");
				return(d_NO);
			}
        }

	    inMMTReadRecordEx(srTransRec.HDTid,srTransRec.MITid);
		
		memset(strMMT[0].szTID,0x00,sizeof(strMMT[0].szTID));
        memcpy(strMMT[0].szTID, srTransRec.szDCCFXTID, 8);
		inLen=strlen(srTransRec.szDCCFXMID);
		memset(szTemp, 0x30, sizeof(szTemp));
        memcpy(&szTemp[15-inLen], srTransRec.szDCCFXMID, inLen);
		memset(strMMT[0].szMID,0x00,sizeof(strMMT[0].szMID));
        memcpy(strMMT[0].szMID, szTemp, 15);
		
        inMMTSaveEx(strMMT[0].MMTid);
		inDatabase_TerminalCloseDatabase();
        //inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);
    }
    else
    {
		inCTOS_LocalAPGetData();
		if(d_OK != inRet)
	       return inRet;


 	   vdDebug_LogPrintf("TESTLANG OPTOUT %d", srTransRec.byTransType);
       if (srTransRec.byTransType == SALE_OFFLINE){
	   	
			fOptOut = inFLGGet("fCompOptOut");

			vdDebug_LogPrintf("testlang compopt out");


			if (fOptOut == 1){

                vdDebug_LogPrintf("testlang reload comp data");
				if(inHDTReadData(BDO_COMPLETION_OPTOUT_HDT_INDEX) != d_OK)
					 vdDebug_LogPrintf("COMPLETION OPTOUT HOST DISABLED");		
	    
				if(strHDT_Temp.fHostEnable == TRUE)
					fBDOOptOutHostEnabled = TRUE;

			}
				
       }else{

	   		fOptOut = inFLGGet("fStraightOptOut");
	   
	   		if (fOptOut == 1){

	   			if(inHDTReadData(BDO_OPTOUT_HDT_INDEX) != d_OK)
					vdDebug_LogPrintf("OPTOUT HOST DISABLED");
		
				if(strHDT_Temp.fHostEnable == TRUE)
					fBDOOptOutHostEnabled = TRUE;
       		}

       	}
	   
        inRet = inCTOS_LocalAPReloadTable();
        if(d_OK != inRet)
            return inRet;
    }

    CTOS_LCDTClearDisplay();    
    vdCTOS_DispStatusMessage("PROCESSING...       ");
   
    return inRet;
}

int inProcessRequestDCC(void)
{
    int inResult,i,iLine;
    char szErrorMessage[30+1];
    char szBcd[INVOICE_BCD_SIZE+1];
    TRANS_DATA_TABLE *srTransPara;
    TRANS_DATA_TABLE srTransParaTmp;
	int inRetry=2;
	
  	srTransRec.ulTraceNum = wub_bcd_2_long(strHDT.szDCCRateandLogTraceNo,3);
		
    
    if ((VOID != srTransRec.byTransType) && (SALE_TIP != srTransRec.byTransType))
        srTransRec.ulOrgTraceNum = srTransRec.ulTraceNum;

	memcpy(strHDT_Temp.szDCCRateandLogTraceNo, strHDT.szDCCRateandLogTraceNo , INVOICE_BCD_SIZE);
    inHDTDCCSave(6);

    srTransPara = &srTransRec;

	CTOS_LCDTClearDisplay();
	
	iLine = ((strTCT.byTerminalType%2)?3:4);
	vduiClearBelow(iLine);
	setLCDPrint(iLine, DISPLAY_POSITION_LEFT, "Connecting to");
	setLCDPrint(iLine+1, DISPLAY_POSITION_LEFT, "DCC FX RATE HOST...");

	vdCTOS_DispStatusMessage("PROCESSING...");

#if 0				
	if (2 == strTCT.byTerminalType)
		setLCDPrint(V3_ERROR_LINE_ROW, DISPLAY_POSITION_LEFT, "Processing...        ");
	else	
    	setLCDPrint(8, DISPLAY_POSITION_LEFT, "Processing...        ");  
#endif

	srTransPara->byOffline = CN_FALSE;
	if(srTransRec.usTerminalCommunicationMode == GPRS_MODE || srTransRec.usTerminalCommunicationMode == WIFI_MODE)	
	{
		inResult = inCTOS_PreConnect();//Fix for CRITICAL ERROR on GPRS
		if(d_OK != inResult)
			return inResult;
	}

    if (srCommFuncPoint.inConnect(&srTransRec) != ST_SUCCESS)
    {
        if(srTransPara->shTransResult == 0)
            srTransPara->shTransResult = TRANS_COMM_ERROR;
        inCTOS_inDisconnect();
        //vdSetErrorMessage("CONNECT FAILED");
        
		if(strCPT.fCommBackUpMode == CN_TRUE) //Comms fallback -- jzg
		{
		
			if(inCTOS_CommsFallback(strHDT.inHostIndex) != d_OK) //Comms fallback -- jzg
				return ST_CONNECT_FAILED;;
			
			if (srCommFuncPoint.inConnect(&srTransRec) != ST_SUCCESS){
				inCTOS_inDisconnect();
				return ST_CONNECT_FAILED;
			}else{
				fCommAlreadyOPen = VS_TRUE;
			}
			
		}else
        	return ST_CONNECT_FAILED;
    }	

    //vdIncSTAN(srTransPara);
    vdIncDCCSTAN(srTransPara);
			
    do
    {

        inResult = inBuildDCCOnlineMsg(srTransPara);

		if(srTransPara->shTransResult == TRANS_REJECTED)
			return ST_ERROR;

		if(srTransPara->shTransResult == TRANS_REJECT_APPROVED)
			return TRANS_REJECT_APPROVED;
		
		if(inResult != ST_RECEIVE_TIMEOUT_ERR)
			return inResult;
			
        if(inResult != ST_SUCCESS)
        {
			inRetry--;
			if(inRetry <= 0)
			{
                inTCTSave(1);
                if (ST_RESP_MATCH_ERR == inResult)
                {
                    vdDebug_LogPrintf("inBuildOnlineMsg %d",inResult);
                    return inResult;
                }
                return inResult;
			}
			else
                srTransPara->byPackType = DCC_RATEREQUEST_RETRY;
        }
        else
            break;			
    }while(inRetry != 0);

    vdDebug_LogPrintf("srTransPara->szRespCode (%s)", srTransPara->szRespCode);
	
	if (memcmp(srTransPara->szRespCode, "00", 2))
		return ST_ERROR;

    return ST_SUCCESS;
}

int inCheckDCCRespCode(TRANS_DATA_TABLE *srTransPara)
{
    int inResult=TRANS_COMM_ERROR;
    char szErrorMessage[30+1];
	
    vdDebug_LogPrintf("inCheckHostRespCode %s",srTransPara->szRespCode);
    if (!memcmp(srTransPara->szRespCode, "00", 2))
    {
        inResult = TRANS_AUTHORIZED;
        srTransPara->shTransResult = TRANS_AUTHORIZED;
        strcpy(srTransPara->szRespCode, "00");
        DebugAddSTR("txn approval",srTransPara->szAuthCode ,6);  
    }
    else
    {
	    if((srTransPara->szRespCode[0] >= '0' && srTransPara->szRespCode[0] <= '9') &&
	    (srTransPara->szRespCode[1] >= '0' && srTransPara->szRespCode[1] <= '9'))
	    {
			memset(szErrorMessage, 0x00, sizeof(szErrorMessage));
			sprintf(szErrorMessage,"RC:%02d", atoi(srTransPara->szRespCode));
			if(atoi(srTransPara->szRespCode) == 12 || atoi(srTransPara->szRespCode) == 16 || atoi(srTransPara->szRespCode) == 21
			|| atoi(srTransPara->szRespCode) == 31 || atoi(srTransPara->szRespCode) == 41 || atoi(srTransPara->szRespCode) > 90) 
			{
				vdDisplayErrorMsgResp3("PROCESSING TXN", "AS PHP", "PLEASE CALL BDO", szErrorMessage);
				inResult = TRANS_REJECT_APPROVED;
			}
			else
			{
				vdDisplayErrorMsgResp2(" ", "PLEASE CALL BDO", szErrorMessage);
				inResult = TRANS_REJECTED;
			}		
	        
	    }
	    else
	        inResult = ST_UNPACK_DATA_ERR;
    }
	
    return (inResult);
}


int inSendPendingDCCLogs(void)
{
	int inRet = d_NO;

	if(srTransRec.byTransType != SALE_OFFLINE)
	{
		inRet = inCTOS_EMVTCUpload();
	    if(d_OK != inRet)
	        return inRet;
	    else
			vdSetErrorMessage("");
	}

				
    inRet=inProcessTransLogTrans(&srTransRec, 1, 2, GET_ALL_EXCEPT_TIP);
    if(d_OK != inRet)
        return inRet;
    else
        vdSetErrorMessage("");

	return d_OK;

}

int inVoidDCCTransaction(void)
{
	int inRet = d_NO;

	srTransRec.fOptOut= VS_TRUE;
	srTransRec.byTransType = srTransRec.byPackType = VOID;
	fAdviceTras = VS_FALSE;

	inHDTRead(srTransRec.HDTid); 
	inRet = inBuildAndSendIsoData();
    if(d_OK != inRet){

		/*BDO: Set ECR response code to EN - COMM ERROR -- sidumili*/
		if ((strlen(srTransRec.szRespCode) <= 0) || (srTransRec.shTransResult == TRANS_TERMINATE)){
			strcpy(srTransRec.szRespCode,"");
			strcpy(srTransRec.szECRRespCode, ECR_COMMS_ERR);
		}

		if(strTCT.inDCCMode == AUTO_OPTOUT_MODE)
			vdCTOS_SetTransType(SALE);
		
		return inRet;
    }

	if(memcmp(srTransRec.szTempTime, srTransRec.szTime, TIME_BCD_SIZE) == 0) /*if time are the same it means there is no DE12 receive, get new date and time*/
        vdGetTimeDate(&srTransRec);

	srTransRec.fOptOutVoided = TRUE;
	
    inRet = inCTOS_SaveBatchTxn();
    if(d_OK != inRet)
        return inRet;

	strHDT.inHostIndex = srTransRec.HDTid;
    inRet = inCTOS_UpdateAccumTotal();
    if(d_OK != inRet)
        return inRet;


    inRet=inProcessTransLogTrans(&srTransRec, 1, 2, GET_ALL_EXCEPT_TIP);
    if(d_OK != inRet)
        return inRet;
    else
        vdSetErrorMessage("");
	

	return d_OK;
}

int inRevertToPHP(void)
{
	int inRet = d_NO;
    BYTE szTempAuthCode[AUTH_CODE_DIGITS+1];
	TRANS_DATA_TABLE srtmpTransRec;

	memset(&srtmpTransRec,0x00,sizeof(TRANS_DATA_TABLE));
	memcpy(&srtmpTransRec,&srTransRec,sizeof(TRANS_DATA_TABLE));

	inRet = inSendPendingDCCLogs();
	if(d_OK != inRet)
    {
		return VS_OPTOUT_FAILED;		
    }

	inRet = inCTOS_CheckMustSettleBDOHost();
	if(d_OK != inRet)
    {
		vdDisplayErrorMsgResp2("","MUST SETTLE","");
		vdSetECRResponse(ECR_OPER_CANCEL_RESP);
		return inRet;
    }

	if (strMMT_Temp[0].MMTid == 0 && strMMT_Temp[0].HDTid == 0 )
         {
              vdDisplayErrorMsgResp2(" ", "OPT OUT", "NOT ALLOWED");
              return d_NO;
         }

	if(srTransRec.usTerminalCommunicationMode == ETHERNET_MODE)
	{
		if(inCheckEthernetSocketConnected() == BROKEN_PIPE || inCheckEthernetConnected() == ST_COMMS_DISCONNECT)
		{
			vdDisplayErrorMsgResp2("PLEASE RETRY","OPT OUT","TRANSACTION");
			return ST_COMMS_DISCONNECT;	
		}
	}
	else if(strCPT.inCommunicationMode == DIAL_UP_MODE)
	{
		if(inCheckModemConnected() != d_OK)
		{
			vdDisplayErrorMsgResp2("PLEASE RETRY","OPT OUT","TRANSACTION");
			return ST_COMMS_DISCONNECT;
		}
	}
	
	inRet = inCTOS_CheckVOID();
    if(d_OK != inRet)
    {
		return inRet;		
    }

	if(srTransRec.byOrgTransType == SALE || srTransRec.byOrgTransType == SALE_OFFLINE)
	{
		DebugAddHEX("OptOutTransType INV",srTransRec.szInvoiceNo,INVOICE_BCD_SIZE);
		
		srTransRec.byOptOutOrigTransType = srTransRec.byOrgTransType;
		inRet = inDatabase_OptOutbyTransTypeBatchUpdate(srTransRec.byOptOutOrigTransType, srTransRec.szInvoiceNo);// SAVE TO BATCH INCASE SALE/OFFLINE FAILS
		
	}
	
	inRet = inVoidDCCTransaction();
	if(d_OK != inRet)
	{
		//vdDisplayErrorMsgResp2("CANNOT OPT OUT","CONTINUING","DCC TRANSACTION");
		vdDisplayErrorMsgResp2("PLEASE RETRY","OPT OUT","TRANSACTION");
		return inRet;
	}

	memcpy(srTransRec.szOptOutVoidInvoiceNo,srTransRec.szInvoiceNo,INVOICE_BCD_SIZE);
		
	if(srTransRec.byEntryMode == CARD_ENTRY_ICC)
	{
		vdResetAllCardData();
		vdCTOS_SetTransEntryMode(CARD_ENTRY_ICC);//Fix where byEntryMode is set to 0 by vdResetAllCardData().
		inRet = inCTOS_EMVCardReadProcess();
		if(d_OK != inRet)
			return inRet;
	}
	
	srTransRec.fDCC = VS_FALSE;
	fAdviceTras = VS_FALSE;

		
	memset(szTempAuthCode,0x00,AUTH_CODE_DIGITS+1);
	memcpy(szTempAuthCode,srTransRec.szAuthCode,strlen(srTransRec.szAuthCode));
	
	inRet = inCTOS_LocalAPGetData();
	if(d_OK != inRet)
		return inRet;


	inRet = inCTOS_LocalAPReloadTableEx();
	if(d_OK != inRet)
		return inRet;

	if(fBDOOptOutHostEnabled == TRUE){
		//inMMTReadRecord(BDO_OPTOUT_HDT_INDEX,srTransRec.MITid);	
		if (srTransRec.byTransType == SALE_OFFLINE)
		   inMMTReadRecord(BDO_COMPLETION_OPTOUT_HDT_INDEX,srTransRec.MITid);	
		else   
		   inMMTReadRecord(BDO_OPTOUT_HDT_INDEX,srTransRec.MITid);	
	}else
		inMMTReadRecord(BDO_HDT_INDEX,srTransRec.MITid);
	
	memcpy(srTransRec.szAuthCode,szTempAuthCode,strlen(szTempAuthCode));//Fix for blank AUTH CODE on completion for DCC Semi-Aggressive mode.
	
	inRet = inCTOS_EMVProcessing();
	if(d_OK != inRet)
    	return inRet;  

	inRet = inCTOS_GetInvoice();
    if(d_OK != inRet)
        return inRet;
	
	inRet = inBuildAndSendIsoData();

    if(d_OK != inRet)
	{

		/*BDO: Set ECR response code to EN - COMM ERROR -- sidumili*/
		if (strlen(srTransRec.szRespCode) <= 0)
		{
			strcpy(srTransRec.szECRRespCode, ECR_COMMS_ERR);
		}

		
        return VS_OPTOUT_FAILED;
    }

	inRet = inCTOS_SaveBatchTxn();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_UpdateAccumTotal();
    if(d_OK != inRet)
        return inRet;

	inRet=inDisconnectIfNoPendingADVICEandUPLOAD(&srTransRec, strHDT.inNumAdv);
    if(d_OK != inRet)
        return inRet;
	
	fECRBuildSendOK = TRUE;	
	if (fECRBuildSendOK){	
	    inRet = inMultiAP_ECRSendSuccessResponse();
	}

    inRet = ushCTOS_printOptOutReceipt();
		
    if(d_OK != inRet)
        return inRet;

	inRet = inDatabase_OptOutCompleteBatchUpdate(srTransRec.szOptOutVoidInvoiceNo);
	if(d_OK != inRet)
	{
		vdDisplayErrorMsgResp2("OPT OUT", "BATCH UPDATE", "FAILED");
		return inRet;
	}
	
    inCTLOS_Updatepowrfail(PFR_IDLE_STATE);

	CTOS_LCDTClearDisplay(); //BDO UAT 0012: Merchant copy still being displayed during TC Upload -- jzg
		
    inRet = inCTOS_EMVTCUpload();
#if 0	
    if(d_OK != inRet)
        return inRet;
    else
        vdSetErrorMessage("");
#endif
	CTOS_LCDTClearDisplay(); //BDO UAT 0012: Merchant copy still being displayed during Advice Upload -- sidumili
	
	inRet=inProcessAdviceTrans(&srTransRec, strHDT.inNumAdv);
#if 0
	if(d_OK != inRet)
		return inRet;
	else
		vdSetErrorMessage("");
#endif


	memset(&srTransRec,0x00,sizeof(TRANS_DATA_TABLE));
	memcpy(&srTransRec,&srtmpTransRec,sizeof(TRANS_DATA_TABLE));

    return d_OK;
	
}

int inCTOS_DCCOptOut(void)
{
	int inRet = d_NO;
	
	CTOS_LCDTClearDisplay();

	
	vdCTOS_TxnsBeginInit();

	if(fGetECRTransactionFlg() != TRUE)
		inCTOSS_MultiStopResumeAP("SHARLS_ECRBDO");
	
	inRet = inDCCOptOutFlowProcess();
	
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



int inDCCOptOutFlowProcess(void)
{

	int inRet = d_NO;
	BYTE byTransType = 0;

	fECRBuildSendOK = FALSE; /* BDO: For ECR -- sidumili */
	fTimeOutFlag = FALSE; /*BDO: Flag for timeout --sidumili*/
    srTransRec.fOptOut = TRUE;

#if 0	
    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;
		
    inRet = inCTOS_CheckTranAllowd();
    if(d_OK != inRet)
        return inRet;
#endif
	memset(&strPIT,0x00,sizeof(STRUCT_PIT));
	inPITRead(OPT_OUT);
	
	if(inFunctionKeyPasswordEx("OPT OUT", strPIT.inPasswordLevel)!=d_OK)
	{
		memset(szFuncTitleName,0,sizeof(szFuncTitleName));
		return d_NO;
	}
	
    if((strTCT.fSingleComms) && (fPreConnectEx == FALSE) || (srTransRec.usTerminalCommunicationMode != GPRS_MODE)|| (srTransRec.usTerminalCommunicationMode != WIFI_MODE)){
		    inRet = inCTOS_PreConnectEx();

		if (inRet != d_OK)
			return inRet;
	}

	while(1)
	{
		
	    inRet = inCTOS_GeneralGetInvoice();
	    if(d_EDM_USER_CANCEL == inRet)
	    {
			vdSetErrorMessage("");
	        return inRet;
	    }

	    if (inMultiAP_CheckMainAPStatus() == d_OK)
	    {
	        inRet = inCTOS_MultiAPBatchSearch(d_IPC_CMD_VOID_SALE);
			
			if(d_NOT_RECORD == inRet)
			{
				if(fGetECRTransactionFlg() == TRUE)
					return inRet;
				else
					continue;
			}
	        else if(d_OK != inRet)
	            return inRet;

	    }
	    else
	    {
	        if (inMultiAP_CheckSubAPStatus() == d_OK)
	        {
	            inRet = inCTOS_MultiAPGetVoid();
	            if(d_OK != inRet)
	                return inRet;
	        }       
	        inRet = inCTOS_BatchSearch();
			if(d_NOT_RECORD == inRet)
			{
				if(fGetECRTransactionFlg() == TRUE)
					return inRet;
				else
					continue;
			}
	        else if(d_OK != inRet)
	            return inRet;

	    }

		inRet = inCTOS_CheckMustSettleBDOHost();
		if(d_OK != inRet)
	    {
			vdDisplayErrorMsgResp2("","MUST SETTLE","");
			vdSetECRResponse(ECR_OPER_CANCEL_RESP);
			return inRet;
	    }
	
		srTransRec.usTerminalCommunicationMode = strCPT.inCommunicationMode;//If Sale used Comms Fallback, need to set srTransRec.usTerminalCommunicationMode to value in CPT.
		
		memcpy(srTransRec.szTempTime, srTransRec.szTime, TIME_BCD_SIZE); /*get original time*/


	    inRet = inCTOS_CheckOptOut();		
	    if(d_OK != inRet)
	    {
			if (fGetECRTransactionFlg() == TRUE)
			{
			    strcpy(srTransRec.szRespCode,"");
				strcpy(srTransRec.szECRRespCode, ECR_OPER_CANCEL_RESP);
				return inRet;
			}
			else
			{
				srTransRec.fOptOut = TRUE;//Set flag to TRUE since parameter is overwritten during inDatabase_BatchSearch()
				continue;
			}
	    }
		else
			break;

	}

    inRet = inCTOS_LoadCDTandIIT();
    if(d_OK != inRet)
        return inRet;


    inRet = inCTOS_VoidSelectHostNoPreConnect();
    if(d_OK != inRet)
        return inRet;


    inRet = inCTOS_CheckMustSettle();
    if(d_OK != inRet){
		
		//if (fGetECRTransactionFlg() == TRUE){
		    strcpy(srTransRec.szRespCode,"");
			//strcpy(srTransRec.szECRRespCode, ECR_OPER_CANCEL_RESP);
		//}
			
        return inRet;

    }
	
	//vdCTOS_SetTransType(OPT_OUT);
    inRet = inCTOS_ConfirmOptOutInvAmt();
    if(d_OK != inRet){		
		    strcpy(srTransRec.szRespCode,"");
			strcpy(srTransRec.szECRRespCode, ECR_OPER_CANCEL_RESP);		
        return inRet;

    }
	
	if ((strTCT.fSingleComms != TRUE) || (srTransRec.usTerminalCommunicationMode == WIFI_MODE) || (srTransRec.usTerminalCommunicationMode == GPRS_MODE)){
		inRet = inCTOS_PreConnect();
		if(d_OK != inRet)
			return inRet;
	}
	
	
	if(srTransRec.byOrgTransType == SALE || srTransRec.byOrgTransType == SALE_OFFLINE)
	{
		DebugAddHEX("OptOutTransType INV",srTransRec.szInvoiceNo,INVOICE_BCD_SIZE);
		
		srTransRec.byOptOutOrigTransType = srTransRec.byOrgTransType;
		inRet = inDatabase_OptOutbyTransTypeBatchUpdate(srTransRec.byOptOutOrigTransType, srTransRec.szInvoiceNo);// SAVE TO BATCH INCASE SALE/OFFLINE FAILS
		
	}
		
	if(srTransRec.fOptOutVoided == FALSE)
	{
		inRet = inVoidDCCTransaction();
		if(d_OK != inRet)
		{
			//vdDisplayErrorMsgResp2(" ", "OPT OUT", "FAILED");
			vdDisplayErrorMsgResp2("PLEASE RETRY","OPT OUT","TRANSACTION");
			return inRet;
		}
	}

	vdResetAllCardData();
	srTransRec.fDCC = VS_FALSE;
	srTransRec.byVoided = VS_FALSE;
	fAdviceTras = VS_FALSE;
	vdDispTransTitle(srTransRec.byTransType);


	memset(srTransRec.szBaseAmount,0x00,sizeof(srTransRec.szBaseAmount));
	memcpy(srTransRec.szBaseAmount, srTransRec.szDCCLocalAmount,sizeof(srTransRec.szDCCLocalAmount));
	DebugAddHEX("LOCAL AMOUNT",srTransRec.szBaseAmount,AMT_BCD_SIZE);
	
	memcpy(srTransRec.szOptOutVoidInvoiceNo,srTransRec.szInvoiceNo,INVOICE_BCD_SIZE);
	DebugAddHEX("szOptOutVoidInvoiceNo",srTransRec.szOptOutVoidInvoiceNo,INVOICE_BCD_SIZE);
	
	if(srTransRec.byOptOutOrigTransType == SALE)
		inRet = inCTOS_WaveFlowProcess();
	else if(srTransRec.byOptOutOrigTransType == SALE_OFFLINE)
		inRet = inCTOS_SaleOffLineFlowProcess();
	else
	{
		vdDisplayErrorMsgResp2("","UNSUPPORTED","TRANSACTION");
		return inRet;
	}
	
	if(d_OK != inRet && inRet != ADVICE_FAILED && inRet != TRANSLOG_FAILED)
	{
		vdDisplayErrorMsgResp2("PLEASE RETRY","OPT OUT","TRANSACTION");
		return inRet;
	}

	DebugAddHEX("szInvoiceNo",srTransRec.szInvoiceNo,INVOICE_BCD_SIZE);
	DebugAddHEX("szOptOutVoidInvoiceNo",srTransRec.szOptOutVoidInvoiceNo,INVOICE_BCD_SIZE);

	inRet = inDatabase_OptOutCompleteBatchUpdate(srTransRec.szOptOutVoidInvoiceNo);
	if(d_OK != inRet)
	{
		vdDisplayErrorMsgResp2("OPT OUT", "BATCH UPDATE", "FAILED");
		return inRet;
	}

	
	return d_OK;

}

int inCTOS_ConfirmOptOutInvAmt(void)
{
    BYTE szAmtTmp1[16+1];
    BYTE szAmtTmp2[16+1];
    char szDisplayBuf[30];
    BYTE   key;
    USHORT result;
	BYTE szTemp1[30+1];
	int inRemaining=0;
	BYTE szPAN1[20+1];
	BYTE szPAN2[20+1];
    
    CTOS_LCDTClearDisplay();
    vdDispTransTitle(srTransRec.byTransType);
	
    memset(szDisplayBuf, 0x00, sizeof(szDisplayBuf));
    memset(szAmtTmp1, 0x00, sizeof(szAmtTmp1));
    memset(szAmtTmp2, 0x00, sizeof(szAmtTmp2));
    sprintf(szDisplayBuf, "%s", strCST.szCurSymbol);
    wub_hex_2_str(srTransRec.szTotalAmount, szAmtTmp1, 6);
	if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
		vdDCCModifyAmount(szAmtTmp1,szAmtTmp2); //vdDCCModifyAmount(&szAmtTmp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szAmtTmp1, szAmtTmp2);
	

   	memset(szTemp1,0,sizeof(szTemp1));
		
   	inIITRead(strCDT.IITid);
	if (strIIT.fMaskPanDisplay == TRUE)
	{
		vdCTOS_FormatPAN(strIIT.szPANFormat, srTransRec.szPAN, szTemp1);
		strcpy(szTemp1, srTransRec.szPAN);
		cardMasking(szTemp1, 5);		
	}
	else
	{ 	
		vdCTOS_FormatPAN2(strTCT.DisplayPANFormat, srTransRec.szPAN, szTemp1);
	}	
	if (strlen(szTemp1) > 20)
	{
       memset(szPAN1, 0x00, sizeof(szPAN1));
       memset(szPAN2, 0x00, sizeof(szPAN2));
       inRemaining = strlen(szTemp1) - 20;
       
       memcpy(szPAN1, szTemp1, 20);
       memcpy(szPAN2, &szTemp1[20], inRemaining);
       CTOS_LCDTPrintXY(1, 3, szPAN1);
		     CTOS_LCDTPrintXY(1, 4, szPAN2);
    }
	else
    	CTOS_LCDTPrintXY(1, 3, szTemp1);

	CTOS_LCDTPrintXY(1, 5, "AMOUNT");
	setLCDPrint(6, DISPLAY_POSITION_LEFT, szDisplayBuf);
	CTOS_LCDTPrintXY(MAX_CHAR_PER_LINE-(strlen(szAmtTmp2)+2)*2,  6, szAmtTmp2);		

	setLCDPrint(7, DISPLAY_POSITION_CENTER,"CONFIRM OPT OUT?");
	setLCDPrint(8, DISPLAY_POSITION_CENTER,"NO[X] YES[OK]");

    
	CTOS_TimeOutSet(TIMER_ID_1, UI_TIMEOUT);
    vduiWarningSound();

    CTOS_KBDBufFlush();//cleare key buffer
    
    while(1)
    { 
        
        CTOS_KBDHit(&key);
        if(key == d_KBD_ENTER)
        {
            result = d_OK;
			vdClearBelowLine(2);
			vdCTOS_DispStatusMessage("PROCESSING...");  
            break;
        }
        else if((key == d_KBD_CANCEL))
        {
            result = d_NO;
            vdSetErrorMessage("USER CANCEL");
            break;
        }
        if(CTOS_TimeOutCheck(TIMER_ID_1) == d_YES)
        {
            result = d_NO;
            vdSetErrorMessage("TIME OUT");
            break;
        }       
    }
    
    return result;
}

int inCTOS_CheckOptOut(void)
{
	vdDebug_LogPrintf("byVoided[%d] :: fOptOut[%d] :: fOptOutComplete[%d]",srTransRec.byVoided,srTransRec.fOptOut,srTransRec.fOptOutComplete);
	if(srTransRec.fDCC != TRUE)
    {
		vdDisplayErrorMsgResp2(" ", "OPT OUT", "NOT ALLOWED");
		return d_NO;
    }
	else if(srTransRec.fOptOutComplete == TRUE)
	{
		vdDisplayErrorMsgResp2(" ", "ALREADY", "OPTED OUT");
		return d_NO;
	}
		
    if(srTransRec.byVoided == TRUE && srTransRec.fOptOut == FALSE)
    {
		vdDisplayErrorMsgResp2(" ", "OPT OUT", "NOT ALLOWED");
        return d_NO;
    }

    if(srTransRec.byTransType == PRE_AUTH)
    {
        vdDisplayErrorMsgResp2(" ", "OPT OUT", "NOT ALLOWED");
        return d_NO;
    }

	if(srTransRec.byTransType == SMAC_BALANCE)
    {
        vdDisplayErrorMsgResp2(" ", "OPT OUT", "NOT ALLOWED");
        return d_NO;
    }

	if(srTransRec.byTransType == BALANCE_INQUIRY)
    {
        vdDisplayErrorMsgResp2(" ", "OPT OUT", "NOT ALLOWED");
        return d_NO;
    }
#if 1
    //to find the original transaction of the sale tip to be voided - Meena 26/12/12 - START
    if(srTransRec.byTransType == SALE_TIP)
    {
        szOriginTipTrType = srTransRec.byOrgTransType;
        srTransRec.byOrgTransType = srTransRec.byTransType;
    }
    else //to find the original transaction of the sale tip to be voided - Meena 26/12/12 - END
        srTransRec.byOrgTransType = srTransRec.byTransType;
#endif

	srTransRec.fOptOut = TRUE;
	srTransRec.byTransType = VOID;
	srTransRec.byPackType = VOID;
    return d_OK;
}

#ifdef DCC_SIGNPAD

int inDCCSignPadBody(char *szBuffer, int inType)
{
	int inResult = -1;
	int inLength = 0;
	int inSelectCurrencyTimeOut = get_env_int("SPADCURRECYTO");
	int inSignatureTimeOut = get_env_int("SPADSIGNTO");
	BYTE szAmtBuff[20+1];
	BYTE szBaseAmt[AMT_ASC_SIZE + 1] = {0};
	BYTE szHostCountryAmt[20+1] = {0};
	BYTE szRequestID[14+1]={0};
	char szFxRate[MAX_CHAR_PER_LINE+1];
	CTOS_RTC GetRTC;
	//version16
	VS_BOOL fDisplayMarkup = inFLGGet("fSPadDCCMarkUp");

	vdDebug_LogPrintf("test fSPadDCCMarkUp = %d", fDisplayMarkup);

	
	vdDebug_LogPrintf("***inGCreateCashSignBody START***");

	CTOS_RTCGet(&GetRTC);
	sprintf(szRequestID ,"%d%02d%02d%02d%02d%02d",2000+GetRTC.bYear,GetRTC.bMonth,GetRTC.bDay,GetRTC.bHour,GetRTC.bMinute,GetRTC.bSecond);
	vdDebug_LogPrintf("szRequestID is %s",szRequestID);
	
	if (inType == AVAILABILITY)
	{
	    sprintf(szBuffer,"<start>{\"commandId\":\"0\",\"commandData\":{\"requestId\":\"%s\"}}<end>",szRequestID);
		vdDebug_LogPrintf("REQUEST BODY %s :: len[%d]", szBuffer,strlen(szBuffer));
	}

	else if(inType == DCC_RATE)
	{	
//get the Host Country/local amount	
		memset(szHostCountryAmt,0x00,sizeof(szHostCountryAmt));

		if(strTCT.inDCCMode == NORMAL_MODE)
			wub_hex_2_str(srTransRec.szTotalAmount, szBaseAmt, 6); 
		else if(strTCT.inDCCMode == AUTO_OPTOUT_MODE)
			wub_hex_2_str(srTransRec.szDCCLocalAmount, szBaseAmt, 6); 
		
		vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szBaseAmt,szHostCountryAmt);

//get exchange rate
		inLength=strlen(srTransRec.szDCCFXRate)-srTransRec.inDCCFXRateMU;
		memset(szFxRate,0x00,sizeof(szFxRate));
		memcpy(szFxRate,srTransRec.szDCCFXRate,inLength);
		memcpy(&szFxRate[inLength],".",1);
		memcpy(&szFxRate[inLength+1],&srTransRec.szDCCFXRate[inLength],srTransRec.inDCCFXRateMU);
	
//get the card holder currency
		inCSTReadHostID(srTransRec.szDCCCur);
		if(strTCT.fFormatDCCAmount == TRUE)
		    vdDCCModifyAmount(srTransRec.szDCCCurAmt,szAmtBuff);
		else
		    vdCTOS_FormatAmount(strCST.szAmountFormat, srTransRec.szDCCCurAmt,szAmtBuff);


//version16	
         if (fDisplayMarkup == 1){
		 	vdDebug_LogPrintf("test display with mark up");

			sprintf(szBuffer,"<start>{\"commandId\": \"4\",\"commandData\":{\"selectTimeout\":%d,\"dccCurrencies\":[{\"dccCurrencyCode\":\"%s\",\"dccAmount\":\"%s %s\",\"dccMarkup\":\"\",\"dccRate\":\"1 %s = %s\",\"dccOrder\":\"1\"},{\"dccCurrencyCode\":\"%s\",\"dccAmount\":\"%s %s\",\"dccMarkup\":\"%s\",\"dccRate\":\"\",\"dccOrder\":\"2\"}],\"requestId\":\"%s\"}}<end>",
			inSelectCurrencyTimeOut,srTransRec.szDCCLocalCur,srTransRec.szDCCLocalSymbol,szHostCountryAmt,strCST.szCurSymbol,szFxRate,srTransRec.szDCCCur,strCST.szCurSymbol,szAmtBuff,srTransRec.szDCCMarkupPer, szRequestID);

         }else{
            vdDebug_LogPrintf("test display no mark up");

			sprintf(szBuffer,"<start>{\"commandId\": \"4\",\"commandData\":{\"selectTimeout\":%d,\"dccCurrencies\":[{\"dccCurrencyCode\":\"%s\",\"dccAmount\":\"%s %s\",\"dccRate\":\"1 %s = %s\",\"dccOrder\":\"1\"},{\"dccCurrencyCode\":\"%s\",\"dccAmount\":\"%s %s\",\"dccRate\":\"\",\"dccOrder\":\"2\"}],\"requestId\":\"%s\"}}<end>",
			inSelectCurrencyTimeOut,srTransRec.szDCCLocalCur,srTransRec.szDCCLocalSymbol,szHostCountryAmt,strCST.szCurSymbol,szFxRate,srTransRec.szDCCCur,strCST.szCurSymbol,szAmtBuff,szRequestID);
         }
//version16
		
		vdDebug_LogPrintf("REQUEST BODY %s :: len[%d]", szBuffer,strlen(szBuffer));
	}
	
	else if(inType == GET_PAYMENT_SIGNATURE)
	{		
		//get exchange rate
		inLength=strlen(srTransRec.szDCCFXRate)-srTransRec.inDCCFXRateMU;
		memset(szFxRate,0x00,sizeof(szFxRate));
		memcpy(szFxRate,srTransRec.szDCCFXRate,inLength);
		memcpy(&szFxRate[inLength],".",1);
		memcpy(&szFxRate[inLength+1],&srTransRec.szDCCFXRate[inLength],srTransRec.inDCCFXRateMU);
		
		sprintf(szBuffer,"<start>{\"commandId\":\"1\",\"commandData\":{\"signTimeout\":\"%d\",\"strAmount\":\"%s %s\",\"strRate\":\"1 %s = %s %s\",\"requestId\":\"%s\"}}<end>",inSignatureTimeOut,strCST.szCurSymbol,srTransRec.szTotalAmount,strCST.szCurSymbol,srTransRec.szDCCLocalSymbol,szFxRate,szRequestID);
		vdDebug_LogPrintf("REQUEST BODY %s :: len[%d]", szBuffer,strlen(szBuffer));
	}

	
	
	return d_OK;
}

int base64_decode(char *input) {
    int len = 0;
    unsigned char *output = (unsigned char *)input;
    int c1, c2, c3, c4;

	vdDebug_LogPrintf("***base64_decode***");
	
    while (*input) {
    c1 = *input++;
    if (CHAR64(c1) == XX) return -1;
    c2 = *input++;
    if (CHAR64(c2) == XX) return -1;
    c3 = *input++;
    if (c3 != '=' && CHAR64(c3) == XX) return -1; 
    c4 = *input++;
    if (c4 != '=' && CHAR64(c4) == XX) return -1;
    *output++ = (CHAR64(c1) << 2) | (CHAR64(c2) >> 4);
    ++len;
    if (c3 == '=') break;
    *output++ = ((CHAR64(c2) << 4) & 0xf0) | (CHAR64(c3) >> 2);
    ++len;
    if (c4 == '=') break;
    *output++ = ((CHAR64(c3) << 6) & 0xc0) | CHAR64(c4);
    ++len;
    }

    return len;
}


int iDecode64(char *sz_Encoded, int i_EncodeLen, unsigned char *pbt_Data, int *pi_DataLen)
{
	//char szEncData[8192+1];			//Temporary Buffer
	char *szEncData = NULL;
	int iDataLen = 0;
	int iRetVal = -1;

	vdDebug_LogPrintf("***iDecode64***");
	//Copy sz_Encoded into a buffer

	szEncData = (char *) malloc(60000 * sizeof(char));
	if (szEncData == NULL) 
    {
        vdDebug_LogPrintf("failed to allocate memory szWorkBuff1");
    }
	else
		memset(szEncData, 0x00, 60000*sizeof(char));
	
	memset(szEncData, 0x00, sizeof(szEncData));
	memcpy (szEncData, sz_Encoded, i_EncodeLen);
	//vdDebug_LogPrintf("szEncData[%s]len[%d]",szEncData,strlen(szEncData));
	iDataLen = base64_decode(szEncData);
	if (0 >= iDataLen)
	{
		goto ErrHandler;				//Failed to decode string
	}

	//Prepare to copy decoded bytes to pbt_Data
	//if (iDataLen > *pi_DataLen)
	//{
	//	iRetVal = ERR_ENC_INSUFF_BUFFER;		//Buffer not large enough
	//	goto ErrHandler;
	//}
	memcpy(pbt_Data, szEncData, iDataLen); 
	iRetVal = 0;

	free(szEncData);
	
CleanUp:
	*pi_DataLen = iDataLen;				//Return Data Len
	return iRetVal;

ErrHandler:
	goto CleanUp;
}

int inConvertToPNG(BYTE *uszECRAscData)
{
	unsigned int inECRAscData = 0;
	unsigned int inECRHexData = 0;
	unsigned char *uszECRHexData = NULL;
	char signfilename[64+1]={0};
	char szInvoiceNo[6+1];
	FILE *ptr_myfile = NULL;

	uszECRHexData = (unsigned char *) malloc(60000 * sizeof(unsigned char));
	if (uszECRHexData == NULL) 
    {
        vdDebug_LogPrintf("failed to allocate memory szWorkBuff1");
    }
	else
		memset(uszECRHexData, 0x00, 60000*sizeof(unsigned char));
	
	inECRAscData = strlen((char*)uszECRAscData);
	inECRAscData += (4 - inECRAscData%4); // data must able divide by 4. if not, error will happen
	vdDebug_LogPrintf("inECRAscData %d",inECRAscData);
	iDecode64((char *) uszECRAscData,inECRAscData,uszECRHexData,&inECRHexData);
	vdDebug_LogPrintf("data len %d",inECRHexData);
	DebugAddHEX("IMAGE FILE",uszECRHexData,inECRHexData);

	memset(szInvoiceNo, 0x00, sizeof(szInvoiceNo));
    wub_hex_2_str(srTransRec.szInvoiceNo, szInvoiceNo, INVOICE_BCD_SIZE);

	sprintf(signfilename,"signDCC%06ld.png",atol(szInvoiceNo));
	
	ptr_myfile = fopen(signfilename, "wb");
	if (!ptr_myfile) {
		vdDebug_LogPrintf("Unable to open file!");
		return 1;
	}

	fseek(ptr_myfile, 0L, SEEK_SET);
	fwrite(uszECRHexData, inECRHexData, 1, ptr_myfile);
	fclose(ptr_myfile);

	free(uszECRHexData);

	return d_OK;
}

int inDCCSignPad_InitCOM(BYTE bCommPort)
{
	char szBaud[3];
	int inResult = d_OK;


    vdDebug_LogPrintf("byRS232ECRPort[%d]",strTCT.byRS232ECRPort);
	vdDebug_LogPrintf("fECRBaudRate[%d]",strTCT.fECRBaudRate);


	if (strTCT.fECRBaudRate == 1){	
		vdDebug_LogPrintf("BAUD RATE IS 9600");
		inResult = CTOS_RS232Open(bCommPort, 9600, 'N', 8, 1);
	}
	else if (strTCT.fECRBaudRate == 2){
		vdDebug_LogPrintf("BAUD RATE IS 19200");
		inResult = CTOS_RS232Open(bCommPort, 19200, 'N', 8, 1);
	}

	else if (strTCT.fECRBaudRate == 3){	
		vdDebug_LogPrintf("BAUD RATE IS 115200");
		inResult = CTOS_RS232Open(bCommPort, 115200, 'N', 8, 1);
	}	

	vdDebug_LogPrintf("::inResult[%d]::ECRPort[%d]", inResult, bCommPort);
	
	return inResult;
}

int inDetectSignPad(BYTE COMMPort)
{
	BOOL fRcvdOK = FALSE;
	int inSize = 0, ret = -1, d_READY_TIMEOUT = 100, timeout = 5;
	int inRet = 0;
	USHORT lECRRecvLen = 0;
	ULONG tick;
	char szResultString[10+1];
	char szECRSendBuf[4096 + 1];
	char szECRReceiveBuf[4096 + 1];
	
	memset(szECRSendBuf,0x00,sizeof(szECRSendBuf));
	memset(szECRReceiveBuf,0x00,sizeof(szECRReceiveBuf));
	inDCCSignPadBody(szECRSendBuf,AVAILABILITY);

	CTOS_RS232FlushRxBuffer(COMMPort);
	CTOS_RS232FlushTxBuffer(COMMPort);
	
	do{
		ret = CTOS_RS232TxReady(COMMPort);
		vdDebug_LogPrintf("CTOS_RS232TxReady[%d]",ret);
		if (ret == d_OK)
		{
			//inPrintDCCSingPadPacket("TX:", (BYTE *) szECRSendBuf, inSize);
			break;
		}
	}while ((CTOS_TickGet() - tick) < d_READY_TIMEOUT);

	if (ret == d_OK)
	{
		inSize = strlen(szECRSendBuf);
		vdDebug_LogPrintf("CTOS_RS232TxData inSize %d",inSize);
		CTOS_RS232TxData(COMMPort, szECRSendBuf, inSize);
		
		CTOS_Delay(1000);

		CTOS_TimeOutSet (TIMER_ID_1 , timeout*100);
		fRcvdOK = FALSE;
		while (1)
		{
			if(CTOS_TimeOutCheck(TIMER_ID_1 )  == d_YES)
				break;
			
			CTOS_Delay(10);
			
			// Check if data is available in COM1 port // 
			ret = CTOS_RS232RxReady(COMMPort, &lECRRecvLen); 
			vdDebug_LogPrintf("CTOS_RS232RxReady[%d] :: lECRRecvLen[%d]",ret,lECRRecvLen);
			CTOS_Delay(500);
			
			if(ret == d_OK && lECRRecvLen) 
			{ 
				// Get Data from COM2 port 
				CTOS_RS232RxData(COMMPort, szECRReceiveBuf, &lECRRecvLen);
				vdDebug_LogPrintf("1. szECRReceiveBuf[%s] :: lECRRecvLen[%d]",szECRReceiveBuf,lECRRecvLen);
				CTOS_Delay(10);
				
				fRcvdOK = TRUE; 			
			} 

			if (fRcvdOK)
				break;
			
		}
		
	}

	memset(szResultString,0x00,sizeof(szResultString));
	inRet = inExtractField((unsigned char *) szECRReceiveBuf,szResultString,"resultCode");
	vdDebug_LogPrintf("inExtractField [%d] :: szResultString[%s] :: atoi[%d]",inRet,szResultString,atoi(szResultString));
	
	if(inRet != d_OK || atoi(szResultString) != 0)
	{
		vdDisplayErrorMsgResp2("","DCC SIGN-PAD","NOT CONNECTED");
		return d_NO;
	}

	return d_OK;
}


int inSignPadSendReceive(BYTE COMMPort, int inType) {
	VS_BOOL fRcvdOK = FALSE;
	VS_BOOL fDisplayForExRate = inFLGGet("fSpadForExRate");
	VS_BOOL fDisplayMarkup = inFLGGet("fSPadDCCMarkUp");
	int inLength = 0;
	int d_READY_TIMEOUT	= 100, inRet = -1, timeout = 5;
	int inSize = 0;
	int inSendsize=0;
	int inLineIncrement=4;
	int inLine=4;
	int inLine2 = 3;
	int inCounter = 0;
	int inSelectCurrencyTimeOut = get_env_int("SPADCURRECYTO") + 1;
	int inSignatureTimeOut = get_env_int("SPADSIGNTO") + 1;
	USHORT ret;
	USHORT lECRRecvLen;
	ULONG tick;
	BYTE bkey;
	char szECRSendBuf[4096 + 1];
	char szECRReceiveBuf[4096 + 1];
	char *ptr = NULL;
	char *signPtr = NULL;
	char *ConvertedsignPtr = NULL;
	char szResultString[4096+1];
	char szSelectedCurrency[3+1] = {0};
	char szTemp[MAX_CHAR_PER_LINE+1];
	char szTemp1[MAX_CHAR_PER_LINE+1];
	char szTemp2[MAX_CHAR_PER_LINE+1];
	char szTemp3[MAX_CHAR_PER_LINE+1];
	float inMarkup = 0;

	vdDebug_LogPrintf("REINER :: inSelectCurrencyTimeOut %d",inSelectCurrencyTimeOut);
	vdDebug_LogPrintf("REINER :: inSignatureTimeOut %d",inSignatureTimeOut);
	vdDebug_LogPrintf("REINER :: fDisplayMarkup %d",fDisplayMarkup);
	
	inDCCSignPad_InitCOM(COMMPort);
	
	if(inDetectSignPad(COMMPort) != d_OK)
		return SIGNPAD_NOT_DETECTED;

	if ((strTCT.byTerminalType % 2) == 0)
		inLine = 5;
	
	ptr = (char *) malloc(60000 * sizeof(char));
	if (ptr == NULL) 
    {
        vdDebug_LogPrintf("failed to allocate memory ptr");
    }
	else
		memset(ptr,0x00,60000*sizeof(char));
	
	signPtr = (char *) malloc(60000 * sizeof(char));
	if (signPtr == NULL) 
    {
        vdDebug_LogPrintf("failed to allocate memory signPtr");
    }
	else
		memset(signPtr,0x00,60000*sizeof(char));

	ConvertedsignPtr = (char *) malloc(60000 * sizeof(char));
	if (ConvertedsignPtr == NULL) 
    {
        vdDebug_LogPrintf("failed to allocate memory signPtr");
    }
	else
		memset(ConvertedsignPtr,0x00,60000*sizeof(char));
	
	

//DCC SELECTION START
	if(inType == DCC_RATE)
	{
		if(strTCT.inDCCMode == NORMAL_MODE)
			srTransRec.fDCC = VS_FALSE;
		
		memset(szECRSendBuf,0x00,sizeof(szECRSendBuf));
		memset(szECRReceiveBuf,0x00,sizeof(szECRReceiveBuf));
		memset(ptr,0x00,60000*sizeof(char));

		inDCCSignPadBody(szECRSendBuf,inType);

		CTOS_RS232FlushRxBuffer(COMMPort);
		CTOS_RS232FlushTxBuffer(COMMPort);
	
		do{
			ret = CTOS_RS232TxReady(COMMPort);
			vdDebug_LogPrintf("CTOS_RS232TxReady[%d]",ret);
			if (ret == d_OK)
			{
				//inPrintDCCSingPadPacket("TX:", (BYTE *) szECRSendBuf, inSize);
				break;
			}
		}while ((CTOS_TickGet() - tick) < d_READY_TIMEOUT);

	if(fDisplayForExRate)
		inLine--;
			
	if(fDisplayMarkup)
		inLine--;

		memset(szTemp,0x00,sizeof(szTemp));
		memset(szTemp1,0x00,sizeof(szTemp1));
		memset(szTemp2,0x00,sizeof(szTemp2));
		inMSGResponseCodeRead(szTemp,szTemp1,szTemp2,0,11);
			
		CTOS_LCDTClearDisplay();    
		setLCDPrint27(inLine,DISPLAY_POSITION_CENTER,szTemp);
		setLCDPrint27(inLine+1,DISPLAY_POSITION_CENTER,szTemp1);
		setLCDPrint27(inLine+2,DISPLAY_POSITION_CENTER,szTemp2);

	if(fDisplayForExRate)
	{
		inLength=strlen(srTransRec.szDCCFXRate)-srTransRec.inDCCFXRateMU;
		memset(szTemp,0x00,sizeof(szTemp));
		memcpy(szTemp,srTransRec.szDCCFXRate,inLength);
		memcpy(&szTemp[inLength],".",1);
		memcpy(&szTemp[inLength+1],&srTransRec.szDCCFXRate[inLength],srTransRec.inDCCFXRateMU);
			
		setLCDPrint(inLine+inLineIncrement, DISPLAY_POSITION_LEFT, "Exchange Rate:");
		inLineIncrement++;
		setLCDPrint(inLine+inLineIncrement, DISPLAY_POSITION_RIGHT,szTemp);
		inLineIncrement++;
	}

	if(fDisplayMarkup)
	{
		memset(szTemp,0x00,sizeof(szTemp));
		memset(szTemp1,0x00,sizeof(szTemp1));
		memset(szTemp2,0x00,sizeof(szTemp2));
		
		inMarkup = atof(srTransRec.szDCCMarkupPer);
		sprintf(szTemp,"%.2f",inMarkup);
		sprintf(szTemp1,"%20.20s",szTemp);
		//sprintf(szTemp1,"%s",szTemp);
		sprintf(szTemp2,"Markup:%s",szTemp1);
		strcat(szTemp2,"%");
		
		setLCDPrint(inLine+inLineIncrement,DISPLAY_POSITION_LEFT,szTemp2);
	}
	

			
		if(inDetectSignPad(COMMPort) != d_OK)
				return SIGNPAD_NOT_DETECTED;
		
		if (ret == d_OK)
		{
			inSize = strlen(szECRSendBuf);
		    vdDebug_LogPrintf("CTOS_RS232TxData inSize %d",inSize);
			CTOS_RS232TxData(COMMPort, szECRSendBuf, inSize);
					
			CTOS_Delay(1000);
			//CTOS_TimeOutSet (TIMER_ID_1 , 3000);//30 second timeout before falling back to terminal's dcc rate screen.
			
			fRcvdOK = FALSE;
			CTOS_TimeOutSet (TIMER_ID_2 , inSelectCurrencyTimeOut * 100);

			while (1)
			{
				vdDebug_LogPrintf("TIMEOUT CHECK");
				if(CTOS_TimeOutCheck(TIMER_ID_2 )  == d_YES)
				{	
					vdDebug_LogPrintf("TIMEOUT REACHED");
					//vdDisplayErrorMsgResp2("","DCC SIGN-PAD","NOT CONNECTED");
					inRet = d_KBD_CANCEL;
					break;
				}
				
				if(strTCT.inDCCMode == NORMAL_MODE)//Cancel Key applicable only on Normal DCC mode.
				{
					CTOS_KBDHit(&bkey);
		            if(bkey == d_KBD_CANCEL)
		            {
		            	inRet = d_KBD_CANCEL;
						break;
		            }
				}
				
				CTOS_Delay(500);
				
				// Check if data is available in COM1 port // 
				ret = CTOS_RS232RxReady(COMMPort, &lECRRecvLen); 
				vdDebug_LogPrintf("CTOS_RS232RxReady[%d] :: lECRRecvLen[%d]",ret,lECRRecvLen);
				CTOS_Delay(100);
				
				if(ret == d_OK && lECRRecvLen) 
				{ 
					// Get Data from COM2 port 
					CTOS_RS232RxData(COMMPort, szECRReceiveBuf, &lECRRecvLen);
					vdDebug_LogPrintf("2. szECRReceiveBuf[%s] :: lECRRecvLen[%d]",szECRReceiveBuf,lECRRecvLen);
					CTOS_Delay(10);
					
					if(!memcmp(&szECRReceiveBuf[lECRRecvLen - 5],"<end>",5))
					{
						fRcvdOK = TRUE;					
					}				
					
					strcat(ptr,szECRReceiveBuf);
					memset(szECRReceiveBuf,0x00,sizeof(szECRReceiveBuf));
				} 

				if (fRcvdOK)
					break;
				
			}

			if(fRcvdOK == TRUE)
			{
				inRet = inGetResultCode(ptr, DCC_RATE);
				if(inRet == d_OK)
				{
					inExtractField((unsigned char *)ptr, szSelectedCurrency, "selectedCurrency");
					if(!strcmp(szSelectedCurrency,srTransRec.szDCCCur))//Selected Card holder currency.
					{
						if(strTCT.inDCCMode == NORMAL_MODE)
						{
							srTransRec.fDCC = VS_TRUE;						
							memset(srTransRec.szDCCLocalAmount,0x00,sizeof(srTransRec.szDCCLocalAmount));
							memcpy(srTransRec.szDCCLocalAmount, srTransRec.szTotalAmount,sizeof(srTransRec.szTotalAmount));
						}
						else if(strTCT.inDCCMode == AUTO_OPTOUT_MODE)
						{
							inRet = VS_CONTINUE;//Opt-in. Would continue printing succeeding receipt copies.
						}
					}
					else
					{
						if(strTCT.inDCCMode == AUTO_OPTOUT_MODE)
						{
							inRet = FAIL;//Opt-out.
						}
					}
				}
				else
					return SIGNPAD_NOT_DETECTED; 
			}
			
		}
	}
//DCC SELECTION END

//GET PAYMENT SIGNATURE START
	else if(inType == GET_PAYMENT_SIGNATURE)
	{
		memset(szECRSendBuf,0x00,sizeof(szECRSendBuf));
		memset(szECRReceiveBuf,0x00,sizeof(szECRReceiveBuf));
		memset(ptr,0x00,60000*sizeof(char));
		inDCCSignPadBody(szECRSendBuf,inType);

		CTOS_RS232FlushRxBuffer(COMMPort);
		CTOS_RS232FlushTxBuffer(COMMPort);

//SIGN_AGAIN:
	
		do{
			ret = CTOS_RS232TxReady(COMMPort);
			vdDebug_LogPrintf("CTOS_RS232TxReady[%d]",ret);
			if (ret == d_OK)
			{
				//inPrintDCCSingPadPacket("TX:", (BYTE *) szECRSendBuf, inSize);
				break;
			}
		}while ((CTOS_TickGet() - tick) < d_READY_TIMEOUT);

		memset(szTemp,0x00,sizeof(szTemp));
		memset(szTemp1,0x00,sizeof(szTemp1));
		memset(szTemp2,0x00,sizeof(szTemp2));
		inMSGResponseCodeRead(szTemp,szTemp1,szTemp2,1,11);
		
		CTOS_LCDTClearDisplay();    
		setLCDPrint27(inLine2,DISPLAY_POSITION_CENTER,szTemp);
		setLCDPrint27(inLine2+1,DISPLAY_POSITION_CENTER,szTemp1);
		setLCDPrint27(inLine2+2,DISPLAY_POSITION_CENTER,szTemp2);

		setLCDPrint27(inLine2+5,DISPLAY_POSITION_RIGHT,"PLEASE RETRY[OK]");
		
		if(inDetectSignPad(COMMPort) != d_OK)
				return SIGNPAD_NOT_DETECTED;
		
		if (ret == d_OK)
		{
		
SIGN_AGAIN:

			inSize = strlen(szECRSendBuf);
		    vdDebug_LogPrintf("CTOS_RS232TxData inSize %d",inSize);
			CTOS_RS232TxData(COMMPort, szECRSendBuf, inSize);
					
			CTOS_Delay(1000);

			CTOS_TimeOutSet (TIMER_ID_2 , inSignatureTimeOut * 100);

			fRcvdOK = FALSE;
			while (1)
			{
				if(CTOS_TimeOutCheck(TIMER_ID_2 )  == d_YES)
				{	
					vdDebug_LogPrintf("TIMEOUT REACHED");
					inRet = d_NO;
					break;
				}

				CTOS_KBDHit(&bkey);
	            if(bkey == d_KBD_CANCEL)
	            {
	            	inRet = d_NO;
					break;
	            }

				if(bkey == d_KBD_ENTER)
	            {
	            	CTOS_RS232FlushRxBuffer(COMMPort);
					CTOS_RS232FlushTxBuffer(COMMPort);
					
	            	do{
						ret = CTOS_RS232TxReady(COMMPort);
						vdDebug_LogPrintf("CTOS_RS232TxReady[%d]",ret);
						if (ret == d_OK)
						{
							//inPrintDCCSingPadPacket("TX:", (BYTE *) szECRSendBuf, inSize);
							break;
						}
					}while ((CTOS_TickGet() - tick) < d_READY_TIMEOUT);
	            	goto SIGN_AGAIN;
	            }
				
				CTOS_Delay(500);
				
				// Check if data is available in COM1 port // 
				ret = CTOS_RS232RxReady(COMMPort, &lECRRecvLen); 
				vdDebug_LogPrintf("CTOS_RS232RxReady[%d] :: lECRRecvLen[%d]",ret,lECRRecvLen);
				CTOS_Delay(100);
				
				if(ret == d_OK && lECRRecvLen) 
				{ 
					if(inCounter == 0)
						CTOS_LCDTClearDisplay();//clear display on first instance only.    
					
					vdCTOS_DispStatusMessage("PROCESSING...");
					// Get Data from COM2 port 
					CTOS_RS232RxData(COMMPort, szECRReceiveBuf, &lECRRecvLen);
					vdDebug_LogPrintf("2. szECRReceiveBuf[%s] :: lECRRecvLen[%d]",szECRReceiveBuf,lECRRecvLen);
					CTOS_Delay(10);
					
					if(!memcmp(&szECRReceiveBuf[lECRRecvLen - 5],"<end>",5))
					{
						fRcvdOK = TRUE;					
					}				
					
					strcat(ptr,szECRReceiveBuf);
					memset(szECRReceiveBuf,0x00,sizeof(szECRReceiveBuf));
					inCounter++;
				} 

				if (fRcvdOK)
					break;
				
			}
		}

		if (fRcvdOK)
		{
			inRet = inGetResultCode(ptr, GET_PAYMENT_SIGNATURE);
			vdDebug_LogPrintf("GET_PAYMENT_SIGNATURE inGetResultCode %d",inRet);
			if(inRet == d_OK)
			{
				inRet = inExtractSignature((unsigned char *) ptr,signPtr,"signatureImage");
				if(inRet != d_OK)
					vdDisplayErrorMsgResp2("SIGNATURE","EXTRACTION","FAILED");	
				else
				{
					vdFormatBase64Response(signPtr,ConvertedsignPtr);
					
					inRet = inConvertToPNG(ConvertedsignPtr);
					if(inRet != d_OK)
						vdDisplayErrorMsgResp2("","IMAGE CONVERSION","FAILED");					
				}
			}
			else
				srTransRec.fSignPadBypassSignature = TRUE;
				
		}
		
	}
//GET PAYMENT SIGNATURE END

	free(ptr);
	free(signPtr);
	free(ConvertedsignPtr);
	
	return inRet;
}

void vdGetDCCSignatureFilename(char *ptrNewFilename)
{
	char szNewFileName[24+1];
    char szInvoiceNo[6+1];
    
    memset(szInvoiceNo, 0x00, sizeof(szInvoiceNo));
    wub_hex_2_str(srTransRec.szInvoiceNo, szInvoiceNo, INVOICE_BCD_SIZE);
    
    memset(szNewFileName, 0x00, sizeof(szNewFileName));
    sprintf(szNewFileName, "signDCC%06ld.png", atol(szInvoiceNo));
	memcpy(ptrNewFilename, szNewFileName, strlen(szNewFileName));
}

void vdLinuxCommandClearDCCPNG(void)
{
    char szSystemCmdPath[128+1];

	memset(szSystemCmdPath, 0x00, sizeof(szSystemCmdPath));
	strcpy(szSystemCmdPath, "rm signDCC*.png");
	system(szSystemCmdPath);
}

#endif


