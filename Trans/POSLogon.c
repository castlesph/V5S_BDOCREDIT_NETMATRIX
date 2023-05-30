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



int inCTOS_LogonFlowProcess(void)
{
    int inRet = d_NO;

    USHORT ushEMVtagLen;
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];




    vdCTOS_SetTransType(LOG_ON);
    
    //display title
    vdDispTransTitle(LOG_ON);
    
    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;

	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;

	//inRet = inCTOS_SelectLogonIIT();
	//if(d_OK != inRet)
    //    return inRet;

	//	inRet = inCTOS_SeletLogonPIT();
	//		if(d_OK != inRet)
    //    return inRet;

    inRet = inCTOS_SelectDebitHost();
    if(d_OK != inRet)
        return inRet;


    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_LOGON);
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
	//inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid); moved inside inCTOS_SelectDebitHost

	//inFirstInitConnectFuncPoint();
		
    inRet = inCTOS_PreConnect();
    if(d_OK != inRet)
        return inRet;
		
    inRet = inCTOS_CheckIssuerEnable();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_CheckTranAllowd();
    if(d_OK != inRet)
        return inRet;

    inRet = inBuildAndSendIsoData();
    if(d_OK != inRet){

				// sidumili: delete created reversal
			  inMyFile_ReversalDelete();
				
        return inRet;
    }

		//sidumili
		vdDisplayMessage("LOGON", "SUCCESSFUL", "");

    return d_OK;
}


int inCTOS_SelectDebitHost(void) 
{
    short shGroupId ;
    int inHostIndex;
    short shCommLink;
    int inCurrencyIdx=0;
	char szDebug[40]={0};
	char szStr[16+1]={0};


    inHostIndex =  53;
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
		
		vdDebug_LogPrintf("inCTOS_SelectHost =[%d]",srTransRec.HDTid);

        inCurrencyIdx = strHDT.inCurrencyIdx;

        if (inCSTReadEx(inCurrencyIdx) != d_OK) 
        {
            inDatabase_TerminalCloseDatabase();
            vdSetErrorMessage("LOAD CST ERR");
            return(d_NO);
        }

        if(strTCT.fSingleComms) 
           inHostIndex=1;
		
        if(inCPTReadEx(inHostIndex) != d_OK)
        {
            inDatabase_TerminalCloseDatabase();
            vdSetErrorMessage("LOAD CPT ERR");
            return(d_NO);
        }

        inMMTReadRecordEx(srTransRec.HDTid,srTransRec.MITid);
		
        inDatabase_TerminalCloseDatabase();
        return (d_OK);
    }
}

int inCTOS_LOGON(void)
{
    int inRet = d_NO;
		int result;
    
    CTOS_LCDTClearDisplay();

    vdCTOS_TxnsBeginInit();
    
    inRet = inCTOS_LogonFlowProcess();

    inCTOS_inDisconnect();

    vdCTOS_TransEndReset();

    return inRet;
}

int inCTOS_DoAutoLogon(void){

	int inRet;
	
	inDCTRead(srTransRec.HDTid,srTransRec.MITid);

  if (srTransRec.byTransType == SETTLE){
		strDCT.fDebitLogonRequired = VS_TRUE;
		inDCTSave(srTransRec.HDTid,srTransRec.MITid);
		
  }

	if(strDCT.fDebitLogonRequired == VS_FALSE)
		return d_OK;

	CTOS_LCDTClearDisplay();
	vdDispTransTitle(LOG_ON);

	
	setLCDPrint(3,DISPLAY_POSITION_LEFT, "LOGON REQUIRED");	
	setLCDPrint(4,DISPLAY_POSITION_LEFT, "ERROR CODE:81");	
	CTOS_Delay(1000);


	setLCDPrint(3,DISPLAY_POSITION_LEFT, "PLEASE WAIT...");	
	setLCDPrint(4,DISPLAY_POSITION_LEFT, "PROCESSING LOGON");	
	CTOS_Delay(1000);

	CTOS_LCDTClearDisplay();
	vdDispTransTitle(LOG_ON);
	
	inRet = inCTOS_LOGON();
		if(d_OK != inRet)
			return inRet;

  if(ST_SUCCESS != inRet){	
		strDCT.fDebitLogonRequired = VS_TRUE;	
		inDCTSave(srTransRec.HDTid,srTransRec.MITid);
		return inRet;
  }

	strDCT.fDebitLogonRequired = VS_FALSE;

	inDCTSave(srTransRec.HDTid,srTransRec.MITid);
		
	return d_OK;
}

//sidumili: [LOAD IIT TABLE FOR LOGON TRXN]
int inCTOS_SelectLogonIIT(void){
	int inRet = d_OK;
	int inIITId;

	inIITId = 1;
	
	inRet = inGetIssuerRecord(inIITId);

	if (inRet != d_OK)
		return(inRet);
	
  return d_OK;
}


int inCTOS_SeletLogonPIT(void){
	int inRet = d_OK;
	int inTxnTypeID;

	inTxnTypeID = srTransRec.byTransType;

	inRet = inPITRead(inTxnTypeID);

	if (inRet != d_OK)
		return(inRet);
	
  return d_OK;
	
}
