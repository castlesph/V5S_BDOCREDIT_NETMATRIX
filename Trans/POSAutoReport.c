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
#include "..\Includes\POSAutoReport.h"
#include "..\Includes\POSbatch.h"
#include "..\ui\Display.h"
#include "..\Includes\V5IsoFunc.h"
#include "..\Accum\Accum.h"
#include "..\print\Print.h"
#include "..\Comm\V5Comm.h"
#include "..\Includes\MultiApLib.h"
#include "..\Aptrans\MultiAptrans.h"
#include "../Includes/wub_lib.h"
#include "..\database\par.h"
#include "..\Includes\POSAutoReport.h"

extern int inHDTRead(int inSeekCnt);
extern int inCSTRead(int inSeekCnt);
extern int inCPTRead(int inSeekCnt);
extern int inPARSave(int inSeekCnt);

int inCTOS_AutoReportFlowProcess(void)
{
    int inRet = d_NO;

    USHORT ushEMVtagLen;
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];


    vdCTOS_SetTransType(POS_AUTO_REPORT);

    //display title
    vdDispTransTitle(POS_AUTO_REPORT);


    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;

	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;

    inRet = inCTOS_SelectAutoReportHost();
    if(d_OK != inRet)
        return inRet;
    


 
    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_POS_AUTO_REPORT);
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


    inRet = inCTOS_GetPOSAutoReportData();
     if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_PreConnect();
    if(d_OK != inRet)
        return inRet;

    inRet = inBuildAndSendIsoData();
    if(d_OK != inRet)
        return inRet;



    return d_OK;
}


int inCTOS_SelectAutoReportHost(void) 
{
    short shGroupId ;
    int inHostIndex;
    short shCommLink;
    int inCurrencyIdx=0;
	char szStr[16+1]={0};


    inHostIndex =  1;
    
     vdDebug_LogPrintf("inCTOS_SelectHost =[%d]",inHostIndex);
    
    // if (inMultiAP_CheckSubAPStatus() == d_OK)
    //    return d_OK;
     
    if ( inHDTRead(inHostIndex) != d_OK)
    {
        //vdSetErrorMessage("HOST SELECTION ERR");
		inHDTReadData(inHostIndex);
		strcpy(szStr,strHDT_Temp.szHostLabel);
		memset(strHDT_Temp.szHostLabel,0x00,16+1);
		sprintf(strHDT_Temp.szHostLabel," %s ",szStr);
		vdDisplayErrorMsgResp2(strHDT_Temp.szHostLabel, "TRANSACTION", "NOT ALLOWED");
        return(d_NO);
    } 
    else 
    {
        
        srTransRec.HDTid = inHostIndex;

        inCurrencyIdx = strHDT.inCurrencyIdx;

        if (inCSTRead(inCurrencyIdx) != d_OK) 
        {
            
            vdSetErrorMessage("LOAD CST ERR");
            return(d_NO);
        }


        if ( inCPTRead(inHostIndex) != d_OK)
        {
            
            vdSetErrorMessage("LOAD CPT ERR");
            return(d_NO);
        }


        return (d_OK);
    }
}


int inCTOS_GetPOSAutoReportData(void){


	inPARRead(1);
 
	memcpy(strHDT.szTPDU,strPAR.szPARTPDU,5);

	vdDebug_LogPrintf("gladytest strHDT.szTPDU - %s", strHDT.szTPDU);

	strcpy(srTransRec.szTID, strPAR.szPARTID);
   	strcpy(srTransRec.szMID, strPAR.szPARMID);
	
    	return d_OK;

}


int inCTOS_POS_AUTO_REPORT(void)
{
	int inRet = d_NO;
	CTOS_RTC SetRTC;
	BYTE szCurrDate[9] = {0};


	//POS auto report: check if enabled, if not then exit - start -- jzg
	memset(szCurrDate, 0x00, sizeof(szCurrDate));
	CTOS_RTCGet(&SetRTC);
	sprintf(szCurrDate,"%02d-%02d-%02d", SetRTC.bYear, SetRTC.bMonth, SetRTC.bDay);

	inRet = inCTOS_GetPOSAutoReportData();
	if (d_OK != inRet)
		return inRet;

	if ((strPAR.fPAREnable != TRUE) || (strcmp(strPAR.szPARLastLogonDate, szCurrDate) == 0))
		return d_OK;
	//POS auto report: check if enabled, if not then exit - end -- jzg


	CTOS_LCDTClearDisplay();

	vdCTOS_TxnsBeginInit();

	inRet = inCTOS_AutoReportFlowProcess();
	if (inRet == d_OK)
	{
		vdDebug_LogPrintf("inCTOS_POS_AUTO_REPORT::save");
		memset(strPAR.szPARLastLogonDate, 0, sizeof(strPAR.szPARLastLogonDate));
		memcpy(strPAR.szPARLastLogonDate, szCurrDate, strlen(szCurrDate));
		vdDebug_LogPrintf("Last logon date 2 = [%s]", strPAR.szPARLastLogonDate);
		inPARSave(1);
	}

	inCTOS_inDisconnect();

	vdCTOS_TransEndReset();

	return inRet;
}

