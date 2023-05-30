
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <ctosapi.h>

#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <signal.h>
#include <pthread.h>
#include <sys/shm.h>
#include <linux/errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include "..\includes\LocalAptrans.h"
#include "..\Includes\POSTypedef.h"
#include "..\Includes\POSTrans.h"
#include "..\Debug\Debug.h"
#include "..\UI\Display.h"
#include "..\Database\DatabaseFunc.h"
#include "..\includes\LocalFunc.h"
#include "..\powrfail\POSPOWRFAIL.h"

#include <sqlite3.h>

extern BOOL fBDOOptOutHostEnabled;

int inCTOS_LocalAPSaveData(void)
{
	BYTE bret;
	
	inTCTSave(1);
	bret= inLocalAP_Database_BatchDelete();
	vdDebug_LogPrintf("inLocalAP_Database_BatchDelete,bret=[%d]", bret);
	if(d_OK != bret)
	{
		vdSetErrorMessage("LocalAP BatchDelete ERR");
    	return bret;
	}
	
	bret = inLocalAP_Database_BatchInsert(&srTransRec);
	vdDebug_LogPrintf("inLocalAP_Database_BatchInsert=[%d]", bret);
	if(d_OK != bret)
	{
		vdSetErrorMessage("LocalAP BatchInsert ERR");
    	return bret;
	}

	return d_OK;
}

int inCTOS_LocalAPGetData(void)
{
    BYTE bret;
    
    vdDebug_LogPrintf("inCTOS_LocalAPGetData-----");
    
    inDatabase_TerminalOpenDatabaseEx(DB_LOCALAP);
    
    bret = inLocalAP_Database_BatchRead(&srTransRec);
    vdDebug_LogPrintf("inLocalAP_Database_BatchReadbret=[%d]", bret);
    if(d_OK != bret)
    {
        inDatabase_TerminalCloseDatabase();
        vdSetErrorMessage("LocalAP BatchRead ERR");
        return bret;
    }

    bret= inLocalAP_Database_BatchDelete();
    vdDebug_LogPrintf("inLocalAP_Database_BatchDelete,bret=[%d]", bret);
    if(d_OK != bret)
    {
        inDatabase_TerminalCloseDatabase();
        vdSetErrorMessage("LocalAP Batch Delete ERR");
        return bret;
    }

    inDatabase_TerminalCloseDatabase();
	return d_OK;
}

int inCTOS_LocalAPReloadTable(void)
{
	short shGroupId ;
    int inHostIndex;
    short shCommLink;
	int inCurrencyIdx=0;
	char szStr[16+1]={0};
	
	vdDebug_LogPrintf("inCTOS_LocalAPReloadTable-CDTid[%d]--IITid[%d]--",srTransRec.CDTid,srTransRec.IITid);

	inDatabase_TerminalOpenDatabase();
	
	if (srTransRec.CDTid > 0)
	{
		if(inCDTReadEx(srTransRec.CDTid) != d_OK)
		{
			vdSetErrorMessage("LOAD CDT ERROR");
			return(d_NO);
	    }
	}

 	if (srTransRec.IITid > 0) 
 	{
    	//inGetIssuerRecord(srTransRec.IITid);
		if(inIITReadEx(srTransRec.IITid) != d_OK)
		{
			inDatabase_TerminalCloseDatabase();
			vdSetErrorMessage("LOAD IIT ERROR");
			return(d_NO);
	    }
 	}

	if(fBDOOptOutHostEnabled == TRUE){
		 if (srTransRec.byTransType == SALE_OFFLINE)
		 	strCDT.HDTid = BDO_COMPLETION_OPTOUT_HDT_INDEX;
		 else 	
			strCDT.HDTid = BDO_OPTOUT_HDT_INDEX;
	}else
		strCDT.HDTid = BDO_HDT_INDEX;
	
    inHostIndex = (short) strCDT.HDTid;
	
    vdDebug_LogPrintf("inCTOS_SelectHost =[%d],HDTid=[%d]",inHostIndex,strCDT.HDTid); 
    if(inHDTReadEx(inHostIndex) != d_OK)
    {
        //vdDisplayErrorMsg(1, 8, "HOST SELECTION ERR");
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
        srTransRec.HDTid = inHostIndex;
        inCurrencyIdx = strHDT.inCurrencyIdx;
        
        if (inCSTReadEx(inCurrencyIdx) != d_OK)
        {	
            inDatabase_TerminalCloseDatabase();
            vdDisplayErrorMsg(1, 8, "CST ERR");  
            return(d_NO);
        }
		
        if(strTCT.fSingleComms == TRUE)
			inHostIndex=1;
		
        if ( inCPTReadEx(inHostIndex) != d_OK)
        {
            inDatabase_TerminalCloseDatabase();
            vdDisplayErrorMsg(1, 8, "CPT ERR");
            return(d_NO);
        }
        inDatabase_TerminalCloseDatabase();
    }

	return (d_OK);
}


int inCTOS_LocalAPReloadTableEx(void)
{
	short shGroupId ;
    int inHostIndex;
    short shCommLink;
	int inCurrencyIdx=0;
	char szStr[16+1]={0};
	
	vdDebug_LogPrintf("inCTOS_LocalAPReloadTable-CDTid[%d]--IITid[%d]--",srTransRec.CDTid,srTransRec.IITid);

	inDatabase_TerminalOpenDatabase();
	
	if (srTransRec.CDTid > 0)
	{
		if(inCDTReadEx(srTransRec.CDTid) != d_OK)
		{
			vdSetErrorMessage("LOAD CDT ERROR");
			return(d_NO);
	    }
	}

 	if (srTransRec.IITid > 0) 
 	{
    	//inGetIssuerRecord(srTransRec.IITid);
		if(inIITReadEx(srTransRec.IITid) != d_OK)
		{
			inDatabase_TerminalCloseDatabase();
			vdSetErrorMessage("LOAD IIT ERROR");
			return(d_NO);
	    }
 	}

	if(fBDOOptOutHostEnabled == TRUE){
		//strCDT.HDTid = BDO_OPTOUT_HDT_INDEX;	
		if (srTransRec.byTransType == SALE_OFFLINE)
		   strCDT.HDTid = BDO_COMPLETION_OPTOUT_HDT_INDEX;
		else   
		   strCDT.HDTid = BDO_OPTOUT_HDT_INDEX;
	}else
		strCDT.HDTid = BDO_HDT_INDEX;
	
    inHostIndex = (short) strCDT.HDTid;
	
    vdDebug_LogPrintf("inCTOS_SelectHost =[%d],HDTid=[%d]",inHostIndex,strCDT.HDTid); 
    if(inHDTReadEx(inHostIndex) != d_OK)
    {
        //vdDisplayErrorMsg(1, 8, "HOST SELECTION ERR");
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
        srTransRec.HDTid = inHostIndex;
        inCurrencyIdx = strHDT.inCurrencyIdx;
        
        if (inCSTReadEx(inCurrencyIdx) != d_OK)
        {	
            inDatabase_TerminalCloseDatabase();
            vdDisplayErrorMsg(1, 8, "CST ERR");  
            return(d_NO);
        }
		
        if(strTCT.fSingleComms == TRUE)
			inHostIndex=1;
		
        if ( inCPTReadEx(inHostIndex) != d_OK)
        {
            inDatabase_TerminalCloseDatabase();
            vdDisplayErrorMsg(1, 8, "CPT ERR");
            return(d_NO);
        }
        inDatabase_TerminalCloseDatabase();
    }

	return (d_OK);
}

