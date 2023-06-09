
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

#include "POSFunctionsList.h"
#include "..\Includes\POSTypedef.h"

#include <ctosapi.h>
#include <semaphore.h>
#include <pthread.h>

#include "..\Includes\POSTypedef.h"
#include "..\Includes\POSSetting.h"
#include "..\Includes\POSAuth.h"
#include "..\Includes\POSConfig.h"
#include "..\Includes\POSOffline.h"
#include "..\Includes\POSRefund.h"
#include "..\Includes\POSSale.h"
#include "..\Includes\POSVoid.h"
#include "..\Includes\POSTipAdjust.h"
#include "..\Includes\POSVoid.h"
#include "..\Includes\POSBatch.h"
#include "..\Includes\POSSettlement.h"
#include "..\Includes\POSReload.h"
#include "..\Includes\POSTrans.h"


/* BDO CLG: Fleet card support -- jzg */
#include "..\Includes\POSFleet.h"


#include "..\Includes\CTOSInput.h"

#include "..\ui\Display.h"
#include "..\print\print.h"
#include "..\Debug\Debug.h"
#include "..\Includes\DMenu.h"
#include "..\Ctls\POSWave.h"


/*gcitra*/
#include "..\Includes\POSBinVer.h"
#include "..\Includes\POSAutoReport.h"
/*gcitra*/

//gcitra-0728
#include "..\Includes\POSInstallment.h"
#include "..\Includes\POSLogon.h"
#include "..\Includes\POSBalanceInq.h"
#include "..\Includes\POSCashAdvance.h"

//gcitra-0728

#include "..\FileModule\myFileFunc.h"

//SMAC
#include "..\Includes\POSSmac.h"
//SMAC

#include "..\TMS\TMS.h" //aaronnino for remote download setup 7 of 12

#include "..\Aptrans\MultiAptrans.h"
#include "..\Includes\POSDCC.h"

extern char szGlobalAPName[25];

extern TRANS_DATA_TABLE* srGetISOEngTransDataAddress(void);

#define MAXFUNCTIONS 		2048
//version16
BOOL fSmacScan = FALSE;

//verison16

// can declare any functions type and link with string.
Func_vdFunc stFunctionList_vdFunc[] = {
	{"inCTOS_SALE_OFFLINE", inCTOS_SALE_OFFLINE},
	{"inCTOS_WAVE_SALE", inCTOS_WAVE_SALE},
	{"inCTOS_WAVE_REFUND", inCTOS_WAVE_REFUND},
	{"vdCTOS_InitWaveData", (DMENU_FUN)vdCTOS_InitWaveData},
	{"inCTOS_VOID", inCTOS_VOID},
	{"inCTOS_SETTLEMENT", inCTOS_SETTLEMENT},
	{"inCTOS_SETTLE_ALL", inCTOS_SETTLE_ALL},
	{"inCTOS_PREAUTH", inCTOS_PREAUTH},
	{"inCTOS_REFUND", inCTOS_REFUND},
	{"inCTOS_TIPADJUST", inCTOS_TIPADJUST},
	{"inCTOS_BATCH_REVIEW", inCTOS_BATCH_REVIEW},
	{"inCTOS_BATCH_TOTAL", inCTOS_BATCH_TOTAL},
	{"inCTOS_REPRINT_LAST", inCTOS_REPRINT_LAST},
	{"inCTOS_REPRINT_ANY", inCTOS_REPRINT_ANY},
	{"inCTOS_REPRINTF_LAST_SETTLEMENT", inCTOS_REPRINTF_LAST_SETTLEMENT},
		
	{"inCTOS_PRINT_SUMMARY_ALL", inCTOS_PRINT_SUMMARY_ALL},
	{"inCTOS_PRINTF_SUMMARY", inCTOS_PRINTF_SUMMARY},
  {"inCTOS_PRINT_DETAIL_ALL", inCTOS_PRINT_DETAIL_ALL},
	{"inCTOS_PRINTF_DETAIL", inCTOS_PRINTF_DETAIL},
		
	{"inCTOS_REPRINT_LAST", inCTOS_REPRINT_LAST},
	{"inCTOS_REPRINT_ANY", inCTOS_REPRINT_ANY},
	{"inCTOS_REPRINTF_LAST_SETTLEMENT", inCTOS_REPRINTF_LAST_SETTLEMENT},
	{"inCTOS_Reprint_Settle_Selection", inCTOS_Reprint_Settle_Selection},
	{"vdCTOS_uiPowerOff", (DMENU_FUN)vdCTOS_uiPowerOff},
	{"vdCTOS_IPConfig", (DMENU_FUN)vdCTOS_IPConfig},
	{"vdCTOS_DialConfig", (DMENU_FUN)vdCTOS_DialConfig},
	{"vdCTOS_ModifyEdcSetting", (DMENU_FUN)vdCTOS_ModifyEdcSetting},
	{"vdCTOS_GPRSSetting", (DMENU_FUN)vdCTOS_GPRSSetting},
	{"vdCTOS_DeleteBatch", (DMENU_FUN)vdCTOS_DeleteBatch},
	{"vdCTOS_PrintEMVTerminalConfig", (DMENU_FUN)vdCTOS_PrintEMVTerminalConfig},
	{"vdCTOS_TipAllowd", (DMENU_FUN)vdCTOS_TipAllowd},
	{"vdCTOS_Debugmode", (DMENU_FUN)vdCTOS_Debugmode},
	{"vdCTOSS_CtlsMode", (DMENU_FUN)vdCTOSS_CtlsMode},
	{"vdCTOS_DemoMode", (DMENU_FUN)vdCTOS_DemoMode},	
	{"vdCTOSS_DownloadMode", (DMENU_FUN)vdCTOSS_DownloadMode},	
	{"vdCTOSS_CheckMemory", (DMENU_FUN)vdCTOSS_CheckMemory},	
	{"CTOSS_SetRTC", (DMENU_FUN)CTOSS_SetRTC},	
	//gcitra
	{"inCTOS_BINCHECK", (DMENU_FUN)inCTOS_BINCHECK},	
	{"inCTOS_POS_AUTO_REPORT", (DMENU_FUN)inCTOS_POS_AUTO_REPORT},	
	{"inCTOS_SALE", (DMENU_FUN)inCTOS_SALE},
	{"inCTOS_BALANCE_INQUIRY", inCTOS_BALANCE_INQUIRY},
	{"inCTOS_LOGON",inCTOS_LOGON},
	{"inCTOS_CASH_ADVANCE",inCTOS_CASH_ADVANCE},

//gcitra-0728
	{"inCTOS_INSTALLMENT", (DMENU_FUN)inCTOS_INSTALLMENT},	
	{"inCTOS_INSTBINCHECK",inCTOS_INSTBINCHECK},
//gcitra-0728
	//gcitra
	{"vdCTOS_DeleteReversal", (DMENU_FUN)vdCTOS_DeleteReversal},
	/*albert - start - Aug2014 - manual settlement*/	
    {"inCTOS_ManualSettle", (DMENU_FUN)inCTOS_ManualSettle},
	/*albert - end - Aug2014 - manual settlement*/
	{"vdCTOSS_InjectMKKey", (DMENU_FUN)vdCTOSS_InjectMKKey}, // Inject Key
	{"vdCTOS_HostInfo", (DMENU_FUN)vdCTOS_HostInfo},	
	{"inCTOS_RELOAD", inCTOS_RELOAD},	
	{"vdCTOS_PrintCRC",(DMENU_FUN)vdCTOS_PrintCRC},
	{"vdCTOS_PrintRS232Report",(DMENU_FUN)vdCTOS_PrintRS232Report},

		/*sidumili: [prompt for password]*/
	{"inCTOS_PromptPassword", inCTOS_PromptPassword},
	
	//BDO UAT 0007: Change comms shortcut - start -- jzg
	{"vdChangeComms", (DMENU_FUN)vdChangeComms},

	//BDO: [Select Telco Setting] -- sidumili
	{"inSelectTelcoSetting", (DMENU_FUN)inSelectTelcoSetting},

	/* BDO CLG: Revised menu functions -- jzg */
	{"vdCTOS_FunctionKey", vdCTOS_FunctionKey},

	//0722
	{"vdEditSTAN", vdEditSTAN},
	//0722

	{"inCTOS_FLEET", inCTOS_FLEET}, /* BDO CLG: Fleet card support -- jzg */

	{"vdCTOS_ThemesSetting", (DMENU_FUN)vdCTOS_ThemesSetting},
	{"vdCTOSS_EditTable", (DMENU_FUN)vdCTOSS_EditTable},
//SMAC
	{"inCTOS_SMACLOGON",inCTOS_SMACLOGON},
	{"inCTOS_SMACAward",inCTOS_SMACAward},
	{"inCTOS_SMACRedeem",inCTOS_SMACRedeem},	
	{"inCTOS_SMACBalanceInq",inCTOS_SMACBalanceInq},
//SMAC

	//wifi-mod2
	{"WIFI_Scan", WIFI_Scan},
	//wifi-mod2

	//aaronnino for remote download setup 8 of 12 start
	{"inCTOSS_TMSDownloadRequest", (DMENU_FUN)inCTOSS_TMSDownloadRequest},
    {"vdCTOS_TMSSetting", (DMENU_FUN)vdCTOS_TMSSetting},
    //aaronnino for remote download setup 8 of 12 end

	{"vdCTOSS_PrintTerminalConfig", (DMENU_FUN)vdCTOSS_PrintTerminalConfig},
	{"vdCTOSS_SelectPinpadType", (DMENU_FUN)vdCTOSS_SelectPinpadType},
	{"vdCTOS_EditEnvParam", (DMENU_FUN)vdCTOS_EditEnvParamDB},

	{"inCTOS_SETTLE_ALL_MERCHANT", inCTOS_SETTLE_ALL_MERCHANT},
    {"szSetupMenuFunction",szSetupMenuFunction},
    {"inCTOS_Settle_Selection",inCTOS_Settle_Selection},
    
    {"inCTOS_PRINT_SUMMARY_SELECTION",inCTOS_PRINT_SUMMARY_SELECTION},
    {"inCTOS_PRINT_DETAIL_SELECTION",inCTOS_PRINT_DETAIL_SELECTION},
    {"vdSetECRConfig", (DMENU_FUN)vdSetECRConfig},
	{"vdCTOS_PrintIP",(DMENU_FUN)vdCTOS_PrintIP},
	{"vdCTOS_ISOLogger",(DMENU_FUN)vdCTOS_ISOLogger},

	/* SM: Revised menu functions */
	{"vdCTOS_SMFunctionKey", vdCTOS_SMFunctionKey},
	{"vdCTOS_SMHostInfo",vdCTOS_SMHostInfo},

	/*TBG APPLICATION*/
	{"inCTOS_CashBackMenu", inCTOS_CashBackMenu},
#if 1
	/*auto treats and reserve apps*/
	{"inAutoTreats", inAutoTreats},	
	{"inReserveApp1", inReserveApp1},
	{"inReserveApp2", inReserveApp2},
	{"inReserveApp3", inReserveApp3},
	{"inReserveApp4", inReserveApp4},
	{"inReserveApp5", inReserveApp5},
	{"inQRPAY", inQRPAY},
	{"inCTOS_Retrieve",inCTOS_Retrieve},
	{"inBDOPayMenu", inBDOPayMenu},
#endif		
	//adc
	{"vdCTOS_TMSRangeSetting",vdCTOS_TMSRangeSetting},
	//adc
	
	{"inCTOS_DCCOptOut", inCTOS_DCCOptOut},
	{"vdCTOS_PrintPreAuthReport", vdCTOS_PrintPreAuthReport},
	{"inCTOS_SMACKitSale",inCTOS_SMACKitSale},
	{"inCTOS_SMACRenewal",inCTOS_SMACRenewal},
	{"inCTOS_SMACPtsAwarding",inCTOS_SMACPtsAwarding},
	{"inBDOLoyaltyMenu",inBDOLoyaltyMenu}, // BDO Loyalty -- sidumili
#ifdef NETMATRIX
	{"inNetmatrixRKI",inNetmatrixRKI},
#endif
	{"", (DFUNCTION_LIST)NULL},
};

// can declare any functions type and link with string.
Func_inISOPack stFunctionList_inISOPack[] = {
	{"inPackIsoFunc02", inPackIsoFunc02},
	{"inPackIsoFunc03", inPackIsoFunc03},
	{"inPackIsoFunc04", inPackIsoFunc04},
	{"inPackIsoFunc06", inPackIsoFunc06},
	{"inPackIsoFunc07", inPackIsoFunc07},	
	{"inPackIsoFunc11", inPackIsoFunc11},
	{"inPackIsoFunc12", inPackIsoFunc12},
	{"inPackIsoFunc13", inPackIsoFunc13},
	{"inPackIsoFunc14", inPackIsoFunc14},
	{"inPackIsoFunc22", inPackIsoFunc22},
	{"inPackIsoFunc23", inPackIsoFunc23},
	{"inPackIsoFunc24", inPackIsoFunc24},
	{"inPackIsoFunc25", inPackIsoFunc25},
	{"inPackIsoFunc35", inPackIsoFunc35},
	{"inPackIsoFunc37", inPackIsoFunc37},
	{"inPackIsoFunc38", inPackIsoFunc38},
	{"inPackIsoFunc39", inPackIsoFunc39},
	{"inPackIsoFunc41", inPackIsoFunc41},
	{"inPackIsoFunc42", inPackIsoFunc42},
	{"inPackIsoFunc45", inPackIsoFunc45},
	{"inPackIsoFunc48", inPackIsoFunc48},
	{"inPackIsoFunc49", inPackIsoFunc49},
	{"inPackIsoFunc51", inPackIsoFunc51},
	{"inPackIsoFunc52", inPackIsoFunc52},
	{"inPackIsoFunc54", inPackIsoFunc54},
	{"inPackIsoFunc55", inPackIsoFunc55},
	{"inPackIsoFunc56", inPackIsoFunc56},
	{"inPackIsoFunc57", inPackIsoFunc57},
	{"inPackIsoFunc60", inPackIsoFunc60},
	{"inPackIsoFunc61", inPackIsoFunc61},
	{"inPackIsoFunc62", inPackIsoFunc62},
	{"inPackIsoFunc63", inPackIsoFunc63},
	{"inPackIsoFunc64", inPackIsoFunc64},
	{"", (DFUNCTION_inISOPack)NULL},
};

// can declare any functions type and link with string.
Func_inISOUnPack stFunctionList_inISOUnPack[] = {
	{"inUnPackIsoFunc02", inUnPackIsoFunc02},
	//SMAC
	{"inUnPackIsoFunc04", inUnPackIsoFunc04},
	//SAMC
	{"inUnPackIsoFunc12", inUnPackIsoFunc12},
	{"inUnPackIsoFunc13", inUnPackIsoFunc13},
	{"inUnPackIsoFunc37", inUnPackIsoFunc37},
	{"inUnPackIsoFunc38", inUnPackIsoFunc38},
	{"inUnPackIsoFunc39", inUnPackIsoFunc39},	
	{"inUnPackIsoFunc41", inUnPackIsoFunc41},
	{"inUnPackIsoFunc48", inUnPackIsoFunc48},
	{"inUnPackIsoFunc55", inUnPackIsoFunc55},
	{"inUnPackIsoFunc57", inUnPackIsoFunc57},
	{"inUnPackIsoFunc61", inUnPackIsoFunc61},	
	{"inUnPackBINVer63",  inUnPackBINVer63},
	{"inUnPackIsoFunc63", inUnPackIsoFunc63},
	{"inSMACUnPackIsoFunc60",inSMACUnPackIsoFunc60},
	{"inSMACUnPackIsoFunc61",inSMACUnPackIsoFunc61},
	{"", (DFUNCTION_inISOUnPack)NULL},
};

// can declare any functions type and link with string.
Func_inISOCheck stFunctionList_inISOCheck[] = {
	{"", (DFUNCTION_inISOCheck)NULL},
};

int inPOSFunctionList(void)
{		
}

int inCTOSS_ExeFunction(char *INuszFunctionName)
{
	int inDex, inRetVal = -1;

	 if (INuszFunctionName[0] == 0x00)
		 return inRetVal;

	 for (inDex = 0; inDex < MAXFUNCTIONS; ++inDex)
	 {
			if (stFunctionList_vdFunc[inDex].uszFunctionName[0]==0x00)
			{
		        vduiWarningSound();
				vduiDisplayStringCenter(7,INuszFunctionName);
				vduiDisplayStringCenter(8,"FUNCTION INVALID");
				break;
			}
			
			if (!strcmp((char *)INuszFunctionName, (char *)stFunctionList_vdFunc[inDex].uszFunctionName))
			{
			   vdDebug_LogPrintf("%s", INuszFunctionName); 	  			
			   inRetVal = stFunctionList_vdFunc[inDex].d_FunctionP();
			   break;
			}
	 }
	 return(inRetVal);
}

int inExeFunction_PackISO(char *INuszFunctionName, unsigned char *uszSendData)
{
	int inDex, inRetVal = ST_SUCCESS;
    TRANS_DATA_TABLE* srTransPara;

    srTransPara = srGetISOEngTransDataAddress();

	 if (INuszFunctionName[0] == 0x00)
		 return inRetVal;

	 for (inDex = 0; inDex < MAXFUNCTIONS; ++inDex)
	 {
		  if (stFunctionList_inISOPack[inDex].uszFunctionName[0]==0x00)
		  {
			  vduiWarningSound();
			  vduiDisplayStringCenter(7,INuszFunctionName);
			  vduiDisplayStringCenter(8,"FUNCTION INVALID");
			  break;
		  }
		  if (!strcmp((char *)INuszFunctionName, (char *)stFunctionList_inISOPack[inDex].uszFunctionName))
		  {
			   vdDebug_LogPrintf("%s", INuszFunctionName);		 
			   inRetVal = stFunctionList_inISOPack[inDex].d_FunctionP(srTransPara, uszSendData);
			   break;
		  }
	 }
	 return(inRetVal);
}

int inExeFunction_UnPackISO(char *INuszFunctionName, unsigned char *uszReceiveData)
{	
	int inDex, inRetVal = ST_SUCCESS;
    TRANS_DATA_TABLE* srTransPara;

    srTransPara = srGetISOEngTransDataAddress();

	if (INuszFunctionName[0] == 0x00)
		return inRetVal;
		
	 for (inDex = 0; inDex < MAXFUNCTIONS; ++inDex)
	 {
		  if (stFunctionList_inISOUnPack[inDex].uszFunctionName[0]==0x00)
		  {
			  vduiWarningSound();
			  vduiDisplayStringCenter(7,INuszFunctionName);
			  vduiDisplayStringCenter(8,"FUNCTION INVALID");
			  break;
		  }
		  if (!strcmp((char *)INuszFunctionName, (char *)stFunctionList_inISOUnPack[inDex].uszFunctionName))
		  {
			   vdDebug_LogPrintf("%s", INuszFunctionName);		  
			   inRetVal = stFunctionList_inISOUnPack[inDex].d_FunctionP(srTransPara, uszReceiveData);
			   break;
		  }
	 }
	 return(inRetVal);
}

int inExeFunction_CheckISO(char *INuszFunctionName, unsigned char *uszSendData, unsigned char *uszReceiveData)
{
	int inDex, inRetVal = ST_SUCCESS;
    TRANS_DATA_TABLE* srTransPara;
    
    srTransPara = srGetISOEngTransDataAddress();

	 if (INuszFunctionName[0] == 0x00)
		 return inRetVal;

	 for (inDex = 0; inDex < MAXFUNCTIONS; ++inDex)
	 {
		  if (stFunctionList_inISOCheck[inDex].uszFunctionName[0]==0x00)
		  {
			  vduiWarningSound();
			  vduiDisplayStringCenter(7,INuszFunctionName);
			  vduiDisplayStringCenter(8,"FUNCTION INVALID");
			  break;
		  }
		  if (!strcmp((char *)INuszFunctionName, (char *)stFunctionList_inISOCheck[inDex].uszFunctionName))
		  {
			   vdDebug_LogPrintf("%s", INuszFunctionName);		 		  
			   inRetVal = stFunctionList_inISOCheck[inDex].d_FunctionP(srTransPara, uszSendData, uszReceiveData);
			   break;
		  }
	 }
	 return(inRetVal);
}

//0722


void vdEditSTAN(void){

	vdSTANNo(TRUE);

 	return d_OK;

}

void vdSTANNo(BOOL fGetSTABNo)
{
    unsigned char chkey;
    short shHostIndex;
    int inResult,inRet;
    char szStr[d_LINE_SIZE + 1];
    BYTE key;
		ULONG ulTraceNo=0L;
		BYTE strOut[30];
		USHORT usLen=0;
    //by host and merchant
    shHostIndex = inCTOS_SelectHostSetting();
    if (shHostIndex == -1)
        return;
		CTOS_LCDTClearDisplay();
		vdDispTitleString("STAN NO.");

		CTOS_LCDTPrintXY(1, 3, "STAN NO.");

		ulTraceNo=wub_bcd_2_long(strHDT.szTraceNo,3); 
		memset(szStr, 0, sizeof(szStr));
		sprintf(szStr, "%06ld", ulTraceNo);
		CTOS_LCDTPrintXY(1, 4, szStr);

    if(fGetSTABNo == FALSE) 
        CTOS_KBDGet(&key);
		else
		{
        while(1)
        {   
            CTOS_LCDTPrintXY(1, 7, "New:");
            memset(strOut,0x00, sizeof(strOut));
            inRet= shCTOS_GetNum(8, 0x01,  strOut, &usLen, 1, 6, 0, d_INPUT_TIMEOUT);
            if (inRet == d_KBD_CANCEL )
                break;
            else if(0 == inRet )
                break;
            else if(inRet>=1)
            {
                ulTraceNo=atoi(strOut);
								memset(szStr, 0, sizeof(szStr));
								sprintf(szStr, "%06ld", ulTraceNo);
								inAscii2Bcd(szStr, strHDT.szTraceNo, 3);
								inHDTSave(shHostIndex);
                break;
            }   
            if(inRet == d_KBD_CANCEL)
                break;
        } 
		}
}

//wifi-mod2
int WIFI_Scan(void){

	CTOS_LCDTClearDisplay();


	CTOS_LCDTPrintXY(1, 4, "Scanning for WIFI");
	
	CTOS_LCDTPrintXY(1, 5, "Please wait...");

	if(strCPT.inCommunicationMode == WIFI_MODE)
	{
		inCTOSS_COMMWIFISCAN();
		srTransRec.usTerminalCommunicationMode = strCPT.inCommunicationMode;
		if (inCTOS_InitComm(srTransRec.usTerminalCommunicationMode) != d_OK) 
		{
			//vdDisplayErrorMsg(1, 8, "COMM INIT ERR");
			//vdDisplayErrorMsgResp2(" ", " ", "COMM INIT ERR");
			vdDisplayErrorMsgResp2("WIFI","Initialization","Error");
			return;
		}				
	}
}


//0722

void vdCTOSS_PrintTerminalConfig(void)
{
    CTOS_LCDTClearDisplay();
    vdPrintTerminalConfig();
    
    return;
}

void vdCTOSS_SelectPinpadType(void)
{
    BYTE bRet;
    BYTE szInputBuf[15+1];
    int inResult,inResult1;
    TRANS_TOTAL stBankTotal;
    BYTE strOut[30],strtemp[17],key;
    USHORT ret;
    USHORT usLen;
    BYTE szTempBuf[12+1];
    BOOL isKey;
    int shHostIndex = 1;
    int inNum = 0;
    int inRet = 0;

    inRet = inTCTRead(1);  
    vdDebug_LogPrintf(". inTCTRead(%d)",inRet);

    CTOS_LCDTClearDisplay();
    vdDispTitleString("SETTING");
    while(1)
    {
        clearLine(3);
        clearLine(4);
        clearLine(5);
        clearLine(6);
        clearLine(7);
        clearLine(8);
        setLCDPrint(3, DISPLAY_POSITION_LEFT, "PINPAD TYPE");
        if(strTCT.byPinPadType == 0)
            setLCDPrint(4, DISPLAY_POSITION_LEFT, "0");
        if(strTCT.byPinPadType == 1)
            setLCDPrint(4, DISPLAY_POSITION_LEFT, "1");        
        if(strTCT.byPinPadType == 2)
            setLCDPrint(4, DISPLAY_POSITION_LEFT, "2");
		if(strTCT.byPinPadType == 3)
            setLCDPrint(4, DISPLAY_POSITION_LEFT, "3");
  
        
        CTOS_LCDTPrintXY(1, 5, "0-None	1-PCI100");
        CTOS_LCDTPrintXY(1, 6, "2-OTHER 3-V3P");
        
        strcpy(strtemp,"New:") ;
        CTOS_LCDTPrintXY(1, 7, strtemp);
        memset(strOut,0x00, sizeof(strOut));
        ret= shCTOS_GetNum(8, 0x01,  strOut, &usLen, 1, 1, 0, d_INPUT_TIMEOUT);
        if (ret == d_KBD_CANCEL )
            break;
        else if(0 == ret )
            break;
        else if(ret==1)
        {
            if (strOut[0]==0x30 || strOut[0]==0x31 || strOut[0]==0x32 || strOut[0]==0x33)
            {
                 if(strOut[0] == 0x31)
                 {
                        strTCT.byPinPadType = 1;
                 }
                 if(strOut[0] == 0x30)
                 {
                        strTCT.byPinPadType = 0;
                 }
                 if(strOut[0] == 0x32)
                 {
                        strTCT.byPinPadType = 2;
                 }
				 if(strOut[0] == 0x33)
                 {
                        strTCT.byPinPadType = 3;
                 }
 
                
                 inRet = inTCTSave(1);
                 
                 vdDebug_LogPrintf(". inTCTSave(%d)",inRet);
                 break;
             }
             else
             {
                vduiWarningSound();
                vduiDisplayStringCenter(6,"PLEASE SELECT");
                vduiDisplayStringCenter(7,"A VALID");
                vduiDisplayStringCenter(8,"PINPAD TYPE");
                CTOS_Delay(2000);       
            }
        }
        if (ret == d_KBD_CANCEL )
            break ;
    }
       
    return ;
}

int inCTOS_CashBackMenu(void)
{
   int inRet = 0;

   inRet = inCTOSS_CheckMemoryStatus();
	 if(d_OK != inRet)
        return inRet;

	 put_env_int("TBGAPPMENUID", strTCT.inMenuid);

   if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        inTCTRead(1);
        
        inRet = inCTOS_MultiSwitchApp("V5S_BDOTBG", d_IPC_CMD_TBG_APP);
        
        if(d_OK != inRet)
        {
           vdDebug_LogPrintf("inCTOS_CashBackMenu Credit inCTOS_MultiSwitchApp FAIL");
           return inRet;
        }
    }
	  else
    {
        inTCTRead(1);
        if((strTCT.byTerminalType % 2) == 0)
        {
            CTOS_LCDForeGndColor(RGB(13, 43, 112));
            CTOS_LCDBackGndColor(RGB(255, 255, 255));
        }        
        inF1KeyEvent();
    }

    return d_OK;
}

int inAutoTreats(void)
{
   	int inRet = 0;

   	inRet = inCTOSS_CheckMemoryStatus();
	if(d_OK != inRet)
        return inRet;

   inRet = inCTOS_MultiSwitchApp("V3_AUTOTREATS", d_IPC_CMD_AUTOTREATS);
   
   if(d_OK != inRet)
   {
	  vdDebug_LogPrintf("inAutoTreats FAIL");
	  return inRet;
   }


    return d_OK;
}


int inReserveApp1(void)
{
   	int inRet = 0;
	char szAppName[30];

   	inRet = inCTOSS_CheckMemoryStatus();
	if(d_OK != inRet)
        return inRet;

   memset(szAppName, 0x00, sizeof(szAppName));

   inCTOSS_GetEnvDB("RESAPP1", szAppName);

   vdDebug_LogPrintf("inReserveApp1 APPNAME %s", szAppName);

   inRet = inCTOS_MultiSwitchApp(szAppName, d_IPC_CMD_RESERVE_APP1);
   
   if(d_OK != inRet)
   {
	  vdDebug_LogPrintf("reserve app 1 FAIL");
	  return inRet;
   }


    return d_OK;
}


int inReserveApp2(void)
{
   	int inRet = 0;
	char szAppName[30];

   	inRet = inCTOSS_CheckMemoryStatus();
	if(d_OK != inRet)
        return inRet;

   memset(szAppName, 0x00, sizeof(szAppName));

   inCTOSS_GetEnvDB("RESAPP2", szAppName);

   inRet = inCTOS_MultiSwitchApp(szAppName, d_IPC_CMD_RESERVE_APP2);
   
   if(d_OK != inRet)
   {
	  vdDebug_LogPrintf("reserve app 2 FAIL");
	  return inRet;
   }


    return d_OK;
}


int inReserveApp3(void)
{
   	int inRet = 0;
	char szAppName[30];

   	inRet = inCTOSS_CheckMemoryStatus();
	if(d_OK != inRet)
        return inRet;

   memset(szAppName, 0x00, sizeof(szAppName));

   inCTOSS_GetEnvDB("RESAPP3", szAppName);

   inRet = inCTOS_MultiSwitchApp(szAppName, d_IPC_CMD_RESERVE_APP3);
   
   if(d_OK != inRet)
   {
	  vdDebug_LogPrintf("reserve app 3 FAIL");
	  return inRet;
   }


    return d_OK;
}

int inReserveApp4(void)
{
   	int inRet = 0;
	char szAppName[30];

   	inRet = inCTOSS_CheckMemoryStatus();
	if(d_OK != inRet)
        return inRet;

   memset(szAppName, 0x00, sizeof(szAppName));

   inCTOSS_GetEnvDB("RESAPP4", szAppName);

   inRet = inCTOS_MultiSwitchApp(szAppName, d_IPC_CMD_RESERVE_APP4);
   
   if(d_OK != inRet)
   {
	  vdDebug_LogPrintf("reserve app 4 FAIL");
	  return inRet;
   }


    return d_OK;
}

int inReserveApp5(void)
{
   	int inRet = 0;
	char szAppName[30];

   	inRet = inCTOSS_CheckMemoryStatus();
	if(d_OK != inRet)
        return inRet;

   memset(szAppName, 0x00, sizeof(szAppName));

   inCTOSS_GetEnvDB("RESAPP5", szAppName);

   inRet = inCTOS_MultiSwitchApp(szAppName, d_IPC_CMD_RESERVE_APP5);
   
   if(d_OK != inRet)
   {
	  vdDebug_LogPrintf("reserve app 5 FAIL");
	  return inRet;
   }


    return d_OK;
}

//FOR QRPAY
int inQRPAY(void)
{
   	int inRet = 0;
	char szAppName[30];



   	inRet = inCTOSS_CheckMemoryStatus();
	if(d_OK != inRet)
        return inRet;
#if 0
   memset(szAppName, 0x00, sizeof(szAppName));
   strcpy(szAppName, "V3_QRPAY");


   vdDebug_LogPrintf("inReserveApp1 APPNAME %s", szAppName);

   inRet = inCTOS_MultiSwitchApp(szAppName, d_IPC_CMD_QRPAY);
   
   vdCTOS_TransEndReset();
   
   if(d_OK != inRet)
   {
	  vdDebug_LogPrintf("inQRPAY app FAIL");
	  return inRet;
   }
#else

	//testlang
	if (fGetECRTransactionFlg() == TRUE)
	 put_env_int("ECRQR",1);
	else
	 put_env_int("ECRQR",0);
	//testlang

	inRet = inQRAppSelection(PAYMENT);

	vdDebug_LogPrintf("inQRPAY inRet=[%d]",inRet);

	DebugAddHEX("inQRPAY BASE AMOUNT",srTransRec.szBaseAmount,AMT_BCD_SIZE);

    //version16
	if (inRet == SMAC_HDT_INDEX){
		fSmacScan = TRUE;
		
		vdDebug_LogPrintf("inQRPAY inRet == SMAC_HDT_INDEX");
		
		if (strTCT.fSMMode == TRUE)
			inCTOS_WAVE_SALE();
		else
			inCTOS_SMACRedeem();
		fSmacScan = FALSE;
	}
	
	put_env_int("ECRQR",0);

	if(d_OK != inRet)
    {
	  vdDebug_LogPrintf("inQRPAY app FAIL");
	  return inRet;
    }
#endif

    return d_OK;
}

int inCTOS_Retrieve(void)
{
   	int inRet = 0;
	char szAppName[30];



   	inRet = inCTOSS_CheckMemoryStatus();
	if(d_OK != inRet)
        return inRet;
#if 0
   memset(szAppName, 0x00, sizeof(szAppName));
   strcpy(szAppName, "V3_QRPAY");


   vdDebug_LogPrintf("inReserveApp1 APPNAME %s", szAppName);

   inRet = inCTOS_MultiSwitchApp(szAppName, d_IPC_CMD_RETRIEVE);
   
   if(d_OK != inRet)
   {
	  vdDebug_LogPrintf("reserve app FAIL");
	  return inRet;
   }
#else
	inRet = inQRAppSelection(RETRIEVE);
	if(d_OK != inRet)
	{
		vdDebug_LogPrintf("inQRPAY app FAIL");
		return inRet;
	}
#endif


    return d_OK;
}


int inBDOPayMenu(void)
{
   	int inRet = 0;
	char szAppName[30];	
	char szAmtBuff[AMT_ASC_SIZE+1];

	vdDebug_LogPrintf("inBDOPayMenu START");

   	inRet = inCTOSS_CheckMemoryStatus();
	if(d_OK != inRet)
        return inRet;

	
#if 1
   memset(szAppName, 0x00, sizeof(szAppName));
   strcpy(szAppName, "V3_QRPAY");

   vdDebug_LogPrintf("APPNAME %s COMMAND %d", szAppName, d_IPC_CMD_BDOPAY_SALE);


   wub_hex_2_str(srTransRec.szBaseAmount,szAmtBuff,AMT_BCD_SIZE);
   vdDebug_LogPrintf("BDOPAY AMOUT IS %s",szAmtBuff);
   inCTOSS_PutEnvDB("DIGIWALLETAMT",szAmtBuff);


   //testlang
   if (fGetECRTransactionFlg() == TRUE)
   	put_env_int("ECRQR",1);
   else
   	put_env_int("ECRQR",0);
   //testlang

   
   
   if(strTCT.inECRTrxnMenu == 0){
   		memset(strHDT.szAPName, 0x00, sizeof(szAppName));
   		strcpy(strHDT.szAPName, "V3_QRPAY");
        inCTOS_MultiAPSaveData_Wallet(d_IPC_CMD_BDOPAY_SALE);
   }
	
   inRet = inCTOS_MultiSwitchApp(szAppName, d_IPC_CMD_BDOPAY_SALE);

   //teatlang
   put_env_int("ECRQR",0);
   
   if(d_OK != inRet)
   {
	  vdDebug_LogPrintf("reserve app FAIL");
	  return inRet;
   }


    return d_OK;

#else
	inRet = inQRAppSelection(PAYMENT);
	if(d_OK != inRet)
    {
	  vdDebug_LogPrintf("inQRPAY app FAIL");
	  return inRet;
    }
#endif

    return d_OK;
}


//END-QRPAY

