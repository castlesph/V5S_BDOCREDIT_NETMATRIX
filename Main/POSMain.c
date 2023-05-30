
/*******************************************************************************

*******************************************************************************/

#include <string.h>
#include <stdio.h>
#include <ctosapi.h>
#include <ctoserr.h>
#include <stdlib.h>
#include <stdarg.h>
#include <emv_cl.h>

#include "..\Includes\POSTypedef.h"
#include "..\Debug\Debug.h"

#include "..\FileModule\myFileFunc.h"
#include "../DataBase/DataBaseFunc.h"

#include "..\Includes\showbmp.h"
#include "..\Includes\POSMain.h"
#include "..\Includes\POSTrans.h"
#include "..\Includes\POSHost.h"
#include "..\Includes\POSSale.h"
#include "..\Includes\POSConfig.h"
#include "..\ui\Display.h"
#include "..\Includes\Dmenu.h"
#include "..\Includes\POSVoid.h"
#include "..\powrfail\POSPOWRFAIL.h"
#include "..\Comm\V5Comm.h"
#include "..\Includes\CardUtil.h"

#include "..\Includes\MultiApLib.h"
#include "..\Aptrans\MultiAptrans.h"
#include "..\Includes\CfgExpress.h"
#include "..\Includes\Wub_lib.h"
#include "..\Aptrans\MultiShareECR.h"
#include "..\Aptrans\MultiShareCOM.h"
#include "..\Ctls\POSCtls.h"

//gcitra
#include "..\ctls\POSWave.h"
//gcitra


/* BDO CLG: Terminal lock screen -- jzg */
#include "..\Includes\CTOSInput.h"

//smac
#include "..\Includes\posSmac.h"
//smac

#include "..\Debug\Debug.h"

#include "..\Accum\Accum.h" //aaronnino for BDOCLG ver 9.0 fix on issue#00032 "must settle" response on transactions per host after 1 day if batch is not empty 7 of 9
#include "..\TMS\TMS.h"

BOOL fAmountFromIdle = FALSE;


extern VS_BOOL fPreConnectEx;

extern USHORT CTOS_VirtualFunctionKeyHit(BYTE *key);
extern USHORT CTOS_VirtualFunctionKeySet( CTOS_VIRTUAL_FUNCTION_KEY_SET_PARA* pPara, BYTE FuncKeyCount);

extern BOOL fBINVerPreConnectEx;
extern BOOL fRePrintFlag;
int inBattChargingCounter = 0;

//powersave
static BYTE stgIdleEvent= 0;
//powersave
BOOL fQRECRMenu = 0;

CTOS_VIRTUAL_FUNCTION_KEY_SET_PARA stKeyPara [1] = 
{
    //{0,400, 80, 480},  //F1
    //{80, 400, 160, 480}, //F2
    //{160, 400, 240, 480}, //F3
    //{240, 400, 320, 480} //F4
    
    {0, 400, 320, 480} //F4
};



//issue:218
BOOL fEntryCardfromIDLE;
BOOL fIdleInsert;
//issue:218

extern int isPredial;
//USHORT usEthType = 1;

//wifi-mod
extern USHORT usHWSupport;
//wifi-mod


//for ATPBIN routing
BOOL fRouteToSpecificHost;
BOOL fnGlobalOrigHostEnable;
//int inHostOrigNumber;



BOOL fInstApp; //BDO: Parameterized manual key entry for installment --jzg

BOOL fIdleSwipe; //aaronnino for BDOCLG ver 9.0 fix on issue #00059 Card entry is recognized even on non Card Entry Prompt or non Idle Screen display 1 of 8

static BYTE stgFirstIdleKey = 0x00;

//POS auto report: bootup sequence -- jzg
extern int inCTOS_POS_AUTO_REPORT(void);

//Auto-settlement: settle all function -- jzg
extern int inCTOS_SETTLE_ALL(void);

extern BOOL fGPRSConnectOK;
extern BOOL fAutoSettle;

/*BDO: Hold the last GPRS Signal Data --sidumili*/
BYTE szHoldNetworkName[128+1] = {0};
BYTE szHoldBmpSignal[50+1] = {0};
int inHoldGPRSSignal = 0;
int inTimes = 0;

/*BDO: Hold the last GPRS Signal Data--sidumili*/

extern BOOL fERMTransaction;

static int inGPRSResetCounter = 0;
int inGPRSResetTimeOut = 0;
int inDimScreenTimeOut = 0;
BOOL fDimOnIdle = 0;
BOOL fDimFlag = 0;

BOOL fLoyaltyApp;

BYTE chGetFirstIdleKey(void)
{
    return stgFirstIdleKey;
}

void vdSetFirstIdleKey(BYTE bFirstKey)
{
    stgFirstIdleKey = bFirstKey;
}

int inCTOS_ValidFirstIdleKey(void)
{
    if((chGetFirstIdleKey() >= d_KBD_1) && (chGetFirstIdleKey() <= d_KBD_9))
        return d_OK;
    else
        return d_NO;
}

int inCTOS_ECRTask(void)
{

    if (strTCT.fECR) // tct
    {
	    inMultiAP_ECRGetMainroutine(); 
    }

    return SUCCESS;
}

int inDoAutosettlement(void)
{    
	int inCurrTime = 0,
		inASTTime = 0,
		inWHour = 0,
		inWMin = 0;
  	CTOS_RTC rtcClock;
  	CTOS_RTC SetRTC;
  	BYTE szCurrTime[7] = {0};
  	BYTE szCurrDate[8] = {0};
		int inResult = 0;
		STRUCT_FILE_SETTING strFile;

    //aaronnino for BDOCLG ver 9.0 fix on issue#00032 "must settle" response on transactions per host after 1 day if batch is not empty start 8 of 9
		ACCUM_REC srAccumRec;
		int inHostCount, inMerchantCount, inMMTTotalNumofHost = 0, inMMTTotalNumofRec = 0, inMMTTotalNumofMerchants = 5; 
    //aaronnino for BDOCLG ver 9.0 fix on issue#00032 "must settle" response on transactions per host after 1 day if batch is not empty end 8 of 9

    memset(szCurrTime, 0x00, sizeof(szCurrTime));
    CTOS_RTCGet(&rtcClock);
    sprintf(szCurrTime,"%02d%02d%02d", rtcClock.bHour, rtcClock.bMinute, rtcClock.bSecond);
    inCurrTime = wub_str_2_long(szCurrTime);
		
    //aaronnino for BDOCLG ver 9.0 fix on issue#00032 "must settle" response on transactions per host after 1 day if batch is not empty start 9 of 9
    if (strTCT.fNextDayMustSettle == TRUE)  
    {
       memset(szCurrDate, 0x00, sizeof(szCurrDate));
       CTOS_RTCGet(&SetRTC);
       sprintf(szCurrDate,"%02d%02d%02d", SetRTC.bYear, SetRTC.bMonth, SetRTC.bDay);
       
       inTCTRead(1);
       if ((strcmp(szCurrDate,strTCT.szCurrentDate)!=0) && (strcmp(szCurrDate,"000000")!=0))
       {
          memcpy(strTCT.szCurrentDate,szCurrDate,sizeof(szCurrDate));
          inTCTSave(1);	   	
          inCTOS_MerchantCheckBatchAllOperation();
          CTOS_LCDTClearDisplay();
       }
    }
		//aaronnino for BDOCLG ver 9.0 fix on issue#00032 "must settle" response on transactions per host after 1 day if batch is not empty end 9 of 9

    inPASRead(1);
    //vdDebug_LogPrintf("szCurrTime=[%s],[%s][%s][%s]",szCurrTime,strPAS.szSTLTime1,strPAS.szSTLTime2,strPAS.szSTLTime3);

    if (strPAS.fEnable){

		memset(szCurrDate, 0x00, sizeof(szCurrDate));
		CTOS_RTCGet(&SetRTC);
		sprintf(szCurrDate,"%02d%02d%02d", SetRTC.bYear, SetRTC.bMonth, SetRTC.bDay);

		vdDebug_LogPrintf("TEST strPAS.fFirstBootUp 1 %d", strPAS.fFirstBootUp);


		//if (strPAS.fFirstBootUp == 1){	
			//vdDebug_LogPrintf("TEST strPAS.fFirstBootUp 2 %d", strPAS.fFirstBootUp);
			//strPAS.fFirstBootUp = 0;
			//memcpy(strPAS.szlastSettleDate,szCurrDate,sizeof(szCurrDate));
			//inResult = inPASSave(1);				
			//return SUCCESS;
		//}


		vdDebug_LogPrintf("DATE %s %s ", szCurrDate, strPAS.szlastSettleDate);

		//if (strncmp(szCurrDate,strPAS.szlastSettleDate,8)!=0){

		if (wub_str_2_long(szCurrDate) > wub_str_2_long(strPAS.szlastSettleDate)){


			vdDebug_LogPrintf("TIME %s %s ", szCurrTime, strPAS.szSTLTime1);

    		if (((strncmp(szCurrTime, strPAS.szSTLTime1,4) == 0) ||
    		(strncmp(szCurrTime, strPAS.szSTLTime2,4) == 0) ||
    		(strncmp(szCurrTime, strPAS.szSTLTime3,4) == 0)) &&
    		(strPAS.fOnGoing != TRUE))
    		{
         		inWMin = rtcClock.bMinute + strPAS.inRetryTime;
         		inWHour = rtcClock.bHour;
         
         		if (inWMin >= 60)
         		{
             		inWHour++;
             		inWMin = inWMin - 60;
         		}
         
         		if (inWHour >= 24)
             		inWHour = inWHour - 24;

		 
		 		vdDebug_LogPrintf("strPAS.fOnGoing %d ", strPAS.fOnGoing);
         		strPAS.fOnGoing = TRUE;
         		memset(strPAS.szWaitTime, 0, sizeof(strPAS.szWaitTime));
         		sprintf(strPAS.szWaitTime, "%02d%02d%02d", inWHour, inWMin, rtcClock.bSecond);
         		//vdDebug_LogPrintf("sszWaitTime=[%s]",strPAS.szWaitTime);
         		inPASSave(1);
    		}

			fAutoSettle=FALSE;
			//vdDebug_LogPrintf("fOnGoing=[%d],inCurrTime=[%s],[%s]",strPAS.fOnGoing,szCurrTime,strPAS.szWaitTime);
			if (strPAS.fOnGoing == TRUE)
			{
				if (((inCurrTime > wub_str_2_long(strPAS.szWaitTime)) && (inCurrTime > 226100)) ||
					(inCurrTime <= wub_str_2_long(strPAS.szWaitTime)))
				{
					fAutoSettle=TRUE;
					//inCTOS_SETTLE_ALL();
					inCTOS_SETTLE_ALL_MERCHANT();
					
					memcpy(strPAS.szlastSettleDate,szCurrDate,sizeof(szCurrDate));
					inPASSave(1);
					//inTCTSave(1);	  
				}
				else
				{
					strPAS.fOnGoing = FALSE;
					inPASSave(1);
				}
			}
    	}

    }

	//inCTOSS_GetRAMMemorySize("LAST IDLE");
	
	return SUCCESS;
}

int inCTOS_IdleVirtualFunctionKey(void)
{
	USHORT ret;
	
	if (strTCT.byTerminalType == 4)
	{
		BYTE Tkey = 0;	
		Tkey = (sizeof(stKeyPara) / sizeof(CTOS_VIRTUAL_FUNCTION_KEY_SET_PARA))%0x100;
		ret = CTOS_VirtualFunctionKeySet(stKeyPara, Tkey);
	}

    return SUCCESS;
}

int inCTOS_IdleRunningTestFun6(void)
{
    return SUCCESS;
}

int inCTOS_IdleRunningTestFun7(void)
{
    return SUCCESS;
}

int inCTOS_IdleRunningTestFun8(void)
{
    return SUCCESS;
}

int inCTOS_IdleCheckMemoryStatus(void)
{
#define SAFE_LIMIT_SIZE 6000
#define SAFE_FLASH_SIZE 20000

		ULONG ulUsedDiskSize = 0;
		ULONG ulTotalDiskSize = 0;
		ULONG ulUsedRamSize = 0;
		ULONG ulTotalRamSize = 0;
	
		ULONG ulAvailableRamSize = 0;
		ULONG ulAvailDiskSize = 0;
		
		UCHAR szUsedDiskSize[50];
		UCHAR szTotalDiskSize[50];
		UCHAR szUsedRamSize[50];
		UCHAR szTotalRamSize[50];
		
		UCHAR szAvailableRamSize[50];
		UCHAR szAvailableDiskSize[50];
		
	
		memset(szUsedDiskSize,0,sizeof(szUsedDiskSize));
		memset(szTotalDiskSize,0,sizeof(szTotalDiskSize));
		memset(szUsedRamSize,0,sizeof(szUsedRamSize));
		memset(szTotalRamSize,0,sizeof(szTotalRamSize));
		memset(szAvailableRamSize,0,sizeof(szAvailableRamSize));
		memset(szAvailableDiskSize,0,sizeof(szAvailableDiskSize));
		
		usCTOSS_SystemMemoryStatus( &ulUsedDiskSize , &ulTotalDiskSize, &ulUsedRamSize, &ulTotalRamSize );
		//vdDebug_LogPrintf("[%ld],[%ld][%ld][%ld]",ulUsedDiskSize,ulTotalDiskSize,ulUsedRamSize,ulTotalRamSize);
		ulAvailableRamSize = ulTotalRamSize - ulUsedRamSize;
		ulAvailDiskSize = ulTotalDiskSize - ulUsedDiskSize;
		
		sprintf(szTotalDiskSize,"%s:%ld","Total disk",ulTotalDiskSize); 
		sprintf(szUsedDiskSize,"%s:%ld","Used	disk",ulUsedDiskSize);
		sprintf(szAvailableDiskSize,"%s:%ld","Avail disk",ulAvailDiskSize);
		
		sprintf(szTotalRamSize,"%s:%ld","Total RAM",ulTotalRamSize);	
		sprintf(szUsedRamSize,"%s:%ld","Used   RAM",ulUsedRamSize);
		sprintf(szAvailableRamSize,"%s:%ld","Avail RAM",ulAvailableRamSize);
		vdDebug_LogPrintf("ulAvailDiskSize[%ld],ulAvailableRamSize[%ld]",ulAvailDiskSize,ulAvailableRamSize);
	
		if (ulAvailableRamSize < SAFE_LIMIT_SIZE)
		{
			vdCTOSS_MainAPMemoryRecover();
		}

		if (ulAvailDiskSize < SAFE_FLASH_SIZE)
		{
			CTOS_LCDTClearDisplay();

			CTOS_Beep();
			vduiDisplayStringCenter(3,"TERMINAL");
			vduiDisplayStringCenter(4,"WILL REBOOT");
			vduiDisplayStringCenter(5,"PLEASE WAIT");   	
			CTOS_Delay(5000);
			
			CTOS_SystemReset();				
		}
		return SUCCESS;
		
	}



/*************************************************************************************************/
//sidumili: added [patrick suggestion] - [START]
/*************************************************************************************************/

extern int inEthernet_GetTerminalIP(char *szTerminalIP);

/*sidumili: added [patrick suggested]*/
int inCTOS_ConfigureCommDevice(void)
{
    BOOL BolDetachLANChange=TRUE;
    BYTE strOut[30],strtemp[17];


		srTransRec.usTerminalCommunicationMode = strCPT.inCommunicationMode;
		//vduiClearBelow(3);
		//CTOS_LCDTPrintXY (1,7, "Please Wait 		"); 			
		//if(strCPT.inCommunicationMode == ETHERNET_MODE)
		//		CTOS_LCDTPrintXY(1, 8, "Init LAN... 		");
		//else if(strCPT.inCommunicationMode == GPRS_MODE)
		//		CTOS_LCDTPrintXY(1, 8, "Init GPRS...		 ");

											
		if (inCTOS_InitComm(srTransRec.usTerminalCommunicationMode) != d_OK) 
		{
			 
				//vdDisplayErrorMsg(1, 8, "COMM INIT ERR");
				//vdDisplayErrorMsgResp2("","Initialization","Error");
				//return;
		}
		srCommFuncPoint.inInitComm(&srTransRec,srTransRec.usTerminalCommunicationMode);
		srCommFuncPoint.inGetCommConfig(&srTransRec);
		srCommFuncPoint.inSetCommConfig(&srTransRec);			


#if 0
	if(BolDetachLANChange==TRUE)
	{
		inCPTRead(1);
		srTransRec.usTerminalCommunicationMode = strCPT.inCommunicationMode;
		vduiClearBelow(3);
		CTOS_LCDTPrintXY (1,7, "Please Wait 	"); 	  
		if(strCPT.inCommunicationMode == ETHERNET_MODE)
			CTOS_LCDTPrintXY(1, 8, "Init LAN... 	");
		else if(strCPT.inCommunicationMode == GPRS_MODE)
			CTOS_LCDTPrintXY(1, 8, "Init GPRS...	 ");
		else if(strCPT.inCommunicationMode == DIAL_UP_MODE)
			CTOS_LCDTPrintXY(1, 8, "Init Modem...	  ");

		if (inCTOS_InitComm(srTransRec.usTerminalCommunicationMode) != d_OK) 
		{
		   
			//vdDisplayErrorMsg(1, 8, "COMM INIT ERR");
			vdDisplayErrorMsgResp2(" ", " ", "COMM INIT ERR");
			return;
		}
		
		srCommFuncPoint.inInitComm(&srTransRec, strCPT.inCommunicationMode);
		srCommFuncPoint.inGetCommConfig(&srTransRec);
		srCommFuncPoint.inSetCommConfig(&srTransRec);		
	
	}		   
#endif
/*
	if(strCPT.inCommunicationMode == ETHERNET_MODE)
	{
	   if(strTCP.fDHCPEnable != IPCONFIG_DHCP)
	   {
			//inEthernet_GetTerminalIP(strtemp);

			// set static IP			
			//strTCP.fDHCPEnable = IPCONFIG_STATIC;
			//strcpy(srEthernetRec.strLocalIP, strtemp);
			//srCommFuncPoint.inSetCommConfig(&srTransRec); 

			// set DHCP
			//strTCP.fDHCPEnable = IPCONFIG_DHCP;
			srCommFuncPoint.inSetCommConfig(&srTransRec); 

		   //vduiClearBelow(3);
		   //setLCDPrint(3, DISPLAY_POSITION_LEFT, "DHCP TERMINAL IP");
		   //setLCDPrint(4, DISPLAY_POSITION_LEFT, strtemp);
	   }
	}
*/
	return SUCCESS;
}

/*************************************************************************************************/
//function: inCTOS_InitWIFI 
//wifi initialization upon boot up of terminal
//aaronnino
/*************************************************************************************************/

int inCTOS_InitWIFI(void)
{
    inCPTRead(1);
		inTCTRead(1);
		inTCPRead(1);
		
    srTransRec.usTerminalCommunicationMode = strCPT.inCommunicationMode;
		vduiClearBelow(3);

		vdDebug_LogPrintf("AAA - WIFI INIT ON IDLE");

		if(strCPT.inCommunicationMode == WIFI_MODE)
    {
       CTOS_LCDTPrintXY(1, 8, "Init WIFI...	  ");

	   inFirstInitConnectFuncPoint();
	   
       if (inCTOS_InitComm(srTransRec.usTerminalCommunicationMode) != d_OK) 
       {
          //vdDisplayErrorMsgResp2(" ", " ", "COMM INIT ERR");
          vdDisplayErrorMsgResp2("WIFI","Initialization","Error");
          return d_NO;
       }
       srCommFuncPoint.inInitComm(&srTransRec, strCPT.inCommunicationMode);
       srCommFuncPoint.inGetCommConfig(&srTransRec);
       srCommFuncPoint.inSetCommConfig(&srTransRec);		
    }
		
	return d_OK;
}


int inCTOS_ConfigureCTLSReader(void)
{
	//inCTOSS_GetRAMMemorySize("FIRST IDLE");
	
	// patrick add code 20140903
	//inTCTRead(1);
	if (strTCT.fFirstInit)
	{	
		
		//inCTOS_ConfigureCommDevice();
		
		if (NO_CTLS != inCTOSS_GetCtlsMode())
		{
			vdCTOS_InitWaveData();
			clearLine(1);//clear line 1 after init wave - to prevent garbage display when terminal goes back to idle
		}
		
		strTCT.fFirstInit = 0;
		inTCTSave(1);		
	}

	return SUCCESS;
}

/*************************************************************************************************/
//sidumili: added [patrick suggestion] - [START]
/*************************************************************************************************/
int inCTOS_DisplayIdleBMP(void)
{
#if 0
	if (strTCT.fSMMode	== TRUE)
    	vdDisplayAnimateBmp(0, 30, "Insert4.bmp", "Insert5.bmp", "Insert6.bmp", NULL, NULL);
	else
		vdDisplayAnimateBmp(0, 30, "Insert1.bmp", "Insert2.bmp", "Insert3.bmp", NULL, NULL);
#endif

	if(strlen(strTCT.szIdleLogo1)<=0)
	{
		if(strTCT.fSMMode == TRUE)
			displayAppbmpDataEx(0, 30, "Insert4.bmp");
			//vdDisplayAnimateBmp(0, 30, "Insert4.bmp", "Insert5.bmp", "Insert6.bmp", NULL, NULL);
		else
			displayAppbmpDataEx(0, 30, "Insert1.bmp");
			//vdDisplayAnimateBmp(0, 30, "Insert1.bmp", "Insert2.bmp", "Insert3.bmp", NULL, NULL);
	}
	else
		displayAppbmpDataEx(0, 30, strTCT.szIdleLogo1);
    return SUCCESS;
}

int inCTOS_IdleDisplayDateAndTime(void)
{
    CTOS_RTC SetRTC;
    BYTE szCurrentTime[20];


    memset(szCurrentTime, 0x00, sizeof(szCurrentTime));
    CTOS_RTCGet(&SetRTC);
	sprintf(szCurrentTime,"%d-%02d-%02d  %02d:%02d     ",SetRTC.bYear, SetRTC.bMonth, SetRTC.bDay, SetRTC.bHour,SetRTC.bMinute);

    CTOS_LCDTPrintXY (13,1, szCurrentTime);
    
    return SUCCESS;
}

int inCTOS_DisplayComTypeICO(void)
{    
	//WIFI-MOD2
	#define SMALL_ICON_LEN	24
	#define SMALL_ICON_GAP	2
	#define FIRST_SMALL_ICON	1
	#define SMALL_ICON_LEN2 	5
	//WIFI-MOD2


    USHORT usRet;
    USHORT usRet1;
    DWORD pdwStatus ;
    BYTE  bPercentage ;
    static int inLoop = 0;
    static int inGPRSSignal = 0;

    //------
    static USHORT usNetworkType = 0;
    static USHORT usEthType = 1;
    static BYTE szNetworkName[128+1] = {0};
	static unsigned long linux_time = 0;
	unsigned long linux_crttime;	
    //------
    
	static int gIdleDisplayIcon = 0;
	static BYTE szWIFISSID[50];

	//wifi-mod
	STRUCT_SHARLS_COM Sharls_COMData;
	static int inWifiSignal = 0;
	memset(&Sharls_COMData, 0x00, sizeof(STRUCT_SHARLS_COM));
	//wifi-mod

		//------
		linux_crttime = CTOS_TickGet();
		//------
		
    if(strTCT.fDemo)
    {
        displayAppbmpDataEx(300, 90, "DEMO.bmp");
    }

/*
    if(strTCT.fECR)
    {
    	if((strTCT.byTerminalType % 2) == 0)
			displayAppbmpDataEx(270, 330, "ECR1.bmp");
		else
        displayAppbmpDataEx(270, 180, "ECR1.bmp");
    }
*/

	// Reset GPRS -- sidumili	
	if (inGPRSResetTimeOut > 0)
	{
		if (strCPT.inCommunicationMode == GPRS_MODE)
		{
			// GPRS Reset
			inGPRSResetCounter++;
			vdSetGPRSResetTimeOut(inGPRSResetCounter);

			//vdDebug_LogPrintf("inGPRSResetCounter=[%d], inGPRSResetTimeOut=[%d]", inGPRSResetCounter, inGPRSResetTimeOut);
			vdDebug_LogPrintf("chGetGPRSResetTimeOut %d :: inGPRSResetTimeOut %d",chGetGPRSResetTimeOut(), inGPRSResetTimeOut);
			if (chGetGPRSResetTimeOut() >= inGPRSResetTimeOut)
			{	
				vdDebug_LogPrintf("Try Disconnect GRPS");
				CTOS_Delay(300);
				inCTOS_inDisconnect();
				CTOS_Delay(300);
				
				vdDebug_LogPrintf("Try resetting GRPS");
				CTOS_Delay(300);
				inCTOSS_COMM_GPRSReset();				
				CTOS_Delay(300);
								
				inGPRSResetCounter = 1;
			    vdSetGPRSResetTimeOut(inGPRSResetCounter);
			}
			else
			{
				vdDebug_LogPrintf("Do not Reset GPRS!!!");
			}
		}		
	}
	
	if(strTCT.fDisplayBattery == TRUE)
	{
		
	    pdwStatus = 0x00;
	    usRet = CTOS_BatteryStatus(&pdwStatus);
	    vdDebug_LogPrintf("**CTOS_BatteryStatus [%X] [%02X]**", usRet, pdwStatus);
	    usRet1 = CTOS_BatteryGetCapacity(&bPercentage);
	    vdDebug_LogPrintf("**CTOS_BatteryGetCapacity [%X] [%d]**", usRet1, bPercentage);


	    if(d_BATTERY_NOT_EXIST == usRet1)
	    {
	        displayAppbmpDataEx(75, 1, "0N.bmp");
	    }
	    else if(d_OK == usRet1)
	    {
	        if(bPercentage <= 25)
	        {
	            if(d_OK == usRet && (pdwStatus & d_MK_BATTERY_CHARGE))
	            {
	                displayAppbmpDataEx(75, 1, "25N.bmp");
	                //vdBattChargingDisplay(25);
	            }
	            else
	            {
	                displayAppbmpDataEx(75, 1, "25.bmp");
	            }
	        }
	        else if(bPercentage <= 50)
	        {
	            if(d_OK == usRet && (pdwStatus & d_MK_BATTERY_CHARGE))
	            {
	                displayAppbmpDataEx(75, 1, "50N.bmp");
	                //vdBattChargingDisplay(50);
	            }
	            else
	            {
	                displayAppbmpDataEx(75, 1, "50.bmp");
	            }
	        }
	        else if(bPercentage <= 75)
	        {
	            if(d_OK == usRet && (pdwStatus & d_MK_BATTERY_CHARGE))
	            {
	                displayAppbmpDataEx(75, 1, "75N.bmp");
	                //vdBattChargingDisplay(75);
	            }
	            else
	            {
	                displayAppbmpDataEx(75, 1, "75.bmp");
	            }
	            
	        }
	        else if(bPercentage <= 100)
	        {
	            displayAppbmpDataEx(75, 1, "100.bmp");
	        }
	    }
	}
	// sidumili: [commented]
  //  inLoop ++;
	if(strCPT.inCommunicationMode == ETHERNET_MODE)
	{	
	    displayAppbmpDataEx(1, 1, "LAN.bmp");
		//CTOS_LCDTPrintXY (1,1, "E");		
	}
	else if(strCPT.inCommunicationMode == DIAL_UP_MODE)
	{
	    displayAppbmpDataEx(1, 1, "MODEM.bmp");
		//CTOS_LCDTPrintXY (1,1, "M");		
	}		
	else if(strCPT.inCommunicationMode == GPRS_MODE)
	{
			vdDebug_LogPrintf("**GPRS IDLE TIME linux_crttime[%d]--linux_time[%d]--inLoop[%d]--fGPRSConnectOK[%d]--linux_time500[%d]", linux_crttime, linux_time, inLoop, fGPRSConnectOK, linux_time+500);
	    if (linux_crttime > linux_time + 500 || inLoop == 0)
        {   
          /* BDO: [Return signal / network name] -- sidumili*/
				inLoop = 1;
				linux_time = CTOS_TickGet();	
        inGPRSSignal = inCTOSS_GetGPRSSignalEx(&usNetworkType, szNetworkName,&usEthType);
        vdDebug_LogPrintf("**inCTOSS_GetGPRSSignal inGPRSSignal=[%d]**usEthType=[%d]", inGPRSSignal,usEthType);
        vdDebug_LogPrintf("**d_MOBILE_NETWORK_UMTS->usNetworkType [%2x][%2x][%d]**", d_MOBILE_NETWORK_UMTS , usNetworkType, (d_MOBILE_NETWORK_UMTS && usNetworkType));
		vdDebug_LogPrintf("**d_MOBILE_NETWORK_LTE->usNetworkType [%2x][%2x][%d]**", d_MOBILE_NETWORK_LTE , usNetworkType, (d_MOBILE_NETWORK_LTE && usNetworkType));

         /* BDO: [Return signal / network name] -- sidumili*/

		 /*BDO: Hold the last GPRS Signal Data--sidumili/hubing*/
			 if (inGPRSSignal > 0){
				strcpy(szHoldNetworkName, szNetworkName);
				inHoldGPRSSignal = inGPRSSignal;
				inTimes = 0;
			 }
			 else
			 {
				inTimes++;
			 	if (inTimes == 3)
			 	{
			 	memset(szHoldNetworkName, 0x00,sizeof(szHoldNetworkName));
				inHoldGPRSSignal = 0;
				inTimes = 0;
			 	}
				 vdDebug_LogPrintf("**inTimes =[%d]**szHoldNetworkName=[%s]", inTimes,szHoldNetworkName);
			 }
			 /*BDO: Hold the last GPRS Signal Data--sidumili/hubing*/

        }
		



				//inLoop ++; //sidumili: [added]
        //if(inLoop > 0xFFFF)
        //    inLoop = 0;
				
        if(fGPRSConnectOK == TRUE){	
#if 0
					CTOS_LCDTSelectFontSize(d_FONT_8x16);
					CTOS_LCDTPrintXY (10,2, "GPRS");		
					CTOS_LCDTSelectFontSize(d_FONT_16x30);
#else
		CTOS_LCDTSelectFontSize(d_FONT_8x16);

		if (d_MOBILE_NETWORK_LTE == usNetworkType)
			displayAppbmpDataEx(30, 15, "4G.bmp");
		else if (d_MOBILE_NETWORK_UMTS & usNetworkType)
			//CTOS_LCDTPrintXY (10,2, "3G  ");
			displayAppbmpDataEx(30, 15, "3G.bmp");
		else if (d_MOBILE_NETWORK_GPRS & usNetworkType)
			//CTOS_LCDTPrintXY (10,2, "GPRS");
			displayAppbmpDataEx(30, 15, "G.bmp");
		else if (d_MOBILE_NETWORK_GPRS & usNetworkType)
			//CTOS_LCDTPrintXY (10,2, "GPRS");
			displayAppbmpDataEx(30, 15, "G.bmp");
		//else
		//	CTOS_LCDTPrintXY (10,2, "NONE");
		
		CTOS_LCDTSelectFontSize(d_FONT_16x30);
#endif

        }else{      

			{
			CTOS_LCDTSelectFontSize(d_FONT_8x16);
			//CTOS_LCDTPrintXY (10,2, "        ");
			displayAppbmpDataEx(30, 15, "None.bmp");
			CTOS_LCDTSelectFontSize(d_FONT_16x30);
			}
		}
					

				vdDebug_LogPrintf("**inGPRSSignal =[%d]**szHoldNetworkName=[%s]", inGPRSSignal,szHoldNetworkName);

				if (inGPRSSignal > 0){
					CTOS_LCDTSelectFontSize(d_FONT_16x16);
					CTOS_LCDTPrintXY (1, 3, szNetworkName);
					CTOS_LCDTSelectFontSize(d_FONT_16x30);
				}
				else{

					if (strlen(szHoldNetworkName) > 0 )
					{
#if 0
						CTOS_LCDTSelectFontSize(d_FONT_8x16);
						CTOS_LCDTPrintXY (10,2, "GPRS");		
						CTOS_LCDTSelectFontSize(d_FONT_16x30);
#else
						if (d_MOBILE_NETWORK_LTE & usNetworkType)
							displayAppbmpDataEx(30, 15, "4G.bmp");
						else if (d_MOBILE_NETWORK_UMTS & usNetworkType)
							displayAppbmpDataEx(30, 15, "3G.bmp");
						else if (d_MOBILE_NETWORK_GPRS & usNetworkType)
							displayAppbmpDataEx(30, 15, "G.bmp");
						else if (d_MOBILE_NETWORK_GPRS & usNetworkType)
							displayAppbmpDataEx(30, 15, "G.bmp");
#endif
					
						CTOS_LCDTSelectFontSize(d_FONT_16x16);
						CTOS_LCDTPrintXY (1, 3, szHoldNetworkName);
						CTOS_LCDTSelectFontSize(d_FONT_16x30);

					}
					else
					{
						CTOS_LCDTSelectFontSize(d_FONT_16x16);
						CTOS_LCDTPrintXY (1, 3, "No Service");
						CTOS_LCDTSelectFontSize(d_FONT_16x30);
					}
				}

        if(1 == inHoldGPRSSignal)
            displayAppbmpDataEx(1, 1, "G1.bmp");
        else if(2 == inHoldGPRSSignal)
            displayAppbmpDataEx(1, 1, "G2.bmp");
        else if(3 == inHoldGPRSSignal)
            displayAppbmpDataEx(1, 1, "G3.bmp");
        else if(4 == inHoldGPRSSignal)
            displayAppbmpDataEx(1, 1, "G4.bmp");
        else
            displayAppbmpDataEx(1, 1, "G0.bmp");

        //CTOS_LCDTPrintXY (1,1, "G");		
			 
	}
	//wifi-mod
#if 1
	else if(strCPT.inCommunicationMode == WIFI_MODE)
		{
		
			 CTOS_LCDTSelectFontSize(d_FONT_8x16);
			 CTOS_LCDTPrintXY (10,2, "WIFI"); 	
			 CTOS_LCDTSelectFontSize(d_FONT_16x30);
			 
			 
			 if (linux_crttime > linux_time + 500 || inLoop == 0)
			 { 
					inLoop = 1;
					linux_time = CTOS_TickGet();
					inGPRSSignal = inCTOSS_GetGPRSSignalEx1(&usNetworkType, szNetworkName, &usEthType, &Sharls_COMData);
					inWifiSignal = Sharls_COMData.inReserved2;
					inGPRSSignal = inWifiSignal;
						
					vdDebug_LogPrintf("AAA - inGPRSSignal[%d]inWifiSignal[%d] Sharls_COMData.szWIFISSID[%s]", inGPRSSignal, inWifiSignal, Sharls_COMData.szWIFISSID);
					
					/*BDO: Hold the last GPRS Signal Data--sidumili/hubing*/
					if (inGPRSSignal > 0)
					{
						 strcpy(szHoldNetworkName, Sharls_COMData.szWIFISSID);
						 vdDebug_LogPrintf("AAA-szHoldNetworkName[%s]", Sharls_COMData.szWIFISSID);
						 inHoldGPRSSignal = inGPRSSignal;
						 inTimes = 0;
						 
						 if ((usHWSupport & d_MK_HW_WIFI) == d_MK_HW_WIFI)
						 {		
									switch(inWifiSignal)
									{
									case 0:
										strcpy(szHoldBmpSignal, "VFNone.bmp");
										break;
									case 1:
										strcpy(szHoldBmpSignal, "VF1.bmp");
										break;
									case 2:
										strcpy(szHoldBmpSignal, "VF2.bmp");
										break;
									case 3:
										strcpy(szHoldBmpSignal, "VF3.bmp");
										break;
									case 4:
										strcpy(szHoldBmpSignal, "VF4.bmp");
										break;
									default:
										strcpy(szHoldBmpSignal, "VF5.bmp");
										break;
									}
						 }
						 else
						 {
									if (0 == usHWSupport)
										 strcpy(szHoldBmpSignal, "VFInit.bmp");
									else
										 strcpy(szHoldBmpSignal, "VFNone.bmp");
						 }
					
					}
					else
					{
						 inTimes++;
						 if (inTimes == 3)
						 {
								memset(szHoldNetworkName, 0x00,sizeof(szHoldNetworkName));
								//memset(szHoldBmpSignal, 0x00,sizeof(szHoldBmpSignal));
								inHoldGPRSSignal = 0;
								inTimes = 0;
						 }
						 vdDebug_LogPrintf("**inTimes =[%d]**szHoldNetworkName=[%s]", inTimes,szHoldNetworkName);
					}
					/*BDO: Hold the last GPRS Signal Data--sidumili/hubing*/
			 }
			 
			 if (strlen(szHoldNetworkName) > 0)
			 {
					CTOS_LCDTSelectFontSize(d_FONT_8x16);
					CTOS_LCDTPrintXY (1,3, szHoldNetworkName);
					CTOS_LCDTSelectFontSize(d_FONT_16x30);
					
					if (inWifiSignal > 0) 	
						 displayAppbmpDataEx(1, 1, szHoldBmpSignal);
			 } 
			 else
			 {
					CTOS_LCDTSelectFontSize(d_FONT_8x16);
					CTOS_LCDTPrintXY (1,3, szHoldNetworkName);
					CTOS_LCDTSelectFontSize(d_FONT_16x30);
					
					if (0 == usHWSupport)
						 strcpy(szHoldBmpSignal, "VFNone.bmp");
					else
						 strcpy(szHoldBmpSignal, "VFNone.bmp");
					
					displayAppbmpDataEx(1, 1, szHoldBmpSignal);
			 }
			 
			 vdDebug_LogPrintf("AAA - usHWSupport - %d inWifiSignal - %d", usHWSupport, inWifiSignal);
			 ////display wifi icon
		
		
		
		}

	#else 
		else if(strCPT.inCommunicationMode == WIFI_MODE){
	
	
			CTOS_LCDTSelectFontSize(d_FONT_8x16);
			CTOS_LCDTPrintXY (10,2, "WIFI");		
			CTOS_LCDTSelectFontSize(d_FONT_16x30);


			
			inGPRSSignal = inCTOSS_GetGPRSSignalEx1(&usNetworkType, szNetworkName, &usEthType, &Sharls_COMData);
			
	
			inWifiSignal = Sharls_COMData.inReserved2;
			
			memset(szWIFISSID,0x00,sizeof(szWIFISSID));
			if (Sharls_COMData.usWIFIType == 1)
				strcpy(szWIFISSID,Sharls_COMData.szWIFISSID);	
	
			if (inWifiSignal > 0){
				CTOS_LCDTSelectFontSize(d_FONT_8x16);
				//CTOS_LCDTPrintAligned(3, szWIFISSID, d_LCD_ALIGNLEFT);
				//CTOS_LCDTPrintAligned(3, Sharls_COMData.szWIFISSID, d_LCD_ALIGNLEFT);
				CTOS_LCDTPrintXY (1,3, szWIFISSID);
				CTOS_LCDTSelectFontSize(d_FONT_16x30);
			}	
	
			
			vdDebug_LogPrintf("usHWSupport	- %d", usHWSupport);
			////display wifi icon
			if ((usHWSupport & d_MK_HW_WIFI) == d_MK_HW_WIFI)
			{		
				if(0 == inWifiSignal)
					//displaybmpEx(319-(SMALL_ICON_LEN+SMALL_ICON_GAP)*4, 0, "VFNone.bmp"); 	
					displayAppbmpDataEx(1, 1, "VFNone.bmp");
				else if(1 == inWifiSignal)
					//displaybmpEx(319-(SMALL_ICON_LEN+SMALL_ICON_GAP)*4, 0, "VF1.bmp");
					displayAppbmpDataEx(1, 1, "VF1.bmp");
				else if(2 == inWifiSignal)
					//displaybmpEx(319-(SMALL_ICON_LEN+SMALL_ICON_GAP)*4, 0, "VF2.bmp");
					displayAppbmpDataEx(1, 1, "VF2.bmp");
				else if(3 == inWifiSignal)
					//displaybmpEx(319-(SMALL_ICON_LEN+SMALL_ICON_GAP)*4, 0, "VF3.bmp");
					displayAppbmpDataEx(1, 1, "VF3.bmp");
				else if(4 == inWifiSignal)
					//displaybmpEx(319-(SMALL_ICON_LEN+SMALL_ICON_GAP)*4, 0, "VF4.bmp");
					displayAppbmpDataEx(1, 1, "VF4.bmp");
				else
				{
					//displaybmpEx(319-(SMALL_ICON_LEN+SMALL_ICON_GAP)*4, 0, "VF4.bmp");
					displayAppbmpDataEx(1, 1, "VF5.bmp");
				}
			}
			else
			{
				if (0 == usHWSupport)
					//displaybmpEx(319-(SMALL_ICON_LEN+SMALL_ICON_GAP)*4, 0, "VFInit.bmp");
					displayAppbmpDataEx(1, 1, "VFInit.bmp");
				else
					//displaybmpEx(319-(SMALL_ICON_LEN+SMALL_ICON_GAP)*4, 0, "VFNone.bmp");
					displayAppbmpDataEx(1, 1, "VFNone.bmp");
			}
	
			
#if 0
			CTOS_LCDTSelectFontSize(d_FONT_16x16);
			//CTOS_LCDTPrintXY (1, 2, szNetworkName);
			displayAppbmpDataEx(1, 1, "VF4.bmp");
			//CTOS_LCDTPrintAligned(2, Sharls_COMData.szWIFISSID, d_LCD_ALIGNLEFT);
			CTOS_LCDTSelectFontSize(d_FONT_16x30);
	
	
			if ((strlen(szWIFISSID) > 0) && (inGPRSSignal > 0))
			{
				//if (gIdleDisplayIcon == 1)
				//{
					CTOS_LCDTSelectFontSize(d_FONT_16x16);
					//CTOS_LCDTPrintXY (1, 2, szNetworkName);
					CTOS_LCDTPrintAligned(2, szWIFISSID, d_LCD_ALIGNLEFT);
					CTOS_LCDTSelectFontSize(d_FONT_16x30);
				//}
			}
			else{
				//gIdleDisplayIcon = 0;
				//CTOS_LCDTSelectFontSize(d_FONT_16x16);
				//CTOS_LCDTPrintXY (1, 3, "No Service");
				//CTOS_LCDTSelectFontSize(d_FONT_16x30);
			}
#endif
			
		}
	//wifi-mod
#endif

    //test-glad
    //inCTOS_ConfigureCommDevice();//add to get IP during bootup
    return SUCCESS;
}

typedef struct 
{
	int  (*inCTOS_IdleRunningFun)(void);
} IDLE_FUNC;


IDLE_FUNC g_IdleRunningFun[] = 
{
    inCTOS_ConfigureCTLSReader,
    inCTOS_DisplayIdleBMP,
    inCTOS_DisplayComTypeICO,
    inCTOS_IdleDisplayDateAndTime,
    inCTOS_ECRTask,
    //powersave
    inCTOSS_JumpToSleepMode,
    //powersave
    inDoAutosettlement,
    inCTOS_IdleCheckMemoryStatus,
    //adc
    inCTOS_ADC_Download,
    //adc
    //inCTOS_IdleVirtualFunctionKey,
    //inCTOS_IdleRunningTestFun6,
    //inCTOS_IdleRunningTestFun7,
    //inCTOS_IdleRunningTestFun8,
    inDimScreen,
    NULL
        
};


int inCTOSS_InitAP(void)
{
	USHORT ret;
	USHORT usResult,usStatus,usReterr;
	int inRet =0;
	USHORT inADCMissed=0;
	
	ret = CTOS_SetFunKeyPassword(strTCT.szFunKeyPW, 1);
	vdDebug_LogPrintf("CTOS_SetFunKeyPassword=[%s],ret=[%d]", strTCT.szFunKeyPW,ret);
	
	ret = CTOS_SetPMEnterPassword(strTCT.szPMpassword, 1);	
	vdDebug_LogPrintf("CTOS_SetPMEnterPassword=[%s],ret=[%d]", strTCT.szPMpassword,ret);

		/**********************
			CTOS_PrinterSetHeatLevel 
			default value is 2. 
			= 0 : Ultra light. 	= 1 : Very light. 
			= 2 : Light. 		= 3 : Medium. 
			= 4 : Dark. 		= 5 : Very dark. 
			= 6 : Ultra dark.
		***********************/
	ret = CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel);	
	vdDebug_LogPrintf("CTOS_PrinterSetHeatLevel=[%d],ret=[%d]", strTCT.inPrinterHeatLevel,ret);

	if (strTCT.fEnableManualKeyEntry == TRUE)
		put_env_int("BDOMANUAL",1);
	else
		put_env_int("BDOMANUAL",0);

	if (strTCT.fSMMode == TRUE)
	{
		put_env_char("#3LMENU","FUNCTION");
		put_env_int("#PINDISPOPT", 1); 
	}
	else
	{
		put_env_char("#3LMENU","");
		//put_env_int("#PINDISPOPT", 0);
		put_env_int("#PINDISPOPT", 1);
	}


    //testalng
    //put_env_int("#PINDISPOPT", 1); 
	//endtest
	
	put_env_char("BDOAMTSPC","         ");

	//if(get_env_int("CRCINIT") == 0)
	if(get_env_int("CRCINIT") != 1)
	{
		vdGetCRC_ALL();
		put_env_int("CRCINIT",1);
	}

	if(strEFTPub.inEFTEnable = get_env_int("EFTSECVAL") >= 0)
		inEFTPubSave(6);

	if (strTCT.fFirstInit)
		inDCCMMTUpdate();

	put_env_int("CONNECTED",0);
	put_env_int("BINROUTE",0);
	vdDebug_LogPrintf("inFLGRead[%d]",inFLGRead(1));

	fQRECRMenu = inFLGGet("fQRECRMenu");

	inDetailReportHeader();


		if(strCPT.inCommunicationMode == ETHERNET_MODE)
			{
				inRet = CTOS_EthernetOpen(); //for test
				vdDebug_LogPrintf("inCTOSS_InitAP  ----- CTOS_EthernetOpen[%d]",inRet);
			}

	
	
	if(inFLGGet("fADCReport") == TRUE)
	{
		inADCMissed = inADC_Missed();

		vdDebug_LogPrintf("ADC missed - %d", inADCMissed);
		//test only
		//inADCMissed = 1;//test-glad
		//inFLGSet("fCTMSDL",0);
		if(inFLGGet("fCTMSDL") == TRUE || inCheckTMSBackUpFilesExists() == d_OK || inADCMissed == 1 )
		//if(inFLGGet("fCTMSDL") == TRUE || inCheckTMSBackUpFilesExists() == d_OK  )
		{
			if(inCheckTMSBackUpFilesExists() == d_OK)
			{
				vdDebug_LogPrintf("test 4 inCTOSS_TMSReadDetailData");
				inCTOSS_TMSReadDetailData();
				put_env_int("MISSEDADC",0);
				//inCTOSS_TMSReadStatusData();
				//fFreshDownload = FALSE;
			}//else
			   //fFreshDownload = TRUE;
				
			fRePrintFlag = FALSE;
			vdDebug_LogPrintf("TEST 3 before print adc report - %d", strTMSDetail.inDLTrigger);
			inPrintADCReport(0);
			inFLGSet("fCTMSDL",0);
			put_env_int("MISSEDADC",0);
			put_env_int("ADL",1);//test
		}
	}

	if(inCheckFileExist(TBD_FILE_NAME) == d_OK)
	{
		usResult = CTOS_CTMSGetStatus(&usStatus, &usReterr);//ONLY UPDATE TXN DATA IF DOWNLOAD IS SUCCESSFUL
	    vdDebug_LogPrintf("init app CTOS_CTMSGetStatus usResult[%d] usStatus[%d] usReterr[%d]", usResult, usStatus, usReterr);
		if(usResult == d_CTMS_UPDATE_FINISHED)
			inCTOSS_TMSRestoreTxnData();
	}

	fDimOnIdle = get_env_int("DIMONIDLE");
	inDimScreenTimeOut = get_env_int("DIMIDLETIME");
	
	if(inDimScreenTimeOut <= 0)
		inDimScreenTimeOut = 60;
	else
		inDimScreenTimeOut = inDimScreenTimeOut*60;
	
	return SUCCESS;
}


/* BDO: Terminal screen lock - start -- jzg */
int inDisplayLockScreen()
{
	BYTE strOut[30] = {0},
    bKey = 0x00;
	USHORT shRet = 0,
		shLen = 0,
		iInitX = 0,
		shMinLen = 4,
		shMaxLen = 6;
	BYTE szTitleDisplay[MAX_CHAR_PER_LINE + 1] = {0},
		szTitle[MAX_CHAR_PER_LINE + 1] = {0};

	if(strTCT.fScreenLocked != TRUE)
		return -1;

	CTOS_TimeOutSet (TIMER_ID_1 , 3000);
	
	CTOS_LCDTClearDisplay();
	memset(szTitle, 0x00, sizeof(szTitle));
	strcpy(szTitle, "TERMINAL LOCKED");
	iInitX = (MAX_CHAR_PER_LINE - strlen(szTitle)*2) / 2;
	memset(szTitleDisplay, 0x00, sizeof(szTitleDisplay));
	memset(szTitleDisplay, 0x20, MAX_CHAR_PER_LINE);
	memcpy(&szTitleDisplay[iInitX], szTitle, strlen(szTitle));	
	CTOS_LCDTSetReverse(TRUE);
	CTOS_LCDTPrintXY(1, 1, szTitleDisplay);
	CTOS_LCDTSetReverse(FALSE);

	if(get_env_int("LOCKPROMPT") == 1) /* BDOCLG: Revised logic for lockscreen prompt -- jzg */
	{
		setLCDPrint(4, DISPLAY_POSITION_CENTER, "TERMINAL LOCKED?");
		setLCDPrint(6, DISPLAY_POSITION_CENTER, "[O]YES     [X]NO");

		while(1)
		{
			if(CTOS_TimeOutCheck(TIMER_ID_1) == d_YES)
				return 1;

			CTOS_KBDHit(&bKey);

			if(bKey == d_KBD_ENTER)
			{
				put_env_int("LOCKPROMPT", 0); /* BDOCLG: Revised logic for lockscreen prompt -- jzg */
				break;
			}
			else if(bKey == d_KBD_CANCEL)
			{
				put_env_int("LOCKPROMPT", 1); /* BDOCLG: Revised logic for lockscreen prompt -- jzg */
				strTCT.fScreenLocked = FALSE;
				inTCTSave(1);
				CTOS_LCDTClearDisplay();
				return 0;
			}
		}
	}

	put_env_int("LOCKPROMPT", 0); /* BDOCLG: Revised logic for lockscreen prompt -- jzg */
	
	while(1)
	{
		vduiClearBelow(3);
		setLCDPrint(5, DISPLAY_POSITION_CENTER, "ENTER PASSWORD:"); /* BDOCLG-00129: ENTER PASSWORD: should be centered O_O -- jzg */
    shMaxLen=6;
		memset(strOut,0x00, sizeof(strOut));
		shRet = InputString(1, 6, 0x01, 0x02, strOut, &shMaxLen, shMinLen, d_INPUT_TIMEOUT);
		if((shRet == d_KBD_CANCEL) || (shRet == 0) || (shRet == 255))
        return 1;
		else if(shRet >= 1)
		{
			if(strcmp(strOut, strTCT.szLockPassword) == 0)
			{
				put_env_int("LOCKPROMPT", 1); /* BDOCLG: Revised logic for lockscreen prompt -- jzg */
				inTCTRead(1);
				strTCT.fScreenLocked = FALSE;
				inTCTSave(1);
				CTOS_LCDTClearDisplay();
				return 0;
			}
			else
			{
				vdDisplayErrorMsg(1, 8, "WRONG PASSWORD");
				return 1;
			}
		}
	}

}
/* BDO: Terminal screen lock - end -- jzg */


int inCTOS_IdleEventProcess(void)
{
#define CTOS_ILDE_TIMER  60

    DWORD dwWait=0, dwWakeup=0;
    USHORT ret;
    USHORT byMSR_status;
    BYTE key;
    BYTE bySC_status;
    BYTE babuff[128];
    BYTE sT1Buf[128] ,sT2Buf[128] ,sT3Buf[128];
    USHORT bT1Len=128 ,bT2Len=128 ,bT3Len=128;
	//USHORT usTk1Len, usTk2Len, usTk3Len;
    //BYTE szTk1Buf[TRACK_I_BYTES], szTk2Buf[TRACK_II_BYTES_50], szTk3Buf[TRACK_III_BYTES];
    int i = 0, inRet;
    int i1=0, i2=0;
    BYTE baTemp[128];
	USHORT usTk1Len=TRACK_I_BYTES, usTk2Len=TRACK_II_BYTES, usTk3Len=TRACK_III_BYTES;
	BYTE szTk1Buf[TRACK_I_BYTES], szTk2Buf[TRACK_II_BYTES], szTk3Buf[TRACK_III_BYTES];
    CTOS_SCStatus(d_SC_USER, &bySC_status);
    if(bySC_status & d_MK_SC_PRESENT)
    {
        inSetTextMode();
        vdRemoveCard();
    }

		
    CTOS_TimeOutSet(TIMER_ID_4, CTOS_ILDE_TIMER);  //Only IDLE loop use TIMER_ID_4, please don't use this TIMER_ID_4 in other place in application
    vduiKeyboardBackLight(VS_FALSE);

	
	//powersave	
    vdSetIdleEvent(1);
	//powersave
#if 0
    vdDebug_LogPrintf("**strTCT.fECR[%d]**", strTCT.fECR);
	if (strTCT.fECR) // tct
	{
		usCTOSS_ECRInitialize();	
	}
#endif

	// patrick add code 20140903
	/*inTCTRead(1);
	if (strTCT.fFirstInit)
	{	
		if (NO_CTLS != inCTOSS_GetCtlsMode())
		{
			vdCTOS_InitWaveData();
			strTCT.fFirstInit = 0;
			inTCTSave(1);
		}
	}*/
	inCTOSS_InitAP();
	//inCTOS_ConfigureCommDevice();

#if 0
	if (strTCT.byTerminalType == 4)
	{
		BYTE Tkey = 0;	
		Tkey = (sizeof(stKeyPara) / sizeof(CTOS_VIRTUAL_FUNCTION_KEY_SET_PARA))%0x100;
		ret = CTOS_VirtualFunctionKeySet(stKeyPara, Tkey);
	}
#endif	

	inCTOS_IdleVirtualFunctionKey();


	while(1)
    {
		/* BDO CLG: Terminal lock screen -- jzg */
		if(inDisplayLockScreen() > 0)
			continue;
	
		fEntryCardfromIDLE=FALSE;
		fIdleInsert = FALSE;
		fInstApp = FALSE; //BDO: Parameterized manual key entry for installment --jzg
		fCommAlreadyOPen = FALSE;		 
		isPredial=0;

        //set smac flag to false - this flag will only be true if transaction is SMAC
        fSMACTRAN = VS_FALSE;
		fAdviceTras = VS_FALSE;
		 //06112015

		 fIdleSwipe=FALSE; //aaronnino for BDOCLG ver 9.0 fix on issue #00059 Card entry is recognized even on non Card Entry Prompt or non Idle Screen display 2 of 8

         fPreConnectEx = FALSE;
		 fBINVerPreConnectEx = FALSE;
		 fRePrintFlag = FALSE;
         //1026        
//		 inCSTRead(1);
		 //1026

		 if(strTCT.byERMMode)
			fERMTransaction=TRUE;
		 else
			fERMTransaction=FALSE;

		 fLoyaltyApp = FALSE;

		/* BDO: USD setup - Load BDO host index to get the correct currency index - start -- jzg */
		inDatabase_TerminalOpenDatabase();
		inHDTReadEx(1); 
		inCSTReadEx(strHDT.inCurrencyIdx); 
		inDatabase_TerminalCloseDatabase();
		/* BDO: USD setup - Load BDO host index to get the correct currency index - end -- jzg */

		//Open the Back Light in the LCD Display //
		//vduiLightOn();
		//return idle delay problem, move to head
		if(CTOS_TimeOutCheck(TIMER_ID_4) == d_YES)
		{
			i = 0;
			while(g_IdleRunningFun[i].inCTOS_IdleRunningFun != NULL)
				g_IdleRunningFun[i++].inCTOS_IdleRunningFun();
		}

		dwWait = d_EVENT_KBD | d_EVENT_MSR | d_EVENT_SC;
		//System waits the device the be set acts.   //System waits for target devices to be triggered and will not return until any target device is triggered //


#if 1
/*
		if (strTCT.byTerminalType == 4)
		{
			BYTE Tkey = 0;	
			Tkey = (sizeof(stKeyPara) / sizeof(CTOS_VIRTUAL_FUNCTION_KEY_SET_PARA))%0x100;
			ret = CTOS_VirtualFunctionKeySet(stKeyPara, Tkey);
		}

		if (strTCT.byTerminalType == 4)
		{
			do{
				ret = CTOS_VirtualFunctionKeyHit(&key);
				if (key == d_KBD_INVALID)
				{
					CTOS_KBDHit(&key);
					break;
				}

				 CTOS_KBDBufPut(key);				
			}while(key != d_KBD_INVALID);

			if (key != d_KBD_INVALID) // patrick, please do not remove this part of code
			{
				CTOS_KBDBufPut(key);
			}			
		}
*/

	if (strTCT.byTerminalType == 4)
	{
		do{
			ret = CTOS_VirtualFunctionKeyHit(&key);
			if (key == d_KBD_INVALID)
			{
				CTOS_KBDHit(&key);
				break;
			}

		 	CTOS_KBDBufPut(key);				
		}while(key != d_KBD_INVALID);

		if (key != d_KBD_INVALID) // patrick, please do not remove this part of code
		{
			CTOS_KBDBufPut(key);
		}			
	}


#endif

        ret = CTOS_SystemWait(20, dwWait, &dwWakeup);

        vdSetFirstIdleKey(0x00);
        CTOS_SCStatus(d_SC_USER, &bySC_status);
        if ((dwWakeup & d_EVENT_KBD) == d_EVENT_KBD)
        {
			vdSetIdleEvent(1);			
            vduiKeyboardBackLight(VS_TRUE);
			vduiScreenBackLight(VS_TRUE);
			//powersave
			vdCTOS_uiIDLEWakeUpSleepMode();
			//powersave
	
            //Detect if any key is pressed and get which key, but not get actual key.
            //If you get actual key, use to "CTOS_KBDGet" function//
            CTOS_KBDGet(&key);
            
            switch(key)
            {
                case d_KBD_UP:
				case d_KBD_DOWN:	
					//inTCTRead(1);

                    
					vdDebug_LogPrintf("crash testing key down/up selected");
					if((strTCT.byTerminalType % 2) == 0)
		           {
		              
					  vdDebug_LogPrintf("crash testing before CTOS_LCDForeGndColor");
		              CTOS_LCDForeGndColor(RGB(13, 43, 112));
		              CTOS_LCDBackGndColor(RGB(255, 255, 255));
		           }
					else
						inSetTextMode();

					vdDebug_LogPrintf("crash testing before call F! key event");
                    inF1KeyEvent();
					vdDebug_LogPrintf("crash testing after  call F! key event");
                    CTOS_LCDTClearDisplay();
					if(fIdleSwipe != TRUE) //aaronnino for BDOCLG ver 9.0 fix on issue #00059 Card entry is recognized even on non Card Entry Prompt or non Idle Screen display 3 of 8
						byMSR_status = CTOS_MSRRead(szTk1Buf, &usTk1Len, szTk2Buf, &usTk2Len, szTk3Buf, &usTk3Len);

					break;
					
                case d_KBD_F1:  
					
					/* BDOCLG: change to BDO color scheme if in icon mode - start -- jzg */
					//inTCTRead(1);
					if((strTCT.byTerminalType % 2) == 0)
					{
						CTOS_LCDForeGndColor(RGB(13, 43, 112));
						CTOS_LCDBackGndColor(RGB(255, 255, 255));
					}else
						break;
					/* BDOCLG: change to BDO color scheme if in icon mode - end -- jzg */

                    inF1KeyEvent();
                    CTOS_LCDTClearDisplay();
					if(fIdleSwipe != TRUE) //aaronnino for BDOCLG ver 9.0 fix on issue #00059 Card entry is recognized even on non Card Entry Prompt or non Idle Screen display 3 of 8
						byMSR_status = CTOS_MSRRead(szTk1Buf, &usTk1Len, szTk2Buf, &usTk2Len, szTk3Buf, &usTk3Len);
                    break;
					
                case d_KBD_F2:                     
					inF2KeyEvent();
                    CTOS_LCDTClearDisplay();
                    break;

                case d_KBD_F3:                     
					inF3KeyEvent();
                    CTOS_LCDTClearDisplay();
                    break;

                case d_KBD_F4:
					
					inF4KeyEvent();					
                    CTOS_LCDTClearDisplay();
                    break;

                case d_KBD_ENTER:   

					/* BDOCLG: change to BDO color scheme if in icon mode - start -- jzg */
					inTCTRead(1);
					if((strTCT.byTerminalType % 2) == 0)
					{
						CTOS_LCDForeGndColor(RGB(13, 43, 112));
						CTOS_LCDBackGndColor(RGB(255, 255, 255));
					}
					/* BDOCLG: change to BDO color scheme if in icon mode - end -- jzg */
									
					inEnterKeyEvent();
                    CTOS_LCDTClearDisplay();
					if(fIdleSwipe != TRUE) //aaronnino for BDOCLG ver 9.0 fix on issue #00059 Card entry is recognized even on non Card Entry Prompt or non Idle Screen display 4 of 8
						byMSR_status = CTOS_MSRRead(szTk1Buf, &usTk1Len, szTk2Buf, &usTk2Len, szTk3Buf, &usTk3Len);
					inSetTextMode();
					vdRemoveCard();
                    break;

                case d_KBD_CANCEL:
                    break;


                case d_KBD_0:
#if 0
									/* BDOCLG: Make 0 as function key shortcut only for touch screen terminals - start -- jzg */
									if((strTCT.byTerminalType % 2) == 0)
										if(strTCT.fSMMode == 0)
											vdCTOS_FunctionKey();
										else
											vdCTOS_SMFunctionKey();
									
									/* BDOCLG: Make 0 as function key shortcut only for touch screen terminals - end -- jzg */
									
                    //inF1KeyEvent();
                    //CTOS_LCDTClearDisplay();
                    if(fIdleSwipe != TRUE) //aaronnino for BDOCLG ver 9.0 fix on issue #00059 Card entry is recognized even on non Card Entry Prompt or non Idle Screen display 5 of 8
												byMSR_status = CTOS_MSRRead(szTk1Buf, &usTk1Len, szTk2Buf, &usTk2Len, szTk3Buf, &usTk3Len);
										inSetTextMode();
										vdRemoveCard();

					vdCTOSS_ClearTouchPanelTest();
#endif					
                    break;
					
				case d_KBD_DOT:
					CTOS_PrinterFline(24);
					break;
					
				case d_KBD_1:	
//gcitra-0728
					//vdCTOSS_GetALLWaveSetting();
                    //break;
//gcitra-0728
                case d_KBD_2:
                case d_KBD_3:		
                case d_KBD_4:
                case d_KBD_5:
                case d_KBD_6:
                case d_KBD_7:
                case d_KBD_8:
                case d_KBD_9:
                    vdSetFirstIdleKey(key);
					fAmountFromIdle = TRUE;
					//gcitra
                    //inCTOS_SALE();
					inRet=inCTOS_SelectCurrencyfromIDLE();
					if(d_OK != inRet)
					{
						CTOS_LCDTClearDisplay();
						continue;
					}
	
                    if (strTCT.fDefaultCashAdvance == 1)
						inCTOS_CASH_ADVANCE();
					else
                   		inCTOS_WAVE_SALE();
					//gcitra
                    vdSetFirstIdleKey(0x00);
                    CTOS_LCDTClearDisplay();
                    break;
					
                default:
	                break;
            }

			vdCTOSS_ClearTouchPanelTest();
            vduiKeyboardBackLight(VS_FALSE);
            
        }
        else if ((dwWakeup & d_EVENT_MSR) == d_EVENT_MSR)
        {
					/* BDO CLG: MOTO setup - start -- jzg */
					if (strTCT.fMOTO == 1)
						continue;
					/* BDO CLG: MOTO setup - end -- jzg */

            //Open the Back Light in the LCD Display //
            vduiKeyboardBackLight(VS_TRUE);
			vduiScreenBackLight(VS_TRUE);
            vduiLightOn();
            vdCTOS_SetTransEntryMode(CARD_ENTRY_MSR);
            
			//issue:218
			fEntryCardfromIDLE = TRUE;
			//issue:218
			//gcitra

			fIdleSwipe=TRUE; //aaronnino for BDOCLG ver 9.0 fix on issue #00059 Card entry is recognized even on non Card Entry Prompt or non Idle Screen display 6 of 8
			
			//inCTOS_SALE();
#if 0			
			inRet=inCTOS_SelectCurrencyfromIDLE();
			if(d_OK != inRet)
			{
				byMSR_status = CTOS_MSRRead(szTk1Buf, &usTk1Len, szTk2Buf, &usTk2Len, szTk3Buf, &usTk3Len);//Clear MSR event if user cancels.
				CTOS_LCDTClearDisplay();
				continue;
			}	
#endif			
			if (strTCT.fDefaultCashAdvance == 1)
				inCTOS_CASH_ADVANCE();
			else
				inCTOS_WAVE_SALE();
			//gcitra
			
            CTOS_LCDTClearDisplay();
	        vduiKeyboardBackLight(VS_FALSE);
            CTOS_MSRRead(szTk1Buf, &usTk1Len, szTk2Buf, &usTk2Len, szTk3Buf, &usTk3Len);
			vdCTOSS_ClearTouchPanelTest();
            continue;
            
        }
        else if (((dwWakeup & d_EVENT_SC) == d_EVENT_SC) || (bySC_status & d_MK_SC_PRESENT))
        {
			/* BDO CLG: MOTO setup - start -- jzg */
			if (strTCT.fMOTO == 1)
				continue;
			/* BDO CLG: MOTO setup - end -- jzg */
				
            //Open the Back Light in the LCD Display //
            vduiKeyboardBackLight(VS_TRUE);
			vduiScreenBackLight(VS_TRUE);
            vduiLightOn();
            vdCTOS_SetTransEntryMode(CARD_ENTRY_ICC);
            
			//gcitra
			//inCTOS_SALE();
			//issue:218
			fEntryCardfromIDLE = TRUE;
			fIdleInsert = TRUE;
			//issue:218
#if 0
			inRet=inCTOS_SelectCurrencyfromIDLE();
			if(d_OK != inRet)
			{
				CTOS_LCDTClearDisplay();
				vdRemoveCard();
				continue;
			}	
#endif			
			if (strTCT.fDefaultCashAdvance == 1)
				inCTOS_CASH_ADVANCE();
			else
				inCTOS_WAVE_SALE();
			//gcitra
			
            CTOS_LCDTClearDisplay();
            vduiKeyboardBackLight(VS_FALSE);

			
			//powersave
			//vdSetIdleEvent(1);
			//powersave
			
            vdRemoveCard();
			vdCTOSS_ClearTouchPanelTest();
            continue;
        }
    }
}

int main(int argc,char *argv[])
{
          char szvalue[1+1];
		  
	inSetTextMode();
	CTOS_BackLightSetBrightness(d_BKLIT_LCD, get_env_int("BRIGHTNESS"));
	inCTOSS_ProcessCfgExpress();

	inDatabase_TerminalOpenDatabase();
    inTCTReadEx(1);
    inCPTReadEx(1);
    inPCTReadEx(1);
    inCSTReadEx(1);
    inTCPRead(1);
	inDatabase_TerminalCloseDatabase();
	
	vdUpdateDynamicMenu();
	
    vdThreadRunAppColdInit();
	if (get_env_int("AUTORECOVER") != 8)
	{
		int inReturn;
		vdDebug_LogPrintf("main 1");
	
		inReturn = inMultiAP_ForkTask();
		//inReturn = inMultiAP_ForkTaskEx();

		vdDebug_LogPrintf("main 2 inReturn [%d]", inReturn);
		
		if(d_OK == inMultiAP_CheckSubAPStatus())
		{
			vdDebug_LogPrintf("inWaitTime =[%d]",strTCT.inWaitTime);
			if (strTCT.inWaitTime <= 0)
				strTCT.inWaitTime = 100;
			while (1)
			{
				inMultiAP_GetMainroutine();			
				CTOS_Delay(strTCT.inWaitTime);
			}
		}
		else
		{
			inMultiAP_ForkSharlsAp();
		}

		
		vdDebug_LogPrintf("main END");
	}
	else
	{
		inMultiAP_ForkTaskEx();
	}
	//put_env_int("AUTORECOVER", 0);
	//inCTOS_ConfigureCommDevice();
    		//inCTOS_InitWIFI();
	
    CTOS_LCDTClearDisplay();
	inCTOS_DisplayIdleBMP();
	CTOS_Delay(1000);

	fGPRSConnectOK = FALSE;

	//if(d_OK == inMultiAP_CheckSubAPStatus())
	//testlang-removelater
		if (get_env_int("AUTORECOVER") != 8)
			inCTLOS_Getpowrfail();
	
	
	put_env_int("AUTORECOVER", 0);
	
	put_env_int("SCCRASH", 0);

	if (get_env_int("MAINRESET") != 1){
		put_env_int("CRDTCTR",0);
		put_env_int("INSTCTR",0);
		put_env_int("DEBTCTR",0);
		put_env_int("CUPCTR",0);
		put_env_int("QRPAYCTR",0);
	}
	
	put_env_int("MAINRESET",0);
	put_env_int("CREDITBUSY",0);

	put_env_int("ECRQR",0);

	inCTOS_InitWIFI();
	
	vdSetADLParams();

	//testlang
	//vdMenuOverwrite();

// For GPRS Reset
	inGPRSResetCounter = 0;
	inGPRSResetTimeOut = get_env_int("GPRSRESETTIMEOUT");
	if (inGPRSResetTimeOut < 0) 
		inGPRSResetTimeOut = 1800; // 30 minutes
	else
		inGPRSResetTimeOut = inGPRSResetTimeOut * 60;

	vdSetGPRSResetTimeOut(0);
	
         if(strTCT.fSMMode==1)
         	{
	     if ( inCTOSS_GetEnvDB ("BLNKAUTH", szvalue) != d_OK )
	                   inCTOSS_PutEnvDB("BLNKAUTH", "0");
         	}
	//POS auto report: bootup sequence -- jzg
	inCTOS_POS_AUTO_REPORT();

	vdCTOSS_ClearTouchPanelTest();

	vdDebug_LogPrintf("**strTCT.fECR[%d]**", strTCT.fECR);
	if (strTCT.fECR) // tct
	{
		usCTOSS_ECRInitialize();	
	}



	inCTOS_ConfigureCommDevice();//add to get IP during bootup

	#if 0 // or testing only..03212023 - reversal file
	vdDebug_LogPrintf("MAIN AAA");
	
		vdChecksReversalFile();
	#endif	

	inCTOS_IdleEventProcess();

	#if 0 // or testing only..03212023 - reversal file
	vdDebug_LogPrintf("MAIN BBB");
	
		vdChecksReversalFile();
	#endif


	vdDebug_LogPrintf("main END");

}

void vdCTOSS_ClearTouchPanelTest(void)
{
	BYTE str[256],size = 5;
	ULONG rb;
	BYTE count = 0;

	int pen_up = 0;
	int pen_down = 0;
	int bXpen_up = 0, bXpen_down = 0;
	int bXCoordinate = 0, bYCoordinate = 0;
	int temp_iX = 0,temp_iY = 0;
	USHORT ret;
    BYTE key;

	if (strTCT.byTerminalType == 4)
	{
		do{
			ret = CTOS_VirtualFunctionKeyHit(&key);
			vdDebug_LogPrintf("CTOS_VirtualFunctionKeyHit.key=[%d][%c]",key,key);
			if (key == d_KBD_INVALID)
			{
				CTOS_KBDHit(&key);
				break;
			}

		}while(key != d_KBD_INVALID);
	}
	
}


//powersave
int inCTOSS_JumpToSleepMode(void)
{  
	char szMessage[30+1];
	static int inSleepTime = 2;
	static int Sleepflag = 0;
	static int offonflag = 0;
	static unsigned long linux_time = 0;
	unsigned long linux_crttime;


	if(get_env_int("POWERSAVE") != 1)
		return d_OK;

	linux_crttime = CTOS_TickGet();

	vdDebug_LogPrintf("inCTOSS_JumpToSleepMode");

    
	
	if (chGetIdleEvent() == 1)
	{
		inSleepTime = get_env_int("SLEEPTIME");
		if (inSleepTime < 0)
			inSleepTime = 90;

		if (inSleepTime == 0)
			Sleepflag = 1;
				
		vdDebug_LogPrintf("inCTOSS_JumpToSleepMode,inSleepTime=[%d],Sleepflag=[%d]", inSleepTime,Sleepflag);
		vdSetIdleEvent(0);
		
		linux_time = CTOS_TickGet();
	}



    vdDebug_LogPrintf("TEST linux_crttime = %d %d",linux_crttime, linux_time + (inSleepTime*100));
	if((linux_crttime > linux_time + (inSleepTime*100)) && Sleepflag != 1)
	{
		vdCTOS_uiIDLESleepMode();
	}

	if (inCTOSS_CheckBatteryChargeStatus() == d_OK)
	{
	    vdDebug_LogPrintf("TEST CTOS_TickGet"); 
		linux_time = CTOS_TickGet();
	}

    return SUCCESS;
}
//powersave

BYTE chGetIdleEvent(void)
{
    vdDebug_LogPrintf("chGetIdleEvent %d %c",stgIdleEvent, stgIdleEvent);
    return stgIdleEvent;
}

void vdSetIdleEvent(BYTE bIdleEvent)
{
    vdDebug_LogPrintf("crash teting chGetIdleEvent");
    stgIdleEvent = bIdleEvent;
}

void vdSetGPRSResetTimeOut(int bTimeOut)
{
    inGPRSResetCounter = bTimeOut;
}

int chGetGPRSResetTimeOut(void)
{
    //vdDebug_LogPrintf("chGetGPRSResetTimeOut %d",inGPRSResetCounter);
	
    return inGPRSResetCounter;
}

int inDimScreen(void)
{
	static unsigned long linux_time = 0;
	unsigned long linux_crttime;
	
	vdDebug_LogPrintf("fDimOnIdle %d :: fDimFlag %d",fDimOnIdle, fDimFlag);

	if(fDimOnIdle == FALSE)
		return;

	if(fDimFlag == TRUE)//Do not check timer once dim is implemented.
		return;
	
	linux_crttime = CTOS_TickGet();

	if (chGetIdleEvent() == 1)
	{
		vdSetIdleEvent(0);
		
		linux_time = CTOS_TickGet();
	}

	vdDebug_LogPrintf("TEST linux_crttime = %d %d",linux_crttime, linux_time + (inDimScreenTimeOut*100));
	if((linux_crttime > linux_time + (inDimScreenTimeOut*100)))
		vduiScreenBackLight(FALSE);
	else
		vdDebug_LogPrintf("DIM SCREEN TIMEOUT NOT REACHED");
		
	return ST_SUCCESS;
}


#if 0
void vdMenuOverwrite(void)
{
    char szSystemCmdPath[128+1];    
    char szNewFileName[24+1];
    char szSource[24+1];
    char szDestination[24+1];

    int inDestinationIndex=0;



	
    memset(szSystemCmdPath, 0x00, sizeof(szSystemCmdPath));
    sprintf(szSystemCmdPath, "rm %s%s",LOCAL_PATH, szDestination);
    system(szSystemCmdPath);
	
    memset(szSystemCmdPath, 0x00, sizeof(szSystemCmdPath));
    //sprintf(szSystemCmdPath, "echo cp %s%s %s%s", LOCAL_PATH, szSource, LOCAL_PATH, szDestination);
	sprintf(szSystemCmdPath, "cp %s%s %s%s", LOCAL_PATH, szSource, LOCAL_PATH, szDestination);

	vdDebug_LogPrintf("szSource[%s]", szSource);
	vdDebug_LogPrintf("szDestination[%s]", szDestination);
	vdDebug_LogPrintf("szSystemCmdPath[%s]", szSystemCmdPath);
	
	inSetColorMenuMode();
    system(szSystemCmdPath);
}
#endif

int vdChecksReversalFile(void)
{

		int isExist = 0;		
		char szFileName[d_BUFF_SIZE] = {0};				
		
		memset(szFileName, 0x00, sizeof(szFileName));

		strcpy(szFileName, "BDO LOYALTY11801.rev");

		isExist = isReversalFileExist(szFileName);
		vdDebug_LogPrintf("vdChecksReversalFile isReversalFileExist isExist %d", isExist);	

		return isExist;
}
