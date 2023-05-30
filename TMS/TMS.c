/*******************************************************************************

*******************************************************************************/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctosapi.h>
#include <EMVAPLib.h>
#include <EMVLib.h>

#include <unistd.h>
#include <pwd.h>


#include <sys/shm.h>
#include <linux/errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/stat.h>


#include "..\Includes\Wub_lib.h"

#include "..\Includes\POSTypedef.h"
#include "..\FileModule\myFileFunc.h"

#include "..\Includes\msg.h"
#include "..\Includes\CTOSInput.h"
#include "..\ui\Display.h"

#include "..\Includes\V5IsoFunc.h"
#include "..\Comm\V5Comm.h"
#include "..\Includes\Trans.h"   


#include "..\Includes\CTOSInput.h"


#include "..\debug\debug.h"
#include "..\Accum\Accum.h"

#include "..\Includes\POSMain.h"
#include "..\Includes\POSTrans.h"
#include "..\Includes\POSHost.h"
#include "..\Includes\POSSale.h"
#include "..\Database\DatabaseFunc.h"
#include "..\Includes\POSHost.h"
#include "..\Includes\Wub_lib.h"
#include "..\Includes\myEZLib.h"
#include "..\accum\accum.h"
#include "..\Includes\POSSetting.h"
#include "..\Debug\Debug.h"
#include "..\filemodule\myFileFunc.h"
#include "..\Includes\POSTrans.h"
#include "..\Includes\CTOSInput.h"
#include "..\Ctls\PosWave.h"
#include "..\TMS\TMS.h"
#include "..\POWRFAIL\POSPOWRFAIL.h"


#include "..\Includes\MultiApLib.h"
#include "..\Aptrans\MultiAptrans.h"
#include "..\Aptrans\MultiShareEMV.h"
#include "..\print\Print.h"


//adc
extern int inADLTimeRangeUsed;
BOOL fBatchNotEmpty = FALSE;
int inDLTrigger = FALSE;

//adc

extern BYTE szIP[50+1];
extern BYTE szDNS1[50+1];
extern BYTE szDNS2[50+1];
extern BYTE szGateWay[50+1];
extern BYTE szSubnetMask[50+1];

extern BOOL fRePrintFlag;
#include "..\ApTrans\MultiShareCOM.h"
	

#if 0

#ifndef d_CTMS_INFO_LAST_UPDATE_TIME
#define d_CTMS_INFO_LAST_UPDATE_TIME 0x01
#endif

USHORT CTOS_CTMSGetInfo(IN BYTE Info_ID, IN void *stInfo)
{
    CTOS_RTC SetRTC;
    
    CTOS_RTCGet(&SetRTC);

    SetRTC.bMonth -= 2;

    memcpy(stInfo, &SetRTC, sizeof(CTOS_RTC));

    return d_OK;
}

#endif

int inCTOSS_TMSCheckIfDefaultApplication(void)
{
    CTOS_stCAPInfo stinfo;
	BYTE exe_dir[128]={0};
	BYTE exe_subdir[128]={0};
	USHORT inExeAPIndex = 0;

    getcwd(exe_dir, sizeof(exe_dir)); //Get current working dir string
	strcpy(exe_subdir, &exe_dir[9]);
	inExeAPIndex = atoi(exe_subdir);
	memset(&stinfo, 0x00, sizeof(CTOS_stCAPInfo));
    if(CTOS_APGet(inExeAPIndex, &stinfo) != d_OK)
	{
		CTOS_APGet(inExeAPIndex, &stinfo);
	}

    vdDebug_LogPrintf("stinfo.bFlag[%02X]", stinfo.bFlag);
    if (stinfo.bFlag != d_AP_FLAG_DEF_SEL_EX)
        return d_NO;
    else
        return d_OK;
    
}

int inCTOSS_TMSChkBatchEmpty(void)
{
    int inResult;

    vdDebug_LogPrintf("inCTOSS_TMSChkBatchEmpty start");
    
    if (inMultiAP_CheckMainAPStatus() == d_OK)
	{
		inResult = inCTOSS_TMSChkBatchEmptyProcess();
        if(inResult != d_OK)
            return inResult;
        else
		    inResult = inCTOS_MultiAPALLAppEventID(d_IPC_CMD_CHK_BATCH_EMPTY);

        if(inResult != d_FAIL)
            inResult = d_OK;
	}
	else
	{
		inResult = inCTOSS_TMSChkBatchEmptyProcess();
	}
    
    vdDebug_LogPrintf("inCTOSS_TMSChkBatchEmpty return[%d]", inResult);
    
    return (inResult);
}


int inCTOSS_TMSChkBatchEmptyProcess(void)
{
    int inResult;
    int shHostIndex = 1;
    int inNum = 0;
    int inNumOfHost = 0;
    int inNumOfMerchant = 0;
    int inLoop =0 ;
    ACCUM_REC srAccumRec;
    STRUCT_FILE_SETTING strFile;
    char szAPName[25];
	int inAPPID;

	memset(szAPName,0x00,sizeof(szAPName));
	inMultiAP_CurrentAPNamePID(szAPName, &inAPPID);

    //check host num
    inNumOfHost = inHDTNumRecord();
    
    vdDebug_LogPrintf("[inNumOfHost]-[%d]", inNumOfHost);
    for(inNum =1 ;inNum <= inNumOfHost; inNum++)
    {
        if(inHDTRead(inNum) == d_OK)
        {
            vdDebug_LogPrintf("szAPName=[%s]-[%s]----",szAPName,strHDT.szAPName);
			if (strcmp(szAPName, strHDT.szAPName)!=0)
			{
				continue;
			}
            
            inMMTReadNumofRecords(strHDT.inHostIndex,&inNumOfMerchant);
        
            vdDebug_LogPrintf("[inNumOfMerchant]-[%d]strHDT.inHostIndex[%d]", inNumOfMerchant,strHDT.inHostIndex);
            for(inLoop=1; inLoop <= inNumOfMerchant;inLoop++)
            {
            /*
                if((inResult = inMMTReadRecord(strHDT.inHostIndex, strMMT[inLoop-1].MMTid)) !=d_OK)
                {
                    vdDebug_LogPrintf("[read MMT fail]-Mitid[%d]strHDT.inHostIndex[%d]inResult[%d]", strMMT[inLoop-1].MMTid,strHDT.inHostIndex,inResult);
                    continue;
                    //break;
                }
                else    // delete batch where hostid and mmtid is match  
                { 
                */
                    strMMT[0].HDTid = strHDT.inHostIndex;
                    strMMT[0].MITid = strMMT[inLoop-1].MITid;
                    srTransRec.MITid = strMMT[inLoop-1].MITid;

                    vdDebug_LogPrintf("srTransRec.MITid[%d]strHDT.inHostIndex[%d]", srTransRec.MITid, strHDT.inHostIndex);
                    memset(&srAccumRec,0,sizeof(srAccumRec));
                    memset(&strFile,0,sizeof(strFile));
                    memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
                    memset(&strFile,0,sizeof(strFile));
                    vdCTOS_GetAccumName(&strFile, &srAccumRec);

                if((inResult = inMyFile_CheckFileExist(strFile.szFileName)) > 0)
                {
                    vdDebug_LogPrintf("inCTOSS_TMSChkBatchEmpty Not Empty");
                    //vdDisplayErrorMsg(1, 8, "BATCH NOT", "EMPTY,SKIPPED.");
                    vdSetErrorMessage("");
                    return (d_FAIL);
                }
                else
                {
                    vdDebug_LogPrintf("EMPTY BATCH");
                }
                
            //    }
            }
        }
        else
            continue;

    }
    
    return (d_OK);
}

int inCTOSS_TMSPreConfig(int inComType)
{    
    CTMS_GPRSInfo stgprs;    
    CTMS_ModemInfo stmodem;    
    CTMS_EthernetInfo st;
		CTMS_WIFIInfo stWF;
    int inNumOfRecords = 0;
    BYTE szSerialNum[17+1], szInputBuf[21+1];
    BYTE count = 2,i;
    BYTE tmpbuf[16 + 1];
    int len;
    USHORT usRet;
    unsigned char ckey;
    USHORT usStatusLine=8, usRes=0;
	
    inHDTRead(1);
    inMMTReadNumofRecords(strHDT.inHostIndex, &inNumOfRecords);
    
    memset(szSerialNum, 0x00, sizeof(szSerialNum));
	memset(tmpbuf, 0x00, sizeof(tmpbuf));

	CTOS_CTMSGetConfig(d_CTMS_SERIALNUM, szSerialNum);
	if(strlen(szSerialNum) <= 0)
	    CTOS_GetFactorySN(szSerialNum);
	for (i=0; i<strlen(szSerialNum); i++)
	{
		if (szSerialNum[i] < 0x30 || szSerialNum[i] > 0x39)
		{
			szSerialNum[i] = 0;
			break;
		}
	}
	len = strlen(szSerialNum);
	strcpy(tmpbuf,"0000000000000000");

	//testonly
	//strcpy(tmpbuf,"1999999999999997");
	memcpy(&tmpbuf[16-len],szSerialNum,len);
	vdDebug_LogPrintf("szSerialNum=[%s].tmpbuf=[%s]..",szSerialNum,tmpbuf);
	
    CTOS_CTMSSetConfig(d_CTMS_SERIALNUM, tmpbuf);//if TID is 12345678, SN is 0000000012345678
    CTOS_CTMSSetConfig(d_CTMS_RECOUNT, &count);

    if(strTCP.fDHCPEnable)
        CTOS_CTMSSetConfig(d_CTMS_LOCALIP, "0.0.0.0");
    else
        CTOS_CTMSSetConfig(d_CTMS_LOCALIP, strTCP.szTerminalIP);// If it is DHCP, also need to configure any value, otherwise please put the value from database

    if(ETHERNET_MODE == strTCT.inTMSComMode)
    {
        CTOS_LCDTClearDisplay();
        vdDispTitleString("ETHERNET SETTINGS");
	
    	vdDebug_LogPrintf("ETHERNET_MODE..");
        memset(&st, 0x00, sizeof (CTMS_EthernetInfo));

		st.bDHCP = strTCP.fDHCPEnable;
		if(strTCP.fDHCPEnable == FALSE)
		{
			strcpy(st.strLocalIP,strTCP.szTerminalIP);
	        strcpy(st.strGateway, strTCP.szGetWay);
	        strcpy(st.strMask, strTCP.szSubNetMask);
		}
		else
		{
			vdPrint_EthernetStatus();
			strcpy(st.strLocalIP,szIP);
	        strcpy(st.strGateway, szGateWay);
	        strcpy(st.strMask, szSubnetMask);			
		}
        

        strcpy(st.strRemoteIP, strTCT.szTMSRemoteIP);
        st.usRemotePort = strTCT.usTMSRemotePort;


		CTOS_LCDTClearDisplay();
		vdDispTitleString("ETHERNET SETTINGS");

		memset(szSerialNum, 0x00, sizeof(szSerialNum));
		CTOS_CTMSGetConfig(d_CTMS_SERIALNUM, szSerialNum);

        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "SN: %s", szSerialNum);         
        setLCDPrint(2, DISPLAY_POSITION_LEFT, szInputBuf); 

        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "IP: %s", st.strRemoteIP);         
        setLCDPrint(3, DISPLAY_POSITION_LEFT, szInputBuf); 

        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "PORT: %d", st.usRemotePort);         
        setLCDPrint(4, DISPLAY_POSITION_LEFT, szInputBuf); 
	
        usRes=CTOS_CTMSSetConfig(d_CTMS_ETHERNET_CONFIG, &st);
    }
    else if(DIAL_UP_MODE == strTCT.inTMSComMode)
    {
    	vdDebug_LogPrintf("DIAL_UP_MODE..");

        CTOS_LCDTClearDisplay();
        vdDispTitleString("DIALUP SETTINGS");

        memset(&stmodem, 0x00, sizeof (CTMS_ModemInfo));
        //stmodem.bMode = d_M_MODE_AYNC_FAST;
        //stmodem.bHandShake = d_M_HANDSHAKE_V32BIS_AUTO_FB;
        stmodem.bMode  = d_M_MODE_SDLC_FAST;
        stmodem.bHandShake = d_M_HANDSHAKE_V22_ONLY;
        stmodem.bCountryCode = d_M_COUNTRY_SINGAPORE;

        strcpy(stmodem.strRemotePhoneNum, strTCT.szTMSRemotePhone);
		vdDebug_LogPrintf("strRemotePhoneNum[%s]..",stmodem.strRemotePhoneNum);
        strcpy(stmodem.strID, strTCT.szTMSRemoteID);	
		vdDebug_LogPrintf("strID[%s]..",stmodem.strID);
        strcpy(stmodem.strPW, strTCT.szTMSRemotePW);
		vdDebug_LogPrintf("strPW[%s]..",stmodem.strPW);

        strcpy(stmodem.strRemoteIP, strTCT.szTMSRemoteIP);
        stmodem.usRemotePort = strTCT.usTMSRemotePort;

		stmodem.usPPPRetryCounter = 2;
		stmodem.ulPPPTimeout = 34463;
		stmodem.ulDialTimeout = 34463;
		vdDebug_LogPrintf("strRemoteIP[%s].usRemotePort=[%d].",stmodem.strRemoteIP,stmodem.usRemotePort);

		memset(szSerialNum, 0x00, sizeof(szSerialNum));
		CTOS_CTMSGetConfig(d_CTMS_SERIALNUM, szSerialNum);


        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "SN: %s", szSerialNum);         
        setLCDPrint(2, DISPLAY_POSITION_LEFT, szInputBuf); 

        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "IP: %s", stmodem.strRemoteIP);         
        setLCDPrint(3, DISPLAY_POSITION_LEFT, szInputBuf); 

        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "PORT: %d", stmodem.usRemotePort);         
        setLCDPrint(4, DISPLAY_POSITION_LEFT, szInputBuf); 
        
        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "PHONE: %s", stmodem.strRemotePhoneNum);         
        setLCDPrint(5, DISPLAY_POSITION_LEFT, szInputBuf); 
		
        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "ID: %s", stmodem.strID);         
        setLCDPrint(6, DISPLAY_POSITION_LEFT, szInputBuf); 

        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "PASSWORD: %s", stmodem.strPW);         
        setLCDPrint(6, DISPLAY_POSITION_LEFT, szInputBuf);
		
        usRes=CTOS_CTMSSetConfig(d_CTMS_MODEM_CONFIG, &stmodem);
    }
    else if(GPRS_MODE == strTCT.inTMSComMode)
    {
		CTMS_GPRSInfo stgprs;

        CTOS_LCDTClearDisplay();
        vdDispTitleString("GPRS SETTINGS");
		
		memset(&stgprs, 0x00, sizeof (CTMS_GPRSInfo));
		CTOS_CTMSGetConfig(d_CTMS_GPRS_CONFIG, &stgprs);
		
		memset(stgprs.strAPN, 0x00, sizeof(stgprs.strAPN));
		strcpy(stgprs.strAPN,strTCP.szAPN);
	
		memset(stgprs.strID, 0x00, sizeof(stgprs.strID));
		strcpy(stgprs.strID,strTCP.szUserName);

		
		memset(stgprs.strPW, 0x00, sizeof(stgprs.strPW));
		strcpy(stgprs.strPW,strTCP.szPassword);
		
              vdDebug_LogPrintf("GPRS_MODE..");
        memset(&stgprs, 0x00, sizeof (CTMS_GPRSInfo));
        strcpy(stgprs.strAPN, strTCP.szAPN);
        strcpy(stgprs.strID, strTCP.szUserName);
        strcpy(stgprs.strPW, strTCP.szPassword);
 
        strcpy(stgprs.strRemoteIP, strTCT.szTMSRemoteIP);
        stgprs.usRemotePort = strTCT.usTMSRemotePort;
        stgprs.ulSIMReadyTimeout = 60000;
        stgprs.ulGPRSRegTimeout = 60000;
        stgprs.usPPPRetryCounter = 5;
        stgprs.ulPPPTimeout = 60000;
        stgprs.ulTCPConnectTimeout = 60000;

		//test
		stgprs.ulTCPTxTimeout=60000;
		stgprs.ulTCPRxTimeout=60000;


		
		stgprs.bSIMSlot=1;

		memset(szSerialNum, 0x00, sizeof(szSerialNum));
		CTOS_CTMSGetConfig(d_CTMS_SERIALNUM, szSerialNum);


        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "SN: %s", szSerialNum);         
        setLCDPrint(2, DISPLAY_POSITION_LEFT, szInputBuf); 

        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "IP: %s", stgprs.strRemoteIP);		 
        setLCDPrint(3, DISPLAY_POSITION_LEFT, szInputBuf); 

        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "PORT: %d", stgprs.usRemotePort);		 
        setLCDPrint(4, DISPLAY_POSITION_LEFT, szInputBuf);

        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "APN: %s", stgprs.strAPN);		 
        setLCDPrint(5, DISPLAY_POSITION_LEFT, szInputBuf);

        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "USER NAME: %s", stgprs.strID);		 
        setLCDPrint(6, DISPLAY_POSITION_LEFT, szInputBuf);
		
        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "PASSWORD: %s", stgprs.strPW);		 
        setLCDPrint(7, DISPLAY_POSITION_LEFT, szInputBuf);
		
        usRes=CTOS_CTMSSetConfig(d_CTMS_GPRS_CONFIG, &stgprs);
		vdDebug_LogPrintf("GPRS CTOS_CTMSSetConfig ret = %d", usRes);
    }
    else if(WIFI_MODE == strTCT.inTMSComMode)
    {
        CTOS_LCDTClearDisplay();
        vdDispTitleString("WIFI SETTINGS");
        
        vdDebug_LogPrintf("WIFI..");
        memset(&stWF, 0x00, sizeof (CTMS_WIFIInfo));
        usRet = CTOS_CTMSGetConfig(d_CTMS_WIFI_CONFIG, &stWF);


		strcpy(stWF.baPassword, strTCP.szWifiPassword);
		strcpy(stWF.baSSid, strTCP.szWifiSSID);
		//stWF.bProtocal = 3;
		//stWF.bGroup = 2;
		//stWF.bPairwise = 2;
		stWF.bDHCP = strTCP.fDHCPEnable;
		stWF.bSCAN_Mode = 1;
		stWF.IsAutoConnect =48;
		stWF.IsHidden =48;

		memset(stWF.strLocalIP, 0x00, sizeof(stWF.strLocalIP));
		memset(stWF.strMask, 0x00, sizeof(stWF.strMask));	
		memset(stWF.strGateway, 0x00, sizeof(stWF.strGateway));

		if (strTCP.fDHCPEnable){
			strcpy(stWF.strLocalIP, "0.0.0.0");
			strcpy(stWF.strMask, "0.0.0.0");
			strcpy(stWF.strGateway, "0.0.0.0");
		}else{
			strcpy(stWF.strLocalIP, strTCP.szTerminalIP);
			strcpy(stWF.strMask, strTCP.szSubNetMask);
			strcpy(stWF.strGateway, strTCP.szGetWay);
		}
	
		
        //if (usRet != d_OK)
        //{
        //   CTOS_LCDTPrintXY(1, 7, "Please Set CTMS");
        //   vdDisplayErrorMsg(1, 8, "CTMS Get Fail");
        //   return d_NO;
        //}
           CTOS_LCDTClearDisplay();
           vdDispTitleString("WIFI SETTINGS");
        
           memset(szSerialNum, 0x00, sizeof(szSerialNum));
           CTOS_CTMSGetConfig(d_CTMS_SERIALNUM, szSerialNum);
           
           memset(szInputBuf, 0x00, sizeof(szInputBuf));
           sprintf(szInputBuf, "SN: %s", szSerialNum);         
           setLCDPrint(2, DISPLAY_POSITION_LEFT, szInputBuf); 
           
           memset(szInputBuf, 0x00, sizeof(szInputBuf));
           sprintf(szInputBuf, "IP: %s", stWF.strRemoteIP);         
           setLCDPrint(3, DISPLAY_POSITION_LEFT, szInputBuf); 
           
           memset(szInputBuf, 0x00, sizeof(szInputBuf));
           sprintf(szInputBuf, "PORT: %d", stWF.usRemotePort);         
           setLCDPrint(4, DISPLAY_POSITION_LEFT, szInputBuf); 


		   //bProtocal
		   if (strcmp(strTCP.szWifiProtocal, "WEP")  == 0)
		   {
			   stWF.bProtocal = d_WIFI_PROTOCOL_WEP;
		   }
		   else if (strcmp(strTCP.szWifiProtocal, "WPA")  == 0)
		   {
			   stWF.bProtocal = d_WIFI_PROTOCOL_WPA;
		   }
		   else if (strcmp(strTCP.szWifiProtocal, "WPA2")  == 0)
		   {
			   stWF.bProtocal = 3;
		   }
		   
		   //Pairwise
		   if (strcmp(strTCP.szWifiPairwise, "TKIP")  == 0)
		   {
			   stWF.bPairwise = d_WIFI_PAIRWISE_TKIP;
		   }
		   else if (strcmp(strTCP.szWifiPairwise, "CCMP")  == 0)
		   {
			   stWF.bPairwise = d_WIFI_PAIRWISE_CCMP;
		   }
		   else if (strcmp(strTCP.szWifiPairwise, "CCMPTKI")  == 0)
		   {
			   stWF.bPairwise = d_WIFI_PAIRWISE_TKIPCCMP;
		   }
		   
		   //Group
		   if (strcmp(strTCP.szWifiGroup, "TKIP")  == 0)
		   {
			   stWF.bGroup = d_WIFI_GROUP_TKIP;
		   }
		   else if (strcmp(strTCP.szWifiGroup, "CCMP") == 0)
		   {
			   stWF.bGroup = d_WIFI_GROUP_CCMP;
		   }
		   else if (strcmp(strTCP.szWifiGroup, "CCMPTKI")  == 0)
		   {
			  stWF.bGroup = d_WIFI_GROUP_TKIPCCMP;
		   }
           
           usRes=CTOS_CTMSSetConfig(d_CTMS_WIFI_CONFIG , &stWF);

		   
				   vdDebug_LogPrintf("stWF.IsAutoConnect - %d", stWF.IsAutoConnect);
		   vdDebug_LogPrintf("stWF.IsHidden - %d", stWF.IsHidden);
		   vdDebug_LogPrintf("stWF.baPassword - %s", stWF.baPassword);
		   vdDebug_LogPrintf("stWF.baSSid - %s", stWF.baSSid);
		   vdDebug_LogPrintf("stWF.bProtocal - %d", stWF.bProtocal);
		   vdDebug_LogPrintf("stWF.bGroup - %d", stWF.bGroup);
		   vdDebug_LogPrintf("stWF.bPairwise - %d", stWF.bPairwise);
		   vdDebug_LogPrintf("stWF.strRemoteIP - %s", stWF.strRemoteIP);
		   vdDebug_LogPrintf("stWF.usRemotePort - %d", stWF.usRemotePort);
		   vdDebug_LogPrintf("stWF.bDHCP - %d", stWF.bDHCP);
		   vdDebug_LogPrintf("stWF.strLocalIP - %s", stWF.strLocalIP);
		   vdDebug_LogPrintf("stWF.strMask - %s", stWF.strMask);
		   vdDebug_LogPrintf("stWF.strGateway - %s", stWF.strGateway);
		   vdDebug_LogPrintf("stWF.bSCAN_Mode - %d", stWF.bSCAN_Mode);
    }


	setLCDPrint(8, DISPLAY_POSITION_LEFT, "ANY KEY TO CONTINUE");
	CTOS_KBDGet(&ckey);

	return usRes;
}

int inCTOSS_CheckIntervialDateFrom2013(int y,int m,int d)
{
    int x[13]={0,31,28,31,30,31,30,31,31,30,31,30,31};
    long i,s=0;
    
    for(i=2013;i<y;i++)
    {
        if(i%4==0&&i%100!=0||i%400==0)
            s+=366;
        else 
            s+=365;
    }
            
    if(y%4==0&&y%100!=0||y%400==0)
        x[2]=29;
    
    for(i=1;i<m;i++)
        s+=x[i];
        
    s+=d;

    vdDebug_LogPrintf("Date[%ld]", s);
    return s;
}


int inCTOSS_SettlementCheckTMSDownloadRequest(void)
{
    
    CTMS_UpdateInfo st;
    CTOS_RTC SetRTC;
    int inYear, inMonth, inDate,inDateGap;
    USHORT usStatus, usReterr;
    USHORT usResult;
    USHORT usComType = d_CTMS_NORMAL_MODE;

    USHORT usNetworkType = 0;
    USHORT usEthType = 1;
    BYTE szNetworkName[128+1] = {0};
	int inGPRSSignal;
	STRUCT_SHARLS_COM Sharls_COMData;

    //testonly
    BYTE bKey, baStr[21];
	USHORT usRet;

	char szSerialTID[17+1];
	BYTE szSerialNum[17+1];
	
	CTMS_UpdateInfo stInfo;
	//testonly

    //adc
	if (get_env_int("ADLTYPE") != 1)	
		return d_OK;	
	//adc

	inCTLOS_Updatepowrfail(PFR_IDLE_STATE);
    //only default APP support TMS download
    vdDebug_LogPrintf("Check Default APP");
    if(inCTOSS_TMSCheckIfDefaultApplication() != d_OK)
        return d_NO;
    vdDebug_LogPrintf("Check Main APP");    
    if (inMultiAP_CheckSubAPStatus() == d_OK)
        return d_NO;

	//if(DIAL_UP_MODE == strTCT.inTMSComMode)
		//return d_NO;
    //#define d_CTMS_INFO_LAST_UPDATE_TIME 0x01
    //USHORT CTOS_CTMSGetInfo(IN BYTE Info_ID, IN void *stInfo);
    usResult = CTOS_CTMSGetInfo(d_CTMS_INFO_LAST_UPDATE_TIME, &SetRTC);
	vdDebug_LogPrintf("CTOS_CTMSGetInfo usResult=[%x]",usResult);
	//if(d_OK != usResult && d_CTMS_NO_INFO_DATA != usResult)
    //    return d_NO;


	if (d_OK == usResult)
	{
	    inYear = SetRTC.bYear;
	    inMonth = SetRTC.bMonth;
	    inDate = SetRTC.bDay;
	    CTOS_RTCGet(&SetRTC);

	    //inDateGap = inCTOSS_CheckIntervialDateFrom2013(SetRTC.bYear, SetRTC.bMonth, SetRTC.bDay) - inCTOSS_CheckIntervialDateFrom2013(inYear, inMonth, inDate);

		inDateGap = inCTOSS_CheckIntervialDateFrom2013((SetRTC.bYear+2000), SetRTC.bMonth, SetRTC.bDay) - inCTOSS_CheckIntervialDateFrom2013((inYear+2000), inMonth, inDate);
		 

		vdDebug_LogPrintf("inDateGap=[%d],strTCT.usTMSGap=[%d]",inDateGap,strTCT.usTMSGap);

		if(inDateGap < strTCT.usTMSGap)
	        return d_NO;
	}


#if 1
		vdDebug_LogPrintf("ADC TEST FOR INVALID SERIAL");
		if (inMMTReadRecord(1,1) == d_OK) {
			memset(szSerialTID, 0x00, sizeof(szSerialTID));
			sprintf(szSerialTID,"00000000%s", srTransRec.szTID);
	
			vdDebug_LogPrintf("TID %s", szSerialTID);
	
			
			memset(szSerialNum, 0x00, sizeof(szSerialNum));
			CTOS_CTMSGetConfig(d_CTMS_SERIALNUM, szSerialNum);
	
			
			vdDebug_LogPrintf("szSerialNum %s", szSerialNum);
				
			if (strcmp(szSerialTID, szSerialNum) != 0){
				
				vdDisplayErrorMsgResp2("","INVALID","SERIAL NUMBER");
				inDLTrigger = MANUAL_DOWNLOAD;

				if(inFLGGet("fADCReport") == TRUE){
					inCTOSS_TMSBackUpDetailData();//save for powerfail
					inPrintADCReport(3);
				}
		   
				return d_NO;
	
			}
	
	
		}
#endif



	if (GPRS_MODE == strTCT.inTMSComMode){


       inGPRSSignal = inCTOSS_GetGPRSSignalEx(&usNetworkType, szNetworkName,&usEthType);
	   if (inGPRSSignal <=0){
	   	
			vdDisplayErrorMsgResp2("","GPRS","NO SIGNAL");
			inDLTrigger = AUTO_DOWNLOAD;

	   		if(inFLGGet("fADCReport") == TRUE){
				inCTOSS_TMSBackUpDetailData();//save for powerfail
		   		inPrintADCReport(2);
	   		}
	   
	   		return d_NO;

	   }
	}

	if (ETHERNET_MODE == strTCT.inTMSComMode){


	   if(inCheckConnection() != d_OK){	   

	   	
			vdDisplayErrorMsgResp2("","CONNECTION","TERMINATED");
			inDLTrigger = AUTO_DOWNLOAD;

	   		if(inFLGGet("fADCReport") == TRUE){
				inCTOSS_TMSBackUpDetailData();//save for powerfail
		   		inPrintADCReport(2);
	   		}
	   
	   		return d_NO;

	   }
	}
	

    //check if batch settle
    //should check all application?
    vdDebug_LogPrintf("Check Batch Empty");
    //if(inCTOSS_TMSChkBatchEmpty() != d_OK)
        //return d_NO;
    //if(inCheckBatchEmtpy() > 0)
    //add checking if there's pending reversal
    if((inCountBatchesWithTxn() > 0) || (inCheckPendingReversal_for_CTMS() == 1))
        return d_NO;	

    //check if TMS is downloading
    //vdDebug_LogPrintf("Check Get Status");
    //usResult = CTOS_CTMSGetStatus(&usStatus, &usReterr);
    //if (usResult == d_CTMS_UPDATE_FINISHED)
    //{
    //    strTCT.usTMSStatus = FALSE;
    //    inTCTSave(1);        
    //}
    //else
    //{
    //    return d_NO;
    //}
    //vdDebug_LogPrintf("Check Get Status %d %d", usStatus, usReterr);
    if(ETHERNET_MODE == strTCT.inTMSComMode)
        usComType = d_CTMS_DEFAULT_ETHERNET;
    else if(DIAL_UP_MODE == strTCT.inTMSComMode)
        usComType = d_CTMS_NAC_DEFAULT_MODEM;
    else if(GPRS_MODE == strTCT.inTMSComMode)
        usComType = d_CTMS_DEFAULT_GPRS;
	else if(WIFI_MODE == strTCT.inTMSComMode)
        usComType = d_CTMS_DEFAULT_WIFI;

    
    vdDebug_LogPrintf("inCTOSS_TMSPreConfig");
    usResult = inCTOSS_TMSPreConfig2(usComType);
    vdDebug_LogPrintf("inCTOSS_TMSPreConfig ret[%d] usComType[%d]", usResult, strTCT.inTMSComMode);

//test only
/*
    setLCDPrint(8, DISPLAY_POSITION_LEFT, "TMS Download");
    CTOS_Delay(10000);
    return d_OK;
*/
#if 0
		//CTOS_CTMSInitDaemonProcess(d_CTMS_DEFAULT_GPRS);
		inDLTrigger = AUTO_DOWNLOAD;

		CTOS_LCDTClearDisplay();
		CTOS_LCDTPrintXY(1, 8, "PLEASE WAIT...");      
		usResult = CTOS_CTMSInitDaemonProcess(usComType);

		vdDebug_LogPrintf("CTOS_CTMSInitDaemonProcess %d",usResult );

    	if (usResult != d_OK) {        
			memset(baStr, 0x00, sizeof (baStr));        
			sprintf(baStr, "Ret = 0x%04X        ", usRet);       
			/*              d_CTMS_CONFIG_ERROR(0x5705): CTMS didn't this communication setting.        
			d_CTMS_COMMUNICATION_NOT_READY(0x5706): This communication is not ready.        
			d_CTMS_PROCESSING(0x5707): The demon process is running.         */        
			//CTOS_LCDTPrintXY(1, 2, baStr);        
			//CTOS_LCDTPrintXY(1, 3, "Initial Daemon Fail ");        
			//CTOS_LCDTPrintXY(1, 8, "Press any key leave ");        
			//CTOS_KBDGet(&bKey);      
			vdDisplayErrorMsgResp2("CTMS","INITIALIZE","FAILED");
			return 1;    
		}	
	

	REGET:    
		//Warning: If demon process is already starting, appcation can't switch communication mode. Because the CTMS will create new socket for this demon process.	CTOS_KBDHit(&bKey);	
		//if(bKey != d_KBD_CANCEL) {		
			usRet = CTOS_CTMSGetUpdateType(&stInfo);		
			if (usRet == d_CTMS_PROCESSING) {			
				goto REGET;		
		}	//}	
	
	
		vdDebug_LogPrintf("CTOS_CTMSGetUpdateType result = %x",usResult );
	
		vdDebug_LogPrintf("Update Type : %02d", stInfo.bType);

		if (stInfo.bType == 64)
			strcpy(strTMSDetail.szUpdateType,"PARAMETER");
		else if (stInfo.bType == 0)
			strcpy(strTMSDetail.szUpdateType,"NO UPDATE");
		else
			strcpy(strTMSDetail.szUpdateType,"APPLICATION");
#endif	
	//testonly


	//if(inFLGGet("fADCReport") == TRUE)
	{
		inDLTrigger = AUTO_DOWNLOAD;	
		strTMSDetail.inDLTrigger = AUTO_DOWNLOAD;
		inCTOSS_TMSBackUpDetailData(); // BackUp for printing 
		//inCTOSS_TMSBackUpStatusData(); // BackUp for printing
	}

	if(inFLGGet("fCTMSBackUp") == TRUE)
		inCTOSS_TMSBackupTxnData(); // BackUp MMTid/HDTid/InvoinceNo/LastInvoiceNo
		
    CTOS_CTMSUtility(usComType);
    
    /*usResult = CTOS_CTMSInitDaemonProcess(usComType);
    vdDebug_LogPrintf("CTOS_CTMSInitDaemonProcess ret[%d]", usResult);
    
    usResult = CTOS_CTMSGetUpdateType(&st);
    vdDebug_LogPrintf("CTOS_CTMSInitDaemonProcess ret[%d]st.bNums[%d]", usResult, st.bNums);
    if(usResult == d_OK && st.bNums > 0)
    {
        strTCT.usTMSStatus = TRUE;
        inTCTSave(1);
        
        CTOS_CTMSUtility(usComType);
    }*/

	inCTLOS_Updatepowrfail(PFR_IDLE_STATE);
    return d_OK;
}

int inCTOSS_CheckIfPendingTMSDownload(void)
{
    USHORT usResult;
    USHORT usStatus, usReterr;
    BYTE bDisplayBuf[50];
    USHORT i, loop = 0;
    USHORT usComType = d_CTMS_NORMAL_MODE;


    //if(FALSE == strTCT.usTMSStatus)
    //    return d_OK;

    CTOS_LCDTClearDisplay();

    if(ETHERNET_MODE == strCPT.inCommunicationMode)
        usComType = d_CTMS_DEFAULT_ETHERNET;
    else if(DIAL_UP_MODE == strCPT.inCommunicationMode)
        usComType = d_CTMS_DEFAULT_MODEM;
    else if(GPRS_MODE == strCPT.inCommunicationMode)
        usComType = d_CTMS_DEFAULT_GPRS;


    usResult = CTOS_CTMSGetStatus(&usStatus, &usReterr);
    vdDebug_LogPrintf("CTOS_CTMSGetStatus usResult[%d] usStatus[%d] usReterr[%d]", usResult, usStatus, usReterr);
    if (usResult == d_CTMS_UPDATE_FINISHED)
    {
        //strTCT.usTMSStatus = FALSE;
        //inTCTSave(1);
            
        return d_OK;
    }
    else
    {
        CTOS_CTMSUtility(usComType);
    }
}


int inCTOSS_TMSDownloadRequest(void)
{
    
    CTMS_UpdateInfo st;
    CTOS_RTC SetRTC;
    int inYear, inMonth, inDate,inDateGap;
    USHORT usStatus, usReterr;
    USHORT usResult;
    USHORT usComType = d_CTMS_NORMAL_MODE;
	CTMS_UpdateInfo stInfo;

	
    CTMS_GPRSInfo stgprs;    

    //testonly
    BYTE bKey, baStr[21];
	USHORT usRet;

	char szSerialTID[17+1];
	BYTE szSerialNum[17+1];
	//testonly

    int inRet;

    USHORT usNetworkType = 0;
    USHORT usEthType = 1;
    BYTE szNetworkName[128+1] = {0};
	int inGPRSSignal;
	STRUCT_SHARLS_COM Sharls_COMData;


	put_env_int("POWERFAILTMS", 1); //set flag to 1 for POWERFAILTMS

	CTOS_LCDTClearDisplay();
	vdDispTitleString("CTMS Init");
    CTOS_LCDTPrintXY (1,8, "Please Wait");
	
    //only default APP support TMS download
    vdDebug_LogPrintf("Check Default APP");
    if(inCTOSS_TMSCheckIfDefaultApplication() != d_OK)
        return d_NO;
    vdDebug_LogPrintf("Check Main APP");    
    if (inMultiAP_CheckSubAPStatus() == d_OK)
        return d_NO;
	
    //#define d_CTMS_INFO_LAST_UPDATE_TIME 0x01
    //USHORT CTOS_CTMSGetInfo(IN BYTE Info_ID, IN void *stInfo);
    //usResult = CTOS_CTMSGetInfo(d_CTMS_INFO_LAST_UPDATE_TIME, &SetRTC);
	//vdDebug_LogPrintf("CTOS_CTMSGetInfo usResult=[%x]",usResult);
	//if(d_OK != usResult && d_CTMS_NO_INFO_DATA != usResult)
    //    return d_NO;


   //invalid serial

#if 1 
	vdDebug_LogPrintf("ADC TEST FOR INVALID SERIAL");
    if (inMMTReadRecord(1,1) == d_OK) {
		memset(szSerialTID, 0x00, sizeof(szSerialTID));
		sprintf(szSerialTID,"00000000%s", srTransRec.szTID);

		vdDebug_LogPrintf("TID %s", szSerialTID);

		
		memset(szSerialNum, 0x00, sizeof(szSerialNum));
		CTOS_CTMSGetConfig(d_CTMS_SERIALNUM, szSerialNum);

		
		vdDebug_LogPrintf("szSerialNum %s", szSerialNum);
			
        if (strcmp(szSerialTID, szSerialNum) != 0){
			
			vdDisplayErrorMsgResp2("","INVALID","SERIAL NUMBER");
			inDLTrigger = MANUAL_DOWNLOAD;

            
			//strcpy(strTMSDetail.szAppVer,strTCT.szAppVersionHeader);
			
	   		if(inFLGGet("fADCReport") == TRUE){
				inCTOSS_TMSBackUpDetailData();//save for powerfail
		   		inPrintADCReport(3);
	   		}
	   
	   		return d_NO;

        }


	}

  //
   


	//check if connected
	if (ETHERNET_MODE == strTCT.inTMSComMode){


	   //inGPRSSignal = inCTOSS_GetGPRSSignalEx1(&usNetworkType, szNetworkName, &usEthType, &Sharls_COMData);
	   
	   if(inCheckConnection() != d_OK){	   
	   //if (inGPRSSignal <=0){
	   	
			vdDisplayErrorMsgResp2("","CONNECTION","TERMINATED");
			inDLTrigger = MANUAL_DOWNLOAD;

	   		if(inFLGGet("fADCReport") == TRUE){
				inCTOSS_TMSBackUpDetailData();//save for powerfail
		   		inPrintADCReport(2);
	   		}
	   
	   		return d_NO;

	   }
	}


	if (GPRS_MODE == strTCT.inTMSComMode){


	   
       inGPRSSignal = inCTOSS_GetGPRSSignalEx(&usNetworkType, szNetworkName,&usEthType);
	   if (inGPRSSignal <=0){
	   	
			vdDisplayErrorMsgResp2("","GPRS","NO SIGNAL");
			inDLTrigger = MANUAL_DOWNLOAD;

	   		if(inFLGGet("fADCReport") == TRUE){
				inCTOSS_TMSBackUpDetailData();//save for powerfail
		   		inPrintADCReport(2);
	   		}
	   
	   		return d_NO;

	   }
	}


#endif
	
	if((inCountBatchesWithTxn() > 0) || (inCheckPendingReversal_for_CTMS() == 1))
	{
		put_env_int("ADL",1);
		fBatchNotEmpty = TRUE;

		inDLTrigger = MANUAL_DOWNLOAD;

		if(inFLGGet("fADCReport") == TRUE){
			inCTOSS_TMSBackUpDetailData();//save for powerfail
			inPrintADCReport(1);
		}
				
		return d_NO;
	}

    //check if TMS is downloading
    //vdDebug_LogPrintf("Check Get Status");
    //usResult = CTOS_CTMSGetStatus(&usStatus, &usReterr);
    //if (usResult == d_CTMS_UPDATE_FINISHED)
    //{
    //    strTCT.usTMSStatus = FALSE;
    //    inTCTSave(1);        
    //}
    //else
    //{
    //    return d_NO;
    //}
    //vdDebug_LogPrintf("Check Get Status %d %d", usStatus, usReterr);
    
    inCTOS_TMSPreConfigSetting();

	
    
	//if(inCTOS_TMSPreConfigSetting() != d_OK)
	//{
        //vdDisplayErrorMsg(1, 8, "USER CANCEL");
        //return d_NO;		
	//}
	
    if(ETHERNET_MODE == strTCT.inTMSComMode)
        usComType = d_CTMS_DEFAULT_ETHERNET;
    else if(DIAL_UP_MODE == strTCT.inTMSComMode)
        usComType = d_CTMS_DEFAULT_MODEM;
    else if(GPRS_MODE == strTCT.inTMSComMode)
        usComType = d_CTMS_DEFAULT_GPRS;
		else if(WIFI_MODE == strTCT.inTMSComMode)
        usComType = d_CTMS_DEFAULT_WIFI;


	vdDebug_LogPrintf(" before inCTOSS_TMSPreConfig sim slot = %d", stgprs.bSIMSlot );

    vdDebug_LogPrintf("inCTOSS_TMSPreConfig");
    usResult = inCTOSS_TMSPreConfig(usComType);
    vdDebug_LogPrintf("inCTOSS_TMSPreConfig ret[%d] usComType[%d]", usResult, strTCT.inTMSComMode);


	vdDebug_LogPrintf(" after inCTOSS_TMSPreConfig sim slot = %d", stgprs.bSIMSlot );

	inDLTrigger = MANUAL_DOWNLOAD;

	//testonly
	memset(&strTMSDetail, 0x00, sizeof(strTMSDetail));
	#if 0
		//CTOS_CTMSInitDaemonProcess(d_CTMS_DEFAULT_GPRS);
		
		CTOS_LCDTClearDisplay();
		CTOS_LCDTPrintXY(1, 8, "PLEASE WAIT...");      
		usResult = CTOS_CTMSInitDaemonProcess(usComType);

		
		vdDebug_LogPrintf(" before CTOS_CTMSInitDaemonProcess sim slot = %d", stgprs.bSIMSlot );

		//vdDebug_LogPrintf("CTOS_CTMSInitDaemonProcess %d",usResult );

    	if (usResult != d_OK) {        
			memset(baStr, 0x00, sizeof (baStr));        
			sprintf(baStr, "Ret = 0x%04X        ", usRet);       
			/*              d_CTMS_CONFIG_ERROR(0x5705): CTMS didn't this communication setting.        
			d_CTMS_COMMUNICATION_NOT_READY(0x5706): This communication is not ready.        
			d_CTMS_PROCESSING(0x5707): The demon process is running.         */        
			//CTOS_LCDTPrintXY(1, 2, baStr);        
			//CTOS_LCDTPrintXY(1, 3, "Initial Daemon Fail ");        
			//CTOS_LCDTPrintXY(1, 8, "Press any key leave ");        
			//CTOS_KBDGet(&bKey);      
			vdDisplayErrorMsgResp2("CTMS","INITIALIZE","FAILED");
			return 1;    
		}	
	

	REGET:    
		//Warning: If demon process is already starting, appcation can't switch communication mode. Because the CTMS will create new socket for this demon process.	CTOS_KBDHit(&bKey);	
		//if(bKey != d_KBD_CANCEL) {		
			usRet = CTOS_CTMSGetUpdateType(&stInfo);	

		
		vdDebug_LogPrintf(" after  CTOS_CTMSGetUpdateType sim slot = %d", stgprs.bSIMSlot );
			//vdDebug_LogPrintf("CTOS_CTMSGetUpdateType result = %x",usRet );
			if (usRet == d_CTMS_PROCESSING) {			
				goto REGET;		
		}	//}	
		//vdDebug_LogPrintf("CTOS_CTMSInitDaemonProcess result = %x",usResult );
		//usResult = CTOS_CTMSGetUpdateType(&stInfo);
	
	
	
		vdDebug_LogPrintf("Update Type : %02d", stInfo.bType);

		if (stInfo.bType == 64)
			strcpy(strTMSDetail.szUpdateType,"PARAMETER");
		else if (stInfo.bType == 0)
			strcpy(strTMSDetail.szUpdateType,"NO UPDATE");
		else
			strcpy(strTMSDetail.szUpdateType,"APPLICATION");
	#endif	
	//testonly

    

//test only
/*
    setLCDPrint(8, DISPLAY_POSITION_LEFT, "TMS Download");
    CTOS_Delay(10000);
    return d_OK;
*/
	//if(inFLGGet("fADCReport") == TRUE)
	//{
		inDLTrigger = MANUAL_DOWNLOAD;	
	    strTMSDetail.inDLTrigger = MANUAL_DOWNLOAD;
		inCTOSS_TMSBackUpDetailData(); // BackUp for printing 
		//inCTOSS_TMSBackUpStatusData(); // BackUp for printing
	//}
	if(inFLGGet("fCTMSBackUp") == TRUE)
		inCTOSS_TMSBackupTxnData(); // BackUp MMTid/HDTid/InvoinceNo/LastInvoiceNo

	CTOS_LCDTClearDisplay();
	CTOS_LCDTPrintXY (1, 8, "DO NOT TURN OFF...");


    /*before start downlaad, we close current communacation device - 20151102*/
    //CTOS_EthernetClose();
    //inRet = srCommFuncPoint.inInitComm(&srTransRec,GPRS_MODE); 
    //    srCommFuncPoint.inEndComm(&srTransRec); 

	vdDebug_LogPrintf("befor CTOS_TCP_GPRSClose");

	//CTOS_EthernetClose();
    //CTOS_TCP_GPRSClose();

    //vdDebug_LogPrintf("inCTOSS_TMSPreConfig");
    //usResult = inCTOSS_TMSPreConfig(usComType);
    //vdDebug_LogPrintf("inCTOSS_TMSPreConfig ret[%d] usComType[%d]", usResult, strTCT.inTMSComMode);


	//vdDebug_LogPrintf("befor CTOS_CTMSUtility");


	//memset(&stgprs, 0x00, sizeof (CTMS_GPRSInfo));
	//CTOS_CTMSGetConfig(d_CTMS_GPRS_CONFIG, &stgprs);

	//vdDebug_LogPrintf(" before CTOS_CTMSUtility sim slot = %d", stgprs.bSIMSlot );


    CTOS_CTMSUtility(usComType);
    
    /*usResult = CTOS_CTMSInitDaemonProcess(usComType);
    vdDebug_LogPrintf("CTOS_CTMSInitDaemonProcess ret[%d]", usResult);
    
    usResult = CTOS_CTMSGetUpdateType(&st);
    vdDebug_LogPrintf("CTOS_CTMSInitDaemonProcess ret[%d]st.bNums[%d]", usResult, st.bNums);
    if(usResult == d_OK && st.bNums > 0)
    {
        strTCT.usTMSStatus = TRUE;
        inTCTSave(1);
        
        CTOS_CTMSUtility(usComType);
    }*/



	vdDebug_LogPrintf ("inCTOSS_TMSDownloadRequest -- END");

    return d_OK;
}

void inCTOSS_TMS_USBUpgrade(void)
{
    char szSystemCmdPath[250];
    //char szSystemTime[50];
    //CTOS_RTC SetRTC;

	//CTOS_RTCGet(&SetRTC);
    //memset(szSystemTime, 0x00, sizeof(szSystemTime));
    //sprintf(szSystemTime, "%02d" ,SetRTC.bDay);
    
	vduiClearBelow(3);
	CTOS_LCDTPrintXY (1,7, "PLEASE WAIT"); 	  

    memset(szSystemCmdPath, 0x00, sizeof(szSystemCmdPath));                    
    //sprintf(szSystemCmdPath, "cp -f /media/mdisk/vxupdate/V5S_MCCCREDITx.prm .%s", PUBLIC_PATH);
    sprintf(szSystemCmdPath, "cp -f /home/ap/pub/menu.bmp ./media/mdisk/vxupdate/");
    system(szSystemCmdPath);	

    vdDebug_LogPrintf(szSystemCmdPath); 	
}


int inCTOSS_TMSPreConfig2(int inComType)
{    
    CTMS_GPRSInfo stgprs;    
    CTMS_ModemInfo stmodem;    
    CTMS_EthernetInfo st;
    int inNumOfRecords = 0;
    BYTE szSerialNum[17+1], szInputBuf[21+1];
    BYTE count = 2,i;
	BYTE tmpbuf[16 + 1];
	int len;
    unsigned char ckey;
	USHORT usStatusLine=8, usRes=0;
	CTMS_WIFIInfo stWF;
	USHORT usRet;
	BYTE szTemp[4+1];
	
    inHDTRead(1);
    inMMTReadNumofRecords(strHDT.inHostIndex, &inNumOfRecords);
    
    memset(szSerialNum, 0x00, sizeof(szSerialNum));
	memset(tmpbuf, 0x00, sizeof(tmpbuf));

	CTOS_CTMSGetConfig(d_CTMS_SERIALNUM, szSerialNum);
	if(strlen(szSerialNum) <= 0)
	    CTOS_GetFactorySN(szSerialNum);
	for (i=0; i<strlen(szSerialNum); i++)
	{
		if (szSerialNum[i] < 0x30 || szSerialNum[i] > 0x39)
		{
			szSerialNum[i] = 0;
			break;
		}
	}
	len = strlen(szSerialNum);
	strcpy(tmpbuf,"0000000000000000");
	memcpy(&tmpbuf[16-len],szSerialNum,len);
	vdDebug_LogPrintf("szSerialNum=[%s].tmpbuf=[%s]..",szSerialNum,tmpbuf);
	
    CTOS_CTMSSetConfig(d_CTMS_SERIALNUM, tmpbuf);//if TID is 12345678, SN is 0000000012345678
    CTOS_CTMSSetConfig(d_CTMS_RECOUNT, &count);

    if(strTCP.fDHCPEnable)
        CTOS_CTMSSetConfig(d_CTMS_LOCALIP, "0.0.0.0");
    else
        CTOS_CTMSSetConfig(d_CTMS_LOCALIP, strTCP.szTerminalIP);// If it is DHCP, also need to configure any value, otherwise please put the value from database

    if(ETHERNET_MODE == strTCT.inTMSComMode)
    {
        //CTOS_LCDTClearDisplay();
        //vdDispTitleString("ETHERNET SETTINGS");
	
    	vdDebug_LogPrintf("ETHERNET_MODE..");
        memset(&st, 0x00, sizeof (CTMS_EthernetInfo));

		st.bDHCP = strTCP.fDHCPEnable;
		if(strTCP.fDHCPEnable == FALSE)
		{
			strcpy(st.strLocalIP,strTCP.szTerminalIP);
	        strcpy(st.strGateway, strTCP.szGetWay);
	        strcpy(st.strMask, strTCP.szSubNetMask);
		}
		else
		{
			vdPrint_EthernetStatus();
			strcpy(st.strLocalIP,szIP);
	        strcpy(st.strGateway, szGateWay);
	        strcpy(st.strMask, szSubnetMask);			
		}

        strcpy(st.strRemoteIP, strTCT.szTMSRemoteIP);
        st.usRemotePort = strTCT.usTMSRemotePort;

/*
		CTOS_LCDTClearDisplay();
		vdDispTitleString("ETHERNET SETTINGS");

		memset(szSerialNum, 0x00, sizeof(szSerialNum));
		CTOS_CTMSGetConfig(d_CTMS_SERIALNUM, szSerialNum);

        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "SN: %s", szSerialNum);         
        setLCDPrint(2, DISPLAY_POSITION_LEFT, szInputBuf); 

        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "IP: %s", st.strRemoteIP);         
        setLCDPrint(3, DISPLAY_POSITION_LEFT, szInputBuf); 

        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "PORT: %d", st.usRemotePort);         
        setLCDPrint(4, DISPLAY_POSITION_LEFT, szInputBuf); 
*/		
        usRes=CTOS_CTMSSetConfig(d_CTMS_ETHERNET_CONFIG, &st);
    }
    else if(DIAL_UP_MODE == strTCT.inTMSComMode)
    {
			CTMS_NacInfo stNAC;
	
			vdDebug_LogPrintf("DIAL_UP_MODE..");

			memset(&stNAC, 0x00, sizeof (stNAC));
			CTOS_CTMSGetConfig(d_CTMS_NAC_CONFIG, &stNAC);
	
			DebugAddHEX("stNAC.baSourceAddr", stNAC.baSourceAddr, 2);
			DebugAddHEX("stNAC.baDestAddr", stNAC.baDestAddr, 2);
	
			vdDebug_LogPrintf("stNAC.baSourceAddr[%s]..",stNAC.baSourceAddr);
			vdDebug_LogPrintf("stNAC.baDestAddr[%s]..",stNAC.baDestAddr);
			
			memset(szTemp, 0x00, sizeof(szTemp));
			wub_str_2_hex(strTCT.szTMSNACProtocol, szTemp, 2);		  
			stNAC.bProtocol=szTemp[0];
			
			stNAC.usBlockSize=1024;
	
			memset(szTemp, 0x00, sizeof(szTemp));
			wub_str_2_hex(strTCT.szTMSNACSourceAddr, szTemp, 4);		
			memcpy(stNAC.baSourceAddr, szTemp, 2);
	
			memset(szTemp, 0x00, sizeof(szTemp));
			wub_str_2_hex(strTCT.szTMSNACDestAddr, szTemp, 4);				  
			memcpy(stNAC.baDestAddr, szTemp, 2);
	
			
			stNAC.bLenType=0;
			stNAC.bAddLenFlag=0;
			//vdDebug_LogPrintf("DIAL_UP_MODE..");
			
			usRes=CTOS_CTMSSetConfig(d_CTMS_NAC_CONFIG, &stNAC);
			
			//CTOS_LCDTClearDisplay();
			//vdDispTitleString("DIALUP SETTINGS");
	
			memset(&stmodem, 0x00, sizeof (CTMS_ModemInfo));
			CTOS_CTMSGetConfig(d_CTMS_MODEM_CONFIG, &stmodem);
			
			//stmodem.bMode = d_M_MODE_AYNC_FAST;
			//stmodem.bHandShake = d_M_HANDSHAKE_V32BIS_AUTO_FB;
			stmodem.bMode  = d_M_MODE_SDLC_FAST;
			stmodem.bHandShake = d_M_HANDSHAKE_V22_ONLY;
			stmodem.bCountryCode = d_M_COUNTRY_SINGAPORE;
	
			strcpy(stmodem.strRemotePhoneNum, strTCT.szTMSRemotePhone);
			vdDebug_LogPrintf("strRemotePhoneNum[%s]..",stmodem.strRemotePhoneNum);
			strcpy(stmodem.strID, strTCT.szTMSRemoteID);	
			vdDebug_LogPrintf("strID[%s]..",stmodem.strID);
			strcpy(stmodem.strPW, strTCT.szTMSRemotePW);
			vdDebug_LogPrintf("strPW[%s]..",stmodem.strPW);
	
			strcpy(stmodem.strRemoteIP, strTCT.szTMSRemoteIP);
			stmodem.usRemotePort = strTCT.usTMSRemotePort;
	
			stmodem.usPPPRetryCounter = 2;
			stmodem.ulPPPTimeout = 34463;
			stmodem.ulDialTimeout = 34463;
			vdDebug_LogPrintf("strRemoteIP[%s].usRemotePort=[%d].",stmodem.strRemoteIP,stmodem.usRemotePort);
			stmodem.bType = d_CTMS_MODEM; //d_CTMS_TCP_MODEM, d_CTMS_MODEM
			stmodem.ulBaudRate = 115200;
			stmodem.bParity = 'N'; 
			stmodem.bDataBits = 8;
			stmodem.bStopBits = 1;
			stmodem.usDialDuration = 30;				// Dialing maximum total duration in second. Range: 0~255
			stmodem.usDTMFOnTime = 95;				 // DTMF on time in ms.
			stmodem.usDTMFOffTime = 95; 			   // DTMF off time in ms.	  
			stmodem.bTxPowerLevel = 3;				   // Tx Power Level(refer to Modem Functions)
			stmodem.bRxPowerLevel = 3;
			
			//memset(szSerialNum, 0x00, sizeof(szSerialNum));
			//CTOS_CTMSGetConfig(d_CTMS_SERIALNUM, szSerialNum);
	
	/*
			memset(szInputBuf, 0x00, sizeof(szInputBuf));
			sprintf(szInputBuf, "SN: %s", szSerialNum); 		
			setLCDPrint(2, DISPLAY_POSITION_LEFT, szInputBuf); 
	
			memset(szInputBuf, 0x00, sizeof(szInputBuf));
			sprintf(szInputBuf, "IP: %s", stmodem.strRemoteIP); 		
			setLCDPrint(3, DISPLAY_POSITION_LEFT, szInputBuf); 
	
			memset(szInputBuf, 0x00, sizeof(szInputBuf));
			sprintf(szInputBuf, "PORT: %d", stmodem.usRemotePort);		   
			setLCDPrint(4, DISPLAY_POSITION_LEFT, szInputBuf); 
			
			memset(szInputBuf, 0x00, sizeof(szInputBuf));
			sprintf(szInputBuf, "PHONE: %s", stmodem.strRemotePhoneNum);		 
			setLCDPrint(5, DISPLAY_POSITION_LEFT, szInputBuf); 
			
			memset(szInputBuf, 0x00, sizeof(szInputBuf));
			sprintf(szInputBuf, "ID: %s", stmodem.strID);		  
			setLCDPrint(6, DISPLAY_POSITION_LEFT, szInputBuf); 
	
			memset(szInputBuf, 0x00, sizeof(szInputBuf));
			sprintf(szInputBuf, "PASSWORD: %s", stmodem.strPW); 		
			setLCDPrint(6, DISPLAY_POSITION_LEFT, szInputBuf);
	*/
			usRes=CTOS_CTMSSetConfig(d_CTMS_MODEM_CONFIG, &stmodem);
		}
    else if(GPRS_MODE == strTCT.inTMSComMode)
    {
		CTMS_GPRSInfo stgprs;

        //CTOS_LCDTClearDisplay();
        //vdDispTitleString("GPRS SETTINGS");
		
		memset(&stgprs, 0x00, sizeof (CTMS_GPRSInfo));
		CTOS_CTMSGetConfig(d_CTMS_GPRS_CONFIG, &stgprs);
		
        if(strlen(stgprs.strAPN) > 0)
            strcpy(strTCP.szAPN, stgprs.strAPN);

        if(strlen(stgprs.strID) > 0)
            strcpy(strTCP.szUserName, stgprs.strID);

        if(strlen(stgprs.strPW) > 0)
		    strcpy(strTCP.szPassword, stgprs.strPW);
		
              vdDebug_LogPrintf("GPRS_MODE..");
        memset(&stgprs, 0x00, sizeof (CTMS_GPRSInfo));
        strcpy(stgprs.strAPN, strTCP.szAPN);
        strcpy(stgprs.strID, strTCP.szUserName);
        strcpy(stgprs.strPW, strTCP.szPassword);
 
        strcpy(stgprs.strRemoteIP, strTCT.szTMSRemoteIP);
        stgprs.usRemotePort = strTCT.usTMSRemotePort;
        stgprs.ulSIMReadyTimeout = 10000;
        stgprs.ulGPRSRegTimeout = 10000;
        stgprs.usPPPRetryCounter = 5;
        stgprs.ulPPPTimeout = 10000;
        stgprs.ulTCPConnectTimeout = 10000;

		//test
		stgprs.ulTCPTxTimeout=10000;
		stgprs.ulTCPRxTimeout=10000;
		stgprs.bSIMSlot=1;

		memset(szSerialNum, 0x00, sizeof(szSerialNum));
		CTOS_CTMSGetConfig(d_CTMS_SERIALNUM, szSerialNum);

/*
        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "SN: %s", szSerialNum);         
        setLCDPrint(2, DISPLAY_POSITION_LEFT, szInputBuf); 

        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "IP: %s", stgprs.strRemoteIP);		 
        setLCDPrint(3, DISPLAY_POSITION_LEFT, szInputBuf); 

        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "PORT: %d", stgprs.usRemotePort);		 
        setLCDPrint(4, DISPLAY_POSITION_LEFT, szInputBuf);

        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "APN: %s", stgprs.strAPN);		 
        setLCDPrint(5, DISPLAY_POSITION_LEFT, szInputBuf);

        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "USER NAME: %s", stgprs.strID);		 
        setLCDPrint(6, DISPLAY_POSITION_LEFT, szInputBuf);
		
        memset(szInputBuf, 0x00, sizeof(szInputBuf));
        sprintf(szInputBuf, "PASSWORD: %s", stgprs.strPW);		 
        setLCDPrint(7, DISPLAY_POSITION_LEFT, szInputBuf);
*/		
        usRes=CTOS_CTMSSetConfig(d_CTMS_GPRS_CONFIG, &stgprs);
    }

/*
	setLCDPrint(8, DISPLAY_POSITION_LEFT, "ANY KEY TO CONTINUE");
	CTOS_KBDGet(&ckey);
*/

    else if(WIFI_MODE == strTCT.inTMSComMode)
    {
        CTOS_LCDTClearDisplay();
        vdDispTitleString("WIFI SETTINGS");
        
        vdDebug_LogPrintf("WIFI..");
        memset(&stWF, 0x00, sizeof (CTMS_WIFIInfo));
        usRet = CTOS_CTMSGetConfig(d_CTMS_WIFI_CONFIG, &stWF);


		strcpy(stWF.strRemoteIP, strTCT.szTMSRemoteIP);
	    stWF.usRemotePort = strTCT.usTMSRemotePort;

		strcpy(stWF.baPassword, strTCP.szWifiPassword);
		strcpy(stWF.baSSid, strTCP.szWifiSSID);
		//stWF.bProtocal = 3;
		//stWF.bGroup = 2;
		//stWF.bPairwise = 2;
		stWF.bDHCP = strTCP.fDHCPEnable;
		stWF.bSCAN_Mode = 1;
		stWF.IsAutoConnect =48;
		stWF.IsHidden =48;

		memset(stWF.strLocalIP, 0x00, sizeof(stWF.strLocalIP));
		memset(stWF.strMask, 0x00, sizeof(stWF.strMask));	
		memset(stWF.strGateway, 0x00, sizeof(stWF.strGateway));

		if (strTCP.fDHCPEnable){
			strcpy(stWF.strLocalIP, "0.0.0.0");
			strcpy(stWF.strMask, "0.0.0.0");
			strcpy(stWF.strGateway, "0.0.0.0");
		}else{
			strcpy(stWF.strLocalIP, strTCP.szTerminalIP);
			strcpy(stWF.strMask, strTCP.szSubNetMask);
			strcpy(stWF.strGateway, strTCP.szGetWay);
		}
	
		
        //if (usRet != d_OK)
        //{
        //   CTOS_LCDTPrintXY(1, 7, "Please Set CTMS");
        //   vdDisplayErrorMsg(1, 8, "CTMS Get Fail");
        //   return d_NO;
       // }
           CTOS_LCDTClearDisplay();
           vdDispTitleString("WIFI SETTINGS");
        
           memset(szSerialNum, 0x00, sizeof(szSerialNum));
           CTOS_CTMSGetConfig(d_CTMS_SERIALNUM, szSerialNum);
           
           memset(szInputBuf, 0x00, sizeof(szInputBuf));
           sprintf(szInputBuf, "SN: %s", szSerialNum);         
           setLCDPrint(2, DISPLAY_POSITION_LEFT, szInputBuf); 
           
           memset(szInputBuf, 0x00, sizeof(szInputBuf));
           sprintf(szInputBuf, "IP: %s", stWF.strRemoteIP);         
           setLCDPrint(3, DISPLAY_POSITION_LEFT, szInputBuf); 
           
           memset(szInputBuf, 0x00, sizeof(szInputBuf));
           sprintf(szInputBuf, "PORT: %d", stWF.usRemotePort);         
           setLCDPrint(4, DISPLAY_POSITION_LEFT, szInputBuf); 


		   //bProtocal
		   if (strcmp(strTCP.szWifiProtocal, "WEP")  == 0)
		   {
			   stWF.bProtocal = d_WIFI_PROTOCOL_WEP;
		   }
		   else if (strcmp(strTCP.szWifiProtocal, "WPA")  == 0)
		   {
			   stWF.bProtocal = d_WIFI_PROTOCOL_WPA;
		   }
		   else if (strcmp(strTCP.szWifiProtocal, "WPA2")  == 0)
		   {
			   stWF.bProtocal = 3;
		   }
		   
		   //Pairwise
		   if (strcmp(strTCP.szWifiPairwise, "TKIP")  == 0)
		   {
			   stWF.bPairwise = d_WIFI_PAIRWISE_TKIP;
		   }
		   else if (strcmp(strTCP.szWifiPairwise, "CCMP")  == 0)
		   {
			   stWF.bPairwise = d_WIFI_PAIRWISE_CCMP;
		   }
		   else if (strcmp(strTCP.szWifiPairwise, "CCMPTKI")  == 0)
		   {
			   stWF.bPairwise = d_WIFI_PAIRWISE_TKIPCCMP;
		   }
		   
		   //Group
		   if (strcmp(strTCP.szWifiGroup, "TKIP")  == 0)
		   {
			   stWF.bGroup = d_WIFI_GROUP_TKIP;
		   }
		   else if (strcmp(strTCP.szWifiGroup, "CCMP") == 0)
		   {
			   stWF.bGroup = d_WIFI_GROUP_CCMP;
		   }
		   else if (strcmp(strTCP.szWifiGroup, "CCMPTKI")  == 0)
		   {
			  stWF.bGroup = d_WIFI_GROUP_TKIPCCMP;
		   }
           
           usRes=CTOS_CTMSSetConfig(d_CTMS_WIFI_CONFIG , &stWF);

		   	vdDebug_LogPrintf("stWF.IsAutoConnect - %d", stWF.IsAutoConnect);
	vdDebug_LogPrintf("stWF.IsHidden - %d", stWF.IsHidden);
	vdDebug_LogPrintf("stWF.baPassword - %s", stWF.baPassword);
	vdDebug_LogPrintf("stWF.baSSid - %s", stWF.baSSid);
	vdDebug_LogPrintf("stWF.bProtocal - %d", stWF.bProtocal);
	vdDebug_LogPrintf("stWF.bGroup - %d", stWF.bGroup);
	vdDebug_LogPrintf("stWF.bPairwise - %d", stWF.bPairwise);
	vdDebug_LogPrintf("stWF.strRemoteIP - %s", stWF.strRemoteIP);
	vdDebug_LogPrintf("stWF.usRemotePort - %d", stWF.usRemotePort);
	vdDebug_LogPrintf("stWF.bDHCP - %d", stWF.bDHCP);
	vdDebug_LogPrintf("stWF.strLocalIP - %s", stWF.strLocalIP);
	vdDebug_LogPrintf("stWF.strMask - %s", stWF.strMask);
	vdDebug_LogPrintf("stWF.strGateway - %s", stWF.strGateway);
	vdDebug_LogPrintf("stWF.bSCAN_Mode - %d", stWF.bSCAN_Mode);
    }

	return usRes;
}


//adc
int inCTOSS_ADLSettlementCheckTMSDownloadRequest(void)
{
    
    CTMS_UpdateInfo st;
    CTOS_RTC SetRTC;
    int inYear, inMonth, inDate,inDateGap;
    USHORT usStatus, usReterr;
    USHORT usResult;
    USHORT usComType = d_CTMS_NORMAL_MODE;
	
    USHORT usNetworkType = 0;
    USHORT usEthType = 1;
    BYTE szNetworkName[128+1] = {0};
	int inGPRSSignal;
	
    //testonly
    BYTE bKey, baStr[21];
	USHORT usRet;

	char szSerialTID[17+1];
	BYTE szSerialNum[17+1];
	
	CTMS_UpdateInfo stInfo;
	//testonly
	STRUCT_SHARLS_COM Sharls_COMData;

	inCTLOS_Updatepowrfail(PFR_IDLE_STATE);

	
	CTOS_LCDTClearDisplay();
	vdDispTitleString("CTMS Init");
    CTOS_LCDTPrintXY (1,8, "Please Wait");


    vdDebug_LogPrintf("TEST 1");

    //only default APP support TMS download
    vdDebug_LogPrintf("Check Default APP");
    if(inCTOSS_TMSCheckIfDefaultApplication() != d_OK)
        return d_NO;
    vdDebug_LogPrintf("Check Main APP");    
    if (inMultiAP_CheckSubAPStatus() == d_OK)
        return d_NO;

	//if(DIAL_UP_MODE == strTCT.inTMSComMode)
		//return d_NO;
    //#define d_CTMS_INFO_LAST_UPDATE_TIME 0x01
    //USHORT CTOS_CTMSGetInfo(IN BYTE Info_ID, IN void *stInfo);
    usResult = CTOS_CTMSGetInfo(d_CTMS_INFO_LAST_UPDATE_TIME, &SetRTC);
	vdDebug_LogPrintf("CTOS_CTMSGetInfo usResult=[%x]",usResult);
	//if(d_OK != usResult && d_CTMS_NO_INFO_DATA != usResult)
    //    return d_NO;

	if (inADLTimeRangeUsed == 1)
		put_env_int("ADLTRY1",1);	
	else if (inADLTimeRangeUsed == 2)
		put_env_int("ADLTRY2",1);	
	else if (inADLTimeRangeUsed == 3)
		put_env_int("ADLTRY3",1);	


//testonly
#if 1
	if (d_OK == usResult)
	{
	    inYear = SetRTC.bYear;
	    inMonth = SetRTC.bMonth;
	    inDate = SetRTC.bDay;
	    CTOS_RTCGet(&SetRTC);

	    //inDateGap = inCTOSS_CheckIntervialDateFrom2013(SetRTC.bYear, SetRTC.bMonth, SetRTC.bDay) - inCTOSS_CheckIntervialDateFrom2013(inYear, inMonth, inDate);

		inDateGap = inCTOSS_CheckIntervialDateFrom2013((SetRTC.bYear+2000), SetRTC.bMonth, SetRTC.bDay) - inCTOSS_CheckIntervialDateFrom2013((inYear+2000), inMonth, inDate);
		 

		vdDebug_LogPrintf("inDateGap=[%d],strTCT.usTMSGap=[%d]",inDateGap,strTCT.usTMSGap);

		if(inDateGap < strTCT.usTMSGap)
	        return d_NO;
	}
#endif

    //check if batch settle
    //should check all application?
    //vdDebug_LogPrintf("Check Batch Empty");
    //if(inCTOSS_TMSChkBatchEmpty() != d_OK)
        //return d_NO;
    //if(inCheckBatchEmtpy() > 0)
    //    return d_NO;	

    //check if TMS is downloading
    //vdDebug_LogPrintf("Check Get Status");
    //usResult = CTOS_CTMSGetStatus(&usStatus, &usReterr);
    //if (usResult == d_CTMS_UPDATE_FINISHED)
    //{
    //    strTCT.usTMSStatus = FALSE;
    //    inTCTSave(1);        
    //}
    //else
    //{
    //    return d_NO;
    //}
    //vdDebug_LogPrintf("Check Get Status %d %d", usStatus, usReterr);
    if(ETHERNET_MODE == strTCT.inTMSComMode)
        usComType = d_CTMS_DEFAULT_ETHERNET;
    else if(DIAL_UP_MODE == strTCT.inTMSComMode)
        usComType = d_CTMS_NAC_DEFAULT_MODEM;
    else if(GPRS_MODE == strTCT.inTMSComMode)
        usComType = d_CTMS_DEFAULT_GPRS;
	else if(WIFI_MODE == strTCT.inTMSComMode)
        usComType = d_CTMS_DEFAULT_WIFI;
	
    vdDebug_LogPrintf("inCTOSS_TMSPreConfig");
	//CTOS_LCDTClearDisplay();
    usResult = inCTOSS_TMSPreConfig2(usComType);
    vdDebug_LogPrintf("inCTOSS_TMSPreConfig ret[%d] usComType[%d]", usResult, strTCT.inTMSComMode);

//test only
/*
    setLCDPrint(8, DISPLAY_POSITION_LEFT, "TMS Download");
    CTOS_Delay(10000);
    return d_OK;
*/


#if 1
		vdDebug_LogPrintf("ADC TEST FOR INVALID SERIAL");
		if (inMMTReadRecord(1,1) == d_OK) {
			memset(szSerialTID, 0x00, sizeof(szSerialTID));
			sprintf(szSerialTID,"00000000%s", srTransRec.szTID);
	
			vdDebug_LogPrintf("TID %s", szSerialTID);
	
			
			memset(szSerialNum, 0x00, sizeof(szSerialNum));
			CTOS_CTMSGetConfig(d_CTMS_SERIALNUM, szSerialNum);
	
			
			vdDebug_LogPrintf("szSerialNum %s", szSerialNum);
				
			if (strcmp(szSerialTID, szSerialNum) != 0){
				
				vdDisplayErrorMsgResp2("","INVALID","SERIAL NUMBER");
				inDLTrigger = AUTO_DOWNLOAD;
	
				if(inFLGGet("fADCReport") == TRUE){
					inCTOSS_TMSBackUpDetailData();//save for powerfail
					inPrintADCReport(3);
				}
		   
				return d_NO;
	
			}
	
	
		}
#endif

	//check if connected
	
	if (ETHERNET_MODE == strTCT.inTMSComMode){


	   if(inCheckConnection() != d_OK){	   
	   	
			vdDisplayErrorMsgResp2("","CONNECTION","TERMINATED");
			inDLTrigger = AUTO_DOWNLOAD;

	   		if(inFLGGet("fADCReport") == TRUE){
				inCTOSS_TMSBackUpDetailData();//save for powerfail
		   		inPrintADCReport(2);
	   		}
	   
	   		return d_NO;

	   }
	}
	
	if (GPRS_MODE == strTCT.inTMSComMode){


       inGPRSSignal = inCTOSS_GetGPRSSignalEx(&usNetworkType, szNetworkName,&usEthType);
	   if (inGPRSSignal <=0){
	   	
			vdDisplayErrorMsgResp2("","GPRS","NO SIGNAL");
			inDLTrigger = AUTO_DOWNLOAD;

	   		if(inFLGGet("fADCReport") == TRUE){
				inCTOSS_TMSBackUpDetailData();//save for powerfail
		   		inPrintADCReport(2);
	   		}
	   
	   		return d_NO;

	   }
	}

	inDLTrigger = AUTO_DOWNLOAD;

	if((inCountBatchesWithTxn() > 0) || (inCheckPendingReversal_for_CTMS() == 1))
	{
		put_env_int("ADL",1);
		fBatchNotEmpty = TRUE;

		if(inFLGGet("fADCReport") == TRUE){
			inCTOSS_TMSBackUpDetailData();//save for powerfail
			inPrintADCReport(1);
		}
				
		return d_NO;
	}


#if 0
		//CTOS_CTMSInitDaemonProcess(d_CTMS_DEFAULT_GPRS);
		
		CTOS_LCDTClearDisplay();
		CTOS_LCDTPrintXY(1, 8, "PLEASE WAIT...");      
		usResult = CTOS_CTMSInitDaemonProcess(usComType);

		vdDebug_LogPrintf("CTOS_CTMSInitDaemonProcess %d",usResult );

    	if (usResult != d_OK) {        
			memset(baStr, 0x00, sizeof (baStr));        
			sprintf(baStr, "Ret = 0x%04X        ", usRet);       
			/*              d_CTMS_CONFIG_ERROR(0x5705): CTMS didn't this communication setting.        
			d_CTMS_COMMUNICATION_NOT_READY(0x5706): This communication is not ready.        
			d_CTMS_PROCESSING(0x5707): The demon process is running.         */        
			//CTOS_LCDTPrintXY(1, 2, baStr);        
			//CTOS_LCDTPrintXY(1, 3, "Initial Daemon Fail ");        
			//CTOS_LCDTPrintXY(1, 8, "Press any key leave ");        
			//CTOS_KBDGet(&bKey);      
			vdDisplayErrorMsgResp2("CTMS","INITIALIZE","FAILED");
			return 1;    
		}	
	

	REGET:    
		//Warning: If demon process is already starting, appcation can't switch communication mode. Because the CTMS will create new socket for this demon process.	CTOS_KBDHit(&bKey);	
		//if(bKey != d_KBD_CANCEL) {		
			usRet = CTOS_CTMSGetUpdateType(&stInfo);		
			if (usRet == d_CTMS_PROCESSING) {			
				goto REGET;		
		}	//}	
		//vdDebug_LogPrintf("CTOS_CTMSInitDaemonProcess result = %x",usResult );
		//usResult = CTOS_CTMSGetUpdateType(&stInfo);
	
	
		vdDebug_LogPrintf("CTOS_CTMSGetUpdateType result = %x",usResult );
	
		vdDebug_LogPrintf("Update Type : %02d", stInfo.bType);

		if (stInfo.bType == 64)
			strcpy(strTMSDetail.szUpdateType,"PARAMETER");
		else if (stInfo.bType == 0)
			strcpy(strTMSDetail.szUpdateType,"NO UPDATE");
		else
			strcpy(strTMSDetail.szUpdateType,"APPLICATION");
#endif	
	//testonly

	//if(inFLGGet("fADCReport") == TRUE)
	{
	   
	    strTMSDetail.inDLTrigger = AUTO_DOWNLOAD;
		inDLTrigger = AUTO_DOWNLOAD;	
		inCTOSS_TMSBackUpDetailData(); // BackUp for printing 
		//inCTOSS_TMSBackUpStatusData(); // BackUp for printing
	}

	if(inFLGGet("fCTMSBackUp") == TRUE)
		inCTOSS_TMSBackupTxnData(); // BackUp MMTid/HDTid/InvoinceNo/LastInvoiceNo
		
    CTOS_CTMSUtility(usComType);
    
    /*usResult = CTOS_CTMSInitDaemonProcess(usComType);
    vdDebug_LogPrintf("CTOS_CTMSInitDaemonProcess ret[%d]", usResult);
    
    usResult = CTOS_CTMSGetUpdateType(&st);
    vdDebug_LogPrintf("CTOS_CTMSInitDaemonProcess ret[%d]st.bNums[%d]", usResult, st.bNums);
    if(usResult == d_OK && st.bNums > 0)
    {
        strTCT.usTMSStatus = TRUE;
        inTCTSave(1);
        
        CTOS_CTMSUtility(usComType);
    }*/

	inCTLOS_Updatepowrfail(PFR_IDLE_STATE);
    return d_OK;
}
//adc


/*backup transaction data should be by merchant and by host, so follow the MMT*/
int inCTOSS_TMSBackupTxnData(void)
{
	BOOL fInvoiceNo = FALSE;
	int inMMTNum = 0;
	int inIdx = 0;
	int inRet = d_OK;
	int inMerchID[400]={0};
	
	//TXN_BAK_DATA		strTBD;
	//extern STRUCT_MMT strMMTRec;

	vdDebug_LogPrintf("=====inCTOSS_TMSBackupTxnData=====");

	
	if (inCheckFileExist(TBD_FILE_NAME) == d_OK)
		inRemoveConfRecFile(TBD_FILE_NAME);

	CTOS_LCDTPrintXY (1, 7, "Saving");
	CTOS_LCDTPrintXY (1, 8, "Transaction Data..");
	CTOS_Delay(2000);

	inTCTRead(1);
	
	/*the backup txn data record depend on the merchant record*/
	
	/*get transaction data by MMT*/
	inDatabase_TerminalOpenDatabase();
	inMMTEnabledMerchants(inMerchID);
	inMMTNum = inMMTEnabledMerchants(inMerchID);
	vdDebug_LogPrintf("inMMTNumRecord[%d]", inMMTNum);
	for (inIdx=0; inIdx<inMMTNum; inIdx++)
	{
		vdDebug_LogPrintf("MMTid %d",inMerchID[inIdx]);
		
		memset(&strTBD, 0x00, sizeof(TXN_BAK_DATA));
		memset(&strMMTRec,0x00,sizeof(STRUCT_MMT));
		
		inMMTReadSelectedData(inMerchID[inIdx]);
		strMMTRec.MMTid = inMerchID[inIdx];
		vdDebug_LogPrintf("inIdx[%d]MMTid[%d]HDTid[%d] MITid[%d]", inIdx,strMMTRec.MMTid, strMMTRec.HDTid, strMMTRec.MITid);

		/*HDTid*/
		strTBD.inHDTid = strMMTRec.HDTid;

		/*MITid*/
		strTBD.inMITid = strMMTRec.MITid;

		/*Batch number*/
		memcpy(strTBD.szBatchNo, strMMTRec.szBatchNo, BATCH_NO_BCD_SIZE);

		/*Trace number get from HDT, (will it be set in MMT???)*/
		inHDTReadEx(strMMTRec.HDTid);
		memcpy(strTBD.szTraceNo, strHDT.szTraceNo, TRACE_NO_BCD_SIZE);

		if (!fInvoiceNo)  
		{
			/*Invoice No*/
			memcpy(strTBD.szInvoiceNo, strTCT.szInvoiceNo, INVOICE_BCD_SIZE);
			memcpy(strTBD.szLastInvoiceNo, strTCT.szLastInvoiceNo, INVOICE_BCD_SIZE);
			fInvoiceNo = TRUE;  
		}
		
		
		DebugAddHEX("strTBD.szBatchNo", strTBD.szBatchNo, 3);
		DebugAddHEX("strTBD.szTraceNo", strTBD.szTraceNo, 3);
		DebugAddHEX("strTBD.szInvoiceNo", strTBD.szInvoiceNo, 3);
		DebugAddHEX("strTBD.szInvoiceNo", strTBD.szLastInvoiceNo, 3);

		/*Save to backup file -- append only*/
		inRet = inAppendConfRec(TBD_FILE_NAME, sizeof(TXN_BAK_DATA), (char *)&strTBD);
		vdDebug_LogPrintf("Save Rec[%d]", inRet);
	}
	
	inDatabase_TerminalCloseDatabase();
	return d_OK;
	
}

int inCTOSS_TMSBackUpDetailData(void)
{
	int inRet = d_OK;
	char szTemp1[d_LINE_SIZE + 1] = {0};
	char szTemp2[d_LINE_SIZE + 1] = {0};
	CTMS_UpdateInfo st;
    CTMS_GPRSInfo stgprs;     
    CTMS_EthernetInfo stEth;
	CTMS_WIFIInfo stWF;
	//CTOS_RTC GetPreDL_RTC;
	//TMS_DETAIL_DATA	strTMSDetail;
	//extern STRUCT_MMT strMMTRec;
	
	//memset(&strTMSDetail, 0x00, sizeof(strTMSDetail));
		
	vdDebug_LogPrintf("--inCTOSS_TMSBackUpDetailData--");

	if (inCheckFileExist(TMS_DETAIL_FILE_NAME) == d_OK)
		inRemoveConfRecFile(TMS_DETAIL_FILE_NAME);
#if 0
//	Save Backup RTC to PREDLRTC in case of power off scenario causing empty TMS Detail structure.
	CTOS_RTCGet(&GetPreDL_RTC);
	memset(szTemp1,0x00,sizeof(szTemp1));
	sprintf(szTemp1,"GetPreDL_RTC : %d%02d%02d%02d%02d%02d",2000+GetPreDL_RTC.bYear,GetPreDL_RTC.bMonth,GetPreDL_RTC.bDay,GetPreDL_RTC.bHour,GetPreDL_RTC.bMinute,GetPreDL_RTC.bSecond);
	vdDebug_LogPrintf("REINER :: GetPreDL_RTC %s",szTemp1);
	inCTOSS_PutEnvDB("PREDLRTC",szTemp1);
#endif
	CTOS_LCDTClearDisplay();
	CTOS_LCDTPrintXY (1, 8, "Saving CTMS Data..");
	CTOS_Delay(2000);
	
	vdDebug_LogPrintf("inDLTrigger=[%d]", inDLTrigger);

	//inRet = inMMTReadRecord(1, 1);
	//strcpy(strTMSDetail.szTID,srTransRec.szTID);
	//strcpy(strTMSDetail.szMID,srTransRec.szMID);
		
	inTCTRead(1);
	
	// DLTrigger
	strTMSDetail.inDLTrigger = inDLTrigger;

	// Days Gap
	memset(szTemp1,0x00,sizeof(szTemp1));
	sprintf(szTemp1,"%d",strTCT.usTMSGap);
	strcpy(strTMSDetail.szDayGap, szTemp1);

	
	// TerminalIP
	memset(szIP, 0x00, sizeof(szIP));
	if (strCPT.inCommunicationMode == GPRS_MODE)
		inCTOSS_SIMGetGPRSIPInfo();
	else if (strCPT.inCommunicationMode == WIFI_MODE)
		inWIFI_GetConnectConfig();
	else
	{
		if(strTCP.fDHCPEnable == 1)
			vdPrint_EthernetStatus();
		else
			strcpy(szIP,(char *)strTCP.szTerminalIP);			
	}
	
	// Server IP/Port
	memset(szTemp1,0x00,sizeof(szTemp1));
	memset(szTemp2,0x00,sizeof(szTemp2));
	if(strCPT.inCommunicationMode == ETHERNET_MODE)
	{
		vdDebug_LogPrintf("");
		memset(&stEth,0x00,sizeof(CTMS_EthernetInfo));
		CTOS_CTMSGetConfig(d_CTMS_ETHERNET_CONFIG, &stEth);
		strcpy(szTemp1,stEth.strRemoteIP);
		sprintf(szTemp2,"%d",stEth.usRemotePort);
	}
	else if(strCPT.inCommunicationMode == GPRS_MODE)
	{
		memset(&stgprs,0x00,sizeof(CTMS_GPRSInfo));
		CTOS_CTMSGetConfig(d_CTMS_GPRS_CONFIG, &stgprs);	
		strcpy(szTemp1,stgprs.strRemoteIP);
		sprintf(szTemp2,"%d",stgprs.usRemotePort);
	}
	else if(strCPT.inCommunicationMode == WIFI_MODE)
	{
		memset(&stWF,0x00,sizeof(CTMS_WIFIInfo));
		CTOS_CTMSGetConfig(d_CTMS_WIFI_CONFIG, &stWF);	
		strcpy(szTemp1,stWF.strRemoteIP);
		sprintf(szTemp2,"%d",stWF.usRemotePort);
	}


	//Get ADC Start and End times
	inCTOSS_GetEnvDB ("ADL1START", strTMSDetail.szADCStartTime1); 
	inCTOSS_GetEnvDB ("ADL1END", strTMSDetail.szADCEndTime1);
	inCTOSS_GetEnvDB ("ADL2START", strTMSDetail.szADCStartTime2); 
	inCTOSS_GetEnvDB ("ADL2END", strTMSDetail.szADCEndTime2);
	inCTOSS_GetEnvDB ("ADL3START", strTMSDetail.szADCStartTime3); 
	inCTOSS_GetEnvDB ("ADL3END", strTMSDetail.szADCEndTime3);
	strcpy(strTMSDetail.szAppVer,strTCT.szAppVersionHeader);

	CTOS_RTCGet(&strTMSDetail.PreDownload_RTC);

	inCTOSS_GetEnvDB("CREDITCRC",strTMSDetail.szCreditCRC);
	inCTOSS_GetEnvDB("DEBITCRC",strTMSDetail.szDebitCRC);
	inCTOSS_GetEnvDB("INSTCRC",strTMSDetail.szInstCRC);
	inCTOSS_GetEnvDB("CUPCRC",strTMSDetail.szCUPCRC);
	inCTOSS_GetEnvDB("QPAYCRC",strTMSDetail.szQRPayCRC);
	
	vdDebug_LogPrintf("strTMSDetail.inDLStatus=[%d]", strTMSDetail.inDLStatus);
	vdDebug_LogPrintf("strTMSDetail.usReterr=[%d]", strTMSDetail.usReterr);
	vdDebug_LogPrintf("strTMSDetail.inDLTrigger=[%d]", strTMSDetail.inDLTrigger);
	vdDebug_LogPrintf("strTMSDetail.szTID=[%s]", strTMSDetail.szTID);
	vdDebug_LogPrintf("strTMSDetail.szMID=[%s]", strTMSDetail.szMID);
	vdDebug_LogPrintf("strTMSDetail.szDayGap=[%s]", strTMSDetail.szDayGap);
	vdDebug_LogPrintf("strTMSDetail.szADCStartTime1=[%s]", strTMSDetail.szADCStartTime1);
	vdDebug_LogPrintf("strTMSDetail.szADCStartEnd1=[%s]", strTMSDetail.szADCEndTime1);
	vdDebug_LogPrintf("strTMSDetail.szADCStartTime2=[%s]", strTMSDetail.szADCStartTime2);
	vdDebug_LogPrintf("strTMSDetail.szADCStartEnd2=[%s]", strTMSDetail.szADCEndTime2);
	vdDebug_LogPrintf("strTMSDetail.szADCStartTime3=[%s]", strTMSDetail.szADCStartTime3);
	vdDebug_LogPrintf("strTMSDetail.szADCStartEnd3=[%s]", strTMSDetail.szADCEndTime3);
	vdDebug_LogPrintf("strTMSStatus.szAppVer=[%s]", strTMSDetail.szAppVer);
	vdDebug_LogPrintf("strTMSStatus.szPreDLTime=[%02d%02d%02d]", strTMSDetail.PreDownload_RTC.bHour,strTMSDetail.PreDownload_RTC.bMinute,strTMSDetail.PreDownload_RTC.bSecond);
	vdDebug_LogPrintf("strTMSStatus.szPreDLDate=[%02d%02d%02d]", strTMSDetail.PreDownload_RTC.bYear,strTMSDetail.PreDownload_RTC.bMonth,strTMSDetail.PreDownload_RTC.bDay);
	vdDebug_LogPrintf("strTMSStatus.szCreditCRC=[%s]", strTMSDetail.szCreditCRC);
	vdDebug_LogPrintf("strTMSStatus.szDebitCRC=[%s]", strTMSDetail.szDebitCRC);
	vdDebug_LogPrintf("strTMSStatus.szInstCRC=[%s]", strTMSDetail.szInstCRC);
	vdDebug_LogPrintf("strTMSStatus.szCUPCRC=[%s]", strTMSDetail.szCUPCRC);
	vdDebug_LogPrintf("strTMSStatus.szQRPayCRC=[%s]", strTMSDetail.szQRPayCRC);

	/*Save to backup file -- append only*/
	inRet = inAppendConfRec(TMS_DETAIL_FILE_NAME, sizeof(TMS_DETAIL_DATA), (char *)&strTMSDetail);
	vdDebug_LogPrintf("Save Detail Rec[%d]", inRet);
	
	return inRet;
}

int inCTOSS_TMSBackUpReprintDetailData(void)
{
	int inRet = d_OK;
	CTOS_RTC SetRTC;
	char szTemp1[d_LINE_SIZE + 1] = {0};
	char szTemp2[d_LINE_SIZE + 1] = {0};
	CTMS_UpdateInfo st;
    CTMS_GPRSInfo stgprs;     
    CTMS_EthernetInfo stEth;
	CTMS_WIFIInfo stWF;
	//TMS_DETAIL_DATA	strTMSDetail;
	extern STRUCT_MMT strMMTRec;
	
	//memset(&strTMSDetail, 0x00, sizeof(strTMSDetail));//Removed memset as it resets reprint details.
		
	vdDebug_LogPrintf("--inCTOSS_TMSBackUprReprintDetailData--");

	if (inCheckFileExist(TMS_REPRINT_DETAIL_FILE_NAME) == d_OK)
		inRemoveConfRecFile(TMS_REPRINT_DETAIL_FILE_NAME);

	CTOS_LCDTClearDisplay();
	CTOS_LCDTPrintXY (1, 8, "Saving CTMS Data..");
	CTOS_Delay(2000);

	strcpy(strTMSDetail.szTID,srTransRec.szTID);
	strcpy(strTMSDetail.szMID,srTransRec.szMID);
	
	// TerminalIP
	memset(szIP, 0x00, sizeof(szIP));
	if (strCPT.inCommunicationMode == GPRS_MODE)
		inCTOSS_SIMGetGPRSIPInfo();
	else if (strCPT.inCommunicationMode == WIFI_MODE)
		inWIFI_GetConnectConfig();
	else
	{
		if(strTCP.fDHCPEnable == 1)
			vdPrint_EthernetStatus();
		else
			strcpy(szIP,(char *)strTCP.szTerminalIP);			
	}
	
	// Server IP/Port
	memset(szTemp1,0x00,sizeof(szTemp1));
	memset(szTemp2,0x00,sizeof(szTemp2));
	if(strCPT.inCommunicationMode == ETHERNET_MODE)
	{
		vdDebug_LogPrintf("");
		memset(&stEth,0x00,sizeof(CTMS_EthernetInfo));
		CTOS_CTMSGetConfig(d_CTMS_ETHERNET_CONFIG, &stEth);
		strcpy(szTemp1,stEth.strRemoteIP);
		sprintf(szTemp2,"%d",stEth.usRemotePort);
	}
	else if(strCPT.inCommunicationMode == GPRS_MODE)
	{
		memset(&stgprs,0x00,sizeof(CTMS_GPRSInfo));
		CTOS_CTMSGetConfig(d_CTMS_GPRS_CONFIG, &stgprs);	
		strcpy(szTemp1,stgprs.strRemoteIP);
		sprintf(szTemp2,"%d",stgprs.usRemotePort);
	}
	else if(strCPT.inCommunicationMode == WIFI_MODE)
	{
		memset(&stWF,0x00,sizeof(CTMS_WIFIInfo));
		CTOS_CTMSGetConfig(d_CTMS_WIFI_CONFIG, &stWF);	
		strcpy(szTemp1,stWF.strRemoteIP);
		sprintf(szTemp2,"%d",stWF.usRemotePort);
	}

	vdDebug_LogPrintf("strTMSDetail.inDLTrigger=[%d]", strTMSDetail.inDLTrigger);
	vdDebug_LogPrintf("strTMSDetail.inDLStatus=[%d]",strTMSDetail.inDLStatus);
	vdDebug_LogPrintf("strTMSDetail.usReterr=[%d]",strTMSDetail.usReterr);
	vdDebug_LogPrintf("strTMSDetail.szTID=[%s]", strTMSDetail.szTID);
	vdDebug_LogPrintf("strTMSDetail.szMID=[%s]", strTMSDetail.szMID);
	vdDebug_LogPrintf("strTMSDetail.szDayGap=[%s]", strTMSDetail.szDayGap);
	vdDebug_LogPrintf("strTMSDetail.szADCStartTime1=[%s]", strTMSDetail.szADCStartTime1);
	vdDebug_LogPrintf("strTMSDetail.szADCStartEnd1=[%s]", strTMSDetail.szADCEndTime1);
	vdDebug_LogPrintf("strTMSDetail.szADCStartTime2=[%s]", strTMSDetail.szADCStartTime2);
	vdDebug_LogPrintf("strTMSDetail.szADCStartEnd2=[%s]", strTMSDetail.szADCEndTime2);
	vdDebug_LogPrintf("strTMSDetail.szADCStartTime3=[%s]", strTMSDetail.szADCStartTime3);
	vdDebug_LogPrintf("strTMSDetail.szADCStartEnd3=[%s]", strTMSDetail.szADCEndTime3);
	vdDebug_LogPrintf("strTMSStatus.szAppVer=[%s]", strTMSDetail.szAppVer);
	vdDebug_LogPrintf("strTMSDetail.szDLStartTime=[%s]", strTMSDetail.szDLStartTime);
	vdDebug_LogPrintf("strTMSStatus.szDLEndTime=[%s]", strTMSDetail.szDLEndTime);
	vdDebug_LogPrintf("strTMSStatus.szUpdateType=[%s]", strTMSDetail.szUpdateType);
	
	inRet = inAppendConfRec(TMS_REPRINT_DETAIL_FILE_NAME, sizeof(TMS_DETAIL_DATA), (char *)&strTMSDetail);
	vdDebug_LogPrintf("Save Reprint Detail Rec[%d]", inRet);
	if(inRet != d_OK)
		return inRet;
	
	return inRet;
}

/*Restore the txn data base on Backup record*/
int inCTOSS_TMSRestoreTxnData(void)
{
	BOOL fInvoiceNo = FALSE;
	int inTBDNum = 0;
	int inMMTNum = 0;
	int inIdx = 0;
	int inRet = d_OK;
	int inFileSize = 0;
	
	//TXN_BAK_DATA		strTBD;
	extern STRUCT_MMT strMMTRec;

	vdDebug_LogPrintf("=====inCTOSS_TMSRestoreTxnData=====");

	if (inCheckFileExist(TBD_FILE_NAME) != d_OK)
		return d_OK;

	CTOS_LCDTClearDisplay();
	CTOS_LCDTPrintXY (1, 7, "Loading");
	CTOS_LCDTPrintXY (1, 7, "Transaction Data..");
	CTOS_Delay(2000);

	inTBDNum = inGetNumberOfConfRecs(TBD_FILE_NAME, sizeof(TXN_BAK_DATA));
	
	vdDebug_LogPrintf("inDB_GetTableTotalRecNum[%d]", inTBDNum);

	inDatabase_TerminalOpenDatabase();
	/*loop read record from backup file*/
	for (inIdx=1; inIdx<=inTBDNum; inIdx++)
	{
		memset(&strTBD, 0x00, sizeof(strTBD));
		inRet = inLoadConfRec(TBD_FILE_NAME, sizeof(TXN_BAK_DATA), inIdx-1, (char *)&strTBD);
		vdDebug_LogPrintf("Read TBD Tab[%d]HDTid[%d] MITid[%d]", inRet, strTBD.inHDTid, strTBD.inMITid);		
		DebugAddHEX("strTBD.szBatchNo", strTBD.szBatchNo, 3);
		DebugAddHEX("strTBD.szTraceNo", strTBD.szTraceNo, 3);

		/*Update MMT*/
		/*find the match MMT record, by HDTid and MITid*/
		inRet = inMMTReadRecordEx(strTBD.inHDTid, strTBD.inMITid);
		if (inRet == d_OK)//only read success then update the result
		{
			memcpy(strMMT[0].szBatchNo, strTBD.szBatchNo, BATCH_NO_BCD_SIZE);
			//inMMTSaveEx(strMMT[0].MMTid);
			inTMSMMTSave(strMMT[0].MMTid);
		}
		vdDebug_LogPrintf("updating [%s]", strMMT[0].szMerchantName);

		/*Update HDT*/
		inRet = inHDTReadEx(strTBD.inHDTid);
		if (inRet == d_OK)//only read success then update the result
		{
			memcpy(strHDT.szTraceNo, strTBD.szTraceNo, TRACE_NO_BCD_SIZE);
			inHDTSaveEx(strTBD.inHDTid);
		}

		// Save InvoiceNo/LastInvoiceNo  
		if (!fInvoiceNo)  
		{   
			memcpy(strTCT.szInvoiceNo, strTBD.szInvoiceNo, INVOICE_BCD_SIZE);   
			memcpy(strTCT.szLastInvoiceNo, strTBD.szLastInvoiceNo, INVOICE_BCD_SIZE);   
			inTCTInvoiceNoSave(1);   
			fInvoiceNo = TRUE;  
		}
		
	}
	inDatabase_TerminalCloseDatabase();
	/*after restore data, delete the backup data*/
	if (inCheckFileExist(TBD_FILE_NAME) == d_OK)
		inRemoveConfRecFile(TBD_FILE_NAME);

	return d_OK;
}

int inCTOSS_TMSReadDetailData(void)
{
	int inCount = 0;
	int inMMTNum = 0;
	int inIdx = 0;
	int inRet = d_OK;
	int inFileSize = 0;
	BOOL fInvoiceNo = FALSE;
	
	//TMS_DETAIL_DATA		strTMSDetail;
	//extern STRUCT_MMT strMMTRec;

	vdDebug_LogPrintf("--inCTOSS_TMSReadDetailData--");



	//if (inCheckFileExist(TMS_DETAIL_FILE_NAME) != d_OK)
	//	return d_OK;

	inFileSize = inCheckFileExistReturnSIze(TMS_DETAIL_FILE_NAME);
	vdDebug_LogPrintf("test inResult %d", inFileSize);

	if (inRet == d_NO)
		return d_OK;

	CTOS_LCDTClearDisplay();
	CTOS_LCDTPrintXY (1, 7, "Loading CTMS Data..");
	CTOS_Delay(2000);


	vdDebug_LogPrintf("test sizeof TMS_DETAIL_DATA %d", sizeof(TMS_DETAIL_DATA));

	//inCount = inGetNumberOfConfRecs(TMS_DETAIL_FILE_NAME, sizeof(TMS_DETAIL_DATA));
	inCount = inGetNumberOfConfRecs(TMS_DETAIL_FILE_NAME, inFileSize);
	
	vdDebug_LogPrintf("inGetNumberOfConfRecs,inCount=[%d]", inCount);

	if (inCount > 0)
	{
		memset(&strTMSDetail, 0x00, sizeof(strTMSDetail));
		//inRet = inLoadConfRec(TMS_DETAIL_FILE_NAME, sizeof(TMS_DETAIL_DATA), inIdx-1, (char *)&strTMSDetail);
		inRet = inLoadConfRec(TMS_DETAIL_FILE_NAME, inFileSize, inIdx-1, (char *)&strTMSDetail);

		vdDebug_LogPrintf("strTMSDetail.inDLStatus=[%d]", strTMSDetail.inDLStatus);
		vdDebug_LogPrintf("strTMSDetail.usReterr=[%d]", strTMSDetail.usReterr);
		vdDebug_LogPrintf("strTMSDetail.inDLTrigger=[%d]", strTMSDetail.inDLTrigger);
		vdDebug_LogPrintf("strTMSDetail.szTID=[%s]", strTMSDetail.szTID);
		vdDebug_LogPrintf("strTMSDetail.szMID=[%s]", strTMSDetail.szMID);
		vdDebug_LogPrintf("strTMSDetail.szDayGap=[%s]", strTMSDetail.szDayGap);
		vdDebug_LogPrintf("strTMSDetail.szADCStartTime1=[%s]", strTMSDetail.szADCStartTime1);
		vdDebug_LogPrintf("strTMSDetail.szADCStartEnd1=[%s]", strTMSDetail.szADCEndTime1);
		vdDebug_LogPrintf("strTMSDetail.szADCStartTime2=[%s]", strTMSDetail.szADCStartTime2);
		vdDebug_LogPrintf("strTMSDetail.szADCStartEnd2=[%s]", strTMSDetail.szADCEndTime2);
		vdDebug_LogPrintf("strTMSDetail.szADCStartTime3=[%s]", strTMSDetail.szADCStartTime3);
		vdDebug_LogPrintf("strTMSDetail.szADCStartEnd3=[%s]", strTMSDetail.szADCEndTime3);
		vdDebug_LogPrintf("strTMSStatus.szAppVer=[%s]", strTMSDetail.szAppVer);
		vdDebug_LogPrintf("strTMSStatus.szPreDLTime=[%02d%02d%02d]", strTMSDetail.PreDownload_RTC.bHour,strTMSDetail.PreDownload_RTC.bMinute,strTMSDetail.PreDownload_RTC.bSecond);
		vdDebug_LogPrintf("strTMSStatus.szPreDLDate=[%02d%02d%02d]", strTMSDetail.PreDownload_RTC.bYear,strTMSDetail.PreDownload_RTC.bMonth,strTMSDetail.PreDownload_RTC.bDay);

	}	

	/*after restore data, delete the backup data*/
	if (inCheckFileExist(TMS_DETAIL_FILE_NAME) == d_OK)
		inRemoveConfRecFile(TMS_DETAIL_FILE_NAME);
	
	return d_OK;
}

int inCheckTMSBackUpFilesExists(void)
{

	if(inCheckFileExist(TMS_DETAIL_FILE_NAME) == d_OK)
	{
		vdDebug_LogPrintf("TMS BACK-UP FILE EXISTS");
		return d_OK;
	}
	else
	{
		vdDebug_LogPrintf("NO EXISTING TMS BACK-UP FILE");
		return d_NO;
	}
	
}

int inCheckTMSReprintBackUpFilesExists(void)
{

	if(inCheckFileExist(TMS_REPRINT_DETAIL_FILE_NAME) == d_OK)
	{
		vdDebug_LogPrintf("TMS REPRINT BACK-UP FILE EXISTS");
		return d_OK;
	}
	else
	{
		vdDebug_LogPrintf("NO EXISTING TMS REPRINT BACK-UP FILE");
		return d_NO;
	}
	
}


int inCTOSS_TMSReadReprintDetailData(void)
{
	int inCount = 0;
	int inMMTNum = 0;
	int inIdx = 0;
	int inRet = d_OK;
	int inFileSize = 0;
	BOOL fInvoiceNo = FALSE;
	
	//TMS_DETAIL_DATA		strTMSDetail;
	//extern STRUCT_MMT strMMTRec;

	vdDebug_LogPrintf("--inCTOSS_TMSReadReprintDetailData--");

	if (inCheckFileExist(TMS_REPRINT_DETAIL_FILE_NAME) != d_OK)
		return d_OK;

	CTOS_LCDTClearDisplay();
	//CTOS_LCDTPrintXY (1, 7, "Loading CTMS Data..");
	//CTOS_Delay(2000);

	inCount = inGetNumberOfConfRecs(TMS_REPRINT_DETAIL_FILE_NAME, sizeof(TMS_DETAIL_DATA));
	
	vdDebug_LogPrintf("inGetNumberOfConfRecs,inCount=[%d]", inCount);

	if (inCount > 0)
	{
		memset(&strTMSDetail, 0x00, sizeof(strTMSDetail));
		inRet = inLoadConfRec(TMS_REPRINT_DETAIL_FILE_NAME, sizeof(TMS_DETAIL_DATA), inIdx-1, (char *)&strTMSDetail);

		vdDebug_LogPrintf("strTMSDetail.inDLTrigger=[%d]", strTMSDetail.inDLTrigger);
		vdDebug_LogPrintf("strTMSDetail.szTID=[%s]", strTMSDetail.szTID);
		vdDebug_LogPrintf("strTMSDetail.szMID=[%s]", strTMSDetail.szMID);
		vdDebug_LogPrintf("strTMSDetail.szDayGap=[%s]", strTMSDetail.szDayGap);
		vdDebug_LogPrintf("strTMSDetail.szADCStartTime1=[%s]", strTMSDetail.szADCStartTime1);
		vdDebug_LogPrintf("strTMSDetail.szADCStartEnd1=[%s]", strTMSDetail.szADCEndTime1);
		vdDebug_LogPrintf("strTMSDetail.szADCStartTime2=[%s]", strTMSDetail.szADCStartTime2);
		vdDebug_LogPrintf("strTMSDetail.szADCStartEnd2=[%s]", strTMSDetail.szADCEndTime2);
		vdDebug_LogPrintf("strTMSDetail.szADCStartTime3=[%s]", strTMSDetail.szADCStartTime3);
		vdDebug_LogPrintf("strTMSDetail.szADCStartEnd3=[%s]", strTMSDetail.szADCEndTime3);
		vdDebug_LogPrintf("strTMSStatus.szAppVer=[%s]", strTMSDetail.szAppVer);
		vdDebug_LogPrintf("strTMSDetail.szDLStartTime=[%s]", strTMSDetail.szDLStartTime);
		vdDebug_LogPrintf("strTMSStatus.szDLEndTime=[%s]", strTMSDetail.szDLEndTime);
		vdDebug_LogPrintf("strTMSStatus.szUpdateType=[%s]", strTMSDetail.szUpdateType);
	}	

	return d_OK;
}

int inCheckifAutoDL(void)
{
	int inRet = FALSE;
	USHORT usResult = 0;
	//long inDLStartTime = 0;
	//long inDLStartTime = 0;
	char szDLStartTime[40+1] = {0};
	char szDLEndTime[40+1] = {0};
	char szTemp3[40+1] = {0};
	CTOS_RTC SetRTC_DL;

	vdDebug_LogPrintf("*** inCheckifAutoDL ***");

	if(fRePrintFlag == TRUE)
		return d_OK;
	
	//usResult = CTOS_CTMSGetInfo(d_CTMS_INFO_LAST_UPDATE_TIME, &SetRTC_DL);
	memcpy(&SetRTC_DL,&strTMSDetail.PreDownload_RTC,sizeof(CTOS_RTC));
	vdDebug_LogPrintf("CTOS_CTMSGetInfo usResult=[%x]",usResult);
	
	if(d_OK == usResult)
	{
		vdGetADCDateTime(TIME,&SetRTC_DL,strTMSDetail.szDLStartTime);
		//strcpy(strTMSDetail.szDLStartTime,szTemp1);
	}

	memcpy(szTemp3,strTMSDetail.szDLStartTime,2);
	memcpy(&szTemp3[2],&strTMSDetail.szDLStartTime[3],2);

	vdDebug_LogPrintf("strTMSDetail.szDLStartTime %s",strTMSDetail.szDLStartTime);
	vdDebug_LogPrintf("DL TIME %s = %lu",szTemp3,atol(szTemp3));

	//inCTOSS_GetEnvDB ("ADL1START", szDLStartTime);
	//inCTOSS_GetEnvDB ("ADL1END", szDLEndTime);

	strcpy(szDLStartTime,strTMSDetail.szADCStartTime1);
	strcpy(szDLEndTime,strTMSDetail.szADCEndTime1);

	vdDebug_LogPrintf("START TIME 1 %s = %lu",szDLStartTime,atol(szDLStartTime));
	vdDebug_LogPrintf("END TIME 1 %s = %lu",szDLEndTime,atol(szDLEndTime));
	
	if( atol (szDLStartTime) <= atol(szTemp3) && atol(szTemp3) <= atol(szDLEndTime) )
		return TRUE;


	//inCTOSS_GetEnvDB ("ADL2START", szDLStartTime);
	//inCTOSS_GetEnvDB ("ADL2END", szDLEndTime);
	strcpy(szDLStartTime,strTMSDetail.szADCStartTime2);
	strcpy(szDLEndTime,strTMSDetail.szADCEndTime2);

	vdDebug_LogPrintf("START TIME 2 %s = %lu",szDLStartTime,atol(szDLStartTime));
	vdDebug_LogPrintf("END TIME 2 %s = %lu",szDLEndTime,atol(szDLEndTime));
	
	if( atol (szDLStartTime) <= atol(szTemp3) && atol(szTemp3) <= atol(szDLEndTime) )
		return TRUE;


	//inCTOSS_GetEnvDB ("ADL3START", szDLStartTime);
	//inCTOSS_GetEnvDB ("ADL3END", szDLEndTime);
	strcpy(szDLStartTime,strTMSDetail.szADCStartTime3);
	strcpy(szDLEndTime,strTMSDetail.szADCEndTime2);
	

	vdDebug_LogPrintf("START TIME 3 %s = %lu",szDLStartTime,atol(szDLStartTime));
	vdDebug_LogPrintf("END TIME 3 %s = %lu",szDLEndTime,atol(szDLEndTime));
	
	if( atol (szDLStartTime) <= atol(szTemp3) && atol(szTemp3) <= atol(szDLEndTime) )
		return TRUE;


	vdDebug_LogPrintf("RETURN IS FALSE");
	return inRet;
}

void vdAssesTMSDownloadStatus(CTOS_RTC *GetRTC)
{
	USHORT usResult = 0;
	int inDateGap=0;
	char szTime[6+1]={0};
	char szCTMSDL_DateTime[24+1]={0};
	char szPreDL_DateTime[24+1]={0};
	char szCreditCRC[8+1]={0};
	char szDebitCRC[8+1]={0};
	char szInstCRC[8+1]={0};
	char szCUPCRC[8+1]={0};
	char szQRPayCRC[8+1]={0};
	STRUCT_TIME_INFO strTimeStart;
	STRUCT_TIME_INFO strTimeStop;
	STRUCT_TIME_INFO strDiff;
	CTOS_RTC GetCTMSRTC_DL;
//Check for CRC Change

	if(strTMSDetail.inDLTrigger != MANUAL_DOWNLOAD && strTMSDetail.inDLTrigger != AUTO_DOWNLOAD)
		return;
		
	inCTOSS_GetEnvDB("CREDITCRC",szCreditCRC);
	inCTOSS_GetEnvDB("DEBITCRC",szDebitCRC);
	inCTOSS_GetEnvDB("INSTCRC",szInstCRC);
	inCTOSS_GetEnvDB("CUPCRC",szCUPCRC);
	inCTOSS_GetEnvDB("QPAYCRC",szQRPayCRC);

	vdDebug_LogPrintf("szCreditCRC %s 	:: 	strTMSDetail.szCreditCRC %s",szCreditCRC,strTMSDetail.szCreditCRC);
	vdDebug_LogPrintf("szDebitCRC %s 	:: 	strTMSDetail.szDebitCRC %s",szDebitCRC,strTMSDetail.szDebitCRC);
	vdDebug_LogPrintf("szInstCRC %s 	:: 	strTMSDetail.szInstCRC %s",szInstCRC,strTMSDetail.szInstCRC);
	vdDebug_LogPrintf("szCUPCRC %s 		:: 	strTMSDetail.szCUPCRC %s",szCUPCRC,strTMSDetail.szCUPCRC);
	vdDebug_LogPrintf("szQRPayCRC %s 	:: 	strTMSDetail.szQRPayCRC %s",szQRPayCRC,strTMSDetail.szQRPayCRC);


	//Any changes to CRC of any application, download is successful.
	if(strcmp(szCreditCRC,strTMSDetail.szCreditCRC) || strcmp(szDebitCRC,strTMSDetail.szDebitCRC) || strcmp(szInstCRC,strTMSDetail.szInstCRC) || strcmp(szCUPCRC,strTMSDetail.szCUPCRC) || strcmp(szQRPayCRC,strTMSDetail.szQRPayCRC))
	{
		strTMSDetail.inDLStatus = d_CTMS_UPDATE_FINISHED;
		strcpy(strTMSDetail.szUpdateType,"APPLICATION");
		return;
	}
	else 
		strTMSDetail.inDLStatus = d_CTMS_UPDATE_ERR;

	vdDebug_LogPrintf("NO CRC CHANGES");
	
//Check for Day difference
#if 0
	usResult = CTOS_CTMSGetInfo(d_CTMS_INFO_LAST_UPDATE_TIME, &GetCTMSRTC_DL);
	vdDebug_LogPrintf("CTOS_CTMSGetInfo usResult=[%x]",usResult);
	
    inDateGap = inCTOSS_CheckIntervialDateFrom2013((strTMSDetail.PreDownload_RTC.bYear+2000), strTMSDetail.PreDownload_RTC.bMonth, strTMSDetail.PreDownload_RTC.bDay) - inCTOSS_CheckIntervialDateFrom2013((GetCTMSRTC_DL.bYear+2000), GetCTMSRTC_DL.bMonth, GetCTMSRTC_DL.bDay);
	 
	vdDebug_LogPrintf("inDateGap=[%d]",inDateGap);

	if(inDateGap > 1)
	{
		strTMSDetail.inDLStatus = d_CTMS_UPDATE_ERR;
        return;
	}

//Check for Time difference
	sprintf(szCurrDate,"%02d%02d%02d", GetRTC->bYear, GetRTC->bMonth, GetRTC->bDay);
	sprintf(szPreDLDate,"%02d%02d%02d", strTMSDetail.PreDownload_RTC.bYear, strTMSDetail.PreDownload_RTC.bMonth, strTMSDetail.PreDownload_RTC.bDay);

	//check if time is more than 24 hours
	if(GetCTMSRTC_DL.bHour < GetRTC->bHour)
	{
		strTMSDetail.inDLStatus = d_CTMS_UPDATE_ERR;
        return;
	}
	else if(GetCTMSRTC_DL.bHour == strTMSDetail.PreDownload_RTC.bHour)
	{
		if(GetCTMSRTC_DL.bMinute < strTMSDetail.PreDownload_RTC.bHour)
		{
			strTMSDetail.inDLStatus = d_CTMS_UPDATE_ERR;
	        return;
		}
		else if(GetCTMSRTC_DL.bMinute == strTMSDetail.PreDownload_RTC.bHour)
		{
			if(GetCTMSRTC_DL.bSecond < strTMSDetail.PreDownload_RTC.bSecond)
			{
				strTMSDetail.inDLStatus = d_CTMS_UPDATE_ERR;
		        return;
			}
		}
	}
	
	memset(&strTimeStart,0x00,sizeof(STRUCT_TIME_INFO));
	strTimeStart.hours = GetCTMSRTC_DL.bHour;
	strTimeStart.minutes= GetCTMSRTC_DL.bMinute;
	strTimeStart.seconds = GetCTMSRTC_DL.bSecond;
	vdDebug_LogPrintf("START :: HRS %d :: MINS %d :: SECS %d",strTimeStart.hours,strTimeStart.minutes,strTimeStart.seconds);
	
	memset(&strTimeStop,0x00,sizeof(STRUCT_TIME_INFO));
	strTimeStop.hours = strTMSDetail.PreDownload_RTC.bHour;
	strTimeStop.minutes= strTMSDetail.PreDownload_RTC.bMinute;
	strTimeStop.seconds = strTMSDetail.PreDownload_RTC.bSecond;
	vdDebug_LogPrintf("STOP :: HRS %d :: MINS %d :: SECS %d",strTimeStop.hours,strTimeStop.minutes,strTimeStop.seconds);
	
	memset(&strDiff,0x00,sizeof(STRUCT_TIME_INFO));
	differenceBetweenTimePeriod(&strTimeStop,&strTimeStart,&strDiff);	
	vdDebug_LogPrintf("DIFF :: HRS %d :: MINS %d :: SECS %d",strDiff.hours,strDiff.minutes,strDiff.seconds);

//Checking for negative hours. Almost 24 hours difference.
	if(strDiff.hours < 0)
	{
		strTMSDetail.inDLStatus = d_CTMS_UPDATE_ERR;
			return;
	}
	
	if(strDiff.minutes > get_env_int("DLGAPTEST"))
		strTMSDetail.inDLStatus = d_CTMS_UPDATE_ERR;
	else
		strTMSDetail.inDLStatus = d_CTMS_UPDATE_FINISHED;
#else
	usResult = CTOS_CTMSGetInfo(d_CTMS_INFO_LAST_UPDATE_TIME, &GetCTMSRTC_DL);
	vdDebug_LogPrintf("CTOS_CTMSGetInfo usResult=[%x]",usResult);
	vdDebug_LogPrintf("szCTMSDL_DateTime : %d%02d%02d%02d%02d%02d",2000+GetCTMSRTC_DL.bYear,GetCTMSRTC_DL.bMonth,GetCTMSRTC_DL.bDay,GetCTMSRTC_DL.bHour,GetCTMSRTC_DL.bMinute,GetCTMSRTC_DL.bSecond);

	memset(szCTMSDL_DateTime,0x00,sizeof(szCTMSDL_DateTime));
	memset(szPreDL_DateTime,0x00,sizeof(szPreDL_DateTime));
	
	sprintf(szCTMSDL_DateTime,"%d%02d%02d%02d%02d%02d",2000+GetCTMSRTC_DL.bYear,GetCTMSRTC_DL.bMonth,GetCTMSRTC_DL.bDay,GetCTMSRTC_DL.bHour,GetCTMSRTC_DL.bMinute,GetCTMSRTC_DL.bSecond);

	//vdDebug_LogPrintf("REINER strTMSDetail.PreDownload_RTC.bYear %d",strTMSDetail.PreDownload_RTC.bYear);
	//if(strTMSDetail.PreDownload_RTC.bYear > 0)//Check if PreDownload_RTC was populated. If not use the backup RTC.
		sprintf(szPreDL_DateTime,"%d%02d%02d%02d%02d%02d",2000+strTMSDetail.PreDownload_RTC.bYear,strTMSDetail.PreDownload_RTC.bMonth,strTMSDetail.PreDownload_RTC.bDay,strTMSDetail.PreDownload_RTC.bHour,strTMSDetail.PreDownload_RTC.bMinute,strTMSDetail.PreDownload_RTC.bSecond);
	//else
		//inCTOSS_GetEnvDB("PREDLRTC",szPreDL_DateTime);

	//inCTOSS_PutEnvDB("PREDLRTC","");
	
	vdDebug_LogPrintf("szCTMSDL_DateTime [%s]",szCTMSDL_DateTime);
	vdDebug_LogPrintf("szPreDL_DateTime  [%s]",szPreDL_DateTime);
	
	if(atoll(szCTMSDL_DateTime) > atoll(szPreDL_DateTime))//If CTMS DL Date and Time is greater than Pre DL Time, latest download was recorded by CTMS library.
	{
		strTMSDetail.inDLStatus = d_CTMS_UPDATE_FINISHED;
	}
	else
	{
		strTMSDetail.inDLStatus = d_CTMS_UPDATE_ERR;
	}
#endif
	return;
}
