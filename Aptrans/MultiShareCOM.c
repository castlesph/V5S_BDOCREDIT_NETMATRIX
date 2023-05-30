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

#include "..\ApTrans\MultiApTrans.h"
#include "..\Database\DatabaseFunc.h"

#include "..\Includes\POSTypedef.h"
#include "..\Includes\Wub_lib.h"

#include "..\Debug\Debug.h"

#include "..\ApTrans\MultiShareCOM.h"

static int gCommMode = -1;//for Sharls_COM modem
BOOL fGPRSConnectOK = 0;
static USHORT usEthType = 0;

#define COMM_HEADER_FILE "/home/ap/pub/commheader.txt"
#define COMM_BUFF_FILE "/home/ap/pub/commbuff.txt"

#define SEND_BUF	(20*1024)
#define RECEIVE_BUF	(50*1024) 

#define MAX_BUF	6000

#define d_KBD_INVALID_COM						0xFE

int g_inCURLConnect = 1;

//wifi-mod
USHORT usHWSupport = 0;
//wifi-mod

USHORT usPreconnectStatus;
//extern int isPredial;


BYTE szSendData[SEND_BUF];
BYTE szReceiveData[RECEIVE_BUF];

BYTE szIP[50+1];
BYTE szDNS1[50+1];
BYTE szDNS2[50+1];
BYTE szGateWay[50+1];
BYTE szSubnetMask[50+1];




#if 0
typedef struct
{
	unsigned short usGPRSNetworkType;
	char szGPRSNetworkName[20+1];
	BYTE bgGPRSSignal;
	BYTE bgGPRSType;
	BYTE usEthType;
	BYTE usWIFIType;
	BYTE szWIFISSID[50];
	BYTE usGPSType;
	BYTE usBLUETOOTHType;
	BYTE usDIALPPType;
	BYTE inReserved1;
	BYTE inReserved2;
	BYTE inReserved3;
	BYTE szReserved1[50];
	BYTE szReserved2[50];
	BYTE szReserved3[50];
	BYTE szReserved4[50];
} STRUCT_SHARLS_COM ;
#endif

static int init_connect = 0;

BYTE chGetInit_Connect(void)
{
    return init_connect;
}

void vdSetInit_Connect(int Init_Connect)
{
    init_connect = Init_Connect;
}


static long inCTOSS_COMM_GetFileSize(const char* pchFileName)
{
    FILE  *fPubKey;
	long curpos,length;

	vdDebug_LogPrintf("lnGetFileSize[%s]", pchFileName);
	fPubKey = fopen( (char*)pchFileName, "rb" );
	if(fPubKey == NULL)
		return -1;

	curpos=ftell(fPubKey);
	fseek(fPubKey,0L,SEEK_END);
	length=ftell(fPubKey);
	fseek(fPubKey,curpos,SEEK_SET);

	fclose(fPubKey);
	vdDebug_LogPrintf("lnGetFileSize[%d],length=[%d]", curpos,length);

    return(length);
}


static int inCTOSS_COMM_WriteFile(unsigned char *pchFileName, unsigned char *pchRecBuf, int inMaxRecSize)
{
	int h_file;
	int inRetVal = 0;
	FILE  *fPubKey;
	int times,i;
	
	vdDebug_LogPrintf("inWriteFile[%s],inMaxRecSize=[%d]", pchFileName,inMaxRecSize);
	
	fPubKey = fopen((char *)pchFileName, "wb+" );
	if(fPubKey == NULL)
		return -1;

	if (inMaxRecSize > MAX_BUF)
	{
		times = inMaxRecSize/MAX_BUF;
		for (i = 0;i<times;i++)
		{
			inRetVal = fwrite(&pchRecBuf[i*MAX_BUF],MAX_BUF, 1, fPubKey);
		}

		times = inMaxRecSize%MAX_BUF;
		if(times>0)
		{
			inRetVal = fwrite(&pchRecBuf[i*MAX_BUF],times, 1, fPubKey);
		}
		
	}
	else
	inRetVal = fwrite(pchRecBuf,inMaxRecSize, 1, fPubKey);
	fclose(fPubKey);

	vdDebug_LogPrintf("inWriteFile[%d].inMaxRecSize=[%d]...", inRetVal,inMaxRecSize);

	return inRetVal;
}

static int inCTOSS_COMM_ReadFile(unsigned char *pchFileName, unsigned char *pchRecBuf, int inMaxRecSize)
{
	int h_file;
	int inRetVal = 0;
	FILE  *fPubKey;
	int times,i;
	
	vdDebug_LogPrintf("ReadFile[%s],inMaxRecSize=[%d]", pchFileName,inMaxRecSize);
	
	fPubKey = fopen((char *)pchFileName, "rb" );
	if(fPubKey == NULL)
		return -1;

	if (inMaxRecSize > MAX_BUF)
	{
		times = inMaxRecSize/MAX_BUF;
		for (i = 0;i<times;i++)
		{
			inRetVal = fread (&pchRecBuf[i*MAX_BUF], 1, MAX_BUF, fPubKey);
		}

		times = inMaxRecSize%MAX_BUF;
		if(times>0)
		{
			inRetVal = fread (&pchRecBuf[i*MAX_BUF], 1, times, fPubKey);
		}
		
	}
	else
	inRetVal = fread (pchRecBuf, 1, inMaxRecSize, fPubKey);
	fclose(fPubKey);

	vdDebug_LogPrintf("ReadFile[%d].inMaxRecSize=[%d]...", inRetVal,inMaxRecSize);

	return inRetVal;
}


int inMultiAP_Database_COM_ClearEx(void)
{
	int inRetVal = 0;

	memset(szSendData,0x00,SEND_BUF);
	memset(szReceiveData,0x00,RECEIVE_BUF);
	memset(&strCOM,0x00,sizeof(STRUCT_COM));
#if 1	
	inRetVal = inCTOSS_COMM_GetFileSize(COMM_HEADER_FILE);
	//vdDebug_LogPrintf("[%s] =[%d] ", COMM_HEADER_FILE,inRetVal);
	if (inRetVal >= 0)
		remove(COMM_HEADER_FILE);

	inRetVal = inCTOSS_COMM_GetFileSize(COMM_BUFF_FILE);
	//vdDebug_LogPrintf("[%s] =[%d] ", COMM_BUFF_FILE,inRetVal);
	if (inRetVal >= 0)
		remove(COMM_BUFF_FILE);
#endif
	return d_OK;
}

int inMultiAP_Database_COM_SaveEx(void)
{
	int inRetVal = 0;
	unsigned char pchRecBuf[1000];
	int inMaxRecSize = 0;
	
	memset(pchRecBuf,0x00,sizeof(pchRecBuf));
	inMaxRecSize = sizeof(STRUCT_COM);
	memcpy(pchRecBuf,&strCOM,inMaxRecSize);
	//vdDebug_LogPrintf("Database_COM_SaveEx =[%d] ", inMaxRecSize);
	
	inRetVal = inCTOSS_COMM_WriteFile(COMM_HEADER_FILE,pchRecBuf,inMaxRecSize);
	if (inRetVal <= 0)
		return d_NO;

	//vdDebug_LogPrintf("Database_COM_SaveEx inSendLen=[%d] ", strCOM.inSendLen);
	if (strCOM.inSendLen > 0)
	{
		inRetVal = inCTOSS_COMM_WriteFile(COMM_BUFF_FILE,szSendData,strCOM.inSendLen);
		if (inRetVal <= 0)
		return d_NO;
	}

	return d_OK;
}

int inMultiAP_Database_COM_ReadEx(void)
{
	int inRetVal = 0;
	unsigned char pchRecBuf[1000];
	int inMaxRecSize = 0;
	memset(pchRecBuf,0x00,sizeof(pchRecBuf));
	inMaxRecSize = sizeof(STRUCT_COM);

	vdDebug_LogPrintf("Database_COM_ReadEx =[%d] ", inMaxRecSize);
	inRetVal = inCTOSS_COMM_ReadFile(COMM_HEADER_FILE,pchRecBuf,inMaxRecSize);
	if (inRetVal <= 0)
		return d_NO;
	
	memset(&strCOM,0x00,inMaxRecSize);
	memcpy(&strCOM,pchRecBuf,inMaxRecSize);

	vdDebug_LogPrintf("Database_COM_ReadEx inReceiveLen=[%d] ", strCOM.inReceiveLen);
	if (strCOM.inReceiveLen > 0)
	{
		memset(szReceiveData,0x00,RECEIVE_BUF);
		inRetVal = inCTOSS_COMM_ReadFile(COMM_BUFF_FILE,szReceiveData,strCOM.inReceiveLen);
		if (inRetVal <= 0)
			return d_NO;
	}

	return d_OK;
}



int inCTOSS_COMM_Initialize(TRANS_DATA_TABLE *srTransPara,int inMode)
{
    BYTE bInBuf[40];
    BYTE bOutBuf[40];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;

    //check if signal is OK
		USHORT usNetworkType = 0;
		BYTE szNetworkName[128+1];
		
#if 0
    //0615
	//wifi-mod2
	STRUCT_SHARLS_COM Sharls_COMData;
	
	if(strCPT.inCommunicationMode == WIFI_MODE)
		{
			inCTOSS_GetGPRSSignalEx1(&usNetworkType, szNetworkName, &usEthType, &Sharls_COMData);
		}
	else
	//wifi-mod2
	inCTOSS_GetGPRSSignalEx(&usNetworkType, szNetworkName,&usEthType);

	//wifi-mod2
	if ((fGPRSConnectOK != TRUE) && ((inMode == GPRS_MODE) || (inMode == WIFI_MODE)))
		return d_NO;
	//wifi-mod2
	//0615
#endif

	
	vdDebug_LogPrintf("--inCTOSS_COMM_Initialize,chGetInit_Connect=[%d]",chGetInit_Connect());
	if (chGetInit_Connect() == 1)
		return inCTOSS_COMM_InitializeAndConnect(srTransPara,inMode);

    memset(bOutBuf, 0x00, sizeof(bOutBuf)); 

    //inMultiAP_Database_COM_Clear();//change DB to txt file
    inMultiAP_Database_COM_ClearEx();

    //strCOM.inCommMode = GPRS_MODE;//for test
    //strCOM.inCommMode = ETHERNET_MODE;//for test
    strCOM.inCommMode = inMode;
	gCommMode = inMode;//for Sharls_COM modem
	//for Sharls_COM modem
	if (inMode == DIAL_UP_MODE)
	{
		strCOM.bPredialFlag = strCPT.fPreDial;
		strCOM.inParaMode = strCPT.inParaMode;
		strCOM.inHandShake = strCPT.inHandShake;
		strCOM.inCountryCode = strCPT.inCountryCode;

		strcpy(strCOM.szPriPhoneNum,strCPT.szPriTxnPhoneNumber);
		strcpy(strCOM.szSecPhoneNum,strCPT.szSecTxnPhoneNumber);

		strcpy(strCOM.szATCMD1,strMMT[0].szATCMD1);
		strcpy(strCOM.szATCMD2,strMMT[0].szATCMD2);
		strcpy(strCOM.szATCMD3,strMMT[0].szATCMD3);
		strcpy(strCOM.szATCMD4,strMMT[0].szATCMD4);
		strcpy(strCOM.szATCMD5,strMMT[0].szATCMD5);
	}
    //inMultiAP_Database_COM_Save();
	inMultiAP_Database_COM_SaveEx();
		vdDebug_LogPrintf("--inCTOSS_COMM_Initialize,fGPRSConnectOK=[%d]",fGPRSConnectOK);

	//if ((fGPRSConnectOK != TRUE) && (strCPT.inCommunicationMode == GPRS_MODE)){
	//	return d_NO;
	//}
	if (inMode== GPRS_MODE)
	{
    	CTOS_KBDBufPut(d_KBD_INVALID_COM);
		CTOS_Delay(200);
	}
    
    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_COM", d_IPC_CMD_COMM_INIT, bInBuf, usInLen, bOutBuf, &usOutLen);

	vdDebug_LogPrintf("--inCTOSS_COMM_Initialize d_IPC_CMD_COMM_INIT result =[%d] - %d", usResult,  bOutBuf[0]);
    if(d_OK == usResult)
    {
        //status
        if(bOutBuf[0] == IPC_COMM_SUCC)            
            return d_OK;
        else
            return d_NO;
    }
    
    return usResult;
}




int inCTOSS_COMM_InitializeAndConnect(TRANS_DATA_TABLE *srTransPara,int inMode)
{
    BYTE bInBuf[40];
    BYTE bOutBuf[40];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;

    //check if signal is OK
		USHORT usNetworkType = 0;
		BYTE szNetworkName[128+1];
		
#if 0
    //0615
	//wifi-mod2
	STRUCT_SHARLS_COM Sharls_COMData;
	
	if(strCPT.inCommunicationMode == WIFI_MODE)
		{
			inCTOSS_GetGPRSSignalEx1(&usNetworkType, szNetworkName, &usEthType, &Sharls_COMData);
		}
	else
	//wifi-mod2
	inCTOSS_GetGPRSSignalEx(&usNetworkType, szNetworkName,&usEthType);

	//wifi-mod2
	if ((fGPRSConnectOK != TRUE) && ((inMode == GPRS_MODE) || (inMode == WIFI_MODE)))
		return d_NO;
	//wifi-mod2
	//0615
#endif


    memset(bOutBuf, 0x00, sizeof(bOutBuf)); 

    //inMultiAP_Database_COM_Clear();//change DB to txt file
    inMultiAP_Database_COM_ClearEx();

    //strCOM.inCommMode = GPRS_MODE;//for test
    //strCOM.inCommMode = ETHERNET_MODE;//for test
    strCOM.inCommMode = inMode;
	gCommMode = inMode;//for Sharls_COM modem
	//for Sharls_COM modem
	if (inMode == DIAL_UP_MODE)
	{
		strCOM.bPredialFlag = strCPT.fPreDial;
		strCOM.inParaMode = strCPT.inParaMode;
		strCOM.inHandShake = strCPT.inHandShake;
		strCOM.inCountryCode = strCPT.inCountryCode;

		strcpy(strCOM.szPriPhoneNum,strCPT.szPriTxnPhoneNumber);
		strcpy(strCOM.szSecPhoneNum,strCPT.szSecTxnPhoneNumber);

		strcpy(strCOM.szATCMD1,strMMT[0].szATCMD1);
		strcpy(strCOM.szATCMD2,strMMT[0].szATCMD2);
		strcpy(strCOM.szATCMD3,strMMT[0].szATCMD3);
		strcpy(strCOM.szATCMD4,strMMT[0].szATCMD4);
		strcpy(strCOM.szATCMD5,strMMT[0].szATCMD5);
	}

	
    if(srTransRec.byTransType != SETTLE)
    {
        strcpy(strCOM.szPriHostIP,strCPT.szPriTxnHostIP);
        strcpy(strCOM.szSecHostIP,strCPT.szSecTxnHostIP);
        strCOM.ulPriHostPort = strCPT.inPriTxnHostPortNum;
        strCOM.ulSecHostPort = strCPT.inSecTxnHostPortNum;
        vdDebug_LogPrintf("-inCTOSS_COMM_InitializeAndConnect[%s]port[%ld]",strCOM.szPriHostIP,strCOM.ulPriHostPort);
    }
    else
    {
        strcpy(strCOM.szPriHostIP,strCPT.szPriSettlementHostIP);
        strcpy(strCOM.szSecHostIP,strCPT.szSecSettlementHostIP);
        strCOM.ulPriHostPort = strCPT.inPriSettlementHostPort;
        strCOM.ulSecHostPort = strCPT.inSecSettlementHostPort;
        vdDebug_LogPrintf("--inCTOSS_COMM_InitializeAndConnect[%s]port[%ld]",strCOM.szPriHostIP,strCOM.ulPriHostPort);

    } 
	strCOM.bSSLFlag = strCPT.fSSLEnable;
	strCOM.inGPRSSingal = strCPT.fDialMode;//for GPRS connection mode,0=CTOS API, 1= Linux TCP/ip API
	strCOM.inReceiveTimeOut = strCPT.inTCPResponseTimeout;
	strCOM.inConnectionTimeOut = strCPT.inTCPConnectTimeout;

	
	vdDebug_LogPrintf("--inCTOSS_COMM_InitializeAndConnect,SSLFlag=[%d],inGPRSSingal=[%d]",strCOM.bSSLFlag,strCOM.inGPRSSingal);

    //inMultiAP_Database_COM_Save();
	inMultiAP_Database_COM_SaveEx();
		vdDebug_LogPrintf("--inCTOSS_COMM_InitializeAndConnect,fGPRSConnectOK=[%d]",fGPRSConnectOK);

	//if ((fGPRSConnectOK != TRUE) && (strCPT.inCommunicationMode == GPRS_MODE)){
	//	return d_NO;
	//}
	if (inMode== GPRS_MODE)
	{
    	CTOS_KBDBufPut(d_KBD_INVALID_COM);
		//CTOS_Delay(200);
	}
    
    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_COM", d_IPC_CMD_COMM_INIT_CONNECTEx, bInBuf, usInLen, bOutBuf, &usOutLen);
    if(d_OK == usResult)
    {
        //status
        if(bOutBuf[0] == IPC_COMM_SUCC)            
            return d_OK;
        else
            return d_NO;
    }
    
    return usResult;
}



int inCTOSS_COMM_Connect(TRANS_DATA_TABLE *srTransPara)
{
    BYTE bInBuf[40];
    BYTE bOutBuf[40];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;

		USHORT usNetworkType = 0;
		BYTE szNetworkName[128+1];


	//wifi-mod2
	STRUCT_SHARLS_COM Sharls_COMData;

	BYTE bDevice;

	vdDebug_LogPrintf("--inCTOSS_COMM_Connect--");
	vdDebug_LogPrintf("chGetInit_Connect[%d]", chGetInit_Connect());
	vdDebug_LogPrintf("HDTid[%d]", srTransRec.HDTid);
	vdDebug_LogPrintf("fGPRSConnectOK[%d]", fGPRSConnectOK);
	vdDebug_LogPrintf("strCPT.inCommunicationMode[%d].srTransPara->usTerminalCommunicationMode[%d]", strCPT.inCommunicationMode, srTransPara->usTerminalCommunicationMode);
	vdDebug_LogPrintf("g_inCURLConnect[%d]", g_inCURLConnect);

	if (srTransRec.HDTid == BDO_LOYALTY_HDT_INDEX)
	{
		// if use CURL connect
		if (1 == g_inCURLConnect)
		{						
			vdDebug_LogPrintf("CURL->inCTOSS_COMM_Connect");
		
			if (srTransPara->usTerminalCommunicationMode == GPRS_MODE)
				bDevice = d_TCP_DEVICE_GPRS;

			if (srTransPara->usTerminalCommunicationMode == WIFI_MODE)
				bDevice = d_TCP_DEVICE_WIFI;

			if (srTransPara->usTerminalCommunicationMode == ETHERNET_MODE)
				bDevice = d_TCP_DEVICE_ETHERNET;

			memset(bInBuf, 0x00, sizeof(bInBuf));
			memset(bOutBuf, 0x00, sizeof(bOutBuf));
			bInBuf[0] = bDevice;
			
			usResult = inMultiAP_RunIPCCmdTypes("SHARLS_COM", d_IPC_CMD_COMM_BIND_DEVICE, bInBuf, usInLen, bOutBuf, &usOutLen);
			
			vdDebug_LogPrintf("return inCTOSS_COMM_Connect");
			vdDebug_LogPrintf("[CURL]CONNECTION....SUCCESS");
			return d_OK;
		}
	}

	//if (usPreconnectStatus == 2)
	{
		if(srTransRec.byPackType != DCC_RATEREQUEST && srTransRec.byPackType != DCC_RATEREQUEST_RETRY)
			vdDispTransTitleCardTypeandTotal(srTransRec.byTransType);  /*BDO: Display TOTAL AMOUNT during connection -- sidumili*/
	}

	vdDebug_LogPrintf("*****GLADY******* fCommAlreadyOPen = %d",fCommAlreadyOPen);

	vdDebug_LogPrintf("--inCTOSS_COMM_Connectb,chGetInit_Connect=[%d]",chGetInit_Connect());
		if (chGetInit_Connect() == 1)
			return d_OK;

	//if (isPredial == TRUE)
	//	return d_OK;

#if 0	
	if(strCPT.inCommunicationMode == WIFI_MODE)
		inCTOSS_GetGPRSSignalEx1(&usNetworkType, szNetworkName, &usEthType, &Sharls_COMData);
	else
	//wifi-mod2
		inCTOSS_GetGPRSSignalEx(&usNetworkType, szNetworkName,&usEthType);
	
	 vdDebug_LogPrintf("--inCTOSS_COMM_Connect,fGPRSConnectOK=[%d],inCommunicationMode=[%d]",fGPRSConnectOK,strCPT.inCommunicationMode);
	if ((fGPRSConnectOK != TRUE) && (strCPT.inCommunicationMode == GPRS_MODE)) // flag to determine whether need do comm connection or not.
	{
	    //vdCTOS_DispStatusMessage("GPRS Connect Failed");
	    vdDisplayErrorMsgResp2(" ", "GPRS Problem2","Please Call");
		CTOS_Delay(2000); 
		return d_NO;
	}

	//wifi-mod2
	if ((fGPRSConnectOK != TRUE) && (strCPT.inCommunicationMode == WIFI_MODE)) // flag to determine whether need do comm connection or not.
	{
		//vdCTOS_DispStatusMessage("WIFI Connect Failed");
	    vdDisplayErrorMsgResp2(" ", "WIFI Problem","Please Call");
		CTOS_Delay(2000); 
		return d_NO;
	}
	//wifi-mod2
#endif
    memset(bOutBuf, 0x00, sizeof(bOutBuf));
    //inMultiAP_Database_COM_Clear();
	inMultiAP_Database_COM_ClearEx();

    if(srTransRec.byTransType != SETTLE)
    {
        strcpy(strCOM.szPriHostIP,strCPT.szPriTxnHostIP);
        strcpy(strCOM.szSecHostIP,strCPT.szSecTxnHostIP);
        strCOM.ulPriHostPort = strCPT.inPriTxnHostPortNum;
        strCOM.ulSecHostPort = strCPT.inSecTxnHostPortNum;
        vdDebug_LogPrintf("-inCTOSS_COMM_Connect[%s]port[%ld]",strCOM.szPriHostIP,strCOM.ulPriHostPort);
    }
    else
    {
        strcpy(strCOM.szPriHostIP,strCPT.szPriSettlementHostIP);
        strcpy(strCOM.szSecHostIP,strCPT.szSecSettlementHostIP);
        strCOM.ulPriHostPort = strCPT.inPriSettlementHostPort;
        strCOM.ulSecHostPort = strCPT.inSecSettlementHostPort;
        vdDebug_LogPrintf("--inCTOSS_COMM_Connect[%s]port[%ld]",strCOM.szPriHostIP,strCOM.ulPriHostPort);

    } 
	strCOM.bSSLFlag = strCPT.fSSLEnable;
	strCOM.inGPRSSingal = strCPT.fDialMode;//for GPRS connection mode,0=CTOS API, 1= Linux TCP/ip API
	strCOM.inReceiveTimeOut = strCPT.inTCPResponseTimeout;
	strCOM.inConnectionTimeOut = strCPT.inTCPConnectTimeout;

	
	vdDebug_LogPrintf("--inCTOSS_COMM_Connectb,SSLFlag=[%d],inGPRSSingal=[%d]",strCOM.bSSLFlag,strCOM.inGPRSSingal);
    //inMultiAP_Database_COM_Save();
	inMultiAP_Database_COM_SaveEx();

/*
	if (usPreconnectStatus == 1)
	{
    	CTOS_KBDBufPut(d_KBD_INVALID_COM);
		usResult = inMultiAP_RunIPCCmdTypes("SHARLS_COM", d_IPC_CMD_COMM_CONNECT_PreConnect1, bInBuf, usInLen, bOutBuf, &usOutLen);	
	}
	else if (usPreconnectStatus == 2)
	{
    	CTOS_KBDBufPut(d_KBD_INVALID_COM);
		usResult = inMultiAP_RunIPCCmdTypes("SHARLS_COM", d_IPC_CMD_COMM_CONNECT_PreConnect2, bInBuf, usInLen, bOutBuf, &usOutLen);	
	}
	else
*/
	{
    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_COM", d_IPC_CMD_COMM_CONNECT, bInBuf, usInLen, bOutBuf, &usOutLen);
	}


	
	vdDebug_LogPrintf("*****GLADY1******* CONNECT RESULT = %d %d",usResult, bOutBuf[0]);
    if(d_OK == usResult)
    {
        //status
        if(bOutBuf[0] == IPC_COMM_SUCC){   
			
			//isPredial = 1;
			//fCommAlreadyOPen = TRUE;
			
			vdDebug_LogPrintf("*****GLADY******* CONNECT RESULT success= %d",fCommAlreadyOPen);
            return d_OK;
        }else
				//0722
				{
				    srTransRec.shTransResult = TRANS_TERMINATE;
					usResult = (bOutBuf[1] | bOutBuf[2] << 8);
					vdDebug_LogPrintf("--usResult=[%d],[%x]",usResult,usResult);
					
					if ((usResult == 9175) || (usResult == 9104) || (usResult == 12336)) //aaronnino for bdo ver 9.0 issue#00680 NO ERROR MESSAGE FOR CREDIT,DEBIT & CUP at the end of the transaction for GPRS & WIFI
						vdDisplayErrorMsgResp2(" ", "Connect Failed","Please Try Again");
            return d_NO;
        }
				//0722
    }
    
    return usResult;
}

int inCTOSS_COMM_Send(TRANS_DATA_TABLE *srTransPara,unsigned char *uszSendData,unsigned long ulSendLen)
{
    BYTE bInBuf[40];
    BYTE bOutBuf[40];
    //BYTE bySendTemp[2048];
	BYTE bySendTemp[SEND_BUF];
    BYTE byTempLen[10];
    BYTE byTempHEXLen[10];
    int inHeader;
    
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;

//0721
#if 0
		USHORT usNetworkType = 0;
		BYTE szNetworkName[128+1];

		inCTOSS_GetGPRSSignalEx(&usNetworkType, szNetworkName,&usEthType);

		vdDebug_LogPrintf("--inCTOSS_COMM_Connect,fGPRSConnectOK=[%d],inCommunicationMode=[%d]",fGPRSConnectOK,strCPT.inCommunicationMode);
		if ((fGPRSConnectOK != TRUE) && (strCPT.inCommunicationMode == GPRS_MODE)) // flag to determine whether need do comm connection or not.
		{
			return d_NO;
		}
#endif
//0721
		vdDebug_LogPrintf("--inCTOSS_COMM_Send,chGetInit_Connect=[%d]",chGetInit_Connect());

	if(srTransRec.byPackType != DCC_RATEREQUEST && srTransRec.byPackType != DCC_RATEREQUEST_RETRY)
		vdDispTransTitleCardTypeandTotal(srTransRec.byTransType); //aaronnino for BDOCLG ver 9.0 fix on issue #00139 HAVE A DEFAULT TITLE DISPLAY OF TXN TYPE CARD LABEL 6 of 8

    memset(bOutBuf, 0x00, sizeof(bOutBuf)); 

    //inMultiAP_Database_COM_Clear();
	inMultiAP_Database_COM_ClearEx();

    inHeader = strCPT.inIPHeader;
    strCOM.bSSLFlag = strCPT.fSSLEnable;

	if (gCommMode == DIAL_UP_MODE)//for Sharls_COM modem
		inHeader = NO_HEADER_LEN;
    //inHeader = HEX_EXCLUDE_LEN;//for test
    vdDebug_LogPrintf("inCTOSS_COMM_Send[%ld]",ulSendLen);
    
    switch(inHeader)
    {
        case NO_HEADER_LEN:
            strCOM.inSendLen = ulSendLen;
            vdDebug_LogPrintf("---***inCTOSS_COMM_Send[%ld]",ulSendLen);
            
            memcpy(bySendTemp, uszSendData, ulSendLen);
            memcpy(szSendData,bySendTemp,strCOM.inSendLen);
            break;
            
        case HEX_EXCLUDE_LEN:
            bySendTemp[0] = ((ulSendLen & 0x0000FF00) >> 8);
            bySendTemp[1] = (ulSendLen & 0x000000FF);

            strCOM.inSendLen = ulSendLen + 2;
            
            vdDebug_LogPrintf("---inCTOSS_COMM_Send[%ld]",ulSendLen);
            memcpy(&bySendTemp[2], uszSendData, ulSendLen);
            memcpy(szSendData,bySendTemp,strCOM.inSendLen);

            break;

        case BCD_EXCLUDE_LEN:
            sprintf(byTempLen,"%04ld",ulSendLen);
            wub_str_2_hex(byTempLen,byTempHEXLen,4);
            memcpy(bySendTemp,byTempHEXLen,2);           
            strCOM.inSendLen = ulSendLen + 2;
            
            memcpy(&bySendTemp[2], uszSendData, ulSendLen);
            memcpy(szSendData,bySendTemp,strCOM.inSendLen);
            break;

        case HEX_INCLUDE_LEN:
            ulSendLen += 2;

            bySendTemp[0] = ((ulSendLen & 0x0000FF00) >> 8);
            bySendTemp[1] = (ulSendLen & 0x000000FF);

            strCOM.inSendLen = ulSendLen + 2;
            vdDebug_LogPrintf("---HEX_INCLUDE_LEN[%ld]",ulSendLen);
            memcpy(&bySendTemp[2], uszSendData, ulSendLen);
            memcpy(szSendData,bySendTemp,strCOM.inSendLen);   
            break;
            

        case BCD_INCLUDE_LEN:            
            ulSendLen += 2;

            sprintf(byTempLen,"%04ld",ulSendLen);
            wub_str_2_hex(byTempLen,byTempHEXLen,4);
            memcpy(bySendTemp,byTempHEXLen,2);           
            strCOM.inSendLen = ulSendLen + 2;
            
            memcpy(&bySendTemp[2], uszSendData, ulSendLen);
            memcpy(szSendData,bySendTemp,strCOM.inSendLen);
            
            break;

        default:
            
            bySendTemp[0] = ((ulSendLen & 0x0000FF00) >> 8);
            bySendTemp[1] = (ulSendLen & 0x000000FF);

            strCOM.inSendLen = ulSendLen + 2;
            
            vdDebug_LogPrintf("---inCTOSS_COMM_Send[%ld]",ulSendLen);
            memcpy(&bySendTemp[2], uszSendData, ulSendLen);
            memcpy(szSendData,bySendTemp,strCOM.inSendLen);

            break;
    }
    
    strCOM.inHeaderFormat = inHeader;


	//testlang
    //if (fCrash == TRUE){
	//	vdCTOSS_ReForkSubAP("SHARLS_COM");
		
	//	vdDebug_LogPrintf("crash_test fcrash %d", fCrash);
		//vdDebug_LogPrintf("crash time refork %s", szTime);
    //}
	//testlang-removelater
    
    //inMultiAP_Database_COM_Save();
	inMultiAP_Database_COM_SaveEx();

    if (strCPT.inCommunicationMode == GPRS_MODE){
		if (chGetInit_Connect() == 1)
			usResult = inMultiAP_RunIPCCmdTypesExx("SHARLS_COM", d_IPC_CMD_COMM_SENDEx, bInBuf, usInLen, bOutBuf, &usOutLen);
		else
    		usResult = inMultiAP_RunIPCCmdTypesExx("SHARLS_COM", d_IPC_CMD_COMM_SEND, bInBuf, usInLen, bOutBuf, &usOutLen);
    
    	vdDebug_LogPrintf("---commsend inCTOSS_COMM_Send result = [%ld]",usResult);

		vdDebug_LogPrintf("SEND RETURNED ST_SHARLS_COMM_CRASH");

       vdDebug_LogPrintf("send result = %d", usResult);
	   
		if (usResult == ST_SHARLS_COMM_CRASH){

			vdDebug_LogPrintf("ST_SHARLS_COMM_CRASHT");
			//CTOS_LCDTPrintXY (1,3, "ST_SHARLS_COMM_CRASHT");
			//CTOS_Delay(2000);
			fSharlsCommCrash = TRUE;
			return ST_SHARLS_COMM_CRASH;
		}

		
    }else{
    
		if (chGetInit_Connect() == 1)
			usResult = inMultiAP_RunIPCCmdTypes("SHARLS_COM", d_IPC_CMD_COMM_SENDEx, bInBuf, usInLen, bOutBuf, &usOutLen);
		else
			usResult = inMultiAP_RunIPCCmdTypes("SHARLS_COM", d_IPC_CMD_COMM_SEND, bInBuf, usInLen, bOutBuf, &usOutLen);

    }

	
    vdDebug_LogPrintf("---GLAD TEST inCTOSS_COMM_Send[%ld] - %d",usResult, bOutBuf[0]);
    if(d_OK == usResult)
    {
        //status
        if(bOutBuf[0] == IPC_COMM_SUCC)            
            return d_OK;
        else
            return d_NO;
    }
    else
        return d_NO;
    
    //return usResult;
}

int inCTOSS_COMM_Receive(TRANS_DATA_TABLE *srTransPara,unsigned char *uszRecData)
{
    BYTE bInBuf[40];
    BYTE bOutBuf[40];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;
		int inHeader;

    static USHORT usNetworkType = 0;
    static USHORT usEthType = 0;
    static BYTE szNetworkName[128+1] = {0};

	//wifi-mod2
	STRUCT_SHARLS_COM Sharls_COMData;
    //wifi-mod2


    memset(bOutBuf, 0x00, sizeof(bOutBuf));    
    inHeader = strCPT.inIPHeader;
	if (gCommMode == DIAL_UP_MODE)//for Sharls_COM modem
		inHeader = NO_HEADER_LEN;
	inCTOSS_CheckMemoryStatusEx("BEFORE inMultiAP_RunIPCCmdTypes d_IPC_CMD_COMM_RECEIVE");
    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_COM", d_IPC_CMD_COMM_RECEIVE, bInBuf, usInLen, bOutBuf, &usOutLen);
    inCTOSS_CheckMemoryStatusEx("AFTER inMultiAP_RunIPCCmdTypes d_IPC_CMD_COMM_RECEIVE");
    vdDebug_LogPrintf("---inCTOSS_COMM_Receive.usResult[%d]bOutBuf[0]=[%d]",usResult,bOutBuf[0]);
    if(d_OK == usResult)
    {
        //status
        if(bOutBuf[0] == IPC_COMM_SUCC) 
        {      
            //inMultiAP_Database_COM_Read();
			inMultiAP_Database_COM_ReadEx();
            //vdDebug_LogPrintf("---strCOM.inReceiveLen[%d],.inIPHeader=[%d]",strCOM.inReceiveLen,strCPT.inIPHeader);
            //vdDebug_LogPrintf("rec data==[%d][%s]",strCOM.inReceiveLen,szReceiveData);
            if(inHeader == NO_HEADER_LEN)
            {
                usResult = strCOM.inReceiveLen;
                memcpy(uszRecData,szReceiveData,strCOM.inReceiveLen);

				//puts("Server reply :");
				//puts(uszRecData);	
            }
            else
            {
                usResult = strCOM.inReceiveLen-2;
                memcpy(uszRecData,&szReceiveData[2],strCOM.inReceiveLen-2);
            }
			//after receive clear database
			//inMultiAP_Database_COM_Clear();
			inMultiAP_Database_COM_ClearEx();
            return usResult;
        }
        else
//to prevent sending reversal if network disconnected
            //return 0;
        {
			//wifi-mod2			
					if(strCPT.inCommunicationMode == WIFI_MODE)
						{
						inCTOSS_GetGPRSSignalEx1(&usNetworkType, szNetworkName, &usEthType, &Sharls_COMData);
						}
					else
			//wifi-mod2

					inCTOSS_GetGPRSSignalEx(&usNetworkType, szNetworkName,&usEthType);
					//vdDebug_LogPrintf("**inCTOSS_GetGPRSSignalEx usEthType=[%d]**fGPRSConnectOK=[%d]", usEthType, fGPRSConnectOK);

					if (fGPRSConnectOK != TRUE)
						return -7;
					else
						return 0;
        }
    }
    
    return usResult;
}

int inCTOSS_COMM_Disconnect(TRANS_DATA_TABLE *srTransPara)
{
    BYTE bInBuf[40];
    BYTE bOutBuf[40];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;

	int inGPRSSignal;
	
	USHORT usNetworkType = 0;
	BYTE szNetworkName[128+1];
	
	CTOS_RTC SetRTC;
    char szDate[4+1];
    char szTime[6+1];
    char szBuf[2+1];

    vdDebug_LogPrintf("** inCTOSS_COMM_Disconnect **");

	vdDebug_LogPrintf("removelater inCTOSS_COMM_Disconnect");

	//CTOS_LCDTPrintXY (1,3, "TEST DISCONNECT");
	//CTOS_Delay(2000);

	if (fSharlsCommCrash == TRUE && strCPT.inCommunicationMode == GPRS_MODE){
		
		//CTOS_LCDTPrintXY (1,3, "DO NOT DISCONNECT");
		//CTOS_LCDTPrintXY (1,8, "PROCESSING DATA");
		//CTOS_Delay(2000);
		return d_OK;
	}

	//removelater
	//return d_OK;

	//	if ((strCPT.inCommunicationMode == GPRS_MODE) || (strCPT.inCommunicationMode == WIFI_MODE)) 
	//	      return d_OK;


    memset(bOutBuf, 0x00, sizeof(bOutBuf)); 
	gCommMode = -1;//for Sharls_COM modem

    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_COM", d_IPC_CMD_COMM_DISCONNECT, bInBuf, usInLen, bOutBuf, &usOutLen);
		
    if(d_OK == usResult)
    {
        //status
        if(bOutBuf[0] == IPC_COMM_SUCC)            
            return d_OK;
        else
            return d_NO;
    }
    
    return usResult;
}

int inCTOSS_COMM_End(TRANS_DATA_TABLE *srTransPara)
{
    BYTE bInBuf[40];
    BYTE bOutBuf[40];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;


	//FIX to not disconnect in network if GPRS mode.
	if ((strCPT.inCommunicationMode == GPRS_MODE) || (strCPT.inCommunicationMode == WIFI_MODE)  || (strCPT.inCommunicationMode == ETHERNET_MODE)) 
		return d_OK;

    memset(bOutBuf, 0x00, sizeof(bOutBuf)); 
		gCommMode = -1;//for Sharls_COM modem

    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_COM", d_IPC_CMD_COMM_END, bInBuf, usInLen, bOutBuf, &usOutLen);
    if(d_OK == usResult)
    {
        //status
        if(bOutBuf[0] == IPC_COMM_SUCC)            
            return d_OK;
        else
            return d_NO;
    }
    
    return usResult;
}

int inCTOSS_GetGPRSSignal(unsigned short* usNetworkType, char* szNetworkName,unsigned short* usEthType)
{
    BYTE bInBuf[40];
    BYTE bOutBuf[40];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;
    int inSignal;

//	USHORT usType;
    BYTE szType[2+1];

    memset(bOutBuf, 0x00, sizeof(bOutBuf)); 

    usResult = inMultiAP_RunIPCCmdTypesEx("SHARLS_COM", d_IPC_CMD_GPRS_SIGNAL, bInBuf, usInLen, bOutBuf, &usOutLen);

	*usEthType = bOutBuf[1];
    inSignal = bOutBuf[2];
	
	memset(szType, 0x00, sizeof(szType));
	memcpy(szType, &bOutBuf[3], 2);
	*usNetworkType = (szType[0] | szType[1] << 8);

	strcpy(szNetworkName, &bOutBuf[6]);
	szNetworkName[strlen(szNetworkName)-1] = 0x00;
	
    vdDebug_LogPrintf("---NETWORK TYPE[%02X][%s]", *usNetworkType, szNetworkName);					
    vdDebug_LogPrintf("---inCTOSS_GetGPRSSignal[%02X %02X %02X]", bOutBuf[0], bOutBuf[1], bOutBuf[2]);
    if(d_OK == usResult)
    {
        //status
        if(bOutBuf[0] == IPC_COMM_SUCC){
						if (inSignal < 1)
							fGPRSConnectOK = FALSE;
						else
							fGPRSConnectOK = TRUE;
							
            return inSignal;
        }	
        else{
						fGPRSConnectOK = FALSE;
						usResult = 0;
            return usResult;
        }
    }
		else{
			inSignal = 0;
			usResult = 0;
			fGPRSConnectOK = FALSE;
			return usResult;
		}
    
    return usResult;
}

//wifi-mod
int inCTOSS_COMMWIFISCAN(void)
{
    BYTE bInBuf[40];
    BYTE bOutBuf[40];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;

	 vdDebug_LogPrintf("**inCTOSS_COMMScanWIFI START**");	
	 
   memset(bOutBuf, 0x00, sizeof(bOutBuf));
   memset(bInBuf, 0x00, sizeof(bInBuf));
   //strcpy(bInBuf, "RGB2762B0|FFFFFF");
	 strcpy(bInBuf, "RGB134371|FFFFFF");
   usInLen = strlen(bInBuf);
   usResult = inMultiAP_RunIPCCmdTypes("SHARLS_COM", d_IPC_CMD_WIFISCAN, bInBuf, usInLen, bOutBuf, &usOutLen);

   return ST_SUCCESS;
}


int inCTOSS_GetGPRSSignalEx(unsigned short* usNetworkType, char* szNetworkName,unsigned short* usEthType)
{
    BYTE bInBuf[40];
    BYTE bOutBuf[1000];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;
    int inSignal;
	int inGPRSConnected;
	STRUCT_SHARLS_COM Sharls_COMData;

//	USHORT usType;
    BYTE szType[2+1];

    memset(bOutBuf, 0x00, sizeof(bOutBuf));
	memset(&Sharls_COMData, 0x00, sizeof(STRUCT_SHARLS_COM));

    usResult = inMultiAP_RunIPCCmdTypesEx("SHARLS_COM", d_IPC_CMD_GPRS_SIGNALEX, bInBuf, usInLen, bOutBuf, &usOutLen);

	memcpy(&Sharls_COMData,&bOutBuf[1],sizeof(STRUCT_SHARLS_COM));
	
	*usEthType = Sharls_COMData.usEthType;
    inSignal = Sharls_COMData.bgGPRSSignal;
	
	*usNetworkType = Sharls_COMData.usGPRSNetworkType;
	strcpy(szNetworkName, Sharls_COMData.szGPRSNetworkName);
	inGPRSConnected = Sharls_COMData.bgGPRSType;
	
    vdDebug_LogPrintf("---NETWORK TYPE[%02X][%s],inGPRSConnected=[%d], %d", *usNetworkType, szNetworkName,inGPRSConnected,usResult);					
    vdDebug_LogPrintf("---inCTOSS_GetGPRSSignal[%02X %02X %02X]", bOutBuf[0], bOutBuf[1], bOutBuf[2]);


		
    if(d_OK == usResult)
    {
        
        //status
        if(bOutBuf[0] == IPC_COMM_SUCC){
        //if(bOutBuf[1] == IPC_COMM_SUCC){
        //if ((bOutBuf[1] == 01) && (bOutBuf[2] == 00)){	
						if (inGPRSConnected == TRUE)
							fGPRSConnectOK = TRUE;
						else
							fGPRSConnectOK = FALSE;

					
            return inSignal;
        }	
        else{
					
						fGPRSConnectOK = FALSE;
						usResult = 0;
            return usResult;
        }
    }
		else{
			
			inSignal = 0;
			usResult = 0;
			fGPRSConnectOK = FALSE;
			return usResult;
		}
    
    return usResult;
}


int inCTOSS_GetGPRSSignalEx1(unsigned short* usNetworkType, char* szNetworkName,unsigned short* usEthType, STRUCT_SHARLS_COM* Sharls_COMData)
{
    BYTE bInBuf[40];
    BYTE bOutBuf[1000];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;
    int inSignal;
	int inGPRSConnected;
	int inmedomstatus;
//	STRUCT_SHARLS_COM Sharls_COMData;

//	USHORT usType;
    BYTE szType[2+1];

    memset(bOutBuf, 0x00, sizeof(bOutBuf));
//	memset(&Sharls_COMData, 0x00, sizeof(STRUCT_SHARLS_COM));

    usResult = inMultiAP_RunIPCCmdTypesEx("SHARLS_COM", d_IPC_CMD_GPRS_SIGNALEX, bInBuf, usInLen, bOutBuf, &usOutLen);

	memcpy(Sharls_COMData, &bOutBuf[1],sizeof(STRUCT_SHARLS_COM));
	
	*usEthType = Sharls_COMData->usEthType;
    //inSignal = Sharls_COMData->bgGPRSSignal;
	inmedomstatus = Sharls_COMData->inReserved1;
	
	*usNetworkType = Sharls_COMData->usGPRSNetworkType;
	strcpy(szNetworkName, Sharls_COMData->szGPRSNetworkName);
	//inGPRSConnected = Sharls_COMData->bgGPRSType;
	usHWSupport = (Sharls_COMData->szReserved1[0] | Sharls_COMData->szReserved1[1] << 8);

	vdDebug_LogPrintf("---inmedomstatus[%d],usHWSupport=[%04x]", inmedomstatus,usHWSupport);
    vdDebug_LogPrintf("---NETWORK TYPE[%02X][%s],inGPRSConnected=[%d]", *usNetworkType, szNetworkName,inGPRSConnected);					
    vdDebug_LogPrintf("---inCTOSS_GetGPRSSignal[%02X %02X %02X]", bOutBuf[0], bOutBuf[1], bOutBuf[2]);
	vdDebug_LogPrintf("---wifi status[%d],WIFISSID=[%s], signal[%d]", Sharls_COMData->usWIFIType,Sharls_COMData->szWIFISSID, Sharls_COMData->inReserved2);

	inSignal = Sharls_COMData->inReserved2;

	vdDebug_LogPrintf("Result - %d - %d", usResult, inSignal);

	if(strCPT.inCommunicationMode == WIFI_MODE)
	{
		// Added to check WIFI is connected "usWIFIType" -- sidumili
		if ((d_OK == usResult) && (Sharls_COMData->usWIFIType > 0))
		{		  
			 vdDebug_LogPrintf("Result OK - %d | inSignal - %d", usResult, inSignal);
			
			 if (Sharls_COMData->usWIFIType > 0) // Connected
			 {
				if (inSignal > 0)
				{
					vdDebug_LogPrintf("Connected WIFI with SSID[%s], Signal[%d]", Sharls_COMData->szWIFISSID, inSignal);
					fGPRSConnectOK = TRUE;
					return inSignal;
				}
				else
				{
					vdDebug_LogPrintf("Not Connected WIFI with SSID[%s], Signal[%d]", Sharls_COMData->szWIFISSID, inSignal);
					fGPRSConnectOK = FALSE;
					usResult = 0;
					return usResult;
				}
			 }
			 else
			 {
				vdDebug_LogPrintf("Failed!!! Connection WIFI with SSID[%s], Signal[%d]", Sharls_COMData->szWIFISSID, inSignal);
				fGPRSConnectOK = FALSE;
				usResult = 0;
				return usResult;
			 }				
		}
		else
		{
			vdDebug_LogPrintf("Failed!!! Connection WIFI with SSID[%s], Signal[%d]", Sharls_COMData->szWIFISSID, inSignal);
			vdDebug_LogPrintf("Result not OK - %d", usResult);
			inSignal = 0;
			usResult = 0;
			fGPRSConnectOK = FALSE;
			return usResult;
		}
	}
	else
	{
		if(d_OK == usResult)
	    {
	         
			 vdDebug_LogPrintf("Result OK - %d", usResult);
	        //status
	        //if(bOutBuf[0] == IPC_COMM_SUCC){  
	        //if ((bOutBuf[1] == 01) && (bOutBuf[2] == 00)){	
	        if (inSignal > 0){
				
				vdDebug_LogPrintf("IPC_COMM_SUCC - %d", fGPRSConnectOK);
							//if (inGPRSConnected > 0)
				fGPRSConnectOK = TRUE;
							//else
								//fGPRSConnectOK = FALSE;
								
	            return inSignal;
	        }	
	        else{
							fGPRSConnectOK = FALSE;
							usResult = 0;
	            return usResult;
	        }
	    }
		else
		{
				
				vdDebug_LogPrintf("Result not OK - %d", usResult);
				inSignal = 0;
				usResult = 0;
				fGPRSConnectOK = FALSE;
				return usResult;
		}
	}
    
    return usResult;
}
//wifi-mode

int inCTOSS_COMMSetFont(char *font)
{
    BYTE bInBuf[40];
    BYTE bOutBuf[40];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;

	 vdDebug_LogPrintf("**inCTOSS_COMMSetFont START**");	
	 
    memset(bOutBuf, 0x00, sizeof(bOutBuf));
	memset(bInBuf, 0x00, sizeof(bInBuf));
	strcpy(bInBuf,font);
	usInLen = strlen(bInBuf);
    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_COM", d_IPC_CMD_SETFONT, bInBuf, usInLen, bOutBuf, &usOutLen);

    return ST_SUCCESS;
}	


int inCTOSS_SIMGetGPRSIP(void)
{
	BYTE bInBuf[100];
	BYTE bOutBuf[100];
	BYTE *ptr = NULL;
	USHORT usInLen = 0;
	USHORT usOutLen = 0;
	USHORT usResult;
	//BYTE szGPRSIP[50+1];

	memset(szIP,0,sizeof(szIP));
	memset(szDNS1,0,sizeof(szDNS1));
	memset(szDNS2,0,sizeof(szDNS2));
	memset(szGateWay,0,sizeof(szGateWay));
	memset(szSubnetMask,0,sizeof(szSubnetMask));

	vdDebug_LogPrintf("**inCTOSS_SIMGetGPRSIP**");	
	 
	memset(bOutBuf, 0x00, sizeof(bOutBuf));
	memset(bInBuf, 0x00, sizeof(bInBuf));
	usResult = inMultiAP_RunIPCCmdTypes("SHARLS_COM", d_IPC_CMD_COMM_GETGPRSIP, bInBuf, usInLen, bOutBuf, &usOutLen);
	if(d_OK == usResult)
    {
        if(bOutBuf[0] == IPC_COMM_SUCC)
        {
          	memset(szIP,0x00,sizeof(szIP));
  			    strcpy(szIP,&bOutBuf[1]);
  			    vdDebug_LogPrintf("szGPRSIP=[%s]",szIP);
            return d_OK;
        }
        else
            return d_NO;
    }
	return ST_SUCCESS;
}



int inCTOSS_GPRSPing(unsigned char *strIPURL)
{
	BYTE bInBuf[100];
	BYTE bOutBuf[100];
	BYTE *ptr = NULL;
	USHORT usInLen = 0;
	USHORT usOutLen = 0;
	USHORT usResult;
	//BYTE szGPRSIP[50+1];

	vdDebug_LogPrintf("**inCTOSS_GPRSPing**");	
	 
	memset(bOutBuf, 0x00, sizeof(bOutBuf));
	memset(bInBuf, 0x00, sizeof(bInBuf));

	strcpy(bInBuf,strIPURL);
	usInLen = strlen(bInBuf);
	
	usResult = inMultiAP_RunIPCCmdTypes("SHARLS_COM", d_IPC_CMD_COMM_GETGPRSPING, bInBuf, usInLen, bOutBuf, &usOutLen);
	if(d_OK == usResult)
    {
        if(bOutBuf[0] == IPC_COMM_SUCC)
        {
            return d_OK;
        }
        else
            return d_NO;
    }
	return d_NO;
}


/*Get up the configuration of Ethernet */
int inWIFI_GetConnectConfig(void)
{
   BYTE buf[32];
	 USHORT usLen = 32,ret;
	 BYTE Tempbuff[50+1];

   memset(szIP,0,sizeof(szIP));
   memset(szDNS1,0,sizeof(szDNS1));
   memset(szDNS2,0,sizeof(szDNS2));
   memset(szGateWay,0,sizeof(szGateWay));
   memset(szSubnetMask,0,sizeof(szSubnetMask));

   usLen = sizeof(buf);
	 memset(buf,0,usLen);
	 CTOS_WifiConfigGet(d_WIFI_CONFIG_DHCP,buf,&usLen);
	 buf[usLen] = 0;
   vdDebug_LogPrintf("**d_WIFI_CONFIG_DHCP[%s]**",buf);
	 if(buf[0] == '0')
	 	{
	     vdDebug_LogPrintf("--DHCP OFF--");
	 	}
	 else
	 	{
	     vdDebug_LogPrintf("--DHCP ON--");
	 	}
	 
   usLen = sizeof(buf);
	 memset(buf,0,usLen);
	 CTOS_WifiConfigGet(d_WIFI_CONFIG_AUTOCON_AP,buf,&usLen);
	 buf[usLen] = 0;
   vdDebug_LogPrintf("**d_WIFI_CONFIG_AUTOCON_AP[%s]**",buf);

	 if(buf[0] == '0')
	 	{
			 vdDebug_LogPrintf("--AutoCon OFF--");
	 	}
	 else
	 	{
			 vdDebug_LogPrintf("--AutoCon ON--");
	 	}

		usLen = sizeof(buf);
    memset(buf,0,usLen);
    CTOS_WifiConfigGet(d_WIFI_CONFIG_IP,buf,&usLen);
    buf[usLen] = 0;
    vdDebug_LogPrintf("**d_WIFI_CONFIG_IP[%s]**",buf);
		strcpy(szIP, buf);
		
    usLen = sizeof(buf);
    memset(buf,0,usLen);
    CTOS_WifiConfigGet(d_WIFI_CONFIG_MASK,buf,&usLen);
    buf[usLen] = 0;
    vdDebug_LogPrintf("**d_WIFI_CONFIG_MASK[%s]**",buf);
		strcpy(szSubnetMask, buf);

   usLen = sizeof(buf);
	 memset(buf,0,usLen);
	 CTOS_WifiConfigGet(d_WIFI_CONFIG_GATEWAY,buf,&usLen);
	 buf[usLen] = 0;
	 vdDebug_LogPrintf("**d_WIFI_CONFIG_GATEWAY[%s]**",buf);
	 strcpy(szGateWay, buf);

 usLen = sizeof(buf);
	 memset(buf,0,usLen);
	 CTOS_WifiConfigGet(d_WIFI_CONFIG_DNSIP,buf,&usLen);
	 buf[usLen] = 0;
	 vdDebug_LogPrintf("**d_WIFI_CONFIG_DNSIP[%s]**",buf);
	 strcpy(szDNS1, buf);

 usLen = sizeof(buf);
	 memset(buf,0,usLen);
	 CTOS_WifiConfigGet(d_WIFI_CONFIG_MAC,buf,&usLen);
	 buf[usLen] = 0;
	 vdDebug_LogPrintf("**d_WIFI_CONFIG_MAC[%s]**",buf);; 
 
	vdDebug_LogPrintf("**WIFI_GetConnectConfig END**");
	return ST_SUCCESS;
}

int inCTOSS_SIMGetGPRSIPInfo(void)
{
	BYTE bInBuf[100];
	BYTE bOutBuf[1000];
	BYTE buf[32];
	BYTE *ptr = NULL;
	USHORT usInLen = 0;
	USHORT usOutLen = 0;
	USHORT usResult;
	BYTE szGPRSIP[50+1];
	STRUCT_IP_INFO IPInfo;
	 
	memset(bOutBuf, 0x00, sizeof(bOutBuf));
	memset(bInBuf, 0x00, sizeof(bInBuf));

	usResult = inMultiAP_RunIPCCmdTypes("SHARLS_COM", d_IPC_CMD_COMM_GETGPRSIPINFO, bInBuf, usInLen, bOutBuf, &usOutLen);
	
	//usResult = inMultiAP_RunIPCCmdTypes("SHARLS_COM", d_IPC_CMD_COMM_GETCONFIG, bInBuf, usInLen, bOutBuf, &usOutLen);

	vdDebug_LogPrintf("*****GLADY1******* get ip result = %d %d",usResult, bOutBuf[0]);

	
	vdDebug_LogPrintf("*****GLADY1******* get ip result = %d %d",usResult, bOutBuf[1]);

	
	vdDebug_LogPrintf("*****GLADY1******* get ip result = %d %d",usResult, bOutBuf[2]);
	if(d_OK == usResult)
    {
        if(bOutBuf[0] == IPC_COMM_SUCC)
        {
            memset(&IPInfo,0x00,sizeof(STRUCT_IP_INFO));
            memcpy(&IPInfo,&bOutBuf[1],sizeof(STRUCT_IP_INFO));

            memset(szIP,0,sizeof(szIP));
            memset(szDNS1,0,sizeof(szDNS1));
            memset(szDNS2,0,sizeof(szDNS2));
            memset(szGateWay,0,sizeof(szGateWay));
            memset(szSubnetMask,0,sizeof(szSubnetMask));

						strcpy(szIP, IPInfo.szIP);
						vdDebug_LogPrintf("AAA - szIP GPRS: %s", szIP);
						strcpy(szGateWay, IPInfo.szGetWay);
						vdDebug_LogPrintf("AAA - szGateWay GPRS: %s", szGateWay);
						strcpy(szSubnetMask, IPInfo.szSubNetMask);
						vdDebug_LogPrintf("AAA - szSubnetMask GPRS: %s", szSubnetMask);
						strcpy(szDNS1, IPInfo.szHostDNS1);
						vdDebug_LogPrintf("AAA - szDNS1 GPRS: %s", szDNS1);
						strcpy(szDNS2, IPInfo.szHostDNS2);
						vdDebug_LogPrintf("AAA - szDNS2 GPRS: %s", szDNS2);
            
            
            return d_OK;
        }
        else
            return d_NO;
    }
	return ST_SUCCESS;
}


void vdPrint_EthernetStatus(void)
{
        CTOS_RTC clock;
        char Time[30];
        int i = 0;
        BYTE Display[31][30]={0};
        BYTE bTag, baValue[20][50], pbLen[20];

		BYTE baTmpBuf[128];
		BYTE bTmpLen = 0;

		memset(szIP,0,sizeof(szIP));
		memset(szDNS1,0,sizeof(szDNS1));
		memset(szDNS2,0,sizeof(szDNS2));
		memset(szGateWay,0,sizeof(szGateWay));
		memset(szSubnetMask,0,sizeof(szSubnetMask));

        //CTOS_RTCGet(&clock);  //Get the real time clock
        //sprintf( Time, "20%02d/%02d/%02d %02d:%02d:%02d", 
        //       clock.bYear, clock.bMonth, clock.bDay, clock.bHour, clock.bMinute, clock.bSecond);
        //CTOS_PrinterPutString("[Ethernet Info]");
		//inCTOSS_CapturePrinterQRCodeBuffer("[Ethernet Info]",0);
        memset(Display,0x00,sizeof(Display)); //clean the memory of Display 
        for(i=1;i<=18;i++)
		{
	        pbLen[i] = 50;
	        CTOS_EthernetConfigGet ( i, baValue[i], &pbLen[i] ); 
			//CTOS_Delay(100);
	        baValue[i][pbLen[i]] = '\0';
			//printf("%02d.%22s, %2d\n", i, baValue[i], pbLen[i]);
        }

		CTOS_Delay(100);
		for(i=1;i<=18;i++)
		{
	        pbLen[i] = 50;
	        CTOS_EthernetConfigGet ( i, baValue[i], &pbLen[i] ); 
			//CTOS_Delay(100);
	        baValue[i][pbLen[i]] = '\0';
			//printf("%02d.%22s, %2d\n", i, baValue[i], pbLen[i]);
        }
        
        check_Ethernet( baValue[14], 1); // CONN MODE  number = 1                    
		check_Ethernet( baValue[12], 2); // IP MODE  number = 2

		sprintf(Display[1],"ETHERNET  : %s", baValue[10]);                    
		sprintf(szIP,"%s", baValue[1]);                    
		sprintf(szSubnetMask,"%s", baValue[2]);                    
		sprintf(szGateWay,"%s", baValue[3]);                    
        sprintf(szDNS1,"%s", baValue[16]);  
		
#if 0
		sprintf(Display[1],"ETHERNET  : %s", baValue[10]);                    
		sprintf(Display[2],"LOCAL IP  : %s", baValue[1]);                    
		sprintf(Display[3],"MASK      : %s", baValue[2]);                    
		sprintf(Display[4],"GATEWAY IP: %s", baValue[3]);                    
		sprintf(Display[5],"HOST IP   : %s", baValue[4]);                    
		sprintf(Display[6],"HOST PORT : %s", baValue[8]);                    
		sprintf(Display[7],"MAC       : %s", baValue[11]);                    
		sprintf(Display[8],"CONN MODE : %s", baValue[14]);                    
		sprintf(Display[9],"IP MODE   : %s", baValue[12]);                    
		sprintf(Display[10],"DNS SERVER: %s", baValue[16]);                    
		//sprintf(Display[11],"HOST URL  : %s", baValue[17]);   

		for(i=1; i<=10; i++) 
		{
			CTOS_PrinterPutString(Display[i]);
			inCTOSS_CapturePrinterQRCodeBuffer(Display[i],0);
		}
		//CTOS_PrinterFline(60);
#endif

}

void check_Ethernet(BYTE *baValue_now,int number){
 // CONN MODE  number = 1
 // IP MODE  number = 2    
    if(number == 1)
	{
        if(*baValue_now == '0') sprintf(baValue_now, "Auto-connect");
        if(*baValue_now == '1') sprintf(baValue_now, "Not support");
        if(*baValue_now == '2') sprintf(baValue_now, "Manual");
    }
	
    if(number == 2)
	{
        if(*baValue_now == '0') sprintf(baValue_now, "Static");
        if(*baValue_now == '1') sprintf(baValue_now, "DHCP");
    }
    
}

int inCTOSS_COMM_GPRSReset(void)
{
	BYTE bInBuf[100];
	BYTE bOutBuf[100];
	BYTE *ptr = NULL;
	USHORT usInLen = 0;
	USHORT usOutLen = 0;
	USHORT usResult;
	int inRet = d_NO;

	vdDebug_LogPrintf("**inCTOSS_GPRSReset**");	
	 
	memset(bOutBuf, 0x00, sizeof(bOutBuf));
	memset(bInBuf, 0x00, sizeof(bInBuf));
		
	usResult = inMultiAP_RunIPCCmdTypes("SHARLS_COM", d_IPC_CMD_COMM_RESETGPRS, bInBuf, usInLen, bOutBuf, &usOutLen);
	vdDebug_LogPrintf("inCTOSS_GPRSReset, usResult=[%d], bOutBuf[0]=[%2X]", usResult, bOutBuf[0]);
	if(d_OK == usResult)
    {
        if(bOutBuf[0] == IPC_COMM_SUCC)
        {
            inRet = d_OK;
        }
        else
            inRet = d_NO;
    }
	
	return inRet;
}

