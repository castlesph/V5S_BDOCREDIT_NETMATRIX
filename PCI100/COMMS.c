#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctosapi.h>
#include <iccmifare.h>
#include <tclcard.h>
#include <vwdleapi.h>


#include "COMMS.h"

#include "..\filemodule\myFileFunc.h"




static BYTE bPort = d_COM1;

/*
void vdDisplayErrorMsg(int inColumn, int inRow,  char *msg)
{
    
    CTOS_LCDTPrintXY(inColumn, inRow, "                                        ");
    CTOS_LCDTPrintXY(inColumn, inRow, msg);
    CTOS_Beep();
    CTOS_Delay(1500);
}
*/
void vdCTOSS_SetRS232Port(int CommPort)
{
	if (CommPort == 0)
		bPort = -1;
	
	if (CommPort == 1)
		bPort = d_COM1;

	if (CommPort == 2)
		bPort = d_COM2;

	return;
}
void vdCTOSS_RNG(BYTE *baResult)
{
	CTOS_RNG(baResult);
}

int inCTOSS_USBOpen(void)
{
	//Enable USB Function // 
	if (CTOS_USBOpen() != d_OK)
	//if (CTOS_USBHostOpen(0x0CA6,0xA010) != d_OK)
	{ 
		vdDisplayErrorMsg(1, 8, "USB Open Fail");
		return d_NO;
	}
	else
	{
		vdDisplayErrorMsg(1, 8, "USB Open OK");

		CTOS_LCDTPrintXY(1, 8, "                                             ");
	}
	//Cancel the currently transmission of data to host // 
	CTOS_USBTxFlush(); 
	//Clear all the data currently received from host // 
	CTOS_USBRxFlush();

	return d_OK;
}

int inCTOSS_USBSendBuf(char *szSnedBuf,int inlen)
{
	char str[300];
	char tmpbuf[50];
	BYTE key;
	int i=0,j=1;
	
	// Check if COM1 is ready to send data 
	//CTOS_LCDTPrintXY(1, 7, "sending...     ");
	
	while (1)
	{
		// Check if Cancel key is pressed // 
		CTOS_KBDHit(&key); 
		if(key == d_KBD_CANCEL) 
		{ 
			return d_NO; 
		}	
		if (CTOS_USBTxReady() == d_OK)
			break;
	}
	
	// Send data via COM1 port 
	if (CTOS_USBTxData(szSnedBuf,inlen) != d_OK)
	//if (CTOS_USBHostTxData(szSnedBuf,inlen,6000) != d_OK)
	{ 
		vdDisplayErrorMsg(1, 8, "USB Send Buf Error");
		return d_NO; 
	}

	memset(str,0x00,sizeof(str));
	sprintf(str,"send     [%d]       ",inlen);
	CTOS_LCDTPrintXY(1, 7, str);
	
	memset(str,0x00,sizeof(str));
	strcpy(str,"BUF ");
	for (i=0; i<inlen; i++)
	{
		memset(tmpbuf,0x00,sizeof(tmpbuf));
		sprintf(tmpbuf,"%02x ",szSnedBuf[i]);
		strcat(str,tmpbuf);

		if (i%6 == 0 && i != 0)
		{
			CTOS_LCDTPrintXY(1, 8+j, str);
			memset(str,0x00,sizeof(str));
			strcpy(str,"BUF ");
			j++;
		}
	}
	CTOS_LCDTPrintXY(1, 8+8, str);

	return d_OK;
}

int inCTOSS_USBRecvBuf(char *szRecvBuf,int *inlen)
{
	USHORT ret;
	USHORT len = 0;
	BYTE key;
	char str[30];

	CTOS_Delay(1500);
	
	while (1)
	{ 
		// Check if Cancel key is pressed // 
		CTOS_KBDHit(&key); 
		if(key == d_KBD_CANCEL) 
		{ 
			break; 
		} 
		// Check if data is available in USB port // 
		CTOS_LCDTPrintXY(1, 6, "RECEIVING...");

		ret = CTOS_USBRxReady(&len);
		if(ret == d_OK && len) 
		{
			// Get Data from USB port 
			CTOS_USBRxData(szRecvBuf,&len);
			//CTOS_USBHostRxData(szRecvBuf,&len,6000);
			*inlen = len;

			memset(str,0x00,sizeof(str));
			sprintf(str,"receive     [%d]       ",len);
			CTOS_LCDTPrintXY(1, 6, str);
			
			CTOS_USBRxFlush();
			CTOS_USBTxFlush();
			//inCTOSS_USBClose();
			//CTOS_Delay(100);
			//inCTOSS_USBOpen();
			return d_OK;
		} 
	}
	
	return d_NO;
	
}

int inCTOSS_USBClose(void)
{
	USHORT ret;
	
	//Clear all the data currently received from host// 
	CTOS_USBRxFlush(); 
	//Disable USB Function // 
	ret = CTOS_USBClose();
	//ret = CTOS_USBHostClose();

	return ret;
}




int inCTOSS_RS232Open(ULONG ulBaudRate, BYTE bParity, BYTE bDataBits, BYTE bStopBits)
{
	USHORT ret;

	//vdDebug_LogPrintf("-->>inCTOSS_RS232Open bPort[%d]--ulBaudRate[%d]--bParity[%d]--bDataBits[%d]--bStopBits[%d]", bPort, ulBaudRate, bParity, bDataBits, bStopBits);

	if (bPort < 0)
	{
		vdDisplayErrorMsg(1, 8, "COM Port Error");
		return d_NO;
	}

	ret = CTOS_RS232Open(bPort, ulBaudRate, bParity, bDataBits, bStopBits);

	//vdDebug_LogPrintf("-->>inCTOSS_RS232Open bPort[%d]--ret[%d]", bPort, ret);
		
	if(ret != d_OK) 
	{ 
		vdDisplayErrorMsg(1, 8, "Open COM Error");
		return ret;
	}
	else
	{
		//if (strTCT.byRS232DebugPort != 0){
		//	vdDisplayErrorMsg(1, 8, "Open COM OK");
			//CTOS_LCDTPrintXY(1, 8, "										     ");
	//	}
		
	}

	CTOS_RS232FlushTxBuffer(bPort);
	CTOS_RS232FlushRxBuffer(bPort);
/*
	//The RTS control signal from this system which indicates this system is ready to receive data
	ret = CTOS_RS232SetRTS(bPort, d_ON); 
	if (ret != d_OK) 
	{ 
		vdDisplayErrorMsg(1, 8, "V7 Rec Err");
		return ret;
	} 
	else
	{
		vdDisplayErrorMsg(1, 8, "V7 Rec OK");
		CTOS_LCDTPrintXY(1, 8, "										     ");
	}

	//The CTS status of remote host/device for the specified port // 
	ret = CTOS_RS232GetCTS(bPort); 
	if (ret != d_OK) 
	{
		vdDisplayErrorMsg(1, 8, "PC Rec Err");
		return ret;
	} 
	else
	{
		vdDisplayErrorMsg(1, 8, "PC Rec OK");
		CTOS_LCDTPrintXY(1, 8, "										     ");
	}
*/
	return d_OK;
}

#define SEND_LEN	10

int inCTOSS_RS232SendBuf(char *szSnedBuf,int inlen)
{
	char str[50];
	BYTE key;
	int times,i;
	
	if (bPort < 0)
	{
		vdDisplayErrorMsg(1, 8, "COM Port Error");
		return d_NO;
	}
	
	// Check if COM1 is ready to send data
	//if (strTCT.byRS232DebugPort != 0){
	//	CTOS_LCDTPrintXY(1, 7, "sending...");
	//}
	CTOS_Delay(10);
	
	CTOS_RS232FlushRxBuffer(bPort);
	while (1)
	{
		CTOS_KBDBufFlush(); // sidumili: clear buffer of keyboard
		
		// Check if Cancel key is pressed // 
		CTOS_KBDHit(&key); 
		if(key == d_KBD_CANCEL) 
		{ 
			//vdDebug_LogPrintf("-->>inCTOSS_RS232SendBuf CANCEL.!!!");
			return d_NO; 
		}	
		if (CTOS_RS232TxReady(bPort) == d_OK)
			break;
	}
/*	
	if (inlen > SEND_LEN)
	{
		times = inlen/SEND_LEN;
		for (i = 0;i<times;i++)
		{
			CTOS_RS232TxData(bPort, &szSnedBuf[i*SEND_LEN], SEND_LEN);
			vdPCIDebug_HexPrintf("send",&szSnedBuf[i*SEND_LEN],SEND_LEN);
		}

		times = inlen%SEND_LEN;
		if(times>0)
		{
			CTOS_RS232TxData(bPort, &szSnedBuf[i*SEND_LEN], times);
			vdPCIDebug_HexPrintf("send",&szSnedBuf[i*SEND_LEN],times);
		}
		
	}
	else
*/
	{
		/*************************************************/
		//sidumili:
		//vdPrintPCIDebug_HexPrintf(TRUE, "PCi100 SEND", szSnedBuf, inlen);
		/*************************************************/
	
		// Send data via COM1 port 
		if(CTOS_RS232TxData(bPort, szSnedBuf, inlen) != d_OK) 
		{ 
			vdDisplayErrorMsg(1, 8, "COM Send Buf Error");
			//Flushing the RS232 receive buffer // 
			CTOS_RS232FlushRxBuffer(bPort); 
			return d_NO; 
		}
	}

	//if (strTCT.byRS232DebugPort != 0){
	//	memset(str,0x00,sizeof(str));
	//	sprintf(str,"send     [%d]       ",inlen);
	//	CTOS_LCDTPrintXY(1, 7, str);
	//}
	CTOS_Delay(10);
	
	return d_OK;
}

int inCTOSS_RS232RecvBuf(char *szRecvBuf,int *inlen,int timeout)
{
	USHORT ret = d_NO;
	BYTE key;
	USHORT len = 0;
	USHORT len1=0;
	char str[50];
	int status;
	VS_BOOL fRcvdOK = FALSE;

	memset(szRecvBuf, 0x00, sizeof(szRecvBuf));
	
	if (bPort < 0)
	{
		vdDisplayErrorMsg(1, 8, "COM Port Error");
		return d_NO;
	}
	
	CTOS_RS232FlushTxBuffer(bPort);
	CTOS_TimeOutSet (TIMER_ID_1 , timeout*100);

	//vdDebug_LogPrintf("-->>inCTOSS_RS232RecvBuf timeout[%d]", timeout);
	//vdDebug_LogPrintf("-->>inCTOSS_RS232RecvBuf timeout*100[%d]", timeout*100);
	
	while (1)
	{
		CTOS_KBDBufFlush(); // sidumili: clear buffer of keyboard
		
		if(CTOS_TimeOutCheck(TIMER_ID_1 )  == d_YES){
						//vdDebug_LogPrintf("-->>inCTOSS_RS232RecvBuf TIMEOUT.!!!");
            return d_NO;
		}
		
		// Check if Cancel key is pressed // 
		CTOS_KBDHit(&key); 
		if((key == d_KBD_CANCEL) || (key == d_USER_CANCEL))
		{ 
			CTOS_KBDBufFlush(); // sidumili: flash keyboard buffer to disable cancel key
			//break; 			// sidumili: [COMMENTED] flash keyboard buffer to disable cancel key
			//vdDebug_LogPrintf("-->>inCTOSS_RS232RecvBuf CANCEL.!!!");
		}
		
		//CTOS_LCDTPrintXY(1, 8, "receiving...");
		CTOS_Delay(10);
		
		// Check if data is available in COM1 port // 
		ret = CTOS_RS232RxReady(bPort, &len); 

		//vdDebug_LogPrintf("-->>CTOS_RS232RxReady ret[%d]--len[%d]", ret, len);
		
		//CTOS_Delay(1500);
		CTOS_Delay(100);
		
		if(ret == d_OK && len) 
		{ 
			// Get Data from COM1 port 
			CTOS_RS232RxData(bPort, szRecvBuf, &len);
			if (szRecvBuf[len-1] != 0x03)
			{
				//CTOS_Delay(1000);
				CTOS_Delay(500);
				CTOS_RS232RxData(bPort, &szRecvBuf[len], &len1);
				len = len+len1;
			}

			//if (strTCT.byRS232DebugPort != 0){
			//	memset(str,0x00,sizeof(str));
			//	sprintf(str,"receive     [%d]       ",len);
			//	CTOS_LCDTPrintXY(1, 8, str);
			//}
			CTOS_Delay(10);
			
			*inlen = len;

			fRcvdOK = TRUE;
			
			//return d_OK;
		} 

		//sidumili
		if (fRcvdOK)
			break;
		
	}

	/*************************************************/
	//sidumili:
	//vdPrintPCIDebug_HexPrintf(FALSE, "PCi100 RCVD", szRecvBuf, len);
	/*************************************************/
		
	//sidumili:
	if (fRcvdOK)
		return(d_OK);

	return d_NO;
}


int inCTOSS_RS232Close()
{
	USHORT ret;

	if (bPort < 0)
	{
		vdDisplayErrorMsg(1, 8, "COM Port Error");
		return d_NO;
	}
	
	ret = CTOS_RS232Close(bPort);

	//vdDebug_LogPrintf("-->>inCTOSS_RS232Close bPort[%d]--ret[%d]", bPort, ret);

	return ret;
}



int inCTOSS_USBHostOpen(void)
{
	//Enable USB Function // 
	if (CTOS_USBHostOpen(0x0CA6,0xA010) != d_OK)
	{ 
		vdDisplayErrorMsg(1, 8, "USB Open Fail");
		return d_NO;
	}
	else
	{
		vdDisplayErrorMsg(1, 8, "USB Open OK");

		CTOS_LCDTPrintXY(1, 8, "                                             ");
	}

	return d_OK;
}

int inCTOSS_USBHostSendBuf(char *szSnedBuf,int inlen)
{
	char str[300];
	char tmpbuf[50];
	BYTE key;
	int i=0,j=1;
	
	// Check if COM1 is ready to send data 
	//if (strTCT.byRS232DebugPort != 0){
	//	CTOS_LCDTPrintXY(1, 7, "sending...     ");
	//}

	// Send data via COM1 port 
	if (CTOS_USBHostTxData(szSnedBuf,inlen,6000) != d_OK)
	{ 
		vdDisplayErrorMsg(1, 8, "USB Send Buf Error");
		return d_NO; 
	}

	//memset(str,0x00,sizeof(str));
	//sprintf(str,"send     [%d]       ",inlen);
	//CTOS_LCDTPrintXY(1, 7, str);
	
	memset(str,0x00,sizeof(str));
	strcpy(str,"BUF ");
	for (i=0; i<inlen; i++)
	{
		memset(tmpbuf,0x00,sizeof(tmpbuf));
		sprintf(tmpbuf,"%02x ",szSnedBuf[i]);
		strcat(str,tmpbuf);

		if (i%6 == 0 && i != 0)
		{
			CTOS_LCDTPrintXY(1, 8+j, str);
			memset(str,0x00,sizeof(str));
			strcpy(str,"BUF ");
			j++;
		}
	}
	CTOS_LCDTPrintXY(1, 8+8, str);

	return d_OK;
}

int inCTOSS_USBHostRecvBuf(char *szRecvBuf,int *inlen)
{
	USHORT ret;
	ULONG len = 0;
	BYTE key;
	char str[30];

	CTOS_Delay(1500);
	
	while (1)
	{ 
		// Check if Cancel key is pressed // 
		CTOS_KBDHit(&key); 
		if(key == d_KBD_CANCEL) 
		{ 
			break; 
		} 
		// Check if data is available in USB port // 

		//if (strTCT.byRS232DebugPort != 0){
		//	CTOS_LCDTPrintXY(1, 6, "receiving...");
		//}

		{
			// Get Data from USB port 
			CTOS_USBHostRxData((unsigned char*)szRecvBuf,&len,6000);
			*inlen = len;

			//if (strTCT.byRS232DebugPort != 0){
			//	memset(str,0x00,sizeof(str));
			//	sprintf(str,"receive     [%ld]       ",len);
			//	CTOS_LCDTPrintXY(1, 6, str);
			//}

			return d_OK;
		} 
	}
	
	return d_NO;
	
}

int inCTOSS_USBHostClose(void)
{
	USHORT ret;
	
	//Disable USB Function // 
	ret = CTOS_USBHostClose();

	return ret;
}




