#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctosapi.h>
/** These two files are necessary for calling CTOS API **/
#include <ctosapi.h>
#include <stdarg.h>//kobe added

#include "debugPCI.h"

//---
#include "../FileModule/myFileFunc.h"
#include "..\Includes\Wub_lib.h"
#include "..\Includes\myEZLib.h"
//---


static BYTE ifDebugMode = FALSE;

#define d_READY_TIMEOUT		100
#define d_DEBUG_PORT d_COM1

static BYTE DebugLog[4096 + 2];
static LONG DebugLen;
static CTOS_RTC stRTC;
static INT iDebugTOTimes = 0;
static BYTE DebugPort = d_DEBUG_PORT;
static int byRS232DebugPort = 0;


unsigned int Input_strlen(unsigned char *str)
{
    unsigned int i;
    i = 0;
    while (str[i ++] != 0x00) ;
    return i - 1;
}

unsigned int Input_find_str_end_pt(unsigned char *str)
{
    unsigned int i;
    i = 0;
    while (str[i] != 0x00)
        i ++;
    return i;
}


void Input_strcat(unsigned char *dest, unsigned char *sour)
{
    unsigned int i, j;
    i = Input_find_str_end_pt(dest);
    j = 0;
    while (sour[j] != 0x00)
    {
        dest[i ++] = sour[j ++];
    }
    dest[i] = 0x00;
}

void Input_memcpy(unsigned char *dest, unsigned char *sour, unsigned int len)
{
    while (len--)
    {
        *dest++ = *sour++;
    }
}


/****************
 * if bPort == 0xFF --> USB mode
 ****************/
static void SetDebugMode(BYTE bMode, BYTE bPort)
{
	if (0 == byRS232DebugPort)
	{
		ifDebugMode = FALSE;
		return;
	}
	else
		ifDebugMode = TRUE;
}

static void DebugInit(void)
{
    
    if (!ifDebugMode) return;

    DebugLen = 0;

 //   if (DebugPort == 0xFF)
	if (8 == byRS232DebugPort)
	{
		DebugPort = 0xFF;
      CTOS_USBOpen();
	}
	
    if (1 == byRS232DebugPort)
    {
    	DebugPort= d_COM1;
      CTOS_RS232Open(DebugPort, 115200, 'N', 8, 1);
    }

	if (2 == byRS232DebugPort)
	{
		DebugPort= d_COM2;
      CTOS_RS232Open(DebugPort, 115200, 'N', 8, 1);
	}
	
}

static void DebugExport232(void)
{
	ULONG tick;
	USHORT ret;
	
	if (!ifDebugMode) return;
	
	tick = CTOS_TickGet();
	do {
        if (DebugPort == 0xFF)
          ret = CTOS_USBTxReady();
        else
          ret = CTOS_RS232TxReady(DebugPort);
		if (ret == d_OK)
			break;
		//CTOS_Delay(50);
	} while ((CTOS_TickGet() - tick) < d_READY_TIMEOUT);
	
	if (ret == d_OK) {
		DebugLog[DebugLen++] = 0x0D;
		DebugLog[DebugLen++] = 0x0A;
        if (DebugPort == 0xFF)
        {
			CTOS_USBTxFlush();			
			CTOS_USBTxData(DebugLog, DebugLen);
        }
        else
            CTOS_RS232TxData(DebugPort, DebugLog, DebugLen);
		tick = CTOS_TickGet();
		do {
          if (DebugPort == 0xFF)
          {
			CTOS_USBTxFlush();
			ret = CTOS_USBTxReady();
          }
          else
			ret = CTOS_RS232TxReady(DebugPort);
			if (ret == d_OK)
				break;
			//CTOS_Delay(50);
		} while ((CTOS_TickGet() - tick) < d_READY_TIMEOUT);
	}
	//CTOS_RS232Close(d_DEBUG_PORT);
    
    DebugLen = 0;
}

static void DebugAddSTR(BYTE *title, BYTE *baMsg, USHORT len)
{

   // if (0 == byRS232DebugPort)
    //    return;

	 if (0 ==strTCT.byRS232DebugPort)
        return;
    
	SetDebugMode(1, 0xFF);
	DebugInit();
	
	if (!ifDebugMode) return;
	
	if (baMsg == NULL) return;
	
	CTOS_RTCGet(&stRTC);
	
	memset(DebugLog, 0x00, sizeof(DebugLog));
	sprintf(DebugLog, "<%02d:%02d:%02d> ", stRTC.bHour, stRTC.bMinute, stRTC.bSecond);
	DebugLen = Input_strlen(DebugLog);
	
	DebugLog[DebugLen++] = '[';
	Input_strcat(&DebugLog[DebugLen], title);
	DebugLen += Input_strlen(title);
	DebugLog[DebugLen++] = ']';
	DebugLog[DebugLen++] = ' ';
	
	Input_memcpy(&DebugLog[DebugLen], baMsg, strlen(baMsg));
	DebugLen += strlen(baMsg);
	
	DebugExport232();
}


void vdPCIDebug_LogPrintf(const char* fmt, ...)
{
    char printBuf[2048];
	char msg[2048];
	char space[100];
	int inSendLen;
	va_list marker;
	int j = 0;
    char szAPName[25];
	int inAPPID;

    if (0 == byRS232DebugPort)
        return;
    
    memset(msg, 0x00, sizeof(msg));
	memset(printBuf, 0x00, sizeof(printBuf));
	memset(space, 0x00, sizeof(space));
	
	va_start( marker, fmt );
	vsprintf( msg, fmt, marker );
	va_end( marker );
	
	memset(printBuf, 0x00, sizeof(printBuf));		
	strcat(printBuf, msg);
	strcat(printBuf, space);
	strcat(printBuf ,"\n" );
	
	inSendLen = strlen(printBuf);


	strcpy(szAPName,"PCI100");


    DebugAddSTR(szAPName,printBuf,inSendLen);
}

void vdPCIDebug_HexPrintf(char *display,char *szHexbuf, int len)
{
	char szbuf[1000];
	memset(szbuf,0x00,sizeof(szbuf));

	//sidumili: added
	if (0 ==strTCT.byRS232DebugPort)
					return;

	PCI100_HEX_2_DSP(szHexbuf,szbuf,len);
	vdPCIDebug_LogPrintf("[%s]=[%s]",display,szbuf);
}

void vdPrintPCIDebug_HexPrintf(BOOL fSend,char *display,char *szHexbuf, int len)
{
	char szbuf[2048];
	char szDebug[500]={0};

	//----
	char printBuf[2048];
	char msg[2048];
	char space[100];
	int inSendLen;
	va_list marker;
	int j = 0;
    char szAPName[25];
	int inAPPID;
	//----
	
	memset(szbuf,0x00,sizeof(szbuf));
	
	PCI100_HEX_2_DSP(szHexbuf,szbuf,len);
	
	memset(szDebug, 0x00, sizeof(szDebug));
	inSendLen = strlen(szbuf);
	if (fSend){
		sprintf(szDebug, "PCi100 SEND - Len[%d]", inSendLen);
		inPrintDebug(szDebug);
		inPrintISOPacket("TX", szbuf, inSendLen);
	}
	else{
		sprintf(szDebug, "PCi100 RCVD - Len[%d]", inSendLen);
		inPrintDebug(szDebug);
		inPrintISOPacket("RX", szbuf, inSendLen);
	}
		
}

