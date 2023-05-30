#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctosapi.h>
/** These two files are necessary for calling CTOS API **/
#include <ctosapi.h>
#include <stdarg.h>//kobe added

#include "sqlite3.h"

#include "DebugNMX.h"


static sqlite3 * db;
static sqlite3_stmt *stmt;
static int inStmtSeq;

#define DB_TERMINAL "/home/ap/pub/TERMINAL.S3DB"


static BYTE ifDebugMode = FALSE;

#define d_READY_TIMEOUT		100
#define d_DEBUG_PORT d_COM1

static BYTE DebugLog[4096 + 2];
static LONG DebugLen;
static CTOS_RTC stRTC;
static INT iDebugTOTimes = 0;
static BYTE DebugPort = d_DEBUG_PORT;
static int byRS232DebugPort = 0;//0 not debug, 8= USB debug, 1 =COM1 debug, 2=COM2 debug

int inNMX_TCTRead(int inSeekCnt)
{
	int result;
	int len = 0;
	int inResult = -1;
 	char *sql = "SELECT byRS232DebugPort FROM TCT WHERE TCTid = ?";

	/* open the database */
	result = sqlite3_open(DB_TERMINAL,&db);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 1;
	}
	
	sqlite3_exec( db, "begin", 0, 0, NULL );
	/* prepare the sql, leave stmt ready for loop */
	result = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (result != SQLITE_OK) {
		sqlite3_close(db);
		return 2;
	}

	sqlite3_bind_int(stmt, 1, inSeekCnt);

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	do {
		result = sqlite3_step(stmt);
		if (result == SQLITE_ROW) { /* can read data */
			inResult = d_OK;
			inStmtSeq = 0;
           
            /*byRS232DebugPort*/
			byRS232DebugPort = sqlite3_column_int(stmt,inStmtSeq );

		}
	} while (result == SQLITE_ROW);	

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);
	//�ر�sqlite����
	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inResult);
}

unsigned char cNMX_toupper(unsigned char dat)
{
	//a - z = 0x61 - 0x7A
	//A - Z = 0x41 - 0x5A

	if (dat >= 0x61 && dat <= 0x7A)
		dat -= 0x20;

	return dat;
}

unsigned char cNMX_pack_byte(unsigned char h, unsigned char l)
{
    unsigned char i, j, k;
    short z;

    j = cNMX_toupper(h);
    k = cNMX_toupper(l);

    if ((j >= '0' && j <= '9') || (j >= 'A' && j <= 'Z'))
    	;
    else
    	j = '0';

    if ((k >= '0' && k <= '9') || (k >= 'A' && k <= 'Z'))
    	;
    else
    	k = '0';

    if ((j >= 'A') && (j <= 'F'))
    {
    	z = 10;
    	z += (short) j;
    	z -= 65;
    	i = (unsigned char) (0xFF & z);
    }
    else
    	i = j - '0';

    i <<= 4;

    if ((k >= 'A') && (k <= 'F'))
    {
    	z = 10;
    	z += (short) k;
    	z -= 65;
    	i |= (unsigned char) (0xFF & z);
    }
    else
    	i |= (k - '0');

    return i;
}

unsigned int inNMX_str_2_hex(unsigned char *str, unsigned char *hex, unsigned int len)
{
    unsigned int i;
    for (i = 0; i < len / 2; i ++)
    {
        hex[i] = cNMX_pack_byte(str[i * 2], str[i * 2 + 1]);
    }
    return len / 2;
}


unsigned int inNMX_strlen(unsigned char *str)
{
    unsigned int i;
    i = 0;
    while (str[i ++] != 0x00) ;
    return i - 1;
}

unsigned int inNMX_find_str_end_pt(unsigned char *str)
{
    unsigned int i;
    i = 0;
    while (str[i] != 0x00)
        i ++;
    return i;
}


void inNMX_strcat(unsigned char *dest, unsigned char *sour)
{
    unsigned int i, j;
    i = inNMX_find_str_end_pt(dest);
    j = 0;
    while (sour[j] != 0x00)
    {
        dest[i ++] = sour[j ++];
    }
    dest[i] = 0x00;
}

void inNMX_memcpy(unsigned char *dest, unsigned char *sour, unsigned int len)
{
    while (len--)
    {
        *dest++ = *sour++;
    }
}

unsigned char inNMX_hex_2_ascii(unsigned char hex)
{
    if (hex <= 9)
        return hex + '0';
    else
        return hex - 10 + 'A';
}


void inNMX_str_append_byte_hex(unsigned char *str, unsigned char dat)
{
    unsigned int i;
    i = inNMX_find_str_end_pt(str);
    str[i ++] = inNMX_hex_2_ascii(dat / 16);
    str[i ++] = inNMX_hex_2_ascii(dat % 16);
    str[i] = 0x00;
}

unsigned int inNMX_hex_2_str(unsigned char *hex, unsigned char *str, unsigned int len)
{
    unsigned int i;
    str[0] = 0;
    for (i = 0; i < len; i ++)
        inNMX_str_append_byte_hex(str, hex[i]);
    return len * 2;
}


/****************
 * if bPort == 0xFF --> USB mode
 ****************/
static void vdNMX_SetDebugMode(BYTE bMode, BYTE bPort)
{
	if (0 == byRS232DebugPort)
	{
		ifDebugMode = FALSE;
		return;
	}
	else
		ifDebugMode = TRUE;
}

static void vdNMX_DebugInit(void)
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

static void vdNMX_DebugExport232(void)
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

static void vdNMX_DebugAddSTR(BYTE *title, BYTE *baMsg, USHORT len)
{

    if (0 == byRS232DebugPort)
        return;
    
	vdNMX_SetDebugMode(1, 0xFF);
	vdNMX_DebugInit();
	
	if (!ifDebugMode) return;
	
	if (baMsg == NULL) return;
	
	CTOS_RTCGet(&stRTC);
	
	memset(DebugLog, 0x00, sizeof(DebugLog));
	sprintf(DebugLog, "<%02d:%02d:%02d> ", stRTC.bHour, stRTC.bMinute, stRTC.bSecond);
	DebugLen = inNMX_strlen(DebugLog);
	
	DebugLog[DebugLen++] = '[';
	inNMX_strcat(&DebugLog[DebugLen], title);
	DebugLen += inNMX_strlen(title);
	DebugLog[DebugLen++] = ']';
	DebugLog[DebugLen++] = ' ';
	
	inNMX_memcpy(&DebugLog[DebugLen], baMsg, strlen(baMsg));
	DebugLen += strlen(baMsg);
	
	vdNMX_DebugExport232();
}

void vdNMX_DebugAddHEX(BYTE *title, BYTE *hex, USHORT len)
{
    if (0 == byRS232DebugPort)
        return;
    
	vdNMX_SetDebugMode(1, 0xFF);
	vdNMX_DebugInit();
	
	if (!ifDebugMode) return;

    if(len > 1024)
        len = 1024;

	if (len > (sizeof (DebugLog) / 2) - 8)
		len = (sizeof (DebugLog) / 2) - 8;
	
	CTOS_RTCGet(&stRTC);
	
	memset(DebugLog, 0x00, sizeof(DebugLog));
	sprintf(DebugLog, "<%02d:%02d:%02d> ", stRTC.bHour, stRTC.bMinute, stRTC.bSecond);
	DebugLen = inNMX_strlen(DebugLog);
	DebugLog[DebugLen++] = '[';
	DebugLog[DebugLen] = 0x00;
	inNMX_strcat(&DebugLog[DebugLen], title);
	DebugLen += inNMX_strlen(title);
	DebugLog[DebugLen++] = ']';
	DebugLog[DebugLen++] = ' ';
	DebugLen += inNMX_hex_2_str(hex, &DebugLog[DebugLen], len);
	
	vdNMX_DebugExport232();
}


/*
void vdNMX_Debug_LogPrintf(const char* fmt, ...)
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


	strcpy(szAPName,"NMX");


    vdNMX_DebugAddSTR(szAPName,printBuf,inSendLen);
}
*/


