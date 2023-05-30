/** 
**  A Template for developing new terminal shared application
**/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctosapi.h>

/** These two files are necessary for calling CTOS API **/
#include "../Includes/myEZLib.h"
#include "../Includes/POSTypedef.h"

#include "../FileModule/myFileFunc.h"
#include "..\Includes\Wub_lib.h"
#include "..\Includes\myEZLib.h"

#include "../DataBase/DataBaseFunc.h"
#include "../Debug/Debug.h"

#define SHOW_SCRREN 1
#define d_LINE_DOT 12

BOOL fLogByUSB;
BOOL fLogByRS232;
BOOL fZMKByRS232;
BOOL ONUSB = FALSE; 

#define d_LCD_Width 16+1
static CTOS_FONT_ATTRIB stgFONT_ATTRIB;





void vdMyEZLib_ComPortInit()
{
    int inResult;
    USHORT usVendorID=0x0CA6, usProductID=0xA050, usRtn;
    
    fLogByUSB   = FALSE;
    fLogByRS232 = FALSE; 
    
    CTOS_RS232Close(DBG_PORT);
    if(ONUSB==TRUE)
    {
    
        CTOS_USBHostOpen(usVendorID, usProductID); 
        fLogByUSB = TRUE;   
    }
    else
    {            
        if((inResult=CTOS_RS232Open(DBG_PORT, 115200, 'N', 8, 1)) == d_OK)
        {
            fLogByRS232 = TRUE;    
        }        
    }
}



void vdMyEZLib_Printf(const char* fmt, ...)
{
    char printBuf[2048];
    char msg[2048];
    int inSendLen;
    va_list marker;
    BYTE baTemp[PAPER_X_SIZE * 64];   
    CTOS_FONT_ATTRIB stFONT_ATTRIB;

    memset(msg, 0x00, sizeof(msg));
    
    va_start( marker, fmt );
    vsprintf( msg, fmt, marker );
    va_end( marker );
    
    memset(printBuf, 0x00, sizeof(printBuf));
    strcat(printBuf, msg);
    strcat(printBuf ,"\n" );
    
    inSendLen = strlen(printBuf);
    
    memset (baTemp, 0x00, sizeof(baTemp));      
    stgFONT_ATTRIB.FontSize = d_FONT_16x16;      // Font Size = 12x24
    stgFONT_ATTRIB.X_Zoom = 1;       // The width magnifies X_Zoom diameters
    stgFONT_ATTRIB.Y_Zoom = 2;       // The height magnifies Y_Zoom diameters
    stgFONT_ATTRIB.X_Space = 0;      // The width of the space between the font with next font
    stgFONT_ATTRIB.Y_Space = 0;      // The Height of the space between the font with next font        
    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, printBuf, &stFONT_ATTRIB);
    //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3); 
    inCCTOS_PrinterBufferOutput(printBuf,&stgFONT_ATTRIB,1);
}






/*==========================================================================*
 *Name:vdMyEZLib_LogPrintf                                                  *                           
 *input: as Like vdMyEZLib_LogPrintf("%s", test);                           *           
 *output: void                                                              *
 *Description:                                                              *
 *  Caller can ouput that any data type wanted to check to console by RS232 *
 *==========================================================================*/
void vdMyEZLib_LogPrintff(unsigned char *fmt, short inlen)
{

    char printBuf[2048];
    char msg[2048];
    short i=0;
    
        
    memset(msg, 0x00, sizeof(msg));
    memset(printBuf, 0x00, sizeof(printBuf));
    memset(printBuf, 0x30, inlen*2);
    for ( i=0 ;i<inlen; i++)
    {
        sprintf(&printBuf[i*2], "%02X", fmt[i]);
    }

    vdMyEZLib_LogPrintf(printBuf);
      
}


void vdMyEZLib_Rpad(char *pad, char *space)
{
    short inlen;
    
    for(inlen=0; inlen<(79-strlen(pad)); inlen ++)
        space[inlen]=0x20;
}


void vdMyEZLib_LogPrintf(const char* fmt, ...)
{
    char printBuf[2048];
    char msg[2048];
    char space[100];
    int inSendLen;
    va_list marker;
    int j = 0;
               
    if(fLogByUSB == FALSE && fLogByRS232 == FALSE)
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

    
    j = (int)strTCT.byRS232DebugPort;        
    if(j == 1 ) //Remark this line to view log
    {
           
        if(fLogByUSB==TRUE)
        {       
            if (CTOS_USBTxReady() == d_OK)
                CTOS_USBTxData(printBuf, inSendLen);
        }
        else
        {        
            while(CTOS_RS232TxReady(DBG_PORT) != d_OK);
            CTOS_RS232TxData(DBG_PORT, printBuf, inSendLen);    
         
        }
    }
    return;        
}

int inAscii2Bcd(BYTE *szAscii, BYTE *szBcd, int inBcdLen)
{
    int inAsciiLen = inBcdLen*2;
    int inBcdIdx;
    int inAsciiIdx;
    BYTE szAscii2[inBcdLen*2+1];
    BYTE byLo;
    BYTE byHi;
        
    memset(szAscii2, 0x00, sizeof(szAscii2));
    /*pad zero for ascii buffer*/
    if((inAsciiLen = strlen(szAscii)) <= (inBcdLen*2))
    {
        memset(szAscii2, 0x30, inBcdLen*2);
        memcpy(&szAscii2[(inBcdLen*2)-inAsciiLen], szAscii, inAsciiLen);        
        vdMyEZLib_LogPrintf("[inAscii2Bcd]---szAscii2[%s], szAscii[%s]", szAscii2, szAscii);
    }
    else
    {       
        memcpy(szAscii2, szAscii, inBcdLen*2);
    }   
        
    
    inAsciiIdx=0;
    inBcdIdx=0;
    while(inBcdIdx < inBcdLen)
    {
        //for Hi Bit
        if(szAscii2[inAsciiIdx] >= 'A' && szAscii2[inAsciiIdx] <= 'F')
            byHi = (szAscii2[inAsciiIdx]-0x37) << 4; // 0x61 - 0x37 = 0x0A  
        else if(szAscii2[inAsciiIdx] >= 'a' && szAscii2[inAsciiIdx] <= 'f')
            byHi = (szAscii2[inAsciiIdx]-0x57) << 4;        
        else
            byHi = szAscii2[inAsciiIdx] << 4;   
        
        
        //for Low Bit
        if(szAscii2[inAsciiIdx+1] >= 'A' && szAscii2[inAsciiIdx+1] <= 'F')
            byLo = (szAscii2[inAsciiIdx+1]-0x37) & 0x0F; // 0x61('A') - 0x37 = 0x0A 
        else if(szAscii2[inAsciiIdx+1] >= 'a' && szAscii2[inAsciiIdx+1] <= 'f')
            byLo = (szAscii2[inAsciiIdx+1]-0x57) & 0x0F;        
        else
            byLo = szAscii2[inAsciiIdx+1] & 0x0F;   
                
        
        //byLo = szAscii2[inAsciiIdx+1] & 0x0F;
                                        
        szBcd[inBcdIdx] = byHi | byLo;
               
        
        inBcdIdx++;
        inAsciiIdx = inBcdIdx *2;
                
    }
    
    
    return TRUE;        
    
}


int inBcd2Ascii(BYTE *szBcd, BYTE *szAscii, int inBcdLen)
{
    int inBcdIdx;
    int inAsciiIdx;
    BYTE szAscii2[3];
    BYTE byLo;
    BYTE byHi;
    
    inBcdIdx = 0;
    inAsciiIdx = 0;
    while(inBcdIdx < inBcdLen)
    {
        sprintf(szAscii2, "%02x", szBcd[inBcdIdx]);
        memcpy(&szAscii[inAsciiIdx], szAscii2, 2);
        inBcdIdx ++;
        inAsciiIdx = inBcdIdx*2;        
    }

    return TRUE;    
    
}

int inBcd2Bin(BYTE *szBcd, int inBcdLen)
{
    char szAscii[inBcdLen*2+1];
    int inBin;
    
    memset(szAscii, 0x00, sizeof(szAscii));

    if(inBcd2Ascii(szBcd, szAscii, inBcdLen))
    {
        inBin = atoi(szAscii);
        return inBin;
    }                        
    
    return ST_ERROR;
}

int inBin2Bcd(int inBin, BYTE *szBcd, int inBcdLen)
{
    char szAscii[inBcdLen*2+1];
    memset(szAscii, 0x00, sizeof(szAscii));

    sprintf(szAscii, "%d", inBin);
    vdMyEZLib_LogPrintf("[inBin2Bcd]---Bin2Ascii[%s]",szAscii);
    
    
    return(inAscii2Bcd(szAscii, szBcd, inBcdLen));
}

int inBcdAddOne(BYTE *szInBcd, BYTE *szOutBcd, int inBcdLen)
{
    int inBin;
    int inResult;
    char szAscii[inBcdLen*2+1];
    
    
    memset(szAscii, 0x00, sizeof(szAscii));
        
    /*BCD to Bin*/
    inBin = inBcd2Bin(szInBcd, inBcdLen);
    vdMyEZLib_LogPrintf("[inBcdAddOne]---BCD 2 Bin[%d]", inBin);
    
    /*Bin++*/
    inBin++;
    
    /*Bin to BCD*/
    inResult = inBin2Bcd(inBin, szOutBcd, inBcdLen);
        
    return inResult;
    
}

   
//gcitra
void vdFormatAmount(char *str, char *strCur, char *strAmt, BOOL fVoid)
{
	int inAmtLen = 0,
		inCtr = 0,
		inTmpLen = 0,
		i = 0;
	char szTmpBuf[101] = {0},
		szTmpAmt[101] = {0},
		szDec[3] = {0};

	memset(szTmpBuf, 0, sizeof(szTmpBuf));
	inAmtLen = strlen(strAmt) -2;

	memcpy(szDec, &strAmt[inAmtLen], 2);
	memcpy(szTmpAmt, strAmt, inAmtLen);

	for (i = strlen(szTmpAmt)-1; i >= 0; i--)
	{
		if (inCtr >= 3)
		{
			szTmpBuf[inTmpLen] = ',';
			++i;
			inCtr = 0;
		}
		else
		{
			szTmpBuf[inTmpLen] = szTmpAmt[i];
			inCtr++;
		}
		inTmpLen++;
	}
	inTmpLen--;

	memset(szTmpAmt, 0, sizeof(szTmpAmt));
	for (i = 0; i <= inTmpLen; i++)
		szTmpAmt[i] = szTmpBuf[inTmpLen - i];

	if (strlen(strCur) > 0)
	{
		strCur[3] = 0x00;
		
		if (fVoid == TRUE)
			sprintf(str, "-%s %s.%s", strCur, szTmpAmt, szDec);
		else
			sprintf(str, "%s %s.%s", strCur, szTmpAmt, szDec);
	}
	else
	{
		if (fVoid == TRUE)
			sprintf(str, "-%s.%s", szTmpAmt, szDec);
		else
			sprintf(str, "%s.%s", szTmpAmt, szDec);
	}

}
//gcitra

#if 1
/*albert - start - Aug2014 - compute crc*/
void vdComputeCRC(unsigned long lnCRC, char *ptrCRC)
{
    unsigned char szCRC[8+1];

    memset(szCRC, 0, sizeof(szCRC));
    sprintf(szCRC, "%08ld",lnCRC);
    sprintf(ptrCRC,"%02x%02x%02x%02x",(unsigned char)((szCRC[0])*(szCRC[4])),
				      (unsigned char)((szCRC[1])*(szCRC[5])),
				      (unsigned char)((szCRC[2])*(szCRC[6])),
				      (unsigned char)((szCRC[3])*(szCRC[7])));

}
/*albert - end - Aug2014 - compute crc*/
#endif

/*Delete ECR Log File -- sidumili*/
void vdDeleteISOECRLog()
{
	int inResult = d_NO;

	CTOS_LCDTClearDisplay();
	if((inResult = CTOS_FileDelete("ECRISO.LOG")) != d_OK)
  {
		vdDisplayErrorMsg(1, 6, "ECR LOG not found!");
  }  
	else
	{
		vdDisplayErrorMsg(1, 6, "ECR LOG deleted!");
	}
	CTOS_Delay(1000);
}

int inSaveISOLog(BOOL fSendPacket, unsigned char *pucMessage, int inLen)
{
	char ucLineBuffer[80] = {0};
	unsigned char *pucBuff;
	int inBuffPtr = 0;
	FILE *ISOFile;
	char szBuf[100] = {0};
	int inRecCnt = 0;
	int inResult = 0;
	CTOS_RTC SetRTC;
	BYTE szCurrentTime[20] = {0};

	inTCTRead(1);
	if((inLen > 0) && (strTCT.fISOLogging == TRUE))
	{
		if((ISOFile = fopen(ISOLOG_FILE, "r+t")) == NULL)
		{
			ISOFile = fopen(ISOLOG_FILE, "w+t");
		}
		else
		{
			fseek(ISOFile, 0, SEEK_SET);
			memset(szBuf, 0, sizeof(szBuf));
			fgets(szBuf, 80, ISOFile);
			inRecCnt = atoi(szBuf);
			vdDebug_LogPrintf("Log Rec Count: [%d]\n", inRecCnt);
			fclose(ISOFile);

			if((inRecCnt >= strTCT.inTxnLogLimit) && (fSendPacket == TRUE))
			{
				if((inResult = CTOS_FileDelete("ISO.LOG")) != d_OK)
				{
					vdDisplayErrorMsg(1, 6, "Error deleting ISOLOG!");
				}  
				ISOFile = fopen(ISOLOG_FILE, "w+t");
				inRecCnt = 0;
			}
			else
				ISOFile = fopen(ISOLOG_FILE, "r+t");
		}
		
		fseek(ISOFile, 0, SEEK_SET);
		if(fSendPacket == TRUE)
			++inRecCnt;
		fprintf(ISOFile, "%d\n", inRecCnt);
		fclose(ISOFile);


		ISOFile = fopen(ISOLOG_FILE, "a+t");

	  memset(szCurrentTime, 0x00, sizeof(szCurrentTime));
	  CTOS_RTCGet(&SetRTC);
		sprintf(szCurrentTime, "%02d/%02d/%02d %02d:%02d\n", SetRTC.bMonth, SetRTC.bDay, SetRTC.bYear, SetRTC.bHour, SetRTC.bMinute);

		memset(szBuf, 0, sizeof(szBuf));
		switch(srTransRec.byPackType)
		{
			case SALE:
				strcpy(szBuf, "TXN: SALE");
				break;
			case PRE_AUTH:
				strcpy(szBuf, "TXN: PRE_AUTH");
				break;
			case PRE_COMP:
				strcpy(szBuf, "TXN: PRE_COMP");
				break;
			case TC_UPLOAD:
				strcpy(szBuf, "TXN: TC_UPLOAD");
				break;
			case SEND_ADVICE:
				strcpy(szBuf, "TXN: SEND_ADVICE");
				break;
			case REVERSAL:
				strcpy(szBuf, "TXN: REVERSAL");
				break;
			case REFUND:
				strcpy(szBuf, "TXN: REFUND");
				break;				
			case VOID:
				strcpy(szBuf, "TXN: VOID");
				break;
			case SALE_TIP:
				strcpy(szBuf, "TXN: SALE_TIP");
				break;
			case SALE_OFFLINE:
				strcpy(szBuf, "TXN: SALE_OFFLINE");
				break;
			case SETTLE:
				strcpy(szBuf, "TXN: SETTLE");
				break;
			case CLS_BATCH:
				strcpy(szBuf, "TXN: CLS_BATCH");
				break;
			case BATCH_UPLOAD:
				strcpy(szBuf, "TXN: BATCH_UPLOAD");
				break;
			case SALE_ADJUST:
				strcpy(szBuf, "TXN: SALE_ADJUST");
				break;
			case SIGN_ON:
				strcpy(szBuf, "TXN: SIGN_ON");
				break;
			case EPP_SALE:
				strcpy(szBuf, "TXN: EPP_SALE");
				break;
			case VOID_REFUND:
				strcpy(szBuf, "TXN: VOID_REFUND");
				break;
			case VOID_REVERSAL:
				strcpy(szBuf, "TXN: VOID_REVERSAL");
				break;
			case REFUND_REVERSAL:
				strcpy(szBuf, "TXN: REFUND_REVERSAL");
				break;				
			case PREAUTH_REVERSAL:
				strcpy(szBuf, "TXN: PREAUTH_REVERSAL");
				break;
			case VOIDREFUND_REVERSAL:
				strcpy(szBuf, "TXN: VOIDREFUND_REVERSAL");
				break;
			case BIN_VER:
				strcpy(szBuf, "TXN: BIN_VER");
				break;
			case CASH_ADVANCE:
				strcpy(szBuf, "TXN: CASH_ADVANCE");
				break;
			case BALANCE_INQUIRY:
				strcpy(szBuf, "TXN: BALANCE_INQUIRY");
				break;
      case LOG_ON:
        strcpy(szBuf, "TXN: LOG_ON");
        break;
      case RELOAD:
        strcpy(szBuf, "TXN: RELOAD");
        break;
			case FLEET_SALE:
				strcpy(szBuf, "TXN: FLEET_SALE");
				break;
			case SMAC_ACTIVATION:
				strcpy(szBuf, "TXN: SMAC_ACTIVATION");
				break;
			case SMAC_AWARD:
				strcpy(szBuf, "TXN: SMAC_AWARD");
				break;
      case SMAC_REDEEM:
        strcpy(szBuf, "TXN: SMAC_REDEEM");
        break;
      case SMAC_BALANCE:
        strcpy(szBuf, "TXN: SMAC_BALANCE");
        break;
      case BIN_ROUTING:
         strcpy(szBuf, "TXN: BIN_ROUTING");
         break;
      case DCC_CHECKSTATUS:
         strcpy(szBuf, "TXN: DCC_CHECKSTATUS");
         break;
      case DCC_RATEREQUEST:
         strcpy(szBuf, "TXN: DCC_RATEREQUEST");
         break;
      case DCC_LOGGING:
         strcpy(szBuf, "TXN: DCC_LOGGING");
         break;
      case DCC_RATEREQUEST_RETRY:
         strcpy(szBuf, "TXN: DCC_RATEREQUEST_RETRY");
         break;
	  case DCC_LOGGING_RETRY:
         strcpy(szBuf, "TXN: DCC_LOGGING_RETRY");
         break;
	  case QUASI_REVERSAL:
         strcpy(szBuf, "TXN: QUASI_REVERSAL");
         break;
	  case CASHADVANCE_REVERSAL:
	  	 strcpy(szBuf, "TXN: CASHADVANCE_REVERSAL");
         break;
		}

		if (fSendPacket)
		{
			fputs("Send ISO Packet:\n", ISOFile);
			strcat(szBuf, " REQ\n");
		}
		else
		{
			fputs("Receive ISO Packet:\n", ISOFile);
			strcat(szBuf, " RESP\n");
		}

		fputs(szCurrentTime, ISOFile);
		fputs(szBuf, ISOFile);
		fputs("-------------------------------------\n", ISOFile);

		//CTOS_PrinterFline(d_LINE_DOT); 

		pucBuff = pucMessage + inLen;
		while (pucBuff > pucMessage)
		{
			memset(ucLineBuffer,0x00, sizeof(ucLineBuffer));
			for (inBuffPtr = 0; (inBuffPtr < 32) && (pucBuff > pucMessage); inBuffPtr += 3)
			{
				sprintf(&ucLineBuffer[inBuffPtr], "%02X ", *pucMessage);
				pucMessage++;
			}
			ucLineBuffer[32] = '\n';
			fputs(ucLineBuffer, ISOFile);
		} 
		fputs("\n\n", ISOFile);

		fclose(ISOFile);
	}
}

void vdDeleteISOLog()
{
	int inResult = d_NO;

	CTOS_LCDTClearDisplay();

  CTOS_FileDelete("ISO.LOG");
	CTOS_FileDelete("0ISO.LOG");
	CTOS_FileDelete("1ISO.LOG");
	CTOS_FileDelete("2ISO.LOG");
	CTOS_FileDelete("3ISO.LOG");
	CTOS_FileDelete("4ISO.LOG");
	CTOS_FileDelete("5ISO.LOG");
	CTOS_FileDelete("6ISO.LOG");
	CTOS_FileDelete("7ISO.LOG");

	#if 0
	if((inResult = CTOS_FileDelete("ISO.LOG")) != d_OK)
  {
		vdDisplayErrorMsg(1, 6, "ISOLOG not found!");
  }  
	else
	{
		vdDisplayErrorMsg(1, 6, "ISOLOG deleted!");
	}
	CTOS_Delay(1000);
	#endif
	
	return;
}

void vdRenameISOLog()
{
	int inResult = d_NO;
	int inCount;
	char szCountFileName[8];
	FILE *ISOFile;

	CTOS_LCDTClearDisplay();

  if((ISOFile = fopen(ISOLOG_FILE, "r+t")) != NULL)
  {
  	for (inCount = 1; inCount <= 7; ++inCount)
  		{

			   char szFileName[]="ISO.LOG", szFileDir[]="/home/ap/pub/";
				 
         sprintf(szCountFileName, "%d", inCount);
  			 strcat(szCountFileName, szFileName);

				  vdDebug_LogPrintf("AAA - vdRenameISOLog szCountFileName[%s]", szCountFileName);

          vdDebug_LogPrintf("AAA - 0 szFileDir[%s]", szFileDir);
          strcat(szFileDir, szCountFileName);
          vdDebug_LogPrintf("AAA -1 szFileDir[%s]", szFileDir);

				  //if((ISOFile = fopen(szFileDir, "r")) == NULL)
				    if(access(szFileDir, 0)!=0)
				  	{
				  	    vdDebug_LogPrintf("AAA - FILE DOES NOT EXIST");

				  	    inResult = rename("/home/ap/pub/ISO.LOG", szFileDir);

								vdDebug_LogPrintf("AAA - %d", inResult);
								
                if(inResult != d_OK)
                {
                    vdDebug_LogPrintf("AAA - ISO.LOG RENAMED FAILED!");
										break;
                }
								else
									{
                   vdDebug_LogPrintf("AAA - ISO.LOG RENAMED OK!");
										break;
									}
								//break;
				  	}


					if (inCount == 7)
          {
             CTOS_FileDelete("1ISO.LOG");
						 CTOS_FileRename("2ISO.LOG", "1ISO.LOG");
						 CTOS_FileRename("3ISO.LOG", "2ISO.LOG");
						 CTOS_FileRename("4ISO.LOG", "3ISO.LOG");
						 CTOS_FileRename("5ISO.LOG", "4ISO.LOG");
						 CTOS_FileRename("6ISO.LOG", "5ISO.LOG");
						 CTOS_FileRename("7ISO.LOG", "6ISO.LOG");
						 break;
          }

				 vdDebug_LogPrintf("AAA - szCountFileName[%s] inCount[%d]", szCountFileName, inCount);
        
  		}
  }
	else
		vdDebug_LogPrintf("AAA - CANNOT READ ISO.LOG!");
	return;
}

void vdMyEZLib_Printf2(const char* fmt, ...)
{
    char printBuf[2048];
    char msg[2048];
    int inSendLen;
    va_list marker;
    BYTE baTemp[PAPER_X_SIZE * 64];   
    CTOS_FONT_ATTRIB stFONT_ATTRIB;

    memset(msg, 0x00, sizeof(msg));
    
    va_start( marker, fmt );
    vsprintf( msg, fmt, marker );
    va_end( marker );
    
    memset(printBuf, 0x00, sizeof(printBuf));
    strcpy(printBuf, msg);
    strcat(printBuf ,"\n" );
    
    inSendLen = strlen(printBuf);
    
    memset (baTemp, 0x00, sizeof(baTemp));      
    stFONT_ATTRIB.FontSize = d_FONT_16x16;      // Font Size = 12x24
    stFONT_ATTRIB.X_Zoom = 1;       // The width magnifies X_Zoom diameters
    stFONT_ATTRIB.Y_Zoom = 2;       // The height magnifies Y_Zoom diameters
    stFONT_ATTRIB.X_Space = 0;      // The width of the space between the font with next font
    stFONT_ATTRIB.Y_Space = 0;      // The Height of the space between the font with next font        
    CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, printBuf, &stFONT_ATTRIB);
    CTOS_PrinterBufferOutput((BYTE *)baTemp, 4); 
    //inCCTOS_PrinterBufferOutput(printBuf,&stFONT_ATTRIB,1);
}

void vdMyEZLib_Printf3(BOOL inLabelFlag, unsigned char *DELabel, const char* fmt, ...)
{
    char printBuf[2048];
    char msg[2048];
    int inSendLen;
    va_list marker;
    BYTE baTemp[PAPER_X_SIZE * 64];   
    CTOS_FONT_ATTRIB stFONT_ATTRIB;

    memset(msg, 0x00, sizeof(msg));
    
    va_start( marker, fmt );
    vsprintf( msg, fmt, marker );
    va_end( marker );
    
    memset(printBuf, 0x00, sizeof(printBuf));
    //strcpy(printBuf, msg);
    if(inLabelFlag)
		strcpy(printBuf, DELabel);
	else
		strcpy(printBuf, "   ");

	strcat(printBuf, msg);
	//strcat(printBuf ,"\n" );

    inSendLen = strlen(printBuf);
/*    
    memset (baTemp, 0x00, sizeof(baTemp));      
    stFONT_ATTRIB.FontSize = d_FONT_16x16;      // Font Size = 12x24
    stFONT_ATTRIB.X_Zoom = 1;       // The width magnifies X_Zoom diameters
    stFONT_ATTRIB.Y_Zoom = 2;       // The height magnifies Y_Zoom diameters
    stFONT_ATTRIB.X_Space = 0;      // The width of the space between the font with next font
    stFONT_ATTRIB.Y_Space = 0;      // The Height of the space between the font with next font        
    CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, printBuf, &stFONT_ATTRIB);
    CTOS_PrinterBufferOutput((BYTE *)baTemp, 4); 
*/
	inPrint(printBuf);
    //inCCTOS_PrinterBufferOutput(printBuf,&stFONT_ATTRIB,1);
}


void vdMyEZLib_HexDump(unsigned char *msg, unsigned char *fmt, short inlen)
{
    char printBuf[128+1];
    short i=0;
    short index=0;
	BOOL inLabelFlag=TRUE;	
   
    //vdMyEZLib_Printf2("%s Len: (%d)\n",msg, inlen);    
    memset(printBuf, 0x00, sizeof(printBuf));
    for ( i=0 ;i<inlen; i++)
    {
        sprintf(&printBuf[index*3], "%02x ", fmt[i]);
        
        if(index == 13)
        {
            //vdMyEZLib_Printf2(printBuf);
            if(i>13)
				inLabelFlag=FALSE;
            vdMyEZLib_Printf3(inLabelFlag,msg,printBuf);
            memset(printBuf, 0x00, sizeof(printBuf));
            index=0;
        }
        else
            index++; 
    }
	
	if(i>13)
		inLabelFlag=FALSE;
		
    vdMyEZLib_Printf3(inLabelFlag,msg,printBuf);
}

