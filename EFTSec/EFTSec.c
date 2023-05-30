#if 1
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctosapi.h>

#include "../Includes/POSTypedef.h"
#include "../Includes/ISOEnginee.h"
#include "../Debug/Debug.h"
#include "../Database/DatabaseFunc.h"
#include "../Iso8583/iso.h"

#include <eftsec.h>


#endif

extern int inPrintISOPacket(unsigned char *pucTitle,unsigned char *pucMessage, int inLen);

int inEFTSecEncrypt(TRANS_DATA_TABLE *srTransPara, unsigned char *uszSendData, int *inSendLen)
{
    unsigned char uszTPDU[5+1];
    unsigned char uszMTI[2+1];
    unsigned char uszBitmap[8+1];
    unsigned char uszBuf[20+1];
    int inLen, inResult;

	//vdCTOSS_EFT_TestHardcodeKey(0x0123, 0x0004);

    //if (strTCT.fPrintISOMessage == VS_TRUE)
        //inPrintISOPacket("TX (EFTSEC)" , uszSendData, *inSendLen);
	
    DebugAddHEX("Before Modify", uszSendData, *inSendLen);
    
    memset(uszTPDU, 0x00, sizeof(uszTPDU));
    memset(uszMTI, 0x00, sizeof(uszMTI));
    memset(uszBitmap, 0x00, sizeof(uszBitmap));
	
	vdDebug_LogPrintf("srTransPara->HDTid(%d)",srTransPara->HDTid);
	 
    inResult = inCTOSS_Process_8583_UnPack(srTransPara->HDTid, uszSendData, *inSendLen, uszTPDU, uszMTI, uszBitmap);
    
    vdDebug_LogPrintf("inCTOSS_Process_8583_UnPack(%d)",inResult);
	DebugAddHEX("uszTPDU", uszTPDU, 5);
	DebugAddHEX("uszMTI", uszMTI, 2);
    DebugAddHEX("uszBitmap", uszBitmap, 8);
	
    //get DE4 value
    memset(uszBuf, 0x00, sizeof(uszBuf));
    inResult = inCTOSS_GetISOFieldData(4, uszBuf, &inLen);
    vdDebug_LogPrintf("inCTOSS_GetISOFieldData 4[%d] Len[%d]Value[%02X%02X%02X%02X%02X%02X]",inResult, inLen, uszBuf[0], uszBuf[1], uszBuf[2], uszBuf[3], uszBuf[4], uszBuf[5]);
    
    //get DE62 value
    memset(uszBuf, 0x00, sizeof(uszBuf));
    inResult = inCTOSS_GetISOFieldData(62, uszBuf, &inLen);
    vdDebug_LogPrintf("inCTOSS_GetISOFieldData 62[%d] Len[%d]Value[%02X%02X%02X%02X%02X%02X%02X%02X]",inResult, inLen, uszBuf[0], uszBuf[1], uszBuf[2], uszBuf[3], uszBuf[4], uszBuf[5], uszBuf[6], uszBuf[7]);
    
    //get DE39 value
    memset(uszBuf, 0x00, sizeof(uszBuf));
    inResult = inCTOSS_GetISOFieldData(39, uszBuf, &inLen);
    vdDebug_LogPrintf("inCTOSS_GetISOFieldData 39[%d] Len[%d] Value[%s]",inResult, inLen, uszBuf);
	
    uszBitmap[6] &= 0xFB; //turn off DE54
    uszBitmap[7] |= 0x80; //turn on DE57
    
    //update DE55
    inLen = 7;
    memcpy(uszBuf, "\x00\x05\x31\x32\x33\x34\x35", inLen);
    inCTOSS_SetISOFieldData(55, uszBuf, inLen);
    
    //add DE57
    inLen = 8;
    memcpy(uszBuf, "\x00\x06\x31\x31\x31\x31\x35\x37", inLen);
    inCTOSS_SetISOFieldData(57, uszBuf, inLen);
    
    inResult = inCTOSS_Process_8583_Pack(srTransPara->HDTid, uszSendData,  inSendLen, uszTPDU, uszMTI, uszBitmap);
    
    vdDebug_LogPrintf("inCTOSS_Process_8583_Pack(%d)",inResult);
    
    DebugAddHEX("After Modify", uszSendData, *inSendLen);
	
	memcpy(&uszSendData[1], strEFT.szSecureNII, 2); 
	inResult = inCTOSS_ProcessEFTSend(srTransPara->HDTid,
	strEFT.usKeySet,//0x0123,
	strEFT.usKeyIndex,//0x0004,
	1, 
	"2211", 
	"4004000020080200",
	"001",
	"91000503",
	(unsigned char *)uszSendData, inSendLen);

    vdDebug_LogPrintf("inCTOSS_ProcessEFTSend(%d)",inResult);

	//DebugAddHEX("inCTOSS_ProcessEFTSend", uszSendData, inSendLen);
			
    return inResult;
}

int inEFTSecDecrypt(TRANS_DATA_TABLE *srTransPara, unsigned char *uszReceiveData, unsigned char *szErrResponse)
{
	int inReceiveLen=0;
    int inResult;

	inResult=inCTOSS_ProcessEFTRecv(srTransPara->HDTid,
    strEFT.usKeySet,//0x0123,
    strEFT.usKeyIndex,//0x0004,
    1, 
    "2211", 
    (unsigned char *)uszReceiveData, &inReceiveLen, 
    szErrResponse);

	vdDebug_LogPrintf("inCTOSS_ProcessEFTRecv(%d)",inResult);
	vdDebug_LogPrintf("szErrResponse(%s)",szErrResponse);
					
	return inResult;
}

