
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <ctosapi.h>
#include <sys/types.h>
#include <linux/errno.h>

#include "sqlite3.h"
#include "DebugNMX.h"
#include "V5SLibNetMatrix.h"
#include "NMXDefine.h"
#include "NMXEncode.h"
#include "..\Debug\Debug.h"






//NMX_TLED_HEADER srNMXHeader;


NMX_FUNC_TABLE srNMXLibFunc;


static unsigned char g_DiversificationData[3+1];
static unsigned char g_CurrentTLEDEK[16+1];
static unsigned char g_CurrentRKIDEK[16+1];

static sqlite3 * db;
static sqlite3_stmt *stmt;
static int inStmtSeq;


//#define SMART_CARD_TEST_ONLY

char g_szTestTLEKID[10] = {0};


extern int inCTOSS_GetISOFieldData(IN int inField, OUT unsigned char *szData, OUT int *inLen);
extern int inCTOSS_SetISOFieldData(IN int inField, IN unsigned char *szData, IN int inLen);
extern int inCTOSS_Process_8583_UnPack(IN int inHDTid, IN unsigned char *uszISOData, IN int inISOLen, OUT unsigned char *uszTPDU, OUT unsigned char *uszMTI, OUT unsigned char *uszBitmap);
extern int inCTOSS_Process_8583_Pack(IN int inHDTid, OUT unsigned char *uszISOData, OUT int *inISOLen, IN unsigned char *uszTPDU, IN unsigned char *uszMTI, IN unsigned char *uszBitmap);
extern int inNMX_TCTRead(int inSeekCnt);
extern void DebugAddHEX(BYTE *title, BYTE *hex, USHORT len);
extern int inPMPCInitSmartCard(void);
extern int inCTOSS_NMX_3DESEncryptCBC(unsigned char *szTMK, unsigned char *szDatan, int inLen, unsigned char *szOutputData);
extern int inCTOSS_NMX_3DESDecryptCBC(unsigned char *szTMK, unsigned char *szDatanEncrypt, int inLen, unsigned char *szOutputData);
extern int inCTOSS_NMX_GenerateMAC(int inFinancialTxn, NMX_TLED_HEADER *srNMXHeader, unsigned char *inSendBuffer, int inPacketSize, unsigned  char *szMACValue);

extern unsigned int inNMX_hex_2_str(unsigned char *hex, unsigned char *str, unsigned int len);
extern unsigned int inNMX_str_2_hex(unsigned char *str, unsigned char *hex, unsigned int len);


#define     CTOS_KMS2_VERSION            0x01


#define     SMART_CARD_SW12_SUCCESS     0x9000

#define     SMART_CARD_PERSONAL_PROCESS     1
#define     SMART_CARD_OPERATION             2


//#define     TLE_DOWNLOAD_TEST       1

void vdCTOSS_NMX_GetSmartCardErrorMessage(unsigned short usSW12, unsigned char *szErrResponse)
{
    switch (usSW12)
    {
        case 0x6A86:
            strcpy(szErrResponse, "Incorrect Para P1 P2");
            break;
        case 0x6A84:
            strcpy(szErrResponse, "Insufficient memory");
            break;
        case 0x6882:
            strcpy(szErrResponse, "Secure Messaging Not Supported");
            break;
        case 0x6986:
            strcpy(szErrResponse, "Command Not Allowed");
            break;
        case 0x6982:
            strcpy(szErrResponse, "Security status not satisfied");
            break;
        case 0x6983:
            strcpy(szErrResponse, "Invalid File ID");
            break;
        case 0x6E00:
            strcpy(szErrResponse, "CLA not supported");
            break;
        case 0x6A81:
            strcpy(szErrResponse, "Function not supported");
            break;
        case 0x6B00:
            strcpy(szErrResponse, "Incorrect Para P1 P2");
            break;
        case 0x6A83:
            strcpy(szErrResponse, "Record Not Found");
            break;
        case 0x6A82:
            strcpy(szErrResponse, "Key not found");
            break;
        case 0x6984:
            strcpy(szErrResponse, "Invalid Data");
            break;
        case 0x6985:
            strcpy(szErrResponse, "Condition not satisfied");
            break;
        case 0x6D00:
            strcpy(szErrResponse, "INS value not supported");
            break;
        case 0x6700:
            strcpy(szErrResponse, "Wrong length");
            break;
        case 0x6A80:
            strcpy(szErrResponse, "Wrong data");
            break;

        default :
            if(usSW12 >= 0x6500 && usSW12 < 0x6600)
                strcpy(szErrResponse, "Response byte remaining");
            else if(usSW12 >= 0x6900 && usSW12 < 0x6A00)
                strcpy(szErrResponse, "Authentication Failed");
            break;
    }
}

int inCTOSS_NMX_SmartCardSelectApplication(OUT char *szErrResponse)
{
    USHORT bSLen,bRLen;
    BYTE baSAPDU[255],baRAPDU[255]; 
    unsigned short usSW12;

#ifdef SMART_CARD_TEST_ONLY
    return NMX_OK;
#endif

    //APDU Data
    baSAPDU[0]=0x00; //CLA
    baSAPDU[1]=0xA4; //INS
    baSAPDU[2]=0x04; //P1
    baSAPDU[3]=0x0C; //P2
    baSAPDU[4]=0x07; //LC
    memcpy(&baSAPDU[5], "\xA0\x00\x00\x47\x53\x05\x01", 7); //Data
    bSLen = 12;
    bRLen = sizeof(baRAPDU);

    DebugAddHEX("inCTOSS_NMX_SmartCardSelectApplication   send", baSAPDU, bSLen);  

    if (CTOS_SCSendAPDU(d_SC_SAM1, baSAPDU, bSLen, baRAPDU, &bRLen) != d_OK)
    {
        return NMX_SC_SELECTAPP_ERR;
    }
    
    DebugAddHEX("inCTOSS_NMX_SmartCardSelectApplication   recv", baRAPDU, bRLen);  

    usSW12 = baRAPDU[0] << 8 + baRAPDU[1];
    vdNMX_Debug_LogPrintf("usSW12[%X] ", usSW12);

    if(SMART_CARD_SW12_SUCCESS != usSW12)
    {
        vdCTOSS_NMX_GetSmartCardErrorMessage(usSW12, szErrResponse);
        return NMX_SC_SELECTAPP_ERR;
    }

    return NMX_OK;
}

int inCTOSS_NMX_SmartCardGetAppletInfo(unsigned char *szAppletName, unsigned char *szAppletVersion, OUT char *szErrResponse)
{
    USHORT bSLen,bRLen;
    BYTE baSAPDU[255],baRAPDU[255];

    USHORT usTagLen;
    USHORT usTag;

    int index;;
    unsigned short usSW12;
    
    //APDU Data
    baSAPDU[0]=0x00; //CLA
    baSAPDU[1]=0x12; //INS
    baSAPDU[2]=0x00; //P1
    baSAPDU[3]=0x00; //P2
    baSAPDU[4]=0x00; //LE
    bSLen = 5;
    bRLen = sizeof(baRAPDU);

    DebugAddHEX("inCTOSS_NMX_SmartCardGetAppletInfo   send", baSAPDU, bSLen);  

    if (CTOS_SCSendAPDU(d_SC_SAM1, baSAPDU, bSLen, baRAPDU, &bRLen) != d_OK)
    {
        return NMX_SC_SELECTAPP_ERR;
    }

    DebugAddHEX("inCTOSS_NMX_SmartCardGetAppletInfo   recv", baRAPDU, bRLen);  

    index = 0;
    usTag = baRAPDU[index++];
    if(0x75 == usTag) //Applet Name in TAG 0x75 
    {
        usTagLen = baRAPDU[index++];
        memcpy(szAppletName, &baRAPDU[index], usTagLen);
        vdNMX_Debug_LogPrintf("szAppletName[%s] ", szAppletName);
        index += usTagLen;
    }
    else
    {
        return NMX_SC_SELECTAPP_ERR;
    }

    usTag = baRAPDU[index++];
    if(0x76 == usTag) //Applet Version in TAG 0x76 
    {
        usTagLen = baRAPDU[index++];
        memcpy(szAppletVersion, &baRAPDU[index], usTagLen);
        vdNMX_Debug_LogPrintf("szAppletVersion[%02X.%02X.%02X] ", szAppletVersion[0], szAppletVersion[1], szAppletVersion[2]);
        index += usTagLen;
    }
    else
    {
        return NMX_SC_SELECTAPP_ERR;
    }

    usSW12 = baRAPDU[bRLen-2] << 8 + baRAPDU[bRLen-1];
    vdNMX_Debug_LogPrintf("usSW12[%X]", usSW12);

    if(SMART_CARD_SW12_SUCCESS != usSW12)
    {
        vdCTOSS_NMX_GetSmartCardErrorMessage(usSW12, szErrResponse);
        return NMX_SC_SELECTAPP_ERR;
    }

    return NMX_OK;
}

int inCTOSS_NMX_SmartCardPINVerifyRequest(IN unsigned char *szEncryptPIN, IN int inLen, OUT char *szErrResponse)
{
    USHORT bSLen,bRLen;
    BYTE baSAPDU[255],baRAPDU[255];

    unsigned short usSW12;

#ifdef SMART_CARD_TEST_ONLY
    return NMX_OK;
#endif

    //APDU Data
    baSAPDU[0]=0x00; //CLA
    baSAPDU[1]=0x20; //INS
    baSAPDU[2]=0x00; //P1
    baSAPDU[3]=0x00; //P2
    baSAPDU[4]=inLen; //LC
    memcpy(&baSAPDU[5], szEncryptPIN, inLen); //Data
    bSLen = 5 + inLen;
    bRLen = sizeof(baRAPDU);

    DebugAddHEX("inCTOSS_NMX_SmartCardPINVerifyRequest   send", baSAPDU, bSLen);  

    if (CTOS_SCSendAPDU(d_SC_SAM1, baSAPDU, bSLen, baRAPDU, &bRLen) != d_OK)
    {
        return NMX_SC_SELECTAPP_ERR;
    }

    DebugAddHEX("inCTOSS_NMX_SmartCardPINVerifyRequest   recv", baRAPDU, bRLen);  

    usSW12 = baRAPDU[0] << 8 + baRAPDU[1];
    vdNMX_Debug_LogPrintf("usSW12[%X] ", usSW12);

    if(SMART_CARD_SW12_SUCCESS != usSW12)
    {
        vdCTOSS_NMX_GetSmartCardErrorMessage(usSW12, szErrResponse);
        return NMX_SC_SELECTAPP_ERR;
    }

    return NMX_OK;
}


int inCTOSS_NMX_SmartCardPINChangeRequest(IN unsigned char *szEncryptPIN, IN int inLen, OUT char *szErrResponse)
{
    USHORT bSLen,bRLen;
    BYTE baSAPDU[255],baRAPDU[255];

    unsigned short usSW12;

#ifdef SMART_CARD_TEST_ONLY
    return NMX_OK;
#endif

    //APDU Data
    baSAPDU[0]=0x80; //CLA
    baSAPDU[1]=0x30; //INS
    baSAPDU[2]=0x00; //P1
    baSAPDU[3]=0x00; //P2
    baSAPDU[4]=inLen; //LC
    memcpy(&baSAPDU[5], szEncryptPIN, inLen); //Data
    bSLen = 5 + inLen;
    bRLen = sizeof(baRAPDU);

    DebugAddHEX("inCTOSS_NMX_SmartCardPINChangeRequest   send", baSAPDU, bSLen);  

    if (CTOS_SCSendAPDU(d_SC_USER, baSAPDU, bSLen, baRAPDU, &bRLen) != d_OK)
    {
        return NMX_SC_SELECTAPP_ERR;
    }

    DebugAddHEX("inCTOSS_NMX_SmartCardPINChangeRequest   recv", baRAPDU, bRLen);  

    usSW12 = baRAPDU[0] << 8 + baRAPDU[1];
    vdNMX_Debug_LogPrintf("usSW12[%X] ", usSW12);

    if(SMART_CARD_SW12_SUCCESS != usSW12)
    {
        vdCTOSS_NMX_GetSmartCardErrorMessage(usSW12, szErrResponse);
        return NMX_SC_SELECTAPP_ERR;
    }

    return NMX_OK;
}


int inCTOSS_NMX_SmartCardReadAcqIDVendorID(OUT unsigned char *byAcqID, OUT unsigned char *byVendorID, OUT char *szErrResponse)
{
//#ifdef SMART_CARD_TEST_ONLY
    //memcpy(byVendorID, "CARDBIZ\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 20);
    //memcpy(byAcqID, "UOB\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 20);
    memcpy(byAcqID,"\x30\x31\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 20);
    memcpy(byVendorID, "\x30\x31\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 20);
    //memcpy(byAcqID, "\x41\x63\x71\x30\x30\x31", 6);
	
    return NMX_OK;
//#endif
    
}

int inCTOSS_NMX_SmartCardSendCryptogramXGetTSK(IN unsigned char *szCryptogramX, IN unsigned char *szRndX, OUT unsigned char *szEncryptTSK, OUT unsigned char *szKCV, OUT char *szErrResponse)
{
    USHORT bSLen,bRLen;
    BYTE baSAPDU[255],baRAPDU[255];

    int index;
    
    unsigned short usSW12;

#ifdef SMART_CARD_TEST_ONLY
    memcpy(szEncryptTSK, "\x71\x97\xAF\x7F\x54\xB5\x1C\x6B\xF5\xE3\xB3\xDD\x8C\xB8\x38\xE0", 16);
    memcpy(szKCV, "\xDD\xAD", 2);
    return NMX_OK;
#endif

    //APDU Data
    baSAPDU[0]=0x00; //CLA
    baSAPDU[1]=0x45; //INS
    baSAPDU[2]=0x00; //P1
    baSAPDU[3]=SMART_CARD_OPERATION; //P2
    baSAPDU[4]=16; //LC
    memcpy(&baSAPDU[5], szRndX, 8); //Data
    memcpy(&baSAPDU[13], szCryptogramX, 8);
    bSLen = 21;
    bRLen = sizeof(baRAPDU);

    DebugAddHEX("inCTOSS_NMX_SmartCardSendCryptogramXGetTSK   send", baSAPDU, bSLen);  

    if (CTOS_SCSendAPDU(d_SC_SAM1, baSAPDU, bSLen, baRAPDU, &bRLen) != d_OK)
    {
        return NMX_SC_SELECTAPP_ERR;
    }

    DebugAddHEX("inCTOSS_NMX_SmartCardSendCryptogramXGetTSK   recv", baRAPDU, bRLen);  
    
    if(2 == bRLen && 0x61 == baRAPDU[0])
    {
        baSAPDU[0]=0x00; //CLA
        baSAPDU[1]=0xC0; //INS
        baSAPDU[2]=0x00; //P1
        baSAPDU[3]=0x00; //P2
        baSAPDU[4]=baRAPDU[1]; //LC

        bSLen = 5;
        bRLen = sizeof(baRAPDU);

        DebugAddHEX("0xC0   send", baSAPDU, bSLen);  

        if (CTOS_SCSendAPDU(d_SC_SAM1, baSAPDU, bSLen, baRAPDU, &bRLen) != d_OK)
        {
            return NMX_SC_SELECTAPP_ERR;
        }

        DebugAddHEX("0xC0   recv", baRAPDU, bRLen);  
        //0873337C6C84086DD2844EBD34D52D1563F19000

        index = 0;
        memcpy(szEncryptTSK, &baRAPDU[index], 16);
        index += 16;
        memcpy(szKCV, &baRAPDU[index], 2);
        index += 2;

        usSW12 = baRAPDU[index] << 8 + baRAPDU[index+1];
        vdNMX_Debug_LogPrintf("usSW12[%X] ", usSW12);
    }

    if(SMART_CARD_SW12_SUCCESS != usSW12)
    {
        vdCTOSS_NMX_GetSmartCardErrorMessage(usSW12, szErrResponse);
        return NMX_SC_SELECTAPP_ERR;
    }

    return NMX_OK;
}

int inCTOSS_NMX_SmartCardRequestAppKey(OUT unsigned char *szEncryptKey, OUT int *inLen, OUT unsigned char *szKCV, OUT char *szErrResponse)
{
    USHORT bSLen,bRLen;
    BYTE baSAPDU[255],baRAPDU[255];

    int index;
    
    unsigned short usSW12;

#ifdef SMART_CARD_TEST_ONLY
    *inLen = 24;
    memcpy(szEncryptKey, "123456789012345678901234", *inLen);
    memcpy(szKCV, "\x12\x34", 2);
    return NMX_OK;
#endif

    //APDU Data
    baSAPDU[0]=0x00; //CLA
    baSAPDU[1]=0x46; //INS
    baSAPDU[2]=0x00; //P1
    baSAPDU[3]=0x00; //P2   Key ID: 0x00 ?APP KEY 
    baSAPDU[4]=0x00; //LE
    bSLen = 5;
    bRLen = sizeof(baRAPDU);

    DebugAddHEX("inCTOSS_NMX_SmartCardRequestAppKey   send", baSAPDU, bSLen);  

    if (CTOS_SCSendAPDU(d_SC_SAM1, baSAPDU, bSLen, baRAPDU, &bRLen) != d_OK)
    {
        return NMX_SC_SELECTAPP_ERR;
    }

    DebugAddHEX("inCTOSS_NMX_SmartCardRequestAppKey   recv", baRAPDU, bRLen);  

    index = 0;
    memcpy(szEncryptKey, &baRAPDU[index], 24);
    *inLen = 24;
    index += 24;
    memcpy(szKCV, &baRAPDU[index], 2);
    index += 2;
    
    usSW12 = baRAPDU[index] << 8 + baRAPDU[index+1];
    vdNMX_Debug_LogPrintf("usSW12[%X] ", usSW12);

    if(SMART_CARD_SW12_SUCCESS != usSW12)
    {
        vdCTOSS_NMX_GetSmartCardErrorMessage(usSW12, szErrResponse);
        return NMX_SC_SELECTAPP_ERR;
    }

    return NMX_OK;
}


int inCTOSS_NMX_SmartCardInitMutualAuth(IN unsigned char *szEncryptRndA1A2,  OUT unsigned char *szEnRndA1B2B1A2, OUT char *szErrResponse)
{
    USHORT bSLen,bRLen;
    BYTE baSAPDU[255],baRAPDU[255];

    int index;
    
    unsigned short usSW12;

#ifdef SMART_CARD_TEST_ONLY
    memcpy(szEnRndA1B2B1A2, "\x5E\x1E\xFE\x79\x5D\xFC\x96\x4C\x93\x3E\x2E\xDF\x0B\x99\x71\x06", 16);
    return NMX_OK;
#endif
    
    //APDU Data
    baSAPDU[0]=0x00; //CLA
    baSAPDU[1]=0x43; //INS
    baSAPDU[2]=0x00; //P1
    baSAPDU[3]=0x00; //P2
    baSAPDU[4]=8; //LC
    memcpy(&baSAPDU[5], szEncryptRndA1A2, 8);
    bSLen = 13;
    bRLen = sizeof(baRAPDU);

    DebugAddHEX("inCTOSS_NMX_SmartCardInitMutualAuth   send", baSAPDU, bSLen);  

    if (CTOS_SCSendAPDU(d_SC_SAM1, baSAPDU, bSLen, baRAPDU, &bRLen) != d_OK)
    {
        return NMX_SC_SELECTAPP_ERR;
    }

    DebugAddHEX("inCTOSS_NMX_SmartCardInitMutualAuth   recv", baRAPDU, bRLen);  

    if(2 == bRLen && 0x61 == baRAPDU[0])
    {
        baSAPDU[0]=0x00; //CLA
        baSAPDU[1]=0xC0; //INS
        baSAPDU[2]=0x00; //P1
        baSAPDU[3]=0x00; //P2
        baSAPDU[4]=baRAPDU[1]; //LC

        bSLen = 5;
        bRLen = sizeof(baRAPDU);

        DebugAddHEX("0xC0   send", baSAPDU, bSLen);  

        if (CTOS_SCSendAPDU(d_SC_SAM1, baSAPDU, bSLen, baRAPDU, &bRLen) != d_OK)
        {
            return NMX_SC_SELECTAPP_ERR;
        }

        DebugAddHEX("0xC0   recv", baRAPDU, bRLen);  
        //0873337C6C84086DD2844EBD34D52D1563F19000

        index = 0;
        memcpy(szEnRndA1B2B1A2, &baRAPDU[index], 16);
        index += 16;

        usSW12 = baRAPDU[index] << 8 + baRAPDU[index+1];
        vdNMX_Debug_LogPrintf("usSW12[%X] ", usSW12);
    }
        
    if(SMART_CARD_SW12_SUCCESS != usSW12)
    {
        vdCTOSS_NMX_GetSmartCardErrorMessage(usSW12, szErrResponse);
        return NMX_SC_SELECTAPP_ERR;
    }

    return NMX_OK;
}

int inCTOSS_NMX_SmartCardMutualAuth(IN unsigned char *szEncryptRndB1B2, OUT char *szErrResponse)
{
    USHORT bSLen,bRLen;
    BYTE baSAPDU[255],baRAPDU[255];
    
    unsigned short usSW12;

#ifdef SMART_CARD_TEST_ONLY
    return NMX_OK;
#endif

    //APDU Data
    baSAPDU[0]=0x00; //CLA
    baSAPDU[1]=0x44; //INS
    baSAPDU[2]=0x00; //P1
    baSAPDU[3]=0x00; //P2 
    baSAPDU[4]=8; //LC
    memcpy(&baSAPDU[5], szEncryptRndB1B2, 8);
    bSLen = 13;
    bRLen = sizeof(baRAPDU);

    DebugAddHEX("inCTOSS_NMX_SmartCardMutualAuth   send", baSAPDU, bSLen);  

    if (CTOS_SCSendAPDU(d_SC_SAM1, baSAPDU, bSLen, baRAPDU, &bRLen) != d_OK)
    {
        return NMX_SC_SELECTAPP_ERR;
    }

    DebugAddHEX("inCTOSS_NMX_SmartCardMutualAuth   recv", baRAPDU, bRLen);  
    
    usSW12 = baRAPDU[0] << 8 + baRAPDU[1];
    vdNMX_Debug_LogPrintf("usSW12[%X] ", usSW12);

    if(SMART_CARD_SW12_SUCCESS != usSW12)
    {
        vdCTOSS_NMX_GetSmartCardErrorMessage(usSW12, szErrResponse);
        return NMX_SC_SELECTAPP_ERR;
    }

    return NMX_OK;
}

int inCTOSS_NMX_SmartCardRequestSession(IN unsigned char *byAcqID, IN unsigned char *byVendorID, OUT unsigned char *bySmartCardSerNo, OUT unsigned char *byEcrySession, OUT unsigned char *bySessionKCVHex, OUT char *szErrResponse)
{
    USHORT bSLen,bRLen;
    BYTE baSAPDU[255],baRAPDU[255];

    int index;
    
    unsigned short usSW12;

#ifdef SMART_CARD_TEST_ONLY
    memcpy(bySmartCardSerNo, "12345678900987654321", 20);
    memcpy(byEcrySession, "0A0B0C0D0E0F0102", 16);
    memcpy(bySessionKCVHex, "\x12\x34", 2);
    return NMX_OK;
#endif

    //APDU Data
    baSAPDU[0]=0x00; //CLA
    baSAPDU[1]=0x41; //INS
    baSAPDU[2]=0x00; //P1
    baSAPDU[3]=0x00; //P2
    baSAPDU[4]=40; //LC
    memcpy(&baSAPDU[5], byAcqID, 20);
    memcpy(&baSAPDU[25], byVendorID, 20);
    bSLen = 45;
    bRLen = sizeof(baRAPDU);

    DebugAddHEX("inCTOSS_NMX_SmartCardRequestSession   send", baSAPDU, bSLen);  

    if (CTOS_SCSendAPDU(d_SC_SAM1, baSAPDU, bSLen, baRAPDU, &bRLen) != d_OK)
    {
        return NMX_SC_SELECTAPP_ERR;
    }

    DebugAddHEX("inCTOSS_NMX_SmartCardRequestSession   recv", baRAPDU, bRLen);  

    if(2 == bRLen && 0x61 == baRAPDU[0])
    {
        baSAPDU[0]=0x00; //CLA
        baSAPDU[1]=0xC0; //INS
        baSAPDU[2]=0x00; //P1
        baSAPDU[3]=0x00; //P2
        baSAPDU[4]=baRAPDU[1]; //LC

        bSLen = 5;
        bRLen = sizeof(baRAPDU);

        DebugAddHEX("0xC0   send", baSAPDU, bSLen);  

        if (CTOS_SCSendAPDU(d_SC_SAM1, baSAPDU, bSLen, baRAPDU, &bRLen) != d_OK)
        {
            return NMX_SC_SELECTAPP_ERR;
        }

        DebugAddHEX("0xC0   recv", baRAPDU, bRLen);  
        //0873337C6C84086DD2844EBD34D52D1563F19000

        index = 0;
        memcpy(bySmartCardSerNo, &baRAPDU[index], 20);
        index += 20;
        memcpy(byEcrySession, &baRAPDU[index], 16);
        index += 16;
        memcpy(bySessionKCVHex, &baRAPDU[index], 2);
        index += 2;

        usSW12 = baRAPDU[index] << 8 + baRAPDU[index+1];
        vdNMX_Debug_LogPrintf("usSW12[%X] ", usSW12);
    }

    if(SMART_CARD_SW12_SUCCESS != usSW12)
    {
        vdCTOSS_NMX_GetSmartCardErrorMessage(usSW12, szErrResponse);
        return NMX_SC_SELECTAPP_ERR;
    }

    return NMX_OK;
}


int inCTOSS_NMX_SmartCardAuthSession(IN unsigned char *szEncrypSession, IN int inDataLen, OUT unsigned char *szClearData, OUT char *szErrResponse)
{
    USHORT bSLen,bRLen;
    int inOutputLen;
    BYTE baSAPDU[255],baRAPDU[255], szTestBUF1[255];

    int index;
    
    unsigned short usSW12;

#ifdef SMART_CARD_TEST_ONLY
    memcpy(szClearData, szEncrypSession, 101);
    return NMX_OK;
#endif

    
    //APDU Data
    baSAPDU[0]=0x00; //CLA
    baSAPDU[1]=0x42; //INS
    baSAPDU[2]=0x00; //P1
    baSAPDU[3]=0x00; //P2
    baSAPDU[4]=inDataLen; //LC
    memcpy(&baSAPDU[5], szEncrypSession, inDataLen);
    bSLen = 5 + inDataLen;
    bRLen = sizeof(baRAPDU);

    DebugAddHEX("inCTOSS_NMX_SmartCardAuthSession   send", baSAPDU, bSLen);  

    if (CTOS_SCSendAPDU(d_SC_SAM1, baSAPDU, bSLen, baRAPDU, &bRLen) != d_OK)
    {
        return NMX_SC_SELECTAPP_ERR;
    }

    DebugAddHEX("inCTOSS_NMX_SmartCardAuthSession   recv", baRAPDU, bRLen);  

    if(2 == bRLen && 0x61 == baRAPDU[0])
    {
        baSAPDU[0]=0x00; //CLA
        baSAPDU[1]=0xC0; //INS
        baSAPDU[2]=0x00; //P1
        baSAPDU[3]=0x00; //P2
        baSAPDU[4]=baRAPDU[1]; //LC

        bSLen = 5;
        bRLen = sizeof(baRAPDU);

        DebugAddHEX("0xC0   send", baSAPDU, bSLen);  

        if (CTOS_SCSendAPDU(d_SC_SAM1, baSAPDU, bSLen, baRAPDU, &bRLen) != d_OK)
        {
            return NMX_SC_SELECTAPP_ERR;
        }

        DebugAddHEX("0xC0   recv", baRAPDU, bRLen);  

        usSW12 = baRAPDU[bRLen-2] << 8 + baRAPDU[bRLen-1];
        vdNMX_Debug_LogPrintf("usSW12[%X] ", usSW12);

        if(SMART_CARD_SW12_SUCCESS == usSW12)
        {
            bRLen -= 2;
            
            inOutputLen = 254;
            memset(szTestBUF1, 0x00, sizeof(szTestBUF1));
            iDecode250 (baRAPDU, bRLen, szTestBUF1, &inOutputLen);

            DebugAddHEX("After iDecode250", szTestBUF1, inOutputLen);  

            bRLen = inOutputLen;
            memcpy(baRAPDU, szTestBUF1, inOutputLen);

            index = 0;
            memcpy(szClearData, &baRAPDU[index], 101);
            //RKI
            index += 6;     //KID
            index += 1;
            index += 16;    //DEK
            index += 1;
            index += 4;     //KCV
            index += 1;
            index += 16;    //MEK
            index += 1;
            index += 4;     //KCV
            index += 1;

            //TLE
            index += 6;     //KID
            index += 1;
            index += 16;    //DEK
            index += 1;
            index += 4;     //KCV
            index += 1;
            index += 16;    //MEK
            index += 1;
            index += 4;     //KCV

        }
        
    }
    else
    {
        index = 0;
        memcpy(szClearData, &baRAPDU[index], 101);
        index += 101;
        
        usSW12 = baRAPDU[index] << 8 + baRAPDU[index+1];
        vdNMX_Debug_LogPrintf("usSW12[%X] ", usSW12);
    }
    
    if(SMART_CARD_SW12_SUCCESS != usSW12)
    {
        vdCTOSS_NMX_GetSmartCardErrorMessage(usSW12, szErrResponse);
        return NMX_SC_SELECTAPP_ERR;
    }

    return NMX_OK;
}






int inCTOSS_NMXCheckFileExist(char *szFileName)
{
    ULONG ulFileSize = 0;
    ULONG ulHandle;
    USHORT usResult;
        
    usResult = CTOS_FileGetSize(szFileName, &ulFileSize);                         

    vdNMX_Debug_LogPrintf("inCTOSS_NMXCheckFileExist[%s] usResult[%d] ulFileSize[%ld]", szFileName, usResult, ulFileSize);
    if (ulFileSize > 0 || usResult == d_OK)                                                      
        return ulFileSize;
    else if(usResult == d_FS_FILE_NOT_FOUND)
        return  -6;         
                                                                           
    return -1;
}

int inCTOSS_NMXDeleteFile(char *szFileName)
{
	int inResult;

	
	if((inResult = CTOS_FileDelete(szFileName)) != d_OK)
    {
        return -1;
    }     
	
    return 0;
	
}

int inCTOSS_TestSaveNMXTLEKey(unsigned char *szTLEDEK, unsigned char *szTLEMEK)
{
    char szNMXKeyFileNamae[128];
    char szKeyBuf[128];
    char private_path[50] = "./fs_data/";
    FILE *hHandle;
    int inResult;
    
    memset(szNMXKeyFileNamae, 0x00, sizeof (szNMXKeyFileNamae));
    sprintf(szNMXKeyFileNamae, "%s_NMX.dat", private_path);

    hHandle = fopen(szNMXKeyFileNamae, "wb+");

    memset(szKeyBuf, 0x00, sizeof(szKeyBuf));
    memcpy(&szKeyBuf[0], szTLEDEK, 16);
    memcpy(&szKeyBuf[16], szTLEMEK, 16);
    inResult = fwrite((void*) szKeyBuf, 32, 1, hHandle);
    
    fclose(hHandle);

    vdNMX_Debug_LogPrintf("inCTOSS_TestSaveNMXTLEKey[%d] ", inResult);
    DebugAddHEX("szTLEDEK", szTLEDEK, 16);  
    DebugAddHEX("szTLEMEK", szTLEMEK, 16);  

    return 0;
}

int inCTOSS_TestReadNMXTLEKey(unsigned char *szTLEDEK, unsigned char *szTLEMEK)
{
    char szNMXKeyFileNamae[128];
    char szKeyBuf[128];
    char private_path[50] = "./fs_data/";
    FILE *hHandle;
    int inResult;
    
    memset(szNMXKeyFileNamae, 0x00, sizeof (szNMXKeyFileNamae));
    sprintf(szNMXKeyFileNamae, "%s_NMX.dat", private_path);

    hHandle = fopen(szNMXKeyFileNamae, "rb");

    memset(szKeyBuf, 0x00, sizeof(szKeyBuf));

    inResult = fread((void*) szKeyBuf, 32, 1, hHandle);
    
    fclose(hHandle);
    
    memcpy(szTLEDEK, &szKeyBuf[0], 16);
    memcpy(szTLEMEK, &szKeyBuf[16], 16);

    vdNMX_Debug_LogPrintf("inCTOSS_TestReadNMXTLEKey[%d] ", inResult);
    DebugAddHEX("szTLEDEK", szTLEDEK, 16);  
    DebugAddHEX("szTLEMEK", szTLEMEK, 16);   

    return 0;
}

int inCTOSS_TestDeleteNMXTLEKey(void)
{
    int inResult;
    char szNMXKeyFileNamae[128];
    char private_path[50] = "./fs_data/";

    memset(szNMXKeyFileNamae, 0x00, sizeof (szNMXKeyFileNamae));
    sprintf(szNMXKeyFileNamae, "%s_NMX.dat", private_path);

    if((inResult = inCTOSS_NMXCheckFileExist(szNMXKeyFileNamae)) >= 0)
    {
        if (0 != inCTOSS_NMXDeleteFile(szNMXKeyFileNamae))
            return -1;
    }

    return 0;
}

int inCTOSS_TestSaveNMXRKIKey(unsigned char *szRKIDEK, unsigned char *szRKIMEK)
{
    char szNMXKeyFileNamae[128];
    char szKeyBuf[128];
    char private_path[50] = "./fs_data/";
    FILE *hHandle;
    int inResult;
    
    memset(szNMXKeyFileNamae, 0x00, sizeof (szNMXKeyFileNamae));
    sprintf(szNMXKeyFileNamae, "%s_NMXRKI.dat", private_path);

    hHandle = fopen(szNMXKeyFileNamae, "wb+");

    memset(szKeyBuf, 0x00, sizeof(szKeyBuf));
    memcpy(&szKeyBuf[0], szRKIDEK, 16);
    memcpy(&szKeyBuf[16], szRKIMEK, 16);
    inResult = fwrite((void*) szKeyBuf, 32, 1, hHandle);
    
    fclose(hHandle);

    vdNMX_Debug_LogPrintf("inCTOSS_TestSaveNMXRKIKey[%d] ", inResult);
    DebugAddHEX("szRKIDEK", szRKIDEK, 16);  
    DebugAddHEX("szRKIMEK", szRKIMEK, 16);  

    return 0;
}

int inCTOSS_TestReadNMXRKIKey(unsigned char *szRKIDEK, unsigned char *szRKIMEK)
{
    char szNMXKeyFileNamae[128];
    char szKeyBuf[128];
    char private_path[50] = "./fs_data/";
    FILE *hHandle;
    int inResult;
    
    memset(szNMXKeyFileNamae, 0x00, sizeof (szNMXKeyFileNamae));
    sprintf(szNMXKeyFileNamae, "%s_NMXRKI.dat", private_path);

    hHandle = fopen(szNMXKeyFileNamae, "rb");

    memset(szKeyBuf, 0x00, sizeof(szKeyBuf));

    inResult = fread((void*) szKeyBuf, 32, 1, hHandle);
    
    fclose(hHandle);
    
    memcpy(szRKIDEK, &szKeyBuf[0], 16);
    memcpy(szRKIMEK, &szKeyBuf[16], 16);

    vdNMX_Debug_LogPrintf("inCTOSS_TestReadNMXRKIKey[%d] ", inResult);
    DebugAddHEX("szRKIDEK", szRKIDEK, 16);  
    DebugAddHEX("szRKIMEK", szRKIMEK, 16);   

    return 0;
}

int inCTOSS_TestDeleteNMXRKIKey(void)
{
    int inResult;
    char szNMXKeyFileNamae[128];
    char private_path[50] = "./fs_data/";

    memset(szNMXKeyFileNamae, 0x00, sizeof (szNMXKeyFileNamae));
    sprintf(szNMXKeyFileNamae, "%s_NMXRKI.dat", private_path);

    if((inResult = inCTOSS_NMXCheckFileExist(szNMXKeyFileNamae)) >= 0)
    {
        if (0 != inCTOSS_NMXDeleteFile(szNMXKeyFileNamae))
            return -1;
    }

    return 0;
}

int inCTOSS_TestNMXTLEEncryptDataCBCMode(IN int inFinancialTxn, int inKeySet, int inKeyIndex, unsigned char *szDataIn, int inDataLen, unsigned char *szDataout )
{
    unsigned char szDEK[32];
    unsigned char szMEK[32];
    unsigned char szBuf[512];

    memset(szDEK, 0x00, sizeof(szDEK));
    memset(szMEK, 0x00, sizeof(szMEK));

    if(inFinancialTxn)
        inCTOSS_TestReadNMXTLEKey(szDEK, szMEK);
    else
        inCTOSS_TestReadNMXRKIKey(szDEK, szMEK);

    inCTOSS_NMX_3DESEncryptCBC(szDEK, szDataIn, inDataLen, szBuf);
    memcpy(szDataout, szBuf, inDataLen);

    return NMX_OK;
}

int inCTOSS_TestNMXTLEDecryptDataCBCMode(IN int inFinancialTxn, int inKeySet, int inKeyIndex, unsigned char *szDataIn, int inDataLen, unsigned char *szDataout )
{
    unsigned char szDEK[32];
    unsigned char szMEK[32];
    unsigned char szBuf[512];

    memset(szDEK, 0x00, sizeof(szDEK));
    memset(szMEK, 0x00, sizeof(szMEK));

    if(inFinancialTxn)
        inCTOSS_TestReadNMXTLEKey(szDEK, szMEK);
    else
        inCTOSS_TestReadNMXRKIKey(szDEK, szMEK);

    inCTOSS_NMX_3DESDecryptCBC(szDEK, szDataIn, inDataLen, szBuf);
    memcpy(szDataout, szBuf, inDataLen);

    return NMX_OK;
}



int inCTOSS_NMX_Read(int inSeekCnt)
{
	int result;
	int inResult = d_NO;
	char *sql = "SELECT szAppID, szRKIKID, szTLEKID, szVersion, szEncAlgo, szKeyMag, szMACAlgo, szCommandCode, szDeviceMode, szDeviceSerNo, szFlag, szCounter, szSensitiveFieldBMP, inRKIDEKKeySet, inRKIMEKKeySet, inRKIKeyIndex, inTLEDEKKeySet, inTLEMEKKeySet, inTLEKeyIndex, inNMXEnable FROM NMX WHERE NMXid = ?";
		
	/* open the database */
	result = sqlite3_open(DB_NMX_LIB,&db);
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
				
			/* szAppID */			
			strcpy((char*)srNMXHeader.szAppID, (char *)sqlite3_column_text(stmt,inStmtSeq));

            /*szRKIKID*/
			strcpy((char*)srNMXHeader.szRKIKID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

			/*szTLEKID*/
			strcpy((char*)srNMXHeader.szTLEKID, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /*szVersion*/
			strcpy((char*)srNMXHeader.szVersion, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /*szEncAlgo*/
			strcpy((char*)srNMXHeader.szEncAlgo, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /*szKeyMag*/
			strcpy((char*)srNMXHeader.szKeyMag, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /*szMACAlgo*/
			strcpy((char*)srNMXHeader.szMACAlgo, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /*szCommandCode*/
			strcpy((char*)srNMXHeader.szCommandCode, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /*szDeviceMode*/
			strcpy((char*)srNMXHeader.szDeviceMode, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /*szDeviceSerNo*/
			strcpy((char*)srNMXHeader.szDeviceSerNo, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /*szFlag*/
			strcpy((char*)srNMXHeader.szFlag, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
            
            /*szCounter*/
			strcpy((char*)srNMXHeader.szCounter, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));

            /*szSensitiveFieldBMP*/
			strcpy((char*)srNMXHeader.szSensitiveFieldBMP, (char *)sqlite3_column_text(stmt,inStmtSeq +=1 ));
			
            /* inRKIDEKKeySet */
			srNMXHeader.inRKIDEKKeySet = sqlite3_column_int(stmt,inStmtSeq +=1);

            /* inRKIMEKKeySet */
			srNMXHeader.inRKIMEKKeySet = sqlite3_column_int(stmt,inStmtSeq +=1);

            /* inRKIKeyIndex */
			srNMXHeader.inRKIKeyIndex = sqlite3_column_int(stmt,inStmtSeq +=1);

            /* inTLEDEKKeySet */
			srNMXHeader.inTLEDEKKeySet = sqlite3_column_int(stmt,inStmtSeq +=1);

            /* inTLEMEKKeySet */
			srNMXHeader.inTLEMEKKeySet = sqlite3_column_int(stmt,inStmtSeq +=1);

            /* inTLEKeyIndex */
			srNMXHeader.inTLEKeyIndex = sqlite3_column_int(stmt,inStmtSeq +=1);

            /* inNMXEnable */
			srNMXHeader.inNMXEnable = sqlite3_column_int(stmt,inStmtSeq +=1);
            
		}
	} while (result == SQLITE_ROW);

    vdNMX_Debug_LogPrintf("srNMXHeader.inTLEDEKKeySet[%d]", srNMXHeader.inTLEDEKKeySet);
    vdNMX_Debug_LogPrintf("srNMXHeader.inTLEMEKKeySet[%d]", srNMXHeader.inTLEMEKKeySet);
    vdNMX_Debug_LogPrintf("srNMXHeader.inTLEKeyIndex[%d]", srNMXHeader.inTLEKeyIndex);
    vdNMX_Debug_LogPrintf("srNMXHeader.szTLEKID[%s]", srNMXHeader.szTLEKID);
    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(inResult);
}


int inCTOSS_NMX_Save(int inSeekCnt)
{
	int result;
	char *sql = "UPDATE NMX SET szAppID = ?, szRKIKID = ?, szTLEKID = ?, szVersion = ?, szEncAlgo = ?, szKeyMag = ?, szMACAlgo = ?, szCommandCode = ?, szDeviceMode = ?, szDeviceSerNo = ?, szFlag = ?, szCounter = ?, szSensitiveFieldBMP = ?, inRKIDEKKeySet = ?, inRKIMEKKeySet = ?, inRKIKeyIndex = ?, inTLEDEKKeySet = ?, inTLEMEKKeySet = ?, inTLEKeyIndex = ?, inNMXEnable = ? WHERE  NMXid = ?";
		
	/* open the database */
	result = sqlite3_open(DB_NMX_LIB,&db);
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

	inStmtSeq = 0;

    /* szAppID */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srNMXHeader.szAppID, strlen((char*)srNMXHeader.szAppID), SQLITE_STATIC);
    /* szRKIKID */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srNMXHeader.szRKIKID, strlen((char*)srNMXHeader.szRKIKID), SQLITE_STATIC);
    /* szTLEKID */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srNMXHeader.szTLEKID, strlen((char*)srNMXHeader.szTLEKID), SQLITE_STATIC);
    /* szVersion */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srNMXHeader.szVersion, strlen((char*)srNMXHeader.szVersion), SQLITE_STATIC);
    /* szEncAlgo */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srNMXHeader.szEncAlgo, strlen((char*)srNMXHeader.szEncAlgo), SQLITE_STATIC);
    /* szKeyMag */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srNMXHeader.szKeyMag, strlen((char*)srNMXHeader.szKeyMag), SQLITE_STATIC);
    /* szMACAlgo */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srNMXHeader.szMACAlgo, strlen((char*)srNMXHeader.szMACAlgo), SQLITE_STATIC);
    /* szCommandCode */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srNMXHeader.szCommandCode, strlen((char*)srNMXHeader.szCommandCode), SQLITE_STATIC);
    /* szDeviceMode */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srNMXHeader.szDeviceMode, strlen((char*)srNMXHeader.szDeviceMode), SQLITE_STATIC);
    /* szDeviceSerNo */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srNMXHeader.szDeviceSerNo, strlen((char*)srNMXHeader.szDeviceSerNo), SQLITE_STATIC);
    /* szFlag */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srNMXHeader.szFlag, strlen((char*)srNMXHeader.szFlag), SQLITE_STATIC);
    /* szCounter */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srNMXHeader.szCounter, strlen((char*)srNMXHeader.szCounter), SQLITE_STATIC);
    /* szSensitiveFieldBMP */
	result = sqlite3_bind_text(stmt, inStmtSeq +=1, (char*)srNMXHeader.szSensitiveFieldBMP, strlen((char*)srNMXHeader.szSensitiveFieldBMP), SQLITE_STATIC);
    /* inRKIDEKKeySet */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, srNMXHeader.inRKIDEKKeySet);
    /* inRKIMEKKeySet */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, srNMXHeader.inRKIMEKKeySet);
    /* inRKIKeyIndex */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, srNMXHeader.inRKIKeyIndex);
    /* inTLEDEKKeySet */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, srNMXHeader.inTLEDEKKeySet);
    /* inTLEMEKKeySet */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, srNMXHeader.inTLEMEKKeySet);
    /* inTLEKeyIndex */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, srNMXHeader.inTLEKeyIndex);
    /* inNMXEnable */
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, srNMXHeader.inNMXEnable);
	
	result = sqlite3_bind_int(stmt, inStmtSeq +=1, inSeekCnt);

	result = sqlite3_step(stmt);
	if( result != SQLITE_DONE ){
		sqlite3_close(db);
		return 3;
	}

    
	sqlite3_exec(db,"commit;",NULL,NULL,NULL);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

    return(d_OK);
}



void vdCTOSS_NMX_getRandomNumber(unsigned char * uszRandomNumber, int inByteSize)
{
    BYTE baRNG[32];
    int i = 0 ;
    
    CTOS_RNG(baRNG); 

    for(i=0; i<inByteSize; i++)
    {
        uszRandomNumber[i] = baRNG[i]%10 + 0x30;
    }
    
    //strcpy(uszRandomNumber, "514");
}

void vdCTOSS_NMX_getRandomHexData(unsigned char * uszRandomNumber, int inByteSize)
{
    BYTE baRNG[32];
    
    CTOS_RNG(baRNG); 

    memcpy(uszRandomNumber, baRNG, inByteSize);
}

int inCTOSS_NMX__SHA1(unsigned char *InputBuffer, unsigned long nb, unsigned char *sha20)
{
    SHA_CTX SHA_CTX;
    BYTE baSHA[32];

    //Initialize the SHA_CTX structure and perpart for the SHA1 operation //                                     
    CTOS_SHA1Init(&SHA_CTX);

    //Perform the SHA1 algorithm with the input data //                                                     
    CTOS_SHA1Update(&SHA_CTX,InputBuffer, nb);                                                          
                                                                                                          
    //Finalize the SA1 operation and retrun the result //                                                   
    CTOS_SHA1Final(baSHA,&SHA_CTX);        
    
    memcpy(sha20, baSHA, 20);
    
    return NMX_OK;
}

int inCTOSS_NMX_Save3DESClearKeyForEncrypt(int inKeySet, int inKeyIndex, unsigned char *szClearKey)
{
	CTOS_KMS2KEYWRITE_PARA para;
	USHORT ret;
	BYTE KeyData[16];
	
	memcpy(KeyData, szClearKey, 16);

	memset(&para, 0x00, sizeof(CTOS_KMS2KEYWRITE_PARA));
	para.Version = CTOS_KMS2_VERSION;
	para.Info.KeySet = inKeySet;
	para.Info.KeyIndex = inKeyIndex;
	para.Info.KeyType = KMS2_KEYTYPE_3DES;
	para.Info.KeyVersion = 0x01;
	para.Info.KeyAttribute = KMS2_KEYATTRIBUTE_PIN | KMS2_KEYATTRIBUTE_ENCRYPT | KMS2_KEYATTRIBUTE_MAC;
	para.Protection.Mode = KMS2_KEYPROTECTIONMODE_PLAINTEXT;
	para.Value.pKeyData = KeyData;
	para.Value.KeyLength = 16;
    
	ret = CTOS_KMS2KeyWrite(&para);
    
    vdNMX_Debug_LogPrintf("store for encrypt KeySet[%d] KeyIndex[%d] ret[%d]", para.Info.KeySet, para.Info.KeyIndex, ret);
    if(ret != NMX_OK)
        return ret;

    return NMX_OK;

}

int inCTOSS_NMX_Save3DESClearKeyForDecrypt(int inKeySet, int inKeyIndex, unsigned char *szClearKey)
{
	CTOS_KMS2KEYWRITE_PARA para;
	USHORT ret;
	BYTE KeyData[16];
	
	memcpy(KeyData, szClearKey, 16);

	memset(&para, 0x00, sizeof(CTOS_KMS2KEYWRITE_PARA));
	para.Version = CTOS_KMS2_VERSION;
	para.Info.KeySet = inKeySet + 1;
	para.Info.KeyIndex = inKeyIndex;
	para.Info.KeyType = KMS2_KEYTYPE_3DES;
	para.Info.KeyVersion = 0x01;
    para.Info.KeyAttribute = KMS2_KEYATTRIBUTE_PIN | KMS2_KEYATTRIBUTE_ENCRYPT | KMS2_KEYATTRIBUTE_MAC | KMS2_KEYATTRIBUTE_DECRYPT;
    para.Protection.Mode = KMS2_KEYPROTECTIONMODE_PLAINTEXT;
	para.Value.pKeyData = KeyData;
	para.Value.KeyLength = 16;
    
	ret = CTOS_KMS2KeyWrite(&para);

    vdNMX_Debug_LogPrintf("store for decrypt KeySet[%d] KeyIndex[%d] ret[%d]", para.Info.KeySet, para.Info.KeyIndex, ret);
    if(ret != NMX_OK)
        return ret;

    return NMX_OK;

}


int inCTOSS_NMX_KMS3DESDecryptSessionKeyAndStoreIt(int inTMKKeySet, int inTMKKeyIndex, int inSessionKeySet, int inSessionKeyIndex, unsigned char *szEncryptDataIn, int inDataLen, unsigned char *szDecrypDataKCV)
{
    CTOS_KMS2KEYWRITE_PARA para;
    USHORT ret; 
    int inKCVLen = 3;
    
    memset(&para, 0x00, sizeof(CTOS_KMS2KEYWRITE_PARA));    
    para.Version = CTOS_KMS2_VERSION;
    para.Info.KeySet = inSessionKeySet;
    para.Info.KeyIndex = inSessionKeyIndex;
    para.Info.KeyType = KMS2_KEYTYPE_3DES;
    para.Info.KeyVersion = 0x01;
    para.Info.KeyAttribute = KMS2_KEYATTRIBUTE_ENCRYPT | KMS2_KEYATTRIBUTE_DECRYPT | KMS2_KEYATTRIBUTE_PIN | KMS2_KEYATTRIBUTE_MAC;
    para.Protection.Mode = KMS2_KEYPROTECTIONMODE_KPK_CBC;
    para.Protection.CipherKeySet = inTMKKeySet;
    para.Protection.CipherKeyIndex = inTMKKeyIndex;
    para.Value.pKeyData = szEncryptDataIn;  
    para.Value.KeyLength = inDataLen;
    para.Verification.Method = KMS2_KEYVERIFICATIONMETHOD_DEFAULT; 
    
    para.Verification.KeyCheckValueLength = inKCVLen;
    para.Verification.pKeyCheckValue = szDecrypDataKCV;
    vdNMX_DebugAddHEX("Encrypted szEncryptDataIn-------",szEncryptDataIn,16);

    ret = CTOS_KMS2KeyWrite(&para);
    if(ret != d_OK)
        return ret;
    
    vdNMX_DebugAddHEX("KCV-------",szDecrypDataKCV,3);
    return NMX_OK;
    
}

int inCTOSS_NMX_KMS3DESEncryptData(int inKeySet, int inKeyIndex, unsigned char *szDataIn, int inDataLen, unsigned char *szDataout )
{
    CTOS_KMS2DATAENCRYPT_PARA para;
    BYTE plaindata[512];
    //BYTE pICV[255];
    USHORT ret;
    //USHORT ICVLength;
    
    
    vdNMX_DebugAddHEX("inCTOSS_NMX_KMS3DESEncryptDataIN-------",szDataIn, inDataLen);
    
    memset(&para, 0x00, sizeof(CTOS_KMS2DATAENCRYPT_PARA));
	para.Version = CTOS_KMS2_VERSION;
	para.Protection.CipherKeySet = inKeySet;
	para.Protection.CipherKeyIndex = inKeyIndex;
	para.Protection.CipherMethod = KMS2_DATAENCRYPTCIPHERMETHOD_CBC;
	//para.Protection.CipherMethod = KMS2_DATAENCRYPTCIPHERMETHOD_ECB;
	para.Protection.SK_Length = 0;

	memset(plaindata, 0x00, sizeof(plaindata));
    memcpy(plaindata, szDataIn, inDataLen);

    //ICVLength = 8;
    //memset(pICV, 0x00, sizeof(pICV));
    
    //para.Input.ICVLength = ICVLength;
	//para.Input.pData = pICV;
	para.Input.Length = inDataLen;
	para.Input.pData = plaindata;
	para.Output.pData = szDataout;

	ret = CTOS_KMS2DataEncrypt(&para);
    
    vdNMX_Debug_LogPrintf("KMS encry KeySet[%d] KeyIndex[%d] ret[%d]", para.Protection.CipherKeySet, para.Protection.CipherKeyIndex, ret);
    if(ret != d_OK)
        return ret;

    vdNMX_DebugAddHEX("inCTOSS_NMX_KMS3DESEncryptDataOut-------",szDataout, inDataLen);
    return NMX_OK;
}

int inCTOSS_NMX_KMS3DESDecryptData(int inKeySet, int inKeyIndex, unsigned char *szDataIn, int inDataLen, unsigned char *szDataout )
{
    CTOS_KMS2DATAENCRYPT_PARA para;
    BYTE plaindata[512];
    //BYTE pICV[255];
    USHORT ret;
    //USHORT ICVLength;
    
    vdNMX_DebugAddHEX("inCTOSS_NMX_KMS3DESDecryptszDataIn-------",szDataIn, inDataLen);

    memset(&para, 0x00, sizeof(CTOS_KMS2DATAENCRYPT_PARA));
	para.Version = CTOS_KMS2_VERSION;
	para.Protection.CipherKeySet = inKeySet+1;
	para.Protection.CipherKeyIndex = inKeyIndex;
	para.Protection.CipherMethod = KMS2_DATAENCRYPTCIPHERMETHOD_CBC;
    //para.Protection.CipherMethod = KMS2_DATAENCRYPTCIPHERMETHOD_ECB;
	para.Protection.SK_Length = 0;

	memset(plaindata, 0x00, sizeof(plaindata));
    memcpy(plaindata, szDataIn, inDataLen);

    //ICVLength = 8;
    //memset(pICV, 0x00, sizeof(pICV));

    //para.Input.ICVLength = ICVLength;
	//para.Input.pData = pICV;
    
	para.Input.Length = inDataLen;
	para.Input.pData = plaindata;
	para.Output.pData = szDataout;

	ret = CTOS_KMS2DataEncrypt(&para);
    
    vdNMX_Debug_LogPrintf("KMS decrypt KeySet[%d] KeyIndex[%d] ret[%d]", para.Protection.CipherKeySet, para.Protection.CipherKeyIndex, ret);
    if(ret != d_OK)
        return ret;

    vdNMX_DebugAddHEX("inCTOSS_NMX_KMS3DESDecryptDataOut-------",szDataout, inDataLen);
    return NMX_OK;
}

int inCTOSS_NMX_3DESEncryptCBC(unsigned char *szTMK, unsigned char *szDatan, int inLen, unsigned char *szOutputData)
{
    unsigned long aulIV[8] = {0};
    unsigned long aulPlain[8] = {0};
    unsigned char szDataInBackup[1024];
    int i,j,k;
    int iTotalBlock;

    vdNMX_Debug_LogPrintf("inCTOSS_NMX_3DESEncryptCBC Encry Start Len[%d]", inLen);
    vdNMX_DebugAddHEX("TMK",szTMK, 16);
    vdNMX_DebugAddHEX("DataIn",szDatan, inLen);

    memcpy(szDataInBackup, szDatan, inLen);
    
    memset(aulIV, 0x00, sizeof(aulIV));
    iTotalBlock = inLen / 8;
    j = 0;
    for (i = 0; i < iTotalBlock; i++)
	{
		j = i * 8;
		memcpy (aulPlain, &szDatan[j] , 8);
		for (k = 0; k < 2; k++)
		{
			aulPlain[k] = aulPlain[k] ^ aulIV[k];		//Plaintext XOR with 
		}											//previous Cipher Block
		memcpy (&szDatan[j], aulPlain, 8);

		CTOS_DES (d_ENCRYPTION, &szTMK[0], 8, (char *)&szDatan[j], 8, (char *)&szDatan[j]);	//Encrypt
		CTOS_DES (d_DECRYPTION, &szTMK[8], 8, (char *)&szDatan[j], 8, (char *)&szDatan[j]);	//Decrypt
		CTOS_DES (d_ENCRYPTION, &szTMK[0], 8, (char *)&szDatan[j], 8, (char *)&szDatan[j]);	//Encrypt

		memcpy (aulIV, (char *)&szDatan[j], 8);

	}
    
    memcpy (szOutputData, szDatan, inLen);
    vdNMX_DebugAddHEX("DataOut",szOutputData, inLen);
    vdNMX_Debug_LogPrintf("inCTOSS_NMX_3DESEncryptCBC Encry End");

    memcpy(szDatan, szDataInBackup, inLen);
    
    return NMX_OK;
}

int inCTOSS_NMX_3DESDecryptCBC(unsigned char *szTMK, unsigned char *szDatanEncrypt, int inLen, unsigned char *szOutputData)
{
    unsigned long aulIV[8] = {0};
    unsigned long aulPlain[8] = {0};
    unsigned char szDataInBackup[1024];
    unsigned char szDataBK[1024] = {0};
    int i,j,k;
    int iTotalBlock;

    vdNMX_Debug_LogPrintf("inCTOSS_NMX_3DESDecryptCBC Decry Start inLen[%d]", inLen);
    vdNMX_DebugAddHEX("TMK",szTMK, 16);
    vdNMX_DebugAddHEX("DataIn",szDatanEncrypt, inLen);

    memcpy(szDataInBackup, szDatanEncrypt, inLen);
    
    memset(aulIV, 0x00, sizeof(aulIV));
    memcpy(szDataBK, szDatanEncrypt, inLen);
    iTotalBlock = inLen/8;
    j = 0;
    
    for (i = 0; i < iTotalBlock; i++)
	{
		j = i * 8;

        CTOS_DES (d_DECRYPTION, &szTMK[0], 8, (char *)&szDatanEncrypt[j], 8, (char *)&szDatanEncrypt[j]);	//Encrypt
		CTOS_DES (d_ENCRYPTION, &szTMK[8], 8, (char *)&szDatanEncrypt[j], 8, (char *)&szDatanEncrypt[j]);	//Decrypt
		CTOS_DES (d_DECRYPTION, &szTMK[0], 8, (char *)&szDatanEncrypt[j], 8, (char *)&szDatanEncrypt[j]);	//Encrypt

		memcpy (aulPlain, szDatanEncrypt + j, 8);
		for (k = 0; k < 2; k++)
		{
			aulPlain[k] = aulPlain[k] ^ aulIV[k];		//Plaintext XOR with 
		}											//previous Cipher Block
		memcpy (szDatanEncrypt + j, aulPlain, 8);
		memcpy (aulIV, szDataBK + j, 8);
	}

    memcpy (szOutputData, szDatanEncrypt, inLen);

    vdNMX_DebugAddHEX("DataOut",szOutputData, inLen);
    vdNMX_Debug_LogPrintf("inCTOSS_NMX_3DESDecryptCBC Decry End");

    memcpy(szDatanEncrypt, szDataInBackup, inLen);
    
    return NMX_OK;
}

int	inCTOSS_NMX_GenKID (unsigned long ul_ID, char *sz_KID, int *pi_KIDLen)
{
	unsigned long	ulRes = ul_ID;			//Division Result
	int				iRmdr = 0;				//Remainder
	char			aszKID[KID_LENGTH + 1];
	int				iIdx = KID_LENGTH - 1;

	if (KID_LENGTH + 1 > *pi_KIDLen) return -1;

	//Clears KID Buffer
	memset (aszKID, 0x00, KID_LENGTH + 1);
	
	//Divide by KID_DIVIDER and get Remainder
	while (1)
	{
		iRmdr = (int)(ulRes % (unsigned long)KID_DIVIDER);
		ulRes = ulRes / (unsigned long)KID_DIVIDER;
		
		if (0 > iIdx) { break;}
		aszKID[iIdx--] = iRmdr + 35;
		
		if (KID_DIVIDER > ulRes) { break;}
	}
	aszKID[iIdx--] = (int)ulRes + 35;
	
	//Pad with Special KID_PAD_CHR
	for (; iIdx >= 0; iIdx--)
	{
		aszKID[iIdx] = KID_PAD_CHR;
	}

	//Copy to Output Buffer
	memcpy (sz_KID, aszKID, KID_LENGTH + 1);
	*pi_KIDLen = KID_LENGTH + 1;
	
	return 0;
}


int	inCTOSS_NMX_GetKIDNo (char *sz_KID, int i_KIDLen, unsigned long *pul_ID)
{
	char aszKID[KID_LENGTH + 1];
	unsigned long ulRes;
	unsigned long ulMul;

	int i	 = 0;
	int iLen = 0;

	i_KIDLen = strlen (sz_KID);
	if (KID_LENGTH != i_KIDLen) return -1;

	memset (aszKID, 0x00, KID_LENGTH + 1);
	memcpy (aszKID, sz_KID, i_KIDLen);

	// find out how many chars are actually being used		
	i = 0;
	while (aszKID[i] == KID_PAD_CHR)
	{i++;}

	iLen = i;

	// calculate the correct multiplier for the first digit
	ulMul = 1L;
	for (i = 0; i < (KID_LENGTH - iLen - 1); i++)
		ulMul *= KID_DIVIDER;

	ulRes = 0L;
	for (i = iLen; i < KID_LENGTH; i++)
	{		
		ulRes = ulRes + (ulMul * (aszKID[i] - 35));
		ulMul /= KID_DIVIDER;		
	}

	*pul_ID = ulRes;
	return 0;
}

int inCTOSS_NMX_GetApplicationKey(IN unsigned char *byTSK, OUT unsigned char *byAppKey, OUT char *szErrResponse)
{
    BYTE byEncryptKey[24 + 1];
    BYTE byClearKey[24 + 1];
    BYTE byAppKeyKCV[2 + 1];
    BYTE byKCV[3 + 1];

    int inResult;
    
    unsigned char szNULLBuffer[16 + 1];
    unsigned char szKCVOutBuf[16 + 1];
    int inEncryptLen;

#ifdef SMART_CARD_TEST_ONLY
    memcpy(byAppKey, "\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF", 16);
    return NMX_OK;    
#endif

    inResult = inCTOSS_NMX_SmartCardRequestAppKey(byEncryptKey, &inEncryptLen, byKCV, szErrResponse);
    vdNMX_Debug_LogPrintf("inCTOSS_NMX_SmartCardRequestAppKey inResult[%d] ", inResult);
    if(NMX_OK != inResult)
        return inResult;
    
    inResult = inCTOSS_NMX_3DESDecryptCBC(byTSK, byEncryptKey, inEncryptLen, byClearKey);
    vdNMX_Debug_LogPrintf("inCTOSS_NMX_3DESDecryptCBC inResult[%d] ", inResult);
    if(NMX_OK != inResult)
        return inResult;
    
    memset(szNULLBuffer, 0x00, sizeof(szNULLBuffer));
    inCTOSS_NMX_3DESEncryptCBC(byClearKey, szNULLBuffer, 8, szKCVOutBuf);
    vdNMX_Debug_LogPrintf("byKCV [%02X %02X] szNULLBuffer[%02X %02X]", byKCV[0], byKCV[1], szKCVOutBuf[0], szKCVOutBuf[1]);
    //if(0 != memcmp(szKCVOutBuf, byKCV, 2))
    //    return NMX_GET_APPKEY_ERR;


    memcpy(byAppKey, byClearKey, 16);
    
    return NMX_OK;
}


void vdCTOSS_NMX_XOR (unsigned char *pbt_Data1, unsigned char *pbt_Data2, int i_DataLen, unsigned char *pbt_Output)
{
	int i = 0;
	for (i = 0; i < i_DataLen; i++)
	{
		pbt_Output[i] = pbt_Data1[i] ^ pbt_Data2[i];
	}
}


int inCTOSS_NMX_WaitingForSmartCard(void)
{
    DWORD dwWait=0, dwWakeup=0;
    USHORT ret;
    BYTE key;
    BYTE bySC_status;
    
    CTOS_LCDTClearDisplay();
    CTOS_LCDTPrintXY(1, 7, "PLS INSERT SMART CARD");

    while(1)
    {
        dwWait = d_EVENT_KBD | d_EVENT_SC;

        ret = CTOS_SystemWait(200, dwWait, &dwWakeup);

        CTOS_SCStatus(d_SC_SAM1, &bySC_status);

        if ((dwWakeup & d_EVENT_KBD) == d_EVENT_KBD)
        {
            CTOS_KBDGet(&key);

            if(key == d_KBD_CANCEL)
                return NMX_CANCEL;
        }
        else if (((dwWakeup & d_EVENT_SC) == d_EVENT_SC) || (bySC_status & d_MK_SC_PRESENT))
        {
            return NMX_OK;
        }
    }
}

void vdCTOSS_NMX_RemoveCard(void)
{
    BYTE bySC_status;

    CTOS_LCDTClearDisplay();
    
    while(1)
    {
            
        CTOS_SCStatus(d_SC_SAM1, &bySC_status);
        if(bySC_status & d_MK_SC_PRESENT)
        {
            CTOS_LCDTPrintXY(1, 7,"PLEASE REMOVE CARD");
            CTOS_Beep();
            CTOS_Delay(300);
            CTOS_Beep();
            continue;
        }
        
        break;
    }
}

int inNMX_SHA1(unsigned char *InputBuffer, unsigned long nb, unsigned char *sha20)
{
    SHA_CTX SHA_CTX;
    BYTE baSHA[32];

    //Initialize the SHA_CTX structure and perpart for the SHA1 operation //                                     
    CTOS_SHA1Init(&SHA_CTX);

    //Perform the SHA1 algorithm with the input data //                                                     
    CTOS_SHA1Update(&SHA_CTX,InputBuffer, nb);                                                          
                                                                                                          
    //Finalize the SA1 operation and retrun the result //                                                   
    CTOS_SHA1Final(baSHA,&SHA_CTX);        
    
    memcpy(sha20, baSHA, 20);
    
    return NMX_OK;
}


int inCTOSS_NMX_InitSecureChannel (unsigned char *i_pcAcquirerID, unsigned char *i_pcVendorID, unsigned char *o_pucTSK, int *o_piKeyLen, OUT char *szErrResponse)
{
    unsigned char szRandomNumber[16 + 1];
    unsigned char szRandomNumHex[20 + 1];
    unsigned char szNULLBuffer[20 + 1];
    unsigned char szAcqIDHex[20 + 1];
    unsigned char szVendorIDHex[20 + 1];
    unsigned char szCryptogramX[20 + 1];
    unsigned char szEncryptTSK[20 + 1];
    unsigned char szHexA[10 + 1];
    unsigned char szHexB[10 + 1];
    unsigned char szHexC[10 + 1];
    unsigned char szHexD[10 + 1];
    unsigned char szHexAD[10 + 1];
    unsigned char szHexBC[10 + 1];
    unsigned char szHexADBC[20 + 1];
    unsigned char szHexF[20 + 1];
    unsigned char szHexG[30 + 1];
    unsigned char szClearTSK[20 + 1];
    unsigned char szKCV[8 + 1];
    unsigned char szIAKKCV[8 + 1];
    unsigned char szIAK[16 + 1];
    int inResult;

    vdNMX_Debug_LogPrintf("test inCTOSS_NMX_InitSecureChannel");
    
    vdCTOSS_NMX_getRandomNumber(szRandomNumber, 16);
    
//#ifdef SMART_CARD_TEST_ONLY
    //strcpy(szRandomNumber, "0102030405060708");                       
//#endif

    memset(szNULLBuffer, 0x00, sizeof(szNULLBuffer));
    memset(szAcqIDHex, 0x00, sizeof(szAcqIDHex));
    memset(szVendorIDHex, 0x00, sizeof(szVendorIDHex));
    memset(szRandomNumHex, 0x00, sizeof(szRandomNumHex));
    memset(szIAK, 0x00, sizeof(szIAK));

	
    inNMX_str_2_hex(szRandomNumber, szRandomNumHex, 16);
    inNMX_str_2_hex(i_pcAcquirerID, szAcqIDHex, 40);
    inNMX_str_2_hex(i_pcVendorID, szVendorIDHex, 40);

	//vdDebug_LogPrintf("szAcqIDHex %s", szAcqIDHex);
	//vdDebug_LogPrintf("szVendorIDHex %s", szVendorIDHex);


    memset(szHexA, 0x00, sizeof(szHexA));
    memset(szHexB, 0x00, sizeof(szHexA));
    memset(szHexC, 0x00, sizeof(szHexA));
    memset(szHexD, 0x00, sizeof(szHexA));
    memset(szHexAD, 0x00, sizeof(szHexAD));
    memset(szHexBC, 0x00, sizeof(szHexBC));
    memset(szHexADBC, 0x00, sizeof(szHexADBC));
    memset(szHexF, 0x00, sizeof(szHexF));
    memset(szHexG, 0x00, sizeof(szHexG));

	DebugAddHEX("i_pcAcquirerID ",i_pcAcquirerID,20);
	DebugAddHEX("i_pcVendorID ",i_pcVendorID,20);

    memcpy(szHexA, i_pcAcquirerID, 10);
    memcpy(szHexB, i_pcAcquirerID+10, 10);
    memcpy(szHexC, i_pcVendorID, 10);
    memcpy(szHexD, i_pcVendorID+10, 10);


	DebugAddHEX("szHexA ",szHexA,10);
	DebugAddHEX("szHexB ",szHexB,10);
	DebugAddHEX("szHexC ",szHexC ,10);
	DebugAddHEX("szHexD ",szHexD,10);


    vdCTOSS_NMX_XOR(szHexA, szHexD, 10, szHexAD);
	DebugAddHEX("szHexAD ",szHexAD, 20);

    vdCTOSS_NMX_XOR(szHexB, szHexC, 10, szHexBC);
	vdDebug_LogPrintf("szHexBC %s",szHexBC);

    memcpy(szHexADBC, szHexAD, 10);
    memcpy(szHexADBC+10, szHexBC, 10);
	DebugAddHEX("szHexADBC ",szHexADBC,20);

    vdCTOSS_NMX_XOR(szHexADBC, szRandomNumHex, 20, szHexF);

	DebugAddHEX("szHexF ",szHexF,20);

    inNMX_SHA1(szHexF, 20, szHexG);
    memcpy(szIAK, szHexG, 16);
	DebugAddHEX("szHexG",szHexG,20);


    DebugAddHEX("szHexADBC %s", szHexADBC, 20);
    DebugAddHEX("szHexF %s", szHexF, 20);
    DebugAddHEX("szHexG %s", szHexG, 20);
   
    DebugAddHEX("IAK %s", szIAK, 16);
    
    memset(szCryptogramX, 0x00, sizeof(szCryptogramX));
    inCTOSS_NMX_3DESEncryptCBC(szIAK, szRandomNumHex, 8, szCryptogramX);

    DebugAddHEX("szRandomNumHex", szRandomNumHex, 8);
    DebugAddHEX("szCryptogramX", szCryptogramX, 8);
    
    memset(szNULLBuffer, 0x00, sizeof(szNULLBuffer));
    memset(szEncryptTSK, 0x00, sizeof(szEncryptTSK));
    memset(szKCV, 0x00, sizeof(szKCV));
    inResult = inCTOSS_NMX_SmartCardSendCryptogramXGetTSK(szCryptogramX, szRandomNumHex, szEncryptTSK, szKCV, szErrResponse);
    if(NMX_OK != inResult)
        return inResult;
    
    DebugAddHEX("eTSK", szEncryptTSK, 16);

    memset(szClearTSK, 0x00, sizeof(szClearTSK));
    inCTOSS_NMX_3DESEncryptCBC(szIAK, szEncryptTSK, 16, szClearTSK);
    DebugAddHEX("TSK", szClearTSK, 16);

    memset(szNULLBuffer, 0x00, sizeof(szNULLBuffer));
    inCTOSS_NMX_3DESEncryptCBC(szClearTSK, szNULLBuffer, 8, szIAKKCV);

    vdDebug_LogPrintf("IAK KCV[%02X %02X]  KCV ResponseFromCard[%02X %02X]", szIAKKCV[0], szIAKKCV[1], szKCV[0], szKCV[1]);
    if(0 != memcmp(szIAKKCV, szKCV, 2))
        return NMX_GET_TSK_ERR;
    
    *o_piKeyLen = 16;
    memcpy(o_pucTSK, szClearTSK, 16);
    
    DebugAddHEX("TSK", o_pucTSK, 16);
    
    return NMX_OK;
}

int inCTOSS_NMX_MutualAuthentication (unsigned char *szTSK, OUT unsigned char *szRndA1B2B1A2, OUT char *szErrResponse)
{
    int inResult;
    unsigned char szRandomNumber[16 + 1];
    unsigned char szApplKey[16 + 1];
    unsigned char szEncryptRndA1A2[16 + 1];
    unsigned char szEnRndA1B2B1A2[16 + 1];
    unsigned char szClearRndA1B2B1A2[16 + 1];
    unsigned char szClearRndB1B2[16 + 1];
    unsigned char szEnRndB1B2[16 + 1];

    vdNMX_Debug_LogPrintf("inCTOSS_NMX_MutualAuthentication");
    
    vdCTOSS_NMX_getRandomHexData(szRandomNumber, 8);

#ifdef SMART_CARD_TEST_ONLY
    memcpy(szRandomNumber,  "\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8", 8);
#endif

    memset(szApplKey, 0x00, sizeof(szApplKey));
    inResult = inCTOSS_NMX_GetApplicationKey(szTSK, szApplKey, szErrResponse);
    vdNMX_Debug_LogPrintf("inCTOSS_NMX_GetApplicationKey inResult[%d]", inResult);
    //if(NMX_OK != inResult)
    //    return inResult;

    inCTOSS_NMX_3DESEncryptCBC(szApplKey, szRandomNumber, 8, szEncryptRndA1A2);

    
    vdNMX_DebugAddHEX("eRndA1RndA2", szEncryptRndA1A2, 8);

    inResult = inCTOSS_NMX_SmartCardInitMutualAuth(szEncryptRndA1A2,  szEnRndA1B2B1A2, szErrResponse);
    //if(NMX_OK != inResult)
    //    return inResult;

    DebugAddHEX("szEnRndA1B2B1A2", szEnRndA1B2B1A2, 16);
    
    inCTOSS_NMX_3DESEncryptCBC(szApplKey, szEnRndA1B2B1A2, 16, szClearRndA1B2B1A2);

    vdNMX_DebugAddHEX("szApplKey", szApplKey, 16);
    vdNMX_DebugAddHEX("szClearRndA1B2B1A2", szClearRndA1B2B1A2, 16);

    vdNMX_DebugAddHEX("szRandomNumber", szRandomNumber, 16);
    //ensure RndA1 and RndA2 is the correct
    if(0 != memcmp(szRandomNumber, szClearRndA1B2B1A2, 4) || 0 != memcmp(szRandomNumber+4, szClearRndA1B2B1A2+12, 4))
    {
        vdNMX_Debug_LogPrintf("error ");
        return NMX_MULTI_AUTH_ERR;
    }

    memcpy(szClearRndB1B2, szClearRndA1B2B1A2+8, 4);
    memcpy(szClearRndB1B2+4, szClearRndA1B2B1A2+4, 4);

    inCTOSS_NMX_3DESEncryptCBC(szApplKey, szClearRndB1B2, 8, szEnRndB1B2);

    DebugAddHEX("szEnRndB1B2", szEnRndB1B2, 8);
    
    inResult = inCTOSS_NMX_SmartCardMutualAuth(szEnRndB1B2, szErrResponse);
    if(NMX_OK != inResult)
        return inResult;

    memcpy(szRndA1B2B1A2, szClearRndA1B2B1A2, 16);
    DebugAddHEX("szRndA1B2B1A2", szRndA1B2B1A2, 16);

    return NMX_OK;
}

int inCTOSS_NMX_PINVerification (unsigned char *szRndA1B2B1A2, OUT char *szErrResponse)
{
    unsigned char szSmartCardPIN[32 + 1];
    unsigned char szSmartPINHex[16 + 1];
    unsigned char szEncrySmartPIN[16 + 1];
    int inLen = 0;
    int inPad = 0;


    memset(szSmartCardPIN, 0x00, sizeof(szSmartCardPIN));
    srNMXLibFunc.vdEnterSmartCardPIN(szSmartCardPIN);
    
    vdDebug_LogPrintf("inCTOSS_NMX_PINVerification [%s]", szSmartCardPIN);
    inLen = strlen(szSmartCardPIN);

    if(0 == inLen)
        return NMX_CANCEL;

    memset(szSmartPINHex, 0x00, sizeof(szSmartPINHex));
    memcpy(szSmartPINHex, szSmartCardPIN, inLen);
    if(0 != inLen%8)
    {
        szSmartPINHex[inLen] = 0x80;
        inLen = (inLen/8 + 1) * 8;
    }
    
    memset(szEncrySmartPIN, 0x00, sizeof(szEncrySmartPIN));
    inCTOSS_NMX_3DESEncryptCBC(szRndA1B2B1A2, szSmartPINHex, inLen, szEncrySmartPIN);

    inLen = inCTOSS_NMX_SmartCardPINVerifyRequest(szEncrySmartPIN, inLen, szErrResponse);
    if(NMX_OK != inLen)
        return inLen;
    
    return NMX_OK;
}

int inCTOSS_NMX_ChangePIN (unsigned char *szRndA1B2B1A2, OUT char *szErrResponse)
{
    unsigned char szSmartCardPIN[32 + 1];
    unsigned char szSmartPINHex[16 + 1];
    unsigned char szEncrySmartPIN[16 + 1];
    int inLen = 0;
    int inPad = 0;

    
    memset(szSmartCardPIN, 0x00, sizeof(szSmartCardPIN));
    srNMXLibFunc.vdEnterSmartCardNewPIN(szSmartCardPIN);
    
    vdNMX_Debug_LogPrintf("inCTOSS_NMX_ChangePIN [%s]", szSmartCardPIN);
    inLen = strlen(szSmartCardPIN);

    if(0 == inLen)
        return NMX_CANCEL;

    memset(szSmartPINHex, 0x00, sizeof(szSmartPINHex));
    memcpy(szSmartPINHex, szSmartCardPIN, inLen);
    if(0 != inLen%8)
    {
        szSmartPINHex[inLen] = 0x80;
        inLen = (inLen/8 + 1) * 8;
    }

    memset(szEncrySmartPIN, 0x00, sizeof(szEncrySmartPIN));
    inCTOSS_NMX_3DESEncryptCBC(szRndA1B2B1A2, szSmartPINHex, inLen, szEncrySmartPIN);

    inLen = inCTOSS_NMX_SmartCardPINChangeRequest(szEncrySmartPIN, inLen, szErrResponse);
    if(NMX_OK != inLen)
        return inLen;
    
    return NMX_OK;
}


int inCTOSS_NMX_FormRKIorTLEDownloadMessage(int inType, IN unsigned char *szTPDU, IN unsigned long ulTraceNO, IN unsigned char *szTID, IN unsigned char *szMID, unsigned char *byPayloadDE57, int inDE57Len, unsigned char *bySendData, int *inSendDataLen)
{
    int inLen = 0;
    int inOutputLen;
    char szHexBuf[3+1];
    char szAsicBuf[255+1];
    char szTPDUHex[5+1];

    memset(szTPDUHex, 0x00, sizeof(szTPDUHex));
    inNMX_str_2_hex(szTPDU, szTPDUHex, 10);
    
    memcpy(&bySendData[inLen], szTPDUHex, 5);
    inLen += 5;

    memcpy(&bySendData[inLen], "\x08\x00", 2);
    inLen += 2;

    memcpy(&bySendData[inLen], "\x20\x20\x01\x00\x00\xC0\x00\x80", 8);
    inLen += 8;

    //DE 3
    if(1 == inType)
        memcpy(&bySendData[inLen], "\x95\x00\x01", 3);  //RKI
    else
        memcpy(&bySendData[inLen], "\x95\x00\x00", 3);  //TLE download
    inLen += 3;

    memset(szAsicBuf, 0x00, sizeof(szAsicBuf));
    sprintf(szAsicBuf, "%06ld", ulTraceNO);
    inNMX_str_2_hex(szAsicBuf, szHexBuf, 6);

    //DE 11
    memcpy(&bySendData[inLen], szHexBuf, 3);
    inLen += 3;

    //DE 24
    memcpy(&bySendData[inLen], &szTPDUHex[1], 2);
    inLen += 2;

    //DE 41
    memset(&bySendData[inLen], 0x00, 8);
    memcpy(&bySendData[inLen], szTID, strlen(szTID));
    inLen += 8;

    //DE 42
    memset(&bySendData[inLen], 0x00, 15);
    memcpy(&bySendData[inLen], szMID, strlen(szMID));
    inLen += 15;

    //DE 57
    memset(szAsicBuf, 0x00, sizeof(szAsicBuf));
    sprintf(szAsicBuf, "%04d", inDE57Len);
    inNMX_str_2_hex(szAsicBuf, szHexBuf, 4);
    memcpy(&bySendData[inLen], szHexBuf, 2);
    inLen += 2;
    memcpy(&bySendData[inLen], byPayloadDE57, inDE57Len);
    inLen += inDE57Len;

    *inSendDataLen = inLen;
    
    DebugAddHEX("ISO", bySendData, inLen);
    
{
/*
    "4D444D794E444178"
    "41565A344E544977414441414D41"
    "4177414441414D41417741444141"
    "4D414177414441414D4141774144"
    "41414D414177415449344D533079"
    "4E7A45744D546734414441414D41"
    "4177414441414D41417741444141"
    "4D41417741544178415441774E7A"
    "5978414441414D41417741444141"
    "4D414177414441414D4141774144"
    "41414D414177414441414D414177"
    "41592F69726E5158696852766B31"
    "4D72436B6C412B5345424E6B4D34"
    "51773D3D"
*/
 //   "4D444D794E44417841565A344E544977414441414D414177414441414D414177414441414D414177414441414D414177414441414D414177415449344D5330794E7A45744D546734414441414D414177414441414D414177414441414D41417741544178415441774E7A5978414441414D414177414441414D414177414441414D414177414441414D414177414441414D41417741592F69726E5158696852766B314D72436B6C412B5345424E6B4D3451773D3D"

/*
    char szTestBUF1[1024];
    char szTestBUF2[1024];
    int inTestLen;
    int inOutputLen;
    memset(szTestBUF1, 0x00, sizeof(szTestBUF1));
    memset(szTestBUF2, 0x00, sizeof(szTestBUF2));
    strcpy(szTestBUF1, "4D444D794E44417841565A344E544977414441414D414177414441414D414177414441414D414177414441414D414177414441414D414177415449344D5330794E7A45744D546734414441414D414177414441414D414177414441414D41417741544178415441774E7A5978414441414D414177414441414D414177414441414D414177414441414D414177414441414D41417741592F69726E5158696852766B314D72436B6C412B5345424E6B4D3451773D3D");
    inTestLen = strlen(szTestBUF1);
    inNMX_str_2_hex(szTestBUF1,szTestBUF2,inTestLen);

    inTestLen = inTestLen/2;
    inOutputLen = 1024;
    vdNMX_DebugAddHEX("En DE57", szTestBUF2, inTestLen);
    iDecode64(szTestBUF2, inTestLen, szTestBUF1, &inOutputLen);
    inTestLen = inOutputLen;
    vdNMX_DebugAddHEX("iDecode64", szTestBUF1, inTestLen);

    
    iDecode250 (szTestBUF1, inTestLen, szTestBUF2, &inOutputLen);
    inTestLen = inOutputLen;
    vdNMX_DebugAddHEX("iDecode250", szTestBUF2, inTestLen);
*/
}    
    return NMX_OK;
}

int inCTOSS_AnalyseRKIKeyInjectionResponse(IN unsigned char *szTSK, IN unsigned char *szRndA1B2B1A2, IN unsigned char *szResponseMessage,IN int inResponseLen, IN unsigned long ulTraceNO, IN unsigned char *szTID, OUT char *szErrResponse)
{
    int i = 0;
    int inResult;
    unsigned char szHexBuf[3+1];
    unsigned char szAsicBuf[6+1];
    unsigned char szRespCode[2+1];
    unsigned char szDEK[16+1];
    unsigned char szMEK[16+1];
    unsigned char szClearDEK[16+1];
    unsigned char szClearMEK[16+1];
    
    int inDE57Len;
    unsigned char szDE57[256];

    unsigned char szClearKeyResponse[256];

    vdDebug_LogPrintf("inCTOSS_AnalyseRKIKeyInjectionResponse");
    DebugAddHEX("szResponseMessage", szResponseMessage, inResponseLen);
    
    i = 0;
    i += 5; //TPDU
    if(0 != memcmp(&szResponseMessage[i], "\x08\x10", 2))
        return NMX_INVALID_RESP;
    i += 2; //MTI
    i += 8; //Bitmap
    if(0 != memcmp(&szResponseMessage[i], "\x95\x00\x01", 3))
        return NMX_INVALID_RESP;
    i += 3; //Processing code

    memset(szAsicBuf, 0x00, sizeof(szAsicBuf));
    sprintf(szAsicBuf, "%06ld", ulTraceNO);
    inNMX_str_2_hex(szAsicBuf, szHexBuf, 6);
    if(0 != memcmp(&szResponseMessage[i], szHexBuf, 3))
        return NMX_INVALID_RESP;
    i += 3; //Processing code

    i += 3; //Transaction Time 
    i += 2; //Transaction Date 
    i += 2; //NII
    i += 12;//Reference number
    
    memset(szRespCode, 0x00, sizeof(szRespCode));
    memcpy(szRespCode, &szResponseMessage[i], 2);
    i += 2; //Response code

    if(0 != memcmp(&szResponseMessage[i], szTID, 8))
        return NMX_INVALID_RESP;
    i += 8; //TID

    if(0 == memcmp(szRespCode, "ER", 2))
    {   
        if(szResponseMessage[14] & 0x04) //DE62
        {
            memcpy(szHexBuf, &szResponseMessage[i], 2);
            inNMX_hex_2_str((char*)szHexBuf, (char*)szAsicBuf, 2);
            szAsicBuf[4] = 0x00;
            memcpy(szErrResponse, &szResponseMessage[i+2], atoi(szAsicBuf));
        }

        return NMX_HOST_REJECT;
    }
    else
    {
        //test only
        //int inTestHostRespLen;
        //char szTestHostResponse[512];

        //memset(szTestHostResponse, 0x00, sizeof(szTestHostResponse));
        //strcpy(szTestHostResponse, "60000002700810203801000A800080950001000383161541041402703232323330393331343135373030323133313030343501564D444D794E444178415441784165726A78596D51304E51316D664E586B394F6273536E74392F7972615969307248655558463071545173414D4E376E453577304144534D373758416E627652523078784A33755751596D366A775A426F736573453573414E58315454667A387277354E3769497535794267437A4E52727371766773684F57717039317A3070334C544C7A47705A4B78316A5957762F");
        //inTestHostRespLen = strlen(szTestHostResponse);
        //wub_str_2_hex(szTestHostResponse, szResponseMessage, inTestHostRespLen);
        
        if(szResponseMessage[14] & 0x80) //DE57
        {
            char szTestBUF1[1024];
            char szTestBUF2[1024];
            char szDEKKCV[10];
            char szMEKKCV[10];
            unsigned char szNULLBuffer[16 + 1];
            unsigned char szKCVOutBuf[16 + 1];
            int inTestLen;
            int inOutputLen;

            memset(szTestBUF1, 0x00, sizeof(szTestBUF1));
            memset(szTestBUF2, 0x00, sizeof(szTestBUF2));
            
            memcpy(szHexBuf, &szResponseMessage[i], 2);
            inNMX_hex_2_str((char*)szHexBuf, (char*)szAsicBuf, 2);
            szAsicBuf[4] = 0x00;
            memset(szDE57, 0x00, sizeof(szDE57));
            inDE57Len = atoi(szAsicBuf);
            memcpy(szTestBUF1, &szResponseMessage[i+2], inDE57Len);
            inTestLen = inDE57Len;
            inOutputLen = 1024;
            DebugAddHEX("En DE57", szTestBUF1, inTestLen);
            iDecode64(szTestBUF1, inTestLen, szTestBUF2, &inOutputLen);
            inTestLen = inOutputLen;
            DebugAddHEX("iDecode64", szTestBUF2, inTestLen);
            inOutputLen = 1024;
            iDecode250 (szTestBUF2, inTestLen, szTestBUF1, &inOutputLen);
            inTestLen = inOutputLen;
            DebugAddHEX("iDecode250", szTestBUF1, inTestLen);

            inDE57Len = inTestLen;
            memcpy(szDE57, szTestBUF1, inDE57Len);

            vdDebug_LogPrintf("Host Resnse EncryData[%d]", inDE57Len-10);
            DebugAddHEX("Host Resnse EncryData", &szDE57[10], inDE57Len-10);
            
            memset(szClearKeyResponse, 0x00, sizeof(szClearKeyResponse));
            inResult = inCTOSS_NMX_SmartCardAuthSession(&szDE57[10], inDE57Len-10, szClearKeyResponse, szErrResponse);
            if(NMX_OK != inResult)
                return NMX_AUTH_SESSION_ERR;

            inCTOSS_NMX_Read(1);
            memcpy((char*)srNMXHeader.szRKIKID, szClearKeyResponse, 6);
            memcpy((char*)srNMXHeader.szTLEKID, &szClearKeyResponse[51], 6);

            vdDebug_LogPrintf("srNMXHeader.szRKIKID[%s] srNMXHeader.szTLEKID[%s]", srNMXHeader.szRKIKID, srNMXHeader.szTLEKID);
            //testing only, can't test here, just in case save database error, 
            memset(g_szTestTLEKID, 0x00, sizeof(g_szTestTLEKID));
            strcpy(g_szTestTLEKID, srNMXHeader.szTLEKID);

            
            DebugAddHEX("g_szTestTLEKID", g_szTestTLEKID, 6);
            
            memset(szDEK, 0x00, sizeof(szDEK));
            memset(szMEK, 0x00, sizeof(szMEK));
            memcpy(szDEK, &szClearKeyResponse[7], 16);
            memcpy(szMEK, &szClearKeyResponse[29], 16);

            memset(szDEKKCV, 0x00, sizeof(szDEKKCV));
            memset(szMEKKCV, 0x00, sizeof(szMEKKCV));
            memcpy(szDEKKCV, &szClearKeyResponse[24], 4);
            memcpy(szMEKKCV, &szClearKeyResponse[46], 4);

            DebugAddHEX("RKI DEK", szDEK, 16);
            DebugAddHEX("RKI MEK", szMEK, 16);

            DebugAddHEX("RKI DEK KCV", szDEKKCV, 4);
            DebugAddHEX("RKI MEK KCV", szMEKKCV, 4);

            memset(szNULLBuffer, 0x00, sizeof(szNULLBuffer));
            inCTOSS_NMX_3DESEncryptCBC(szDEK, szNULLBuffer, 8, szKCVOutBuf);

            memset(szNULLBuffer, 0x00, sizeof(szNULLBuffer));
            inCTOSS_NMX_3DESEncryptCBC(szMEK, szNULLBuffer, 8, szKCVOutBuf);

            memset(szClearDEK, 0x00, sizeof(szClearDEK));
            memset(szClearMEK, 0x00, sizeof(szClearMEK));

            //inCTOSS_NMX_Save3DESClearKeyForEncrypt(srNMXHeader.inRKIDEKKeySet, srNMXHeader.inRKIKeyIndex, szDEK);
            //inCTOSS_NMX_Save3DESClearKeyForDecrypt(srNMXHeader.inRKIDEKKeySet, srNMXHeader.inRKIKeyIndex, szDEK);
            //inCTOSS_NMX_Save3DESClearKeyForEncrypt(srNMXHeader.inRKIMEKKeySet, srNMXHeader.inRKIKeyIndex, szMEK);
            //inCTOSS_NMX_Save3DESClearKeyForDecrypt(srNMXHeader.inRKIMEKKeySet, srNMXHeader.inRKIKeyIndex, szMEK);

			//testlang
			CTOS_KMS2Init();
			//endtest
            vdDebug_LogPrintf("RKI DEK  %d=%d",srNMXHeader.inRKIDEKKeySet, srNMXHeader.inRKIKeyIndex);
			vdDebug_LogPrintf("RKI MEK  %d=%d",srNMXHeader.inRKIMEKKeySet, srNMXHeader.inRKIKeyIndex);

            inCTOSS_NMX_SaveAESClearKeyForEncrypt(srNMXHeader.inRKIDEKKeySet, srNMXHeader.inRKIKeyIndex, szDEK);
            inCTOSS_NMX_SaveAESClearKeyForDecrypt(srNMXHeader.inRKIDEKKeySet, srNMXHeader.inRKIKeyIndex, szDEK);
            inCTOSS_NMX_SaveAESClearKeyForEncrypt(srNMXHeader.inRKIMEKKeySet, srNMXHeader.inRKIKeyIndex, szMEK);
            inCTOSS_NMX_SaveAESClearKeyForDecrypt(srNMXHeader.inRKIMEKKeySet, srNMXHeader.inRKIKeyIndex, szMEK);

            inCTOSS_TestSaveNMXRKIKey(szDEK, szMEK);

            memset(szDEK, 0x00, sizeof(szDEK));
            memset(szMEK, 0x00, sizeof(szMEK));
            memcpy(szDEK, &szClearKeyResponse[58], 16);
            memcpy(szMEK, &szClearKeyResponse[80], 16);

            memset(szDEKKCV, 0x00, sizeof(szDEKKCV));
            memset(szMEKKCV, 0x00, sizeof(szMEKKCV));
            memcpy(szDEKKCV, &szClearKeyResponse[75], 4);
            memcpy(szMEKKCV, &szClearKeyResponse[97], 4);

            DebugAddHEX("TLE DEK", szDEK, 16);
            DebugAddHEX("TLE MEK", szMEK, 16);

            DebugAddHEX("TLE DEK KCV", szDEKKCV, 4);
            DebugAddHEX("TLE MEK KCV", szMEKKCV, 4);

            memset(szNULLBuffer, 0x00, sizeof(szNULLBuffer));
            inCTOSS_NMX_3DESEncryptCBC(szDEK, szNULLBuffer, 8, szKCVOutBuf);

            memset(szNULLBuffer, 0x00, sizeof(szNULLBuffer));
            inCTOSS_NMX_3DESEncryptCBC(szMEK, szNULLBuffer, 8, szKCVOutBuf);

            memset(szClearDEK, 0x00, sizeof(szClearDEK));
            memset(szClearMEK, 0x00, sizeof(szClearMEK));


            vdDebug_LogPrintf("TLE DEK  %d=%d",srNMXHeader.inTLEDEKKeySet, srNMXHeader.inTLEKeyIndex);
			vdDebug_LogPrintf("TLE MEK  %d=%d",srNMXHeader.inTLEMEKKeySet, srNMXHeader.inTLEKeyIndex);

         
            inCTOSS_NMX_SaveAESClearKeyForEncrypt(srNMXHeader.inTLEDEKKeySet, srNMXHeader.inTLEKeyIndex, szDEK);
            inCTOSS_NMX_SaveAESClearKeyForDecrypt(srNMXHeader.inTLEDEKKeySet, srNMXHeader.inTLEKeyIndex, szDEK);

            //testlang-removelater
            srNMXHeader.inTLEMEKKeySet = 0xC001;
			srNMXHeader.inTLEKeyIndex = 0x0001;
			//inCTOSS_NMX_SaveAESClearKeyForEncrypt(srNMXHeader.inTLEMEKKeySet, srNMXHeader.inTLEKeyIndex, szMEK);
            //inCTOSS_NMX_SaveAESClearKeyForDecrypt(srNMXHeader.inTLEMEKKeySet, srNMXHeader.inTLEKeyIndex, szMEK);
            inCTOSS_NMX_Save3DESClearKeyForEncrypt(srNMXHeader.inRKIMEKKeySet, srNMXHeader.inRKIKeyIndex, szMEK);
            inCTOSS_NMX_Save3DESClearKeyForDecrypt(srNMXHeader.inRKIMEKKeySet, srNMXHeader.inRKIKeyIndex, szMEK);

            inCTOSS_TestSaveNMXTLEKey(szDEK, szMEK);
            
            inCTOSS_NMX_Save(1);
        }
        else
        {
            return NMX_INVALID_RESP;
        }
    }

    return NMX_OK;
}

int inCTOSS_AnalyseTLEDownloadResponse(IN unsigned char *szResponseMessage,IN int inResponseLen, IN unsigned long ulTraceNO, IN unsigned char *szTID, OUT char *szErrResponse)
{
    int i = 0;
    int inResult;
    unsigned char szHexBuf[3+1];
    unsigned char szAsicBuf[6+1];
    unsigned char szRespCode[2+1];
    unsigned char szDEK[16+1];
    unsigned char szMEK[16+1];
    
    int inDE57Len;
    unsigned char szDE57[256];

    unsigned char szClearKeyResponse[256];

    vdNMX_Debug_LogPrintf("inCTOSS_AnalyseTLEDownloadResponse");

    i = 0;
    i += 5; //TPDU
    if(0 != memcmp(&szResponseMessage[i], "\x08\x10", 2))
        return NMX_INVALID_RESP;
    i += 2; //MTI
    i += 8; //Bitmap
    if(0 != memcmp(&szResponseMessage[i], "\x95\x00\x00", 3))
        return NMX_INVALID_RESP;
    i += 3; //Processing code

    memset(szAsicBuf, 0x00, sizeof(szAsicBuf));
    sprintf(szAsicBuf, "%06ld", ulTraceNO);
    inNMX_str_2_hex(szAsicBuf, szHexBuf, 6);
    if(0 != memcmp(&szResponseMessage[i], szHexBuf, 3))
        return NMX_INVALID_RESP;
    i += 3; //Processing code

    i += 3; //Transaction Time 
    i += 2; //Transaction Date 
    i += 2; //NII
    i += 12;//Reference number
    
    memset(szRespCode, 0x00, sizeof(szRespCode));
    memcpy(szRespCode, &szResponseMessage[i], 2);
    i += 2; //Response code

    if(0 != memcmp(&szResponseMessage[i], szTID, 8))
        return NMX_INVALID_RESP;
    i += 8; //TID

    if(0 == memcmp(szRespCode, "ER", 2))
    {   
        if(szResponseMessage[14] & 0x04) //DE62
        {
            memcpy(szHexBuf, &szResponseMessage[i], 2);
            inNMX_hex_2_str((char*)szHexBuf, (char*)szAsicBuf, 2);
            szAsicBuf[4] = 0x00;
            memcpy(szErrResponse, &szResponseMessage[i+2], atoi(szAsicBuf));
        }

        return NMX_HOST_REJECT;
    }
    else
    {
        if(szResponseMessage[14] & 0x80) //DE57
        {            
            char szTestBUF1[1024];
            char szTestBUF2[1024];
            int inTestLen;
            int inOutputLen;
            
            inCTOSS_NMX_Read(1);

            memset(szTestBUF1, 0x00, sizeof(szTestBUF1));
            memset(szTestBUF2, 0x00, sizeof(szTestBUF2));

            memcpy(szHexBuf, &szResponseMessage[i], 2);
            inNMX_hex_2_str((char*)szHexBuf, (char*)szAsicBuf, 2);
            szAsicBuf[4] = 0x00;
            memset(szDE57, 0x00, sizeof(szDE57));
            inDE57Len = atoi(szAsicBuf);
            memcpy(szTestBUF1, &szResponseMessage[i+2], inDE57Len);
            inTestLen = inDE57Len;
            inOutputLen = 1024;
            vdNMX_DebugAddHEX("En DE57", szTestBUF1, inTestLen);
            iDecode64(szTestBUF1, inTestLen, szTestBUF2, &inOutputLen);
            inTestLen = inOutputLen;
            vdNMX_DebugAddHEX("iDecode64", szTestBUF2, inTestLen);
            inOutputLen = 1024;
            iDecode250 (szTestBUF2, inTestLen, szTestBUF1, &inOutputLen);
            inTestLen = inOutputLen;
            vdNMX_DebugAddHEX("iDecode250", szTestBUF1, inTestLen);

            inDE57Len = inTestLen;
            memcpy(szDE57, szTestBUF1, inDE57Len);

            memset(szClearKeyResponse, 0x00, sizeof(szClearKeyResponse));
            memcpy(szClearKeyResponse, &szDE57[10], inDE57Len-10);            
            vdNMX_DebugAddHEX("szClearKeyResponse", szClearKeyResponse, inDE57Len-10);
            
            memcpy((char*)srNMXHeader.szTLEKID, szClearKeyResponse, 6);

            memset(szDEK, 0x00, sizeof(szDEK));
            memset(szMEK, 0x00, sizeof(szMEK));
            memcpy(szDEK, &szClearKeyResponse[7], 16);
            memcpy(szMEK, &szClearKeyResponse[29], 16);

            vdNMX_DebugAddHEX("TLE DEK", szDEK, 16);
            vdNMX_DebugAddHEX("TLE MEK", szMEK, 16);

            inCTOSS_NMX_Save3DESClearKeyForEncrypt(srNMXHeader.inTLEDEKKeySet, srNMXHeader.inTLEKeyIndex, szDEK);
            inCTOSS_NMX_Save3DESClearKeyForDecrypt(srNMXHeader.inTLEDEKKeySet, srNMXHeader.inTLEKeyIndex, szDEK);
            inCTOSS_NMX_Save3DESClearKeyForEncrypt(srNMXHeader.inTLEMEKKeySet, srNMXHeader.inTLEKeyIndex, szMEK);
            inCTOSS_NMX_Save3DESClearKeyForDecrypt(srNMXHeader.inTLEMEKKeySet, srNMXHeader.inTLEKeyIndex, szMEK);

            inCTOSS_TestSaveNMXTLEKey(szDEK, szMEK);
            
            inCTOSS_NMX_Save(1);
        }
        else
        {
            return NMX_INVALID_RESP;
        }
    }

    return NMX_OK;
}


void vdCTOSS_NMX_TurnOnBit(unsigned char *uszBitmap, int inBit)
{
    int    inBitmapIndex, inBitIndex;

    inBitmapIndex = inBit/8;
    inBitIndex = inBit%8;
    if(0 == inBitIndex)
        inBitmapIndex--;

    switch(inBitIndex)
    {
        case 0:
            uszBitmap[inBitmapIndex] |= 0x01;
            break;
        case 1:
            uszBitmap[inBitmapIndex] |= 0x80;
            break;
        case 2:
            uszBitmap[inBitmapIndex] |= 0x40;
            break;
        case 3:
            uszBitmap[inBitmapIndex] |= 0x20;
            break;
        case 4:
            uszBitmap[inBitmapIndex] |= 0x10;
            break;
        case 5:
            uszBitmap[inBitmapIndex] |= 0x08;
            break;
        case 6:
            uszBitmap[inBitmapIndex] |= 0x04;
            break;
        case 7:
            uszBitmap[inBitmapIndex] |= 0x02;
            break;
        default:
            break;
    }
    
}

void vdCTOSS_NMX_TurnOffBit(unsigned char *uszBitmap, int inBit)
{
    int    inBitmapIndex, inBitIndex;

    inBitmapIndex = inBit/8;
    inBitIndex = inBit%8;
    if(0 == inBitIndex)
        inBitmapIndex--;

    switch(inBitIndex)
    {
        case 0:
            uszBitmap[inBitmapIndex] &= 0xFE;
            break;
        case 1:
            uszBitmap[inBitmapIndex] &= 0x7F;
            break;
        case 2:
            uszBitmap[inBitmapIndex] &= 0xBF;
            break;
        case 3:
            uszBitmap[inBitmapIndex] &= 0xDF;
            break;
        case 4:
            uszBitmap[inBitmapIndex] &= 0xEF;
            break;
        case 5:
            uszBitmap[inBitmapIndex] &= 0xF7;
            break;
        case 6:
            uszBitmap[inBitmapIndex] &= 0xFB;
            break;
        case 7:
            uszBitmap[inBitmapIndex] &= 0xFD;
            break;
        default:
            break;
    }
    
}

int inCTOSS_NMX_MACCalc(int inFinancialTxn, NMX_TLED_HEADER *srNMXHeader, unsigned char *msg, int msg_len, unsigned char *MAC)
{
    int inKeySet;
    int inKeyIndex;
    USHORT usRet;
    USHORT in_len_full;
    BYTE icv[24];
    USHORT icvlength;
    BYTE plaindata[1024];
    BYTE cipherdata[1024];
    CTOS_KMS2MAC_PARA macparams;

    if(MAC == NULL || msg == NULL)
        return(NMX_INVALID_PARA);

    memset(MAC, 0x00, 8);

    in_len_full = msg_len;

    if(in_len_full % 8 != 0)
        in_len_full = (((in_len_full / 8) + 1) * 8);

    memset(&macparams, 0x00, sizeof(macparams));        
    memset(plaindata, 0x00, sizeof(plaindata));


    //for testing
	inKeySet = 0xC001;
	inKeyIndex = 0x0001;
	strcpy(srNMXHeader->szMACAlgo, "3");
	vdDebug_LogPrintf("mac algo = %s", srNMXHeader->szMACAlgo);

	DebugAddHEX("msg ",msg,msg_len);


    
    macparams.Version = CTOS_KMS2_VERSION;
    macparams.Protection.CipherKeySet = inKeySet;
    macparams.Protection.CipherKeyIndex = inKeyIndex;
    //if(MAC_ALGO_ANSI_99 == srNMXHeader->szMACAlgo[0] || MAC_ALGO_SHA1_X99 == srNMXHeader->szMACAlgo[0])
        macparams.Protection.CipherMethod = KMS2_MACMETHOD_CBC;
    //else if(MAC_ALGO_ANSI_919 == srNMXHeader->szMACAlgo[0] || MAC_ALGO_SHA1_X919 == srNMXHeader->szMACAlgo[0])
    //    macparams.Protection.CipherMethod = KMS2_MACMETHOD_X9_19;

	memset(icv, 0x00, sizeof(icv));
	
    icvlength = 8;
    memcpy(plaindata, msg, msg_len);
    macparams.Input.Length = in_len_full;
    macparams.Input.pData = plaindata;
    macparams.ICV.Length = icvlength;
    macparams.ICV.pData = icv;
    macparams.Output.pData = cipherdata;

	vdDebug_LogPrintf("macparams.Version %d", macparams.Version);
 	vdDebug_LogPrintf("Protection.CipherKeySet %d", macparams.Protection.CipherKeySet);
   	vdDebug_LogPrintf("Protection.CipherKeyIndex %d", macparams.Protection.CipherKeyIndex);
   	vdDebug_LogPrintf("Protection.CipherMethod %d", macparams.Protection.CipherMethod);
    vdDebug_LogPrintf("macparams.Input.pData %s", macparams.Input.pData);
	vdDebug_LogPrintf("macparams.Input.Length %d", macparams.Input.Length);
	vdDebug_LogPrintf("macparams.ICV.Length %d", macparams.ICV.Length);
	vdDebug_LogPrintf("macparams.ICV.pData %s", macparams.ICV.pData);

	
    usRet = CTOS_KMS2MAC(&macparams);

    vdNMX_Debug_LogPrintf("CTOS_KMS2MAC usRet[%d]macparams.Output.Length[%d]", usRet, macparams.Output.Length);

    if(usRet)
    {
        return(NMX_CAL_MAC_ERR);
    }

    vdNMX_DebugAddHEX("Calc MAC", macparams.Output.pData,macparams.Output.Length);
    
    memcpy(MAC, macparams.Output.pData, 8);

    return(NMX_OK);

}

int inCTOSS_NMX_GenerateMAC(int inFinancialTxn, NMX_TLED_HEADER *srNMXHeader, unsigned char *inSendBuffer, int inPacketSize, unsigned  char *szMACValue)
{
    unsigned char uszMAC[16 + 1];
    unsigned char uszhash[20 + 1];
    unsigned char uszMACData[24 + 1];
    int inMACData = 0;

	//FOR TESTING
	//int Keyset, KeyIndex;
	//KeySet = 0xC001;
	//KeyIndex = 0x0001;


	vdDebug_LogPrintf("GENERATE mac");
	//FOR TESTING

    if (MAC_ALGO_SHA1_X99 == srNMXHeader->szMACAlgo[0] || MAC_ALGO_SHA1_X919 == srNMXHeader->szMACAlgo[0])
    {
        memset(uszhash, 0x00, sizeof(uszhash));
        inCTOSS_NMX__SHA1(inSendBuffer, inPacketSize, uszhash);

        memset(uszMACData, 0x00, sizeof(uszMACData));
        memcpy(uszMACData, uszhash, 20);
        inMACData = 24;

        vdNMX_DebugAddHEX("HASH", uszMACData, inMACData);

        memset(uszMAC, 0x00, sizeof(uszMAC));
        if(inCTOSS_NMX_MACCalc(inFinancialTxn, srNMXHeader, uszMACData, inMACData, uszMAC) != NMX_OK)
            return(NMX_CAL_MAC_ERR);
    }
    else
    {
        memset(uszMAC, 0x00, sizeof(uszMAC));
        if(inCTOSS_NMX_MACCalc(inFinancialTxn, srNMXHeader, inSendBuffer, inPacketSize, uszMAC) != NMX_OK)
            return(NMX_CAL_MAC_ERR);
    }

    vdNMX_DebugAddHEX("inCTOSS_NMX_GenerateMAC", uszMAC, 8);

    memcpy(szMACValue, uszMAC, 8);

    return NMX_OK;
}

void vdCTOSS_NMX_SetOddParity (unsigned char *pbt_Buff, int i_BuffLen)
{
	int iBit = 0, i = 0;

	//Calculate Number of 1 bits
	for (i = 0; i < i_BuffLen; i++)
	{
		iBit = ( (pbt_Buff[i] & 0x01) > 0 ) + 
			   ( (pbt_Buff[i] & 0x02) > 0 ) + 
			   ( (pbt_Buff[i] & 0x04) > 0 ) + 
			   ( (pbt_Buff[i] & 0x08) > 0 ) + 
			   ( (pbt_Buff[i] & 0x10) > 0 ) + 
			   ( (pbt_Buff[i] & 0x20) > 0 ) + 
			   ( (pbt_Buff[i] & 0x40) > 0 ) + 
			   ( (pbt_Buff[i] & 0x80) > 0 );

		//If Number of 1 bits is EVEN
		if ((iBit % 2) == 0)
			pbt_Buff[i] = (unsigned char) (pbt_Buff[i] ^ 0x01);	//Change the last bit
																//1 -> 0 or 0 - > 1
	}
}


int inCTOSS_NMX_GetCurrentTLEDEK(IN NMX_TLED_HEADER *srNMXHeader)
{	
	char aszPlain[APPID_SZ + KEYID_SZ + TXNCOUNTER_SZ + 1];
    unsigned long ulCounter;
    unsigned long ulKID;

    if(KEY_MANAGE_PER_TERMINAL == srNMXHeader->szKeyMag[0])
	{
	    vdNMX_Debug_LogPrintf("KEY_MANAGE_PER_TERMINAL");
	    return NMX_OK;
    }
    else if(KEY_MANAGE_PER_TXN == srNMXHeader->szKeyMag[0])
    {
        vdNMX_Debug_LogPrintf("KEY_MANAGE_PER_TXN szCounter[%s]szTLEKID[%s]szAppID[%s]", srNMXHeader->szCounter, srNMXHeader->szTLEKID, srNMXHeader->szAppID);
        
        //pad with NULL
        memset(aszPlain, 0x00, sizeof(aszPlain));
		//Use Key to encrypt AppID + KID + Counter
		sprintf (aszPlain, "%s%s%s", srNMXHeader->szCounter, 
									 srNMXHeader->szTLEKID, 
									 srNMXHeader->szAppID); 

        vdNMX_Debug_LogPrintf("aszPlain[%s]", aszPlain);
        memset(g_CurrentTLEDEK, 0x00, sizeof(g_CurrentTLEDEK));
		inCTOSS_NMX_KMS3DESEncryptData(srNMXHeader->inTLEDEKKeySet, srNMXHeader->inTLEKeyIndex, aszPlain, 16, g_CurrentTLEDEK);
        //only support TDES, so always  Result 1 len == DEK len, no need to encrypt again

		//Set Odd Parity
		vdCTOSS_NMX_SetOddParity (g_CurrentTLEDEK, 16);

        vdNMX_Debug_LogPrintf("ulCounter[%ld]", ulCounter);
        ulCounter = atol(srNMXHeader->szCounter);
        ulCounter ++;
        sprintf(srNMXHeader->szCounter, "%06ld", ulCounter);

        inCTOSS_NMX_GetKIDNo(srNMXHeader->szTLEKID, strlen(srNMXHeader->szTLEKID), &ulKID);

        vdNMX_Debug_LogPrintf("KID [%s] = [%ld]", srNMXHeader->szTLEKID, ulKID);
        ulKID ++;
        inCTOSS_NMX_GenKID(ulKID, srNMXHeader->szTLEKID, (int*)&ulCounter);
        vdNMX_Debug_LogPrintf("KID+ [%s] = [%ld]", srNMXHeader->szTLEKID, ulKID);

        inCTOSS_NMX_Save(1);
	}

    return NMX_OK;
}    

int inCTOSS_NMX_GetCurrentRKIDEK(IN NMX_TLED_HEADER *srNMXHeader)
{	
	char aszPlain[APPID_SZ + KEYID_SZ + TXNCOUNTER_SZ + 1];
    unsigned long ulCounter;
    unsigned long ulKID;

    if(KEY_MANAGE_PER_TERMINAL == srNMXHeader->szKeyMag[0])
	{
	    vdNMX_Debug_LogPrintf("RKIDEK KEY_MANAGE_PER_TERMINAL");
	    return NMX_OK;
    }
    else if(KEY_MANAGE_PER_TXN == srNMXHeader->szKeyMag[0])
    {
        vdNMX_Debug_LogPrintf("RKIDEK KEY_MANAGE_PER_TERMINAL szCounter[%s]szRKIKID[%s]szAppID[%s]", srNMXHeader->szCounter, srNMXHeader->szRKIKID, srNMXHeader->szAppID);
        
        //pad with NULL
        memset(aszPlain, 0x00, sizeof(aszPlain));
		//Use Key to encrypt AppID + KID + Counter
		sprintf (aszPlain, "%s%s%s", srNMXHeader->szCounter, 
									 srNMXHeader->szRKIKID, 
									 srNMXHeader->szAppID); 

        vdNMX_Debug_LogPrintf("RKIDEK aszPlain[%s]", aszPlain);
        memset(g_CurrentRKIDEK, 0x00, sizeof(g_CurrentRKIDEK));
		inCTOSS_NMX_KMS3DESEncryptData(srNMXHeader->inRKIDEKKeySet, srNMXHeader->inRKIKeyIndex, aszPlain, 16, g_CurrentRKIDEK);
        //only support TDES, so always  Result 1 len == DEK len, no need to encrypt again

		//Set Odd Parity
		vdCTOSS_NMX_SetOddParity (g_CurrentRKIDEK, 16);

        vdNMX_Debug_LogPrintf("ulCounter[%ld]", ulCounter);
        ulCounter = atol(srNMXHeader->szCounter);
        ulCounter ++;
        sprintf(srNMXHeader->szCounter, "%06ld", ulCounter);

        inCTOSS_NMX_GetKIDNo(srNMXHeader->szRKIKID, strlen(srNMXHeader->szRKIKID), &ulKID);

        vdNMX_Debug_LogPrintf("KID [%s] = [%ld]", srNMXHeader->szRKIKID, ulKID);
        ulKID ++;
        inCTOSS_NMX_GenKID(ulKID, srNMXHeader->szRKIKID, (int*)&ulCounter);
        vdNMX_Debug_LogPrintf("KID+ [%s] = [%ld]", srNMXHeader->szRKIKID, ulKID);

        inCTOSS_NMX_Save(1);
	}

    return NMX_OK;
}    


int inCTOSS_NMX_EncryptSensitiveFieldsData(IN int inFinancialTxn, IN NMX_TLED_HEADER *srNMXHeader, IN INOUT unsigned char *uszBitmap)
{
    unsigned char fieldEncryp[16+1];
    unsigned char fieldEncrypHex[16+1];
    unsigned char bEncrypt[16+1]; 
    unsigned char uszField57[1024];
    unsigned char uszCarrierField[1024];
    unsigned char uszeachFiled[255];
    unsigned char uszeachFiledOutput[255];
    unsigned char uszEncryOutBuf[1024];
    unsigned char uszFieldDataBuf[512+1];
    unsigned char uszLenAsic[4+1];
    //unsigned long aulPlain[8] = {0};
    //unsigned long aulIV[8] = {0};
    unsigned char ucBitSelector;
    char szTempBuf[100];
    char btFieldNum = 1;
    
    int i, j, k;
    //int iTotalBlock;
    int inTempDataLen;
    int inPadNum;
    int inResult;
    int inFieldDataLen;
    int inLoop;
    int inBitMapIndex;
    int inEncryptDataLen;
    int inCarrierFieldLen;
    int ineachFiledLen;
    int ineachFiledOutputLen;
    unsigned char* pucByte;    
    
    memset(fieldEncryp, 0, sizeof(fieldEncryp));
    memcpy((char *) fieldEncryp, srNMXHeader->szSensitiveFieldBMP, 16);
    inNMX_str_2_hex((char*)fieldEncryp, (char*)fieldEncrypHex, 16);

    for (i = 0; i < 8 ; i++)
    {
        bEncrypt[i] = uszBitmap[i] & fieldEncrypHex[i];
    }

    vdNMX_DebugAddHEX("Encry Field", bEncrypt, 8);
        
    pucByte = bEncrypt;
    inEncryptDataLen = 0;
    memset(uszField57, 0x00, sizeof(uszField57));

    
    vdNMX_Debug_LogPrintf("srNMXHeader.szTLEKID[%s] srNMXHeader.szCounter[%s]", srNMXHeader->szTLEKID, srNMXHeader->szCounter);

    memcpy(&uszField57[inEncryptDataLen], srNMXHeader->szAppID, APPID_SZ);
    inEncryptDataLen += APPID_SZ;

    if(inFinancialTxn)
        memcpy(&uszField57[inEncryptDataLen], srNMXHeader->szTLEKID, KEYID_SZ);
    else
        memcpy(&uszField57[inEncryptDataLen], srNMXHeader->szRKIKID, KEYID_SZ);
    inEncryptDataLen += KEYID_SZ;

    memcpy(&uszField57[inEncryptDataLen], srNMXHeader->szVersion, VERSION_SZ);
    inEncryptDataLen += VERSION_SZ;

    memcpy(&uszField57[inEncryptDataLen], srNMXHeader->szEncAlgo, ENC_ALGO_SZ);
    inEncryptDataLen += ENC_ALGO_SZ;

    memcpy(&uszField57[inEncryptDataLen], srNMXHeader->szKeyMag, KYM_MANAGE_SZ);
    inEncryptDataLen += KYM_MANAGE_SZ;

    memcpy(&uszField57[inEncryptDataLen], srNMXHeader->szMACAlgo, MAC_ALGO_SZ);
    inEncryptDataLen += MAC_ALGO_SZ;

    memcpy(&uszField57[inEncryptDataLen], srNMXHeader->szFlag, FLAG_SZ);
    inEncryptDataLen += FLAG_SZ;

    memcpy(&uszField57[inEncryptDataLen], srNMXHeader->szCounter, TXNCOUNTER_SZ);
    inEncryptDataLen += TXNCOUNTER_SZ;

    memcpy(&uszField57[inEncryptDataLen], g_DiversificationData, 3);
    inEncryptDataLen += 3;

    vdNMX_DebugAddHEX("Clear Field 57", uszField57, inEncryptDataLen);

    inCarrierFieldLen = 0;
    memset(uszCarrierField, 0x00, sizeof(uszCarrierField));
    for (inBitMapIndex = 0; inBitMapIndex < 8; inBitMapIndex++, pucByte++)
    {
        ucBitSelector = 0x80;
        for (inLoop = 0; inLoop < 8; inLoop++, ucBitSelector >>= 1, btFieldNum++)
        {
            if (*pucByte & ucBitSelector)
            {
                vdNMX_Debug_LogPrintf("ENCRYPT F.%d ", btFieldNum);

                inFieldDataLen = 0;
                ineachFiledLen = 0;
                memset(uszFieldDataBuf, 0x00, sizeof(uszFieldDataBuf));
                memset(uszeachFiled, 0x00, sizeof(uszeachFiled));
                
                vdCTOSS_NMX_TurnOffBit(uszBitmap, btFieldNum);
                inResult = inCTOSS_GetISOFieldData(btFieldNum, uszFieldDataBuf, &inFieldDataLen);

                //01h - Delimiter with byte value of 0x01 to separate each Sensitive Field in the concatenated list 
                if(inCarrierFieldLen > 0)
                {
                    uszCarrierField[inCarrierFieldLen] = 0x01;
                    inCarrierFieldLen += 1;
                }
                
                // Field Index 
                uszeachFiled[ineachFiledLen] = btFieldNum;
                ineachFiledLen += 1;

                //Field Length
                //uszeachFiled[ineachFiledLen] = inFieldDataLen;
                //ineachFiledLen += 1;

                // Sensitive Field value
                memcpy(&uszeachFiled[ineachFiledLen], uszFieldDataBuf, inFieldDataLen);
                ineachFiledLen += inFieldDataLen;
                uszFieldDataBuf[inFieldDataLen] = 0;

                sprintf((char *) szTempBuf, "DE.%d Length %d Value %02X %02X", btFieldNum, inFieldDataLen, uszFieldDataBuf[0], uszFieldDataBuf[1]);
                vdNMX_DebugAddHEX((char *) szTempBuf, uszFieldDataBuf, inFieldDataLen);

                ineachFiledOutputLen = sizeof(uszeachFiledOutput);
                memset(uszeachFiledOutput, 0x00, sizeof(uszeachFiledOutput));
                vdNMX_DebugAddHEX("Field before encode 250", uszeachFiled, ineachFiledLen);
                iEncode250(uszeachFiled, ineachFiledLen, uszeachFiledOutput, &ineachFiledOutputLen);
                vdNMX_DebugAddHEX("Field after encode 250", uszeachFiledOutput, ineachFiledOutputLen);

                
                memcpy(&uszCarrierField[inCarrierFieldLen],  uszeachFiledOutput, ineachFiledOutputLen);
                inCarrierFieldLen += ineachFiledOutputLen;

                vdNMX_DebugAddHEX("uszCarrierField", uszCarrierField, inCarrierFieldLen);
                
            }
        }
    }

    memcpy(&uszField57[inEncryptDataLen], uszCarrierField, inCarrierFieldLen);
    inEncryptDataLen += inCarrierFieldLen;
    
    //inTempDataLen = (inEncryptDataLen - 25);
    //inEncryptDataLen = sizeof(uszField57);
    //iEncode250(&uszField57[25], inTempDataLen, &uszField57[25], &inEncryptDataLen);
    //inEncryptDataLen += 25;

    vdNMX_DebugAddHEX("After iEncode250 DE57", uszField57, inEncryptDataLen);
    vdNMX_Debug_LogPrintf("inEncryptDataLen[%d]", inEncryptDataLen);
    
    inPadNum = 8 - ((inEncryptDataLen-22) % 8) - 1;
    memset(&uszField57[inEncryptDataLen], 0x00, inPadNum);
    inEncryptDataLen += inPadNum;
    uszField57[inEncryptDataLen] = (inPadNum + 1);
    inEncryptDataLen += 1;

    vdNMX_DebugAddHEX("After pad DE57", uszField57, inEncryptDataLen);
    vdNMX_Debug_LogPrintf("inEncryptDataLen[%d]  srNMXHeader->szKeyMag[%d]", inEncryptDataLen, srNMXHeader->szKeyMag[0]);
    
    if(KEY_MANAGE_PER_TERMINAL == srNMXHeader->szKeyMag[0])
	{
	    if(inFinancialTxn)
            inResult = inCTOSS_TestNMXTLEEncryptDataCBCMode(inFinancialTxn, srNMXHeader->inTLEDEKKeySet, srNMXHeader->inTLEKeyIndex, &uszField57[22], inEncryptDataLen-22, &uszField57[22]);
        else
            inResult = inCTOSS_TestNMXTLEEncryptDataCBCMode(inFinancialTxn, srNMXHeader->inRKIDEKKeySet, srNMXHeader->inRKIKeyIndex, &uszField57[22], inEncryptDataLen-22, &uszField57[22]);
        if(NMX_OK != inResult)
            return NMX_ENCRYPT_ERR;
    }
    else if(KEY_MANAGE_PER_TXN == srNMXHeader->szKeyMag[0])
    {
        memset(uszEncryOutBuf, 0x00, sizeof(uszEncryOutBuf));

        if(inFinancialTxn)
            inCTOSS_NMX_3DESEncryptCBC(g_CurrentTLEDEK, &uszField57[22], (inEncryptDataLen-22), uszEncryOutBuf);
        else
            inCTOSS_NMX_3DESEncryptCBC(g_CurrentRKIDEK, &uszField57[22], (inEncryptDataLen-22), uszEncryOutBuf);

        memcpy(&uszField57[22], uszEncryOutBuf, (inEncryptDataLen-22));
    }

    vdNMX_DebugAddHEX("Encry Field 57", uszField57, inEncryptDataLen);
    vdNMX_Debug_LogPrintf("inEncryptDataLen[%d]", inEncryptDataLen);

    inTempDataLen = (inEncryptDataLen - 22);
    inEncryptDataLen = sizeof(uszField57);
    memset(uszEncryOutBuf, 0x00, sizeof(uszEncryOutBuf));

    vdNMX_DebugAddHEX("Before Encode64", &uszField57[22], inTempDataLen);
    vdNMX_Debug_LogPrintf("inEncryptDataLen[%d]", inTempDataLen);
    iEncode64(&uszField57[22], inTempDataLen, (char*)uszEncryOutBuf, &inEncryptDataLen);
    vdNMX_DebugAddHEX("After Encode64", uszEncryOutBuf, inEncryptDataLen);
    vdNMX_Debug_LogPrintf("inEncryptDataLen[%d]", inEncryptDataLen);
    memcpy(&uszField57[22], uszEncryOutBuf, inEncryptDataLen);
    inEncryptDataLen += 22;
    
    vdNMX_DebugAddHEX("After iEncode64 DE57", uszField57, inEncryptDataLen);

    memset(uszLenAsic, 0x00, sizeof(uszLenAsic));
    sprintf(uszLenAsic, "%04d", inEncryptDataLen);
    inNMX_str_2_hex((char*)uszLenAsic, (char*)uszEncryOutBuf, 4);
    memcpy(&uszEncryOutBuf[2], uszField57, inEncryptDataLen);
    
    //add DE57
    vdCTOSS_NMX_TurnOnBit(uszBitmap, 57);
    inCTOSS_SetISOFieldData(57, uszEncryOutBuf, inEncryptDataLen+2);

    vdNMX_DebugAddHEX("Field 57", uszEncryOutBuf, inEncryptDataLen+2);
    
    return NMX_OK;
}

int inCTOSS_NMX_DecryptSensitiveFieldsData(IN int inFinancialTxn, IN NMX_TLED_HEADER *srNMXHeader, IN INOUT unsigned char *uszBitmap)
{
    int i, j, k;
    int iTotalBlock;
    int inPadNum;
    unsigned long aulPlain[8] = {0};
    unsigned long aulIV[8] = {0};
    
    int inResult;
    int inFiled57Len;
    int inTempDataLen;
    unsigned char uszLenAsic[4+1];
    unsigned char uszLenHex[4+1];
    unsigned char uszDE57EncryptDataBK[512];
    unsigned char uszDE57EncryptData[512];
    unsigned char uszEncryOutBuf[512];
    int inDE57EncryptDataLen;
    unsigned char uszClearSensitiveData[512];
    unsigned char uszeachFieldData[255];
    unsigned char uszCleareachFieldData[255];
    int inClearSensitiveDataLen;
    unsigned char uszField57[512];
    int inFieldDataLen;
    int inBuffDencryptCount = 0;
    int ptrNum;
    int ineachFiledLen;
    int inClearFiledLen;
    int inLen;
    int inTag;
    unsigned char szBuf[512 + 1];

    vdNMX_Debug_LogPrintf("inCTOSS_NMX_DecryptSensitiveFieldsData");
    
    memset(uszField57, 0x00, sizeof(uszField57));
    inResult = inCTOSS_GetISOFieldData(57, uszField57, &inFieldDataLen);

    vdNMX_DebugAddHEX("Encry Field 57", uszField57, inFieldDataLen);

    memcpy(uszLenHex, uszField57, 2);
    inNMX_hex_2_str((char*)uszLenHex, (char*)uszLenAsic, 2);
    uszLenAsic[4] = 0x00;
    inFiled57Len = atoi((char*)uszLenAsic);
    
    if(inFieldDataLen != (inFiled57Len+2))
        return NMX_INVALID_ISO;

    inDE57EncryptDataLen = inFiled57Len - 22;
    memcpy(uszDE57EncryptData, uszField57+2+22, inDE57EncryptDataLen);
    inTempDataLen = inDE57EncryptDataLen; 
    inDE57EncryptDataLen = sizeof(uszDE57EncryptData);
    iDecode64(uszDE57EncryptData, inTempDataLen, uszDE57EncryptData, &inDE57EncryptDataLen);

    vdNMX_DebugAddHEX("After iDecode64 57", uszDE57EncryptData, inDE57EncryptDataLen);
    vdNMX_Debug_LogPrintf("inDE57EncryptDataLen[%d]", inDE57EncryptDataLen);
    if(0 != inDE57EncryptDataLen%8)
        return NMX_INVALID_ISO;

    if(KEY_MANAGE_PER_TERMINAL == srNMXHeader->szKeyMag[0])
    {
        if(inFinancialTxn)
            inResult = inCTOSS_TestNMXTLEDecryptDataCBCMode(inFinancialTxn, srNMXHeader->inTLEDEKKeySet, srNMXHeader->inTLEKeyIndex, uszDE57EncryptData, inDE57EncryptDataLen, uszDE57EncryptData);
        else
            inResult = inCTOSS_TestNMXTLEDecryptDataCBCMode(inFinancialTxn, srNMXHeader->inRKIDEKKeySet, srNMXHeader->inRKIKeyIndex, uszDE57EncryptData, inDE57EncryptDataLen, uszDE57EncryptData);
        
        if(NMX_OK != inResult)
            return NMX_DECRYPT_ERR;
    }
    else if(KEY_MANAGE_PER_TXN == srNMXHeader->szKeyMag[0])
    {     
        memset(uszEncryOutBuf, 0x00, sizeof(uszEncryOutBuf));
        if(inFinancialTxn)
            inCTOSS_NMX_3DESDecryptCBC(g_CurrentTLEDEK, uszDE57EncryptData, inDE57EncryptDataLen, uszEncryOutBuf);
        else
            inCTOSS_NMX_3DESDecryptCBC(g_CurrentRKIDEK, uszDE57EncryptData, inDE57EncryptDataLen, uszEncryOutBuf);

        memcpy(uszDE57EncryptData, uszEncryOutBuf, inDE57EncryptDataLen);
        /*
        memset(aulIV, 0x00, sizeof(aulIV));
        memcpy(uszDE57EncryptDataBK, uszDE57EncryptData, inDE57EncryptDataLen);
        iTotalBlock = inDE57EncryptDataLen/8;
        j = 0;
        
        for (i = 0; i < iTotalBlock; i++)
		{
			j = i * 8;

            CTOS_DES (d_DECRYPTION, &g_CurrentTLEDEK[0], 8, (char *)&uszDE57EncryptData[j], 8, (char *)&uszDE57EncryptData[j]);	//Encrypt
			CTOS_DES (d_ENCRYPTION, &g_CurrentTLEDEK[8], 8, (char *)&uszDE57EncryptData[j], 8, (char *)&uszDE57EncryptData[j]);	//Decrypt
			CTOS_DES (d_DECRYPTION, &g_CurrentTLEDEK[0], 8, (char *)&uszDE57EncryptData[j], 8, (char *)&uszDE57EncryptData[j]);	//Encrypt

			memcpy (aulPlain, uszDE57EncryptData + j, 8);
			for (k = 0; k < 2; k++)
			{
				aulPlain[k] = aulPlain[k] ^ aulIV[k];		//Plaintext XOR with 
			}											//previous Cipher Block
			memcpy (uszDE57EncryptData + j, aulPlain, 8);
			memcpy (aulIV, uszDE57EncryptDataBK + j, 8);
		}
		*/
    }

    vdNMX_DebugAddHEX("After decrypt 57", uszDE57EncryptData, inDE57EncryptDataLen);
    
    if(1 > uszDE57EncryptData[inDE57EncryptDataLen-1] 
        || uszDE57EncryptData[inDE57EncryptDataLen-1] > 7)
    {
        return NMX_INVALID_RESP;
    }

    vdNMX_Debug_LogPrintf("g_DiversificationData[%s]uszDE57EncryptData[%s]", g_DiversificationData, uszDE57EncryptData);
    
    if(0 != memcmp(g_DiversificationData, uszDE57EncryptData, 3))
    {
        return NMX_INVALID_RESP;
    }   
    
    inPadNum = uszDE57EncryptData[inDE57EncryptDataLen-1];
    inDE57EncryptDataLen -= (inPadNum);

    //inClearSensitiveDataLen = sizeof(uszClearSensitiveData);
    //iDecode250(&uszDE57EncryptData[3], inDE57EncryptDataLen-3, &uszClearSensitiveData[0], &inClearSensitiveDataLen);

    vdNMX_Debug_LogPrintf("inDE57EncryptDataLen[%d] inPadNum[%d]", inDE57EncryptDataLen, inPadNum);

    inClearSensitiveDataLen = inDE57EncryptDataLen-3;
    if(0 >= inClearSensitiveDataLen)
    {
        vdNMX_Debug_LogPrintf("No Encryp Data");

        return NMX_OK;
    }
    
    memcpy(uszClearSensitiveData, &uszDE57EncryptData[3], inClearSensitiveDataLen);
    vdNMX_DebugAddHEX("with iDecode250 57", uszClearSensitiveData, inClearSensitiveDataLen);
    
    inBuffDencryptCount = 0;
    while(inBuffDencryptCount < inClearSensitiveDataLen )
    {
        ptrNum = inBuffDencryptCount;
        
        while(1)
        {
            inBuffDencryptCount ++;
            
            if(inBuffDencryptCount >= inClearSensitiveDataLen)
                break;
            if(uszClearSensitiveData[inBuffDencryptCount] == 0x01)
                break;
        }

        vdNMX_Debug_LogPrintf("ptrNum = %d inBuffDencryptCount = %d", ptrNum, inBuffDencryptCount);
        
        ineachFiledLen = inBuffDencryptCount-ptrNum;
        memcpy(uszeachFieldData, &uszClearSensitiveData[ptrNum], ineachFiledLen);
        
        //01h - Delimiter with byte value of 0x01 to separate each Sensitive Field in the concatenated list 
        inBuffDencryptCount ++;

        vdNMX_DebugAddHEX("uszeachFieldData", uszeachFieldData, ineachFiledLen);
        inClearFiledLen = sizeof(uszCleareachFieldData);
        iDecode250(uszeachFieldData, ineachFiledLen, uszCleareachFieldData, &inClearFiledLen);
        vdNMX_DebugAddHEX("uszCleareachFieldData", uszCleareachFieldData, inClearFiledLen);
        
        // Tag
        inTag = uszCleareachFieldData[0];
        
        // Length
        //inLen = uszClearSensitiveData[inBuffDencryptCount];
        //inBuffDencryptCount += 1;
        
        // Value
        memset(szBuf, 0, sizeof(szBuf));
        inLen = inClearFiledLen - 1;
        memcpy(szBuf, &uszCleareachFieldData[1], inLen);

        vdNMX_Debug_LogPrintf("DECRYPT F.%d ", inTag);
        vdNMX_DebugAddHEX("DECRYPT Value", szBuf, inLen);

        if (inTag > 64)
            return NMX_DECRYPT_ERR;

        vdCTOSS_NMX_TurnOnBit(uszBitmap, inTag);
        inCTOSS_SetISOFieldData(inTag, szBuf, inLen);

    }

    return inBuffDencryptCount;
    
}

int inCTOSS_NMX_RKIKeyInjectionProcess(IN unsigned char *szTPDU, IN unsigned long ulTraceNO, IN unsigned char *szTID, IN unsigned char *szMID, OUT char *szErrResponse)
{
    int inResult;
    BYTE byAcqID[40+1];
    BYTE byVendorID[40+1];
    BYTE byTSK[32+1];
    int inKeyLen = 0;

    BYTE bySmartCardSerNo[SMARTCARD_SERN_SZ + 1];
    BYTE byEcrySession[16 + 1];
    BYTE bySessionKCVHex[2 + 1];
    BYTE bySessionKCVAsic[4 + 1];
    BYTE szRndA1B2B1A2[16+1];

    BYTE byPayloadDE57[255];
    BYTE tempBuf[255];
    int inDE57Len = 0;
    int inTempBufLen = 0;

    BYTE bySendData[512];
    int inSendDataLen = 0;

    BYTE byReceiveData[512];
    int inRecvDataLen = 0;
    
    int inOutputLen;
    char szAsicBuf[255+1];
	//char szTPDU[20];

    
    inNMX_TCTRead(1);

    vdNMX_Debug_LogPrintf("inCTOSS_NMX_RKIKeyInjection");

    if (srNMXLibFunc.vdEnterSmartCardPIN == 0x00 || srNMXLibFunc.inSendData == 0x00 || srNMXLibFunc.inRecData == 0x00)
        return  NMX_FUNCTION_NOT_INIT;
    
    inResult = inCTOSS_NMX_WaitingForSmartCard();
    vdNMX_Debug_LogPrintf("inCTOSS_NMX_WaitingForSmartCard[%d]", inResult);
    if(NMX_OK != inResult)
        return inResult;

    inPMPCInitSmartCard();

    inResult = inCTOSS_NMX_SmartCardSelectApplication(szErrResponse);
    vdNMX_Debug_LogPrintf("inResult[%d]", inResult);
    if(NMX_OK != inResult)
        return inResult;

    inCTOSS_NMX_SmartCardGetAppletInfo(byAcqID, byVendorID, szErrResponse);
    
    memset(byAcqID, 0x00, sizeof(byAcqID));
    memset(byVendorID, 0x00, sizeof(byVendorID));
    inResult = inCTOSS_NMX_SmartCardReadAcqIDVendorID(byAcqID, byVendorID, szErrResponse);
    if(NMX_OK != inResult)
        return inResult;

    memset(byTSK, 0x00, sizeof(byTSK));
    inResult = inCTOSS_NMX_InitSecureChannel(byAcqID, byVendorID, byTSK, &inKeyLen, szErrResponse);  
    vdNMX_Debug_LogPrintf("inResult[%d]", inResult);
    if(NMX_OK != inResult)
        return inResult;

    inResult = inCTOSS_NMX_MutualAuthentication(byTSK, szRndA1B2B1A2, szErrResponse);  
    if(NMX_OK != inResult)
        return inResult;


#if 0
    inResult = inCTOSS_NMX_PINVerification(szRndA1B2B1A2, szErrResponse);  
    if(NMX_OK != inResult)
        return inResult;

    memset(bySmartCardSerNo, 0x00, sizeof(bySmartCardSerNo));
    memset(byEcrySession, 0x00, sizeof(byEcrySession));
    memset(bySessionKCVHex, 0x00, sizeof(bySessionKCVHex));
    inResult = inCTOSS_NMX_SmartCardRequestSession(byAcqID, byVendorID, bySmartCardSerNo, byEcrySession, bySessionKCVHex, szErrResponse);  
    if(NMX_OK != inResult)
        return inResult;

    inNMX_hex_2_str((char*)bySessionKCVHex, (char*)bySessionKCVAsic, 2);

    inCTOSS_NMX_Read(1);

    if(0 == strlen(srNMXHeader.szEncAlgo))
        strcpy(srNMXHeader.szEncAlgo, "03");
    if(0 == strlen(srNMXHeader.szKeyMag))
        strcpy(srNMXHeader.szKeyMag, "2");
    if(0 == strlen(srNMXHeader.szMACAlgo))
        strcpy(srNMXHeader.szMACAlgo, "4");
    if(0 == strlen(srNMXHeader.szCommandCode))
        strcpy(srNMXHeader.szCommandCode, "01");
    if(0 == strlen(srNMXHeader.szDeviceMode))
        strcpy(srNMXHeader.szDeviceMode, "CASTLES V3");
    if(0 == strlen(srNMXHeader.szDeviceSerNo))
        strcpy(srNMXHeader.szDeviceSerNo, szTID);
    if(0 == strlen(srNMXHeader.szAppID))
        strcpy(srNMXHeader.szAppID, "01");

    if(0 == srNMXHeader.inRKIDEKKeySet)
        srNMXHeader.inRKIDEKKeySet = 100;
    if(0 == srNMXHeader.inRKIMEKKeySet)
        srNMXHeader.inRKIMEKKeySet = 104;
    if(0 == srNMXHeader.inRKIKeyIndex)
        srNMXHeader.inRKIKeyIndex = 2;
    if(0 == srNMXHeader.inTLEDEKKeySet)
        srNMXHeader.inTLEDEKKeySet = 120;
    if(0 == srNMXHeader.inTLEMEKKeySet)
        srNMXHeader.inTLEMEKKeySet = 124;
    if(0 == srNMXHeader.inTLEKeyIndex)
        srNMXHeader.inTLEKeyIndex = 2;
    
    /*inDE57Len = 0;
    memset(byPayloadDE57, 0x00, sizeof(byPayloadDE57));
    memcpy(&byPayloadDE57[inDE57Len], srNMXHeader.szEncAlgo, ENC_ALGO_SZ);
    inDE57Len += ENC_ALGO_SZ;
    memcpy(&byPayloadDE57[inDE57Len], srNMXHeader.szKeyMag, KYM_MANAGE_SZ);
    inDE57Len += KYM_MANAGE_SZ;
    memcpy(&byPayloadDE57[inDE57Len], srNMXHeader.szMACAlgo, MAC_ALGO_SZ);
    inDE57Len += MAC_ALGO_SZ;
    memcpy(&byPayloadDE57[inDE57Len], srNMXHeader.szCommandCode, CMDCODE_SZ);
    inDE57Len += CMDCODE_SZ;
    byPayloadDE57[inDE57Len++] = 0x01;
    memcpy(&byPayloadDE57[inDE57Len], srNMXHeader.szDeviceMode, DEVICE_MODEL_SZ);
    inDE57Len += DEVICE_MODEL_SZ;
    byPayloadDE57[inDE57Len++] = 0x01;
    memcpy(&byPayloadDE57[inDE57Len], srNMXHeader.szDeviceSerNo, DEVICE_SERINAL_SZ);
    inDE57Len += DEVICE_SERINAL_SZ;
    byPayloadDE57[inDE57Len++] = 0x01;
    memcpy(&byPayloadDE57[inDE57Len], srNMXHeader.szAppID, APPID_SZ);
    inDE57Len += APPID_SZ;
    byPayloadDE57[inDE57Len++] = 0x01;
    memcpy(&byPayloadDE57[inDE57Len], bySmartCardSerNo, SMARTCARD_SERN_SZ);
    inDE57Len += SMARTCARD_SERN_SZ;
    byPayloadDE57[inDE57Len++] = 0x01;
    memcpy(&byPayloadDE57[inDE57Len], byEcrySession, 16);
    inDE57Len += 16;
    byPayloadDE57[inDE57Len++] = 0x01;
    memcpy(&byPayloadDE57[inDE57Len], bySessionKCVAsic, 4);
    inDE57Len += 4;*/
    
    inDE57Len = 0;
    inTempBufLen = 0;
    memset(byPayloadDE57, 0x00, sizeof(byPayloadDE57));
    memset(tempBuf, 0x00, sizeof(tempBuf));
    memset(szAsicBuf, 0x00, sizeof(szAsicBuf));   
    memcpy(&tempBuf[inTempBufLen], srNMXHeader.szEncAlgo, ENC_ALGO_SZ);
    inTempBufLen += ENC_ALGO_SZ;
    memcpy(&tempBuf[inTempBufLen], srNMXHeader.szKeyMag, KYM_MANAGE_SZ);
    inTempBufLen += KYM_MANAGE_SZ;
    memcpy(&tempBuf[inTempBufLen], srNMXHeader.szMACAlgo, MAC_ALGO_SZ);
    inTempBufLen += MAC_ALGO_SZ;
    memcpy(&tempBuf[inTempBufLen], srNMXHeader.szCommandCode, CMDCODE_SZ);
    inTempBufLen += CMDCODE_SZ; 
    inOutputLen = 255;
    iEncode250(tempBuf, inTempBufLen, szAsicBuf, &inOutputLen);
    memcpy(&byPayloadDE57[inDE57Len], szAsicBuf, inOutputLen);
    inDE57Len += inOutputLen;
    byPayloadDE57[inDE57Len++] = 0x01;
    
    inTempBufLen = 0;
    memset(tempBuf, 0x00, sizeof(tempBuf));
    memset(szAsicBuf, 0x00, sizeof(szAsicBuf));    
    memcpy(&tempBuf[inTempBufLen], srNMXHeader.szDeviceMode, DEVICE_MODEL_SZ);
    inTempBufLen += DEVICE_MODEL_SZ;
    inOutputLen = 255;
    iEncode250(tempBuf, inTempBufLen, szAsicBuf, &inOutputLen);
    memcpy(&byPayloadDE57[inDE57Len], szAsicBuf, inOutputLen);
    inDE57Len += inOutputLen;
    byPayloadDE57[inDE57Len++] = 0x01;
    
    inTempBufLen = 0;
    memset(tempBuf, 0x00, sizeof(tempBuf));
    memset(szAsicBuf, 0x00, sizeof(szAsicBuf));
    memcpy(&tempBuf[inTempBufLen], srNMXHeader.szDeviceSerNo, DEVICE_SERINAL_SZ);
    inTempBufLen += DEVICE_SERINAL_SZ;
    inOutputLen = 255;
    iEncode250(tempBuf, inTempBufLen, szAsicBuf, &inOutputLen);
    memcpy(&byPayloadDE57[inDE57Len], szAsicBuf, inOutputLen);
    inDE57Len += inOutputLen;
    byPayloadDE57[inDE57Len++] = 0x01;
    
    inTempBufLen = 0;
    memset(tempBuf, 0x00, sizeof(tempBuf));
    memset(szAsicBuf, 0x00, sizeof(szAsicBuf));
    memcpy(&tempBuf[inTempBufLen], srNMXHeader.szAppID, APPID_SZ);
    inTempBufLen += APPID_SZ;
    inOutputLen = 255;
    iEncode250(tempBuf, inTempBufLen, szAsicBuf, &inOutputLen);
    memcpy(&byPayloadDE57[inDE57Len], szAsicBuf, inOutputLen);
    inDE57Len += inOutputLen;
    byPayloadDE57[inDE57Len++] = 0x01;
    
    inTempBufLen = 0;
    memset(tempBuf, 0x00, sizeof(tempBuf));
    memset(szAsicBuf, 0x00, sizeof(szAsicBuf));
    memcpy(&tempBuf[inTempBufLen], bySmartCardSerNo, SMARTCARD_SERN_SZ);
    inTempBufLen += SMARTCARD_SERN_SZ;
    inOutputLen = 255;
    iEncode250(tempBuf, inTempBufLen, szAsicBuf, &inOutputLen);
    memcpy(&byPayloadDE57[inDE57Len], szAsicBuf, inOutputLen);
    inDE57Len += inOutputLen;
    byPayloadDE57[inDE57Len++] = 0x01;
    
    
    inTempBufLen = 0;
    memset(tempBuf, 0x00, sizeof(tempBuf));
    memset(szAsicBuf, 0x00, sizeof(szAsicBuf));
    memcpy(&tempBuf[inTempBufLen], byEcrySession, 16);
    inTempBufLen += 16;
    inOutputLen = 255;
    iEncode250(tempBuf, inTempBufLen, szAsicBuf, &inOutputLen);
    memcpy(&byPayloadDE57[inDE57Len], szAsicBuf, inOutputLen);
    inDE57Len += inOutputLen;
    byPayloadDE57[inDE57Len++] = 0x01;
    
    
    inTempBufLen = 0;
    memset(tempBuf, 0x00, sizeof(tempBuf));
    memset(szAsicBuf, 0x00, sizeof(szAsicBuf));
    memcpy(&tempBuf[inTempBufLen], bySessionKCVAsic, 4);
    inTempBufLen += 4;
    inOutputLen = 255;
    iEncode250(tempBuf, inTempBufLen, szAsicBuf, &inOutputLen);
    memcpy(&byPayloadDE57[inDE57Len], szAsicBuf, inOutputLen);
    inDE57Len += inOutputLen;
    //byPayloadDE57[inDE57Len++] = 0x01;
    
    vdNMX_DebugAddHEX("Enc250 DE57 field wise then packed 0x01", byPayloadDE57, inDE57Len);

    memset(szAsicBuf, 0x00, sizeof(szAsicBuf));
    memcpy(szAsicBuf, byPayloadDE57, inDE57Len);
    memset(byPayloadDE57, 0x00, sizeof(byPayloadDE57));
    inOutputLen = 255;

    iEncode64(szAsicBuf, inDE57Len, byPayloadDE57, &inOutputLen);
    inDE57Len = inOutputLen;

    vdNMX_DebugAddHEX("Enc64 DE57", byPayloadDE57, inDE57Len);

    //only Device Model Code, Device Serial Number and Smartcard Serial Number different, try one by one
    //3033 32 34 3031 01 434153544C45532056330030003000300030003000300030003000300030           01 3231333036303838003000300030003000300030003000300030003000300030 01 3031 01 3030373535003000300030003000300030003000300030003000300030003000300030 01 955588E33F5DA20C8886AC5F51AB3221 01 32353245
    //3033 32 34 3031 01 5678353230003000300030003000300030003000300030003000300030003000300030 01 3238312D3237312D313838003000300030003000300030003000300030       01 3031 01 3030373631003000300030003000300030003000300030003000300030003000300030 01 8FE2AE74178A146F93532B0A4940F921 01 36433843

/*#if 1
    //testing 1, hardcode the whole message as GHL terminal
    {
        memset(szAsicBuf, 0x00, sizeof(szAsicBuf));
        memset(byPayloadDE57, 0x00, sizeof(byPayloadDE57));
    
        strcpy(szAsicBuf, "4D444D794E44417841565A344E544977414441414D414177414441414D414177414441414D414177414441414D414177414441414D414177415449344D5330794E7A45744D546734414441414D414177414441414D414177414441414D41417741544178415441774E7A5978414441414D414177414441414D414177414441414D414177414441414D414177414441414D41417741592F69726E5158696852766B314D72436B6C412B5345424E6B4D3451773D3D");
        inDE57Len = strlen(szAsicBuf);
        wub_str_2_hex(szAsicBuf,byPayloadDE57,inDE57Len);
        inDE57Len = inDE57Len/2;
    }

    //testing 2, hardcode the whole message as GHL terminal expect Smartcard Serial Number
    {
        memset(szAsicBuf, 0x00, sizeof(szAsicBuf));
        memset(byPayloadDE57, 0x00, sizeof(byPayloadDE57));
    
        strcpy(byPayloadDE57, "303332343031015678353230003000300030003000300030003000300030003000300030003000300030013238312D3237312D313838003000300030003000300030003000300030013031013030373535003000300030003000300030003000300030003000300030003000300030018FE2AE74178A146F93532B0A4940F9210136433843");
        inDE57Len = strlen(byPayloadDE57);
        wub_str_2_hex(byPayloadDE57,szAsicBuf,inDE57Len);
        inDE57Len = inDE57Len/2;

        memset(byPayloadDE57, 0x00, sizeof(byPayloadDE57));
        inOutputLen = 255;

        iEncode64(szAsicBuf, inDE57Len, byPayloadDE57, &inOutputLen);
        inDE57Len = inOutputLen;
    }

    //testing 3, hardcode the whole message as GHL terminal expect Device Model Code, Device Serial Number
    {
        memset(szAsicBuf, 0x00, sizeof(szAsicBuf));
        memset(byPayloadDE57, 0x00, sizeof(byPayloadDE57));
    
        strcpy(byPayloadDE57, "30333234303101434153544C45532056330030003000300030003000300030003000300030013231333036303838003000300030003000300030003000300030003000300030013031013030373631003000300030003000300030003000300030003000300030003000300030018FE2AE74178A146F93532B0A4940F9210136433843");
        inDE57Len = strlen(byPayloadDE57);
        wub_str_2_hex(byPayloadDE57,szAsicBuf,inDE57Len);
        inDE57Len = inDE57Len/2;

        memset(byPayloadDE57, 0x00, sizeof(byPayloadDE57));
        inOutputLen = 255;

        iEncode64(szAsicBuf, inDE57Len, byPayloadDE57, &inOutputLen);
        inDE57Len = inOutputLen;
    }

    //testing 4, use original data, just update Smartcard Serial Number to GHL one
    {
        memset(szAsicBuf, 0x00, sizeof(szAsicBuf));
        memset(byPayloadDE57, 0x00, sizeof(byPayloadDE57));
    
        strcpy(byPayloadDE57, "30333234303101434153544C4553205633003000300030003000300030003000300030003001323133303630383800300030003000300030003000300030003000300030003001303101303037363100300030003000300030003000300030003000300030003000300030003001955588E33F5DA20C8886AC5F51AB32210132353245");
        inDE57Len = strlen(byPayloadDE57);
        wub_str_2_hex(byPayloadDE57,szAsicBuf,inDE57Len);
        inDE57Len = inDE57Len/2;

        memset(byPayloadDE57, 0x00, sizeof(byPayloadDE57));
        inOutputLen = 255;

        iEncode64(szAsicBuf, inDE57Len, byPayloadDE57, &inOutputLen);
        inDE57Len = inOutputLen;
    }

    //testing 5, use original data, update Device Model Code, Device Serial Number, Smartcard Serial Number to GHL one
    {
        memset(szAsicBuf, 0x00, sizeof(szAsicBuf));
        memset(byPayloadDE57, 0x00, sizeof(byPayloadDE57));
    
        strcpy(byPayloadDE57, "303332343031015678353230003000300030003000300030003000300030003000300030003000300030013238312D3237312D31383800300030003000300030003000300030003001303101303037363100300030003000300030003000300030003000300030003000300030003001955588E33F5DA20C8886AC5F51AB32210132353245");
        inDE57Len = strlen(byPayloadDE57);
        wub_str_2_hex(byPayloadDE57,szAsicBuf,inDE57Len);
        inDE57Len = inDE57Len/2;

        memset(byPayloadDE57, 0x00, sizeof(byPayloadDE57));
        inOutputLen = 255;

        iEncode64(szAsicBuf, inDE57Len, byPayloadDE57, &inOutputLen);
        inDE57Len = inOutputLen;
    }
#endif*/

    inCTOSS_NMX_FormRKIorTLEDownloadMessage(1, szTPDU, ulTraceNO, szTID, szMID, byPayloadDE57, inDE57Len, bySendData, &inSendDataLen);

#ifdef SMART_CARD_TEST_ONLY
    inRecvDataLen = 332;
    inNMX_str_2_hex("60024000000810203801000A80008095000100000111111101010240313233343536373839303132303031323334353637380114303334343031010001011122334455660111223344556677889900112233445566011122334401AABBCCDDEEFFAABBCCDDEEFFAABBCCDD01AABBCCDD016655443322110112345678901234567890123456789012011234567801ABCDEFABCDEFABCDEFABCDEFABCDEFAB01ABCDEFAB000000", (char *)byReceiveData, inRecvDataLen);
    inRecvDataLen = inRecvDataLen/2;
#else
    if (srNMXLibFunc.inSendData((char *)0x00, (char *)bySendData, inSendDataLen) != NMX_OK)
    {
        return NMX_SEND_DATA_ERR;
    }

    inRecvDataLen = srNMXLibFunc.inRecData((char *)0x00, (char *)byReceiveData);
    if (inRecvDataLen <= 0)
    {
        return NMX_RECV_DATA_ERR;
    }
#endif

    inResult = inCTOSS_AnalyseRKIKeyInjectionResponse(byTSK, szRndA1B2B1A2, byReceiveData, inRecvDataLen, ulTraceNO, szTID, szErrResponse);
    if(NMX_OK != inResult)
        return inResult;
#endif
    vdNMX_Debug_LogPrintf("inCTOSS_NMX_RKIKeyInjection End");
    return NMX_OK;
}

int inCTOSS_NMX_RKIKeyInjection(IN unsigned char *szTPDU, IN unsigned long ulTraceNO, IN unsigned char *szTID, IN unsigned char *szMID, OUT char *szErrResponse)
{
    int inResult;

    inResult = inCTOSS_NMX_RKIKeyInjectionProcess(szTPDU, ulTraceNO, szTID, szMID, szErrResponse);

    vdCTOSS_NMX_RemoveCard();

    return inResult;
    
}

int inCTOSS_NMX_TLEDownload(IN int inHDTid, IN unsigned char *szTPDU, IN unsigned long ulTraceNO, IN unsigned char *szTID, IN unsigned char *szMID, OUT char *szErrResponse)
{
    int inResult;
    
    BYTE byPayloadDE57[255];
    BYTE tempBuf[255];
    int inDE57Len = 0;
    int inTempBufLen = 0;
    int inPadNum;

    BYTE bySendData[512];
    int inSendDataLen = 0;

    BYTE byReceiveData[512];
    int inRecvDataLen = 0;

    int inOutputLen;
    char szAsicBuf[255+1];

    inNMX_TCTRead(1);

    vdNMX_Debug_LogPrintf("inCTOSS_NMX_TLEDownload");
    
    inCTOSS_NMX_Read(1);

    if(0 == strlen(srNMXHeader.szEncAlgo))
        strcpy(srNMXHeader.szEncAlgo, "03");
    if(0 == strlen(srNMXHeader.szKeyMag))
        strcpy(srNMXHeader.szKeyMag, "2");
    if(0 == strlen(srNMXHeader.szMACAlgo))
        strcpy(srNMXHeader.szMACAlgo, "3");
    if(0 == strlen(srNMXHeader.szCommandCode))
        strcpy(srNMXHeader.szCommandCode, "01");
    if(0 == strlen(srNMXHeader.szDeviceMode))
        strcpy(srNMXHeader.szDeviceMode, "CASTLES V3");
    if(0 == strlen(srNMXHeader.szDeviceSerNo))
        strcpy(srNMXHeader.szDeviceSerNo, szTID);
    if(0 == strlen(srNMXHeader.szAppID))
        strcpy(srNMXHeader.szAppID, "01");

    if(0 == srNMXHeader.inRKIDEKKeySet)
        srNMXHeader.inRKIDEKKeySet = 100;
    if(0 == srNMXHeader.inRKIMEKKeySet)
        srNMXHeader.inRKIMEKKeySet = 104;
    if(0 == srNMXHeader.inRKIKeyIndex)
        srNMXHeader.inRKIKeyIndex = 2;
    if(0 == srNMXHeader.inTLEDEKKeySet)
        srNMXHeader.inTLEDEKKeySet = 120;
    if(0 == srNMXHeader.inTLEMEKKeySet)
        srNMXHeader.inTLEMEKKeySet = 124;
    if(0 == srNMXHeader.inTLEKeyIndex)
        srNMXHeader.inTLEKeyIndex = 2;

#ifdef TLE_DOWNLOAD_TEST
{
    inCTOSS_NMX_Save3DESClearKeyForEncrypt(srNMXHeader.inRKIDEKKeySet, srNMXHeader.inRKIKeyIndex, "\xA8\xFD\xB0\x46\x73\x38\x9B\xF2\x3E\x2C\x7F\xEA\xB6\xF1\x9E\xA2");
    inCTOSS_NMX_Save3DESClearKeyForDecrypt(srNMXHeader.inRKIDEKKeySet, srNMXHeader.inRKIKeyIndex, "\xA8\xFD\xB0\x46\x73\x38\x9B\xF2\x3E\x2C\x7F\xEA\xB6\xF1\x9E\xA2");
    inCTOSS_NMX_Save3DESClearKeyForEncrypt(srNMXHeader.inRKIMEKKeySet, srNMXHeader.inRKIKeyIndex, "\xB0\xFD\xB0\x46\x73\x38\x9B\xF2\x26\x2C\x7F\xEA\xB6\xF1\x9E\xA2");
    inCTOSS_NMX_Save3DESClearKeyForDecrypt(srNMXHeader.inRKIMEKKeySet, srNMXHeader.inRKIKeyIndex, "\xB0\xFD\xB0\x46\x73\x38\x9B\xF2\x26\x2C\x7F\xEA\xB6\xF1\x9E\xA2");
    inCTOSS_TestSaveNMXRKIKey("\xA8\xFD\xB0\x46\x73\x38\x9B\xF2\x3E\x2C\x7F\xEA\xB6\xF1\x9E\xA2", "\xB0\xFD\xB0\x46\x73\x38\x9B\xF2\x26\x2C\x7F\xEA\xB6\xF1\x9E\xA2");

    memcpy(srNMXHeader.szDeviceMode, "\x56\x78\x35\x32\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 20);
    
    memcpy(srNMXHeader.szDeviceSerNo,"\x32\x38\x31\x2D\x32\x37\x31\x2D\x31\x38\x38\x00\x00\x00\x00\x00\x00\x00\x00\x00", 20);

    strcpy(szTPDU, "6002700000");
    ulTraceNO = 569;
    strcpy(szTID, "21310045");
    strcpy(szMID, "000001050023054");
}
#endif

    inDE57Len = 0;
    inTempBufLen = 0;
    memset(byPayloadDE57, 0x00, sizeof(byPayloadDE57));
    memset(tempBuf, 0x00, sizeof(tempBuf));
    memset(szAsicBuf, 0x00, sizeof(szAsicBuf));   
    memcpy(&tempBuf[inTempBufLen], srNMXHeader.szEncAlgo, ENC_ALGO_SZ);
    inTempBufLen += ENC_ALGO_SZ;
    memcpy(&tempBuf[inTempBufLen], srNMXHeader.szKeyMag, KYM_MANAGE_SZ);
    inTempBufLen += KYM_MANAGE_SZ;
    memcpy(&tempBuf[inTempBufLen], srNMXHeader.szMACAlgo, MAC_ALGO_SZ);
    inTempBufLen += MAC_ALGO_SZ;
    memcpy(&tempBuf[inTempBufLen], srNMXHeader.szCommandCode, CMDCODE_SZ);
    inTempBufLen += CMDCODE_SZ; 
    inOutputLen = 255;
    iEncode250(tempBuf, inTempBufLen, szAsicBuf, &inOutputLen);
    memcpy(&byPayloadDE57[inDE57Len], szAsicBuf, inOutputLen);
    inDE57Len += inOutputLen;
    byPayloadDE57[inDE57Len++] = 0x01;
    
    inTempBufLen = 0;
    memset(tempBuf, 0x00, sizeof(tempBuf));
    memset(szAsicBuf, 0x00, sizeof(szAsicBuf));    
    memcpy(&tempBuf[inTempBufLen], srNMXHeader.szDeviceMode, DEVICE_MODEL_SZ);
    inTempBufLen += DEVICE_MODEL_SZ;
    inOutputLen = 255;
    iEncode250(tempBuf, inTempBufLen, szAsicBuf, &inOutputLen);
    memcpy(&byPayloadDE57[inDE57Len], szAsicBuf, inOutputLen);
    inDE57Len += inOutputLen;
    byPayloadDE57[inDE57Len++] = 0x01;
    
    inTempBufLen = 0;
    memset(tempBuf, 0x00, sizeof(tempBuf));
    memset(szAsicBuf, 0x00, sizeof(szAsicBuf));
    memcpy(&tempBuf[inTempBufLen], srNMXHeader.szDeviceSerNo, DEVICE_SERINAL_SZ);
    inTempBufLen += DEVICE_SERINAL_SZ;
    inOutputLen = 255;
    iEncode250(tempBuf, inTempBufLen, szAsicBuf, &inOutputLen);
    memcpy(&byPayloadDE57[inDE57Len], szAsicBuf, inOutputLen);
    inDE57Len += inOutputLen;
    byPayloadDE57[inDE57Len++] = 0x01;
    
    inTempBufLen = 0;
    memset(tempBuf, 0x00, sizeof(tempBuf));
    memset(szAsicBuf, 0x00, sizeof(szAsicBuf));
    memcpy(&tempBuf[inTempBufLen], srNMXHeader.szAppID, APPID_SZ);
    inTempBufLen += APPID_SZ;
    inOutputLen = 255;
    iEncode250(tempBuf, inTempBufLen, szAsicBuf, &inOutputLen);
    memcpy(&byPayloadDE57[inDE57Len], szAsicBuf, inOutputLen);
    inDE57Len += inOutputLen;
    
    vdNMX_DebugAddHEX("Enc250 DE57 field wise then packed 0x01", byPayloadDE57, inDE57Len);

    memset(szAsicBuf, 0x00, sizeof(szAsicBuf));
    memcpy(szAsicBuf, byPayloadDE57, inDE57Len);
    memset(byPayloadDE57, 0x00, sizeof(byPayloadDE57));
    inOutputLen = 255;

    iEncode64(szAsicBuf, inDE57Len, byPayloadDE57, &inOutputLen);
    inDE57Len = inOutputLen;

    vdNMX_DebugAddHEX("Enc64 DE57", byPayloadDE57, inDE57Len);    
   
    inCTOSS_NMX_FormRKIorTLEDownloadMessage(0, szTPDU, ulTraceNO, szTID, szMID, byPayloadDE57, inDE57Len, bySendData, &inSendDataLen);

    inResult = inCTOSS_NMX_ProcessTLEDownloadSendData(inHDTid, "0000000000000080", bySendData, &inSendDataLen);
    vdNMX_Debug_LogPrintf("inResult[%d]", inResult);
    DebugAddHEX("After NMX send data:",bySendData,inSendDataLen);
    if(0 > inResult)
        return inResult;
            
#ifdef TLE_DOWNLOAD_TEST
    {
        memset(bySendData, 0x00, sizeof(bySendData));
        strcpy(bySendData, "60000002700810203801000A8000819500000005691727100512027030303135383434373331333830303231333130303435015030312121212125393031303332343031212121212323464141523443567A4C566A527744634669566D4E387854457A5354314C6757666C756279376159356D666A69346C57432F557A735744617135503368634A67663534374264564434644E7942346664523174396A3852797977454A6D396F674E33424A5770443752685039456970343948372B457338696C4C59594475304478FBDEA5D02D57B4FB");
        inRecvDataLen = strlen(bySendData);
        inNMX_str_2_hex(bySendData, byReceiveData, inRecvDataLen);
        inRecvDataLen = inRecvDataLen/2;
    }
#else

    if (srNMXLibFunc.inSendData((char *)0x00, (char *)bySendData, inSendDataLen) != NMX_OK)
    {
        return NMX_SEND_DATA_ERR;
    }

    inRecvDataLen = srNMXLibFunc.inRecData((char *)0x00, (char *)byReceiveData);
    if (inRecvDataLen <= 0)
    {
        return NMX_RECV_DATA_ERR;
    }
#endif

    memset(szErrResponse, 0x00, sizeof(szErrResponse));
    inResult = inCTOSS_NMX_ProcessTLEDownloadRecvData(inHDTid, "0000000000000080", byReceiveData, &inRecvDataLen, szErrResponse);
    vdNMX_Debug_LogPrintf("inResult[%d] szErrResponse[%s]", inResult, szErrResponse);
    DebugAddHEX("After NMX recv data:",byReceiveData,inRecvDataLen);
    if(0 > inResult)
        return inResult;
    
    memset(szErrResponse, 0x00, sizeof(szErrResponse));
    inResult = inCTOSS_AnalyseTLEDownloadResponse(byReceiveData, inRecvDataLen, ulTraceNO, szTID, szErrResponse);
    if(NMX_OK != inResult)
        return inResult;

    vdNMX_Debug_LogPrintf("inCTOSS_NMX_TLEDownload End");
    
    return NMX_OK;
    
}

int inCTOSS_NMX_ChangeSamrtCardPINProcess(OUT char *szErrResponse)
{
    int inResult;
    BYTE byAcqID[40+1];
    BYTE byVendorID[40+1];
    BYTE byTSK[32+1];
    BYTE szRndA1B2B1A2[16+1];
    int inKeyLen = 0;

    vdNMX_Debug_LogPrintf("inCTOSS_NMX_ChangeSamrtCardPIN");
    
    if (srNMXLibFunc.vdEnterSmartCardPIN == 0x00 || srNMXLibFunc.vdEnterSmartCardNewPIN == 0x00)
        return  NMX_FUNCTION_NOT_INIT;

    inResult = inCTOSS_NMX_WaitingForSmartCard();
    vdNMX_Debug_LogPrintf("inCTOSS_NMX_WaitingForSmartCard[%d]", inResult);
    if(NMX_OK != inResult)
        return inResult;

    inPMPCInitSmartCard();

    inResult = inCTOSS_NMX_SmartCardSelectApplication(szErrResponse);
    vdNMX_Debug_LogPrintf("inResult[%d]", inResult);
    if(NMX_OK != inResult)
        return inResult;

    inCTOSS_NMX_SmartCardGetAppletInfo(byAcqID, byVendorID, szErrResponse);
    
    memset(byAcqID, 0x00, sizeof(byAcqID));
    memset(byVendorID, 0x00, sizeof(byVendorID));
    inResult = inCTOSS_NMX_SmartCardReadAcqIDVendorID(byAcqID, byVendorID, szErrResponse);
    if(NMX_OK != inResult)
        return inResult;

    memset(byTSK, 0x00, sizeof(byTSK));
    inResult = inCTOSS_NMX_InitSecureChannel(byAcqID, byVendorID, byTSK, &inKeyLen, szErrResponse);  
    vdNMX_Debug_LogPrintf("inResult[%d]", inResult);
    if(NMX_OK != inResult)
        return inResult;

    inResult = inCTOSS_NMX_MutualAuthentication(byTSK, szRndA1B2B1A2, szErrResponse);  
    if(NMX_OK != inResult)
        return inResult;

    inResult = inCTOSS_NMX_PINVerification(szRndA1B2B1A2, szErrResponse);  
    if(NMX_OK != inResult)
        return inResult;

    inResult = inCTOSS_NMX_ChangePIN(szRndA1B2B1A2, szErrResponse);  
    if(NMX_OK != inResult)
        return inResult;

    vdNMX_Debug_LogPrintf("inCTOSS_NMX_ChangeSamrtCardPIN End");
    
    return NMX_OK;
}

int inCTOSS_NMX_ChangeSamrtCardPIN(OUT char *szErrResponse)
{
    int inResult;

    inResult = inCTOSS_NMX_ChangeSamrtCardPINProcess(szErrResponse);

    return inResult;
}

int inCTOSS_NMX_DestroyKeys(void)
{
    int inResult;
    unsigned char szDEK[16+1];
    unsigned char szMEK[16+1];

    memset(szDEK, 0x00, sizeof(szDEK));
    memset(szMEK, 0x00, sizeof(szMEK));
    
    inCTOSS_NMX_Save3DESClearKeyForEncrypt(srNMXHeader.inRKIDEKKeySet, srNMXHeader.inRKIKeyIndex, szDEK);
    if(NMX_OK != inResult)
        return NMX_DESTROY_KEY_ERR;
    inCTOSS_NMX_Save3DESClearKeyForEncrypt(srNMXHeader.inRKIMEKKeySet, srNMXHeader.inRKIKeyIndex, szMEK);
    if(NMX_OK != inResult)
        return NMX_DESTROY_KEY_ERR;

    
    inCTOSS_NMX_Save3DESClearKeyForEncrypt(srNMXHeader.inTLEDEKKeySet, srNMXHeader.inTLEKeyIndex, szDEK);
    if(NMX_OK != inResult)
        return NMX_DESTROY_KEY_ERR;
    inCTOSS_NMX_Save3DESClearKeyForEncrypt(srNMXHeader.inTLEMEKKeySet, srNMXHeader.inTLEKeyIndex, szMEK);
    if(NMX_OK != inResult)
        return NMX_DESTROY_KEY_ERR;
            
    return NMX_OK;
}

int inCTOSS_NMX_ProcessSendData(IN int inHDTid, 
                                            INOUT unsigned char *pstReqBuf, INOUT unsigned int *inReqSiz)
{
    unsigned char uszTPDU[5+1];
    unsigned char uszMTI[2+1];
    unsigned char uszBitmap[8+1];
    unsigned char uszMACValue[8+1];
	unsigned char szPayload[1024];
	unsigned char uszEncryOutBuf[1024];
    unsigned char uszFullMessage[1024];
	int inEncryptDataLen;

	
    int inResult;


    inNMX_TCTRead(1);

    //for testing
#if 1
    memset(srNMXHeader.szDeviceMode, 0x00, sizeof(srNMXHeader.szDeviceMode));
    strcpy(srNMXHeader.szEncAlgo, "01");
	strcpy(srNMXHeader.szKeyMag, "4");
    strcpy(srNMXHeader.szMACAlgo, "3");
    strcpy(srNMXHeader.szCommandCode, "01");
    strcpy(srNMXHeader.szDeviceMode, "");
    strcpy(srNMXHeader.szDeviceSerNo, "");
    strcpy(srNMXHeader.szAppID, "01");
#endif
	//end testing

    DebugAddHEX("pstReqBuf:",pstReqBuf,inReqSiz);


    inCTOSS_NMX_Read(1);


    inCTOSS_NMX_GetCurrentTLEDEK(&srNMXHeader);

    //generate MAC
    memset(uszMACValue, 0x00, sizeof(uszMACValue));
    inResult = inCTOSS_NMX_GenerateMAC(1, &srNMXHeader, pstReqBuf+5, (*inReqSiz - 5), uszMACValue);
    vdNMX_Debug_LogPrintf("inCTOSS_NMX_GenerateMAC[%d]", inResult);
    if(NMX_OK != inResult)
    {
        return inResult;
    }

	//Generate random number
    memset(g_DiversificationData, 0x00, sizeof(g_DiversificationData));
    vdCTOSS_NMX_getRandomNumber(g_DiversificationData, 3);
    vdNMX_Debug_LogPrintf("g_DiversificationData[%s]", g_DiversificationData);

	//concat random number and ISO message
	memset(szPayload, 0x00, sizeof(szPayload));
	strcpy(szPayload,g_DiversificationData);
	strcat(szPayload,pstReqBuf);

	//encrypt cipher data
    inCTOSS_NMX_3DESEncryptCBC(g_CurrentTLEDEK, szPayload, strlen(szPayload), uszEncryOutBuf);


	//build the Full message
    memset(uszFullMessage, 0x00, sizeof(uszFullMessage));
	inEncryptDataLen = 0;
	//tpdu
	memcpy(uszFullMessage, "6007000000",10);
	inEncryptDataLen = 10;
	//header
	memcpy(&uszFullMessage[inEncryptDataLen], srNMXHeader.szAppID, APPID_SZ);
    inEncryptDataLen += APPID_SZ;

    memcpy(&uszFullMessage[inEncryptDataLen], srNMXHeader.szTLEKID, KEYID_SZ);
    inEncryptDataLen += KEYID_SZ;

    memcpy(&uszFullMessage[inEncryptDataLen], srNMXHeader.szVersion, VERSION_SZ);
    inEncryptDataLen += VERSION_SZ;

    memcpy(&uszFullMessage[inEncryptDataLen], srNMXHeader.szEncAlgo, ENC_ALGO_SZ);
    inEncryptDataLen += ENC_ALGO_SZ;

    memcpy(&uszFullMessage[inEncryptDataLen], srNMXHeader.szKeyMag, KYM_MANAGE_SZ);
    inEncryptDataLen += KYM_MANAGE_SZ;

    memcpy(&uszFullMessage[inEncryptDataLen], srNMXHeader.szMACAlgo, MAC_ALGO_SZ);
    inEncryptDataLen += MAC_ALGO_SZ;

    memcpy(&uszFullMessage[inEncryptDataLen], srNMXHeader.szFlag, FLAG_SZ);
    inEncryptDataLen += FLAG_SZ;

    memcpy(&uszFullMessage[inEncryptDataLen], srNMXHeader.szCounter, TXNCOUNTER_SZ);
    inEncryptDataLen += TXNCOUNTER_SZ;

    memcpy(&uszFullMessage[inEncryptDataLen], srNMXHeader.szCounter, TXNCOUNTER_SZ);
    inEncryptDataLen += TXNCOUNTER_SZ;

    memcpy(&uszFullMessage[inEncryptDataLen], uszEncryOutBuf, strlen(uszEncryOutBuf));
    inEncryptDataLen += strlen(uszEncryOutBuf);


    memcpy(&uszFullMessage[inEncryptDataLen], uszMACValue, 8);
    inEncryptDataLen += 8;

     
    return (inEncryptDataLen);
}

int inCTOSS_NMX_ProcessRecvData(IN int inHDTid, 
                                            IN unsigned char *szSensitiveBitmap,
                                            INOUT unsigned char *pstReqBuf, INOUT unsigned int *inReqSiz, 
                                            OUT char *szErrResponse)
{
    int inResult;
    unsigned char uszTPDU[5+1];
    unsigned char uszMTI[2+1];
    unsigned char uszBitmap[8+1];
    unsigned char szMACbuf[64];
    unsigned char szSourceMACbuf[64];

    int inFieldDataLen;
    unsigned char uszFieldDataBuf[512+1];

    vdNMX_Debug_LogPrintf("inCTOSS_NMX_ProcessRecvData");
    
    // UnPack ISO8583
    memset(uszTPDU, 0x00, sizeof(uszTPDU));
    memset(uszMTI, 0x00, sizeof(uszMTI));
    memset(uszBitmap, 0x00, sizeof(uszBitmap));
    inResult = inCTOSS_Process_8583_UnPack(inHDTid, pstReqBuf, *inReqSiz, uszTPDU, uszMTI, uszBitmap);
    vdNMX_Debug_LogPrintf("inCTOSS_Process_8583_UnPack[%d]", inResult);
    if(NMX_OK != inResult)
    {
        return NMX_INVALID_ISO;
    }

    //if DE64 not exist
    if(!(uszBitmap[7] & 0x01))
    {
        return NMX_WRONG_MAC;
    }

    inResult = inCTOSS_GetISOFieldData(39, uszFieldDataBuf, &inFieldDataLen);
    vdNMX_Debug_LogPrintf("DE39[%s]", uszFieldDataBuf);
    if (memcmp(uszFieldDataBuf, "ER", 2) == 0)
    {
        inResult = inCTOSS_GetISOFieldData(62, uszFieldDataBuf, &inFieldDataLen);
        strcpy(szErrResponse, &uszFieldDataBuf[2]);
        return NMX_HOST_REJECT;
    }

    memset(szSourceMACbuf, 0x00, sizeof(szSourceMACbuf));
    inResult = inCTOSS_GetISOFieldData(64, szSourceMACbuf, &inFieldDataLen);
    vdNMX_DebugAddHEX("MAC", szSourceMACbuf, inFieldDataLen);
    
    inCTOSS_NMX_Read(1);
    
    //if DE57 is on?
    if (uszBitmap[7] & 0x80)
    {
        if(inCTOSS_NMX_DecryptSensitiveFieldsData(1, &srNMXHeader, uszBitmap) < 0)
        {
            inFieldDataLen = 0;
            memset(uszFieldDataBuf, 0x00, sizeof(uszFieldDataBuf));
            inCTOSS_SetISOFieldData(39, uszFieldDataBuf, inFieldDataLen);

            vdNMX_Debug_LogPrintf("NMX_DECRYPT_ERR");
            return NMX_DECRYPT_ERR;
        }
    }

    vdCTOSS_NMX_TurnOffBit(uszBitmap, 57);
    vdCTOSS_NMX_TurnOffBit(uszBitmap, 64);

    // Pack ISO8583
    inResult = inCTOSS_Process_8583_Pack(inHDTid, pstReqBuf, inReqSiz, uszTPDU, uszMTI, uszBitmap);
    vdNMX_Debug_LogPrintf("inResult[%d] *inReqSiz[%d]", inResult, *inReqSiz);
    vdNMX_DebugAddHEX("NMX decrypt ISO", pstReqBuf, (* inReqSiz));
    
    memset(szMACbuf, 0x00, sizeof(szMACbuf));
    inResult = inCTOSS_NMX_GenerateMAC(1, &srNMXHeader, pstReqBuf + 5, (*inReqSiz - 5), szMACbuf);
    if(NMX_OK != inResult)
    {
        *inReqSiz = 0;
        return inResult;
    }

    vdNMX_DebugAddHEX("MAC RESPONSE", szSourceMACbuf, 4);
    vdNMX_DebugAddHEX("MAC CAL", szMACbuf, 4);

    if (memcmp(szMACbuf, szSourceMACbuf, 4) != 0)
    {   
        strcpy(szErrResponse, "WRONG MAC!!!");
        *inReqSiz = 0;
        return NMX_WRONG_MAC;
    }

    
    return *inReqSiz;
    
}

int inCTOSS_NMX_ProcessTLEDownloadSendData(IN int inHDTid, 
                                            IN unsigned char *szSensitiveBitmap,
                                            INOUT unsigned char *pstReqBuf, INOUT unsigned int *inReqSiz)
{
    unsigned char uszTPDU[5+1];
    unsigned char uszMTI[2+1];
    unsigned char uszBitmap[8+1];
    unsigned char uszMACValue[8+1];
    int inResult;


    inNMX_TCTRead(1);
    
    vdNMX_Debug_LogPrintf("inCTOSS_NMX_ProcessTLEDownloadSendData [%s]", szSensitiveBitmap);
    
    if(strlen(szSensitiveBitmap) != 16)
    {
        return NMX_INVALID_PARA;
    }

    memset(g_DiversificationData, 0x00, sizeof(g_DiversificationData));
    vdCTOSS_NMX_getRandomNumber(g_DiversificationData, 3);
    vdNMX_Debug_LogPrintf("g_DiversificationData[%s]", g_DiversificationData);
    

    inCTOSS_NMX_Read(1);

    if(0 == strlen(srNMXHeader.szEncAlgo))
        strcpy(srNMXHeader.szEncAlgo, "03");
    if(0 == strlen(srNMXHeader.szKeyMag))
        strcpy(srNMXHeader.szKeyMag, "2");
    if(0 == strlen(srNMXHeader.szMACAlgo))
        strcpy(srNMXHeader.szMACAlgo, "3");
    if(0 == strlen(srNMXHeader.szCommandCode))
        strcpy(srNMXHeader.szCommandCode, "01");
    if(0 == strlen(srNMXHeader.szDeviceMode))
        strcpy(srNMXHeader.szDeviceMode, "CASTLES V3");
    if(0 == strlen(srNMXHeader.szAppID))
        strcpy(srNMXHeader.szAppID, "01");
    if(0 == strlen(srNMXHeader.szTLEKID))
        strcpy(srNMXHeader.szTLEKID, g_szTestTLEKID);

    vdNMX_Debug_LogPrintf("srNMXHeader.szTLEKID[%s]g_szTestTLEKID[%s]", srNMXHeader.szTLEKID, g_szTestTLEKID);

    if(0 == srNMXHeader.inRKIDEKKeySet)
        srNMXHeader.inRKIDEKKeySet = 100;
    if(0 == srNMXHeader.inRKIMEKKeySet)
        srNMXHeader.inRKIMEKKeySet = 104;
    if(0 == srNMXHeader.inRKIKeyIndex)
        srNMXHeader.inRKIKeyIndex = 2;
    if(0 == srNMXHeader.inTLEDEKKeySet)
        srNMXHeader.inTLEDEKKeySet = 120;
    if(0 == srNMXHeader.inTLEMEKKeySet)
        srNMXHeader.inTLEMEKKeySet = 124;
    if(0 == srNMXHeader.inTLEKeyIndex)
        srNMXHeader.inTLEKeyIndex = 2;

    vdNMX_Debug_LogPrintf("srNMXHeader.szTLEKID[%s] srNMXHeader.szCounter[%s]", srNMXHeader.szTLEKID, srNMXHeader.szCounter);
    if(KEY_MANAGE_PER_TERMINAL == srNMXHeader.szKeyMag[0])
        strcpy(srNMXHeader.szCounter, "!!!!##");
    
    inCTOSS_NMX_GetCurrentRKIDEK(&srNMXHeader);

#ifdef TLE_DOWNLOAD_TEST
{
    strcpy(g_DiversificationData, "139");
    memcpy(srNMXHeader.szRKIKID, "\x21\x21\x21\x21\x25\x39", 6);
    memcpy(srNMXHeader.szCounter,"\x21\x21\x21\x21\x23\x23", 6);
}
#endif

    memset(uszTPDU, 0x00, sizeof(uszTPDU));
    memset(uszMTI, 0x00, sizeof(uszMTI));
    memset(uszBitmap, 0x00, sizeof(uszBitmap));

    inResult = inCTOSS_Process_8583_UnPack(inHDTid, pstReqBuf, *inReqSiz, uszTPDU, uszMTI, uszBitmap);
    vdNMX_Debug_LogPrintf("inCTOSS_Process_8583_UnPack[%d] MAC ON?[%d]", inResult, uszBitmap[7] & 0x01);
    if(NMX_OK != inResult)
    {
        return NMX_INVALID_ISO;
    }

    if (uszBitmap[7] & 0x01)
    {
        vdCTOSS_NMX_TurnOffBit(uszBitmap, 64);
        inResult = inCTOSS_Process_8583_Pack(inHDTid, pstReqBuf, inReqSiz, uszTPDU, uszMTI, uszBitmap);
    }   

    memset(uszMACValue, 0x00, sizeof(uszMACValue));
    inResult = inCTOSS_NMX_GenerateMAC(0, &srNMXHeader, pstReqBuf+5, (*inReqSiz - 5), uszMACValue);
    vdNMX_Debug_LogPrintf("inCTOSS_NMX_GenerateMAC[%d]", inResult);
    if(NMX_OK != inResult)
    {
        return inResult;
    }
    
    memcpy(srNMXHeader.szSensitiveFieldBMP, szSensitiveBitmap, 16);
    inResult = inCTOSS_NMX_EncryptSensitiveFieldsData(0, &srNMXHeader, uszBitmap);
    vdNMX_Debug_LogPrintf("inCTOSS_NMX_EncryptSensitiveFieldsData[%d]", inResult);
    if(NMX_OK != inResult)
    {
        return inResult;
    }

     //add DE64
    vdCTOSS_NMX_TurnOnBit(uszBitmap, 64);
    //memset(uszMACValue+4, 0x00, 4);
    inCTOSS_SetISOFieldData(64, uszMACValue, 8);
    
    // Pack ISO8583
    inResult = inCTOSS_Process_8583_Pack(inHDTid, pstReqBuf, inReqSiz, uszTPDU, uszMTI, uszBitmap);
    vdNMX_DebugAddHEX("NMX encry ISO", pstReqBuf, (* inReqSiz));
    
    return (int) (* inReqSiz);
}


int inCTOSS_NMX_ProcessTLEDownloadRecvData(IN int inHDTid, 
                                            IN unsigned char *szSensitiveBitmap,
                                            INOUT unsigned char *pstReqBuf, INOUT unsigned int *inReqSiz, 
                                            OUT char *szErrResponse)
{
    int inResult;
    unsigned char uszTPDU[5+1];
    unsigned char uszMTI[2+1];
    unsigned char uszBitmap[8+1];
    unsigned char szMACbuf[64];
    unsigned char szSourceMACbuf[64];

    int inFieldDataLen;
    unsigned char uszFieldDataBuf[512+1];

    vdNMX_Debug_LogPrintf("inCTOSS_NMX_ProcessRecvData");
    
    // UnPack ISO8583
    memset(uszTPDU, 0x00, sizeof(uszTPDU));
    memset(uszMTI, 0x00, sizeof(uszMTI));
    memset(uszBitmap, 0x00, sizeof(uszBitmap));
    inResult = inCTOSS_Process_8583_UnPack(inHDTid, pstReqBuf, *inReqSiz, uszTPDU, uszMTI, uszBitmap);
    vdNMX_Debug_LogPrintf("inCTOSS_Process_8583_UnPack[%d]", inResult);
    if(NMX_OK != inResult)
    {
        return NMX_INVALID_ISO;
    }

    //if DE64 not exist
    if(!(uszBitmap[7] & 0x01))
    {
        return NMX_WRONG_MAC;
    }

    inResult = inCTOSS_GetISOFieldData(39, uszFieldDataBuf, &inFieldDataLen);
    vdNMX_Debug_LogPrintf("DE39[%s]", uszFieldDataBuf);
    if (memcmp(uszFieldDataBuf, "ER", 2) == 0)
    {
        inResult = inCTOSS_GetISOFieldData(62, uszFieldDataBuf, &inFieldDataLen);
        strcpy(szErrResponse, &uszFieldDataBuf[2]);
        return NMX_HOST_REJECT;
    }

    memset(szSourceMACbuf, 0x00, sizeof(szSourceMACbuf));
    inResult = inCTOSS_GetISOFieldData(64, szSourceMACbuf, &inFieldDataLen);
    vdNMX_DebugAddHEX("MAC", szSourceMACbuf, inFieldDataLen);
    
    inCTOSS_NMX_Read(1);
    
    vdCTOSS_NMX_TurnOffBit(uszBitmap, 64);

    //if DE57 is on?
    if (uszBitmap[7] & 0x80)
    {
        vdCTOSS_NMX_TurnOffBit(uszBitmap, 57);
    
        if(inCTOSS_NMX_DecryptSensitiveFieldsData(0, &srNMXHeader, uszBitmap) < 0)
        {
            inFieldDataLen = 0;
            memset(uszFieldDataBuf, 0x00, sizeof(uszFieldDataBuf));
            inCTOSS_SetISOFieldData(39, uszFieldDataBuf, inFieldDataLen);

            vdNMX_Debug_LogPrintf("NMX_DECRYPT_ERR");
            return NMX_DECRYPT_ERR;
        }
    }

    // Pack ISO8583
    inResult = inCTOSS_Process_8583_Pack(inHDTid, pstReqBuf, inReqSiz, uszTPDU, uszMTI, uszBitmap);
    vdNMX_Debug_LogPrintf("inResult[%d] *inReqSiz[%d]", inResult, *inReqSiz);
    vdNMX_DebugAddHEX("NMX decrypt ISO", pstReqBuf, (* inReqSiz));
    
    memset(szMACbuf, 0x00, sizeof(szMACbuf));
    inResult = inCTOSS_NMX_GenerateMAC(0, &srNMXHeader, pstReqBuf + 5, (*inReqSiz - 5), szMACbuf);
    if(NMX_OK != inResult)
    {
        *inReqSiz = 0;
        return inResult;
    }

    vdNMX_DebugAddHEX("MAC RESPONSE", szSourceMACbuf, 4);
    vdNMX_DebugAddHEX("MAC CAL", szMACbuf, 4);

    if (memcmp(szMACbuf, szSourceMACbuf, 4) != 0)
    {   
        strcpy(szErrResponse, "WRONG MAC!!!");
        *inReqSiz = 0;
        return NMX_WRONG_MAC;
    }

    
    return *inReqSiz;
    
}

NMX_FUNC_TABLE* vdGetNMX_FUNC_TABLEAddress(void)
{
    return ((NMX_FUNC_TABLE*)(&srNMXLibFunc));
}



int inCTOSS_NMX_SaveAESClearKeyForEncrypt(int inKeySet, int inKeyIndex, unsigned char *szClearKey)
{
	BYTE KeyData[16];
	int KeySet, KeyIndex;
	BYTE str[17];
	int inRet;
	BYTE key[33];

	CTOS_KMS2KEYWRITE_PARA para;
	//memset(KeyData,0x00, sizeof(KeyData));
	//Pack(szClearKey, 32, KeyData);//Pack only if master key is not BCD

	//KeySet = 0xC001;
	//KeyIndex = 0x0001;

	DebugAddHEX("szClearKey = ", szClearKey, 16);
	vdDebug_LogPrintf("keyset %d",inKeySet);
	vdDebug_LogPrintf("keyindex %d",inKeyIndex);


	
	memset(&para, 0x00, sizeof(CTOS_KMS2KEYWRITE_PARA));
	para.Version = 0x01;
	para.Info.KeySet = KeySet;
	para.Info.KeyIndex = KeyIndex;
	para.Info.KeyType = KMS2_KEYTYPE_AES;
	para.Info.KeyVersion = 0x01;
	para.Info.KeyAttribute = KMS2_KEYATTRIBUTE_PIN | KMS2_KEYATTRIBUTE_ENCRYPT | KMS2_KEYATTRIBUTE_MAC | KMS2_KEYATTRIBUTE_KPK;
	para.Protection.Mode = KMS2_KEYPROTECTIONMODE_PLAINTEXT;
	para.Value.pKeyData = szClearKey;
	para.Value.KeyLength = 16;
	inRet = CTOS_KMS2KeyWrite(&para);
	if(inRet != d_OK)
	{
		sprintf(str, "ret = 0x%04X", inRet);
		CTOS_LCDTPrintXY(1, 8, str);
		vdDebug_LogPrintf("inject  error");
		return d_OK;
	}

	vdDebug_LogPrintf("inject  OK");

}

int inCTOSS_NMX_SaveAESClearKeyForDecrypt(int inKeySet, int inKeyIndex, unsigned char *szClearKey){
	BYTE KeyData[16];
	int KeySet, KeyIndex;
	BYTE str[17];
	int inRet;
	BYTE key[33];

	CTOS_KMS2KEYWRITE_PARA para;
	//memset(KeyData,0x00, sizeof(KeyData));
	//Pack(szClearKey, 32, KeyData);//Pack only if master key is not BCD

	//KeySet = 0xC001;
	//KeyIndex = 0x0001;

	memset(&para, 0x00, sizeof(CTOS_KMS2KEYWRITE_PARA));
	para.Version = 0x01;
	para.Info.KeySet = KeySet;
	para.Info.KeyIndex = KeyIndex + 1;
	para.Info.KeyType = KMS2_KEYTYPE_AES;
	para.Info.KeyVersion = 0x01;
	para.Info.KeyAttribute = KMS2_KEYATTRIBUTE_PIN | KMS2_KEYATTRIBUTE_ENCRYPT | KMS2_KEYATTRIBUTE_MAC | KMS2_KEYATTRIBUTE_KPK;
	para.Protection.Mode = KMS2_KEYPROTECTIONMODE_PLAINTEXT;
	para.Value.pKeyData = szClearKey;
	para.Value.KeyLength = 16;
	inRet = CTOS_KMS2KeyWrite(&para);
	if(inRet != d_OK)
	{
		sprintf(str, "ret = 0x%04X", inRet);
		CTOS_LCDTPrintXY(1, 8, str);
		vdDebug_LogPrintf("inject  error");
		return d_OK;
	}

	vdDebug_LogPrintf("inject  OK");


}


