#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctosapi.h>
#include <emv_cl.h>
#include <EMVAPLib.h>
#include <EMVLib.h>
#include <vwdleapi.h>


#include "..\Includes\POSTypedef.h"
#include "..\Debug\Debug.h"

#include "..\Includes\POSMain.h"
#include "..\Includes\POSTrans.h"
#include "..\Includes\POSHost.h"
#include "..\Includes\POSSale.h"
#include "..\Includes\POSbatch.h"
#include "..\ui\Display.h"
#include "..\Includes\V5IsoFunc.h"
#include "..\Accum\Accum.h"
#include "..\print\Print.h"
#include "..\Comm\V5Comm.h"
#include "..\Includes\MultiApLib.h"
#include "..\Aptrans\MultiAptrans.h"
#include "..\Includes\Wub_lib.h"
#include "..\Database\DatabaseFunc.h"
#include "..\ApTrans\MultiShareEMV.h"
#include "..\Includes\CardUtil.h"
#include "..\Includes\POSSetting.h"
#include "..\Includes\Desfire.h"
#include "..\Includes\aes.h"
#include <openssl/cmac.h>


#include "POSCtls.h"
#include "POSMifare.h"




#define	d_MsessionFlag		0x00
#define d_AsessionFlag		0x01

extern BOOL fAutoSMACLogon;
extern BOOL fTimeOutFlag;
BYTE GlobalDivKey[16+1];

int inGetSessionKey(BYTE *bSessionKey)
{
	int r = 0, inRet = -1;
	unsigned short RecvLen = 0;
	BYTE szKey[16+1] = {0};
	BYTE bEncRandA[16+1] = {0};
	BYTE bEncRandB[16+1] = {0};
	BYTE bRandA[16+1] = {0};
	BYTE bRandB[16+1] = {0};
	BYTE bRandAEx[16+1] = {0};
	BYTE bRandBEx[16+1] = {0};
	BYTE bRandA_bRandBEx[32+1] = {0};
	BYTE bEncbRandA_bRandBEx[32+1] = {0};
	BYTE bIV[16+1] = {0};
	BYTE szTempBuff[16+1] = {0};
	char szRandA[32+1] = {0};
	char szEncRandB[32+1] = {0};
	char szRandBEx[32+1] = {0};
	char szRandA_RandBEx[32+1] = {0};
	unsigned char szRespBuf[500] = {0};
	unsigned char szRecvBuf[500] = {0};
	
	szRespBuf[0] = 0xAA;
	szRespBuf[1] = 0x06;
	RecvLen=64;

	//DebugAddHEX("SEND szRespBuf",szRespBuf,2);
	r = CTOS_CLAPDU(szRespBuf, 2, szRecvBuf, &RecvLen);
	//vdDebug_LogPrintf("r %d :: szRecvBuf[0] %02x, RecvLen %d",r,szRecvBuf[0],RecvLen);
		
	if (r || RecvLen < 5 || (szRecvBuf[0] != 0xAF && szRecvBuf[0] != 0))
		return 1;
	
	//DebugAddHEX("RECV szRespBuf",szRecvBuf,RecvLen);

	
	memset(bRandB,0x00,sizeof(bRandB));
	memset(bIV,0x00,sizeof(bIV));
	memcpy(bEncRandB,&szRecvBuf[1],16);		//get encrypted random B. 
	memcpy(bIV,bEncRandB,16);				//Encrypted random B will be used as IV for encryption later.
	memcpy(szKey,GlobalDivKey,16);			//get diversified key to be used for decryption and encryption.
	
	inRet = CTOS_AES(d_DECRYPTION, szKey, bEncRandB, 16, bRandB);//decrypt random B using iv 000000000... 
			
	memcpy(bRandBEx,&bRandB[1],15);
	memcpy(&bRandBEx[15],bRandB,1);			//get random B' by shifting random B eight bytes to the left.
		
	vdGenerateRandomKey(16, szRandA);		//generate Random A.
	
	Pack(szRandA,32,bRandA);

	memcpy(bRandA_bRandBEx,bRandA,16);
	memcpy(&bRandA_bRandBEx[16],bRandBEx,16);//concatenate Random A and Random B'

	AES128_CBC_encrypt_buffer(bEncbRandA_bRandBEx,bRandA_bRandBEx,32,(const uint8_t *)szKey,(const uint8_t *)bIV);
	
	//DebugAddHEX("szEncbRandA_bRandBEx",bEncbRandA_bRandBEx,32);

	memset(bIV,0x00,sizeof(bIV));
	memcpy(bIV,&bEncbRandA_bRandBEx[16],16);//get last 16 bytes of bEncbRandA_bRandBEx as IV.
	
	memset(szRespBuf,0x00,sizeof(szRespBuf));
	szRespBuf[0] = 0xAF;
	memcpy(&szRespBuf[1],bEncbRandA_bRandBEx,32);
	RecvLen=64;

	//DebugAddHEX("SEND szRespBuf",szRespBuf,33);
	r = CTOS_CLAPDU(szRespBuf, 33, szRecvBuf, &RecvLen);
	//vdDebug_LogPrintf("r %d :: szRecvBuf[0] %02x, RecvLen %d",r,szRecvBuf[0],RecvLen);
		
	if (r || RecvLen < 5 || (szRecvBuf[0] != 0xAF && szRecvBuf[0] != 0))
		return 1;
	
	//DebugAddHEX("RECV szRespBuf",szRecvBuf,RecvLen);
	
	memset(bEncRandA,0x00,sizeof(bEncRandA));
	memcpy(bEncRandA,&szRecvBuf[1],16);
	AES128_CBC_decrypt_buffer(bRandAEx,bEncRandA,16,(const uint8_t *)szKey,(const uint8_t *)bIV);
	memcpy(szTempBuff,&bRandAEx[15],1);
	memcpy(&szTempBuff[1],bRandAEx,15);
		
	if(memcmp(szTempBuff,bRandA,16) != 0)
	{
		//vdDebug_LogPrintf("random A verification failed");
		return d_NO;
	}

	//vdDebug_LogPrintf("random A match");
	
	memset(bSessionKey,0x00,sizeof(bSessionKey));
	memcpy(bSessionKey,bRandA,4);
	memcpy(&bSessionKey[4],bRandB,4);
	memcpy(&bSessionKey[8],&bRandA[12],4);
	memcpy(&bSessionKey[12],&bRandB[12],4);

	DebugAddHEX("bSessionKey",bSessionKey,16);
	
	return d_OK;

}
int inGetCMAC(BYTE *bInput, int inLen, BYTE *bOutput, BYTE *bSessionKey)
{
	size_t mactlen;
	
	CMAC_CTX *ctx = CMAC_CTX_new();
	CMAC_Init(ctx, bSessionKey, 16, EVP_aes_128_cbc(), NULL);
	//DebugAddHEX("bInput",bInput,6);
	vdDebug_LogPrintf("message length = %lu bytes (%lu bits)",inLen, inLen*8);
	CMAC_Update(ctx, bInput, inLen);
	CMAC_Final(ctx, bOutput, &mactlen);
	//vdDebug_LogPrintf("CMAC LEN %d",mactlen);
	CMAC_CTX_free(ctx);
	return d_OK;
}

void vdGenerateRandomKey(int inLen, BYTE *ptrResult)
{
	int i;
	time_t t;
	BYTE szRandomKey[64+1];
    BYTE sKey[2+1];
	int inRandonNum=0;

    vdDebug_LogPrintf("vdGenerateRandomKey");
	vdDebug_LogPrintf("Len:%d", inLen);
	
	memset(szRandomKey, 0, sizeof(szRandomKey));
	
	/* Intializes random number generator */
	srand((unsigned) time(&t));
	
	/* get 16 random numbers from 0 to 49 */
	for( i = 0 ; i < inLen ; i++ ) {
	   inRandonNum=rand() % 255;
	   //vdDebug_LogPrintf("b=%02X", (int)inRandonNum);
	   memset(sKey, 0, sizeof(sKey));
	   sprintf(sKey, "%02X", inRandonNum);
	   memcpy(&szRandomKey[i*2], sKey, 2);
	}
	//vdDebug_LogPrintf("*szRandomKey", szRandomKey);
	vdDebug_LogPrintf("szRandomKey:%s", szRandomKey);
	
	memcpy(ptrResult,szRandomKey,(inLen*2));
}

int inDesfireReadStdData(BYTE fid, unsigned long Offset, unsigned long Length, BYTE *p)
{
	unsigned short buffsize = 0;
	BYTE buff[64] = {0};
	int i = 0, r = 0;
	int ret = 0;


	buff[0] = 0xBD;
	buff[1] = fid;
	buff[2] = Offset & 0xFF;
	buff[3] = (Offset >> 8) & 0xFF;
	buff[4] = (Offset >> 16) & 0xFF;
	buff[5] = Length & 0xFF;
	buff[6] = (Length >> 8) & 0xFF;
	buff[7] = (Length >> 16) & 0xFF;


	buffsize=64;
	i = CTOS_CLAPDU(buff, 8, buff, &buffsize);

	
	
	if (i!= d_OK|| (buffsize < 8) || (buff[0] != 0xAF && buff[0] != 0))
		return 1;

	r = buffsize;
	
	while (buff[0] == 0xAF)
	{
		--r;
		memcpy (p, buff+1, r);
		p += r;
		ret += r;
		buff[0] = 0xAF;

		buffsize=64;
		i = CTOS_CLAPDU(buff, 1, buff, &buffsize);
		
		if (i || (buffsize < 8) || (buff[0] != 0xAF && buff[0] != 0))
			return i;
		r = buffsize;
	}
	
	r -= 9;
	ret += r;
	memcpy (p, buff+1, r);

	return ret;
}


int inDesfireWriteStdData(BYTE fid, unsigned long Offset, unsigned long Length, BYTE *p)
{
	unsigned short buffsize = 0;
	BYTE buff[64] = {0};
	int i = 0, r = 0;
	int ret = 0;


	buff[0] = 0x3D;
	buff[1] = fid;
	buff[2] = Offset & 0xFF;
	buff[3] = (Offset >> 8) & 0xFF;
	buff[4] = (Offset >> 16) & 0xFF;
	buff[5] = Length & 0xFF;
	buff[6] = (Length >> 8) & 0xFF;
	buff[7] = (Length >> 16) & 0xFF;

	memcpy(&buff[8],p,Length);
	
	buffsize=64;
	//DebugAddHEX("buff",buff,Length+8);
	i = CTOS_CLAPDU(buff, Length+8, buff, &buffsize);


	if (i!= d_OK|| (buffsize < 8) || (buff[0] != 0xAF && buff[0] != 0))
		return 1;

	r = buffsize;
		
	return i;
}

int inDesfireGetBalance(BYTE PurseID, long *pVal)
{
	unsigned short RecvLen = 0;
	unsigned char szRespBuf[500] = {0};
	unsigned char szRecvBuf[500] = {0};	
	int r = 0;

	
	szRespBuf[0] = 0x6C;
	szRespBuf[1] = PurseID;
	RecvLen=64;
	r = CTOS_CLAPDU(szRespBuf, 2, szRecvBuf, &RecvLen);

	
	if (r || RecvLen < 5 || szRecvBuf[0] != 0x00)
		return r;

	*pVal = szRecvBuf[1] + szRecvBuf[2] * 256 + szRecvBuf[3] *256 * 256 + szRecvBuf[4] * 256 * 256 * 256;
	return 0x00;
}

int inDesfireStdDebit(BYTE PurseID, long *pVal)
{
	int r = 0, inRet = -1;
	unsigned short RecvLen = 0;
	unsigned char szRespBuf[500] = {0};
	unsigned char szRecvBuf[500] = {0};
	unsigned long DebitAmount = (unsigned long *)pVal;
	BYTE bSessionKey[16+1] = {0}; 
	BYTE bCMAC[16+1] = {0};
	
	inRet = inGetSessionKey(bSessionKey);
	if(inRet != d_OK)
		return d_NO;
	
	szRespBuf[0] = 0xDC;
	szRespBuf[1] = PurseID;
	szRespBuf[2] = DebitAmount & 0xFF;
	szRespBuf[3] = (DebitAmount >> 8) & 0xFF;
	szRespBuf[4] = (DebitAmount >> 16) & 0xFF;
	szRespBuf[5] = (DebitAmount >> 24) & 0xFF;
	

	memset(bCMAC,0x00,sizeof(bCMAC));
	
	inGetCMAC(szRespBuf,6,bCMAC,bSessionKey);
	memcpy(&szRespBuf[6],bCMAC,8);
	
	RecvLen=64;
#if 0
	DebugAddHEX("DEBIT BUFFER",szRespBuf,6);
	r = CTOS_CLAPDU(szRespBuf, 6, szRecvBuf, &RecvLen);
#else
	DebugAddHEX("DEBIT BUFFER",szRespBuf,14);
	r = CTOS_CLAPDU(szRespBuf, 14, szRecvBuf, &RecvLen);
#endif
	vdDebug_LogPrintf("r %d :: szRecvBuf[0] %02x",r,szRecvBuf[0]);
		
	if (r || RecvLen < 5 || szRecvBuf[0] != 0x00)
		return 1;

	return 0x00;
}


int inDesfireStdCredit(BYTE PurseID, long *pVal)
{
	int i,inLen,r = 0, inRet = -1;
	unsigned short RecvLen = 0;
	unsigned char szRespBuf[500] = {0};
	unsigned char szRecvBuf[500] = {0};
	unsigned long DebitAmount = (unsigned long *)pVal;
	BYTE bSessionKey[16+1] = {0}; 
	BYTE bCMAC[16+1] = {0};

	
	inRet = inGetSessionKey(bSessionKey);
	if(inRet != d_OK)
		return d_NO;

	vdDebug_LogPrintf("CreditAmount %lu",DebitAmount);
	
	szRespBuf[0] = 0x0C;
	szRespBuf[1] = PurseID;
	szRespBuf[2] = DebitAmount & 0xFF;
	szRespBuf[3] = (DebitAmount >> 8) & 0xFF;
	szRespBuf[4] = (DebitAmount >> 16) & 0xFF;
	szRespBuf[5] = (DebitAmount >> 24) & 0xFF;

	memset(bCMAC,0x00,sizeof(bCMAC));
	
	inGetCMAC(szRespBuf,6,bCMAC,bSessionKey);
	memcpy(&szRespBuf[6],bCMAC,8);
	
	RecvLen=64;
#if 0
	DebugAddHEX("CREDIT BUFFER",szRespBuf,6);
	r = CTOS_CLAPDU(szRespBuf, 6, szRecvBuf, &RecvLen);
#else
	DebugAddHEX("CREDIT BUFFER",szRespBuf,14);
	r = CTOS_CLAPDU(szRespBuf, 14, szRecvBuf, &RecvLen);
#endif

	vdDebug_LogPrintf("r %d :: szRecvBuf[0] %02x",r,szRecvBuf[0]);
		
	if (r || RecvLen < 5 || szRecvBuf[0] != 0x00)
		return 1;

		
	return 0x00;
}



BYTE ith(BYTE c)
{
	if(c >= '0' && c <= '9')
	{
		return c - '0';
	}
	else if(c >= 'A' && c <= 'F')
	{
		return c - 'A' + 10;
	}
	else if(c >= 'a' && c <= 'f')
	{
		return c - 'a' + 10;
	}
	
	return 0;
}

void Pack(BYTE *pData, USHORT usLen, BYTE *pResult)
{
	USHORT i;
	BYTE v;
	
	for(i = 0; i < usLen; i += 2)
	{
		v = ith(pData[i]);
		v <<= 4;
		v |= ith(pData[i+1]);
		*pResult++ = v;
	}
}




int inReadMIFARECard(void)
{
    USHORT uRtn;
    BYTE baATQA[16];
    BYTE bSAK[16];
    BYTE baCSN[16];
    BYTE bCSNLen;
    BYTE baATS[16];
	BYTE byKeyBuf;
    USHORT bATSLen;
    
	CTOS_TimeOutSet(TIMER_ID_2 , inGetIdleTimeOut(FALSE));

    do{	
		if(CTOS_TimeOutCheck(TIMER_ID_2) == d_YES)
		{
			fTimeOutFlag = TRUE; /*BDO: Flag for timeout --sidumili*/
			return READ_CARD_TIMEOUT;
		}
		
        uRtn = CTOS_CLTypeAActiveFromIdle(0,baATQA,bSAK,baCSN,&bCSNLen);

		CTOS_KBDHit(&byKeyBuf);
        if (byKeyBuf == d_KBD_CANCEL)
        {
            CTOS_KBDBufFlush ();
            return USER_CANCEL;
        }	
		
    }while(uRtn != 0);
    uRtn =  CTOS_CLRATS(0,baATS,&bATSLen); 
    if(uRtn != d_OK)  
    {
        //CTOS_LCDTPrint("RATS NG\n");
        return uRtn;
    } 

    return uRtn;
}


int inGetEncryptedKey(char *szInputData, char *szOutputData, int inOperation)
{
	BYTE iv[100];
	BYTE cipherdata[100];
	CTOS_KMS2DATAENCRYPT_PARA para2;
	USHORT KeySet;
	USHORT KeyIndex;
	int inRet;
	BYTE plaindata[33];
	BYTE lastb[65]; 


	memset(plaindata,0x00, sizeof(plaindata));
	Pack(szInputData, 64, plaindata);
	DebugAddHEX("PLAIN DATA",plaindata,32);
	memset(iv, 0x00, sizeof(iv));
	strcpy(iv,"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
	KeySet = 0xC001;
	switch(inOperation)
	{
		case READ_CARD_INFO:	
			KeyIndex = 0x0001;
			break;
		case WRITE_CARD_INFO:	
			KeyIndex = 0x0002;	
			break;
		case READ_CARD_BALANCE:	
			KeyIndex = 0x0003;
			break;
		case WRITE_CARD_BALANCE:	
			KeyIndex = 0x0004;	
			break;
		default:
			break;
	}

	memset(cipherdata, 0x00, sizeof(cipherdata));
	memset(&para2, 0x00, sizeof(CTOS_KMS2DATAENCRYPT_PARA));
	para2.Version = 0x01;
	para2.Protection.CipherKeySet = KeySet;
	para2.Protection.CipherKeyIndex = KeyIndex;
	para2.Protection.CipherMethod = KMS2_DATAENCRYPTCIPHERMETHOD_CBC;
	para2.Protection.SK_Length = 0;
	para2.Input.Length = 32;
	para2.Input.pData = plaindata;
	para2.Input.ICVLength = 16;
	para2.Input.pICV  = iv;
	para2.Output.pData = cipherdata;
	inRet = CTOS_KMS2DataEncrypt(&para2);
	if(inRet != d_OK)
	{
		vdDebug_LogPrintf("encrypt error");
		return d_NO;
	}
	  memcpy(szOutputData,&cipherdata[16],16);
	return d_OK;
}



int inDiversifyKey(BYTE *byDiversifiedOutput, int inOperation)
{
	
	BYTE Keytest[33];
	BYTE key[33];
	int inRet;
	int inlen;
	BYTE iv[33];
	BYTE K1[33]; 
	BYTE K2[33];

	BYTE lastb[65]; 
	BYTE lastbpack[33]; 
	BYTE pad[33];
	int length;

	BYTE a[33];
	BYTE b[33];
	BYTE out[33];
	BYTE out2[100];
	BYTE output[33];
	BYTE divkey[33];

	char szUID[14+1];
	char szApplicationID[6+1];
	char szSystemIdentifier[20+1];
	char szDiversificationInput[100+1];
	char szDiversificationOutput[100+1];
	char szK2[32+1];
	BYTE szDiversifiedKey[100];

	AES_Init();

	memset(szUID,0x00, sizeof(szUID));
	memset(szApplicationID,0x00, sizeof(szApplicationID));
	memset(szSystemIdentifier,0x00, sizeof(szSystemIdentifier));
	
	wub_hex_2_str(strVersion.abUid,szUID,7);
	strcpy(szApplicationID,"F11290");
	inCTOSS_GetEnvDB ("SYSID", szSystemIdentifier);


	memset(szDiversificationInput, 0x00, sizeof(szDiversificationInput));
	strcpy(szDiversificationInput, "01");//div constant
	strcat(szDiversificationInput,szUID);
	strcat(szDiversificationInput,szApplicationID);
	strcat(szDiversificationInput,szSystemIdentifier);

	//pad
	strcat(szDiversificationInput,"8000000000000000000000000000");

	//vdDebug_LogPrintf("DIV input with padding  %s",szDiversificationInput);

	//get last 16 bytes for XOR
	memset(lastb, 0x00, sizeof(lastb));
	strncpy(lastb,&szDiversificationInput[32],32);
	//vdDebug_LogPrintf("last 16 bytes %s", lastb);

	memset(a,0x00, sizeof(a));
	Pack(lastb, 32, a);

	switch(inOperation)
	{
		case READ_CARD_INFO:	
			inCTOSS_GetEnvDB("K1K2",szK2);
			break;
		case WRITE_CARD_INFO:	
			inCTOSS_GetEnvDB("K2K2",szK2);
			break;
		case READ_CARD_BALANCE:	
			inCTOSS_GetEnvDB("K5K2",szK2);
			break;
		case WRITE_CARD_BALANCE:	
			inCTOSS_GetEnvDB("K6K2",szK2);
			break;
		default:
			break;
	}
	
    Pack(szK2, 32, K2);
	
	AESMAC_Xor128(a, K2, out);

	wub_hex_2_str(out, out2, 16);

	memcpy(&szDiversificationInput[32],out2,32);

	vdDebug_LogPrintf("szDiversificationInput %s", szDiversificationInput);

	memset(szDiversifiedKey, 0x00, sizeof(szDiversifiedKey));

	inRet = inGetEncryptedKey(szDiversificationInput,szDiversifiedKey, inOperation);
	if(inRet != d_OK)
		return d_NO;
	

	vdDebug_LogPrintf("diversified mkey = %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
	szDiversifiedKey[0], szDiversifiedKey[1],szDiversifiedKey[2],szDiversifiedKey[3],
	szDiversifiedKey[4], szDiversifiedKey[5],szDiversifiedKey[6],szDiversifiedKey[7],
	szDiversifiedKey[8], szDiversifiedKey[9],szDiversifiedKey[10],szDiversifiedKey[11],
	szDiversifiedKey[12], szDiversifiedKey[13],szDiversifiedKey[14],szDiversifiedKey[15]);
	
	memcpy(byDiversifiedOutput,szDiversifiedKey,16);
    return d_OK;

}

int InjectAESKey(char *MasterKey, int inOperation)
{

	BYTE KeyData[16];
	int KeySet, KeyIndex;
	BYTE str[17];
	int inRet;
	BYTE key[33];


	CTOS_KMS2KEYWRITE_PARA para;
	memset(KeyData,0x00, sizeof(KeyData));
	Pack(MasterKey, 32, KeyData);//Pack only if master key is not BCD
	KeySet = 0xC001;
	
	//KeyIndex = 0x0001;
	switch(inOperation)
	{
		case READ_CARD_INFO:	
			KeyIndex = 0x0001;
			break;
		case WRITE_CARD_INFO:	
			KeyIndex = 0x0002;	
			break;
		case READ_CARD_BALANCE:	
			KeyIndex = 0x0003;
			break;
		case WRITE_CARD_BALANCE:	
			KeyIndex = 0x0004;	
			break;
		default:
			break;
	}
	
	memset(&para, 0x00, sizeof(CTOS_KMS2KEYWRITE_PARA));
	para.Version = 0x01;
	para.Info.KeySet = KeySet;
	para.Info.KeyIndex = KeyIndex;
	para.Info.KeyType = KMS2_KEYTYPE_AES;
	para.Info.KeyVersion = 0x01;
	para.Info.KeyAttribute = KMS2_KEYATTRIBUTE_PIN | KMS2_KEYATTRIBUTE_ENCRYPT | KMS2_KEYATTRIBUTE_MAC | KMS2_KEYATTRIBUTE_KPK;
	para.Protection.Mode = KMS2_KEYPROTECTIONMODE_PLAINTEXT;
	para.Value.pKeyData = KeyData;
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

	return d_OK;
}


int inDiversifyProcess(BYTE byKeyNo, int inOperation)
{
	int inRet;
	USHORT usRtn;
	ULONG ulAPRtn;
	BYTE byDivKey[32+1];
	
	inRet = inDiversifyKey(byDivKey,inOperation);
	if(inRet != d_OK)
	{
		vdDisplayErrorMsgResp2("KEY","DIVERSIFICATION","FAILED");
		return d_NO;
	}
	DebugAddHEX("DIVERSIFIED KEY",byDivKey,16);

	memset(GlobalDivKey,0x00,sizeof(GlobalDivKey));
	memcpy(GlobalDivKey,byDivKey,16);
	
	usRtn = CTOS_DesfireAuthenticateAES(byKeyNo, (BYTE *)byDivKey, 16);
	if(usRtn != 0x00)
	{
		vdDisplayErrorMsgResp2("AES","AUTHENTICATION","FAILED");
		vdDebug_LogPrintf("CTOS_DesfireAuthenticateAES FAILED[%lu]",usRtn);
		CTOS_Delay(1500);
		return d_NO;
	}
	else
		vdDebug_LogPrintf("CTOS_DesfireAuthenticateAES[%d]",usRtn);

	return d_OK;
}

int inSelectAppAndGetUID(void)
{
	ULONG ulAPRtn;
	
	ulAPRtn = CTOS_DesfireSelectApplication("\xF1\x12\x90");
	if(ulAPRtn != 0x00)
	{
		//vdDisplayErrorMsgResp2("SELECT APPLICATION","FAILED","");
		vdDebug_LogPrintf("CTOS_DesfireSelectApplication FAIL [%d]",ulAPRtn);
		CTOS_Delay(1500);
		return d_NO;
	}
	else
		vdDebug_LogPrintf("CTOS_DesfireSelectApplication SUCCESS[%d]",ulAPRtn);

	memset(&strVersion,0x00,sizeof(VERSION_INFO));
	ulAPRtn = CTOS_DesfireGetVersion(&strVersion);
	if(ulAPRtn != 0x00)
	{
		vdDebug_LogPrintf("CTOS_DesfireGetVersion FAIL [%d]",ulAPRtn);
		//vdDisplayErrorMsgResp2("GET UID","FAILED","");
		return d_NO;
	}
	else
		vdDebug_LogPrintf("CTOS_DesfireGetVersion SUCCESS [%d]",ulAPRtn);
	
	DebugAddHEX("CARD UID",strVersion.abUid,7);

	return d_OK;
}


int inGetMifareCardFields(BYTE byTransType)
{
	int inRet = -1;
	
	BYTE byDivKey[32+1];
	BYTE bUID[14+1];
	BYTE bUID2[14+1];
	BYTE bMKey[32+1];
	BYTE szCardName[26+1]={0};
	BYTE bTempTransType;
	int usRtn = -1;//USHORT usRtn = -1;
	ULONG ulAPRtn = -1;


	/*ACTIVATE MIFARE CARD READING*/

	vdDispTransTitle(srTransRec.byTransType);
	bTempTransType = srTransRec.byTransType;
	
	if(byTransType == SALE)
	{
		usRtn = inReadMIFARECardEx();
		vdDebug_LogPrintf("inReadMIFARECardEx %d %02x",usRtn,usRtn);
		if(usRtn == NOT_DETECTED)
			return VS_CONTINUE;
	}
	else
	{
#if 0
		if(strTCT.byTerminalType % 2 == 0)
			setLCDPrint27(6,DISPLAY_POSITION_CENTER,"PLEASE TAP CARD");	
		else
			setLCDPrint27(4,DISPLAY_POSITION_CENTER,"PLEASE TAP CARD");	
#endif
	
		usRtn = inReadMIFARECard();
		if(usRtn != d_OK)
		{
			//vdDisplayErrorMsgResp2("CARD READING","FAILED","");
			vdDebug_LogPrintf("inReadMIFARECard FAIL [%d]",usRtn);
			CTOS_Delay(1500);

			if(usRtn == USER_CANCEL)
				return USER_CANCEL;
			else if(usRtn == READ_CARD_TIMEOUT)
				return READ_CARD_TIMEOUT;
			else
				return d_NO;
		}
		else
			vdDebug_LogPrintf("usReadMIFARECard[%d]",inRet);
		
	}
	
	
	if(usCheckSMACKeys(0xC001, 0x0001) != d_OK || CheckIfSmacEnableonIdleSale() != d_OK)
	{
		CTOS_LCDTClearDisplay();
		vduiDisplayStringCenter(7,"PERFORMING AUTO");
		vduiDisplayStringCenter(8,"SMAC LOGON");
		CTOS_Beep();
		WaitKey(1);	
		
		inRet = inCTOS_SMACLogonFlowProcessEx();
		if(d_OK != inRet)
		{
			vdSetECRResponse(ECR_OPER_CANCEL_RESP);
			return LOGON_FAILED;
		}
		vdCTOS_SetTransType(bTempTransType); // Set TransType back to Sale
		fAutoSMACLogon = TRUE;

		memset(srTransRec.szRespCode,0x00,sizeof(srTransRec.szRespCode));
			
		if(srTransRec.byTransType == SALE)
			return READ_SMAC_CARD;

	}
	
	inRet = inSelectAppAndGetUID();
	if(inRet != d_OK)
	{
		if(byTransType != SALE)
			vdDisplayErrorMsgResp2("GET","APP AND UID","FAILED");
		return d_NO;
	}

	inRet = inDiversifyProcess(0x01, READ_CARD_INFO);	
	if(inRet != d_OK)
	{
		if(byTransType != SALE)
			vdDisplayErrorMsgResp2("KEY","DIVERSIFICATION","FAILED");
		return d_NO;
	}

	CTOS_Sound(1300, 70);
	
	inRet = inGetPersonalInfo();
	if(inRet != d_OK)
	{
		if(byTransType != SALE)
			vdDisplayErrorMsgResp2("READ","PERSONAL INFO","FAILED");
		return d_NO;
	}

	inRet = inGetMembershipInfo();
	if(inRet != d_OK)
	{
		if(byTransType != SALE)
			vdDisplayErrorMsgResp2("READ","MEMBERSHIP INFO","FAILED");
		return d_NO;
	}

	inRet = inCheckCardStatus();
	if(inRet != d_OK)
	{
		vdSetECRResponse(ECR_DECLINED_ERR);
		return d_NO;
	}

// GET BALANCE START

	inRet = inDiversifyProcess(0x05, READ_CARD_BALANCE);
	if(inRet != d_OK)
	{
		if(byTransType != SALE)
			vdDisplayErrorMsgResp2("KEY","DIVERSIFICATION","FAILED");
		return d_NO;
	}

	ulAPRtn = inDesfireGetBalance(FILE_ID_PTS_BAL, &srTransRec.ulSMACPay_CardBalance);
	if(ulAPRtn != 0x00)
	{
		if(byTransType != SALE)
			vdDisplayErrorMsgResp2("READ","BALANCE","FAILED");
		vdDebug_LogPrintf("CTOS_DesfireGetValue FAILED[%d]",ulAPRtn);
		CTOS_Delay(1500);
		return d_NO;
	}
	else
	{
		vdDebug_LogPrintf("CTOS_DesfireGetValue[%d] [%lu]",ulAPRtn,srTransRec.ulSMACPay_CardBalance);
	}
//GET BALANCE END

#if 0
	inRet = inGetDemographicInfo();
	if(inRet != d_OK)
		return d_NO;

	inRet = inGetEmploymentInfo();
	if(inRet != d_OK)
		return d_NO;
#endif

	return d_OK;
	
}


int inGetPersonalInfo(void)
{
	int inOffset = 0;
	BYTE bFileIDData_2[76+1];
	ULONG ulAPRtn = -1;
	ULONG ulDataLen;
	char szTemp[4+1];

	ulAPRtn = inDesfireReadStdData(FILE_ID_PERSONAL_INFO, 0, PERSONAL_INFO_LEN, bFileIDData_2);
	vdDebug_LogPrintf("bFileIDData_2[%s]",bFileIDData_2);
	if(ulAPRtn != PERSONAL_INFO_LEN)
	{
		//vdDisplayErrorMsgResp2("READ","PERSONAL INFO","FAILED");
		vdDebug_LogPrintf("inDesfireReadStdData FAILED[%d]",ulAPRtn);
		CTOS_Delay(1500);
		return d_NO;
	}
	else
	{
		vdDebug_LogPrintf("inDesfireReadStdData[%d] [%lu]",ulAPRtn,ulDataLen);
		//vdDebug_LogPrintf("bFileIDData_2[%s]",bFileIDData_2);
		DebugAddHEX("PERSONAL INFO",bFileIDData_2,ulAPRtn);
	}

	memcpy(strPersonal_Info.bCardNo,bFileIDData_2,16);
	inOffset+=16;
	memcpy(strPersonal_Info.bCardHolderName,&bFileIDData_2[inOffset],26);
	inOffset+=26;
	memcpy(strPersonal_Info.bExpiryDate,&bFileIDData_2[inOffset],10);
	inOffset+=10;
	memcpy(strPersonal_Info.bCardSeqNo,&bFileIDData_2[inOffset],2);
	inOffset+=2;
	memcpy(strPersonal_Info.bCardStatus,&bFileIDData_2[inOffset],2);
	inOffset+=2;	
	memcpy(strPersonal_Info.bCardPerDate,&bFileIDData_2[inOffset],10);
	inOffset+=10;	
	memcpy(strPersonal_Info.bLastDataSync,&bFileIDData_2[inOffset],10);

	vdDebug_LogPrintf("CARD NUMBER     [%s]",strPersonal_Info.bCardNo);
	vdDebug_LogPrintf("CARD HOLDER NAME[%s]",strPersonal_Info.bCardHolderName);
	vdDebug_LogPrintf("EXPIRY          [%s]",strPersonal_Info.bExpiryDate);
	vdDebug_LogPrintf("CARD SEQ NUMBER [%s]",strPersonal_Info.bCardSeqNo);
	vdDebug_LogPrintf("CARD STATUS     [%s]",strPersonal_Info.bCardStatus);
	vdDebug_LogPrintf("CARD PER DATE   [%s]",strPersonal_Info.bCardPerDate);
	vdDebug_LogPrintf("LAST DATA SYNC  [%s]",strPersonal_Info.bLastDataSync);

	strcpy(srTransRec.szPAN,strPersonal_Info.bCardNo);
	
	memcpy(srTransRec.bySMACPay_CardSeqNo,strPersonal_Info.bCardSeqNo,2);
	
	memset(szTemp,0x00,sizeof(szTemp));
	memcpy(szTemp,&strPersonal_Info.bExpiryDate[8],2);
	memcpy(&szTemp[2],strPersonal_Info.bExpiryDate,2);
	wub_str_2_hex(szTemp,srTransRec.szExpireDate,4);
	
	memcpy(srTransRec.szCardholderName,strPersonal_Info.bCardHolderName,strlen(strPersonal_Info.bCardHolderName));	
	memcpy(srTransRec.bySMACPay_CardStatus,strPersonal_Info.bCardStatus,2);	
	memcpy(srTransRec.bySMACPay_CardPerDate,strPersonal_Info.bCardPerDate,10);
	memcpy(srTransRec.bySMACPay_LastDataSync,strPersonal_Info.bLastDataSync,10);
	memcpy(srTransRec.bySMACPay_ExpiryDate,strPersonal_Info.bExpiryDate,10);

	vdDebug_LogPrintf("bySMACPay_CardStatus				[%s]",srTransRec.bySMACPay_CardStatus);
	vdDebug_LogPrintf("bySMACPay_CardPerDate          	[%s]",srTransRec.bySMACPay_CardPerDate);
	vdDebug_LogPrintf("bySMACPay_LastDataSync 			[%s]",srTransRec.bySMACPay_LastDataSync);
	vdDebug_LogPrintf("bySMACPay_ExpiryDate				[%s]",srTransRec.bySMACPay_ExpiryDate);
	
	return d_OK;
	
}

int inGetMembershipInfo(void)
{
	int inOffset = 0;
	BYTE bFileIDData_3[31+1];
	ULONG ulAPRtn = -1;
	ULONG ulDataLen;

	ulAPRtn = inDesfireReadStdData(FILE_ID_MEMBERSHIP_INFO, 0, MEMBERSHIP_INFO_LEN, bFileIDData_3);
	if(ulAPRtn != MEMBERSHIP_INFO_LEN)
	{
		//vdDisplayErrorMsgResp2("READ","MEMBERSHIP INFO","FAILED");
		vdDebug_LogPrintf("inDesfireReadStdData FAILED[%d]",ulAPRtn);
		CTOS_Delay(1500);
		return d_NO;
	}
	else
	{
		vdDebug_LogPrintf("inDesfireReadStdData[%d] [%lu]",ulAPRtn,ulDataLen);
		//vdDebug_LogPrintf("bFileIDData_3[%s]",bFileIDData_3);
		DebugAddHEX("MEMBERSHIP INFO",bFileIDData_3,ulAPRtn);
	}

	memcpy(strMembership_Info.bMemberSince,bFileIDData_3,7);
	inOffset+=7;
	memcpy(strMembership_Info.bMembershipType,&bFileIDData_3[inOffset],1);
	inOffset+=1;
	memcpy(strMembership_Info.bTenure,&bFileIDData_3[inOffset],2);
	inOffset+=2;
	memcpy(strMembership_Info.bAcquiChannel,&bFileIDData_3[inOffset],1);
	inOffset+=1;
	memcpy(strMembership_Info.bKitAcqDate,&bFileIDData_3[inOffset],10);
	inOffset+=10;	
	memcpy(strMembership_Info.bKitAcqCompany,&bFileIDData_3[inOffset],4);
	inOffset+=4;	
	memcpy(strMembership_Info.bKitAcqBranch,&bFileIDData_3[inOffset],6);

	vdDebug_LogPrintf("MEMBER SINCE    [%s]",strMembership_Info.bMemberSince);
	vdDebug_LogPrintf("MEMBERSHIP TYPE [%s]",strMembership_Info.bMembershipType);
	vdDebug_LogPrintf("TENURE          [%s]",strMembership_Info.bTenure);
	vdDebug_LogPrintf("ACQUI CHANNEL   [%s]",strMembership_Info.bAcquiChannel);
	vdDebug_LogPrintf("KIT ACQ DATE    [%s]",strMembership_Info.bKitAcqDate);
	vdDebug_LogPrintf("KIT ACQ COMPANY [%s]",strMembership_Info.bKitAcqCompany);
	vdDebug_LogPrintf("KIT ACQ BRANCH  [%s]",strMembership_Info.bKitAcqBranch);
	
	memcpy(srTransRec.bySMACPay_MemberSince,strMembership_Info.bMemberSince,7);
	
	return d_OK;
}


int inGetDemographicInfo(void)
{
	int inOffset = 0;
	BYTE bFileIDData_4[16+1];
	ULONG ulAPRtn = -1;
	ULONG ulDataLen;

	ulAPRtn = inDesfireReadStdData(FILE_ID_DEMOGRAPHIC_INFO, 0, DEMOGRAPHIC_INFO_LEN, bFileIDData_4);
	if(ulAPRtn != DEMOGRAPHIC_INFO_LEN)
	{
		vdDisplayErrorMsgResp2("READ","DEMOGRAPHIC INFO","FAILED");
		//vdDebug_LogPrintf("inDesfireReadStdData FAILED[%d]",ulAPRtn);
		CTOS_Delay(1500);
		return d_NO;
	}
	else
	{
		vdDebug_LogPrintf("inDesfireReadStdData[%d] [%lu]",ulAPRtn,ulDataLen);
		vdDebug_LogPrintf("bFileIDData_4[%s]",bFileIDData_4);
		DebugAddHEX("DEMOGRAPHIC INFO",bFileIDData_4,ulAPRtn);
	}

	memcpy(strDemographic_Info.bBirthDate,bFileIDData_4,10);
	inOffset+=10;
	memcpy(strDemographic_Info.bGender,&bFileIDData_4[inOffset],1);
	inOffset+=1;
	memcpy(strDemographic_Info.bCity,&bFileIDData_4[inOffset],5);

	vdDebug_LogPrintf("BIRTH DATE      [%s]",strDemographic_Info.bBirthDate);
	vdDebug_LogPrintf("GENDER          [%s]",strDemographic_Info.bGender);
	vdDebug_LogPrintf("CITY            [%s]",strDemographic_Info.bCity);
	
	return d_OK;
}

int inGetEmploymentInfo(void)
{
	int inOffset = 0;
	BYTE bFileIDData_5[20+1];
	ULONG ulAPRtn = -1;
	ULONG ulDataLen;


	ulAPRtn = inDesfireReadStdData(FILE_ID_EMPLOYMENT_INFO, 0, PERSONAL_INFO_LEN, bFileIDData_5);
	if(ulAPRtn != PERSONAL_INFO_LEN)
	{
		vdDisplayErrorMsgResp2("READ","EMPLOYMENT INFO","FAILED");
		vdDebug_LogPrintf("inDesfireReadStdData FAILED[%d]",ulAPRtn);
		CTOS_Delay(1500);
		return d_NO;
	}
	else
	{
		vdDebug_LogPrintf("inDesfireReadStdData[%d] [%lu]",ulAPRtn,ulDataLen);
		//vdDebug_LogPrintf("bFileIDData_5[%s]",bFileIDData_5);
		DebugAddHEX("EMPLOYMENT INFO",bFileIDData_5,ulAPRtn);
	}

	memcpy(strEmployment_Info.bEmployeeNo,bFileIDData_5,10);
	inOffset+=10;
	memcpy(strEmployment_Info.bCompanyCode,&bFileIDData_5[inOffset],4);
	inOffset+=4;
	memcpy(strEmployment_Info.bBranchCode,&bFileIDData_5[inOffset],6);
	
	return d_OK;
}



void inGenerateSubKey(char *MKEY, int inOperation)
{
	BYTE iv[33];
	BYTE K1[33]; 
	BYTE K2[33];
	BYTE Keytest[16+1];
	
	AES_Init();

	memset(Keytest,0x00, sizeof(Keytest));

	Pack(MKEY, 32, Keytest);
	vdDebug_LogPrintf("inGenerateSubKey --- 1");
		
	memset(iv, 0x00, sizeof(iv));
	AESMAC_GenerateSubKey(Keytest, 16,iv, K1, K2);
	vdDebug_LogPrintf("inGenerateSubKey --- 2");	

	memset(Keytest,0x00, sizeof(Keytest));
	wub_hex_2_str(K2,Keytest,16);

	switch(inOperation)
	{
		case READ_CARD_INFO:	
			put_env_charEx("K1K2",Keytest);
			vdDebug_LogPrintf("inGenerateSubKey --- A");	
			break;
		case WRITE_CARD_INFO:	
			put_env_charEx("K2K2",Keytest);
			vdDebug_LogPrintf("inGenerateSubKey --- B");	
			break;
		case READ_CARD_BALANCE:	
			put_env_charEx("K5K2",Keytest);
			vdDebug_LogPrintf("inGenerateSubKey --- C");	
			break;
		case WRITE_CARD_BALANCE:	
			put_env_charEx("K6K2",Keytest);
			vdDebug_LogPrintf("inGenerateSubKey --- D");	
			break;
		default:
			break;
	}

	return;
	/*end of generate subkey*/
}


int inWriteCardHolderName(BYTE *szCardHolderName)
{
	int inOffset = 0;
	BYTE bFileIDData_2[76+1];
	USHORT uRtn;
	ULONG ulAPRtn = -1;
	ULONG ulDataLen;

	ulAPRtn = CTOS_DesfireWriteData(FILE_ID_PERSONAL_INFO, 16, 26, szCardHolderName);
	if(ulAPRtn != 0x00)
	{
		vdDisplayErrorMsgResp2("WRITE","CARD HOLDER","NAME FAILED");
		vdDebug_LogPrintf("inWriteCardHolderName FAILED[%d]",ulAPRtn);
		CTOS_Delay(1500);
		return d_NO;
	}
	else
		vdDebug_LogPrintf("inWriteCardHolderName[%d]",ulAPRtn);

	uRtn = CTOS_DesfireCommitTransaction();
	if(uRtn != 0x00)
	{
		vdDisplayErrorMsgResp2("COMMIT","CARD HOLDER","NAME FAILED");
		vdDebug_LogPrintf("inWriteCardHolderName FAILED[%d]",uRtn);
		CTOS_Delay(1500);
		return d_NO;
	}
	else
		vdDebug_LogPrintf("CTOS_DesfireCommitTransaction[%d]",uRtn);


	return d_OK;
	
}


int inWriteDatatoCard(BYTE byField, BYTE *byValue)
{
	int inLen = 0;
	BYTE bTemp[30+1]={0};
	USHORT uRtn;
	ULONG ulAPRtn = -1;
	ULONG ulDataLen;

	inLen = strlen(byValue);
	memset(bTemp,0x30,sizeof(bTemp));
	
	if(memcmp(byValue,bTemp,inLen) == 0)//If Field is all zeroes, do not write data to card.
		return d_OK;
	
	switch(byField)
	{
	 	case FIELD_CARD_NAME:
			ulAPRtn = inDesfireWriteStdData(FILE_ID_PERSONAL_INFO,16,26,byValue);
			if(ulAPRtn != 0x00)
			{
				vdDisplayErrorMsgResp2("WRITE","FIELD_CARD_NAME","NAME FAILED");
				vdDebug_LogPrintf("Write FIELD_CARD_NAME FAILED[%d]",ulAPRtn);
				CTOS_Delay(1500);
				return d_NO;
			}
			else
				vdDebug_LogPrintf("Write FIELD_CARD_NAME[%d]",ulAPRtn);
			break;
		case FIELD_EXP_DATE:
			ulAPRtn = inDesfireWriteStdData(FILE_ID_PERSONAL_INFO, 42, 10, byValue);
			if(ulAPRtn != 0x00)
			{
				vdDisplayErrorMsgResp2("WRITE","FIELD_EXP_DATE","NAME FAILED");
				vdDebug_LogPrintf("Write FIELD_EXP_DATE FAILED[%d]",ulAPRtn);
				CTOS_Delay(1500);
				return d_NO;
			}
			else
				vdDebug_LogPrintf("Write FIELD_EXP_DATE[%d]",ulAPRtn);
			break;
		case FIELD_CARD_SEQ_NO:
			ulAPRtn = inDesfireWriteStdData(FILE_ID_PERSONAL_INFO, 52, 2, byValue);	
			if(ulAPRtn != 0x00)
			{
				vdDisplayErrorMsgResp2("WRITE","FIELD_CARD_SEQ_NO","NAME FAILED");
				vdDebug_LogPrintf("Write FIELD_CARD_SEQ_NO FAILED[%d]",ulAPRtn);
				CTOS_Delay(1500);
				return d_NO;
			}
			else
				vdDebug_LogPrintf("Write FIELD_CARD_SEQ_NO[%d]",ulAPRtn);
			break;
		case FIELD_CARD_STATUS:
			ulAPRtn = inDesfireWriteStdData(FILE_ID_PERSONAL_INFO, 54, 2, byValue);
			if(ulAPRtn != 0x00)
			{
				vdDisplayErrorMsgResp2("WRITE","FILE_ID_PERSONAL_INFO","NAME FAILED");
				vdDebug_LogPrintf("Write FILE_ID_PERSONAL_INFO FAILED[%d]",ulAPRtn);
				CTOS_Delay(1500);
				return d_NO;
			}
			else
				vdDebug_LogPrintf("Write FILE_ID_PERSONAL_INFO[%d]",ulAPRtn);
			break;
		case FIELD_CARD_PER_DATE:
			ulAPRtn = inDesfireWriteStdData(FILE_ID_PERSONAL_INFO, 56, 10, byValue);
			if(ulAPRtn != 0x00)
			{
				vdDisplayErrorMsgResp2("WRITE","FIELD_CARD_PER_DATE","NAME FAILED");
				vdDebug_LogPrintf("Write FIELD_CARD_PER_DATE FAILED[%d]",ulAPRtn);
				CTOS_Delay(1500);
				return d_NO;
			}
			else
				vdDebug_LogPrintf("Write FIELD_CARD_PER_DATE[%d]",ulAPRtn);
			break;
		case FIELD_LAST_SYNC_DATE:
			ulAPRtn = inDesfireWriteStdData(FILE_ID_PERSONAL_INFO, 66, 10, byValue);
			if(ulAPRtn != 0x00)
			{
				vdDisplayErrorMsgResp2("WRITE","FIELD_LAST_SYNC_DATE","NAME FAILED");
				vdDebug_LogPrintf("Write FIELD_LAST_SYNC_DATE FAILED[%d]",ulAPRtn);
				CTOS_Delay(1500);
				return d_NO;
			}
			else
				vdDebug_LogPrintf("Write FIELD_LAST_SYNC_DATE[%d]",ulAPRtn);
			break;
		case FIELD_MEMBER_SINCE:
			ulAPRtn = inDesfireWriteStdData(FILE_ID_MEMBERSHIP_INFO, 0, 7, byValue);
			
			if(ulAPRtn != 0x00)
			{
				vdDisplayErrorMsgResp2("WRITE","FIELD_MEMBER_SINCE","NAME FAILED");
				vdDebug_LogPrintf("Write FIELD_MEMBER_SINCE FAILED[%d]",ulAPRtn);
				CTOS_Delay(1500);
				return d_NO;
			}
			else
				vdDebug_LogPrintf("Write FIELD_MEMBER_SINCE[%d]",ulAPRtn);
			break;
		case FIELD_MEMBER_TYPE:
			ulAPRtn = inDesfireWriteStdData(FILE_ID_MEMBERSHIP_INFO, 7, 1, byValue);
			if(ulAPRtn != 0x00)
			{
				vdDisplayErrorMsgResp2("WRITE","FIELD_MEMBER_TYPE","NAME FAILED");
				vdDebug_LogPrintf("Write FIELD_MEMBER_TYPE FAILED[%d]",ulAPRtn);
				CTOS_Delay(1500);
				return d_NO;
			}
			else
				vdDebug_LogPrintf("Write FIELD_MEMBER_TYPE[%d]",ulAPRtn);
			break;
		case FIELD_TENURE:
			ulAPRtn = inDesfireWriteStdData(FILE_ID_MEMBERSHIP_INFO, 8, 2, byValue);
			if(ulAPRtn != 0x00)
			{
				vdDisplayErrorMsgResp2("WRITE","FIELD_TENURE","NAME FAILED");
				vdDebug_LogPrintf("Write FIELD_TENURE FAILED[%d]",ulAPRtn);
				CTOS_Delay(1500);
				return d_NO;
			}
			else
				vdDebug_LogPrintf("Write FIELD_TENURE[%d]",ulAPRtn);
			break;
		case FIELD_ACQUI_CHANNEL:
			ulAPRtn = inDesfireWriteStdData(FILE_ID_MEMBERSHIP_INFO, 10, 1, byValue);
			if(ulAPRtn != 0x00)
			{
				vdDisplayErrorMsgResp2("WRITE","FIELD_ACQUI_CHANNEL","NAME FAILED");
				vdDebug_LogPrintf("Write FIELD_ACQUI_CHANNEL FAILED[%d]",ulAPRtn);
				CTOS_Delay(1500);
				return d_NO;
			}
			else
				vdDebug_LogPrintf("Write FIELD_ACQUI_CHANNEL[%d]",ulAPRtn);
			break;
		case FIELD_KIT_ACQUI_DATE:
			ulAPRtn = inDesfireWriteStdData(FILE_ID_MEMBERSHIP_INFO, 11, 10, byValue);
			if(ulAPRtn != 0x00)
			{
				vdDisplayErrorMsgResp2("WRITE","FIELD_KIT_ACQUI_DATE","NAME FAILED");
				vdDebug_LogPrintf("Write FIELD_KIT_ACQUI_DATE FAILED[%d]",ulAPRtn);
				CTOS_Delay(1500);
				return d_NO;
			}
			else
				vdDebug_LogPrintf("Write FIELD_KIT_ACQUI_DATE[%d]",ulAPRtn);
			break;
		case FIELD_KIT_ACQUI_COMPANY:
			ulAPRtn = inDesfireWriteStdData(FILE_ID_MEMBERSHIP_INFO, 21, 4, byValue);
			if(ulAPRtn != 0x00)
			{
				vdDisplayErrorMsgResp2("WRITE","FIELD_KIT_ACQUI_COMPANY","NAME FAILED");
				vdDebug_LogPrintf("Write FIELD_KIT_ACQUI_COMPANY FAILED[%d]",ulAPRtn);
				CTOS_Delay(1500);
				return d_NO;
			}
			else
				vdDebug_LogPrintf("Write FIELD_KIT_ACQUI_COMPANY[%d]",ulAPRtn);
			break;
		case FIELD_KIT_ACQUI_BRANCH:
			ulAPRtn = inDesfireWriteStdData(FILE_ID_MEMBERSHIP_INFO, 25, 6, byValue);
			if(ulAPRtn != 0x00)
			{
				vdDisplayErrorMsgResp2("WRITE","FIELD_KIT_ACQUI_BRANCH","NAME FAILED");
				vdDebug_LogPrintf("Write FIELD_KIT_ACQUI_BRANCH FAILED[%d]",ulAPRtn);
				CTOS_Delay(1500);
				return d_NO;
			}
			else
				vdDebug_LogPrintf("Write FIELD_KIT_ACQUI_BRANCH[%d]",ulAPRtn);
			break;
		case FIELD_BIRTH_DATE:
			ulAPRtn = inDesfireWriteStdData(FILE_ID_DEMOGRAPHIC_INFO, 0, 10, byValue);
			if(ulAPRtn != 0x00)
			{
				vdDisplayErrorMsgResp2("WRITE","FIELD_BIRTH_DATE","NAME FAILED");
				vdDebug_LogPrintf("Write FIELD_BIRTH_DATE FAILED[%d]",ulAPRtn);
				CTOS_Delay(1500);
				return d_NO;
			}
			else
				vdDebug_LogPrintf("Write FIELD_BIRTH_DATE[%d]",ulAPRtn);
			break;
		case FIELD_GENDER:
			ulAPRtn = inDesfireWriteStdData(FILE_ID_DEMOGRAPHIC_INFO, 10, 1, byValue);
			if(ulAPRtn != 0x00)
			{
				vdDisplayErrorMsgResp2("WRITE","FIELD_GENDER","NAME FAILED");
				vdDebug_LogPrintf("Write FIELD_GENDER FAILED[%d]",ulAPRtn);
				CTOS_Delay(1500);
				return d_NO;
			}
			else
				vdDebug_LogPrintf("Write FIELD_GENDER[%d]",ulAPRtn);
			break;
		case FIELD_CITY:
			ulAPRtn = inDesfireWriteStdData(FILE_ID_DEMOGRAPHIC_INFO, 11, 5, byValue);
			if(ulAPRtn != 0x00)
			{
				vdDisplayErrorMsgResp2("WRITE","FIELD_CITY","NAME FAILED");
				vdDebug_LogPrintf("Write FIELD_CITY FAILED[%d]",ulAPRtn);
				CTOS_Delay(1500);
				return d_NO;
			}
			else
				vdDebug_LogPrintf("Write FIELD_CITY[%d]",ulAPRtn);
			break;
		default:
			break;
	}
	
	

	return d_OK;
}


int inWriteMifareCardFields(void)
{
	int inRet = -1;
	
	BYTE byDivKey[32+1];
	BYTE bUID[14+1];
	BYTE bUID2[14+1];
	BYTE bMKey[32+1];
	BYTE szCardName[26+1]={0};
	BYTE szCardNo[16+1]={0};
	USHORT usRtn = -1;
	ULONG ulAPRtn = -1;
	ULONG ulDataLen;
	ULONG ulPoints = 0;
	ULONG ulHostRespPoints = 0;

	if(srTransRec.fVirtualCard == TRUE)
		return d_OK;

#if 0	
	CTOS_LCDTClearDisplay();
	vdDispTransTitle(srTransRec.byTransType);

    if ((strTCT.byTerminalType % 2) == 0)
    {
		setLCDPrint27(7, DISPLAY_POSITION_CENTER, " PLEASE TAP FOR ");	
		setLCDPrint27(8, DISPLAY_POSITION_CENTER, "CARD UPDATE");		
	}
	else
	{
		setLCDPrint27(4, DISPLAY_POSITION_CENTER, " PLEASE TAP FOR ");	
		setLCDPrint27(5, DISPLAY_POSITION_CENTER, "CARD UPDATE");	
	}
#else
	vdDisplayTapCardforUpdate();
#endif

TAP_AGAIN:
	
	inRet = inReadMIFARECard();
	if(inRet != d_OK)
	{
		vdDebug_LogPrintf("inReadMIFARECard FAIL [%d]",inRet);
		CTOS_Delay(1500);

		if(inRet == USER_CANCEL)
			return USER_CANCEL;
		else if(inRet == READ_CARD_TIMEOUT)
			return READ_CARD_TIMEOUT;
		else
		{
			vdDisplayTapCardforUpdate();
			goto TAP_AGAIN;
		}
			
	}
	else
		vdDebug_LogPrintf("inReadMIFARECard[%d]",inRet);
	

	inRet = inSelectAppAndGetUID();
	if(inRet != d_OK)
	{
		vdDisplayErrorMsgResp2("GET","APP AND UID","FAILED");
		vdDisplayTapCardforUpdate();
		goto TAP_AGAIN;
	}


	inRet = inDiversifyProcess(0x01, READ_CARD_INFO);
	if(inRet != d_OK)
	{
		vdDisplayErrorMsgResp2("KEY","DIVERSIFICATION","FAILED");
		vdDisplayTapCardforUpdate();
		goto TAP_AGAIN;
	}


	ulAPRtn = inDesfireReadStdData(FILE_ID_PERSONAL_INFO, 0, 16, szCardNo);
	if(ulAPRtn != 16)
	{
		vdDisplayErrorMsgResp2("CARD READ","FAILED","");
		vdDebug_LogPrintf("inDesfireReadStdData FAILED[%d]",ulAPRtn);
		CTOS_Delay(1500);
		vdDisplayTapCardforUpdate();
		goto TAP_AGAIN;
	}
	else
	{
		if(strcmp(srTransRec.szPAN,szCardNo) != 0)
		{
			//setLCDPrint27(3, DISPLAY_POSITION_CENTER, "PLEASE TAP");
			//setLCDPrint27(4, DISPLAY_POSITION_CENTER, "    CORRECT CARD    ");
			vdDisplayErrorMsgResp2("PLEASE TAP","CORRECT CARD","");
			goto TAP_AGAIN;
		}
	}

	inRet = inDiversifyProcess(0x02, WRITE_CARD_INFO);
	if(inRet != d_OK)
	{
		vdDisplayErrorMsgResp2("KEY","DIVERSIFICATION","FAILED");
		goto TAP_AGAIN;
	}
	
	inRet = inWriteDatatoCard(FIELD_CARD_NAME,strPersonal_Info.bCardHolderName);
	if(inRet != d_OK)
		return d_NO;		
	inRet = inWriteDatatoCard(FIELD_EXP_DATE,strPersonal_Info.bExpiryDate);
	if(inRet != d_OK)
		return d_NO;
	inRet = inWriteDatatoCard(FIELD_CARD_SEQ_NO,strPersonal_Info.bCardSeqNo);
	if(inRet != d_OK)
		return d_NO;
	inRet = inWriteDatatoCard(FIELD_CARD_PER_DATE,strPersonal_Info.bCardPerDate);
	if(inRet != d_OK)
		return d_NO;
	inRet = inWriteDatatoCard(FIELD_CARD_STATUS,strPersonal_Info.bCardStatus);
	if(inRet != d_OK)
		return d_NO;
	inRet = inWriteDatatoCard(FIELD_LAST_SYNC_DATE,strPersonal_Info.bLastDataSync);
	if(inRet != d_OK)
		return d_NO;

	if(srTransRec.byTransType == KIT_SALE)
	{
		inRet = inWriteDatatoCard(FIELD_MEMBER_SINCE,strMembership_Info.bMemberSince);
		if(inRet != d_OK)
			return d_NO;
		inRet = inWriteDatatoCard(FIELD_MEMBER_TYPE,strMembership_Info.bMembershipType);
		if(inRet != d_OK)
			return d_NO;
		inRet = inWriteDatatoCard(FIELD_TENURE,strMembership_Info.bTenure);
		if(inRet != d_OK)
			return d_NO;
		inRet = inWriteDatatoCard(FIELD_ACQUI_CHANNEL,strMembership_Info.bAcquiChannel);
		if(inRet != d_OK)
			return d_NO;
		inRet = inWriteDatatoCard(FIELD_KIT_ACQUI_DATE,strMembership_Info.bKitAcqDate);
		if(inRet != d_OK)
			return d_NO;
		inRet = inWriteDatatoCard(FIELD_KIT_ACQUI_COMPANY,strMembership_Info.bKitAcqCompany);
		if(inRet != d_OK)
			return d_NO;
		inRet = inWriteDatatoCard(FIELD_KIT_ACQUI_BRANCH,strMembership_Info.bKitAcqBranch);		
		if(inRet != d_OK)
			return d_NO;
	}
	
	usRtn = CTOS_DesfireCommitTransaction();
	if(usRtn != 0x00)
	{
		vdDisplayErrorMsgResp2("COMMIT","FAILED","");
		vdDebug_LogPrintf("CTOS_DesfireCommitTransaction FAILED[%d]",usRtn);
		CTOS_Delay(1500);
		return d_NO;
	}
	else
		vdDebug_LogPrintf("CTOS_DesfireCommitTransaction[%d]",usRtn);

	if(srTransRec.byTransType == RENEWAL || srTransRec.byTransType == PTS_AWARDING
		|| inCheckSMACPayRedemption(&srTransRec) == TRUE || inCheckSMACPayBalanceInq(&srTransRec) == TRUE || inCheckSMACPayVoid(&srTransRec) == TRUE)
	{

		ulHostRespPoints = atol(srTransRec.szSMACPay_HostBalance);
		if(ulHostRespPoints == srTransRec.ulSMACPay_CardBalance)//RETREIVED DURING CARD READING.
		{
			vdDebug_LogPrintf("POINTS ARE THE SAME. NO NEED TO UPDATE");
			return d_OK;
		}


		inRet = inDiversifyProcess(0x06, WRITE_CARD_BALANCE);
		if(inRet != d_OK)
		{
			vdDisplayErrorMsgResp2("KEY","DIVERSIFICATION","FAILED");
			goto TAP_AGAIN;
		}

		
		vdDebug_LogPrintf("ulSMACPay_CardBalance[%lu] :: ulHostRespPoints[%lu]", srTransRec.ulSMACPay_CardBalance, ulHostRespPoints);	
		if(srTransRec.ulSMACPay_CardBalance> ulHostRespPoints)
		{
			vdDebug_LogPrintf("%lu - %lu", srTransRec.ulSMACPay_CardBalance, ulHostRespPoints);			
			ulPoints = srTransRec.ulSMACPay_CardBalance - ulHostRespPoints;
			vdDebug_LogPrintf("POINTS TO BE SUBTRACTED [%lu]",ulPoints);
			usRtn = inDesfireStdDebit(FILE_ID_PTS_BAL,ulPoints);
			if(usRtn != 0x00)
			{
				vdDisplayErrorMsgResp2("","DEBIT","FAILED");
				vdDebug_LogPrintf("inDesfireStdDebit FAILED[%d]",usRtn);

				if(usRtn == d_BOUNDARY_ERROR)
					vdDisplayErrorMsgResp2("NOT","ENOUGH","POINTS");
				
				CTOS_Delay(1500);
				return d_NO;
			}
			else
				vdDebug_LogPrintf("inDesfireStdDebit[%d]",usRtn);		
		}
		else if(ulHostRespPoints > srTransRec.ulSMACPay_CardBalance)
		{
			vdDebug_LogPrintf("%lu - %lu", ulHostRespPoints,srTransRec.ulSMACPay_CardBalance);
			ulPoints = ulHostRespPoints - srTransRec.ulSMACPay_CardBalance;
			vdDebug_LogPrintf("POINTS TO BE ADDED [%lu]",ulPoints);
			usRtn = inDesfireStdCredit(FILE_ID_PTS_BAL,ulPoints);
			if(usRtn != 0x00)
			{
				vdDisplayErrorMsgResp2("","CREDIT","FAILED");
				vdDebug_LogPrintf("inDesfireStdCredit FAILED[%d]",usRtn);
				CTOS_Delay(1500);
				return d_NO;
			}
			else
				vdDebug_LogPrintf("inDesfireStdCredit[%d]",usRtn);
		}

		usRtn = CTOS_DesfireCommitTransaction();
		if(usRtn != 0x00)
		{
			vdDisplayErrorMsgResp2("COMMIT","FAILED","");
			vdDebug_LogPrintf("CTOS_DesfireCommitTransaction FAILED[%d]",usRtn);
			CTOS_Delay(1500);
			return d_NO;
		}
		else
			vdDebug_LogPrintf("CTOS_DesfireCommitTransaction[%d]",usRtn);

	}
	
	return d_OK;
	
}


int inCheckCardStatus(void)
{
	if(srTransRec.byTransType == PTS_AWARDING)
	{
		//Offline Points Awarding for BLOCKED/ACTIVE, ACTIVE/REGISTERED and ACTIVE/ACTIVE	
		if(!memcmp(strPersonal_Info.bCardStatus,"BA",2) || !memcmp(strPersonal_Info.bCardStatus,"AR",2) || !memcmp(strPersonal_Info.bCardStatus,"AA",2))
		{
			vdDebug_LogPrintf("1. fOffline_PtsAwarding is TRUE");
			srTransRec.fOffline_PtsAwarding = TRUE;
			return d_OK;
		}
	}
	
	return d_OK;
	
}

int inReadMIFARECardEx(void)
{
    USHORT uRtn;
    BYTE baATQA[16];
    BYTE bSAK[16];
    BYTE baCSN[16];
    BYTE bCSNLen;
    BYTE baATS[16];
	BYTE byKeyBuf;
    USHORT bATSLen;
    
	uRtn = CTOS_CLTypeAActiveFromIdle(0,baATQA,bSAK,baCSN,&bCSNLen);
	vdDebug_LogPrintf("CTOS_CLTypeAActiveFromIdle %d %02x",uRtn, uRtn);
	if(uRtn != 0)
		return uRtn;
    uRtn =  CTOS_CLRATS(0,baATS,&bATSLen);
	vdDebug_LogPrintf("CTOS_CLRATS %d %02x",uRtn,uRtn);
    if(uRtn != d_OK)  
    {
        //CTOS_LCDTPrint("RATS NG\n");
        return uRtn;
    } 

    return uRtn;
}


int inWriteExpiry(void)
{
	int inRet = -1;
	
	BYTE byDivKey[32+1];
	BYTE bUID[14+1];
	BYTE bUID2[14+1];
	BYTE bMKey[32+1];
	BYTE szCardName[26+1]={0};
	BYTE szCardNo[16+1]={0};
	USHORT usRtn = -1;
	ULONG ulAPRtn = -1;
	ULONG ulDataLen;
	ULONG ulPoints = 0;
	ULONG ulHostRespPoints = 0;

	if(srTransRec.fVirtualCard == TRUE)
		return d_OK;
	
	CTOS_LCDTClearDisplay();
	vdDispTransTitle(srTransRec.byTransType);
	
    if ((strTCT.byTerminalType % 2) == 0)
    {
		setLCDPrint27(7, DISPLAY_POSITION_CENTER, " PLEASE TAP FOR ");	
		setLCDPrint27(8, DISPLAY_POSITION_CENTER, "CARD UPDATE");		
	}
	else
	{
		setLCDPrint27(4, DISPLAY_POSITION_CENTER, " PLEASE TAP FOR ");	
		setLCDPrint27(5, DISPLAY_POSITION_CENTER, "CARD UPDATE");	
	}

TAP_AGAIN:
	
	inRet = inReadMIFARECard();
	if(inRet != d_OK)
	{
		vdDebug_LogPrintf("inReadMIFARECard FAIL [%d]",inRet);
		CTOS_Delay(1500);

		if(inRet == USER_CANCEL)
			return USER_CANCEL;
		else if(inRet == READ_CARD_TIMEOUT)
			return READ_CARD_TIMEOUT;
		else
			goto TAP_AGAIN;
	}
	else
		vdDebug_LogPrintf("inReadMIFARECard[%d]",inRet);
	

	inRet = inSelectAppAndGetUID();
	if(inRet != d_OK)
	{
		vdDisplayErrorMsgResp2("GET","APP AND UID","FAILED");
		goto TAP_AGAIN;
	}

	inRet = inDiversifyProcess(0x02, WRITE_CARD_INFO);
	if(inRet != d_OK)
	{
		vdDisplayErrorMsgResp2("KEY","DIVERSIFICATION","FAILED");
		goto TAP_AGAIN;
	}
	
	memset(strPersonal_Info.bExpiryDate,0x00,sizeof(strPersonal_Info.bExpiryDate));
	strcpy(strPersonal_Info.bExpiryDate,"07-31-2021");
	inRet = inWriteDatatoCard(FIELD_EXP_DATE,strPersonal_Info.bExpiryDate);
	if(inRet != d_OK)
		return d_NO;
	
	usRtn = CTOS_DesfireCommitTransaction();
	if(usRtn != 0x00)
	{
		vdDisplayErrorMsgResp2("COMMIT","FAILED","");
		vdDebug_LogPrintf("CTOS_DesfireCommitTransaction FAILED[%d]",usRtn);
		CTOS_Delay(1500);
		return d_NO;
	}
	else
		vdDebug_LogPrintf("CTOS_DesfireCommitTransaction[%d]",usRtn);

	return d_OK;
	
}

void vdLogPersonalInfo(char *szLog)
{
	vdDebug_LogPrintf("***** %s *****",szLog);
	vdDebug_LogPrintf("CARD NUMBER     [%s]",strPersonal_Info.bCardNo);
	vdDebug_LogPrintf("CARD HOLDER NAME[%s]",strPersonal_Info.bCardHolderName);
	vdDebug_LogPrintf("EXPIRY          [%s]",strPersonal_Info.bExpiryDate);
	vdDebug_LogPrintf("CARD SEQ NUMBER [%s]",strPersonal_Info.bCardSeqNo);
	vdDebug_LogPrintf("CARD STATUS     [%s]",strPersonal_Info.bCardStatus);
	vdDebug_LogPrintf("CARD PER DATE   [%s]",strPersonal_Info.bCardPerDate);
	vdDebug_LogPrintf("LAST DATA SYNC  [%s]",strPersonal_Info.bLastDataSync);
}

void vdDisplayTapCardforUpdate(void)
{
	CTOS_LCDTClearDisplay();
	vdDispTransTitle(srTransRec.byTransType);
	
	if ((strTCT.byTerminalType % 2) == 0)
    {
		setLCDPrint27(7, DISPLAY_POSITION_CENTER, " PLEASE TAP FOR ");	
		setLCDPrint27(8, DISPLAY_POSITION_CENTER, "CARD UPDATE");		
	}
	else
	{
		setLCDPrint27(4, DISPLAY_POSITION_CENTER, " PLEASE TAP FOR ");	
		setLCDPrint27(5, DISPLAY_POSITION_CENTER, "CARD UPDATE");	
	}
}
