#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <ctosapi.h>


#include "PCI100.h"
#include "PCI100des.h"
#include "comms.h"

#include "..\filemodule\myFileFunc.h"
#include "..\debug\debug.h"
#include "..\Pinpad\Pinpad.h"



static unsigned long p_inBaudrate = 115200;

static char p_szAdminKey[24+1] = "\x01\x02\x03\x04\x05\x06\x07\x08\x11\x12\x13\x14\x15\x16\x17\x18\x21\x22\x23\x24\x25\x26\x27\x28";

static char szHexSKenc[16+1];
static char szHexSKKek[16+1];
static char szHexSKMac[16+1];


void PCI100_3DES_CBC(int AdminKey,char *szAdminKey,char *ICV,char *Encrypt_Data, int inEncrypt_Datalen, char *MKdiv)
{
	int i, sz, times;
	char szInbuf[250];
	char szOutbuf[250];
	unsigned char  *s = Encrypt_Data;
	int inlen;

	times = inEncrypt_Datalen / 8;
	memset(szOutbuf, 0x00, sizeof(szOutbuf));

	for(i = 0; i < times; i++)
	{
		memset(szInbuf, 0x00, sizeof(szInbuf));
		memcpy(szInbuf, &s[i*8], 8);

		if (i == 0)
		{			
			PCI100_XOR(szInbuf,ICV,8);
		}
		else
		{		
			PCI100_XOR(szInbuf,szOutbuf,8);
		}

		if (AdminKey == 3)
			TripleDes_24Key(szAdminKey,szInbuf,szOutbuf,'E');
		else
			TripleDes_16Key(szAdminKey,szInbuf,szOutbuf,'E');
		
		memcpy(&MKdiv[i*8], szOutbuf, 8);
	}


	times = inEncrypt_Datalen % 8;
	if(times > 0)
	{
		memset(szInbuf, 0x00, sizeof(szInbuf));

		memcpy(szInbuf, s, times);
		PCI100_XOR(szInbuf,szOutbuf,8);

		if (AdminKey == 3)
			TripleDes_24Key(szAdminKey,szInbuf,szOutbuf,'E');
		else
			TripleDes_16Key(szAdminKey,szInbuf,szOutbuf,'E');

		memcpy(&MKdiv[i*8], szOutbuf, 8);
	}

}


void PCI100_Check_KCV(int Keylen,char *szMasterKey,char *szKCV)
{
	char szbuf[8+1];
	 
	memset(szbuf, 0x00, sizeof(szbuf));

	if (Keylen == 24)
			TripleDes_24Key(szMasterKey,szbuf,szKCV,'E');
	
	if (Keylen == 16)
			TripleDes_16Key(szMasterKey,szbuf,szKCV,'E');

	if (Keylen == 8)
			dess(szMasterKey,szbuf,szKCV,'E');

}

void PCI100_Check_DLE(char *InOutBuf,int *inlen)
{
	unsigned int i,j;
	int len;
	unsigned char  *s = InOutBuf;

	if (*inlen == 0)
		return;

	len = *inlen;

    for (i = len-1; i > 1; i--)
    {
		if (s[i] == PCI100_DLE)
		{
			*inlen += 1;
			for (j=*inlen; j>i+1; j--)
			{
				InOutBuf[j-1] = InOutBuf[j-2];
			}
			InOutBuf[i+1] = PCI100_DLE;
		}
    }
}


void PCI100_Check_DLE_R(char *InOutBuf,int *inlen)
{
	unsigned int i,j;
	int len;
	unsigned char  *s = InOutBuf;

	if (*inlen == 0)
		return;

	len = *inlen-2;

    for (i = 1; i < len; i++)
    {
		if (s[i] == PCI100_DLE)
		{
			len -= 1;
			for (j = i; j < *inlen; j++)
			{
				InOutBuf[j] = InOutBuf[j+1];
			}
			*inlen -= 1;
		}
    }
}


void PCI100_Encrypted_Data(char *InBuf,int inlen,char *OutBuf)
{
	int i, times;
	char szInbuf[250];
	char szOutbuf[250];
	unsigned char  *s = InBuf;

	times = inlen / 8;
	memset(szOutbuf, 0x00, sizeof(szOutbuf));

	for(i = 0; i < times; i++)
	{
		memset(szInbuf, 0x00, sizeof(szInbuf));
		memcpy(szInbuf, &s[i*8], 8);

		TripleDes_16Key(szHexSKenc,szInbuf,szOutbuf,'E');

		memcpy(&OutBuf[i*8], szOutbuf, 8);
	}


}

void PCI100_Decode_Data(char *InBuf,int inlen,char *OutBuf)
{
	int i, times;
	char szInbuf[250];
	char szOutbuf[250];
	unsigned char  *s = InBuf;

	times = inlen / 8;
	memset(szOutbuf, 0x00, sizeof(szOutbuf));

	for(i = 0; i < times; i++)
	{
		memset(szInbuf, 0x00, sizeof(szInbuf));
		memcpy(szInbuf, &s[i*8], 8);

		TripleDes_16Key(szHexSKenc,szInbuf,szOutbuf,'D');

		memcpy(&OutBuf[i*8], szOutbuf, 8);
	}


}



void PCI100_Mac_Data(char *InBuf,int inlen,char *OutBuf)
{
	int i, sz, times;
	char szInbuf[250];
	char szOutbuf[250];
	unsigned char  *s = InBuf;
	char szICV[8+1];

	times = inlen / 8;
	memset(szOutbuf, 0x00, sizeof(szOutbuf));
	memset(szICV, 0x00, sizeof(szICV));

	for(i = 0; i < times; i++)
	{
		memset(szInbuf, 0x00, sizeof(szInbuf));
		memcpy(szInbuf, &s[i*8], 8);

		if (i == 0)
		{	
			PCI100_XOR(szInbuf,szICV,8);
		}
		else
		{
			PCI100_XOR(szInbuf,szOutbuf,8);
		}

		TripleDes_16Key(szHexSKMac,szInbuf,szOutbuf,'E');
	}

	memcpy(OutBuf, szOutbuf, 8);
	
}



void PCI100_PaddingData(char *InOutBuf,int *inlen)
{
	unsigned int i;
	int len;

	len = *inlen;
	i = len % 8;

	if (i != 0)
	{
		memcpy(&InOutBuf[len],"\x00\x00\x00\x00\x00\x00\x00\x00",(8-i));
		*inlen += (8-i);
	}
}



unsigned char PCI100_lrc(unsigned char *buf, unsigned int len)
{
    unsigned int i;
    unsigned char lrc;
    lrc = 0;
    for (i = 0; i < len; i ++)
    {
        lrc ^= buf[i];
    }
    return lrc;
}

int inPCI100_GetDeviceInfo(char *szVersion, char *DSN)
{
	char szSendBuf[SEND_BUF+1];
	int inSendlen = 0;
	char szRecvBuf[RECV_BUF+1];
	int inRecvlen = 0;

	int status;

	memset(szSendBuf,0x00,sizeof(szSendBuf));
	
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_STX;
	szSendBuf[inSendlen++] = GET_DEVICE_INFO;

	szSendBuf[inSendlen++] = PCI100_lrc(&szSendBuf[2],1);

	PCI100_Check_DLE(szSendBuf,&inSendlen);
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_ETX;

	//inCTOSS_USBSendBuf(szSendBuf,inSendlen);
	//inCTOSS_USBHostSendBuf(szSendBuf,inSendlen);
	inCTOSS_RS232SendBuf(szSendBuf,inSendlen);

	memset(szRecvBuf,0x00,sizeof(szRecvBuf));
	//inCTOSS_USBRecvBuf(szRecvBuf,&inRecvlen);
	//inCTOSS_USBHostRecvBuf(szRecvBuf,&inRecvlen);
	//status = inCTOSS_RS232RecvBuf(szRecvBuf,&inRecvlen,1);
	status = inCTOSS_RS232RecvBuf(szRecvBuf,&inRecvlen,5);
	if (status != d_OK)
		return status;
	
	PCI100_Check_DLE_R(szRecvBuf,&inRecvlen);
	vdPCIDebug_HexPrintf("GetDeviceInfo",szRecvBuf,inRecvlen);

	status = szRecvBuf[2];

	if (status == d_OK)
	{
		memcpy(szVersion,&szRecvBuf[3],4);

		memcpy(DSN,&szRecvBuf[7],16);
	}

	return status;
}


int inPCI100_InitialAuthentication(char *T_RN,char *PinPadRN, char *PinPadCrypto)
{
	char szSendBuf[SEND_BUF+1];
	int inSendlen = 0;
	char szRecvBuf[RECV_BUF+1];
	int inRecvlen = 0;

	int status;

	memset(szSendBuf,0x00,sizeof(szSendBuf));
	
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_STX;
	szSendBuf[inSendlen++] = INITTIAL_AUTHENTICATION;

	memcpy(&szSendBuf[inSendlen],T_RN,8);
	inSendlen +=8;

	szSendBuf[inSendlen++] = PCI100_lrc(&szSendBuf[2],9);

	PCI100_Check_DLE(szSendBuf,&inSendlen);
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_ETX;

	//inCTOSS_USBSendBuf(szSendBuf,inSendlen);
	//inCTOSS_USBHostSendBuf(szSendBuf,inSendlen);
	inCTOSS_RS232SendBuf(szSendBuf,inSendlen);

	memset(szRecvBuf,0x00,sizeof(szRecvBuf));
	//inCTOSS_USBRecvBuf(szRecvBuf,&inRecvlen);
	//inCTOSS_USBHostRecvBuf(szRecvBuf,&inRecvlen);
	status = inCTOSS_RS232RecvBuf(szRecvBuf,&inRecvlen,5);
	if (status != d_OK)
		return status;
	
	PCI100_Check_DLE_R(szRecvBuf,&inRecvlen);
	vdPCIDebug_HexPrintf("InitialAuth",szRecvBuf,inRecvlen);

	status = szRecvBuf[2];

	if (status == d_OK)
	{
		memcpy(PinPadRN,&szRecvBuf[3],8);

		memcpy(PinPadCrypto,&szRecvBuf[11],8);
	}

	return status;
}


int inPCI100_MutualAuthentication(char *TermCryptogram)
{
	char szSendBuf[SEND_BUF+1];
	int inSendlen = 0;
	char szRecvBuf[RECV_BUF+1];
	int inRecvlen = 0;

	int status;

	memset(szSendBuf,0x00,sizeof(szSendBuf));
	
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_STX;
	szSendBuf[inSendlen++] = MUTUAL_AUTHENTICATION;

	memcpy(&szSendBuf[inSendlen],TermCryptogram,8);
	inSendlen +=8;

	szSendBuf[inSendlen++] = PCI100_lrc(&szSendBuf[2],9);

	PCI100_Check_DLE(szSendBuf,&inSendlen);
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_ETX;

	//inCTOSS_USBSendBuf(szSendBuf,inSendlen);
	//inCTOSS_USBHostSendBuf(szSendBuf,inSendlen);
	inCTOSS_RS232SendBuf(szSendBuf,inSendlen);

	memset(szRecvBuf,0x00,sizeof(szRecvBuf));
	//inCTOSS_USBRecvBuf(szRecvBuf,&inRecvlen);
	//inCTOSS_USBHostRecvBuf(szRecvBuf,&inRecvlen);
	status = inCTOSS_RS232RecvBuf(szRecvBuf,&inRecvlen,5);

	vdPCIDebug_HexPrintf("-->>inPCI100_MutualAuthentication",szRecvBuf,inRecvlen);
	vdDebug_LogPrintf("-->>inPCI100_MutualAuthentication status[%d]", status);
		
	if (status != d_OK)
		return status;
	
	PCI100_Check_DLE_R(szRecvBuf,&inRecvlen);
	vdPCIDebug_HexPrintf("MutualAuth",szRecvBuf,inRecvlen);

	status = szRecvBuf[2];

	return status;
}


int inPCI100_MutualAuthenticationProcess(void)
{
	int status;
	char szVersion[4+1];

	char PinPadRN[8+1];
	char PinPadCrypto[8+1];
	char szT_RN[8+1];
	char szR_RN[8+1];

	char szTermCrypto[8+1];
	char szPinPadCrypto[8+1];

	char szHexICV[50];
	char szHexMKdiv[50];
	char szHexDSN[16+1];

	char szHexencData[16+1];
	char szHexKekData[16+1];
	char szHexMacData[16+1];

	char szICV[100] = "0000000000000000";
	char szbuf[100];

	//if (strTCT.fDemo == TRUE)
	//	return(d_OK);

	memset(szHexICV,0x00,sizeof(szHexICV));
	memset(szHexMKdiv,0x00,sizeof(szHexMKdiv));

	PCI100_DSP_2_HEX(szICV,szHexICV,8);


	memset(szVersion,0x00,sizeof(szVersion));
	memset(szHexDSN,0x00,sizeof(szHexDSN));
	status = inPCI100_GetDeviceInfo(szVersion,szHexDSN);
	if (status != d_OK)
	{
		vdDisplayErrorMsg(1, 8, "Get Device Info error");
		return status;
	}

	PCI100_3DES_CBC(3,p_szAdminKey,szHexICV,szHexDSN,16,szHexMKdiv);
	vdPCIDebug_HexPrintf("szHexMKdiv",szHexMKdiv,16);

	memset(PinPadRN,0x00,sizeof(PinPadRN));
	memset(PinPadCrypto,0x00,sizeof(PinPadCrypto));
	memset(szT_RN,0x00,sizeof(szT_RN));
	memset(szR_RN,0x00,sizeof(szR_RN));
	//Generate 8 bytes random number
	//vdCTOSS_RNG(szT_RN);
	
	status = inPCI100_InitialAuthentication(szT_RN,PinPadRN,PinPadCrypto);
	if (status != d_OK)
	{
		vdDisplayErrorMsg(1, 8, "Initial Auth error");
		return status;
	}
	memcpy(szR_RN,PinPadRN,8);

	memset(szHexSKenc,0x00,sizeof(szHexSKenc));
	memset(szHexencData,0x00,sizeof(szHexencData));
	memcpy(&szHexencData[0],&szT_RN[0],4);
	memcpy(&szHexencData[4],&szR_RN[4],4);
	memcpy(&szHexencData[8],&szT_RN[4],4);
	memcpy(&szHexencData[12],&szR_RN[0],4);
	PCI100_3DES_CBC(2,szHexMKdiv,szHexICV,szHexencData,16,szHexSKenc);
	vdPCIDebug_HexPrintf("szHexSKenc",szHexSKenc,16);

	memset(szTermCrypto,0x00,sizeof(szTermCrypto));
	TripleDes_16Key(szHexSKenc,szR_RN,szTermCrypto,'E');
	vdPCIDebug_HexPrintf("szTermCryptogram",szTermCrypto,8);

	memset(szPinPadCrypto,0x00,sizeof(szPinPadCrypto));
	TripleDes_16Key(szHexSKenc,szT_RN,szPinPadCrypto,'E');
	vdPCIDebug_HexPrintf("szPinPadCrypto",szPinPadCrypto,8);
	
	vdPCIDebug_HexPrintf("MutualAuthProcess szTermCrypto: ",szTermCrypto,8);

	status = inPCI100_MutualAuthentication(szTermCrypto);
	if (status != d_OK)
	{
		//vdDisplayErrorMsg(1, 8, "Mutual Auth error");
		return status;
	}
	//else
	//	vdDisplayErrorMsg(1, 8, "Mutual Auth OK");

	
	memset(szHexSKKek,0x00,sizeof(szHexSKKek));
	memset(szHexKekData,0x00,sizeof(szHexKekData));
	memcpy(&szHexKekData[0],&szR_RN[4],4);
	memcpy(&szHexKekData[4],&szT_RN[0],4);
	memcpy(&szHexKekData[8],&szR_RN[0],4);
	memcpy(&szHexKekData[12],&szT_RN[4],4);
	PCI100_3DES_CBC(2,szHexMKdiv,szHexICV,szHexKekData,16,szHexSKKek);
	vdPCIDebug_HexPrintf("szHexSKKek",szHexSKKek,16);

	memset(szHexSKMac,0x00,sizeof(szHexSKMac));
	memset(szHexMacData,0x00,sizeof(szHexMacData));
	memcpy(&szHexMacData[0],&szT_RN[4],4);
	memcpy(&szHexMacData[4],&szR_RN[0],4);
	memcpy(&szHexMacData[8],&szT_RN[0],4);
	memcpy(&szHexMacData[12],&szR_RN[4],4);
	PCI100_3DES_CBC(2,szHexMKdiv,szHexICV,szHexMacData,16,szHexSKMac);
	vdPCIDebug_HexPrintf("szHexSKMac",szHexSKMac,16);

	return status;
}


int inPCI100_SetSerialNumber(char *szDSN)
{
	char szSendBuf[SEND_BUF+1];
	int inSendlen = 0;
	char szRecvBuf[RECV_BUF+1];
	int inRecvlen = 0;

	int status;

	memset(szSendBuf,0x00,sizeof(szSendBuf));
	
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_STX;
	szSendBuf[inSendlen++] = SET_SERIAL_NUMBER;

	memcpy(&szSendBuf[inSendlen],szDSN,16);
	inSendlen +=16;

	szSendBuf[inSendlen++] = 0x00;
	
	szSendBuf[inSendlen++] = PCI100_lrc(&szSendBuf[2],18);

	PCI100_Check_DLE(szSendBuf,&inSendlen);
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_ETX;

	//inCTOSS_USBSendBuf(szSendBuf,inSendlen);
	//inCTOSS_USBHostSendBuf(szSendBuf,inSendlen);
	vdPCIDebug_HexPrintf("SetSerialNumber",szSendBuf,inSendlen);
	inCTOSS_RS232SendBuf(szSendBuf,inSendlen);

	memset(szRecvBuf,0x00,sizeof(szRecvBuf));
	//inCTOSS_USBRecvBuf(szRecvBuf,&inRecvlen);
	//inCTOSS_USBHostRecvBuf(szRecvBuf,&inRecvlen);
	status = inCTOSS_RS232RecvBuf(szRecvBuf,&inRecvlen,5);
	if (status != d_OK)
		return status;
	
	PCI100_Check_DLE_R(szRecvBuf,&inRecvlen);
	vdPCIDebug_HexPrintf("SetSerialNumber recv",szRecvBuf,inRecvlen);

	status = szRecvBuf[2];
	if (status != d_OK)
	{
		vdDisplayErrorMsg(1, 8, "Set DSN error");
		return status;
	}
	else{
		vdDisplayErrorMsg(1, 8, "Set DSN OK");
	}

	return status;
}


int inPCI100_ResetPINPad(char *szMac)
{
	char szSendBuf[SEND_BUF+1];
	int inSendlen = 0;
	char szRecvBuf[RECV_BUF+1];
	int inRecvlen = 0;

	int status;

	memset(szSendBuf,0x00,sizeof(szSendBuf));
	
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_STX;
	szSendBuf[inSendlen++] = RESET_PINPAD;

	memcpy(&szSendBuf[inSendlen],szMac,8);
	inSendlen +=8;

	szSendBuf[inSendlen++] = PCI100_lrc(&szSendBuf[2],9);

	PCI100_Check_DLE(szSendBuf,&inSendlen);
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_ETX;

	//inCTOSS_USBSendBuf(szSendBuf,inSendlen);
	//inCTOSS_USBHostSendBuf(szSendBuf,inSendlen);
	vdPCIDebug_HexPrintf("ResetPINPad",szSendBuf,inSendlen);
	inCTOSS_RS232SendBuf(szSendBuf,inSendlen);

	memset(szRecvBuf,0x00,sizeof(szRecvBuf));
	//inCTOSS_USBRecvBuf(szRecvBuf,&inRecvlen);
	//inCTOSS_USBHostRecvBuf(szRecvBuf,&inRecvlen);
	status = inCTOSS_RS232RecvBuf(szRecvBuf,&inRecvlen,5);
	if (status != d_OK)
		return status;
	
	PCI100_Check_DLE_R(szRecvBuf,&inRecvlen);
	vdPCIDebug_HexPrintf("ResetPINPad recv",szRecvBuf,inRecvlen);

	status = szRecvBuf[2];
	if (status != d_OK)
	{
		vdDisplayErrorMsg(1, 8, "Reset PINPad error");
		return status;
	}
	else
		vdDisplayErrorMsg(1, 8, "Reset PINPad OK");

	return status;
}


int inPCI100_SaveGeneralMK(int MKID,int Keylen,char *szMasterKey)
{
	char szSendBuf[SEND_BUF+1];
	int inSendlen = 0;
	char szRecvBuf[RECV_BUF+1];
	int inRecvlen = 0;
	char szKCV[8+1];

	int status;

	if (Keylen == 8)
	{
		if (MKID < MINIMUM_DES_KEY || MKID > MAXIMUM_DES_KEY)
		{
			vdDisplayErrorMsg(1, 8, "Key Index Error");
			return d_STAT_BAD_PARAMETER;
		}
	}

	if (Keylen == 16 || Keylen == 24)
	{
		if (MKID < MINIMUM_3DES_KEY || MKID > MAXIMUM_3DES_KEY)
		{
			vdDisplayErrorMsg(1, 8, "Key Index Error");
			return d_STAT_BAD_PARAMETER;
		}
	}

	memset(szSendBuf,0x00,sizeof(szSendBuf));
	memset(szKCV,0x00,sizeof(szKCV));
	
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_STX;
	szSendBuf[inSendlen++] = SAVE_GENERAL_MK;
	szSendBuf[inSendlen++] = MKID;
	szSendBuf[inSendlen++] = Keylen;

	memcpy(&szSendBuf[inSendlen],szMasterKey,Keylen);
	inSendlen +=Keylen;

	PCI100_Check_KCV(Keylen,szMasterKey,szKCV);
	vdPCIDebug_HexPrintf("Check_KCV",szKCV,8);
	memcpy(&szSendBuf[inSendlen],szKCV,3);
	inSendlen +=3;
	
	szSendBuf[inSendlen++] = PCI100_lrc(&szSendBuf[2],6+Keylen);

	PCI100_Check_DLE(szSendBuf,&inSendlen);
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_ETX;

	//inCTOSS_USBSendBuf(szSendBuf,inSendlen);
	//inCTOSS_USBHostSendBuf(szSendBuf,inSendlen);
	vdPCIDebug_HexPrintf("MK",szSendBuf,inSendlen);
	inCTOSS_RS232SendBuf(szSendBuf,inSendlen);

	memset(szRecvBuf,0x00,sizeof(szRecvBuf));
	//inCTOSS_USBRecvBuf(szRecvBuf,&inRecvlen);
	//inCTOSS_USBHostRecvBuf(szRecvBuf,&inRecvlen);
	status = inCTOSS_RS232RecvBuf(szRecvBuf,&inRecvlen,5);
	if (status != d_OK)
		return status;
	
	PCI100_Check_DLE_R(szRecvBuf,&inRecvlen);
	vdPCIDebug_HexPrintf("MK recv",szRecvBuf,inRecvlen);

	status = szRecvBuf[2];
	if (status != d_OK)
	{
		vdDisplayErrorMsg(1, 8, "Save MK error");
		return status;
	}
	else{

		vdDisplayErrorMsg(1, 8, "Save MK OK");
	}

	return status;
}


int inPCI100_SaveMKByTK(int TKID,int MKID,int EncKeylen,char *szEncMasterKey,char *szKCV)
{
	char szSendBuf[SEND_BUF+1];
	int inSendlen = 0;
	char szRecvBuf[RECV_BUF+1];
	int inRecvlen = 0;

	int status;

	if (EncKeylen == 8)
	{
		if (MKID < MINIMUM_DES_KEY || MKID > MAXIMUM_DES_KEY)
		{
			vdDisplayErrorMsg(1, 8, "Key Index Error");
			return d_STAT_BAD_PARAMETER;
		}
	}

	if (EncKeylen == 16 || EncKeylen == 24)
	{
		if (MKID < MINIMUM_3DES_KEY || MKID > MAXIMUM_3DES_KEY)
		{
			vdDisplayErrorMsg(1, 8, "Key Index Error");
			return d_STAT_BAD_PARAMETER;
		}
	}

	memset(szSendBuf,0x00,sizeof(szSendBuf));
	
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_STX;
	szSendBuf[inSendlen++] = SAVE_MK_BY_TK;
	szSendBuf[inSendlen++] = TKID;
	szSendBuf[inSendlen++] = MKID;
	szSendBuf[inSendlen++] = EncKeylen;

	memcpy(&szSendBuf[inSendlen],szEncMasterKey,EncKeylen);
	inSendlen +=EncKeylen;

	memcpy(&szSendBuf[inSendlen],szKCV,3);
	inSendlen +=3;
	
	szSendBuf[inSendlen++] = PCI100_lrc(&szSendBuf[2],7+EncKeylen);

	PCI100_Check_DLE(szSendBuf,&inSendlen);
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_ETX;

	//inCTOSS_USBSendBuf(szSendBuf,inSendlen);
	//inCTOSS_USBHostSendBuf(szSendBuf,inSendlen);
	vdPCIDebug_HexPrintf("MKByTK",szSendBuf,inSendlen);
	inCTOSS_RS232SendBuf(szSendBuf,inSendlen);

	memset(szRecvBuf,0x00,sizeof(szRecvBuf));
	//inCTOSS_USBRecvBuf(szRecvBuf,&inRecvlen);
	//inCTOSS_USBHostRecvBuf(szRecvBuf,&inRecvlen);
	status = inCTOSS_RS232RecvBuf(szRecvBuf,&inRecvlen,5);
	if (status != d_OK)
		return status;
	
	PCI100_Check_DLE_R(szRecvBuf,&inRecvlen);
	vdPCIDebug_HexPrintf("MKByTK recv",szRecvBuf,inRecvlen);

	status = szRecvBuf[2];
	if (status != d_OK)
	{
		vdDisplayErrorMsg(1, 8, "Save MK error");
		return status;
	}
	else{
		vdDisplayErrorMsg(1, 8, "Save MK OK");
	}

	return status;
}

int inPCI100_DisplayMessage(int PositionX,int PositionY,int Displen,char *szDispMessage)
{
	char szSendBuf[SEND_BUF+1];
	int inSendlen = 0;
	char szRecvBuf[RECV_BUF+1];
	int inRecvlen = 0;
	char szTimeOut[2+1];
	char szMacBlock[50+1];

	char szEncData[SEND_BUF+1];
	int inEncDatalen = 0;
	
	int status;
	char szbuf[SEND_BUF+1];
	

	memset(szSendBuf,0x00,sizeof(szSendBuf));
	
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_STX;
	szSendBuf[inSendlen++] = DISP_MESSAGE;

	memset(szEncData,0x00,sizeof(szEncData));	
	szEncData[inEncDatalen++] = PositionX;//PositionX
	szEncData[inEncDatalen++] = PositionY;//PositionY

	szEncData[inEncDatalen++] = Displen+1;
	szEncData[inEncDatalen++] = 0xF0;// 0xF1= big font; 0xF0=small font
	memcpy(&szEncData[inEncDatalen],szDispMessage,Displen);
	inEncDatalen +=Displen;

	PCI100_PaddingData(szEncData,&inEncDatalen);
	//memset(szbuf,0x00,sizeof(szbuf));
	//PCI100_HEX_2_DSP(szEncData,szbuf,inEncDatalen);
	//vdPCIDebug_LogPrintf("PaddingData=[%d][%s]",inEncDatalen,szbuf);
	
	PCI100_Encrypted_Data(szEncData,inEncDatalen,&szSendBuf[inSendlen]);
	inSendlen += inEncDatalen;

	PCI100_Mac_Data(szEncData,inEncDatalen,&szSendBuf[inSendlen]);
	inSendlen += 8;
	
	szSendBuf[inSendlen++] = PCI100_lrc(&szSendBuf[2],inSendlen-2);

	PCI100_Check_DLE(szSendBuf,&inSendlen);
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_ETX;

	//inCTOSS_USBSendBuf(szSendBuf,inSendlen);
	//inCTOSS_USBHostSendBuf(szSendBuf,inSendlen);
	vdPCIDebug_HexPrintf("DisplayMessage",szSendBuf,inSendlen);
	inCTOSS_RS232SendBuf(szSendBuf,inSendlen);

	memset(szRecvBuf,0x00,sizeof(szRecvBuf));
	//inCTOSS_USBRecvBuf(szRecvBuf,&inRecvlen);
	//inCTOSS_USBHostRecvBuf(szRecvBuf,&inRecvlen);
	status = inCTOSS_RS232RecvBuf(szRecvBuf,&inRecvlen,5);
	if (status != d_OK)
		return status;
	
	PCI100_Check_DLE_R(szRecvBuf,&inRecvlen);
	vdPCIDebug_HexPrintf("DisplayMessage recv",szRecvBuf,inRecvlen);

	status = szRecvBuf[2];
	if (status == d_OK){
		CTOS_Delay(1500);
		//CTOS_Delay(10);
	}

	return status;
}

int inPCI100_SetIdleMessage(int Displen,char *szDispMessage)
{
	char szSendBuf[SEND_BUF+1];
	int inSendlen = 0;
	char szRecvBuf[RECV_BUF+1];
	int inRecvlen = 0;
	char szTimeOut[2+1];

	char szEncData[SEND_BUF+1];
	int inEncDatalen = 0;
	
	int status;
	char szbuf[SEND_BUF+1];
	

	memset(szSendBuf,0x00,sizeof(szSendBuf));
	
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_STX;
	szSendBuf[inSendlen++] = IDLE_MESSAGE;

	memset(szEncData,0x00,sizeof(szEncData));
	memcpy(&szEncData[inEncDatalen],szDispMessage,Displen);
	inEncDatalen +=Displen;

	PCI100_PaddingData(szEncData,&inEncDatalen);
	//memset(szbuf,0x00,sizeof(szbuf));
	//PCI100_HEX_2_DSP(szEncData,szbuf,inEncDatalen);
	//vdPCIDebug_LogPrintf("PaddingData=[%d][%s]",inEncDatalen,szbuf);
	
	PCI100_Encrypted_Data(szEncData,inEncDatalen,&szSendBuf[inSendlen]);
	inSendlen += inEncDatalen;

	PCI100_Mac_Data(szEncData,inEncDatalen,&szSendBuf[inSendlen]);
	inSendlen += 8;
	
	szSendBuf[inSendlen++] = PCI100_lrc(&szSendBuf[2],inSendlen-2);

	PCI100_Check_DLE(szSendBuf,&inSendlen);
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_ETX;

	//inCTOSS_USBSendBuf(szSendBuf,inSendlen);
	//inCTOSS_USBHostSendBuf(szSendBuf,inSendlen);
	vdPCIDebug_HexPrintf("IdleMessage",szSendBuf,inSendlen);
	inCTOSS_RS232SendBuf(szSendBuf,inSendlen);

	memset(szRecvBuf,0x00,sizeof(szRecvBuf));
	//inCTOSS_USBRecvBuf(szRecvBuf,&inRecvlen);
	//inCTOSS_USBHostRecvBuf(szRecvBuf,&inRecvlen);
	status = inCTOSS_RS232RecvBuf(szRecvBuf,&inRecvlen,5);
	if (status != d_OK)
		return status;
	
	PCI100_Check_DLE_R(szRecvBuf,&inRecvlen);
	vdPCIDebug_HexPrintf("IdleMessage recv",szRecvBuf,inRecvlen);

	status = szRecvBuf[2];

	return status;
}

int inPCI100_SaveGeneralWK(int MKID,int WKID,int EncKeylen,char *szEncWKey,char *szKCV)
{
	char szSendBuf[SEND_BUF+1];
	int inSendlen = 0;
	char szRecvBuf[RECV_BUF+1];
	int inRecvlen = 0;

	int status;

	//if (strTCT.fDemo == TRUE){
	//	return(d_OK);
	//}

	if (EncKeylen == 8)
	{
		if (WKID < MINIMUM_DES_KEY || WKID > MAXIMUM_DES_KEY)
		{
			vdDisplayErrorMsg(1, 8, "Key Index Error");
			return d_STAT_BAD_PARAMETER;
		}
	}

	if (EncKeylen == 16 || EncKeylen == 24)
	{
		if (WKID < MINIMUM_3DES_KEY || WKID > MAXIMUM_3DES_KEY)
		{
			vdDisplayErrorMsg(1, 8, "Key Index Error");
			return d_STAT_BAD_PARAMETER;
		}
	}

	memset(szSendBuf,0x00,sizeof(szSendBuf));
	
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_STX;
	szSendBuf[inSendlen++] = SAVE_GENERAL_WK;
	szSendBuf[inSendlen++] = MKID;
	szSendBuf[inSendlen++] = WKID;
	szSendBuf[inSendlen++] = EncKeylen;

	memcpy(&szSendBuf[inSendlen],szEncWKey,EncKeylen);
	inSendlen +=EncKeylen;

	memcpy(&szSendBuf[inSendlen],szKCV,3);
	inSendlen +=3;
	
	szSendBuf[inSendlen++] = PCI100_lrc(&szSendBuf[2],7+EncKeylen);

	PCI100_Check_DLE(szSendBuf,&inSendlen);
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_ETX;

	//inCTOSS_USBSendBuf(szSendBuf,inSendlen);
	//inCTOSS_USBHostSendBuf(szSendBuf,inSendlen);
	vdPCIDebug_HexPrintf("WK",szSendBuf,inSendlen);
	inCTOSS_RS232SendBuf(szSendBuf,inSendlen);

	memset(szRecvBuf,0x00,sizeof(szRecvBuf));
	//inCTOSS_USBRecvBuf(szRecvBuf,&inRecvlen);
	//inCTOSS_USBHostRecvBuf(szRecvBuf,&inRecvlen);
	status = inCTOSS_RS232RecvBuf(szRecvBuf,&inRecvlen,5);
	if (status != d_OK)
		return status;
	
	PCI100_Check_DLE_R(szRecvBuf,&inRecvlen);
	vdPCIDebug_HexPrintf("WK recv",szRecvBuf,inRecvlen);

	status = szRecvBuf[2];

	if (status != d_OK)
	{
		vdDisplayErrorMsg(1, 8, "Save WK error");
		return status;
	}
	else{
		//vdDisplayErrorMsg(1, 8, "Save WK OK");
	}

	return status;
}


int inPCI100_GetPIN(int WKID,int TimeOut,int MaxPINlen,int MinPINlen,int NullPIN,int PANLen,char *szPAN,char *PinBlock)
{
	char szSendBuf[SEND_BUF+1];
	int inSendlen = 0;
	char szRecvBuf[RECV_BUF+1];
	int inRecvlen = 0;
	char szTimeOut[2+1];
	char szPinBlock[50+1];

	char szEncData[SEND_BUF+1];
	int inEncDatalen = 0;
	
	int status;
	char szbuf[SEND_BUF+1];

	//if (strTCT.fDemo == TRUE)
	//	return(d_OK);
	
	vdDebug_LogPrintf("-->>inPCI100_GetPIN TimeOut[%d]", TimeOut);
	
	memset(szSendBuf,0x00,sizeof(szSendBuf));
	
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_STX;
	szSendBuf[inSendlen++] = GET_PIN;

	memset(szEncData,0x00,sizeof(szEncData));
	szEncData[inEncDatalen++] = WKID;

	memset(szbuf,0x00,sizeof(szbuf));
	sprintf(szbuf,"%04x",TimeOut);
	PCI100_DSP_2_HEX(szbuf,szTimeOut,2);
	memcpy(&szEncData[inEncDatalen],szTimeOut,2);
	inEncDatalen +=2;
	
	szEncData[inEncDatalen++] = MaxPINlen;
	szEncData[inEncDatalen++] = MinPINlen;
	szEncData[inEncDatalen++] = NullPIN;
	szEncData[inEncDatalen++] = 0x00;//PBType;
	szEncData[inEncDatalen++] = PANLen;
	memcpy(&szEncData[inEncDatalen],szPAN,PANLen);
	inEncDatalen +=PANLen;
	szEncData[inEncDatalen++] = 0x00;//Session Key Length

	PCI100_PaddingData(szEncData,&inEncDatalen);
	//memset(szbuf,0x00,sizeof(szbuf));
	//PCI100_HEX_2_DSP(szEncData,szbuf,inEncDatalen);
	//vdPCIDebug_LogPrintf("PaddingData=[%d][%s]",inEncDatalen,szbuf);
	
	PCI100_Encrypted_Data(szEncData,inEncDatalen,&szSendBuf[inSendlen]);
	inSendlen += inEncDatalen;

	PCI100_Mac_Data(szEncData,inEncDatalen,&szSendBuf[inSendlen]);
	inSendlen += 8;
	
	szSendBuf[inSendlen++] = PCI100_lrc(&szSendBuf[2],inSendlen-2);

	PCI100_Check_DLE(szSendBuf,&inSendlen);
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_ETX;

	//inCTOSS_USBSendBuf(szSendBuf,inSendlen);
	//inCTOSS_USBHostSendBuf(szSendBuf,inSendlen);
	vdPCIDebug_HexPrintf("GetPIN",szSendBuf,inSendlen);
	inCTOSS_RS232SendBuf(szSendBuf,inSendlen);

	memset(szRecvBuf,0x00,sizeof(szRecvBuf));
	//inCTOSS_USBRecvBuf(szRecvBuf,&inRecvlen);
	//inCTOSS_USBHostRecvBuf(szRecvBuf,&inRecvlen);
	status = inCTOSS_RS232RecvBuf(szRecvBuf,&inRecvlen,TimeOut * 2);

	vdDebug_LogPrintf("-->>inPCI100_GetPIN BEFORE status[%d]", status);
	
	//status = inCTOSS_RS232RecvBuf(szRecvBuf,&inRecvlen,TimeOut);
	
	
	if (status != d_OK)
		return status;
	
	PCI100_Check_DLE_R(szRecvBuf,&inRecvlen);
	vdPCIDebug_HexPrintf("GetPIN recv",szRecvBuf,inRecvlen);

	status = szRecvBuf[2];

	vdDebug_LogPrintf("-->>inPCI100_GetPIN AFTER status[%d]", status);
	
	if (status != d_OK)
	{
		//vdDisplayErrorMsg(1, 8, "Get PIN error");
		CTOS_LCDTClearDisplay();
		vdDispTransTitle(srTransRec.byTransType);
		vdDisplayErrorMsg(1, 8, "USER CANCEL");
		return d_ERROR;
	}
	else
	{
		memset(szbuf,0x00,sizeof(szbuf));
		memset(szPinBlock,0x00,sizeof(szPinBlock));
		PCI100_Decode_Data(&szRecvBuf[3],16,szPinBlock);
		vdPCIDebug_HexPrintf("szPinBlock",szPinBlock,16);
		
		PCI100_Mac_Data(szPinBlock,16,szbuf);
		//vdPCIDebug_HexPrintf("MAC",szbuf,8);
		if (memcmp(szbuf,&szRecvBuf[19],8) == 0)
		{
			//vdDisplayErrorMsg(1, 8, "Get PIN OK");
			status = szPinBlock[0];
			memcpy(PinBlock,&szPinBlock[1],8);
			status = d_OK; // sidumili: added
		}
	}

	vdDebug_LogPrintf("-->>inPCI100_GetPIN RETURN status[%d]", status);

	return status;
}


int inPCI100_GetMAC(int WKID,char *szICV,int Datalen,char *szData,char *MacBlock)
{
	char szSendBuf[SEND_BUF+1];
	int inSendlen = 0;
	char szRecvBuf[RECV_BUF+1];
	int inRecvlen = 0;
	char szTimeOut[2+1];
	char szMacBlock[50+1];

	char szEncData[SEND_BUF+1];
	int inEncDatalen = 0;
	
	int status;
	char szbuf[SEND_BUF+1];
	

	memset(szSendBuf,0x00,sizeof(szSendBuf));
	
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_STX;
	szSendBuf[inSendlen++] = GET_MAC;

	memset(szEncData,0x00,sizeof(szEncData));
	szEncData[inEncDatalen++] = WKID;
	
	szEncData[inEncDatalen++] = 0x00;//Method to be used for MAC calculation.00h : CBC Encryption
	szEncData[inEncDatalen++] = 0x00;//Session Key Length
	memcpy(&szEncData[inEncDatalen],szICV,8);
	inEncDatalen +=8;

	szEncData[inEncDatalen++] = Datalen;
	memcpy(&szEncData[inEncDatalen],szData,Datalen);
	inEncDatalen +=Datalen;

	PCI100_PaddingData(szEncData,&inEncDatalen);
	//memset(szbuf,0x00,sizeof(szbuf));
	//PCI100_HEX_2_DSP(szEncData,szbuf,inEncDatalen);
	//vdPCIDebug_LogPrintf("PaddingData=[%d][%s]",inEncDatalen,szbuf);
	
	PCI100_Encrypted_Data(szEncData,inEncDatalen,&szSendBuf[inSendlen]);
	inSendlen += inEncDatalen;

	PCI100_Mac_Data(szEncData,inEncDatalen,&szSendBuf[inSendlen]);
	inSendlen += 8;
	
	szSendBuf[inSendlen++] = PCI100_lrc(&szSendBuf[2],inSendlen-2);

	PCI100_Check_DLE(szSendBuf,&inSendlen);
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_ETX;

	//inCTOSS_USBSendBuf(szSendBuf,inSendlen);
	//inCTOSS_USBHostSendBuf(szSendBuf,inSendlen);
	vdPCIDebug_HexPrintf("GetMAC",szSendBuf,inSendlen);
	inCTOSS_RS232SendBuf(szSendBuf,inSendlen);

	memset(szRecvBuf,0x00,sizeof(szRecvBuf));
	//inCTOSS_USBRecvBuf(szRecvBuf,&inRecvlen);
	//inCTOSS_USBHostRecvBuf(szRecvBuf,&inRecvlen);
	status = inCTOSS_RS232RecvBuf(szRecvBuf,&inRecvlen,5);
	if (status != d_OK)
		return status;
	
	PCI100_Check_DLE_R(szRecvBuf,&inRecvlen);
	vdPCIDebug_HexPrintf("GetMAC recv",szRecvBuf,inRecvlen);

	status = szRecvBuf[2];
	if (status != d_OK)
	{
		vdDisplayErrorMsg(1, 8, "Get MAC error");
		return d_ERROR;
	}
	else
	{
		memset(szbuf,0x00,sizeof(szbuf));
		memset(szMacBlock,0x00,sizeof(szMacBlock));
		PCI100_Decode_Data(&szRecvBuf[3],8,szMacBlock);
		vdPCIDebug_HexPrintf("szMacBlock",szMacBlock,8);
		
		PCI100_Mac_Data(szMacBlock,8,szbuf);
		//vdPCIDebug_HexPrintf("MAC",szbuf,8);
		if (memcmp(szbuf,&szRecvBuf[11],8) == 0)
		{
			vdDisplayErrorMsg(1, 8, "Get MAC OK");
			memcpy(MacBlock,szMacBlock,8);	
		}
	}

	return status;
}


int inPCI100_SetBacklight(int OnOff)
{
	char szSendBuf[SEND_BUF+1];
	int inSendlen = 0;
	char szRecvBuf[RECV_BUF+1];
	int inRecvlen = 0;

	int status;

	char szbuf[SEND_BUF+1];
	char szEncData[SEND_BUF+1];
	int inEncDatalen = 0;

	memset(szSendBuf,0x00,sizeof(szSendBuf));
	
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_STX;
	szSendBuf[inSendlen++] = SET_BACK_LIGHT;

	memset(szEncData,0x00,sizeof(szEncData));
	szEncData[inEncDatalen++] = 0x00;//LCD: 0x00 
	szEncData[inEncDatalen++] = OnOff;//Turn Off: 0x00 ,Turn On: 0x01

	PCI100_PaddingData(szEncData,&inEncDatalen);
	memset(szbuf,0x00,sizeof(szbuf));
	PCI100_HEX_2_DSP(szEncData,szbuf,inEncDatalen);
	vdDebug_LogPrintf("PaddingData=[%d][%s]",inEncDatalen,szbuf);
	
	PCI100_Encrypted_Data(szEncData,inEncDatalen,&szSendBuf[inSendlen]);
	inSendlen += inEncDatalen;

	PCI100_Mac_Data(szEncData,inEncDatalen,&szSendBuf[inSendlen]);
	inSendlen += 8;

	szSendBuf[inSendlen++] = PCI100_lrc(&szSendBuf[2],5);

	PCI100_Check_DLE(szSendBuf,&inSendlen);
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_ETX;

	//inCTOSS_USBSendBuf(szSendBuf,inSendlen);
	//inCTOSS_USBHostSendBuf(szSendBuf,inSendlen);
	vdPCIDebug_HexPrintf("SetBacklight",szSendBuf,inSendlen);
	inCTOSS_RS232SendBuf(szSendBuf,inSendlen);

	memset(szRecvBuf,0x00,sizeof(szRecvBuf));
	//inCTOSS_USBRecvBuf(szRecvBuf,&inRecvlen);
	//inCTOSS_USBHostRecvBuf(szRecvBuf,&inRecvlen);
	status = inCTOSS_RS232RecvBuf(szRecvBuf,&inRecvlen,5);

	vdDebug_LogPrintf("-->>inPCI100_SetBacklight BEFORE status[%d]", status);
	
	if (status != d_OK)
		return status;
	
	PCI100_Check_DLE_R(szRecvBuf,&inRecvlen);
	vdPCIDebug_HexPrintf("SetBacklight recv",szRecvBuf,inRecvlen);

	status = szRecvBuf[2];

	vdDebug_LogPrintf("-->>inPCI100_SetBacklight AFTER status[%d]", status);
	
	return status;
}


int inPCI100_CheckBaudrate(void)
{
	int status;
	char szVersion[10];
	char szHexDSN[16+1];
	
	//check the default baudrate is ok
	memset(szVersion,0x00,sizeof(szVersion));
	memset(szHexDSN,0x00,sizeof(szHexDSN));
	status = inPCI100_GetDeviceInfo(szVersion,szHexDSN);
	vdDebug_LogPrintf("ChangeBaudrate=[%d]",status);
	
	if (status != d_OK)
	{
		inCTOSS_RS232Close();
		CTOS_Delay(200);
		inCTOSS_RS232Open(9600,'N',8,1);
	}

	return status;
}


int inPCI100_ChangeBaudrate(void)
{
	char szSendBuf[SEND_BUF+1];
	int inSendlen = 0;
	char szRecvBuf[RECV_BUF+1];
	int inRecvlen = 0;
	unsigned int inBaudrate = 115200;

	int status;

	char szbuf[SEND_BUF+1];
	char szEncData[SEND_BUF+1];
	int inEncDatalen = 0;


	vdCTOSS_SetRS232Port(strTCT.byPinPadPort);
	inCTOSS_RS232Open(p_inBaudrate,'N',8,1);

	status = inPCI100_CheckBaudrate();
	if (status == d_OK)
	{
		CTOS_Delay(200);
		inCTOSS_RS232Close();
		return d_OK;
	}

	status = inPCI100_MutualAuthenticationProcess();
	if (status != d_OK)
	{
		CTOS_Delay(200);
		inCTOSS_RS232Close();
		return status;
	}

	memset(szSendBuf,0x00,sizeof(szSendBuf));
	
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_STX;
	szSendBuf[inSendlen++] = CHANGE_BAUD;

	memset(szEncData,0x00,sizeof(szEncData));
	//memcpy(&szEncData[inEncDatalen],"\x00\x01\xC2\x00",4);
	//inEncDatalen +=4;
	memset(szbuf,0x00,sizeof(szbuf));
	sprintf(szbuf,"%08x",inBaudrate);
	PCI100_DSP_2_HEX(szbuf,szEncData,4);
	inEncDatalen +=4;

	PCI100_PaddingData(szEncData,&inEncDatalen);
	memset(szbuf,0x00,sizeof(szbuf));
	PCI100_HEX_2_DSP(szEncData,szbuf,inEncDatalen);
	vdDebug_LogPrintf("PaddingData=[%d][%s]",inEncDatalen,szbuf);
	
	PCI100_Encrypted_Data(szEncData,inEncDatalen,&szSendBuf[inSendlen]);
	inSendlen += inEncDatalen;

	PCI100_Mac_Data(szEncData,inEncDatalen,&szSendBuf[inSendlen]);
	inSendlen += 8;

	szSendBuf[inSendlen++] = PCI100_lrc(&szSendBuf[2],5);

	PCI100_Check_DLE(szSendBuf,&inSendlen);
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_ETX;

	//inCTOSS_USBSendBuf(szSendBuf,inSendlen);
	//inCTOSS_USBHostSendBuf(szSendBuf,inSendlen);
	vdPCIDebug_HexPrintf("Baudrate",szSendBuf,inSendlen);
	inCTOSS_RS232SendBuf(szSendBuf,inSendlen);

	memset(szRecvBuf,0x00,sizeof(szRecvBuf));
	//inCTOSS_USBRecvBuf(szRecvBuf,&inRecvlen);
	//inCTOSS_USBHostRecvBuf(szRecvBuf,&inRecvlen);
	status = inCTOSS_RS232RecvBuf(szRecvBuf,&inRecvlen,5);
	//if (status != d_OK)
	//	return status;
	
	PCI100_Check_DLE_R(szRecvBuf,&inRecvlen);
	vdPCIDebug_HexPrintf("Baudrate recv",szRecvBuf,inRecvlen);

	status = szRecvBuf[2];
	if (status != d_OK)
	{
		vdDisplayErrorMsg(1, 8, "Set Baudrate error");
	}
	
	inCTOSS_RS232Close();
	CTOS_Delay(200);

	
	inCTOSS_RS232Open(inBaudrate,'N',8,1);
	p_inBaudrate = inBaudrate;
	CTOS_Delay(200);
	inCTOSS_RS232Close();
	return status;
}

int inPCI100_SaveMKProcess(int MKID,int Keylen,char *szMasterKey)
{
	int status;

	status = inPCI100_ChangeBaudrate();
	if (status != d_OK)
		return status;
	
	vdCTOSS_SetRS232Port(strTCT.byPinPadPort);
	inCTOSS_RS232Open(p_inBaudrate,'N',8,1);

	status = inPCI100_SaveGeneralMK(MKID,Keylen,szMasterKey);

	inCTOSS_RS232Close();

	return status;
}


int inPCI100_SaveWKProcess(int MKID,int WKID,int Keylen,char *szEncWKey,char *szKCV)
{
	int status;

	vdCTOS_PinEntryPleaseWaitDisplay();
	
	status = inPCI100_ChangeBaudrate();

	
	if (status != d_OK)
		return status;

	
	vdCTOSS_SetRS232Port(strTCT.byPinPadPort);
	inCTOSS_RS232Open(p_inBaudrate,'N',8,1);

	vdCTOS_PinEntryPleaseWaitDisplay();
	
	status = inPCI100_SaveGeneralWK(MKID,WKID,Keylen,szEncWKey,szKCV);

	
	if (status != d_OK)
		return status;

	inCTOSS_RS232Close();

	return status;
}



int inPCI100_GetPINProcess(int WKID,int TimeOut,int MaxPINlen,int MinPINlen,int NullPIN,int PANLen,char *szPAN,char *PinBlock)
{
	char szbuf[100];
	char szHexBuf[50];
	char szKCV[10];
	int status;
	int MKID;
	int keylen;
	int inRet = d_NO;


	status = inPCI100_ChangeBaudrate();
	if (status != d_OK)
		return status;

	vdCTOSS_SetRS232Port(strTCT.byPinPadPort);
	inCTOSS_RS232Open(p_inBaudrate,'N',8,1);

	status = inPCI100_MutualAuthenticationProcess();

	vdDebug_LogPrintf("-->>[1]inPCI100_MutualAuthenticationProcess status[%d]", status);
	
	if (status != d_OK){

		//--sidumili: Re-MutualAuthenticationProcess
		status = inPCI100_MutualAuthenticationProcess();
		vdDebug_LogPrintf("-->>[2]inPCI100_MutualAuthenticationProcess status[%d]", status);

		if (status != d_OK){
			CTOS_LCDTClearDisplay();
			vdDispTransTitle(srTransRec.byTransType);
			vdDisplayErrorMsg(1, 7, "Mutual Auth Error");
			vdDisplayErrorMsg(1, 8, "Pls. Retry Trxn");
			return status;
		}
	}
	
	inPCI100_SetBacklight(0x01);
	status = inPCI100_GetPIN(WKID,TimeOut,MaxPINlen,MinPINlen,NullPIN,PANLen,szPAN,PinBlock);
	inPCI100_SetBacklight(0x00);
		
	inCTOSS_RS232Close();

	vdDebug_LogPrintf("-->>[1]inPCI100_GetPIN status[%d]:MinPINlen[%d]:MaxPINlen[%d]", status, MinPINlen, MaxPINlen);

	if (status != d_OK){
		return(d_NO);
	}
	else{
		return(d_OK);
	}
		
	#if 0
	if ((status >= MinPINlen) && (status <= MaxPINlen)){
		return(d_OK);
	}
	else{
		return(d_NO);
	}
	#endif
	
	//return status;
}

int inPCI100_GetMACProcess(int WKID,char *szICV,int Datalen,char *szData,char *MacBlock)
{
	char szbuf[100];
	char szHexBuf[50];
	char szKCV[10];
	int status;
	int MKID;
	int keylen;

	status = inPCI100_ChangeBaudrate();
	if (status != d_OK)
		return status;

	vdCTOSS_SetRS232Port(strTCT.byPinPadPort);
	inCTOSS_RS232Open(p_inBaudrate,'N',8,1);
	
	status = inPCI100_MutualAuthenticationProcess();
	if (status != d_OK)
		return status;
	
	status = inPCI100_GetMAC(WKID,szICV,Datalen,szData,MacBlock);

	inCTOSS_RS232Close();

	return status;
}

int inPCI100_DisplayMessageProcess(int PositionX,int PositionY,int Displen,char *szDispMessage)
{
	char szbuf[100];
	char szHexBuf[50];
	char szKCV[10];
	int status;
	int MKID;
	int keylen;

	if (Displen > 16 || Displen < 0)
		return d_STAT_BAD_PARAMETER;

	status = inPCI100_ChangeBaudrate();
	if (status != d_OK)
		return status;

	vdCTOSS_SetRS232Port(strTCT.byPinPadPort);
	inCTOSS_RS232Open(p_inBaudrate,'N',8,1);
	
	status = inPCI100_MutualAuthenticationProcess();
	if (status != d_OK)
		return status;

	inPCI100_SetBacklight(0x01);
	status = inPCI100_DisplayMessage(PositionX,PositionY,Displen,szDispMessage);
	inPCI100_SetBacklight(0x00);
	
	inCTOSS_RS232Close();

	return status;
}

int inPCI100_DisplayMessageProcessNoAuth(int PositionX,int PositionY,int Displen,char *szDispMessage)
{
	char szbuf[100];
	char szHexBuf[50];
	char szKCV[10];
	int status;
	int MKID;
	int keylen;

	if (Displen > 16 || Displen < 0)
		return d_STAT_BAD_PARAMETER;

	vdCTOSS_SetRS232Port(strTCT.byPinPadPort);
	inCTOSS_RS232Open(p_inBaudrate,'N',8,1);

	inPCI100_SetBacklight(0x01);
	status = inPCI100_DisplayMessage(PositionX,PositionY,Displen,szDispMessage);
	inPCI100_SetBacklight(0x00);
	
	inCTOSS_RS232Close();

	return status;
}


int inPCI100_SetIdleMessageProcess(int Displen,char *szDispMessage)
{
	char szbuf[100];
	char szHexBuf[50];
	char szKCV[10];
	int status;
	int MKID;
	int keylen;

	if (Displen > 16 || Displen < 0)
		return d_STAT_BAD_PARAMETER;

	status = inPCI100_ChangeBaudrate();
	if (status != d_OK)
		return status;

	vdCTOSS_SetRS232Port(strTCT.byPinPadPort);
	inCTOSS_RS232Open(p_inBaudrate,'N',8,1);
	
	status = inPCI100_MutualAuthenticationProcess();
	if (status != d_OK)
		return status;

	//inPCI100_SetBacklight(0x01);
	status = inPCI100_SetIdleMessage(Displen,szDispMessage);
	//inPCI100_SetBacklight(0x00);
	
	inCTOSS_RS232Close();

	return status;
}

/***********************************************************************************/
//sidumili: 
//function: to display message on PCi100
int inPCI100_GetPIN_Message(int WKID,int TimeOut,int MaxPINlen,int MinPINlen,int NullPIN,int PANLen,char *szPAN,char *szmessage1,char *szmessage2,char *szmessage3,char *PinBlock)
{
	char szSendBuf[SEND_BUF+1];
	int inSendlen = 0;
	char szRecvBuf[RECV_BUF+1];
	int inRecvlen = 0;
	char szTimeOut[2+1];
	char szPinBlock[50+1];

	char szEncData[SEND_BUF+1];
	int inEncDatalen = 0;

	char szMessData[SEND_BUF+1];
	int inMessDatalen = 0;
	int intmplen;

	char szProcMsg[SEND_BUF+1] = "\xF1\x50\x72\x6F\x63\x65\x73\x73\x69\x6E\x67\x2E\x2E\x2E";
	int inProcMsgLen = 14;
	
	int status;
	char szbuf[SEND_BUF+1];
	

	memset(szSendBuf,0x00,sizeof(szSendBuf));
	
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_STX;
	szSendBuf[inSendlen++] = GET_PIN_MSG;

	memset(szEncData,0x00,sizeof(szEncData));
	szEncData[inEncDatalen++] = WKID;

	memset(szbuf,0x00,sizeof(szbuf));
	sprintf(szbuf,"%04x",TimeOut);
	PCI100_DSP_2_HEX(szbuf,szTimeOut,2);
	memcpy(&szEncData[inEncDatalen],szTimeOut,2);
	inEncDatalen +=2;
	
	szEncData[inEncDatalen++] = MaxPINlen;
	szEncData[inEncDatalen++] = MinPINlen;
	szEncData[inEncDatalen++] = NullPIN;
	szEncData[inEncDatalen++] = 0x00;//PBType;
	szEncData[inEncDatalen++] = PANLen;
	memcpy(&szEncData[inEncDatalen],szPAN,PANLen);
	inEncDatalen +=PANLen;
	szEncData[inEncDatalen++] = 0x00;//Session Key Length

	memset(szMessData,0x00,sizeof(szMessData));
	inMessDatalen = 0;
	intmplen = strlen(szmessage1);
	if (intmplen > 0)
	{
		if (intmplen > 16)
			intmplen = 16;

		memcpy(&szMessData[inMessDatalen],szmessage1,intmplen);
		inMessDatalen += intmplen;
	}

	intmplen = strlen(szmessage2);
	if (intmplen > 0)
	{
		if (intmplen > 16)
			intmplen = 16;

		szMessData[inMessDatalen] = 0x0A;
		inMessDatalen++;
		memcpy(&szMessData[inMessDatalen],szmessage2,intmplen);
		inMessDatalen += intmplen;
	}

	intmplen = strlen(szmessage3);
	if (intmplen > 0)
	{
		if (intmplen > 16)
			intmplen = 16;

		szMessData[inMessDatalen] = 0x0A;
		inMessDatalen++;
		memcpy(&szMessData[inMessDatalen],szmessage3,intmplen);
		inMessDatalen += intmplen;
	}

	if (inMessDatalen > 0)
	{
		szEncData[inEncDatalen++] = inMessDatalen;
		memcpy(&szEncData[inEncDatalen],szMessData,inMessDatalen);
		inEncDatalen +=inMessDatalen;
	}

	szEncData[inEncDatalen++] = inProcMsgLen;
	memcpy(&szEncData[inEncDatalen],szProcMsg,inProcMsgLen);
	inEncDatalen +=inProcMsgLen;

	PCI100_PaddingData(szEncData,&inEncDatalen);
	//memset(szbuf,0x00,sizeof(szbuf));
	//PCI100_HEX_2_DSP(szEncData,szbuf,inEncDatalen);
	//vdPCIDebug_LogPrintf("PaddingData=[%d][%s]",inEncDatalen,szbuf);
	
	PCI100_Encrypted_Data(szEncData,inEncDatalen,&szSendBuf[inSendlen]);
	inSendlen += inEncDatalen;

	PCI100_Mac_Data(szEncData,inEncDatalen,&szSendBuf[inSendlen]);
	inSendlen += 8;
	
	szSendBuf[inSendlen++] = PCI100_lrc(&szSendBuf[2],inSendlen-2);

	PCI100_Check_DLE(szSendBuf,&inSendlen);
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_ETX;

	//inCTOSS_USBSendBuf(szSendBuf,inSendlen);
	//inCTOSS_USBHostSendBuf(szSendBuf,inSendlen);
	vdPCIDebug_HexPrintf("GetPIN",szSendBuf,inSendlen);
	inCTOSS_RS232SendBuf(szSendBuf,inSendlen);

	memset(szRecvBuf,0x00,sizeof(szRecvBuf));
	//inCTOSS_USBRecvBuf(szRecvBuf,&inRecvlen);
	//inCTOSS_USBHostRecvBuf(szRecvBuf,&inRecvlen);
	status = inCTOSS_RS232RecvBuf(szRecvBuf,&inRecvlen,TimeOut*2);
	if (status != d_OK)
		return status;
	
	PCI100_Check_DLE_R(szRecvBuf,&inRecvlen);
	vdPCIDebug_HexPrintf("GetPIN recv",szRecvBuf,inRecvlen);

	status = szRecvBuf[2];
	if (status != d_OK)
	{
		//vdDisplayErrorMsg(1, 8, "Get PIN error");
		CTOS_LCDTClearDisplay();
		vdDispTransTitle(srTransRec.byTransType);
		vdDisplayErrorMsg(1, 8, "USER CANCEL");
		return d_ERROR;
	}
	else
	{
		memset(szbuf,0x00,sizeof(szbuf));
		memset(szPinBlock,0x00,sizeof(szPinBlock));
		PCI100_Decode_Data(&szRecvBuf[3],16,szPinBlock);
		vdPCIDebug_HexPrintf("szPinBlock",szPinBlock,16);
		
		PCI100_Mac_Data(szPinBlock,16,szbuf);
		//vdPCIDebug_HexPrintf("MAC",szbuf,8);
		if (memcmp(szbuf,&szRecvBuf[19],8) == 0)
		{
			//vdDisplayErrorMsg(1, 8, "Get PIN OK");
			status = szPinBlock[0];
			memcpy(PinBlock,&szPinBlock[1],8);	
			status = d_OK; // sidumili: [added]
		}
	}

	return status;
}

/***********************************************************************************/

/***********************************************************************************/
//sidumili
int inPCI100_GetPIN_MessageProcess(int WKID,int TimeOut,int MaxPINlen,int MinPINlen,int NullPIN,int PANLen,char *szPAN,char *szmessage1,char *szmessage2,char *szmessage3,char *PinBlock)
{
	char szbuf[100];
	char szHexBuf[50];
	char szKCV[10];
	int status;
	int MKID;
	int keylen;
	USHORT ret;

	status = inPCI100_ChangeBaudrate();
	if (status != d_OK)
		return status;

	vdCTOSS_SetRS232Port(strTCT.byPinPadPort);
	inCTOSS_RS232Open(p_inBaudrate,'N',8,1);

	status = inPCI100_MutualAuthenticationProcess();
	//if (status != d_OK)
	//	return status;

	if (status != d_OK){

		CTOS_Delay(200);
		inCTOSS_RS232Close();

		//--sidumili: Re-MutualAuthenticationProcess
		vdCTOSS_SetRS232Port(strTCT.byPinPadPort);
		inCTOSS_RS232Open(p_inBaudrate,'N',8,1);
	
		status = inPCI100_MutualAuthenticationProcess();
		
		if (status != d_OK){
			CTOS_LCDTClearDisplay();
			vdDispTransTitle(srTransRec.byTransType);
			vdDisplayErrorMsg(1, 7, "Mutual Auth Error");
			vdDisplayErrorMsg(1, 8, "Pls. Retry Trxn");

			CTOS_Delay(200);
			inCTOSS_RS232Close();
			
			return(d_NO);
		}
	}

	inPCI100_SetBacklight(0x01);
	status = inPCI100_GetPIN_Message(WKID,TimeOut,MaxPINlen,MinPINlen,NullPIN,PANLen,szPAN,szmessage1,szmessage2,szmessage3,PinBlock);
	inPCI100_SetBacklight(0x00);

	CTOS_Delay(200);	
	inCTOSS_RS232Close();

	//sidumili: [START]
	if (status != d_OK){
		return(d_NO);
	}
	else{
		return(d_OK);
	}
	//sidumili: [END]

	return status;
}

/***********************************************************************************/

/***********************************************************************************/
int inPCI100_CheckMK(int MKid)
{
	char szSendBuf[SEND_BUF+1];
	int inSendlen = 0;
	char szRecvBuf[RECV_BUF+1];
	int inRecvlen = 0;
	char szTimeOut[2+1];

	char szEncData[SEND_BUF+1];
	int inEncDatalen = 0;
	
	int status;
	char szbuf[SEND_BUF+1];
	

	memset(szSendBuf,0x00,sizeof(szSendBuf));
	
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_STX;
	szSendBuf[inSendlen++] = MK_TYPE_FLAG;

	memset(szEncData,0x00,sizeof(szEncData));
	szEncData[inEncDatalen++] = MKid;

	PCI100_PaddingData(szEncData,&inEncDatalen);
	
	PCI100_Encrypted_Data(szEncData,inEncDatalen,&szSendBuf[inSendlen]);
	inSendlen += inEncDatalen;

	PCI100_Mac_Data(szEncData,inEncDatalen,&szSendBuf[inSendlen]);
	inSendlen += 8;
	
	szSendBuf[inSendlen++] = PCI100_lrc(&szSendBuf[2],inSendlen-2);

	PCI100_Check_DLE(szSendBuf,&inSendlen);
	szSendBuf[inSendlen++] = PCI100_DLE;
	szSendBuf[inSendlen++] = PCI100_ETX;

	//inCTOSS_USBSendBuf(szSendBuf,inSendlen);
	//inCTOSS_USBHostSendBuf(szSendBuf,inSendlen);
	vdPCIDebug_HexPrintf("CheckMK",szSendBuf,inSendlen);
	inCTOSS_RS232SendBuf(szSendBuf,inSendlen);

	memset(szRecvBuf,0x00,sizeof(szRecvBuf));
	//inCTOSS_USBRecvBuf(szRecvBuf,&inRecvlen);
	//inCTOSS_USBHostRecvBuf(szRecvBuf,&inRecvlen);
	status = inCTOSS_RS232RecvBuf(szRecvBuf,&inRecvlen,5);

	vdDebug_LogPrintf("-->>inCTOSS_RS232RecvBuf status[%d]", status);
	
	if (status != d_OK)
		return status;
	
	PCI100_Check_DLE_R(szRecvBuf,&inRecvlen);
	vdPCIDebug_HexPrintf("CheckMK recv",szRecvBuf,inRecvlen);

	status = szRecvBuf[2];

	//vdPrintPCIDebug_HexPrintf(TRUE, "inPCI100_CheckMK", szRecvBuf, inRecvlen);
	vdDebug_LogPrintf("-->>inPCI100_CheckMK status[%d]", status);
	
	if (status == d_STAT_MK_NOT_LOAD)
	{	
		CTOS_LCDTClearDisplay();
		vdDispTransTitle(srTransRec.byTransType);
		
		//vdDisplayErrorMsg(1, 8, "Key is not loaded");
		vdDisplayErrorMsg(1, 8, "Please Inject Key");
	}
	return status;
}

/***********************************************************************************/

/***********************************************************************************/
int inPCI100_CheckMKType_Flag(int MKid)
{
	char szbuf[100];
	char szHexBuf[50];
	char szKCV[10];
	int status;
	int MKID;
	int keylen;

	status = inPCI100_ChangeBaudrate();
	if (status != d_OK)
		return status;

	vdCTOSS_SetRS232Port(strTCT.byPinPadPort);
	inCTOSS_RS232Open(p_inBaudrate,'N',8,1);
	
	status = inPCI100_MutualAuthenticationProcess();
	
	if (status != d_OK){

	CTOS_Delay(200);
	inCTOSS_RS232Close();

	//--sidumili: Re-MutualAuthenticationProcess
	vdCTOSS_SetRS232Port(strTCT.byPinPadPort);
	inCTOSS_RS232Open(p_inBaudrate,'N',8,1);

	status = inPCI100_MutualAuthenticationProcess();

		if (status != d_OK){
			CTOS_LCDTClearDisplay();
			vdDispTransTitle(srTransRec.byTransType);
			vdDisplayErrorMsg(1, 7, "Mutual Auth Error");
			vdDisplayErrorMsg(1, 8, "Pls. Retry Trxn");

			CTOS_Delay(200);
			inCTOSS_RS232Close();
			
			return(d_NO);
		}
	}

	status = inPCI100_CheckMK(MKid);
	
	inCTOSS_RS232Close();

	return status;
}

/***********************************************************************************/
