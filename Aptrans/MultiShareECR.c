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

#include "..\ApTrans\MultiShareECR.h"
#include "..\Includes\MultiApLib.h"

USHORT usCTOSS_ECRInitialize(void)
{
    BYTE bInBuf[40];
    BYTE bOutBuf[40];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;
	char szAPName[25];
	int inAPPID;
	
	memset(bOutBuf,0x00,sizeof(bOutBuf));
	memset(szAPName,0x00,sizeof(szAPName));
	inMultiAP_CurrentAPNamePID(szAPName, &inAPPID);
    memset(bOutBuf, 0x00, sizeof(bOutBuf));    
	strcpy(bInBuf, szAPName);
	usInLen = strlen(szAPName);

    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_ECR", d_IPC_CMD_ECR_Initialize, bInBuf, usInLen, bOutBuf, &usOutLen);
    vdDebug_LogPrintf("**usCTOSS_ECRInitialize [%d]**", usResult);
    if(d_OK == usResult)
    {
        //status
/*
        ptr = ptCTOSS_FindTagAddr(SHARE_EMV_RESP_STATU, bOutBuf, usOutLen);
        if (NULL == ptr)
        {
            usResult = d_NO;
        }
        else
        {
            usResult = ptr[SHARE_EMV_DEFINE_TAGS_LEN+SHARE_EMV_DEFINE_LEN];
        }
*/
    }
    
    return usResult;
}

USHORT usCTOSS_ECR_MultiDataGet(IN BYTE *pTagString, INOUT USHORT *pLen, OUT BYTE *pValue)
{
    BYTE bTagStringHex[256];
    BYTE bInBuf[256];
    BYTE bOutBuf[2048];
    BYTE *ptr = NULL;
    USHORT usTagStringLen = 0;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;
    USHORT usDataLen = 0;

    inMultiAP_Database_EMVTransferDataInit();

    usTagStringLen = strlen(pTagString);
    wub_str_2_hex(pTagString, bTagStringHex, usTagStringLen);

    usInLen = 0;
    memset(bInBuf, 0x00, sizeof(bInBuf));
    //TagString
/*
    usInLen += usCTOSS_PackTagLenValue(&bInBuf[usInLen], SHARE_EMV_GET_MULTI_TAG, usTagStringLen, bTagStringHex);
    
    memset(bOutBuf, 0x00, sizeof(bOutBuf));    
    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_ECR", d_IPC_CMD_ECR_GetPackageData, bInBuf, usInLen, bOutBuf, &usOutLen);
*/
     if(d_OK == usResult)
    {
        //status
/*        
        ptr = ptCTOSS_FindTagAddr(SHARE_EMV_RESP_STATU, bOutBuf, usOutLen);
        if(NULL == ptr)
        {
            usResult = d_NO;
        }
        else
        {
            usResult = ptr[SHARE_EMV_DEFINE_TAGS_LEN+SHARE_EMV_DEFINE_LEN];

            //pValue
            inMultiAP_Database_EMVTransferDataRead(&usDataLen, pValue);
            *pLen =  usDataLen; 
        }
*/
    }

    return usResult;
}

USHORT usCTOSS_ECR_MultiDataSet(IN USHORT usLen, IN BYTE *pValue)
{
    BYTE bInBuf[2048];
    BYTE bOutBuf[64];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult = 0;

    inMultiAP_Database_EMVTransferDataInit();
    
    usInLen = 0;
    memset(bInBuf, 0x00, sizeof(bInBuf));
    //Tags TLV data
    inMultiAP_Database_EMVTransferDataWrite(usLen, pValue);

    memset(bOutBuf, 0x00, sizeof(bOutBuf));    
    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_ECR", d_IPC_CMD_ECR_SetPackageData, bInBuf, usInLen, bOutBuf, &usOutLen);
    if(d_OK == usResult)
    {
        //status
/*        
        ptr = ptCTOSS_FindTagAddr(SHARE_EMV_RESP_STATU, bOutBuf, usOutLen);
        if(NULL == ptr)
        {
            usResult = d_NO;
        }
        else
        {
            usResult = ptr[SHARE_EMV_DEFINE_TAGS_LEN+SHARE_EMV_DEFINE_LEN];
        }
*/        
    }

    return usResult;
}

