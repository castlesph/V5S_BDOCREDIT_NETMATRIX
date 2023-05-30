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
#include "..\Includes\postrans.h"

#include "..\Debug\Debug.h"

#include "MultiShareEMV.h"


#define EMV_DATA_POOL_MAX   2048
static BYTE szEMVDataPool[2048];
static USHORT usEMVDataTotalLen;

/* ==========================================================================
 * FUNCTION NAME: TermDataGet
 * DESCRIPTION:               
 * RETURN:        
 * ========================================================================== */   
short usCTOSS_GetEMVDataPoolTagData(USHORT usTag, BYTE *buf)
{
    USHORT i, usLen;
    BYTE byTag[2];
	
    byTag[0] = (BYTE)(usTag / 256);
    byTag[1] = (BYTE)(usTag % 256);
	
    i = 0;
 
    while (i < usEMVDataTotalLen)
    {
        usLen = szEMVDataPool[i + 2] * 256 + szEMVDataPool[i + 3];
        if (szEMVDataPool[i] == byTag[0] && szEMVDataPool[i + 1] == byTag[1])
        {
            wub_memcpy(buf, &szEMVDataPool[i + 4], usLen);
            return usLen;
        }
        i += 4 + usLen;
    }
	
    return 0;
}

/***************
 *
 *Remove the data from the terminal
 *[in] tag
 *
 **************/
void vdCTOSS_EMVDataPoolTagRemove(WORD tag)
{
    BYTE byTag[2];
    USHORT i, j, len;

    i = j = 0;

    byTag[0] = (BYTE)(tag / 256);
    byTag[1] = (BYTE)(tag % 256);
    while (i < usEMVDataTotalLen)
    {
        len = 4 + szEMVDataPool[i + 2] * 256 + szEMVDataPool[i + 3];
        if (byTag[0] == szEMVDataPool[i] && byTag[1] == szEMVDataPool[i + 1])
        {
            i += len;
            continue;
        } else
        {
            wub_memcpy(&szEMVDataPool[j], &szEMVDataPool[i], len);
            i += len;
            j += len;
        }
    }

    usEMVDataTotalLen = j;
}

/* ==========================================================================
 * FUNCTION NAME: ShowAPList
 * DESCRIPTION: Add tag data to EMV data global pool 
 * RETURN:        
 * ========================================================================== */
USHORT usCTOSS_AddOrUpdateTagToEMVDataPool(USHORT usTag, USHORT usLen, BYTE *ucValue)
{
    USHORT i, usTmpLen;
    BYTE byTag[2],key;
    
    
    byTag[0] = (BYTE)(usTag / 256);
    byTag[1] = (BYTE)(usTag % 256);

    i = 0;
    while (i < usEMVDataTotalLen)
    {
        usTmpLen = szEMVDataPool[i + 2] * 256 + szEMVDataPool[i + 3];
        if (szEMVDataPool[i] == byTag[0] && szEMVDataPool[i + 1] == byTag[1])
        {
            if (usTmpLen == usLen)
            {
                wub_memcpy(&szEMVDataPool[i + 4], ucValue, usLen);
                return d_OK;
            }
            else
                vdCTOSS_EMVDataPoolTagRemove(usTag);
        }
        i += 4 + usTmpLen;
    }
    
    //Add new
    if (usEMVDataTotalLen + 2 + 2 + usLen >= EMV_DATA_POOL_MAX)
    {
        return EMV_POOL_FULL;
    }
    
    szEMVDataPool[usEMVDataTotalLen ++] = (BYTE)(usTag / 256);
    szEMVDataPool[usEMVDataTotalLen ++] = (BYTE)(usTag % 256);
    szEMVDataPool[usEMVDataTotalLen ++] = (BYTE)(usLen / 256);
    szEMVDataPool[usEMVDataTotalLen ++] = (BYTE)(usLen % 256);
    wub_memcpy(&szEMVDataPool[usEMVDataTotalLen], ucValue, usLen);
    usEMVDataTotalLen += usLen;
    return d_OK;
}

/*
USHORT usCTOSS_FindTagFromDataPackage(USHORT tag, BYTE *value, USHORT *length, const BYTE *buffer, USHORT bufferlen)
{
    BYTE *ptr = NULL;
    BYTE bTagBuf[4];
    USHORT bufLen;
    USHORT len = 0;
    USHORT bytesRead;
    USHORT usTagLen;
    
    if ((tag & 0x1F00) == 0x1F00)
    {
        usTagLen = 2;
        bTagBuf[0] = tag >> 8;
        bTagBuf[1] = tag & 0x00FF;
    }
    else
    {
        usTagLen = 1;
        bTagBuf[0] = tag;
    }
    
    *length = len;
    
    ptr = (BYTE *) & buffer[0];
    bufLen = bufferlen;

    bytesRead = 0;

    while(bytesRead < bufLen)
    {
        if(0 == memcmp(bTagBuf, &ptr[bytesRead], usTagLen))
        {
            bytesRead += usTagLen;
            len = ptr[bytesRead++];
            memcpy(value, &ptr[bytesRead], len);
            *length = len;

            break;
        }
        else
        {   
            if ((ptr[bytesRead] & 0x1F) == 0x1F)
                bytesRead += 2;
            else
                bytesRead ++;
            len = ptr[bytesRead++];
            bytesRead += len;
        }
     
    }
    
    if(*length > 0)
        return d_OK;

    return d_NO;
}
*/
USHORT usCTOSS_FindTagFromDataPackage(unsigned int tag, BYTE *value, USHORT *length, const BYTE *buffer, USHORT bufferlen)
{
    BYTE *ptr = NULL;
    BYTE bTagBuf[4];
    USHORT bufLen;
    USHORT len = 0;
    USHORT bytesRead;
    USHORT usTagLen;

	if ((tag & 0xDF8000) == 0xDF8000)
	{
		usTagLen = 3;
		bTagBuf[0] = tag >> 16;
		bTagBuf[1] = tag >> 8;
		bTagBuf[2] = tag & 0x0000FF;
	}
    //else if ((tag & 0x9F00) == 0x9F00)
    else if ((tag & 0x1F00) == 0x1F00)
    {
        usTagLen = 2;
        bTagBuf[0] = tag >> 8;
        bTagBuf[1] = tag & 0x00FF;
    }
    else
    {
        usTagLen = 1;
        bTagBuf[0] = tag;
    }
    
    *length = len;
    
    ptr = (BYTE *) & buffer[0];
    bufLen = bufferlen;

    bytesRead = 0;

    while(bytesRead < bufLen)
    {
        if(0 == memcmp(bTagBuf, &ptr[bytesRead], usTagLen))
        {
            bytesRead += usTagLen;
            len = ptr[bytesRead++];
            memcpy(value, &ptr[bytesRead], len);
            *length = len;

            break;
        }
        else
        {   
            if (((ptr[bytesRead] & 0xDF) == 0xDF) && ((ptr[bytesRead+1] & 0x80) == 0x80))
                bytesRead += 3;
//            else if ((ptr[bytesRead] & 0x9F) == 0x9F)
			else if ((ptr[bytesRead] & 0x1F) == 0x1F)
                bytesRead += 2;
            else
                bytesRead ++;
            len = ptr[bytesRead++];
            bytesRead += len;
        }
     
    }
    
    if(*length > 0)
        return d_OK;

    return d_NO;
}

BYTE* ptCTOSS_FindTagAddr(BYTE *bFindTag, BYTE *bInString, USHORT usInStringLen)
{
    BYTE bBuf[5];
    USHORT usOffset = 0;
    
    while(1)
    {
        if(0 == memcmp(bFindTag, &bInString[usOffset], SHARE_EMV_DEFINE_TAGS_LEN))
        {
            return &bInString[usOffset];
        }
        else
        {
            usOffset += SHARE_EMV_DEFINE_TAGS_LEN;
            memcpy(bBuf, &bInString[usOffset], SHARE_EMV_DEFINE_LEN);
            usOffset += SHARE_EMV_DEFINE_LEN;

            bBuf[SHARE_EMV_DEFINE_LEN] = 0x00;
            usOffset += atoi(bBuf);
        }

        if(usOffset >= usInStringLen)
        {
            return NULL;
        }
    }
}

USHORT usCTOSS_PackTagLenValue(BYTE *bDataBuf, BYTE *bTag, USHORT usTagValueLen, BYTE *bTagValue)
{
    BYTE bBuf[8];
    USHORT usInLen = 0;
    
    memcpy(bDataBuf, bTag, SHARE_EMV_DEFINE_TAGS_LEN);
    usInLen = SHARE_EMV_DEFINE_TAGS_LEN;

    memset(bBuf, 0x00, sizeof(bBuf));
    sprintf(bBuf, "%03d", usTagValueLen);
    memcpy(&bDataBuf[usInLen], bBuf, SHARE_EMV_DEFINE_LEN);
    usInLen += SHARE_EMV_DEFINE_LEN;

    memcpy(&bDataBuf[usInLen], bTagValue, usTagValueLen);
    usInLen += usTagValueLen;

    return usInLen;
}

USHORT usCTOSS_GetTagLenValue(BYTE *bDataBuf, USHORT usDataBufLen, BYTE *bTag, USHORT *usTagValueLen, BYTE *bTagValue)
{
    BYTE bBuf[8];
    BYTE *ptr = NULL;
    USHORT usDataLen = 0;

    ptr = ptCTOSS_FindTagAddr(bTag, bDataBuf, usDataBufLen);
    if(NULL == ptr)
    {
        *usTagValueLen = usDataLen;
        return usDataLen;
    }
    else
    {
        memcpy(bBuf, ptr+SHARE_EMV_DEFINE_TAGS_LEN, SHARE_EMV_DEFINE_LEN);
        bBuf[SHARE_EMV_DEFINE_LEN] = 0x00;
        usDataLen = atoi(bBuf);

        memcpy(bTagValue, ptr+SHARE_EMV_DEFINE_TAGS_LEN+SHARE_EMV_DEFINE_LEN, usDataLen);
        *usTagValueLen = usDataLen;
    }

    return usDataLen;
}



USHORT usCTOSS_GetCardPresent(void)
{
    BYTE bInBuf[40];
    BYTE bOutBuf[40];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;

    memset(bOutBuf, 0x00, sizeof(bOutBuf));    
    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_EMV", d_IPC_CMD_GetCardPresent, bInBuf, usInLen, bOutBuf, &usOutLen);
    if(d_OK == usResult)
    {
        //status
        ptr = ptCTOSS_FindTagAddr(SHARE_EMV_RESP_STATU, bOutBuf, usOutLen);
        if(NULL == ptr)
        {
            usResult = FALSE;
        }
        else
        {
            usResult = ptr[SHARE_EMV_DEFINE_TAGS_LEN+SHARE_EMV_DEFINE_LEN];
        }
    }
    else
    {
        usResult = FALSE;
    }

    return usResult;
}

USHORT usCTOSS_EMVInitialize(void)
{
    BYTE bInBuf[40];
    BYTE bOutBuf[40];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;

    memset(bOutBuf, 0x00, sizeof(bOutBuf));    
    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_EMV", d_IPC_CMD_EMV_Initialize, bInBuf, usInLen, bOutBuf, &usOutLen);
    if(d_OK == usResult)
    {
        //status
        ptr = ptCTOSS_FindTagAddr(SHARE_EMV_RESP_STATU, bOutBuf, usOutLen);
        if(NULL == ptr)
        {
            usResult = d_NO;
        }
        else
        {
            usResult = ptr[SHARE_EMV_DEFINE_TAGS_LEN+SHARE_EMV_DEFINE_LEN];
        }
    }
    
    return usResult;
}


USHORT usCTOSS_EMV_TxnAppSelect(IN BYTE* pPreferAID, IN USHORT usPreferAIDLen, OUT BYTE* pSelectedAID, OUT USHORT* pSelectedAIDLen, OUT BYTE *pSelectedAppLabel, OUT USHORT *pSelectedAppLabelLen)
{
	BYTE bTagStringHex[256];
    BYTE bInBuf[512];
		BYTE bIntmpBuf[512];
    BYTE bOutBuf[2048];
    BYTE *ptr = NULL;
    USHORT usTagStringLen = 0;
    USHORT usInLen = 0,ustmpInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;
    USHORT usDataLen = 0;
	USHORT usFallback = 0;

    usInLen = 0;
    memset(bInBuf, 0x00, sizeof(bInBuf));
		ustmpInLen = 0;
    memset(bIntmpBuf, 0x00, sizeof(bIntmpBuf));
    //Prefer AID
    usInLen += usCTOSS_PackTagLenValue(&bInBuf[usInLen], SHARE_EMV_PREFER_AID, usPreferAIDLen, pPreferAID);
		memcpy(bIntmpBuf,bInBuf,usInLen);
		ustmpInLen = usInLen;

		
    usTagStringLen = strlen(GET_EMV_TAG_AFTER_SELECT_APP);
    wub_str_2_hex(GET_EMV_TAG_AFTER_SELECT_APP, bTagStringHex, usTagStringLen);
    usInLen = 0;
    memset(bInBuf, 0x00, sizeof(bInBuf));
    //TagString
    usInLen += usCTOSS_PackTagLenValue(&bInBuf[usInLen], SHARE_EMV_GET_MULTI_TAG, usTagStringLen, bTagStringHex);
		memcpy(&bIntmpBuf[ustmpInLen],bInBuf,usInLen);
		ustmpInLen += usInLen;

		vdPCIDebug_HexPrintf("TxnAppSelect",bIntmpBuf,ustmpInLen);
    memset(bOutBuf, 0x00, sizeof(bOutBuf));    
    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_EMV", d_IPC_CMD_EMV_App_SelectEx, bIntmpBuf, ustmpInLen, bOutBuf, &usOutLen);
    if(d_OK == usResult)
    {
        //status
        ptr = ptCTOSS_FindTagAddr(SHARE_EMV_RESP_STATU, bOutBuf, usOutLen);
        if(NULL == ptr)
        {
            usResult = d_NO;
        }
        else
        {
            usResult = ptr[SHARE_EMV_DEFINE_TAGS_LEN+SHARE_EMV_DEFINE_LEN];
            vdDebug_LogPrintf("pSelectedAID usResult[%d]", usResult);
			if(usResult != 0)
			{
				//VISA: Testcase 29 - should display "CARD BLOCKED" instead of doing fallback - start -- jzg
				if (usResult == 12) //JCB: If application is blocked deny the transaction -- jzg
				{
					vdDebug_LogPrintf("card blocked usResult[%d]", usResult);
					return EMV_CARD_BLOCKED;
				}
				//VISA: Testcase 29 - should display "CARD BLOCKED" instead of doing fallback - end -- jzg

				//EMV: If AID not found display "TRANS NOT ALLOWED" - start -- jzg
				if (usResult == 2)
				{
					vdDebug_LogPrintf("trans not allowed usResult[%d]", usResult);
					return EMV_TRANS_NOT_ALLOWED;
				}
				//EMV: If AID not found display "TRANS NOT ALLOWED" - end -- jzg
				
				usFallback = ptr[SHARE_EMV_DEFINE_TAGS_LEN+SHARE_EMV_DEFINE_LEN + 1];
				if(usFallback == 1)//fallback
				{
					vdDebug_LogPrintf("fallback usResult[%d]", usResult);
					return EMV_FALLBACK;
					
				}
				
				vdDebug_LogPrintf("return, fallback usResult[%d]", usResult);
			}
            else
            {
                //pSelectedAID
                usCTOSS_GetTagLenValue(bOutBuf, usOutLen, SHARE_EMV_SELECTED_AID, &usDataLen, pSelectedAID);
                *pSelectedAIDLen =  usDataLen; 
                
                //pSelectedAppLabel
                usCTOSS_GetTagLenValue(bOutBuf, usOutLen, SHARE_EMV_SELECTED_APP_LAB, &usDataLen, pSelectedAppLabel);
                *pSelectedAppLabelLen =  usDataLen; 
            }
        }
    }
    
    return usResult;
}


USHORT usCTOSS_EMV_TxnPerform(void)
{
    BYTE bTagStringHex[256];
    BYTE bInBuf[512];
    BYTE bOutBuf[2048];
    BYTE *ptr = NULL;
    USHORT usTagStringLen = 0;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult,ustmpResult;
    USHORT usDataLen = 0;

		usTagStringLen = strlen(GET_EMV_TAG_AFTER_1STAC);
    wub_str_2_hex(GET_EMV_TAG_AFTER_1STAC, bTagStringHex, usTagStringLen);

    usInLen = 0;
    memset(bInBuf, 0x00, sizeof(bInBuf));
    //TagString
    usInLen += usCTOSS_PackTagLenValue(&bInBuf[usInLen], SHARE_EMV_GET_MULTI_TAG, usTagStringLen, bTagStringHex);

    memset(bOutBuf, 0x00, sizeof(bOutBuf));    

	//test
	vdDebug_LogPrintf("usCTOSS_EMV_TxnPerform start");
    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_EMV", d_IPC_CMD_EMV_Txn_PerformEx, bInBuf, usInLen, bOutBuf, &usOutLen);
	//usResult = inMultiAP_RunIPCCmdTypesEx("SHARLS_EMV", d_IPC_CMD_EMV_Txn_PerformEx, bInBuf, usInLen, bOutBuf, &usOutLen);
	vdDebug_LogPrintf("usCTOSS_EMV_TxnPerform end %s",bOutBuf);

    //test
    if(d_OK == usResult)
    {
        //status    
		if (memcmp(bOutBuf,SHARE_EMV_SUB_IPC,3) == 0)
		{
			if (memcmp(&bOutBuf[3],SHARE_EMV_ONLINEPIN,1) == 0)
			{
				usResult = inGetIPPPin();
				CTOS_LCDTClearDisplay();// clear the PIN entry screen.
				if(usResult != d_NO && usResult != d_KMS2_GET_PIN_ABORT)
					vdDispTitleAndCardProcessing();					
				
				vdDebug_LogPrintf("usResult=[%d],usResult=[%x]",usResult,usResult);

				/* CUP: set srTransRec.fEMVPIN if PIN Bypass - start -- jzg */
				if (usResult == d_KMS2_GET_PIN_NULL_PIN)
					srTransRec.fEMVPIN = FALSE;
				else
					srTransRec.fEMVPIN = TRUE;
				/* CUP: set srTransRec.fEMVPIN if PIN Bypass - end -- jzg */
				
				usInLen = 0;
    			memset(bInBuf, 0x00, sizeof(bInBuf));
				strcpy(bInBuf,SHARE_EMV_SUB_IPC);
				strcat(bInBuf,SHARE_EMV_ONLINEPIN);
				usInLen = strlen(bInBuf);
				bInBuf[usInLen] = (unsigned char)(usResult		& 0xFF);
		   		bInBuf[usInLen+1] = (unsigned char)(usResult >>  8 & 0xFF);
				usInLen += 2;
				vdDebug_LogPrintf("usInLen=[%d],str=[%s]",usInLen,bInBuf);

				memset(bOutBuf, 0x00, sizeof(bOutBuf));    
    			usResult = inMultiAP_RunIPCCmdTypes("SHARLS_EMV", d_IPC_CMD_EMV_Txn_PerformEx, bInBuf, usInLen, bOutBuf, &usOutLen);

				if(d_OK != usResult)
					return usResult;
			}
		}
        ptr = ptCTOSS_FindTagAddr(SHARE_EMV_RESP_STATU, bOutBuf, usOutLen);
        if(NULL == ptr)
        {
            usResult = d_NO;
        }
        else
        {
            usResult = ptr[SHARE_EMV_DEFINE_TAGS_LEN+SHARE_EMV_DEFINE_LEN];
			vdDebug_LogPrintf("ptr[%d]",usResult);
        }

		ustmpResult=0;
		//full status
		usCTOSS_GetTagLenValue(bOutBuf, usOutLen, SHARE_EMV_FULL_RESP_STATUS, &usDataLen, &ustmpResult);
        vdDebug_LogPrintf("ustmpResult=[%d]",ustmpResult);
		if(ustmpResult==10512 || ustmpResult==10511)//for PIN TIMEOUT and PIN CANCEL
		{
			vdSetErrorMessage("ABORTED");
		}
    }
    
    return usResult;
}

USHORT usCTOSS_EMV_PowerOffICC()
{
	BYTE bInBuf[40];
	BYTE bOutBuf[40];
	BYTE *ptr = NULL;
	USHORT usInLen = 0;
	USHORT usOutLen = 0;
	USHORT usResult;

	memset(bOutBuf, 0x00, sizeof(bOutBuf));    
	usResult = inMultiAP_RunIPCCmdTypes("SHARLS_EMV", d_IPC_CMD_EMV_PowerOffICC, bInBuf, usInLen, bOutBuf, &usOutLen);
	if(d_OK == usResult)
	{
		//status
		ptr = ptCTOSS_FindTagAddr(SHARE_EMV_RESP_STATU, bOutBuf, usOutLen);
		if(NULL == ptr)
		{
			usResult = d_NO;
		}
		else
		{
			usResult = ptr[SHARE_EMV_DEFINE_TAGS_LEN+SHARE_EMV_DEFINE_LEN];
		}
	}
	
	return usResult;
}


USHORT usCTOSS_EMV_PowerOnICC()
{
	BYTE bInBuf[40];
	BYTE bOutBuf[40];
	BYTE *ptr = NULL;
	USHORT usInLen = 0;
	USHORT usOutLen = 0;
	USHORT usResult;

	memset(bOutBuf, 0x00, sizeof(bOutBuf));    
	usResult = inMultiAP_RunIPCCmdTypes("SHARLS_EMV", d_IPC_CMD_EMV_PowerOnICC, bInBuf, usInLen, bOutBuf, &usOutLen);
	if(d_OK == usResult)
	{
		//status
		ptr = ptCTOSS_FindTagAddr(SHARE_EMV_RESP_STATU, bOutBuf, usOutLen);
		if(NULL == ptr)
		{
			usResult = d_NO;
		}
		else
		{
			usResult = ptr[SHARE_EMV_DEFINE_TAGS_LEN+SHARE_EMV_DEFINE_LEN];
		}
	}
	
	return usResult;
}

USHORT usCTOSS_EMV_TxnCompletion(IN EMV_ONLINE_RESPONSE_DATA* pOnlineResponseData)
{
    BYTE bInBuf[1024];
    BYTE bOutBuf[512];
    BYTE bBuf[10];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;
		BYTE bIntmpBuf[1024];
		USHORT ustmpInLen = 0;
		BYTE bTagStringHex[256];
		USHORT usTagStringLen = 0;

    usInLen = 0;
    memset(bInBuf, 0x00, sizeof(bInBuf));
    //EMV_ONLINE_RESPONSE_DATA
    //bAction
    usInLen += usCTOSS_PackTagLenValue(&bInBuf[usInLen], SHARE_EMV_2ND_GEN_AC_ACTION, 1, (BYTE*)&(pOnlineResponseData->bAction));

    //pAuthorizationCode
    usInLen += usCTOSS_PackTagLenValue(&bInBuf[usInLen], SHARE_EMV_8A_RESP_CODE, strlen(pOnlineResponseData->pAuthorizationCode), (BYTE*)(pOnlineResponseData->pAuthorizationCode));

    //pIssuerAuthenticationData
    if(pOnlineResponseData->IssuerAuthenticationDataLen > 0)
    {
        usInLen += usCTOSS_PackTagLenValue(&bInBuf[usInLen], SHARE_EMV_ARPC, (pOnlineResponseData->IssuerAuthenticationDataLen), (BYTE*)(pOnlineResponseData->pIssuerAuthenticationData));
    }

    //pIssuerScript
    if(pOnlineResponseData->IssuerScriptLen > 0)
    {
        usInLen += usCTOSS_PackTagLenValue(&bInBuf[usInLen], SHARE_EMV_ISSUE_SCRIPT, (pOnlineResponseData->IssuerScriptLen), (BYTE*)(pOnlineResponseData->pIssuerScript));
    }
		memcpy(bIntmpBuf,bInBuf,usInLen);
		ustmpInLen = usInLen;

		
    usTagStringLen = strlen(GET_EMV_TAG_AFTER_2NDAC);
    wub_str_2_hex(GET_EMV_TAG_AFTER_2NDAC, bTagStringHex, usTagStringLen);

    usInLen = 0;
    memset(bInBuf, 0x00, sizeof(bInBuf));
    //TagString
    usInLen += usCTOSS_PackTagLenValue(&bInBuf[usInLen], SHARE_EMV_GET_MULTI_TAG, usTagStringLen, bTagStringHex);

		memcpy(&bIntmpBuf[ustmpInLen],bInBuf,usInLen);
		ustmpInLen += usInLen;
		vdPCIDebug_HexPrintf("TxnAppSelect",bIntmpBuf,ustmpInLen);

    memset(bOutBuf, 0x00, sizeof(bOutBuf));    
    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_EMV", d_IPC_CMD_EMV_Txn_CompletionEx, bIntmpBuf, ustmpInLen, bOutBuf, &usOutLen);
    if(d_OK == usResult)
    {
        //status
        ptr = ptCTOSS_FindTagAddr(SHARE_EMV_RESP_STATU, bOutBuf, usOutLen);
        if(NULL == ptr)
        {
            usResult = d_NO;
        }
        else
        {
            usResult = ptr[SHARE_EMV_DEFINE_TAGS_LEN+SHARE_EMV_DEFINE_LEN];
        }
    }
    
    return usResult;
}


USHORT usCTOSS_EMV_DataGet(IN USHORT usTag, INOUT USHORT *pLen, OUT BYTE *pValue)
{
    BYTE bInBuf[256];
    BYTE bOutBuf[256];
    BYTE bBuf[10];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;
    USHORT usTagLocal;
    USHORT usDataLen = 0;

    usInLen = 0;
    memset(bInBuf, 0x00, sizeof(bInBuf));
    //usTag
    memset(bBuf, 0x00, sizeof(bBuf));
    usTagLocal = usTag;
    memcpy(bBuf, (BYTE*)&usTagLocal, sizeof(USHORT));
    usInLen += usCTOSS_PackTagLenValue(&bInBuf[usInLen], SHARE_EMV_TAG, sizeof(USHORT), bBuf);
    
    memset(bOutBuf, 0x00, sizeof(bOutBuf));    
    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_EMV", d_IPC_CMD_EMV_GetOneData, bInBuf, usInLen, bOutBuf, &usOutLen);
    if(d_OK == usResult)
    {
        //status
        ptr = ptCTOSS_FindTagAddr(SHARE_EMV_RESP_STATU, bOutBuf, usOutLen);
        if(NULL == ptr)
        {
            usResult = d_NO;
        }
        else
        {
            usResult = ptr[SHARE_EMV_DEFINE_TAGS_LEN+SHARE_EMV_DEFINE_LEN];

            //pValue
            usCTOSS_GetTagLenValue(bOutBuf, usOutLen, SHARE_EMV_TAG_VALUE, &usDataLen, pValue);
            *pLen =  usDataLen; 

            
            vdDebug_LogPrintf("usCTOSS_EMV_DataGet usResult[%d] usTagLen[%d]",usResult, usDataLen);
        }
    }

    return usResult;
}


USHORT usCTOSS_EMV_DataSet(IN USHORT usTag, IN USHORT usLen, IN BYTE *pValue)
{
    BYTE bInBuf[256];
    BYTE bOutBuf[256];
    BYTE bBuf[10];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult;
    USHORT usTagLocal;

    usInLen = 0;
    memset(bInBuf, 0x00, sizeof(bInBuf));
    //usTag
    memset(bBuf, 0x00, sizeof(bBuf));
    usTagLocal = usTag;
    memcpy(bBuf, (BYTE*)&usTagLocal, sizeof(USHORT));
    usInLen += usCTOSS_PackTagLenValue(&bInBuf[usInLen], SHARE_EMV_TAG, sizeof(USHORT), bBuf);

    //pValue
    usInLen += usCTOSS_PackTagLenValue(&bInBuf[usInLen], SHARE_EMV_TAG_VALUE, usLen, pValue);

    memset(bOutBuf, 0x00, sizeof(bOutBuf));    
    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_EMV", d_IPC_CMD_EMV_SetOneData, bInBuf, usInLen, bOutBuf, &usOutLen);
    if(d_OK == usResult)
    {
        //status
        ptr = ptCTOSS_FindTagAddr(SHARE_EMV_RESP_STATU, bOutBuf, usOutLen);
        if(NULL == ptr)
        {
            usResult = d_NO;
        }
        else
        {
            usResult = ptr[SHARE_EMV_DEFINE_TAGS_LEN+SHARE_EMV_DEFINE_LEN];
        }
    }
    
    return usResult;
}

USHORT usCTOSS_EMV_MultiDataGet(IN BYTE *pTagString, INOUT USHORT *pLen, OUT BYTE *pValue)
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
    usInLen += usCTOSS_PackTagLenValue(&bInBuf[usInLen], SHARE_EMV_GET_MULTI_TAG, usTagStringLen, bTagStringHex);
    
    memset(bOutBuf, 0x00, sizeof(bOutBuf));    
    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_EMV", d_IPC_CMD_EMV_GetPackageData, bInBuf, usInLen, bOutBuf, &usOutLen);
    if(d_OK == usResult)
    {
        //status
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
    }

    return usResult;
}


USHORT usCTOSS_EMV_MultiDataSet(IN USHORT usLen, IN BYTE *pValue)
{
    BYTE bInBuf[2048];
    BYTE bOutBuf[64];
    BYTE *ptr = NULL;
    USHORT usInLen = 0;
    USHORT usOutLen = 0;
    USHORT usResult = 0;

    inDatabase_TerminalOpenDatabaseEx(DB_EMV);   
    inMultiAP_Database_EMVTransferDataInitEx();
    
    usInLen = 0;
    memset(bInBuf, 0x00, sizeof(bInBuf));
    //Tags TLV data
    inMultiAP_Database_EMVTransferDataWriteEx(usLen, pValue);
    inDatabase_TerminalCloseDatabase();
#if 0
    memset(bOutBuf, 0x00, sizeof(bOutBuf));    
    usResult = inMultiAP_RunIPCCmdTypes("SHARLS_EMV", d_IPC_CMD_EMV_SetPackageData, bInBuf, usInLen, bOutBuf, &usOutLen);
    if(d_OK == usResult)
    {
        //status
        ptr = ptCTOSS_FindTagAddr(SHARE_EMV_RESP_STATU, bOutBuf, usOutLen);
        if(NULL == ptr)
        {
            usResult = d_NO;
        }
        else
        {
            usResult = ptr[SHARE_EMV_DEFINE_TAGS_LEN+SHARE_EMV_DEFINE_LEN];
        }
    }

    return usResult;
#endif		
}

