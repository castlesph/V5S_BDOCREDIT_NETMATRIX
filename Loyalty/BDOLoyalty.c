#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctosapi.h>
#include <vwdleapi.h>
#include <sqlite3.h>
#include <time.h>

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
//#include "..\PCI100\COMMS.h"

#include "..\POWRFAIL\POSPOWRFAIL.h"
#include <ctos_qrcode.h>
#include <curl\curl.h>

#include "..\Includes\CTOSInput.h"

#include "BDOLoyalty.h"
#include <openssl\rsa.h>
#include <openssl\sha.h>
#include <openssl\pem.h>
#include <openssl\Err.h>

const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

BYTE szAccessToken[50];

typedef struct MemoryStruct {
	char *memory;
	char *function;
	size_t size;
}MemoryStruct;



extern BOOL fTimeOutFlag;
extern BOOL fECRBuildSendOK;
extern BOOL fECRTxnFlg;
extern BOOL fEnteredMenu;

extern BOOL fLoyaltyApp;

BOOL ulRevTraceNum = FALSE;
extern BOOL inRevSettFlag; //for inRequestAccessToken fxn. wont request/send if	no reversal file found.
static CTOS_FONT_ATTRIB stgFONT_ATTRIB;

int inResCurlFlag = 0;

BYTE szGblResponse[30+10];


size_t b64_encoded_size(size_t inlen)
{
	size_t ret;

	ret = inlen;
	if (inlen % 3 != 0)
		ret += 3 - (inlen % 3);
	ret /= 3;
	ret *= 4;

	return ret;
}


char *b64_encode(const unsigned char *in, size_t len)
{
	char   *out;
	size_t  elen;
	size_t  i;
	size_t  j;
	size_t  v;

	if (in == NULL || len == 0)
		return NULL;

	elen = b64_encoded_size(len);
	out  = malloc(elen+1);
	out[elen] = '\0';

	for (i=0, j=0; i<len; i+=3, j+=4) {
		v = in[i];
		v = i+1 < len ? v << 8 | in[i+1] : v << 8;
		v = i+2 < len ? v << 8 | in[i+2] : v << 8;

		out[j]   = b64chars[(v >> 18) & 0x3F];
		out[j+1] = b64chars[(v >> 12) & 0x3F];
		if (i+1 < len) {
			out[j+2] = b64chars[(v >> 6) & 0x3F];
		} else {
			out[j+2] = '=';
		}
		if (i+2 < len) {
			out[j+3] = b64chars[v & 0x3F];
		} else {
			out[j+3] = '=';
		}
	}

	return out;
}

size_t read_callback(void *dest, size_t size, size_t nmemb, void *userp)
{
	struct MemoryStruct *wt = (struct MemoryStruct *)userp;
	size_t buffer_size = size*nmemb;

	vdDebug_LogPrintf("read_callback=[%d][%s]", buffer_size, dest);

	if (wt->size) {
		/* copy as much as possible from the source to the destination */
		size_t copy_this_much = wt->size;
		if (copy_this_much > buffer_size)
			copy_this_much = buffer_size;
		memcpy(dest, wt->memory, copy_this_much);

		wt->memory += copy_this_much;
		wt->size -= copy_this_much;
		
		vdDebug_LogPrintf("read_callback=[%d][%s]", wt->size, dest);
		
		return copy_this_much; /* we copied this many bytes */
	}

	return 0; /* no more data left to deliver */
}

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	vdDebug_LogPrintf("write_callback=[%d][%s]", realsize, contents);
	
	mem->memory = realloc(mem->memory, mem->size + realsize + 1);
	if (mem->memory == NULL) {
		/* out of memory! */
		vdDebug_LogPrintf("not enough memory (realloc returned NULL)");
		return 0;
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);

	vdDebug_LogPrintf("write_callback=[%d][%s]", realsize, contents);
	
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

int inCTOS_LOYALTY(void)
{
	int inRet = d_NO;
	BYTE szTempBaseAmount[AMT_BCD_SIZE+1];
	BOOL fRestoreAMount = FALSE;


	CTOS_LCDTClearDisplay();

	DebugAddHEX("loyalty AMOUNT",srTransRec.szBaseAmount,AMT_BCD_SIZE);

	//need to save amount before init - fix if transaction amount is entered fro idle
	if (memcmp(srTransRec.szBaseAmount, "\x00\x00\x00\x00\x00\x00", 6) != 0){
		vdDebug_LogPrintf("copy amount");
		memset(szTempBaseAmount, 0x00, sizeof(szTempBaseAmount));
		memcpy(szTempBaseAmount, srTransRec.szBaseAmount, 6);
		DebugAddHEX("loyalty AMOUNT 2",szTempBaseAmount,AMT_BCD_SIZE);

		fRestoreAMount = TRUE;

	}
	
	vdCTOS_TxnsBeginInit();
	if (fRestoreAMount == TRUE){
		vdDebug_LogPrintf("restore amount");
		memset(srTransRec.szBaseAmount, 0x00, sizeof(srTransRec.szBaseAmount));
		memcpy(srTransRec.szBaseAmount, szTempBaseAmount,6);
		DebugAddHEX("loyalty AMOUNT",srTransRec.szBaseAmount,AMT_BCD_SIZE);

	}

	srTransRec.fBDOLoyalty = TRUE;
	
	inRet = inCTOS_LoyaltyFlowProcess();
	
	/* Send response to ECR -- sidumili */
	if (!fECRBuildSendOK){	
		inMultiAP_ECRSendSuccessResponse();
	}	
	fECRBuildSendOK = FALSE;
	/* Send response to ECR -- sidumili */
	inCTOS_inDisconnect();
	
	vdCTOS_TransEndReset();
	
	return inRet;
}

#if 0
void vdRetrieveData(int TransType)
{
	
	//save to retrive batch - to be able to still retrive records during power fail and cancel
	
	if (TransType == SALE)
	{
		
		BYTE szGetInv[INVOICE_ASC_SIZE + 1] = {0};	
		int inRtrvOut;
		BYTE szExpiryDate[10];
		BYTE szPosEntry[3];
				
	
		memset(szPosEntry, 0x00, sizeof(szPosEntry));
		if (srTransRec.byEntryMode == CARD_ENTRY_MSR)
			strcpy(szPosEntry, "022");
		else if (srTransRec.byEntryMode == CARD_ENTRY_MANUAL)
			 strcpy(szPosEntry, "012");
		else if (srTransRec.byEntryMode == CARD_ENTRY_ICC)
			 strcpy(szPosEntry, "052");
				
	
		memcpy(srPHQRRtrvTransRec.szBaseAmount, srTransRec.szBaseAmount, 6);
		memcpy(srPHQRRtrvTransRec.szInvoiceNo, srTransRec.szInvoiceNo, 3);
		srPHQRRtrvTransRec.ulTraceNum = srTransRec.ulTraceNum;
	
		memcpy(srPHQRRtrvTransRec.szTID, srTransRec.szTID, 8);
		memcpy(srPHQRRtrvTransRec.szMID, srTransRec.szMID, 15);
	
		memcpy(srPHQRRtrvTransRec.szPAN, srTransRec.szPAN, sizeof(srTransRec.szPAN));
		memcpy(srPHQRRtrvTransRec.szServiceCode, srTransRec.szServiceCode, 3);
		memcpy(srPHQRRtrvTransRec.byEntryMode, szPosEntry, 3);
	
		vdDebug_LogPrintf("SAVE TO RTRV byEntryMode:[%s]",srPHQRRtrvTransRec.byEntryMode);
		vdDebug_LogPrintf("SAVE TO RTRV **szTID[%s]..szMID=[%s]..",srPHQRRtrvTransRec.szTID,srPHQRRtrvTransRec.szMID);			
		vdDebug_LogPrintf("SAVE TO RTRV ulTraceNum:[%06ld]", srPHQRRtrvTransRec.ulTraceNum);
		vdDebug_LogPrintf("SAVE TO RTRV PAN:[%s]",srPHQRRtrvTransRec.szPAN);
		vdDebug_LogPrintf("SAVE TO RTRV szServiceCode/sequence_number:[%s]",srPHQRRtrvTransRec.szServiceCode);			
		vdDebug_LogPrintf("SAVE TO RTRV szBaseAmount[%02X%02X%02X%02X%02X%02X]", srPHQRRtrvTransRec.szBaseAmount[0], srPHQRRtrvTransRec.szBaseAmount[1], srPHQRRtrvTransRec.szBaseAmount[2], srPHQRRtrvTransRec.szBaseAmount[3], srPHQRRtrvTransRec.szBaseAmount[4], srPHQRRtrvTransRec.szBaseAmount[5]);
		vdDebug_LogPrintf("SAVE TO RTRV szInvoiceNo[%02X%02X%02X]", srPHQRRtrvTransRec.szInvoiceNo[0], srPHQRRtrvTransRec.szInvoiceNo[1], srPHQRRtrvTransRec.szInvoiceNo[2]);
				//vdDebug_LogPrintf("SAVE TO RTRV szExpireDate[%s]",srPHQRRtrvTransRec.szExpireDate);
					
		wub_hex_2_str(srTransRec.szInvoiceNo, szGetInv, 3); 	
		vdDebug_LogPrintf("SAVE TO RTRV last inv num is [%s]", szGetInv);
	
	
		#if 1
		//put_env_charEx("PHQRLASTINV",szGetInv);	
		//add for retrivelast
		put_env_int("QRLASTTXN",srTransRec.byTransType); 
	
		//put_env_int("PHQRLASTINV2", atoi(szGetInv));
		put_env("PHQRLASTINV2", szGetInv, strlen(szGetInv));
	
				
		inRtrvOut = inDatabase_BatchSaveRrtrieveDataPHQR(&srPHQRRtrvTransRec, DF_BATCH_APPEND);
		vdDebug_LogPrintf("SAVE TO RTRV RESULT inRtrvOut [%d]", inRtrvOut);
			
		if(inRtrvOut != ST_SUCCESS)
			return ST_ERROR;
		#endif
	
				
	}

}
#endif

int inReversalRoutine(void)
{
	BYTE szinVoiceNum[INVOICE_BCD_SIZE + 1];
	//int szinVoiceNum2;
	int inResult, inRet;
	int inResult2, inResRevRet;
    char szBcd[INVOICE_BCD_SIZE+1];
	MemoryStruct write_data, read_data;
	


   	vdDebug_LogPrintf("--START inReversalRoutine--");


	//FOR TEsting only
	#if 0
		inDatabase_PHQRBatchDeleteRetrieveData();	
	#endif

	memset(szinVoiceNum,0x00,sizeof(szinVoiceNum));

	get_env("PHQRLASTINV2", szinVoiceNum, sizeof(szinVoiceNum));
   	vdDebug_LogPrintf("--inReversalRoutine-szinVoiceNum [%s]", szinVoiceNum);

	wub_str_2_hex(szinVoiceNum,srTransRec.szInvoiceNo,6);
	
    inResult = inDatabase_PHQRBatchSearchRetrieveData(&srPHQRRtrvTransRec, srTransRec.szInvoiceNo);
	

   	vdDebug_LogPrintf("--inReversalRoutine-inDatabase_PHQRBatchSearchRetrieveData-inResult-inRevSettFlag-[%d][%d]", inResult, inRevSettFlag);
   	//vdDebug_LogPrintf("--inReversalRoutine-inDatabase_PHQRBatchSearchRetrieveData-inResult-[%d]", inResult);

	if(inResult == d_OK)
	{		

		int inCounter = 0;
		
		ulRevTraceNum = 1; // to get data from inDatabase_PHQRBatchSearchRetrieveData > for reversal create body data

        //vdDisplayErrorMsgResp2("REVERSAL","FILE","FOUND");
		vdDebug_LogPrintf("inReversalRoutine REVERSAL INVOICE FOUND");


		// commented, fill in inCreateBody fxn instead
		//vdSetRetrieveData();	 


	//send request for REVERSAL HERE
	#if 1

		if(inRevSettFlag) //activate only for on settlement function. will only send token if reversal data found.
		{
		
			vdCTOS_DispStatusMessage("PROCESSING...");

			inRet = inRequestAccessToken();	
			vdDebug_LogPrintf("inReversalRoutine inRet [%d]", inRet);
			
			if(d_OK != inRet)
				return inRet;	
			else
				inRevSettFlag = FALSE;
		}
		

	
		inResRevRet = inCURLSend_request(&read_data,&write_data, REVERSAL);		
		
	#else
		do
		{

			inResRevRet = inCURLSend_request(&read_data,&write_data, REVERSAL); 	
			if(inCounter >= 3){
				
				vdDisplayErrorMsgResp2("REVERSAL","RETRY","MATCH!");
				break;
			}	
			
			inCounter++;
			
		}
		while(inResRevRet != d_OK);		
	#endif
		
		vdDebug_LogPrintf("inReversalRoutine inCURLSend_request REVERSAL inResRevRet %d", inResRevRet);

		if(d_OK != inResRevRet)
		{
			//vdDisplayErrorMsgResp2("REVERSAL","FAILED","Please Try Again");
			#if 0
			inResRevRet = inDatabase_PHQRBatchDeleteRetrieveData();		
			vdDebug_LogPrintf("inReversalRoutine inDatabase_PHQRBatchDeleteRetrieveData inResult2 [%d]", inResRevRet);			
			#endif
			
       		return inResRevRet;
		}

		
		#if 1
		//Successful Reversal - increment invoince number for next online redemption txn
       	vdDebug_LogPrintf("inReversalRoutine inCTOS_GetInvoice 1");
        memset(szBcd, 0x00, sizeof(szBcd));
        memcpy(szBcd, strTCT.szInvoiceNo, INVOICE_BCD_SIZE);    
        inBcdAddOne(szBcd, strTCT.szInvoiceNo, INVOICE_BCD_SIZE);
        
        if((inResult = inTCTSave(1)) != ST_SUCCESS)
        {
        	vdDebug_LogPrintf("get inv load tct error");
            vdSetErrorMessage("LOAD TCT ERR");
            return ST_ERROR;
        }		

		//retain current invoince number. else null result for save data.
        memcpy(srTransRec.szInvoiceNo,strTCT.szInvoiceNo, 3);		
		#endif

	
		//delete table and clear retrieve data	struct
		inResult2 = inDatabase_PHQRBatchDeleteRetrieveData();			
        memset(&srPHQRRtrvTransRec, 0x00, sizeof(RTRV_BPT_TRANS_DATA_TABLE));

		//00144 - Asterisk “*” is missing in Clear Reversal
		#ifdef BLT_REV_PFR
		inMyFile_ReversalDelete();
		#endif

		vdDebug_LogPrintf("inReversalRoutine inDatabase_PHQRBatchDeleteRetrieveData inResult2 [%d]", inResult2);
		
	}
	else
	{		
		vdDebug_LogPrintf("inReversalRoutine REVERSAL INVOICE  NOT FOUND");
		inRevSettFlag = FALSE;
	
		
		//retain current invoince number. else null result for save data.
        memcpy(srTransRec.szInvoiceNo,strTCT.szInvoiceNo, 3);
		
		
	}
	vdDebug_LogPrintf(" inReversalRoutine FINAL inCTOS_GetInvoice invoice num %x%x%x%x",srTransRec.szInvoiceNo[0], srTransRec.szInvoiceNo[1],srTransRec.szInvoiceNo[2], srTransRec.szInvoiceNo[3]);
	
	vdDebug_LogPrintf("inReversalRoutine END");

	return d_OK;
}


void vdSetRetrieveData()
{

	vdDebug_LogPrintf("vdSetRetrieveData- szBaseAmount");
	//memcpy(srTransRec.szBaseAmount, srPHQRRtrvTransRec.szBaseAmount, 6);	
	memcpy(srTransRec.szTotalAmount, srPHQRRtrvTransRec.szBaseAmount, 6);	

	
	vdDebug_LogPrintf("vdSetRetrieveData- szInvoiceNo");
	memcpy(srTransRec.szInvoiceNo, srPHQRRtrvTransRec.szInvoiceNo, 3);	

	
	vdDebug_LogPrintf("vdSetRetrieveData- ulTraceNum");
	srTransRec.ulTraceNum = srPHQRRtrvTransRec.ulTraceNum;
	//if(srTransRec.ulTraceNum > 0)
	//	ulRevTraceNum = 1;

	
	vdDebug_LogPrintf("vdSetRetrieveData- szTID");

	memcpy(srTransRec.szTID, srPHQRRtrvTransRec.szTID, 8);

	
	vdDebug_LogPrintf("vdSetRetrieveData- szMID");
	memcpy(srTransRec.szMID, srPHQRRtrvTransRec.szMID, 15);

	
	vdDebug_LogPrintf("vdSetRetrieveData- szPAN");

	memcpy(srTransRec.szPAN, srPHQRRtrvTransRec.szPAN, sizeof(srPHQRRtrvTransRec.szPAN));

	
	vdDebug_LogPrintf("v- szServiceCode");
	memcpy(srTransRec.szServiceCode, srPHQRRtrvTransRec.szServiceCode, 3);

	
	vdDebug_LogPrintf("vdSetRetrieveData- byEntryMode");
	//memcpy(srTransRec.byEntryMode, srPHQRRtrvTransRec.byEntryMode, 3);
	//wub_hex_2_str(srPHQRRtrvTransRec.byEntryMode, srTransRec.byEntryMode , 3);
	//wub_str_2_hex();
	//strcpy(srTransRec.byEntryMode, srPHQRRtrvTransRec.byEntryMode);

	
	vdDebug_LogPrintf("vdSetRetrieveData- szExpireDate");

	//strcpy(srTransRec.szExpireDate, srPHQRRtrvTransRec.szExpireDate);
	

	

	vdDebug_LogPrintf("GET FROM RTRV byEntryMode:[%s]",srPHQRRtrvTransRec.byEntryMode);
	vdDebug_LogPrintf("GET FROM RTRV **szTID[%s]..szMID=[%s]..",srTransRec.szTID,srTransRec.szMID);			
	vdDebug_LogPrintf("GET FROM RTRV ulTraceNum:[%06ld]", srTransRec.ulTraceNum);
	vdDebug_LogPrintf("GET FROM RTRV PAN:[%s]",srTransRec.szPAN);
	vdDebug_LogPrintf("GET FROM RTRV szServiceCode/sequence_number:[%s]",srTransRec.szServiceCode);			
	vdDebug_LogPrintf("GET FROM RTRV szBaseAmount[%02X%02X%02X%02X%02X%02X]", srTransRec.szBaseAmount[0], srTransRec.szBaseAmount[1], srTransRec.szBaseAmount[2], srTransRec.szBaseAmount[3], srTransRec.szBaseAmount[4], srTransRec.szBaseAmount[5]);
	DebugAddHEX("GET FROM RTRV szInvoiceNo",srTransRec.szInvoiceNo,INVOICE_BCD_SIZE);
//	vdDebug_LogPrintf("GET FROM RTRV ExpDate[%s]",srPHQRRtrvTransRec.szExpireDate);



}

int inCTOS_LoyaltyFlowProcess(void)
{
	int inRet = d_NO;
	int inRet2 = d_NO;
	

	MemoryStruct write_data, read_data;

#ifdef BLT_REV_PFR
	BYTE szinVoiceNum[INVOICE_BCD_SIZE + 1];
	//int szinVoiceNum2;
	int inResult;
	int inResult2, inResRevRet;
    char szBcd[INVOICE_BCD_SIZE+1];

#endif

	fECRBuildSendOK = FALSE; /* BDO: For ECR -- sidumili */
	fTimeOutFlag = FALSE; /*BDO: Flag for timeout --sidumili*/
	fLoyaltyApp = TRUE;

    vdCTOS_SetTransType(SALE);
    
    //display title
    vdDispTransTitle(SALE);
		
	srTransRec.fVoidOffline = CN_FALSE;
    
    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;

	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;

    inRet = inCTOS_GetTxnBaseAmount();
    if(d_OK != inRet)
        return inRet;

	inRet = inCTOS_GetCardFields(); 
    if(d_OK != inRet)
        return inRet;

	// host index
	srTransRec.HDTid = BDO_LOYALTY_HDT_INDEX;
	strCDT.HDTid = BDO_LOYALTY_HDT_INDEX;

	// issuer index
	srTransRec.IITid = BDO_LOYALTY_ISSUER_INDEX;
	strIIT.inIssuerNumber = BDO_LOYALTY_ISSUER_INDEX;
	strCDT.IITid = BDO_LOYALTY_ISSUER_INDEX;

	inIITRead(srTransRec.IITid);

	strcpy(srTransRec.szCardLable, strIIT.szIssuerLabel);
	vdDebug_LogPrintf("1 copy card label %s", srTransRec.szCardLable);
	
	
	inRet = inBDOEnterLast4Digits(FALSE);
	if(inRet != d_OK)
			return inRet;

	inRet = inCTOS_SelectHost();
	if(d_OK != inRet)
		return inRet;

	inRet=inCTOS_DisplayCardTitle(6, 7); //Display Issuer logo: re-aligned Issuer label and PAN lines -- jzg
	if(d_OK != inRet)
		return inRet;


	inRet = inCTOS_UpdateTxnTotalAmount();
	if(d_OK != inRet)
		return inRet;

	inRet = inConfirmPAN();
	if(d_OK != inRet)
		return inRet;		

	CTOS_LCDTClearDisplay();
    vdDispTransTitle(SALE);

	vdCTOS_DispStatusMessage("PROCESSING...");

	vdDebug_LogPrintf("strCPT.inCommunicationMode %d",strCPT.inCommunicationMode);


//testlang-removelater
#if 1
	if (strCPT.inCommunicationMode == ETHERNET_MODE)
	{		
		inRet = inCurl_CommsInit(); 
			if (inRet != d_OK)
				return inRet;

		//exit on failed comm result. 04122023
		//#2 00206 - SM : Overlapping displayed in Redemption BDO Loyalty  and No error message displayed if host is down
		if (srTransRec.shTransResult == 94)
			return d_NO;			
	}
	else if(strCPT.inCommunicationMode == GPRS_MODE && get_env_int("QRPING") == TRUE)
	{
		inCTOSS_GPRSPing(strCPT.szPriTxnHostIP);
	}
#endif
	inMMTReadRecord(strCDT.HDTid,srTransRec.MITid);

	inBLTRead(1);

//testlang-removelater
#if 1

	// Request Access Token
	inRet = inRequestAccessToken();
	if(d_OK != inRet)
		return inRet;	
#endif


   	vdDebug_LogPrintf("--inRequestAccessToken--");
    inRet = inCTOS_GetInvoice();

	vdDebug_LogPrintf("get invoice return %d", inRet);
	if(d_OK != inRet)
		return inRet;

	#if 1
	//2.	00149 (No Reversal is sent on the next online BDO Loyalty transaction (Bal Inq or Redemption)) 
	//START OF Reversal Routine
	inResult = inReversalRoutine();

	vdDebug_LogPrintf("inCTOS_LoyaltyFlowProcess inResult [%d] inResCurlFlag [%d]", inResult, inResCurlFlag);
	
	if(d_OK != inResult){

		// ADDED display error - no error display on failed reversal
		if(inResCurlFlag > 0)
			vdDisplayCurlErrorMsg();


		//00210 - SM: After host response Invalid Account, terminal displayed error again "Failure When Receiving Data from the Peer"in BDO Loyalty Redemption transaction
		inResCurlFlag = 0;
		
		return inResult;
	}
	
	#endif

	

	//testlang-removelater
	#if 1
	inRet = inCURLSend_request(&read_data,&write_data, SALE);

	vdDebug_LogPrintf("inCTOS_LoyaltyFlowProcess inCURLSend_request inRet %d", inRet);

	if (inRet == ST_RECEIVE_TIMEOUT_ERR){
		vdDebug_LogPrintf("receive timeout");
		inRet2 = inCURLSend_request(&read_data,&write_data, REVERSAL);
		if(inRet2 == d_OK)
			inDatabase_PHQRBatchDeleteRetrieveData();
		else
			return inRet2;
			
	}

	if(d_OK != inRet)
	{
		 //BYTE uszSendData[ISO_SEND_SIZE + 1];
        //vdDisplayErrorMsgResp2("REDEMPTION","NOT","SUCCESSFUL!!!!");
		vdDebug_LogPrintf("inCTOS_LoyaltyFlowProcess REDEMPTION NOT SUCCESSFUL inResCurlFlag [%d]!!!!", inResCurlFlag);		

	   // ADDED display error - #3 related to 00206 - SM : Overlapping displayed in Redemption BDO Loyalty	and No error message displayed if host is down
	   if(inResCurlFlag > 0)
		   vdDisplayCurlErrorMsg();

	   //00210 - SM: After host response Invalid Account, terminal displayed error again "Failure When Receiving Data from the Peer"in BDO Loyalty Redemption transaction
	   inResCurlFlag = 0;

       return inRet;
	}
	else
	{		

		// DElete reversal should be made in inCTOS_SaveBatchTxn.
		#ifdef BLT_REV_PFR
		//inRet = inMyFile_ReversalDelete();		
		//vdDebug_LogPrintf("inCTOS_LoyaltyFlowProcess inMyFile_ReversalDelete inRet %d", inRet);
		#endif

		vdDebug_LogPrintf("inCTOS_LoyaltyFlowProcess BEFORE inDatabase_PHQRBatchDeleteRetrieveData inRet %d", inRet);
		
		//inRet = inDatabase_PHQRBatchDeleteRetrieveData();	
		
		//vdDebug_LogPrintf("inCTOS_LoyaltyFlowProcess AFTER inDatabase_PHQRBatchDeleteRetrieveData inRet %d", inRet);		
		
	}
	#else

	inRet = inCURLSend_request(&read_data,&write_data, SALE);

	vdDebug_LogPrintf("inCTOS_LoyaltyFlowProcess inCURLSend_request inRet %d", inRet);

	if (inRet == ST_RECEIVE_TIMEOUT_ERR){
		vdDebug_LogPrintf("receive timeout");
		inCURLSend_request(&read_data,&write_data, REVERSAL);
	}
	if(d_OK != inRet)
       return inRet;
	
	#endif


//testlang
            //set datetime
            //CTOS_RTCGet(&SetRTC);
			//memset(szTemp, 0x00, sizeof(szTemp));
			//sprintf(szTemp ,"%02d%02d",SetRTC.bMonth, SetRTC.bDay);
			//wub_str_2_hex(szTemp,srTransRec.szDate,4);

			//memset(szTemp, 0x00, sizeof(szTemp));
			//sprintf(szTemp ,"%02d%02d%02d",SetRTC.bHour,SetRTC.bMinute,SetRTC.bSecond);
			//wub_str_2_hex(szTemp,srTransRec.szTime,6);	
//endtest

#if 1
    inRet = inCTOS_SaveBatchTxn();
    if(d_OK != inRet)
        return inRet;
	else
	{
		inRet = inDatabase_PHQRBatchDeleteRetrieveData(); 	// delete record on table.
		vdDebug_LogPrintf("inCTOS_LoyaltyFlowProcess AFTER inDatabase_PHQRBatchDeleteRetrieveData inRet %d", inRet);	
	}

#endif	

    vdDebug_LogPrintf("inCTOS_UpdateAccumTotal");
	
    inRet = inCTOS_UpdateAccumTotal();
    if(d_OK != inRet)
		return inRet;

    //copy card label here - to make sure card label has a value before printing
    //strcpy(srTransRec.szCardLable, strIIT.szIssuerLabel);
	//vdDebug_LogPrintf("2 copy card label %s", srTransRec.szCardLable);
	//vdDebug_LogPrintf("copy card label %s", srTransRec.szCardLable);

	fECRBuildSendOK = TRUE;	
	if (fECRBuildSendOK){	
	    inRet = inMultiAP_ECRSendSuccessResponse();
	}

	inRet = ushCTOS_printReceipt();
	if(d_OK != inRet)
		return inRet;

	CTOS_LCDTClearDisplay(); 

	vdDebug_LogPrintf("inDisconnectIfNoPendingADVICEandUPLOAD");

    inCTLOS_Updatepowrfail(PFR_IDLE_STATE);


	//remove later -- jzg
	return d_OK;
}

int inCTOS_POINSTINQ(void)
{
	int inRet = d_NO;

	CTOS_LCDTClearDisplay();
	
	vdCTOS_TxnsBeginInit();

	srTransRec.fBDOLoyalty = TRUE;

	inRet = inCTOS_PointsInqFlowProcess();
	
	/* Send response to ECR -- sidumili */
	if (!fECRBuildSendOK){	
		inMultiAP_ECRSendSuccessResponse();
	}	
	fECRBuildSendOK = FALSE;
	/* Send response to ECR -- sidumili */
	inCTOS_inDisconnect();
	
	vdCTOS_TransEndReset();
	
	return inRet;
}


int inCTOS_PointsInqFlowProcess(void)
{
	int inRet = d_NO;
	MemoryStruct write_data, read_data;


	fECRBuildSendOK = FALSE; /* BDO: For ECR -- sidumili */
	fTimeOutFlag = FALSE; /*BDO: Flag for timeout --sidumili*/
	fLoyaltyApp = TRUE;

    vdCTOS_SetTransType(POINTS_INQUIRY);
    
    //display title
    vdDispTransTitle(POINTS_INQUIRY);
		
	srTransRec.fVoidOffline = CN_FALSE;
    
    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;

	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;

	inRet = inCTOS_GetCardFields(); 
    if (d_OK != inRet)
      return inRet;

	// host index
	srTransRec.HDTid = BDO_LOYALTY_HDT_INDEX;
	strCDT.HDTid = BDO_LOYALTY_HDT_INDEX;

	// issuer index
	srTransRec.IITid = BDO_LOYALTY_ISSUER_INDEX;
	strIIT.inIssuerNumber = BDO_LOYALTY_ISSUER_INDEX;
	strCDT.IITid = BDO_LOYALTY_ISSUER_INDEX;

	inIITRead(srTransRec.IITid);

	strcpy(srTransRec.szCardLable, strIIT.szIssuerLabel);

	inRet = inBDOEnterLast4Digits(FALSE);
	if (inRet != d_OK)
	  return inRet;

	inRet = inCTOS_SelectHost();
	if(d_OK != inRet)
		return inRet;

	inRet=inCTOS_DisplayCardTitle(6, 7); //Display Issuer logo: re-aligned Issuer label and PAN lines -- jzg
	if (d_OK != inRet)
		return inRet;

	inRet = inConfirmPAN();
	if (d_OK != inRet)
		return inRet;		

	CTOS_LCDTClearDisplay();
    vdDispTransTitle(POINTS_INQUIRY);

	vdCTOS_DispStatusMessage("PROCESSING...");

	vdDebug_LogPrintf("strCPT.inCommunicationMode %d",strCPT.inCommunicationMode);

	if (strCPT.inCommunicationMode == ETHERNET_MODE)
	{		
		inRet = inCurl_CommsInit(); 
			if (inRet != d_OK)
				return inRet;

		//exit on failed comm result. 04122023
		//#2 00206 - SM : Overlapping displayed in Redemption BDO Loyalty  and No error message displayed if host is down
		if (srTransRec.shTransResult == 94)
			return d_NO;			
	}
	else if(strCPT.inCommunicationMode == GPRS_MODE && get_env_int("QRPING") == TRUE)
	{
		inCTOSS_GPRSPing(strCPT.szPriTxnHostIP);
	}


    vdDebug_LogPrintf("test strCDT.HDTid=%d srTransRec.MITid=%d", strCDT.HDTid,srTransRec.MITid);
	inMMTReadRecord(strCDT.HDTid,srTransRec.MITid);

	inBLTRead(1);

	// Request Access Token
	inRet = inRequestAccessToken();
	
	if(d_OK != inRet)
		return inRet;	
	

   	vdDebug_LogPrintf("--inRequestAccessToken--");
    inRet = inCTOS_GetInvoice();
	if(d_OK != inRet)
		return inRet;


#ifdef BLT_REV_PFR
	inRet = inReversalRoutine();

   	vdDebug_LogPrintf("--inCTOS_PointsInqFlowProcess inReversalRoutine--inRet [%d] inResCurlFlag [%d]", inRet, inResCurlFlag);

	if(d_OK != inRet){

		// ADDED display error - no error display on failed reversal
		if(inResCurlFlag > 0)
			vdDisplayCurlErrorMsg();

		inResCurlFlag = 0;
		return inRet;
	}
#endif

	
	inRet = inCURLSend_request(&read_data,&write_data, POINTS_INQUIRY);
	if(d_OK != inRet){

		vdDebug_LogPrintf("inCTOS_PointsInqFlowProcess POINTS_INQUIRY NOT SUCCESSFUL!!!!");		


		// ADDED display error - #3 related to 00206 - SM : Overlapping displayed in Redemption BDO Loyalty  and No error message displayed if host is down
		if(inResCurlFlag > 0)
			vdDisplayCurlErrorMsg();

		
		//00210 - SM: After host response Invalid Account, terminal displayed error again "Failure When Receiving Data from the Peer"in BDO Loyalty Redemption transaction
		inResCurlFlag = 0;
		
		return inRet;
	}


    if (inRet == d_OK){
		InDisplayLoyaltyBalance();
    }

	if(inFLGGet("fPrintPtsInqRcpt") == TRUE){
		inRet = ushCTOS_printReceipt();
		if(d_OK != inRet)
			return inRet;
	}

	
	return d_OK;
}


int inCreateBody(char *szBuffer, int inType)
{
	int inResult = -1;	
	BYTE szAmtBuff[20+1];
	BYTE szBaseAmt[AMT_ASC_SIZE + 1] = {0};
	char szInvoiceNum[6+1];
	BYTE szInv[INVOICE_ASC_SIZE + 1] = {0};

    char szBcd[INVOICE_BCD_SIZE+1];
	BYTE szTemp[30];

	BYTE szPosEntry[5];
	BYTE szExpiryDate[10];

	BYTE szGetInv[INVOICE_ASC_SIZE + 1] = {0};


	vdDebug_LogPrintf("***inCreateBody START***");
	vdDebug_LogPrintf("inType=[%d]", inType);

	memset(szPosEntry, 0x00, sizeof(szPosEntry));

	if (srTransRec.byEntryMode == CARD_ENTRY_MSR)
		strcpy(szPosEntry, "022");
	else if (srTransRec.byEntryMode == CARD_ENTRY_MANUAL)
		strcpy(szPosEntry, "012");
	else if (srTransRec.byEntryMode == CARD_ENTRY_ICC)
		strcpy(szPosEntry, "052");


    memset(szBuffer, 0x00, sizeof(szBuffer));
	if (inType == REQUEST_ACCESS_TOKEN)
	{
		
	}
	else if (inType == SALE)
	{

		vdDebug_LogPrintf("***inCreateBody SALE***");
	
		memset(szAmtBuff, 0x00, sizeof(szAmtBuff));
		wub_hex_2_str(srTransRec.szTotalAmount, szBaseAmt, 6); 
		vdCTOS_FormatAmount("NNNNNNNNNNNN", szBaseAmt,szAmtBuff); 

		memset(szBcd, 0x00, sizeof(szBcd));
		memcpy(szBcd, strHDT.szTraceNo, INVOICE_BCD_SIZE);
		inBcdAddOne(szBcd, strHDT.szTraceNo, INVOICE_BCD_SIZE);	
		srTransRec.ulTraceNum = wub_bcd_2_long(strHDT.szTraceNo,3);

		vdDebug_LogPrintf("ulTraceNum:[%06ld]", srTransRec.ulTraceNum);

		inHDTSave(strHDT.inHostIndex); // fix not incrementing trace num. - 03112023
		


        vdDebug_LogPrintf("redemption test1");
		vdDebug_LogPrintf("inCreateBody invoice num %x%x%x",srTransRec.szInvoiceNo[0], srTransRec.szInvoiceNo[1],srTransRec.szInvoiceNo[2]);		
        memset(szInvoiceNum, 0x00, sizeof(szInvoiceNum));
		memset(szInv, 0x00, sizeof(szInv));
        wub_hex_2_str(srTransRec.szInvoiceNo,szInv,INVOICE_BCD_SIZE);
		sprintf(szInvoiceNum,"%ld",atol(szInv));//remove leading zeros
		//sprintf(szInvoiceNum,"%ld",atol(szInv));//remove leading zeros
		vdDebug_LogPrintf("redemption test2");

		memset(szTemp, 0x00, sizeof(szTemp));
    	wub_hex_2_str(srTransRec.szExpireDate, szTemp,EXPIRY_DATE_BCD_SIZE);

		memset(szExpiryDate, 0x00, sizeof(szExpiryDate));
		strcpy(szExpiryDate,"20");
		memcpy(&szExpiryDate[2],szTemp, 2);
		memcpy(&szExpiryDate[4],"-", 1);
		memcpy(&szExpiryDate[5],&szTemp[2], 2);

		// To save Exp date, for PFR
		strcpy(srPHQRRtrvTransRec.szExpireDate, szExpiryDate);
		vdDebug_LogPrintf("inCreateBody > SAVE TO RTRV ExpDate[%s]",srPHQRRtrvTransRec.szExpireDate);
		put_env("PHQRLASTEXPDATE", szExpiryDate, strlen(szExpiryDate));
			

		purge_chr(srTransRec.szServiceCode, '=');

		sprintf(szBuffer,"{\n\"transaction_amount\":%s,\n\"transaction_type\":\"%s\",\n\"audit_number\":%ld,\n\"pos_entry_mode\":\"%s\",\n\"account_number\":\"%s\",\n\"card_expiry_date\":\"%s\",\n\"terminal_id\":\"%s\",\n\"merchant_id\":\"%s\",\n\"invoice_number\":\"%s\",\n\"sequence_number\":\"%s\"\n}",
		szAmtBuff,
		"burn",
		srTransRec.ulTraceNum,
		szPosEntry,
		//gtest
		srTransRec.szPAN,
		//"8880512877742417",
		szExpiryDate,		
		//"test_merchant_location",
		//"test_merchant_id",
		srTransRec.szTID,
		srTransRec.szMID,
		//"00052129",
		//"000014431583",
		szInvoiceNum,
		srTransRec.szServiceCode);

	
		
	}
	else if(inType == REVERSAL)
	{		
	
		vdDebug_LogPrintf("***inCreateBody REVERSAL**[%d]*", ulRevTraceNum);
		vdDebug_LogPrintf("***inCreateBody REVERSAL byEntryMode**[%s]*", srPHQRRtrvTransRec.byEntryMode);
		vdDebug_LogPrintf("***inCreateBody REVERSAL**szTID[%s]..szMID=[%s]..",srPHQRRtrvTransRec.szTID,srPHQRRtrvTransRec.szMID); 		
		vdDebug_LogPrintf("***inCreateBody REVERSAL ulTraceNum:[%06ld]", srPHQRRtrvTransRec.ulTraceNum);
		vdDebug_LogPrintf("***inCreateBody REVERSAL PAN:[%s]",srTransRec.szPAN);
		vdDebug_LogPrintf("***inCreateBody REVERSAL szServiceCode/sequence_number:[%s]",srPHQRRtrvTransRec.szServiceCode); 		
		vdDebug_LogPrintf("***inCreateBody REVERSAL szBaseAmount[%02X%02X%02X%02X%02X%02X]", srPHQRRtrvTransRec.szBaseAmount[0], srPHQRRtrvTransRec.szBaseAmount[1], srPHQRRtrvTransRec.szBaseAmount[2], srPHQRRtrvTransRec.szBaseAmount[3], srPHQRRtrvTransRec.szBaseAmount[4], srPHQRRtrvTransRec.szBaseAmount[5]);
		vdDebug_LogPrintf("***inCreateBody REVERSAL szTotalAmount[%02X%02X%02X%02X%02X%02X]", srPHQRRtrvTransRec.szTotalAmount[0], srPHQRRtrvTransRec.szTotalAmount[1], srPHQRRtrvTransRec.szTotalAmount[2], srPHQRRtrvTransRec.szTotalAmount[3], srPHQRRtrvTransRec.szTotalAmount[4], srPHQRRtrvTransRec.szTotalAmount[5]);
		DebugAddHEX("***inCreateBody REVERSAL szInvoiceNo",srPHQRRtrvTransRec.szInvoiceNo,INVOICE_BCD_SIZE);



		// -- FOR [{"code":"bdo-08","message":"Audit number mismatch"}
		if(ulRevTraceNum)
		{			
			//For other data,  refer to vdRetrieveData			
			srTransRec.ulTraceNum = srPHQRRtrvTransRec.ulTraceNum; // or AUDIT NUMBER
			
			strcpy(szPosEntry, srPHQRRtrvTransRec.byEntryMode);		
			
			//strcpy(szTemp, srPHQRRtrvTransRec.szExpireDate);		
			//strcpy(szTemp, "2027-05");		
			get_env("PHQRLASTEXPDATE",szTemp,sizeof(szTemp));
			vdDebug_LogPrintf("***inCreateBody REVERSAL szExpireDate**[%s]*", szTemp);


			#if 0
			memset(szAmtBuff, 0x00, sizeof(szAmtBuff));
			wub_hex_2_str(srPHQRRtrvTransRec.szTotalAmount, szBaseAmt, 6); 
			vdCTOS_FormatAmount("NNNNNNNNNNNN", szBaseAmt,szAmtBuff); 	
			#else
			memset(szAmtBuff, 0x00, sizeof(szAmtBuff));
			wub_hex_2_str(srPHQRRtrvTransRec.szBaseAmount, szBaseAmt, 6); 
			vdCTOS_FormatAmount("NNNNNNNNNNNN", szBaseAmt,szAmtBuff); 			
			#endif

			memcpy(srTransRec.szPAN, srPHQRRtrvTransRec.szPAN, sizeof(srPHQRRtrvTransRec.szPAN));

	        memset(szInvoiceNum, 0x00, sizeof(szInvoiceNum));
			memset(szInv, 0x00, sizeof(szInv));
	        wub_hex_2_str(srPHQRRtrvTransRec.szInvoiceNo,szInv,INVOICE_BCD_SIZE);
			sprintf(szInvoiceNum,"%ld",atol(szInv));//remove leading zeros

			memcpy(srTransRec.szTID, srPHQRRtrvTransRec.szTID, 8);
			
			memcpy(srTransRec.szMID, srPHQRRtrvTransRec.szMID, 15);		

			memcpy(srTransRec.szServiceCode, srPHQRRtrvTransRec.szServiceCode, 3);			
			
			
		}
		else
		{

	        memset(szInvoiceNum, 0x00, sizeof(szInvoiceNum));
			memset(szInv, 0x00, sizeof(szInv));
	        wub_hex_2_str(srTransRec.szInvoiceNo,szInv,INVOICE_BCD_SIZE);
			sprintf(szInvoiceNum,"%ld",atol(szInv));//remove leading zeros

			
			memset(szAmtBuff, 0x00, sizeof(szAmtBuff));
			wub_hex_2_str(srTransRec.szTotalAmount, szBaseAmt, 6); 
			vdCTOS_FormatAmount("NNNNNNNNNNNN", szBaseAmt,szAmtBuff); 
		
			memset(szBcd, 0x00, sizeof(szBcd));
			memcpy(szBcd, strHDT.szTraceNo, INVOICE_BCD_SIZE);
			srTransRec.ulTraceNum = wub_bcd_2_long(strHDT.szTraceNo,3);			


			memset(szTemp, 0x00, sizeof(szTemp));
		    wub_hex_2_str(srTransRec.szExpireDate, szTemp,EXPIRY_DATE_BCD_SIZE);

			memset(szExpiryDate, 0x00, sizeof(szExpiryDate));
			strcpy(szExpiryDate,"20");
			memcpy(&szExpiryDate[2],szTemp, 2);
			memcpy(&szExpiryDate[4],"-", 1);
			memcpy(&szExpiryDate[5],&szTemp[2], 2);
		}

		purge_chr(srTransRec.szServiceCode, '=');

		#ifdef BLT_REV_PFR
			sprintf(szBuffer,"{\n\"transaction_amount\":%s,\n\"audit_number\":%ld,\n\"pos_entry_mode\":\"%s\",\n\"account_number\":\"%s\",\n\"card_expiry_date\":\"%s\",\n\"terminal_id\":\"%s\",\n\"merchant_id\":\"%s\",\n\"invoice_number\":\"%s\",\n\"sequence_number\":\"%s\"\n}",
			szAmtBuff,
			srTransRec.ulTraceNum,
			szPosEntry,
			srTransRec.szPAN,
			szTemp,
			srTransRec.szTID,
			srTransRec.szMID,
			//"00052129",
			//"000014431583",		
			szInvoiceNum,
			srTransRec.szServiceCode);
		#else
			sprintf(szBuffer,"{\n\"transaction_amount\":%s,\n\"audit_number\":%ld,\n\"pos_entry_mode\":\"%s\",\n\"account_number\":\"%s\",\n\"card_expiry_date\":\"%s\",\n\"terminal_id\":\"%s\",\n\"merchant_id\":\"%s\",\n\"sequence_number\":\"%s\"\n}",
			szAmtBuff,
			srTransRec.ulTraceNum,
			szPosEntry,
			srTransRec.szPAN,
			szTemp,
			srTransRec.szTID,
			srTransRec.szMID,
			srTransRec.szServiceCode);		
		#endif
		
	}
	else if (inType == POINTS_INQUIRY)
	{

		memset(szBcd, 0x00, sizeof(szBcd));
		memcpy(szBcd, strHDT.szTraceNo, INVOICE_BCD_SIZE);
		inBcdAddOne(szBcd, strHDT.szTraceNo, INVOICE_BCD_SIZE);	
		srTransRec.ulTraceNum = wub_bcd_2_long(strHDT.szTraceNo,3);

		inHDTSave(strHDT.inHostIndex);
	
        vdDebug_LogPrintf("pts inq test1");
        memset(szInvoiceNum, 0x00, sizeof(szInvoiceNum));
		memset(szInv, 0x00, sizeof(szInv));
        wub_hex_2_str(srTransRec.szInvoiceNo,szInv,INVOICE_BCD_SIZE);
		sprintf(szInvoiceNum,"%ld",atol(szInv));//remove leading zeros
		vdDebug_LogPrintf("pts inq test2");

		memset(szTemp, 0x00, sizeof(szTemp));
    	wub_hex_2_str(srTransRec.szExpireDate, szTemp,EXPIRY_DATE_BCD_SIZE);


		sprintf(szBuffer,"{\n\"merchant_id\":\"%s\",\n\"terminal_id\":\"%s\",\n\"invoice_number\":\"%s\",\n\"card_expiry_date\":\"%s\",\n\"pos_entry_mode\":\"%s\",\n \"audit_number\":\"%ld\",\n\"sequence_number\":\"%s\"\n}",
		srTransRec.szMID,
		srTransRec.szTID,
		//"test_merchant_id",
		//"test_merchant_location",
		szInvoiceNum,
		szTemp,
		szPosEntry,
		srTransRec.ulTraceNum,
		srTransRec.szServiceCode);

	}


	vdDebug_LogPrintf("REQUEST BODY %s :: len[%d]", szBuffer,strlen(szBuffer));
	
	vdDebug_LogPrintf("***inCreateBody END***");

	return d_OK;
}



int inCURLSend_request(struct MemoryStruct *contents,struct MemoryStruct *response, int TransType)
{
	CURL *curl;
    CURLcode res;
	static char errbuf[CURL_ERROR_SIZE];
	char postthis[2000];
	BYTE szHTTP[50 + 1] = {0};
	BYTE szEndPoint[200 + 1];
	BYTE szMethod[10 + 1] = {0};
	BYTE szContent[1000 + 1] = {0};
	BYTE szCURLURL[1000 + 1] = {0};
	BYTE szIPPort[50 + 1] = {0};
	BYTE szHeaderCacheControl[100 + 1] = {0};
	BYTE szHeaderContentType[100 + 1] = {0};
	BYTE szHeaderConnection[100 + 1] = {0};
	BYTE szAuthBasic[1000 + 1];
	BYTE szAuthBearer[1000 + 1];
	char encMessage [1000];
	char  *szEncB64Message;
	BYTE szRequest[3000+1] = {0};
	BYTE szResponse[3000+1] = {0};
	BYTE szCAFileName[30];
	BYTE szFileFullPath[32+1];
	int inFileSize = 0;
	char szProxyURL[30+1];
	char szContent_len[30+1];
	BOOL isProxy = TRUE;
	int inCPTIndex;
	
	CTOS_RTC SetRTC;
	char szTempDate[20];
	char szInvoiceNum[6+1];
	BYTE szInv[INVOICE_ASC_SIZE + 1] = {0};

	//testlang
	long response_code;
	BYTE szBalance[30+10];
	BYTE szTemp[30+10];
	char szHostDateAndTime[30];
	
	int inResult;
	BYTE uszSendData[ISO_SEND_SIZE + 1];

	
	struct curl_slist *headerlist = NULL;
	MemoryStruct write_data, read_data;
	
	vdDebug_LogPrintf("--inCURLSend_request--");
	vdDebug_LogPrintf("TransType=[%d]", TransType);

	BOOL fXMLPrint = (BOOL)get_env_int("XMLPRINT");

	vdDebug_LogPrintf("--inCURLSend_request--");
	vdDebug_LogPrintf("srTransRec.HDTid=[%d],strHDT.inHostIndex=[%d]", srTransRec.HDTid, strHDT.inHostIndex);
	vdDebug_LogPrintf("strCPT.inCommunicationMode[%d].srTransRec.usTerminalCommunicationMode[%d]", strCPT.inCommunicationMode, srTransRec.usTerminalCommunicationMode);
	vdDebug_LogPrintf("Primary[%s]port[%ld]",strCPT.szPriTxnHostIP,strCPT.inPriTxnHostPortNum);
	vdDebug_LogPrintf("Secondary[%s]port[%ld]",strCPT.szSecTxnHostIP,strCPT.inSecTxnHostPortNum);
	vdDebug_LogPrintf("SSL[%d]",strCPT.fSSLEnable);
	vdDebug_LogPrintf("fXMLPrint[%d]",fXMLPrint);

	memset(postthis, 0x00, sizeof(postthis));
	memset(szEndPoint, 0x00, sizeof(szEndPoint));
	memset(szHTTP, 0x00, sizeof(szHTTP));
	memset(szCURLURL, 0x00, sizeof(szCURLURL));
	memset(szIPPort, 0x00, sizeof(szIPPort));
	

	// Check PEM File
	if (strCPT.fSSLEnable == TRUE)
	{
		memset(szCAFileName, 0x00, sizeof(szCAFileName));
		sprintf(szCAFileName, "%s%s", CADIR, DEFAULT_CACERT);
		vdDebug_LogPrintf("szCAFileName[%s]", szCAFileName);

		memset(szFileFullPath, 0x00, sizeof(szFileFullPath));
		sprintf(szFileFullPath, "%s", szCAFileName);
		inFileSize = inGetCAFileSize(szFileFullPath);
		vdDebug_LogPrintf("CA File Full Path[%s] Size[%d]", szFileFullPath, inFileSize);
		vdDebug_LogPrintf("debug: verify peer");
		
	    if (inFileSize <= 0)    
	      vdDebug_LogPrintf("Cert file does not exist.");
	    else 
	    	vdDebug_LogPrintf("Cert file exist.");
	}
	
	write_data.memory = malloc(1); 
	write_data.size = 0;

	res = curl_global_init(CURL_GLOBAL_DEFAULT);
	vdDebug_LogPrintf("curl_global_init[%d]",res);
	/* Check for errors */
	if (res != CURLE_OK) {		
		vdDebug_LogPrintf("curl_global_init failed");	
		return d_OK;
	}
	vdDebug_LogPrintf("curl_global_init successful 1");

	if (TransType == REQUEST_ACCESS_TOKEN){
		// Set content
		strcpy(szContent, "grant_type=");
		strcat(szContent, "client_credentials");
		vdDebug_LogPrintf("szContent=[%s]", szContent);
	}else{
		memset(szContent, 0x00, sizeof(szContent));
		inCreateBody(szContent, TransType);
	//}else{
	//	memset(szContent, 0x00, sizeof(szContent));
	//	inCreateBody(szContent, SALE);

#ifdef BLT_REV_PFR

		//save to retrive batch - to be able to still retrive records during power fail and cancel

		if (TransType == SALE)
		{
			
			BYTE szGetInv[INVOICE_ASC_SIZE + 1] = {0};	
			int inRtrvOut;
			BYTE szExpiryDate[10];
			BYTE szPosEntry[3];
			

			
			memset(szPosEntry, 0x00, sizeof(szPosEntry));
			if (srTransRec.byEntryMode == CARD_ENTRY_MSR)
				strcpy(szPosEntry, "022");
			else if (srTransRec.byEntryMode == CARD_ENTRY_MANUAL)
				 strcpy(szPosEntry, "012");
			else if (srTransRec.byEntryMode == CARD_ENTRY_ICC)
				 strcpy(szPosEntry, "052");

			//vdDebug_LogPrintf("SAVE TO RTRV inPOSEntry is [%s]", szPosEntry);

		
			vdDebug_LogPrintf("ORIGINAL ulTraceNum:[%06ld]", srTransRec.ulTraceNum);

			memcpy(srPHQRRtrvTransRec.szBaseAmount, srTransRec.szBaseAmount, 6);
			memcpy(srPHQRRtrvTransRec.szInvoiceNo, srTransRec.szInvoiceNo, 3);
			srPHQRRtrvTransRec.ulTraceNum = srTransRec.ulTraceNum;

			memcpy(srPHQRRtrvTransRec.szTID, srTransRec.szTID, 8);
			memcpy(srPHQRRtrvTransRec.szMID, srTransRec.szMID, 15);

			memcpy(srPHQRRtrvTransRec.szPAN, srTransRec.szPAN, sizeof(srTransRec.szPAN));
			memcpy(srPHQRRtrvTransRec.szServiceCode, srTransRec.szServiceCode, 3);
			memcpy(srPHQRRtrvTransRec.byEntryMode, szPosEntry, 3);

			vdDebug_LogPrintf("SAVE TO RTRV byEntryMode:[%s]",srPHQRRtrvTransRec.byEntryMode);
			vdDebug_LogPrintf("SAVE TO RTRV **szTID[%s]..szMID=[%s]..",srPHQRRtrvTransRec.szTID,srPHQRRtrvTransRec.szMID);			
			vdDebug_LogPrintf("SAVE TO RTRV ulTraceNum:[%06ld]", srPHQRRtrvTransRec.ulTraceNum);
			vdDebug_LogPrintf("SAVE TO RTRV PAN:[%s]",srPHQRRtrvTransRec.szPAN);
			vdDebug_LogPrintf("SAVE TO RTRV szServiceCode/sequence_number:[%s]",srPHQRRtrvTransRec.szServiceCode);			
			vdDebug_LogPrintf("SAVE TO RTRV szBaseAmount[%02X%02X%02X%02X%02X%02X]", srPHQRRtrvTransRec.szBaseAmount[0], srPHQRRtrvTransRec.szBaseAmount[1], srPHQRRtrvTransRec.szBaseAmount[2], srPHQRRtrvTransRec.szBaseAmount[3], srPHQRRtrvTransRec.szBaseAmount[4], srPHQRRtrvTransRec.szBaseAmount[5]);
			vdDebug_LogPrintf("SAVE TO RTRV szInvoiceNo[%02X%02X%02X]", srPHQRRtrvTransRec.szInvoiceNo[0], srPHQRRtrvTransRec.szInvoiceNo[1], srPHQRRtrvTransRec.szInvoiceNo[2]);
			vdDebug_LogPrintf("inCreateBody > SAVE TO RTRV ExpDate[%s]",srPHQRRtrvTransRec.szExpireDate);
				
			wub_hex_2_str(srTransRec.szInvoiceNo, szGetInv, 3); 	
			vdDebug_LogPrintf("SAVE TO RTRV last inv num is [%s]", szGetInv);


			#if 1
			//put_env_charEx("PHQRLASTINV",szGetInv); 	
			//add for retrivelast
			put_env_int("QRLASTTXN",srTransRec.byTransType); 

			//put_env_int("PHQRLASTINV2", atoi(szGetInv));
			put_env("PHQRLASTINV2", szGetInv, strlen(szGetInv));


			//00144 - Asterisk “*” is missing in Clear Reversal
			//#ifdef BLT_REV_PFR
			#if 1
			if((inResult = inMyFile_ReversalSave(&uszSendData[0], 512)) != ST_SUCCESS)
			{
					vdDebug_LogPrintf(". inSave_inMyFile_ReversalSave(%04x)",inResult);
					//inCTOS_inDisconnect();
					//inResult = ST_ERROR;
			}	
			
			#endif		

			
			//put_env("PHQRLASTEXPDATE", szExpiryDate, strlen(szExpiryDate));

			inRtrvOut = inDatabase_BatchSaveRrtrieveDataPHQR(&srPHQRRtrvTransRec, DF_BATCH_APPEND);

			vdDebug_LogPrintf("SAVE TO RTRV RESULT inRtrvOut [%d]", inRtrvOut);
			
			if(inRtrvOut != ST_SUCCESS)
				return ST_ERROR;
			#endif

			
		}
#endif


	}

	curl = curl_easy_init();
	vdDebug_LogPrintf("curl_easy_init[%d]",curl);
	if (curl)
	{
		strcpy(szHTTP, "https://");
		//sprintf(szIPPort, "%s:%ld", strCPT.szPriTxnHostIP, strCPT.inPriTxnHostPortNum); // IP Base
		//sprintf(szIPPort, "%s", "api01.apigateway.sit.bdo.com.ph"); // URL Base
		//sprintf(szIPPort, "%s", "api08.apigateway.sit.bdo.com.ph"); // URL Base
		//sprintf(szIPPort, "%s", "23.8.151.228"); // IP Base
		//sprintf(szIPPort, "%s", strCPT.szPriTxnHostIP); // IP Base

		
		//for testing only 03112023
		#if 1
		sprintf(szIPPort, "%s", strLoyalty.BaseURL);
		#else
		sprintf(szIPPort, "%s", "api25.apigateway.uat.bdo.com.ph");

		#endif
		
		vdDebug_LogPrintf("ipport %s", szIPPort);

		memset(szEndPoint, 0x00, sizeof(szEndPoint));
		switch (TransType)
		{
			case REQUEST_ACCESS_TOKEN:
					strcpy(szEndPoint, strLoyalty.AccessTokenURL);
					vdDebug_LogPrintf("AccessTokenURL %s", szEndPoint);

					strcpy(szMethod, "POST");
				break;
			case POINTS_INQUIRY:
					//sprintf(szEndPoint, "%s%s", strLoyalty.PtsInquiryURL,"8880512877742439");
					sprintf(szEndPoint, "%s%s", strLoyalty.PtsInquiryURL,srTransRec.szPAN);
					strcpy(szMethod, "POST");
				break;
			case SALE:
					#if 0
					sprintf(szEndPoint, "/v1/perx/loyalty-transactions12");
					#else
					sprintf(szEndPoint, strLoyalty.RedemptionURL);
					#endif
					
					strcpy(szMethod, "POST");
				break;
			case REVERSAL:
        			memset(szInvoiceNum, 0x00, sizeof(szInvoiceNum));
					memset(szInv, 0x00, sizeof(szInv));
        			wub_hex_2_str(srTransRec.szInvoiceNo,szInv,INVOICE_BCD_SIZE);
					sprintf(szInvoiceNum,"%ld",atol(szInv));//remove leading zeros

					vdDebug_LogPrintf("reversal invoice %s", szInvoiceNum);

					sprintf(szEndPoint, "%s%s", strLoyalty.ReversalURL, szInvoiceNum);
					strcpy(szMethod, "PUT");


		}

		vdDebug_LogPrintf("szEndPoint=[%s]", szEndPoint);
		sprintf(szCURLURL, "%s%s%s",  szHTTP, szIPPort, szEndPoint); // URL
		vdDebug_LogPrintf("szCURLURL=[%s]", szCURLURL);
		curl_easy_setopt(curl, CURLOPT_URL,szCURLURL);
		
		/*inogre SSL verify*/
		if (strCPT.fSSLEnable == TRUE){
			vdDebug_LogPrintf("SSL enable");
			curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");			
			curl_easy_setopt(curl, CURLOPT_CAINFO, szFileFullPath);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
		    vdDebug_LogPrintf("SSL - skip certificate");
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
			//curl_easy_setopt(curl, CURLOPT_URL,szCURLURL);
		}

		vdDebug_LogPrintf("CURLOPT_CUSTOMREQUEST : szMethod[%s]", szMethod);
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, szMethod);

		memset(szHeaderCacheControl, 0x00, sizeof(szHeaderCacheControl));
		strcpy(szHeaderCacheControl, "Cache-Control: ");
		strcat(szHeaderCacheControl, szCacheControl);
		vdDebug_LogPrintf("szHeaderCacheControl %s",szHeaderCacheControl);

		memset(szHeaderConnection, 0x00, sizeof(szHeaderConnection));
		strcpy(szHeaderConnection, "Connection: ");
		strcat(szHeaderConnection, szConnection);
		vdDebug_LogPrintf("szHeaderConnection %s",szHeaderConnection);

		memset(szHeaderContentType, 0x00, sizeof(szHeaderContentType));
		strcpy(szHeaderContentType, "Content-Type: ");
		if (TransType == REQUEST_ACCESS_TOKEN)
			strcat(szHeaderContentType, szContentTypeFORM);
		else
			strcat(szHeaderContentType, szContentTypeJSON);
		
		vdDebug_LogPrintf("szHeaderContentType %s",szHeaderContentType);


		if (TransType == REQUEST_ACCESS_TOKEN){

			//COMPUTATTION FOR BASE64 
			//sprintf(encMessage, "%s:%s", "4jjSaOanJpmHiWB4DNfJywADvwQ9EQCARabpdzDWJkqk6OWl", "LI9UajfaSsTpbIjtrbZkw3glTDTwzR7QYH3qpi0i4snhPy9hTKoQghgmelhmATMh");
			//sprintf(encMessage, "%s:%s", "GeJG47zTcYapIoZdraXIownHIZLG4YlxgA5czNxWpkGNcaai", "qsXs6GD2g3Hfev6DCWY7GDh2xuEVAM4fZPbTHtPsuNDjD3XIPr0ocakoDZLxaoJw");

			//for testing only 03112023
			#if 1
			sprintf(encMessage, "%s:%s", strLoyalty.szAuthUserName, strLoyalty.szAuthPassword);
			#else
			sprintf(encMessage, "%s:%s", "BbUOy7f6WNAOVGpciAvKY2J2bgyhwiQnLqdh4CmPGy7Ov55w", "M8Gdbyo4DG9UC9onqaADCmcONJy93bGAe41v89lJm1Du866VzpmEBgFBAzgSiLWP");
			#endif

			vdDebug_LogPrintf("**** ATTEMPT message to encrypt - [%s] ",  encMessage);
			szEncB64Message = b64_encode((const unsigned char *)encMessage, strlen(encMessage));
			vdDebug_LogPrintf("**** ATTEMPT BASE64 format - [%s]", szEncB64Message);		
			//COMPUTATTION FOR BASE64 

			memset(szAuthBasic, 0x00, sizeof(szAuthBasic));
			strcpy(szAuthBasic, "Authorization: Basic ");
			strcat(szAuthBasic, szEncB64Message);
			vdDebug_LogPrintf("szAuthBasic %s",szAuthBasic);
		}else{
			memset(szAuthBasic, 0x00, sizeof(szAuthBasic));
			strcpy(szAuthBasic, "Authorization: Bearer ");
			strcat(szAuthBasic, szAccessToken);

		}

		// Set content
		//strcpy(szContent, "grant_type=");
		//strcat(szContent, "client_credentials");
		//vdDebug_LogPrintf("szContent=[%s]", szContent);

		//Set content length;		
		memset(szContent_len,0x00,sizeof(szContent_len));
		sprintf(szContent_len,"content-length: %d",strlen(szContent));
		vdDebug_LogPrintf("content-length: %d",strlen(szContent));	
		
		headerlist = curl_slist_append(headerlist,szHeaderCacheControl);
		//headerlist = curl_slist_append(headerlist,szHeaderConnection);
		//headerlist = curl_slist_append(headerlist, szContent_len);
		headerlist = curl_slist_append(headerlist,szHeaderContentType);
		headerlist = curl_slist_append(headerlist,szAuthBasic);
		vdDebug_LogPrintf("curl_slist_append data1=[%s]",headerlist->data);
		vdDebug_LogPrintf("curl_slist_append data2=[%s]",headerlist->next->data);
		vdDebug_LogPrintf("curl_slist_append data3=[%s]",headerlist->next->next->data);
		//vdDebug_LogPrintf("curl_slist_append data4=[%s]",headerlist->next->next->next->data);
		//vdDebug_LogPrintf("curl_slist_append data5=[%s]",headerlist->next->next->next->next->data);

		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
		curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");

		if (TransType == REQUEST_ACCESS_TOKEN)

		vdDebug_LogPrintf("DATA TO SEND %s",szContent);
		vdDebug_LogPrintf("POSTFIELDSIZE %li",(long)strlen(szContent));
		
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (char *)szContent);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(szContent));

		//}else{
		//vdDebug_LogPrintf("DATA TO SEND %s",szContent);
		//vdDebug_LogPrintf("POSTFIELDSIZE %li",(long)strlen(szContent));
		
		//curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (char *)szContent);
		//curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(szContent));

		//}

        //testlang-removelater
        //read_data.memory = malloc(1); 
		//read_data.size = 0;
		//memcpy(&read_data, szContent, strlen(szContent));


		/* we want to use our own read function */
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
		
		/* pointer to pass to our read function */
		curl_easy_setopt(curl, CURLOPT_READDATA, (void *)&read_data);
		
		/* send all data to this function  */
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
		
		/* we pass our 'chunk' struct to the callback function */
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&write_data);

		curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

		if (isProxy)
		{
		    inCPTRead(BDO_LOYALTY_HDT_INDEX);
			if (inCPTIndex == 1){
				sprintf(szProxyURL,"%s:%d",strCPT.szPriTxnHostIP, strCPT.inPriTxnHostPortNum);
				vdDebug_LogPrintf("testlang index 1 proxy %s", szProxyURL);
				vdDebug_LogPrintf("teslang %s-%d", strCPT.szPriTxnHostIP, strCPT.inPriTxnHostPortNum);
			}else{	
				sprintf(szProxyURL,"%s:%d",strCPT.szSecTxnHostIP, strCPT.inSecTxnHostPortNum);
				vdDebug_LogPrintf("testlang index 2 proxy %s", szProxyURL);
				
				vdDebug_LogPrintf("teslang %s-%d", strCPT.szSecTxnHostIP, strCPT.inSecTxnHostPortNum);
			}

			vdDebug_LogPrintf("proxy %s", szProxyURL);

			curl_easy_setopt(curl, CURLOPT_PROXY, szProxyURL);
		}
		


		//if (TransType == SALE){

		//curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT , 1L);
		//curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1L);
		//}else{
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT , 360L);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 360L);

		//}

		/* get it! */ 
		if (fXMLPrint) //5.	00166 (7 to 8 seconds white screen displayed on request after reversal approved displayed in BDO Loyalty
		{
			char szReqBuff[2000] = {0};

			vdDebug_LogPrintf("test szcontent %s",szContent);
			//strcpy(szReqBuff, szContent);
			memset(szReqBuff, 0x00, sizeof(szReqBuff));
			memcpy(szReqBuff, szContent, strlen(szContent));

			vdDebug_LogPrintf("szReqBuff %s", szReqBuff);
			vdDebug_LogPrintf("szReqBuff len %d", strlen(szReqBuff));

			inCurlPrintPacket("TX-LOYALTY BODY", szReqBuff, strlen(szReqBuff), TRUE);
			vdDebug_LogPrintf("TX-LOYALTY BODY");
		}

		res = curl_easy_perform(curl);	
		vdDebug_LogPrintf("curl_easy_perform res=[%d]",res);
		vdCTOS_DispStatusMessage("RECEIVING...");


#if 0
		if (fXMLPrint && (res == CURLE_OPERATION_TIMEDOUT || res == CURLE_OK))
		{
			char szReqBuff[2000] = {0};

			vdDebug_LogPrintf("test szcontent %s",szContent);
			//strcpy(szReqBuff, szContent);
			memset(szReqBuff, 0x00, sizeof(szReqBuff));
			memcpy(szReqBuff, szContent, strlen(szContent));

			vdDebug_LogPrintf("szReqBuff %s", szReqBuff);
			vdDebug_LogPrintf("szReqBuff len %d", strlen(szReqBuff));

			inCurlPrintPacket("TX-LOYALTY BODY", szReqBuff, strlen(szReqBuff), TRUE);
			vdDebug_LogPrintf("curle_operation_timeout");
		}
#endif

		if(res != CURLE_OK)
		{
			vdDebug_LogPrintf("NOT CURLE_OK!!! curl_easy_perform [%d][%s]", res, curl_easy_strerror(res));


			// ADDED display error - #3 related to 00206 - SM : Overlapping displayed in Redemption BDO Loyalty  and No error message displayed if host is down
			inResCurlFlag = res;

			vdDebug_LogPrintf("curl_easy_cleanup !!!");

			/* always cleanup */ 
			curl_easy_cleanup(curl);			

			vdDebug_LogPrintf("curl_slist_free_all !!!");
			/* cleanup headerlist */
			curl_slist_free_all(headerlist); /* free the list again */

			vdDebug_LogPrintf("free memory!!!");
			/* free memory */
			free(write_data.memory);
			//write_data.size = 0;

			vdDebug_LogPrintf("curl_global_cleanup !!!");
			/* we're done with libcurl, so clean it up */ 
			curl_global_cleanup();

			vdDebug_LogPrintf("curl_easy_reset !!!");
			/* reset all handle */
			curl_easy_reset(curl);
			
			vdDebug_LogPrintf("set to 0 !!!");
			//inRet = d_NO;

			vdDebug_LogPrintf("Exit encounter error!!!");



			//CTOS_Delay(1000);

			//return timeout - will be use to process reversal
			if (res == 28)
				return ST_RECEIVE_TIMEOUT_ERR;
			
			return(d_NO);

		}
		else
		{

			//00210 - SM: After host response Invalid Account, terminal displayed error again "Failure When Receiving Data from the Peer"in BDO Loyalty Redemption transaction
			inResCurlFlag = 0;
		
			vdDebug_LogPrintf("CURLE_OK!!!");
			vdDebug_LogPrintf("%lu bytes retrieved\n", (unsigned long)write_data.size);

    		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
			vdDebug_LogPrintf("curl get info %ld", response_code);

			memset(szResponse, 0x00, sizeof(szResponse));
			memcpy(szResponse, write_data.memory, write_data.size);
			//gtest
			//if (TransType == SALE){
			//	vdDebug_LogPrintf("transaction approved");
			//	memset(szResponse, 0x00, sizeof(szResponse));
			//	strcpy(szResponse,"{\"data\":{\"additional_data\":null,\"approval_code\":\"0001II\",\"audit_number\":9,\"cadencie_mid\":\"0000004444\",\"created_at\":\"2023-04-05 14:32:48\",\"merchant_id\":\"100000000001\",\"reference_number\":\"0001II230327\",\"response_code\":\"00\",\"terminal_id\":\"00100000\"},\"meta\":{}}");
			//	vdDebug_LogPrintf("response %s", szResponse);
			//}
			//endtest

			
			vdDebug_LogPrintf("Len[%d], szResponse=[%s]", write_data.size, response);

			vdDebug_LogPrintf("curl_easy_cleanup !!!");
			/* always cleanup */ 
			curl_easy_cleanup(curl);			
			
			vdDebug_LogPrintf("curl_slist_free_all !!!");
			/* cleanup headerlist */
			curl_slist_free_all(headerlist); /* free the list again */

			vdDebug_LogPrintf("free memory!!!");
			/* free memory */
			free(write_data.memory);
			write_data.size = 0;
			vdDebug_LogPrintf("curl_global_cleanup !!!");
			/* we're done with libcurl, so clean it up */ 
			curl_global_cleanup();

			vdDebug_LogPrintf("curl_easy_reset !!!");
			/* reset all handle */
			curl_easy_reset(curl);


            if (fXMLPrint == 1) //5.	00166 (7 to 8 seconds white screen displayed on request after reversal approved displayed in BDO Loyalty
			{
				char szReqBuff[2000] = {0};

				vdDebug_LogPrintf("test szResponse %s",szResponse);
				memset(szReqBuff, 0x00, sizeof(szReqBuff));
				memcpy(szReqBuff, szResponse, strlen(szResponse));

				vdDebug_LogPrintf("szReqBuff %s", szReqBuff);
				vdDebug_LogPrintf("szReqBuff len %d", strlen(szReqBuff));

				inCurlPrintPacket("RX-LOYALTY BODY", szReqBuff, strlen(szReqBuff), FALSE);
				vdDebug_LogPrintf("szResponse %s", szResponse);
            }

			//get date from response 
			memset(szHostDateAndTime, 0x00, sizeof(szHostDateAndTime));
			inExtractField(szResponse, szHostDateAndTime, "created_at");
			vdDebug_LogPrintf("created_at %s", szHostDateAndTime);


			if (strlen(szHostDateAndTime) > 0){
				memset(szTempDate, 0x00, sizeof(szTempDate));
				strncpy(szTempDate, &szHostDateAndTime[5],2);
				strncat(szTempDate, &szHostDateAndTime[8],2);
				wub_str_2_hex(szTempDate,srTransRec.szDate,4);

				memset(szTempDate, 0x00, sizeof(szTempDate));
				strncpy(szTempDate, &szHostDateAndTime[11],2);
				strncat(szTempDate, &szHostDateAndTime[14],2);
				strncat(szTempDate, &szHostDateAndTime[17],2);
				wub_str_2_hex(szTempDate,srTransRec.szTime,6);

			}else{
            	//set datetime
            	CTOS_RTCGet(&SetRTC);
				memset(szTempDate, 0x00, sizeof(szTempDate));
				sprintf(szTempDate ,"%02d%02d",SetRTC.bMonth, SetRTC.bDay);
				wub_str_2_hex(szTempDate,srTransRec.szDate,4);
				
				memset(szTempDate, 0x00, sizeof(szTempDate));
				sprintf(szTempDate ,"%02d%02d%02d",SetRTC.bHour,SetRTC.bMinute,SetRTC.bSecond);
				wub_str_2_hex(szTempDate,srTransRec.szTime,6);		
			}	

            
            vdDebug_LogPrintf("TransType %d", TransType);
			if (TransType == REQUEST_ACCESS_TOKEN){
				memset(szAccessToken, 0x00, sizeof(szAccessToken));
				inExtractField(szResponse, szAccessToken, "access_token");
				vdDebug_LogPrintf("szAccessToken = %s", szAccessToken);

			}

			if (TransType == POINTS_INQUIRY){
				memset(srTransRec.szRespCode, 0x00, sizeof(srTransRec.szRespCode));
				inExtractField(szResponse, srTransRec.szRespCode, "response_code");
				vdDebug_LogPrintf("PTS INQUIRY srTransRec.szRespCode = %s", srTransRec.szRespCode);

                //testlang
                //strcpy(srTransRec.szRespCode,"05");
                if (strcmp(srTransRec.szRespCode,"00") == 0){
					vdDebug_LogPrintf("approved");
					memset(szBalance, 0x00, sizeof(szBalance));
					//use inExtractFieldEx for numerix values from JSOn format
					inExtractFieldEx(szResponse, szBalance, "transaction_amount");
					
					vdDebug_LogPrintf("szBalance %s", szBalance);
					memset(szTemp, 0x00, sizeof(szTemp));
        			sprintf(szTemp, "%012.0f", atof(szBalance));

					wub_str_2_hex(szTemp,srTransRec.szTotalAmount,12);
					wub_str_2_hex(szTemp,srTransRec.szBaseAmount,12);
					return d_OK;
				}else{
					vdDebug_LogPrintf("not approved");
					inExtractField(szResponse, szTemp, "message");
					vdDebug_LogPrintf("messsage %s", szTemp);
					//vdDisplayErrorMsgResp2(" ", szTemp, "");
					vdClearBelowLine(2);
					CTOS_LCDTPrintXY(1, 5, szTemp);
					CTOS_Beep();
   					CTOS_Delay(2000);
   					CTOS_LCDTClearDisplay();

					return d_NO;
				}

			}

			if (TransType == SALE){
				vdDebug_LogPrintf("transaction SALE");
                //gtest
				//memset(szResponse, 0x00, sizeof(szResponse));
				//strcpy(szResponse,"{\"data\":{\"additional_data\":null,\"approval_code\":\"0001II\",\"audit_number\":9,\"cadencie_mid\":\"0000004444\",\"created_at\":\"2023-04-02T03:07:10.374Z\",\"merchant_id\":\"100000000001\",\"reference_number\":\"0001II230327\",\"response_code\":\"00\",\"terminal_id\":\"00100000\"},\"meta\":{}}");
				//vdDebug_LogPrintf("response %s", szResponse);
				//endtest

				
				memset(srTransRec.szRespCode, 0x00, sizeof(srTransRec.szRespCode));
				inExtractField(szResponse, srTransRec.szRespCode, "response_code");
				vdDebug_LogPrintf("SALE srTransRec.szRespCode = %s", srTransRec.szRespCode);

				if (strcmp(srTransRec.szRespCode,"00") == 0){

					
					BYTE szDateTime[19 + 1];

					//vdDisplayErrorMsgResp2(" ", "APPROVED", "");

					//00144 - Asterisk “*” is missing in Clear Reversal & 00177 - BDO Loyalty wherein the reversal was not cleared when performing Points Inquiry
					#ifdef BLT_REV_PFR
					//inResult = inMyFile_ReversalDelete();		
					//vdDebug_LogPrintf("inCURLSend_request inMyFile_ReversalDelete inRet %d", inResult);
					#endif

				    memset(srTransRec.szRRN, 0x00, sizeof(srTransRec.szRRN));
					inExtractField(szResponse, srTransRec.szRRN, "reference_number");

					memset(srTransRec.szAuthCode, 0x00, sizeof(srTransRec.szAuthCode));
					inExtractField(szResponse, srTransRec.szAuthCode, "approval_code");

					//00196 - Incorrect date and time printed on the transaction receipt. #1
					//memset(szDateTime,0x00,sizeof(szDateTime));
					//inExtractField(szResponse, srTransRec.szDateTimeLoy, "created_at");					
					//vdDebug_LogPrintf("SALE srTransRec.szDateTimeLoy = %s", srTransRec.szDateTimeLoy);
					
				}else{
					inExtractField(szResponse, szTemp, "message");
					//vdDisplayErrorMsgResp2(" ", szTemp, "");
					vdClearBelowLine(2);
					CTOS_LCDTPrintXY(1, 5, szTemp);
					CTOS_Beep();
   					CTOS_Delay(2000);
   					CTOS_LCDTClearDisplay();


					return d_NO;
				}


			}

			
			if (TransType == REVERSAL){			
				
				BYTE szCode[30+10];
				BYTE szMessage[30+10];

				memset(szCode,0x00,sizeof(szCode));
				memset(szMessage,0x00,sizeof(szMessage));
				
				memset(srTransRec.szRespCode, 0x00, sizeof(srTransRec.szRespCode));
				inExtractField(szResponse, srTransRec.szRespCode, "response_code");
				inExtractField(szResponse, szCode, "code");
				inExtractField(szResponse, szMessage, "message");
				
				vdDebug_LogPrintf("REVERSAL RESULT : srTransRec.szRespCode = %s szCode = %s szMessage = %s", srTransRec.szRespCode, szCode, szMessage);

				
				if (strcmp(srTransRec.szRespCode,"00") != 0)
				{
					// fix for {"code":"bdo-07","message":"Invoice number mismatch"}, unable to proceed with points inquiry and redemption.					
					// fix for {"code":"bdo-08","message":"Audit number mismatch"}, unable to proceed with points inquiry and redemption.
					if (strcmp(szCode,"bdo-07") == 0 || strcmp(szCode,"bdo-08") == 0){
						
						vdDebug_LogPrintf("inCURLSend_request REVERSAL RESULT HERE!!!");			
						inDatabase_PHQRBatchDeleteRetrieveData();	
					}

					inExtractField(szResponse, szMessage, "message");
					vdClearBelowLine(2);
					CTOS_LCDTPrintXY(1, 5, szMessage);
					CTOS_Beep();
   					CTOS_Delay(2000);
   					CTOS_LCDTClearDisplay();
					
					
					vdDebug_LogPrintf("inCURLSend_request REVERSAL RESULT UNSUCCESSFUL");			
					return d_NO;
				}
				else{
					vdDebug_LogPrintf("inCURLSend_request REVERSAL RESULT SUCCESSFUL");	
					//vdDisplayErrorMsgResp2("REVERSAL", "APPROVED", "");
				}

			}

		}

		
	}
	
	return d_OK;
}

int inRequestAccessToken(void)
{
	int inRet = d_NO;
	MemoryStruct write_data, read_data;

	vdDebug_LogPrintf("--inRequestAccessToken--");
	
	inRet = inCURLSend_request(&read_data,&write_data, REQUEST_ACCESS_TOKEN);

	vdDebug_LogPrintf("after --inRequestAccessToken--");
	
	return d_OK;
}

int inCurl_CommsInit(void)
{

	int inRetVal; 

	vdDebug_LogPrintf("--inCurl_CommsInit--");

	inCPTRead(srTransRec.HDTid);

	vdDebug_LogPrintf("srTransRec.HDTid=[%d]", srTransRec.HDTid);
	vdDebug_LogPrintf("strCPT.inCommunicationMode[%d]",strCPT.inCommunicationMode);
	vdDebug_LogPrintf("SSL[%d]",strCPT.fSSLEnable);
	vdDebug_LogPrintf("fShareComEnable[%d]", strTCT.fShareComEnable);
	vdDebug_LogPrintf("inIPHeader[%d]", strCPT.inIPHeader);
	vdDebug_LogPrintf("Primary[%s]port[%ld]",strCPT.szPriTxnHostIP,strCPT.inPriTxnHostPortNum);
	vdDebug_LogPrintf("Secondary[%s]port[%ld]",strCPT.szSecTxnHostIP,strCPT.inSecTxnHostPortNum);
	vdDebug_LogPrintf("fDHCPEnable[%d]", strTCP.fDHCPEnable);
	vdDebug_LogPrintf("szAPN[%s].szUserName[%s].szPassword[%s]", strTCP.szAPN, strTCP.szUserName, strTCP.szPassword);

	srTransRec.usTerminalCommunicationMode = strCPT.inCommunicationMode;

    if (inCTOS_InitComm(srTransRec.usTerminalCommunicationMode) != d_OK) 
    {
        //vdSetErrorMessage("COMM INIT ERR");
        //vdDisplayErrorMsgResp2(" ", " ", "COMM INIT ERR");
		vdDisplayErrorMsgResp2("","Initialization","Error");
		vdSetErrorMessage("");
		vdDebug_LogPrintf("Initialization error - inCTOS_InitComm");
        return(d_NO);
    }

    inRetVal = inCTOS_CheckInitComm(srTransRec.usTerminalCommunicationMode); 

	if (inRetVal != d_OK)
	{
		if (srTransRec.usTerminalCommunicationMode == GPRS_MODE)
		{
			vdDisplayErrorMsgResp2(" ", "GPRS Problem","Please Try Again");
			vdSetErrorMessage("");
		}
		//wifi-mod2
		else if (srTransRec.usTerminalCommunicationMode == WIFI_MODE)		
		{
			vdDisplayErrorMsgResp2(" ", "WIFI Problem","Please Try Again");
			vdSetErrorMessage("");
		}
		//wifi-mod2
		else
		{
			//vdDisplayErrorMsgResp2(" ", " ", "COMM INIT ERR");
			vdDisplayErrorMsgResp2("","Initialization","Error");
			
			vdDebug_LogPrintf("Initialization error - inCTOS_CheckInitComm");
			vdSetErrorMessage("");
		}
	
		return(d_NO);
	}

	srCommFuncPoint.inConnect(&srTransRec);

	return d_OK;
}

int inGetCAFileSize(const char *szFileName)
{
	FILE *pFile = NULL;
	int inSize = 0;
	
	pFile = fopen(szFileName, "rb");
	if (pFile == NULL)
		return -1;
	
	fseek(pFile, 0, SEEK_END);
	inSize=ftell(pFile);
	fclose(pFile);
	
	return inSize;
}



int InDisplayLoyaltyBalance(void){

	char szAmount[12+1];
	char szStr[12+1];

	vdDebug_LogPrintf("-->>InDisplayBalance[START]");

	CTOS_LCDTClearDisplay();
	vdDispTransTitle(POINTS_INQUIRY);

	CTOS_LCDTPrintXY(1, 3, "APPROVED");
	CTOS_LCDTPrintXY(1, 4, "BAL:");

    wub_hex_2_str(srTransRec.szTotalAmount, szAmount, AMT_BCD_SIZE);      
    memset(szStr, 0x00, sizeof(szStr));
    sprintf(szStr, "%lu.%02lu", atol(szAmount)/100, atol(szAmount)%100);
    setLCDPrint(6, DISPLAY_POSITION_LEFT, strCST.szCurSymbol);
    CTOS_LCDTPrintXY(MAX_CHAR_PER_LINE-(strlen(szStr)+1)*2,  6, szStr);


	CTOS_LCDTPrintXY(1,8,"PRESS ANY KEY");
	WaitKey(10);
	//vduiPressAnyKey();

	vdDebug_LogPrintf("-->>InDisplayBalance[END]");
	
	return d_OK;



}



int inExtractFieldEx(unsigned char *uszRecData, char *szField, char *szSearchString){
	char *ptr;
 	char szWorkBuff1[4096+1];
 	char szWorkBuff2[4096+1];
 	char szSearchToken[2];
 	int i;
	char ch;
	int x;
	BYTE szBuffer[50];


	vdDebug_LogPrintf("inExtractField");

	//vdDebug_LogPrintf("extract field %s", uszRecData);

 	memset(szSearchToken, 0x00, sizeof(szSearchToken));
 	szSearchToken[0] = '"';
 	memset(szWorkBuff1, 0x00, sizeof(szWorkBuff1));
 	ptr = NULL;
 	strcpy(szWorkBuff1,uszRecData);
 	ptr =strstr(szWorkBuff1, szSearchString);

    if (ptr == NULL)
		{
			vdDebug_LogPrintf("inExtractField  NULL");
			
			return FAIL;
   	 	}
	
 	memset(szWorkBuff2, 0x00, sizeof(szWorkBuff2));
 	strcpy(szWorkBuff2, ptr);

	vdDebug_LogPrintf("search token %s", szSearchToken);
	vdDebug_LogPrintf("szWorkBuff1 %s", szWorkBuff1);
	vdDebug_LogPrintf("szWorkBuff2 %s", szWorkBuff2);



    //for (i = 1; i<3; i++){


		vdDebug_LogPrintf("inExtractField  --- i [%d]", i);
			
  		memset(szWorkBuff1, 0x00, sizeof(szWorkBuff1));
  		ptr = NULL;
  		strcpy(szWorkBuff1, szWorkBuff2);
		
  
  		ptr =strstr(szWorkBuff1, szSearchToken);
		vdDebug_LogPrintf("szWorkBuff1 %s", szWorkBuff1);
  
 		memset(szWorkBuff2, 0x00, sizeof(szWorkBuff2));
  		strcpy(szWorkBuff2, ptr+2);
		vdDebug_LogPrintf("test szWorkBuff2 %s", szWorkBuff2);

		
  
    //}
    //limit field size to 20, adjust if needed
    x=0;
	memset(szBuffer, 0x00, sizeof(szBuffer));
	for (i=0; i<21; i++){
		ch=0;
		ch = szWorkBuff2[i];
		memset(szField, 0x00, sizeof(szField));
		vdDebug_LogPrintf("szWorkBuff2[i] = %c ", szWorkBuff2[i]);
		
		//if(ch>0x29 && ch<0x40 )
		if (ch=='0' || ch=='1' || ch=='2' || ch=='3' || ch=='4' || ch=='5'
			|| ch=='6' || ch=='7' || ch=='8' || ch=='9'){ 
			vdDebug_LogPrintf("copy character");
			szBuffer[x] = ch;
			vdDebug_LogPrintf("szField after copy %s ", szBuffer);
			x++;
		}
		

	}
 	strcpy(szField, szBuffer);

 
 	vdDebug_LogPrintf("szField %s ", szField);

	return d_OK;
}


// ADDED display error - #3 related to 00206 - SM : Overlapping displayed in Redemption BDO Loyalty  and No error message displayed if host is down
void vdDisplayCurlErrorMsg()
{


	vdDebug_LogPrintf("vdDisplayCurlErrorMsg inResCurlFlag [%d]", inResCurlFlag); 	

	//for testing
	//vdSetErrorMessage(curl_easy_strerror(res));
	switch(inResCurlFlag)
	{
		case 7:
			vdDisplayErrorMsgResp2("COULDN'T", "CONNECT", "TO SERVER");
			break;
		case 56:
			vdDisplayErrorMsgResp2("FAILURE WHEN", "RECEIVING DATA", "FROM THE PEER");
			break;
		default:
			vdDisplayErrorMsgResp2("CONNECT", "FAILED", "");	
			break;
			
	}

return;
}
