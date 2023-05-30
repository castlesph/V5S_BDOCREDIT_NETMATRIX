/*******************************************************************************

*******************************************************************************/

#include <string.h>
#include <stdio.h>
#include <ctosapi.h>
#include <stdlib.h>
#include <stdarg.h>
#include <typedef.h>


#include "..\Includes\POSTypedef.h"


#include "..\Includes\POSMain.h"
#include "..\Includes\POSTrans.h"
#include "..\Includes\POSHost.h"
#include "..\Includes\POSTipAdjust.h"
#include "..\Includes\POSbatch.h"
#include "..\Includes\V5IsoFunc.h"
#include "..\ui\Display.h"
#include "..\accum\accum.h"
#include "..\print\Print.h"
#include "..\Comm\V5Comm.h"
#include "..\Includes\MultiApLib.h"
#include "..\Aptrans\MultiAptrans.h"
#include "..\debug\debug.h"

extern BOOL fECRBuildSendOK;

int inCTOS_TipAdjustFlowProcess(void)
{
    int inRet = d_NO,
	inResult = 0;
	BYTE szTipAmountTemp[AMT_BCD_SIZE + 1]={0};


    vdCTOS_SetTransType(SALE_TIP);
    
    //display title
    vdDispTransTitle(SALE_TIP); 

    inRet = inCTOS_CheckTipAllowd();
    if(d_OK != inRet)
        return inRet;
       
    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_CheckTranAllowd();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_GeneralGetInvoice();
    if(d_OK != inRet)
        return inRet;

	//save tipamount from ECR since it will be cleared by inCTOS_MultiAPBatchSearch.
	if(fGetECRTransactionFlg() == TRUE)
		memcpy(szTipAmountTemp,srTransRec.szTipAmount,AMT_BCD_SIZE);
	
    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        inRet = inCTOS_MultiAPBatchSearch(d_IPC_CMD_TIP_ADJUST);
        if(d_OK != inRet)
            return inRet;

    }
    else
    {
        if (inMultiAP_CheckSubAPStatus() == d_OK)
        {
            inRet = inCTOS_MultiAPGetVoid();
            if(d_OK != inRet)
                return inRet;
        }       
        inRet = inCTOS_BatchSearch();
        if(d_OK != inRet)
            return inRet;
    }

	//srTransRec.byUploaded = CN_FALSE;
	
	inRet = inCTOS_CheckHOSTTipAllowd();	
	if(d_OK != inRet)
		return inRet;

    inRet = inCTOS_CheckTipadjust();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_LoadCDTandIIT();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_VoidSelectHostNoPreConnect();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_CheckMustSettle();
    if(d_OK != inRet)
        return inRet;

   
    inRet = inCTOS_ConfirmInvAmt();
    if(d_OK != inRet)
        return inRet;

/*		
		inRet=inCTOS_PreConnect();
    if(d_OK != inRet)
        return inRet;
*/
	if(fGetECRTransactionFlg() == TRUE)	//get tipamount from ECR.
	{
		memset(srTransRec.szTipAmount,0x00,sizeof(srTransRec.szTipAmount));
		memcpy(srTransRec.szTipAmount, szTipAmountTemp,AMT_BCD_SIZE);
	}
	else
	{
	    inRet = inCTOS_GetTipAfjustAmount();
	    if(d_OK != inRet)
	    	return inRet;			    
	}
	
    inRet = inCTOS_UpdateTxnTotalAmount();
    if(d_OK != inRet)
        return inRet;

    inRet = inBuildAndSendIsoData();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_SaveBatchTxn();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_UpdateAccumTotal();
    if(d_OK != inRet)
        return inRet;

	fECRBuildSendOK = TRUE;	
	if (fECRBuildSendOK){	
	    inRet = inMultiAP_ECRSendSuccessResponse();
	}
	
		/*sidumili: Fix on Issue#: 000181*/
		if (strTCT.fPrintTipReceipt){
				inRet = ushCTOS_printReceipt();
				if(d_OK != inRet)
    		    return inRet;
    		else
    		    vdSetErrorMessage("");
		}else{
				CTOS_LCDTPrintXY(1, 8, "TIP ADJUST SUCCESS");
				CTOS_Delay(1000);
				inRet = d_OK;
		}

		//BDO: Should be able to reprint TIP ADJ txn even when tip adj receipt printing is off - start -- jzg
		memcpy(strTCT.szLastInvoiceNo,srTransRec.szInvoiceNo,INVOICE_BCD_SIZE);
		
		if((inResult = inTCTSave(1)) != ST_SUCCESS)
			vdDisplayErrorMsg(1, 8, "Update TCT fail");
		//BDO: Should be able to reprint TIP ADJ txn even when tip adj receipt printing is off - start -- jzg
    
    return d_OK;
}

int inCTOS_TIPADJUST(void)
{
    int inRet = d_NO;
    
    CTOS_LCDTClearDisplay();
    
    vdCTOS_TxnsBeginInit();

    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiStopResumeAP("SHARLS_ECRBDO");
    
    inRet = inCTOS_TipAdjustFlowProcess();
	if(inRet != d_OK)
	   	vdSetECRResponse(ECR_OPER_CANCEL_RESP);
	
    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiResumeContinueAP("SHARLS_ECRBDO");

	/* Send response to ECR -- sidumili */
	if (!fECRBuildSendOK){	
		inMultiAP_ECRSendSuccessResponse();
	}

	fECRBuildSendOK = FALSE;
		
    inCTOS_inDisconnect();

    vdCTOS_TransEndReset();

    return inRet;
}


int inCTOS_CheckHOSTTipAllowd(void)
{   
#if 1
	/* BDO: Tip Allow flag moved to HDT - start -- jzg */
	inHDTRead(srTransRec.HDTid);

	if(strHDT.fHDTTipAllow != TRUE)
	{
		//vdSetErrorMessage("TIP NOT ALLOWED");
		CTOS_LCDTClearDisplay();
		vdDisplayErrorMsgResp2(" ", "TIP", "NOT ALLOWED");
		return d_NO;
	}
	else
		return d_OK;
	/* BDO: Tip Allow flag moved to HDT - end -- jzg */
#else
    // allow only tip for bdo, amex, bpi, diners and bankard
	if ((srTransRec.HDTid == 1) || (srTransRec.HDTid == 2) || (srTransRec.HDTid == 3) ||(srTransRec.HDTid == 4) ||(srTransRec.HDTid == 6) ||(srTransRec.HDTid == 23) ||(srTransRec.HDTid == 24)){    
		return d_OK;
	}else{
		vdSetErrorMessage("TIP NOT ALLOWED");
		return d_NO;
	}
#endif
}


