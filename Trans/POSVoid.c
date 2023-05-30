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
#include "..\Includes\POSSale.h"
#include "..\Includes\POSbatch.h"
#include "..\ui\Display.h"
#include "..\Includes\V5IsoFunc.h"
#include "..\Accum\Accum.h"
#include "..\print\Print.h"
#include "..\Comm\V5Comm.h"
#include "..\Includes\MultiApLib.h"
#include "..\Aptrans\MultiAptrans.h"
#include "..\POWRFAIL\POSPOWRFAIL.h"
#include "..\Debug\Debug.h"


//enhance ecr
extern BOOL fECRTxnFlg;

/* For ECR -- sidumili */
extern BOOL fECRBuildSendOK; 
extern BOOL fTimeOutFlag; /*BDO: Flag for timeout --sidumili*/
/* For ECR -- sidumili */

extern VS_BOOL fPreConnectEx;
extern int inReversalType;

int inCTOS_VoidFlowProcess(void)
{
    int inRet = d_NO;

	fECRBuildSendOK = FALSE; /* BDO: For ECR -- sidumili */
	fTimeOutFlag = FALSE; /*BDO: Flag for timeout --sidumili*/
    vdCTOS_SetTransType(VOID);
    
    //display title
    vdDispTransTitle(VOID); 

    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;
		
    inRet = inCTOS_CheckTranAllowd();
    if(d_OK != inRet)
        return inRet;

    //if ((strTCT.fSingleComms) && (fPreConnectEx == FALSE) || (srTransRec.usTerminalCommunicationMode != WIFI_MODE)){ 
    if((strTCT.fSingleComms) && ((fPreConnectEx == FALSE) || (srTransRec.usTerminalCommunicationMode != GPRS_MODE)|| (srTransRec.usTerminalCommunicationMode != WIFI_MODE))){
		    inRet = inCTOS_PreConnectEx();

		if (inRet != d_OK)
			return inRet;
	}

	while(1)
	{
	    inRet = inCTOS_GeneralGetInvoice();
	    if(d_EDM_USER_CANCEL == inRet)
	        return inRet;

	    if (inMultiAP_CheckMainAPStatus() == d_OK)
	    {
	        inRet = inCTOS_MultiAPBatchSearch(d_IPC_CMD_VOID_SALE);
			vdDebug_LogPrintf("inCTOS_MultiAPBatchSearch, inRet=[%d]", inRet);

			if(d_NOT_RECORD == inRet || d_NOT_ALLOWED == inRet)
			{
			    
				if (srTransRec.HDTid == 117)
					return inRet;
				
				if(fGetECRTransactionFlg() == TRUE)
					return inRet;
				else
					continue;
			}
	        else if(d_OK != inRet)
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
			if(d_NOT_RECORD == inRet)
			{
				if(fGetECRTransactionFlg() == TRUE)
					return inRet;
				else
					continue;
			}
	        else if(d_OK != inRet)
	            return inRet;

	    }

		srTransRec.usTerminalCommunicationMode = strCPT.inCommunicationMode;//If Sale used Comms Fallback, need to set srTransRec.usTerminalCommunicationMode to value in CPT.
		
		memcpy(srTransRec.szTempTime, srTransRec.szTime, TIME_BCD_SIZE); /*get original time*/
		
	    inRet = inCTOS_CheckVOID();
	    if(d_OK != inRet)
	    {
			if (fGetECRTransactionFlg() == TRUE)
			{
			    strcpy(srTransRec.szRespCode,"");
				strcpy(srTransRec.szECRRespCode, ECR_OPER_CANCEL_RESP);
				return inRet;
			}
			else
			{
				vdCTOS_SetTransType(VOID);//Set transtype to void to fix issue where void header is overwritten by CARD VER/BAL INQ.
				if(srTransRec.fOptOut == TRUE)//If invoice trying to void is optout but already voided, set to false to as not display the header as OPT OUT
					srTransRec.fOptOut = FALSE;
				continue;
			}
	    }
		else
			break;

	}

	//version16
	//if (srTransRec.byTransType == VOID_PREAUTH)
	//    vdDispTransTitle(VOID_PREAUTH); 
	//version16


	if(inCheckSMACPayVoid(&srTransRec) == TRUE)
		vdLoadSMACPayCardDetails();


    //version16
    vdDebug_LogPrintf("smac scan %d", srTransRec.byEntryMode);
    if (srTransRec.byEntryMode == SMAC_SCAN){
		if (inIITRead(srTransRec.IITid) != d_OK)
		{
        	vdDebug_LogPrintf("inCTOS_LoadCDTandIIT LOAD IIT ERROR [%d]", srTransRec.IITid);
			vdSetErrorMessage("LOAD IIT ERROR");
			inDatabase_TerminalCloseDatabase();
			return(d_NO);
    	}
    }else{
    	inRet = inCTOS_LoadCDTandIIT();
    	if(d_OK != inRet)
        	return inRet;
    }

    inRet = inCTOS_VoidSelectHostNoPreConnect();
    if(d_OK != inRet)
        return inRet;

	//if(strTCT.fATPBinRoute == TRUE && srTransRec.HDTid == 1 && srTransRec.fDualBrandedCredit == FALSE)//Use ATPBinRouting NII if ATPBinRoute is enabled for void.
	if(srTransRec.fBINRouteApproved == TRUE && srTransRec.HDTid == 1 && srTransRec.fDualBrandedCredit == FALSE)//Use ATPBinRouting NII if ATPBinRoute is enabled for void.
		memcpy(strHDT.szTPDU,strTCT.ATPTPDU,5);

    inRet = inCTOS_CheckMustSettle();
    if(d_OK != inRet){
		
		//if (fGetECRTransactionFlg() == TRUE){
		    //strcpy(srTransRec.szRespCode,"");
			//strcpy(srTransRec.szECRRespCode, ECR_OPER_CANCEL_RESP);
		//}
			
        return inRet;

    }
    
    inRet = inCTOS_ConfirmInvAmt();
    if(d_OK != inRet){		
		    strcpy(srTransRec.szRespCode,"");
			strcpy(srTransRec.szECRRespCode, ECR_OPER_CANCEL_RESP);		
        return inRet;

    }

	//if ((strTCT.fSingleComms != TRUE) || (srTransRec.usTerminalCommunicationMode == WIFI_MODE)){	
	if ((strTCT.fSingleComms != TRUE) || (srTransRec.usTerminalCommunicationMode == WIFI_MODE) || (srTransRec.usTerminalCommunicationMode == GPRS_MODE)){
		inRet = inCTOS_PreConnect();
		if(d_OK != inRet)
			return inRet;
	}

	if(inCheckIfSMCardTransRec() == TRUE)//Set the below values before voiding for the handling of card name and balance on void printing.
	{
		srTransRec.fPrintSMCardHolder = FALSE;
		srTransRec.fPrintCardHolderBal = FALSE;
		memset(srTransRec.SmacBalance,0x00,sizeof(srTransRec.SmacBalance));
		memset(srTransRec.szSMACBDORewardsBalance,0x00,sizeof(srTransRec.szSMACBDORewardsBalance));
	}
	
    inRet = inBuildAndSendIsoData();
    if(d_OK != inRet){

		/*BDO: Set ECR response code to EN - COMM ERROR -- sidumili*/
		if ((strlen(srTransRec.szRespCode) <= 0) || (srTransRec.shTransResult == TRANS_TERMINATE)){
			strcpy(srTransRec.szRespCode,"");
			strcpy(srTransRec.szECRRespCode, ECR_COMMS_ERR);
		}
		
		return inRet;
    }

	//vdUpdateSMACAmount(); /*BDO: For SMAC which not save the DE04 response due its smac amount balance*/

    if(memcmp(srTransRec.szTempTime, srTransRec.szTime, TIME_BCD_SIZE) == 0) /*if time are the same it means there is no DE12 receive, get new date and time*/
        vdGetTimeDate(&srTransRec);
	
    inRet = inCTOS_SaveBatchTxn();
    if(d_OK != inRet)
        return inRet;

	//if(strTCT.fDCC && srTransRec.fDCC)
	//{ 		
		//inMyFile_TransLogSave(&srTransRec, DCC_LOGGING);
	//} 

    inRet = inCTOS_UpdateAccumTotal();
    if(d_OK != inRet)
        return inRet;

	// patrick add code 20141205 start, modified -- sidumili
	fECRBuildSendOK = TRUE;	
	if (fECRBuildSendOK){	
	    inRet = inMultiAP_ECRSendSuccessResponse();
	}
	// patrick add code 20141205 start, modified -- sidumili


	inRet=inDisconnectVoidIfNoPendingADVICEandUPLOAD(&srTransRec, strHDT.inNumAdv);

	if(inCheckSMACPayVoid(&srTransRec) == TRUE)
	{
		inRet = inWriteMifareCardFields();
		if(d_OK != inRet)
			vdDisplayErrorMsgResp2("","CARD NOT","UPDATED");


	}
	
    inRet = ushCTOS_printReceipt();
    if(d_OK != inRet)
        return inRet;
    else
        vdSetErrorMessage("");

    inCTLOS_Updatepowrfail(PFR_IDLE_STATE);

    if (!srTransRec.byOffline)
    {
        CTOS_LCDTClearDisplay();

		if(strTCT.fDCC && srTransRec.fDCC)
        {

            inRet=inProcessTransLogTrans(&srTransRec, 1, 2, GET_ALL_EXCEPT_TIP);
            if(d_OK != inRet)
                return inRet;
            else
                vdSetErrorMessage("");
		}

        inRet=inProcessAdviceTrans(&srTransRec, strHDT.inNumAdv);
        if(d_OK != inRet)
            return inRet;
        else
            vdSetErrorMessage("");
		
        if(strTCT.fDCC && srTransRec.fDCC)
        {
#if 0
            inRet=inProcessTransLogTrans(&srTransRec, 1, 2, GET_ALL_EXCEPT_TIP);
            if(d_OK != inRet)
                return inRet;
            else
                vdSetErrorMessage("");
#endif            
            inRet=inProcessTransLogTrans(&srTransRec, 1, 2, GET_TIP_ONLY);
            if(d_OK != inRet)
                return inRet;
            else
                vdSetErrorMessage("");
        }
    }
	
    return d_OK;
}

int inCTOS_VOID(void)
{
    int inRet = d_NO;
    
    CTOS_LCDTClearDisplay();

    
    vdCTOS_TxnsBeginInit();

    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiStopResumeAP("SHARLS_ECRBDO");
    
    inRet = inCTOS_VoidFlowProcess();
    
    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiResumeContinueAP("SHARLS_ECRBDO");
	
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
