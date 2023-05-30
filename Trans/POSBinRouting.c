/*******************************************************************************

*******************************************************************************/

#include <string.h>
#include <stdio.h>
#include <ctosapi.h>
#include <stdlib.h>
#include <stdarg.h>
#include <typedef.h>
#include <EMVAPLib.h>
#include <EMVLib.h>
#include <EMV_cl.h>


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
#include "..\POWRFAIL\POSPOWRFAIL.h"


//gcitra
#include "..\Includes\CTOSInput.h"
#include "..\Includes\ISOEnginee.h"
//gcitra
extern BOOL fECRBuildSendOK; 

extern BOOL fRouteToSpecificHost;

//extern int inHostOrigNumber;
extern BOOL fnGlobalOrigHostEnable;
int inAMEXMITNumber;

BOOL fAMEXHostEnable;
BOOL fDinersHostEnable;

extern BOOL fUSDSelected;

extern BOOL fSkipBINRoutingForDebit;
extern BOOL fSkipBINRoutingForCUP;

static int ginATPBinRoute = 0;
extern BOOL fSmacScan;

void vdSetATPBinRouteFlag(int flag)
{
	ginATPBinRoute = flag;
}

int inGetATPBinRouteFlag(void)
{
	return ginATPBinRoute;
}


int inCTOSS_CheckCTLSEMVCard(void)
{
#if 0	//Removed due to change of handling on CTLS on BIN Routing
	vdDebug_LogPrintf("inCTOSS_CheckCTLSEMVCard,byEntryMode=[%d],bWaveSID=[%d]",srTransRec.byEntryMode,srTransRec.bWaveSID);
	if (srTransRec.byEntryMode == CARD_ENTRY_WAVE &&
		(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_2 ||
		 srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC ||
		 srTransRec.bWaveSID == d_VW_SID_AE_EMV ||
		 srTransRec.bWaveSID == d_VW_SID_CUP_EMV ||		 
		 srTransRec.bWaveSID == 0x63 || //JSPEEDY
		 srTransRec.bWaveSID == 0x65 || //JSPEEDY
		 srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP))
			 return VS_CONTINUE;
#endif


	//if (srTransRec.byEntryMode == CARD_ENTRY_ICC && strCDT.HDTid == 36)
	//	return VS_CONTINUE;

	if (strCDT.fPANCatchAll == VS_FALSE)
		return VS_CONTINUE;


	if (fSkipBINRoutingForDebit == TRUE){
		strCDT.HDTid = 53;	
		srTransRec.inCardType = DEBIT_CARD;
		srTransRec.IITid = 1;	
		inIITRead(srTransRec.IITid);
		strcpy(srTransRec.szCardLable, strIIT.szIssuerLabel);
		return VS_CONTINUE;
	}

	if (fSkipBINRoutingForCUP == TRUE){
		strCDT.HDTid = 36;	
		srTransRec.IITid = 9;
		inIITRead(srTransRec.IITid);
		strcpy(srTransRec.szCardLable, strIIT.szIssuerLabel);
		return VS_CONTINUE;
	}

	return d_OK;
}



int inCTOSS_ATPBinRoutingProcess(void)
{
    int inRet = d_NO;
	TRANS_DATA_TABLE srtmpTransRec;
	int inOrigMITNumber;

	//version16
    BYTE szQrCodeText[200];
	BYTE szBuffer [50];
	//version16


	inRet = inCTOSS_CheckCTLSEMVCard();
    if(d_OK != inRet)
        return inRet;

	memset(&srtmpTransRec,0x00,sizeof(TRANS_DATA_TABLE));
	memcpy(&srtmpTransRec,&srTransRec,sizeof(TRANS_DATA_TABLE));

	//inHostOrigNumber = inCheckIfHostEnable(strCDT.HDTid);



    //CHECK IF AMEX HOST ENABLE
	if (inCheckIfHostEnable(2) != 0 )
		fAMEXHostEnable = TRUE;
	else
		fAMEXHostEnable = FALSE;

	if (inCheckIfHostEnable(59) != 0 )
		fDinersHostEnable = TRUE;
	else
		fDinersHostEnable = FALSE;
	
#if 0
	vdDebug_LogPrintf("fAMEXHostEnableTEST %d", fAMEXHostEnable);
	//vdDebug_LogPrintf("fnGlobalOrigHostEnable %d", fnGlobalOrigHostEnable);

    if (fAMEXHostEnable == TRUE) //for AMEX
    {
        inOrigMITNumber = srTransRec.MITid;
        if(fUSDSelected == TRUE)
            inMMTReadRecord(4,srTransRec.MITid);
        else
            inMMTReadRecord(2,srTransRec.MITid);
        inAMEXMITNumber = srTransRec.MITid;
        inSaveAmexData();    
        srTransRec.MITid = inOrigMITNumber;
    }
#endif
	//inRet = inCTOS_SelectHostEx();
	inRet = inCTOS_SelectBinRouteHost();
	inDatabase_TerminalCloseDatabase();
    if(d_OK != inRet)
        return inRet;


	vdDebug_LogPrintf("inMMTReadRecord %d %d ", srTransRec.HDTid, srTransRec.MITid);

	inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);

	//version16
		if (fSmacScan == TRUE){
			memset(szQrCodeText, 0x00, sizeof(szQrCodeText));
			//sprintf(szQrCodeText,"D01%s%d%s%s%s%s%s%s",srTransRec.szBaseAmount,
			//srTransRec.ulTraceNum,srTransRec.szTID, 
			//srTransRec.szMID, srTransRec.szInvoiceNo,
			//strMMT[0].szMerchantName,strMMT[0].szRctHdr1);
			strcpy(szQrCodeText,"D01");

			memset(szBuffer, 0x00, sizeof(szBuffer));
			wub_hex_2_str(srTransRec.szBaseAmount, szBuffer, 6);
			vdDebug_LogPrintf("testlang amount %s", szBuffer);
			strcat(szQrCodeText, szBuffer);

			memset(szBuffer, 0x00, sizeof(szBuffer));
			wub_hex_2_str(strHDT.szTraceNo, szBuffer, 3);
			vdDebug_LogPrintf("testlang stan %s", szBuffer);
			strcat(szQrCodeText, szBuffer);

			
			strcat(szQrCodeText, srTransRec.szTID);
			vdDebug_LogPrintf("testlang TID %s", srTransRec.szTID);

			strcat(szQrCodeText, srTransRec.szMID);
			vdDebug_LogPrintf("testlang MID %s", srTransRec.szMID);
		

			memset(szBuffer, 0x00, sizeof(szBuffer));
			wub_hex_2_str(strTCT.szInvoiceNo, szBuffer, 3);
			vdDebug_LogPrintf("testlang invoice %s", szBuffer);
			strcat(szQrCodeText, szBuffer);

			strcat(szQrCodeText, strMMT[0].szMerchantName);
			vdDebug_LogPrintf("testlang Merchant name  %s", strMMT[0].szMerchantName);
		
			strcat(szQrCodeText, strMMT[0].szRctHdr1);
			vdDebug_LogPrintf("testlang Merchant header %s", strMMT[0].szRctHdr1);

			vdDebug_LogPrintf("testlang szQrCodeText %s", szQrCodeText);


			inRet = inCTOSS_DisplayQRCodeAndConfirm(szQrCodeText);

			if(d_OK != inRet)
				return inRet;



		}


	memcpy(strHDT.szTPDU,strTCT.ATPTPDU,5);


    inRet = inCTOS_CheckMustSettle();
    if(d_OK != inRet)
        return inRet;


    inRet = inCTOS_CheckIssuerEnable();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_CheckTranAllowd();
    if(d_OK != inRet)
        return inRet;


    //inRet = inCTOS_GetCVV2();
    //if(d_OK != inRet)
    //    return inRet;

	//gcitra
	//inRet = inGetPolicyNumber();
	//if(d_OK != inRet)
	//	return inRet;	
	//gcitra


    inRet = inCTOS_EMVProcessing();
    if(d_OK != inRet)
        return inRet;   


	if((srTransRec.usTerminalCommunicationMode == GPRS_MODE) || (srTransRec.usTerminalCommunicationMode == WIFI_MODE)){
	 
		 inRet = inCTOS_PreConnect();
		 if(d_OK != inRet)
			 return inRet;
	}else{
	
		 if (strTCT.fSingleComms){	 
			 if(inCPTRead(1) != d_OK)
			 {
				 vdSetErrorMessage("LOAD CPT ERR");
				 return(d_NO);
			 }
		 //}else
		 //{
		 //	 inRet = inCTOS_PreConnect();
		 //	 if(d_OK != inRet)
		//		 return inRet;
		 }
	}


    inRet = inCTOS_GetInvoice();
    if(d_OK != inRet)
        return inRet;

    inRet = inBuildAndSendIsoData();
	fAMEXHostEnable = FALSE;
	fDinersHostEnable = FALSE;
    if(d_OK != inRet)			
        return inRet;


	vdDebug_LogPrintf("**AFTER inBuildAndSendIsoData** %d", fRouteToSpecificHost);

	//inRet = inAnalyzeBinResponseCode();

    if (fRouteToSpecificHost == 1){	
		srTransRec.fBINRouteApproved = 0;
		put_env_int("BINROUTE",1);//Set Bin Route to 1 for sub apps not to call inCTOS_GetInvoice() twice.
		inCTLOS_Updatepowrfail(PFR_IDLE_STATE);//Fix to issue 1153. Powerfail receipt is always printed if turned off while connecting to specific host.
	   return VS_CONTINUE;
    }else{
    	srTransRec.fBINRouteApproved = 1;
    }

#if 0
	if (fUSDSelected){
		inCTOS_SelectHost();

	}
#endif

    inRet = inCTOS_SaveBatchTxn();
    if(d_OK != inRet)
        return inRet;

	if(srTransRec.byTransType == PRE_AUTH)
	{
		inRet = inCTOS_UpdatePreAuthAccumTotal();
	    if(d_OK != inRet)
	        return inRet;
	}
	else
	{
	    inRet = inCTOS_UpdateAccumTotal();
	    if(d_OK != inRet)
	        return inRet;
	}

	inRet=inDisconnectIfNoPendingADVICEandUPLOAD(&srTransRec, strHDT.inNumAdv);
    if(d_OK != inRet)
        return inRet;
	
	// patrick add code 20141205 start, modified -- sidumili
	fECRBuildSendOK = TRUE;	
	if (fECRBuildSendOK){	
	    inRet = inMultiAP_ECRSendSuccessResponse();
	}

    inRet = ushCTOS_printReceipt();
		
    if(d_OK != inRet)
        return inRet;

		
    inCTLOS_Updatepowrfail(PFR_IDLE_STATE);

	CTOS_LCDTClearDisplay(); //BDO UAT 0012: Merchant copy still being displayed during TC Upload -- jzg
		
    inRet = inCTOS_EMVTCUpload();
    if(d_OK != inRet)
        return inRet;
    else
        vdSetErrorMessage("");

	CTOS_LCDTClearDisplay(); //BDO UAT 0012: Merchant copy still being displayed during Advice Upload -- sidumili
	
	inRet=inProcessAdviceTrans(&srTransRec, strHDT.inNumAdv);
		if(d_OK != inRet)
				return inRet;
		else
				vdSetErrorMessage("");


	memset(&srTransRec,0x00,sizeof(TRANS_DATA_TABLE));
	memcpy(&srTransRec,&srtmpTransRec,sizeof(TRANS_DATA_TABLE));

    return d_OK;
}

int inCTOSS_ATPBinRoutingProcessCompCheck(void)
{
    int inRet = d_NO;
	TRANS_DATA_TABLE srtmpTransRec;
	int inOrigMITNumber;

	inRet = inCTOSS_CheckCTLSEMVCard();
    if(d_OK != inRet)
        return inRet;

	memset(&srtmpTransRec,0x00,sizeof(TRANS_DATA_TABLE));
	memcpy(&srtmpTransRec,&srTransRec,sizeof(TRANS_DATA_TABLE));

    //CHECK IF AMEX HOST ENABLE
	if (inCheckIfHostEnable(2) != 0 )
		fAMEXHostEnable = TRUE;
	else
		fAMEXHostEnable = FALSE;

	if (inCheckIfHostEnable(59) != 0 )
		fDinersHostEnable = TRUE;
	else
		fDinersHostEnable = FALSE;
#if 0
	vdDebug_LogPrintf("fAMEXHostEnableTEST %d", fAMEXHostEnable);
	//vdDebug_LogPrintf("fnGlobalOrigHostEnable %d", fnGlobalOrigHostEnable);

	if (fAMEXHostEnable == TRUE){ //for AMEX	
	    inOrigMITNumber = srTransRec.MITid;
		inMMTReadRecord(2,srTransRec.MITid);
		inAMEXMITNumber = srTransRec.MITid;
	    inSaveAmexData();

		srTransRec.MITid = inOrigMITNumber;
	}
#endif

	//inRet = inCTOS_SelectHostEx();
	inRet = inCTOS_SelectBinRouteHost();
	inDatabase_TerminalCloseDatabase();
    if(d_OK != inRet)
        return inRet;


	inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);


	memcpy(strHDT.szTPDU,strTCT.ATPTPDU,5);


    inRet = inCTOS_CheckMustSettle();
    if(d_OK != inRet)
        return inRet;


    inRet = inCTOS_CheckIssuerEnable();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_CheckTranAllowd();
    if(d_OK != inRet)
        return inRet;


    //inRet = inCTOS_GetCVV2();
    //if(d_OK != inRet)
    //    return inRet;

	//gcitra
	//inRet = inGetPolicyNumber();
	//if(d_OK != inRet)
	//	return inRet;	
	//gcitra


    inRet = inCTOS_EMVProcessing();
    if(d_OK != inRet)
        return inRet;   

	inRet = inCTOS_GetOffApproveNO();
    if(d_OK != inRet)
        return inRet;

	if((srTransRec.usTerminalCommunicationMode == GPRS_MODE) || (srTransRec.usTerminalCommunicationMode == WIFI_MODE)){
	 
		 inRet = inCTOS_PreConnect();
		 if(d_OK != inRet)
			 return inRet;
	}else{
	
		 if (strTCT.fSingleComms){	 
			 if(inCPTRead(1) != d_OK)
			 {
				 vdSetErrorMessage("LOAD CPT ERR");
				 return(d_NO);
			 }
		 }else
		 {
			 inRet = inCTOS_PreConnect();
			 if(d_OK != inRet)
				 return inRet;
		 }
	}

    inRet = inCTOS_GetInvoice();
    if(d_OK != inRet)
        return inRet;

	vdGetTimeDate(&srTransRec);// Fix for DE12 and DE13 value is 0 on bin routing.
	
    inRet = inBuildAndSendIsoData();
    if(d_OK != inRet)			
        return inRet;


	vdDebug_LogPrintf("**AFTER inBuildAndSendIsoData** %d", fRouteToSpecificHost);

	//inRet = inAnalyzeBinResponseCode();

    if (fRouteToSpecificHost == 1){
	   srTransRec.fBINRouteApproved = 0;
	   put_env_int("BINROUTE",1);//Set Bin Route to 1 for sub apps not to call inCTOS_GetInvoice() twice.
	   inCTLOS_Updatepowrfail(PFR_IDLE_STATE);//Fix to issue 1153. Powerfail receipt is always printed if turned off while connecting to specific host. 
	   return VS_CONTINUE;
    }else{
    	srTransRec.fBINRouteApproved = 1;
    }
	
    inRet = inCTOS_SaveBatchTxn();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_UpdateAccumTotal();
    if(d_OK != inRet)
        return inRet;

	inRet=inDisconnectIfNoPendingADVICEandUPLOAD(&srTransRec, strHDT.inNumAdv);
    if(d_OK != inRet)
        return inRet;
	
	// patrick add code 20141205 start, modified -- sidumili
	fECRBuildSendOK = TRUE;	
	if (fECRBuildSendOK){	
	    inRet = inMultiAP_ECRSendSuccessResponse();
	}

    inRet = ushCTOS_printReceipt();
		
    if(d_OK != inRet)
        return inRet;

		
    inCTLOS_Updatepowrfail(PFR_IDLE_STATE);

	CTOS_LCDTClearDisplay(); //BDO UAT 0012: Merchant copy still being displayed during TC Upload -- jzg
		
    inRet = inCTOS_EMVTCUpload();
    if(d_OK != inRet)
        return inRet;
    else
        vdSetErrorMessage("");

	CTOS_LCDTClearDisplay(); //BDO UAT 0012: Merchant copy still being displayed during Advice Upload -- sidumili
	
	inRet=inProcessAdviceTrans(&srTransRec, strHDT.inNumAdv);
		if(d_OK != inRet)
				return inRet;
		else
				vdSetErrorMessage("");


	memset(&srTransRec,0x00,sizeof(TRANS_DATA_TABLE));
	memcpy(&srTransRec,&srtmpTransRec,sizeof(TRANS_DATA_TABLE));

    return d_OK;
}



#if 0
inCheckIfHostEnable(void){

	vdDebug_LogPrintf("strCDT.HDTid %d", strCDT.HDTid);


	if(inHDTRead(strCDT.HDTid) != d_OK){
		fnGlobalOrigHostEnable =0;
		return 0;
	}else{
	    if (strHDT.fHostEnable == 1){
			fnGlobalOrigHostEnable = 1;
			return strCDT.HDTid; //return orig host number to be used for AMEX
		}else{
			fnGlobalOrigHostEnable = 0;	
			return 0;
			
		}
	}

}
#endif
inCheckIfHostEnable(int inHostNum){

	vdDebug_LogPrintf("strCDT.HDTid %d", strCDT.HDTid);


	if(inHDTRead(inHostNum) != d_OK){
		fnGlobalOrigHostEnable =0;
		return 0;
	}else{
	    if (strHDT.fHostEnable == 1){
			fnGlobalOrigHostEnable = 1;
			
			vdDebug_LogPrintf("inCheckIfHostEnable enable");
			return 1; 
		}else{
			fnGlobalOrigHostEnable = 0;	
			
			vdDebug_LogPrintf("inCheckIfHostEnable disable");
			return 0;
			
		}
	}

}



int inSETIssuerForCatchAll(void)
{


	if ((strTCT.fATPBinRoute == TRUE) && (strCDT.fPANCatchAll == TRUE)){
		
		
	vdDebug_LogPrintf("inSETIssuerForCatchAll %d %d", srTransRec.byEntryMode, srTransRec.bWaveSID);
	
	if (srTransRec.byEntryMode == CARD_ENTRY_WAVE){ 

	     if (srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_2 || srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC)
		 	srTransRec.IITid = 2;
		 else if (srTransRec.bWaveSID == d_VW_SID_AE_EMV)
		 	srTransRec.IITid = 3;	 
		 else if (srTransRec.bWaveSID == d_VW_SID_CUP_EMV)
		 	srTransRec.IITid = 9; 
		 else if (srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP)
		 	srTransRec.IITid = 4;
	     else if (srTransRec.bWaveSID == 0x63 || srTransRec.bWaveSID == 0x65)
		 	srTransRec.IITid = 12;
		 else if (srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS)
		 	srTransRec.IITid = 8;
	}else if (srTransRec.byEntryMode == CARD_ENTRY_ICC){
	
		if ((memcmp(srTransRec.stEMVinfo.T84,"\xA0\x00\x00\x00\x03",5) == 0) || (memcmp(srTransRec.stEMVinfo.T84,"\xa0\x00\x00\x00\x03",5) == 0)) 		
		 	srTransRec.IITid = 2;
		else if ((memcmp(srTransRec.stEMVinfo.T84,"\xA0\x00\x00\x00\x04",5) == 0) || (memcmp(srTransRec.stEMVinfo.T84,"\xa0\x00\x00\x00\x04",5) == 0))		
		 	srTransRec.IITid = 4;
		else if ((memcmp(srTransRec.stEMVinfo.T84,"\xA0\x00\x00\x00\x65",5) == 0) || (memcmp(srTransRec.stEMVinfo.T84,"\xa0\x00\x00\x00\x65",5) == 0))		
			srTransRec.IITid = 12;
		else if ((memcmp(srTransRec.stEMVinfo.T84,"\xA0\x00\x00\x00\x25",5) == 0) || (memcmp(srTransRec.stEMVinfo.T84,"\xa0\x00\x00\x00\x25",5) == 0))		
			srTransRec.IITid = 3;
		else if ((memcmp(srTransRec.stEMVinfo.T84,"\xA0\x00\x00\x03\x33",5) == 0) || (memcmp(srTransRec.stEMVinfo.T84,"\xa0\x00\x00\x03\x33",5) == 0))		
			srTransRec.IITid = 9;    
		else if ((memcmp(srTransRec.stEMVinfo.T84,"\xA0\x00\x00\x03\x06",5) == 0) || (memcmp(srTransRec.stEMVinfo.T84,"\xa0\x00\x00\x03\x06",5) == 0)
			      || (memcmp(srTransRec.stEMVinfo.T84,"\xA0\x00\x00\x06\x35",5) == 0)	|| (memcmp(srTransRec.stEMVinfo.T84,"\xa0\x00\x00\x06\x35",5) == 0))												   
			srTransRec.IITid = 6;
		else if ((memcmp(srTransRec.stEMVinfo.T84,"\xA0\x00\x00\x01\x52",5) == 0) || (memcmp(srTransRec.stEMVinfo.T84,"\xa0\x00\x00\x01\x52",5) == 0))		
			srTransRec.IITid = 8;
	}

	vdDebug_LogPrintf("inSETIssuerForCatchAll %d", srTransRec.IITid);

	if (srTransRec.IITid > 0){
		inIITRead(srTransRec.IITid);
		strcpy(srTransRec.szCardLable, strIIT.szIssuerLabel);
		strcpy(strCDT.szCardLabel, srTransRec.szCardLable);
		
		vdDebug_LogPrintf("strIIT.szIssuerLabel %s", strIIT.szIssuerLabel);
		vdDebug_LogPrintf("strIIT.szIssuerLabel %s", strIIT.szIssuerLogo);
		
	}

	}

	return d_OK;

}

