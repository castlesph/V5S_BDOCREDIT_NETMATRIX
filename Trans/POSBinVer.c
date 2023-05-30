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


#include "..\Includes\POSTypedef.h"
#include "..\Debug\Debug.h"

#include "..\Includes\POSMain.h"
#include "..\Includes\POSTrans.h"
#include "..\Includes\POSHost.h"
#include "..\Includes\POSBinVer.h"
#include "..\Includes\POSbatch.h"
#include "..\ui\Display.h"
#include "..\Includes\V5IsoFunc.h"
#include "..\Accum\Accum.h"
#include "..\print\Print.h"
#include "..\Comm\V5Comm.h"
#include "..\Includes\MultiApLib.h"
#include "..\Aptrans\MultiAptrans.h"
#include "../Includes/wub_lib.h"
#include "..\Includes\POSSale.h"
#include "../Database/DatabaseFunc.h"

extern VS_BOOL fPreConnectEx;


/* Issue# 000096: BIN VER Checking - start -- jzg*/
BOOL fBINVer;
char szBINVerSTAN[8];
/* Issue# 000096: BIN VER Checking - end -- jzg*/


extern BOOL fInstApp; //BDO: Parameterized manual key entry for installment -- jzg


extern void setLCDPrint27(int line,int position,char * pbBuf);

extern BOOL fECRBuildSendOK; /* For ECR -- sidumili */
extern BOOL fBINVerPreConnectEx;

int inCTOS_BINCheckFlowProcess(void)
{
    int inRet = d_NO;

    USHORT ushEMVtagLen;
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];
	
	fECRBuildSendOK = FALSE; /* BDO: For ECR -- sidumili */

    vdCTOS_SetTransType(BIN_VER);
    
    //display title
    //vdDispTransTitle(BIN_VER);


    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;

	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;

    inRet = inCTOS_PreConnectAndInit();
    if(d_OK != inRet)
        return inRet;
	
    //if (strTCT.byCtlsMode == 0)
		inRet = inCTOS_GetCardFields();
	//else
    //	inRet = inCTOS_WaveGetCardFields();
	
	inHDTRead(strCDT.HDTid);
	if(strHDT.fBinVerEnable == 0)
	{
		vdDisplayErrorMsgResp2(" ","BIN CHECK", "NOT ALLOWED");
		return(d_NO);
	}
	
    if(d_OK != inRet)
        return inRet;
	
	inRet = inBDOEnterLast4Digits(FALSE);
	if(inRet != d_OK)
			return inRet;
    
    //inRet = inCTOS_SelectHost();
    //if(d_OK != inRet)
        //return inRet;

	//gcitra - put display here not in amount entry
	inRet=inCTOS_DisplayCardTitle(6, 7); //Display Issuer logo: re-aligned Issuer label and PAN lines -- jzg
	if(d_OK != inRet)
		return inRet;
	
	inRet = inConfirmPAN();
	if(d_OK != inRet)
		return inRet;		
	
	inRet = inCheckIfFleetCard();
	if(d_OK != inRet)
		return inRet;	
	//gcitr

    inRet = inCTOS_SelectHostEx2();
    if(d_OK != inRet)
        return inRet;
    
    //if (inMMTReadRecord(strCDT.HDTid,srTransRec.MITid) != d_OK) // Also check if Merchant using host is enabled
    if (inMMTReadRecordEx(strCDT.HDTid,srTransRec.MITid) != d_OK) // Also check if Merchant using host is enabled
    {
        vdDisplayErrorMsgResp2(" ", "TRANSACTION", "NOT ALLOWED");
        inDatabase_TerminalCloseDatabase();
        return(d_NO);
    }	
    inDatabase_TerminalCloseDatabase();

#if 0
    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_BINVER);
        if(d_OK != inRet)
            return inRet;
    }
    else
    {
        if (inMultiAP_CheckSubAPStatus() == d_OK)
        {
            inRet = inCTOS_MultiAPGetData();
            if(d_OK != inRet)
                return inRet;
            
            inRet = inCTOS_MultiAPReloadTable();
            if(d_OK != inRet)
                return inRet;
        }
        inRet = inCTOS_MultiAPCheckAllowd();
        if(d_OK != inRet)
            return inRet;
    }
#endif

	//remove prompt fro selection-Merchant selection is done by inCTOS_TEMPCheckAndSelectMutipleMID
	//	  inRet = inCTOS_CheckAndSelectMutipleMID();
	//	  if(d_OK != inRet)
	//		  return inRet;
	//inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);

 
    inRet = inCTOS_GetBINVerData();
    if (d_OK != inRet)
      return inRet;

    inRet = inCTOS_PreConnect();
    if(d_OK != inRet)
       return inRet;

     inRet = inBuildAndSendIsoData();

    if(d_OK != inRet)
        return inRet;

	/*BDO: Reset response code after receive, for ecr "OPERATOR CANCEL" -- sidumili */
	if ((fGetECRTransactionFlg() == TRUE) && (strTCT.fSelectECRTrxn == TRUE))
		memset(srTransRec.szRespCode, 0x00, sizeof(srTransRec.szRespCode));
	/*BDO: Reset response code after receive, for ecr "OPERATOR CANCEL" -- sidumili */
	
    inRet= inCTOS_ProceedToSale();
    if(d_OK != inRet)
        return inRet;

		vdSetFirstIdleKey(0x00);


		/* Issue# 000096: BIN VER Checking - start -- jzg*/
		fBINVer = TRUE;
		sprintf(szBINVerSTAN, "%d", (int)srTransRec.ulTraceNum);
		//inHDTSave(strHDT.inHostIndex);
		/* Issue# 000096: BIN VER Checking - end -- jzg*/

		srTransRec.fBINVer = TRUE;
		sprintf(srTransRec.szBINVerSTAN, "%d", (int)srTransRec.ulTraceNum); /* BDO-00112: No BIN Check printed on reciept -- jzg */

    CTOS_LCDTClearDisplay();
    vdCTOS_SetTransType(SALE);
    vdDispTransTitle(srTransRec.byTransType);
     
//1030
   //inRet = inCTOS_SaleFlowProcess();
   inRet = inCTOS_WaveFlowProcess();
		if(d_OK != inRet){	
			fBINVer = FALSE;
			memset(szBINVerSTAN, 0, strlen(szBINVerSTAN));
        return inRet;
		}
		
	 //inRet=inCTOS_WAVE_SALE();
//1030


		/* Issue# 000096: BIN VER Checking - start -- jzg*/
		fBINVer = FALSE;
	 	memset(szBINVerSTAN, 0, strlen(szBINVerSTAN));
		/* Issue# 000096: BIN VER Checking - end -- jzg*/

    return d_OK;
}

int inCTOS_GetBINVerData(void){


	inBVTRead(1);
 
	memcpy(strHDT.szTPDU,strBVT.szBINVerTPDU,5);
	strcpy(srTransRec.szTID, strBVT.szBINVerTID);
   	strcpy(srTransRec.szMID, strBVT.szBINVerMID);
	
    	return d_OK;

}

int inCTOS_ProceedToSale(void){

	BYTE key;
       int inRet;
       
	char szBIN[6+1];
	char szIssuer1[24+1];
	char szIssuer2[24+1];
	int inLen = 0;
    	//CTOS_LCDTClearDisplay();
    	//vdDispTransTitle(BIN_VER);

	vduiClearBelow(2);

	memset(szBIN, 0x00, sizeof(szBIN));
	strncpy(szBIN, srTransRec.szPAN, 6);


	do{

		if(VS_TRUE == strTCT.fDemo)
			strcpy(szField63,"BANCO DE ORO");

		inLen = strlen(szField63);

		if(inLen<=20)
		{
			setLCDPrint27(3,DISPLAY_POSITION_LEFT, "CARD ISSUER:");		
			setLCDPrint27(4, DISPLAY_POSITION_RIGHT, szField63);
		}
		else
		{
			memset(szIssuer1,0x00,sizeof(szIssuer1));
			memset(szIssuer2,0x00,sizeof(szIssuer2));
			
	 		setLCDPrint27(2,DISPLAY_POSITION_LEFT, "CARD ISSUER:");	
			
	       	memcpy(szIssuer1,szField63,20);
			memcpy(szIssuer2,&szField63[20],inLen-20);

			setLCDPrint27(3, DISPLAY_POSITION_RIGHT, szIssuer1);
			setLCDPrint27(4, DISPLAY_POSITION_CENTER, szIssuer2);
		}
		

		//000212 After Bin Check, terminal should display what keypad to press on Proceed and cancel start
		setLCDPrint27(5, DISPLAY_POSITION_LEFT, "BIN:");
		setLCDPrint27(5, DISPLAY_POSITION_RIGHT, szBIN);
		//CTOS_LCDTPrintXY(1, 8, "PROCEED[F1]CANCEL[F4]"); //sidumili: Fix on Issue#:000212
		CTOS_LCDTPrintXY(1,7,"1. PROCEED");		
		CTOS_LCDTPrintXY(1,8,"2. CANCEL");
		//000212 After Bin Check, terminal should display what keypad to press on Proceed and cancel end  
		key=WaitKey(60);

		if (key == d_KBD_1){
			inRet = d_OK;
			break;
		}else if ((key == d_KBD_2) || (key == d_KBD_CANCEL)){
			if(fGetECRTransactionFlg() == TRUE)
				vdDisplayErrorMsgResp2("","TRANS CANCELLED","");
			
			inRet = d_NO;
			break;
		}

	}while(1);

	return inRet;

}




int inUnPackBINVer63(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{


    int inLen;

 
   memset(szField63, 0x00, sizeof(szField63));
    inLen =((uszUnPackBuf[0] / 16 * 10) + uszUnPackBuf[0] % 16) *100;
    inLen += (uszUnPackBuf[1] / 16 * 10) + uszUnPackBuf[1] % 16;


//smac
		if (((srTransRec.byTransType == SALE) && (srTransRec.HDTid == SMAC_HDT_INDEX)) ||
			(((srTransRec.byTransType == SETTLE) || (srTransRec.byTransType == CLS_BATCH)) && (srTransRec.HDTid == SMAC_HDT_INDEX))){
				memcpy(szField63, (char *)&uszUnPackBuf[0], inLen);
				inSMACAnalyzeField63();
	}else
//smac
		memcpy(szField63, (char *)&uszUnPackBuf[2], inLen);

    return ST_SUCCESS;
}


int inCTOS_BINCHECK(void)
{
    int inRet = d_NO;



    CTOS_LCDTClearDisplay();
    
    vdCTOS_TxnsBeginInit();

	//vdCTOSS_SetWaveTransType(1);

	//inRet = inCTOSS_CLMOpenAndGetVersion();
	//if(d_OK != inRet)
    //    return inRet;
	vdCTOS_SetTransType(BIN_VER);
    inRet = inCTOS_GetBINVerData();
    if (d_OK != inRet)
      return inRet;

    #if 0
    //if ((strTCT.fSingleComms) && (fPreConnectEx == FALSE)){
     if ((strTCT.fSingleComms) && (fBINVerPreConnectEx == FALSE)){
		inRet = inCTOS_PreConnectEx();

		if (inRet != d_OK)
			return inRet;
	}
    #endif
	
    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiStopResumeAP("SHARLS_ECRBDO");
    
    inRet = inCTOS_BINCheckFlowProcess();
    
    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiResumeContinueAP("SHARLS_ECRBDO");

	//vdCTOSS_CLMClose();

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

int inCTOS_INSTBINCHECK(void)
{
    int inRet = d_NO;



    CTOS_LCDTClearDisplay();
    
    vdCTOS_TxnsBeginInit();
	
	vdCTOSS_SetWaveTransType(1);

	inRet = inCTOSS_CLMOpenAndGetVersion();
	if(d_OK != inRet)
        return inRet;
   
    inRet = inCTOS_INSTBINCheckFlowProcess();

	vdCTOSS_CLMClose();

    inCTOS_inDisconnect();

    vdCTOS_TransEndReset();

    return inRet;
}

int inCTOS_INSTBINCheckFlowProcess(void)
{
    int inRet = d_NO;
	int inNumRecs = 0;
    USHORT ushEMVtagLen;
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];




    vdCTOS_SetTransType(BIN_VER);
    
    //display title
    vdDispTransTitle(BIN_VER);

		fInstApp = TRUE; //BDO: Parameterized manual key entry for installment -- jzg

    inRet = inCTOSS_CheckMemoryStatus();
    if(d_OK != inRet)
        return inRet;


    inRet = inCTOS_GetTxnPassword();
    if(d_OK != inRet)
        return inRet;

	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;

#if 1
	inRet = inCTOS_GetCardFields();
#else    
    if (strTCT.byCtlsMode == 0)
		inRet = inCTOS_GetCardFields();
	else
    	inRet = inCTOS_WaveGetCardFields();
#endif
	
    if(d_OK != inRet)
        return inRet;

	memset(strMultiPRM, 0, sizeof(strMultiPRM));
	
	inRet = inPRMReadbyinInstGroupEx(strCDT.inInstGroup, &inNumRecs);
	
	if(strlen(strMultiPRM[0].szPrintPromoLabel) <= 0 || strMultiPRM[0].fInstBINVerEnable == 0/* || //check if no records found or Installment BIN Ver is disabled
		strCDT.HDTid == CUP_HDT_INDEX || strCDT.HDTid == CUPUSD_HDT_INDEX*/)//check if card is CUP
	{
		CTOS_LCDTClearDisplay();
		vdDisplayErrorMsgResp2(" ", "BIN CHECK", "NOT ALLOWED");
		return inRet;	
	}
	
	inRet = inBDOEnterLast4Digits(TRUE);
	if(inRet != d_OK)
        return inRet;
    
    inRet = inCTOS_SelectHost();
    if(d_OK != inRet)
        return inRet;

	//gcitra - put display here not in amount entry
	inRet=inCTOS_DisplayCardTitle(6, 7); //Display Issuer logo: re-aligned Issuer label and PAN lines -- jzg
	if(d_OK != inRet)
		return inRet;
	
	inRet = inConfirmPAN();
	if(d_OK != inRet)
		return inRet;		
	//gcitr
 
    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_BINVER);
        if(d_OK != inRet)
            return inRet;
    }
    else
    {
        if (inMultiAP_CheckSubAPStatus() == d_OK)
        {
            inRet = inCTOS_MultiAPGetData();
            if(d_OK != inRet)
                return inRet;
            
            inRet = inCTOS_MultiAPReloadTable();
            if(d_OK != inRet)
                return inRet;
        }
        inRet = inCTOS_MultiAPCheckAllowd();
        if(d_OK != inRet)
            return inRet;
    }

	//remove prompt fro selection-Merchant selection is done by inCTOS_TEMPCheckAndSelectMutipleMID
	//	  inRet = inCTOS_CheckAndSelectMutipleMID();
	//	  if(d_OK != inRet)
	//		  return inRet;
	inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);

 
    inRet = inCTOS_GetBINVerData();
    if (d_OK != inRet)
      return inRet;

    inRet = inCTOS_PreConnect();
    if(d_OK != inRet)
       return inRet;

     inRet = inBuildAndSendIsoData();

    if(d_OK != inRet)
        return inRet;


    inRet= inCTOS_ProceedToSale();
    if(d_OK != inRet)
        return inRet;

		vdSetFirstIdleKey(0x00);

		fBINVer= VS_TRUE;
		srTransRec.fBINVer = VS_TRUE;
		
		sprintf(srTransRec.szBINVerSTAN, "%d", (int)srTransRec.ulTraceNum);
		
		//vdDebug_LogPrintf("**GET BINVER STAN  %d - %x%x%x**", srTransRec.ulTraceNum,srTransRec.szBINVerSTAN[0],srTransRec.szBINVerSTAN[1],srTransRec.szBINVerSTAN[2]);
		
    //memcpy(srTransRec.szBINVerSTAN, strBVT.szBINVerSTAN, INVOICE_BCD_SIZE);    

     CTOS_LCDTClearDisplay();
     vdCTOS_SetTransType(SALE);
	 fInstApp = TRUE;
     vdDispTransTitle(srTransRec.byTransType);

    inRet = inCTOS_InstallmentFlowProcess();

		fBINVer= VS_FALSE;

    return d_OK;
}


int  inCheckIfFleetCard(void){


  if ((strTCT.fFleetGetLiters == 1 || strTCT.fGetDescriptorCode == 1) && (strCDT.IITid == 14)){	
	vdDisplayErrorMsgResp2(" ", "TRANSACTION", "NOT ALLOWED");
  	return d_NO;
  }else{
	return d_OK;
  }
}
