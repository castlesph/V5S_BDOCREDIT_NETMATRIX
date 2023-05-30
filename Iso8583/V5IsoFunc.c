#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctosapi.h>
#include <EMVAPLib.h>
#include <EMVLib.h>
#include <emv_cl.h>

#include "../Includes/wub_lib.h"
#include "../Includes/Encryption.h"
#include "../Includes/msg.h"
#include "../Includes/myEZLib.h"

#include "../Includes/V5IsoFunc.h"
#include "../Includes/POSTypedef.h"
#include "../Comm/V5Comm.h"
#include "../FileModule/myFileFunc.h"
#include "../UI/Display.h"
#include "../Includes/Trans.h"
#include "../UI/Display.h"
#include "../Accum/Accum.h"
#include "../POWRFAIL/POSPOWRFAIL.h"
#include "../DataBase/DataBaseFunc.h"
#include "../Includes/POSTrans.h"
#include "..\Debug\Debug.h"
#include "..\Includes\POSTrans.h"
#include "..\Includes\Showbmp.h"
#include "..\Includes\POSHost.h"
#include "..\Includes\ISOEnginee.h"
//1127
#include "../Ctls/POSCtls.h"

#include "..\Aptrans\MultiShareCOM.h"

#include <emvaplib.h>

//gcitra-0728
#include <eftsec.h>
//gcitra-0728

#include "..\Includes\POSSale.h"
#include "..\Includes\POSBinVer.h"
#include "..\Aptrans\MultiAptrans.h"
//version16
extern BYTE szSMACScanResponsetext[50];

extern fAdviceTras;
extern BOOL fSmacScan;

int inReversalType=0;

int inDataCnt;
BYTE TempKey;
int inFinalSend;
BYTE szDataForMAC[512];
int  inMacMsgLen;

extern USHORT usPreconnectStatus;
//version16
BYTE szECRSMACField02[50];
extern BYTE szBarcodeText[50];


//extern BOOL fAMEXHostEnable;
extern BOOL fUSDSelected;
BOOL fBuildandSendProcess = VS_FALSE;

BYTE byField_02_ON;
BYTE byField_14_ON;
BYTE byField_35_ON;
BYTE byField_45_ON;
BYTE byField_48_ON;

extern BOOL fSMACTRAN;
extern char szField63[999];

BYTE	szAmexTID[TERMINAL_ID_BYTES+1];
BYTE	szAmexMID[MERCHANT_ID_BYTES+1];
BYTE   szORIGTraceNo[TRACE_NO_BCD_SIZE+1];
//extern int inHostOrigNumber;
extern BOOL fnGlobalOrigHostEnable;
//extern int inHostOrigNumber;
extern int inAMEXMITNumber;
extern BOOL fBinRouteDCC;
extern BOOL fRouteToSpecificHost;



ISO_FUNC_TABLE srIsoFuncTable[] =
{
    {
        inPackMessageIdData,/*inPackMTI*/
		inPackPCodeData,/*inPackPCode*/
        vdModifyBitMapFunc,/*vdModifyBitMap*/
        inCheckIsoHeaderData,/*inCheckISOHeader*/
        inAnalyseReceiveData,/*inTransAnalyse*/
        inAnalyseAdviceData  /*inAdviceAnalyse*/
    },
};

static TRANS_DATA_TABLE *ptsrISOEngTransData = NULL;

extern int gvSettleType; /* BDO: Manual settlement prompt after failed settlement -- jzg */

void vdSetISOEngTransDataAddress(TRANS_DATA_TABLE *srTransPara)
{
    ptsrISOEngTransData= srTransPara;
}

TRANS_DATA_TABLE* srGetISOEngTransDataAddress(void)
{
    return ptsrISOEngTransData;
}



void vdDispTextMsg(char *szTempMsg)
{    
//    CTOS_LCDUClearDisplay();
//    CTOS_LCDTPutchXY(1,8,"TEST");
//    CTOS_KBDGet(&TempKey);
}

void vdDecideWhetherConnection(TRANS_DATA_TABLE *srTransPara)
{
    vdMyEZLib_LogPrintf("**vdDecideWhetherConnection START**");
    

    vdDebug_LogPrintf(". BefTrnsType(%d) UpLoad(%d) Offline (%d)",srTransPara->byTransType,
                                                              srTransPara->byUploaded,
                                                              srTransPara->byOffline);
                                                              
    if(srTransPara->byTransType != VOID)
    {    
        if(srTransPara->byTransType == SALE_TIP || srTransPara->byTransType == SALE_ADJUST)
        {
			srTransPara->byOffline = CN_TRUE;
           
        }
       /* else if(srTransPara->byTransType == SALE_OFFLINE)
        {
            srTransPara->byUploaded = CN_FALSE;
            srTransPara->byOffline = CN_TRUE;
        }*/
        else if(srTransPara->byTransType == SALE &&
            srTransPara->byEntryMode == CARD_ENTRY_ICC &&
            srTransPara->shTransResult == TRANS_AUTHORIZED &&
            0 == memcmp(&srTransPara->szAuthCode[0], "Y1", 2) && 
            0x40 == srTransPara->stEMVinfo.T9F27)
        {
            srTransPara->byUploaded = CN_FALSE;
            srTransPara->byOffline = CN_TRUE;
        }
        else if(srTransPara->byTransType == SALE &&
            srTransPara->byEntryMode != CARD_ENTRY_ICC &&
            srTransPara->shTransResult == TRANS_AUTHORIZED &&
            srTransPara->byOffline == CN_TRUE &&
            fAmountLessThanFloorLimit() == d_OK )
        {
            srTransPara->byUploaded = CN_FALSE;
            srTransPara->byOffline = CN_TRUE;
        }
		else if(srTransPara->byTransType == SALE_OFFLINE && memcmp(&srTransPara->szAuthCode[0], "Y1", 2)==0)
		{
            srTransPara->byUploaded = CN_FALSE;
            srTransPara->byOffline = CN_TRUE;
		}
        else
        {
            srTransPara->byUploaded = CN_TRUE;
            srTransPara->byOffline = CN_FALSE;
        }
    }
    else
    {
        //Start Should be Online void the Intial SALE amount.
        if(srTransPara->byOrgTransType == SALE)
        {
            //if(srTransPara->byUploaded == CN_FALSE) //Y1 or below floor limit, and not upload yet   
						if (srTransPara->fOnlineSALE == CN_FALSE)
                srTransPara->byOffline = CN_TRUE;
            else
                srTransPara->byOffline = CN_FALSE;
							
        }
        else if(srTransPara->byOrgTransType == SALE_OFFLINE)
        {
            vdDebug_LogPrintf("srTransRec.byTransType: %d, srTransRec.szAuthCode: %s", srTransRec.byTransType, srTransRec.szAuthCode);	
			vdDebug_LogPrintf("byTransType[%d],byOffline[%d],byUploaded[%d]",srTransRec.byTransType,srTransRec.byOffline,srTransRec.byUploaded);
//0703
//change to make all Offline void transactions to be sent as advice.

			if(memcmp(srTransRec.szAuthCode,"Y1",2) == 0)
			{
#if 0
				if(srTransPara->byUploaded == CN_FALSE)
	                srTransPara->byOffline = CN_TRUE;  // Terminal should still do offline void.
	            else
	                srTransPara->byOffline = CN_FALSE; //piggy backed and uploaded to host already
#endif
				//srTransPara->byUploaded = CN_FALSE;
            	srTransPara->byOffline = CN_TRUE;
			}
			else
			{
				srTransPara->byOffline = CN_FALSE; 
	            srTransPara->byUploaded = CN_TRUE;
			}

			//srTransPara->byOffline = CN_FALSE; 
            //srTransPara->byUploaded = CN_TRUE;
//0703
        }
        else if(srTransPara->byOrgTransType == SALE_TIP)
        {
//0703
//change to make all Offline void transactions to be sent as advice.

            //if(srTransPara->byUploaded == CN_FALSE) //Y1 or below floor limit, and not upload yet
			if (srTransPara->fVoidOffline == CN_TRUE)							
                srTransPara->byOffline = CN_TRUE;
            else
                srTransPara->byOffline = CN_FALSE;
//0703

        }
/*
	if (srTransPara->byOrgTransType==SALE_OFFLINE && srTransPara->byTransType==VOID && (memcmp(srTransRec.szAuthCode,"Y1",2) == 0))
	{
	 	    srTransPara->byUploaded = CN_FALSE;
			srTransPara->byOffline = CN_TRUE;
	}
*/
        //End Should be Online void the Intial SALE amount.
    }
    vdDebug_LogPrintf(". AftTrnsType(%d) srTransPara->byOrgTransType[%d]byEntryMode[%d] shTransResult[%d] szAuthCode[%s] 9F27[%02X] UpLoad(%d) Offline (%d)",
                                                              srTransPara->byTransType,
                                                              srTransPara->byOrgTransType,
                                                              srTransPara->byEntryMode,
                                                              srTransPara->shTransResult,
                                                              srTransPara->szAuthCode,
                                                              srTransPara->stEMVinfo.T9F27,
                                                              srTransPara->byUploaded,
                                                              srTransPara->byOffline);
    
    vdMyEZLib_LogPrintf("**vdDecideWhetherConnection END**");
    return;
}


/************************************************************************
Function Name: inBuildAndSendIsoData()
Description:
    To generate iso data and send to host
Parameters:
    [IN] srTransPara

Return: ST_SUCCESS  
        ST_ERROR
        TRANS_COMM_ERROR
        ST_SEND_DATA_ERR
        ST_UNPACK_DATA_ERR
    
************************************************************************/
int inBuildAndSendIsoData(void)
{
    int inResult,i;
    char szErrorMessage[30+1];
    char szBcd[INVOICE_BCD_SIZE+1];
    TRANS_DATA_TABLE *srTransPara;
    TRANS_DATA_TABLE srTransParaTmp;
    int inHDTid=0;
	
	//commsbackup
	BOOL fConnectFailed=FALSE;
	//commsbackup
	
  	memset(szBcd, 0x00, sizeof(szBcd));

	vdDebug_LogPrintf("**inBuildAndSendIsoData START*srTransRec.byTransType[%d]*", srTransRec.byTransType);
	
	if (srTransRec.byTransType == BIN_VER){	
		inBVTRead(1);
		
		memcpy(szBcd, strBVT.szBINVerSTAN, INVOICE_BCD_SIZE);
		inBcdAddOne(szBcd, strBVT.szBINVerSTAN, INVOICE_BCD_SIZE); 
		srTransRec.ulTraceNum = wub_bcd_2_long(strBVT.szBINVerSTAN,3);
		inBVTSave(1);
		
	}else{

		vdDebug_LogPrintf("**inBuildAndSendIsoData 1**");

	    //version16
	    if (srTransRec.HDTid == SMAC_HDT_INDEX && srTransRec.byTransType == SALE && fSmacScan == TRUE){ 
			srTransRec.ulTraceNum = wub_bcd_2_long(strHDT.szTraceNo,3);
	    }else{
			vdDebug_LogPrintf("**inBuildAndSendIsoData 2**");
	    
			memcpy(szBcd, strHDT.szTraceNo, INVOICE_BCD_SIZE);
			//save for retrieval later if reversal before transaction fails
			memset(szORIGTraceNo, 0x00, sizeof(szORIGTraceNo));
			memcpy(szORIGTraceNo, strHDT.szTraceNo, INVOICE_BCD_SIZE);	
			inBcdAddOne(szBcd, strHDT.szTraceNo, INVOICE_BCD_SIZE);	
  			srTransRec.ulTraceNum = wub_bcd_2_long(strHDT.szTraceNo,3);
	    }
	}


  if ((VOID != srTransRec.byTransType) && (SALE_TIP != srTransRec.byTransType)){
        srTransRec.ulOrgTraceNum = srTransRec.ulTraceNum;
		vdDebug_LogPrintf("**inBuildAndSendIsoData 3**");
		
  }

	//vdDebug_LogPrintf("**inBuildAndSendIsoData ulOrgTraceNum[%ld]**", srTransPara->ulOrgTraceNum);
	//vdDebug_LogPrintf("inBuildAndSendIsoData ulTraceNum=[%06ld]", srTransRec.ulTraceNum);

	//gcitra 
	//if ((srTransRec.byTransType != BIN_VER) && (srTransRec.byTransType != CASH_LOYALTY)) {
	
	if ((srTransRec.byTransType != BIN_VER) && (srTransRec.byTransType != CASH_LOYALTY) /*&& (inGetATPBinRouteFlag() != TRUE)*/) {
		
		inHDTSave(strHDT.inHostIndex);
	}
    //gcitra



		
  srTransPara = &srTransRec;

	vdDebug_LogPrintf("**inBuildAndSendIsoData V02**");
	if (srTransPara->byTransType != SETTLE)
		inCTLOS_Updatepowrfail(PFR_BEGIN_SEND_ISO);

    strHDT.fSignOn = CN_TRUE; //notsupport SignON
        
    if(strHDT.fSignOn == CN_FALSE)
    {
        if( (srTransRec.byTransType == SALE)    ||  // SALE
            (srTransRec.byTransType == REFUND)  ||  // REFUND
            (srTransRec.byTransType == PRE_AUTH)||  // PREAUTH
            (srTransRec.byTransType == SETTLE)    // SETTLE
          )
        {
            i = srTransPara->HDTid;
            inHDTRead(srTransPara->HDTid);
            memcpy(&srTransParaTmp, srTransPara, sizeof(TRANS_DATA_TABLE));
            memset( &srTransRec, 0x00, sizeof(TRANS_DATA_TABLE));
            CTOS_LCDTClearDisplay();
			
			DebugAddSTR("Sign on false","---",12);  
            //SignOnTrans(i);            
            if(strHDT.fSignOn == CN_FALSE)
            {
                srTransRec.shTransResult = TRANS_TERMINATE;
				vdSetErrorMessage("TRANS TERMINATE");
                inCTOS_inDisconnect();
                return ST_ERROR;
            }
            memset( &srTransRec, 0x00, sizeof(TRANS_DATA_TABLE));
            CTOS_LCDTClearDisplay();
            memcpy(srTransPara, &srTransParaTmp, sizeof(TRANS_DATA_TABLE));
            inHDTRead(srTransPara->HDTid);
						
			vdDebug_LogPrintf("**inBuildAndSendIsoData TEST 2 V02**");
            srTransPara->ulTraceNum = wub_bcd_2_long(strHDT.szTraceNo,3);
        }
    }
	
    //CTOS_LCDTClearDisplay();
    if(srTransRec.byTransType == VOID || srTransRec.byTransType == SALE_TIP)
		CTOS_LCDTClearDisplay();
	else
       vdClearBelowLine(2);
		/* BDO CLG: Fleet card support - start -- jzg */
		//if(srTransRec.fFleetCard == TRUE)
		//	vdDispTransTitle(FLEET_SALE);
		//else
		/* BDO CLG: Fleet card support - end -- jzg */
		
		if(srTransRec.byTransType == SALE_OFFLINE || srTransRec.byTransType == SETTLE || srTransRec.byTransType == SMAC_ACTIVATION)
	    	vdDispTransTitle(srTransRec.byTransType);
		else
			vdDispTransTitleAndCardType(srTransRec.byTransType);
		
	//if(strCPT.inCommunicationMode != WIFI_MODE)
	vdCTOS_DispStatusMessage("PROCESSING...");  
	
    vdDecideWhetherConnection(srTransPara);

		//BDO SIT #08: TIP Adjust transaction should not dial - start -- jzg
		if (srTransRec.byTransType == SALE_TIP)
			srTransPara->byOffline = CN_TRUE; 
		//BDO SIT #08: TIP Adjust transaction should not dial - end -- jzg

		/* BDO: Must immediately prompt "Must Settle" if settlement failed - start -- jzg */
     if(srTransPara->byTransType == SETTLE)
	{
	    //remove - must settle flag will be updated once settle transaction is triggered
	    //strMMT[0].fMustSettFlag = CN_TRUE;
		strcpy(strMMT[0].szSettleDate,"00000000");
	    inMMTSave(strMMT[0].MMTid);
	}
		/* BDO: Must immediately prompt "Must Settle" if settlement failed - end -- jzg */
    
    if (CN_FALSE == srTransPara->byOffline)
    {        
        if(VS_TRUE == strTCT.fDemo)
        {
            vdDebug_LogPrintf("DEMO Call Connect!!");
        }
        else
        {
            vdDebug_LogPrintf("Call Connect!!sharecom[%d]",strTCT.fShareComEnable);
            //gcitra      
	    	if (fCommAlreadyOPen == VS_FALSE){
					
				vdDebug_LogPrintf("fCommAlreadyOPen = %d",fCommAlreadyOPen);
				  usPreconnectStatus = 2;
				  vdDebug_LogPrintf("BEFORE srCommFuncPoint.inConnect");
				inCTOSS_CheckMemoryStatusEx("BEFORE srCommFuncPoint.inConnect");
            	if (srCommFuncPoint.inConnect(&srTransRec) != ST_SUCCESS)
            	{
            		vdDebug_LogPrintf("AFTER FAILED CONNECT");
					fConnectFailed = TRUE;
					
					inCTOS_inDisconnect();
					if(strCPT.fCommBackUpMode == CN_TRUE) //Comms fallback -- jzg
					{
						fConnectFailed = FALSE;
					
						if(inCTOS_CommsFallback(strHDT.inHostIndex) != d_OK) //Comms fallback -- jzg
							return ST_ERROR;
						
						if (srCommFuncPoint.inConnect(&srTransRec) != ST_SUCCESS)
						{
							fConnectFailed = TRUE;
							inCTOS_inDisconnect();
						}
						else
						{
							fCommAlreadyOPen = VS_TRUE;
						}
					}

					if (fConnectFailed == TRUE) 
					{            
            			if (srTransPara->shTransResult == 0)
            				srTransPara->shTransResult = TRANS_COMM_ERROR;

						//0722
						fCommAlreadyOPen = VS_FALSE;
									
						if (srTransPara->shTransResult == TRANS_TERMINATE)
						{
							//aaronnino for BDOCLG ver 9.0 fix on issue #00121 Message error display  Connect Failed should be Connect Failed start
							//vdSetErrorMessage("CONNECT FAILED");
							CTOS_LCDTClearDisplay();
							#if 0
							CTOS_Sound(1000, 50);
							CTOS_LCDTPrintXY(1,7,"Connect Failed");			
							CTOS_LCDTPrintXY(1,8,"Please Call");
							vdSetErrorMessage("");
							CTOS_Delay(1000);
							CTOS_LCDTPrintXY(1,7,"              "); 
							CTOS_LCDTPrintXY(1,8,"           ");
							
							//vdCTOS_MultiLineDisplayMessage("", "Connect Failed", "Please Call");
							vdDisplayErrorMsgResp2(" ", "Connect Failed", "Please Call");
							vdSetErrorMessage("");
							#endif
							return ST_NO_CONNECT_ERR; //aaronnino for BDOCLG ver 9.0 fix on issue #00460 Settle failed retries should not count terminal level connection error
							}
						else  
							{
							      if (srTransRec.usTerminalCommunicationMode == WIFI_MODE)
							      	{
							      	   vdDisplayErrorMsgResp2(" ", "WIFI Problem","Please Call");
						             vdSetErrorMessage("");   
            				     return ST_ERROR;
							      	}
                				vdDisplayErrorMsgResp2(" ", " ", "TRANS COMM ERROR");
    						        vdSetErrorMessage("");   
                				return ST_ERROR;
							}
									//0722
        			}
				}
			else
			{
            	 fCommAlreadyOPen = VS_TRUE;

          }
			inCTOSS_CheckMemoryStatusEx("AFTER srCommFuncPoint.inConnect");
	   }
			//gcitra
     }

		vdDebug_LogPrintf("AFTER SUCCESSFULL CONNECT");
				/*BDO: Separate dialing number for BIN Ver - start -- jzg */
        if(srTransPara->byTransType != BIN_VER)
        {
           //inReversalType = 1; //pre trans
           if(inProcessReversal(srTransPara, PRE_TXN) != ST_SUCCESS) //BDO: Revised reversal function -- jzg
           {
              inReversalType = 2; 
              inCTOS_inDisconnect();
              if(srTransRec.byTransType == SETTLE) //aaronnino for BDOCLG ver 9.0 fix on issue #00500 and #00501 
                 return ST_REVERSAL_SETTLE_ERR;
              else
                 return ST_ERROR;
           }
		   else
		   {
				inReversalType = 0; 
				memset(srTransRec.szRespCode,0x00,sizeof(srTransRec.szRespCode));//clear srTransRec.szRespCode after successful reversal
		   }
        }
				/*BDO: Separate dialing number for BIN Ver - end -- jzg */
        vdDebug_LogPrintf("AFTER inProcessReversal");
        if(srTransPara->byTransType == SETTLE)
        {
            if ((inResult = inProcessAdviceTrans(srTransPara, -1)) != ST_SUCCESS)
            {
                vdDebug_LogPrintf(". inProcessAdviceTrans(%d) ADV_ERROR!!", inResult);
                inCTOS_inDisconnect();
				vdSetErrorMessage("Advice Error");
                return ST_ERROR;
            }

			if(strTCT.fATPBinRoute == TRUE)//Reload HDT. Fix for issue where ATP NII is used succeeding messages if there are pending advice on settlement.
				inHDTRead(srTransPara->HDTid);
			
            if ((inResult = inProcessTransLogTrans(srTransPara, -1, 1, GET_ALL)) != ST_SUCCESS)
            {
                vdDebug_LogPrintf(". inProcessAdviceTrans(%d) ADV_ERROR!!", inResult);
                inCTOS_inDisconnect();
				vdSetErrorMessage("Advice Error");
                return ST_ERROR;
            }

			
			if ((inResult = inProcessEMVTCUpload_PreAuthDCC(srTransPara, -1)) != ST_SUCCESS)
			{
				vdDebug_LogPrintf(". inProcessAdviceTrans(%d) ADV_ERROR!!", inResult);
				inCTOS_inDisconnect();
				vdSetErrorMessage("TC Upload Error");
				return ST_ERROR;
			}
			else							
				inHDTRead(srTransPara->HDTid);//Reload HDT since inProcessEMVTCUpload_PreAuthDCC() uses szDCCAuthTPDU().

            if ((inResult = inProcessEMVTCUpload_Settlement(srTransPara, -1)) != ST_SUCCESS)
            {
                vdDebug_LogPrintf(". inProcessAdviceTrans(%d) ADV_ERROR!!", inResult);
                inCTOS_inDisconnect();
				vdSetErrorMessage("TC Upload Error");
                return ST_ERROR;
            }
            
			if(strTCT.fATPBinRoute == TRUE)//Reload HDT. Fix for issue where ATP NII is used succeeding messages if there are pending TC Upload on settlement.
				inHDTRead(srTransPara->HDTid);
        }
        
    }
    else
    {
        CTOS_RTC SetRTC;
        BYTE szCurrentTime[20];
    
        CTOS_RTCGet(&SetRTC);
	    sprintf(szCurrentTime,"%02d%02d",SetRTC.bMonth, SetRTC.bDay);
        wub_str_2_hex(szCurrentTime,srTransPara->szDate,DATE_ASC_SIZE);
        sprintf(szCurrentTime,"%02d%02d%02d", SetRTC.bHour,SetRTC.bMinute,SetRTC.bSecond);
        wub_str_2_hex(szCurrentTime,srTransPara->szTime,TIME_ASC_SIZE);
		vdDebug_LogPrintf("AFTER CTOS_RTCGet");

       #if 0
	   vdDebug_LogPrintf("srTransRec.byTransType: %d, srTransRec.szAuthCode: %s", srTransRec.byTransType, srTransRec.szAuthCode);
	   
       if(srTransRec.byTransType == SALE_OFFLINE && memcmp(srTransRec.szAuthCode,"Y1",2)) /*force offline should still be done online*/
       {
          if(VS_TRUE == strTCT.fDemo)
          {
             vdDebug_LogPrintf("DEMO Call Connect!!");
          }
          else
          {
             vdDebug_LogPrintf("Call Connect!!sharecom[%d]",strTCT.fShareComEnable);
             
             if (fCommAlreadyOPen == VS_FALSE)
             {
                vdDebug_LogPrintf("fCommAlreadyOPen = %d",fCommAlreadyOPen);
                if (srCommFuncPoint.inConnect(&srTransRec) != ST_SUCCESS)
                {
                   
                   fConnectFailed = TRUE;
                   
                   inCTOS_inDisconnect();
                   if(strCPT.fCommBackUpMode == CN_TRUE) //Comms fallback -- jzg
                   {
                      fConnectFailed = FALSE;
                      
                      if(inCTOS_CommsFallback(strHDT.inHostIndex) != d_OK) //Comms fallback -- jzg
                      return ST_ERROR;
                      
                      if (srCommFuncPoint.inConnect(&srTransRec) != ST_SUCCESS)
                      {
                         fConnectFailed = TRUE;
                         inCTOS_inDisconnect();
                      }
                      else
                      {
                         fCommAlreadyOPen = VS_TRUE;
                      }
                   }
                   
                   if (fConnectFailed == TRUE) 
                   {            
                       if (srTransPara->shTransResult == 0)
                       srTransPara->shTransResult = TRANS_COMM_ERROR;
                       
                       //0722
                       fCommAlreadyOPen = VS_FALSE;
                       
                       if (srTransPara->shTransResult == TRANS_TERMINATE)
                       {
                          CTOS_LCDTClearDisplay();
                          return ST_NO_CONNECT_ERR; 
                       }
                       else  
                          vdSetErrorMessage("TRANS COMM ERROR");
											 
                       return ST_ERROR;
                       //0722
                   }
                }
                else
                {
                   
                   fCommAlreadyOPen = VS_TRUE;
                   
                   if ((inResult = inBuildOnlineMsg(srTransPara)) != ST_SUCCESS)
                   {			
                      if (((srTransPara->byEntryMode == CARD_ENTRY_ICC) ||
                      (srTransPara->bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
                      (srTransPara->bWaveSID == d_VW_SID_AE_EMV) ||
                      (srTransPara->bWaveSID == d_VW_SID_CUP_EMV) ||
                      (srTransPara->bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
                      (srTransPara->bWaveSID == d_VW_SID_VISA_WAVE_QVSDC)) &&
                      (srTransPara->byTransType == SALE || srTransPara->byTransType == PRE_AUTH))				
                      /* EMV: Revised EMV details printing - end -- jzg */ // patrick fix contactless 20140828
                      { 
                         if((inResult == ST_SEND_DATA_ERR) ||
                         (inResult == ST_UNPACK_DATA_ERR))
                         {
                            srTransPara->shTransResult = TRANS_COMM_ERROR;
                         }
                            vdDebug_LogPrintf("CARD_ENTRY_ICC Flow");
                      } 
                      else
                      {
                         vdDebug_LogPrintf("inBuildOnlineMsg %d",inResult);
                      }
                      
                      if(srTransPara->byTransType != SETTLE)
                      {
                         if((inResult == ST_SEND_DATA_ERR) || (inResult == ST_UNPACK_DATA_ERR))
                         {
                            inReversalType = 2;
                            inProcessReversal(srTransPara, POST_TXN); //BDO: Revised reversal function -- jzg
                            return(ST_ERROR);
                         }
                      }
                      
                      return inResult;
                   
                   }
                 inProcessAdviceTrans(&srTransRec, strHDT.inNumAdv);
                }
             }
             //gcitra
          }
    }

		#endif
    }

		/* BDO: Must immediately prompt "Must Settle" if settlement failed - start -- jzg */
    if(srTransPara->byTransType != SETTLE)
		{
				/*for TLE field 57*/
				byField_02_ON = 0;
				byField_14_ON = 0;
				byField_35_ON = 0;
				byField_45_ON = 0;
				byField_48_ON = 0;
		}
		/* BDO: Must immediately prompt "Must Settle" if settlement failed - end -- jzg */

    srTransPara->byContinueTrans = CN_FALSE;
    do
    {	  
        if (CN_FALSE == srTransPara->byOffline)
        {
                fBuildandSendProcess = VS_TRUE;
				vdDebug_LogPrintf("BEFORE inBuildOnlineMsg");
            if ((inResult = inBuildOnlineMsg(srTransPara)) != ST_SUCCESS)
            {			
				if (((srTransPara->byEntryMode == CARD_ENTRY_ICC) ||
				//(srTransPara->bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||		
				(srTransPara->bWaveSID == 0x65) ||
				(srTransPara->bWaveSID == d_VW_SID_AE_EMV) ||
				(srTransPara->bWaveSID == d_VW_SID_CUP_EMV) ||
				(srTransPara->bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
				//(srTransPara->bWaveSID == d_VW_SID_JCB_WAVE_2) ||
				(srTransPara->bWaveSID == 0x63) ||
				(srTransPara->bWaveSID == d_EMVCL_SID_DISCOVER_DPAS) ||
				(srTransPara->bWaveSID == d_VW_SID_VISA_WAVE_QVSDC)) &&
                (srTransPara->byTransType == SALE || srTransPara->byTransType == PRE_AUTH))				
				/* EMV: Revised EMV details printing - end -- jzg */ // patrick fix contactless 20140828
                { 
                    if((inResult == ST_SEND_DATA_ERR) ||
                       (inResult == ST_UNPACK_DATA_ERR))
                    {
                        srTransPara->shTransResult = TRANS_COMM_ERROR;
                    }
                    vdDebug_LogPrintf("CARD_ENTRY_ICC Flow");
                } 
                else
                {
                    vdDebug_LogPrintf("inBuildOnlineMsg %d",inResult);
                }

				if(srTransPara->byTransType != SETTLE){
					
					if((inResult == ST_RECEIVE_TIMEOUT_ERR) || (inResult == ST_UNPACK_DATA_ERR) /*|| (inResult == ST_SEND_DATA_ERR)*/)//Remove ST_SEND_DATA_ERR. Causes CRITICAL ERROR
					{
						inReversalType = 2;
						//inProcessReversalEx(srTransPara, POST_TXN);
						fBuildandSendProcess = VS_FALSE;//Set to false to display "Connection Terminated" on POST TXN reversal.
						inProcessReversal(srTransPara, POST_TXN); //BDO: Revised reversal function -- jzg
						return(ST_ERROR);
					}
					else if(inResult == TRANS_BINROUTE_REJECTED)
					{
						inMyFile_ReversalDelete();
						return(ST_ERROR);
					}
					else
					{
						if(srTransPara->byPackType != SEND_ADVICE){
							vdDebug_LogPrintf("3. Connection Terminated Please Try Again");
						    vdDisplayErrorMsgResp2(" Connection ","Terminated","Please Try Again");
						}
						
   			 			memset(srTransPara->szRespCode, 0, sizeof(srTransPara->szRespCode));/*do not execute retry transaction, display remaining trans amount*/
		   				return(ST_ERROR);
					}
				}

                return inResult;
								
            }
						
        }
        else //if (srTransRec.byTransType != SALE_OFFLINE)
        {
            if((srTransRec.byTransType == SALE_OFFLINE && memcmp(srTransRec.szAuthCode, "Y1",2) == 0) || (srTransRec.byTransType == SALE_TIP))
            {
                /* If the transaction is completed, offline transaction do not need to analyze any information*/
                if (inProcessOfflineTrans(srTransPara) != ST_SUCCESS)
                {
                    vdDebug_LogPrintf("inProcessOfflineTrans Err");
                    inCTOS_inDisconnect();
                    return ST_ERROR;
                }
                else
                    break;
            }
        }


        if (inAnalyseIsoData(srTransPara) != ST_SUCCESS)
        {
            vdDebug_LogPrintf("inAnalyseIsoData Err byTransType[%d]shTransResult[%d]srTransPara->szRespCode[%s]", srTransPara->byTransType, srTransRec.shTransResult, srTransPara->szRespCode);

            if((srTransPara->byTransType == SETTLE) && (!memcmp(srTransPara->szRespCode,"95",2)))
            {
            	  inResult = inPorcessTransUpLoad(srTransPara);
                if(inResult != ST_SUCCESS)
                {
									srTransRec.shTransResult = TRANS_COMM_ERROR;
									inCTOS_inDisconnect();

									/* BDO: Display the correct error message if batch upload error or settlement recon err -- jzg */
									if(inResult == ST_CLS_BATCH_ERR)
										{
    										//vdSetErrorMessage("SETTLE FAILED");
    										vdDisplayErrorMsgResp2(" ", " ","SETTLE FAILED");
    			              vdSetErrorMessage("");
										}
									else
										vdSetErrorMessage("BATCH UPLOAD ERROR");
						
									return ST_ERROR;
                }
            }
						#if 0 //aaronnino for BDOCLG ver 9.0 fix on issue #00241 No Manual Settle/Clear Batch prompt after 3 failed
						/* BDO: Manual settlement prompt after failed settlement - start -- jzg */
						else if((srTransPara->byTransType == SETTLE) && (gvSettleType != MULTI_SETTLE))
						{
							inBDOManualSettle();
							return ST_ERROR;
						}
						/* BDO: Manual settlement prompt after failed settlement - end -- jzg */
						#endif
#ifdef ONLINE_PIN_SUPPORT
						/* POC: 2 dip online pin - start -- jzg*/
						else if((srTransPara->byTransType == SALE) && (!memcmp(srTransPara->szRespCode, RESP_DO_ONLINE_PIN, 2)))
            {
            		vdDebug_LogPrintf("JEFF::MUST ENTER PIN");
								inMyFile_ReversalDelete();
            		vdSetErrorMessage("MUST ENTER PIN");
								return ST_RESP_DO_ONLINE_PIN;
            }
						/* POC: 2 dip online pin - end -- jzg*/
#endif
						else
            {

                if((strHDT.fReversalEnable == CN_TRUE) && (srTransPara->byTransType != SETTLE) && (srTransRec.shTransResult == TRANS_REJECTED || srTransRec.shTransResult == TRANS_CALL_BANK))
                {
                    inMyFile_ReversalDelete();
                }
				//else
				//{
				//	inProcessReversalEx(srTransPara, POST_TXN);
				//}
                
                inCTOS_inDisconnect();
                
                if((inGetErrorMessage(szErrorMessage) > 0) || (srTransRec.shTransResult == TRANS_REJECTED))
                {
                    vdDebug_LogPrintf("2nd AC failed or Host reject");
                }

                return ST_ERROR;
            }
        }
        else
        {
        
					vdCTOS_SyncHostDateTime();        	
					/*BDO: Separate dialing number for BIN Ver - start -- jzg */
					if(srTransPara->byTransType != BIN_VER)
						if((strHDT.fReversalEnable == CN_TRUE) && (srTransPara->byTransType != SETTLE))
						{
							inMyFile_ReversalDelete();//
						}
					/*BDO: Separate dialing number for BIN Ver - end -- jzg */
        }
    
    } while (srTransPara->byContinueTrans);

	DebugAddSTR("inBuildAndSendIsoData","end",20);

		/*BDO: Separate dialing number for BIN Ver - start -- jzg */
		if((srTransPara->byTransType == BIN_VER) && (strCPT.inCommunicationMode == DIAL_UP_MODE))
		{
			inCTOS_inDisconnect();
			fCommAlreadyOPen = FALSE;
		}
		/*BDO: Separate dialing number for BIN Ver - end -- jzg */

		
		//remove "Processing" display after printing 
		//vduiClearBelow(2);


	if(memcmp(srTransRec.szAuthCode,"Y1",2) == 0) 
		if(strTCT.fDisplayAPPROVED == TRUE && srTransRec.byTransType != VOID && srTransRec.byTransType != SALE_TIP)
			vdDisplayErrorMsgResp2(" ", " ", "APPROVED");

    return ST_SUCCESS;
    
}

/************************************************************************
Function Name: inSnedReversalToHost()
Description:
    Send Reversal Data To Host
Parameters:
    [IN] srTransPara
         inTransCode

Return: ST_SUCCESS  
        ST_ERROR
        TRANS_COMM_ERROR
        ST_SEND_DATA_ERR
        ST_UNPACK_DATA_ERR
************************************************************************/
//int inSnedReversalToHost(TRANS_DATA_TABLE *srTransPara, int inTransCode)
int inSnedReversalToHost(TRANS_DATA_TABLE *srTransPara, int inTransCode, short shTxnFlag)
{
    int inResult;
    int inSendLen, inReceLen;
    BYTE uszSendData[ISO_SEND_SIZE + 1], uszReceData[ISO_REC_SIZE + 1];
    CHAR szFileName[d_BUFF_SIZE];
    BOOL fModifyReversal = FALSE;
	//version16
	int inRet;
	
    memset(szFileName,0,sizeof(szFileName));
    sprintf(szFileName, "%s%02d%02d.rev"
                        , strHDT.szHostLabel
                        , strHDT.inHostIndex
                        , srTransRec.MITid);
    
	DebugAddSTR("inSnedReversalToHost",szFileName,12);  
    
    vdDebug_LogPrintf("Rever Name %s",szFileName);
    
    if((inResult = inMyFile_CheckFileExist(szFileName)) < 0)
    {
        vdDebug_LogPrintf("inMyFile_CheckFileExist <0");
        return ST_SUCCESS;
    }

    //version16- fix for reversal powerfail issue
	strHDT.inFailedREV = strHDT.inFailedREV+1;
	inHDTSave(strHDT.inHostIndex);
	vdDebug_LogPrintf("increment strHDT.inFailedREV = %d", strHDT.inFailedREV);

	inRet = inExceedMaxTimes_ReversalDelete2();

	if (inRet == ST_SUCCESS)
		return ST_SUCCESS;
	else if (inRet == ST_ERROR)
		return ST_ERROR;
	//end of fixes
    
    inSendLen = inResult;
    
    vdDebug_LogPrintf("inMyFile_ReversalRead(%d)",inResult);
    if((inResult = inMyFile_ReversalRead(&uszSendData[0],sizeof(uszSendData))) == ST_SUCCESS)
    {   
		if (shTxnFlag == POST_TXN)//only post_txn need reset the field39
		{
			
			if(srTransPara->byEMVReversal > 0)
			{
				vdDebug_LogPrintf("modify reversal");
				//case EMV_CRITICAL_ERROR:
				inSendLen =	insert_field(uszSendData, 37, srTransPara->szRRN, uszSendData);	
				inSendLen =	insert_field(uszSendData, 38, srTransPara->szAuthCode, uszSendData);	
				fModifyReversal = TRUE;
				//break;							
			}
    	}

		if(fModifyReversal == TRUE)
        {
            //inMyFile_ReversalDelete();
            inMyFile_ReversalDelete2();
			
            if((inResult = inMyFile_ReversalSave(&uszSendData[0], inSendLen)) != ST_SUCCESS)
            {
                vdDebug_LogPrintf(". inSave_inMyFile_ReversalSave(%04x)",inResult);
                inCTOS_inDisconnect();
                inResult = ST_ERROR;
            }	
        }	
		
        DebugAddHEX("Reversal orig", uszSendData, inSendLen);
        inCTOSS_ISOEngCheckEncrypt(srTransPara->HDTid, uszSendData, &inSendLen);
        DebugAddHEX("Reversal Encrypt", uszSendData, inSendLen);
        if ((inReceLen = inSendAndReceiveFormComm(srTransPara,
                             (unsigned char *)uszSendData,
                             inSendLen,
                             (unsigned char *)uszReceData)) <= ST_SUCCESS)
        {
            vdDebug_LogPrintf("inSnedReversalToHost Send Err %d", inReceLen);
            srTransRec.shTransResult = TRANS_COMM_ERROR;

			if(inReceLen == ST_COMMS_DISCONNECT  || ST_RECEIVE_TIMEOUT_ERR)
				return inReceLen;
			else				
	            return ST_SEND_DATA_ERR;
        }
        
        vdSetISOEngTransDataAddress(srTransPara);
        inResult = inCTOSS_UnPackIsodata(srTransPara->HDTid,
                                     (unsigned char *)uszSendData,
                                     inSendLen,
                                     (unsigned char *)uszReceData,
                                     inReceLen);
        if (inResult != ST_SUCCESS)
        {
            vdDebug_LogPrintf("inSnedReversalToHost inCTOSS_UnPackIsodata Err");
            return ST_UNPACK_DATA_ERR;
        }else
        {   
           	if (memcmp(srTransPara->szRespCode, "00", 2) == 0 || 
			   (memcmp(srTransPara->szRespCode, "39", 2) == 0 && srTransPara->HDTid == SMGIFTCARD_HDT_INDEX) || 
			   (memcmp(srTransPara->szRespCode, "95", 2) == 0 && srTransPara->HDTid == SMSHOPCARD_HDT_INDEX ) )
    		{
                inResult = CTOS_FileDelete(szFileName);
                if (inResult != d_OK)
    			{
    			    vdDebug_LogPrintf(". inSnedReversalToHost %04x",inResult);
                    inCTOS_inDisconnect();
                    return ST_ERROR;
    			} 
                else{
					strHDT.inFailedREV = 0;
					inDatabase_TerminalOpenDatabase();
					inHDTSaveFailedRev(strHDT.inHostIndex);
					
                    vdDebug_LogPrintf("rev. file deelted succesfully after send rev to host");
					//tag reversal as deleted in MMT
					strMMT[0].fPendingReversal = FALSE;
					inMMTSaveEx(strMMT[0].MMTid);
		            inDatabase_TerminalCloseDatabase();
                }
                
    		}
			else
    		{
    		    vdDebug_LogPrintf(". inSnedReversalToHost Resp Err %02x%02x",srTransPara->szRespCode[0],srTransPara->szRespCode[1]);
                inCTOS_inDisconnect();

                return ST_ERROR;
    		}
        }
    }
	
    vdDebug_LogPrintf("**inSnedReversalToHost END**");
    
    return ST_SUCCESS;
}

/************************************************************************
Function Name: inSaveReversalFile()
Description:
    Save Reversal Data into file
Parameters:
    [IN] srTransPara
         inTransCode

Return: ST_SUCCESS  
        ST_ERROR
        ST_BUILD_DATD_ERR
************************************************************************/
int inSaveReversalFile(TRANS_DATA_TABLE *srTransPara, int inTransCode)
{
    int inResult = ST_SUCCESS;
    int inSendLen, inReceLen;
    unsigned char uszSendData[ISO_SEND_SIZE + 1], uszReceData[ISO_REC_SIZE + 1];

    
    vdDebug_LogPrintf("**inSaveReversalFile START TxnType[%d]Orig[%d]**", srTransPara->byTransType, srTransPara->byOrgTransType);

    if(REFUND == srTransPara->byTransType)
        srTransPara->byPackType = REFUND_REVERSAL;
    else if(VOID == srTransPara->byTransType && REFUND == srTransPara->byOrgTransType)
        srTransPara->byPackType = VOIDREFUND_REVERSAL;
    else if(VOID == srTransPara->byTransType)
        srTransPara->byPackType = VOID_REVERSAL;        
    else if(PRE_AUTH == srTransPara->byTransType)
        srTransPara->byPackType = PREAUTH_REVERSAL;	
	else if(CASH_ADVANCE == srTransPara->byTransType)
        srTransPara->byPackType = CASHADVANCE_REVERSAL;	
		/* BDO: Quasi should be parametrized per issuer - start -- jzg */
	//else if ((srTransPara->byTransType == SALE) && (strIIT.fQuasiCash == TRUE))
		//srTransPara->byPackType = QUASI_REVERSAL;
		/* BDO: Quasi should be parametrized per issuer - end -- jzg */
    else
        srTransPara->byPackType = REVERSAL;

    vdDebug_LogPrintf(" byPackType(%d)",srTransPara->byPackType);   
	
    vdSetISOEngTransDataAddress(srTransPara);
	if ((inSendLen = inCTOSS_PackIsoDataNoEncryp(srTransPara->HDTid, strHDT.szTPDU, uszSendData, srTransPara->byPackType)) <= ST_SUCCESS)
    {  
		inCTOS_inDisconnect();
        vdDebug_LogPrintf(" inSave_inSendLen %d",inSendLen);
        vdDebug_LogPrintf("**inSaveReversalFile ST_BUILD_DATD_ERR**");
        srTransPara->byPackType = inTransCode;
        inResult = ST_BUILD_DATD_ERR;
    }
    
    vdDebug_LogPrintf(". inSaveReversalFile Send(%02x)(%02x)(%02x)(%02x)(%02x)(%02x)(%02x)(%02x)(%02x)(%02x)",uszSendData[0],uszSendData[1],uszSendData[2],uszSendData[3],uszSendData[4],uszSendData[5],uszSendData[6],uszSendData[7],uszSendData[8],uszSendData[9]);

    vdDebug_LogPrintf(". inSaveReversalFile Send Len(%d)",inSendLen);

    if((inResult = inMyFile_ReversalSave(&uszSendData[0], inSendLen)) != ST_SUCCESS)
    {
        vdDebug_LogPrintf(". inSave_inMyFile_ReversalSave(%04x)",inResult);
        inCTOS_inDisconnect();
        inResult = ST_ERROR;
    }

	strMMT[0].fPendingReversal = TRUE;
	inMMTSave(strMMT[0].MMTid);
    
    srTransPara->byPackType = inTransCode;
    
    return inResult;
}


/************************************************************************
Function Name: inProcessReversal()
Description:
    Processing Reversal the transaction flow
Parameters:
    [IN] srTransPara

Return: ST_SUCCESS  
        ST_ERROR
************************************************************************/

int inProcessReversal(TRANS_DATA_TABLE *srTransPara, short shTxnFlag)
{    
    int inResult,inTransCode;

	/* BDO: [SEND REVERSAL TRIES] --sidumili */
	int inRevTries = 3;
	BOOL fAutoDelRev = FALSE;
	/* BDO: [SEND REVERSAL TRIES] --sidumili */

  
    /*for TLE field 57*/
    byField_02_ON = 0;
    byField_14_ON = 0;
    byField_35_ON = 0;
    byField_45_ON = 0;
    byField_48_ON = 0;
	
    vdDebug_LogPrintf("**inProcessReversal START**");
    
    inResult = ST_SUCCESS;    
    inTransCode = srTransPara->byTransType;    
    srTransPara->byPackType = REVERSAL;
    vdDebug_LogPrintf(". inProcessReversal transtype %d",srTransPara->byTransType);
    vdDebug_LogPrintf(". inProcessReversal pack type %d",srTransPara->byPackType);
    vdDebug_LogPrintf(". inProcessReversal HDTid %d",srTransPara->HDTid);


	/* BDO PHASE 2:[Flag for auto delete reversal file if host does not respond] -- sidumili */
	fAutoDelRev = strHDT.fAutoDelReversal; 

	/* BDO PHASE 2:[Reversal Tries] -- sidumili */
	inRevTries = strHDT.inReversalTries;

	vdDebug_LogPrintf("-->>inProcessReversal fAutoDelReversal[%d] -- inReversalTries[%d]", fAutoDelRev, inRevTries);

	/* Check reversal flag, If flag is true then open reversal file and send data to host */    
	if ((inResult = inSnedReversalToHost(srTransPara,inTransCode,shTxnFlag)) != ST_SUCCESS)
	{
	    vdDebug_LogPrintf(". Process_inSnedReversalToHost %d",inResult);

		/*sidumili: [commented as suggested by patrick]*/
		#if 1		
		if(inExceedMaxTimes_ReversalDelete() != ST_SUCCESS)
		{
			vdDisplayErrorMsg(1, 8, "Delete REV Fail...");
		}
		else
		{
			if(strHDT.inFailedREV <= 0)//Enhancement to automatically proceed to sale after reversal retry exceeded scenario
			{
				if(inResult == ST_COMMS_DISCONNECT || inResult == ST_SEND_DATA_ERR)
				{
					vdDisplayErrorMsgResp2(" Connection ","Terminated","Please Try Again");
				}
				else
				{
					inResult=ST_SUCCESS;
					memset(srTransPara->szRespCode,0x00,RESP_CODE_SIZE+1);
				}
			}
				
		}
		#endif
	}
	/*sidumili: [commented as suggested by patrick]*/

	/* BDO PHASE2: [Fix for delete reversal for force 0410 response] -- sidumili */
	if ((strlen(srTransPara->szRespCode) > 0) && (inResult == ST_SUCCESS))
	{
		inMyFile_ReversalDelete();

		//BDO: Revised reversal function - start -- jzg
		if (shTxnFlag == POST_TXN)
		{
			if(strcmp((char *)srTransRec.szRespCode, "00") ==  0)
			{
				strcpy(srTransRec.szRespCode,"");
				strcpy(srTransRec.szECRRespCode, ECR_COMMS_ERR);
			}
						
			if(srTransPara->byTransType != PRE_AUTH)
			{
				//aaronnino for BDOCLG ver 9.0 fix on issue #00118 Message error display Rvrsal Ok, Try Again should be Reversal OK start
				vdDisplayErrorMsgResp2(" ", "Reversal OK", "Please Try Again");
				vdSetErrorMessage(""); 
				inReversalType=1;
        		//aaronnino for BDOCLG ver 9.0 fix on issue #00118 Message error display Rvrsal Ok, Try Again should be Reversal OK end

                //make responce code as -1 - for ECR transaction 
				strcpy(srTransRec.szRespCode,"");
				strcpy(srTransRec.szECRRespCode, ECR_DECLINED_ERR);
				
				return(ST_SUCCESS);
			}
			else
				return(ST_ERROR);
		}
		//BDO: Revised reversal function - end -- jzg

 		 //return(ST_SUCCESS); //BDO: Pending rev should not exit the current txn flow -- jzg

		inResult = ST_SUCCESS;
	}
	/* BDO PHASE2: [Fix for delete reversal for force 0410 response] -- sidumili */

	if(strcmp((char *)srTransRec.szRespCode, "00") ==  0)
	{
		strcpy(srTransRec.szRespCode,"");
		strcpy(srTransRec.szECRRespCode, ECR_COMMS_ERR);
	}

	//BDO: should display COMM ERROR if pending reversal has no reply - start -- jzg
	if((inResult != ST_SUCCESS) && (shTxnFlag == PRE_TXN))
	{
		memcpy(strHDT.szTraceNo,szORIGTraceNo, INVOICE_BCD_SIZE);	
		inHDTSave(strHDT.inHostIndex);        
		return(ST_ERROR);
	}
	//BDO: should display COMM ERROR if pending reversal has no reply - end -- jzg

#if 1
    if(inResult == ST_SUCCESS)
    {
        inMyFile_ReversalDelete();
        /* Check reversal flag, If flag is true then create reversal file */
		/*BDO: No reversal on SMAC_ACTIVATION/SMAC_BALANCE/BALANCE_INQUIRY(SM Guarantor) -- sidumili*/
		
		vdDebug_LogPrintf(". inProcessReversal byTransType[%d] :: byPackType[%d] :: byOrgTransType[%d] :: byUploaded[%d] :: byOffline[%d] :: fCompletion[%d]", 
			srTransPara->byTransType, srTransPara->byPackType,srTransPara->byOrgTransType,srTransPara->byUploaded,srTransPara->byOffline,srTransPara->fCompletion);
        if ((strHDT.fReversalEnable == CN_TRUE) && (srTransRec.byTransType != SETTLE) && (srTransRec.byTransType != SIGN_ON) && (srTransRec.byTransType != BIN_VER) && 
			(srTransRec.byTransType!=PRE_AUTH) && (srTransRec.byTransType != SMAC_ACTIVATION) && 
			(srTransRec.byTransType != SMAC_BALANCE) && (srTransRec.byTransType != BALANCE_INQUIRY) && (srTransRec.byTransType != SALE_OFFLINE) && 
			!(srTransRec.byTransType == VOID && (srTransRec.byOrgTransType == SALE_OFFLINE || srTransRec.fCompletion == TRUE)) && (srTransRec.byTransType != KIT_SALE) 
			&& (srTransRec.byTransType != RENEWAL) && (srTransRec.byTransType != PTS_AWARDING))
        {
            vdDebug_LogPrintf("inSaveReversalFile START");
            if ((inResult = inSaveReversalFile(srTransPara,inTransCode)) != ST_SUCCESS)
            {
                vdDebug_LogPrintf(". Process_inSaveReversalFile %04x",inResult);
            }
        }
    }
    
    srTransPara->byTransType = inTransCode; 
    
    vdDebug_LogPrintf("**inProcessReversal TYPE(%d) Rest(%d)END**",srTransPara->byTransType,
                                                                     inResult);
		
	/*BDO PHASE 2: [Reversal - success]*/
	if ((strlen(srTransPara->szRespCode) > 0) && (inResult == ST_SUCCESS) && (srTransPara->byPackType == REVERSAL)){
		return(ST_SUCCESS);
	}
#endif		
    return inResult;
}


#if 0
/************************************************************************
Function Name: inProcessReversal()
Description:
    Processing Reversal the transaction flow
Parameters:
    [IN] srTransPara

Return: ST_SUCCESS  
        ST_ERROR
************************************************************************/

int inProcessReversalEx(TRANS_DATA_TABLE *srTransPara, short shTxnFlag)
{    
    int inResult,inTransCode;

	/* BDO: [SEND REVERSAL TRIES] --sidumili */
	int inRevTries = 3;
	BOOL fAutoDelRev = FALSE;
	/* BDO: [SEND REVERSAL TRIES] --sidumili */
  
    /*for TLE field 57*/
    byField_02_ON = 0;
    byField_14_ON = 0;
    byField_35_ON = 0;
    byField_45_ON = 0;
    byField_48_ON = 0;
	
    vdDebug_LogPrintf("**inProcessReversal START**");
    
    inResult = ST_SUCCESS;    
    inTransCode = srTransPara->byTransType;    
    srTransPara->byPackType = REVERSAL;
    vdDebug_LogPrintf(". transtype %d",srTransPara->byTransType);
    vdDebug_LogPrintf(". pack type %d",srTransPara->byPackType);

	/* BDO PHASE 2:[Flag for auto delete reversal file if host does not respond] -- sidumili */
	fAutoDelRev = strHDT.fAutoDelReversal; 

	/* BDO PHASE 2:[Reversal Tries] -- sidumili */
	inRevTries = strHDT.inReversalTries;

	vdDebug_LogPrintf("-->>inProcessReversal fAutoDelReversal[%d] -- inReversalTries[%d]", fAutoDelRev, inRevTries);
#if 0
	/* Check reversal flag, If flag is true then open reversal file and send data to host */    
	if ((inResult = inSnedReversalToHost(srTransPara,inTransCode)) != ST_SUCCESS)
	{
	    vdDebug_LogPrintf(". Process_inSnedReversalToHost %d",inResult);

		/*sidumili: [commented as suggested by patrick]*/
		#if 1		
		if(inExceedMaxTimes_ReversalDelete() != ST_SUCCESS)
		{
			vdDisplayErrorMsg(1, 8, "Delete REV Fail...");
		}
		#endif
	}
	/*sidumili: [commented as suggested by patrick]*/

	/* BDO PHASE2: [Fix for delete reversal for force 0410 response] -- sidumili */
	if ((strlen(srTransPara->szRespCode) > 0) && (inResult == ST_SUCCESS))
	{
		inMyFile_ReversalDelete();

		//BDO: Revised reversal function - start -- jzg
		if (shTxnFlag == POST_TXN)
		{
			if(srTransPara->byTransType != PRE_AUTH)
			{
				//aaronnino for BDOCLG ver 9.0 fix on issue #00118 Message error display Rvrsal Ok, Try Again should be Reversal OK start
				vdDisplayErrorMsgResp2(" ", "Reversal OK", "Please Try Again");
				vdSetErrorMessage(""); 
				inReversalType=1;
        		//aaronnino for BDOCLG ver 9.0 fix on issue #00118 Message error display Rvrsal Ok, Try Again should be Reversal OK end

                //make responce code as -1 - for ECR transaction 
				strcpy(srTransRec.szRespCode,"");
				strcpy(srTransRec.szECRRespCode, ECR_DECLINED_ERR);
				
				return(ST_SUCCESS);
			}
			else
				return(ST_ERROR);
		}
		//BDO: Revised reversal function - end -- jzg

 		 //return(ST_SUCCESS); //BDO: Pending rev should not exit the current txn flow -- jzg

		inResult = ST_SUCCESS;
	}
	/* BDO PHASE2: [Fix for delete reversal for force 0410 response] -- sidumili */



	//BDO: should display COMM ERROR if pending reversal has no reply - start -- jzg
	if((inResult != ST_SUCCESS) && (shTxnFlag == PRE_TXN))
	{
		memcpy(strHDT.szTraceNo,szORIGTraceNo, INVOICE_BCD_SIZE);	
		inHDTSave(strHDT.inHostIndex);        
		return(ST_ERROR);
	}
	//BDO: should display COMM ERROR if pending reversal has no reply - end -- jzg
#endif

    if(inResult == ST_SUCCESS)
    {
        inMyFile_ReversalDelete();
        /* Check reversal flag, If flag is true then create reversal file */
		/*BDO: No reversal on SMAC_ACTIVATION/SMAC_BALANCE/BALANCE_INQUIRY(SM Guarantor) -- sidumili*/
		
		vdDebug_LogPrintf(". inProcessReversal byTransType[%d] :: byPackType[%d] :: byOrgTransType[%d] :: byUploaded[%d] :: byOffline[%d] :: fCompletion[%d]", 
			srTransPara->byTransType, srTransPara->byPackType,srTransPara->byOrgTransType,srTransPara->byUploaded,srTransPara->byOffline,srTransPara->fCompletion);
        if ((strHDT.fReversalEnable == CN_TRUE) && (srTransRec.byTransType != SETTLE) && (srTransRec.byTransType != SIGN_ON) && (srTransRec.byTransType != BIN_VER) && 
			(srTransRec.byTransType!=PRE_AUTH) && (srTransRec.byTransType != SMAC_ACTIVATION) && 
			(srTransRec.byTransType != SMAC_BALANCE) && (srTransRec.byTransType != BALANCE_INQUIRY) && (srTransRec.byTransType != SALE_OFFLINE) && 
			!(srTransRec.byTransType == VOID && (srTransRec.byOrgTransType == SALE_OFFLINE || srTransRec.fCompletion == TRUE)) )
        {
            vdDebug_LogPrintf("inSaveReversalFile START");
            if ((inResult = inSaveReversalFile(srTransPara,inTransCode)) != ST_SUCCESS)
            {
                vdDebug_LogPrintf(". Process_inSaveReversalFile %04x",inResult);
            }
        }
    }
    
    srTransPara->byTransType = inTransCode; 
    
    vdDebug_LogPrintf("**inProcessReversal TYPE(%d) Rest(%d)END**",srTransPara->byTransType,
                                                                     inResult);
		
	/*BDO PHASE 2: [Reversal - success]*/
	if ((strlen(srTransPara->szRespCode) > 0) && (inResult == ST_SUCCESS) && (srTransPara->byPackType == REVERSAL)){
		return(ST_SUCCESS);
	}
		
    return inResult;
}
#endif


int inProcessAdviceTrans(TRANS_DATA_TABLE *srTransPara, int inAdvCnt)
{
	int inResult,inUpDateAdviceIndex;
	int inCnt;
	TRANS_DATA_TABLE srAdvTransTable;
	ISO_FUNC_TABLE srAdviceFunc;
	STRUCT_ADVICE strAdvice;
	
	BYTE szBaseAmount[12+1] = {0};
	BYTE szTipAmount[12+1] = {0};
	BYTE szLocalTotalAmount[12+1] = {0};


	inCTLOS_Updatepowrfail(PFR_IDLE_STATE);

	/* Issue# 000187 - start -- jzg */
	//1127
	//add to do not do any advice for Y1, advice will be sent on the next online transaction
	if ((stRCDataAnalyze.usTransResult == d_EMV_CHIP_OFF_APPROVAL) && (srTransPara->byTransType != SETTLE))
		return d_OK;
	//1127
	/* Issue# 000187 - end -- jzg */

	if(inCheckConnection() != d_OK)
		return ST_ERROR;

	memset((char *)&srAdvTransTable, 0, sizeof(TRANS_DATA_TABLE));
	memset((char *)&strAdvice, 0, sizeof(strAdvice));
	memcpy((char *)&srAdvTransTable, (char *)srTransPara, sizeof(TRANS_DATA_TABLE));
	memcpy((char *)&srAdviceFunc, (char *)&srIsoFuncTable[0], sizeof(ISO_FUNC_TABLE));

	inResult = ST_SUCCESS;

	vdDebug_LogPrintf("inProcessAdviceTrans byPackType(%d)byTransType(%d)", srAdvTransTable.byPackType, strAdvice.byTransType);
	
	while(1)
	{
		inResult = inMyFile_AdviceRead(&inUpDateAdviceIndex,&strAdvice,&srAdvTransTable);

		vdDebug_LogPrintf("ADVICE inUpDateAdviceIndex[%d] inMyFile_AdviceRead Rult(%d)(%d)(%d)(%d)", inUpDateAdviceIndex, inResult, srAdvTransTable.ulTraceNum, srAdvTransTable.byPackType, strAdvice.byTransType);

		if(inResult == ST_ERROR || inResult == RC_FILE_READ_OUT_NO_DATA)
		{
			inResult = ST_SUCCESS;
			break;
		}

		if(inResult == ST_SUCCESS)
		{
			if(strTCT.fDCC && srTransRec.fDCC)
			    memcpy(srTransRec.szAdviceInvoiceNo, srAdvTransTable.szInvoiceNo, INVOICE_BCD_SIZE);
			
			vdDebug_LogPrintf("srTransPara->HDTid = [%d] CVV2[%s]Tip[%02X%02X%02X%02X%02X%02X]", srTransPara->HDTid,srAdvTransTable.szCVV2, srAdvTransTable.szTipAmount[0], srAdvTransTable.szTipAmount[1], srAdvTransTable.szTipAmount[2], srAdvTransTable.szTipAmount[3], srAdvTransTable.szTipAmount[4], srAdvTransTable.szTipAmount[5]);
			inMyFile_HDTTraceNoAdd(srTransPara->HDTid);
			inHDTRead(srTransPara->HDTid);

			//if(inGetATPBinRouteFlag() )
			if (srAdvTransTable.fBINRouteApproved == 1)
					 memcpy(strHDT.szTPDU,strTCT.ATPTPDU,5);

			//advice need add traceNum
			//srAdvTransTable.ulTraceNum = wub_bcd_2_long(strHDT.szTraceNo,3);
            fAdviceTras = VS_TRUE;
			inResult = inPackSendAndUnPackData(&srAdvTransTable, strAdvice.byTransType);

			vdDebug_LogPrintf(". inProcessAdviceTrans Rult(%d)srAdvTransTable.byTCFailUpCnt[%d]", inResult, srAdvTransTable.byTCFailUpCnt);
			if (memcmp(srAdvTransTable.szRespCode, "00", 2))
				inResult = ST_ERROR;

			if ((inResult == ST_SUCCESS))
			{
				if ((srAdviceFunc.inAdviceAnalyse != 0x00))
				{
					vdSetISOEngTransDataAddress(&srAdvTransTable);
					inResult = srAdviceFunc.inAdviceAnalyse(CN_FALSE);
				}

				if (inResult == ST_SUCCESS)
				{
					vdDebug_LogPrintf(". inAdviceAnalyse Rult(%d)", inResult);

					srAdvTransTable.byUploaded = CN_TRUE;
					srAdvTransTable.byPreviouslyUploaded = CN_TRUE;
					

					//Should be Online void the Intial SALE amount.
					//use szStoreID to store how much amount fill up in DE4 for VOID
					memcpy(srAdvTransTable.szStoreID, srAdvTransTable.szTotalAmount, 6);  


					if(srTransRec.fDCC)
					{
						memset(szBaseAmount,0x00,sizeof(szBaseAmount));
						memset(szTipAmount,0x00,sizeof(szTipAmount));
						memset(szLocalTotalAmount,0x00,sizeof(szLocalTotalAmount));
						memset(srTransRec.szLocalStoreID,0x00,sizeof(srTransRec.szLocalStoreID));
						
						wub_hex_2_str(srAdvTransTable.szDCCLocalTipAmount, szTipAmount, 6);
						wub_hex_2_str(srAdvTransTable.szDCCLocalAmount, szBaseAmount, 6); 
						sprintf(szLocalTotalAmount, "%012.0f", atof(szBaseAmount) + atof(szTipAmount));
						vdDebug_LogPrintf("szLocalTotalAmount [%s]",szBaseAmount);
						wub_str_2_hex(szLocalTotalAmount,srAdvTransTable.szLocalStoreID,12);
					}

					if((inResult = inMyFile_BatchSave(&srAdvTransTable,DF_BATCH_UPDATE)) == ST_SUCCESS)
					{
						inResult = inMyFile_AdviceUpdate(inUpDateAdviceIndex);
						vdDebug_LogPrintf(". inProcessAdviceTrans Update Rult(%d)**", inResult);
					}

					if (inResult != ST_SUCCESS)
					{
						vdDebug_LogPrintf(". inProcessAdviceTrans Err(%d)**", inResult);
						break;
					}
				}
			}
		}

		if(inResult != ST_SUCCESS)
		{
			if(srTransPara->byTransType == SETTLE)
			{
				srTransRec.shTransResult = TRANS_COMM_ERROR;
				inCTOS_inDisconnect();
				return ST_ERROR;
			}
			else
				return ST_SUCCESS;
		}

		if(inAdvCnt != -1)
		{
			inAdvCnt --;
			if(inAdvCnt == 0)
				break;
		}
	}

	vdDebug_LogPrintf("**inProcessAdviceTrans(%d) END**", inResult);
	return (inResult);
}



#if 1
int inProcessEMVTCUpload(TRANS_DATA_TABLE *srTransPara, int inAdvCnt)
{
    int inResult,inUpDateAdviceIndex;
    int inCnt;
    TRANS_DATA_TABLE srOrigTransFromBatch;
    TRANS_DATA_TABLE srAdvTransTable;
    ISO_FUNC_TABLE srAdviceFunc;
    STRUCT_ADVICE strAdvice;

    memset((char *)&srAdvTransTable, 0, sizeof(TRANS_DATA_TABLE));
    memset((char *)&strAdvice, 0, sizeof(strAdvice));
    
    memcpy((char *)&srAdvTransTable, (char *)srTransPara, sizeof(TRANS_DATA_TABLE));
    memcpy((char *)&srAdviceFunc, (char *)&srIsoFuncTable[0], sizeof(ISO_FUNC_TABLE));
    
    inResult = ST_SUCCESS;
        
    vdDebug_LogPrintf("inProcessEMVTCUpload byPackType(%d)byTransType(%d)", srAdvTransTable.byPackType, strAdvice.byTransType);
    while(1)
    {
        inResult = inMyFile_TCUploadFileRead(&inUpDateAdviceIndex,&strAdvice,&srAdvTransTable);
        
        if(strAdvice.byTransType == TC_UPLOAD)
            srAdvTransTable.byPackType = TC_UPLOAD;
        
        if(inResult == ST_ERROR || inResult == RC_FILE_READ_OUT_NO_DATA)
        {
            inResult = ST_SUCCESS;
            break;
        }

        memcpy(&srOrigTransFromBatch, &srAdvTransTable, sizeof(TRANS_DATA_TABLE));
        if(inResult == ST_SUCCESS)
        {
            vdDebug_LogPrintf("srTransPara->HDTid = [%d] ", srTransPara->HDTid);
            inMyFile_HDTTraceNoAdd(srTransPara->HDTid);
            inHDTRead(srTransPara->HDTid);

			if(inGetATPBinRouteFlag())
				memcpy(strHDT.szTPDU,strTCT.ATPTPDU,5);
	
			fAdviceTras = VS_TRUE;
            inResult = inPackSendAndUnPackData(&srAdvTransTable, strAdvice.byTransType);
            
            vdDebug_LogPrintf(". inProcessEMVTCUpload Rult(%d)srAdvTransTable.byTCFailUpCnt[%d]srTransPara->szRespCode[%s]", inResult, srAdvTransTable.byTCFailUpCnt,srAdvTransTable.szRespCode);

  
            if(srAdvTransTable.byTCFailUpCnt >= 2)
            {
              srAdvTransTable.byTCuploaded = CN_TRUE;
              srAdvTransTable.byUploaded = CN_TRUE;
              inResult = inMyFile_TCUploadFileUpdate(inUpDateAdviceIndex);
              vdDebug_LogPrintf(". inProcessEMVTCUpload Update Rult(%d)**", inResult);
                      
              if (inResult != ST_SUCCESS)
              {
                  vdDebug_LogPrintf(". inProcessEMVTCUpload Err(%d)**", inResult);
                  break;
              }
            }
            if (inResult == ST_SUCCESS)
            {
                if(memcmp(srAdvTransTable.szRespCode,"00",2) != 0)
                {
                    vdDebug_LogPrintf(". resp not succ(%s)**srTransPara->byPackType[%d]strAdvice.byTransType[%d]", srAdvTransTable.szRespCode,srTransPara->byPackType,strAdvice.byTransType);
                    if( strAdvice.byTransType == TC_UPLOAD )
                    {
                        srOrigTransFromBatch.byTCFailUpCnt++;                    
                        inMyFile_BatchSave(&srOrigTransFromBatch,DF_BATCH_UPDATE);
                        inCTOS_inDisconnect();
                        return ST_ERROR;
                    }
                }
                else
                {
                    srAdvTransTable.byTCuploaded = CN_TRUE;
                    srAdvTransTable.byUploaded = CN_TRUE;
                    inResult = inMyFile_TCUploadFileUpdate(inUpDateAdviceIndex);
                    vdDebug_LogPrintf(". inProcessEMVTCUpload Update Rult(%d)**", inResult);
                          
                    if (inResult != ST_SUCCESS)
                    {
                      vdDebug_LogPrintf(". inProcessEMVTCUpload Err(%d)**", inResult);
                      break;
                    }
                }    
            }
            else
            {
                if(strAdvice.byTransType == TC_UPLOAD)
                {
                    srOrigTransFromBatch.byTCFailUpCnt++; 
                    inMyFile_BatchSave(&srOrigTransFromBatch,DF_BATCH_UPDATE);
                }
            }
            
        }
        
        if(inResult != ST_SUCCESS)
        {
            if(srTransPara->byTransType == SETTLE)
            {
                srTransRec.shTransResult = TRANS_COMM_ERROR;
                inCTOS_inDisconnect();
                return ST_ERROR;
            }
            else
                return ST_SUCCESS;
        }

        
        if(inAdvCnt != -1)
        {
            inAdvCnt --;
            if(inAdvCnt == 0)
                break;
        }
    }
    
    vdDebug_LogPrintf("**inProcessEMVTCUpload(%d) END**", inResult);
	return (inResult);
}
#else
int inProcessEMVTCUpload(TRANS_DATA_TABLE *srTransPara, int inAdvCnt)
{
                int inResult,inUpDateAdviceIndex;
                int inCnt;
                TRANS_DATA_TABLE srOrigTransFromBatch;
                TRANS_DATA_TABLE srAdvTransTable;
                ISO_FUNC_TABLE srAdviceFunc;
                STRUCT_ADVICE strAdvice;
 
                memset((char *)&srAdvTransTable, 0, sizeof(TRANS_DATA_TABLE));
                memset((char *)&strAdvice, 0, sizeof(strAdvice));
                memcpy((char *)&srAdvTransTable, (char *)srTransPara, sizeof(TRANS_DATA_TABLE));
                memcpy((char *)&srAdviceFunc, (char *)&srIsoFuncTable[0], sizeof(ISO_FUNC_TABLE));
 
                inResult = ST_SUCCESS;
 
                vdDebug_LogPrintf("inProcessEMVTCUpload byPackType(%d)byTransType(%d)", srAdvTransTable.byPackType, strAdvice.byTransType);
 
                inResult = inMyFile_TCUploadFileRead(&inUpDateAdviceIndex,&strAdvice,&srAdvTransTable);
 
                if(strAdvice.byTransType == TC_UPLOAD)
                                srAdvTransTable.byPackType = TC_UPLOAD;
 
                if(inResult == ST_ERROR || inResult == RC_FILE_READ_OUT_NO_DATA)
                {
                                return ST_SUCCESS;
                }
 
                memcpy(&srOrigTransFromBatch, &srAdvTransTable, sizeof(TRANS_DATA_TABLE));
                if(inResult == ST_SUCCESS)
                {
                                vdDebug_LogPrintf("srTransPara->HDTid = [%d] ", srTransPara->HDTid);
                                inMyFile_HDTTraceNoAdd(srTransPara->HDTid);
                                inHDTRead(srTransPara->HDTid);
 
                                inResult = inPackSendAndUnPackData(&srAdvTransTable, strAdvice.byTransType);
                                vdDebug_LogPrintf(". inProcessEMVTCUpload Rult(%d)srTransPara->szRespCode[%s]", inResult, srAdvTransTable.szRespCode);
 
                                if (inResult == ST_SUCCESS)
                                {
                                                if(memcmp(srAdvTransTable.szRespCode,"00",2) != 0)
                                                {
                                                                vdDebug_LogPrintf(". resp not succ(%s)**srTransPara->byPackType[%d]strAdvice.byTransType[%d]", srAdvTransTable.szRespCode,srTransPara->byPackType,strAdvice.byTransType);
                                                                if( strAdvice.byTransType == TC_UPLOAD )
                                                                {
                                                                                srOrigTransFromBatch.byTCFailUpCnt++;                   
                                                                                inMyFile_BatchSave(&srOrigTransFromBatch,DF_BATCH_UPDATE);
                                                                                inCTOS_inDisconnect();
                                                                                return ST_ERROR;
                                                                }
                                                }
                                                else
                                                {
                                                                srAdvTransTable.byTCuploaded = CN_TRUE;
                                                                srAdvTransTable.byUploaded = CN_TRUE;
                                                                inResult = inMyFile_TCUploadFileUpdate(inUpDateAdviceIndex);
                                                                vdDebug_LogPrintf(". inProcessEMVTCUpload Update Rult(%d)**", inResult);
 
                                                                if (inResult != ST_SUCCESS)
                                                                {
                                                                                vdDebug_LogPrintf(". inProcessEMVTCUpload Err(%d)**", inResult);
                                                                                return ST_SUCCESS;
                                                                }
                                                }   
                                }
                }
 
                if(inResult != ST_SUCCESS)
                {
                                if(srTransPara->byTransType == SETTLE)
                                {
                                                srTransRec.shTransResult = TRANS_COMM_ERROR;
                                                inCTOS_inDisconnect();
                                                return ST_ERROR;
                                }
                                else
                                {
                                                inMyFile_TCUploadDelete();
                                                return ST_SUCCESS;
                                }
                }
 
                vdDebug_LogPrintf("**inProcessEMVTCUpload(%d) END**", inResult);
                return (inResult);
}
#endif

/************************************************************************
Function Name: inPackSendAndUnPackData()
Description:
    Composed upload host information.
    Analysis of host return message.
Parameters:
    [IN] srTransPara
         inTransCode
Return: ST_SUCCESS  
        ST_ERROR
        ST_BUILD_DATD_ERR
        ST_SEND_DATA_ERR
        ST_UNPACK_DATA_ERR
************************************************************************/

int inPackSendAndUnPackData(TRANS_DATA_TABLE *srTransPara, int inTransCode)
{
    int inResult;
    int inSendLen, inReceLen;
    unsigned char uszSendData[ISO_SEND_SIZE + 1], uszReceData[ISO_REC_SIZE + 1];
    
    vdDebug_LogPrintf("**inPackSendAndUnPackData START**");
	//inCTOSS_GetRAMMemorySize("PACK&UNPACK START");
    
    memset(uszSendData, 0x00, sizeof(uszSendData));
    memset(uszReceData, 0x00, sizeof(uszReceData));

    inResult = ST_SUCCESS;
	vdDebug_LogPrintf("HDTid[%d] :: byTransType[%d] :: strTCT.fDCC[%d] :: strCDT.fDCCEnable[%d] ::inGetATPBinRouteFlag[%d] ::fRouteToSpecificHost[%d]",
		srTransPara->HDTid, srTransPara->byTransType, strTCT.fDCC, strCDT.fDCCEnable, inGetATPBinRouteFlag(),fRouteToSpecificHost);

    vdSetISOEngTransDataAddress(srTransPara);
		if (srTransPara->byPackType == DCC_LOGGING || srTransPara->byPackType == DCC_RATEREQUEST || srTransPara->byPackType == DCC_RATEREQUEST_RETRY || srTransPara->byPackType == DCC_LOGGING_RETRY)
		{
			inFXTRead(1);

			if ((inSendLen = inCTOSS_PackIsoDataEx(srTransPara->HDTid, strFXT.szFXTTPDU, uszSendData, inTransCode)) <= ST_SUCCESS)
			//if (inSendLen = inCTOSS_PackIsoDataNoEncryp(srTransPara->HDTid, strFXT.szFXTTPDU, uszSendData, inTransCode) <= ST_SUCCESS)
			{
				 inCTOS_inDisconnect(); 	 
				 vdDebug_LogPrintf(" inSendLen %d",inSendLen);
				 vdDebug_LogPrintf("**inPackSendAndUnPackData ST_BUILD_DATD_ERR**");
				 return ST_BUILD_DATD_ERR;
			}
		}
		else if(srTransPara->byTransType == PRE_AUTH && strTCT.fDCC == TRUE && (strCDT.fDCCEnable == TRUE || srTransPara->fDCCAuth == 1) 
			&& inGetATPBinRouteFlag() != TRUE && (srTransPara->HDTid != 2 && srTransPara->HDTid != 4/*Not AMEX and AMEX USD host*/) && inCheckIssuerforBINRoute() == TRUE /*&& fRouteToSpecificHost == FALSE*/)
		{
			inFXTRead(1);

			if ((inSendLen = inCTOSS_PackIsoDataEx(srTransPara->HDTid, strFXT.szDCCAuthTPDU, uszSendData, inTransCode)) <= ST_SUCCESS)
			{
				 inCTOS_inDisconnect(); 	 
				 vdDebug_LogPrintf(" inSendLen %d",inSendLen);
				 vdDebug_LogPrintf("**inPackSendAndUnPackData ST_BUILD_DATD_ERR**");
				 return ST_BUILD_DATD_ERR;
			}
		}
		else
		{
			if ((inSendLen = inCTOSS_PackIsoDataEx(srTransPara->HDTid, strHDT.szTPDU, uszSendData, inTransCode)) <= ST_SUCCESS)
			{
				 inCTOS_inDisconnect(); 	 
				 vdDebug_LogPrintf(" inSendLen %d",inSendLen);
				 vdDebug_LogPrintf("**inPackSendAndUnPackData ST_BUILD_DATD_ERR**");
				 return ST_BUILD_DATD_ERR;
			}
		}

	inResult = inCTOSS_CheckBitmapSetBit(5);
    vdDebug_LogPrintf("inCTOSS_CheckSetBit 5 [%ld]", inResult);
	inResult = inCTOSS_CheckBitmapSetBit(11);
    vdDebug_LogPrintf("inCTOSS_CheckSetBit 11 [%ld]", inResult);
	
    vdDebug_LogPrintf(". inPackData Send Len(%d)",inSendLen);

	if(srTransPara->byPackType == BATCH_UPLOAD)//display SETTLE header during BATCH UPLOAD
		vdDispTransTitle(SETTLE);
	
    if ((inReceLen = inSendAndReceiveFormComm(srTransPara,
    (unsigned char *)uszSendData,
    inSendLen,
    (unsigned char *)uszReceData)) <= 0)                         
    {

		
        if(inReceLen == ST_COMMS_DISCONNECT)
            return ST_COMMS_DISCONNECT;

        if(inReceLen == ST_RECEIVE_TIMEOUT_ERR) 
            return ST_RECEIVE_TIMEOUT_ERR;
		
        vdDebug_LogPrintf(". inPackData ST_SEND_DATA_ERR");
        return ST_SEND_DATA_ERR;
    }

    vdDebug_LogPrintf(". inPackData Rec Len(%d)",inReceLen);

    vdSetISOEngTransDataAddress(srTransPara);

    if(srTransPara->byPackType == DCC_RATEREQUEST_RETRY || srTransPara->byPackType == DCC_LOGGING_RETRY) /*set msg id 08 01 to 08 00*/
        uszSendData[6]=0x00;
		
	inResult = inCTOSS_UnPackIsodataEx(srTransPara->HDTid,
								  (unsigned char *)uszSendData,
								  inSendLen,
								  (unsigned char *)uszReceData,
								  inReceLen);
    vdDebug_LogPrintf("**inPackSendAndUnPackData inResult=[%d]srTransPara->szRespCode[%s]",inResult,srTransPara->szRespCode);

    if (inResult != ST_SUCCESS)
    {
        vdSetErrorMessage("INVALID RESPONSE");
        inResult = ST_UNPACK_DATA_ERR;
//		    inCTOS_inDisconnect();
    }

	//inCTOSS_GetRAMMemorySize("PACK&UNPACK END");
    vdDebug_LogPrintf("**inPackSendAndUnPackData END**");
    return inResult;
}





/************************************************************************
Function Name: inBuildOnlineMsg()
Description:
   To handle online messages and check the response code and authorization code
Parameters:
    [IN] srTransPara

Return: ST_SUCCESS  
        ST_ERROR
        ST_UNPACK_DATA_ERR
        ST_SEND_DATA_ERR
************************************************************************/
int inBuildOnlineMsg(TRANS_DATA_TABLE *srTransPara)
{
    int inResult;
	TRANS_DATA_TABLE srTransParaTmp;
	char szTraceNo[6+1];
    
    vdDebug_LogPrintf("**inBuildOnlineMsg START TxnType[%d]Orig[%d]**", srTransPara->byTransType, srTransPara->byOrgTransType);

    if(VOID == srTransPara->byTransType && REFUND == srTransPara->byOrgTransType)
        srTransPara->byPackType = VOID_REFUND;
	//if(VOID == srTransPara->byTransType && SALE_OFFLINE == srTransPara->byOrgTransType)
	if(VOID == srTransPara->byTransType && (SALE_OFFLINE == srTransPara->byOrgTransType || srTransPara->fCompletion == CN_TRUE))
	{
		srTransPara->byPackType = OFFLINE_VOID;

		//if (srTransPara->byOrgTransType == SALE_TIP)//Get current time for voiding tip adjusted completion transaction.
	    	vdGetTimeDate(srTransPara);			
	}
	else
        srTransPara->byPackType = srTransPara->byTransType;

	memset(&srTransParaTmp, 0x00, sizeof(TRANS_DATA_TABLE));
	memcpy(&srTransParaTmp, srTransPara, sizeof(TRANS_DATA_TABLE));
    vdDebug_LogPrintf(" byPackType(%d)",srTransPara->byPackType);    

    inResult = inPackSendAndUnPackData(srTransPara, srTransPara->byPackType);

    vdDebug_LogPrintf("AAA inResult[%d]", inResult);
	  //for comms disconnection while receiving	
		if (inResult == -7){
			//do not display anything- display is handles by inSendAndReceiveFormComm
#if 0
			 //aaronnino for BDOCLG ver 9.0 fix on issue #00120 Message error display COMM ERROR should be Comm Error start
			 CTOS_LCDTClearDisplay();
             CTOS_Sound(1000, 50);
			 CTOS_LCDTPrintXY(1,7,"No Host Response");
	//        CTOS_LCDTPrintXY(1,7,"Comm Error");
        	 CTOS_LCDTPrintXY(1,8,"Please Try Again");
        	 CTOS_Delay(1000);
				vdSetErrorMessage(""); 
#endif
			//inBDOAutoReversal(srTransPara, POST_TXN);
			//aaronnino for BDOCLG ver 9.0 fix on issue #00120 Message error display COMM ERROR should be Comm Error end
			 inCTOS_inDisconnect();
			 return ST_COMMS_DISCONNECT;
		}

    
    if (inResult == ST_BUILD_DATD_ERR)
    {  
        vdDebug_LogPrintf("**inBuildOnlineMsg TRANS_COMM_ERROR**");
        srTransPara->shTransResult = TRANS_COMM_ERROR;
        //vdSetErrorMessage("SEND DATA ERR");
        //aaronnino for BDOCLG ver 9.0 fix on issue #00245 "COMM ERROR" displays when you press cancel upon processing/receiving instead of "COMM ERROR START 1of 4
        if (fAdviceTras == VS_TRUE)
			     return ST_ERROR;
		
		if(srTransPara->byPackType != SEND_ADVICE){
		   vdDebug_LogPrintf("2. Connection","Terminated","Please Try Again");
	       vdDisplayErrorMsgResp2(" Connection ","Terminated","Please Try Again"); 
		}

		vdSetErrorMessage(""); 
		
		//vdSetErrorMessage("COMM ERROR"); //aaa issue#00011 Connection Failure response for LAN displays "SEND DATA ERROR" instead of "COMM ERROR"
        //aaronnino for BDOCLG ver 9.0 fix on issue #00245 "COMM ERROR" displays when you press cancel upon processing/receiving instead of "COMM ERROR END 1 of 4
		//inCTOS_inDisconnect();
        return ST_ERROR;
    }
    else if (inResult == ST_SEND_DATA_ERR || inResult == ST_UNPACK_DATA_ERR || inResult == ST_RECEIVE_TIMEOUT_ERR)
    {
        srTransRec.shTransResult = TRANS_COMM_ERROR;
//do not display anything- display is handles by inSendAndReceiveFormComm
        //vdSetErrorMessage("SEND DATA ERR");
    	//if (srTransRec.byTransType != SETTLE)  //aaronnino for BDOCLG ver 9.0 fix on issue #0033 and #0034 "settle failed" error response after "comm error" 6 of 8
    	//{
    	  //aaronnino for BDOCLG ver 9.0 fix on issue #00245 "COMM ERROR" displays when you press cancel upon processing/receiving instead of "COMM ERROR START 2 of 4
        	//CTOS_LCDTClearDisplay();
        	//CTOS_Sound(1000, 50);
        	//CTOS_LCDTPrintXY(1,7,"No Host Response");
        	//CTOS_LCDTPrintXY(1,8,"Please Try Again");
        	//CTOS_Delay(1000);
			//CTOS_LCDTPrintXY(1,7,"                ");
        	//CTOS_LCDTPrintXY(1,8,"                ");
			//vdSetErrorMessage(""); 
			//vdSetErrorMessage("COMM ERROR"); //aaa issue#00011 Connection Failure response for LAN displays "SEND DATA ERROR" instead of "COMM ERROR"
        	//aaronnino for BDOCLG ver 9.0 fix on issue #00245 "COMM ERROR" displays when you press cancel upon processing/receiving instead of "COMM ERROR END 2 of 4
    	//}
    
	    vdDebug_LogPrintf("**inBuildOnlineMsg ST_SEND_DATA_ERR**");
	    return inResult;
    }
	else
    {
		//Fix for STAN not incrementing if previous transaction is PRE_AUTH and BIN ROUTING is enabled.
		if( (!memcmp(srTransPara->szRespCode, "00", 2)) && (inGetATPBinRouteFlag() == TRUE) && (srTransPara->byTransType == PRE_AUTH || 
			(srTransPara->byTransType == SALE_OFFLINE && memcmp(srTransPara->szAuthCode,"Y1",2) != 0) ))
		{
			memset(szTraceNo,0x00,sizeof(szTraceNo));
			sprintf(szTraceNo, "%06ld", srTransPara->ulTraceNum);
			inAscii2Bcd(szTraceNo, strHDT.szTraceNo, 3);
			inHDTSave(strHDT.inHostIndex);	
		}
		
        srTransPara->shTransResult = inCheckHostRespCode(srTransPara);
        vdDebug_LogPrintf(". shTransResult %d",srTransPara->shTransResult);
        
        if (srTransPara->shTransResult == TRANS_AUTHORIZED)
        {
            if (ST_SUCCESS != inBaseRespValidation(&srTransParaTmp,srTransPara))
				return ST_RESP_MATCH_ERR;
        }
        else if (srTransPara->shTransResult == ST_UNPACK_DATA_ERR)
        {
            vdDebug_LogPrintf("**inBuildOnlineMsg shTransResult UNPACK_ERR**");
            srTransPara->shTransResult = TRANS_COMM_ERROR;// for not delete reversal file
            //aaronnino for BDOCLG ver 9.0 fix on issue #0033 and #0034 "settle failed" error response after "comm error" 7 of 8 start
            if ((srTransPara->byTransType == SETTLE) && (!memcmp(srTransPara->szRespCode,"95",2))) /* Don't display resp error if batch upload -- jzg */
            {
							CTOS_LCDTClearDisplay();
							CTOS_Sound(1000, 50);
							CTOS_LCDTPrintXY(1,8,"RESP ERROR");
							CTOS_Delay(1000);				
            }
			else //aaronnino for BDOCLG ver 9.0 fix on issue #0033 and #0034 "settle failed" error response after "comm error" 7 of  8 end
				vdSetErrorMessage("RESP ERROR");
            return ST_UNPACK_DATA_ERR;
        }
		else if (srTransPara->shTransResult == TRANS_BINROUTE_REJECTED)
			return TRANS_BINROUTE_REJECTED;

    }
    
    vdDebug_LogPrintf("**inBuildOnlineMsg END**");
    return ST_SUCCESS;
}

int inBuildDCCOnlineMsg(TRANS_DATA_TABLE *srTransPara)
{
    int inResult;
	TRANS_DATA_TABLE srTransParaTmp;
    BOOL fEFTSecChangeVal;
	
    vdDebug_LogPrintf("**inBuildOnlineMsg START TxnType[%d]Orig[%d]**", srTransPara->byTransType, srTransPara->byOrgTransType);

	memset(&srTransParaTmp, 0x00, sizeof(TRANS_DATA_TABLE));
	memcpy(&srTransParaTmp, srTransPara, sizeof(TRANS_DATA_TABLE));
    vdDebug_LogPrintf(" byPackType(%d)",srTransPara->byPackType);    

	inEFTPubRead(6);// Read if first DCC host has enabled EFTSec
	if(strEFTPub.inEFTEnable == 1)//disable EFTSec as rate request does not support EFTSec
	{
		fEFTSecChangeVal = 1;
		put_env_int("EFTSECVAL",strEFTPub.inEFTEnable);
		strEFTPub.inEFTEnable = 0; 
		inEFTPubSave(6);
	}	

    inResult = inPackSendAndUnPackData(srTransPara, srTransPara->byPackType);

	if(fEFTSecChangeVal == 1)//Return the original value of EFTSec Enable
	{
		strEFTPub.inEFTEnable = get_env_int("EFTSECVAL");
		inEFTPubSave(6);
	}

    //for comms disconnection while receiving	
    if (inResult == ST_COMMS_DISCONNECT){
        inCTOS_inDisconnect();
        return ST_COMMS_DISCONNECT;
    }

    if (inResult == ST_BUILD_DATD_ERR)
    {  
        vdDebug_LogPrintf("**inBuildOnlineMsg TRANS_COMM_ERROR**");
        srTransPara->shTransResult = TRANS_COMM_ERROR;
        //vdSetErrorMessage("SEND DATA ERR");
        //aaronnino for BDOCLG ver 9.0 fix on issue #00245 "COMM ERROR" displays when you press cancel upon processing/receiving instead of "COMM ERROR START 1of 4
        if (fAdviceTras == VS_TRUE)
			     return ST_ERROR;

       vdDisplayErrorMsgResp2(" Connection ","Terminated","Please Try Again"); 
		   vdSetErrorMessage(""); 
		//vdSetErrorMessage("COMM ERROR"); //aaa issue#00011 Connection Failure response for LAN displays "SEND DATA ERROR" instead of "COMM ERROR"
        //aaronnino for BDOCLG ver 9.0 fix on issue #00245 "COMM ERROR" displays when you press cancel upon processing/receiving instead of "COMM ERROR END 1 of 4
		//inCTOS_inDisconnect();
        return ST_ERROR;
    }
    else if (inResult == ST_SEND_DATA_ERR || inResult == ST_UNPACK_DATA_ERR || inResult == ST_RECEIVE_TIMEOUT_ERR)
    {
        srTransRec.shTransResult = TRANS_COMM_ERROR;
//do not display anything- display is handles by inSendAndReceiveFormComm
        //vdSetErrorMessage("SEND DATA ERR");
    	//if (srTransRec.byTransType != SETTLE)  //aaronnino for BDOCLG ver 9.0 fix on issue #0033 and #0034 "settle failed" error response after "comm error" 6 of 8
    	//{
    	  //aaronnino for BDOCLG ver 9.0 fix on issue #00245 "COMM ERROR" displays when you press cancel upon processing/receiving instead of "COMM ERROR START 2 of 4
        	//CTOS_LCDTClearDisplay();
        	//CTOS_Sound(1000, 50);
        	//CTOS_LCDTPrintXY(1,7,"No Host Response");
        	//CTOS_LCDTPrintXY(1,8,"Please Try Again");
        	//CTOS_Delay(1000);
			//CTOS_LCDTPrintXY(1,7,"                ");
        	//CTOS_LCDTPrintXY(1,8,"                ");
			//vdSetErrorMessage(""); 
			//vdSetErrorMessage("COMM ERROR"); //aaa issue#00011 Connection Failure response for LAN displays "SEND DATA ERROR" instead of "COMM ERROR"
        	//aaronnino for BDOCLG ver 9.0 fix on issue #00245 "COMM ERROR" displays when you press cancel upon processing/receiving instead of "COMM ERROR END 2 of 4
    	//}
    
    vdDebug_LogPrintf("**inBuildOnlineMsg inResult**");
    return inResult;
    }else
    {
		if(srTransPara->byPackType == DCC_LOGGING || srTransPara->byPackType == DCC_LOGGING_RETRY)
            srTransPara->shTransResult = inCheckHostRespCode(srTransPara);
		else
		    srTransPara->shTransResult = inCheckDCCRespCode(srTransPara);
        vdDebug_LogPrintf(". shTransResult %d",srTransPara->shTransResult);
        
        if (srTransPara->shTransResult == TRANS_AUTHORIZED)
        {
            if (ST_SUCCESS != inBaseRespValidation(&srTransParaTmp,srTransPara))
				return ST_RESP_MATCH_ERR;
        }
        else if (srTransPara->shTransResult == ST_UNPACK_DATA_ERR)
        {
            vdDebug_LogPrintf("**inBuildOnlineMsg shTransResult UNPACK_ERR**");
            srTransPara->shTransResult = TRANS_COMM_ERROR;// for not delete reversal file
            //aaronnino for BDOCLG ver 9.0 fix on issue #0033 and #0034 "settle failed" error response after "comm error" 7 of 8 start
            if ((srTransPara->byTransType == SETTLE) && (!memcmp(srTransPara->szRespCode,"95",2))) /* Don't display resp error if batch upload -- jzg */
            {
							CTOS_LCDTClearDisplay();
							CTOS_Sound(1000, 50);
							CTOS_LCDTPrintXY(1,8,"RESP ERROR");
							CTOS_Delay(1000);				
            }
			else //aaronnino for BDOCLG ver 9.0 fix on issue #0033 and #0034 "settle failed" error response after "comm error" 7 of  8 end
				vdSetErrorMessage("RESP ERROR");
            return ST_UNPACK_DATA_ERR;
        }

    }
    
    vdDebug_LogPrintf("**inBuildOnlineMsg END**");
    return ST_SUCCESS;
}

/************************************************************************
Function Name: inSetBitMapCode()
Description:
    Use the transaction code to generate the corresponding bitmap code
Parameters:
    [IN] srTransPara
         srPackFunc
         inTempBitMapCode
Return: ST_SUCCESS  
        inBitMapArrayIndex
************************************************************************/

int inSetBitMapCode(TRANS_DATA_TABLE *srTransPara, int inTransCode)
{
    int    inBitMapIndex = -1;

    inBitMapIndex = inTransCode;
    
    return inBitMapIndex;
}

/************************************************************************
Function Name: inPackMessageIdData()
Description:
    Pack message id data
Parameters:
    [IN] srTransPara
         inTransCode
         uszPackData
Return: inPackLen
************************************************************************/
int inPackMessageIdData(int inTransCode, unsigned char *uszPackData, char *szMTI)
{
    int    inPackLen;
    TRANS_DATA_TABLE *srTransPara;
    
    inPackLen = 0;
    srTransPara = srGetISOEngTransDataAddress();

    wub_str_2_hex(szMTI, (char *)&uszPackData[inPackLen], MTI_ASC_SIZE);

    if(srTransPara->byPackType != BATCH_UPLOAD && srTransPara->byPackType != TC_UPLOAD)
    {   
       wub_str_2_hex(szMTI, (char *)srTransPara->szMassageType, MTI_ASC_SIZE);
    }

    inPackLen += MTI_BCD_SIZE;
    
    return inPackLen;
}

/************************************************************************
Function Name: inPackPCodeData()
Description:
    Pack message id data
Parameters:
    [IN] srTransPara
         inTransCode
         uszPackData
Return: inPackLen
************************************************************************/
int inPackPCodeData(int inTransCode, unsigned char *uszPackData, char *szPCode)
{
    char szTempFile03[10];
    int    inPackLen;
    TRANS_DATA_TABLE *srTransPara;
	
    inPackLen = 0;
    srTransPara = srGetISOEngTransDataAddress();

    
	vdDebug_LogPrintf(". inPackPCodeData [%02X] %s", inTransCode, szPCode);

	if(srTransPara->byPackType == BATCH_UPLOAD)
	{
		memset(szTempFile03,0x00,sizeof(szTempFile03));
		memcpy(szTempFile03,srTransPara->szIsoField03,PRO_CODE_BCD_SIZE);
	}

	wub_str_2_hex(szPCode, srTransPara->szIsoField03, PRO_CODE_ASC_SIZE);

	if(srTransPara->byPackType == BATCH_UPLOAD)
	{
		memcpy(srTransPara->szIsoField03,szTempFile03,PRO_CODE_BCD_SIZE);
		
		if(inFinalSend == CN_TRUE && srTransPara->HDTid != SMAC_HDT_INDEX)
			srTransPara->szIsoField03[2] = 0x00;
	}

    inPackLen += PRO_CODE_BCD_SIZE;

	vdDebug_LogPrintf(". szPCode %s [%02X%02X%02X]", szPCode, srTransPara->szIsoField03[0], srTransPara->szIsoField03[1], srTransPara->szIsoField03[2]);


	return inPackLen;
}

/************************************************************************
Function Name: vdModifyBitMapFunc()
Description:
    Modify bitmap array
Parameters:
    [IN] srTransPara
         inTransCode
         inBitMap
Return: 
************************************************************************/
void vdModifyBitMapFunc(int inTransCode, int *inBitMap)
{
    BYTE szTipAmount[20];
    TRANS_DATA_TABLE *srTransPara;


    srTransPara = srGetISOEngTransDataAddress();
    
    if(inTransCode == SIGN_ON)
    {
        return;
    }

//smac - Get the terminal's date and time if bit 12 is ON
   if (inCTOSS_CheckBitmapSetBit(12) == CN_TRUE) 
		inGetDateAndTime();
//smac


    vdDebug_LogPrintf(". vdModifyBitMapFunc inTransCode[%d]byEntryMode[%d]byTransType[%d]szCVV2[%s]byPackType[%d]byOrgTransType[%d]byUploaded[%d]byPreviouslyUploaded[%d]byOffline[%d]", 
    inTransCode, srTransPara->byEntryMode, srTransPara->byTransType, srTransPara->szCVV2,srTransPara->byPackType,srTransPara->byOrgTransType,srTransPara->byUploaded,srTransPara->byPreviouslyUploaded,srTransPara->byOffline);


//1125   
//    if((inTransCode != BATCH_UPLOAD) && (inTransCode != REVERSAL) && (inTransCode != SETTLE) && (inTransCode != CLS_BATCH))
	if((inTransCode != BATCH_UPLOAD) && (inTransCode != SETTLE) && (inTransCode != CLS_BATCH))
//1125
    {
	
        if(srTransPara->byEntryMode == CARD_ENTRY_MSR ||
           srTransPara->byEntryMode == CARD_ENTRY_ICC)
        {
            {
                vdMyEZLib_LogPrintf(". usTrack1Len>0");
                vdCTOSS_SetBitMapOff(inBitMap, 45);
            }
        }
        
        if ((srTransPara->byEntryMode == CARD_ENTRY_ICC || 
			(srTransPara->byEntryMode == CARD_ENTRY_WAVE &&
			(srTransPara->bWaveSID == d_VW_SID_VISA_WAVE_2 ||
			//(srTransPara->bWaveSID == d_VW_SID_JCB_WAVE_2) ||
			(srTransPara->bWaveSID == 0x63) ||
			//(srTransPara->bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
			(srTransPara->bWaveSID == 0x65) ||
			 srTransPara->bWaveSID == d_VW_SID_VISA_WAVE_QVSDC ||
			 srTransPara->bWaveSID == d_VW_SID_AE_EMV ||
			 srTransPara->bWaveSID == d_VW_SID_CUP_EMV ||	 
		     srTransPara->bWaveSID == d_EMVCL_SID_DISCOVER_DPAS ||
			 srTransPara->bWaveSID == d_VW_SID_PAYPASS_MCHIP))) && 
            (  srTransPara->byTransType == SALE
            || srTransPara->byTransType == SALE_OFFLINE
            || srTransPara->byTransType == PRE_AUTH
            || srTransPara->byTransType == REFUND
            || srTransPara->byTransType == SALE_TIP
            || srTransPara->byTransType == VOID
            || srTransPara->byTransType == CASH_ADVANCE
            | srTransPara->byTransType == VOID_PREAUTH))
//issue-00375- add field 23 and 55 for chip cash advance
        {



            if ((srTransPara->byTransType == VOID) &&  (srTransPara->byOrgTransType == SALE_OFFLINE || srTransPara->byOrgTransType == SALE_TIP) && (memcmp(srTransPara->szAuthCode, "Y1",2) !=0)){	
				if (srTransPara->fOnlineSALE != CN_TRUE){// do not remove 55 and 23 if original trans is ONLINE SALE  - cannot get the orig tran if scenario is OFFLINE -> TIP -> VOID
					vdCTOSS_SetBitMapOff(inBitMap, 23);
					vdCTOSS_SetBitMapOff(inBitMap, 55);
				}else{												
					vdCTOSS_SetBitMapOn(inBitMap, 23);
					vdCTOSS_SetBitMapOn(inBitMap, 55);

										  }

											
            }else if ((srTransPara->byTransType == SALE_TIP) &&  (srTransPara->byOrgTransType == SALE_OFFLINE) && (memcmp(srTransPara->szAuthCode, "Y1",2) !=0)){	
									vdCTOSS_SetBitMapOff(inBitMap, 23);
									vdCTOSS_SetBitMapOff(inBitMap, 55);
            }else{

					if(srTransPara->byPackType != DCC_RATEREQUEST && srTransPara->byPackType != DCC_RATEREQUEST_RETRY && srTransPara->byPackType != DCC_LOGGING && srTransPara->byPackType != DCC_LOGGING_RETRY)
					{
	            		vdDebug_LogPrintf("Transcation set DE55 T5F34_len[%d]", srTransPara->stEMVinfo.T5F34_len);
	            		vdCTOSS_SetBitMapOn(inBitMap, 55);
	            
	            		if(srTransPara->stEMVinfo.T5F34_len > 0)
	                		vdCTOSS_SetBitMapOn(inBitMap, 23); 
					}
            }
        }
    
        if (srTransPara->byEntryMode == CARD_ENTRY_MANUAL && 
			srTransPara->byPackType != DCC_LOGGING && srTransPara->byPackType != DCC_LOGGING_RETRY && srTransPara->byPackType != DCC_RATEREQUEST && srTransPara->byPackType != DCC_RATEREQUEST_RETRY)
        {
            vdMyEZLib_LogPrintf(". byEntryMode CN_TRUE");
            vdCTOSS_SetBitMapOn(inBitMap, 2);
            vdCTOSS_SetBitMapOn(inBitMap, 14);
            vdCTOSS_SetBitMapOff(inBitMap, 35);
        }



        memset(szTipAmount, 0x00, sizeof(szTipAmount));
        wub_hex_2_str(srTransPara->szTipAmount, szTipAmount, 6);
        DebugAddSTR("Tip", szTipAmount, 12);

		
        if(atol(szTipAmount) > 0)
        {
            
            vdCTOSS_SetBitMapOn(inBitMap, 54);

            //Should be Online void the Intial SALE amount.
            //use szStoreID to store how much amount fill up in DE4 for VOID
            if(srTransPara->byTransType == VOID && 0 == memcmp(srTransPara->szStoreID, srTransPara->szBaseAmount, 6))
            {
                vdCTOSS_SetBitMapOff(inBitMap, 54);
            }

						//start modifications - to be the same with vfi app - if Void offline, even if with tip, remove field 54 and add field 60
						if ((srTransPara->byTransType == VOID) && (srTransPara->byOffline == CN_TRUE)){			
							vdCTOSS_SetBitMapOff(inBitMap, 54);
							vdCTOSS_SetBitMapOn(inBitMap, 60);
						}
						//end modifications

        }

		

        if(strlen(srTransPara->szCVV2) > 0)
        {
            vdCTOSS_SetBitMapOn(inBitMap, 48);
        }
		

    }
    else if(inTransCode == BATCH_UPLOAD)
    {
        if(srTransPara->byEntryMode == CARD_ENTRY_ICC || 
			(srTransPara->byEntryMode == CARD_ENTRY_WAVE &&
			(srTransPara->bWaveSID == d_VW_SID_VISA_WAVE_2 ||
			 srTransPara->bWaveSID == d_VW_SID_VISA_WAVE_QVSDC ||
			 //(srTransPara->bWaveSID == d_VW_SID_JCB_WAVE_2) ||
			 (srTransPara->bWaveSID == 0x63) ||
			 //(srTransPara->bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
			 (srTransPara->bWaveSID == 0x65) ||
			 srTransPara->bWaveSID == d_VW_SID_AE_EMV ||
			 srTransPara->bWaveSID == d_VW_SID_CUP_EMV ||
			 srTransPara->bWaveSID == d_EMVCL_SID_DISCOVER_DPAS ||
			 srTransPara->bWaveSID == d_VW_SID_PAYPASS_MCHIP)))
        {

            if ((srTransPara->byOrgTransType == SALE_OFFLINE || srTransPara->byOrgTransType == SALE_TIP) && (memcmp(srTransPara->szAuthCode, "Y1",2) !=0)){		
							vdCTOSS_SetBitMapOff(inBitMap, 23);
							vdCTOSS_SetBitMapOff(inBitMap, 55);
							
            }else{
            	vdDebug_LogPrintf(("BATCH_UPLOAD set DE55"));
            	vdCTOSS_SetBitMapOn(inBitMap, 55);

            	if(srTransPara->stEMVinfo.T5F34_len > 0)
                vdCTOSS_SetBitMapOn(inBitMap, 23); 
            	}
        }
#if 0//Removed. DE 54 should not be sent on batch upload of Sale with tip transaction.
        memset(szTipAmount, 0x00, sizeof(szTipAmount));
        wub_hex_2_str(srTransPara->szTipAmount, szTipAmount, 6);
		
        DebugAddSTR("Tip", szTipAmount, 12);
		
        if(atol(szTipAmount) > 0)
        {
            vdCTOSS_SetBitMapOn(inBitMap, 54);
        }
#endif
        if(strlen(srTransPara->szCVV2) > 0)
        {
            vdCTOSS_SetBitMapOn(inBitMap, 48);
        }
    }
    else if((inTransCode == SETTLE) && (inTransCode == CLS_BATCH))
    {
        vdDebug_LogPrintf(("Settlement modify field"));
    }



	//gcitra
	/*sidumili: Issue#: 000269 [modfied condition*/
	vdDebug_LogPrintf("szIssuerLabel[%s] policy len[%d] :: fGetPolicyNumber[%d]",strIIT.szIssuerLabel,strlen(srTransPara->szPolicyNumber),strIIT.fGetPolicyNumber);
	if ((srTransPara->byTransType != SETTLE) && (srTransPara->byTransType != CLS_BATCH) && (srTransPara->byPackType!= DCC_RATEREQUEST) && (srTransPara->byPackType != DCC_RATEREQUEST_RETRY) 
		&& (strlen(srTransPara->szPolicyNumber) > 0 && (strIIT.fGetPolicyNumber == TRUE || srTransPara->byPackType == BATCH_UPLOAD)) ){
		vdDebug_LogPrintf("ON field 63 - 1");
		vdCTOSS_SetBitMapOn(inBitMap, 63);
	}		





	if ((srTransPara->byTransType== SALE_OFFLINE) && (srTransPara->byEntryMode== CARD_ENTRY_ICC)){
		
		vdCTOSS_SetBitMapOff(inBitMap, 23);
		vdCTOSS_SetBitMapOff(inBitMap, 55);
		
	}


  //ON field 38 if VOID off Offline transaction
  //0706
  //to add field 38 to offline void - void of offline is always offline - so no need to check if already uploaded
  //if((srTransPara->byTransType == VOID) && (srTransPara->byUploaded = CN_TRUE) && (srTransPara->byOrgTransType == SALE_OFFLINE))
  //smac
	//if((srTransPara->byTransType == VOID) && (srTransPara->byOffline == CN_TRUE))
	  //if((srTransPara->byTransType == VOID) && (srTransPara->byOffline == CN_TRUE) && ((srTransPara->HDTid !=SMAC_HDT_INDEX) || (srTransPara->HDTid !=SMGUARANTOR_HDT_INDEX)))  
	if((srTransPara->byTransType == VOID) && (srTransPara->byOffline == CN_TRUE) && (inCheckIfSMCardTransPara(srTransPara) == FALSE))  
	  vdCTOSS_SetBitMapOn(inBitMap,38);

  

  //smac
	//0706



	//Issue# 000188 - start -- jzg
  //smac
	  //if (srTransPara->byTransType == SALE_OFFLINE)	  
	  //if ((srTransPara->byTransType == SALE_OFFLINE) && ((srTransPara->HDTid !=SMAC_HDT_INDEX) || (srTransPara->HDTid !=SMGUARANTOR_HDT_INDEX)))
    if ((srTransPara->byTransType == SALE_OFFLINE) && (inCheckIfSMCardTransPara(srTransPara) == FALSE))
  //smac
	{
		vdCTOSS_SetBitMapOff(inBitMap, 37);
	}
	//Issue# 000188 - end -- jzg

	/* DINERS: Tip Adj -- jzg */
	if (srTransPara->byTransType == SALE_TIP)
	{
		vdCTOSS_SetBitMapOn(inBitMap, 37);
		
		if(inTransCode != BATCH_UPLOAD)//Removed. DE 54 should not be sent on batch upload of Sale with tip transaction.
			vdCTOSS_SetBitMapOn(inBitMap, 54);
	}



	if (srTransPara->byPackType == BATCH_UPLOAD)
		vdCTOSS_SetBitMapOn(inBitMap, 37);


#if 0//Change Request to include DE37 on Tip Adjust Advice
	if ((srTransPara->byTransType == SALE_TIP) && 
			(srTransPara->byUploaded == CN_FALSE) && 
			(srTransPara->byOffline == CN_TRUE)){
			
				vdCTOSS_SetBitMapOff(inBitMap, 37);
				//vdCTOSS_SetBitMapOff(inBitMap, 54);		
				//vdCTOSS_SetBitMapOff(inBitMap, 60);
			
			//vdCTOSS_SetBitMapOn(inBitMap, 37);
			//vdCTOSS_SetBitMapOn(inBitMap, 60); /* BDO-00166: Tip Adjust should have DE60 -- jzg */
	}
#endif



	if((srTransPara->byTransType == SALE_TIP) && 
		(srTransPara->byUploaded == CN_TRUE) && 
		(srTransPara->byOffline == CN_TRUE))
	{
		vdCTOSS_SetBitMapOn(inBitMap, 37);
		vdCTOSS_SetBitMapOn(inBitMap, 60); /* BDO-00166: Tip Adjust should have DE60 -- jzg */
	}


//start modifications - to be the same with vfi app - if Void offline, even if with tip, remove field 54 and add field 60
	if ((srTransPara->byTransType == VOID) && (srTransPara->byOffline == CN_TRUE)){ 
		vdCTOSS_SetBitMapOff(inBitMap, 54);
		vdCTOSS_SetBitMapOn(inBitMap, 60);
	}
//end modifications



//EMV: Online PIN enchancement - start -- jzg
#ifdef ONLINE_PIN_SUPPORT
	vdDebug_LogPrintf("JEFF:: EMV PIN [%d]", (int)srTransRec.fEMVPIN);
	if(srTransRec.fEMVPIN == TRUE) 
		vdCTOSS_SetBitMapOn(inBitMap, 52);
#endif
//EMV: Online PIN enchancement - end -- jzg


	/* BDO CLG: Fleet card support/revised bitmap loading - start -- jzg */
	if(srTransPara->fFleetCard == TRUE)
	{
		if(strTCT.fFleetGetLiters == TRUE)
			vdCTOSS_SetBitMapOn(inBitMap, 63);

		if((strTCT.fFleetGetLiters == TRUE)&&(strTCT.fGetDescriptorCode == TRUE))
			vdCTOSS_SetBitMapOn(inBitMap, 61);

	}
	/* BDO CLG: Fleet card support/ revised bitmap loading - end -- jzg */

	//if (srTransPara->byTransType == SMAC_BALANCE)
	//	vdCTOSS_SetBitMapOn(inBitMap, 52);

#if 0
	vdDebug_LogPrintf("fAMEXHostEnable: %d srTransPara->byTransType: %d", fAMEXHostEnable, srTransPara->byTransType);

	//if (inHostOrigNumber == 2 && fnGlobalOrigHostEnable == 1)//set bit 48 if AMEX host is enable
	//if ((fAMEXHostEnable == TRUE) && (srTransRec.byTransType == SALE || srTransRec.byTransType == CASH_ADVANCE || srTransRec.byTransType == SALE_OFFLINE || srTransRec.byTransType == PRE_AUTH))
	if (fAMEXHostEnable == TRUE)// Removed. Changed BIN Routing Implementation on AMEX.
		vdCTOSS_SetBitMapOn(inBitMap, 48);
#endif
	vdDebug_LogPrintf("srTransPara->fDCC: %d srTransPara->byPackType: %d", srTransPara->fDCC, srTransPara->byPackType);

	#if 0 
	if(srTransPara->fDCC && (srTransPara->byPackType == SALE || srTransPara->byPackType == SEND_ADVICE))
	{
		vdCTOSS_SetBitMapOn(inBitMap, 6);
		vdCTOSS_SetBitMapOn(inBitMap, 49);
		vdCTOSS_SetBitMapOn(inBitMap, 51);
	}
    #endif

	
	if (inTransCode == REVERSAL || inTransCode == CASHADVANCE_REVERSAL)
	{
	
		vdCTOSS_SetBitMapOff(inBitMap, 35);
		vdCTOSS_SetBitMapOn(inBitMap, 2);
		vdCTOSS_SetBitMapOn(inBitMap, 14);

		if(srTransPara->fDCC && srTransPara->byTransType == SALE)
		{
			vdCTOSS_SetBitMapOn(inBitMap, 6);
			vdCTOSS_SetBitMapOn(inBitMap, 49);
			vdCTOSS_SetBitMapOn(inBitMap, 51);
		}
	}
	
	if (inTransCode==SEND_ADVICE)
	{
		//vdCTOSS_SetBitMapOff(inBitMap, 37);//Change Request to include DE37 on Tip Adjust Advice
		vdCTOSS_SetBitMapOn(inBitMap, 38);
	}

	if(srTransPara->byTransType == VOID && (srTransPara->byOrgTransType == SALE_OFFLINE) 
		&& (srTransPara->byUploaded == CN_TRUE) && (memcmp(srTransPara->szAuthCode,"Y1",2) != 0) )//Void completion includes DE60 contating the DE4 value since DE4 will be set to 0.
	{
		vdCTOSS_SetBitMapOn(inBitMap, 60);
	}

	if (inTransCode==OFFLINE_VOID)
	{
		// REMOVED: DE37 should be sent on void of Y1 transaction
		//if(memcmp(srTransPara->szAuthCode,"Y1",2) == 0) 
			//vdCTOSS_SetBitMapOff(inBitMap, 37);

		vdCTOSS_SetBitMapOn(inBitMap, 38);//Fix for DE38 not sent on Void Completion		
	}

    #if 0
	if(srTransPara->fDCC && srTransPara->byPackType == TC_UPLOAD)
	{
		vdCTOSS_SetBitMapOn(inBitMap, 6);
		vdCTOSS_SetBitMapOn(inBitMap, 49);
		vdCTOSS_SetBitMapOn(inBitMap, 51);
	}
    #endif
	
	if( (inTransCode==SEND_ADVICE && srTransPara->byTransType == SALE_TIP) || 
		(inTransCode == VOID && srTransPara->byOrgTransType == SALE_TIP && (srTransPara->byPreviouslyUploaded == TRUE)) ||
		(inTransCode==OFFLINE_VOID && srTransPara->byPackType == SEND_ADVICE && srTransPara->byOrgTransType == SALE_TIP) || 
		(inTransCode==OFFLINE_VOID && srTransPara->byTransType == VOID && srTransPara->byPackType == OFFLINE_VOID && srTransPara->byOrgTransType == SALE_TIP) || 
		(inTransCode == VOID_REVERSAL  && srTransPara->byOrgTransType == SALE_TIP && (srTransPara->byPreviouslyUploaded == TRUE)))
	{	
		
		if(memcmp(srTransPara->szStoreID, srTransPara->szBaseAmount, 6) != 0)
		{
			vdCTOSS_SetBitMapOn(inBitMap, 54);
		}

		vdCTOSS_SetBitMapOn(inBitMap, 60);
	}

    #if 0 
	if (inTransCode == VOID_REVERSAL)
	{
		if(srTransPara->fDCC && (srTransPara->byTransType == VOID))
		{
			vdCTOSS_SetBitMapOn(inBitMap, 6);
			vdCTOSS_SetBitMapOn(inBitMap, 49);
			vdCTOSS_SetBitMapOn(inBitMap, 51);
		}
	}
	#endif
	
	if(srTransPara->fDCC && inTransCode != DCC_LOGGING && inTransCode != DCC_LOGGING_RETRY)
	{
		vdCTOSS_SetBitMapOn(inBitMap, 6);
		vdCTOSS_SetBitMapOn(inBitMap, 49);
		vdCTOSS_SetBitMapOn(inBitMap, 51);
	}

	if(srTransPara->fDCC && (inTransCode == DCC_LOGGING || inTransCode == DCC_LOGGING_RETRY)) // Remove DE37 and DE54 on Translog
	{
		vdCTOSS_SetBitMapOff(inBitMap, 23);
		vdCTOSS_SetBitMapOff(inBitMap, 37);
		vdCTOSS_SetBitMapOff(inBitMap, 54);
		vdCTOSS_SetBitMapOff(inBitMap, 55);
	}
	//if(srTransPara->byTransType == VOID && (srTransPara->byPackType == VOID) && (srTransPara->byOrgTransType == SALE_TIP) 
	//	&& srTransPara->byUploaded == TRUE)
	//{
	//	vdCTOSS_SetBitMapOn(inBitMap, 60);
	//}

	if(srTransPara->byTransType == KIT_SALE || srTransPara->byTransType == RENEWAL || srTransPara->byTransType == PTS_AWARDING)
	{
		if(srTransPara->byEntryMode == CARD_ENTRY_WAVE)
			vdCTOSS_SetBitMapOn(inBitMap, 23);
	}

	if( inCheckSMACPayRedemption(srTransPara) == TRUE || inCheckSMACPayBalanceInq(srTransPara) == TRUE || inCheckSMACPayVoid(srTransPara) == TRUE )
	{
		vdDebug_LogPrintf("INSIDE MODIFYBITMAP SMACPAY");
		
		vdCTOSS_SetBitMapOn(inBitMap, 2);
		vdCTOSS_SetBitMapOn(inBitMap, 14);
		vdCTOSS_SetBitMapOn(inBitMap, 23);
		vdCTOSS_SetBitMapOn(inBitMap, 61);
		vdCTOSS_SetBitMapOn(inBitMap, 62);

		vdCTOSS_SetBitMapOff(inBitMap, 35);	
		vdCTOSS_SetBitMapOff(inBitMap, 52);	

		if(inCheckSMACPayVoid(srTransPara) == TRUE)
			vdCTOSS_SetBitMapOn(inBitMap, 37);	
	}



       //VERSION16
       if((inTransCode != SETTLE) && (inTransCode != CLS_BATCH)
		  && (srTransPara->byPackType != DCC_RATEREQUEST) && (srTransPara->byPackType != DCC_RATEREQUEST_RETRY) 
		  && (srTransPara->byPackType != DCC_LOGGING) && (srTransPara->byPackType != DCC_LOGGING_RETRY)
		  && (srTransPara->byTransType != KIT_SALE) && (srTransPara->byTransType != RENEWAL) &&  (srTransPara->byTransType != PTS_AWARDING)
	   )
       {
       		if (strHDT.fSendPosSerial)
	   		vdCTOSS_SetBitMapOn(inBitMap, 48);
        }


       if ((srTransPara->HDTid == SMAC_HDT_INDEX) && (inTransCode == SALE) && fSmacScan == TRUE){
	   		vdCTOSS_SetBitMapOff(inBitMap, 2);	
			vdCTOSS_SetBitMapOff(inBitMap, 14);	
			vdCTOSS_SetBitMapOff(inBitMap, 23);
			vdCTOSS_SetBitMapOff(inBitMap, 35);
       }

	   //#00153 - Incorrect data element in Smac QR Void
	   if (srTransPara->byEntryMode != CARD_ENTRY_MANUAL && srTransPara->HDTid == SMAC_HDT_INDEX && srTransPara->byTransType == VOID && srTransPara->byOrgTransType == SALE){
	   	
		vdDebug_LogPrintf("INSIDE MODIFYBITMAP SMACPAY #00153 - Incorrect data element in Smac QR Void #2");
		   vdCTOSS_SetBitMapOff(inBitMap, 14); 
	   	}

	   vdDebug_LogPrintf("vdModifyBitMapFunc byTransType inTransCode srTransPara->HDTid %d %d %d", srTransPara->byTransType, inTransCode, srTransPara->HDTid);


	   //#00154 - Incorrect data element in Smac QR  Sale Reversal & Void Reversal #1
	   if (srTransPara->byEntryMode != CARD_ENTRY_MANUAL && srTransPara->HDTid == SMAC_HDT_INDEX && inTransCode == REVERSAL && srTransPara->byTransType == SALE){
		   vdDebug_LogPrintf("INSIDE MODIFYBITMAP SMACPAY #00154 - Incorrect data element in Smac QR  Sale Reversal & Void Reversal #1");

			//00189 - Missing data element in Smac Card  Sale Reversal
			if(fSmacScan)
			{	
			   vdCTOSS_SetBitMapOff(inBitMap, 02); 
			   vdCTOSS_SetBitMapOff(inBitMap, 14); 
			}

	   }
		


		if (srTransPara->byTransType == VOID_PREAUTH)
			vdCTOSS_SetBitMapOn(inBitMap, 4);
	   
	   //VERSION16

	
}

/************************************************************************
Function Name: inSendAndReceiveFormComm()
Description:
    Call function to send and receive data
Parameters:
    [IN] srTransPara
         uszSendData
         inSendLen
         uszReceData
Return: inResult --> Receive data len;
        ST_ERROR
************************************************************************/

int inSendAndReceiveFormComm(TRANS_DATA_TABLE* srTransPara,
                             unsigned char* uszSendData,
                             int inSendLen,
                             unsigned char* uszReceData)
{
	BOOL fConnectFailed = FALSE;
    int inResult,usRtn,shRet;
    BYTE key;
	int inDelRevVal = strHDT.inDeleteREV;
    static USHORT usNetworkType = 0;
    static USHORT usEthType = 1;
    static BYTE szNetworkName[128+1] = {0};
	STRUCT_SHARLS_COM Sharls_COMData;
	DWORD dwStatus;
	
	 if ((inDelRevVal > 99) || (inDelRevVal == 0)) 
     {
         inDelRevVal = 3;	
     }
    
    vdDebug_LogPrintf("**inSendAndReceiveFormComm START**");

	//inEFTPubRead(srTransRec.HDTid);//get EFTSec flag. Disable ISO log parsing if EFTSec is enabled.

	//vdMyEZLib_LogPrintff(uszSendData,inSendLen);
    DebugAddHEX("send da",uszSendData,inSendLen);
    if(VS_TRUE == strTCT.fDemo)
    {
        vdDebug_LogPrintf("DEMO Call inSendData!!");
        inResult = d_OK;
    }
    else
    {
    	inCTOSS_CheckMemoryStatusEx("BEFORE srCommFuncPoint.inSendData");

#ifdef NETMATRIX
	    inResult = inCTOSS_NMX_ProcessSendData(srTransPara->HDTid, uszSendData, &inSendLen);
        vdDebug_LogPrintf("inResult[%d]", inResult);
        DebugAddHEX("After NMX send data:",uszSendData,inSendLen);
		return ST_ERROR;
#endif
	

        inResult = srCommFuncPoint.inSendData(srTransPara,uszSendData,inSendLen);
		inCTOSS_CheckMemoryStatusEx("AFTER srCommFuncPoint.inSendData");
        //if((strTCT.fPrintISOMessage == VS_TRUE) && (inResult == d_OK))
            //inPrintISOPacket("TX:" , uszSendData, inSendLen);
            //vdPrintParseISO(srTransRec.byTransType,"TX" ,uszSendData+5);
        if(inResult == d_OK && strTCT.fPrintISOMessage == VS_TRUE)
            vdPrintISOOption("TX",uszSendData, inSendLen);


       vdDebug_LogPrintf("inSendData return %d", inResult);
		
		//testlang
		if (inResult == ST_SHARLS_COMM_CRASH){
			vdDebug_LogPrintf("return sendrecievr ST_SHARLS_COMM_CRASH");
			return ST_ERROR;
		}
    }

    if((strTCT.fISOLogging == TRUE) && (inResult == d_OK))
          inSaveISOLog(VS_TRUE, uszSendData, inSendLen);
   

	if(inResult != d_OK && chGetInit_Connect() == 1 && (strCPT.inCommunicationMode == GPRS_MODE || strCPT.inCommunicationMode == WIFI_MODE))
	{
	    if(strCPT.fCommBackUpMode == CN_TRUE) //Comms fallback -- jzg
		{
			fConnectFailed = FALSE;
		
			if(inCTOS_CommsFallback(strHDT.inHostIndex) != d_OK) //Comms fallback -- jzg
				return ST_ERROR;
			
			if (srCommFuncPoint.inConnect(&srTransRec) != ST_SUCCESS)
			{
				fConnectFailed = TRUE;
				inCTOS_inDisconnect();
			}
			else
			{
				fCommAlreadyOPen = VS_TRUE;
			}
		}

		if (fConnectFailed == TRUE) 
		{            
			if (srTransPara->shTransResult == 0)
				srTransPara->shTransResult = TRANS_COMM_ERROR;

			//0722
			fCommAlreadyOPen = VS_FALSE;
						
			if (srTransPara->shTransResult == TRANS_TERMINATE)
			{
				CTOS_LCDTClearDisplay();
				return ST_ERROR; //aaronnino for BDOCLG ver 9.0 fix on issue #00460 Settle failed retries should not count terminal level connection error
			}
			else  
			{
				if (srTransRec.usTerminalCommunicationMode == WIFI_MODE)
				{
					vdDisplayErrorMsgResp2(" ", "WIFI Problem","Please Call");
					vdSetErrorMessage("");   
					return ST_ERROR;
				}
				
				vdDisplayErrorMsgResp2(" ", " ", "TRANS COMM ERROR");
				vdSetErrorMessage("");   
				return ST_ERROR;
			}
						//0722
		}
		else
		{
			inCTOSS_CheckMemoryStatusEx("BEFORE srCommFuncPoint.inSendData 2");
			inResult = srCommFuncPoint.inSendData(srTransPara,uszSendData,inSendLen);
			inCTOSS_CheckMemoryStatusEx("AFTER srCommFuncPoint.inSendData 2");
			if(inResult == d_OK && strTCT.fPrintISOMessage == VS_TRUE)
				vdPrintISOOption("TX",uszSendData, inSendLen);
		}
	}
	
    vdDebug_LogPrintf("**inSendAndReceiveFormComm [%d]",inResult);
    if (inResult != d_OK)
    {
        if( srTransPara->byPackType != TC_UPLOAD )
        {
          if (inPOSTErrorMessage() == TRUE)
			{
				if(srTransPara->byPackType != DCC_LOGGING && srTransPara->byPackType != DCC_LOGGING_RETRY && srTransPara->byPackType != SEND_ADVICE)	
				{
					CTOS_LCDTClearDisplay();	
					vdDisplayErrorMsgResp2("No Response","from Bank","Please Try Again");
				}
				inReversalType=1;
				vdSetErrorMessage("");
            }
						
			//issue-00388
           if ((srTransPara->byPackType == REVERSAL) && (strHDT.inFailedREV+1 >= inDelRevVal))
					 {
				CTOS_LCDTClearDisplay();
				#if 0
				CTOS_LCDTPrintXY(1,8,"Last Reversal Failed");
				CTOS_Delay(2000);					
				CTOS_LCDTPrintXY(1,8,"				  ");
				#else
				//vdCTOS_MultiLineDisplayMessage("","","LAST REVERSAL FAILED");
				vdDebug_LogPrintf("1. LAST REVERSAL FAILED");
		        //vdDisplayErrorMsgResp2(" ", " ", "LAST REVERSAL FAILED");
				inReversalType=1;
				#endif
           }
					 else if ((srTransPara->byPackType == REVERSAL) && (strHDT.inFailedREV+1 < inDelRevVal))
					 {
				CTOS_LCDTClearDisplay();
				#if 0
				CTOS_LCDTPrintXY(1,8,"Reversal Failed");
				CTOS_Delay(2000);					
				CTOS_LCDTPrintXY(1,8,"				  ");
				#else
				//vdCTOS_MultiLineDisplayMessage("","","REVERSAL FAILED");
				vdDebug_LogPrintf("1. REVERSAL FAILED");
				 vdDisplayErrorMsgResp2(" ", " ", "REVERSAL FAILED");
				inReversalType=2;
				#endif
			}
			//issue-00388		
			vdDebug_LogPrintf("test strHDT.inFailedREV = %d", strHDT.inFailedREV);
			#if 0
            CTOS_Sound(1000, 50);
            CTOS_LCDTPrintXY(1,7,"Comm Error");
            CTOS_LCDTPrintXY(1,8,"Please Try Again");
            CTOS_Delay(1000);
    		CTOS_LCDTPrintXY(1,7,"          ");
            CTOS_LCDTPrintXY(1,8,"                ");
    		vdSetErrorMessage(""); 
			//#else
			if (fAdviceTras == VS_TRUE)
				return ST_ERROR;
	
			#endif

			if (fAdviceTras == VS_TRUE)
				return ST_ERROR;
    	
        }
        
		    inSetTextMode();				
        //inCTOS_inDisconnect();
        return ST_ERROR;
    }else
    {
        //vdDisplayAnimateBmp(0,0, "Comms1.bmp", "Comms2.bmp", "Comms3.bmp", "Comms4.bmp", NULL);
        if(VS_TRUE == strTCT.fDemo)
        {
            vdDebug_LogPrintf("DEMO Call inRecData!!");
            inResult = inCTOS_PackDemoResonse(srTransPara,uszReceData);
        }
        else
        {
            if(strCPT.inCommunicationMode == DIAL_UP_MODE)
                CTOS_TimeOutSet(TIMER_ID_3, strCPT.inMRespTimeOut * 100);
            else
                CTOS_TimeOutSet(TIMER_ID_3, strCPT.inTCPResponseTimeout * 100);
            inCTOSS_CheckMemoryStatusEx("BEFORE srCommFuncPoint.inRecData");
            inResult = srCommFuncPoint.inRecData(srTransPara,uszReceData);
			inCTOSS_CheckMemoryStatusEx("AFTER srCommFuncPoint.inRecData");
			vdDebug_LogPrintf("AAA - inResult[%d]", inResult);
			if(strCPT.inCommunicationMode == WIFI_MODE)
				vdCTOS_DispStatusMessage("");			
			//CTOS_Delay(3000);
#if 0
			if(strCPT.inCommunicationMode == ETHERNET_MODE || strCPT.inCommunicationMode == WIFI_MODE || strCPT.inCommunicationMode == GPRS_MODE)
			{
				inCTOSS_GetGPRSSignalEx1(&usNetworkType, szNetworkName, &usEthType, &Sharls_COMData);
							
				if (usEthType != 1)//ETH connection not detected
					return ST_COMMS_DISCONNECT;
				else
				{
					vdDebug_LogPrintf("check if timeout");
		            if(CTOS_TimeOutCheck(TIMER_ID_3) == d_YES) /*encounter timeout*/
		            {
		                vdDebug_LogPrintf("timeout");
		                inResult = ST_RECEIVE_TIMEOUT_ERR;
		            }
		            else
		                vdDebug_LogPrintf("NOT timeout");
				}
			}
			else if(strCPT.inCommunicationMode == DIAL_UP_MODE)
			{
				if(inResult<=ST_SUCCESS)
				{
			
					vdDebug_LogPrintf("check if timeout");
		            if(CTOS_TimeOutCheck(TIMER_ID_3) == d_YES) /*encounter timeout*/
		            {
		                vdDebug_LogPrintf("timeout");
		                inResult = ST_RECEIVE_TIMEOUT_ERR;
		            }
		            else
		                vdDebug_LogPrintf("NOT timeout");
				}
			}
#endif

			if(strCPT.inCommunicationMode == ETHERNET_MODE)
			{
			    
				if ( CTOS_CradleAttached() == d_NO){
					shRet = CTOS_EthernetOpenEx();
					dwStatus = 0;
				
					usRtn = CTOS_EthernetStatus(&dwStatus);
					//flag = 0;
					vdDebug_LogPrintf("CTOS_EthernetStatus,usRtn=[%x],dwStatus=[%x]", usRtn, dwStatus);
					if (dwStatus & d_STATUS_ETHERNET_PHYICAL_ONLINE)
					{
						if(inResult <= 0)
						{
							vdDebug_LogPrintf("check if timeout");
			            	if(CTOS_TimeOutCheck(TIMER_ID_3) == d_YES) /*encounter timeout*/
			            	{
			                	vdDebug_LogPrintf("timeout");
			                	inResult = ST_RECEIVE_TIMEOUT_ERR;
			            	}
			            	else
			                	vdDebug_LogPrintf("NOT timeout");
						}
					}
				}else{
				
					/*inCTOSS_GetGPRSSignalEx1(&usNetworkType, szNetworkName, &usEthType, &Sharls_COMData);
							
					if (usEthType != 1)//ETH connection not detected
						return ST_COMMS_DISCONNECT;*/
                    if(inResult <= 0)
                    {
                        if(inCheckEthernetSocketConnected() == BROKEN_PIPE || inCheckEthernetConnected() == ST_COMMS_DISCONNECT)
                        {
							if(srTransPara->byPackType == REVERSAL)
							{
								vdDebug_LogPrintf("BROKEN_PIPE");
                            	inResult = ST_COMMS_DISCONNECT;
							}
							else
							{
								vdDebug_LogPrintf("RETURN ST_COMMS_DISCONNECT");
								return ST_COMMS_DISCONNECT;
							}
                        }                                         
                        else
                        {
                            vdDebug_LogPrintf("check if timeout");
                            if(CTOS_TimeOutCheck(TIMER_ID_3) == d_YES) /*encounter timeout*/
                            {
                                vdDebug_LogPrintf("timeout");
                                inResult = ST_RECEIVE_TIMEOUT_ERR;
                            }
                            else
                                vdDebug_LogPrintf("NOT timeout");
                        }
                    }
				}
			}
            else if(strCPT.inCommunicationMode == GPRS_MODE || strCPT.inCommunicationMode == WIFI_MODE || strCPT.inCommunicationMode == DIAL_UP_MODE)
            {
                if(inResult <= 0)
                {
                    if(CTOS_TimeOutCheck(TIMER_ID_3) == d_YES) /*encounter timeout*/
                    {
                        vdDebug_LogPrintf("timeout");
                        inResult = ST_RECEIVE_TIMEOUT_ERR;
                    }
                }
            }
			
			//for disconnection while recieving
			if (inResult == -7)
			{
				if( srTransPara->byPackType != TC_UPLOAD )
				{

					if(fBuildandSendProcess == VS_FALSE)
					{
						if(srTransPara->byPackType != SEND_ADVICE && !(srTransPara->byPackType == REVERSAL && strHDT.inFailedREV+1 >= inDelRevVal))
						{
							CTOS_LCDTClearDisplay();		
							vdDebug_LogPrintf("1. Connection","Terminated","Please Try Again");
							vdDisplayErrorMsgResp2(" Connection ","Terminated","Please Try Again"); 
						}
						vdSetErrorMessage("");
					}

					if(srTransPara->byPackType == REVERSAL)
					//issue-00388			
					{
						#if 0
						if(strCPT.inCommunicationMode == ETHERNET_MODE)
						{
							shRet = CTOS_EthernetOpenEx();
							dwStatus = 0;
							
							usRtn = CTOS_EthernetStatus(&dwStatus);
							//flag = 0;
							vdDebug_LogPrintf("CTOS_EthernetStatus,usRtn=[%x],dwStatus=[%x]", usRtn, dwStatus);
							if (!(dwStatus & d_STATUS_ETHERNET_PHYICAL_ONLINE))
							{
								if(srTransPara->byPackType != SEND_ADVICE)
								{
									CTOS_LCDTClearDisplay();		
									vdDebug_LogPrintf("0. Connection","Terminated","Please Try Again");
									vdDisplayErrorMsgResp2(" Connection ","Terminated","Please Try Again"); 
								}
								vdSetErrorMessage("");
							}
						}
						#endif
						if(strHDT.inFailedREV+1 >= inDelRevVal)
						{
							CTOS_LCDTClearDisplay();
#if 0
							CTOS_LCDTPrintXY(1,8,"Last Reversal Failed");
							CTOS_Delay(2000);					
							CTOS_LCDTPrintXY(1,8,"				  ");
#else
							//vdCTOS_MultiLineDisplayMessage("","","LAST REVERSAL FAILED");
							vdDebug_LogPrintf("2. LAST REVERSAL FAILED");
							//vdDisplayErrorMsgResp2(" "," ","LAST REVERSAL FAILED");
							inReversalType=1;
#endif
						}
						if(strHDT.inFailedREV+1 < inDelRevVal)
						{
							CTOS_LCDTClearDisplay();
#if 0
							CTOS_LCDTPrintXY(1,8,"Reversal Failed");
							CTOS_Delay(2000);					
							CTOS_LCDTPrintXY(1,8,"				  ");
#else
							//vdCTOS_MultiLineDisplayMessage("","","REVERSAL FAILED");
							vdDebug_LogPrintf("2. REVERSAL FAILED");
							vdDisplayErrorMsgResp2(" "," ","REVERSAL FAILED");
							inReversalType=2;
#endif
						}						
						//issue-00388			
					}
#if 0
					CTOS_Sound(1000, 50);
					CTOS_LCDTPrintXY(1,7,"Comm Error");			
					CTOS_LCDTPrintXY(1,8,"Please Try Again");
					vdSetErrorMessage("");
					CTOS_Delay(2000);
					CTOS_LCDTPrintXY(1,7,"                "); 
					CTOS_LCDTPrintXY(1,8,"                ");
					//#else

					if (fAdviceTras == VS_TRUE)
					return ST_ERROR;

					//vdCTOS_MultiLineDisplayMessage("","Comm Error","Please Try Again");
					vdDisplayErrorMsgResp2("Connection","Terminated","Please Try Again");
#endif

					if (fAdviceTras == VS_TRUE)
					return ST_ERROR;

				}                        

				return ST_COMMS_DISCONNECT;

			}

            if(inResult > 0)
            {
               if(strTCT.fISOLogging == TRUE)
			   {
                  if (strCPT.inCommunicationMode == DIAL_UP_MODE)
                        inSaveISOLog(FALSE, uszReceData, inResult);
                  else
                        inSaveISOLog(FALSE, uszReceData, inResult - 2);
               }
            }



     if(strCPT.inCommunicationMode == WIFI_MODE)
		 	   	vdCTOS_DispStatusMessage("RECEIVING...");
		 	
			
			DebugAddHEX("rcv da",uszReceData,inResult);

			vdDebug_LogPrintf("*** HOST RESPONSE RECEVED ***");	

			
			if(inResult > 0)
			{
				inEFTTempRead(srTransRec.HDTid);
				vdDebug_LogPrintf("EFTSEC %d",strEFT_Temp.inEFTEnable);
				//if(strEFT_Temp.inEFTEnable == 1 && inCTOSS_CheckBitmapSetBit(57) == CN_TRUE)
				if(strEFT_Temp.inEFTEnable)
				{					
					if(strCPT.inCommunicationMode == ETHERNET_MODE)        
						inResult-=2;					
				}
				if(strTCT.fPrintISOMessage == VS_TRUE){
					if (strCPT.inCommunicationMode == DIAL_UP_MODE)
						//inPrintISOPacket("RX" , uszReceData, inResult);
						//vdPrintParseISO(srTransRec.byTransType,"RX" ,uszReceData+5);
			            vdPrintISOOption("RX",uszReceData, inResult);
					else
						//inPrintISOPacket("RX" , uszReceData, inResult - 2);
						//vdPrintParseISO(srTransRec.byTransType,"RX" ,uszReceData+5);
						vdPrintISOOption("RX",uszReceData, inResult);
					}
		    }


			if (inResult > 0)
			{   
        		vdMyEZLib_LogPrintff(uszReceData,inResult);
   			}
			else
			{            
                if(srTransPara->byPackType == DCC_LOGGING || srTransPara->byPackType == DCC_LOGGING_RETRY || srTransPara->byPackType == DCC_RATEREQUEST)
                {
                    if(inResult == ST_RECEIVE_TIMEOUT_ERR)
                        return inResult;

                    if(srTransPara->byPackType == DCC_RATEREQUEST)
                    {
                        CTOS_LCDTClearDisplay();
                        vdDisplayErrorMsgResp3("PROCESSING TXN", "AS PHP", "RATE HOST ERROR", "PLS CALL BDO");
					}
					
					return inResult;
                }
				
				if(srTransPara->byPackType != TC_UPLOAD)
				{
					
					if(inResult == ST_RECEIVE_TIMEOUT_ERR && (srTransRec.byTransType == PRE_AUTH || srTransRec.byTransType == SALE_OFFLINE))
						vdDisplayErrorMsgResp2("No Response","from Bank","Please Try Again");
					else if (inPOSTErrorMessage() == TRUE && srTransRec.byTransType != PRE_AUTH && srTransRec.byTransType != SALE_OFFLINE)
                    {
                        //CTOS_LCDTClearDisplay();		
                        if( srTransPara->byPackType == DCC_RATEREQUEST_RETRY)
							vdDisplayErrorMsgResp3("PROCESSING TXN", "AS PHP", "RATE HOST ERROR", "PLS CALL BDO");	
                        else if(srTransPara->byPackType != SEND_ADVICE)
                        {
							if(srTransPara->byPackType == REVERSAL && (strHDT.inFailedREV+1 >= inDelRevVal))
							{
								//Do not display any error after reversal retry exceeded scenario
							}
							else
                            	vdDisplayErrorMsgResp2("No Response","from Bank","Please Try Again");
                        }
                        inReversalType=1;
                        vdSetErrorMessage("");
                    }
					 
					//issue-00388			
					if ((srTransPara->byPackType == REVERSAL) && (strHDT.inFailedREV+1 >= inDelRevVal)){
						//CTOS_LCDTClearDisplay();
						#if 0
						CTOS_LCDTPrintXY(1,8,"Last Reversal Failed");
						CTOS_Delay(2000);					
						CTOS_LCDTPrintXY(1,8,"				  ");
						#else
						//vdCTOS_MultiLineDisplayMessage("","","LAST REVERSAL FAILED");
						vdDebug_LogPrintf("3. LAST REVERSAL FAILED");
						//vdDisplayErrorMsgResp2(" "," ","LAST REVERSAL FAILED");
						inReversalType=1;
						#endif
					}else if ((srTransPara->byPackType == REVERSAL) && (strHDT.inFailedREV+1 < inDelRevVal)){
						CTOS_LCDTClearDisplay();
						#if 0
						CTOS_LCDTPrintXY(1,8,"Reversal Failed");
						CTOS_Delay(2000);					
						CTOS_LCDTPrintXY(1,8,"				  ");
						#else
						//vdCTOS_MultiLineDisplayMessage("","","REVERSAL FAILED");
						vdDebug_LogPrintf("3. REVERSAL FAILED");
						vdDisplayErrorMsgResp2(" "," ","REVERSAL FAILED");
						inReversalType=2;
						#endif
					}						
					//issue-00388			

					#if 0
					CTOS_Sound(1000, 50);
					CTOS_LCDTPrintXY(1,7,"No Host Response");			
					CTOS_LCDTPrintXY(1,8,"Please Try Again");
					vdSetErrorMessage("");
					CTOS_Delay(2000);
					//#else
					
					if (fAdviceTras == VS_TRUE)
						return ST_ERROR;

					//vdCTOS_MultiLineDisplayMessage("","No Host Response","Please Try Again");
					if (inPOSTErrorMessage() == TRUE){
					vdDisplayErrorMsgResp2("No Response","from Bank","Please Try Again");
					inReversalType=1;
					vdSetErrorMessage("");
					}
					#endif

					
					if (fAdviceTras == VS_TRUE)
						return ST_ERROR;

					if(inResult == ST_RECEIVE_TIMEOUT_ERR)
						return inResult;
					
					return ST_ERROR;
				}				
			}
    	}
 	}
    vdDebug_LogPrintf("**inSendAndReceiveFormComm END**");
//	inSetTextMode(); // patrick temp remark 20140421				
    return inResult;
}


/************************************************************************
Function Name: inCheckIsoHeaderData()
Description:
    Check message id value
Parameters:
    [IN] srTransPara
         szSendISOHeader
         szReceISOHeader

Return: ST_SUCCESS
        ST_ERROR
************************************************************************/
int inCheckIsoHeaderData(char *szSendISOHeader, char *szReceISOHeader)
{
    int    inCnt = 0;
    TRANS_DATA_TABLE *srTransPara;

    srTransPara = srGetISOEngTransDataAddress();

    inCnt += TPDU_BCD_SIZE;

    szSendISOHeader[inCnt + 1] += 0x10;
    if (memcmp(&szSendISOHeader[inCnt], &szReceISOHeader[inCnt], MTI_BCD_SIZE))
    {
        if(VS_TRUE == strTCT.fDemo)
        {
            return ST_SUCCESS;
        }
        
        vdMyEZLib_LogPrintf("**ISO header data Error**");
        inCTOS_inDisconnect();
        return ST_ERROR;
    }

    return ST_SUCCESS;
}


/************************************************************************
Function Name: inProcessOfflineTrans()
Description:
    Setup and save the file offline transactions need
Parameters:
    [IN] srTransPara
         szSendISOHeader
         szReceISOHeader

Return: ST_SUCCESS
        ST_ERROR
************************************************************************/
	int inProcessOfflineTrans(TRANS_DATA_TABLE *srTransPara)
	{
		int inResult;

	srTransPara->byPackType = SEND_ADVICE;
		//srTransPara->byPackType = srTransPara->byTransType;
		//if(!memcmp(srTransRec.szAuthCode, "Y1", 2))// for save trans as Y1 TC UPLOAD format
		//	srTransPara->byPackType = TC_UPLOAD;
	
    	return ST_SUCCESS;
}    



/************************************************************************
Function Name: inAnalyseIsoData()
Description:
    Analysis of the host to send back information
Parameters:
    [IN] srTransPara
         
Return: ST_SUCCESS
        ST_ERROR
************************************************************************/
int inAnalyseIsoData(TRANS_DATA_TABLE *srTransPara)
{
    int inResult;
	int inRespCode = atoi(srTransPara->szRespCode_Temp);
    ISO_FUNC_TABLE srPackFunc;
        
    inResult = ST_SUCCESS;
    
    if (srTransPara->byTransType == SALE &&
        srTransPara->byEntryMode == CARD_ENTRY_ICC &&
        srTransPara->shTransResult == TRANS_AUTHORIZED &&
        !memcmp(&srTransPara->szAuthCode[0], "Y1", 2))
    {
        return ST_SUCCESS;
    }

    if (srTransPara->byOffline == CN_TRUE)
    {
        return inResult;
    }

	if(inGetATPBinRouteFlag() == TRUE && (inRespCode == 60 || inRespCode == 69 || inRespCode == 70|| 
		inRespCode == 71 || inRespCode == 72 || inRespCode == 73 || inRespCode == 74 || inRespCode == 79) )
	{
		return ST_SUCCESS;
	}
		
    memset((char *)&srPackFunc, 0x00, sizeof(srPackFunc));
    memcpy((char *)&srPackFunc, (char *)&srIsoFuncTable[0], sizeof(srPackFunc));

    if (srPackFunc.inTransAnalyse != 0x00)
    {
        vdSetISOEngTransDataAddress(srTransPara);
        inResult = srPackFunc.inTransAnalyse();
    }
	vdDebug_LogPrintf("inAnalyseIsoData[%d]", inResult);

	if(VS_TRUE == strTCT.fDemo)
		CTOS_LCDTPrintXY(1, 8, "APPROVE        ");

    return inResult;
}

/************************************************************************
Function Name: inCheckHostRespCode()
Description:
    Check the host response code
Parameters:
    [IN] srTransPara
         
Return: TRANS_AUTHORIZED
        TRANS_COMM_ERROR
        TRANS_AUTHORIZED
        TRANS_CALL_BANK
        TRANS_CANCELLED
        ST_UNPACK_DATA_ERR
************************************************************************/
int inCheckHostRespCode(TRANS_DATA_TABLE *srTransPara)
{
    int    inResult = TRANS_COMM_ERROR;


		
    vdDebug_LogPrintf("inCheckHostRespCode %s",srTransPara->szRespCode);
    if (!memcmp(srTransPara->szRespCode, "00", 2))
    {
        inResult = TRANS_AUTHORIZED;
		srTransPara->shTransResult = TRANS_AUTHORIZED;
		strcpy(srTransPara->szRespCode, "00");
		DebugAddSTR("txn approval",srTransPara->szAuthCode ,6);  
    }
    else
    {
        
        
        if( ((srTransPara->szRespCode[0] >= '0' && srTransPara->szRespCode[0] <= '9') && (srTransPara->szRespCode[1] >= '0' && srTransPara->szRespCode[1] <= '9'))
			|| ((srTransPara->szRespCode[0] >= '0' && srTransPara->szRespCode[0] <= '9') && srTransPara->szRespCode[1] == ' ') )
        {
            inResult = TRANS_REJECTED;
            if((srTransRec.byTransType == SETTLE) && (memcmp(srTransPara->szRespCode,"95",2)))
            {
                //vdDispErrMsg("SETTLE FAILED");
                //vdSetErrorMessage("SETTLE FAILED");
                vdDisplayErrorMsgResp2(" ", " ","SETTLE FAILED");
			          vdSetErrorMessage("");
            }
         else
         {
         
            vdDebug_LogPrintf("inCheckHostRespCode 2 %s",srTransPara->szRespCode);
            if(((memcmp(srTransPara->szRespCode,"95",2)==0) && (srTransPara->byTransType==SETTLE))) 
            {
				inResult = TRANS_REJECT_APPROVED;
                vdDisplayErrorMsgResp2(" ", "BATCH TRANSFER","PLEASE WAIT");
            }
            else
            {
               if(inGetATPBinRouteFlag())
			   {
                  inResult = inAnalyzeBinResponseCode(srTransPara);
                  if (inResult == TRANS_AUTHORIZED)
                     srTransPara->shTransResult = TRANS_AUTHORIZED;
                  else
                  {
                     if(((srTransRec.byTransType == SALE_OFFLINE || srTransRec.byTransType == PRE_AUTH || srTransRec.byTransType == CASH_ADVANCE || srTransRec.byEntryMode == CARD_ENTRY_MANUAL || (inFLGGet("fDebitDualCurrency") == FALSE && strCST.inCurrencyIndex != CURRENCY_PHP)) 
					 	&& inValidBinRouteRespCode() == TRUE) 	&& inResult == TRANS_BINROUTE_REJECTED)
                         vdSetErrorMessage("");	
                     else	
                     {
					 	 if ( memcmp(srTransPara->szRespCode, "86", 2) == 0 && strIIT.fSMErrorRC86 == TRUE)
						 	 vdDisplayErrorMsg86();
                         else if(srTransPara->byPackType != DCC_LOGGING && srTransPara->byPackType != DCC_LOGGING_RETRY) 
                             inCTOS_DisplayResponse(srTransPara);
                     }
                  }
               }
			   else
			   {		   
     			   if ( memcmp(srTransPara->szRespCode, "86", 2) == 0 && strIIT.fSMErrorRC86 == TRUE)
				 	   vdDisplayErrorMsg86();
                   else if(srTransPara->byPackType != DCC_LOGGING && srTransPara->byPackType != DCC_LOGGING_RETRY) 
                       inCTOS_DisplayResponse(srTransPara);
               }
            }
         }
                
        }
        else
            inResult = ST_UNPACK_DATA_ERR;
    }


    return (inResult);
}

int inBaseRespValidation(TRANS_DATA_TABLE *srOrgTransPara,TRANS_DATA_TABLE *srTransPara)
{
	vdDebug_LogPrintf("inBaseRespValidation ulTraceNum=[%ld][%ld]",srOrgTransPara->ulTraceNum,srTransPara->ulTraceNum);
	if (srOrgTransPara->ulTraceNum != srTransPara->ulTraceNum)
	{
		vdSetErrorMessage("STAN Not Match");
		return ST_RESP_MATCH_ERR;
	}
#if 0
    //do not check TID for BIN routing if amex host is enable
	if ((inGetATPBinRouteFlag) && (fAMEXHostEnable == TRUE)){
		return ST_SUCCESS;
	}
#endif	
	vdDebug_LogPrintf("inBaseRespValidation szTID=[%s][%s]",srOrgTransPara->szTID,srTransPara->szTID);
	if (memcmp(srOrgTransPara->szTID,srTransPara->szTID,TERMINAL_ID_BYTES) != 0)
	{
		vdSetErrorMessage("TID Not Match");
		return ST_RESP_MATCH_ERR;
	}

	return ST_SUCCESS;
}

/************************************************************************
Function Name: inCheckTransAuthCode()
Description:
    Check the host authorization code
Parameters:
    [IN] srTransPara
         
Return: ST_SUCCESS
        ST_ERROR
      
************************************************************************/

int inCheckTransAuthCode(TRANS_DATA_TABLE *srTransPara)
{
    int inResult = ST_SUCCESS;

    if(srTransPara->byTransType != SETTLE && srTransPara->byTransType != CLS_BATCH)
    {
        if (!memcmp(&srTransPara->szAuthCode[0], "000000", 6) || 
            !memcmp(&srTransPara->szAuthCode[0], "      ", 6))
        {
            if(srTransPara->byTransType != VOID) //Synergy host does not return Auth.code for void sale
                inResult = ST_ERROR;
        }
    }

    return (inResult);
}


int inAnalyseChipData(TRANS_DATA_TABLE *srTransPara)
{
	int inRespcode;
    int	inResult;
    ushort inlen=0;
    unsigned char stScript[512];
    
//    vduiClearBelow(8); // patrick fix code 20140421
	inRespcode = atoi(srTransRec.szBinRouteRespCode);		

	vdDebug_LogPrintf("fBinRouteDCC[%d] :: szRespCode[%s]",fBinRouteDCC,srTransPara->szRespCode);
	if(srTransPara->byPackType == REVERSAL /*|| (fBinRouteDCC == TRUE && memcmp(srTransPara->szRespCode_Temp, "71", 2) == 0 ) */||
		(inGetATPBinRouteFlag() == TRUE && ((inRespcode == 60) || (inRespcode == 69) || (inRespcode == 70)|| (inRespcode == 71) || (inRespcode == 72) || (inRespcode == 73) || (inRespcode == 74) || (inRespcode == 79))))
	{
		//memset(srTransPara->szRespCode_Temp,0x00,RESP_CODE_SIZE+1);
		return(ST_SUCCESS);
	}

	memset(stScript,0,sizeof(stScript));

    vdDebug_LogPrintf("tag71[%d] tag72[%d]", srTransPara->stEMVinfo.T71Len, srTransPara->stEMVinfo.T72Len);  
    if( srTransPara->stEMVinfo.T71Len>0)
    {
    	memcpy(&stScript[inlen], srTransPara->stEMVinfo.T71, srTransPara->stEMVinfo.T71Len );
    	inlen=srTransPara->stEMVinfo.T71Len;    	
    }
    if( srTransPara->stEMVinfo.T72Len>0)
    {
    	memcpy(&stScript[inlen], srTransPara->stEMVinfo.T72, srTransPara->stEMVinfo.T72Len );
      inlen= inlen + 	srTransPara->stEMVinfo.T72Len;      
    }	
    	
	inResult = shCTOS_EMVSecondGenAC(stScript, inlen);

    if(srTransPara->shTransResult == TRANS_REJECTED)
        return(ST_ERROR);

//send reversal if return of sec gen ac is EMV_CRITICAL_ERROR
	if(inResult == EMV_CRITICAL_ERROR)
	{	
		char szErrMsg[25];

		srTransPara->byEMVReversal = EMV_CRITICAL_ERROR;
		
		memset(szErrMsg,0x00,sizeof(szErrMsg));
		if (inGetErrorMessage(szErrMsg) > 0)
		{
			vdDisplayErrorMsg(1, 8, szErrMsg);
		}

	
		inReversalType = 2;
		//inProcessReversalEx(srTransPara, POST_TXN);
		inProcessReversal(srTransPara, POST_TXN);
		return(ST_ERROR);
	}
//end 

	vdDebug_LogPrintf("inAnalyseChipData[%d] srTransPara->shTransResult[%d] srTransPara->byOffline[%d]  auth code-%s", inResult, srTransPara->shTransResult, srTransPara->byOffline, srTransRec.szAuthCode);

    if(inResult == PP_OK)
    {
        vdDisplayTxnFinishUI();
        //if(0 != memcmp(srTransRec.szAuthCode, "Y3", 2))
        {
            inMyFile_ReversalDelete();

            #if 0
            if (srTransPara->byOffline == CN_FALSE)
    		{		
    		    if(strHDT.inNumAdv > 0)
                {
                    inCTLOS_Updatepowrfail(PFR_BEGIN_BATCH_UPDATE);
    			    inProcessAdviceTrans(srTransPara, strHDT.inNumAdv);
                }
    		}
			#endif
            
        }
        
        
        inResult = ST_SUCCESS;
        
    }
    else
    {
        if (srTransPara->shTransResult == TRANS_AUTHORIZED || srTransPara->shTransResult == TRANS_COMM_ERROR)
        {
        }
        else
        {
       
            vdDebug_LogPrintf(". Resp Err");
        }
        inResult = ST_ERROR;
        
    }
    
    return inResult;
}

int inAnalyseNonChipData(TRANS_DATA_TABLE *srTransPara)
{
	int	inResult = ST_SUCCESS;

	vdDebug_LogPrintf("**inAnalyseNonChipData(TxnResult = %d) [%d] byTransType[%d] START**", srTransPara->shTransResult, srTransPara->byPackType, srTransPara->byTransType);
    if(srTransPara->byPackType == SETTLE || srTransPara->byPackType == CLS_BATCH)
    {
        if(srTransPara->shTransResult != TRANS_AUTHORIZED)
            inResult = ST_ERROR;
        
    }
    else if (srTransPara->shTransResult == TRANS_AUTHORIZED)
	{
	    vdDisplayTxnFinishUI();

        //Should be Online void the Intial SALE amount.
        if(srTransPara->byTransType == VOID)
        {
            inCTOSS_DeleteAdviceByINV(srTransPara->szInvoiceNo);
        }
        
		if (srTransPara->byOffline == CN_FALSE)
		{	
			#if 1
			inCTLOS_Updatepowrfail(PFR_BEGIN_BATCH_UPDATE);
			#else
		    if(strHDT.inNumAdv > 0)
            {     
                inCTLOS_Updatepowrfail(PFR_BEGIN_BATCH_UPDATE);
			    inProcessAdviceTrans(srTransPara, strHDT.inNumAdv);
            }
			#endif
		}
	}
	else if (srTransPara->shTransResult == TRANS_CANCELLED)
	{		
		inResult = ST_ERROR;
	}
	else
	{		
		inResult = ST_ERROR;
	}

	vdDebug_LogPrintf("**inAnalyseNonChipData(%d) END**", inResult);
	return inResult;
}



int inAnalyseReceiveData(void)
{
	int	inResult;
    TRANS_DATA_TABLE* srTransPara;

    srTransPara = srGetISOEngTransDataAddress();

    //if(srTransPara->shTransResult == TRANS_AUTHORIZED)
       //vdCTOS_DispStatusMessage("ANALYZING RESPONSE...");
       //vdCTOS_DispStatusMessage("                     ");
#if 0
//issue#-00152
	if (srTransPara->byTransType != SETTLE)
	inCTLOS_Updatepowrfail(PFR_BEGIN_BATCH_UPDATE);
//issue00152
#endif

    if ((srTransPara->byEntryMode == CARD_ENTRY_ICC) && 
    ((srTransPara->byTransType == SALE) || (srTransPara->byTransType == PRE_AUTH) || (srTransPara->byTransType == REFUND)
    || (srTransPara->byTransType == CASH_ADVANCE)))
	{
		inResult = inAnalyseChipData(srTransPara);
	}
	else
	{
		inResult = inAnalyseNonChipData(srTransPara);
	}

	if(inResult == ST_SUCCESS)
	{
		//issue#-00152
		if (srTransPara->byTransType != SETTLE)//Update POWERFAIL state only after card has approved the transaction.
		{
			inCTLOS_Updatepowrfail(PFR_BEGIN_BATCH_UPDATE);
		}
		//issue00152
	}
		
	return inResult;
}


int inAnalyseAdviceData(int inPackType)
{   
    TRANS_DATA_TABLE *srTransPara;
    
    srTransPara = srGetISOEngTransDataAddress();
    
    if(srTransPara->byTransType == SALE_OFFLINE)
    {
        srTransPara->byUploaded = CN_FALSE;
        
    }else if(srTransPara->byTransType == SALE_TIP || srTransPara->byTransType == SALE_ADJUST)
    {
           if(srTransPara->byOffline == CN_TRUE)
            srTransPara->byUploaded = CN_FALSE;
    }
    
    return ST_SUCCESS;
}



int inPorcessTransUpLoad(TRANS_DATA_TABLE *srTransPara)
{
    int inSendCount,inTotalCnt,inFileMaxLen;
    int inResult;
    int inBatchRecordNum = 0;
    int i;
    TRANS_DATA_TABLE srUploadTransRec,srTransParaTmp;
    STRUCT_FILE_SETTING strFile;
    int  *pinTransDataid = NULL;
    int  *pinTransDataidSend = NULL;

	inCTLOS_Updatepowrfail(PFR_IDLE_STATE); //issue #00360
	CTOS_LCDTClearDisplay();// fix #00044 for V3

    inResult = ST_SUCCESS;
    
    memset(&srUploadTransRec, 0x00, sizeof(TRANS_DATA_TABLE));
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));

    //inBatchRecordNum = inBatchNumRecord();
    inBatchRecordNum = inBatchNumALLRecord();

    vdDebug_LogPrintf("BatchUpload totaltxn[%d]",inBatchRecordNum);
    if(inBatchRecordNum > 0)
    {
        pinTransDataid = (int*)malloc(inBatchRecordNum * sizeof(int));
        pinTransDataidSend = (int*)malloc(inBatchRecordNum * sizeof(int));

	    inBatchByMerchandHost(inBatchRecordNum, srTransRec.HDTid, srTransRec.MITid, srTransRec.szBatchNo, pinTransDataid);

        inTotalCnt = 0;
        for(i=0; i<inBatchRecordNum; i++)
        {
            inDatabase_BatchReadByTransId(&srUploadTransRec, pinTransDataid[i]);
            vdDebug_LogPrintf("BatchUpload curren[%d] Void?[%d]",pinTransDataid[i], srUploadTransRec.byVoided);
            if((srUploadTransRec.byVoided != TRUE) && (srUploadTransRec.byTransType != PRE_AUTH) && (srUploadTransRec.byTransType != SMAC_BALANCE) && (srUploadTransRec.byTransType != BALANCE_INQUIRY)
				&& (srUploadTransRec.byTransType != KIT_SALE) && (srUploadTransRec.byTransType != RENEWAL) && (srUploadTransRec.byTransType != PTS_AWARDING))
            {
                pinTransDataidSend[inTotalCnt] = pinTransDataid[i];
                inTotalCnt ++;
            }
        }

        //in case all is void
        inResult = ST_SUCCESS; 
        inFinalSend = CN_TRUE;

        vdDebug_LogPrintf("BatchUpload total None void txn[%d]",inTotalCnt);
        for (inSendCount = 0; inSendCount < inTotalCnt; inSendCount ++)
        {
            if(((inSendCount + 1) == inTotalCnt))
                inFinalSend = CN_TRUE;
            else
                inFinalSend = CN_FALSE;

            vdDebug_LogPrintf("Before HDTid[%d]MITid[%d]AMT[%02X%02X%02X%02X%02X%02X]", srTransPara->HDTid, srTransPara->MITid, srTransPara->szTotalAmount[0]
                                                                                                                            , srTransPara->szTotalAmount[1]
                                                                                                                            , srTransPara->szTotalAmount[2]
                                                                                                                            , srTransPara->szTotalAmount[3]
                                                                                                                            , srTransPara->szTotalAmount[4]
                                                                                                                            , srTransPara->szTotalAmount[5]);
            inDatabase_BatchReadByTransId(&srUploadTransRec, pinTransDataidSend[inSendCount]);
            
            vdDebug_LogPrintf("After HDTid[%d]MITid[%d]AMT[%02X%02X%02X%02X%02X%02X]", srUploadTransRec.HDTid, srUploadTransRec.MITid, srUploadTransRec.szTotalAmount[0]
                                                                                                                            , srUploadTransRec.szTotalAmount[1]
                                                                                                                            , srUploadTransRec.szTotalAmount[2]
                                                                                                                            , srUploadTransRec.szTotalAmount[3]
                                                                                                                            , srUploadTransRec.szTotalAmount[4]
                                                                                                                            , srUploadTransRec.szTotalAmount[5]);

            if(srUploadTransRec.byTransType == PRE_AUTH || srUploadTransRec.byTransType == SMAC_BALANCE || srUploadTransRec.byTransType == BALANCE_INQUIRY)
            {
                continue;
            }

						//inCTLOS_Updatepowrfail(PFR_IDLE_STATE); //issue #00360
            srUploadTransRec.byPackType =  BATCH_UPLOAD;
            
            vdDebug_LogPrintf(". Bef Add szTraceNo = %02x%02x%02x",strHDT.szTraceNo[0],
                                                                strHDT.szTraceNo[1],
                                                                strHDT.szTraceNo[2]);
            
            inMyFile_HDTTraceNoAdd(srUploadTransRec.HDTid);
            
            vdDebug_LogPrintf(". Aft Add szTraceNo = %02x%02x%02x",strHDT.szTraceNo[0],
                                                                strHDT.szTraceNo[1],
                                                                strHDT.szTraceNo[2]);
            
            srUploadTransRec.ulTraceNum = wub_bcd_2_long(strHDT.szTraceNo,3);
            vdDebug_LogPrintf(". UploadSendTracNum(%d) [%s]",srUploadTransRec.ulTraceNum,srUploadTransRec.szTID);
			memcpy(&srTransParaTmp,&srUploadTransRec,sizeof(TRANS_DATA_TABLE));
            
            if ((inResult = inPackSendAndUnPackData(&srUploadTransRec, srUploadTransRec.byPackType) != ST_SUCCESS))
            {
                vdDebug_LogPrintf(". inPorcessTransUpLoad(%d)_Err",inResult);
                vdDebug_LogPrintf(". byTransType %d",srUploadTransRec.byTransType);
                inResult = ST_UNPACK_DATA_ERR;
                break;
            }
            else
            {
                if (memcmp(srUploadTransRec.szRespCode, "00", 2))
                {
                    vdDebug_LogPrintf(". inPorcessTransUpLoad(%s) BatchUpload Fail", srUploadTransRec.szRespCode);
                    inResult = ST_ERROR;
                    break;
                }
				else
				{
					if (ST_SUCCESS != inBaseRespValidation(&srTransParaTmp,&srUploadTransRec))
					{
						inResult = ST_UNPACK_DATA_ERR;
						break;
					}
				}
            
                vdDebug_LogPrintf(". inPorcessTransUpLoad(%d)BatchUpload OK", inResult);
            }
        }

        free(pinTransDataid);
        free(pinTransDataidSend);
    
    }
    else
    {
        inResult = ST_ERROR;
        vdDebug_LogPrintf("No bath record found");
    }

    inMyFile_HDTTraceNoAdd(srTransPara->HDTid);
    srUploadTransRec.ulTraceNum = wub_bcd_2_long(strHDT.szTraceNo,3);
    vdMyEZLib_LogPrintf(". Aft Upload TraceNum(%d)",srUploadTransRec.ulTraceNum);
		
    if(inResult == ST_SUCCESS && inFinalSend == CN_TRUE)
    {
        srTransPara->byPackType = CLS_BATCH;
		//1202-fix for stan not incemented on batch upload
		srTransPara->ulTraceNum = srUploadTransRec.ulTraceNum;
		//1202
        if ((inResult = inPackSendAndUnPackData(srTransPara, srTransPara->byPackType) != ST_SUCCESS))
        {
            vdMyEZLib_LogPrintf(". FinalSettle(%d)_Err",inResult);
            vdMyEZLib_LogPrintf(". byTransType %d",srTransPara->byTransType);
            inResult = ST_UNPACK_DATA_ERR;
        }

				/* BDO: Check settlement reconciliation response code - start -- jzg */
				if(memcmp(srTransPara->szRespCode, "00", 2) != 0)
				{
					vdDebug_LogPrintf("JEFF::ST_CLS_BATCH_ERR");
					inResult = ST_CLS_BATCH_ERR;
				}
				/* BDO: Check settlement reconciliation response code - end -- jzg */


        inMyFile_HDTTraceNoAdd(srTransPara->HDTid);
        srTransPara->ulTraceNum = wub_bcd_2_long(strHDT.szTraceNo,3);
        vdMyEZLib_LogPrintf(". Aft CLS_BATCH TraceNum(%d)",srTransPara->ulTraceNum);
    }

    return inResult;
}


int inPackIsoFunc02(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    int inPANLen;
    char szTempPan[PAN_SIZE+1];

    vdDebug_LogPrintf("**inPackIsoFunc02 START**");
    
    inDataCnt = 0;
    inPANLen = 0;

    memset(szTempPan, 0x00, sizeof(szTempPan));   
    inPANLen = strlen(srTransPara->szPAN);
    memcpy(szTempPan,srTransPara->szPAN,inPANLen);
    
    uszSendData[inDataCnt ++] = (inPANLen / 10 * 16) + (inPANLen % 10);
        
    if (inPANLen % 2)
        szTempPan[inPANLen ++] = '0';
    
#ifdef TLE
    memset(&uszSendData[inDataCnt], 0x00, (inPANLen+1) / 2);
    byField_02_ON = TRUE;
#else
    wub_str_2_hex(szTempPan, (char *)&uszSendData[inDataCnt], inPANLen);
#endif    
    inDataCnt += (inPANLen / 2);
    
    vdDebug_LogPrintf("  PACK_LEN%d",inDataCnt);
    vdDebug_LogPrintf("**inPackIsoFunc02 END**");
    
    return (inDataCnt);

}

int inPackIsoFunc03(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
	inDataCnt = 0;

	vdDebug_LogPrintf("**inPackIsoFunc03 START**");

	memcpy(&uszSendData[inDataCnt], &srTransPara->szIsoField03[0], PRO_CODE_BCD_SIZE);
	inDataCnt += PRO_CODE_BCD_SIZE;


//OFFline void advice
	if ((srTransPara->byTransType == VOID) && (srTransPara->byOffline == CN_TRUE))
		uszSendData[0] = 0x02;


	//0424
		if ((srTransPara->byTransType == SALE_TIP) /*&& (srTransPara->byUploaded == CN_TRUE)*/ && (srTransPara->byOffline == CN_TRUE))
			uszSendData[0] = 0x02;

	//0424	

	vdDebug_LogPrintf("1. DE03 %02x%02x%02x",uszSendData[0],uszSendData[1],uszSendData[2]);
	if((BATCH_UPLOAD == srTransPara->byPackType))
	{
		//fix Tip adjust Sale , batch upload process code is 02000x, should be 00000x
		if(srTransPara->byTransType == SALE_TIP || srTransPara->byTransType == SALE_ADJUST)
			uszSendData[0] &= 0xF0;		
		
		if(inFinalSend != CN_TRUE)
			uszSendData[2] |= 0x01;
	}
	vdDebug_LogPrintf("strIIT.fQuasiCash[%d]",strIIT.fQuasiCash);
	/* BDO: Quasi should be parametrized per issuer - start -- jzg */
	if((strIIT.fQuasiCash /*|| srTransPara->fQuasiCash*/) &&
	/* BDO: Quasi should be parametrized per issuer - end -- jzg */
		(srTransPara->byPackType != TC_UPLOAD) &&
		((srTransPara->byTransType == SALE) ||
		(srTransPara->byTransType == SALE_TIP) ||
		((srTransPara->byTransType == SALE_OFFLINE) && 
		(inCTOSS_CheckBitmapSetBit(23) == CN_TRUE) &&
		(inCTOSS_CheckBitmapSetBit(55) == CN_TRUE))))
		uszSendData[0] = 0x11;

	/* BDOCLG-00157/00158: Revised code block to compute for correct proc code - start -- jzg */
	//version16
	//if((strIIT.fQuasiCash) && (srTransPara->byPackType == TC_UPLOAD))
	if(srTransPara->byPackType == TC_UPLOAD)
		uszSendData[0] = 0x94;
	/* BDOCLG-00157/00158: Revised code block to compute for correct proc code - end -- jzg */

#if 0
	/* DINERS: Tip Adj -- jzg */
	if(srTransPara->byTransType == SALE_TIP)
		uszSendData[0] = 0x02;
#endif

	if(strTCT.inSMACMode == 0 && srTransPara->HDTid == SMAC_HDT_INDEX && (srTransPara->byTransType == SALE || srTransPara->byTransType == VOID))
		uszSendData[2] = 0x00;

	if(srTransPara->byPackType == REVERSAL && srTransPara->HDTid == SMAC_HDT_INDEX)
	{
		if(srTransPara->byTransType == KIT_SALE)
			wub_str_2_hex("310002",uszSendData,6);
		else if(srTransPara->byTransType == RENEWAL)
			wub_str_2_hex("310003",uszSendData,6);
		else if(srTransPara->byTransType == PTS_AWARDING)
			wub_str_2_hex("310004",uszSendData,6);				
	}

	vdDebug_LogPrintf("2. DE03 %02x%02x%02x",uszSendData[0],uszSendData[1],uszSendData[2]);
	vdMyEZLib_LogPrintf("  PACK_LEN%d",inDataCnt);
	vdMyEZLib_LogPrintf("**inPackIsoFunc03 END**");
	return (inDataCnt);
}

int inPackIsoFunc04(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    inDataCnt = 0;
    BYTE szDCCLocalAmount[AMT_ASC_SIZE+1], szDCCLocalTipAmount[AMT_ASC_SIZE+1], szDCCLocalTotalAmount[AMT_ASC_SIZE+1], szTempAmount[AMT_ASC_SIZE+1];
	
	vdDebug_LogPrintf("***inPackIsoFunc04 START***");
	vdDebug_LogPrintf(". inPackIsoFunc04 byEntryMode[%d]byTransType[%d]byPackType[%d]byOrgTransType[%d]byUploaded[%d]",
		srTransPara->byEntryMode, srTransPara->byTransType, srTransPara->byPackType, srTransPara->byOrgTransType, srTransPara->byUploaded);
    //Should be Online void the Intial SALE amount.

	if(srTransPara->fDCC)
	{
		memset(szDCCLocalAmount, 0, sizeof(szDCCLocalAmount));
		memset(szDCCLocalTipAmount, 0, sizeof(szDCCLocalTipAmount));
		memset(szDCCLocalTotalAmount, 0, sizeof(szDCCLocalTotalAmount));
		memset(szTempAmount, 0, sizeof(szTempAmount));
		
		wub_hex_2_str(srTransPara->szDCCLocalAmount, szDCCLocalAmount, 6);
        wub_hex_2_str(srTransPara->szDCCLocalTipAmount, szDCCLocalTipAmount, 6);
		sprintf(szTempAmount, "%012.0f", atof(szDCCLocalAmount) + atof(szDCCLocalTipAmount));
		vdDebug_LogPrintf("LocalAmount[%d] :: TipAmount[%d]",atof(szDCCLocalAmount),atof(szDCCLocalTipAmount));
		wub_str_2_hex(szTempAmount, szDCCLocalTotalAmount, 12);

		if(srTransPara->byTransType == VOID)
	    {
	        //use szStoreID to store how much amount fill up in DE4 for VOID
	        if (srTransPara->byOffline == CN_TRUE)
				memcpy((char *)&uszSendData[inDataCnt],"\x00\x00\x00\x00\x00\x00",6);
			else
			{
	        	if( (srTransPara->byOrgTransType == SALE_OFFLINE 
					|| (srTransPara->byOrgTransType == SALE_TIP && (srTransPara->byPackType == SEND_ADVICE || srTransPara->byPackType == OFFLINE_VOID) )) 	
					&& (srTransPara->byUploaded == CN_TRUE))
					memcpy((char *)&uszSendData[inDataCnt],"\x00\x00\x00\x00\x00\x00",6);
				else
					memcpy((char *)&uszSendData[inDataCnt], srTransPara->szLocalStoreID, 6);
			}
	    }
	    else		
			memcpy((char *)&uszSendData[inDataCnt], szDCCLocalTotalAmount, 6);
	}	
	else
	{
		if(srTransPara->byTransType == VOID)
	    {
	        //use szStoreID to store how much amount fill up in DE4 for VOID
	        if (srTransPara->byOffline == CN_TRUE)
				memcpy((char *)&uszSendData[inDataCnt],"\x00\x00\x00\x00\x00\x00",6);
			else
			{
	        	if( (srTransPara->byOrgTransType == SALE_OFFLINE 
					|| (srTransPara->byOrgTransType == SALE_TIP && (srTransPara->byPackType == SEND_ADVICE || srTransPara->byPackType == OFFLINE_VOID) )) 	
					&& (srTransPara->byUploaded == CN_TRUE))
					memcpy((char *)&uszSendData[inDataCnt],"\x00\x00\x00\x00\x00\x00",6);
				else
					memcpy((char *)&uszSendData[inDataCnt], srTransPara->szStoreID, 6);
			}
	    }
	    else
	        memcpy((char *)&uszSendData[inDataCnt], srTransPara->szTotalAmount, 6);
	}
	
    inDataCnt += 6;

	vdDebug_LogPrintf("***inPackIsoFunc04 END***");
	
    return (inDataCnt);
}

int inPackIsoFunc06(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    inDataCnt = 0;

	vdDebug_LogPrintf("***inPackIsoFunc06 START***");
    //Should be Online void the Intial SALE amount.
    if(srTransPara->byTransType == VOID)
    {
        //use szStoreID to store how much amount fill up in DE4 for VOID
        if (srTransPara->byOffline == CN_TRUE)
			memcpy((char *)&uszSendData[inDataCnt],"\x00\x00\x00\x00\x00\x00",6);
		else
		{
			if((srTransPara->byOrgTransType == SALE_OFFLINE 
				|| (srTransPara->byOrgTransType == SALE_TIP && (srTransPara->byPackType == SEND_ADVICE || srTransPara->byPackType == OFFLINE_VOID) )) 	
				&& (srTransPara->byUploaded == CN_TRUE))
				memcpy((char *)&uszSendData[inDataCnt],"\x00\x00\x00\x00\x00\x00",6);
			else
	        	memcpy((char *)&uszSendData[inDataCnt], srTransPara->szStoreID, 6);
		}
    }
    else
        memcpy((char *)&uszSendData[inDataCnt], srTransPara->szTotalAmount, 6);
    
    inDataCnt += 6;
	vdDebug_LogPrintf("***inPackIsoFunc06 END***");
    return (inDataCnt);
}


int inPackIsoFunc07(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
   char szTemp[10+1];
   inDataCnt = 0;
   CTOS_RTC SetRTC;

   vdDebug_LogPrintf("***inPackIsoFunc07 START***");

   vdDebug_LogPrintf("byPackType[%d]",srTransPara->byPackType);

   if(srTransPara->byPackType != DCC_LOGGING && srTransPara->byPackType != DCC_LOGGING_RETRY)
   		vdGetTimeDate(srTransPara);

   vdDebug_LogPrintf("AAA - srTransPara->szDate[%02d%02d] || srTransPara->szTime[%02d%02d%02d]", srTransPara->szDate[0], srTransPara->szDate[1], srTransPara->szTime[0],srTransPara->szTime[1],srTransPara->szTime[2]);
   
   //CTOS_RTCGet(&SetRTC);
   memset(szTemp,0,sizeof(szTemp));
   memcpy(szTemp, srTransPara->szDate, DATE_BCD_SIZE);
   memcpy(szTemp+DATE_BCD_SIZE, srTransPara->szTime, TIME_BCD_SIZE);
   
   memcpy((char *)&uszSendData[inDataCnt], szTemp, 5);
   inDataCnt+=5;

   vdDebug_LogPrintf("***inPackIsoFunc07 END***");
   return (inDataCnt);

}



int inPackIsoFunc11(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    char szSTAN[6 + 1];
    
    inDataCnt = 0;    
    memset(szSTAN, 0x00, sizeof(szSTAN));
    
    
    if(srTransPara->byTransType == SETTLE)// 20121204
    {
        sprintf(szSTAN, "%06ld", srTransPara->ulTraceNum);
        wub_str_2_hex(&szSTAN[0], (char *)&uszSendData[inDataCnt], 6);
        vdDebug_LogPrintf("sys trace %d",uszSendData[0], uszSendData[1],uszSendData[2]);        
    }
     else                  
    {
        if((srTransPara->byPackType == TC_UPLOAD) || srTransPara->byTransType == CLS_BATCH)
        {
            vdDebug_LogPrintf("**inPackIsoFunc11 %d**", srTransPara->ulTraceNum);
            sprintf(szSTAN, "%06ld", (srTransPara->ulTraceNum+1));
        }
        else

            sprintf(szSTAN, "%06ld", srTransPara->ulTraceNum);
		
		//vdDebug_LogPrintf("inPackIsoFunc11 srTransPara->byPackType:%d, srTransPara->byTransType: %d, srTransPara->byUploaded: %d", srTransPara->byPackType, srTransPara->byTransType, srTransPara->byUploaded);
        if(srTransPara->byPackType == SEND_ADVICE && srTransPara->byTransType == SALE_TIP && srTransPara->byUploaded == FALSE)
			srTransPara->ulOrgTraceNum=srTransPara->ulTraceNum;
				
        wub_str_2_hex(&szSTAN[0], (char *)&uszSendData[inDataCnt], 6);
    }
    
    inDataCnt += 3;
    
    vdDebug_LogPrintf("  PACK_LEN[%d] %d [%02X%02X%02X] inFinalSend[%d]byPackType[%d]",inDataCnt, srTransPara->byPackType, uszSendData[0], uszSendData[1], uszSendData[2], inFinalSend, srTransPara->byPackType);
    return (inDataCnt);
}

int inPackIsoFunc12(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    char szTempTime[6];
	BYTE szCurrentTime[20];
	CTOS_RTC SetRTC;
	
    vdDebug_LogPrintf("**inPackIsoFunc12 START**");
    inDataCnt = 0;

	if(srTransPara->byTransType == KIT_SALE)
	{
		CTOS_RTCGet(&SetRTC);
	    sprintf(szCurrentTime,"%02d%02d%02d", SetRTC.bHour,SetRTC.bMinute,SetRTC.bSecond);
        wub_str_2_hex(szCurrentTime,srTransPara->szTime,TIME_ASC_SIZE);
		memcpy((char *)&uszSendData[inDataCnt], srTransPara->szTime, 3);
	}
	else
	{
	    if(srTransPara->byPackType == SALE_TIP || srTransPara->byPackType == SALE_ADJUST || srTransPara->byPackType == SALE_TIP)
	        memcpy((char *)&uszSendData[inDataCnt], srTransPara->szOrgTime, 3);
	    else
	       memcpy((char *)&uszSendData[inDataCnt], srTransPara->szTime, 3);
	}
	
    inDataCnt += 3;
    vdDebug_LogPrintf("  PACK_LEN%d %s",inDataCnt, srTransPara->szTime);
    vdDebug_LogPrintf("**inPackIsoFunc12 END**");
    return (inDataCnt);
}

int inPackIsoFunc13(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    char szTempDate[6];
    BYTE szCurrentDate[2+1];
	CTOS_RTC SetRTC;
	
    vdMyEZLib_LogPrintf("**inPackIsoFunc13 START**");
    inDataCnt = 0;

	if(srTransPara->byTransType == KIT_SALE)
	{
		CTOS_RTCGet(&SetRTC);
	    sprintf(szCurrentDate,"%02d%02d",SetRTC.bMonth, SetRTC.bDay);
        wub_str_2_hex(szCurrentDate,srTransPara->szDate,DATE_ASC_SIZE);
		memcpy((char *)&uszSendData[inDataCnt], srTransPara->szDate, 2);
	}
	else
	{
	    if(srTransPara->byPackType == SALE_TIP || srTransPara->byPackType == SALE_ADJUST || srTransPara->byPackType == SALE_TIP)
	        memcpy((char *)&uszSendData[inDataCnt], srTransPara->szOrgDate, 2);
	    else
	        memcpy((char *)&uszSendData[inDataCnt], srTransPara->szDate, 2);
	}
	
    inDataCnt += 2;
    vdMyEZLib_LogPrintf("  PACK_LEN%d",inDataCnt);
    vdMyEZLib_LogPrintf("**inPackIsoFunc13 END**");
    return (inDataCnt);
}

int inPackIsoFunc14(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    char szTempExpDate[6];
    vdMyEZLib_LogPrintf("**inPackIsoFunc14 START**");
    inDataCnt = 0;

#ifdef TLE 
    memcpy((char *)&uszSendData[inDataCnt], "\x00\x00", 2);
    byField_14_ON = TRUE;
#else
    memcpy((char *)&uszSendData[inDataCnt], srTransPara->szExpireDate, 2);
#endif
    inDataCnt += 2;
    vdMyEZLib_LogPrintf("  PACK_LEN%d",inDataCnt);
    vdMyEZLib_LogPrintf("**inPackIsoFunc14 END**");
    return (inDataCnt);
}

int inPackIsoFunc22(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    char szTempEnterMode[5];
	BYTE EMVtagVal[64] = {0};
	
    vdMyEZLib_LogPrintf("**inPackIsoFunc22 START**");
    
    inDataCnt = 0;

	vdDebug_LogPrintf("inPackIsoFunc22 [%d] [%d] [%d] [%d]", srTransPara->byTransType, srTransPara->fVirtualCard, srTransPara->HDTid, fSmacScan);

	if(strIIT.fEMVFallbackEnable == FALSE && srTransPara->byEntryMode == CARD_ENTRY_FALLBACK)
		vdCTOS_SetTransEntryMode(CARD_ENTRY_MSR);

    memset(szTempEnterMode,0,sizeof(szTempEnterMode));
    
    if (srTransPara->byEntryMode == CARD_ENTRY_ICC)
    {
        //for diners-start
        if ((memcmp(srTransPara->stEMVinfo.T84,"\xA0\x00\x00\x01\x52",5) == 0) || (memcmp(srTransPara->stEMVinfo.T84,"\xa0\x00\x00\x01\x52",5) == 0)){	

            memset(EMVtagVal, 0x00, sizeof(EMVtagVal));
			memcpy(EMVtagVal, srTransPara->stEMVinfo.T9F34, 3);

			vdDebug_LogPrintf("inPackIsoFunc22 9F34 = [%02X %02X %02X]", srTransRec.stEMVinfo.T9F34[0], srTransRec.stEMVinfo.T9F34[1], srTransRec.stEMVinfo.T9F34[2]);

			if(((EMVtagVal[0] != 0x03) && (EMVtagVal[0] != 0x05) && (EMVtagVal[0] != 0x1E) && (EMVtagVal[0] != 0x5E)) || (EMVtagVal[0] == 0x3F))
			{
				if(EMVtagVal[0] & 0x01 || EMVtagVal[0] & 0x02 || EMVtagVal[0] & 0x04)
					strcpy(szTempEnterMode,"0051");
				else
					strcpy(szTempEnterMode,"0052");
			}else
				strcpy(szTempEnterMode,"0052");

        }else
        //end
        	strcpy(szTempEnterMode,"0051");
    }
    else if (srTransPara->byEntryMode == CARD_ENTRY_FALLBACK)
    {
				/* BDO: Make sure that entry mode is dependent on type of card -- start - jzg */
        //if((srTransRec.szServiceCode[0] == '2') || (srTransRec.szServiceCode[0] == '6'))    
        if((srTransPara->szServiceCode[0] == '2') || (srTransPara->szServiceCode[0] == '6'))
	        strcpy(szTempEnterMode,"0802");
				else
	        strcpy(szTempEnterMode,"0022");
				/* BDO: Make sure that entry mode is dependent on type of card -- end - jzg */
    }
     else if (srTransPara->byEntryMode == CARD_ENTRY_MSR)
    {
        //gcitra-0910
        //if (srTransPara->byTransType == BIN_VER)
			sprintf(szTempEnterMode,"0022");
		//else
		//gcitra-0910
        //	sprintf(szTempEnterMode,"002%d",srTransPara->byPINEntryCapability);
    }
    else if (srTransPara->byEntryMode  == CARD_ENTRY_MANUAL)
    {        
         //sprintf(szTempEnterMode,"001%d",srTransPara->byPINEntryCapability);
         sprintf(szTempEnterMode,"0012");
    }
	else if (srTransPara->byEntryMode  == CARD_ENTRY_WAVE)
	{		
		strcpy(szTempEnterMode,"0072");
		vdDebug_LogPrintf("TEST inPackIsoFunc22 %d %x",srTransPara->bWaveSID, srTransPara->bWaveSID );
		if ((srTransPara->bWaveSID == d_VW_SID_PAYPASS_MAG_STRIPE) ||
			(srTransPara->bWaveSID == d_VW_SID_VISA_WAVE_MSD) ||
			(srTransPara->bWaveSID == d_VW_SID_AE_MAG_STRIPE) ||
			//(srTransPara->bWaveSID == d_VW_SID_JCB_WAVE_2))	
			(srTransPara->bWaveSID == d_EMVCL_SID_DISCOVER_DPAS_MAG_STRIPE) || //for DINERS MAG
			(srTransPara->bWaveSID == 0x64))	
			//CTLS: Check the service code before setting the POS Entry code - start -- jzg
			//if (srTransPara->szServiceCode[0] == '2')
			//	strcpy(szTempEnterMode,"0902");
			//else
				strcpy(szTempEnterMode,"0912"); 
			//CTLS: Check the service code before setting the POS Entry code - end -- jzg
		else if(srTransPara->byTransType == KIT_SALE)
			strcpy(szTempEnterMode,"0072"); 
	}
	else if(srTransPara->fVirtualCard == TRUE && srTransPara->HDTid == SMAC_HDT_INDEX)
	{		
		strcpy(szTempEnterMode,"0052");		
	}

	//version16
	else if (srTransPara->HDTid == SMAC_HDT_INDEX && fSmacScan == TRUE)
	{
		strcpy(szTempEnterMode,"0052");	
	}
	else if (srTransPara->HDTid == SMAC_HDT_INDEX && srTransPara->byTransType == VOID) //00153 - Incorrect data element in Smac QR Void #3
	{
		vdDebug_LogPrintf("inPackIsoFunc22 00153 - Incorrect data element in Smac QR Void #3");
		
		strcpy(szTempEnterMode,"0052");	
	}
	else
		vdDebug_LogPrintf("inPackIsoFunc22 ELSE!!!");


	
    wub_str_2_hex(szTempEnterMode, (char *)&uszSendData[inDataCnt], 4);
    
    inDataCnt +=2 ; //+= 3; 
    vdMyEZLib_LogPrintf("  PACK_LEN%d",inDataCnt);
    vdMyEZLib_LogPrintf("**inPackIsoFunc22 END**");
    return (inDataCnt);
}





int inPackIsoFunc23(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    vdMyEZLib_LogPrintf("**inPackIsoFunc23 START**");
    inDataCnt = 0;

	if(((srTransPara->byTransType == KIT_SALE || srTransPara->byTransType == RENEWAL || srTransPara->byTransType == PTS_AWARDING) 
		&& srTransPara->byEntryMode == CARD_ENTRY_WAVE) || inCheckSMACPayRedemption(srTransPara) == TRUE || inCheckSMACPayBalanceInq(srTransPara) == TRUE || inCheckSMACPayVoid(srTransPara) == TRUE)
	{
		uszSendData[inDataCnt] = srTransPara->bySMACPay_CardSeqNo[inDataCnt];
		uszSendData[inDataCnt+1] = srTransPara->bySMACPay_CardSeqNo[inDataCnt+1];
	}
	else
	{
	    uszSendData[inDataCnt] = 0x00;
	    uszSendData[inDataCnt+1] = srTransPara->stEMVinfo.T5F34;
	}
    
    inDataCnt += 2;
        
    vdMyEZLib_LogPrintf("  PACK_LEN%d",inDataCnt);
    vdMyEZLib_LogPrintf("**inPackIsoFunc23 END**");
    return (inDataCnt);
}


int inPackIsoFunc24(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    inDataCnt = 0;

    DebugAddHEX("inPackIsoFunc24", strHDT.szNII, 2);
	vdDebug_LogPrintf("byTransType[%d] :: strTCT.fDCC[%d] :: strCDT.fDCCEnable[%d] :: inGetATPBinRouteFlag[%d]",srTransRec.byTransType,strTCT.fDCC,strCDT.fDCCEnable,inGetATPBinRouteFlag());
	

    //gcitra
    if (srTransPara->byTransType == BIN_VER)
		memcpy((char *)&uszSendData[inDataCnt], strBVT.szBINVerNII, 2);
    else  if (srTransPara->byTransType == CASH_LOYALTY)
		memcpy((char *)&uszSendData[inDataCnt], strCLT.szCashLoyaltyNII, 2);
    else  if (srTransPara->byTransType == POS_AUTO_REPORT)
		memcpy((char *)&uszSendData[inDataCnt], strPAR.szPARNII, 2);
	else  if ((srTransPara->byTransType == PRE_AUTH) && strTCT.fDCC == TRUE && strCDT.fDCCEnable == TRUE && inGetATPBinRouteFlag() != TRUE && (srTransPara->HDTid != 2 && srTransPara->HDTid != 4/*Not AMEX and AMEX USD host*/) && inCheckIssuerforBINRoute() == TRUE/*&& fRouteToSpecificHost == FALSE*/)
		memcpy((char *)&uszSendData[inDataCnt], strFXT.szDCCAuthNII, 2);
    else if (srTransPara->byTransType == SALE_TIP){
		if (srTransPara->fBINRouteApproved && srTransPara->byPackType != BATCH_UPLOAD)	
			memcpy((char *)&uszSendData[inDataCnt], strTCT.ATPNII, 2);
        else
			memcpy((char *)&uszSendData[inDataCnt], strHDT.szNII, 2);
    }else{
		vdDebug_LogPrintf("inPackIsoFunc24 A");
		if (inGetATPBinRouteFlag() ||
			//(srTransRec.byTransType == VOID && strTCT.fATPBinRoute == TRUE && srTransRec.HDTid == 1 && srTransRec.fDualBrandedCredit == FALSE) ){
			(srTransPara->byTransType == VOID && srTransPara->fBINRouteApproved == TRUE && srTransPara->HDTid == 1 && srTransPara->fDualBrandedCredit == FALSE) ){

			vdDebug_LogPrintf("inPackIsoFunc24 B");
			memcpy((char *)&uszSendData[inDataCnt], strTCT.ATPNII, 2);
		}else{	
		
			vdDebug_LogPrintf("inPackIsoFunc24 C");
    		memcpy((char *)&uszSendData[inDataCnt], strHDT.szNII, 2);
		}
    }
    //gcitra
	
    inDataCnt += 2;
            
    return (inDataCnt);
}

int inPackIsoFunc25(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    vdMyEZLib_LogPrintf("**inPackIsoFunc25 START**");
    inDataCnt = 0;

//0826 - for amex host
    if((srTransRec.byTransType == PRE_AUTH) && (srTransRec.HDTid == 2))
        wub_str_2_hex("06", (char *)&uszSendData[inDataCnt], 2);
    else	
//0826
        wub_str_2_hex("00", (char *)&uszSendData[inDataCnt], 2);
    
    inDataCnt += 1;
    vdMyEZLib_LogPrintf("  PACK_LEN%d",inDataCnt);
    vdMyEZLib_LogPrintf("**inPackIsoFunc25 END**");
    return (inDataCnt);
}

int inPackIsoFunc35(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    char szTrack2Data[40];
    int inLen;
    int i;
    
    vdMyEZLib_LogPrintf("**inPackIsoFunc35 START**");
    inDataCnt = 0;
    inLen = 0;
    
    memset(szTrack2Data,0x00,sizeof(szTrack2Data));   
    strcpy(szTrack2Data, srTransPara->szTrack2Data);
		


    for (i = 0; i < strlen(szTrack2Data); i ++)
    {
        if (szTrack2Data[i] == '=')
            szTrack2Data[i] = 'D';
			
		if (szTrack2Data[i] == '?' || szTrack2Data[i] == 'F')
            szTrack2Data[i] = 0x00;
    }

    inLen = strlen(szTrack2Data);
    
    /* Data Length */
			
    uszSendData[inDataCnt ++] = (inLen / 10 * 16) + (inLen % 10);

    if (inLen % 2)
    {
        inLen ++;

				if(srTransPara->byTransType == BIN_VER)
					strcat(szTrack2Data, "0");
				else
        	strcat(szTrack2Data, "F");
    }
#ifdef TLE
    memset((char *)&uszSendData[inDataCnt], 0x00, (inLen/2)+1);
    byField_35_ON = TRUE;
#else
    wub_str_2_hex(&szTrack2Data[0], (char *)&uszSendData[inDataCnt], inLen);
#endif
    inDataCnt += (inLen / 2);
    
    vdMyEZLib_LogPrintf("  PACK_LEN%d",inDataCnt);
    vdMyEZLib_LogPrintf("**inPackIsoFunc35 END**");
    
    return (inDataCnt);
}


int inPackIsoFunc37(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    vdMyEZLib_LogPrintf("**inPackIsoFunc37 START**");
    inDataCnt = 0;

    memcpy((char *)&uszSendData[inDataCnt], srTransPara->szRRN, 12);
    inDataCnt += 12;
    
    vdMyEZLib_LogPrintf("  PACK_LEN%d",inDataCnt);
    vdMyEZLib_LogPrintf("**inPackIsoFunc37 END**");
    return inDataCnt;
}

int inPackIsoFunc38(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    vdMyEZLib_LogPrintf("**inPackIsoFunc38 START**");

    inDataCnt = 0;
    memcpy((char *)&uszSendData[inDataCnt], srTransPara->szAuthCode, 6);

    inDataCnt += 6;
    vdMyEZLib_LogPrintf("  PACK_LEN%d",inDataCnt);
    vdMyEZLib_LogPrintf("**inPackIsoFunc38 END**");
    return inDataCnt;
}

int inPackIsoFunc39(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    vdMyEZLib_LogPrintf("**inPackIsoFunc39 START**");
    inDataCnt = 0;
    memcpy((char *)&uszSendData[inDataCnt], srTransPara->szRespCode, 2);
    
    inDataCnt += 2;
    vdMyEZLib_LogPrintf("  PACK_LEN%d",inDataCnt);
    vdMyEZLib_LogPrintf("**inPackIsoFunc39 END**");
    return inDataCnt;
}

int inPackIsoFunc41(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    BYTE szTID[TERMINAL_ID_BYTES+1];

    inDataCnt = 0;    

    memset(szTID, 0x00, sizeof(szTID));
    memset(szTID, 0x20, TERMINAL_ID_BYTES);

	if (srTransRec.byTransType == PRE_AUTH && strTCT.fDCC == TRUE && strCDT.fDCCEnable == TRUE 
			&& inGetATPBinRouteFlag() != TRUE && (srTransPara->HDTid != 2 && srTransPara->HDTid != 4/*Not AMEX and AMEX USD host*/) && inCheckIssuerforBINRoute() == TRUE/*&& fRouteToSpecificHost == FALSE*/){
		memcpy(szTID, strFXT.szFXTTID, strlen(strFXT.szFXTTID));	
	}else{
    	memcpy(szTID, srTransPara->szTID, strlen(srTransPara->szTID));
	}
    memcpy((char *)&uszSendData[inDataCnt], szTID, TERMINAL_ID_BYTES);
    inDataCnt += TERMINAL_ID_BYTES;
    vdDebug_LogPrintf(" TID[%s] PACK_LEN[%d]",szTID, inDataCnt);
    
    return inDataCnt;
}

int inPackIsoFunc42(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    BYTE szMID[MERCHANT_ID_BYTES+1];
    
    inDataCnt = 0;

    memset(szMID, 0x00, sizeof(szMID));
    memset(szMID, 0x20, MERCHANT_ID_BYTES);
	
	if (srTransRec.byTransType == PRE_AUTH && strTCT.fDCC == TRUE && strCDT.fDCCEnable == TRUE 
			&& inGetATPBinRouteFlag() != TRUE && (srTransPara->HDTid != 2 && srTransPara->HDTid != 4/*Not AMEX and AMEX USD host*/) && inCheckIssuerforBINRoute() == TRUE /*&& fRouteToSpecificHost == FALSE*/){
		memcpy(szMID,"00000",5);	
		memcpy(&szMID[5], strFXT.szFXTMID, strlen(strFXT.szFXTMID));		
	}else{
    	memcpy(szMID, srTransPara->szMID, strlen(srTransPara->szMID));
	}
    memcpy((char *)&uszSendData[inDataCnt], szMID, MERCHANT_ID_BYTES);
    inDataCnt += MERCHANT_ID_BYTES;
    vdDebug_LogPrintf(" MID[%s] PACK_LEN[%d]",szMID, inDataCnt);
    
    return inDataCnt;
}

int inPackIsoFunc45(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{

    vdMyEZLib_LogPrintf("**inPackIsoFunc45 START**");
    inDataCnt = 0;
    uszSendData[inDataCnt++] = (srTransPara->usTrack1Len%100)/10*16+
                               (srTransPara->usTrack1Len%100)%10;
    vdMyEZLib_LogPrintf("  45Len%02x",uszSendData[0]);
#ifdef TLE
    memset((char *)&uszSendData[inDataCnt], 0x00, srTransPara->usTrack1Len);
    byField_45_ON = TRUE;
#else
    memcpy((char *)&uszSendData[inDataCnt], srTransPara->szTrack1Data, srTransPara->usTrack1Len);
#endif
    inDataCnt += srTransPara->usTrack1Len;
    
    vdMyEZLib_LogPrintf("  PACK_LEN%d",inDataCnt);
    vdMyEZLib_LogPrintf("**inPackIsoFunc45 END**");
    
    return inDataCnt;
}

int inPackIsoFunc48(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    int inCVV2Len;
    BYTE szBuf[30];
    vdMyEZLib_LogPrintf("**inPackIsoFunc48 START**");
    inDataCnt = 0;

	//verison16-start
	int inPOSSerialLen;
	char szTermSerialNum[30+1];
	char szAscBuf[4 + 1], szBcdBuf[2 + 1];
	int inPacketCnt = 0;
	//version16-end

#if 0
   if (fAMEXHostEnable == TRUE){
	   memset(szBuf, 0x00, sizeof(szBuf));
	   
	   inDataCnt = 0;
	   uszSendData[inDataCnt++] = 0x00;
	   uszSendData[inDataCnt++] = 0x23;

	   memcpy((char *)&uszSendData[inDataCnt], szAmexTID, strlen(szAmexTID));
	   inDataCnt+= strlen(szAmexTID);

	   memcpy((char *)&uszSendData[inDataCnt], szAmexMID, strlen(szAmexMID));
	   inDataCnt+= strlen(szAmexMID);

       return inDataCnt;
   }
#endif
    
#ifdef TLE
    memset(&uszSendData[inDataCnt], 0x00, 2);
    byField_48_ON = TRUE;
    inDataCnt += 2;
#else
    //remove-BDO does not support CVV input
/*
    DebugAddSTR("inPackIsoFunc48", srTransPara->szCVV2, 4);
    inCVV2Len = strlen(srTransPara->szCVV2);
    DebugAddINT("LEN", inCVV2Len);
    memset(szBuf, 0x00, sizeof(szBuf));
    sprintf(szBuf, "%04d", inCVV2Len);
    DebugAddSTR("inPackIsoFunc48", szBuf, 4);
    wub_str_2_hex(szBuf, (char *)&uszSendData[inDataCnt], 4);
    inDataCnt += 2;
    memcpy((char *)&uszSendData[inDataCnt], srTransPara->szCVV2, inCVV2Len);
    inDataCnt += inCVV2Len;
*/
    //version16-start

	/* Packet Data Length */
	vdDebug_LogPrintf("get serial");
	memset(szTermSerialNum, 0x00, sizeof(szTermSerialNum));
    CTOS_GetFactorySN(szTermSerialNum); 

	vdDebug_LogPrintf("get serial %s", szTermSerialNum);

	memset(szBuf, 0x00, sizeof(szBuf));
	strcpy(szBuf,"02");
	strcat(szBuf,szTermSerialNum);

	vdDebug_LogPrintf("after copy 02 and serial");

	inPacketCnt = strlen(szBuf);

	sprintf(szAscBuf, "%04d", inPacketCnt);
	vdDebug_LogPrintf("after get size");

	
	memset(szBcdBuf, 0, sizeof(szBcdBuf));
	wub_str_2_hex(szAscBuf, szBcdBuf, 4);

	memcpy((char *)&uszSendData[inDataCnt], &szBcdBuf[0], 2);
	inDataCnt += 2;

	vdDebug_LogPrintf("after copy size");

	/* Packet Data */
	memcpy((char *)&uszSendData[inDataCnt], &szBuf[0], inPacketCnt);
	inDataCnt += inPacketCnt;

	vdDebug_LogPrintf("after copy packet");
	
	vdMyEZLib_LogPrintf(". Pack Len(%d)",inDataCnt);
	vdMyEZLib_LogPrintf(". Pack data(%s)",szBuf);
	vdMyEZLib_LogPrintf("**field 48 END**");


	//version16-end
#endif

     return inDataCnt;
}


int inPackIsoFunc49(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    inDataCnt = 0;
	BYTE szCurrCode[10];
	char szTemp[10];
	
	vdDebug_LogPrintf("inPackIsoFunc49 [%s]",srTransPara->szDCCLocalCur);

	memset(szTemp,0x00,sizeof(szTemp));
	sprintf(szTemp,"0%s",srTransPara->szDCCLocalCur);
	wub_str_2_hex(szTemp,szCurrCode,4);
	
	memcpy((char *)&uszSendData[inDataCnt], szCurrCode, 2);
	
    inDataCnt += 2;
            
    return (inDataCnt);
}


int inPackIsoFunc51(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    inDataCnt = 0;
	BYTE szCurrCode[10];
	char szTemp[10];

    vdDebug_LogPrintf("inPackIsoFunc51 [%s]",srTransPara->szDCCCur);

	memset(szTemp,0x00,sizeof(szTemp));
	sprintf(szTemp,"0%s",srTransPara->szDCCCur);
	wub_str_2_hex(szTemp,szCurrCode,4);
	
	memcpy((char *)&uszSendData[inDataCnt], szCurrCode, 2);
	
    inDataCnt += 2;
            
    return (inDataCnt);
}


int inPackIsoFunc52(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
	char szTempPin[17];
	vdMyEZLib_LogPrintf("**inPackIsoFunc52 START**");
	inDataCnt = 0;

	/**************************************/
	vdDebug_LogPrintf("inPackIsoFunc52 | szPINBlock[%02X][%02X][%02X]", (unsigned char)srTransRec.szPINBlock[0], (unsigned char)srTransRec.szPINBlock[1], (unsigned char)srTransRec.szPINBlock[2]);
	vdDebug_LogPrintf("inPackIsoFunc52 | inDataCnt[%d]", inDataCnt);
	/**************************************/

	if (srTransPara->byTransType == SMAC_BALANCE || (inCheckIfSMCardInq() == TRUE && srTransPara->byTransType == BALANCE_INQUIRY) ){
		memcpy(srTransRec.szPINBlock, "\x99\x99\x99\x99\x99\x99\x99\x99", 8);
	}

	/* Packet Data */
	memcpy((char *)uszSendData, srTransRec.szPINBlock, 8);

	inDataCnt += 8;
	vdMyEZLib_LogPrintf("  PACK_LEN%d",inDataCnt);
	vdMyEZLib_LogPrintf("**inPackIsoFunc52 END**");
	return inDataCnt;
}


int inPackIsoFunc54(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    int inPacketCnt = 0;
    char szAscBuf[4+1], szBcdBuf[2+1];
    char szPacket[24+1];
    char szBaseAmt[20+1];
    char szVoidTotalAmt[20+1];
    BYTE szDCCLocalTipAmount[AMT_ASC_SIZE+1], szTipAmount[AMT_ASC_SIZE+1];
	
    inDataCnt = 0;
    DebugAddHEX("inPackIsoFunc54",srTransPara->szTipAmount,6);
    
    memset(szPacket, 0x00, sizeof(szPacket));
    
     //Should be Online void the Intial SALE amount.
    if(srTransPara->fDCC && (srTransPara->byTransType == SALE_TIP || srTransPara->byOrgTransType == SALE_TIP))
    {
		memset(szDCCLocalTipAmount, 0x00, sizeof(szDCCLocalTipAmount));
        memset(szTipAmount, 0x00, sizeof(szTipAmount));
		
		wub_hex_2_str(srTransPara->szDCCLocalTipAmount, szDCCLocalTipAmount, 6);
		wub_hex_2_str(srTransPara->szTipAmount, szTipAmount, 6);
		sprintf(szPacket, "%012.0f%012.0f", atof(szDCCLocalTipAmount), atof(szTipAmount));
    }
    else
    {
        if(srTransPara->byTransType == VOID)
        {
            //use szStoreID to store how much amount fill up in DE4 for VOID
            memset(szBaseAmt, 0x00, sizeof(szBaseAmt));
            memset(szVoidTotalAmt, 0x00, sizeof(szVoidTotalAmt));
            
            wub_hex_2_str(srTransPara->szBaseAmount, szBaseAmt, 6);
            wub_hex_2_str(srTransPara->szStoreID, szVoidTotalAmt, 6);
            // patrick add code 20141216
            sprintf(szPacket, "%012.0f", atof(szVoidTotalAmt) - atof(szBaseAmt));
        }
        else
        {
            wub_hex_2_str(srTransPara->szTipAmount, szPacket, 6);
        }
    }
	
    inPacketCnt = strlen(szPacket);
    memset(szAscBuf, 0x00, sizeof(szAscBuf));
    sprintf(szAscBuf, "%04d", inPacketCnt);
	wub_str_2_hex(szAscBuf, szBcdBuf, 4);
	memcpy((char *)&uszSendData[inDataCnt], &szBcdBuf[0], 2);
	inDataCnt += 2;

    DebugAddHEX("inPackIsoFunc54", szBcdBuf, 2);
    
	/* Packet Data */
	memcpy((char *)&uszSendData[inDataCnt], &szPacket[0], inPacketCnt);
	inDataCnt += inPacketCnt;

    DebugAddSTR("inPackIsoFunc54", szPacket, 12);
	
	vdMyEZLib_LogPrintf("**inPackIsoFunc54 START**");
	return inDataCnt;
}



int inPackIsoFunc55(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    vdMyEZLib_LogPrintf("**inPackIsoFunc55 START**");
    
    inDataCnt = 0;

	if (srTransPara->byEntryMode == CARD_ENTRY_ICC)
    	inDataCnt = inPackISOEMVData(srTransPara, uszSendData);
	if (srTransPara->byEntryMode == CARD_ENTRY_WAVE)
	{
		if (srTransPara->bWaveSID == d_VW_SID_PAYPASS_MCHIP)
			inDataCnt = inPackISOPayPassData(srTransPara, uszSendData);

		if (srTransPara->bWaveSID == d_VW_SID_VISA_WAVE_2 ||
			srTransPara->bWaveSID == d_VW_SID_VISA_WAVE_QVSDC )
			inDataCnt = inPackISOPayWaveData(srTransPara, uszSendData);

		//if ((srTransPara->bWaveSID == d_VW_SID_JCB_WAVE_2) ||
			//(srTransPara->bWaveSID == d_VW_SID_JCB_WAVE_QVSDC))	
			
		if ((srTransPara->bWaveSID == 0x63) ||
			(srTransPara->bWaveSID == 0x65))
			inDataCnt = inPackISOJCBCtlsData(srTransPara, uszSendData);
		
		/* CTLS: AMEX ExpressPay 3.0 requirement - start -- jzg */
		if (srTransPara->bWaveSID == d_VW_SID_AE_EMV)
			inDataCnt = inPackISOExpressPayData(srTransPara, uszSendData);
		/* CTLS: AMEX ExpressPay 3.0 requirement - end -- jzg */

		if (srTransPara->bWaveSID == d_VW_SID_CUP_EMV)
			inDataCnt = inPackISOQuickpassData(srTransPara, uszSendData);
		
		if (srTransPara->bWaveSID == d_EMVCL_SID_DISCOVER_DPAS)		
			inDataCnt = inPackISODPasData(srTransPara, uszSendData);
	}

    vdMyEZLib_LogPrintf("  PACK_LEN%d",inDataCnt);
    vdMyEZLib_LogPrintf("**inPackIsoFunc55 END**");
    return inDataCnt;
}

int inPackIsoFunc56(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    vdMyEZLib_LogPrintf("**inPackIsoFunc56 START**");
    inDataCnt = 0;
    
    vdMyEZLib_LogPrintf("  PACK_LEN%d",inDataCnt);
    vdMyEZLib_LogPrintf("**inPackIsoFunc56 END**");
    return inDataCnt;
}

int inPackIsoFunc57(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    int	           in_FieldLen = 0, inPacketCnt = 0, inPacketLen=0;
    BYTE           szAscBuf[4 + 1], szBcdBuf[2 + 1];
    BYTE           szPacket[512 + 1];
    BYTE           szPacketASC[512 + 1];
    unsigned short usLen, usRetVal;
    BYTE           btTrack2[20];
    int            inBitMapIndex;
    BYTE           szDataBuf[255], szTrack2Data[40], szTempPan[19];
    short   i,in_Field35Len=0, in_Field02Len=0;
    char szAscBuf1[4 + 1];
    
        
    inTLERead(1);
    vdMyEZLib_LogPrintf("**inPackIsoFunc57 START**");
    memset(szPacket, 0, sizeof(szPacket));
    inDataCnt = 0; 

 		if(srTransPara->byTransType == SETTLE || srTransPara->byTransType == CLS_BATCH)
 		{
    		inPacketCnt=18;    		   	    
   	    sprintf(szAscBuf, "%04d", inPacketCnt);
		    memset(szBcdBuf, 0, sizeof(szBcdBuf));
		    wub_str_2_hex(szAscBuf, szBcdBuf, 4);
		    memcpy((char *)&uszSendData[inDataCnt], &szBcdBuf[0], 2);		    
		    inDataCnt += 2;
		    memcpy(&uszSendData[inDataCnt], stTLE.szVERSION, 2);
    		inDataCnt += 2;    		
    		
    		memset(szPacketASC, 0x30, 16);    
    		vdTripleDES_CBC(d_ENCRYPTION, szPacketASC, 16, szDataBuf);;     		
			  memcpy((char *)&uszSendData[inDataCnt], &szDataBuf[0], 16);
		    inDataCnt += 16;
				
				vdMyEZLib_LogPrintff(uszSendData,inDataCnt );
				    
 			  return (inDataCnt);
 		} 	        
    else if(srTransPara->byTransType == SIGN_ON)
    {
    		memcpy(&szPacket[inPacketCnt], stTLE.szVERSION, 2);
    		inPacketCnt = inPacketCnt + 2; 
    
        memcpy(&szPacket[inPacketCnt], stTLE.szTMKRefNum, 8);
        inPacketCnt = inPacketCnt + 8;
        /* Packet Data Length */
		    memset(szAscBuf, 0, sizeof(szAscBuf));
		    sprintf(szAscBuf, "%04d", inPacketCnt);
		    memset(szBcdBuf, 0, sizeof(szBcdBuf));
		    wub_str_2_hex(szAscBuf, szBcdBuf, 4);
		    memcpy((char *)&uszSendData[inDataCnt], &szBcdBuf[0], 2);
		    inDataCnt += 2;
			  memcpy((char *)&uszSendData[inDataCnt], &szPacket[0], inPacketCnt);
		    inDataCnt += inPacketCnt;
    
        return (inDataCnt);
    }
    else
    {
        inBitMapIndex = inPacketCnt;
    
        inPacketCnt = inPacketCnt + 8; // skip bit map
        if (byField_02_ON == CN_TRUE)
        {
	          szPacket[inBitMapIndex+0] = 0x40;
	
						strcpy(szTempPan, srTransPara->szPAN);
						in_Field02Len = strlen(srTransPara->szPAN);
						if (in_Field02Len % 2)
						{	
							in_FieldLen= in_Field02Len + 1;
        			szTempPan[in_FieldLen] = '0';        			
            }
            else            		          
             in_FieldLen= in_Field02Len;
    				
    				vdisoTwoOne(srTransPara->szPAN, in_FieldLen, &szPacket[inPacketCnt]);
            
            vdMyEZLib_LogPrintf("**PAN**");
            vdMyEZLib_LogPrintff(&szPacket[inPacketCnt], in_FieldLen/2);
            inPacketCnt += in_FieldLen/2;
        }

    
        if (byField_14_ON == CN_TRUE)
        {
            szPacket[inBitMapIndex + 1] = szPacket[inBitMapIndex + 1] | 0x04;
        
            memcpy((char *)&szPacket[inPacketCnt], srTransPara->szExpireDate, 2);
            vdMyEZLib_LogPrintf("**Expired**");
            vdMyEZLib_LogPrintff(&szPacket[inPacketCnt], 2);
            inPacketCnt += 2;
        }
    
        if (byField_35_ON == CN_TRUE && srTransPara->byPackType != TC_UPLOAD)
        {
            szPacket[inBitMapIndex + 4] = szPacket[inBitMapIndex + 4] | 0x20;
                        
            strcpy(szTrack2Data, srTransPara->szTrack2Data);

				    for (i = 0; i < strlen(szTrack2Data); i ++)
				    {
				        if (szTrack2Data[i] == '=')
				            szTrack2Data[i] = 'D';
				    }
            in_Field35Len = strlen(szTrack2Data);
    				if (in_Field35Len % 2)
    				{
        				in_FieldLen= in_Field35Len + 1;
        				strcat(szTrack2Data, "0");
    				} 
    				else
    					in_FieldLen=  in_Field35Len; 					       
         		vdisoTwoOne(szTrack2Data, in_FieldLen, &szPacket[inPacketCnt]);
            vdMyEZLib_LogPrintf("**Track 2**");
            vdMyEZLib_LogPrintff(&szPacket[inPacketCnt], in_FieldLen/2);
            inPacketCnt += (in_FieldLen/2);
        }

        if (byField_45_ON == CN_TRUE && srTransPara->byPackType != TC_UPLOAD)
        {
            szPacket[inBitMapIndex + 5] = szPacket[inBitMapIndex + 5] | 0x08;
	
            in_FieldLen = strlen(srTransPara->szTrack1Data);	
        
            memcpy((char *)&szPacket[inPacketCnt], srTransPara->szTrack1Data, in_FieldLen);
            inPacketCnt += in_FieldLen;
        }

        if(strTCT.fCVVEnable)
        {
        if (byField_48_ON == CN_TRUE)
        {
            szPacket[inBitMapIndex + 5] = szPacket[inBitMapIndex + 5] | 0x01;
	    
                        sprintf(szAscBuf1,"%s","%04s");
        		sprintf(szAscBuf,szAscBuf1,(char *)srTransPara->szCVV2);
                        
         		vdisoTwoOne(szAscBuf, 4, szBcdBuf);
        		
        		vdMyEZLib_LogPrintf("**CVV**  %s",srTransPara->szCVV2);        
        		vdMyEZLib_LogPrintff(szBcdBuf,2);
        		
            memcpy((char *)&szPacket[inPacketCnt], szBcdBuf, 2);
            inPacketCnt += 2;
        }
        }
    }
    
    memset(szPacketASC, 0x30, sizeof(szPacketASC));
    vdMyEZLib_LogPrintf("**before**  %d",inPacketCnt);
		vdMyEZLib_LogPrintff(szPacket,inPacketCnt );
		
    vdisoOneTwo(szPacket, szPacketASC, inPacketCnt);        
    inPacketCnt = inPacketCnt*2;    
    
    vdMyEZLib_LogPrintf("**before**  %d",inPacketCnt);
		vdMyEZLib_LogPrintf(szPacketASC,inPacketCnt );
		
    if(inPacketCnt%8!=0)
    {
        szPacketASC[inPacketCnt] = 0x38;
        inPacketCnt = inPacketCnt + (8-(inPacketCnt%8));
    }
    
    memset(szDataBuf, 0, sizeof(szDataBuf));
    vdTripleDES_CBC(d_ENCRYPTION, szPacketASC, inPacketCnt, szDataBuf);
    
	/* Packet Data Length */
	  inPacketLen= inPacketCnt+2;  // add 2 for stTLE.szVERSION
    memset(szAscBuf, 0, sizeof(szAscBuf));
    sprintf(szAscBuf, "%04d", inPacketLen);
    memset(szBcdBuf, 0, sizeof(szBcdBuf));
    wub_str_2_hex(szAscBuf, szBcdBuf, 4);
    memcpy((char *)&uszSendData[inDataCnt], &szBcdBuf[0], 2);
    inDataCnt += 2;
    memcpy(&uszSendData[inDataCnt], stTLE.szVERSION, 2);
    inDataCnt += 2;
    
	/* Packet Data */
    memcpy((char *)&uszSendData[inDataCnt], &szDataBuf[0], inPacketCnt);
    inDataCnt += inPacketCnt;
	
	  vdMyEZLib_LogPrintf("**57 data**");
		vdMyEZLib_LogPrintff(uszSendData,inDataCnt );
    vdMyEZLib_LogPrintf("**inPackIsoFunc57 START**");
    return (inDataCnt);
}

int inPackIsoFunc60(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    int inPacketCnt = 0;
    char szAscBuf[4 + 1], szBcdBuf[2 + 1];
    char szPacket[100 + 1];
	char szbuff[4+1];
    BYTE szDCCLocalAmount[AMT_ASC_SIZE+1], szAmount[AMT_ASC_SIZE+1];
	
    vdDebug_LogPrintf("**inPackIsoFunc60 byPackType[%d]ulOrgTraceNum[%ld]szMassageType[%02X%02X]**", srTransPara->byPackType, srTransPara->ulOrgTraceNum, srTransPara->szMassageType[0], srTransPara->szMassageType[1]);
	vdDebug_LogPrintf("**inPackIsoFunc60 byTransType[%d] :: byOrgTransType[%d] :: byUploaded[%d]**", srTransPara->byTransType, srTransPara->byOrgTransType,srTransPara->byUploaded);
    inDataCnt = 0;

		CTOS_RTC SetRTC;
    
    memset(szPacket, 0x00, sizeof(szPacket));

    if((srTransPara->byPackType == DCC_CHECKSTATUS) || (srTransPara->byPackType == DCC_RATEREQUEST) || (srTransPara->byPackType == DCC_LOGGING) || (srTransPara->byPackType== DCC_LOGGING_RETRY) || (srTransPara->byPackType == DCC_RATEREQUEST_RETRY))
    {
    
       CTOS_RTCGet(&SetRTC);
       
       sprintf(szbuff,"%04d",SetRTC.bYear + 2000);
       vdDebug_LogPrintf("AAA szbuff[%s]", szbuff);  
       
       
       strcpy(szPacket, szbuff);
       strcat(szPacket, "                 ");
       
       if (srTransPara->byPackType == DCC_RATEREQUEST || srTransPara->byPackType == DCC_RATEREQUEST_RETRY)
          strcat(szPacket, "890");
       else if (srTransPara->byPackType == DCC_LOGGING || srTransPara->byPackType == DCC_LOGGING_RETRY)
          strcat(szPacket, "891");
       else 
          strcat(szPacket, "831");
       
       strcat(szPacket, "000000000000");
       
       inPacketCnt += 36;
       
       
       /* Packet Data Length */
       memset(szAscBuf, 0, sizeof(szAscBuf));
       sprintf(szAscBuf, "%04d", inPacketCnt);
       memset(szBcdBuf, 0, sizeof(szBcdBuf));
       wub_str_2_hex(szAscBuf, szBcdBuf, 4);
       memcpy((char *)&uszSendData[inDataCnt], &szBcdBuf[0], 2);
       inDataCnt += 2;
       
       
       /* Packet Data */
       memcpy((char *)&uszSendData[inDataCnt], &szPacket[0], inPacketCnt);
       inDataCnt += inPacketCnt;
       
       vdDebug_LogPrintf("AAA - Pack Len(%d)",inDataCnt);
       vdDebug_LogPrintf("**inPackIsoFunc60 END**");
       return inDataCnt;
    
    }
    
    if((srTransPara->byPackType == BATCH_UPLOAD) || (srTransPara->byPackType == TC_UPLOAD))
    {   
        /* Load the Original Data Message in field 60 */
        /* Field 60 contains 4 digits of MID, 6 digits of STAN
           and 12 digits of Reserved space set to spaces.
           */    
		if ((srTransPara->byOrgTransType == SALE) && (srTransPara->byOffline == CN_TRUE))
			strcpy(szPacket, "0200");
		else
			wub_hex_2_str(srTransPara->szMassageType,szPacket,2);
		inPacketCnt += 4;

        sprintf(&szPacket[inPacketCnt], "%06ld", srTransPara->ulOrgTraceNum);
        inPacketCnt += 6;

        
		//issue-00423- put spaces in RRN for SMAC AWARD   
		//if ((srTransPara->szMassageType[0] == 0x02 && srTransPara->szMassageType[1] == 0x20) && ((srTransPara->HDTid == SMAC_HDT_INDEX) || (srTransPara->HDTid == SMGUARANTOR_HDT_INDEX)))
		if ((srTransPara->szMassageType[0] == 0x02 && srTransPara->szMassageType[1] == 0x20) && (inCheckIfSMCardTransPara(srTransPara) == TRUE))
			memcpy(&szPacket[inPacketCnt],"\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20",RRN_BYTES);
#if 0
		else if(srTransPara->byTransType == SALE_TIP)//Use RRN of Sale instead of Tip Adjust
			memcpy(&szPacket[inPacketCnt],srTransPara->szOrgRRN,RRN_BYTES);
#endif
		else
        	memcpy(&szPacket[inPacketCnt],srTransPara->szRRN,RRN_BYTES);
        inPacketCnt += RRN_BYTES;  
    }
    else if(srTransPara->byTransType == SETTLE || srTransPara->byTransType == CLS_BATCH)
    {
        //wub_hex_2_str(srTransRec.szBatchNo,szPacket,3);
        wub_hex_2_str(srTransPara->szBatchNo,szPacket,3);
        
        inPacketCnt += 6;
    }
	else
	{
		if(srTransPara->fDCC && 
		  ( (srTransPara->byTransType == SALE_TIP || srTransPara->byOrgTransType == SALE_TIP) || 
		    (srTransPara->byTransType == VOID && srTransPara->byOrgTransType == SALE_OFFLINE) ) )
		{
			memset(szDCCLocalAmount, 0x00, sizeof(szDCCLocalAmount));
			memset(szAmount, 0x00, sizeof(szAmount));
			
			wub_hex_2_str(srTransPara->szDCCLocalAmount, szDCCLocalAmount, 6);
			wub_hex_2_str(srTransPara->szBaseAmount, szAmount, 6);
			sprintf(szPacket, "%012.0f%012.0f", atof(szDCCLocalAmount), atof(szAmount));
			inPacketCnt += 24;
		}
        else
        {
           if((srTransPara->byOrgTransType == SALE_OFFLINE || srTransPara->byOrgTransType == SALE_TIP) && (srTransPara->byUploaded == CN_TRUE))
           {
               if( (srTransPara->byTransType == VOID && srTransPara->byOrgTransType == SALE_TIP) ||//Fix for total amount instead of original amount set on DE60 on void of uploaded tip adjust transaction
               (srTransPara->byTransType == SALE_TIP && srTransPara->byPackType == SEND_ADVICE) )//Fix for incorrect DE60 on sending of Tip Adjust of Completion
               {
                   wub_hex_2_str(srTransPara->szBaseAmount,szPacket,6);
                   inPacketCnt += 12;
               }
               else
               {
                   wub_hex_2_str(srTransPara->szTotalAmount,szPacket,6);
                   inPacketCnt += 12;
               }
           }
           else
           {
               wub_hex_2_str(srTransPara->szBaseAmount,szPacket,6);
               inPacketCnt += 12;
           }
        }
	}
	
	#if 0
	else if((srTransPara->byOrgTransType == SALE_OFFLINE || srTransPara->byOrgTransType == SALE_TIP) && (srTransPara->byUploaded == CN_TRUE))
	{
        if( (srTransPara->byTransType == VOID && srTransPara->byOrgTransType == SALE_TIP) ||//Fix for total amount instead of original amount set on DE60 on void of uploaded tip adjust transaction
        (srTransPara->byTransType == SALE_TIP && srTransPara->byPackType == SEND_ADVICE) )//Fix for incorrect DE60 on sending of Tip Adjust of Completion
        {
            wub_hex_2_str(srTransPara->szBaseAmount,szPacket,6);
            inPacketCnt += 12;
        }
        else
        {
            wub_hex_2_str(srTransPara->szTotalAmount,szPacket,6);
            inPacketCnt += 12;
        }
	}
    else
    {
        wub_hex_2_str(srTransPara->szBaseAmount,szPacket,6);
        inPacketCnt += 12;
    }
    #endif
	
      
    /* Packet Data Length */
	memset(szAscBuf, 0, sizeof(szAscBuf));
	sprintf(szAscBuf, "%04d", inPacketCnt);
	memset(szBcdBuf, 0, sizeof(szBcdBuf));
	wub_str_2_hex(szAscBuf, szBcdBuf, 4);
	memcpy((char *)&uszSendData[inDataCnt], &szBcdBuf[0], 2);
	inDataCnt += 2;
	/* Packet Data */
	memcpy((char *)&uszSendData[inDataCnt], &szPacket[0], inPacketCnt);
	inDataCnt += inPacketCnt;
	
	vdDebug_LogPrintf(". Pack Len(%d)",inDataCnt);
	vdDebug_LogPrintf("**inPackIsoFunc60 END**");
	return inDataCnt;

}


int inPackIsoFunc61(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
	vdMyEZLib_LogPrintf("**inPackIsoFunc61 START**");
	inDataCnt = 0;
	char szPacket[250+1], szPacketbuff[250+1];
	char szBaseAmt[AMT_ASC_SIZE+1];
  	char szLen[23+1];
	char szTempPAN[40+1];
	char szTempPAN1[40+1];
	unsigned char szTmp[25];
	int inlen;
	char szAscBuf[4 + 1], szBcdBuf[2 + 1];
	int inPacketCnt = 0;
	char szDateTime[10+1]; 
	unsigned char szInvoiceNo[10 + 1];
	unsigned char szInvoiceNoTemp[10 + 1];
	char szTemp[24+1];
	char szDCCMinorUnit[15+1];
	BYTE szDateTimeBuff[14+1];
	BYTE szDateBuff[14+1];
	BYTE szTimeBuff[14+1];
	char szTemplate[100] = {0};
	BYTE szTmpHex[3] = {0};
	CTOS_RTC SetRTC;
    

	vdDebug_LogPrintf("***inPackIsoFunc61 START***");
	
  if (srTransPara->byPackType == DCC_RATEREQUEST || srTransPara->byPackType == DCC_RATEREQUEST_RETRY)
  {
     memset(szPacket, 0x00, sizeof(szPacket)); 
     memset (szPacketbuff, 0x00, sizeof(szPacketbuff));
     
     inFXTRead(1);

	 //Continuation Bit - Fix for issue 0005
	 strcpy(szPacketbuff, "fa02");  
	 
     //FXMID
     memset(szLen, 0x00, sizeof(szLen));
     sprintf(szLen,"%d",strlen(strFXT.szFXTMID)); 
     strcat(szPacketbuff, szLen);
     strcat(szPacketbuff, strFXT.szFXTMID);
     //vdCTOS_Pad_String(szPacketbuff, 15, '0', POSITION_LEFT);	
     
     //FXTID
     memset(szTmp, 0x00, sizeof(szTmp));
	 memset(szTmp, 0x20, 16);
	 memcpy(szTmp,strFXT.szFXTTID, strlen(strFXT.szFXTTID));
	 strcat(szPacketbuff, szTmp);	   
     //strcat(szPacketbuff, strFXT.szFXTTID);
     
     //FXACQID
     memset(szLen,0x00,sizeof(szLen));
     sprintf(szLen,"%d",strlen(strFXT.szACQID)); 
     strcat(szPacketbuff, szLen);
     strcat (szPacketbuff, strFXT.szACQID);
     
     //AMT
     //strcat(szPacketbuff, "608");
     strcat(szPacketbuff, srTransPara->szDCCLocalCur);
     wub_hex_2_str(srTransRec.szTotalAmount, szBaseAmt, 6); 
     vdCTOS_Pad_String(szBaseAmt, 12, '0', POSITION_RIGHT);	
     strcat(szPacketbuff, szBaseAmt);
     strcat(szPacketbuff, "2");
     
     //PAN
     memset(szLen,0x00,sizeof(szLen));
     sprintf(szLen,"%d",strlen(srTransRec.szPAN)); 
     strcat(szPacketbuff, szLen);
     memset(szTempPAN, 0x30, atoi(szLen));
	 memcpy(szTempPAN,srTransRec.szPAN,11);
     strcat (szPacketbuff, szTempPAN);
     
     //CARD TYPE	
     if (strIIT.inIssuerNumber == 2)
     strcat(szPacketbuff, "VSA");
     else if (strIIT.inIssuerNumber == 4)
     strcat(szPacketbuff, "MCD");
     else if (strIIT.inIssuerNumber == 8)
     strcat(szPacketbuff, "DIN");
     else if (strIIT.inIssuerNumber == 3)
     strcat(szPacketbuff, "AMX");
     else if (strIIT.inIssuerNumber == 12)
     strcat(szPacketbuff, "JCB");
     else
     strcat(szPacketbuff, "OTH");
     
     
     strcat(szPacketbuff, "04"); // continuation bit. BIT 17
     strcat(szPacketbuff, "000001"); // TILL ID 
     
     //strcat(szPacketbuff, "08"); //2ND SUB ELEMENT
     //strcat(szPacketbuff, "608"); //CURRENCY CODE
     
     inlen= strlen(szPacketbuff); //PACKET LENGTH
     memset(szTmp, 0x00, sizeof(szTmp));
     
     sprintf((char *)szTmp,"%04x",inlen);
     
     strcpy(szPacket, "71");  //data set ID
     
     strcat(szPacket, szTmp); //packet length
     
     strcat(szPacket, "fa02");  //first bitmap
     
	 strcat(szPacket, "04");  //second bitmap
	
	 //strcat(szPacket, "84");  //second bitmap
     
     //strcat(szPacket, "08");  //third bitmap

	  strcat(szPacket, szPacketbuff); // copy whole body of field 61
     
     vdDebug_LogPrintf("AAA FIELD 61: %s", szPacket);
     //CTOS_Delay(3000);
     
     inPacketCnt += strlen(szPacket);
     
     /* Packet Data Length */
     memset(szAscBuf, 0, sizeof(szAscBuf));
     sprintf(szAscBuf, "%04d", inPacketCnt);
     memset(szBcdBuf, 0, sizeof(szBcdBuf));
     wub_str_2_hex(szAscBuf, szBcdBuf, 4);
     memcpy((char *)&uszSendData[inDataCnt], &szBcdBuf[0], 2);
     inDataCnt += 2;
     
     
     /* Packet Data */
     memcpy((char *)&uszSendData[inDataCnt], &szPacket[0], inPacketCnt);
     inDataCnt += inPacketCnt;
     
     vdDebug_LogPrintf("AAA - Pack Len(%d)",inDataCnt);
     vdDebug_LogPrintf("**inPackIsoFunc61 END**");
     return inDataCnt;
  
  }

	if (srTransPara->byPackType  == DCC_LOGGING || srTransPara->byPackType== DCC_LOGGING_RETRY) 
    {
    
       memset(szPacket, 0x00, sizeof(szPacket)); 
       memset (szPacketbuff, 0x00, sizeof(szPacketbuff));
       
       strcpy(szPacketbuff, "fffe"); //continuation bit
       inFXTRead(1);
       
       //MID and length 61-71.2
       memset(szLen, 0x00, sizeof(szLen));
       sprintf(szLen,"%d",strlen(strFXT.szFXTMID)); 	   
       strcat(szPacketbuff, szLen);

       strcat(szPacketbuff, strFXT.szFXTMID);

       //TID length and TID value 61-71.3
       memset(szTmp, 0x00, sizeof(szTmp));
       memset(szTmp, 0x20, 16);
	   memcpy(szTmp,strFXT.szFXTTID, strlen(strFXT.szFXTTID));
	   strcat(szPacketbuff, szTmp);

	   //Acquirer ID length and Acquirer ID value 61-71.4
       memset(szLen,0x00,sizeof(szLen));
       sprintf(szLen,"%d",strlen(strFXT.szACQID)); 
       strcat(szPacketbuff, szLen);
       strcat (szPacketbuff, strFXT.szACQID);	

	   //PESO Base amount value 61-71.5
       strcat(szPacketbuff, srTransPara->szDCCLocalCur);
       wub_hex_2_str(srTransPara->szDCCLocalAmount, szBaseAmt, 6); 
       strcat(szPacketbuff, szBaseAmt);
	   strcat(szPacketbuff, "2");
       
       //inCSTRead(1); //default  to 1 need to change to accept multi FOREIGN currency
       
       //Foreign amount value 61-71.6
       strcat(szPacketbuff, srTransPara->szDCCCur);
       strcat(szPacketbuff, srTransPara->szDCCCurAmt);
	   sprintf(szDCCMinorUnit,"%d",srTransPara->inDCCCurMU);
	   strcat(szPacketbuff, szDCCMinorUnit);
		
		//PAN 61-71.7
	   memset(szTempPAN,0x00,sizeof(szTempPAN));
	   memset(szLen,0x00,sizeof(szLen));
	   sprintf(szLen,"%d",strlen(srTransPara->szPAN)); 
	   strcat(szPacketbuff, szLen);
	   memset(szTempPAN, 0x30, atoi(szLen));
	   memcpy(szTempPAN,srTransPara->szPAN,10);
	   strcat (szPacketbuff, szTempPAN);

	   //RRN 61-71.8
	   memset(szLen,0x00,sizeof(szLen));
	   sprintf(szLen,"%d",strlen(srTransPara->szRRN));  
	   strcat(szPacketbuff,szLen);
	   strcat(szPacketbuff,srTransPara->szRRN);

	   //Exchange rate 61-71.9
	   memset(szLen, 0x00, sizeof(szLen));
       sprintf(szLen,"%d",srTransPara->inDCCFXRateMU); 
	   strcat(szPacketbuff, szLen);
       strcat(szPacketbuff, srTransPara->szDCCFXRate);
              
       //rate request reference ID 61-71.10
       memset(szLen, 0x00, sizeof(szLen));
       sprintf(szLen,"%02d",strlen(srTransPara->szDCCFXRateRefID));
       strcat(szPacketbuff, szLen);
       
       strcat(szPacketbuff, srTransPara->szDCCFXRateRefID);
       
       //auth code 61-71.11
       strcat(szPacketbuff, srTransPara->szAuthCode);
       
       
       //complete date and time
       //vdGetTimeDate(srTransPara);

	   //YYYYMMDDhhmmss
	   //vdGetYear(srTransPara);
	   CTOS_RTCGet(&SetRTC);
	   memset(szDateTimeBuff,0x00,sizeof(szDateTimeBuff));
       memset(szDateBuff,0x00,sizeof(szDateBuff));
       memset(szTimeBuff,0x00,sizeof(szTimeBuff));

	   wub_hex_2_str(srTransPara->szDate,szDateBuff,2); 
	   wub_hex_2_str(srTransPara->szTime,szTimeBuff,3); 
	   sprintf(szDateTimeBuff,"%04d%s%s",SetRTC.bYear + 2000,szDateBuff,szTimeBuff);
		
	   strcat(szPacketbuff, szDateTimeBuff);

	   //sprintf(szDateTimeBuff,"20%02d",srTransPara->szYear);
	   //memcpy(szDateTimeBuff+4, srTransPara->szDate, DATE_BCD_SIZE);
	   //memcpy(szDateTimeBuff+4+DATE_BCD_SIZE, srTransPara->szTime, TIME_BCD_SIZE);
       //strcat(szPacketbuff, srTransPara->szDateTime);
       
       //dcc process status
       strcat(szPacketbuff, "0");
       
       //authorization message type
       #if 1
       if(srTransPara->byDCCTransType == SALE)	
             strcat(szPacketbuff, "0");
       else if(srTransPara->byDCCTransType == SALE_OFFLINE)	
             strcat(szPacketbuff, "1");
       else if(srTransPara->byDCCTransType == VOID)	
             strcat(szPacketbuff, "3");
       else if(srTransPara->byDCCTransType == SALE_TIP)	
             strcat(szPacketbuff, "6");
	   #else
       if(srTransPara->byTransType == SALE)	
             strcat(szPacketbuff, "0");
       else if(srTransPara->byTransType == SALE_OFFLINE)	
             strcat(szPacketbuff, "1");
       else if(srTransPara->byTransType == VOID)	
             strcat(szPacketbuff, "3");
       else if(srTransPara->byTransType == SALE_TIP)	
             strcat(szPacketbuff, "6");
       #endif
	   vdDebug_LogPrintf("inPackIsoFunc61 byTransType: %d", srTransPara->byDCCTransType);
	   	
       //card type
       strcat(szPacketbuff, srTransPara->szDCCCardType); 
       
       //continuation bit
       strcat(szPacketbuff, "3e"); // continuation bit
       
       //batch number
       memset(szTmp, 0x00, sizeof(szTmp));
	   //wub_hex_2_str(srTransPara->szBatchNo,szTmp,3); 
	   //szTmp[6]=0x00;
	   //strcat(szPacketbuff, szTmp);
	   strcat(szPacketbuff, "000000");//Set batch number to 0
       //strcat(szPacketbuff, srTransPara->szBatchNo);
       
       //DCC_MID
       memset(szLen,0x00,sizeof(szLen));
       sprintf(szLen,"%02d",strlen(srTransPara->szDCCFXMID));
       strcat(szPacketbuff, szLen);
       strcat(szPacketbuff, srTransPara->szDCCFXMID);
       
       //TID
       strcat(szPacketbuff, srTransPara->szDCCFXTID);

#if 0      
       //FXACQID
       memset(szLen,0x00,sizeof(szLen));
       sprintf(szLen,"%d",strlen(strFXT.szACQID)); 
       strcat(szPacketbuff, szLen);
       strcat (szPacketbuff, strFXT.szACQID);
#endif
       //Merchant POS
       strcat(szPacketbuff, "000001");

       //invoice number
       memset(szInvoiceNo,0x00,sizeof(szInvoiceNo));
	   memset(szInvoiceNoTemp,0x00,sizeof(szInvoiceNoTemp));
	   //wub_hex_2_str(srTransRec.szInvoiceNo, szInvoiceNoTemp, INVOICE_BCD_SIZE);
	   wub_hex_2_str(srTransPara->szInvoiceNo, szInvoiceNoTemp, INVOICE_BCD_SIZE);
	   strcpy(szInvoiceNo,"0000");
	   strcat(szInvoiceNo,szInvoiceNoTemp);
       strcat(szPacketbuff,szInvoiceNo);

	   vdDebug_LogPrintf("inPackIsoFunc61 szInvoiceNo: %s", szInvoiceNo);
#if 0
       //trace number
       memset(szTmp, 0x00, sizeof(szTmp));
	   memset(szSTAN, 0x00, sizeof(szSTAN));
       sprintf(szTmp, "%06ld", srTransPara->ulTraceNum); 

	   sprintf(szSTAN,"0000%s",szTmp);
       strcat(szPacketbuff, szSTAN);
#endif

       //get packet length
       inlen= strlen(szPacketbuff);
       memset(szTmp, 0x00, sizeof(szTmp));
       
       sprintf((char *)szTmp,"%04x",inlen);
       
       strcpy(szPacket, "71");  //data set ID
       
       strcat(szPacket, szTmp); //packet length
       
       strcat(szPacket, "fffe");  //first bitmap
       
       strcat(szPacket, "3e");  //second bitmap

       strcat(szPacket, szPacketbuff); // copy whole body of field 61
       
       vdDebug_LogPrintf("AAA FIELD 61: %s", szPacket);
       //CTOS_Delay(3000);
       
       inPacketCnt += strlen(szPacket);
       
       /* Packet Data Length */
       memset(szAscBuf, 0, sizeof(szAscBuf));
       sprintf(szAscBuf, "%04d", inPacketCnt);
       memset(szBcdBuf, 0, sizeof(szBcdBuf));
       wub_str_2_hex(szAscBuf, szBcdBuf, 4);
       memcpy((char *)&uszSendData[inDataCnt], &szBcdBuf[0], 2);
       inDataCnt += 2;
       
       
       /* Packet Data */
       memcpy((char *)&uszSendData[inDataCnt], &szPacket[0], inPacketCnt);
       inDataCnt += inPacketCnt;
       
       vdDebug_LogPrintf("AAA - Pack Len(%d)",inDataCnt);
       vdDebug_LogPrintf("**inPackIsoFunc61 END**");
       return inDataCnt;
    }

	/* BDO CLG: Fleet card support - start -- jzg */
	if(((srTransPara->byTransType == SALE) ||
		(srTransPara->byTransType == VOID)) && /* BDOCLG-00324: Added DE61 & 63 to Fleet void txn -- jzg */
		(srTransPara->fFleetCard == TRUE) && 
		(strTCT.fFleetGetLiters == TRUE) && /* BDOCLG-00347: should be controlled also be parameterized -- jzg */
		(strTCT.fGetDescriptorCode == TRUE))
	{
		vdDebug_LogPrintf("**Fleet DE61 START**");
		uszSendData[inDataCnt++] = 0x00;
		uszSendData[inDataCnt++] = 0x06;

		sprintf(&uszSendData[inDataCnt], "%s    ", srTransPara->szFleetProductCode);
		inDataCnt += 6;	
		vdDebug_LogPrintf("**Fleet DE61 END**");
	}
	else
	/* BDO CLG: Fleet card support - end -- jzg */

#if 0
	{
		uszSendData[inDataCnt++] = 0x00;
		uszSendData[inDataCnt++] = 0x06;
		sprintf((char *)&uszSendData[inDataCnt], "%06ld", wub_bcd_2_long(srTransPara->szInvoiceNo,3));
		inDataCnt += 6;
	}
#endif

	if(srTransPara->byTransType == KIT_SALE) 
	{
		memset(szTemplate,0x00,sizeof(szTemplate));
		memset(szTmpHex,0x00,sizeof(szTmpHex));
		
//FILE ID PERSONAL INFO START
		
		memcpy(&szPacket[inPacketCnt],"02",2);//FILE ID 02
		inPacketCnt+=2;
		memcpy(&szPacket[inPacketCnt],"|",1);// Delimiter
		inPacketCnt+=1;
		//card number
		memcpy(&szPacket[inPacketCnt],strPersonal_Info.bCardNo,16);
		inPacketCnt+=16;
		memset(szTemplate,0x00,sizeof(szTemplate));
		//card name
		memcpy(&szPacket[inPacketCnt],szTemplate,26);//BLANK Cardholder NAME
		inPacketCnt+=26;
		memcpy(&szPacket[inPacketCnt],szTemplate,10);//BLANK Expiry
		inPacketCnt+=10;
		memcpy(&szPacket[inPacketCnt],szTemplate,2);//Blank Sequence Number
		inPacketCnt+=2;
		//memcpy(&szPacket[inPacketCnt],"BP",2);//BP - BLOCKED/PROCESSING
		memcpy(&szPacket[inPacketCnt],strPersonal_Info.bCardStatus,2);
		inPacketCnt+=2;
		memcpy(&szPacket[inPacketCnt],szTemplate,10);//Blank Card Personalization Date
		inPacketCnt+=10;
		memcpy(&szPacket[inPacketCnt],szTemplate,10);//Blank Last Card Chip Data Synch Date 
		inPacketCnt+=10;				
//FILE ID PERSONAL INFO END


		memcpy(&szPacket[inPacketCnt],"~",1);// Another FILE ID indicator
		inPacketCnt+=1;

		
//FILE ID MEMBERSHIP INFO START
		memcpy(&szPacket[inPacketCnt],"03",2);//FILE ID 03
		inPacketCnt+=2;
		memcpy(&szPacket[inPacketCnt],"|",1);// Delimiter
		inPacketCnt+=1;
		memcpy(&szPacket[inPacketCnt],szTemplate,31);//BLANK Membership Info
		inPacketCnt+=31;
//FILE ID MEMBERSHIP INFO END
		
		vdDebug_LogPrintf("fiedl61 %s", szPacket);

		/* Packet Data Length */
		memset(szAscBuf, 0, sizeof(szAscBuf));
		sprintf(szAscBuf, "%04d", inPacketCnt);
		memset(szBcdBuf, 0, sizeof(szBcdBuf));
		wub_str_2_hex(szAscBuf, szBcdBuf, 4);
		memcpy((char *)&uszSendData[inDataCnt], &szBcdBuf[0], 2);
		inDataCnt += 2;
		/* Packet Data */
		memcpy((char *)&uszSendData[inDataCnt], &szPacket[0], inPacketCnt);
		inDataCnt += inPacketCnt;
	}

	if(srTransPara->byTransType == RENEWAL || srTransPara->byTransType == PTS_AWARDING || inCheckSMACPayRedemption(srTransPara) == TRUE
		|| inCheckSMACPayBalanceInq(srTransPara) == TRUE || inCheckSMACPayVoid(srTransPara) == TRUE) 
	{
		memset(szTemplate,0x00,sizeof(szTemplate));
		memset(szTmpHex,0x00,sizeof(szTmpHex));
		
//FILE ID PERSONAL INFO START
		
		memcpy(&szPacket[inPacketCnt],"02",2);//FILE ID 02
		inPacketCnt+=2;
		memcpy(&szPacket[inPacketCnt],"|",1);// Delimiter
		inPacketCnt+=1;
		//Card number
		memcpy(&szPacket[inPacketCnt],strPersonal_Info.bCardNo,16);
		inPacketCnt+=16;
		memset(szTemplate,0x00,sizeof(szTemplate));
		//Card name
		memcpy(&szPacket[inPacketCnt],strPersonal_Info.bCardHolderName,26);
		inPacketCnt+=26;
		//Expiry
		memcpy(&szPacket[inPacketCnt],strPersonal_Info.bExpiryDate,10);
		inPacketCnt+=10;
		//Card Sequence Number
		memcpy(&szPacket[inPacketCnt],strPersonal_Info.bCardSeqNo,2);
		inPacketCnt+=2;
		
		//Card Status
		memcpy(&szPacket[inPacketCnt],strPersonal_Info.bCardStatus,2);
		inPacketCnt+=2;

		//Card Personalization Date
		memcpy(&szPacket[inPacketCnt],strPersonal_Info.bCardPerDate,10);
		inPacketCnt+=10;

		//memcpy(&szPacket[inPacketCnt],szTemplate,10);//Blank Last Card Chip Data Synch Date
		
		//Last Card Chip Data Synch Date 
		memcpy(&szPacket[inPacketCnt],strPersonal_Info.bLastDataSync,10);
		inPacketCnt+=10;
		
//FILE ID PERSONAL INFO END

		/* Packet Data Length */
		memset(szAscBuf, 0, sizeof(szAscBuf));
		sprintf(szAscBuf, "%04d", inPacketCnt);
		memset(szBcdBuf, 0, sizeof(szBcdBuf));
		wub_str_2_hex(szAscBuf, szBcdBuf, 4);
		memcpy((char *)&uszSendData[inDataCnt], &szBcdBuf[0], 2);
		inDataCnt += 2;
		/* Packet Data */
		memcpy((char *)&uszSendData[inDataCnt], &szPacket[0], inPacketCnt);
		inDataCnt += inPacketCnt;

	}
	
	vdMyEZLib_LogPrintf("  PACK_LEN%d",inDataCnt);
	vdMyEZLib_LogPrintf("**inPackIsoFunc61 END**");
	return inDataCnt;
}

int inPackIsoFunc62(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
	  char szPacket[7];

      DebugAddHEX("inPackIsoFunc62", srTransPara->szInvoiceNo, 3);

    inDataCnt = 0;
    uszSendData[inDataCnt++] = 0x00;
    uszSendData[inDataCnt++] = 0x06;
    if(srTransPara->byTransType == SETTLE || srTransPara->byTransType == CLS_BATCH)
    {
    	memcpy((char *)&uszSendData[inDataCnt],"000000",6);
    }
    else
   	{   		
   		sprintf((char *)&uszSendData[inDataCnt], "%06ld", wub_bcd_2_long(srTransPara->szInvoiceNo,3));   		
   	}
    inDataCnt += 6;
    
    vdMyEZLib_LogPrintf("  PACK_LEN%d",inDataCnt);
    vdMyEZLib_LogPrintf("**inPackIsoFunc62 END**");
    return inDataCnt;
}


int inPackIsoFunc63(TRANS_DATA_TABLE *srTransPara, unsigned char *uszSendData)
{
     
	int inPacketCnt = 0;
    int inResult;
    int inTranCardType;
    ACCUM_REC srAccumRec;
	char szAscBuf[4 + 1], szBcdBuf[2 + 1];
	char szTemplate[100], szPacket[200 + 1];
    

	BYTE szTmpBuf[20] = {0},
		szTmpHex[3] = {0};
	int inSize = 0;
	char szTemp[7+1];

	vdDebug_LogPrintf("***inPackIsoFunc63 START***");
	
	memset(szPacket, 0, sizeof(szPacket));
	inDataCnt = 0;

  if (srTransPara->byPackType == DCC_LOGGING || srTransPara->byPackType == DCC_LOGGING_RETRY) 
  {
     strcpy(szPacket,"73000d4000");
     strcat(szPacket,"4000");
     strcat(szPacket,"200000001");
     
     inPacketCnt += 23;
     
     /* Packet Data Length */
     memset(szAscBuf, 0, sizeof(szAscBuf));
     sprintf(szAscBuf, "%04d", inPacketCnt);
     memset(szBcdBuf, 0, sizeof(szBcdBuf));
     wub_str_2_hex(szAscBuf, szBcdBuf, 4);
     memcpy((char *)&uszSendData[inDataCnt], &szBcdBuf[0], 2);
     inDataCnt += 2;
     
     
     
     /* Packet Data */
     memcpy((char *)&uszSendData[inDataCnt], &szPacket[0], inPacketCnt);
     inDataCnt += inPacketCnt;
     
     vdDebug_LogPrintf("AAA - Pack Len(%d)",inDataCnt);
     vdDebug_LogPrintf("**inPackIsoFunc63 END**");
     return inDataCnt;
  
  }

    vdDebug_LogPrintf("Test1111");
    memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
    if((inResult = inCTOS_ReadAccumTotal(&srAccumRec)) == ST_ERROR)
	{
		vdDebug_LogPrintf("[vdUpdateAmountTotal]---Read Total Rec. error");
		return ST_ERROR;	
	}		
    vdDebug_LogPrintf("Test2222");
    //0 is for Credit type, 1 is for debit type
    if(srTransRec.HDTid == SMGUARANTOR_HDT_INDEX || srTransRec.HDTid == SMGIFTCARD_HDT_INDEX)
		inTranCardType = 1;
	else
    	inTranCardType = 0;
    vdDebug_LogPrintf("**inPackIsoFunc63 START**byTransType[%d]Sale[%d]Refund[%d]", srTransPara->byTransType,srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount);


//issue: 
	//if (srTransPara->byTransType == SALE_OFFLINE&&(srTransPara->HDTid == SMAC_HDT_INDEX || srTransPara->HDTid == SMGUARANTOR_HDT_INDEX))
    if (srTransPara->byTransType == SALE_OFFLINE&& inCheckIfSMCardTransPara(srTransPara) == TRUE){
		

		memset(szTemp, 0x00, sizeof(szTemp));
		memset(szPacket, 0x00, sizeof(szPacket));
		//strcpy(szTemp,srTransPara->SmacPoints);
		wub_hex_2_str(srTransPara->SmacPoints, szTemp, AMT_BCD_SIZE);
		vdCTOS_Pad_String(szTemp, 6, '0', POSITION_RIGHT);	
		sprintf(szPacket, "%d%s",srTransPara->inSmacTender,szTemp); 

		inDataCnt =9;	
		
		uszSendData[0]=0X00;
		uszSendData[1]=0X07;
	    	

		memcpy((char *)&uszSendData[2], szPacket, inDataCnt);

		return inDataCnt;


    }
	
    if(srTransPara->byTransType == SETTLE || srTransPara->byTransType == CLS_BATCH)
    {
        if((srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount) == 0 && (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount) == 0
			&& (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount) == 0)
        {
            strcpy(szPacket, "000000000000000");
            strcat(szPacket, "000000000000000");
            //strcat(szPacket, "000");
            inPacketCnt += 30;
			
        }else
        {
            /* SALE */
            memset(szTemplate, 0x00, sizeof(szTemplate));
            sprintf(szTemplate, "%03d", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount + (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount - srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount));
            strcpy(szPacket, szTemplate);
            inPacketCnt += 3;
						
			//format amount 10+2
//            sprintf(szTemplate, "%012.0f", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount);
			//sprintf(szTemplate, "%012.0f", (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount));
			sprintf(szTemplate, "%012.0f", (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount));
            strcat(szPacket, szTemplate);
          inPacketCnt += 12;
            /* REFUND */
            memset(szTemplate, 0x00, sizeof(szTemplate));
            sprintf(szTemplate, "%03d", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount);
            strcat(szPacket, szTemplate);
            inPacketCnt += 3;
			//format amount 10+2
			sprintf(szTemplate, "%012.0f", (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount));
            strcat(szPacket, szTemplate);
            inPacketCnt += 12;
            /*
            memset(szTemplate, 0x00, sizeof(szTemplate));
            sprintf(szTemplate, "%03d", srAccumRec.stBankTotal[inTranCardType].usEMVTCCount);
            strcat(&szPacket[inPacketCnt], szTemplate);
            inPacketCnt += 3;
               */
        }
    }


	//gcitra

		/*sidumili: Issue#: 000269*/
		if((srTransPara->byTransType != SETTLE) && (srTransPara->byTransType != CLS_BATCH) && (strlen(srTransPara->szPolicyNumber) > 0)){
			
			/* Issue# 000165 - start -- jzg */
			//sprintf(szPacket, "%d%s", 12, srTransRec.szPolicyNumber);
			//inPacketCnt =strlen(srTransRec.szPolicyNumber) + 4;

			//sidumili: modified to get the policy number on trandata
			sprintf(szPacket, "%d%s", 12, srTransPara->szPolicyNumber); 
			inPacketCnt =strlen(srTransPara->szPolicyNumber) + 4;				
			
			/* Issue# 000165 - end -- jzg */
			
			memset(szAscBuf, 0, sizeof(szAscBuf));
			sprintf(szAscBuf, "%04d", inPacketCnt);
			memset(szBcdBuf, 0, sizeof(szBcdBuf));
			wub_str_2_hex(szAscBuf, szBcdBuf, 4);
			memcpy((char *)&uszSendData[inDataCnt], &szBcdBuf[0], 2);
	
			inDataCnt += 2;
			inPacketCnt-=2;
	
		}

	//POS auto report: build DE63 - start -- jzg
	if (srTransPara->byTransType == POS_AUTO_REPORT)
	{
		vdDebug_LogPrintf("**POS auto report  START**");

		memset(uszSendData, 0, sizeof(uszSendData));
		uszSendData[0] = 0x00;
		uszSendData[1] = 0x26;
		uszSendData[2] = 0x00;
		uszSendData[3] = 0x24;
		memcpy(&uszSendData[4], "AM", 2);
		memcpy(&uszSendData[6], strPAR.szPARVersion, 10);
		memcpy(&uszSendData[16], "\x30\x30", 2);
		memcpy(&uszSendData[18], strPAR.szPARSerialNumber, 10);
		inDataCnt = 28;

		DebugAddHEX("PAR DE63", uszSendData , inDataCnt);
		vdDebug_LogPrintf(". Pack Len(%d)", inDataCnt);
		vdDebug_LogPrintf("**POS auto report END**");

		return inDataCnt;
	}	  
	//POS auto report: build DE63 - end -- jzg

	//gcitra


	/* BDO CLG: Fleet card support - start -- jzg */
	if(((srTransPara->byTransType == SALE) ||
		(srTransPara->byTransType == VOID)) && /* BDOCLG-00324: Added DE61 & 63 to Fleet void txn -- jzg */
		(srTransPara->fFleetCard == TRUE) &&
		(strTCT.fFleetGetLiters == TRUE)) /* BDOCLG-00347: should be controlled also be parameterized -- jzg */
	{
		vdDebug_LogPrintf("**Fleet DE63 START**");

		sprintf(szTmpBuf, "%d", srTransPara->inFleetNumofLiters);
		inSize = strlen(szTmpBuf);

		memset(uszSendData, 0, sizeof(uszSendData));
		strcpy(uszSendData, "000012");

		memset(szTmpBuf, 0, sizeof(szTmpBuf));
		sprintf(szTmpBuf, "%d", srTransPara->inFleetNumofLiters);
		sprintf(&uszSendData[6], "%s", szTmpBuf);
		inDataCnt = inSize + 6;

		//len 1
		memset(szTmpBuf, 0, sizeof(szTmpBuf));
		memset(szTmpHex, 0, sizeof(szTmpHex));
		sprintf(szTmpBuf, "%04d", inDataCnt - 2);
		wub_str_2_hex(szTmpBuf, szTmpHex, 4);
		uszSendData[0] = szTmpHex[0];
		uszSendData[1] = szTmpHex[1];

		//len 2
		memset(szTmpBuf, 0, sizeof(szTmpBuf));
		memset(szTmpHex, 0, sizeof(szTmpHex));
		sprintf(szTmpBuf, "%04d", inDataCnt - 4);
		wub_str_2_hex(szTmpBuf, szTmpHex, 4);		
		uszSendData[2] = szTmpHex[0];
		uszSendData[3] = szTmpHex[1];


		DebugAddHEX("Fleet DE63", uszSendData , inDataCnt);
		vdDebug_LogPrintf(". Pack Len(%d)", inDataCnt);
		vdDebug_LogPrintf("**Fleet DE63 END**");

		return inDataCnt;
	}
	/* BDO CLG: Fleet card support - end -- jzg */

#if 0
	if(srTransPara->byTransType == KIT_SALE) 
	{
		memset(szTemplate,0x00,sizeof(szTemplate));
		memset(szTmpHex,0x00,sizeof(szTmpHex));
		
//FILE ID PERSONAL INFO START
		
		memcpy(&szPacket[inPacketCnt],"02",2);//FILE ID 02
		inPacketCnt+=2;
		memcpy(&szPacket[inPacketCnt],"|",1);// Delimiter
		inPacketCnt+=1;
		//card number
		memcpy(&szPacket[inPacketCnt],strPersonal_Info.bCardNo,16);
		inPacketCnt+=16;
		memset(szTemplate,0x00,sizeof(szTemplate));
		//card name
		memcpy(&szPacket[inPacketCnt],szTemplate,26);//BLANK Cardholder NAME
		inPacketCnt+=26;
		memcpy(&szPacket[inPacketCnt],szTemplate,10);//BLANK Expiry
		inPacketCnt+=10;
		memcpy(&szPacket[inPacketCnt],szTemplate,2);//Blank Sequence Number
		inPacketCnt+=2;
		memcpy(&szPacket[inPacketCnt],"BP",2);//BP - BLOCKED/PROCESSING
		inPacketCnt+=2;
		memcpy(&szPacket[inPacketCnt],szTemplate,10);//Blank Card Personalization Date
		inPacketCnt+=10;
		memcpy(&szPacket[inPacketCnt],szTemplate,10);//Blank Last Card Chip Data Synch Date 
		inPacketCnt+=10;				
//FILE ID PERSONAL INFO END


		memcpy(&szPacket[inPacketCnt],"~",1);// Another FILE ID indicator
		inPacketCnt+=1;

		
//FILE ID MEMBERSHIP INFO START
		memcpy(&szPacket[inPacketCnt],"03",2);//FILE ID 03
		inPacketCnt+=2;
		memcpy(&szPacket[inPacketCnt],"|",1);// Delimiter
		inPacketCnt+=1;
		memcpy(&szPacket[inPacketCnt],szTemplate,31);//BLANK Membership Info
		inPacketCnt+=31;
//FILE ID MEMBERSHIP INFO END
		
		vdDebug_LogPrintf("fiedl63 %s", szPacket);
	}

	if(srTransPara->byTransType == RENEWAL || srTransPara->byTransType == PTS_AWARDING || inCheckSMACPayRedemption(srTransPara) == TRUE
		|| inCheckSMACPayBalanceInq(srTransPara) == TRUE || inCheckSMACPayVoid(srTransPara) == TRUE) 
	{
		memset(szTemplate,0x00,sizeof(szTemplate));
		memset(szTmpHex,0x00,sizeof(szTmpHex));
		
//FILE ID PERSONAL INFO START
		
		memcpy(&szPacket[inPacketCnt],"02",2);//FILE ID 02
		inPacketCnt+=2;
		memcpy(&szPacket[inPacketCnt],"|",1);// Delimiter
		inPacketCnt+=1;
		//Card number
		memcpy(&szPacket[inPacketCnt],strPersonal_Info.bCardNo,16);
		inPacketCnt+=16;
		memset(szTemplate,0x00,sizeof(szTemplate));
		//Card name
		memcpy(&szPacket[inPacketCnt],strPersonal_Info.bCardHolderName,26);
		inPacketCnt+=26;
		//Expiry
		memcpy(&szPacket[inPacketCnt],strPersonal_Info.bExpiryDate,10);
		inPacketCnt+=10;
		//Card Sequence Number
		memcpy(&szPacket[inPacketCnt],strPersonal_Info.bCardSeqNo,2);
		inPacketCnt+=2;
		
		//Card Status
		//memcpy(&szPacket[inPacketCnt],"AA",2);//AA - ACTIVE/ACTIVE
		memcpy(&szPacket[inPacketCnt],strPersonal_Info.bCardStatus,2);
		inPacketCnt+=2;

		//Card Personalization Date
		//memcpy(&szPacket[inPacketCnt],szTemplate,10);//Blank Card Personalization Date
		//memset(szTmpBuf,0x00,sizeof(szTmpBuf));
		//vdGetFormatSMACPayDate(szTmpBuf);
		memcpy(&szPacket[inPacketCnt],strPersonal_Info.bCardPerDate,10);
		inPacketCnt+=10;

		//memcpy(&szPacket[inPacketCnt],szTemplate,10);//Blank Last Card Chip Data Synch Date
		
		//Last Card Chip Data Synch Date 
		memcpy(&szPacket[inPacketCnt],strPersonal_Info.bLastDataSync,10);
		inPacketCnt+=10;
		
//FILE ID PERSONAL INFO END

		vdDebug_LogPrintf("fiedl63 %s", szPacket);
	}
#endif
	
	
	/* Packet Data Length */
    memset(szAscBuf, 0, sizeof(szAscBuf));
    sprintf(szAscBuf, "%04d", inPacketCnt);
    memset(szBcdBuf, 0, sizeof(szBcdBuf));
    wub_str_2_hex(szAscBuf, szBcdBuf, 4);
    memcpy((char *)&uszSendData[inDataCnt], &szBcdBuf[0], 2);
    inDataCnt += 2;
    /* Packet Data */
    memcpy((char *)&uszSendData[inDataCnt], &szPacket[0], inPacketCnt);
    inDataCnt += inPacketCnt;
	
    vdDebug_LogPrintf(". Pack Len(%d)",inDataCnt);
    vdDebug_LogPrintf("**inPackIsoFunc63 END**");
    return inDataCnt;
	
}

int inPackIsoFunc64(TRANS_DATA_TABLE *srTransPara, unsigned char* uszSendData)
{
    BYTE           szSHABinTemp[20];
    BYTE           szSHAAscTemp[50];
    BYTE           szTempMacResutl[16];
    SHA_CTX        stSHA;
    BYTE           szInitVictor[8];
    BYTE szClearTMK[33], szClearTAK[33], temp[17], ClearTMK[17];   
           
    inTLERead(1);
     
    vdMyEZLib_LogPrintf("**inPackIsoFunc64 START**");
    
    GET_KEY( szClearTMK , szClearTAK);

   
    vdMyEZLib_LogPrintf("**MAC DATA**");
    vdMyEZLib_LogPrintff(szDataForMAC,inMacMsgLen);
    
    CTOS_SHA1Init(&stSHA);   //Perform the SHA1 algorithm with the input data //                                                     
    CTOS_SHA1Update(&stSHA, szDataForMAC, inMacMsgLen);     //Finalize the SHA1 operation and retrun the result //                                                   
    CTOS_SHA1Final(szSHABinTemp,&stSHA);     //vdSHA1Generate(szDataForMAC, inMacMsgLen, szSHABinTemp); //wrong code          
    vdMyEZLib_LogPrintff(szSHABinTemp,20);   vdMyEZLib_LogPrintf("**SHA Generate**");    
    wub_hex_2_str(szSHABinTemp, szSHAAscTemp, 20);    
    memset(szInitVictor, 0x00, sizeof(szInitVictor));
    memset(szTempMacResutl, 0x00, sizeof(szTempMacResutl));
    
    if( srTransRec.byTransType == SIGN_ON)
    {
    	vdMyEZLib_LogPrintf("**SIGN ON CLEAR TAK**");
    	CTOS_MAC (szClearTAK, 16, szInitVictor, szSHAAscTemp, 40, szTempMacResutl);
    }    
    else 
    {
    	   //hard code key
	    memset( temp, 0x00, 17);	   
			vdMyEZLib_LogPrintf("**MAC KEY");	
		 	memcpy(szClearTAK,stTLE.szMACKey,16);	
    	CTOS_MAC (szClearTAK, 16, szInitVictor, szSHAAscTemp, 40, szTempMacResutl);
    }
    inDataCnt = 0;
    
    memcpy((char *)&uszSendData[inDataCnt], szTempMacResutl, 8);
    inDataCnt += 8;
    
    vdMyEZLib_LogPrintf("**inPackIsoFunc64 END**");
    return inDataCnt;
}


//#00153 - Incorrect data element in Smac QR Void #1
int inUnPackIsoFunc02(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{
    //int inLen = 0;
    int inRealLen = 0;
    char szLen[4+1];
    
    BYTE szAIIC[20+1];
    
    vdDebug_LogPrintf("=====inUnPackIsoFunc02=====srTransRec.HDTid [%d]", srTransRec.HDTid);
    
    inDataCnt = 0;
    
    DebugAddHEX("uszUnPackBuf", uszUnPackBuf, 20);
    
    memset(szLen, 0x00, sizeof(szLen));
    wub_hex_2_str(&uszUnPackBuf[0], szLen, 2);
    szLen[2] = 0x00;
    srTransPara->byPanLen = atoi(szLen);
	wub_hex_2_str(&uszUnPackBuf[1], srTransPara->szPAN, (srTransPara->byPanLen+1)/2);

	srTransPara->szPAN[srTransPara->byPanLen]=0x00;
    vdDebug_LogPrintf("srTransPara->szPAN:%s", srTransPara->szPAN);
	
    /*memcpy(szAIIC, (char *) uszUnPackBuf, DATE_BCD_SIZE);
    if (inCheckReversalTrans(srTransPara->byPackType) != d_OK)
        inPrintISOfield("Field02", uszUnPackBuf, DATE_BCD_SIZE, 1);
	*/

    return ST_SUCCESS;
}
int inUnPackIsoFunc11(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{
	unsigned char szSTAN[6 + 1];
    
    memset(szSTAN, 0x00, sizeof(szSTAN));

	wub_hex_2_str(uszUnPackBuf, szSTAN, 3);
	
    srTransPara->ulTraceNum = atol(szSTAN);
	
	vdDebug_LogPrintf("inUnPackIsoFunc11(%s) [%d]", szSTAN,srTransPara->ulTraceNum);
    return ST_SUCCESS;
}

int inUnPackIsoFunc12(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{
	if(srTransPara->byTransType != SALE_TIP)//Do not update Date and Time if Tip Adjust is uploaded to host
	    memcpy(srTransPara->szTime,(char *)uszUnPackBuf,TIME_BCD_SIZE);

	srTransPara->fSetTime=TRUE;
	
    return ST_SUCCESS;
}

int inUnPackIsoFunc13(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{
	if(srTransPara->byTransType != SALE_TIP)//Do not update Date and Time if Tip Adjust is uploaded to host
	    memcpy(srTransPara->szDate,(char *)uszUnPackBuf,DATE_BCD_SIZE);

    srTransPara->fSetDate=TRUE;
	
	return ST_SUCCESS;
}

int inUnPackIsoFunc37(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{
#if 0
	if (srTransPara->byPackType == SEND_ADVICE && srTransPara->byTransType == SALE_TIP)
		memcpy(srTransPara->szOrgRRN, srTransPara->szRRN, 12);

	//vdDebug_LogPrintf("inUnPackIsoFunc37 srTransPara->byPackType:%d, srTransPara->byTransType: %d, srTransPara->byUploaded: %d", srTransPara->byPackType, srTransPara->byTransType, srTransPara->byUploaded);
	if(srTransPara->byPackType == SEND_ADVICE && srTransPara->byTransType == SALE_TIP && srTransPara->byUploaded == FALSE)
		memcpy(srTransPara->szOrgRRN, (char *)uszUnPackBuf, 12);
#endif	
	if (srTransPara->byPackType != REVERSAL && srTransPara->byPackType != SEND_ADVICE)
    	memcpy(srTransPara->szRRN, (char *)uszUnPackBuf, 12);

    return ST_SUCCESS;
}

int inUnPackIsoFunc38(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{
    //do not save auth codinUnPackIsoFunc38e for offline advice response
    vdDebug_LogPrintf("inUnPackIsoFunc38 srTransPara->byPackType: %d", srTransPara->byPackType);
    if(srTransPara->byPackType == REFUND_REVERSAL || srTransPara->byPackType == VOIDREFUND_REVERSAL || srTransPara->byPackType == VOID_REVERSAL
    || srTransPara->byPackType == PREAUTH_REVERSAL || srTransPara->byPackType == CASHADVANCE_REVERSAL || srTransPara->byPackType == QUASI_REVERSAL
    || srTransPara->byPackType == REVERSAL)
        return ST_SUCCESS;

	vdDebug_LogPrintf("2. inUnPackIsoFunc38 srTransPara->byPackType");
	
    if (srTransPara->byPackType != SEND_ADVICE)
        memcpy(srTransPara->szAuthCode, (char *)uszUnPackBuf, AUTH_CODE_DIGITS);

	
	vdDebug_LogPrintf("3. inUnPackIsoFunc38 srTransPara->byPackType");

    return ST_SUCCESS;
}

int inUnPackIsoFunc39(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{	
    memcpy(srTransPara->szRespCode, (char *)uszUnPackBuf, RESP_CODE_SIZE);
	vdDebug_LogPrintf("inUnPackIsoFunc39(%s)", srTransPara->szRespCode);
    return ST_SUCCESS;
}

int inUnPackIsoFunc41(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{	
    
    BYTE        szTempTID[TERMINAL_ID_BYTES+1];
#if 0	
    if ((inGetATPBinRouteFlag) && (fAMEXHostEnable == TRUE))
    {
        memset(szTempTID, 0x00, sizeof(szTempTID));
        memcpy(szTempTID, (char *)uszUnPackBuf, TERMINAL_ID_BYTES);
        if (strcmp (szTempTID,srTransPara->szTID) == 0)
        {
            return ST_SUCCESS;
        }
        else if (strcmp (szTempTID,szAmexTID) == 0)
        {
            inMyFile_ReversalDelete();
            if (fUSDSelected)
            {
                inMMTReadRecord(4,srTransRec.MITid);
                srTransRec.MITid = inAMEXMITNumber;
                strHDT.inHostIndex=srTransRec.HDTid=strCDT.HDTid=4;
            }
            else
            {
                inMMTReadRecord(2,srTransRec.MITid);
                srTransRec.MITid = inAMEXMITNumber;
                strHDT.inHostIndex=srTransRec.HDTid=strCDT.HDTid=2;
            }
        }
    }
#endif

    return ST_SUCCESS;
}

int inUnPackIsoFunc48(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf){

    int inLen, inTotalLen, inTagLen;
	unsigned short usTag;
	BYTE szTag[3+1];
	BYTE szTagLen[2+1];
	int inTaglen;
	BYTE szTagValue[100+1];

    inLen =((uszUnPackBuf[0] / 16 * 10) + uszUnPackBuf[0] % 16) *100;
    inLen += (uszUnPackBuf[1] / 16 * 10) + uszUnPackBuf[1] % 16;

	vdDebug_LogPrintf("testlang inUnPackIsoFunc48 - len %d", inLen);


    if (inLen > 0){
		for (inTotalLen = 2; inTotalLen < inLen;){

			//get tag 
			memset(szTag, 0x00, sizeof(szTag));
			memcpy(szTag, &uszUnPackBuf[inTotalLen],3);
			inTotalLen=inTotalLen+3;
			vdDebug_LogPrintf("tag name %s", szTag);

			//get length
			memset(szTagLen, 0x00, sizeof(szTagLen));
			memcpy(szTagLen, &uszUnPackBuf[inTotalLen],2);
			inTotalLen=inTotalLen+2;
			inTaglen = atoi(szTagLen);
			vdDebug_LogPrintf("tag len %s-%d", szTagLen, inTaglen);
			

            //get value
			memset(szTagValue, 0x00, sizeof(szTagValue));
			memcpy(szTagValue, &uszUnPackBuf[inTotalLen],inTaglen);
			inTotalLen=inTotalLen+inTaglen;
			vdDebug_LogPrintf("tag value %s", szTagValue);

            memset(srTransRec.szBarcodeText, 0x00, sizeof(srTransRec.szBarcodeText));
			if ((strcmp(szTag, "001") == 0) || (strcmp(szTag, "002") == 0) || (strcmp(szTag, "003") == 0)
				|| (strcmp(szTag, "004") == 0) || (strcmp(szTag, "005") == 0))
			{
			    sprintf(srTransRec.szBarcodeText,"%s%s%s",szTag,szTagLen,szTagValue ); 
				vdDebug_LogPrintf("barcode test1 %s", srTransRec.szBarcodeText);	
			}else if (strcmp(szTag, "010") == 0)
			{
			    memset(szSMACScanResponsetext, 0x00, sizeof(szSMACScanResponsetext));
				strcpy(szSMACScanResponsetext, szTagValue);
				vdDebug_LogPrintf("tag 010");
			}else if (strcmp(szTag, "100") == 0)
			{
			    memset(szECRSMACField02,0x00, sizeof(szECRSMACField02));
				strcpy(szECRSMACField02, szTagValue);
				vdDebug_LogPrintf("tag 100 %s", szECRSMACField02);
			}
				


		}

    }

 	return ST_SUCCESS;
}



int inUnPackIsoFunc55(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{
    int inLen, inTotalLen, inTagLen;
	unsigned short usTag;

    inLen =((uszUnPackBuf[0] / 16 * 10) + uszUnPackBuf[0] % 16) *100;
    inLen += (uszUnPackBuf[1] / 16 * 10) + uszUnPackBuf[1] % 16;

    
    vdDebug_LogPrintf("**inEDC_EMV_UnPackData55(%d) START** uszUnPackBuf[%02X %02X]", inLen, uszUnPackBuf[0], uszUnPackBuf[1]);
    DebugAddHEX("DE 55", uszUnPackBuf, inLen+2);

    if (inLen > 0)
    {
    	memset(srTransPara->stEMVinfo.T8A, 0x00, sizeof(srTransPara->stEMVinfo.T8A));
    	memcpy(srTransPara->stEMVinfo.T8A, srTransPara->szRespCode, strlen(srTransPara->szRespCode));

        for (inTotalLen = 2; inTotalLen < inLen;)
        {
            usTag = (unsigned short)uszUnPackBuf[inTotalLen] * 256;
    
    	    if ((uszUnPackBuf[inTotalLen ++] & 0x1F) == 0x1F)
                usTag += ((unsigned short)uszUnPackBuf[inTotalLen ++]);

            vdDebug_LogPrintf("usTag[%X]", usTag);
            switch (usTag)
            {
                case 0x9100 :
                    memset(srTransPara->stEMVinfo.T91, 0x00, sizeof(srTransPara->stEMVinfo.T91));
                    srTransPara->stEMVinfo.T91Len = (unsigned short)uszUnPackBuf[inTotalLen ++];
                    memcpy(srTransPara->stEMVinfo.T91, (char *)&uszUnPackBuf[inTotalLen], srTransPara->stEMVinfo.T91Len);
                    inTotalLen += srTransPara->stEMVinfo.T91Len;
                    vdDebug_LogPrintf(". 91Len(%d)",srTransPara->stEMVinfo.T91Len);
                    DebugAddHEX("Tag 91", srTransPara->stEMVinfo.T91, srTransPara->stEMVinfo.T91Len);
                    ushCTOS_EMV_NewTxnDataSet(TAG_91_ARPC, srTransPara->stEMVinfo.T91Len, srTransPara->stEMVinfo.T91);
                    break;
                case 0x7100 :
                    memset(srTransPara->stEMVinfo.T71, 0x00, sizeof(srTransPara->stEMVinfo.T71));
                    srTransPara->stEMVinfo.T71Len = (unsigned short)uszUnPackBuf[inTotalLen ++];
                    srTransPara->stEMVinfo.T71Len+=2;
                    memcpy(&srTransPara->stEMVinfo.T71[0], (char *)&uszUnPackBuf[inTotalLen-2], srTransPara->stEMVinfo.T71Len);
                    inTotalLen += srTransPara->stEMVinfo.T71Len-2;
                    vdDebug_LogPrintf(". 71Len(%d)",srTransPara->stEMVinfo.T71Len);
                    DebugAddHEX("Tag 71", srTransPara->stEMVinfo.T71, srTransPara->stEMVinfo.T71Len);
                    ushCTOS_EMV_NewTxnDataSet(TAG_71, srTransPara->stEMVinfo.T71Len, srTransPara->stEMVinfo.T71);
                    break;
                case 0x7200 :
                    memset(srTransPara->stEMVinfo.T72, 0x00, sizeof(srTransPara->stEMVinfo.T72));
                    srTransPara->stEMVinfo.T72Len = (unsigned short)uszUnPackBuf[inTotalLen ++];
                    srTransPara->stEMVinfo.T72Len+=2;
                    memcpy(&srTransPara->stEMVinfo.T72[0], (char *)&uszUnPackBuf[inTotalLen-2], srTransPara->stEMVinfo.T72Len);
                    inTotalLen += srTransPara->stEMVinfo.T72Len-2;
                    vdDebug_LogPrintf(". 72Len(%d)",srTransPara->stEMVinfo.T72Len);
                    DebugAddHEX("Tag 72", srTransPara->stEMVinfo.T72, srTransPara->stEMVinfo.T72Len);
                    ushCTOS_EMV_NewTxnDataSet(TAG_72, srTransPara->stEMVinfo.T72Len, srTransPara->stEMVinfo.T72);
                    break;
                 default :
                    vdDebug_LogPrintf("**inEDC_EMV_UnPackData55(%X) Err**", usTag);
                    inTagLen = (unsigned short)uszUnPackBuf[inTotalLen ++];
                    inTotalLen += inTagLen;
                    vdDebug_LogPrintf("**inTagLen(%d) inTotalLen[%d] Err**", inTagLen, inTotalLen);
                    break;
    	    }
    	}    
    }
    else
    {
        inCTOS_inDisconnect();
        return (ST_ERROR);
    }

    return ST_SUCCESS;
}

int inUnPackIsoFunc57(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{
    int        inIndex = 0;
    BYTE       szTmp[32];
    int        inLen;
		BYTE szClearTMK[17] , szClearTAK[17];

    if(srTransPara->byTransType != SIGN_ON)
    {
        return ST_SUCCESS;
    }
    
    inLen = ((uszUnPackBuf[0] / 16 * 10) + uszUnPackBuf[0] % 16) * 100;
    inLen += (uszUnPackBuf[1] / 16 * 10) + uszUnPackBuf[1] % 16;
    vdMyEZLib_LogPrintf("**inEDC_EMV_UnPackData57(%d) START**", inLen);
    inIndex = 2;
    
    inIndex += 2;//skip version
    inIndex += 8;//skip tmk refercence
		
	inTLERead(1);
		
    if (inLen > 10)
    {
        memset(szTmp, 0x00, sizeof(szTmp));
        GET_KEY( szClearTMK , szClearTAK);        
        
        Decrypt3Des(&uszUnPackBuf[inIndex], szClearTMK, szTmp);
        memcpy(stTLE.szTermPinEncryuptKey, szTmp, 8);
        Decrypt3Des(&uszUnPackBuf[inIndex+8], szClearTMK, szTmp);
        memcpy(&stTLE.szTermPinEncryuptKey[8], szTmp, 8);
        inIndex = inIndex +16;//TPK
        
        memset(szTmp, 0x00, sizeof(szTmp));
                
        vdMyEZLib_LogPrintff(&uszUnPackBuf[inIndex],16);
                
        Decrypt3Des(&uszUnPackBuf[inIndex], szClearTMK, szTmp);
        memcpy(stTLE.szMACKey, szTmp, 8);
        Decrypt3Des(&uszUnPackBuf[inIndex+8], szClearTMK, szTmp); 
        memcpy(&stTLE.szMACKey[8], szTmp, 8);       
        inIndex = inIndex +16;//TPK
        
        vdMyEZLib_LogPrintf("szCLEar MAC**");
	
       
        vdMyEZLib_LogPrintff(&uszUnPackBuf[inIndex],16); 
        memset(szTmp, 0x00, sizeof(szTmp));
        Decrypt3Des(&uszUnPackBuf[inIndex], szClearTMK, szTmp);
        memcpy(stTLE.szLineEncryptKey, szTmp, 8);
        Decrypt3Des(&uszUnPackBuf[inIndex+8], szClearTMK, szTmp);  
        memcpy(&stTLE.szLineEncryptKey[8], szTmp, 8);
        inIndex = inIndex +16;//TPK
        
        vdMyEZLib_LogPrintf("szCLEar TPK**");
    }
    else
    {
        inCTOS_inDisconnect();
        return (ST_ERROR);
    }
    
    inTLESave(1);
    vdMyEZLib_LogPrintf("**inEDC_EMV_UnPackData57(%d) END**", inLen);
    return ST_SUCCESS;
}

int inUnPackIsoFunc63(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{
int inLen;

	vdDebug_LogPrintf("inUnPackIsoFunc63 :: srTransPara->byTransType [%d]",srTransPara->byTransType);
	memset(szField63, 0x00, sizeof(szField63));
	inLen =((uszUnPackBuf[0] / 16 * 10) + uszUnPackBuf[0] % 16) *100;
	inLen += (uszUnPackBuf[1] / 16 * 10) + uszUnPackBuf[1] % 16;

	if(inLen<=0)
	{
		return ST_SUCCESS; //return if DE63 is blank
	}
	
	//if (((srTransRec.HDTid == SMAC_HDT_INDEX) || (srTransRec.HDTid == SMGUARANTOR_HDT_INDEX)) && (srTransRec.byTransType != SMAC_BALANCE))
	if (memcmp(srTransPara->szRespCode, "86", 2) == 0 && strIIT.fSMErrorRC86 == TRUE)
	{
		memcpy(szField63, (char *)&uszUnPackBuf[2], inLen);
		//version16- change request - trim extra spaces
		vdDebug_LogPrintf("testlang trim spaces");
		DebugAddHEX("szField63 =",szField63,strlen(szField63));
		vdRemoveExtraSpaces(szField63);
		DebugAddHEX("szField63 =",szField63,strlen(szField63));
	}
	else
	{
		if ((inCheckIfSMCardTransRec() == TRUE) && (srTransRec.byTransType != SMAC_BALANCE))
		{
			if ((srTransRec.byTransType == SALE) || (srTransRec.byTransType == CLS_BATCH) || (srTransRec.byTransType == SETTLE) || 
				(srTransRec.byTransType == VOID) || (srTransRec.byTransType == SMAC_REDEEM) || (srTransRec.byTransType == BALANCE_INQUIRY))
			{
				if( (srTransRec.byTransType == SALE || srTransRec.byTransType == VOID) /*&& (srTransRec.HDTid == SMAC_HDT_INDEX)*/)
					memcpy(szField63, (char *)&uszUnPackBuf[0], inLen+2);
				else
					memcpy(szField63, (char *)&uszUnPackBuf[2], inLen);

				if(srTransPara->HDTid == SMAC_HDT_INDEX)
					inSMACBDORewardsAnalyzeField63();
				else
					inSMACAnalyzeField63();
				//srTransRec.fPrintSMCardHolder = TRUE;
				vdDebug_LogPrintf("inUnPackIsoFunc63 :: srTransRec.fPrintSMCardHolder [%d]",srTransRec.fPrintSMCardHolder);
			}

			if (srTransRec.byTransType == SMAC_ACTIVATION)
			{
				memcpy(szField63, (char *)&uszUnPackBuf[2], inLen);
			}
		}
		else
		  memcpy(szField63, (char *)&uszUnPackBuf[2], inLen);
	}

return ST_SUCCESS;
}

int inUnPackIsoFunc61(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{
    int inLen, inIndex=2;
    char szField61[999+1];
    char szTemp[16+1];
    char szTempBitmap[8+1];
    char szBitmap[8+1];

	if (srTransPara->byPackType == DCC_RATEREQUEST || srTransPara->byPackType == DCC_RATEREQUEST_RETRY)
	{
		if(strcmp((char *)srTransRec.szRespCode, "00") !=  0)//if failed response to Rate Request, do not parse DE61
			return ST_SUCCESS;

	    inLen =((uszUnPackBuf[0] / 16 * 10) + uszUnPackBuf[0] % 16) *100;
        inLen += (uszUnPackBuf[1] / 16 * 10) + uszUnPackBuf[1] % 16;
        
        memset(szField61, 0x00, sizeof(szField61));
        memcpy(szField61, uszUnPackBuf+inIndex, inLen);
        //inPrintISOPacket("szField61", szField61, strlen(szField61));	 
        
        inIndex=6;
        memset(szTempBitmap, 0, sizeof(szTempBitmap));
        memcpy(szTempBitmap, szField61+inIndex, 8);   
        inIndex+=8;
        
        vdCTOS_Pad_String(szTempBitmap, 16, 0x30,POSITION_RIGHT);
        //inPrintISOPacket("szTempBitmap", szTempBitmap, 16);
        
        wub_str_2_hex(szTempBitmap, szBitmap, 16);
		memset(&bitDCC, 0x00, sizeof(bitDCC));
        UnpackDCC(szBitmap, szField61+inIndex);
        
        if(bitDCC[6] != NULL)
        {
            //vdDebug_LogPrintf("*bitDCC[6]: (%s)",bitDCC[6]);
            sscanf(bitDCC[6], "%03s%012s%01d", srTransPara->szDCCCur, srTransPara->szDCCCurAmt, &srTransPara->inDCCCurMU);
            vdDebug_LogPrintf("*srTransPara->szDCCCur: (%s)",srTransPara->szDCCCur);
            vdDebug_LogPrintf("*srTransPara->szDCCCurAmt: (%s)",srTransPara->szDCCCurAmt);
            vdDebug_LogPrintf("*srTransPara->inDCCCurMU: (%d)",srTransPara->inDCCCurMU);
        }
        
        if(bitDCC[9] != NULL)
        {
            vdDebug_LogPrintf("*bitDCC[9]: (%s)",bitDCC[9]);
            sscanf(bitDCC[9], "%01d%09s", &srTransPara->inDCCFXRateMU, srTransPara->szDCCFXRate);
            vdDebug_LogPrintf("*srTransPara->inDCCFXRateMU: (%d)",srTransPara->inDCCFXRateMU);	
            vdDebug_LogPrintf("*srTransPara->szDCCFXRate: (%s)",srTransPara->szDCCFXRate);		
        }
        
        if(bitDCC[10] != NULL)
        {
            vdDebug_LogPrintf("*bitDCC[10] (%s)",bitDCC[10]);
            //strcpy(srTransPara->szDCCFXRateRefID, bitDCC[10]);
            memcpy(srTransPara->szDCCFXRateRefID, bitDCC[10],inDCCLen[10]);
            vdDebug_LogPrintf("*srTransPara->szDCCFXRate: (%s)",srTransPara->szDCCFXRateRefID);
        }
        
        if(bitDCC[15] != NULL)
        {
            vdDebug_LogPrintf("*bitDCC[15] (%s)",bitDCC[15]);
            //strcpy(srTransPara->szDCCCardType, bitDCC[15]);
            memcpy(srTransPara->szDCCCardType, bitDCC[15],inDCCLen[15]);
            vdDebug_LogPrintf("*srTransPara->szDCCCardType: (%s)",srTransPara->szDCCCardType);		
        }
        
        if(bitDCC[20] != NULL)
        {
            vdDebug_LogPrintf("*bitDCC[20] (%s)",bitDCC[20]);
            //strcpy(srTransPara->szDCCFXMID, bitDCC[20]);
			memcpy(srTransPara->szDCCFXMID, bitDCC[20],inDCCLen[20]);
            vdDebug_LogPrintf("*srTransPara->szDCCFXMID: (%s)",srTransPara->szDCCFXMID);
        }
        
        if(bitDCC[21] != NULL)
        {
            vdDebug_LogPrintf("*bitDCC[21] (%s)",bitDCC[21]);
            //strcpy(srTransPara->szDCCFXTID, bitDCC[21]);
			memcpy(srTransPara->szDCCFXTID, bitDCC[21],inDCCLen[21]);
            vdDebug_LogPrintf("*srTransPara->szDCCFXTID: (%s)",srTransPara->szDCCFXTID);
        }
        
        if(bitDCC[22] != NULL)
        {
            vdDebug_LogPrintf("*bitDCC[22] (%s)",bitDCC[22]);
            //strcpy(srTransPara->szDCCMerchPOS, bitDCC[22]);
            memcpy(srTransPara->szDCCMerchPOS, bitDCC[22],inDCCLen[22]);
            vdDebug_LogPrintf("*srTransPara->szDCCMerchPOS: (%s)",srTransPara->szDCCMerchPOS);		
        }
    
    	if(bitDCC[24] != NULL)
        {		
            vdDebug_LogPrintf("*bitDCC[24] (%s)",bitDCC[24]);
            strcpy(srTransPara->szDCCCurSymbol, bitDCC[24]);
			memcpy(srTransPara->szDCCCurSymbol, bitDCC[24],inDCCLen[24]);
            vdDebug_LogPrintf("*srTransPara->szDCCCurSymbol: (%s)",srTransPara->szDCCCurSymbol);				
        }
    	
        if(bitDCC[26] != NULL)
        {		
            vdDebug_LogPrintf("*bitDCC[26] (%s)",bitDCC[26]);
            //strcpy(srTransPara.szDCCMerchPOS, bitDCC[22]);
            sscanf(bitDCC[26], "%08s%01d", srTransPara->szDCCMarkupPer, &srTransPara->inDCCMarkupPerMU);
            vdDebug_LogPrintf("*srTransPara->szDCCMarkupPer: (%s)\nsrTransPara.inDCCMarkupPerMU: %d",srTransPara->szDCCMarkupPer, srTransPara->inDCCMarkupPerMU);				
        }
	}
	
    return ST_SUCCESS;
}



int inPackISOEMVData(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{
     
	int inPacketCnt = 0, inTagLen;
	unsigned short usLen, usRetVal;
	BYTE btTrack2[20];
	char szAscBuf[4 + 1], szBcdBuf[2 + 1];
	char szPacket[512 + 1];
    char szTmp[32+1];
	USHORT ushEMVtagLen = 0;
	BYTE   EMVtagVal[64];
	int inRet;

    
	DebugAddSTR("load f55, inPackISOEMVData","emv",2);	

    vdDebug_LogPrintf("**inPackISOEMVData START**  %d", srTransPara->stEMVinfo.T9C);

	vdMyEZLib_LogPrintf("");
	memset(szPacket, 0, sizeof(szPacket));
	inDataCnt = 0;

    {	

        szPacket[inPacketCnt ++] = 0x5F;
        szPacket[inPacketCnt ++] = 0x2A;
        szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T5F2A, 2);
        inPacketCnt += 2;
        

        DebugAddINT("5F34 Len",srTransPara->stEMVinfo.T5F34_len );
        if(srTransPara->stEMVinfo.T5F34_len > 0)
        {
            if ((memcmp(srTransPara->stEMVinfo.T84,"\xA0\x00\x00\x00\x25",5) == 0) || (memcmp(srTransPara->stEMVinfo.T84,"\xa0\x00\x00\x00\x25",5) == 0))
            {
                szPacket[inPacketCnt ++] = 0x5F;
                szPacket[inPacketCnt ++] = 0x34;
                szPacket[inPacketCnt ++] = 1;
                szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T5F34;
                DebugAddSTR("EMV tag","5f34--finish--",2);
            }
        }
		
		szPacket[inPacketCnt ++] = 0x82;
        szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T82, 2);
        inPacketCnt += 2;

        szPacket[inPacketCnt ++] = 0x84;		
        szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T84_len;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T84, srTransPara->stEMVinfo.T84_len);
        inPacketCnt += srTransPara->stEMVinfo.T84_len;

        szPacket[inPacketCnt ++] = 0x95;
        szPacket[inPacketCnt ++] = 5;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T95, 5);
        inPacketCnt += 5;

        szPacket[inPacketCnt ++] = 0x9A;
        szPacket[inPacketCnt ++] = 3;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9A, 3);
        inPacketCnt += 3;

        szPacket[inPacketCnt ++] = 0x9C;
        szPacket[inPacketCnt ++] = 1;

#if 0
				/* BDO: Quasi should be parametrized per issuer - start -- jzg */
				if((strIIT.fQuasiCash)	&& 
					((srTransPara->byTransType == SALE) || (srTransPara->byTransType == SALE_OFFLINE)))
					szPacket[inPacketCnt ++] = 0x11;
				/* BDO: Quasi should be parametrized per issuer - end -- jzg */
				//Issue# 000143 - start -- jzg
				else if(srTransPara->byTransType == PRE_AUTH)
					szPacket[inPacketCnt ++] = 0x00;
				//Issue# 000143 - end -- jzg
				else
#endif

				szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9C;	// SL check again  //spec said 2 byte
				//Issue# 000141 - end -- jzg	

#if 0
        szPacket[inPacketCnt ++] = 0x5F;
        szPacket[inPacketCnt ++] = 0x2A;
        szPacket[inPacketCnt ++] = 2;
        //memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T5F2A, 2);//test
        memcpy(&szPacket[inPacketCnt], "\x06\x08", 2);//test
        inPacketCnt += 2;
#endif
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x02;
        szPacket[inPacketCnt ++] = 6;
		
        //memcpy(&szPacket[inPacketCnt], "\x00\x00\x00\x00\x00\x00", 6);
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F02, 6);
        inPacketCnt += 6;

        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x03;
        szPacket[inPacketCnt ++] = 6;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F03, 6);
        inPacketCnt += 6;

		if (memcmp(srTransPara->stEMVinfo.T84,"\xA0\x00\x00\x00\x65",5) != 0)// Remove 9F33 on JCB Chip data
		{
	        szPacket[inPacketCnt ++] = 0x9F;
	        szPacket[inPacketCnt ++] = 0x09;
	        szPacket[inPacketCnt ++] = 2;
	        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F09, 2);
	        inPacketCnt += 2;
		}

        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x10;
        szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F10_len;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F10, srTransPara->stEMVinfo.T9F10_len);
        inPacketCnt += srTransPara->stEMVinfo.T9F10_len;
      
	  	szPacket[inPacketCnt ++] = 0x9F;
	  	szPacket[inPacketCnt ++] = 0x1A;
	  	szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F1A, 2);
	  	inPacketCnt += 2;

        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x1E;
        szPacket[inPacketCnt ++] = 8;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F1E, 8);
        inPacketCnt += 8;

        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x26;
        szPacket[inPacketCnt ++] = 8;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F26, 8);
        inPacketCnt += 8;

        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x27;
        szPacket[inPacketCnt ++] = 1;
        szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F27;

		if (memcmp(srTransPara->stEMVinfo.T84,"\xA0\x00\x00\x00\x65",5) != 0)// Remove 9F33 on JCB Chip data
		{
	        szPacket[inPacketCnt ++] = 0x9F;
	        szPacket[inPacketCnt ++] = 0x33;
	        szPacket[inPacketCnt ++] = 3;
	        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F33, 3);
	        inPacketCnt += 3;
		}
        
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x34;
        szPacket[inPacketCnt ++] = 3;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F34, 3);
        inPacketCnt += 3;

        
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x35;
        szPacket[inPacketCnt ++] = 1;
        szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F35;

        
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x36;
        szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F36, 2);
        inPacketCnt += 2;

        
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x37;
        szPacket[inPacketCnt ++] = 4;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F37, 4);
        inPacketCnt += 4;


        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x41;
        szPacket[inPacketCnt ++] = 3;

        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F41, 3);// get chip transaction counter
        inPacketCnt += 3;        

		//gcitra
/*
        DebugAddINT("5F34 Len",srTransPara->stEMVinfo.T5F34_len );
        if(srTransPara->stEMVinfo.T5F34_len > 0)
        {
	        szPacket[inPacketCnt ++] = 0x5F;
	        szPacket[inPacketCnt ++] = 0x34;
	        szPacket[inPacketCnt ++] = 1;
	        szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T5F34;
			DebugAddSTR("EMV tag","5f34--finish--",2);
        }

  */      
    }
	
    /* Packet Data Length */
    memset(szAscBuf, 0, sizeof(szAscBuf));
    sprintf(szAscBuf, "%04d", inPacketCnt);
    memset(szBcdBuf, 0, sizeof(szBcdBuf));
    wub_str_2_hex(szAscBuf, szBcdBuf, 4);
    memcpy((char *)&uszUnPackBuf[inDataCnt], &szBcdBuf[0], 2);
    inDataCnt += 2;
    /* Packet Data */
    memcpy((char *)&uszUnPackBuf[inDataCnt], &szPacket[0], inPacketCnt);
    inDataCnt += inPacketCnt;
    
    vdMyEZLib_LogPrintf(". Pack Len(%d)",inDataCnt);
    vdMyEZLib_LogPrintf("**inPackISOEMVData END**");
    return (inDataCnt);
}


int inPackISOPayWaveData(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{
     
	int inPacketCnt = 0, inTagLen;
	unsigned short usLen, usRetVal;
	BYTE btTrack2[20];
	char szAscBuf[4 + 1], szBcdBuf[2 + 1];
	char szPacket[512 + 1];
    char szTmp[32+1];
	USHORT ushEMVtagLen = 0;
	BYTE   EMVtagVal[64];
	int inRet;
	
    
	DebugAddSTR("load f55, inPackISOPayWaveData","emv",2);	

	vdMyEZLib_LogPrintf("**inPackISOPayWaveData START**");
	memset(szPacket, 0, sizeof(szPacket));
	inDataCnt = 0;

    {	
	    szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x02;
        szPacket[inPacketCnt ++] = 6;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F02, 6);
        inPacketCnt += 6;

        
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x03;
        szPacket[inPacketCnt ++] = 6;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F03, 6);
        inPacketCnt += 6;

		szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x26;
        szPacket[inPacketCnt ++] = 8;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F26, 8);
        inPacketCnt += 8;
		
        szPacket[inPacketCnt ++] = 0x82;
        szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T82, 2);
        inPacketCnt += 2;
	
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x36;
        szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F36, 2);
        inPacketCnt += 2;
		
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x10;
        szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F10_len;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F10, srTransPara->stEMVinfo.T9F10_len);
        inPacketCnt += srTransPara->stEMVinfo.T9F10_len;
		
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x33;
        szPacket[inPacketCnt ++] = 3;
        //memcpy(&szPacket[inPacketCnt], "\xE0\xB0\xC8", 3);       
        //inPacketCnt += 3;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F33, 3);
        inPacketCnt += 3;


		
		
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x1A;
        szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F1A, 2);
        inPacketCnt += 2;

        szPacket[inPacketCnt ++] = 0x95;
        szPacket[inPacketCnt ++] = 5;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T95, 5);
        inPacketCnt += 5;

        szPacket[inPacketCnt ++] = 0x5F;
        szPacket[inPacketCnt ++] = 0x2A;
        szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T5F2A, 2);
        inPacketCnt += 2;

		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x27;
		szPacket[inPacketCnt ++] = 1;
		szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F27;
		
		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x34;
		szPacket[inPacketCnt ++] = 3;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F34, 3);		
		inPacketCnt += 3;
		
		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x35;
		szPacket[inPacketCnt ++] = 1;
		szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F35;

		szPacket[inPacketCnt ++] = 0x84;		
		szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T84_len;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T84, srTransPara->stEMVinfo.T84_len);
		inPacketCnt += srTransPara->stEMVinfo.T84_len;


        szPacket[inPacketCnt ++] = 0x9A;
        szPacket[inPacketCnt ++] = 3;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9A, 3);
        inPacketCnt += 3;

        szPacket[inPacketCnt ++] = 0x9C;
        szPacket[inPacketCnt ++] = 1;
				/* BDO: Quasi should be parametrized per issuer - start -- jzg */
				if((strIIT.fQuasiCash)	&& 
					((srTransPara->byTransType == SALE) || (srTransPara->byTransType == SALE_OFFLINE)))
					szPacket[inPacketCnt ++] = 0x11;
				/* BDO: Quasi should be parametrized per issuer - end -- jzg */
				else
					szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9C;	// SL check again  //spec said 2 byte
				//Issue# 000141 - end -- jzg	

        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x37;
        szPacket[inPacketCnt ++] = 4;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F37, 4);
        inPacketCnt += 4;

		
        /*szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x09;
        szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F09, 2);
        inPacketCnt += 2;*/ //Remove 9F09 on VISA CTLS transactions


        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x1E;
        szPacket[inPacketCnt ++] = 8;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F1E, 8);
        inPacketCnt += 8;
    }

	//visa form factor
	if (srTransPara->stEMVinfo.T9F6E_len > 0){
		szPacket[inPacketCnt ++] = 0x9F;		
		szPacket[inPacketCnt ++] = 0x6E;		
		szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F6E_len;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F6E, srTransPara->stEMVinfo.T9F6E_len);
		inPacketCnt += srTransPara->stEMVinfo.T9F6E_len;
	}
	//visa form factor

	
    /* Packet Data Length */
    memset(szAscBuf, 0, sizeof(szAscBuf));
    sprintf(szAscBuf, "%04d", inPacketCnt);
    memset(szBcdBuf, 0, sizeof(szBcdBuf));
    wub_str_2_hex(szAscBuf, szBcdBuf, 4);
    memcpy((char *)&uszUnPackBuf[inDataCnt], &szBcdBuf[0], 2);
    inDataCnt += 2;
    /* Packet Data */
    memcpy((char *)&uszUnPackBuf[inDataCnt], &szPacket[0], inPacketCnt);
    inDataCnt += inPacketCnt;
    
    vdMyEZLib_LogPrintf(". Pack Len(%d)",inDataCnt);
    vdMyEZLib_LogPrintf("**inPackISOPayWaveData END**");
    return (inDataCnt);
}


int inPackISOPayPassData(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{ 
	int inPacketCnt = 0, inTagLen;
	unsigned short usLen, usRetVal;
	BYTE btTrack2[20];
	char szAscBuf[4 + 1], szBcdBuf[2 + 1];
	char szPacket[512 + 1];
	char szTmp[32+1];
	USHORT ushEMVtagLen = 0;
	BYTE   EMVtagVal[64];
	int inRet;
	BYTE szAmt[20 + 1] = {0};
	BYTE szT9F34[3] = {0};
	int offset = 0;
	
	DebugAddSTR("load f55, inPackISOPayPassData","emv",2);	

	vdMyEZLib_LogPrintf("**inPackISOPayWaveData START**");
	memset(szPacket, 0, sizeof(szPacket));
	inDataCnt = 0;

	{
		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x26;
		szPacket[inPacketCnt ++] = 8;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F26, 8);
		inPacketCnt += 8;
	
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x27;
        szPacket[inPacketCnt ++] = 1;
        szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F27;
		
		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x10;
		szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F10_len;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F10, srTransPara->stEMVinfo.T9F10_len);
		inPacketCnt += srTransPara->stEMVinfo.T9F10_len;

        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x34;
        szPacket[inPacketCnt ++] = 3;

		vdDebug_LogPrintf("srTransPara->IITid=[%d]", srTransPara->IITid);
		if (srTransPara->IITid == 4) // Mastercard -- sidumili
		{			
			readWaveTable("MASTERCARD", "MASTERCARDid", 15); // PP CVM Required Limit(12 bytes)
			memset(szAmt, 0x00, sizeof(szAmt));
			wub_hex_2_str(srTransPara->szTotalAmount, szAmt, AMT_BCD_SIZE);
			vdDebug_LogPrintf("szAmt=[%s],strTableWave.szValue=[%s]", szAmt, strTableWave.szValue);
			DebugAddHEX("srTransPara->stEMVinfo.T9F34=",srTransPara->stEMVinfo.T9F34,3);
			if (atol(szAmt) < atol(strTableWave.szValue))
			{
				szPacket[inPacketCnt]= 0x1F;
				inPacketCnt += 1;
		        szPacket[inPacketCnt]= srTransPara->stEMVinfo.T9F34[1];
				inPacketCnt += 1;
		        szPacket[inPacketCnt]= srTransPara->stEMVinfo.T9F34[2];
				inPacketCnt += 1;			
			}
			else
			{
				memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F34, 3);
				inPacketCnt += 3;
			}
		}
		else
		{
			memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F34, 3);
			inPacketCnt += 3;
		}	
        //inPacketCnt += 3;

		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x35;
		szPacket[inPacketCnt ++] = 1;
		szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F35;
	
		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x37;
		szPacket[inPacketCnt ++] = 4;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F37, 4);
		inPacketCnt += 4;

        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x36;
        szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F36, 2);
        inPacketCnt += 2;

		szPacket[inPacketCnt ++] = 0x84;		
		szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T84_len;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T84, srTransPara->stEMVinfo.T84_len);
		inPacketCnt += srTransPara->stEMVinfo.T84_len;


		szPacket[inPacketCnt ++] = 0x95;
		szPacket[inPacketCnt ++] = 5;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T95, 5);
		inPacketCnt += 5;

		szPacket[inPacketCnt ++] = 0x9A;
		szPacket[inPacketCnt ++] = 3;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9A, 3);
		inPacketCnt += 3;

		szPacket[inPacketCnt ++] = 0x9C;
		szPacket[inPacketCnt ++] = 1;
		/* BDO: Quasi should be parametrized per issuer - start -- jzg */
		//if((strIIT.fQuasiCash)	&& 
		//	((srTransPara->byTransType == SALE) || (srTransPara->byTransType == SALE_OFFLINE)))
		//	szPacket[inPacketCnt ++] = 0x11;
		/* BDO: Quasi should be parametrized per issuer - end -- jzg */
		//else
			szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9C;	// SL check again  //spec said 2 byte
		//Issue# 000141 - end -- jzg	

        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x02;
        szPacket[inPacketCnt ++] = 6;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F02, 6);
        inPacketCnt += 6;

		szPacket[inPacketCnt ++] = 0x5F;
		szPacket[inPacketCnt ++] = 0x2A;
		szPacket[inPacketCnt ++] = 2;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T5F2A, 2);
		inPacketCnt += 2;

		szPacket[inPacketCnt ++] = 0x82;
		szPacket[inPacketCnt ++] = 2;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T82, 2);
		inPacketCnt += 2;
		
		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x1A;
		szPacket[inPacketCnt ++] = 2;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F1A, 2);
		inPacketCnt += 2;
		
		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x33;
		szPacket[inPacketCnt ++] = 3;
		//memcpy(&szPacket[inPacketCnt], "\xE0\xB0\xC8", 3);
		//inPacketCnt += 3;
		
        //memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F33, 3);
        //srTransPara->stEMVinfo.T9F33
        szPacket[inPacketCnt]= srTransPara->stEMVinfo.T9F33[0];
		inPacketCnt += 1;
        szPacket[inPacketCnt]= srTransPara->stEMVinfo.T9F33[1];
		inPacketCnt += 1;
        szPacket[inPacketCnt]= srTransPara->stEMVinfo.T9F33[2];
		inPacketCnt += 1;
		
		
		
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x03;
        szPacket[inPacketCnt ++] = 6;
        memcpy(&szPacket[inPacketCnt], "\x00\x00\x00\x00\x00\x00", 6);
        inPacketCnt += 6;

		
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x09;
        szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F09, 2);
        inPacketCnt += 2;


        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x1E;
        szPacket[inPacketCnt ++] = 8;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F1E, 8);
        inPacketCnt += 8;
		
	}
	
	/* Packet Data Length */
	memset(szAscBuf, 0, sizeof(szAscBuf));
	sprintf(szAscBuf, "%04d", inPacketCnt);
	memset(szBcdBuf, 0, sizeof(szBcdBuf));
	wub_str_2_hex(szAscBuf, szBcdBuf, 4);
	memcpy((char *)&uszUnPackBuf[inDataCnt], &szBcdBuf[0], 2);
	inDataCnt += 2;
	/* Packet Data */
	memcpy((char *)&uszUnPackBuf[inDataCnt], &szPacket[0], inPacketCnt);
	inDataCnt += inPacketCnt;
	
	vdMyEZLib_LogPrintf(". Pack Len(%d)",inDataCnt);
	vdMyEZLib_LogPrintf("**inPackISOPayWaveData END**");
	return (inDataCnt);
}



int inCTOS_PackDemoResonse(TRANS_DATA_TABLE *srTransPara,unsigned char *uszRecData)
{
    int inPackLen;
    BYTE szSTAN[6+1];
    BYTE szTID[TERMINAL_ID_BYTES+1];
    BYTE szMTI[MTI_BCD_SIZE+1];
    BYTE szBitMap[8+1];
    BYTE szCurrentTime[20];
    CTOS_RTC SetRTC;

    //default response turn on 3, 11, 12, 13, 24, 37, 38, 39, 41
    memset(szBitMap, 0x00, sizeof(szBitMap));
    memcpy(szBitMap, "\x20\x38\x01\x00\x0E\x80\x00\x00", 8);

    inPackLen = 0;
    
    memcpy(&uszRecData[inPackLen], "\x60\x00\x01\x00\x00",TPDU_BCD_SIZE);
    inPackLen += TPDU_BCD_SIZE;

    memcpy(szMTI, "\x02\x10", MTI_BCD_SIZE);
    szMTI[1] |= 0x10;
    memcpy(&uszRecData[inPackLen], szMTI, MTI_BCD_SIZE);
    inPackLen += MTI_BCD_SIZE;

    memcpy(&uszRecData[inPackLen], szBitMap, 8);
    inPackLen += 8;

    //DE 3
    memcpy(&uszRecData[inPackLen], "\x00\x00\x00", PRO_CODE_BCD_SIZE);
    inPackLen += PRO_CODE_BCD_SIZE;

    //DE 11
    sprintf(szSTAN, "%06ld", srTransPara->ulTraceNum);
    wub_str_2_hex(&szSTAN[0], (char *)&uszRecData[inPackLen], 6);
    inPackLen += 3;

    //DE 12
    CTOS_RTCGet(&SetRTC);
    memset(szCurrentTime, 0x00, sizeof(szCurrentTime));
    sprintf(szCurrentTime,"%02d%02d%02d",SetRTC.bHour,SetRTC.bMinute,SetRTC.bSecond);
    wub_str_2_hex(&szCurrentTime[0], (char *)&uszRecData[inPackLen], 6);
    inPackLen += 3;

    //DE 13
    memset(szCurrentTime, 0x00, sizeof(szCurrentTime));
    sprintf(szCurrentTime,"%02d%02d",SetRTC.bMonth,SetRTC.bDay);
    wub_str_2_hex(&szCurrentTime[0], (char *)&uszRecData[inPackLen], 4);
    inPackLen += 2;

    //DE 24
    memcpy((char *)&uszRecData[inPackLen], strHDT.szNII, 2);
    inPackLen += 2;

    //DE 37
    memcpy((char *)&uszRecData[inPackLen], "111111111111", 12);
    inPackLen += 12;

    //DE 38
    if(0 == strlen(srTransPara->szAuthCode))
        memcpy((char *)&uszRecData[inPackLen], "123456", 6);
    else
        memcpy((char *)&uszRecData[inPackLen], srTransPara->szAuthCode, 6);
    inPackLen += 6;

    //DE 39
    memcpy((char *)&uszRecData[inPackLen], "00", 2);
    inPackLen += 2;

    //DE 41
    memset(szTID, 0x00, sizeof(szTID));
    memset(szTID, 0x20, TERMINAL_ID_BYTES);
    memcpy(szTID, srTransPara->szTID, strlen(srTransPara->szTID));
    memcpy((char *)&uszRecData[inPackLen], szTID, TERMINAL_ID_BYTES);
    inPackLen += TERMINAL_ID_BYTES;
    
    return inPackLen;
}

void vdInitialISOFunction(ISO_FUNC_TABLE *srPackFunc)
{
	/* Choose ISO_FUNC_TABLE Array */
	memcpy((char *)srPackFunc, (char *)&srIsoFuncTable[0], sizeof(ISO_FUNC_TABLE));
}

int inPackISOExpressPayData(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{
	int inPacketCnt = 0, inTagLen;
	unsigned short usLen, usRetVal;
	BYTE btTrack2[20];
	char szAscBuf[4 + 1], szBcdBuf[2 + 1];
	char szPacket[512 + 1];
	char szTmp[32+1];
	USHORT ushEMVtagLen = 0;
	BYTE   EMVtagVal[64];
	int inRet;


	DebugAddSTR("load f55, inPackISOExpressPayData","emv",2);	

	vdMyEZLib_LogPrintf("**inPackISOExpressPayData START**");
	memset(szPacket, 0, sizeof(szPacket));
	inDataCnt = 0;

	{	
		vdDebug_LogPrintf("5F34 Len [%d]", srTransPara->stEMVinfo.T5F34_len);
		if(srTransPara->stEMVinfo.T5F34_len > 0)
		{
			szPacket[inPacketCnt ++] = 0x5F;
			szPacket[inPacketCnt ++] = 0x34;
			szPacket[inPacketCnt ++] = 1;
			szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T5F34;
			vdDebug_LogPrintf("srTransPara->stEMVinfo.T5F34 [%02X]", srTransPara->stEMVinfo.T5F34);
		}
		
		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x02;
		szPacket[inPacketCnt ++] = 6;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F02, 6);
		inPacketCnt += 6;


		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x03;
		szPacket[inPacketCnt ++] = 6;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F03, 6);
		inPacketCnt += 6;

		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x26;
		szPacket[inPacketCnt ++] = 8;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F26, 8);
		inPacketCnt += 8;

		szPacket[inPacketCnt ++] = 0x82;
		szPacket[inPacketCnt ++] = 2;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T82, 2);
		inPacketCnt += 2;

		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x36;
		szPacket[inPacketCnt ++] = 2;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F36, 2);
		inPacketCnt += 2;

		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x10;
		szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F10_len;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F10, srTransPara->stEMVinfo.T9F10_len);
		inPacketCnt += srTransPara->stEMVinfo.T9F10_len;

		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x33;
		szPacket[inPacketCnt ++] = 3;
		//memcpy(&szPacket[inPacketCnt], "\xE0\xB0\xC8", 3);
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F33, 3);
		inPacketCnt += 3;

		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x1A;
		szPacket[inPacketCnt ++] = 2;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F1A, 2);
		inPacketCnt += 2;

		szPacket[inPacketCnt ++] = 0x95;
		szPacket[inPacketCnt ++] = 5;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T95, 5);
		inPacketCnt += 5;

		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x27;
		szPacket[inPacketCnt ++] = 1;
		szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F27;
		
		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x34;
		szPacket[inPacketCnt ++] = 3;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F34, 3);
		inPacketCnt += 3;
		
		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x35;
		szPacket[inPacketCnt ++] = 1;
		szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F35;
				
		szPacket[inPacketCnt ++] = 0x84;		
		szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T84_len;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T84, srTransPara->stEMVinfo.T84_len);
		inPacketCnt += srTransPara->stEMVinfo.T84_len;
		
		szPacket[inPacketCnt ++] = 0x5F;
		szPacket[inPacketCnt ++] = 0x2A;
		szPacket[inPacketCnt ++] = 2;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T5F2A, 2);
		inPacketCnt += 2;

		szPacket[inPacketCnt ++] = 0x9A;
		szPacket[inPacketCnt ++] = 3;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9A, 3);
		inPacketCnt += 3;

		szPacket[inPacketCnt ++] = 0x9C;
		szPacket[inPacketCnt ++] = 1;
		/* BDO: Quasi should be parametrized per issuer - start -- jzg */
		//if((strIIT.fQuasiCash)	&& 
			//((srTransPara->byTransType == SALE) || (srTransPara->byTransType == SALE_OFFLINE)))
			//szPacket[inPacketCnt ++] = 0x11;
		/* BDO: Quasi should be parametrized per issuer - end -- jzg */
		//else
			szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9C;	// SL check again  //spec said 2 byte
		//Issue# 000141 - end -- jzg	

		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x37;
		szPacket[inPacketCnt ++] = 4;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F37, 4);
		inPacketCnt += 4;

        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x1E;
        szPacket[inPacketCnt ++] = 8;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F1E, 8);
        inPacketCnt += 8;

		/*szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x09;
        szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F09, 2);
        inPacketCnt += 2;*/ //Tag 9F09 not supported on AMEX
		
	}

	/* Packet Data Length */
	memset(szAscBuf, 0, sizeof(szAscBuf));
	sprintf(szAscBuf, "%04d", inPacketCnt);
	memset(szBcdBuf, 0, sizeof(szBcdBuf));
	wub_str_2_hex(szAscBuf, szBcdBuf, 4);
	memcpy((char *)&uszUnPackBuf[inDataCnt], &szBcdBuf[0], 2);
	inDataCnt += 2;
	
	/* Packet Data */
	memcpy((char *)&uszUnPackBuf[inDataCnt], &szPacket[0], inPacketCnt);
	inDataCnt += inPacketCnt;

	vdMyEZLib_LogPrintf(". Pack Len(%d)",inDataCnt);
	vdMyEZLib_LogPrintf("**inPackISOExpressPayData END**");
	return (inDataCnt);
}


int inPackISOQuickpassData(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{
     
	int inPacketCnt = 0, inTagLen;
	unsigned short usLen, usRetVal;
	BYTE btTrack2[20];
	char szAscBuf[4 + 1], szBcdBuf[2 + 1];
	char szPacket[512 + 1];
    char szTmp[32+1];
	USHORT ushEMVtagLen = 0;
	BYTE   EMVtagVal[64];
	int inRet;

    
	DebugAddSTR("load f55, inPackISOQuickpassData","emv",2);	

	vdMyEZLib_LogPrintf("**inPackISOEMVData START**");
	memset(szPacket, 0, sizeof(szPacket));
	inDataCnt = 0;



//remove later --jzg
vdDebug_LogPrintf("inPackISOEMVData:: txn type = [%d]", srTransPara->byTransType);
vdDebug_LogPrintf("inPackISOEMVData:: pack type = [%d]", srTransPara->byPackType);
		
	if(srTransPara->byPackType != REVERSAL)
	{
	    szPacket[inPacketCnt ++] = 0x5F;
	    szPacket[inPacketCnt ++] = 0x2A;
	    szPacket[inPacketCnt ++] = 2;
	    memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T5F2A, 2);
	    inPacketCnt += 2;
	   
#if 0
	    DebugAddINT("5F34 Len",srTransPara->stEMVinfo.T5F34_len );
	    if(srTransPara->stEMVinfo.T5F34_len > 0)
	    {
	        szPacket[inPacketCnt ++] = 0x5F;
	        szPacket[inPacketCnt ++] = 0x34;
	        szPacket[inPacketCnt ++] = 1;
	        szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T5F34;
			DebugAddSTR("EMV tag","5f34--finish--",2);
	    }
#endif
	    
	    szPacket[inPacketCnt ++] = 0x82;
	    szPacket[inPacketCnt ++] = 2;
	    memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T82, 2);
	    inPacketCnt += 2;

	    
	    szPacket[inPacketCnt ++] = 0x84;		
	    szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T84_len;
	    memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T84, srTransPara->stEMVinfo.T84_len);
	    inPacketCnt += srTransPara->stEMVinfo.T84_len;
	}
		
    szPacket[inPacketCnt ++] = 0x95;
    szPacket[inPacketCnt ++] = 5;
    memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T95, 5);
    inPacketCnt += 5;

	if(srTransPara->byPackType != REVERSAL)
	{
        szPacket[inPacketCnt ++] = 0x9A;
        szPacket[inPacketCnt ++] = 3;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9A, 3);
        inPacketCnt += 3;

        
        szPacket[inPacketCnt ++] = 0x9C;
        szPacket[inPacketCnt ++] = 1;
        szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9C;  // SL check again  //spec said 2 byte

       
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x02;
        szPacket[inPacketCnt ++] = 6;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F02, 6);
        inPacketCnt += 6;

        
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x03;
        szPacket[inPacketCnt ++] = 6;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F03, 6);
        inPacketCnt += 6;

        
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x09;
        szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F09, 2);
        inPacketCnt += 2;
       	
  	}
    
    szPacket[inPacketCnt ++] = 0x9F;
    szPacket[inPacketCnt ++] = 0x10;
    szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F10_len;
    memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F10, srTransPara->stEMVinfo.T9F10_len);
    inPacketCnt += srTransPara->stEMVinfo.T9F10_len;
    
	if(srTransPara->byPackType != REVERSAL)
	{
      szPacket[inPacketCnt ++] = 0x9F;
      szPacket[inPacketCnt ++] = 0x1A;
      szPacket[inPacketCnt ++] = 2;
      memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F1A, 2);
      inPacketCnt += 2;
      
      
      szPacket[inPacketCnt ++] = 0x9F;
      szPacket[inPacketCnt ++] = 0x1E;
      szPacket[inPacketCnt ++] = 8;
      memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F1E, 8);
      inPacketCnt += 8;

      
      szPacket[inPacketCnt ++] = 0x9F;
      szPacket[inPacketCnt ++] = 0x26;
      szPacket[inPacketCnt ++] = 8;
      memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F26, 8);
      inPacketCnt += 8;

      
      szPacket[inPacketCnt ++] = 0x9F;
      szPacket[inPacketCnt ++] = 0x27;
      szPacket[inPacketCnt ++] = 1;
      szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F27;

      
      szPacket[inPacketCnt ++] = 0x9F;
      szPacket[inPacketCnt ++] = 0x33;
      szPacket[inPacketCnt ++] = 3;
      memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F33, 3);
      inPacketCnt += 3;

      
      szPacket[inPacketCnt ++] = 0x9F;
      szPacket[inPacketCnt ++] = 0x34;
      szPacket[inPacketCnt ++] = 3;
      memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F34, 3);
      inPacketCnt += 3;

      
      szPacket[inPacketCnt ++] = 0x9F;
      szPacket[inPacketCnt ++] = 0x35;
      szPacket[inPacketCnt ++] = 1;
      szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F35;
	}
		
    szPacket[inPacketCnt ++] = 0x9F;
    szPacket[inPacketCnt ++] = 0x36;
    szPacket[inPacketCnt ++] = 2;
    memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F36, 2);
    inPacketCnt += 2;

	if(srTransPara->byPackType != REVERSAL)
	{
      szPacket[inPacketCnt ++] = 0x9F;
      szPacket[inPacketCnt ++] = 0x37;
      szPacket[inPacketCnt ++] = 4;
      memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F37, 4);
      inPacketCnt += 4;
	  
	  szPacket[inPacketCnt ++] = 0x9F;
      szPacket[inPacketCnt ++] = 0x41;
      szPacket[inPacketCnt ++] = 3;
	  memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F41, 3);// get chip transaction counter
      inPacketCnt += 3;        
    }

	
  /* Packet Data Length */
  memset(szAscBuf, 0, sizeof(szAscBuf));
  sprintf(szAscBuf, "%04d", inPacketCnt);
  memset(szBcdBuf, 0, sizeof(szBcdBuf));
  wub_str_2_hex(szAscBuf, szBcdBuf, 4);
  memcpy((char *)&uszUnPackBuf[inDataCnt], &szBcdBuf[0], 2);
  inDataCnt += 2;
  /* Packet Data */
  memcpy((char *)&uszUnPackBuf[inDataCnt], &szPacket[0], inPacketCnt);
  inDataCnt += inPacketCnt;
  
  vdMyEZLib_LogPrintf(". Pack Len(%d)",inDataCnt);
  vdMyEZLib_LogPrintf("**inPackISOEMVData END**");
  return (inDataCnt);
}


int inPackISOJCBCtlsData(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{
     
	int inPacketCnt = 0, inTagLen;
	unsigned short usLen, usRetVal;
	BYTE btTrack2[20];
	char szAscBuf[4 + 1], szBcdBuf[2 + 1];
	char szPacket[512 + 1];
    char szTmp[32+1];
	USHORT ushEMVtagLen = 0;
	BYTE   EMVtagVal[64];
	int inRet;

    
	DebugAddSTR("load f55, inPackISOJCBCtlsData","emv",2);	

	vdMyEZLib_LogPrintf("**inPackISOEMVData START**");
	memset(szPacket, 0, sizeof(szPacket));
	inDataCnt = 0;

    {	

        szPacket[inPacketCnt ++] = 0x5F;
        szPacket[inPacketCnt ++] = 0x2A;
        szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T5F2A, 2);
        inPacketCnt += 2;
        
		/*
        DebugAddINT("5F34 Len",srTransPara->stEMVinfo.T5F34_len );
        if(srTransPara->stEMVinfo.T5F34_len > 0)
        {
	        szPacket[inPacketCnt ++] = 0x5F;
	        szPacket[inPacketCnt ++] = 0x34;
	        szPacket[inPacketCnt ++] = 1;
	        szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T5F34;
			DebugAddSTR("EMV tag","5f34--finish--",2);
        }
        */
        
		szPacket[inPacketCnt ++] = 0x82;
        szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T82, 2);
        inPacketCnt += 2;

        szPacket[inPacketCnt ++] = 0x84;		
        szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T84_len;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T84, srTransPara->stEMVinfo.T84_len);
        inPacketCnt += srTransPara->stEMVinfo.T84_len;

        szPacket[inPacketCnt ++] = 0x95;
        szPacket[inPacketCnt ++] = 5;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T95, 5);
        inPacketCnt += 5;

        szPacket[inPacketCnt ++] = 0x9A;
        szPacket[inPacketCnt ++] = 3;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9A, 3);
        inPacketCnt += 3;

        szPacket[inPacketCnt ++] = 0x9C;
        szPacket[inPacketCnt ++] = 1;

				/* BDO: Quasi should be parametrized per issuer - start -- jzg */
				//if((strIIT.fQuasiCash)	&& 
				//	((srTransPara->byTransType == SALE) || (srTransPara->byTransType == SALE_OFFLINE)))
				//	szPacket[inPacketCnt ++] = 0x11;
				/* BDO: Quasi should be parametrized per issuer - end -- jzg */
				
				//Issue# 000143 - start -- jzg
				if(srTransPara->byTransType == PRE_AUTH)
					szPacket[inPacketCnt ++] = 0x00;
				//Issue# 000143 - end -- jzg
				else
					szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9C;	// SL check again  //spec said 2 byte
				//Issue# 000141 - end -- jzg	

#if 0
        szPacket[inPacketCnt ++] = 0x5F;
        szPacket[inPacketCnt ++] = 0x2A;
        szPacket[inPacketCnt ++] = 2;
        //memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T5F2A, 2);//test
        memcpy(&szPacket[inPacketCnt], "\x06\x08", 2);//test
        inPacketCnt += 2;
#endif
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x02;
        szPacket[inPacketCnt ++] = 6;
		
        //memcpy(&szPacket[inPacketCnt], "\x00\x00\x00\x00\x00\x00", 6);
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F02, 6);
        inPacketCnt += 6;

        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x03;
        szPacket[inPacketCnt ++] = 6;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F03, 6);
        inPacketCnt += 6;
/*
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x09;
        szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F09, 2);
        inPacketCnt += 2;
*/
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x10;
        szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F10_len;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F10, srTransPara->stEMVinfo.T9F10_len);
        inPacketCnt += srTransPara->stEMVinfo.T9F10_len;
      
	  	szPacket[inPacketCnt ++] = 0x9F;
	  	szPacket[inPacketCnt ++] = 0x1A;
	  	szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F1A, 2);
	  	inPacketCnt += 2;

        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x1E;
        szPacket[inPacketCnt ++] = 8;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F1E, 8);
        inPacketCnt += 8;

        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x26;
        szPacket[inPacketCnt ++] = 8;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F26, 8);
        inPacketCnt += 8;

        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x27;
        szPacket[inPacketCnt ++] = 1;
        szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F27;
/*
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x33;
        szPacket[inPacketCnt ++] = 3;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F33, 3);
        inPacketCnt += 3;
*/
        
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x34;
        szPacket[inPacketCnt ++] = 3;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F34, 3);
        inPacketCnt += 3;

        
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x35;
        szPacket[inPacketCnt ++] = 1;
        szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F35;

        
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x36;
        szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F36, 2);
        inPacketCnt += 2;

        
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x37;
        szPacket[inPacketCnt ++] = 4;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F37, 4);
        inPacketCnt += 4;


        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x41;
        szPacket[inPacketCnt ++] = 3;

        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F41, 3);// get chip transaction counter
        inPacketCnt += 3;  
		
		// JCB JRP20-025 - Addition of Device Information Tags for IC related Data -- sidumili
		szPacket[inPacketCnt ++] = 0x9F;		
		szPacket[inPacketCnt ++] = 0x6E;		
		szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F6E_len;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F6E, srTransPara->stEMVinfo.T9F6E_len);
		inPacketCnt += srTransPara->stEMVinfo.T9F6E_len;
		DebugAddHEX("srTransPara->stEMVinfo.T9F6E=",srTransPara->stEMVinfo.T9F6E,srTransPara->stEMVinfo.T9F6E_len);

		// JCB JRP20-025 - Addition of Partner Discretionary Data (PDD) Tags for IC related Data -- sidumili
		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x7C;
		szPacket[inPacketCnt ++] = 0x20;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F7C, 32);
		inPacketCnt += 32;
		DebugAddHEX("srTransPara->stEMVinfo.T9F7C=",srTransPara->stEMVinfo.T9F7C,32);
			
		//gcitra
/*
        DebugAddINT("5F34 Len",srTransPara->stEMVinfo.T5F34_len );
        if(srTransPara->stEMVinfo.T5F34_len > 0)
        {
	        szPacket[inPacketCnt ++] = 0x5F;
	        szPacket[inPacketCnt ++] = 0x34;
	        szPacket[inPacketCnt ++] = 1;
	        szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T5F34;
			DebugAddSTR("EMV tag","5f34--finish--",2);
        }

  */      
    }
	
    /* Packet Data Length */
    memset(szAscBuf, 0, sizeof(szAscBuf));
    sprintf(szAscBuf, "%04d", inPacketCnt);
    memset(szBcdBuf, 0, sizeof(szBcdBuf));
    wub_str_2_hex(szAscBuf, szBcdBuf, 4);
    memcpy((char *)&uszUnPackBuf[inDataCnt], &szBcdBuf[0], 2);
    inDataCnt += 2;
    /* Packet Data */
    memcpy((char *)&uszUnPackBuf[inDataCnt], &szPacket[0], inPacketCnt);
    inDataCnt += inPacketCnt;
    
    vdMyEZLib_LogPrintf(". Pack Len(%d)",inDataCnt);
    vdMyEZLib_LogPrintf("**inPackISOEMVData END**");
    return (inDataCnt);
}



#if 1
//gcitra
int inDisconnectIfNoPendingADVICEandUPLOAD(TRANS_DATA_TABLE *srTransPara, int inAdvCnt)
{
    int inResult,inUpDateAdviceIndex;
    TRANS_DATA_TABLE srAdvTransTable;
    STRUCT_ADVICE strAdvice;

	BOOL fEMVWave;

	BOOL fDisconnect;

    memset((char *)&srAdvTransTable, 0, sizeof(TRANS_DATA_TABLE));
    memset((char *)&strAdvice, 0, sizeof(strAdvice));
    memcpy((char *)&srAdvTransTable, (char *)srTransPara, sizeof(TRANS_DATA_TABLE));

    inResult = ST_SUCCESS;
	fDisconnect = FALSE;

//check if there's pending advice
    inResult = inMyFile_AdviceRead(&inUpDateAdviceIndex,&strAdvice,&srAdvTransTable);
     
    if(inResult == RC_FILE_READ_OUT_NO_DATA)      
		fDisconnect = TRUE;
	else	
		fDisconnect = FALSE;


        

//check if transaction is EMV

   fEMVWave = FALSE;

	if ((CARD_ENTRY_WAVE == srTransRec.byEntryMode) &&
		//((srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||	
		((srTransRec.bWaveSID == 0x65) ||
		(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
		(srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
		(srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
		//(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_2) ||		
		(srTransRec.bWaveSID == 0x63) ||
		(srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS) ||
		(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC))){
		fEMVWave = TRUE;

	}




	if (fDisconnect == TRUE){

		/* BDOCLG-00314: Fix for TC Upload not uploading during CARD VER -- jzg */
  	if (((srTransRec.byEntryMode == CARD_ENTRY_ICC) || (fEMVWave == TRUE)) && (strTCT.fTrickleFeedEMVUpload == VS_TRUE))
			fDisconnect = FALSE;
		else 
			fDisconnect = TRUE;

	}

    if(srTransPara->fDCC == TRUE)
        fDisconnect = FALSE;

	if (fDisconnect == TRUE)
		inCTOS_inDisconnect();

	return d_OK;
}

//BDO: Revised reversal function - start -- jzg
int inBDOAutoReversal(TRANS_DATA_TABLE *srTransPara, short shTxnFlag)
{
	int inResult;
	
	//BDO: [Auto Reversal after host does not respond] -- sidumili
	if (srCommFuncPoint.inConnect(&srTransRec) != ST_SUCCESS)
	{
		if (srTransPara->shTransResult == 0)
			srTransPara->shTransResult = TRANS_COMM_ERROR;

		inCTOS_inDisconnect();
		vdSetErrorMessage("TRANS COMM ERROR");
		return ST_ERROR;
	}

	inResult	= inProcessReversal(srTransPara, shTxnFlag);
	//BDO: [Auto Reversal after host does not respond] -- sidumili
	if(inResult != ST_SUCCESS)
	{
		inCTOS_inDisconnect();
		return ST_ERROR;
	}
	//BDO: [Auto Reversal after host does not respond] -- sidumili

	return ST_SUCCESS;
}
//BDO: Revised reversal function - end -- jzg

//smac
void inGetDateAndTime(){
	CTOS_RTC SetRTC;
	BYTE szCurrentTime[20];
	
	CTOS_RTCGet(&SetRTC);
	sprintf(szCurrentTime,"%02d%02d",SetRTC.bMonth, SetRTC.bDay);
	wub_str_2_hex(szCurrentTime,srTransRec.szDate,DATE_ASC_SIZE);
	sprintf(szCurrentTime,"%02d%02d%02d", SetRTC.bHour,SetRTC.bMinute,SetRTC.bSecond);
	wub_str_2_hex(szCurrentTime,srTransRec.szTime,TIME_ASC_SIZE);
	
}

//smac


int inSaveAmexData(void){

    memset(szAmexTID, 0x00, sizeof(szAmexTID));
    memset(szAmexMID, 0x00, sizeof(szAmexMID));
	
	strcpy(szAmexTID,srTransRec.szTID);
	strcpy(szAmexMID,srTransRec.szMID); 
	
    return d_OK;
}

int inPOSTErrorMessage(void)
{
    int inResult;
    CHAR szFileName[d_BUFF_SIZE];
    
    memset(szFileName,0,sizeof(szFileName));
    sprintf(szFileName, "%s%02d%02d.rev"
                        , strHDT.szHostLabel
                        , strHDT.inHostIndex
                        , srTransRec.MITid);
    
	DebugAddSTR("inSnedReversalToHost",szFileName,12);  
    
    vdDebug_LogPrintf("Rever Name %s",szFileName);

	if (inReversalType == 2)
		return TRUE;

	if (srTransRec.byTransType == SALE || srTransRec.byTransType == VOID || srTransRec.byTransType == CASH_ADVANCE){
		//check if theres pending reversal
    	if((inResult = inMyFile_CheckFileExist(szFileName)) < 0) 
        	return TRUE;
    	else
        	return FALSE;
	}else
	    return TRUE;
}


int inDisconnectVoidIfNoPendingADVICEandUPLOAD(TRANS_DATA_TABLE *srTransPara, int inAdvCnt)
{
    int inResult,inUpDateAdviceIndex;
    TRANS_DATA_TABLE srAdvTransTable;
    STRUCT_ADVICE strAdvice;

	BOOL fEMVWave;

	BOOL fDisconnect;

    memset((char *)&srAdvTransTable, 0, sizeof(TRANS_DATA_TABLE));
    memset((char *)&strAdvice, 0, sizeof(strAdvice));
    memcpy((char *)&srAdvTransTable, (char *)srTransPara, sizeof(TRANS_DATA_TABLE));

    inResult = ST_SUCCESS;
	fDisconnect = FALSE;

//check if there's pending advice
    inResult = inMyFile_AdviceRead(&inUpDateAdviceIndex,&strAdvice,&srAdvTransTable);
     
    if(inResult == RC_FILE_READ_OUT_NO_DATA)      
		fDisconnect = TRUE;
	else	
		fDisconnect = FALSE;

    if(srTransPara->fDCC == TRUE)
        fDisconnect = FALSE;

	if (fDisconnect == TRUE)
		inCTOS_inDisconnect();
  
	return d_OK;
}


#endif

void vdIncSTAN(TRANS_DATA_TABLE *srTransPara)
{
    char szStr[46 + 1];
	
    memset(szStr, 0, sizeof(szStr));
    srTransPara->ulTraceNum++;
    sprintf(szStr, "%06ld", srTransPara->ulTraceNum);
    inAscii2Bcd(szStr, strHDT.szTraceNo, 3);
    inHDTSave(srTransPara->HDTid);
}

#if 1
int inProcessTransLogTrans(TRANS_DATA_TABLE *srTransPara, int inAdvCnt, int inRetry, int inMode)
{
	int inResult,inUpDateAdviceIndex, inHDTid_Temp;
	int inCnt;
	TRANS_DATA_TABLE srAdvTransTable;
	ISO_FUNC_TABLE srAdviceFunc;
	STRUCT_ADVICE strAdvice;
	int TransLogNumRecord=inDatabase_TransLogNumRecord(inMode);
    int inTranID[TransLogNumRecord];
	int inCount=0;

    //memset((char *)&srAdvTransTable, 0, sizeof(TRANS_DATA_TABLE));
	//inDatabase_TransLogReadAll(&srAdvTransTable);
	
	inCTLOS_Updatepowrfail(PFR_IDLE_STATE);

	if(inCheckConnection() != d_OK)
			return ST_ERROR;

	if(strCPT.inCommunicationMode == DIAL_UP_MODE){
		if(inCheckModemConnected() != d_OK)
			return ST_ERROR;
	}
	
	memset((char *)&srAdvTransTable, 0, sizeof(TRANS_DATA_TABLE));
	memset((char *)&strAdvice, 0, sizeof(strAdvice));
	memcpy((char *)&srAdvTransTable, (char *)srTransPara, sizeof(TRANS_DATA_TABLE));
	memcpy((char *)&srAdviceFunc, (char *)&srIsoFuncTable[0], sizeof(ISO_FUNC_TABLE));

	inResult = ST_SUCCESS;

    inDatabase_TransLogGetTransId(&srAdvTransTable, inTranID, inMode);
	
	vdDebug_LogPrintf("inProcessTransLogTrans byPackType(%d)byTransType(%d),strAdvice.inPacketType(%d)", srAdvTransTable.byPackType, strAdvice.byTransType, strAdvice.inPacketType);
	
	vdDebug_LogPrintf("TransLogNumRecord: %d, inMode: %d", TransLogNumRecord, inMode);
	
	if(TransLogNumRecord <= 0)
        return ST_SUCCESS;
	
	while(1)
	{
		#if 1
		if(TransLogNumRecord <= inCount)
		{
			inResult = ST_SUCCESS;
			break;
		}

		inResult=inDatabase_TransLogRead(inTranID[inCount], &strAdvice, &srAdvTransTable);
		
		inCount++;
		if(inResult != d_OK)
			break;
		#else
		inResult = inMyFile_TransLogRead(&inUpDateAdviceIndex,&strAdvice,&srAdvTransTable);

		if(inResult == ST_ERROR || inResult == RC_FILE_READ_OUT_NO_DATA)
		{
			inResult = ST_SUCCESS;
			break;
		}
        #endif
		if(inResult == ST_SUCCESS)
		{
			//inMyFile_HDTTraceNoAdd(srTransPara->HDTid); //Remove to fix issue of skipping STAN.
			inHDTRead(srTransPara->HDTid);
			
            fAdviceTras = VS_TRUE;
            do
            {
				if(inCheckConnection() != d_OK)
					return ST_ERROR;

				srAdvTransTable.byPackType=strAdvice.inPacketType;
                vdDebug_LogPrintf("inProcessTransLogTrans srAdvTransTable.byPackType: %d", srAdvTransTable.byPackType);
				if(strAdvice.inPacketType==DCC_LOGGING_RETRY)
					srAdvTransTable.ulTraceNum = strAdvice.ulTraceNo;
				else
				{
					inHDTReadData(6);								
					
				    srAdvTransTable.ulTraceNum = wub_bcd_2_long(strHDT_Temp.szDCCRateandLogTraceNo,3);
					
					vdIncDCCSTAN(&srAdvTransTable);
				}

                vdDebug_LogPrintf("2. inProcessTransLogTrans srAdvTransTable.byPackType: %d", srAdvTransTable.byPackType);
				strAdvice.inPacketType=DCC_LOGGING_RETRY;
				strAdvice.ulTraceNo=srAdvTransTable.ulTraceNum; 
				//inMyFile_TransLogUpdatePacketType(inUpDateAdviceIndex, strAdvice);
                inDatabase_TransLogUpdatePackType(&srAdvTransTable);

				vdDebug_LogPrintf("3. inProcessTransLogTrans srAdvTransTable.byPackType: %d", srAdvTransTable.byPackType);
				
				inEFTPubRead(6);// Read if first DCC host has enabled EFTSec
				if(strEFTPub.inEFTEnable == 1)//disable EFTSec as rate request does not support EFTSec
				{
					inHDTid_Temp = srAdvTransTable.HDTid;
					srAdvTransTable.HDTid = 6;//To send the Trans Log to the DCC host id where EFTSec is disabled.
	                inResult = inBuildDCCOnlineMsg(&srAdvTransTable);
					srAdvTransTable.HDTid = inHDTid_Temp;//revert to original value
				}
				else
				{
					vdDebug_LogPrintf("4. inProcessTransLogTrans srAdvTransTable.byPackType: %d", srAdvTransTable.byPackType);
					inResult = inBuildDCCOnlineMsg(&srAdvTransTable);
				}
                vdDebug_LogPrintf("inProcessTransLogTrans:(%d)", inResult);
				vdDebug_LogPrintf("srTransPara->shTransResult:(%d)", srAdvTransTable.shTransResult);
				
				if(srAdvTransTable.shTransResult == TRANS_REJECTED)
					return ST_ERROR;
				
                if(inResult != ST_SUCCESS && inResult != ST_RECEIVE_TIMEOUT_ERR)
                    return inResult;	

                if(inResult != ST_SUCCESS)
                {
                    inRetry--;
                    if(inRetry <= 0)
                    {
                        inTCTSave(1);							
                        if (ST_RESP_MATCH_ERR == inResult)
                        {
                            return inResult;
                        }
                        return inResult;
                    }
                    else
                    {
						strAdvice.inPacketType=DCC_LOGGING_RETRY;
                    }
                }
                else
                    break;			
            }while(inRetry != 0);
				
			if (memcmp(srAdvTransTable.szRespCode, "00", 2))
				inResult = ST_ERROR;

			if ((inResult == ST_SUCCESS))
			{
				if ((srAdviceFunc.inAdviceAnalyse != 0x00))
				{
					vdSetISOEngTransDataAddress(&srAdvTransTable);
					inResult = srAdviceFunc.inAdviceAnalyse(CN_FALSE);
				}

				if (inResult == ST_SUCCESS)
				{
					//inResult = inMyFile_TransLogUpdate(inUpDateAdviceIndex);
					inResult = inDatabase_TransLogDelete(&srAdvTransTable, DELETE_BY_TRANSTYPE_INVOICE);
				}
			}
		}

		if(inResult != ST_SUCCESS)
		{
			if(srTransPara->byTransType == SETTLE)
			{
				srTransRec.shTransResult = TRANS_COMM_ERROR;
				inCTOS_inDisconnect();
				return ST_ERROR;
			}
			else
				return ST_SUCCESS;
		}

		if(inAdvCnt != -1)
		{
			inAdvCnt --;
			if(inAdvCnt == 0)
				break;
		}
	}

	return (inResult);
}


#else
int inProcessTransLogTrans(TRANS_DATA_TABLE *srTransPara, int inAdvCnt, int inRetry)
{
	int inResult,inUpDateAdviceIndex, inHDTid_Temp;
	int inCnt;
	TRANS_DATA_TABLE srAdvTransTable;
	ISO_FUNC_TABLE srAdviceFunc;
	STRUCT_ADVICE strAdvice;

	
	inCTLOS_Updatepowrfail(PFR_IDLE_STATE);

	memset((char *)&srAdvTransTable, 0, sizeof(TRANS_DATA_TABLE));
	memset((char *)&strAdvice, 0, sizeof(strAdvice));
	memcpy((char *)&srAdvTransTable, (char *)srTransPara, sizeof(TRANS_DATA_TABLE));
	memcpy((char *)&srAdviceFunc, (char *)&srIsoFuncTable[0], sizeof(ISO_FUNC_TABLE));

	inResult = ST_SUCCESS;

	vdDebug_LogPrintf("inProcessTransLogTrans byPackType(%d)byTransType(%d),strAdvice.inPacketType(%d)", srAdvTransTable.byPackType, strAdvice.byTransType, strAdvice.inPacketType);
	
	while(1)
	{
		inResult = inMyFile_TransLogRead(&inUpDateAdviceIndex,&strAdvice,&srAdvTransTable);

		if(inResult == ST_ERROR || inResult == RC_FILE_READ_OUT_NO_DATA)
		{
			inResult = ST_SUCCESS;
			break;
		}

		if(inResult == ST_SUCCESS)
		{
			//inMyFile_HDTTraceNoAdd(srTransPara->HDTid); //Remove to fix issue of skipping STAN.
			inHDTRead(srTransPara->HDTid);
			
            fAdviceTras = VS_TRUE;
            do
            {
				srAdvTransTable.byPackType=strAdvice.inPacketType;

				if(strAdvice.inPacketType==DCC_LOGGING_RETRY)
					srAdvTransTable.ulTraceNum = strAdvice.ulTraceNo;
				else
				{
					inHDTReadData(6);								
					
				    srAdvTransTable.ulTraceNum = wub_bcd_2_long(strHDT_Temp.szDCCRateandLogTraceNo,3);
					
					vdIncDCCSTAN(&srAdvTransTable);
				}

	
				strAdvice.inPacketType=DCC_LOGGING_RETRY;
				strAdvice.ulTraceNo=srAdvTransTable.ulTraceNum; 
				inMyFile_TransLogUpdatePacketType(inUpDateAdviceIndex, strAdvice);

				inEFTPubRead(6);// Read if first DCC host has enabled EFTSec
				if(strEFTPub.inEFTEnable == 1)//disable EFTSec as rate request does not support EFTSec
				{
					inHDTid_Temp = srAdvTransTable.HDTid;
					srAdvTransTable.HDTid = 6;//To send the Trans Log to the DCC host id where EFTSec is disabled.
	                inResult = inBuildDCCOnlineMsg(&srAdvTransTable);
					srAdvTransTable.HDTid = inHDTid_Temp;//revert to original value
				}
				else
					inResult = inBuildDCCOnlineMsg(&srAdvTransTable);
				
                vdDebug_LogPrintf("inProcessTransLogTrans:(%d)", inResult);
				vdDebug_LogPrintf("srTransPara->shTransResult:(%d)", srAdvTransTable.shTransResult);
				
				if(srAdvTransTable.shTransResult == TRANS_REJECTED)
					return ST_ERROR;
				
                if(inResult != ST_SUCCESS && inResult != ST_RECEIVE_TIMEOUT_ERR)
                    return inResult;	

                if(inResult != ST_SUCCESS)
                {
                    inRetry--;
                    if(inRetry <= 0)
                    {
                        inTCTSave(1);							
                        if (ST_RESP_MATCH_ERR == inResult)
                        {
                            return inResult;
                        }
                        return inResult;
                    }
                    else
                    {
						strAdvice.inPacketType=DCC_LOGGING_RETRY;
                    }
                }
                else
                    break;			
            }while(inRetry != 0);
				
			if (memcmp(srAdvTransTable.szRespCode, "00", 2))
				inResult = ST_ERROR;

			if ((inResult == ST_SUCCESS))
			{
				if ((srAdviceFunc.inAdviceAnalyse != 0x00))
				{
					vdSetISOEngTransDataAddress(&srAdvTransTable);
					inResult = srAdviceFunc.inAdviceAnalyse(CN_FALSE);
				}

				if (inResult == ST_SUCCESS)
				{
					inResult = inMyFile_TransLogUpdate(inUpDateAdviceIndex);
				}
			}
		}

		if(inResult != ST_SUCCESS)
		{
			if(srTransPara->byTransType == SETTLE)
			{
				srTransRec.shTransResult = TRANS_COMM_ERROR;
				inCTOS_inDisconnect();
				return ST_ERROR;
			}
			else
				return ST_SUCCESS;
		}

		if(inAdvCnt != -1)
		{
			inAdvCnt --;
			if(inAdvCnt == 0)
				break;
		}
	}

	return (inResult);
}

#endif
void vdIncDCCSTAN(TRANS_DATA_TABLE *srTransPara)
{
    char szStr[46 + 1];
	
    memset(szStr, 0, sizeof(szStr));
    srTransPara->ulTraceNum++;
    sprintf(szStr, "%06ld", srTransPara->ulTraceNum);
    inAscii2Bcd(szStr, strHDT_Temp.szDCCRateandLogTraceNo, 3);
    inHDTDCCSave(6);
}

void vdDisplayErrorMsg86(void)
{
	int inLen=0, inSpace;
	char szError1[24+1];
	char szError2[24+1];
	BOOL fSpace = 0;
		 	
	 inLen = strlen(szField63);
	 vdDebug_LogPrintf("inLen[%d]",inLen);

	 memset(szError1,0x00,sizeof(szError1));
	 memset(szError2,0x00,sizeof(szError2));

	 if(inLen > 40)
	 {
	 	vdDisplayErrorMsgResp2("UNKNOWN", "ERROR", " ");
		return;
	 }
	 
	 if(inLen > 20)
	 {
	 	inSpace = inLen-1;
		while(1)
		{
			if(szField63[inSpace] != ' ')
				inSpace--;
			else
			{
				if(inSpace >= 20)// if space is found but length is still greater than 20, skip.
				{
					inSpace--;
					continue;
				}
				else
				{
					fSpace = 1;
					break;
				}
			}

			if(inSpace<0)
				break;
		}

		if(fSpace == 1)
		{
			memcpy(szError1,szField63,inSpace);
			memcpy(szError2,&szField63[inSpace + 1],inLen - (inSpace+1));
		}
		else//if no space found and length is greater than 20, print as is on 2 separate lines.
		{
			memcpy(szError1,szField63,20);
			memcpy(szError2,&szField63[20],inLen-20);
		}

		vdDebug_LogPrintf("szError1[%s]",szError1);
		vdDebug_LogPrintf("szError2[%s]",szError2);
		vdDisplayErrorMsgResp2(szError1, szError2, " ");
	 }
	 else
	 {
	 	memcpy(szError1,szField63,inLen);
		vdDebug_LogPrintf("szError1[%s]",szError1);
		vdDisplayErrorMsgResp2(szError1, " ", " ");
	 }
	 	
 
}

int inSMACUnPackIsoFunc60(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{
	int inLen;

	memset(szField60, 0x00, sizeof(szField60));
	inLen =((uszUnPackBuf[0] / 16 * 10) + uszUnPackBuf[0] % 16) *100;
	inLen += (uszUnPackBuf[1] / 16 * 10) + uszUnPackBuf[1] % 16;

	//if(inLen<=0)
	//{
	//	return ST_SUCCESS; //return if DE60 is blank
	//}
	vdDebug_LogPrintf("fSMPrintFooterMsg[%d] :: srTransRec.byTransType[%d]",strIIT.fSMPrintFooterMsg,srTransRec.byTransType);
	if (strIIT.fSMPrintFooterMsg && (srTransRec.byTransType == SMAC_BALANCE || srTransRec.byTransType == BALANCE_INQUIRY || srTransRec.byTransType == SALE))
	{
		memcpy(szField60, (char *)&uszUnPackBuf[2], inLen);			
		srTransRec.fSMACFooter = 1;
	}
	return ST_SUCCESS;
}



int inProcessEMVTCUpload_Settlement(TRANS_DATA_TABLE *srTransPara, int inAdvCnt)
{
    int inResult,inUpDateAdviceIndex;
    int inCnt;
    TRANS_DATA_TABLE srOrigTransFromBatch;
    TRANS_DATA_TABLE srAdvTransTable;
    ISO_FUNC_TABLE srAdviceFunc;
    STRUCT_ADVICE strAdvice;

    memset((char *)&srAdvTransTable, 0, sizeof(TRANS_DATA_TABLE));
    memset((char *)&strAdvice, 0, sizeof(strAdvice));
    
    memcpy((char *)&srAdvTransTable, (char *)srTransPara, sizeof(TRANS_DATA_TABLE));
    memcpy((char *)&srAdviceFunc, (char *)&srIsoFuncTable[0], sizeof(ISO_FUNC_TABLE));
    
    inResult = ST_SUCCESS;
        
    vdDebug_LogPrintf("inProcessEMVTCUpload byPackType(%d)byTransType(%d)", srAdvTransTable.byPackType, strAdvice.byTransType);
    while(1)
    {
        inResult = inMyFile_TCUploadFileRead(&inUpDateAdviceIndex,&strAdvice,&srAdvTransTable);

        if ((srTransRec.HDTid < 6) || (srTransRec.HDTid > 35)){
			
			if (srAdvTransTable.fDCCAuth == 1){
		    	inResult = ST_SUCCESS;
            	break;

			}
        }
        
        if(strAdvice.byTransType == TC_UPLOAD)
            srAdvTransTable.byPackType = TC_UPLOAD;
        
        if(inResult == ST_ERROR || inResult == RC_FILE_READ_OUT_NO_DATA)
        {
            inResult = ST_SUCCESS;
            break;
        }

        memcpy(&srOrigTransFromBatch, &srAdvTransTable, sizeof(TRANS_DATA_TABLE));
        if(inResult == ST_SUCCESS)
        {
            vdDebug_LogPrintf("srTransPara->HDTid = [%d] ", srTransPara->HDTid);
            inMyFile_HDTTraceNoAdd(srTransPara->HDTid);
            inHDTRead(srTransPara->HDTid);

			//if(inGetATPBinRouteFlag())
			if (srAdvTransTable.fBINRouteApproved == TRUE)
			{
				memcpy(strHDT.szTPDU,strTCT.ATPTPDU,5);
				memcpy(strHDT.szNII,strTCT.ATPNII,2);
			}
	
			fAdviceTras = VS_TRUE;
            inResult = inPackSendAndUnPackData(&srAdvTransTable, strAdvice.byTransType);
            
            vdDebug_LogPrintf(". inProcessEMVTCUpload Rult(%d)srAdvTransTable.byTCFailUpCnt[%d]srTransPara->szRespCode[%s]", inResult, srAdvTransTable.byTCFailUpCnt,srAdvTransTable.szRespCode);

  
            if(srAdvTransTable.byTCFailUpCnt >= 2)
            {
              srAdvTransTable.byTCuploaded = CN_TRUE;
              srAdvTransTable.byUploaded = CN_TRUE;
              inResult = inMyFile_TCUploadFileUpdate(inUpDateAdviceIndex);
              vdDebug_LogPrintf(". inProcessEMVTCUpload Update Rult(%d)**", inResult);
                      
              if (inResult != ST_SUCCESS)
              {
                  vdDebug_LogPrintf(". inProcessEMVTCUpload Err(%d)**", inResult);
                  break;
              }
            }
            if (inResult == ST_SUCCESS)
            {
                if(memcmp(srAdvTransTable.szRespCode,"00",2) != 0)
                {
                    vdDebug_LogPrintf(". resp not succ(%s)**srTransPara->byPackType[%d]strAdvice.byTransType[%d]", srAdvTransTable.szRespCode,srTransPara->byPackType,strAdvice.byTransType);
                    if( strAdvice.byTransType == TC_UPLOAD )
                    {
                        srOrigTransFromBatch.byTCFailUpCnt++;                    
                        inMyFile_BatchSave(&srOrigTransFromBatch,DF_BATCH_UPDATE);
                        inCTOS_inDisconnect();
                        return ST_ERROR;
                    }
                }
                else
                {
                    srAdvTransTable.byTCuploaded = CN_TRUE;
                    srAdvTransTable.byUploaded = CN_TRUE;
                    inResult = inMyFile_TCUploadFileUpdate(inUpDateAdviceIndex);
                    vdDebug_LogPrintf(". inProcessEMVTCUpload Update Rult(%d)**", inResult);
                          
                    if (inResult != ST_SUCCESS)
                    {
                      vdDebug_LogPrintf(". inProcessEMVTCUpload Err(%d)**", inResult);
                      break;
                    }
                }    
            }
            else
            {
                if(strAdvice.byTransType == TC_UPLOAD)
                {
                    srOrigTransFromBatch.byTCFailUpCnt++; 
                    inMyFile_BatchSave(&srOrigTransFromBatch,DF_BATCH_UPDATE);
                }
            }
            
        }
        
        if(inResult != ST_SUCCESS)
        {
            if(srTransPara->byTransType == SETTLE)
            {
                srTransRec.shTransResult = TRANS_COMM_ERROR;
                inCTOS_inDisconnect();
                return ST_ERROR;
            }
            else
                return ST_SUCCESS;
        }

        
        if(inAdvCnt != -1)
        {
            inAdvCnt --;
            if(inAdvCnt == 0)
                break;
        }
    }
    
    vdDebug_LogPrintf("**inProcessEMVTCUpload(%d) END**", inResult);
	return (inResult);
}


int inProcessEMVTCUpload_PreAuthDCC(TRANS_DATA_TABLE *srTransPara, int inAdvCnt)
{
    int inResult,inUpDateAdviceIndex;
    int inCnt;
    TRANS_DATA_TABLE srOrigTransFromBatch;
    TRANS_DATA_TABLE srAdvTransTable;
    ISO_FUNC_TABLE srAdviceFunc;
    STRUCT_ADVICE strAdvice;

	vdDebug_LogPrintf("inProcessEMVTCUpload_PreAuthDCC");

#if 0
	if ((srTransRec.HDTid < 6) || (srTransRec.HDTid > 35)){
		
			return ST_SUCCESS;
	}
#endif
    memset((char *)&srAdvTransTable, 0, sizeof(TRANS_DATA_TABLE));
    memset((char *)&strAdvice, 0, sizeof(strAdvice));
    
    memcpy((char *)&srAdvTransTable, (char *)srTransPara, sizeof(TRANS_DATA_TABLE));
    memcpy((char *)&srAdviceFunc, (char *)&srIsoFuncTable[0], sizeof(ISO_FUNC_TABLE));
    
    inResult = ST_SUCCESS;
        
    vdDebug_LogPrintf("inProcessEMVTCUpload byPackType(%d)byTransType(%d)", srAdvTransTable.byPackType, strAdvice.byTransType);
    while(1)
    {
        inResult = inMyFile_DCCPreAuthTCUploadFileRead(&inUpDateAdviceIndex,&strAdvice,&srAdvTransTable);

        
        if(strAdvice.byTransType == TC_UPLOAD)
            srAdvTransTable.byPackType = TC_UPLOAD;
        
        if(inResult == ST_ERROR || inResult == RC_FILE_READ_OUT_NO_DATA)
        {
            inResult = ST_SUCCESS;
            break;
        }

        memcpy(&srOrigTransFromBatch, &srAdvTransTable, sizeof(TRANS_DATA_TABLE));
        if(inResult == ST_SUCCESS)
        {
            vdDebug_LogPrintf("srTransPara->HDTid = [%d] ", srTransPara->HDTid);
            inMyFile_HDTTraceNoAdd(srTransPara->HDTid);
            inHDTRead(srTransPara->HDTid);

			inFXTRead(1);
			memcpy(strHDT.szTPDU,strFXT.szDCCAuthTPDU,5);
			memcpy(strHDT.szNII,strFXT.szDCCAuthNII,2);
			
			fAdviceTras = VS_TRUE;
            inResult = inPackSendAndUnPackData(&srAdvTransTable, strAdvice.byTransType);
            
            vdDebug_LogPrintf(". inProcessEMVTCUpload Rult(%d)srAdvTransTable.byTCFailUpCnt[%d]srTransPara->szRespCode[%s]", inResult, srAdvTransTable.byTCFailUpCnt,srAdvTransTable.szRespCode);

  
            if(srAdvTransTable.byTCFailUpCnt >= 2)
            {
              srAdvTransTable.byTCuploaded = CN_TRUE;
              srAdvTransTable.byUploaded = CN_TRUE;
              inResult = inMyFile_DCCPreAuthTCUploadFileUpdate(inUpDateAdviceIndex);
              vdDebug_LogPrintf(". inProcessEMVTCUpload Update Rult(%d)**", inResult);
                      
              if (inResult != ST_SUCCESS)
              {
                  vdDebug_LogPrintf(". inProcessEMVTCUpload Err(%d)**", inResult);
                  break;
              }
            }
            if (inResult == ST_SUCCESS)
            {
                if(memcmp(srAdvTransTable.szRespCode,"00",2) != 0)
                {
                    vdDebug_LogPrintf(". resp not succ(%s)**srTransPara->byPackType[%d]strAdvice.byTransType[%d]", srAdvTransTable.szRespCode,srTransPara->byPackType,strAdvice.byTransType);
                    if( strAdvice.byTransType == TC_UPLOAD )
                    {
                        srOrigTransFromBatch.byTCFailUpCnt++;                    
                        inMyFile_BatchSave(&srOrigTransFromBatch,DF_BATCH_UPDATE);
                        inCTOS_inDisconnect();
                        return ST_ERROR;
                    }
                }
                else
                {
                    srAdvTransTable.byTCuploaded = CN_TRUE;
                    srAdvTransTable.byUploaded = CN_TRUE;
                    inResult = inMyFile_DCCPreAuthTCUploadFileUpdate(inUpDateAdviceIndex);
                    vdDebug_LogPrintf(". inProcessEMVTCUpload Update Rult(%d)**", inResult);
                          
                    if (inResult != ST_SUCCESS)
                    {
                      vdDebug_LogPrintf(". inProcessEMVTCUpload Err(%d)**", inResult);
                      break;
                    }
                }    
            }
            else
            {
                if(strAdvice.byTransType == TC_UPLOAD)
                {
                    srOrigTransFromBatch.byTCFailUpCnt++; 
                    inMyFile_BatchSave(&srOrigTransFromBatch,DF_BATCH_UPDATE);
                }
            }
            
        }
        
        if(inResult != ST_SUCCESS)
        {
            if(srTransPara->byTransType == SETTLE)
            {
                srTransRec.shTransResult = TRANS_COMM_ERROR;
                inCTOS_inDisconnect();
                return ST_ERROR;
            }
            else
                return ST_SUCCESS;
        }

        
        if(inAdvCnt != -1)
        {
            inAdvCnt --;
            if(inAdvCnt == 0)
                break;
        }
    }
    
    vdDebug_LogPrintf("**inProcessEMVTCUpload(%d) END**", inResult);
	return (inResult);
}


int inPackISODPasData(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{ 
	int inPacketCnt = 0, inTagLen;
	unsigned short usLen, usRetVal;
	BYTE btTrack2[20];
	char szAscBuf[4 + 1], szBcdBuf[2 + 1];
	char szPacket[512 + 1];
	char szTmp[32+1];
	USHORT ushEMVtagLen = 0;
	BYTE   EMVtagVal[64];
	int inRet;
	
	DebugAddSTR("load f55, inPackISODPasData","emv",2);	

	vdMyEZLib_LogPrintf("**inPackISOPayWaveData START**");
	memset(szPacket, 0, sizeof(szPacket));
	inDataCnt = 0;

	{
		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x26;
		szPacket[inPacketCnt ++] = 8;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F26, 8);
		inPacketCnt += 8;
	
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x27;
        szPacket[inPacketCnt ++] = 1;
        szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F27;
		
		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x10;
		szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F10_len;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F10, srTransPara->stEMVinfo.T9F10_len);
		inPacketCnt += srTransPara->stEMVinfo.T9F10_len;

        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x34;
        szPacket[inPacketCnt ++] = 3;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F34, 3);
		inPacketCnt += 3;

		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x35;
		szPacket[inPacketCnt ++] = 1;
		szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9F35;
	
		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x37;
		szPacket[inPacketCnt ++] = 4;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F37, 4);
		inPacketCnt += 4;

        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x36;
        szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F36, 2);
        inPacketCnt += 2;

		szPacket[inPacketCnt ++] = 0x84;		
		szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T84_len;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T84, srTransPara->stEMVinfo.T84_len);
		inPacketCnt += srTransPara->stEMVinfo.T84_len;


		szPacket[inPacketCnt ++] = 0x95;
		szPacket[inPacketCnt ++] = 5;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T95, 5);
		inPacketCnt += 5;

		szPacket[inPacketCnt ++] = 0x9A;
		szPacket[inPacketCnt ++] = 3;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9A, 3);
		inPacketCnt += 3;

		szPacket[inPacketCnt ++] = 0x9C;
		szPacket[inPacketCnt ++] = 1;
		/* BDO: Quasi should be parametrized per issuer - start -- jzg */
		//if((strIIT.fQuasiCash)	&& 
		//	((srTransPara->byTransType == SALE) || (srTransPara->byTransType == SALE_OFFLINE)))
		//	szPacket[inPacketCnt ++] = 0x11;
		/* BDO: Quasi should be parametrized per issuer - end -- jzg */
		//else
			szPacket[inPacketCnt ++] = srTransPara->stEMVinfo.T9C;	// SL check again  //spec said 2 byte
		//Issue# 000141 - end -- jzg	

        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x02;
        szPacket[inPacketCnt ++] = 6;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F02, 6);
        inPacketCnt += 6;

		szPacket[inPacketCnt ++] = 0x5F;
		szPacket[inPacketCnt ++] = 0x2A;
		szPacket[inPacketCnt ++] = 2;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T5F2A, 2);
		inPacketCnt += 2;

		szPacket[inPacketCnt ++] = 0x82;
		szPacket[inPacketCnt ++] = 2;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T82, 2);
		inPacketCnt += 2;
		
		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x1A;
		szPacket[inPacketCnt ++] = 2;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F1A, 2);
		inPacketCnt += 2;
		
		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x33;
		szPacket[inPacketCnt ++] = 3;
		//memcpy(&szPacket[inPacketCnt], "\xE0\xB0\xC8", 3);
		//inPacketCnt += 3;
		
        //memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F33, 3);
        //srTransPara->stEMVinfo.T9F33
        szPacket[inPacketCnt]= srTransPara->stEMVinfo.T9F33[0];
		inPacketCnt += 1;
        szPacket[inPacketCnt]= srTransPara->stEMVinfo.T9F33[1];
		inPacketCnt += 1;
        szPacket[inPacketCnt]= srTransPara->stEMVinfo.T9F33[2];
		inPacketCnt += 1;
		
		
		
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x03;
        szPacket[inPacketCnt ++] = 6;
        memcpy(&szPacket[inPacketCnt], "\x00\x00\x00\x00\x00\x00", 6);
        inPacketCnt += 6;

		
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x09;
        szPacket[inPacketCnt ++] = 2;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F09, 2);
        inPacketCnt += 2;


        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x1E;
        szPacket[inPacketCnt ++] = 8;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F1E, 8);
        inPacketCnt += 8;

		
        szPacket[inPacketCnt ++] = 0x9F;
        szPacket[inPacketCnt ++] = 0x41;
        szPacket[inPacketCnt ++] = 3;
        memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F41, 3);// get chip transaction counter
        inPacketCnt += 3;        
#if 0
		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x06;
		szPacket[inPacketCnt ++] = 3;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F06, 3);
		inPacketCnt += 3;		 

		szPacket[inPacketCnt ++] = 0x9F;
		szPacket[inPacketCnt ++] = 0x07;
		szPacket[inPacketCnt ++] = 3;
		memcpy(&szPacket[inPacketCnt], srTransPara->stEMVinfo.T9F07, 3);
		inPacketCnt += 3;		 
#endif
	}
	
	/* Packet Data Length */
	memset(szAscBuf, 0, sizeof(szAscBuf));
	sprintf(szAscBuf, "%04d", inPacketCnt);
	memset(szBcdBuf, 0, sizeof(szBcdBuf));
	wub_str_2_hex(szAscBuf, szBcdBuf, 4);
	memcpy((char *)&uszUnPackBuf[inDataCnt], &szBcdBuf[0], 2);
	inDataCnt += 2;
	/* Packet Data */
	memcpy((char *)&uszUnPackBuf[inDataCnt], &szPacket[0], inPacketCnt);
	inDataCnt += inPacketCnt;
	
	vdMyEZLib_LogPrintf(". Pack Len(%d)",inDataCnt);
	vdMyEZLib_LogPrintf("**inPackISOPayWaveData END**");
	return (inDataCnt);
}



int inSMACUnPackIsoFunc61(TRANS_DATA_TABLE *srTransPara, unsigned char *uszUnPackBuf)
{
	int inLen, inCount=2;
	int inIndex[4+1] = {0};
	int inIndexCount = 0;
	char szKey[32+1];
	char szSystemID[14+1] = {0};
	char szLoyalty_Key1[32+1] = {0};
	char szLoyalty_Key2[32+1] = {0};
	char szLoyalty_Key3[32+1] = {0};
	char szLoyalty_Key4[32+1] = {0};
	char szLoyalty_Key5[32+1] = {0};
	char szLoyalty_Key6[32+1] = {0};
	char szSearchToken[1+1] = {0};
	char szTemp1[256+1] = {0};
	char szTemp2[256+1] = {0};
	char *found = NULL;

	vdDebug_LogPrintf("***inSMACUnPackIsoFunc61***");
	
	memset(szLoyalty_Key1,0x00,sizeof(szLoyalty_Key1));
	memset(szLoyalty_Key2,0x00,sizeof(szLoyalty_Key2));
	memset(szLoyalty_Key5,0x00,sizeof(szLoyalty_Key5));
	memset(szLoyalty_Key6,0x00,sizeof(szLoyalty_Key6));
	
	memset(szField61, 0x00, sizeof(szField61));
	inLen =((uszUnPackBuf[0] / 16 * 10) + uszUnPackBuf[0] % 16) *100;
	inLen += (uszUnPackBuf[1] / 16 * 10) + uszUnPackBuf[1] % 16;

	if(srTransPara->byTransType == SMAC_ACTIVATION)
	{
		memcpy(szField61, (char *)&uszUnPackBuf[2], inLen); 
		
		memset(szSystemID,0x00,sizeof(szSystemID));
		memcpy(szSystemID,szField61,14);
		vdDebug_LogPrintf("szSystemID[%s]",szSystemID);
		inCTOSS_PutEnvDB ("SYSID", szSystemID);

		memcpy(szLoyalty_Key1,&szField61[15],32);
		vdDebug_LogPrintf("szLoyalty_Key1[%s]",szLoyalty_Key1);
		
		szSearchToken[0]='~';
		memcpy(szTemp1,szField61,inLen);
		
		inCount = 0;
		vdDebug_LogPrintf("szTemp1 %s",szTemp1);
		while(1)//Get indeces of ~ character
		{
			if(szTemp1[inCount] == '~')
			{
				vdDebug_LogPrintf("inCount %d",inCount);
				vdDebug_LogPrintf("szTemp1[inCount+1] %c",szTemp1[inCount+1]);
				if(szTemp1[inCount+1] != '~')
				{
					vdDebug_LogPrintf("NOT ~ ON NEXT INDEX. GETTING INDEX %d",inCount);
					inIndex[inIndexCount] = inCount+1;//get index of the start of key string
				}
				else
				{
					vdDebug_LogPrintf("~ ON NEXT INDEX. DISREGARD");
					inIndex[inIndexCount] = -1;
				}
				inIndexCount++;
				vdDebug_LogPrintf("inIndexCount %d",inIndexCount);
			}

			inCount++;

			if(inCount > inLen)
				break;
				
		}

		for(inIndexCount = 0; inIndexCount < 5; inIndexCount++)
		{
			vdDebug_LogPrintf("inIndexCount[%d] = %d",inIndexCount,inIndex[inIndexCount]);
			if(inIndex[inIndexCount] > 0)//not -1
			{
				vdDebug_LogPrintf("COPYING KEY %d", inIndexCount+2);
				switch(inIndexCount)
				{
					case 0:
						memcpy(szLoyalty_Key2,&szTemp1[inIndex[inIndexCount]],32);
						vdDebug_LogPrintf("szLoyalty_Key2 %s",szLoyalty_Key2);
						break;
					case 1:
						memcpy(szLoyalty_Key3,&szTemp1[inIndex[inIndexCount]],32);
						vdDebug_LogPrintf("szLoyalty_Key3 %s",szLoyalty_Key3);
						break;
					case 2:
						memcpy(szLoyalty_Key4,&szTemp1[inIndex[inIndexCount]],32);
						vdDebug_LogPrintf("szLoyalty_Key4 %s",szLoyalty_Key4);
						break;
					case 3:
						memcpy(szLoyalty_Key5,&szTemp1[inIndex[inIndexCount]],32);
						vdDebug_LogPrintf("szLoyalty_Key5 %s",szLoyalty_Key5);
						break;
					case 4:
						memcpy(szLoyalty_Key6,&szTemp1[inIndex[inIndexCount]],32);
						vdDebug_LogPrintf("szLoyalty_Key6 %s",szLoyalty_Key6);
						break;
				}

			}
		
		}

		InjectAESKey(szLoyalty_Key1,READ_CARD_INFO);
		inGenerateSubKey(szLoyalty_Key1,READ_CARD_INFO);
		vdDebug_LogPrintf("inSMACUnPackIsoFunc61 --- A");	
		
		InjectAESKey(szLoyalty_Key2,WRITE_CARD_INFO);
		inGenerateSubKey(szLoyalty_Key2,WRITE_CARD_INFO);
		vdDebug_LogPrintf("inSMACUnPackIsoFunc61 --- B");		
				
		InjectAESKey(szLoyalty_Key5,READ_CARD_BALANCE);
		inGenerateSubKey(szLoyalty_Key5,READ_CARD_BALANCE);
		vdDebug_LogPrintf("inSMACUnPackIsoFunc61 --- C");	
		
		InjectAESKey(szLoyalty_Key6,WRITE_CARD_BALANCE);
		inGenerateSubKey(szLoyalty_Key6,WRITE_CARD_BALANCE);
		vdDebug_LogPrintf("inSMACUnPackIsoFunc61 --- D");	
	
		
	}
	else if(inCheckSMACPayTransaction(srTransPara) == TRUE)
	{
		vdParseSMACPayCardData(srTransPara, (char *)&uszUnPackBuf[2], inLen);

		if(inCheckSMACPayBalanceInq(srTransPara) == TRUE)
		{	
			memset(srTransPara->szTotalAmount,0x00,sizeof(srTransPara->szTotalAmount));
			wub_str_2_hex(srTransPara->szSMACPay_HostBalance,srTransPara->szTotalAmount,12);
		}
	}
		
	return ST_SUCCESS;
}

