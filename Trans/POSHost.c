/*******************************************************************************

*******************************************************************************/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctosapi.h>
#include <EMVAPLib.h>
#include <EMVLib.h>


#include "..\Includes\Wub_lib.h"

#include "..\Includes\POSTypedef.h"
#include "..\FileModule\myFileFunc.h"

#include "..\Includes\msg.h"
#include "..\Includes\CTOSInput.h"
#include "..\ui\Display.h"

#include "..\Includes\V5IsoFunc.h"
#include "..\Comm\V5Comm.h"
#include "..\Includes\Trans.h"   


#include "..\Includes\CTOSInput.h"


#include "..\debug\debug.h"
#include "..\Accum\Accum.h"

#include "..\Includes\POSMain.h"
#include "..\Includes\POSTrans.h"
#include "..\Includes\POSHost.h"
#include "..\Includes\POSSale.h"
#include "..\Database\DatabaseFunc.h"
#include "..\Includes\POSHost.h"
#include "..\Includes\Wub_lib.h"
#include "..\Includes\myEZLib.h"
#include "..\accum\accum.h"
#include "..\Includes\POSSetting.h"
#include "..\Debug\Debug.h"
#include "..\filemodule\myFileFunc.h"
#include "..\Includes\POSTrans.h"
#include "..\Includes\CTOSInput.h"
#include "..\Ctls\PosWave.h"


#include "..\Includes\MultiApLib.h"
#include "..\Aptrans\MultiAptrans.h"
#include "..\Aptrans\MultiShareEMV.h"
#include "../Ctls/POSCtls.h"

#define d_NOT_RECORD            102

#define d_GETPIN_TIMEOUT        6000
#define d_DUPLICATE_INVOICE     0x0080

extern int gvSettleType; //aaa fix on issue #000210 Terminal displays "Batch empty, skip" on all hosts when trying to settle hosts with no transactions 1 of 6
char gblszAmt[20+1]; //aaronnino for BDOCLG ver 9.0 fix on issue #00139 HAVE A DEFAULT TITLE DISPLAY OF TXN TYPE 4 of 8
BOOL gblfBatchEmpty = FALSE;  //aaronnino for BDOCLG ver 9.0 fix on issue #0033 and #0034 "settle failed" error response after "comm error"  1 of 8

extern BOOL fInstApp;

 // patrick add code 20131208
extern BOOL fECRTxnFlg;
 
extern BYTE szTempBaseAmount[AMT_BCD_SIZE+1];; //00126 - SM: Can't process SMAC QR any amount via ECR triggered

/*BDO: For ECR hold response code -- sidumili */
extern BOOL fUSDSelected;

//version16
extern BYTE szSMACScanResponsetext[50];
extern BOOL fSmacScan;

int inCTOS_GetTxnBaseAmount(void)
{
    char szDisplayBuf[30];
    BYTE key;
    BYTE szTemp[20];
    BYTE baAmount[20];
    BYTE bBuf[4+1];
    BYTE bDisplayStr[MAX_CHAR_PER_LINE+1];
    ULONG ulAmount = 0L;
		int inCurrencyIndex = 0;

	//gcitra-0728
	BYTE bFirstKey;
	//gcitra-0728

	vdDebug_LogPrintf("***inCTOS_GetTxnBaseAmount***");
//gcitra-0806
	if (inMultiAP_CheckSubAPStatus() == d_OK)
	   return d_OK;
//gcitra-0806	

	if (1 == inCTOSS_GetWaveTransType())
	if (inMultiAP_CheckSubAPStatus() == d_OK)
        return d_OK;

	
	vdDebug_LogPrintf("BEFORE CHECK AMOUNT ZERO");
	DebugAddHEX("AMOUNT",srTransRec.szBaseAmount,AMT_BCD_SIZE);

	
	if (memcmp(srTransRec.szBaseAmount, "\x00\x00\x00\x00\x00\x00", 6) != 0){
		vdDebug_LogPrintf("AMOUNT NOT ZERO");

		#if 1 // 00126 - SM: Can't process SMAC QR any amount via ECR triggered
		memset(szTempBaseAmount,0x00,sizeof(szTempBaseAmount));
		memcpy(szTempBaseAmount, srTransRec.szBaseAmount, 6); 
		#endif
		
		// sidumili: Issue#:000076 [check transaction maximum amount]
		
		if (inCTOS_ValidateTrxnAmount()!= d_OK){
			return(d_NO);
		}
				
		return d_OK;
	}

#if 1
	if (fECRTxnFlg == 1)
	{

		DebugAddHEX("GLOBAL ECR szTempBaseAmount",szTempBaseAmount,AMT_BCD_SIZE);
	
		vdDebug_LogPrintf("INSIDE fECRTxnFlg");
		if (memcmp(srTransRec.szBaseAmount, "\x00\x00\x00\x00\x00\x00", 6) == 0){		
			vdSetErrorMessage("OUT OF RANGE");
			return(ST_ERROR);  
		}
	}
#endif	

	vdClearBelowLine(2);
    //CTOS_LCDTClearDisplay();
    //vduiLightOn();

		/* BDO CLG: Fleet card support - start -- jzg */
		//if(srTransRec.fFleetCard == TRUE)
		//	vdDispTransTitle(FLEET_SALE);
		//else
		/* BDO CLG: Fleet card support - end -- jzg */	
	    //vdDispTransTitle(srTransRec.byTransType);

//gcitra -- remove Card title display 
/*

    if(CARD_ENTRY_MANUAL == srTransRec.byEntryMode)
    {
        setLCDPrint(2, DISPLAY_POSITION_LEFT, "CARD NO: ");
        memset(bDisplayStr, 0x00, sizeof(bDisplayStr));
        strcpy(bDisplayStr, srTransRec.szPAN);
        CTOS_LCDTPrintXY(MAX_CHAR_PER_LINE-strlen(bDisplayStr)*2, 3, bDisplayStr);
        setLCDPrint(5, DISPLAY_POSITION_LEFT, "EXPIRY DATE(MM/YY):");

        memset(bDisplayStr, 0x00, sizeof(bDisplayStr));
        memset(bBuf, 0x00, sizeof(bBuf));
        wub_hex_2_str(&srTransRec.szExpireDate[1], &bBuf[0], 1);
        memcpy(bDisplayStr, bBuf, 2);
        bDisplayStr[2] = '/';
        memset(bBuf, 0x00, sizeof(bBuf));
        wub_hex_2_str(&srTransRec.szExpireDate[0], &bBuf[0], 1);
        memcpy(bDisplayStr+3, bBuf, 2);
        CTOS_LCDTPrintXY(MAX_CHAR_PER_LINE-strlen(bDisplayStr)*2, 6, bDisplayStr);
    }
    else
    {
    	if (1 != inCTOSS_GetWaveTransType())
        	inCTOS_DisplayCardTitle(4, 5);
    }
*/
//gcitra
    
    CTOS_KBDHit(&key);//clear key buffer
    inDatabase_TerminalOpenDatabase();
    vdDebug_LogPrintf("strCDT.HDTid[%d] strHDT.inCurrencyIdx[%d]", strCDT.HDTid, strHDT.inCurrencyIdx);
    inHDTReadEx(strCDT.HDTid);
    vdDebug_LogPrintf("strHDT.inCurrencyIdx[%d]", strHDT.inCurrencyIdx);
	
	if(fUSDSelected == TRUE)
		strcpy(szDisplayBuf, "USD");
	else
	{
	    inCurrencyIndex = strHDT.inCurrencyIdx;
	    inCSTReadEx(inCurrencyIndex);
	    memset(szDisplayBuf, 0x00, sizeof(szDisplayBuf));
	    sprintf(szDisplayBuf, "%s", strCST.szCurSymbol);
	}
	
    inDatabase_TerminalCloseDatabase();
	vdDispTransTitle(srTransRec.byTransType);
	
    CTOS_LCDTPrintXY(1, 7, "AMOUNT:");

//gcitra-0728
	if(strTCT.fDualCurrency == FALSE)
	{
		if(d_OK == inCTOS_ValidFirstIdleKey())
			bFirstKey = chGetFirstIdleKey();
		else
			bFirstKey = 0x00;
	}
	else
		bFirstKey = 0x00;
//gcitra-0728

    memset(baAmount, 0x00, sizeof(baAmount));
//gcitra-0728
    //key = InputAmount(1, 8, szDisplayBuf, 2, 0x00, baAmount, &ulAmount, d_INPUT_TIMEOUT, 0);
	//key = InputAmount2(1, 8, szDisplayBuf, 2, bFirstKey, baAmount, &ulAmount, d_INPUT_TIMEOUT, 0);
	key = InputAmount2(1, 8, szDisplayBuf, 2, bFirstKey, baAmount, &ulAmount, inGetIdleTimeOut(FALSE), 0); /*BDO: Parameterized idle timeout --sidumili*/
//gcitra-0728


    vdDebug_LogPrintf("inCTOS_GetTxnBaseAmount key[%d]", key);

    if(d_OK == key)
    {
        
        memset(szTemp, 0x00, sizeof(szTemp));
		// patrick add code 20141216
        sprintf(szTemp, "%012.0f", atof(baAmount));
        wub_str_2_hex(szTemp,srTransRec.szBaseAmount,12);

		/*BDO: Hold Amount for SMAC due to during void DE04 is return SMAC balance -- sidumili*/
		wub_str_2_hex(szTemp,srTransRec.szSMACAmount,12);

		
		DebugAddHEX("BASE AMOUNT",srTransRec.szBaseAmount,AMT_BCD_SIZE);
		DebugAddHEX("SMAC AMOUNT",srTransRec.szSMACAmount,AMT_BCD_SIZE);
		

#if 0
		//Installment: checking for minimum installment amount - end -- jzg
		if(srTransRec.byTransType == SALE)
		{
			long amt1=0, amt2=0;	
	
			inTCTRead(1);

	
			amt1 = wub_str_2_long(baAmount);
			amt2 = wub_str_2_long(strTCT.szMinInstAmt);
		
			if(amt1 < amt2)
			{
				char szMinInstAmt[13] = {0};
	
				memset(szMinInstAmt, 0x00, sizeof(szMinInstAmt));
				vdFormatAmount(szMinInstAmt, "", strTCT.szMinInstAmt, FALSE);
				memset(szTemp, 0x00, sizeof(szTemp));
				sprintf(szTemp,"MIN AMOUNT %s", szMinInstAmt);
	
				CTOS_LCDTClearDisplay();
				vdDisplayErrorMsg(1, 8, szTemp);
				vduiWarningSound();
				return -1;	
			}
		}
	//Installment: checking for minimum installment amount - end -- jzg
#endif

			// sidumili: Issue#:000076 [check transaction maximum amount]
			if (inCTOS_ValidateTrxnAmount()!= d_OK){
				return(d_NO);
			}
				memcpy(gblszAmt, szTemp, strlen(szTemp)); //aaronnino for BDOCLG ver 9.0 fix on issue #00139 HAVE A DEFAULT TITLE DISPLAY OF TXN TYPE 5 of 8
    }
    if(0xFF == key)
    {
        //vdSetErrorMessage("Amt entry cancelled");
        return d_NO;
    }
	
	/*sidumili: [USER press cancel]*/
	if (d_USER_CANCEL == key){

			/* BDO CLG: Fleet card support - start -- jzg */
			//if(srTransRec.fFleetCard == TRUE)
			//	vdDispTransTitle(FLEET_SALE);
			//else
			/* BDO CLG: Fleet card support - end -- jzg */	
				vdDispTransTitle(srTransRec.byTransType);
			
			vdSetErrorMessage("Amt entry cancelled");
			return d_NO;
	}
	/*sidumili: [USER press cancel]*/
	
    return key;
}

//gcitra
int inCTOS_INSTGetTxnBaseAmount(void)
{
    char szDisplayBuf[30];
    BYTE key;
    BYTE szTemp[20];
    BYTE baAmount[20];
    BYTE bBuf[4+1];
    BYTE bDisplayStr[MAX_CHAR_PER_LINE+1];
    ULONG ulAmount = 0L;
    double dbAmt3 = 0.00;
    BYTE szBaseAmt[30+1] = {0};
    char *strPTR;

	//gcitra-0728
	BYTE bFirstKey;
	//gcitra-0728


//gcitra-0806
	if (inMultiAP_CheckSubAPStatus() == d_OK)
	   return d_OK;
//gcitra-0806	

	if (1 == inCTOSS_GetWaveTransType())
	if (inMultiAP_CheckSubAPStatus() == d_OK)
        return d_OK;

	if (memcmp(srTransRec.szBaseAmount, "\x00\x00\x00\x00\x00\x00", 6) != 0){
		if (fGetECRTransactionFlg() == TRUE){
			if(srTransRec.byTransType == SALE)
			{
				double amt1=0, amt2=0;	

                memset(baAmount, 0x00, sizeof(baAmount));
				wub_hex_2_str(srTransRec.szBaseAmount, baAmount, 6);
				amt1 = wub_str_2_doble(baAmount);
				amt2 = wub_str_2_doble(strTCT.szMinInstAmt);
				dbAmt3 = strtod(strTCT.szMaxInstAmt, &strPTR);
			
			
				if(amt1 < amt2)
				{
					char szMinInstAmt[13] = {0};
			
					memset(szMinInstAmt, 0x00, sizeof(szMinInstAmt));
					vdFormatAmount(szMinInstAmt, "", strTCT.szMinInstAmt, FALSE);
					memset(szTemp, 0x00, sizeof(szTemp));
					sprintf(szTemp,"MIN AMOUNT %s", szMinInstAmt);
			
					CTOS_LCDTClearDisplay();
					vdDisplayErrorMsg(1, 8, szTemp);
					vduiWarningSound();
					CTOS_Delay(1000);
					return d_NO;	
				}
				
				if(amt1 > dbAmt3)
				{
					char szMaxInstAmt[13] = {0};
			    
					memset(szMaxInstAmt, 0x00, sizeof(szMaxInstAmt));
					vdFormatAmount(szMaxInstAmt, "", strTCT.szMaxInstAmt, FALSE);
					memset(szTemp, 0x00, sizeof(szTemp));
					//sprintf(szTemp,"MAX AMOUNT %s", szMaxInstAmt);
					
					strcpy(szTemp, "OUT OF RANGE");
			
					CTOS_LCDTClearDisplay();
					vdDisplayErrorMsg(1, 8, szTemp);
					vduiWarningSound();
					CTOS_Delay(1000);
					return d_NO;	
				}
			}

		}
		return d_OK;
	}
	
    CTOS_LCDTClearDisplay();
    vduiLightOn();
    
    vdDispTransTitle(srTransRec.byTransType);
    //vdDispTitleString("INSTALLMENT");//aaronnino for BDOCLG ver 9.0 fix on issue #00072 Incorrrect transaction type displayed for INSTALLMENT 2 of 2

//gcitra -- remove Card title display 
/*

    if(CARD_ENTRY_MANUAL == srTransRec.byEntryMode)
    {
        setLCDPrint(2, DISPLAY_POSITION_LEFT, "CARD NO: ");
        memset(bDisplayStr, 0x00, sizeof(bDisplayStr));
        strcpy(bDisplayStr, srTransRec.szPAN);
        CTOS_LCDTPrintXY(MAX_CHAR_PER_LINE-strlen(bDisplayStr)*2, 3, bDisplayStr);
        setLCDPrint(5, DISPLAY_POSITION_LEFT, "EXPIRY DATE(MM/YY):");

        memset(bDisplayStr, 0x00, sizeof(bDisplayStr));
        memset(bBuf, 0x00, sizeof(bBuf));
        wub_hex_2_str(&srTransRec.szExpireDate[1], &bBuf[0], 1);
        memcpy(bDisplayStr, bBuf, 2);
        bDisplayStr[2] = '/';
        memset(bBuf, 0x00, sizeof(bBuf));
        wub_hex_2_str(&srTransRec.szExpireDate[0], &bBuf[0], 1);
        memcpy(bDisplayStr+3, bBuf, 2);
        CTOS_LCDTPrintXY(MAX_CHAR_PER_LINE-strlen(bDisplayStr)*2, 6, bDisplayStr);
    }
    else
    {
    	if (1 != inCTOSS_GetWaveTransType())
        	inCTOS_DisplayCardTitle(4, 5);
    }
*/
//gcitra
    
    CTOS_KBDHit(&key);//clear key buffer

	inHDTReadData(38);//Use the Currency Symbol of BDO REG
	inCSTRead(strHDT_Temp.inCurrencyIdx);

    memset(szDisplayBuf, 0x00, sizeof(szDisplayBuf));
    sprintf(szDisplayBuf, "%s", strCST.szCurSymbol);
    //CTOS_LCDTPrintXY(1, 7, "AMOUNT:");

//gcitra-0728
	if(d_OK == inCTOS_ValidFirstIdleKey())
		bFirstKey = chGetFirstIdleKey();
	else
		bFirstKey = 0x00;
//gcitra-0728


INPUT_AGAIN:

    //vdDispTitleString("INSTALLMENT");//aaronnino for BDOCLG ver 9.0 fix on issue #00072 Incorrrect transaction type displayed for INSTALLMENT 2 of 2
	vdDispTransTitle(srTransRec.byTransType);
	CTOS_LCDTPrintXY(1, 7, "AMOUNT:");

    memset(baAmount, 0x00, sizeof(baAmount));
//gcitra-0728
    //key = InputAmount(1, 8, szDisplayBuf, 2, 0x00, baAmount, &ulAmount, d_INPUT_TIMEOUT, 0);
	//key = InputAmount2(1, 8, szDisplayBuf, 2, bFirstKey, baAmount, &ulAmount, d_INPUT_TIMEOUT, 0);
	key = InputAmount2(1, 8, szDisplayBuf, 2, bFirstKey, baAmount, &ulAmount, inGetIdleTimeOut(FALSE), 0); /*BDO: Parameterized idle timeout --sidumili*/
//gcitra-0728

    if(d_OK == key)
    {
        
        memset(szTemp, 0x00, sizeof(szTemp));
		// patrick add code 20141216
        sprintf(szTemp, "%012.0f", atof(baAmount));
        wub_str_2_hex(szTemp,srTransRec.szBaseAmount,12);

#if 1
		//Installment: checking for minimum installment amount - end -- jzg
		if(srTransRec.byTransType == SALE)
		{
            //issue-00412 change to support amount more than 21,474,836.47
			double amt1=0, amt2=0;	
			//long amt1=0, amt2=0;	
	
			//inTCTRead(1); - remove - advice by ST
  
            //issue-00412 change to support amount more than 21,474,836.47
			//amt1 = wub_str_2_long(baAmount);
			//amt2 = wub_str_2_long(strTCT.szMinInstAmt);
			amt1 = wub_str_2_doble(baAmount);
			amt2 = wub_str_2_doble(strTCT.szMinInstAmt);
			dbAmt3 = strtod(strTCT.szMaxInstAmt, &strPTR);
		
			if(amt1 < amt2)
			{
				char szMinInstAmt[13] = {0};
	
				memset(szMinInstAmt, 0x00, sizeof(szMinInstAmt));
				vdFormatAmount(szMinInstAmt, "", strTCT.szMinInstAmt, FALSE);
				memset(szTemp, 0x00, sizeof(szTemp));
				sprintf(szTemp,"MIN AMOUNT %s", szMinInstAmt);
	
				CTOS_LCDTClearDisplay();
				vdDisplayErrorMsg(1, 8, szTemp);
				vduiWarningSound();
				CTOS_Delay(1000);
				goto INPUT_AGAIN;
				//return -1;	
			}
			
			if(amt1 > dbAmt3)
				{
					char szMaxInstAmt[13] = {0};
			    
					memset(szMaxInstAmt, 0x00, sizeof(szMaxInstAmt));
					vdFormatAmount(szMaxInstAmt, "", strTCT.szMaxInstAmt, FALSE);
					memset(szTemp, 0x00, sizeof(szTemp));
					//sprintf(szTemp,"MAX AMOUNT %s", szMaxInstAmt);
					strcpy(szTemp, "OUT OF RANGE");
			
					CTOS_LCDTClearDisplay();
					vdDisplayErrorMsg(1, 8, szTemp);
					vduiWarningSound();
					CTOS_Delay(1000);
					goto INPUT_AGAIN;
					return d_NO;	
				}
		}
	//Installment: checking for minimum installment amount - end -- jzg
#endif


    }
    if(0xFF == key)
    {
        vdSetErrorMessage("TIME OUT");
        return d_NO;
    }

	if (d_USER_CANCEL == key){

			/* BDO CLG: Fleet card support - start -- jzg */
			//if(srTransRec.fFleetCard == TRUE)
			//	vdDispTransTitle(FLEET_SALE);
			//else
			/* BDO CLG: Fleet card support - end -- jzg */	
				vdDispTransTitle(srTransRec.byTransType);
			
			vdSetErrorMessage("Amt entry cancelled");
			return d_NO;
	}

	
    return key;
}



//gcitra

int inCTOS_GetTxnTipAmount(void)
{
    char szDisplayBuf[30];
    BYTE key;
    BYTE szTemp[20];
    BYTE baAmount[20];
    BYTE baBaseAmount[20];
    BYTE bBuf[4+1];
    BYTE bDisplayStr[MAX_CHAR_PER_LINE+1];
    ULONG ulAmount = 0L;

//gcitra
    BYTE szBaseAmount[12+1];
	BYTE szStr[45];
//gcitra

    DebugAddSTR("inCTOS_GetTxnTipAmount","Processing...       ",20);

	//gcitra
	if (inMultiAP_CheckSubAPStatus() == d_OK)
		return d_OK;
	//gcitra	

    if (d_OK != inCTOS_CheckTipAllowd())
        return d_OK;

	if (1 == inCTOSS_GetWaveTransType())
	if (inMultiAP_CheckSubAPStatus() == d_OK)
        return d_OK;
    
    memset(baBaseAmount, 0x00, sizeof(baBaseAmount));
    wub_hex_2_str(srTransRec.szBaseAmount, baBaseAmount, 6);

    memset(szDisplayBuf, 0x00, sizeof(szDisplayBuf));
    sprintf(szDisplayBuf, "%s", strCST.szCurSymbol);
        
    do
    {
        CTOS_LCDTClearDisplay();
        vdDispTransTitle(srTransRec.byTransType);

//gcitra - remove card display
/*

        if(CARD_ENTRY_MANUAL == srTransRec.byEntryMode)
        {
            setLCDPrint(2, DISPLAY_POSITION_LEFT, "CARD NO: ");
            memset(bDisplayStr, 0x00, sizeof(bDisplayStr));
            strcpy(bDisplayStr, srTransRec.szPAN);
            CTOS_LCDTPrintXY(MAX_CHAR_PER_LINE-strlen(bDisplayStr)*2, 3, bDisplayStr);
            setLCDPrint(5, DISPLAY_POSITION_LEFT, "EXPIRY DATE(MM/YY):");

            memset(bDisplayStr, 0x00, sizeof(bDisplayStr));
            memset(bBuf, 0x00, sizeof(bBuf));
            wub_hex_2_str(&srTransRec.szExpireDate[1], &bBuf[0], 1);
            memcpy(bDisplayStr, bBuf, 2);
            bDisplayStr[2] = '/';
            memset(bBuf, 0x00, sizeof(bBuf));
            wub_hex_2_str(&srTransRec.szExpireDate[0], &bBuf[0], 1);
            memcpy(bDisplayStr+3, bBuf, 2);
            CTOS_LCDTPrintXY(MAX_CHAR_PER_LINE-strlen(bDisplayStr)*2, 6, bDisplayStr);
        }
        else
        {
        	if (1 != inCTOSS_GetWaveTransType())
            	inCTOS_DisplayCardTitle(4, 5);
        }
*/
//gcitra
        CTOS_KBDHit(&key);//clear key buffer



//gcitra - display Base amount during TIP prompt
		CTOS_LCDTPrintXY(1, 4, "AMOUNT:");

		memset(szBaseAmount,0x00,sizeof(szBaseAmount));

		wub_hex_2_str(srTransRec.szBaseAmount, szBaseAmount, AMT_BCD_SIZE);		
		memset(szStr, 0x00, sizeof(szStr));
		sprintf(szStr, "%lu.%02lu", atol(szBaseAmount)/100, atol(szBaseAmount)%100);
		setLCDPrint(5, DISPLAY_POSITION_LEFT, strCST.szCurSymbol);
		CTOS_LCDTPrintXY(MAX_CHAR_PER_LINE-(strlen(szStr)+1)*2,  5, szStr);
//gcitra

		
        CTOS_LCDTPrintXY(1, 7, "TIP:");

        memset(baAmount, 0x00, sizeof(baAmount));
        //key = InputAmount2(1, 8, szDisplayBuf, 2, 0x00, baAmount, &ulAmount, d_INPUT_TIMEOUT, 1);
        key = InputAmount2(1, 8, szDisplayBuf, 2, 0x00, baAmount, &ulAmount, inGetIdleTimeOut(FALSE), 1); /*BDO: Parameterized idle timeout --sidumili*/

        if(d_OK == key)
        {
        
            if(0 == strlen(baAmount)) //by pass TIP
                return d_OK;
            
            memset(szTemp, 0x00, sizeof(szTemp));
			// patrick add code 20141216
            sprintf(szTemp, "%012.0f", atof(baAmount));
            if(strcmp(szTemp, baBaseAmount) > 0)
            {
                clearLine(8);
                vdDisplayErrorMsg(1, 8, "TOO MUCH TIP");
                clearLine(8);
                continue;
            }
            
            wub_str_2_hex(szTemp,srTransRec.szTipAmount,12);
            
            break;
        }
        else if(d_USER_CANCEL == key)
        {   
            clearLine(8);
            vdSetErrorMessage("USER CANCEL");
            clearLine(8);
            return d_NO;
        }
        else if(0xFF == key)
        {   
            clearLine(8);
            vdSetErrorMessage("TIME OUT");
            clearLine(8);
            return d_NO;
        }
        
        
    }while(1);
    
    return key;
}


int inCTOS_GetTipAfjustAmount(void)
{
	char szDisplayBuf[30] = {0};
	BYTE szTemp[20] = {0};
	BYTE szTempTipBuffer[20] = {0};
	BYTE baAmount[20] = {0};
	BYTE baBaseAmount[20] = {0};
	BYTE baTipAmount[20] = {0};
	ULONG ulAmount = 0L;
	BYTE szAmtTmp2[16+1] = {0};
	char szAmt[20 + 1] = {0};
	BYTE key = 0;
    int inLength=0;
    BYTE szDCCFXRate[9+1]; /*DCC Exchange Rate*/
    float dbTipAmount;
		
	DebugAddSTR("inCTOS_GetTipAfjustAmount","Processing...       ",20);
	memset(baBaseAmount, 0x00, sizeof(baBaseAmount));
	wub_hex_2_str(srTransRec.szBaseAmount, baBaseAmount, 6);

	memset(baTipAmount, 0x00, sizeof(baTipAmount));
	memset(szAmtTmp2, 0x00, sizeof(szAmtTmp2));
	wub_hex_2_str(srTransRec.szTipAmount, baTipAmount, 6);

	memset(szDisplayBuf, 0x00, sizeof(szDisplayBuf));
	sprintf(szDisplayBuf, "%s", strCST.szCurSymbol);

	CTOS_LCDTClearDisplay();
	vdDispTransTitle(srTransRec.byTransType);

	memset(szAmtTmp2, 0x00, sizeof(szAmtTmp2));
	//format amount 10+2
	//vdCTOS_FormatAmount(strCST.szAmountFormat, baTipAmount, szAmtTmp2);
	
	if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
	   vdDCCModifyAmount(baTipAmount,&szAmtTmp2); //vdDCCModifyAmount(&szAmtBuff);
    else	   
       vdCTOS_FormatAmount(strCST.szAmountFormat, baTipAmount,szAmtTmp2);
	
	setLCDPrint(5, DISPLAY_POSITION_LEFT, "ORG TIP");
	setLCDPrint(6, DISPLAY_POSITION_LEFT, szDisplayBuf);
	//CTOS_LCDTPrintXY(MAX_CHAR_PER_LINE-(strlen(szAmtTmp2)+1)*2,  6, szAmtTmp2);

	
	CTOS_LCDTPrintXY((MAX_CHAR_PER_LINE - 1)-(strlen(szAmtTmp2)+1)*2,  6, szAmtTmp2);

	CTOS_LCDTPrintXY(1, 7, "TIP");

	do
	{
		CTOS_KBDHit(&key);//clear key buffer

		memset(baAmount, 0x00, sizeof(baAmount));
		//key = InputAmount2(1, 8, szDisplayBuf, 2, 0x00, baAmount, &ulAmount, d_INPUT_TIMEOUT, 1);
		key = InputAmount2(1, 8, szDisplayBuf, 2, 0x00, baAmount, &ulAmount, inGetIdleTimeOut(FALSE), 1); /*BDO: Parameterized idle timeout --sidumili*/

		if(strlen(baAmount) > 0)
		{
			
			memset(szTemp, 0x00, sizeof(szTemp));

			sprintf(szTemp, "%012.0f", atof(baAmount));
			
			memset(szTempTipBuffer,0x00,sizeof(szTempTipBuffer));
			strcpy(szTempTipBuffer,szTemp);
			
			//gcitra
			memset(szAmt, 0x00, sizeof(szAmt));
			inComputePercent((long )strTCT.lnTipPercent, szAmt, atol(baBaseAmount), 2);
			//gcitra

			if(strCST.inMinorUnit != 2)
				vdFormatDCCTipAmt(szTemp);

			if(atol(szTemp) <= 0 && strCST.inMinorUnit == 0)
			{
				clearLine(8);
				vdDisplayErrorMsg(1, 8, "ENTER 1.00 AND ABOVE");
				clearLine(8);
				continue;
			}
			
			vdDebug_LogPrintf("AMOUNT = %s : TIP = %s",szAmt,szTemp);

			if(strcmp(szTemp, szAmt) > 0) 
			{
				clearLine(8);
				vdDisplayErrorMsg(1, 8, "TOO MUCH TIP");
				clearLine(8);
				continue;
			}
			
            wub_str_2_hex(szTemp,srTransRec.szTipAmount,12);
			if(srTransRec.fDCC == TRUE)
			{
                memset(szDCCFXRate, 0, sizeof(szDCCFXRate));
                inLength=strlen(srTransRec.szDCCFXRate)-srTransRec.inDCCFXRateMU;
                memcpy(szDCCFXRate,srTransRec.szDCCFXRate,inLength);
                memcpy(&szDCCFXRate[inLength],".",1);
                memcpy(&szDCCFXRate[inLength+1],&srTransRec.szDCCFXRate[inLength],srTransRec.inDCCFXRateMU);

				//if(strCST.inMinorUnit == 3)
					//vdRightShiftAmount(1,szTemp);

				//if(strCST.inMinorUnit == 0)
					//vdLeftShiftAmout(2,szTemp);
				
				dbTipAmount=(atof(szTempTipBuffer)*(1/atof(szDCCFXRate)));

				
				memset(szTemp, 0, sizeof(szTemp));
				sprintf(szTemp, "%012.0f", dbTipAmount);
				//vdDebug_LogPrintf("3. dbTipAmount = %s",szTemp);

                //vdDebug_LogPrintf("dbTipAmount = %f",dbTipAmount);
				//vdDebug_LogPrintf("atof(szTemp) = %f",atof(szTemp));
#if 0
                if(atof(szTemp) == 0)
                {
                    memset(szAmt, 0, sizeof(szAmt));
                    sprintf(szAmt, "%013.02f", dbTipAmount);
                    //vdDebug_LogPrintf("1. dbTipAmount = %s",szAmt);
                    
                    memset(szTemp, 0, sizeof(szTemp));
                    memcpy(szTemp, szAmt, 10);
                    memcpy(&szTemp[10], &szAmt[11], 2);
                    
                    //vdDebug_LogPrintf("2. dbTipAmount = %s", szTemp);
                }		
#endif
				wub_str_2_hex(szTemp, srTransRec.szDCCLocalTipAmount,12);
			}
		    		
 			break;
		}
		else if(d_USER_CANCEL == key)
		{   
			vdSetErrorMessage("USER CANCEL");
			return d_NO;
		}
		else if(0xFF == key)
		{   
			vdSetErrorMessage("TIME OUT");
			return d_NO;
		}

	}
	while(1);

	return key;
}



int inCTOS_UpdateTxnTotalAmount(void)
{
    BYTE szBaseAmount[20];
    BYTE szTipAmount[20];
    BYTE szTotalAmount[20];
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];
    BYTE  byDataTmp1[32];
    BYTE  byDataTmp2[32];
    BYTE  bPackSendBuf[256];
    USHORT usPackSendLen = 0;
    USHORT ushEMVtagLen;
    ULONG lnTmp;


	//gcitra-0806
		if (inMultiAP_CheckSubAPStatus() == d_OK)
		   return d_OK;
	//gcitra-0806	

    memset(szBaseAmount, 0x00, sizeof(szBaseAmount));
    memset(szTipAmount, 0x00, sizeof(szTipAmount));
    memset(szTotalAmount, 0x00, sizeof(szTotalAmount));

    wub_hex_2_str(srTransRec.szTipAmount, szTipAmount, 6);
    wub_hex_2_str(srTransRec.szBaseAmount, szBaseAmount, 6);

	// patrick fix code 20141216
    sprintf(szTotalAmount, "%012.0f", atof(szBaseAmount) + atof(szTipAmount));
    wub_str_2_hex(szTotalAmount,srTransRec.szTotalAmount,12);
    
    DebugAddSTR(szTotalAmount,szTipAmount,12); 
    DebugAddSTR("Total amount","Tip amount",12); 
    
    DebugAddHEX("Tip amount",srTransRec.szTipAmount,6); 
    DebugAddHEX("Total amount",srTransRec.szTotalAmount,6); 

    //if(CARD_ENTRY_ICC == srTransRec.byEntryMode)
	if (((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||
		(1 == inCTOSS_GetWaveTransType())))
	/*		
	(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
	(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
	(srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
	(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC)))
	/* EMV: Revised EMV details printing - end -- jzg */ // patrick fix contactless 20140828
    {
        memset(byDataTmp1, 0x00, sizeof(byDataTmp1));
        memset(byDataTmp2, 0x00, sizeof(byDataTmp2));
        wub_hex_2_str(srTransRec.szTotalAmount, byDataTmp1, 6);
        lnTmp = atol(byDataTmp1);
        wub_long_2_array(lnTmp, byDataTmp2);

        memcpy(&bPackSendBuf[usPackSendLen++], "\x81", 1);
        bPackSendBuf[usPackSendLen++] = 0x04;
        memcpy(&bPackSendBuf[usPackSendLen], byDataTmp2, 4);
        usPackSendLen += 4;

		if( (srTransRec.byTransType == SALE_TIP || srTransRec.byTransType == SALE_ADJUST) && srTransRec.byPackType == SALE)
			memcpy(srTransRec.stEMVinfo.T9F02, srTransRec.szBaseAmount, 6);
		else	
	        memcpy(srTransRec.stEMVinfo.T9F02, srTransRec.szTotalAmount, 6);
	        
	        memcpy(&bPackSendBuf[usPackSendLen], "\x9F\x02", 2);
	        usPackSendLen += 2;
	        bPackSendBuf[usPackSendLen++] = 0x06;
	        memcpy(&bPackSendBuf[usPackSendLen], srTransRec.stEMVinfo.T9F02, 6);
	        usPackSendLen += 6;
		
		
        if(atol(szTipAmount) > 0)
        {
            memcpy(srTransRec.stEMVinfo.T9F03, srTransRec.szTipAmount, 6);
        }
        else
        {
            memset(szTipAmount, 0x00, sizeof(szTipAmount));
            memcpy(srTransRec.stEMVinfo.T9F03, szTipAmount, 6);
        }

        memcpy(&bPackSendBuf[usPackSendLen], "\x9F\x03", 2);
        usPackSendLen += 2;
        bPackSendBuf[usPackSendLen++] = 0x06;
        memcpy(&bPackSendBuf[usPackSendLen], srTransRec.stEMVinfo.T9F03, 6);
        usPackSendLen += 6;

        usCTOSS_EMV_MultiDataSet(usPackSendLen, bPackSendBuf);
    }
    
    return d_OK;
}



int inCTOS_GetOffApproveNO(void)
{
    USHORT usX =1, usY = 6;
    BYTE bShowAttr = 0x02; 
    USHORT szAuthCodeLen = 6;
    BYTE baPIN[6 + 1];
    BYTE   szAuthCode[6+1];
    BYTE bRet;


    memset(szAuthCode, 0x00, sizeof(szAuthCode));


    CTOS_LCDTClearDisplay();
    vdDispTransTitle(srTransRec.byTransType);
    setLCDPrint(5, DISPLAY_POSITION_LEFT, "ENTER APPROVAL CODE: ");

    while(TRUE)
    {
        vduiClearBelow(8);
        bRet = InputStringAlpha2(1, 8, 0x00, 0x02, szAuthCode, &szAuthCodeLen, 1, d_INPUT_TIMEOUT);

        if (bRet == d_KBD_CANCEL )
        {
            CTOS_LCDTClearDisplay();    
            vdDisplayErrorMsg(1, 8, "USER CANCEL");
            return (d_EDM_USER_CANCEL);
        }

        if(strlen(szAuthCode) >= 6)
        {
            strcpy(srTransRec.szAuthCode, szAuthCode);
            break;
        }
        else
        {
            memset(szAuthCode, 0x00, sizeof(szAuthCode));
            szAuthCodeLen = 6;
            vdDisplayErrorMsg(1, 8, "INVALID INPUT");
        }
    }

    return ST_SUCCESS;
}

int inCTOS_GetInvoice(void)
{

    BYTE key;
    USHORT usX =1, usY = 6;
    BYTE baString[100+1];
    USHORT iStrLen = 6;
    BYTE bShowAttr = 0x02; 
    USHORT usInvoiceLen = 6;
    BYTE baPIN[6 + 1];
    BYTE   szInvNoAsc[6+1];
    BYTE   szInvNoBcd[3];
    BYTE bRet;
    int iLens = 6;
    int  inResult;
    char szBcd[INVOICE_BCD_SIZE+1];
    
    TRANS_DATA_TABLE srTransRecTemp;
    
    DebugAddSTR("inCTOS_GetInvoice","Processing...",20);

	vdDebug_LogPrintf("inCTOS_GetInvoice START [%d]", strTCT.fManualEntryInv);
	
    if (!strTCT.fManualEntryInv)
    {
       	vdDebug_LogPrintf("inCTOS_GetInvoice 1");
        memset(szBcd, 0x00, sizeof(szBcd));
        memcpy(szBcd, strTCT.szInvoiceNo, INVOICE_BCD_SIZE);    
        inBcdAddOne(szBcd, strTCT.szInvoiceNo, INVOICE_BCD_SIZE);
        
        if((inResult = inTCTSave(1)) != ST_SUCCESS)
        {
        	vdDebug_LogPrintf("get inv load tct error");
            vdSetErrorMessage("LOAD TCT ERR");
            return ST_ERROR;
        }

        memcpy(srTransRec.szInvoiceNo,strTCT.szInvoiceNo, 3);
		vdDebug_LogPrintf("inCTOS_GetInvoice invoice num %x%x%x",srTransRec.szInvoiceNo[0], srTransRec.szInvoiceNo[1],srTransRec.szInvoiceNo[2]);

    }
    else
    {
        vdDebug_LogPrintf("inCTOS_GetInvoice 2");

        memset(szInvNoAsc, 0x00, sizeof(szInvNoAsc));
        memset(szInvNoBcd, 0x00, sizeof(szInvNoBcd));
        
        memset((char*)&srTransRecTemp, 0x00, sizeof(TRANS_DATA_TABLE));
        memcpy(&srTransRecTemp, &srTransRec, sizeof(TRANS_DATA_TABLE));
        
        while(TRUE)
        {
            vdDebug_LogPrintf("inCTOS_GetInvoice 3");

            if (strTCT.fECR) // tct
            {
                			
                //If ECR send INV
                if (memcmp(srTransRec.szInvoiceNo, "\x00\x00\x00", 3) != 0)
                {                    
                    inResult = inCTOSS_BatchCheckDuplicateInvoice();
                    vdDebug_LogPrintf("inCTOSS_BatchCheckDuplicateInvoice[%d]", inResult);
                    
                    memcpy(&srTransRec, &srTransRecTemp, sizeof(TRANS_DATA_TABLE));
                    if (d_OK == inResult)
                    {
                        CTOS_LCDTClearDisplay();    
                        vdDisplayErrorMsg(1, 8, "DUPLICATE INVOICE");

                        return (d_NO);
                    }
                    else
                    {
                        return (d_OK);
                    }
                }
            }

			vdDebug_LogPrintf("inCTOS_GetInvoice 4");

            CTOS_LCDTClearDisplay();

						/* BDO CLG: Fleet card support - start -- jzg */
						//if(srTransRec.fFleetCard == TRUE)
						//	vdDispTransTitle(FLEET_SALE);
						//else
						/* BDO CLG: Fleet card support - end -- jzg */	
	            vdDispTransTitle(srTransRecTemp.byTransType);
						
            setLCDPrint(5, DISPLAY_POSITION_LEFT, "Invoice No: ");

            bRet = InputString(usX, usY, 0x00, bShowAttr, szInvNoAsc, &usInvoiceLen, 1, d_GETPIN_TIMEOUT);
            if (bRet == d_KBD_CANCEL )
            {
                CTOS_LCDTClearDisplay();    
                vdSetErrorMessage("USER CANCEL");
                memcpy(&srTransRec, &srTransRecTemp, sizeof(TRANS_DATA_TABLE));
                return (d_EDM_USER_CANCEL);
            }
            
            vdDebug_LogPrintf("inCTOS_GetInvoice 5");

            if(atoi(szInvNoAsc) != 0)
            {
                vdDebug_LogPrintf("inCTOS_GetInvoice 6");

                inAscii2Bcd(szInvNoAsc, szInvNoBcd, INVOICE_BCD_SIZE);
        
                memcpy(srTransRec.szInvoiceNo,szInvNoBcd,3);
                inResult = inCTOSS_BatchCheckDuplicateInvoice();
                vdDebug_LogPrintf("inCTOSS_BatchCheckDuplicateInvoice[%d]", inResult);
                if (d_OK == inResult)
                {
                    vdDebug_LogPrintf("inCTOS_GetInvoice 7");

                    CTOS_LCDTClearDisplay();    
                    vdDisplayErrorMsg(1, 8, "DUPLICATE INVOICE");
                    memset(szInvNoAsc, 0x00, sizeof(szInvNoAsc));
                    usInvoiceLen = 6;

                    memset(srTransRec.szInvoiceNo, 0x00, sizeof(srTransRec.szInvoiceNo));
                    continue;
                }
                else
                {
                    vdDebug_LogPrintf("inCTOS_GetInvoice 8");

                    break;
                }
            }       
        }   

        memcpy(&srTransRec, &srTransRecTemp, sizeof(TRANS_DATA_TABLE));
        memcpy(srTransRec.szInvoiceNo,szInvNoBcd,3);
    }
    
    return (d_OK);
}

VS_BOOL fAmountLessThanFloorLimit(void) 
{
    long lnTotalAmount = 0;
    BYTE   szTotalAmt[12+1];
    
    /* If the transaction amount is less than the floor limit,
        Set the transaction type to OFFLINE */

    wub_hex_2_str(srTransRec.szTotalAmount, szTotalAmt, AMT_BCD_SIZE);      
    lnTotalAmount = atol(szTotalAmt);
    
    if (lnTotalAmount < strCDT.InFloorLimitAmount)
        return(d_OK);

    return(d_NO);
}

int inCTOS_CustComputeAndDispTotal(void)
{
    CTOS_RTC SetRTC;
    BYTE    szTotalAmt[12+1];
    BYTE    szTempBuf[12+1];
    BYTE    szTempBuf1[12+1]; 
    BYTE    szDisplayBuf[30];
    BYTE    szStr[45];

	//gcitra
	if (inMultiAP_CheckSubAPStatus() == d_OK)
		return d_OK;
	//gcitra	

	
    CTOS_LCDTClearDisplay();
    vdDispTransTitle(srTransRec.byTransType);

    CTOS_LCDTPrintXY(1, 5, "TOTAL AMOUNT :");

    wub_hex_2_str(srTransRec.szTotalAmount, szTotalAmt, AMT_BCD_SIZE);      
    memset(szStr, 0x00, sizeof(szStr));
	
	//format amount 10+2
	vdCTOS_FormatAmount(strCST.szAmountFormat, szTotalAmt, szStr);
	//sprintf(szStr,"%10.0f.%02.0f",(atof(szTotalAmt)/100), (atof(szTotalAmt)%100));
    //sprintf(szStr, "%lu.%02lu", atol(szTotalAmt)/100, atol(szTotalAmt)%100);
    setLCDPrint(6, DISPLAY_POSITION_LEFT, strCST.szCurSymbol);
    CTOS_LCDTPrintXY(MAX_CHAR_PER_LINE-(strlen(szStr)+1)*2,  6, szStr);
            
    if(srTransRec.byEntryMode == CARD_ENTRY_ICC)
    {
        return (d_OK);
    }

	//if ((srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||
	if ((srTransRec.bWaveSID == 0x65) ||
	(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
	(srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
	(srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
	//(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_2) ||
	(srTransRec.bWaveSID == 0x63) ||
	(srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS) ||
	(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC))
	
	
	/* EMV: Revised EMV details printing - end -- jzg */ // patrick fix contactless 20140828
    {
        return (d_OK);
    }
    if(srTransRec.byTransType != SALE)
    {
        return (d_OK);
    }
    
    if (fAmountLessThanFloorLimit() == d_OK)
    {
        srTransRec.shTransResult = TRANS_AUTHORIZED;
        srTransRec.byOffline = CN_TRUE;

        //Read the date and the time //
        CTOS_RTCGet(&SetRTC);  
        /* Set Month & Day*/
        memset(szTempBuf,0,sizeof(szTempBuf));
        sprintf(szTempBuf,"%02d%02d",SetRTC.bMonth,SetRTC.bDay);
        wub_str_2_hex(szTempBuf,srTransRec.szDate,4);
        sprintf(szTempBuf1,"%02d",SetRTC.bYear);
        memcpy(srTransRec.szYear,szTempBuf1,2);
        memset(szTempBuf,0,sizeof(szTempBuf));
        sprintf(szTempBuf,"%02d%02d%02d",SetRTC.bHour,SetRTC.bMinute,SetRTC.bSecond);
        wub_str_2_hex(szTempBuf,srTransRec.szTime,6);
    }

		
    return(d_OK);
}

//aaronnino for BDOCLG ver 9.0 fix on issue #00124 Terminal display according to response codes was not updated start 5 of 5
#if 0
int inCTOS_DisplayResponse(void)
{
    int inMsgid = atoi(srTransRec.szRespCode);
    int inHostIndex = srTransRec.HDTid;
    int inResult = 0;
    char szResponseCode[40];

    memset(szResponseCode, 0x00, sizeof(szResponseCode));
    vdDebug_LogPrintf("inMsgid[%d]inHostIndex[%d]szResponseCode[%s]", inMsgid, inHostIndex, szResponseCode);
    inMSGResponseCodeRead(szResponseCode, inMsgid, inHostIndex);  
    if(0 == strlen(szResponseCode) )
    {
        inMSGResponseCodeRead(szResponseCode, inMsgid, 1);
        if(0 != strlen(szResponseCode) )
            vdDisplayErrorMsg(1, 8, szResponseCode);
    }
    else
    {
        vdDisplayErrorMsg(1, 8, szResponseCode);
    }

    vdDebug_LogPrintf("inMsgid[%d]inHostIndex[%d]szResponseCode[%s]", inMsgid, inHostIndex, szResponseCode);
    return(d_OK);  
}
#else
int inCTOS_DisplayResponse(TRANS_DATA_TABLE *srTransPara)
{
    int inMsgid = atoi(srTransPara->szRespCode);
    int inHostIndex = srTransPara->HDTid;
    int inResult = 0;
    char szResponseCode[40], szResponseCode2[40], szResponseCode3[40];
	//version16
	int inRemaining=0;
		 CTOS_LCDTClearDisplay();

    memset(szResponseCode, 0x00, sizeof(szResponseCode));
		memset(szResponseCode2, 0x00, sizeof(szResponseCode2));
		memset(szResponseCode3, 0x00, sizeof(szResponseCode3));

        //version16
		if (srTransRec.HDTid == SMAC_HDT_INDEX && srTransRec.byTransType == SALE && fSmacScan == TRUE && strlen(szSMACScanResponsetext) > 0){
			 if (strlen(szSMACScanResponsetext) < 41){
			 	strcpy(szResponseCode, szSMACScanResponsetext );
			 }else{
			    memcpy(&szResponseCode[0], szSMACScanResponsetext, 40 );

				inRemaining = strlen(szSMACScanResponsetext)-40;
				memcpy(&szResponseCode2[40],&szSMACScanResponsetext[40], inRemaining );
			 }

		}


        inMSGResponseCodeRead(szResponseCode, szResponseCode2, szResponseCode3, inMsgid, 1);

        vdDebug_LogPrintf("inMsgid[%d]inHostIndex[%d]szResponseCode[%s]", inMsgid, inHostIndex, szResponseCode);
        vdDebug_LogPrintf("inMsgid[%d]inHostIndex[%d]szResponseCode2[%s]", inMsgid, inHostIndex, szResponseCode2);
        vdDebug_LogPrintf("inMsgid[%d]inHostIndex[%d]szResponseCode3[%s]", inMsgid, inHostIndex, szResponseCode3);

				vdDebug_LogPrintf("szResponseCode[%d]szResponseCode2[%d]szResponseCode3[%d]",strlen(szResponseCode),strlen(szResponseCode2),strlen(szResponseCode3));

				if((0 != strlen(szResponseCode)) && (0 != strlen(szResponseCode2)) && (0 != strlen(szResponseCode3)))
					{
               //vdDisplayErrorMsgResp(1, 1, 1, 6, 7, 8, szResponseCode, szResponseCode2, szResponseCode3); 
               vdDisplayErrorMsgResp2(szResponseCode, szResponseCode2, szResponseCode3);
					}
				if((0 != strlen(szResponseCode)) && (0 != strlen(szResponseCode2)) && (0 == strlen(szResponseCode3)))
					{
				       //vdDisplayErrorMsgResp(1, 1, 1, 6, 7, 8, " ", szResponseCode, szResponseCode2);
							 vdDisplayErrorMsgResp2(" ", szResponseCode, szResponseCode2);
					}
				if((0 != strlen(szResponseCode)) && (0 == strlen(szResponseCode2)) && (0 == strlen(szResponseCode3)))
					{
              //vdDisplayErrorMsgResp(1, 1, 1, 6, 7, 8, " ", " ", szResponseCode);	
              vdDisplayErrorMsgResp2(" ", " ", szResponseCode);
					}
			
     return(d_OK);  
}
#endif
//aaronnino for BDOCLG ver 9.0 fix on issue #00124 Terminal display according to response codes was not updated end 5 of 5


int inCTOS_GeneralGetInvoice(void)
{
    BYTE key;
    USHORT usX =1, usY = 6;
    BYTE baString[100+1];
    USHORT iStrLen = 6;
    BYTE bShowAttr = 0x02; 
    USHORT usInvoiceLen = 6;
    BYTE baPIN[6 + 1];
    BYTE   szInvNoAsc[6+1];
    BYTE   szInvNoBcd[3];
    BYTE bRet;
    int iLens = 6;
    int  inResult;
    char szBcd[INVOICE_BCD_SIZE+1];

    if (inMultiAP_CheckSubAPStatus() == d_OK)
    {
        return d_OK;
    }

//1010
     if (strTCT.fECR) // tct
     {   
// patrick fix code 20141208 ==if idle want void transaction and ecr flag on. this checking is illegal.  
//       if (memcmp(srTransRec.szInvoiceNo, "\x00\x00\x00", 3) != 0)
      //      return ST_SUCCESS;
      	if (fECRTxnFlg == 1)
      	{
           return ST_SUCCESS;
      	}
 
 
     }
//1010


    memset(szInvNoAsc, 0x00, sizeof(szInvNoAsc));
    memset(szInvNoBcd, 0x00, sizeof(szInvNoBcd));
    
    //CTOS_LCDTClearDisplay();
    vdDispTransTitle(srTransRec.byTransType);
	vdClearBelowLine(2);
    setLCDPrint(5, DISPLAY_POSITION_LEFT, "Invoice No: ");
    
    while(TRUE)
    {
        usInvoiceLen = 6;
        vdDebug_LogPrintf("11bRet[%d]atoi(szInvNoAsc)=[%d]usInvoiceLen[%d]",bRet,atoi(szInvNoAsc),usInvoiceLen);
//        bRet = InputString(usX, usY, 0x00, bShowAttr, szInvNoAsc, &usInvoiceLen, 1, d_GETPIN_TIMEOUT);

				/* BDO: Invoice number entry should not accept special characters -- jzg */
				bRet = InputString2(usX, usY, 0x00, bShowAttr, szInvNoAsc, &usInvoiceLen, 1, d_GETPIN_TIMEOUT);
        vdDebug_LogPrintf("bRet[%d]atoi(szInvNoAsc)=[%d]usInvoiceLen[%d]",bRet,atoi(szInvNoAsc),usInvoiceLen);
        if (bRet == d_KBD_CANCEL )
        {
            CTOS_LCDTClearDisplay();    
            vdSetErrorMessage("USER CANCEL");
            return (d_EDM_USER_CANCEL);
        }
        
        
        if(atoi(szInvNoAsc) != 0)
        {
            inAscii2Bcd(szInvNoAsc, szInvNoBcd, INVOICE_BCD_SIZE);
            DebugAddSTR("INV NUM:",szInvNoAsc,12);  
            memcpy(srTransRec.szInvoiceNo,szInvNoBcd,3);
            break;
        }       
    }

    return ST_SUCCESS;
}


int inCTOS_BatchSearch(void)
{
    int inResult = d_NO;

    inResult = inDatabase_BatchSearch(&srTransRec, srTransRec.szInvoiceNo);

    DebugAddSTR("inCTOS_BatchSearch","Processing...",20);
    
    DebugAddINT("inCTOS_BatchSearch", inResult);

    if(inResult != d_OK)
    {   
        if (inMultiAP_CheckSubAPStatus() != d_OK)
            //vdSetErrorMessage("NO RECORD FOUND");
            //vdDisplayErrorMsg(1, 8, "NO RECORD FOUND");
            vdDisplayErrorMsgResp2("","TRANSACTION","NOT FOUND");
        return d_NOT_RECORD;
    }
    
    memcpy(srTransRec.szOrgDate, srTransRec.szDate, 2);
    memcpy(srTransRec.szOrgTime, srTransRec.szTime, 2);
    
    return inResult;
}

int inCTOS_LoadCDTandIIT(void)
{
	inDatabase_TerminalOpenDatabase();
	
	if (inCDTReadEx(srTransRec.CDTid) != d_OK)
	{
        vdDebug_LogPrintf("inCTOS_LoadCDTandIIT LOAD CDT ERROR [%d]", srTransRec.CDTid);
		vdSetErrorMessage("LOAD CDT ERROR");
		inDatabase_TerminalCloseDatabase();
		return(d_NO);
    }

    //inGetIssuerRecord(strCDT.IITid);
	if (inIITReadEx(srTransRec.IITid) != d_OK)
	{
        vdDebug_LogPrintf("inCTOS_LoadCDTandIIT LOAD IIT ERROR [%d]", srTransRec.IITid);
		vdSetErrorMessage("LOAD IIT ERROR");
		inDatabase_TerminalCloseDatabase();
		return(d_NO);
    }

    inDatabase_TerminalCloseDatabase();
    return ST_SUCCESS;
}


int inCTOS_CheckTipadjust()
{

//do not allow tip on SMAC
    //if ((srTransRec.HDTid== SMAC_HDT_INDEX) || (srTransRec.HDTid == SMGUARANTOR_HDT_INDEX)){
    #if 0
	if (srTransRec.fDCC == TRUE)
	{
		//vdSetErrorMessage("TIP NOT ALLOWED");
		CTOS_LCDTClearDisplay();
		vdDisplayErrorMsgResp2(" ", "TRANSACTION", "NOT ALLOWED");
		return d_NO;
    }
    #endif
	if (inCheckIfSMCardTransRec() == TRUE)
	{
		//vdSetErrorMessage("TIP NOT ALLOWED");
		CTOS_LCDTClearDisplay();
		vdDisplayErrorMsgResp2(" ", "TRANSACTION", "NOT ALLOWED");
		return d_NO;
    }

//end


	if ((srTransRec.byTransType == SALE) || (srTransRec.byTransType == SALE_TIP) || (srTransRec.byTransType == SALE_OFFLINE))
	{
		if ((srTransRec.inNumOfAdjust >= strTCT.inMaxAdjust) && (strTCT.inMaxAdjust!=0))
		{	
		
			vdDisplayErrorMsg(1, 8, "EXCEED ADJ MAX");
			vdSetErrorMessage("ADJUST NOT ALLOWED");
			return d_NO;
		}
		if((srTransRec.byTransType == SALE) || (srTransRec.byTransType == SALE_OFFLINE))
			srTransRec.byOrgTransType = srTransRec.byTransType;
		
		memcpy(srTransRec.szOrgAmount, srTransRec.szTotalAmount, 6);
		srTransRec.inNumOfAdjust = srTransRec.inNumOfAdjust+1;
		if(srTransRec.fDCC)
		{
		    memcpy(srTransRec.szDCCOrigLocalTipAmount, srTransRec.szDCCLocalTipAmount, 6);	
		}
	}
	else
	{
		//vdSetErrorMessage("TIP NOT ALLOWED");
		CTOS_LCDTClearDisplay();
		vdDisplayErrorMsgResp2(" ", "TRANSACTION", "NOT ALLOWED");
		return d_NO;
	}

	srTransRec.byTransType = SALE_TIP;

	return d_OK;
}




int inCTOS_CheckVOID()
{
	vdDebug_LogPrintf("--inCTOS_CheckVOID--");
	vdDebug_LogPrintf("srTransRec.byTransType=[%d]", srTransRec.byTransType);

	if(srTransRec.byVoided == TRUE)
    {
        //vdSetErrorMessage("ALREADY VOIDED");
        vdDisplayErrorMsg(1, 8, "ALREADY VOIDED");
        return d_NO;
    }

//version16-allow void pre-auth
#if 0
    if(srTransRec.byTransType == PRE_AUTH)
    {
        //vdDisplayErrorMsg(1, 8, "VOID NOT ALLOWED"); 
        vdDisplayErrorMsgResp2("","TRANSACTION","NOT ALLOWED");
        return d_NO;
    }
#endif
//version16

	if(srTransRec.byTransType == SMAC_BALANCE)
    {
        //vdDisplayErrorMsg(1, 8, "VOID NOT ALLOWED"); 
        vdDisplayErrorMsgResp2("","TRANSACTION","NOT ALLOWED");
        return d_NO;
    }

	if(srTransRec.byTransType == BALANCE_INQUIRY)
    {
        //vdDisplayErrorMsg(1, 8, "VOID NOT ALLOWED"); 
        vdDisplayErrorMsgResp2("","TRANSACTION","NOT ALLOWED");
        return d_NO;
    }

    //to find the original transaction of the sale tip to be voided - Meena 26/12/12 - START
    if(srTransRec.byTransType == SALE_TIP)
    {
        szOriginTipTrType = srTransRec.byOrgTransType;
        srTransRec.byOrgTransType = srTransRec.byTransType;
    }
    else //to find the original transaction of the sale tip to be voided - Meena 26/12/12 - END
        srTransRec.byOrgTransType = srTransRec.byTransType;

	if(srTransRec.byTransType == KIT_SALE || srTransRec.byTransType == RENEWAL || srTransRec.byTransType == PTS_AWARDING)
    {
        //vdDisplayErrorMsg(1, 8, "VOID NOT ALLOWED"); 
        vdDisplayErrorMsgResp2("","TRANSACTION","NOT ALLOWED");
        return d_NO;
    }


	//version16
	vdDebug_LogPrintf("test trans type %d", srTransRec.byTransType);
	if (srTransRec.byTransType == PRE_AUTH)
		srTransRec.byTransType = VOID_PREAUTH;
	//version16
    else
		srTransRec.byTransType = VOID;

	vdDebug_LogPrintf("test trans type %d", srTransRec.byTransType);
	

    return d_OK;
}


int inCTOS_VoidSelectHost(void) 
{
    short shGroupId ;
    int inHostIndex;
    short shCommLink;
    int inCurrencyIdx=0;
	char szStr[16+1]={0};

    inHostIndex = (short) srTransRec.HDTid;
    
     DebugAddSTR("inCTOS_SelectHost","Processing...",20);
     
    if ( inHDTRead(inHostIndex) != d_OK)
    {
        //vdSetErrorMessage("HOST SELECTION ERR");
		inHDTReadData(inHostIndex);
		strcpy(szStr,strHDT_Temp.szHostLabel);
		memset(strHDT_Temp.szHostLabel,0x00,16+1);
		sprintf(strHDT_Temp.szHostLabel," %s ",szStr);
		vdDisplayErrorMsgResp2(strHDT_Temp.szHostLabel, "TRANSACTION", "NOT ALLOWED");
        return(d_NO);
    } 
    else 
    {
        
        srTransRec.HDTid = inHostIndex;

        inCurrencyIdx = strHDT.inCurrencyIdx;

        if (inCSTRead(inCurrencyIdx) != d_OK) {
            
        vdSetErrorMessage("LOAD CST ERR");
        return(d_NO);
        }

        if ( inMMTReadRecord(inHostIndex,srTransRec.MITid) != d_OK)
        {
            vdSetErrorMessage("LOAD MMT ERR");
            return(d_NO);
        }

        if ( inCPTRead(inHostIndex) != d_OK)
        {
            vdSetErrorMessage("LOAD CPT ERR");
            return(d_NO);
        }

        inCTOS_PreConnect();

        return (d_OK);
    }

    
}

int inCTOS_VoidSelectHostNoPreConnect(void) 
{
    short shGroupId ;
    int inHostIndex;
    short shCommLink;
    int inCurrencyIdx=0;
	char szStr[16+1]={0};

    inHostIndex = (short) srTransRec.HDTid;
    
     DebugAddSTR("inCTOS_SelectHost","Processing...",20);
	 
    inDatabase_TerminalOpenDatabase();
	
    if ( inHDTReadEx(inHostIndex) != d_OK)
    {
        //vdSetErrorMessage("HOST SELECTION ERR");
		inHDTReadDataEx(inHostIndex);
		strcpy(szStr,strHDT_Temp.szHostLabel);
		memset(strHDT_Temp.szHostLabel,0x00,16+1);
		sprintf(strHDT_Temp.szHostLabel," %s ",szStr);
		vdDisplayErrorMsgResp2(strHDT_Temp.szHostLabel, "TRANSACTION", "NOT ALLOWED");  
		inDatabase_TerminalCloseDatabase();
        return(d_NO);
    } 
    else 
    {
        
        srTransRec.HDTid = inHostIndex;

        inCurrencyIdx = strHDT.inCurrencyIdx;

        if (inCSTReadEx(inCurrencyIdx) != d_OK) {
            
        vdSetErrorMessage("LOAD CST ERR");
        return(d_NO);
		inDatabase_TerminalCloseDatabase();
        }

        if ( inMMTReadRecordEx(inHostIndex,srTransRec.MITid) != d_OK)
        {
            vdSetErrorMessage("LOAD MMT ERR");
			inDatabase_TerminalCloseDatabase();
            return(d_NO);
        }

		if (strTCT.fSingleComms)
		{	
			if(inCPTReadEx(1) != d_OK)
			{
				vdSetErrorMessage("LOAD CPT ERR");
				inDatabase_TerminalCloseDatabase();
				return(d_NO);
			}
		}
		else 
        {
			if(inCPTReadEx(inHostIndex) != d_OK)
			{
		        vdSetErrorMessage("LOAD CPT ERR");
				inDatabase_TerminalCloseDatabase();
		        return(d_NO);
			}
        }
        inDatabase_TerminalCloseDatabase();
        return (d_OK);
    }

    
}


int inCTOS_ChkBatchEmpty()
{
    int         inResult;
    //ACCUM_REC srAccumRec;
    //STRUCT_FILE_SETTING strFile;
    
    //memset(&srAccumRec,0,sizeof(srAccumRec));
    //memset(&strFile,0,sizeof(strFile));
    //memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
    //memset(&strFile,0,sizeof(strFile));
    //vdCTOS_GetAccumName(&strFile, &srAccumRec);

    //if((inResult = inMyFile_CheckFileExist(strFile.szFileName)) < 0)
    if(inBatchNumRecord() <= 0)
    {
        if(CN_TRUE == strMMT[0].fMustSettFlag)
        {
            strMMT[0].fMustSettFlag = CN_FALSE;
            inMMTSave(strMMT[0].MMTid);
        }
        
        CTOS_LCDTClearDisplay();
        //if (srTransRec.byTransType == SETTLE)  // sidumili: Issue#:000109 [Display hostname during settle all]
		if ((srTransRec.byTransType == SETTLE) && (gvSettleType==MULTI_SETTLE))  //aaa fix on issue #000210 Terminal displays "Batch empty, skip" on all hosts when trying to settle hosts with no transactions 2 of 6
			{
			   gblfBatchEmpty = TRUE;  //aaronnino for BDOCLG ver 9.0 fix on issue #0033 and #0034 "settle failed" error response after "comm error" 2 of 8
		     vdSetErrorMessage("EMPTY BATCH, SKIP");
			}

    	else
        vdSetErrorMessage("EMPTY BATCH                             ");
				
        return (d_NO);
    }
    
    return (d_OK);
}

//0722
int inCTOS_ChkBatchEmpty2()
{
    int         inResult;
    ACCUM_REC srAccumRec;
    STRUCT_FILE_SETTING strFile;
    
    memset(&srAccumRec,0,sizeof(srAccumRec));
    memset(&strFile,0,sizeof(strFile));
    memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
    memset(&strFile,0,sizeof(strFile));
    vdCTOS_GetAccumName(&strFile, &srAccumRec);

    if((inResult = inMyFile_CheckFileExist(strFile.szFileName)) < 0)
			return (d_NO);
		else	
    	return (d_OK);
}
//0722

int inCTOS_ConfirmInvAmt()
{
    BYTE szAmtTmp1[16+1];
    BYTE szAmtTmp2[16+1];
    char szDisplayBuf[30];
    BYTE   key;
    USHORT result;
		BYTE szTemp1[30+1];
		int inRemaining=0;
		BYTE szPAN1[20+1];
		BYTE szPAN2[20+1];
    
    CTOS_LCDTClearDisplay();

	//version16
    //vdDispTransTitle(srTransRec.byTransType);
	vdDispTransTitle(VOID);
	//version16
	
    memset(szDisplayBuf, 0x00, sizeof(szDisplayBuf));
    memset(szAmtTmp1, 0x00, sizeof(szAmtTmp1));
    memset(szAmtTmp2, 0x00, sizeof(szAmtTmp2));
    sprintf(szDisplayBuf, "%s", strCST.szCurSymbol);
    wub_hex_2_str(srTransRec.szTotalAmount, szAmtTmp1, 6);
	//format amount 10+2
	if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
		vdDCCModifyAmount(szAmtTmp1,szAmtTmp2); //vdDCCModifyAmount(&szAmtTmp2);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, szAmtTmp1, szAmtTmp2);
	
	//sprintf(szAmtTmp2,"%10.0f.%02.0f",(atof(szAmtTmp1)/100), (atof(szAmtTmp1)%100));
    //sprintf(szAmtTmp2, "%lu.%02lu", atol(szAmtTmp1)/100, atol(szAmtTmp1)%100);

//gcitra
    //CTOS_LCDTPrintXY(1, 5, "AMOUNT");
    //setLCDPrint(6, DISPLAY_POSITION_LEFT, szDisplayBuf);
    //CTOS_LCDTPrintXY(MAX_CHAR_PER_LINE-(strlen(szAmtTmp2)+1)*2,  6, szAmtTmp2);

    //version16 -  add preauth void
    if(srTransRec.byTransType == VOID || srTransRec.byTransType == VOID_PREAUTH)
    {
       memset(szTemp1,0,sizeof(szTemp1));
   		
       inIITRead(strCDT.IITid);
       if (strIIT.fMaskPanDisplay == TRUE)
   	   {
          vdCTOS_FormatPAN(strIIT.szPANFormat, srTransRec.szPAN, szTemp1);
          strcpy(szTemp1, srTransRec.szPAN);
          cardMasking(szTemp1, 5);		
       }
   	   else
   	   { 	
          vdCTOS_FormatPAN2(strTCT.DisplayPANFormat, srTransRec.szPAN, szTemp1);
       }	
		   if (strlen(szTemp1) > 20)
		   {
           memset(szPAN1, 0x00, sizeof(szPAN1));
           memset(szPAN2, 0x00, sizeof(szPAN2));
           inRemaining = strlen(szTemp1) - 20;
           
           memcpy(szPAN1, szTemp1, 20);
           memcpy(szPAN2, &szTemp1[20], inRemaining);
           CTOS_LCDTPrintXY(1, 3, szPAN1);
   		     CTOS_LCDTPrintXY(1, 4, szPAN2);
        }
    		else
            CTOS_LCDTPrintXY(1, 3, szTemp1);

		   CTOS_LCDTPrintXY(1, 5, "AMOUNT");
       setLCDPrint(6, DISPLAY_POSITION_LEFT, szDisplayBuf);
       CTOS_LCDTPrintXY(MAX_CHAR_PER_LINE-(strlen(szAmtTmp2)+2)*2,  6, szAmtTmp2);		

		}
    else
    {
       CTOS_LCDTPrintXY(1, 4, "AMOUNT");
       setLCDPrint(5, DISPLAY_POSITION_LEFT, szDisplayBuf);
       CTOS_LCDTPrintXY(MAX_CHAR_PER_LINE-(strlen(szAmtTmp2)+2)*2,  5, szAmtTmp2);
    }
//gcitra

    
    if(srTransRec.byTransType == SALE_TIP)
          setLCDPrint(7, DISPLAY_POSITION_CENTER,"CONFIRM TIP ADJUST");
	//version16
    if(srTransRec.byTransType == VOID || srTransRec.byTransType ==VOID_PREAUTH)
    {
       setLCDPrint(7, DISPLAY_POSITION_CENTER,"CONFIRM VOID");
       setLCDPrint(8, DISPLAY_POSITION_CENTER,"NO[X] YES[OK]");
    }
		else
			 setLCDPrint(8, DISPLAY_POSITION_CENTER,"NO[X] YES[OK]");
    
		CTOS_TimeOutSet(TIMER_ID_1, UI_TIMEOUT);
    vduiWarningSound();

    CTOS_KBDBufFlush();//cleare key buffer
    
    while(1)
    { 
        
        CTOS_KBDHit(&key);
        if(key == d_KBD_ENTER)
        {
            result = d_OK;
			vdClearBelowLine(2);
			vdCTOS_DispStatusMessage("PROCESSING...");  
            break;
        }
        else if((key == d_KBD_CANCEL))
        {
            result = d_NO;
            vdSetErrorMessage("USER CANCEL");
            break;
        }
        if(CTOS_TimeOutCheck(TIMER_ID_1) == d_YES)
        {
            result = d_NO;
            vdSetErrorMessage("TIME OUT");
            break;
        }       
    }
    
    return result;
}

int inCTOS_SettlementSelectAndLoadHost(void)
{
    int key;
    char szBcd[INVOICE_BCD_SIZE+1];
    
    if (inMultiAP_CheckSubAPStatus() == d_OK)
        return d_OK;
    
    //key = inCTOS_SelectHostSetting();
    
    key = inCTOS_SelectHostSettingWithIndicator(1);
    if (key == -1)
    {
        return key;
    }

    memset(szBcd, 0x00, sizeof(szBcd));
    memcpy(szBcd, strHDT.szTraceNo, INVOICE_BCD_SIZE);    
    //inBcdAddOne(szBcd, strHDT.szTraceNo, INVOICE_BCD_SIZE); /*sidumili: [fix on issue#: 000063]*/
    srTransRec.ulTraceNum = wub_bcd_2_long(strHDT.szTraceNo,3);
    inHDTSave(strHDT.inHostIndex);

    return d_OK;
}

int inCTOS_SettlementClearBathAndAccum(BOOL fManualSettlement)
{
    int         inResult;
    BYTE    szBcd[INVOICE_BCD_SIZE+1];
    ACCUM_REC srAccumRec;
    STRUCT_FILE_SETTING strFile;

    vdDebug_LogPrintf("inCTOS_SettlementClearBathAndAccum");
/*    
    memset(szBcd, 0x00, sizeof(szBcd));
    memcpy(szBcd, strMMT[0].szBatchNo, INVOICE_BCD_SIZE);    
    inBcdAddOne(szBcd, strMMT[0].szBatchNo, INVOICE_BCD_SIZE);
    strMMT[0].fMustSettFlag = CN_FALSE;
    inMMTSave(strMMT[0].MMTid);
*/        
    /*albert - start - 20161202 - Reprint of Detail Report for Last Settlement Report*/
    inDatabase_DeleteDetailReport(srTransRec.HDTid, srTransRec.MITid);
    inDatabase_BackupDetailReport(srTransRec.HDTid, srTransRec.MITid);
    /*albert - end - 20161202 - Reprint of Detail Report for Last Settlement Report*/
	
    inDatabase_BatchDelete();

    memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
    inCTOS_ReadAccumTotal(&srAccumRec);
    strcpy(srAccumRec.szTID, srTransRec.szTID);
    strcpy(srAccumRec.szMID, srTransRec.szMID);
    memcpy(srAccumRec.szYear, srTransRec.szYear, DATE_BCD_SIZE);
    memcpy(srAccumRec.szDate, srTransRec.szDate, DATE_BCD_SIZE);
    memcpy(srAccumRec.szTime, srTransRec.szTime, TIME_BCD_SIZE);
    memcpy(srAccumRec.szBatchNo, srTransRec.szBatchNo, BATCH_NO_BCD_SIZE);
		srAccumRec.fManualSettlement=fManualSettlement;
    inCTOS_SaveAccumTotal(&srAccumRec);
    
    memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
    memset(&strFile,0,sizeof(strFile));
    vdCTOS_GetAccumName(&strFile, &srAccumRec);
    vdDebug_LogPrintf("[strFile.szFileName[%s]", strFile.szFileName);
    vdCTOS_SetBackupAccumFile(strFile.szFileName);
    if((inResult = CTOS_FileDelete(strFile.szFileName)) != d_OK)
    {
        vdDebug_LogPrintf("[inMyFile_SettleRecordDelete]---Delete Record error[%04x]", inResult);
    }

    inDatabase_InvoiceNumDelete(srTransRec.HDTid, srTransRec.MITid);
    inMyFile_ReversalDelete();

    inMyFile_AdviceDelete();

    inMyFile_TCUploadDelete();

	//inMyFile_TransLogDelete();
    inDatabase_TransLogDelete(&srTransRec, DELETE_BY_HOSTID_MERCHID);
	
	  vdRenameISOLog();

    memset(szBcd, 0x00, sizeof(szBcd));
    memcpy(szBcd, strMMT[0].szBatchNo, INVOICE_BCD_SIZE);    
    inBcdAddOne(szBcd, strMMT[0].szBatchNo, INVOICE_BCD_SIZE);

	
	strMMT[0].fBatchNotEmpty = 0;	
	strMMT[0].fPendingReversal= 0;	
    strMMT[0].fMustSettFlag = CN_FALSE;
	strMMT[0].fPreAuthExisting = 0;
	strcpy(strMMT[0].szSettleDate,"00000000");// Reset Settle Date during clear batch
    inMMTSave(strMMT[0].MMTid);
	
    vdLinuxCommandClearERMBitmap(); /*albert - ERM*/
	vdLinuxCommandClearDCCPNG(); //Clear all DCC SignPad PNG files.
	//inDatabase_SMACFooterDeleteAll();
	inDatabase_SMACFooterDelete(srTransRec.HDTid, srTransRec.MITid);
	
    return d_OK;
}

int inCTOS_DisplayBatchTotal(void)
{
    int inResult;
    int inTranCardType;
    BYTE szDisplayBuf[40];
    BYTE szAmtBuf[40];
    BYTE szBuf[40];
    USHORT usSaleCount;
    double ulSaleTotalAmount;
    USHORT usRefundCount;
    ULONG  ulRefundTotalAmount;

//00415- add cash advance
	USHORT usCashAdvanceCount;
	double  ulCashAdvanceTotalAmount;



		//BDO UAT 0003: Changed batch totals from refund to void - start -- jzg
    USHORT usVoidCount;
    double ulVoidTotalAmount;
		//BDO UAT 0003: Changed batch totals from refund to void - end -- jzg
		
    ACCUM_REC srAccumRec;

    CTOS_LCDTClearDisplay();
    vdDispTransTitle(BATCH_TOTAL);
    
    memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
    if((inResult = inCTOS_ReadAccumTotal(&srAccumRec)) == ST_ERROR)
    {
        vdDebug_LogPrintf("[vdUpdateAmountTotal]---Read Total Rec. error");
        return ST_ERROR;    
    }

    //0 is for Credit type, 1 is for debit type

	if(srTransRec.HDTid == SMGUARANTOR_HDT_INDEX || srTransRec.HDTid == SMGIFTCARD_HDT_INDEX)
		inTranCardType = 1;
	else
	    inTranCardType = 0;

//issue-00298
    //usSaleCount = (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount);
    //usSaleCount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount; 
    usSaleCount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount;  /*BDO: Include CASH ADVANCE total --sidumili*/

	//ulSaleTotalAmount = (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount);
	ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount; /*BDO: Include CASH ADVANCE total --sidumili*/

    usRefundCount = (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount);
    ulRefundTotalAmount = (srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount);

    //00415 - add cash advance
    usCashAdvanceCount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount;
    ulCashAdvanceTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount;


		//BDO UAT 0003: Changed batch totals from refund to void - start -- jzg
    usVoidCount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount  + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount;
    ulVoidTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount;
		//BDO UAT 0003: Changed batch totals from refund to void - end -- jzg

		
	CTOS_LCDTSelectFontSize(d_FONT_12x24);
	//CTOS_LCDTSelectFontSize(d_FONT_16x30);
#if 0		
    memset(szDisplayBuf, 0x00, sizeof(szDisplayBuf));
    strcpy(szDisplayBuf, "Type      Cnt");
    CTOS_LCDTPrintXY(1, 3, szDisplayBuf);
    CTOS_LCDTPrintAligned(3, "Amt", d_LCD_ALIGNRIGHT);
#endif
	inCSTRead(strHDT.inCurrencyIdx);
	CTOS_LCDTPrintXY(1, 3, "TYPE         CNT                   AMT");
    memset(szDisplayBuf, 0x00, sizeof(szDisplayBuf));
    memset(szAmtBuf, 0x00, sizeof(szAmtBuf));
    memset(szBuf, 0x00, sizeof(szBuf));
    sprintf(szBuf, "%012.0f", ulSaleTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szBuf,szAmtBuf);
	else
	    vdCTOS_FormatAmount(strCST.szAmountFormat, szBuf,szAmtBuf);// patrick add code 20141216	

	memset(szBuf,0x00,sizeof(szBuf));
	sprintf(szBuf,"SALES:        %d",usSaleCount);
    sprintf(szDisplayBuf,"%s%s",strCST.szCurSymbol,szAmtBuf);
    //sprintf(szDisplayBuf, "SALE  %03d  %s", usSaleCount, szAmtBuf);
    //sprintf(szDisplayBuf, "SALE      %03d", usSaleCount);
	//sprintf(szDisplayBuf, "SALE:      %s", szAmtBuf);
#if 0	
	if((strTCT.byTerminalType % 2) == 0){
    	CTOS_LCDTPrintXY(1, 5,"SALES:");	
    	CTOS_LCDTPrintAligned(5, szDisplayBuf, d_LCD_ALIGNRIGHT);
	}else{	
		CTOS_LCDTPrintXY(1, 3,"SALES:");	
		CTOS_LCDTPrintAligned(3, szDisplayBuf, d_LCD_ALIGNRIGHT);
	}
#else	
	CTOS_LCDTPrintXY(1, 5,szBuf);	
    CTOS_LCDTPrintAligned(5, szDisplayBuf, d_LCD_ALIGNRIGHT);
#endif

#if 0
    memset(szDisplayBuf, 0x00, sizeof(szDisplayBuf));
    memset(szAmtBuf, 0x00, sizeof(szAmtBuf));
    memset(szBuf, 0x00, sizeof(szBuf));
    sprintf(szBuf, "%ld", ulRefundTotalAmount);
    vdCTOS_FormatAmount("NNN,NNN,NNn.nn", szBuf,szAmtBuf);// patrick add code 20141216		
    sprintf(szDisplayBuf, "RFUD  %03d  %s", usRefundCount, szAmtBuf);
    CTOS_LCDTPrintXY(1, 6, szDisplayBuf);
#else
		//BDO UAT 0003: Changed batch totals from refund to void - start -- jzg
    memset(szDisplayBuf, 0x00, sizeof(szDisplayBuf));
    memset(szAmtBuf, 0x00, sizeof(szAmtBuf));
    memset(szBuf, 0x00, sizeof(szBuf));
    sprintf(szBuf, "%012.0f", ulVoidTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex <= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szBuf,szAmtBuf);
	else
	    vdCTOS_FormatAmount(strCST.szAmountFormat, szBuf,szAmtBuf);// patrick add code 20141216		

	memset(szBuf,0x00,sizeof(szBuf));
	sprintf(szBuf,"VOIDS:        %d",usVoidCount);
    sprintf(szDisplayBuf,"%s%s",strCST.szCurSymbol,szAmtBuf);
    //sprintf(szDisplayBuf, "VOID  %03d  %s", usVoidCount, szAmtBuf);
    //sprintf(szDisplayBuf, "VOID      %03d", usVoidCount);
    //sprintf(szDisplayBuf, "VOID:      %s", szAmtBuf);
#if 0	
	if((strTCT.byTerminalType % 2) == 0){	
    	CTOS_LCDTPrintXY(1, 7, "VOIDS:");
    	CTOS_LCDTPrintAligned(7, szDisplayBuf, d_LCD_ALIGNRIGHT);
	}else{
    	CTOS_LCDTPrintXY(1, 5, "VOIDS:");
		CTOS_LCDTPrintAligned(5, szDisplayBuf, d_LCD_ALIGNRIGHT);
	}
#else
	CTOS_LCDTPrintXY(1, 7, szBuf);
	CTOS_LCDTPrintAligned(7, szDisplayBuf, d_LCD_ALIGNRIGHT);
#endif
		//BDO UAT 0003: Changed batch totals from refund to void - end -- jzg
#endif

//00415- Add cash advance in batch totals 
#if 0
    memset(szDisplayBuf, 0x00, sizeof(szDisplayBuf));
    memset(szAmtBuf, 0x00, sizeof(szAmtBuf));
    memset(szBuf, 0x00, sizeof(szBuf));

    memset(szDisplayBuf, 0x00, sizeof(szDisplayBuf));
    memset(szAmtBuf, 0x00, sizeof(szAmtBuf));
    memset(szBuf, 0x00, sizeof(szBuf));
    //sprintf(szBuf, "%ld", ulCashAdvanceTotalAmount);
		sprintf(szBuf, "%012.0f", ulCashAdvanceTotalAmount);
    vdCTOS_FormatAmount(strCST.szAmountFormat, szBuf,szAmtBuf);// patrick add code 20141216		
    sprintf(szDisplayBuf, "CADV  %03d  %s", usCashAdvanceCount, szAmtBuf);
    CTOS_LCDTPrintXY(1, 7, szDisplayBuf);
#endif
//

    memset(szDisplayBuf, 0x00, sizeof(szDisplayBuf));
    memset(szAmtBuf, 0x00, sizeof(szAmtBuf));
    memset(szBuf, 0x00, sizeof(szBuf));

#if 0		
    sprintf(szBuf, "%ld", (ulSaleTotalAmount > ulRefundTotalAmount) ? (ulSaleTotalAmount-ulRefundTotalAmount) : (ulRefundTotalAmount - ulSaleTotalAmount));
    vdCTOS_FormatAmount(strCST.szAmountFormat, szBuf,szAmtBuf);// patrick add code 20141216		
    memset(szBuf, 0x00, sizeof(szBuf));
    if(ulSaleTotalAmount > ulRefundTotalAmount)
        szBuf[0] = ' ';
    else
        szBuf[0] = '-';
    sprintf(szDisplayBuf, "TOTL  %03d %s%s", (usSaleCount + usRefundCount), szBuf, szAmtBuf);
#else
		//BDO UAT 0003: Changed batch totals from refund to void - start -- jzg
    sprintf(szBuf, "%012.0f", ulSaleTotalAmount+ulCashAdvanceTotalAmount);

	if(strHDT.inHostIndex >= 6 && strHDT.inHostIndex<= 35 && strTCT.fFormatDCCAmount == TRUE)// handling for DCC
		vdDCCModifyAmount(szBuf,szAmtBuf);
	else
    	vdCTOS_FormatAmount(strCST.szAmountFormat, szBuf,szAmtBuf);// patrick add code 20141216	

	memset(szBuf,0x00,sizeof(szBuf));
	sprintf(szBuf,"TOTAL:        %d",usSaleCount + usCashAdvanceCount);
    sprintf(szDisplayBuf,"%s%s",strCST.szCurSymbol,szAmtBuf);
	//sprintf(szDisplayBuf, "TOTL  %03d %s", usSaleCount+usCashAdvanceCount, szAmtBuf);
	//sprintf(szDisplayBuf, "TOTL      %03d", usSaleCount+usCashAdvanceCount);	
	//sprintf(szDisplayBuf, "TOTAL:     %s", szAmtBuf);	
		//BDO UAT 0003: Changed batch totals from refund to void - end -- jzg
#endif

#if 0
	if((strTCT.byTerminalType % 2) == 0){	
		CTOS_LCDTPrintXY(1, 9, "TOTAL:");
    	CTOS_LCDTPrintAligned(9, szDisplayBuf, d_LCD_ALIGNRIGHT);
	}else{
    	CTOS_LCDTPrintXY(1, 8, "TOTAL:");
		CTOS_LCDTPrintAligned(8, szDisplayBuf, d_LCD_ALIGNRIGHT);
	}
#else
	CTOS_LCDTPrintXY(1, 9, szBuf);
	CTOS_LCDTPrintAligned(9, szDisplayBuf, d_LCD_ALIGNRIGHT);
#endif
    CTOS_LCDTSelectFontSize(d_FONT_16x30);
		
    WaitKey(30);

    return d_OK;
}

int inCTOS_DisplayBatchRecordDetail(int inType)
{
    BYTE szTotalAmount[12+1];
    BYTE szAmtOut[12+1];
    BYTE szINV[6+1];
    BYTE szDisplayBuf[40+1];
    BYTE szTitle[16+1];
   
    CTOS_LCDTClearDisplay();  

    vdDispTransTitle(inType);

    inIITRead(srTransRec.IITid);
//issue-00436 Load the correct currency index (fix fod Still using PHP on batch reveiew even if Host is USD
	inCSTRead(srTransRec.inSavedCurrencyIdx);
    
    memset(szTitle, 0x00, sizeof(szTitle));
    szGetTransTitle(srTransRec.byTransType, szTitle);
    memset(szDisplayBuf, 0x00, sizeof(szDisplayBuf));
    //sprintf(szDisplayBuf, "%s   %s", szTitle, strIIT.szIssuerLabel);
    sprintf(szDisplayBuf, "%s", szTitle);//Removed issuer on Batch Review. Issue 667
    CTOS_LCDTPrintXY(1, 3, szDisplayBuf);

    memset(szDisplayBuf,0,sizeof(szDisplayBuf));
    //vdCTOS_FormatPAN(strIIT.szPANFormat, srTransRec.szPAN, szDisplayBuf);

	strcpy(szDisplayBuf, srTransRec.szPAN);
	//if (strlen(szDisplayBuf) > 16)	
	//	cardMasking(szDisplayBuf, 4);
	//else
	cardMasking(szDisplayBuf, 5);
	
    CTOS_LCDTPrintXY(1, 4, szDisplayBuf);

    memset(szTotalAmount, 0x00, sizeof(szTotalAmount));
    wub_hex_2_str(srTransRec.szTotalAmount, szTotalAmount, 6);
    vdDebug_LogPrintf("szTotalAmount[%s]", szTotalAmount);
//format amount 10+2
	if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
		vdDCCModifyAmount(szTotalAmount,szAmtOut); //vdDCCModifyAmount(&szTemp4);
	else
	    vdCTOS_FormatAmount(strCST.szAmountFormat, szTotalAmount,szAmtOut);
	
    vdDebug_LogPrintf("szDisplayBuf[%s]", szDisplayBuf);
    memset(szDisplayBuf,0,sizeof(szDisplayBuf));
    //sprintf(szDisplayBuf, "%s  %16s", strCST.szCurSymbol, szAmtOut);
    //CTOS_LCDTPrintXY(1, 5, szDisplayBuf);
//format amount 10+2
	vdCTOSS_DisplayAmount(1,5,strCST.szCurSymbol,szAmtOut);

    memset(szINV, 0x00, sizeof(szINV));
    wub_hex_2_str(srTransRec.szInvoiceNo, szINV, 3);
    memset(szDisplayBuf, 0x00, sizeof(szDisplayBuf));
    sprintf(szDisplayBuf, "Invoice:  %ld", atol(szINV));
    CTOS_LCDTPrintXY(1, 6, szDisplayBuf);

	if ((strTCT.byTerminalType%2) == 0)
	{
		CTOS_LCDTPrintAligned(8, "00->UP", d_LCD_ALIGNLEFT);
		CTOS_LCDTPrintAligned(8, "DOT->DOWN", d_LCD_ALIGNRIGHT);
	}
	else
    vdCTOS_LCDGShowUpDown(1,1);
    
    return d_OK;
}

int inCTOSS_DeleteAdviceByINV(BYTE *szInvoiceNo)
{
    int inResult,inUpDateAdviceIndex;
    TRANS_DATA_TABLE srAdvTransTable;
    STRUCT_ADVICE strAdvice;
    
    memset((char *)&srAdvTransTable, 0, sizeof(TRANS_DATA_TABLE));
    memset((char *)&strAdvice, 0, sizeof(strAdvice));
    
    memcpy((char *)&srAdvTransTable, (char *)&srTransRec, sizeof(TRANS_DATA_TABLE));
    
    inResult = ST_SUCCESS;
    inUpDateAdviceIndex = 0;
    while(1)
    {
        inResult = inMyFile_AdviceReadByIndex(inUpDateAdviceIndex,&strAdvice,&srAdvTransTable);
        
        vdDebug_LogPrintf("ADVICE inUpDateAdviceIndex[%d] inMyFile_AdviceRead Rult(%d)(%d)(%d)(%d)", inUpDateAdviceIndex, inResult, srAdvTransTable.ulTraceNum, srAdvTransTable.byPackType, strAdvice.byTransType);
        
        if(inResult == ST_ERROR || inResult == RC_FILE_READ_OUT_NO_DATA)
        {
            inResult = ST_SUCCESS;
            break;
        }
        
        vdDebug_LogPrintf("ulnInvoiceNo[%02X %02X %02X] strAdvice->szInvoiceNo [%02X %02X %02X]", szInvoiceNo[0], szInvoiceNo[1], szInvoiceNo[2], strAdvice.szInvoiceNo[0], strAdvice.szInvoiceNo[1], strAdvice.szInvoiceNo[2]);
        if(0 != memcmp(szInvoiceNo, strAdvice.szInvoiceNo, INVOICE_BCD_SIZE))
        {
            inUpDateAdviceIndex ++;
            continue;
        }
        else
        {
            srAdvTransTable.byUploaded = CN_TRUE;
            inResult = inMyFile_AdviceUpdate(inUpDateAdviceIndex);
            break;
        }
        
    }

    return ST_SUCCESS;
}

int inCTOSS_BatchCheckDuplicateInvoice(void)
{
    int inRet = d_NO;
    
    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        inRet = inCTOS_MultiAPBatchSearch(d_IPC_CMD_CHECK_DUP_INV);

        vdSetErrorMessage("");
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
        
        vdSetErrorMessage("");
        if(d_OK != inRet)
            return inRet;
    }

    return inRet;
}

/***********************************************************/
//sidumili: added function
//check for transaction amount entry base on szMaxTrxnAmt limit
/***********************************************************/
int inCTOS_ValidateTrxnAmount(void)
{
	double dbAmt1 = 0.00, dbAmt2 = 0.00, dbAmt3 = 0.00;
	BYTE szBaseAmt[30+1] = {0};
	char *strPTR;

	/*inTCTRead(1); remove advice by ST*/ 
	memset(szBaseAmt, 0x00, sizeof(szBaseAmt));
	wub_hex_2_str(srTransRec.szBaseAmount, szBaseAmt, AMT_BCD_SIZE);
	dbAmt1 = strtod(szBaseAmt, &strPTR);

	if (fInstApp == TRUE)
		dbAmt2 = strtod(strTCT.szMaxInstAmt, &strPTR);
	else
		dbAmt2 = strtod(strTCT.szMaxTrxnAmt, &strPTR);

	dbAmt3 = strtod(strTCT.szMinTrxnAmt, &strPTR);

	vdDebug_LogPrintf("JEFF::STR TXN AMT: [%s]", szBaseAmt);
	vdDebug_LogPrintf("JEFF::STR MAX AMT: [%s]", strTCT.szMaxTrxnAmt);
	vdDebug_LogPrintf("JEFF::TXN AMT: [%.0f]", dbAmt1);
	vdDebug_LogPrintf("JEFF::MAX AMT: [%.0f]", dbAmt2);
	vdDebug_LogPrintf("JEFF::MIN AMT: [%.0f]", dbAmt3);

	//if((dbAmt1 >= dbAmt2) || (dbAmt1 <= 0))

	if(dbAmt2 != 0)
		if((dbAmt1 > dbAmt2) || (dbAmt1 < dbAmt3))
		{
			vdSetErrorMessage("OUT OF RANGE");
			return(d_NO);
		}

		return(d_OK);
	
}


int inComputePercent (long lnPercent, char *szCalcAmt, long lnBaseAmt, int inFractionalSize)
{
    int inLoopCnt;
    double dbAmount;
    long lnDivisor = 100;
    long lnPercentValue = 0;

		vdDebug_LogPrintf("BASE = %ld", lnBaseAmt);

    //for (inLoopCnt = 0; inLoopCnt < inFractionalSize; inLoopCnt++)
    //    lnDivisor *= 10L;
    dbAmount = (double) lnBaseAmt;
		
		vdDebug_LogPrintf("dbAmount = %f", dbAmount);
    //lnPercentValue = (long) ((dbAmount / lnDivisor) * lnPercent);
    lnPercentValue = (long) ((dbAmount * lnPercent) / lnDivisor);
		
		vdDebug_LogPrintf("lnPercentValue = %ld", lnPercentValue);

    sprintf(szCalcAmt, "%012ld", lnPercentValue);

		
		return(d_OK);
}

/***********************************************************/

BYTE InputStringAlpha2(USHORT usX, USHORT usY, BYTE bInputMode,  BYTE bShowAttr, BYTE *pbaStr, USHORT *usStrLen, USHORT usMinLen, USHORT usTimeOutMS)
{
    char szTemp[24+1];
    USHORT inRet;
	int inCtr=0;
	char szAmount[24+1];
	char chAmount=0x00;
	char szDisplay[24+1];
    unsigned char c;
    BOOL isKey;
	int x=0;
	int inLastKey=255;
	int inKey=0;
	int inKey2=0;
    int inMax=*usStrLen;
	
	char KeyPad[10][4]={{'0', '0', '0', '0'},
	               		{'1', 'Q', 'Z', '0'},
	               		{'2', 'A', 'B', 'C'},
	   					{'3', 'D', 'E', 'F'},
	   					{'4', 'G', 'H', 'I'},
	   					{'5', 'J', 'K', 'L'},
	   					{'6', 'M', 'N', 'O'},
	   					{'7', 'P', 'R', 'S'},
	   					{'8', 'T', 'U', 'V'},
	   					{'9', 'W', 'X', 'Y'}};
	
	memset(szAmount, 0x00, sizeof(szAmount));
	
	CTOS_TimeOutSet(TIMER_ID_1, 100);
	
	while(1)
	{		
		memset(szTemp, 0x00, sizeof(szTemp));  
         
        clearLine(usY);
        CTOS_LCDTPrintXY(40-(strlen(szAmount)*2), usY, szAmount);
		
		CTOS_TimeOutSet(TIMER_ID_3,usTimeOutMS);
		while(1)//loop for time out
		{
            if (CTOS_TimeOutCheck(TIMER_ID_1) == d_YES)
                inLastKey=255;
			
			CTOS_KBDInKey(&isKey);
			if (isKey){ //If isKey is TRUE, represent key be pressed //
				vduiLightOn();
				//Get a key from keyboard //
				CTOS_KBDGet(&c);
				inRet=c;
				break;
			}
			else if (CTOS_TimeOutCheck(TIMER_ID_3) == d_YES)
			{	   
				return 0xFF;
			}
		}

		if(inRet >= 48 && inRet <= 57)
		{
			char szTemp2[24+1];
			
			memset(szTemp, 0x00, sizeof(szTemp));
			sprintf(szTemp, "%c", inRet);
			inKey=atoi(szTemp);
			
			CTOS_TimeOutSet(TIMER_ID_1, 100);
			if((inCtr < inMax) || (inLastKey == inKey))
			{
                vdDebug_LogPrintf("1. inLastKey:(%d), inKey:(%d), inKey2:(%d),ctr:(%d)", inLastKey, inKey, inKey2, inCtr);
				
                if(inLastKey == inKey)
                {
					inKey2++;
					if(inKey2 > 3)
                       inKey2=0;
                }
                else
					inKey2=0;
				                
                if(inLastKey == inKey)
                    inCtr--;
                    
				szAmount[inCtr]=KeyPad[inKey][inKey2];
				inCtr++;

                vdDebug_LogPrintf("2. inLastKey:(%d), inKey:(%d), inKey2:(%d),ctr:(%d)", inLastKey, inKey, inKey2, inCtr);
				
                inLastKey=inKey;

                if(inKey == 0)
				    inLastKey=255;	
			}
		}
		else if(inRet == 67) /*cancel key*/
		{
			return d_KBD_CANCEL;
		}
		else if(inRet == 65) /*entery key*/
		{
			if(strlen(szAmount) > 0)
			{
				memcpy(pbaStr, szAmount, strlen(szAmount));
				*usStrLen=strlen(szAmount);
				return d_KBD_ENTER;
			}
			
		}
		else if(inRet == 82) /*clear key*/
		{		
			inCtr--;
			if(inCtr <= 0)
                inCtr=0;
            szAmount[inCtr]=0x00;
			inKey2=0;
			inLastKey=255;
		}
	}
}

BYTE InputString2(USHORT usX, USHORT usY, BYTE bInputMode,  BYTE bShowAttr, BYTE *pbaStr, USHORT *usStrLen, USHORT usMinLen, USHORT usTimeOutMS)
{
    char szTemp[24+1];
    USHORT inRet;
	int inCtr=0;
	char szAmount[24+1];
	char chAmount=0x00;
	char szDisplay[24+1];
    unsigned char c;
    BOOL isKey;
	int x=0;
	int inKey=0;
    int inMax=*usStrLen;
	
	memset(szAmount, 0x00, sizeof(szAmount));
	
	while(1)
	{		
		memset(szTemp, 0x00, sizeof(szTemp));  
         
        clearLine(usY);
        CTOS_LCDTPrintXY(40-(strlen(szAmount)*2), usY, szAmount);
		
		CTOS_TimeOutSet(TIMER_ID_3,usTimeOutMS);
		while(1)//loop for time out
		{		
			CTOS_KBDInKey(&isKey);
			if (isKey){ //If isKey is TRUE, represent key be pressed //
				vduiLightOn();
				//Get a key from keyboard //
				CTOS_KBDGet(&c);
				inRet=c;
				break;
			}
			else if (CTOS_TimeOutCheck(TIMER_ID_3) == d_YES)
			{	   
				return 0xFF;
			}
		}

		if(inRet >= 48 && inRet <= 57)
		{
			if(inCtr < inMax)
			{
			    memset(szTemp, 0x00, sizeof(szTemp));
			    sprintf(szTemp, "%c", inRet);
                strcat(szAmount, szTemp);			
                inCtr++; 	
			}
		}
		else if(inRet == 67) /*cancel key*/
		{
			return d_KBD_CANCEL;
		}
		else if(inRet == 65) /*entery key*/
		{
			if(strlen(szAmount) > 0)
			{
				memcpy(pbaStr, szAmount, strlen(szAmount));
				*usStrLen=strlen(szAmount);
				return d_KBD_ENTER;
			}
		}
		else if(inRet == 82) /*clear key*/
		{		
			inCtr--;
			if(inCtr <= 0)
                inCtr=0;
            szAmount[inCtr]=0x00;
		}
	}
}

int inNSRFlag(void)
{
    BYTE    szTotalAmt[12+1];
    int fNSRflag = 0;
    wub_hex_2_str(srTransRec.szTotalAmount, szTotalAmt, AMT_BCD_SIZE);    
    vdDebug_LogPrintf("strIIT.fNSR=%d, atol(strTCT.szNSRLimit)=%ld, atol(szTotalAmt)=%ld, srTransRec.byTransType=%d", strIIT.fNSR, atol(strIIT.szNSRLimit), atol(szTotalAmt), srTransRec.byTransType);

    if( (srTransRec.byTransType == SALE) || ((srTransRec.byTransType == SALE_OFFLINE) && (memcmp(srTransRec.szAuthCode,"Y1",2) == 0))|| 
		(srTransRec.byTransType == VOID && srTransRec.byOrgTransType == SALE) /*|| (srTransRec.byTransType == VOID && srTransRec.byOrgTransType == SALE_OFFLINE)*/) 
    {
        if (srTransRec.byEntryMode == CARD_ENTRY_FALLBACK || srTransRec.byEntryMode == CARD_ENTRY_MANUAL)
            fNSRflag=0;
        else
        {
            if(strIIT.fNSR == 1 && (atol(strIIT.szNSRLimit) >= atol(szTotalAmt)))
                fNSRflag = 1;
        }
    }
    
    return fNSRflag;
}

int inCTOSS_CheckNSR(int flag)
{
	unsigned short tagLen;
    char outp[40];
	int fNSRflag = 0;
	BYTE    szTotalAmt[12+1];
	int inRet = d_NO;
	
	//inCTOSS_GetBatchFieldData(&srTransFlexiData, AMEX_NSR_FLAG, &fNSRflag, 1);
	fNSRflag = inNSRFlag();
	
	vdDebug_LogPrintf("inCTOSS_CheckNSR fNSRflag=[%d]",fNSRflag);
	if (fNSRflag == 1)
	{
		if (srTransRec.byEntryMode == CARD_ENTRY_FALLBACK || 
			srTransRec.byEntryMode == CARD_ENTRY_MANUAL ||
			srTransRec.byEntryMode == CARD_ENTRY_WAVE)
		{
			vdDebug_LogPrintf("NSR not support for manual, ctls, fallback");
			return d_NO;
		}
		else
		{			
			if (srTransRec.byEntryMode == CARD_ENTRY_ICC)
			{
				if (flag == 0)
				{
					// for powerfail, share_emv will reset 9F33
					//ushCTOS_EMV_NewTxnDataSet(TAG_9F33_TERM_CAB,3,"\xE0\x08\xC8");
					ushCTOS_EMV_NewTxnDataSet(TAG_9F33_TERM_CAB,3,"\x00\x08\xC8");

					// for powerfail, share_emv will reset 9F1B
					ushCTOS_EMV_NewTxnDataSet(TAG_9F1B_TERM_FLOOR_LIMIT,4,"\x00\x00\x00\x00");
				}
/*
				if (flag == 1)
				{
					memset(outp,0x00,sizeof(outp));
					ushCTOS_EMV_NewDataGet(TAG_9F34_CVM, &tagLen, outp);
					vdPCIDebug_HexPrintf("TAG_9F34_CVM",outp,tagLen);
					outp[2] = '\x00';
					memcpy(srTransRec.stEMVinfo.T9F34,outp,3);
					
					ushCTOS_EMV_NewTxnDataSet(TAG_9F34_CVM,3,outp);
					memset(outp,0x00,sizeof(outp));
					ushCTOS_EMV_NewDataGet(TAG_9F34_CVM, &tagLen, outp);
					vdPCIDebug_HexPrintf("TAG_9F34_CVM",outp,tagLen);
					
				}
*/
			}

			return d_OK;
		}
	}

	return inRet;
}


int inCTOS_ChkifPreAuthExists(void)
{
    int inResult = 0;

	inResult = inBatchPreAuthNumRecord();
    if(inResult <= 0)
    {
        CTOS_LCDTClearDisplay();
        
        //vdSetErrorMessage("NO CARD VER EXISTS                      ");
		vdDisplayErrorMsgResp2("","EMPTY","CARD VER");
        return (d_NO);
    }
    
    return (d_OK);
}

