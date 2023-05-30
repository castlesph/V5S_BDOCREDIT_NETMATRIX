#include <string.h>
#include <stdio.h>
#include <ctosapi.h>
#include <stdlib.h>
#include <stdarg.h>


#include "../Includes/msg.h"
#include "../Includes/wub_lib.h"
#include "../Includes/myEZLib.h"
#include "../Includes/POSTypedef.h"
#include "../Includes/POSTrans.h"

#include "display.h"
#include "../FileModule/myFileFunc.h"
#include "../print/Print.h"
#include "../Includes/CTOSinput.h"
#include "../UI/Display.h"
#include "../Comm/V5Comm.h"
#include "..\Debug\Debug.h"
#include "../Includes/POSDCC.h"

#include "..\Loyalty\BDOLoyalty.h"

extern BOOL fInstApp; 

extern char gblszAmt[20+1]; //aaronnino for BDOCLG ver 9.0 fix on issue #00139 HAVE A DEFAULT TITLE DISPLAY OF TXN TYPE 1 of 8
extern USHORT GPRSCONNETSTATUS;

//smac
extern BOOL fSMACTRAN;
extern fAdviceTras;

#define ERRORLEN 30
#define ERRORLEN1 30
static char szErrorMessage[ERRORLEN+1];
static char szErrorMessage1[ERRORLEN1+1];
static char szErrorMessage2[ERRORLEN1+1];

extern BYTE byPackTypeBeforeDCCLog;
//extern BOOL fOptOutFlag;
extern BOOL fDimFlag;

extern BOOL fLoyaltyApp;

void setLCDReverse(int line,int position, char *pbBuf)
{
    int iInitX = 0;
    int lens = 0;

    //Set the reverse attribute of the character //
    CTOS_LCDTSetReverse(TRUE);  //the reverse enable // 
    
    switch(position)
    {
        case DISPLAY_POSITION_LEFT:
            CTOS_LCDTPrintXY(1, line, pbBuf);
            break;
        case DISPLAY_POSITION_CENTER:
            lens = strlen(pbBuf);
            iInitX = (16 - lens) / 2 + 1;
            CTOS_LCDTPrintXY(iInitX, line, pbBuf);
            break;
        case DISPLAY_POSITION_RIGHT:
            lens = strlen(pbBuf);
            iInitX = 16 - lens + 1;
            CTOS_LCDTPrintXY(iInitX, line, pbBuf);
            break;
    }

    //Set the reverse attribute of the character //
    CTOS_LCDTSetReverse(FALSE); //the reverse enable //     
}

/* BDO-00122: Change line busy to line busy, please try again - start -- jzg */
#if 1
void setLCDPrint(int line,int position, char *pbBuf)
{
	short shXPos = 0,
		shLen = 0;

	shLen = strlen(pbBuf);
	
	switch(position)
	{
		case DISPLAY_POSITION_LEFT:
			CTOS_LCDTPrintXY(1, line, pbBuf);
			break;

		case DISPLAY_POSITION_CENTER:
      shXPos = (MAX_CHAR_PER_LINE - (shLen * 2)) / 2;
			if(shXPos == 0)
				shXPos = 1;
			CTOS_LCDTPrintXY(shXPos, line, pbBuf);
			break;

		case DISPLAY_POSITION_RIGHT:
			shXPos = MAX_CHAR_PER_LINE - (shLen * 2);
			if(shXPos == 0)
				shXPos = 1;
			CTOS_LCDTPrintXY(shXPos, line, pbBuf);
			break;
	}
}
/* BDO-00122: Change line busy to line busy, please try again - end -- jzg */
#else
void setLCDPrint(int line,int position, char *pbBuf)
{
    short shXPos=0, shLen=0;
    int iInitX=0, lens=0;

    shLen = strlen(pbBuf);
    
    switch(position)
    {
        case DISPLAY_POSITION_LEFT:
            CTOS_LCDTPrintXY(1, line, pbBuf);
            break;

        case DISPLAY_POSITION_CENTER:
            #if 0
            lens = strlen(pbBuf);
            
            if((strTCT.byTerminalType == 1) || (strTCT.byTerminalType == 2))
               iInitX = ((22 - lens) / 2) + 1;
            else
                iInitX = ((30 - lens) / 2) + 1;
            
            CTOS_LCDTPrintXY(iInitX, line, pbBuf);
            #endif
            lens = strlen(pbBuf);
            if(lens >= 20)
                iInitX=1;
            else    
                iInitX = (MAX_CHAR_PER_LINE - lens*2) / 2 ;
            CTOS_LCDTPrintXY(iInitX, line, pbBuf);
        break;


        case DISPLAY_POSITION_RIGHT:
            shXPos = MAX_CHAR_PER_LINE - (shLen * 2);
            if(shXPos == 0)
                shXPos = 1;
            CTOS_LCDTPrintXY(shXPos, line, pbBuf);
            break;
    }
}


#endif

void showAmount(IN  BYTE bY, BYTE bStrLen, BYTE *baBuf)
{
    int i;
    
    if(bStrLen > 2)
    {
        CTOS_LCDTPrintXY(13, bY, "0.00");
        for(i = 0;i < bStrLen; i++)
        {
            if ((16 - bStrLen + 1 + i) > 14)
                CTOS_LCDTPutchXY(16 - bStrLen + 1 + i, bY, baBuf[i]);
            else
                CTOS_LCDTPutchXY(16 - bStrLen + i, bY, baBuf[i]);
        }
    }
    else
    {
        CTOS_LCDTPrintXY(13, bY, "0.00");
        for(i = 0;i < bStrLen; i++)
        {
            CTOS_LCDTPutchXY(16 - bStrLen + 1 + i, bY, baBuf[i]);
        }
    }
}

void vduiDisplayInvalidTLE(void)
{
    
    vduiClearBelow(2);
    vduiWarningSound();
    vduiDisplayStringCenter(3,"INVALID SESSION");
    vduiDisplayStringCenter(4,"KEY, PLEASE");
    vduiDisplayStringCenter(5,"DWD SESSION KEY");
    vduiDisplayStringCenter(6,"--INSTRUCTION---");
    CTOS_LCDTPrintXY(1,7,"PRESS [F2] THEN");
    CTOS_LCDTPrintXY(1,8,"PRESS [3]");
    
    CTOS_Delay(2500);
}


void szGetTransTitle(BYTE byTransType, BYTE *szTitle)
{    
    int i;
    szTitle[0] = 0x00;
    
    //vdDebug_LogPrintf("**szGetTransTitle START byTransType[%d]Orig[%d]**", byTransType, srTransRec.byOrgTransType);

//smac
	if (fSMACTRAN){
		if (byTransType == SMAC_ACTIVATION)
			strcpy(szTitle, "SMAC LOGON");
		if (byTransType == SALE_OFFLINE)		
			strcpy(szTitle, "AWARD POINTS");
		if (byTransType == SMAC_BALANCE)	
			strcpy(szTitle, "PTS INQUIRY");
		if (byTransType == SALE)		
			strcpy(szTitle, "REDEMPTION");
		if(byTransType == KIT_SALE)
			strcpy(szTitle, "NEW SMAC");
		if(byTransType == RENEWAL) 
			strcpy(szTitle, "RENEWAL");
		if(byTransType == PTS_AWARDING)  
			strcpy(szTitle, "PTS AWARDING");

    	i = strlen(szTitle);
    	szTitle[i]=0x00;
    	return ;
	}
		
//smac

	if ((fInstApp == TRUE) && (byTransType == SALE)){
		strcpy(szTitle, "INSTALLMENT");
		return;
	}

	if (fLoyaltyApp || srTransRec.HDTid == BDO_LOYALTY_HDT_INDEX)
	{
		switch (byTransType)
		{
			case SALE:
				strcpy(szTitle, "REDEMPTION");
				break;
			case POINTS_INQUIRY:
				strcpy(szTitle, "PTS INQ");
				break;
		}

		return;
	}

    switch(byTransType)
    {
        //version16
        case VOID_PREAUTH:
			strcpy(szTitle, "VOID PREAUTH");
            break;
		//version16		
        case SALE:
            strcpy(szTitle, "SALE");
            break;
        case PRE_AUTH:
			//0826
            //strcpy(szTitle, "PRE AUTH");
            strcpy(szTitle, "CARD VER");
			//0826
            break;
        case PRE_COMP:
            strcpy(szTitle, "AUTH COMP");
            break;
        case REFUND:
            strcpy(szTitle, "REFUND");
            break;
        case VOID:
            if(REFUND == srTransRec.byOrgTransType)
                strcpy(szTitle, "VOID REFUND");
            else if(srTransRec.byOrgTransType == SALE_OFFLINE)
            {
				if(memcmp(srTransRec.szAuthCode,"Y1",2) == 0)
				{
                    strcpy(szTitle, "VOID OFFLINE");					
				}
                else
                {
                    if(strTCT.fCheckout == 1)	
                        strcpy(szTitle, "VOID CHECKOUT");
                    else
                        strcpy(szTitle, "VOID COMPLETION");			
                }
            }
			else if(srTransRec.byOrgTransType == SALE_TIP && (srTransRec.byPackType == OFFLINE_VOID || byPackTypeBeforeDCCLog == OFFLINE_VOID))
			{
				 if(strTCT.fCheckout == 1)	
                    strcpy(szTitle, "VOID CHECKOUT");
                 else
                    strcpy(szTitle, "VOID COMPLETION");			
			}
			else if(srTransRec.byOrgTransType == CASH_ADVANCE)
				strcpy(szTitle, "CASH ADV VOID");
			else	
                strcpy(szTitle, "VOID");
            break;
        case SALE_TIP:
            strcpy(szTitle, "TIP ADJUST");
            break;
			
        case SALE_OFFLINE:
        if(memcmp(srTransRec.szAuthCode,"Y1",2) == 0)
        {
            strcpy(szTitle, "SALE");        
        }
		else
		{
            if(strTCT.fCheckout == 1)	
                strcpy(szTitle, "CHECKOUT");
            else
                strcpy(szTitle, "COMPLETION");
		}
        break;
		
        case SALE_ADJUST: 
            strcpy(szTitle, "ADJUST");
            break;
        case SETTLE:
            strcpy(szTitle, "SETTLE");
            break;
        case SIGN_ON:
            strcpy(szTitle, "SIGN ON");
            break;
        case BATCH_REVIEW:
            strcpy(szTitle, "BATCH REVIEW");
            break;
        case BATCH_TOTAL:
            strcpy(szTitle, "BATCH TOTAL");
            break;
        case REPRINT_ANY:
            strcpy(szTitle, "REPRINT RECEIPT");
            break;

		//gcitra
		case BIN_VER:
			strcpy(szTitle, "BIN CHECK");
			break;
		case CASH_LOYALTY:
			strcpy(szTitle, "REWARD INQUIRY");
			break;	
		case POS_AUTO_REPORT:
			strcpy(szTitle, "POS AUTO REPORT");
			break;	
		case CASH_ADVANCE:
			strcpy(szTitle, "CASH ADV"); //aaronnino for BDOCLG ver 9.0 fix on issue #00216 Cash advance txn title display should be CASH ADV instead of CASH ADVANCE
			break;	
		case BALANCE_INQUIRY:
			strcpy(szTitle, "BALANCE"); //BDO-00143: Changed to BAL INQ -- jzg
			break;			
		//gcitra

		/* BDO CLG: Fleet card support - start -- jzg */
		case FLEET_SALE:
			strcpy(szTitle, "PTT SALE");
			break;
		/* BDO CLG: Fleet card support - end -- jzg */

		case RELOAD:
			strcpy(szTitle, "RELOAD");
			break;

		case SMAC_BALANCE:
			strcpy(szTitle, "BALANCE"); 
			break;

		case OPT_OUT:
			strcpy(szTitle, "OPT OUT"); 
			break;

		case KIT_SALE:
			strcpy(szTitle, "NEW SMAC");
			break;
			
		case RENEWAL:
			strcpy(szTitle, "RENEWAL");
			break;
			
		case PTS_AWARDING:
			strcpy(szTitle, "PTS AWARDING");
			break;
#if 0
		case SMAC_ACTIVATION:	
			strcpy(szTitle, "SMAC LOGON");
			break;
		case SMAC_AWARD:		
			strcpy(szTitle, "AWARD POINTS");
			break;
		case SMAC_BALANCE:	
			strcpy(szTitle, "POINTS INQUIRY");
		//SMAC
#endif		
        default:
            strcpy(szTitle, "");
            break;
    }
    i = strlen(szTitle);
    szTitle[i]=0x00;
    return ;
}

void vdDispTransTitle(BYTE byTransType)
{
    BYTE szTitle[16+1];
    BYTE szTitleDisplay[MAX_CHAR_PER_LINE+1];
    int iInitX = 1;
	vdDebug_LogPrintf("****vdDispTransTitle****");
	vdDebug_LogPrintf("fOptOut[%d]",srTransRec.fOptOut);
    memset(szTitle, 0x00, sizeof(szTitle));
	if(srTransRec.fOptOut)
		strcpy(szTitle,"OPT OUT");
	else
	    szGetTransTitle(byTransType, szTitle);
    iInitX = (MAX_CHAR_PER_LINE - strlen(szTitle)*2) / 2 ;
    memset(szTitleDisplay, 0x00, sizeof(szTitleDisplay));
    memset(szTitleDisplay, 0x20, MAX_CHAR_PER_LINE);
    //memcpy(&szTitleDisplay[iInitX], szTitle, strlen(szTitle));  
    memcpy(&szTitleDisplay[0], szTitle, strlen(szTitle));
    CTOS_LCDTSetReverse(TRUE);
    CTOS_LCDTPrintXY(1, 1, szTitleDisplay);
    CTOS_LCDTSetReverse(FALSE);

		
}


//aaronnino for BDOCLG ver 9.0 fix on issue #00139 HAVE A DEFAULT TITLE DISPLAY OF TXN TYPE start 2 of 8
void vdDispTransTitleCardTypeandTotal(BYTE byTransType)
{
    BYTE szTitle[16+1];
    BYTE szTitleDisplay[MAX_CHAR_PER_LINE+1], szAmtBuff[20+1], szCurAmtBuff[20+1];
    int iInitX = 1;
		int inCardLabellen, inCardDispStart, inMaxDisplen;
		char szDisplayCardLable [MAX_CHAR_PER_LINE+1];
		char szVoidCurrSymbol [10+1];

//issue-00229: do not display amount on TC upload

    //if (inGetATPBinRouteFlag() == TRUE)		
		//return d_OK;


	//00111 - Incorrect display of processing and receiving when performing the transaction MCD04 Test 01 Scenario 01 and Card Details screen is DISABLED	
	//CTOS_LCDTClearDisplay();
	// - 00205 - SM : White screen displayed during processing balance inquiry in BDO Loyalty #1	
	clearLine(3);
	vdDebug_LogPrintf("vdDispTransTitleCardTypeandTotal");


    if(srTransRec.byPackType == TC_UPLOAD || fAdviceTras == TRUE)
        return d_OK;

		/* BDOCLG-00318: Fix for garbage display problem - start -- jzg */
		//inTCTRead(1);
		//if(((strTCT.fFleetGetLiters == TRUE) || (strTCT.fGetDescriptorCode == TRUE)) && (srTransRec.fFleetCard == TRUE))
		//	CTOS_LCDFontSelectMode(d_FONT_TTF_MODE);
		//else
			CTOS_LCDFontSelectMode(d_FONT_FNT_MODE);
		/* BDOCLG-00318: Fix for garbage display problem - end -- jzg */
   
    memset(szTitle, 0x00, sizeof(szTitle));
	if(srTransRec.fOptOut)
		strcpy(szTitle,"OPT OUT");
	else if(byTransType == VOID)
		strcpy(szTitle,"VOID");
	else		
		szGetTransTitle(byTransType, szTitle);

	iInitX = 40;
    memset(szTitleDisplay, 0x00, sizeof(szTitleDisplay));
    memset(szTitleDisplay, 0x20, MAX_CHAR_PER_LINE);
    memcpy(&szTitleDisplay[0], szTitle, strlen(szTitle));
	memset(szDisplayCardLable, 0x00, sizeof(szDisplayCardLable));

	if(strcmp(srTransRec.szCardLable,"CITI MASTER")==0)
		memcpy(&szDisplayCardLable[0],"MASTERCARD",10);
	else if(strcmp(srTransRec.szCardLable,"CITI VISA")==0)
		memcpy(&szDisplayCardLable[0],"VISA",4);
	else
		memcpy(&szDisplayCardLable[0],srTransRec.szCardLable,strlen(srTransRec.szCardLable));
		
    inCardLabellen = strlen(szDisplayCardLable);
		
   
   if ((srTransRec.byTransType == SALE) ||(srTransRec.byTransType == PRE_AUTH) || (srTransRec.byTransType == CASH_ADVANCE) || (srTransRec.byTransType == VOID) || (srTransRec.byTransType == BIN_VER))
   {
          
		BYTE szBaseAmt[AMT_ASC_SIZE + 1] = {0};
		//BYTE szBaseAmt[20 + 1] = {0};

		/* BDOCLG-00318: Fix for garbage display problem - start -- jzg */
		//if(((strTCT.fFleetGetLiters == TRUE) || (strTCT.fGetDescriptorCode == TRUE)) && (srTransRec.fFleetCard == TRUE))
		//{
		//	CTOS_LCDTSetReverse(TRUE);
		//	CTOS_LCDTPrintAligned(1, szTitle, d_LCD_ALIGNLEFT);
		//	CTOS_LCDTPrintAligned(1, szDisplayCardLable, d_LCD_ALIGNRIGHT);
		//	CTOS_LCDTSetReverse(FALSE);
		//}else
			/* BDOCLG-00318: Fix for garbage display problem - end -- jzg */
		//00206 #1 - SM : Overlapping displayed in Redemption BDO Loyalty  and No error message displayed if host is down
		if (srTransRec.HDTid != BDO_LOYALTY_HDT_INDEX)		
		{
	        inCardDispStart = iInitX  - inCardLabellen * 2;
				
			CTOS_LCDFontSelectMode(d_FONT_TTF_MODE);
			//memcpy(&szTitleDisplay[inCardDispStart], szDisplayCardLable, inCardLabellen);
			CTOS_LCDTSetReverse(TRUE);
			//CTOS_LCDTPrintAligned(1, szTitle, d_LCD_ALIGNLEFT);
			//CTOS_LCDTPrintAligned(1, szTitleDisplay, d_LCD_ALIGNLEFT);
			CTOS_LCDTPrintXY(1,1,szTitleDisplay);
			if ((inGetATPBinRouteFlag() != TRUE) && (srTransRec.byTransType != BIN_VER)	)
				   CTOS_LCDTPrintAligned(1, szDisplayCardLable, d_LCD_ALIGNRIGHT);
			
			CTOS_LCDTSetReverse(FALSE);
		}
	    if (srTransRec.byTransType != BIN_VER)
	    {
	       CTOS_LCDFontSelectMode(d_FONT_TTF_MODE);
	       wub_hex_2_str(srTransRec.szTotalAmount, szBaseAmt, 6); 

		   if(srTransRec.fDCC && strTCT.fFormatDCCAmount == TRUE)
			   vdDCCModifyAmount(szBaseAmt,&szAmtBuff); //vdDCCModifyAmount(&szAmtBuff);
		   else	   
		       vdCTOS_FormatAmount(strCST.szAmountFormat, szBaseAmt,szAmtBuff); // patrick fix case #229

		   vdDebug_LogPrintf("vdDispTransTitleCardTypeandTotal - 00151 & 00152");

		   
		   clearLine(3); //00151 - Incorrect UI of Processing and Receiving screen when ATP BR = ON (swipe or fallback)		   
		   clearLine(5); //00152 - Last 4 digits of card number overlapped in  amount displayed during processing
	       setLCDPrint(3, DISPLAY_POSITION_LEFT, "TOTAL:");
		   vdCTOS_DispStatusMessage("PROCESSING...");
	       
	       
	       if (srTransRec.byTransType == VOID)   
	       {
	          memset(szVoidCurrSymbol,0,sizeof(szVoidCurrSymbol));
	          strcpy(szVoidCurrSymbol,strCST.szCurSymbol); 
	          strcat(szVoidCurrSymbol,"-");
	          sprintf(szCurAmtBuff,"%s%s",szVoidCurrSymbol, szAmtBuff);
	          setLCDPrint(5, DISPLAY_POSITION_CENTER, szCurAmtBuff);
	       }
	       else
	       {
	          sprintf(szCurAmtBuff,"%s%s",strCST.szCurSymbol, szAmtBuff);
	          //issue-00371
	          //inCTOS_DisplayCurrencyAmount(srTransRec.szTotalAmount, 5, DISPLAY_POSITION_CENTER);	 
	          setLCDPrint(5, DISPLAY_POSITION_CENTER, szCurAmtBuff);
	       }
	    }
	 }
	 #if 0
   else if(srTransRec.byTransType == BIN_VER)
   {
      inCardDispStart = iInitX  - inCardLabellen * 2;
      CTOS_LCDFontSelectMode(d_FONT_TTF_MODE);
      //memcpy(&szTitleDisplay[inCardDispStart], szDisplayCardLable, inCardLabellen);
      CTOS_LCDTSetReverse(TRUE);
      //CTOS_LCDTPrintAligned(1, szTitle, d_LCD_ALIGNLEFT);
      //CTOS_LCDTPrintAligned(1, szTitleDisplay, d_LCD_ALIGNLEFT);
	  
	  CTOS_LCDTPrintXY(1,1,szTitleDisplay);
	  if (inGetATPBinRouteFlag() == TRUE)	
      	CTOS_LCDTPrintAligned(1, szDisplayCardLable, d_LCD_ALIGNRIGHT);
      CTOS_LCDTSetReverse(FALSE);
   }
	 #endif
	 else
	 	CTOS_LCDFontSelectMode(d_FONT_TTF_MODE); 
}
//aaronnino for BDOCLG ver 9.0 fix on issue #00139 HAVE A DEFAULT TITLE DISPLAY OF TXN TYPE end 2 of 8



void vdDispTitleString(BYTE *szTitle)
{
    BYTE szTitleDisplay[MAX_CHAR_PER_LINE+1];
    int iInitX = 1;
       
    iInitX = (MAX_CHAR_PER_LINE - strlen(szTitle)*2) / 2;
    memset(szTitleDisplay, 0x00, sizeof(szTitleDisplay));
    memset(szTitleDisplay, 0x20, MAX_CHAR_PER_LINE);
    memcpy(&szTitleDisplay[iInitX], szTitle, strlen(szTitle)); //aaronnino for BDOCLG ver 9.0 fix on issue #00072 Incorrrect transaction type displayed for INSTALLMENT 1 of 2 
    //memcpy(&szTitleDisplay[0], szTitle, strlen(szTitle));
		CTOS_LCDTSetReverse(TRUE);
    CTOS_LCDTPrintXY(1, 1, szTitleDisplay);
    CTOS_LCDTSetReverse(FALSE);
}




USHORT clearLine(int line)
{
    CTOS_LCDTGotoXY(1,line);
    CTOS_LCDTClear2EOL();
}

void vdDisplayTxnFinishUI(void)
{
    
    //setLCDPrint(3, DISPLAY_POSITION_CENTER, "Transaction");
    //setLCDPrint(4, DISPLAY_POSITION_CENTER, "Approved");
    //setLCDPrint(5, DISPLAY_POSITION_CENTER, srTransRec.szAuthCode);     
   if(srTransRec.byTransType == LOG_ON)
      return;
   
   if(strlen(srTransRec.szBinRouteRespCode))
   {
       if(memcmp(srTransRec.szBinRouteRespCode, "00", 2) != 0)
       {
           memset(srTransRec.szBinRouteRespCode, 0, sizeof(srTransRec.szBinRouteRespCode));
           return;
       }
   }
	
    if(strTCT.fDisplayAPPROVED == TRUE && srTransRec.byTransType != BALANCE_INQUIRY && srTransRec.byTransType != SMAC_ACTIVATION
		&& srTransRec.byTransType != BIN_VER) // Terminal will display the SMAC balance instead of the "APPROVED" message. 
	{
		CTOS_LCDTClearDisplay();
		
		if ((strTCT.byTerminalType % 2) == 1) 
	        vduiDisplayStringCenter(5,"APPROVED");
	    else 
	        vduiDisplayStringCenter(8, "APPROVED");
		CTOS_Beep();
	}
#if 0
	else
	{
		if(srTransRec.byTransType != BIN_VER && srTransRec.byTransType != BALANCE_INQUIRY && srTransRec.byTransType != SMAC_BALANCE)
		{
			if ((strTCT.byTerminalType % 2) == 1) 
				CTOS_LCDTPrintXY(1, 8, "PRINTING...");
			else 
				CTOS_LCDTPrintXY(1, 16, "PRINTING...");
		}
	}
#endif	
    
}

void vdDispErrMsg(IN BYTE *szMsg)
{
    char szDisplayMsg[40];
    BYTE byKeyBuf;
    
    CTOS_LCDTClearDisplay();
    if(srTransRec.byTransType != 0)
        vdDispTransTitle(srTransRec.byTransType);

    memset(szDisplayMsg, 0x00, sizeof(szDisplayMsg));
    strcpy(szDisplayMsg, szMsg);
    vduiClearBelow(8);
    setLCDPrint(8, DISPLAY_POSITION_LEFT, szDisplayMsg);
    CTOS_TimeOutSet (TIMER_ID_2 , 2*100);
    CTOS_Sound(1000, 50);
    
    while (1)
    {        
        CTOS_KBDHit  (&byKeyBuf);
        if (byKeyBuf == d_KBD_CANCEL ||byKeyBuf == d_KBD_ENTER)
        {
            CTOS_KBDBufFlush ();
            return ;
        }
    }
}


int vdDispTransactionInfo(void)
{
    BYTE byKeyBuf;
    BYTE szTmp1[16+1];
    BYTE szTmp2[16+1];
	BYTE szTmp[130+1];
    
    CTOS_LCDTClearDisplay();
    vdDispTransTitle(srTransRec.byTransType);
    
    setLCDPrint(2, DISPLAY_POSITION_LEFT, "Card NO.");
    setLCDPrint(3, DISPLAY_POSITION_LEFT, srTransRec.szPAN);
    memset(szTmp1, 0x00, sizeof(szTmp1));
    memset(szTmp2, 0x00, sizeof(szTmp2));
	memset(szTmp, 0x00, sizeof(szTmp));
    wub_hex_2_str(srTransRec.szInvoiceNo, szTmp1, 3);
    sprintf(szTmp2,"Inv No:%s", szTmp1);
    setLCDPrint(4, DISPLAY_POSITION_LEFT, szTmp2);
    
    wub_hex_2_str(srTransRec.szTotalAmount, szTmp1, 6);
    setLCDPrint(5, DISPLAY_POSITION_LEFT, "Amount:");
	//format amount 10+2
	vdCTOS_FormatAmount(strCST.szAmountFormat, szTmp1, szTmp);
	sprintf(szTmp2,"%s%s", strCST.szCurSymbol,szTmp);
    //sprintf(szTmp2,"SGD%7lu.%02lu", (atol(szTmp1)/100), (atol(szTmp1)%100));
    setLCDPrint(6, DISPLAY_POSITION_RIGHT, szTmp2);  
    setLCDPrint(8, DISPLAY_POSITION_LEFT, "PRS ENTR TO CONF");
    CTOS_TimeOutSet (TIMER_ID_2 , 30*100);
    
    while (1)
    {
        if(CTOS_TimeOutCheck(TIMER_ID_2 )  == d_OK)
            return  READ_CARD_TIMEOUT;
        
        CTOS_KBDHit  (&byKeyBuf);
        if (byKeyBuf == d_KBD_CANCEL)
        {
            CTOS_KBDBufFlush ();
            return USER_ABORT;
        }
        else if (byKeyBuf == d_KBD_ENTER)
        {
            CTOS_KBDBufFlush ();
            return d_OK;
        }
    }
}

USHORT showBatchRecord(TRANS_DATA_TABLE *strTransData)
{
    char szStr[DISPLAY_LINE_SIZE + 1];
    char szTemp[DISPLAY_LINE_SIZE + 1];
    BYTE byKeyBuf;
    CTOS_LCDTClearDisplay();
    memset(szStr, ' ', DISPLAY_LINE_SIZE);
    sprintf(szStr, "%s", strTransData->szPAN);
    setLCDPrint(1, DISPLAY_POSITION_LEFT, "Card NO:");
    setLCDPrint(2, DISPLAY_POSITION_LEFT, szStr);
    
    memset(szStr, ' ', DISPLAY_LINE_SIZE);
    memset(szTemp, ' ', DISPLAY_LINE_SIZE);
    wub_hex_2_str(strTransData->szBaseAmount, szTemp, AMT_BCD_SIZE);
    sprintf(szStr, "%lu.%lu", atol(szTemp)/100, atol(szTemp)%100);
    setLCDPrint(3, DISPLAY_POSITION_LEFT, "Amount:");
    setLCDPrint(4, DISPLAY_POSITION_LEFT, szStr);

    
    memset(szStr, ' ', DISPLAY_LINE_SIZE);
    sprintf(szStr, "%s", strTransData->szAuthCode);
    setLCDPrint(5, DISPLAY_POSITION_LEFT, "Auth Code:");
    setLCDPrint(6, DISPLAY_POSITION_LEFT,  szStr);


    memset(szStr, ' ', DISPLAY_LINE_SIZE);
    memset(szTemp, ' ', DISPLAY_LINE_SIZE);
    wub_hex_2_str(strTransData->szInvoiceNo, szTemp, INVOICE_BCD_SIZE);
    sprintf(szStr, "%s", szTemp);
    setLCDPrint(7, DISPLAY_POSITION_LEFT, "Invoice NO:");
    setLCDPrint(8, DISPLAY_POSITION_LEFT, szTemp);
     
    CTOS_TimeOutSet (TIMER_ID_2 , 30*100);   
    while (1)
    {
        if(CTOS_TimeOutCheck(TIMER_ID_2 )  == d_OK)
        {
            CTOS_LCDTClearDisplay();
            return  READ_CARD_TIMEOUT;
        }
        CTOS_KBDHit  (&byKeyBuf);
        if (byKeyBuf == d_KBD_CANCEL)
        {
            CTOS_KBDBufFlush ();
            CTOS_LCDTClearDisplay();
            return USER_ABORT;
        }
        else if (byKeyBuf == d_KBD_ENTER)
        {
            CTOS_KBDBufFlush ();
            CTOS_LCDTClearDisplay();
            return d_OK;
        }
    }
}

void vduiLightOn(void)
{
    if (strTCT.fHandsetPresent)  
        CTOS_BackLightSetEx(d_BKLIT_LCD,d_ON,80000);
    else
        CTOS_BackLightSet (d_BKLIT_LCD, d_ON);
}

void vduiKeyboardBackLight(BOOL fKeyBoardLight)
{
    if (strTCT.fHandsetPresent) 
    {
        if(VS_TRUE == fKeyBoardLight)
        {
            
            CTOS_BackLightSetEx(d_BKLIT_KBD,d_ON,0xffffff);
            CTOS_BackLightSetEx(d_BKLIT_LCD,d_ON,0xffffff);
        }
        else
        {
            CTOS_BackLightSetEx(d_BKLIT_KBD,d_OFF,100);
            CTOS_BackLightSetEx(d_BKLIT_LCD,d_OFF,3000);
        }

    }
    else
    {
        if(VS_TRUE == fKeyBoardLight)
            CTOS_BackLightSetEx(d_BKLIT_KBD,d_ON,0xffffff);
        else
            CTOS_BackLightSetEx(d_BKLIT_KBD,d_OFF,100);
    }
}

void vduiPowerOff(void)
{
    BYTE block[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    USHORT ya,yb,xa,xb;
    unsigned char c;
        
    //vduiClearBelow(1);
    CTOS_LCDTClearDisplay(); /*BDO: Clear window -- sidumili*/
	
    vduiDisplayStringCenter(4,"POWER OFF TERMINAL?");
	//gcitra-0728
    
    vduiDisplayStringCenter(7,"NO[X]   YES[OK] ");
	//gcitra-0728
    c=WaitKey(60);
    
    if(c!=d_KBD_ENTER)
    {
            return;
    }    
    
    for(ya =1; ya<5; ya++)
    {
        CTOS_Delay(100);
        CTOS_LCDTGotoXY(1,ya);
        CTOS_LCDTClear2EOL();
    }
    for(yb=8; yb>4; yb--)
    {
        CTOS_Delay(100);
        CTOS_LCDTGotoXY(1,yb);
        CTOS_LCDTClear2EOL();
    }
    CTOS_LCDTPrintXY(1,4,"----------------");
    for(xa=1; xa<8; xa++)
    {
        CTOS_Delay(25);
        CTOS_LCDTPrintXY(xa,4," ");
    }
    for(xb=16; xb>7; xb--)
    {
        CTOS_Delay(25);
        CTOS_LCDTPrintXY(xb,4," ");
    }
            
    CTOS_LCDGShowPic(58, 6, block, 0, 6);
    CTOS_Delay(250);
    CTOS_LCDTGotoXY(7,4);
    CTOS_LCDTClear2EOL();
    CTOS_Delay(250);

    CTOS_PowerOff();
}

void vduiDisplayStringCenter(unsigned char  y,unsigned char *sBuf)
{
	//1027
	//setLCDPrint27(y, DISPLAY_POSITION_CENTER,sBuf);	
	setLCDPrint(y,DISPLAY_POSITION_CENTER,sBuf);

}

void vduiClearBelow(int line)
{
	int i = 0,
		inNumOfLine = 8;

	/* BDOCLG-00005: should clear the rest of the line even for V3 terminals - start -- jzg */
	//inTCTRead(1);
	if((strTCT.byTerminalType % 2) == 0)
		inNumOfLine = 16;

	for(i=line; i<=inNumOfLine; i++)
		clearLine(i);
	/* BDOCLG-00005: should clear the rest of the line even for V3 terminals - end -- jzg */
}

void vduiWarningSound(void)
{
    CTOS_LEDSet(d_LED1, d_ON);
    CTOS_LEDSet(d_LED2, d_ON);
    CTOS_LEDSet(d_LED3, d_ON);
    
    CTOS_Beep();
    CTOS_Delay(300);
    CTOS_Beep();
    
    CTOS_LEDSet(d_LED1, d_OFF);
    CTOS_LEDSet(d_LED2, d_OFF);
    CTOS_LEDSet(d_LED3, d_OFF);
}


void vdDisplayErrorMsg(int inColumn, int inRow,  char *msg)
{
	int inRowtmp;
	
    if ((strTCT.byTerminalType % 2) == 0)
		inRowtmp = V3_ERROR_LINE_ROW;
	else
        inRowtmp = inRow;

    clearLine(inRowtmp);
		
    CTOS_LCDTPrintXY(inColumn, inRowtmp, "                                        ");
    CTOS_LCDTPrintXY(inColumn, inRowtmp, msg);
    CTOS_Beep();
    CTOS_Delay(1500);

	clearLine(inRowtmp);
}
//aaronnino for BDOCLG ver 9.0 fix on issue #00124 Terminal display according to response codes was not updated start 3 of 5
void vdDisplayErrorMsgResp (int inColumn, int inColumn2, int inColumn3, int inRow, int inRow2, int inRow3,  char *msg, char *msg2, char *msg3)
{
    
    CTOS_LCDTPrintXY(inColumn, inRow, "                                        ");
		CTOS_LCDTPrintXY(inColumn2, inRow2, "                                        ");
		CTOS_LCDTPrintXY(inColumn3, inRow3, "                                        ");
    CTOS_LCDTPrintXY(inColumn, inRow, msg);
		CTOS_LCDTPrintXY(inColumn2, inRow2, msg2);
		CTOS_LCDTPrintXY(inColumn3, inRow3, msg3);
    CTOS_Beep();
    CTOS_Delay(1500);
}
//aaronnino for BDOCLG ver 9.0 fix on issue #00124 Terminal display according to response codes was not updated end 3 of 5

void vdDisplayErrorMsgResp2 (char *msg, char *msg2, char *msg3)
{
   CTOS_LCDTClearDisplay();

   if ((strTCT.byTerminalType % 2) == 1) 
   {
		vduiDisplayStringCenter(3,msg);
		vduiDisplayStringCenter(4,msg2);
		vduiDisplayStringCenter(5,msg3);
			
   }
   else 
   {
      vduiDisplayStringCenter(6, msg);
      vduiDisplayStringCenter(7, msg2);
      vduiDisplayStringCenter(8, msg3);
   }
	 
   CTOS_Beep();
   CTOS_Delay(1500);
   CTOS_LCDTClearDisplay();
}

void vdDisplayErrorMsgResp2Ex(char *msg, char *msg2, char *msg3)
{
   //CTOS_LCDTClearDisplay();
   vdClearBelowLine(2);
   
   if ((strTCT.byTerminalType % 2) == 1) 
   {
		vduiDisplayStringCenter(3,msg);
		vduiDisplayStringCenter(4,msg2);
		vduiDisplayStringCenter(5,msg3);
			
   }
   else 
   {
      vduiDisplayStringCenter(6, msg);
      vduiDisplayStringCenter(7, msg2);
      vduiDisplayStringCenter(8, msg3);
   }
	 
   CTOS_Beep();
   CTOS_Delay(1500);
   vdClearBelowLine(2);
}

/* functions for loyalty - Meena 15/01/2012 - start*/
short vduiAskConfirmContinue(int inDisplay)
{
    unsigned char key;
  
    //vduiClearBelow(1);
    CTOS_LCDTClearDisplay();/*BDO: Clear window -- sidumili*/
    vduiDisplayStringCenter(3,"ARE YOU SURE");
    vduiDisplayStringCenter(4,"YOU WANT TO");
	if (inDisplay == 1)		
    	vduiDisplayStringCenter(5,"CLEAR BATCH?");
	else if (inDisplay == 2)	
    	vduiDisplayStringCenter(5,"DELETE REVERSAL?");
	else		
		vduiDisplayStringCenter(5,"CONTINUE?");
	//gcitra-0728
    //CTOS_LCDTPrintXY(1,7,"NO[X]   YES[OK] ");
    vduiDisplayStringCenter(7,"NO[X]   YES[OK] ");
	//gcitra-0728
        
    while(1)
    {
        key = struiGetchWithTimeOut();
        if (key==d_KBD_ENTER)
            return d_OK;
        else if (key==d_KBD_CANCEL)
            return -1;
        else
            vduiWarningSound();
    }
    
}



BYTE struiGetchWithTimeOut(void)
{
    unsigned char c;
    BOOL isKey;
    CTOS_TimeOutSet(TIMER_ID_3,3000);
    
    while(1)//loop for time out
    {
        CTOS_KBDInKey(&isKey);
        if (isKey){ //If isKey is TRUE, represent key be pressed //
            vduiLightOn();
            //Get a key from keyboard //
            CTOS_KBDGet(&c);
            return c;   
        }
        else if (CTOS_TimeOutCheck(TIMER_ID_3) == d_YES)
        {      
            return d_KBD_CANCEL;
        }
    }
}

/* functions for loyalty - Meena 15/01/2012 - End*/

short inuiAskSettlement(void)
{
    unsigned char key;
    while(1) 
    {
        vduiClearBelow(2);
        vduiDisplayStringCenter(2,"DAILY SETTLEMENT");
        vduiDisplayStringCenter(3,"NOTIFICATION");

        vduiDisplayStringCenter(5,"PERFORM");
        vduiDisplayStringCenter(6,"SETTLEMENT?");
        vduiDisplayStringCenter(8,"NO[X] YES[OK]");

        CTOS_KBDGet(&key);
        if(key==d_KBD_ENTER)
            return d_OK;
        else if(key==d_KBD_CANCEL)
            return d_KBD_CANCEL;
        else if(key==d_KBD_F1)
            vduiPowerOff();
    }
        
}

void vduiDisplaySignalStrengthBatteryCapacity(void)
{
    
    BYTE bCapacity, msg2[50];
    USHORT dwRet;
    short insign;
    
    
    if(GPRSCONNETSTATUS== d_OK && strTCT.inMainLine == GPRS_MODE)
    {
        insign=incommSignal();
        if(insign==-1)
        {
            CTOS_LCDTPrintXY (9,1, "SIGNAL:NA");
        }
        else
        {           
            if(insign/6 == 0)
                CTOS_LCDTPrintXY (9,1, "NO SIGNAL");
            else if(insign/6 == 1)
            {                               
               CTOS_LCDTPrintXY (9,1, "S:l____"); 
            }
            else if(insign/6 == 2)
            {                               
               CTOS_LCDTPrintXY (9,1, "S:ll___"); 
            }
            else if(insign/6 == 3)
            {                               
               CTOS_LCDTPrintXY (9,1, "S:lll__"); 
            }
            else if(insign/6 == 4)
            {                               
               CTOS_LCDTPrintXY (9,1, "S:llll_"); 
            }
            else if(insign/6 == 5)
            {                               
               CTOS_LCDTPrintXY (9,1, "S:lllll"); 
            }
            
        }
    }
    
    dwRet= CTOS_BatteryGetCapacityByIC(&bCapacity);  
    if(dwRet==d_OK)
    {
        sprintf(msg2, "B:%d%% ", bCapacity);
        CTOS_LCDTPrintXY (3,1, msg2);
    }
                
}

void vdSetErrorMessage(char *szMessage)
{
    int inErrLen=0;

    inErrLen = strlen(szMessage);
    memset(szErrorMessage,0x00,sizeof(szErrorMessage));
	memset(szErrorMessage1,0x00,sizeof(szErrorMessage1));
    
    if (inErrLen > 0)
    {
        if (inErrLen > ERRORLEN)
            inErrLen = ERRORLEN;
        
        memcpy(szErrorMessage,szMessage,inErrLen);
    }
}

void vdSetErrorMessages(char *szMessage1, char *szMessage2)
{
    int inErrLen1=0, inErrLen2=0;

    inErrLen1 = strlen(szMessage1);
	inErrLen2 = strlen(szMessage2);

    memset(szErrorMessage1,0x00,sizeof(szErrorMessage1));
	memset(szErrorMessage2,0x00,sizeof(szErrorMessage2));
    
    if (inErrLen2 > 0)
    {
            inErrLen1 = ERRORLEN;
		    inErrLen2 = ERRORLEN1;
        
        memcpy(szErrorMessage1,szMessage1,inErrLen1);
		memcpy(szErrorMessage2,szMessage2,inErrLen2);
    }
}


int inGetErrorMessage(char *szMessage)
{
    int inErrLen=0;

    inErrLen = strlen(szErrorMessage);

    if (inErrLen > 0)
    {       
        memcpy(szMessage,szErrorMessage,inErrLen);
    }
    
    return inErrLen;
}

int inGetErrorMessages(char *szMessage1, char *szMessage2)
{
    int inErrLen1=0, inErrLen2=0;

    inErrLen1 = strlen(szErrorMessage1);
	inErrLen2 = strlen (szErrorMessage2);
      
        memcpy(szMessage1,szErrorMessage1,inErrLen1);
		memcpy(szMessage2,szErrorMessage2,inErrLen2);

    return inErrLen2;
}

//gcitra
void setLCDPrint27(int line,int position, char *pbBuf)
{
    int iInitX = 0;
    int lens = 0;

		CTOS_LCDFontSelectMode(d_FONT_FNT_MODE);

    switch(position)
    {
        case DISPLAY_POSITION_LEFT:
            CTOS_LCDTPrintXY(1, line, pbBuf);
            break;
        case DISPLAY_POSITION_CENTER:
            lens = strlen(pbBuf);
            iInitX = (20- lens) / 2 + 1;
            CTOS_LCDTPrintXY(iInitX, line, pbBuf);
            break;
        case DISPLAY_POSITION_RIGHT:
            lens = strlen(pbBuf);
            iInitX = 20- lens + 1;
            CTOS_LCDTPrintXY(iInitX, line, pbBuf);
            break;
    }

		
		CTOS_LCDFontSelectMode(d_FONT_TTF_MODE);
}

//gcitra


//sidumili: display message
void vdDisplayMessage(char *szLine1Msg, char *szLine2Msg, char *szLine3Msg)
{
    CTOS_LCDTClearDisplay();
		vduiClearBelow(2);
		vduiDisplayStringCenter(4, szLine1Msg);
		vduiDisplayStringCenter(5, szLine2Msg);
		vduiDisplayStringCenter(6, szLine3Msg);
		CTOS_Beep(); /*BDO: Added BEEP -- sidumili*/
		WaitKey(1);
}
//sidumili

//sidumili: confirmation
short vduiAskEnterToConfirm(void)
{
    unsigned char key;
  
    
    CTOS_LCDTPrintXY(1,8,"CONFIRM?NO[X]YES[OK]");
        
    while(1)
    {
        key = struiGetchWithTimeOut();
        if (key==d_KBD_ENTER)
            return d_OK;
        else if (key==d_KBD_CANCEL){
					
						//sidumili: disconnect communication when USER PRESS CANCEL KEY
						if (strCPT.inCommunicationMode == DIAL_UP_MODE){
										inCTOS_inDisconnect();
						}
						//sidumili: disconnect communication when USER PRESS CANCEL KEY
					
            return -1;
        	}
        else
            vduiWarningSound();
    }
    
}
//sidumili:

int inDisplayDCCRateScreen(void)
{
	VS_BOOL fDisplayForExRate = inFLGGet("fForExRate");
	VS_BOOL fDisplayMarkup = inFLGGet("fDCCMarkUp");
	char szTemp[MAX_CHAR_PER_LINE+1];
	char szTemp1[MAX_CHAR_PER_LINE+1];
	char szTemp2[MAX_CHAR_PER_LINE+1];
	BYTE szAmtBuff[20+1], szCurAmtBuff[20+1];
	BYTE szBaseAmt[AMT_ASC_SIZE + 1] = {0};
	int iLine,inLength=0;
	BYTE key=0;
	float inMarkup = 0;
	
	//#define RATE_RESPONSE_FULL "\x01\x70\x37\x31\x30\x30\x39\x63\x66\x34\x63\x32\x64\x64\x34\x38\x66\x34\x63\x32\x30\x38\x34\x35\x37\x32\x35\x32\x38\x30\x30\x31\x33\x36\x30\x35\x30\x30\x20\x20\x20\x20\x20\x20\x20\x20\x31\x31\x31\x32\x33\x34\x35\x36\x37\x38\x39\x31\x30\x30\x33\x36\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x34\x37\x32\x38\x30\x30\x31\x38\x34\x38\x39\x34\x33\x32\x30\x32\x30\x31\x32\x30\x39\x32\x32\x31\x32\x32\x38\x31\x38\x33\x35\x36\x30\x33\x36\x56\x53\x41\x64\x64\x37\x35\x34\x30\x38\x34\x39\x35\x35\x36\x30\x30\x38\x34\x35\x37\x32\x35\x32\x38\x30\x30\x31\x33\x36\x30\x35\x30\x32\x20\x20\x20\x20\x20\x20\x20\x20\x30\x30\x30\x30\x30\x31\x41\x55\x44\x34\x38\x33\x2E\x30\x32\x20\x20\x20\x20\x20\x30\x33\x36"
	
	//inUnPackIsoFunc61(&srTransRec,RATE_RESPONSE_FULL);
	
	CTOS_LCDTClearDisplay();
	
	iLine = ((strTCT.byTerminalType%2)?3:4);

	wub_hex_2_str(srTransRec.szTotalAmount, szBaseAmt, 6); 
	vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szBaseAmt,szAmtBuff); 
	sprintf(szCurAmtBuff,"(1)%s %s", srTransRec.szDCCLocalSymbol, szAmtBuff);
	setLCDPrint(2, DISPLAY_POSITION_RIGHT, szCurAmtBuff);

	memset(szAmtBuff,0x00,sizeof(szAmtBuff));
	memset(szCurAmtBuff,0x00,sizeof(szCurAmtBuff));
	memset(szBaseAmt,0x00,sizeof(szBaseAmt));

	inCSTReadHostID(srTransRec.szDCCCur);

    if(strTCT.fFormatDCCAmount == TRUE)
    	vdDCCModifyAmount(srTransRec.szDCCCurAmt,szAmtBuff);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, srTransRec.szDCCCurAmt,szAmtBuff);
	
	
	sprintf(szCurAmtBuff,"(2)%s %s",srTransRec.szDCCCurSymbol, szAmtBuff);// Wait for strCST for foreign currency
	setLCDPrint((strTCT.byTerminalType%2)?3:4, DISPLAY_POSITION_RIGHT, szCurAmtBuff);

	if(fDisplayForExRate)
	{
		inLength=strlen(srTransRec.szDCCFXRate)-srTransRec.inDCCFXRateMU;
		memset(szTemp,0x00,sizeof(szTemp));
		memcpy(szTemp,srTransRec.szDCCFXRate,inLength);
		memcpy(&szTemp[inLength],".",1);
		memcpy(&szTemp[inLength+1],&srTransRec.szDCCFXRate[inLength],srTransRec.inDCCFXRateMU);
			
		setLCDPrint((strTCT.byTerminalType%2)?5:7, DISPLAY_POSITION_LEFT, "Exchange Rate:");
		setLCDPrint((strTCT.byTerminalType%2)?6:8, DISPLAY_POSITION_RIGHT,szTemp);	
	}
	
	if(fDisplayMarkup)
	{
		memset(szTemp,0x00,sizeof(szTemp));
		memset(szTemp1,0x00,sizeof(szTemp1));

		
		inMarkup = atof(srTransRec.szDCCMarkupPer);
		sprintf(szTemp,"%.2f",inMarkup);
		sprintf(szTemp1,"%20.20s",szTemp);
		//sprintf(szTemp1,"%s",szTemp);
		sprintf(szTemp2,"Markup:%s",szTemp1);
		strcat(szTemp2,"%");
		
		setLCDPrint((strTCT.byTerminalType%2)?7:10,DISPLAY_POSITION_LEFT,szTemp2);
	}
	
	srTransRec.fDCC = VS_FALSE;
	
	if(strTCT.inDCCMode == PRINT_DCC_RATES)
	{
		while(1)
		{
			key=WaitKey(inGetIdleTimeOut(TRUE));
			
	       	if(key == d_KBD_1)
	       	{
				return d_OK;
	       	}
	       	else if(key == d_KBD_2)
	       	{	
				srTransRec.fDCC = VS_TRUE;			
			
				memset(srTransRec.szDCCLocalAmount,0x00,sizeof(srTransRec.szDCCLocalAmount));
				memcpy(srTransRec.szDCCLocalAmount, srTransRec.szTotalAmount,sizeof(srTransRec.szTotalAmount));

				return d_OK;
			}
		}
	}
	else
	{
		while(1)
		{
			key=WaitKey(inGetIdleTimeOut(TRUE));
			
	       	if(key == d_KBD_1)
	       	{
				return d_OK;
	       	}
	       	else if(key == d_KBD_2)
	       	{	
				srTransRec.fDCC = VS_TRUE;			
			
				memset(srTransRec.szDCCLocalAmount,0x00,sizeof(srTransRec.szDCCLocalAmount));
				memcpy(srTransRec.szDCCLocalAmount, srTransRec.szTotalAmount,sizeof(srTransRec.szTotalAmount));

				return d_OK;
			}
	        else if(key == d_KBD_CANCEL)
	        {
				return FAIL;
	        } 
			else if(key == 0xFF)
			{
				return FAIL;
			}

		}
	}
	
	
}


int inDisplayRateHostError(void)
{
	int iLine=0;
	BYTE key=0;

	CTOS_LCDTClearDisplay();
	setLCDPrint27((strTCT.byTerminalType%2)?2:3,DISPLAY_POSITION_CENTER,"RATE HOST ERROR");
	setLCDPrint((strTCT.byTerminalType%2)?4:5,DISPLAY_POSITION_LEFT,"PROCEED TO?");
	setLCDPrint((strTCT.byTerminalType%2)?5:6,DISPLAY_POSITION_LEFT,"BDO HOST");
	setLCDPrint((strTCT.byTerminalType%2)?6:7,DISPLAY_POSITION_RIGHT,"(1) YES");
	setLCDPrint((strTCT.byTerminalType%2)?8:9,DISPLAY_POSITION_RIGHT,"(2) NO");

	while(1)
	{
		key=WaitKey(inGetIdleTimeOut(TRUE));

       	if(key == d_KBD_1)
       	{
			return d_OK;
       	}
       	else if(key == d_KBD_2)
      	{	
			return FAIL;
			
		}
        else if(key == d_KBD_CANCEL)
        {
			return FAIL;
        } 
		else if(key == 0xFF)
		{
			return FAIL;
		}

	}
	
}

void vdDisplayErrorMsgResp3 (char *msg, char *msg2, char *msg3, char *msg4)
{
   CTOS_LCDTClearDisplay();

   if ((strTCT.byTerminalType % 2) == 1) 
   {
		vduiDisplayStringCenter(3,msg);
		vduiDisplayStringCenter(4,msg2);
		vduiDisplayStringCenter(5,msg3);
		vduiDisplayStringCenter(6,msg4);
			
   }
   else 
   {
      vduiDisplayStringCenter(6, msg);
      vduiDisplayStringCenter(7, msg2);
      vduiDisplayStringCenter(8, msg3);
	  vduiDisplayStringCenter(9,msg4);
	  
   }
	 
   CTOS_Beep();
   CTOS_Delay(1500);
   CTOS_LCDTClearDisplay();
}

void vdDispTransTitleAndCardType(BYTE byTransType)
{
    BYTE szTitle[16+1];
    BYTE szTitleDisplay[MAX_CHAR_PER_LINE+1], szAmtBuff[20+1], szCurAmtBuff[20+1];
    int iInitX = 1;
		int inCardLabellen, inCardDispStart, inMaxDisplen;
		char szDisplayCardLable [MAX_CHAR_PER_LINE+1];
		char szVoidCurrSymbol [10+1];
	
//issue-00229: do not display amount on TC upload
    //SIT
    if (inGetATPBinRouteFlag() == TRUE)		
		return d_OK;

	if(srTransRec.byPackType == TC_UPLOAD || fAdviceTras == TRUE)
		return d_OK;

	vdDebug_LogPrintf("****vdDispTransTitleAndCardType****");
		/* BDOCLG-00318: Fix for garbage display problem - start -- jzg */
		//inTCTRead(1);
		//if(((strTCT.fFleetGetLiters == TRUE) || (strTCT.fGetDescriptorCode == TRUE)) && (srTransRec.fFleetCard == TRUE))
		//	CTOS_LCDFontSelectMode(d_FONT_TTF_MODE);
		//else
			//CTOS_LCDFontSelectMode(d_FONT_FNT_MODE);
		/* BDOCLG-00318: Fix for garbage display problem - end -- jzg */
   
    memset(szTitle, 0x00, sizeof(szTitle));

	if(srTransRec.fOptOut)
		strcpy(szTitle,"OPT OUT");
	else if(byTransType == VOID)
		strcpy(szTitle,"VOID");
	else		
		szGetTransTitle(byTransType, szTitle);

	iInitX = 40;
    memset(szTitleDisplay, 0x00, sizeof(szTitleDisplay));
    memset(szTitleDisplay, 0x20, MAX_CHAR_PER_LINE);
    memcpy(&szTitleDisplay[0], szTitle, strlen(szTitle));
	memset(szDisplayCardLable, 0x00, sizeof(szDisplayCardLable));

	if(strcmp(srTransRec.szCardLable,"CITI MASTER")==0)
		memcpy(&szDisplayCardLable[0],"MASTERCARD",10);
	else if(strcmp(srTransRec.szCardLable,"CITI VISA")==0)
		memcpy(&szDisplayCardLable[0],"VISA",4);
	else
		memcpy(&szDisplayCardLable[0],srTransRec.szCardLable,strlen(srTransRec.szCardLable));
		
    inCardLabellen = strlen(szDisplayCardLable);
		
   
   if ((srTransRec.byTransType == SALE) ||(srTransRec.byTransType == PRE_AUTH) || (srTransRec.byTransType == CASH_ADVANCE) || (srTransRec.byTransType == VOID) || (srTransRec.byTransType == BIN_VER))
   {
          
		BYTE szBaseAmt[AMT_ASC_SIZE + 1] = {0};
		{
	        inCardDispStart = iInitX  - inCardLabellen * 2;
				
			CTOS_LCDFontSelectMode(d_FONT_TTF_MODE);
			CTOS_LCDTSetReverse(TRUE);
			CTOS_LCDTPrintXY(1,1,szTitleDisplay);
			if ((inGetATPBinRouteFlag() != TRUE) && (srTransRec.byTransType != BIN_VER)	)
				   CTOS_LCDTPrintAligned(1, szDisplayCardLable, d_LCD_ALIGNRIGHT);
			
			CTOS_LCDTSetReverse(FALSE);
		}
#if 0
    if (srTransRec.byTransType != BIN_VER)
    {
       CTOS_LCDFontSelectMode(d_FONT_TTF_MODE);
       wub_hex_2_str(srTransRec.szTotalAmount, szBaseAmt, 6); 
       vdCTOS_FormatAmount(strCST.szAmountFormat, szBaseAmt,szAmtBuff); // patrick fix case #229
       
       setLCDPrint(3, DISPLAY_POSITION_LEFT, "TOTAL:");
       
       
       if (srTransRec.byTransType == VOID)   
       {
          memset(szVoidCurrSymbol,0,sizeof(szVoidCurrSymbol));
          strcpy(szVoidCurrSymbol,strCST.szCurSymbol); 
          strcat(szVoidCurrSymbol,"-");
          sprintf(szCurAmtBuff,"%s%s",szVoidCurrSymbol, szAmtBuff);
          setLCDPrint(5, DISPLAY_POSITION_CENTER, szCurAmtBuff);
       }
       else
       {
          sprintf(szCurAmtBuff,"%s%s",strCST.szCurSymbol, szAmtBuff);
          //issue-00371
          //inCTOS_DisplayCurrencyAmount(srTransRec.szTotalAmount, 5, DISPLAY_POSITION_CENTER);	 
          setLCDPrint(5, DISPLAY_POSITION_CENTER, szCurAmtBuff);
       }

    }
#endif
	 }
#if 0
   else if(srTransRec.byTransType == BIN_VER)
   {
      inCardDispStart = iInitX  - inCardLabellen * 2;
      CTOS_LCDFontSelectMode(d_FONT_TTF_MODE);
      //memcpy(&szTitleDisplay[inCardDispStart], szDisplayCardLable, inCardLabellen);
      CTOS_LCDTSetReverse(TRUE);
      //CTOS_LCDTPrintAligned(1, szTitle, d_LCD_ALIGNLEFT);
      //CTOS_LCDTPrintAligned(1, szTitleDisplay, d_LCD_ALIGNLEFT);
	  
	  CTOS_LCDTPrintXY(1,1,szTitleDisplay);
	  if (inGetATPBinRouteFlag() == TRUE)	
      	CTOS_LCDTPrintAligned(1, szDisplayCardLable, d_LCD_ALIGNRIGHT);
      CTOS_LCDTSetReverse(FALSE);
   }
#endif
	 else
	 	CTOS_LCDFontSelectMode(d_FONT_TTF_MODE); 
}

int inDisplayDCCRateScreenEx(void)
{
	VS_BOOL fDisplayForExRate = inFLGGet("fForExRate");
	VS_BOOL fDisplayMarkup = inFLGGet("fDCCMarkUp");
	char szTemp[MAX_CHAR_PER_LINE+1];
	char szTemp1[MAX_CHAR_PER_LINE+1];
	char szTemp2[MAX_CHAR_PER_LINE+1];
	BYTE szAmtBuff[20+1], szCurAmtBuff[20+1];
	BYTE szBaseAmt[AMT_ASC_SIZE + 1] = {0};
	int iLine,inLength=0;
	BYTE key=0;
	float inMarkup = 0;

	//#define RATE_RESPONSE_FULL "\x01\x70\x37\x31\x30\x30\x39\x63\x66\x34\x63\x32\x64\x64\x34\x38\x66\x34\x63\x32\x30\x38\x34\x35\x37\x32\x35\x32\x38\x30\x30\x31\x33\x36\x30\x35\x30\x30\x20\x20\x20\x20\x20\x20\x20\x20\x31\x31\x31\x32\x33\x34\x35\x36\x37\x38\x39\x31\x30\x30\x33\x36\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x34\x37\x32\x38\x30\x30\x31\x38\x34\x38\x39\x34\x33\x32\x30\x32\x30\x31\x32\x30\x39\x32\x32\x31\x32\x32\x38\x31\x38\x33\x35\x36\x30\x33\x36\x56\x53\x41\x64\x64\x37\x35\x34\x30\x38\x34\x39\x35\x35\x36\x30\x30\x38\x34\x35\x37\x32\x35\x32\x38\x30\x30\x31\x33\x36\x30\x35\x30\x32\x20\x20\x20\x20\x20\x20\x20\x20\x30\x30\x30\x30\x30\x31\x41\x55\x44\x34\x38\x33\x2E\x30\x32\x20\x20\x20\x20\x20\x30\x33\x36"
	
	//inUnPackIsoFunc61(&srTransRec,RATE_RESPONSE_FULL);
	
	CTOS_LCDTClearDisplay();
	
	iLine = ((strTCT.byTerminalType%2)?3:4);
	
	wub_hex_2_str(srTransRec.szDCCLocalAmount, szBaseAmt, 6); 
	vdCTOS_FormatAmount("NN,NNN,NNN,NNn.nn", szBaseAmt,szAmtBuff); 
	sprintf(szCurAmtBuff,"(1)%s %s", srTransRec.szDCCLocalSymbol, szAmtBuff);
	setLCDPrint(2, DISPLAY_POSITION_RIGHT, szCurAmtBuff);

	memset(szAmtBuff,0x00,sizeof(szAmtBuff));
	memset(szCurAmtBuff,0x00,sizeof(szCurAmtBuff));
	memset(szBaseAmt,0x00,sizeof(szBaseAmt));

	inCSTReadHostID(srTransRec.szDCCCur);


    if(strTCT.fFormatDCCAmount == TRUE)
    	vdDCCModifyAmount(srTransRec.szDCCCurAmt,szAmtBuff);
	else
		vdCTOS_FormatAmount(strCST.szAmountFormat, srTransRec.szDCCCurAmt,szAmtBuff);
	
	
	sprintf(szCurAmtBuff,"(2)%s %s",srTransRec.szDCCCurSymbol, szAmtBuff);// Wait for strCST for foreign currency
	setLCDPrint((strTCT.byTerminalType%2)?3:4, DISPLAY_POSITION_RIGHT, szCurAmtBuff);

	if(fDisplayForExRate)
	{
		inLength=strlen(srTransRec.szDCCFXRate)-srTransRec.inDCCFXRateMU;
		memset(szTemp,0x00,sizeof(szTemp));
		memcpy(szTemp,srTransRec.szDCCFXRate,inLength);
		memcpy(&szTemp[inLength],".",1);
		memcpy(&szTemp[inLength+1],&srTransRec.szDCCFXRate[inLength],srTransRec.inDCCFXRateMU);
			
		setLCDPrint((strTCT.byTerminalType%2)?5:7, DISPLAY_POSITION_LEFT, "Exchange Rate:");
		setLCDPrint((strTCT.byTerminalType%2)?6:8, DISPLAY_POSITION_RIGHT,szTemp);	
	}

	if(fDisplayMarkup)
	{
		memset(szTemp,0x00,sizeof(szTemp));
		memset(szTemp1,0x00,sizeof(szTemp1));
		
		inMarkup = atof(srTransRec.szDCCMarkupPer);
		sprintf(szTemp,"%.2f",inMarkup);
		sprintf(szTemp1,"%20.20s",szTemp);
		//sprintf(szTemp1,"%s",szTemp);
		sprintf(szTemp2,"Markup:%s",szTemp1);
		strcat(szTemp2,"%");
		
		setLCDPrint((strTCT.byTerminalType%2)?7:10,DISPLAY_POSITION_LEFT,szTemp2);
	}

	while(1)
	{
		key=WaitKey(inGetIdleTimeOut(TRUE));

       	if(key == d_KBD_1)
       	{
			//srTransRec.fDCC = VS_FALSE;
			return FAIL;
       	}
       	else if(key == d_KBD_2)
       	{	
			return VS_CONTINUE;
		}

	}

	
	
}

void vdDisplayMultiLineMsgAlign(char *msg, char *msg2, char *msg3, int inPosition)
{
   int inAlign = 0;
   
   CTOS_LCDTClearDisplay();
   vdDispTransTitle(srTransRec.byTransType);

   switch (inPosition)
   {
   	 case DISPLAY_POSITION_LEFT:
	 	inAlign = d_LCD_ALIGNLEFT;
	 	break;
	 case DISPLAY_POSITION_RIGHT:
	 	inAlign = d_LCD_ALIGNRIGHT;
	 	break;
	 case DISPLAY_POSITION_CENTER:
	 	inAlign = d_LCD_ALIGNCENTER;
	 	break;
	  default:
	  	inAlign = d_LCD_ALIGNCENTER;
	  	break;
   }
   
	if ((strTCT.byTerminalType % 2) == 0)
   {	
   		if (strlen(msg) > 0)
			CTOS_LCDTPrintAligned(6, msg, inAlign);

		if (strlen(msg2) > 0)
			CTOS_LCDTPrintAligned(7, msg2, inAlign);

		if (strlen(msg3) > 0)
			CTOS_LCDTPrintAligned(8, msg3, inAlign);
   }
   else 
   {
   		if (strlen(msg) > 0)
			setLCDPrint27(4, inAlign, msg);

		if (strlen(msg2) > 0)
			setLCDPrint27(5, inAlign, msg2);

		if (strlen(msg3) > 0)
			setLCDPrint27(6, inAlign, msg3);
   }
	 
   CTOS_Beep();
   CTOS_Delay(1000);
   vduiClearBelow(2);
   
}

void vduiScreenBackLight(BOOL fTerminalActive)
{
	int iBrightness = get_env_int("BRIGHTNESS");
	int iIdleBrightness = get_env_int("IDLEBRIGHTNESS");

	if(get_env_int("DIMONIDLE") <= 0)
		return;
	
	vdDebug_LogPrintf("--vduiScreenBackLight--");
	vdDebug_LogPrintf("fTerminalActive=[%d]", fTerminalActive);

	if(VS_TRUE == fTerminalActive)
	{	
		vdSetIdleEvent(1);
		fDimFlag = FALSE;
		CTOS_BackLightSetBrightness(d_BKLIT_LCD, (iBrightness > 0 ? iBrightness : 50));
	}
	else
	{
		fDimFlag = TRUE;
		CTOS_BackLightSetBrightness(d_BKLIT_LCD, (iIdleBrightness > 0 ? iIdleBrightness : 1));						
	}

	return;
}

