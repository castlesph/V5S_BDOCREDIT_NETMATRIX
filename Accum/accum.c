
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctosapi.h>


#include "accum.h"
#include "..\FileModule\myFileFunc.h"
#include "..\Includes\POSTrans.h"
#include "..\POWRFAIL\POSPOWRFAIL.h"
#include "..\Debug\Debug.h"
#include "..\Includes\Wub_lib.h"
#include "..\Includes\myEZLib.h"
#include "..\Includes\POSSetting.h"
#include "..\ui\Display.h"
#include "../Ctls/POSCtls.h"

extern BOOL fSMACTRAN;

void vdCTOS_GetAccumName(STRUCT_FILE_SETTING *strFile, ACCUM_REC *strTotal)
{
    sprintf(strFile->szFileName, "ACC%02d%02d.total"
                                , strHDT.inHostIndex
                                , srTransRec.MITid);
                                
    strFile->bSeekType           = d_SEEK_FROM_BEGINNING;
    strFile->bStorageType        = d_STORAGE_FLASH ;
    strFile->fCloseFileNow       = TRUE;
    strFile->ulRecSize           = sizeof(ACCUM_REC);
    strFile->ptrRec              = strTotal;    


	vdDebug_LogPrintf("TEST Accum name[%s]", strFile->szFileName);
}


int inCTOS_ReadAccumTotal(ACCUM_REC *strTotal)
{
    STRUCT_FILE_SETTING strFile;
		char exe_dir[100];
    
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));
    memset(strTotal, 0x00, sizeof(ACCUM_REC));

		getcwd(exe_dir, sizeof(exe_dir));
	  vdDebug_LogPrintf("AAA - inCTOS_ReadAccumTotal [%s]", exe_dir);
    
    vdCTOS_GetAccumName(&strFile, strTotal);

    return (inMyFile_RecRead(&strFile));    
}

int inCTOS_SaveAccumTotal(ACCUM_REC *strTotal)
{
    STRUCT_FILE_SETTING strFile;
		char exe_dir[100];
    
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));

		getcwd(exe_dir, sizeof(exe_dir));
	  vdDebug_LogPrintf("AAA - inCTOS_SaveAccumTotal [%s]", exe_dir);
    
    vdCTOS_GetAccumName(&strFile, strTotal);

    return (inMyFile_RecSave(&strFile));    
}

int inCTOS_UpdateAccumTotal(void)
{
    ACCUM_REC srAccumRec;
    BYTE        szTransAmt[12+1];
    BYTE        szTipAmt[12+1];
    BYTE        szOrgAmt[12+1];
    BYTE		szLocalTransAmt[12+1];
    int         inResult;
    int inTranCardType = 0;
    
    BYTE szBaseAmt[AMT_ASC_SIZE + 1] = {0};

    vdDebug_LogPrintf("inCTOS_UpdateAccumTotal %d %d %d %d", srTransRec.byOrgTransType, srTransRec.byTransType, srTransRec.inCardType, srTransRec.IITid);
	
    if(inCheckIfDCCHost() == TRUE && srTransRec.fDCC == TRUE)
    {
		vdDebug_LogPrintf("inCTOS_UpdateDCCAccumTotal");
        return inCTOS_UpdateDCCAccumTotal();
    }
		
    memset(szTransAmt, 0x00, sizeof(szTransAmt));
    memset(szTipAmt, 0x00, sizeof(szTipAmt));
    memset(szOrgAmt, 0x00, sizeof(szOrgAmt));
	memset(szLocalTransAmt, 0x00, sizeof(szLocalTransAmt));
    wub_hex_2_str(srTransRec.szTotalAmount, szTransAmt, 6);
    wub_hex_2_str(srTransRec.szOrgAmount, szOrgAmt, 6);
	wub_hex_2_str(srTransRec.szDCCLocalAmount, szLocalTransAmt, 6);
	wub_hex_2_str(srTransRec.szBaseAmount, szBaseAmt, 6);
	wub_hex_2_str(srTransRec.szTipAmount, szTipAmt, 6);
	
	if (srTransRec.inCardType == CREDIT_CARD)
	{
		inTranCardType = 0;//save credit card accue total
		if(srTransRec.IITid == 23)//change issuer from CITI VISA to VISA
			srTransRec.IITid=2;
		else if(srTransRec.IITid == 24)//change issuer from CITI MC to MC
			srTransRec.IITid=4;
	}
    else
    {
    	inTranCardType = 1;//save debit card accue total
    }

	memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
    if((inResult = inCTOS_ReadAccumTotal(&srAccumRec)) == ST_ERROR)
    {
        vdMyEZLib_LogPrintf("[vdUpdateAmountTotal]---Read Total Rec. error");
		vdSetErrorMessage("Read Accum Error");
        return ST_ERROR;    
    }        

/* for testing --- 07 Jan 2021
    vdDebug_LogPrintf("byTransType[%d].byOrgTransType[%d].szOriginTipTrType[%d]IITid[%d]", srTransRec.byTransType, srTransRec.byOrgTransType, szOriginTipTrType, srTransRec.IITid);
    
	vdDebug_LogPrintf("szTotalAmount=[%s],szTipAmount=[%s],szOrgAmount=[%s],.inCardType[%d]",szTransAmt,szTipAmt,szOrgAmt,srTransRec.inCardType);
    vdDebug_LogPrintf("CardTotal SaleCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount);
    vdDebug_LogPrintf("CardTotal OfflCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usOffSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulOffSaleTotalAmount);
    vdDebug_LogPrintf("CardTotal RefdCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usRefundCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulRefundTotalAmount);            
    vdDebug_LogPrintf("CardTotal VoidCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usVoidSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulVoidSaleTotalAmount);    
    vdDebug_LogPrintf("CardTotal TipCount [%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usTipCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulTipTotalAmount);
	vdDebug_LogPrintf("CardTotal CashAdvCount [%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usCashAdvCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulCashAdvTotalAmount);
	vdDebug_LogPrintf("CardTotal Local SaleCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalSaleTotalAmount);
	vdDebug_LogPrintf("CardTotal Local VoidCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usVoidSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalVoidSaleTotalAmount);	

    vdDebug_LogPrintf("HostTotal SaleCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount);
    vdDebug_LogPrintf("HostTotal OfflCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount);
    vdDebug_LogPrintf("HostTotal RefdCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount);            
    vdDebug_LogPrintf("HostTotal VoidCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount);    
    vdDebug_LogPrintf("HostTotal TipCount [%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount);
    vdDebug_LogPrintf("HostTotal CashAdvCount [%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount);
    vdDebug_LogPrintf("HostTotal Local SaleCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalSaleTotalAmount);
	vdDebug_LogPrintf("HostTotal Local VoidCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalVoidSaleTotalAmount);    
*/

    switch(srTransRec.byTransType)
    {
        //version16
		case VOID_PREAUTH:
			vdDebug_LogPrintf("void pre -auth");
            //srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usPreAuthCount--;
			srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulPreAuthTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulPreAuthTotalAmount - atof(szTransAmt);

            //srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usPreAuthCount--;

			srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulPreAuthTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulPreAuthTotalAmount - atof(szTransAmt);
		//version16
		
		//1102
		case CASH_ADVANCE:
			
            srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usCashAdvCount++;
            srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulCashAdvTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulCashAdvTotalAmount + atof(szTransAmt);
            
            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount++;
            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount + atof(szTransAmt);
			break;
		//1102

        case SALE:
			
			vdDebug_LogPrintf("SALE");
			srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usSaleCount++;
			srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount++;
			srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount + atof(szTransAmt);
            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount + atof(szTransAmt); 
			if(srTransRec.fDCC == TRUE)
			{
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalSaleTotalAmount + atof(szLocalTransAmt);
           	    srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalSaleTotalAmount= srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalSaleTotalAmount + atof(szLocalTransAmt);  
			}
						
//            if((srTransRec.byTransType == SALE) && (srTransRec.byEntryMode == CARD_ENTRY_ICC))
			if (((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||
				/* EMV: Revised EMV details printing - start -- jzg */
				//(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||		
				(srTransRec.bWaveSID == 0x65) ||
				(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
				(srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
				(srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
				(srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
				//(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_2) ||
				(srTransRec.bWaveSID == 0x63) ||
				(srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS) ||
				(srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC)) && (srTransRec.byTransType == SALE))
				/* EMV: Revised EMV details printing - end -- jzg */ // patrick fix contactless 20140828
                srAccumRec.stBankTotal[inTranCardType].usEMVTCCount++;
            break;            
        case SALE_OFFLINE:
            
            srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usOffSaleCount++;
            srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulOffSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulOffSaleTotalAmount + atof(szTransAmt);
            
            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount++;
            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount + atof(szTransAmt);

			if (inCheckIfSMCardTransRec() == FALSE){

            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usSaleCount++;
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount + atof(szTransAmt);
            
            	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount++;
            	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount + atof(szTransAmt);
			}
 
            break;
        case REFUND:
            srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usRefundCount++;
            srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulRefundTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulRefundTotalAmount + atof(szTransAmt);
            
            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount++;
            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount + atof(szTransAmt);
            
            break;
        case VOID:

			
            if(srTransRec.byOrgTransType == CASH_ADVANCE)
			{
				
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usVoidCashAdvCount++;
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulVoidCashAdvTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulVoidCashAdvTotalAmount + atof(szTransAmt);
            
            	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidCashAdvCount++;
            	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidCashAdvTotalAmount + atof(szTransAmt);


				//srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usCashAdvCount--;
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulCashAdvTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulCashAdvTotalAmount - atof(szTransAmt);
			
				//srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount--;
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount - atof(szTransAmt);

            }else
            {
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usVoidSaleCount++;
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount++;  	           	
            	srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulVoidSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulVoidSaleTotalAmount + atof(szTransAmt);
               	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + atof(szTransAmt);

				if(srTransRec.fDCC == TRUE)
				{
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalVoidSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalVoidSaleTotalAmount + atof(szLocalTransAmt);
					srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalVoidSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalVoidSaleTotalAmount + atof(szLocalTransAmt);
				}
            }
			
            if(srTransRec.byOrgTransType == SALE)
            {
            
                //do not decuct void count for SMAC redemption
				//if (inCheckIfSMCardTransRec() == FALSE || srTransRec.HDTid == SMECARD_HDT_INDEX || srTransRec.HDTid == SMPARTNER_HDT_INDEX)
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usSaleCount--;
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount - atof(szTransAmt);
				if(srTransRec.fDCC == TRUE)
					srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalSaleTotalAmount - atof(szLocalTransAmt);	
				
                //do not decuct void count for SMAC redemption
				//if (inCheckIfSMCardTransRec() == FALSE || srTransRec.HDTid == SMECARD_HDT_INDEX || srTransRec.HDTid == SMPARTNER_HDT_INDEX)
                srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount--;

				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount - atof(szTransAmt);
				if(srTransRec.fDCC == TRUE)
					srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalSaleTotalAmount - atof(szLocalTransAmt);
			}
            else if(srTransRec.byOrgTransType == SALE_OFFLINE)
            {

				
				vdDebug_LogPrintf("SMAC ACCUM %d", fSMACTRAN);
				
                //do not decuct void count and amount for SMAC points award
				//if (inCheckIfSMCardTransRec() == FALSE){
                	srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usSaleCount--;
                	srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount - atof(szTransAmt);
                //}
                //do not decuct void count and amount  for SMAC points award
				//if (inCheckIfSMCardTransRec() == FALSE){
					srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount--;
                	srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount - atof(szTransAmt);
                //}
                //do not decuct void count for SMAC points award
				//if (inCheckIfSMCardTransRec() == FALSE)
                srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usOffSaleCount--;
                srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulOffSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulOffSaleTotalAmount - atof(szTransAmt);            

                //do not decuct void count for SMAC points award
				//if (inCheckIfSMCardTransRec() == FALSE)
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount--;
                srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount - atof(szTransAmt);


			vdDebug_LogPrintf("SMAC CardTotal SaleCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount);
			vdDebug_LogPrintf("SMAC CardTotal OfflCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usOffSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulOffSaleTotalAmount);
			vdDebug_LogPrintf("SMAC HostTotal SaleCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount);
			vdDebug_LogPrintf("SMAC HostTotal OfflCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount);

            }
            else if(srTransRec.byOrgTransType == SALE_TIP)
            {
							if (szOriginTipTrType == SALE_OFFLINE)
							{                    
								vdDebug_LogPrintf("JEFF::VOID TIP OFFLINE SALE!");
								/* BDO: To fix incorrect totals in detail and summary report - start -- jzg */
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usSaleCount--;
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount - atof(szTransAmt);
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usOffSaleCount--;
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulOffSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulOffSaleTotalAmount - atof(szTransAmt); 					 
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usTipCount--;
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulTipTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulTipTotalAmount - atof(szTipAmt); 					 


								srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount--;
								srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount - atof(szTransAmt);
								srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount--;
								srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount - atof(szTransAmt);							
								srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount--;
								srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount - atof(szTipAmt);
								/* BDO: To fix incorrect totals in detail and summary report - end -- jzg */
							}
							else if(szOriginTipTrType == SALE) 
							{
								vdDebug_LogPrintf("JEFF::VOID TIP ONLINE SALE!");
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usTipCount--;
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulTipTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulTipTotalAmount - atof(szTipAmt);            
								srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount--;
								srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount - atof(szTipAmt);

								srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usSaleCount--;
								srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount - atof(szTransAmt);            
								srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount--;
								srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount - atof(szTransAmt);								
#if 0
								if(srTransRec.fDCC)// For Tip Handling on DCC Accums. Need to create szLocalTipAmount
								{
									srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalTipTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalTipTotalAmount - atof(szTipAmt);            
									srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalTipTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalTipTotalAmount - atof(szTipAmt);
									srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalSaleTotalAmount - atof(szTransAmt);
									srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalSaleTotalAmount - atof(szTransAmt);								
								}
#endif
							}
            }
            else if(srTransRec.byOrgTransType == REFUND)
            {
                srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usRefundCount--;
                srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulRefundTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulRefundTotalAmount - atof(szTransAmt);
            
                srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount--;
                srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount - atof(szTransAmt);
            }
			else if(srTransRec.byOrgTransType == KIT_SALE)
            {
                srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usKitSaleCount--;
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulKitSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulKitSaleTotalAmount - atof(szTransAmt);

				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usKitSaleCount--;
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulKitSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulKitSaleTotalAmount - atof(szTransAmt);
			}
			else if(srTransRec.byOrgTransType == RENEWAL)
            {
                srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usRenewalCount--;
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulRenewalTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulRenewalTotalAmount - atof(szTransAmt);

				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRenewalCount--;
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRenewalTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRenewalTotalAmount - atof(szTransAmt);
			}
			else if(srTransRec.byOrgTransType == PTS_AWARDING)
            {
                srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usPtsAwardCount--;
				srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulPtsAwardTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulPtsAwardTotalAmount - atof(szTransAmt);

				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usPtsAwardCount--;
				srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulPtsAwardTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulPtsAwardTotalAmount - atof(szTransAmt);
			}
            
            break;
        case SALE_TIP:
					vdDebug_LogPrintf("[**SALE TIP***");
            if(srTransRec.byOrgTransType == SALE_OFFLINE)
            {
							vdDebug_LogPrintf("[**OFFLINE SALE TIP***");
							/* BDO: To fix incorrect totals in detail and summary report - start -- jzg */
							srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usTipCount++;
							srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulTipTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulTipTotalAmount + atof(szTipAmt) - (atof(szOrgAmt) - atof(szBaseAmt)); 					
							srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulOffSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulOffSaleTotalAmount + atof(szTransAmt) - atof(szOrgAmt);  
							srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount + atof(szTransAmt) - atof(szOrgAmt);			 

							srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount++;
							srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount + atof(szTipAmt) - (atof(szOrgAmt) - atof(szBaseAmt));
							srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount + atof(szTipAmt) ;
							srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount + atof(szTransAmt) - atof(szOrgAmt);
							/* BDO: To fix incorrect totals in detail and summary report - end -- jzg */
            }
            else 
            {
							vdDebug_LogPrintf("[**ONLINE SALE TIP***");

							/* BDO: To fix incorrect totals in detail and summary report - start -- jzg */
	            srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usTipCount++;
	            srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulTipTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulTipTotalAmount + atof(szTipAmt) - (atof(szOrgAmt) - atof(szBaseAmt));
							srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount + atof(szTransAmt) - atof(szOrgAmt);
							srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount + atof(szTransAmt) - atof(szOrgAmt); 		   
	            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount++;
	            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount + atof(szTipAmt) - (atof(szOrgAmt) - atof(szBaseAmt));
							/* BDO: To fix incorrect totals in detail and summary report - end -- jzg */
            }
            break;
        case SALE_ADJUST:   
					
					vdDebug_LogPrintf("[**SALE ADJUST***");
            srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount - atof(szOrgAmt);
            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount - atof(szOrgAmt);
            
            srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount + atof(szTransAmt);
            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount + atof(szTransAmt);
            break;


		case KIT_SALE:   
				
			vdDebug_LogPrintf("***KIT SALE***");
			srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usKitSaleCount++;
			srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usKitSaleCount++;
			srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulKitSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulKitSaleTotalAmount + atof(szTransAmt);
			srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulKitSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulKitSaleTotalAmount + atof(szTransAmt); 
	        break;

		case RENEWAL:   
				
			vdDebug_LogPrintf("***RENEWAL***");
			srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usRenewalCount++;
			srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRenewalCount++;
			srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulRenewalTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulRenewalTotalAmount + atof(szTransAmt);
			srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRenewalTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRenewalTotalAmount + atof(szTransAmt); 
	        break;

		case PTS_AWARDING:   
				
			vdDebug_LogPrintf("***PTS AWARDING***");
			srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usPtsAwardCount++;
			srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usPtsAwardCount++;
			srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulPtsAwardTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulPtsAwardTotalAmount + atof(szTransAmt);
			srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulPtsAwardTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulPtsAwardTotalAmount + atof(szTransAmt); 
	        break;
		
        default:
            break;
        
    }

    
    vdDebug_LogPrintf("szTotalAmount=[%s],szTipAmount=[%s],szOrgAmount=[%s],.inCardType[%d]",szTransAmt,szTipAmt,szOrgAmt,srTransRec.inCardType);
    vdDebug_LogPrintf("CardTotal SaleCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount);
    vdDebug_LogPrintf("CardTotal OfflCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usOffSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulOffSaleTotalAmount);
    vdDebug_LogPrintf("CardTotal RefdCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usRefundCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulRefundTotalAmount);            
    vdDebug_LogPrintf("CardTotal VoidCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usVoidSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulVoidSaleTotalAmount);    
    vdDebug_LogPrintf("CardTotal TipCount [%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usTipCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulTipTotalAmount);
	vdDebug_LogPrintf("CardTotal Local SaleCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalSaleTotalAmount);
    vdDebug_LogPrintf("CardTotal Local VoidCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usVoidSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalVoidSaleTotalAmount);    
	
    vdDebug_LogPrintf("HostTotal SaleCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount);
    vdDebug_LogPrintf("HostTotal OfflCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount);
    vdDebug_LogPrintf("HostTotal RefdCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount);            
    vdDebug_LogPrintf("HostTotal VoidCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount);    
    vdDebug_LogPrintf("HostTotal TipCount [%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount);
	vdDebug_LogPrintf("HostTotal Local SaleCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalSaleTotalAmount);
	vdDebug_LogPrintf("HostTotal Local VoidCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalVoidSaleTotalAmount);	 
	
    if((inResult = inCTOS_SaveAccumTotal(&srAccumRec)) == ST_ERROR)
    {
        vdMyEZLib_LogPrintf("[vdUpdateAmountTotal]---Save Total Rec. error");
		vdSetErrorMessage("Save Accum Error");
        return ST_ERROR;    
    }

   	inCTLOS_Updatepowrfail(PFR_BATCH_UPDATE_COMPLETE);

    vdMyEZLib_LogPrintf("total file saved successfully");

    return ST_SUCCESS;
}

//format amount 10+2 change all atol to atof
int inCTOS_UpdateDCCAccumTotal(void)
{
    ACCUM_REC srAccumRec;
    BYTE szTransAmt[12+1];
    BYTE szTipAmt[12+1];
    BYTE szOrgAmt[12+1];
    BYTE szLocalTransAmt[12+1], szLocalTipTransAmt[12+1], szLocalOrigTipTransAmt[12+1];
    int inResult;
    int inTranCardType = 0;


		BYTE szBaseAmt[AMT_ASC_SIZE + 1] = {0};

    vdDebug_LogPrintf("inCTOS_UpdateAccumTotal");
    
    memset(szTransAmt, 0x00, sizeof(szTransAmt));
    memset(szTipAmt, 0x00, sizeof(szTipAmt));
    memset(szOrgAmt, 0x00, sizeof(szOrgAmt));
	memset(szLocalTransAmt, 0x00, sizeof(szLocalTransAmt));
	memset(szLocalTipTransAmt, 0x00, sizeof(szLocalTipTransAmt));
	memset(szLocalOrigTipTransAmt, 0x00, sizeof(szLocalOrigTipTransAmt));
	
    wub_hex_2_str(srTransRec.szTotalAmount, szTransAmt, 6);
    wub_hex_2_str(srTransRec.szOrgAmount, szOrgAmt, 6);
	wub_hex_2_str(srTransRec.szDCCLocalAmount, szLocalTransAmt, 6);
	wub_hex_2_str(srTransRec.szBaseAmount, szBaseAmt, 6);
	wub_hex_2_str(srTransRec.szTipAmount, szTipAmt, 6);
	
	wub_hex_2_str(srTransRec.szDCCLocalTipAmount, szLocalTipTransAmt, 6);
	wub_hex_2_str(srTransRec.szDCCOrigLocalTipAmount, szLocalOrigTipTransAmt, 6);
	
	if (srTransRec.inCardType == CREDIT_CARD)
	{
		inTranCardType = 0;//save credit card accue total
		if(srTransRec.IITid == 23)//change issuer from CITI VISA to VISA
			srTransRec.IITid=2;
		else if(srTransRec.IITid == 24)//change issuer from CITI MC to MC
			srTransRec.IITid=4;
	}
    else
    {
    	inTranCardType = 1;//save debit card accue total
    }

	memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
    if((inResult = inCTOS_ReadAccumTotal(&srAccumRec)) == ST_ERROR)
    {
        vdMyEZLib_LogPrintf("[vdUpdateAmountTotal]---Read Total Rec. error");
		vdSetErrorMessage("Read Accum Error");
        return ST_ERROR;    
    }        

    vdDebug_LogPrintf("byTransType[%d].byOrgTransType[%d].szOriginTipTrType[%d]IITid[%d]", srTransRec.byTransType, srTransRec.byOrgTransType, szOriginTipTrType, srTransRec.IITid);
    
	vdDebug_LogPrintf("szTotalAmount=[%s],szTipAmount=[%s],szOrgAmount=[%s],.inCardType[%d]",szTransAmt,szTipAmt,szOrgAmt,srTransRec.inCardType);
    vdDebug_LogPrintf("CardTotal SaleCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount);
    vdDebug_LogPrintf("CardTotal OfflCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usOffSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulOffSaleTotalAmount);
    vdDebug_LogPrintf("CardTotal RefdCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usRefundCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulRefundTotalAmount);            
    vdDebug_LogPrintf("CardTotal VoidCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usVoidSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulVoidSaleTotalAmount);    
    vdDebug_LogPrintf("CardTotal TipCount [%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usTipCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulTipTotalAmount);
	vdDebug_LogPrintf("CardTotal CashAdvCount [%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usCashAdvCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulCashAdvTotalAmount);
	vdDebug_LogPrintf("CardTotal Local SaleCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalSaleTotalAmount);
	vdDebug_LogPrintf("CardTotal Local VoidCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usVoidSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalVoidSaleTotalAmount);	

    vdDebug_LogPrintf("HostTotal SaleCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount);
    vdDebug_LogPrintf("HostTotal OfflCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount);
    vdDebug_LogPrintf("HostTotal RefdCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount);            
    vdDebug_LogPrintf("HostTotal VoidCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount);    
    vdDebug_LogPrintf("HostTotal TipCount [%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount);
    vdDebug_LogPrintf("HostTotal CashAdvCount [%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usCashAdvCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulCashAdvTotalAmount);
    vdDebug_LogPrintf("HostTotal Local SaleCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalSaleTotalAmount);
	vdDebug_LogPrintf("HostTotal Local VoidCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalVoidSaleTotalAmount);    
	
    switch(srTransRec.byTransType)
    {
        case SALE:
        case SALE_OFFLINE:
            srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usSaleCount++;
            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount++;
            srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount + atof(szTransAmt);
            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount + atof(szTransAmt); 
            if(srTransRec.fDCC == TRUE)
            {
                srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalSaleTotalAmount + atof(szLocalTransAmt);
                srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalSaleTotalAmount= srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalSaleTotalAmount + atof(szLocalTransAmt);  
            }
            
            if (((srTransRec.byEntryMode == CARD_ENTRY_ICC) ||
            /* EMV: Revised EMV details printing - start -- jzg */
            //(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_QVSDC) ||		
            (srTransRec.bWaveSID == 0x65) ||
            (srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
            (srTransRec.bWaveSID == d_VW_SID_PAYPASS_MCHIP) ||
            (srTransRec.bWaveSID == d_VW_SID_AE_EMV) ||
            (srTransRec.bWaveSID == d_VW_SID_CUP_EMV) ||
            //(srTransRec.bWaveSID == d_VW_SID_JCB_WAVE_2) ||
            (srTransRec.bWaveSID == 0x63) ||
            (srTransRec.bWaveSID == d_EMVCL_SID_DISCOVER_DPAS) ||
            (srTransRec.bWaveSID == d_VW_SID_VISA_WAVE_QVSDC)) && (srTransRec.byTransType == SALE))
            /* EMV: Revised EMV details printing - end -- jzg */ // patrick fix contactless 20140828
                srAccumRec.stBankTotal[inTranCardType].usEMVTCCount++;
        break;   

        case VOID:
            srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usVoidSaleCount++;
            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount++;  	           	
            srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulVoidSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulVoidSaleTotalAmount + atof(szTransAmt);
            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount + atof(szTransAmt);
            
            if(srTransRec.fDCC == TRUE) /*increment DCC local void sale count and amount*/
            {
                srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalVoidSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalVoidSaleTotalAmount + atof(szLocalTransAmt) + atof(szLocalTipTransAmt);
                srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalVoidSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalVoidSaleTotalAmount + atof(szLocalTransAmt) + atof(szLocalTipTransAmt);
            }
			
            if(srTransRec.byOrgTransType == SALE || srTransRec.byOrgTransType == SALE_OFFLINE)
            {
                srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usSaleCount--;
                srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount - atof(szTransAmt);
                
                srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount--;
                srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount - atof(szTransAmt);
                
                if(srTransRec.fDCC == TRUE)
                {
                    srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalSaleTotalAmount - atof(szLocalTransAmt);
                    srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalSaleTotalAmount - atof(szLocalTransAmt);
                }
            }
            else if(srTransRec.byOrgTransType == SALE_TIP)
            {
                srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usTipCount--;
                srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulTipTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulTipTotalAmount - atof(szTipAmt); 		   
                srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount--;
                srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount - atof(szTipAmt);
                
                srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usSaleCount--;
                srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount - atof(szTransAmt); 		   
                srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount--;
                srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount - atof(szTransAmt); 							
                if(srTransRec.fDCC == TRUE)/*deduct DCC local tip and amount*/
                {
                    srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalTipTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalTipTotalAmount - atof(szLocalTipTransAmt);
                    srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalTipTotalAmount= srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalTipTotalAmount  - atof(szLocalTipTransAmt);  
                    
                    srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalSaleTotalAmount - atof(szLocalTransAmt);
                    srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalSaleTotalAmount - atof(szLocalTransAmt);
                }
            }
        break;
			
        case SALE_TIP:
            vdDebug_LogPrintf("[**SALE TIP***");
            
            srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usTipCount++;
            srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulTipTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulTipTotalAmount + atof(szTipAmt) - (atof(szOrgAmt) - atof(szBaseAmt));
            srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount + atof(szTransAmt) - atof(szOrgAmt);
            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount + atof(szTransAmt) - atof(szOrgAmt);		   
            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount++;
            srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount + atof(szTipAmt) - (atof(szOrgAmt) - atof(szBaseAmt));
            if(srTransRec.fDCC == TRUE) /*add dcc tip*/
            {
                srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalTipTotalAmount = srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalTipTotalAmount + atof(szLocalTipTransAmt) - atof(szLocalOrigTipTransAmt);
                srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalTipTotalAmount= srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalTipTotalAmount  + atof(szLocalTipTransAmt) - atof(szLocalOrigTipTransAmt);  
            } 
        break;
        
        default:
        break;
    }
    
    vdDebug_LogPrintf("szTotalAmount=[%s],szTipAmount=[%s],szOrgAmount=[%s],.inCardType[%d]",szTransAmt,szTipAmt,szOrgAmt,srTransRec.inCardType);
    vdDebug_LogPrintf("CardTotal SaleCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulSaleTotalAmount);
    vdDebug_LogPrintf("CardTotal OfflCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usOffSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulOffSaleTotalAmount);
    vdDebug_LogPrintf("CardTotal RefdCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usRefundCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulRefundTotalAmount);            
    vdDebug_LogPrintf("CardTotal VoidCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usVoidSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulVoidSaleTotalAmount);    
    vdDebug_LogPrintf("CardTotal TipCount [%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usTipCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulTipTotalAmount);
	vdDebug_LogPrintf("CardTotal Local SaleCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalSaleTotalAmount);
    vdDebug_LogPrintf("CardTotal Local VoidCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usVoidSaleCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulLocalVoidSaleTotalAmount);    
	
    vdDebug_LogPrintf("HostTotal SaleCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulSaleTotalAmount);
    vdDebug_LogPrintf("HostTotal OfflCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usOffSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulOffSaleTotalAmount);
    vdDebug_LogPrintf("HostTotal RefdCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usRefundCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulRefundTotalAmount);            
    vdDebug_LogPrintf("HostTotal VoidCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulVoidSaleTotalAmount);    
    vdDebug_LogPrintf("HostTotal TipCount [%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usTipCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulTipTotalAmount);
	vdDebug_LogPrintf("HostTotal Local SaleCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalSaleTotalAmount);
	vdDebug_LogPrintf("HostTotal Local VoidCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usVoidSaleCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulLocalVoidSaleTotalAmount);	 
	
    if((inResult = inCTOS_SaveAccumTotal(&srAccumRec)) == ST_ERROR)
    {
        vdMyEZLib_LogPrintf("[vdUpdateAmountTotal]---Save Total Rec. error");
		vdSetErrorMessage("Save Accum Error");
        return ST_ERROR;    
    }

   	inCTLOS_Updatepowrfail(PFR_BATCH_UPDATE_COMPLETE);

    vdMyEZLib_LogPrintf("total file saved successfully");

    return ST_SUCCESS;
}

int inCTOS_ClearAccumTotal(void)
{
	short shHostIndex;
	int inResult;
	ACCUM_REC srAccumRec;
    STRUCT_FILE_SETTING strFile;
	
	shHostIndex = inCTOS_SelectHostSetting();
	if (shHostIndex == -1)
		return;
	strHDT.inHostIndex = shHostIndex;
	DebugAddINT("summary host Index",shHostIndex);

    memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
	memset(&strFile,0,sizeof(strFile));
	inResult = inCTOS_CheckAndSelectMutipleMID();
    vdCTOS_GetAccumName(&strFile, &srAccumRec);
	
	if((inResult = CTOS_FileDelete(strFile.szFileName)) != d_OK)
    {
        vdMyEZLib_LogPrintf("[inMyFile_SettleRecordDelete]---Delete Record error[%04x]", inResult);
        return ST_ERROR;
    }     
	
    return ST_SUCCESS;
	
}

void vdCTOS_SetBackupAccumFile(char *szOriFileName)
{
    ACCUM_REC srAccumRec;
    STRUCT_FILE_SETTING strFile;
	char szBKAccumeFileName[30];
	ULONG ulFileSize;
	int inResult;
	
	memset(&srAccumRec,0x00,sizeof(srAccumRec));
	memset(&strFile,0x00,sizeof(strFile));
	memset(szBKAccumeFileName,0x00,sizeof(szBKAccumeFileName));
	strcpy(szBKAccumeFileName,szOriFileName);
	CTOS_FileGetSize(szOriFileName, &ulFileSize);
	strcat(szBKAccumeFileName,".BK");
		
	vdDebug_LogPrintf("delete old BK acculFileSize[%d],del[%d]szOriFileName[%s][%s]",ulFileSize,inResult,szOriFileName,szBKAccumeFileName);
	inCTOS_FileCopy(szOriFileName,szBKAccumeFileName,ulFileSize);

	vdDebug_LogPrintf("szOriFileName[%s]set BKAccum[%s]ulFileSize[%ld]",szOriFileName,szBKAccumeFileName,ulFileSize);
	CTOS_FileGetSize(szBKAccumeFileName, &ulFileSize);
	vdDebug_LogPrintf("BK Acc ulFileSize[%ld]",ulFileSize);

	
}

void vdCTOS_GetBackupAccumFile(STRUCT_FILE_SETTING *strFile, ACCUM_REC *strTotal, int HostIndex, int MITid)
{

	sprintf(strFile->szFileName, "ACC%02d%02d.total%s"
								, HostIndex
								, MITid,".BK");
	
	vdDebug_LogPrintf("get BKAccum[%s]",strFile->szFileName);

								
	strFile->bSeekType			 = d_SEEK_FROM_BEGINNING;
	strFile->bStorageType		 = d_STORAGE_FLASH ;
	strFile->fCloseFileNow		 = TRUE;
	strFile->ulRecSize			 = sizeof(ACCUM_REC);
	strFile->ptrRec 			 = strTotal;	
		
}

int inCTOS_ReadBKAccumTotal(ACCUM_REC *strTotal,int HostIndex, int MITid)
{
    STRUCT_FILE_SETTING strFile;
    
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));
    memset(strTotal, 0x00, sizeof(ACCUM_REC));
    vdCTOS_GetBackupAccumFile(&strFile, strTotal,HostIndex, MITid);

    return (inMyFile_RecRead(&strFile));    
}

int inCTOS_DeleteBKAccumTotal(ACCUM_REC *strTotal,int HostIndex, int MITid)
{
	
    STRUCT_FILE_SETTING strFile;
	int inResult;
    
    memset(&strFile, 0x00, sizeof(STRUCT_FILE_SETTING));
    memset(strTotal, 0x00, sizeof(ACCUM_REC));
    vdCTOS_GetBackupAccumFile(&strFile, strTotal,HostIndex, MITid);
	
	if((inResult = CTOS_FileDelete(strFile.szFileName)) != d_OK)
    {
        vdMyEZLib_LogPrintf("[inMyFile_SettleRecordDelete]---Delete Record error[%04x]", inResult);
        return ST_ERROR;
    }     
	
}
int inCTOS_FileCopy(char *szSourceFile, char *szDesFile,ULONG ulFileSize)
{

	FILE *in = NULL;
	FILE *out = NULL;
	unsigned long ulFileHandle;
	unsigned long ulOutFileHandle;
	char ch;
	ULONG ulFileSizeTemp;
	char *pAccumeData;
	int inresult;
	
	CTOS_FileGetSize(szSourceFile, &ulFileSizeTemp);
    inresult = CTOS_FileOpen(szSourceFile, d_STORAGE_FLASH, &ulFileHandle);
	vdDebug_LogPrintf("CTOS_FileOpen[%d]ulFileSizeTemp[%d]",inresult,ulFileSizeTemp);

	inresult = CTOS_FileSeek(ulFileHandle, 0, d_SEEK_FROM_BEGINNING);
	
	vdDebug_LogPrintf("CTOS_FileSeek[%d]ulFileSizeTemp[%d]",inresult,ulFileSizeTemp);
	pAccumeData = (unsigned char *) malloc(ulFileSizeTemp+1);
	vdDebug_LogPrintf("ulFileSizeTemp[%d]",ulFileSizeTemp);
	
	if(pAccumeData == NULL)
	{	
		vdDisplayErrorMsg(1, 8,	"accume bk fail");
		free(pAccumeData);
		return FAIL;
	}
	
	
    inresult = CTOS_FileRead(ulFileHandle, pAccumeData, &ulFileSizeTemp);
	
	vdDebug_LogPrintf("CTOS_FileRead[%d]ulFileSizeTemp[%d]ulFileSize[%d]",inresult,ulFileSizeTemp,ulFileSize);

	if((inresult  = CTOS_FileClose(ulFileHandle)) != d_OK)
	{				 
		vdDebug_LogPrintf("[CTOS_FileClose]---FileClz err[%04x]", inresult);
		free(pAccumeData);

		return ST_ERROR;
	}

	inresult = CTOS_FileDelete(szDesFile);
	vdDebug_LogPrintf("CTOS_FileDelete[%d]",inresult);


	vdDebug_LogPrintf("33333[%d]",ulFileSize);

	CTOS_Delay(50);
	
	
	inresult = CTOS_FileOpen(szDesFile , d_STORAGE_FLASH , &ulOutFileHandle);
	vdDebug_LogPrintf("CTOS_FileOpen[%d]",inresult);
	if(inresult == d_OK)
	{																						
		/* Move the file pointer to a specific position. 
		* Move backward from the end of the file.		 */
		inresult = CTOS_FileSeek(ulOutFileHandle, 0, d_SEEK_FROM_BEGINNING);
		if (inresult != d_OK)
		{
			vdDebug_LogPrintf("[inMyFile_RecSave]---Rec Seek inResult[%04x]", inresult);
			CTOS_FileClose(ulOutFileHandle);
			free(pAccumeData);
			return ST_ERROR;																		
		}
		else
			;
		/* Write data into this opened file */
		inresult = CTOS_FileWrite(ulOutFileHandle ,pAccumeData ,ulFileSize); 										
		if (inresult != d_OK)
		{
			vdDebug_LogPrintf("[inMyFile_RecSave]---Rec Write error, inResult[%04x]", inresult);
			CTOS_FileClose(ulOutFileHandle);
			
			free(pAccumeData);
			return ST_ERROR; 
		}																		
		
		vdDebug_LogPrintf("[inMyFile_RecSave]---Write finish,  inResult[%d]",  inresult);
		
		{	 
			if((inresult  = CTOS_FileClose(ulOutFileHandle)) != d_OK)
			{				 
				vdDebug_LogPrintf("[inMyFile_RecSave]---FileClz err[%04x]", inresult);
				free(pAccumeData);

				return ST_ERROR;
			}
			else
				ulOutFileHandle = 0x00;

			vdDebug_LogPrintf("[inMyFile_RecSave]---User close immed.");
		}

        vdDebug_LogPrintf("[inMyFile_RecSave]---User did not close immed.");
	}

	free(pAccumeData);
	
	vdDebug_LogPrintf(("last--CTOS_FileWrite,inresult[%d]", (char*)&inresult));
} 



int inCTOS_UpdatePreAuthAccumTotal(void)
{
    ACCUM_REC srAccumRec;
    BYTE        szTransAmt[12+1];
    BYTE        szTipAmt[12+1];
    BYTE        szOrgAmt[12+1];
    BYTE		szLocalTransAmt[12+1];
    int         inResult;
    int inTranCardType = 0;
    
    BYTE szBaseAmt[AMT_ASC_SIZE + 1] = {0};

    vdDebug_LogPrintf("inCTOS_UpdatePreAuthAccumTotal");
	
    if(inCheckIfDCCHost() == TRUE && srTransRec.fDCC == TRUE)
    {
		vdDebug_LogPrintf("inCTOS_UpdateDCCAccumTotal");
        return inCTOS_UpdateDCCAccumTotal();
    }
		
    memset(szTransAmt, 0x00, sizeof(szTransAmt));
    memset(szTipAmt, 0x00, sizeof(szTipAmt));
    memset(szOrgAmt, 0x00, sizeof(szOrgAmt));
	memset(szLocalTransAmt, 0x00, sizeof(szLocalTransAmt));
    wub_hex_2_str(srTransRec.szTotalAmount, szTransAmt, 6);
    wub_hex_2_str(srTransRec.szOrgAmount, szOrgAmt, 6);
	wub_hex_2_str(srTransRec.szDCCLocalAmount, szLocalTransAmt, 6);
	wub_hex_2_str(srTransRec.szBaseAmount, szBaseAmt, 6);
	wub_hex_2_str(srTransRec.szTipAmount, szTipAmt, 6);
	
	
	inTranCardType = 0;//save credit card accue total
	if(srTransRec.IITid == 23)//change issuer from CITI VISA to VISA
		srTransRec.IITid=2;
	else if(srTransRec.IITid == 24)//change issuer from CITI MC to MC
		srTransRec.IITid=4;
	
	memset(&srAccumRec, 0x00, sizeof(ACCUM_REC));
    if((inResult = inCTOS_ReadAccumTotal(&srAccumRec)) == ST_ERROR)
    {
        vdMyEZLib_LogPrintf("[vdUpdateAmountTotal]---Read Total Rec. error");
		vdSetErrorMessage("Read Accum Error");
        return ST_ERROR;    
    }        

    vdDebug_LogPrintf("byTransType[%d].byOrgTransType[%d].szOriginTipTrType[%d]IITid[%d]", srTransRec.byTransType, srTransRec.byOrgTransType, szOriginTipTrType, srTransRec.IITid);
    vdDebug_LogPrintf("CardTotal usPreAuthCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usPreAuthCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulPreAuthTotalAmount);	
	vdDebug_LogPrintf("usPreAuthCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usPreAuthCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulPreAuthTotalAmount);    
	    
	srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usPreAuthCount++;
    srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulPreAuthTotalAmount= srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulPreAuthTotalAmount + atof(szTransAmt);
    
    srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usPreAuthCount++;
    srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulPreAuthTotalAmount = srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulPreAuthTotalAmount + atof(szTransAmt);
	   
    vdDebug_LogPrintf("CardTotal usPreAuthCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].usPreAuthCount, srAccumRec.stBankTotal[inTranCardType].stCardTotal[srTransRec.IITid].ulPreAuthTotalAmount);    
	
	vdDebug_LogPrintf("HostTotal usPreAuthCount[%d] [%12.0f]", srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.usPreAuthCount, srAccumRec.stBankTotal[inTranCardType].stHOSTTotal.ulPreAuthTotalAmount);
	
    if((inResult = inCTOS_SaveAccumTotal(&srAccumRec)) == ST_ERROR)
    {
        vdMyEZLib_LogPrintf("[vdUpdateAmountTotal]---Save Total Rec. error");
		vdSetErrorMessage("Save Accum Error");
        return ST_ERROR;    
    }

   	inCTLOS_Updatepowrfail(PFR_BATCH_UPDATE_COMPLETE);

    vdMyEZLib_LogPrintf("total file saved successfully");

    return ST_SUCCESS;
}

