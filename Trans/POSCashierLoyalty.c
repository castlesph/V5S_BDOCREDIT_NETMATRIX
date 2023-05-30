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
#include "..\Includes\POSCashierLoyalty.h"

#include "..\Includes\POSbatch.h"
#include "..\ui\Display.h"
#include "..\Includes\V5IsoFunc.h"
#include "..\Accum\Accum.h"
#include "..\print\Print.h"
#include "..\Comm\V5Comm.h"
#include "..\Includes\MultiApLib.h"
#include "..\Aptrans\MultiAptrans.h"
#include "../Includes/wub_lib.h"
#include "../Database/DatabaseFunc.h"
#include "..\Includes\POSSale.h"
#include "..\Includes\showbmp.h"
#include "..\Includes\CTOSinput.h"


extern BOOL fRePrintFlag;
extern int inCTOS_GetCashierLoyaltyData(void);

int inCTOS_CashierLoyaltyFlowProcess(void)
{
    int inRet = d_NO;

    USHORT ushEMVtagLen;
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];


    vdCTOS_SetTransType(CASH_LOYALTY);
    
    //display title
    vdDispTransTitle(CASH_LOYALTY);
    
    inRet = inCTOS_GetCashierLoyaltyData();
    if (d_OK != inRet)
      return inRet;
 
    inRet = inCTOS_PreConnect();
    if(d_OK != inRet)
        return inRet;

	 inRet = inCTOS_GetInvoice();
	 if(d_OK != inRet)
			 return inRet;

     inRet = inBuildAndSendIsoData();
    if(d_OK != inRet)
        return inRet;

    inRet = ushCTOS_printReceipt();
    if(d_OK != inRet)
        return inRet;


    return d_OK;
}


int inCTOS_GetCashierLoyaltyData(void){


	inCLTRead(srTransRec.HDTid );

 	memcpy(strHDT.szTPDU,strCLT.szCashLoyaltyTPDU,5);
	strcpy(srTransRec.szTID, strCLT.szCashLoyaltyTID);
   	strcpy(srTransRec.szMID, strCLT.szCashLoyaltyMID);


    	return d_OK;

}

	

int inCTOS_CashierLoyalty(void)
{
    int inRet = d_NO;

   if ( inCLTRead(srTransRec.HDTid) != d_OK)
		return(d_OK);

    CTOS_LCDTClearDisplay();
    
     //vdCTOS_TxnsBeginInit();
     
    inRet = inCTOS_CashierLoyaltyFlowProcess();

    inCTOS_inDisconnect();

    vdCTOS_TransEndReset();

    return inRet;
}

