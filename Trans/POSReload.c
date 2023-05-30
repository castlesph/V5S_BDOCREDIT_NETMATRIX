#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctosapi.h>
#include <vwdleapi.h>
#include <sqlite3.h>

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
#include "..\PCI100\COMMS.h"

#include "..\POWRFAIL\POSPOWRFAIL.h"
#include "..\Includes\POSReload.h"


extern int inCTOS_SelectDebitHost(void);
extern int inGetIPPPin(void);

int inCTOS_ReloadFlowProcess(void)
{
    int inRet = d_NO;

    USHORT ushEMVtagLen;
    BYTE   EMVtagVal[64];
    BYTE   szStr[64];
	int inResult;

    vdCTOS_SetTransType(RELOAD);
    
    //display title
    vdDispTransTitle(RELOAD);
    
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
	
	inRet = inCTOS_UpdateTxnTotalAmount();
    if(d_OK != inRet)
        return inRet;

	inRet = inCTOS_SelectDebitHost();
	if(d_OK != inRet)
		return inRet;
	
    if (inMultiAP_CheckMainAPStatus() == d_OK)
    {
        inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_RELOAD);
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

	//inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid); moved inside inCTOS_SelectDebitHost

    inRet = inCTOS_CheckMustSettle();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_CheckIssuerEnable();
    if(d_OK != inRet)
        return inRet;

    inRet = inCTOS_CheckTranAllowd();
    if(d_OK != inRet)
        return inRet;

	inRet = inCTOS_PreConnect();
    if(d_OK != inRet)
        return inRet;
	
    inRet = inCTOS_SelectAccountType();
    if(d_OK != inRet)
        return inRet;

	inInitializePinPad();
    inRet = inGetIPPPin();
    if(d_OK != inRet)
       return inRet;

	inRet = inCTOS_GetInvoice();
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
    
    inRet = ushCTOS_printReceipt();
    if(d_OK != inRet)
        return inRet;

	inCTLOS_Updatepowrfail(PFR_IDLE_STATE);

	vdSetErrorMessage("");
	
    return inRet;
}




int inCTOS_RELOAD(void)
{
	int inRet = d_NO;
    
    CTOS_LCDTClearDisplay();
    
    vdCTOS_TxnsBeginInit();

//	vdCTOSS_GetAmt();

    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiStopResumeAP("SHARLS_ECRBDO");
    
    inRet = inCTOS_ReloadFlowProcess();
    
    if(fGetECRTransactionFlg() != TRUE)
        inCTOSS_MultiResumeContinueAP("SHARLS_ECRBDO");

    inCTOS_inDisconnect();

    vdCTOS_TransEndReset();
	
	return inRet;
}

