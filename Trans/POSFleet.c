#include <string.h>
#include <stdio.h>
#include <ctosapi.h>
#include <stdlib.h>
#include <stdarg.h>
#include <typedef.h>
#include <EMVAPLib.h>
#include <EMVLib.h>

#include "..\Includes\POSFleet.h"
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
#include "..\Includes\CTOSInput.h"
#include "..\Database\DatabaseFunc.h"


extern BOOL fTimeOutFlag; /*BDO: Flag for timeout --sidumili*/

int inFleetGetLiters()
{
	int inRet = 0,
		inPANLen = 0;
	BYTE strOut[20] = {0};
	short shMaxLen = 2, /* BDOCLG-00318: number of liters entry should be up to 2 digits  -- jzg */
		shMinLen = 1;


	vdDebug_LogPrintf("inFleetGetLiters %d %d",srTransRec.fFleetCard,strTCT.fFleetGetLiters );

	CTOS_LCDTClearDisplay();
	vduiLightOn();
	vdDispTransTitle(SALE);
		
	if((srTransRec.fFleetCard == TRUE) && (strTCT.fFleetGetLiters == TRUE)){

		while(1)
		{	
			vduiClearBelow(8);
			CTOS_LCDTPrintXY(1, 6, "Number of Liters: ");
			memset(strOut,0x00, sizeof(strOut));
			//inRet = InputString(1, 7, 0x00, 0x02, strOut, &shMaxLen, shMinLen, d_INPUT_TIMEOUT);
			inRet = InputString(1, 7, 0x00, 0x02, strOut, &shMaxLen, shMinLen, inGetIdleTimeOut(FALSE)); /*BDO: Parameterized idle timeout --sidumili*/
			if (inRet == d_KBD_CANCEL )
			{
				vdSetErrorMessage("USER CANCEL");
				return d_NO;
			}
			else if(inRet == 0)
				return d_NO;
			else if(inRet == 0xFF)
			{
				fTimeOutFlag = TRUE; /*BDO: Flag for timeout --sidumili*/
				vdSetErrorMessage("TIME OUT");
				return d_NO;
			}
			else if(inRet > 0)
			{
				srTransRec.inFleetNumofLiters = atoi(strOut);
				break;
			}
		}	
	}
	return d_OK;
}


int inFleetSelectProductCode()
{
	int inMenuNumRecs = 0,
	inCtr = 0,
	//inKey = 0,
	inHeaderAttr = 0x01+0x04;

	BYTE strOut[20] = {0};

	char szMenuItems[9000] = {0},
	szHeader[30] = {0};
	BYTE szFleetDesc[DESCRIPTOR_DESC_SIZE + 1];
	BYTE inKey = 0;

    int inRet;
	
	short shMaxLen = 3, shMinLen = 1;


	CTOS_LCDTClearDisplay();
	vduiLightOn();
	vdDispTransTitle(SALE);
	
	if((srTransRec.fFleetCard == TRUE) && (strTCT.fFleetGetLiters == TRUE)){

		while(1)
		{	
			vduiClearBelow(8);
			CTOS_LCDTPrintXY(1, 5, "ENTER DESCRIPTOR");
			CTOS_LCDTPrintXY(1, 6, "NUMBER:");
			memset(strOut,0x00, sizeof(strOut));
			//inRet = InputString(1, 7, 0x00, 0x02, strOut, &shMaxLen, shMinLen, d_INPUT_TIMEOUT);
			inRet = InputString(1, 7, 0x00, 0x02, strOut, &shMaxLen, shMinLen, inGetIdleTimeOut(FALSE)); /*BDO: Parameterized idle timeout --sidumili*/
			if (inRet == d_KBD_CANCEL )
			{
				vdSetErrorMessage("USER CANCEL");
				return d_NO;
			}
			else if(inRet == 0)
				return d_NO;
			else if(inRet == 0xFF)
			{
				fTimeOutFlag = TRUE; /*BDO: Flag for timeout --sidumili*/
				vdSetErrorMessage("TIME OUT");
				return d_NO;
			}
			else if(inRet > 0)
			{
				inFLTRead(atoi(strOut));
      			memset(srTransRec.szFleetProductCode, 0, sizeof(srTransRec.szFleetProductCode));
				sprintf(srTransRec.szFleetProductCode, "%s", strFLT.szDescriptorCode);
				memset(srTransRec.szFleetProductDesc, 0, sizeof(srTransRec.szFleetProductDesc));
				strcpy(srTransRec.szFleetProductDesc, strFLT.szDescription);
				
				break;
			}
		}	
	}
	return d_OK;

#if 0

	if((srTransRec.fFleetCard == TRUE) && 
		(strTCT.fFleetGetLiters == TRUE) && /* Additional condition get liters should be enabled first -- jzg */
		(strTCT.fGetDescriptorCode == TRUE))
	{

		inMenuNumRecs = inFLTNumRecord();

		strcpy(szHeader, " SELECT PRODUCT ");
		memset(szMenuItems, 0, sizeof(szMenuItems));
		for(inCtr = 1; inCtr <= inMenuNumRecs; ++inCtr)
		{
			inFLTRead(inCtr);

			/*BDO: Issue#:00320 : Force to pad in 20 space for fleet description -- sidumili*/
			memset(szFleetDesc, 0x00, sizeof(szFleetDesc));
			strcpy(szFleetDesc, strFLT.szDescription);
			if((strTCT.byTerminalType % 2) != 0)
			vdCTOS_Pad_String(szFleetDesc, 20, IS_SPACE, POSITION_RIGHT);
			/*BDO: Issue#:00320 : Force to pad in 20 space for fleet description -- sidumili*/
			
			strcat(szMenuItems, szFleetDesc);
			if((strlen(szFleetDesc) > 0) &&
				(inCtr != inMenuNumRecs))
				strcat(szMenuItems, "\n");
		}

		inCtr = strlen(szMenuItems) - 1;
		szMenuItems[inCtr] = 0x00;
		inSetColorMenuMode();
		//inKey = MenuDisplay(szHeader, strlen(szHeader), inHeaderAttr, 1, 1, szMenuItems, TRUE);
		inKey = MenuDisplayEx(szHeader, strlen(szHeader), inHeaderAttr, 1, 1, szMenuItems, TRUE, inGetIdleTimeOut(TRUE)); /*Menu with timeout parameter*/
		vdDebug_LogPrintf("::inFleetSelectProductCode::MenuDisplayEx::Menukey[%d]", inKey);
		inSetTextMode();
		if(inKey > 0)
		{
			if(inKey != d_KBD_CANCEL)
			{
				inFLTRead(inKey);
      			memset(srTransRec.szFleetProductCode, 0, sizeof(srTransRec.szFleetProductCode));
				sprintf(srTransRec.szFleetProductCode, "%s", strFLT.szDescriptorCode);
				memset(srTransRec.szFleetProductDesc, 0, sizeof(srTransRec.szFleetProductDesc));
				strcpy(srTransRec.szFleetProductDesc, strFLT.szDescription);
			}
			else if (inKey == 0xFF) /*BDO: Added fot timeout occurd -- sidumili*/
			{
				fTimeOutFlag = TRUE; /*BDO: Flag for timeout --sidumili*/
				return(d_NO);
			}
			else
				return(d_NO);
		}
	}

	return(d_OK);
#endif
}


int inCTOS_FleetFlowProcess()
{
	int inRet = d_NO;

	vdDispTransTitle(FLEET_SALE);

	srTransRec.fVoidOffline = CN_FALSE;

	inRet = inCTOSS_CheckMemoryStatus();
	if(d_OK != inRet)
		return inRet;

	inRet = inCTOS_GetTxnPassword();
	if(d_OK != inRet)
		return inRet;

	inRet = inCTOS_TEMPCheckAndSelectMutipleMID();
	if(d_OK != inRet)
		return inRet;

	inRet = inCTOS_GetCardFields(); 
	if(d_OK != inRet)
			return inRet;

	inRet = inCTOS_SelectHost();
	if(d_OK != inRet)
		return inRet;

	inRet = inCTOS_GetTxnBaseAmount();
  if(d_OK != inRet)
	  return inRet;

	inRet=inCTOS_DisplayCardTitle(6, 7);
	if(d_OK != inRet)
		return inRet;

	inRet = inCTOS_UpdateTxnTotalAmount();
	if(d_OK != inRet)
		return inRet;
	
	inRet = inConfirmPAN();
	if(d_OK != inRet)
		return inRet;

	inRet = inFleetGetLiters();
	if(d_OK != inRet)
		return inRet;

	inRet = inFleetSelectProductCode();
	if(d_OK != inRet)
		return inRet;

	if (inMultiAP_CheckMainAPStatus() == d_OK)
	{
		inRet = inCTOS_MultiAPSaveData(d_IPC_CMD_ONLINES_SALE);
		if(d_OK != inRet)
			return inRet;
	}
	else
	{
		if (inMultiAP_CheckSubAPStatus() == d_OK)
		{
			inRet = inCTOS_MultiAPGetData();
			if(inRet != d_OK)
				return inRet;

			inRet = inCTOS_MultiAPReloadTable();
			if(inRet != d_OK)
				return inRet;
		}
		inRet = inCTOS_MultiAPCheckAllowd();
		if(inRet != d_OK)
			return inRet;
	}

	//remove prompt fro selection-Merchant selection is done by inCTOS_TEMPCheckAndSelectMutipleMID
	//	  inRet = inCTOS_CheckAndSelectMutipleMID();
	//	  if(d_OK != inRet)
	//		  return inRet;
	inMMTReadRecord(srTransRec.HDTid,srTransRec.MITid);

	inRet = inCTOS_CheckMustSettle();
	if(inRet != d_OK)
		return inRet;

	inRet = inCTOS_CheckIssuerEnable();
	if(inRet != d_OK)
		return inRet;

	inRet = inCTOS_CheckTranAllowd();
	if(inRet != d_OK)
		return inRet;

	inRet = inCTOS_PreConnect();
	if(inRet != d_OK)
		return inRet;

	inRet = inCTOS_GetInvoice();
	if(inRet != d_OK)
		return inRet;

	inRet = inBuildAndSendIsoData();
	if(inRet != d_OK)
		return inRet;

	inRet = inCTOS_SaveBatchTxn();
	if(inRet != d_OK)
		return inRet;

	inRet = inCTOS_UpdateAccumTotal();
	if(inRet != d_OK)
		return inRet;

	inRet = ushCTOS_printReceipt();
	if(inRet != d_OK)
		return inRet;

	inCTLOS_Updatepowrfail(PFR_IDLE_STATE);

	inRet=inProcessAdviceTrans(&srTransRec, strHDT.inNumAdv);
	if(inRet != d_OK)
		return inRet;
	else
		vdSetErrorMessage("");

	return(inRet);
}


int inCTOS_FLEET()
{
	int inRet = d_NO;

	CTOS_LCDTClearDisplay();
	vdCTOS_TxnsBeginInit();
	vdCTOS_SetTransType(SALE);
	srTransRec.fFleetCard = TRUE;

	inRet = inCTOS_FleetFlowProcess();

	inCTOS_inDisconnect();
	vdCTOS_TransEndReset();

	return(inRet);	
}
/*BDO: Entry for descriptor code -- sidumili*/
int inFleetGetDescriptorCode(void)
{
	int inRet = 0;
	BYTE strOut[20] = {0};
	short shMaxLen = 2; /* BDOCLG-00318: number of liters entry should be up to 2 digits  -- jzg */
	short shMinLen = 1;
	int inResult = 0;
	int inFLTId = 0;


	vdDebug_LogPrintf("inFleetGetLiters fFleetCard[%d] fFleetGetLiters[%d] fGetDescriptorCode[%d]",srTransRec.fFleetCard,strTCT.fFleetGetLiters, strTCT.fGetDescriptorCode);

	CTOS_LCDTClearDisplay();
	//vduiLightOn();
	vdDispTransTitle(SALE);
		
	if((srTransRec.fFleetCard == TRUE) && (strTCT.fFleetGetLiters == TRUE) && (strTCT.fGetDescriptorCode == TRUE)){
		
		while(1)
		{	
			vduiClearBelow(5);
			CTOS_LCDTPrintXY(1, 6, "Enter Descriptor Code: ");
			memset(strOut,0x00, sizeof(strOut));
			shMaxLen = 2;
			shMinLen = 1;
			//inRet = InputString(1, 7, 0x00, 0x02, strOut, &shMaxLen, shMinLen, d_INPUT_TIMEOUT);
			inRet = InputString(1, 7, 0x00, 0x02, strOut, &shMaxLen, shMinLen, inGetIdleTimeOut(FALSE)); /*BDO: Parameterized idle timeout --sidumili*/
			if (inRet == d_KBD_CANCEL )
			{
				vdSetErrorMessage("USER CANCEL");
				return d_NO;
			}
			else if(inRet == 0)
				return d_NO;
			else if(inRet == 0xFF)
			{
				fTimeOutFlag = TRUE; /*BDO: Flag for timeout --sidumili*/
				vdSetErrorMessage("TIME OUT");
				return d_NO;
			}
			else if(inRet > 0)
			{
				inFLTId = atoi(strOut);
				inResult = inFLTRead(inFLTId);
				memset(srTransRec.szFleetProductCode, 0, sizeof(srTransRec.szFleetProductCode));
				sprintf(srTransRec.szFleetProductCode, "%s", strFLT.szDescriptorCode);
				memset(srTransRec.szFleetProductDesc, 0, sizeof(srTransRec.szFleetProductDesc));
				strcpy(srTransRec.szFleetProductDesc, strFLT.szDescription);

				vdDebug_LogPrintf("::inFleetGetDescriptorCode strOut[%d]:inResult[%d]:inFLTId[%d]", atoi(strOut), inResult, inFLTId);
				vdDebug_LogPrintf("::inFleetGetDescriptorCode szFleetProductCode[%s]:szFleetProductDesc[%s]", srTransRec.szFleetProductCode, srTransRec.szFleetProductDesc);
				
				if (strlen(srTransRec.szFleetProductCode) > 0)
					break;
				else
				{
					vdDisplayErrorMsg(1, 8, "INVALID CODE");
				}		
			}
		}	
	}
	
	return d_OK;
}

