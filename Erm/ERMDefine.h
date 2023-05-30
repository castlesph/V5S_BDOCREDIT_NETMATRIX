/**************************************************************************
 * @doc VFSIGP
 * @module VFSIGPSrc |
 * Source code for the VFSIGP handling functions.
 *
 * Product         :   ERM
 * <nl>Developer   :   SoftPay Development Team ASPAC ADC - Wu Bin, Hu Bing, Ren Hong.
 * <nl>Notes       :
 *
 * @head3 VFSIGP Functions |
 * @index | VFSIGP
 * @end
 *
 * Copyright (C) 2012 by VeriFone Singapore PTE.LTD.
 *
 * No part of this software may be used, stored, compiled, reproduced,
 * modified, transcribed, translated, transmitted, or transferred, in any form
 * or by any means whether electronic, mechanical, magnetic, optical,
 * or otherwise, without the express prior written permission of Singapore PTE.LTD.
 *
 * Revision History
 * ------------------------------------------------------------------------
 *
 *
 ********************************************************************************/
 
#ifndef __ERM_DEFINE_H__
#define	__ERM_DEFINE_H__

#define	ERC_INITIALIZATION_TYPE			1
#define	ERC_FORM_RECEIPT_TYPE			2
#define	ERC_SEND_RECEIPT_TYPE			3
#define	ERC_CANCEL_TYPE					4
#define	ERC_GET_RECEIPT_NUM_TYPE			5
#define	ERC_DELETE_FIRST_RECEIPT_TYPE	6
#define	ERC_DELETE_ALL_RECEIPT_TYPE		7
#define	ERC_MOVE_BAKUP_RECEIPT_TYPE		8


#define	ERM_MODEM_COM_TYPE				1
#define	ERM_UCL_COM_TYPE				9
#define	ERM_RS232_COM_TYPE				11
#define	ERM_VCS_COM_TYPE				12
#define	ERM_COM_ENGINEER_COM_TYPE		14
#define	ERM_COM_RJ485						15


#define DEFAULT_ERC_PIPE_ID      				"P:ERM"
#define DEFAULT_MAIN_APP_PIPE_ID     		"P:MAPP"

//signature status define
#define STATUS_SIGNATURE_OK			0
#define STATUS_SIGPAD_FAILED			1
#define STATUS_NO_SIGN_REQU			2
#define	STATUS_CUST_SKIP				3


#define ERC_SUCCESS								0

#define	ERC_TIME_OUT								-2
#define	ERC_ESCAPE									-3

#define	NO_RECEIPT_ADVICE_FILE					-800
#define	NO_RECEIPT_UPLOAD							-801
#define	PLS_DO_INIT_FIRST							-802
#define	INVALID_ERC_PARA							-803

#define	ERC_INVALID_TRANSACTION					-901  //host response 01
#define ERC_INVALID_BANK_CODE					-902  //host response 02
#define	ERC_FORMAT_ERROR							-930  //host response 30
#define	ERC_KEY_OUT_OF_SYNC						-951  //host response 51
#define	ERC_INVALID_RECEIPT_IMAGE				-952  //host response 52
#define ERC_SWITCH_INOPERATIVE					-991  //host response 91
#define ERC_SYSTEM_ERROR							-996  //host response 96

#define	EC_DEVICE_NAME_SIZE				32


#define	ERC_PABX_CODE_SIZE				5
#define	ERC_PHONE_NUM_SIZE    			30
#define	ERC_ADVICE_FILE_NAME				15
#define	ERC_TPDU_LEN						10
#define ERC_PAN_LEN						19
#define	ERC_AMT_LEN						12
#define	ERC_STAN_LEN						6
#define	ERC_TIME_LEN						6
#define	ERC_DATE_LEN						4
#define	ERC_EXP_DATE_LEN					4
#define	ERC_REF_NUM_LEN					12
#define	ERC_APPROVE_LEN					6
#define	ERC_TID_LEN						8
#define	ERC_MID_LEN						15
#define	ERC_TERM_SERIAL_NO_LEN			17
#define	ERC_BANK_CODE_LEN					22
#define	ERC_MERCHANT_CODE_LEN			22
#define	ERC_STORE_CODE_LEN				22
#define	ERC_PAYMENT_TYPE_LEN				20
#define	ERC_PAYMENT_MEDIA_LEN			20
#define	ERC_BATCH_NO_LEN					6
#define	ERC_INV_LEN						6
#define	ERC_FILE_LEN						19

//only txn encrypt, init not encrypt, it only send logo and key
typedef struct tagERC_STRUCT
{
	short shType;
	
	char szAdviceFileName[ERC_ADVICE_FILE_NAME+1];				// advice file name, no filename extension

	char szPABXCode[ERC_PABX_CODE_SIZE+1];							// PABX
	char szPrimaryPhoneNum[ERC_PHONE_NUM_SIZE+1];					// Primary Host Number
	char szSecondaryPhoneNum[ERC_PHONE_NUM_SIZE+1];				// Secondary Host Number
	char szRecvTimeout[4+1];										// by second
	
	char szTPDU[ERC_TPDU_LEN+1];									// TPDU
	char szPAN[ERC_PAN_LEN+1];										// 02
	char szAmt[ERC_AMT_LEN+1];										// 04
	char szSTAN[ERC_STAN_LEN+1];									// 11
	char szTime[ERC_TIME_LEN+1];									// 12
	char szDate[ERC_DATE_LEN+1];									// 13
	char szExpDate[ERC_EXP_DATE_LEN+1];							// 14
	char szRefNum[ERC_REF_NUM_LEN+1];								// 37
	char szApprCode[ERC_APPROVE_LEN+1];							// 38
	char szTID[ERC_TID_LEN+1];										// 41
	char szMID[ERC_MID_LEN+1];										// 42
	char szTerminalSerialNO[ERC_TERM_SERIAL_NO_LEN+1];			// 46
	char szBankCode[ERC_BANK_CODE_LEN+1];							// 55
	char szMerchantCode[ERC_MERCHANT_CODE_LEN+1];					// 56
	char szStoreCode[ERC_STORE_CODE_LEN+1];						// 57
	char szPaymentType[ERC_PAYMENT_TYPE_LEN+1];					// 58
	char szPaymentMedia[ERC_PAYMENT_MEDIA_LEN+1];					// 59
	char szBatchNum[ERC_BATCH_NO_LEN+1];							// 60
	char szReceiptImageFileName[ERC_FILE_LEN+1];					// 61   store image for txn, init will not use this buf
	char szInvNum[ERC_INV_LEN+1];									// 62
	char szLogoFileName[ERC_FILE_LEN+1];						    // 63   store Logo for init, store INV for txn

	char szSingatureStatus[2+1];									// signature status
	char szRSAKEKVersion[4+1];									// KEK version
	char szReceiptLogoIndex[2+1];								// receipt logo index
	
	VS_BOOL 	fGzipReceiptImage;								// 0 - the Receipt Image havn't zip,  1 - the Receipt Image zip already
	VS_BOOL		fSettle;											// 0 - transaction receipt, 1 - settlement receipt
	
	VS_BOOL		fReserved1;
	VS_BOOL		fReserved2;
	VS_BOOL		fReserved3;
	VS_BOOL		fReserved4;
	VS_BOOL		fReserved5;

	char 		szReserved1[10];								
	char 		szReserved2[10];
	char 		szReserved3[10];
	char 		szReserved4[20];
	char 		szReserved5[50];
	
} ERC_STRUCT;

typedef struct tagERC_RESPONSE
{
	short shType;
	
	short shERCRespStatus;

	char 		szRspReserved1[10];
	char 		szRspReserved2[10];
	char 		szRspReserved3[10];
	char 		szRspReserved4[20];
	char 		szRspReserved5[50];
	
}ERC_RESPONSE;


#endif

