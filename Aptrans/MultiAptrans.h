
#ifndef MULTIAPTRANS_H
#define MULTIAPTRANS_H

#define d_MAX_APP				25
#define	d_AP_FLAG_DEF_SEL_EX	0xC0

#define	d_CTLS_EVENT			99
#define	d_SUCCESS				100
#define	d_FAIL					101
#define	d_NOT_RECORD			102
#define	d_NOT_ALLOWED			103

#define d_MAX_IPC_BUFFER		2048

typedef enum
{
    d_IPC_CMD_ONLINES_SALE		= 0x01,
  	d_IPC_CMD_OFFLINE_SALE		= 0x02,
  	d_IPC_CMD_VOID_SALE			= 0x03,
    d_IPC_CMD_PRE_AUTH			= 0x04,
    d_IPC_CMD_REFUND				= 0x05,
    d_IPC_CMD_TIP_ADJUST			= 0x06,
    d_IPC_CMD_SETTLEMENT			= 0x07,
    d_IPC_CMD_BATCH_REVIEW		= 0x08,
    d_IPC_CMD_BATCH_TOTAL			= 0x09,
    d_IPC_CMD_REPRINT_LAST		= 0x0A,
    d_IPC_CMD_REPRINT_ANY			= 0x0B,
    d_IPC_CMD_REPRINT_LAST_SETT	= 0x0C,
    d_IPC_CMD_SUMMARY_REPORT		= 0x0D,
    d_IPC_CMD_DETAIL_REPORT		= 0x0E,
    d_IPC_CMD_GET_PID				= 0x10,
    d_IPC_CMD_POWER_FAIL			= 0x11,
    d_IPC_CMD_DELETE_BATCH		= 0x12,
    d_IPC_CMD_DELETE_REVERSAL	= 0x13,
    d_IPC_CMD_SETTLE_ALL			= 0x14,
    d_IPC_CMD_CHECK_DUP_INV      = 0x15,
    d_IPC_CMD_WAVE_SALE			= 0x16,
    d_IPC_CMD_WAVE_REFUND			= 0x17,
	//gcitra
	d_IPC_CMD_BINVER = 0x18,
	d_IPC_CMD_POS_AUTO_REPORT = 0x19,
	//gcitra
    d_IPC_CMD_FUN_KEY1			= 0x1A,
    d_IPC_CMD_FUN_KEY2		    = 0x1B,
    d_IPC_CMD_FUN_KEY3			= 0x1C,
    d_IPC_CMD_FUN_KEY4		    = 0x1D,

	
	d_IPC_CMD_CASH_ADVANCE		 = 0x1E,
	d_IPC_CMD_LOGON 			= 0x1F,
	d_IPC_CMD_BALANCE_INQUIRY 	= 0x20,
    d_IPC_CMD_CHK_BATCH_EMPTY    = 0x21,
    d_IPC_CMD_RELOAD             = 0x22,
	d_IPC_CMD_MANUAL_SETTLE		= 0x23,
	d_IPC_CMD_EDC_SETTING  = 0x24,	

	//SMAC
		d_IPC_CMD_SMAC_LOGON		  = 0x25,
		d_IPC_CMD_AWARD_POINTS		  = 0x26,
		d_IPC_CMD_REDEEM			  = 0x27,
		d_IPC_CMD_SMAC_INQ			  = 0x28,
	//SMAC
    d_IPC_CMD_DETAIL_REPORT_ALL			  = 0x29,
    
    d_IPC_CMD_MERCHANT_CHECK_BATCH_ALL=0x2a,
    d_IPC_CMD_SUMMARY_REPORT_ALL			  = 0x2b,
    d_IPC_CMD_SETTLE_MERCHANT_ALL			= 0x2c,

    //TBG MULTI APPLICATION
    d_IPC_CMD_TBG_APP								  =0x2e,

	//autotreats and reserve apps
    d_IPC_CMD_AUTOTREATS    = 0x2f,
    d_IPC_CMD_RESERVE_APP1  = 0x30,  
	d_IPC_CMD_RESERVE_APP2  = 0x31,  
    d_IPC_CMD_RESERVE_APP3  = 0x32,  
    d_IPC_CMD_RESERVE_APP4  = 0x33,  
    d_IPC_CMD_RESERVE_APP5  = 0x34,  

	//FOR QRPAY
    d_IPC_CMD_QRPAY         = 0x35,  
	d_IPC_CMD_RETRIEVE 		= 0x36,
	d_IPC_CMD_BDOPAY_SALE   = 0x37,
	d_IPC_CMD_WECHAT_SALE   = 0x38,
	d_IPC_CMD_ALIPAY_SALE   = 0x39,
	d_IPC_CMD_GCASH_SALE    = 0x3a,
	d_IPC_CMD_GRABPAY_SALE  = 0x3b,
	d_IPC_CMD_SODEXO_SALE   = 0x3c,
	
	d_IPC_CMD_BDOPAY_RETRIEVE   = 0x3d,
	d_IPC_CMD_WECHAT_RETRIEVE   = 0x3e,
	d_IPC_CMD_ALIPAY_RETRIEVE   = 0x3f,
	d_IPC_CMD_GCASH_RETRIEVE    = 0x40,
	d_IPC_CMD_GRABPAY_RETRIEVE  = 0x41,
	d_IPC_CMD_SODEXO_RETRIEVE   = 0x42,
	
	d_IPC_CMD_BDOPAY_VOID		= 0x43,
	d_IPC_CMD_WECHAT_VOID   	= 0x44,
	d_IPC_CMD_ALIPAY_VOID   	= 0x45,
	d_IPC_CMD_GCASH_VOID    	= 0x46,
	d_IPC_CMD_GRABPAY_VOID  	= 0x47,
	d_IPC_CMD_SODEXO_VOID   	= 0x48,
	//END-QRPAY
	d_IPC_CMD_SMAC_KIT_SALE		= 0x49,
	d_IPC_CMD_SMAC_RENEWAL		= 0x4a,
	d_IPC_CMD_SMAC_PTS_AWARDING	= 0x4b,

	//FOR PJQR
	d_IPC_CMD_PHQR_SALE         = 0x4c,
	d_IPC_CMD_PHQR_RETRIEVE 	= 0x4d,

	//FOR UPI
	d_IPC_CMD_UPI_SALE         = 0x4e,
	d_IPC_CMD_UPI_RETRIEVE 	   = 0x4f,
	
	//wifi-mod
    d_IPC_CMD_WIFISCAN			= 0x98,
    //wifi-mod
    
    d_IPC_CMD_SETFONT			= 0x99,
    d_IPC_CMD_GET_CRC_ALL			= 0X97,
	d_IPC_CMD_CARDVER_REPORT		= 0x96,
	//d_IPC_CMD_SETTLEMENT_ALL	= 0x4c,

}IPC_CMD_TYPES;

typedef enum
{
	d_IPC_CMD_CTLS_TRANS	= 0x02,
	d_IPC_CMD_CTLS_CANCLE	= 0x03,
	d_IPC_CMD_CTLS_GETDATA	= 0x04,
	d_IPC_CMD_ERM_INIT			= 0x50,

}IPC_CTLSCMD_TYPES;

int inMultiAP_RunIPCCmdTypes(char *Appname, int IPC_EVENT_ID, BYTE *inbuf, USHORT inlen, BYTE *outbuf, USHORT *outlen);
USHORT inMultiAP_HandleIPC(BYTE *inbuf, USHORT inlen, BYTE *outbuf, USHORT *outlen);
int inMultiAP_GetMainroutine(void);
int inMultiAP_SendChild(BYTE *inbuf, USHORT inlen);

int inCTOS_MultiAPALLAppEventID(int IPC_EVENT_ID);
int inCTOS_MultiAPALLAppEventIDEx(int IPC_EVENT_ID);
int inCTOS_MultiAPBatchSearch(int IPC_EVENT_ID);
int inCTOS_MultiAPSaveData(int IPC_EVENT_ID);
int inCTOS_MultiAPGetData(void);
int inCTOS_MultiAPGetpowrfail(void);
int inCTOS_MultiAPGetVoid(void);
int inCTOS_MultiAPReloadTable(void);
int inCTOS_MultiAPReloadHost(void);
int inCTOS_MultiAPCheckAllowd(void);
int inMultiAP_ECRGetMainroutine(void);
int inMultiAP_ECRSendSuccessResponse(void);
//int inMultiAP_RunIPCCmdTypesEx(char *Appname, int IPC_EVENT_ID, BYTE *inbuf, USHORT inlen, BYTE *outbuf, USHORT *outlen);
int inCTOSS_SetALLApFont(char *font);
int inCTOS_MultiSwitchApp(const char szAppName[25], int IPC_EVENT_ID);
int inCTOS_MultiAPSaveData_Wallet(int IPC_EVENT_ID);

#endif


