#ifndef __CTOSS_TMS_H__
#define __CTOSS_TMS_H__

#define TBD_FILE_NAME		"TBD.BAK"
#define TMS_DETAIL_FILE_NAME		"TMS_DETAIL.BAK"
#define TMS_REPRINT_DETAIL_FILE_NAME		"TMS_REPRINT_DETAIL.BAK"
#define TMS_STATUS_FILE_NAME		"TMS_STATUS.BAK"
#define BATCH_NOT_EMPTY				3
/*Terminal backup data, for TMS update*/
typedef struct tagTxnBackupData
{
	int 	inHDTid;	// match MMT HDTid
	int 	inMITid;	// match MMT MITid
	int		inBKUpdate;	// Update flag
	BYTE	szTraceNo[TRACE_NO_BCD_SIZE+1];
	BYTE	szBatchNo[BATCH_NO_ASC_SIZE+1];
	BYTE	szInvoiceNo[INVOICE_BCD_SIZE+1];
	BYTE	szLastInvoiceNo[INVOICE_BCD_SIZE+1];
	
}TXN_BAK_DATA;

/*TMS Detail Data*/
typedef struct tagTMSDetailData
{

	//BYTE szPreDLDate[40 + 1];
	//BYTE szPreDLTime[40 + 1];
	BYTE szTID[40 + 1];
	BYTE szMID[40 + 1];
	//BYTE szSerialNo[40 + 1];
	BYTE szDLTrigger[40 + 1];	
	BYTE szDayGap[40 + 1];
	//BYTE szTerminalIP[40 + 1];
	//BYTE szTMSServerIP[40 + 1];
	//BYTE szTMSServerPort[40 + 1];
	BYTE szADCStartTime1[40 + 1];
	BYTE szADCEndTime1[40 + 1];
	BYTE szADCStartTime2[40 + 1];
	BYTE szADCEndTime2[40 + 1];
	BYTE szADCStartTime3[40 + 1];
	BYTE szADCEndTime3[40 + 1];
	BYTE szAppVer[40 + 1];
	BYTE szDLStartTime[40 + 1];
	BYTE szDLEndTime[40 + 1];
	BYTE szUpdateType[40 + 1];
	USHORT usReterr;
	int  inDLTrigger;
	int	 inDLStatus;
	BYTE szADCDate[40 + 1];
	BYTE szADCTime[40 + 1];
	char szCreditCRC[8+1];
	char szDebitCRC[8+1];
	char szInstCRC[8+1];
	char szCUPCRC[8+1];
	char szQRPayCRC[8+1];
	char szReson[20+1];
	CTOS_RTC PreDownload_RTC;
}TMS_DETAIL_DATA;

/*TMS Status Data*/
typedef struct tagTMSStatusData
{
	int  inUpdateType;
	BYTE szUpdateType[40 + 1];
	BYTE szStatus[40 + 1];
	BYTE szReason[40 + 1];
	BYTE szDLStartTime[40 + 1];
	BYTE szDLEndTime[40 + 1];
	BYTE szAppVer[40 + 1];
	
}TMS_STATUS_DATA;

TXN_BAK_DATA strTBD;
TMS_DETAIL_DATA	strTMSDetail;
TMS_STATUS_DATA	strTMSStatus;


int inCTOSS_SettlementCheckTMSDownloadRequest(void);

int inCTOSS_CheckIfPendingTMSDownload(void);
int inCTOSS_TMSDownloadRequest(void);
int inCTOSS_TMSChkBatchEmptyProcess(void);
int inCTOSS_TMSChkBatchEmpty(void);
int inCTOSS_TMSDownloadRequest(void);
void inCTOSS_TMS_USBUpgrade(void);
int inCTOSS_TMSPreConfig2(int inComType);
int inCTOSS_ADLSettlementCheckTMSDownloadRequest(void);
int inCTOSS_TMSBackupTxnData(void);
int inCTOSS_TMSRestoreTxnData(void);
int inCTOSS_TMSBackUpDetailData(void);
int inCTOSS_TMSBackUpReprintDetailData(void);
int inCTOSS_TMSReadDetailData(void);
int inCTOSS_TMSBackUpStatusData(void);
int inCTOSS_TMSReadStatusData(void);
int inCheckTMSBackUpFilesExists(void);
int inCheckTMSReprintBackUpFilesExists(void);
int inCTOSS_TMSReadReprintDetailData(void);
int inCheckifAutoDL(void);
void vdAssesTMSDownloadStatus(CTOS_RTC *GetRTC);


#endif //end __CTOSS_TMS_H__
