
#ifndef _DATABASEFUNC__H
#define	_DATABASEFUNC__H

#ifdef	__cplusplus
extern "C" {
#endif
#include "../Database/dct.h"

#include "../Database/prm.h" //Installment: Promo selection table header  -- jzg
#include "../Database/par.h" //POS auto report: added PAR header -- jzg
#include "../Database/pas.h" //Auto-settlement: added AST table -- jzg
#include "../Database/gpt.h" //BDO: [Select Telco Setting] -- sidumili
#include "../Database/flt.h" //Added FLT table -- jzg

//Added other database headers - start -- jzg
#include "../Database/bvt.h"
#include "../Database/clt.h"
//Added other database headers - end -- jzg


#include "../Includes/POSTypedef.h"

#include "../Includes/Trans.h"
#include "../FileModule/myFileFunc.h"

#include "../DataBase/DataBaseFunc.h"


//请注意，需要区分文件名的大小写
#define DB_TERMINAL "/home/ap/pub/TERMINAL.S3DB"
#define DB_BATCH	"./fs_data/V5S_BDOCREDIT.S3DB"
#define DB_EMV	"/home/ap/pub/EMV.S3DB"
#define DB_COM	"/home/ap/pub/COM.S3DB"

#define DB_MULTIAP	"/home/ap/pub/MULTIAP.S3DB"
#define DB_WAVE		"/home/ap/pub/WAVE.S3DB"

#define DB_ERM	"/home/ap/pub/ERM.S3DB"
#define DB_ERMTCT	"/home/ap/pub/ERMTCT.S3DB"

#define DB_CTLS	"/home/ap/pub/CTLS.S3DB"
#define DB_EFT_LIB "/home/ap/pub/EFT.S3DB"

#define DB_MULTIAP_JOURNAL "/home/ap/pub/MULTIAP.S3DB-journal"

#define DB_INVOICE "/home/ap/pub/INVOICE.S3DB"

#define ECRISOLOG_FILE "/home/ap/pub/ECRISO.LOG"

#define ISOLOG_FILE "/home/ap/pub/ISO.LOG"
#define DB_EFTSEC "/home/ap/pub/EFT.S3DB"

#define DB_BDOPAY	"/home/ap/pub/BDOPAY.S3DB"




/* BDO CLG: Revised menu functions -- jzg */
#define FILENAME_SIZE 200

#define	DEFAULT_CACERT				"CACERT.PEM"
#define CADIR						PUBLIC_PATH

#if 0
typedef struct
{
	int DMTrxMenuid;
	int usButtonID;
	char szButtonItemImage[100];
	char szButtonItemLabel[100];
	char szButtonTitleLabel[100];
	char szButtonItemFunc[100];
	char szSubMenuName[100];
} STRUCT_TRXMENU;
STRUCT_TRXMENU strTrxMenu[20];
#endif

int inAIDNumRecord(void);
int inHDTNumRecord(void);
int inTCTNumRecord(void);
int inCDTNumRecord(void);
int inRDTNumRecord(void);
int inEMVNumRecord(void);
int inAIDNumRecord(void);
int inMSGNumRecord(void);
int inTLENumRecord(void);
int inIITNumRecord(void);
int inMITRead(int inSeekCnt);

int inCPTRead(int inSeekCnt);
int inCPTReadEx(int inSeekCnt);
int inCPTSave(int inSeekCnt);

int inPCTRead(int inSeekCnt);
int inPCTSave(int inSeekCnt);

int inHDTRead(int inSeekCnt);
int inHDTReadEx(int inSeekCnt);
int inHDTSave(int inSeekCnt);
int inHDTSaveEx(int inSeekCnt);
int inCDTRead(int inSeekCnt);
int inCDTReadMulti(char *szPAN, int *inFindRecordNum);
int inCDTMAX(void);

int inEMVRead(int inSeekCnt);
int inAIDRead(int inSeekCnt);
int inAIDReadbyRID(int inSeekCnt, char * PRid);
int inTCTRead(int inSeekCnt);
int inTCTSave(int inSeekCnt);
int inTCPRead(int inSeekCnt);
int inTCPSave(int inSeekCnt);
int inMSGRead(int inSeekCnt);
int inTLERead(int inSeekCnt);
int inTLESave(int inSeekCnt);
int inIITRead(int inSeekCnt);
int inIITSave(int inSeekCnt);

int inCSTNumRecord(void);
int inCSTRead(int inSeekCnt);
int inCSTReadEx(int inSeekCnt);
int inCSTSave(int inSeekCnt);

int inMMTReadRecord(int inHDTid,int inMITid);
int inMMTReadRecordEx(int inHDTid,int inMITid);

int inMMTNumRecord(void);

int inMMTReadNumofRecords(int inSeekCnt,int *inFindRecordNum);

int inMMTSave(int inSeekCnt);

int inPITNumRecord(void);
int inPITRead(int inSeekCnt);
int inPITSave(int inSeekCnt);

int inWaveAIDRead(int inSeekCnt);
int inWaveAIDNumRecord(void);
int inWaveEMVNumRecord(void);
int inWaveEMVRead(int inSeekCnt);

//aaronnino for BDOCLG ver 9.0 fix on issue #00124 Terminal display according to response codes was not updated start 2 of 5
#if 0
int inMSGResponseCodeRead(char* szMsg, int inMsgIndex, int inHostIndex);
#else
int inMSGResponseCodeRead(char* szMsg, char* szMsg2, char* szMsg3, int inMsgIndex, int inHostIndex);
#endif
//aaronnino for BDOCLG ver 9.0 fix on issue #00124 Terminal display according to response codes was not updated end 2 of 5


int inDatabase_BatchDeleteHDTidMITid(void);
int inDatabase_BatchDelete(void);
int inDatabase_BatchInsert(TRANS_DATA_TABLE *transData);
int inDatabase_BatchSave(TRANS_DATA_TABLE *transData, int inStoredType);
int inDatabase_BatchRead(TRANS_DATA_TABLE *transData, int inSeekCnt);
int inDatabase_BatchSave(TRANS_DATA_TABLE *transData, int inStoredType);
int inDatabase_BatchSearch(TRANS_DATA_TABLE *transData, char *hexInvoiceNo);
int inDatabase_BatchCheckDuplicateInvoice(char *hexInvoiceNo);
int inBatchNumRecord(void);
int inDatabase_BatchReadByHostidAndMITid(TRANS_DATA_TABLE *transData,int inHDTid,int inMITid);
int inBatchByMerchandHost(int inNumber, int inHostIndex, int inMerchIndex, char *szBatchNo, int *inTranID);
int inDatabase_BatchReadByTransId(TRANS_DATA_TABLE *transData, int inTransDataid);


int inHDTReadHostName(char szHostName[][400], int inCPTID[]);

int inMultiAP_Database_BatchRead(TRANS_DATA_TABLE *transData);
int inMultiAP_Database_BatchUpdate(TRANS_DATA_TABLE *transData);
int inMultiAP_Database_BatchDelete(void);
int inMultiAP_Database_BatchInsert(TRANS_DATA_TABLE *transData);

int inMultiAP_Database_EMVTransferDataInit(void);
int inMultiAP_Database_EMVTransferDataWrite(USHORT usDataLen, BYTE *bEMVData);
int inMultiAP_Database_EMVTransferDataRead(USHORT *usDataLen, BYTE *bEMVData);

int inMultiAP_Database_COM_Read(void);
int inMultiAP_Database_COM_Save(void);
int inMultiAP_Database_COM_Clear(void);

//1027
int inCRCRead(int inSeekCnt);
//1027
int inMMTReadRecord_SettleAll(int inHDTid,int inMITid);

int inMMTReadRecord_Footer(void);

/*BDO PHASE 2: [Function to get the total record of CPT table, use for "Change Comm"] -- sidumili */ 
int inCPTNumRecord(void);
void vdSetJournalModeOff(void);

/* BDO: Removed CARD VER from batch review - start -- jzg */
int inBatchReviewNumRecord(void);
int inBatchReviewByMerchandHost(int inNumber, int inHostIndex, int inMerchIndex, char *szBatchNo, int *inTranID);
/* BDO: Removed CARD VER from batch review - end -- jzg */

/* BDO CLG: Revised menu functions -- jzg */
int inReadDynamicMenu(void);


/* BDO: Make sure we use the BDO Credit host details first -- jzg */
int inGetCreditHostIndex(void);
int inGetCreditHostIndexEx(void);

int inNMTReadNumofRecords(int *inFindRecordNum);

int inMustSettleNumRecord(void);
int inCheckHostEnable_Per_APPLICATION(char *szAPPNAME);

int inSetOfflineLabel(char *szButtonItemLabel);
int inNMTReadRecord(int NMTID);

int inBatchNumALLRecord(void);
int inDatabase_InvoiceNumInsert(TRANS_DATA_TABLE *transData);
int inDatabase_InvoiceNumSearch(TRANS_DATA_TABLE *transData, char *hexInvoiceNo);
int inDatabase_InvoiceNumDelete(int HDTid, int MITid);
int inCheckBatchEmtpy(void);

int inHDTSaveEDCSETTTING(int inSeekCnt);

int inInstallmentCDTReadMulti(char *szPAN, int *inFindRecordNum);
int inInstallmentCDTRead(int inSeekCnt);
int inHDTReadData(int inSeekCnt);
int inHDTReadDataEx(int inSeekCnt);
int inSetTipAllowedLabel(char *szButtonItemLabel);
int inDatabase_IPReportInsert(void);

int inFXTRead(int inSeekCnt);
int inCSTReadHostID(char *szCurCode);

int inMMTReadHostName(char szHostName[][400], int inCPTID[], int inMITid, int inIndicator);
int inSetPriSecConnection(char *szPriTxnHostIP, char *szSecTxnHostIP, int inPriPort, int inSecPort);

int inMMTResetReprintSettle(int inMITid);
int inMMTSetReprintSettle(int inMMTid);

int inMMTNumRecordwithBatch(int inMITid, int inHDTid[]);
int inSetMMTSettleStatusEmpty(int inMITid);
int inHDTReadOrderBySequence(int inHDTid[]);
int inMMTNumRecordwithSettleStatusSuccess(int inMITid, int inHDTid[]);
int inHDTReadHostID(char *szHostName, int inHDTid[]);

/*albert - start - 20161202 - Reprint of Detail Report for Last Settlement Report*/
int inDatabase_BackupDetailReport(int HDTid, int MITid);
int inDatabase_DeleteDetailReport(int HDTid, int MITid);
int inBatchByDetailReport(int inNumber, int inHostIndex, int inMerchIndex, int *inTranID);
int inDatabase_ReadDetailReport(TRANS_DATA_TABLE *transData, int inTransDataid);
int inBackupDetailReportNumRecord(void);
/*albert - end - 20161202 - Reprint of Detail Report for Last Settlement Report*/

int inEFTPubRead(int inSeekCnt);
int inEFTPubSave(int inSeekCnt);
int inHDTReadinSequence(int inSeekCnt);
int inHDTDCCSave(int inSeekCnt);
void vdIncDCCSTAN(TRANS_DATA_TABLE *srTransPara);
int inCSTReadData(int inSeekCnt);
int inDatabase_BatchDeleteTransType(BYTE *byTransType);
int inDCCMMTUpdate(void);
int inDatabase_inSMACFooterRead(char *szBuff, TRANS_DATA_TABLE *transData);
int inDatabase_inSMACFooterSave(char *szBuff, TRANS_DATA_TABLE *transData);
int inDatabase_SMACFooterDeleteAll(void);
int inDatabase_SMACFooterDeletebyTraceNum(TRANS_DATA_TABLE *transData);
int inDatabase_SMACFooterDelete(int HDTid, int MITid);

int inDatabase_TerminalOpenDatabase(void);
int inDatabase_TerminalCloseDatabase(void);
int inDatabase_TerminalOpenDatabaseEx(const char *szDBName);
int inCDTReadEx(int inSeekCnt);
int inIITReadEx(int inSeekCnt);
int inInstallmentCDTReadEx(int inSeekCnt);
int inCSTReadHostIDEx(char *szCurCode);
int inMMTSaveEx(int inSeekCnt);
int inTCTReadEx(int inSeekCnt);
int inPCTReadEx(int inSeekCnt);
int inTCPReadEx(int inSeekCnt);

int inMultiAP_Database_EMVTransferDataInitEx(void);
int inMultiAP_Database_EMVTransferDataWriteEx(USHORT usDataLen, BYTE *bEMVData);
int inMultiAP_Database_EMVTransferDataReadEx(USHORT *usDataLen, BYTE *bEMVData);

int inIITSaveEx(int inSeekCnt);
int inMultiAP_Database_BatchDeleteEx(void);
int inMultiAP_Database_EMVTransferDataInitEx(void);
int inMultiAP_Database_BatchInsertEx(TRANS_DATA_TABLE *transData);
int inHDTReadinSequenceEx(int inSeekCnt);
int inHDTSaveFailedRev(int inSeekCnt);
int inCPT_Update(int inCommMode, int inIPHeader);
int inFLGGet(char *szFlag);
int inFLGRead(int inSeekCnt);
int inFLGSet(char *szFlag, BOOL fValue);
int inCheckHostBatchEmtpy(int inHDTid,int inMITid);
int inDatabase_OptOutInsert(void);
int inDatabase_OptOutCompleteBatchUpdate(char *hexInvoiceNo);
int inMMTReadBDOHost(int inHDTid,int inMITid);
int inMMTBDOMustSettleSave(int inSeekCnt);
int inDCCMMTNumRecordwithBatch(void);
int inDatabase_OptOutbyTransTypeBatchUpdate(BYTE byTransType, char *hexInvoiceNo);
int inTCTReadLastInvoiceNo(int inSeekCnt);
int inMMTReadPreAuthHostName(char szHostName[][400], int inCPTID[], int inMITid, int inIndicator);
int inBatchPreAuthNumRecord(void);
int inDetailReportHeader(void);
int inHDTSaveTraceNo(int inSeekCnt);
int inHDTReadQRMenu(char *szHostName, int inHDTid[]);
int inCountBatchesWithTxn(void);
int inMMTEnabledMerchants(int inMerchID[]);
int inTCTInvoiceNoSave(int inSeekCnt);
int inTMSMMTSave(int inSeekCnt);
int inEFTTempRead(int inSeekCnt);
int inSetBinCheck(int inValue);

int inERMCommSet(char *szFlag, int fValue);
int inSetMobileWalletLabel(char *szButtonItemLabel);
int inCountBatchesWithPendingReversal(void);
int inPHQRRead(int inSeekCnt);

int readWaveTable(char* szTableName, char* szUniqueID, int inSeekCnt);
int inPHQRSave(int inSeekCnt);
int inBDOWechatRead(int inSeekCnt);
int inBDOAlipayRead(int inSeekCnt);




#if 0
int inCheckQRPH_Exist(void);
int inInsertQRPH2Menu(int DMTrxMenuid, int usButtonID, char* szButtonItemImage, char* szButtonItemLabel, char* szButtonTitleLabel, char* szButtonItemFunc, char* szSubMenuName);
int inDeleteQRPH_FromMenu(void);
#endif

#ifdef BLT_REV_PFR

//int inDatabase_BatchSaveRrtrieveDataPHQR(RTRV_BPT_TRANS_DATA_TABLE  *RtrvTransData, int inStoredType);
//int inDatabase_PHQRBatchInsertRetrieveData(RTRV_BPT_TRANS_DATA_TABLE  *RtrvTransData);

#endif

#endif	/* _DATABASEFUNC__H */

