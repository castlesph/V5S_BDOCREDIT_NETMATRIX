#ifndef __DESFIRE_H__
#define __DESFIRE_H__

//File Type
#define d_STANDARD_DATA_FILE			0x00
#define d_BACKUP_FILE							0x01
#define d_VALUE_FILE							0x02
#define d_LINEAR_RECORD_FILE			0x03
#define d_CYCLIC_RECORD_FILE			0x04

//Security related commands define
#define d_CMD_AUTHENTICATE          0x0A
#define d_CMD_AUTHENTICATE_ISO      0x1A
#define d_CMD_AUTHENTICATE_AES      0xAA
#define d_CMD_CHANGE_KEY_SETTINGS   0x54
#define d_CMD_SET_CONFIGURATION     0x5C
#define d_CMD_CHANGE_KEY            0xC4
#define d_CMD_GET_KEY_VERSION       0x64

//PICC level commands define
#define d_CMD_CREATE_APPLICATION	0xCA
#define d_CMD_DELETE_APPLICATION	0xDA
#define d_CMD_GET_APPLICATION_IDS	0x6A
#define d_CMD_FREE_MEMORY		0x6E
#define d_CMD_GET_DF_NAMES		0x6D
#define d_CMD_GET_KEY_SETTINGS		0x45
#define d_CMD_SELECT_APPLICATION	0x5A
#define d_CMD_FORMAT_PICC               0xFC
#define d_CMD_GET_VERSION		0x60
#define d_CMD_GET_CARD_UID		0x51

//Application level commands define
#define d_CMD_GET_FILE_IDS		0x6F
#define d_CMD_GET_FILE_SETTINGS         0xF5
#define d_CMD_CHANGE_FILE_SETTINGS	0x5F
#define d_CMD_CREATE_STD_DATA_FILE	0xCD
#define d_CMD_CREATE_BACKUP_DATA_FILE	0xCB
#define d_CMD_CREATE_VALUE_FILE		0xCC
#define d_CMD_CREATE_LINEAR_RECORD_FILE	0xC1
#define d_CMD_CREATE_CYCLIC_RECORD_FILE	0xC0
#define d_CMD_DELETE_FILE		0xDF
#define d_CMD_GET_ISO_FILE_IDS		0x61

//Data manipulation commands define
#define d_CMD_READ_DATA			0xBD
#define d_CMD_WRITE_DATA		0x3D
#define d_CMD_GET_VALUE			0x6C
#define d_CMD_CREDIT			0x0C
#define d_CMD_DEBIT			0xDC
#define d_CMD_LIMITED_CREDIT		0x1C
#define d_CMD_WRITE_RECORD		0x3B
#define d_CMD_READ_RECORDS		0xBB
#define d_CMD_CLEAR_RECORD_FILE		0xEB
#define d_CMD_COMMIT_TRANSACTION	0xC7
#define d_CMD_ABORT_TRANSACTION		0xA7

//Error Define
#define d_INVALID_AUTH_TYPE         0xFF01
#define d_INVALID_KEYLEN            0xFF02
#define d_INVALID_RN                0xFF03
#define d_INVALID_RESPONSE          0xFF04
#define d_NOT_AUTH_BEFORE						0xFF05
#define d_NOT_SUPPORT_ACCESSRIGHT		0xFF06
#define d_ERROR_KEYNUMBER						0xFF07

//Error Status
#define d_OPERATION_OK			0x00
#define d_NO_CHANGES			0x0C
#define d_OUT_OF_EEPROM_ERROR		0x0E
#define d_ILLEGAL_COMMAND_CODE		0x1C
#define d_INTEGRITY_ERROR		0x1E
#define d_NO_SUCH_KEY			0x40
#define d_LENGTH_ERROR			0x7E
#define d_PERMISSION_DENIED		0x9D
#define d_PARAMETER_ERROR		0x9E
#define d_APPLICATION_NOT_FOUND		0xA0
#define d_APPL_INTEGRITY_ERROR		0xA1
#define d_AUTHENTICATION_ERROR		0xAE
#define d_ADDITIONAL_FRAME		0xAF
#define d_BOUNDARY_ERROR		0xBE
#define d_PICC_INTEGRITY_ERROR		0xC1
#define d_COMMAND_ABORTED		0xCA
#define d_PICC_DISABLED_ERROR		0xCD
#define d_COUNT_ERROR			0xCE
#define d_DUPLICATE_ERROR		0xDE
#define d_EEPROM_ERROR			0xEE
#define d_FILE_NOT_FOUND		0xF0
#define d_FILE_INTEGRITY_ERROR		0xF1


//Struct 
typedef struct{
	BYTE bAID[3];
	BYTE bFID[2];
	BYTE bFileName[16];
	BYTE NameLen;
}FILE_INFO;	


typedef struct{
	BYTE    bHwVendorID;
	BYTE    bHwType;
	BYTE    bHwSubType;
  BYTE    bHwMajorVersion;
	BYTE    bHwMinorVersion;
	BYTE    bHwStorageSize;
	BYTE    bHwProtocol;

	BYTE    bSwVendorID;
	BYTE    bSwType;
	BYTE    bSwSubType;
	BYTE    bSwMajorVersion;
	BYTE    bSwMinorVersion;
	BYTE    bSwStorageSize;
	BYTE    bSwProtocol;

	BYTE    abUid[7+1];
	BYTE    abBatchNo[5+1];
	BYTE    bProductionCW;
	BYTE    bProductionYear;
}VERSION_INFO;
VERSION_INFO strVersion;

//DESFire API
//*************************************************************************************
extern USHORT CTOS_DesfireAuthenticate(BYTE KeyNo, BYTE *InKey, USHORT KeyLen);
extern USHORT CTOS_DesfireAuthenticateISO(BYTE KeyNo, BYTE *InKey, USHORT KeyLen);
extern USHORT CTOS_DesfireAuthenticateAES(BYTE KeyNo, BYTE *InKey, USHORT KeyLen);
extern USHORT CTOS_DesfireChangeKeySettings(BYTE KeySettings);
extern USHORT CTOS_DesfireGetKeySettings(BYTE *bKeySettings, BYTE *bMaxNoOfKeys);
extern USHORT CTOS_DesfireChangeKey(BYTE bKeyNo, BYTE *bOKey, USHORT uOKeyLen, BYTE *bNKey, USHORT uNKeyLen);
extern USHORT CTOS_DesfireGetKeyVersion(BYTE KeyNo, BYTE *KeyVersion);

//PICC Level Commands
extern USHORT CTOS_DesfireCreateApplication(BYTE *bAID, BYTE bKeySett1, BYTE bKeySett2, BYTE *bISOFID, BYTE *bDFName, USHORT uNameLen, BOOL EnablISO);
extern USHORT CTOS_DesfireDeleteApplication(BYTE *bAID);
extern USHORT CTOS_DesfireGetApplicationIDs(BYTE *bAID, USHORT *uAIDLen);
extern USHORT CTOS_DesfireGetDFNames(FILE_INFO *GetFile, USHORT *TotalFile);
extern USHORT CTOS_DesfireSelectApplication(BYTE *bAID);
extern USHORT CTOS_DesfireFormatPICC(void);
extern USHORT CTOS_DesfireGetVersion(VERSION_INFO *GetVersion);
extern USHORT CTOS_DesfireFreeMemory(ULONG *ulSizeOfMemory);
extern USHORT CTOS_DesfireSetConfiguration(BYTE bOption, BYTE *bData, USHORT uDataLen);
extern USHORT CTOS_DesfireGetCardUID(BYTE *bUID);

//Application Level Commands
extern USHORT CTOS_DesfireGetFileIDs(BYTE *bFID, USHORT *uFIDLen);
extern USHORT CTOS_DesfireGetISOFileIDs(BYTE *bFID, USHORT *uFIDLen);
extern USHORT CTOS_DesfireGetFileSettings(BYTE bFileNo, BYTE *bSettings, USHORT *uSettingsLen);
extern USHORT CTOS_DesfireChangeFileSettings(BYTE bFileNo, BYTE bCommMode, USHORT uAccessRight, BOOL bEncrypt);
extern USHORT CTOS_DesfireCreateStdDataFile(BYTE bFileNo, BYTE *bISOFileID, BYTE bComSet, USHORT uAccessRight, ULONG ulFileSize, BOOL EnableISO);
extern USHORT CTOS_DesfireCreateBackupDataFile(BYTE bFileNo, BYTE *bISOFileID, BYTE bComSet, USHORT ubAccessRight, ULONG ulFileSize, BOOL EnableISO);
extern USHORT CTOS_DesfireCreateValueFile(BYTE bFileNo,BYTE bComSet,USHORT bAccessRight, ULONG ulLowerLimit, ULONG ulUpperLimit, ULONG ulValue, BYTE bLimitedCreditEnabled);
extern USHORT CTOS_DesfireCreateLinearRecordFile(BYTE bFileNo, BYTE *bISOFID, BYTE bComSet, USHORT uAccessRight, ULONG ulRecordSize, ULONG ulMaxNumOfRecords, BOOL EnableISO);
extern USHORT CTOS_DesfireCreateCyclicRecordFile(BYTE bFileNo, BYTE *bISOFID, BYTE bComSet, USHORT uAccessRight, ULONG ulRecordSize, ULONG ulMaxNumOfRecords, BOOL EnableISO);
extern USHORT CTOS_DesfireDeleteFile(BYTE bFileNo);

//Data Manipulation Commands
extern USHORT CTOS_DesfireReadData(BYTE bFileNo, ULONG ulOffSet, ULONG ulLength, BYTE *bGetData, ULONG *ulDataLen);
extern USHORT CTOS_DesfireWriteData(BYTE bFileNo, ULONG ulOffSet, ULONG ulLength, BYTE *WriteData);
extern USHORT CTOS_DesfireGetValue(BYTE bFileNo, ULONG *ulGetValue);
extern USHORT CTOS_DesfireCredit(BYTE bFileNo, ULONG ulCreditValue);
extern USHORT CTOS_DesfireDebit(BYTE bFileNo, ULONG ulDebitValue);
extern USHORT CTOS_DesfireLimitedCredit(BYTE bFileNo, ULONG ulCreditValue);
extern USHORT CTOS_DesfireWriteRecord(BYTE bFileNo, ULONG ulOffSet, ULONG ulLength, BYTE *WriteData);
extern USHORT CTOS_DesfireReadRecords(BYTE bFileNo, ULONG ulOffSet, ULONG ulLength, BYTE *bGetData, ULONG *ulDataLen);
extern USHORT CTOS_DesfireClearRecordFile(BYTE bFileNo);
extern USHORT CTOS_DesfireCommitTransaction(void);
extern USHORT CTOS_DesfireAbortTransaction(void);

#endif
