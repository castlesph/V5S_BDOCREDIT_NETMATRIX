#ifndef ___MULTI_SHARE_EMV___
#define ___MULTI_SHARE_EMV___

#include <Emvaplib.h>

typedef enum
{
    d_IPC_CMD_GetCardPresent		    = 0x01,
	d_IPC_CMD_EMV_Initialize		    = 0x02,
	d_IPC_CMD_EMV_App_Select		    = 0x03,
    d_IPC_CMD_EMV_Txn_Perform	    	= 0x04,
    d_IPC_CMD_EMV_Txn_Completion		= 0x05,
    d_IPC_CMD_EMV_GetOneData	        = 0x06,
    d_IPC_CMD_EMV_SetOneData			= 0x07,
    d_IPC_CMD_EMV_GetPackageData		= 0x08,
    d_IPC_CMD_EMV_SetPackageData	    = 0x09,
    d_IPC_CMD_EMV_PowerOffICC	    	= 0x0A,
	d_IPC_CMD_EMV_PowerOnICC			= 0x0B,
	d_IPC_CMD_EMV_WAVESETTAGS			= 0x0D,
	d_IPC_CMD_EMV_INJECTMK				= 0x0E,
	d_IPC_CMD_EMV_WGET					= 0x0F, 	
	//d_IPC_CMD_SETFONT					= 0x99,
	d_IPC_CMD_EMV_Txn_PerformEx	    	= 0x10,//for trans speed 20150317
	d_IPC_CMD_EMV_Txn_CompletionEx		= 0x11,//for trans speed 20150317
	d_IPC_CMD_EMV_App_SelectEx		    = 0x12,//for trans speed 20150317

}IPC_EMVCMD_TYPES;



#define SHARE_EMV_INVALIDE_RESP             98
#define SHARE_EMV_INVALID_PARA              99

//define len
#define SHARE_EMV_DEFINE_LEN                3

#define SHARE_EMV_DEFINE_TAGS_LEN           4

#define SHARE_EMV_01_LEN                    "001"
#define SHARE_EMV_02_LEN                    "002"
#define SHARE_EMV_03_LEN                    "003"
#define SHARE_EMV_04_LEN                    "004"


//define Tags
#define SHARE_EMV_PREFER_AID                "IN01"
#define SHARE_EMV_2ND_GEN_AC_ACTION        "IN02"
#define SHARE_EMV_TAG                        "IN03"
#define SHARE_EMV_TAG_VALUE                 "IN04"
#define SHARE_EMV_8A_RESP_CODE              "IN05"
#define SHARE_EMV_ARPC                       "IN06"
#define SHARE_EMV_ISSUE_SCRIPT              "IN07"
#define SHARE_EMV_GET_MULTI_TAG             "IN08"
#define SHARE_EMV_SET_MULTI_TAG             "IN09"
#define SHARE_EMV_POWEROFF_TAG              "IN10"
#define SHARE_EMV_POWERON_TAG               "IN11"



#define SHARE_EMV_RESP_STATU                "OT01"
#define SHARE_EMV_SELECTED_AID              "OT02"
#define SHARE_EMV_SELECTED_APP_LAB          "OT03"
#define SHARE_EMV_GET_MULTI_TAG_RESP        "OT04"
#define SHARE_EMV_FULL_RESP_STATUS			"OT05" // 2 bytes unsigned short data.
#define SHARE_EMV_SUB_IPC                   "IPC"
#define SHARE_EMV_ONLINEPIN                 "1"
#define SHARE_EMV_SELECTAPPLIST             "2"


typedef struct
{
	int			inDispFlag;
    BYTE        szDisplay1[50+1];
    BYTE        szDisplay2[50+1];
    BYTE        szDisplay3[50+1];
    BYTE        szDisplay4[50+1];
    BYTE        szDisplay5[50+1];
    BYTE        szDisplay6[50+1];
	BYTE        szDisplay7[50+1];
	BYTE        szDisplay8[50+1];
	BYTE        szDisplay9[50+1];
	BYTE        szDisplay10[50+1];
	BYTE        szDisplay11[50+1];
	BYTE        szDisplay12[50+1];
	BYTE        szDisplay13[50+1];
	BYTE        szDisplay14[50+1];
} OFFLINEPINDISPLAY_REC;



USHORT usCTOSS_EMV_PowerOffICC(void);
USHORT usCTOSS_EMV_PowerOnICC(void);
USHORT usCTOSS_AddOrUpdateTagToEMVDataPool(USHORT usTag, USHORT usLen, BYTE *ucValue);
short usCTOSS_GetEMVDataPoolTagData(USHORT usTag, BYTE *buf);
void vdCTOSS_EMVDataPoolTagRemove(WORD tag);
//USHORT usCTOSS_FindTagFromDataPackage(USHORT tag, BYTE *value, USHORT *length, const BYTE *buffer, USHORT bufferlen);
USHORT usCTOSS_FindTagFromDataPackage(unsigned int tag, BYTE *value, USHORT *length, const BYTE *buffer, USHORT bufferlen);


BYTE* ptCTOSS_FindTagAddr(BYTE *bFindTag, BYTE *bInString, USHORT usInStringLen);
USHORT usCTOSS_PackTagLenValue(BYTE *bDataBuf, BYTE *bTag, USHORT usTagValueLen, BYTE *bTagValue);
USHORT usCTOSS_GetTagLenValue(BYTE *bDataBuf, USHORT usDataBufLen, BYTE *bTag, USHORT *usTagValueLen, BYTE *bTagValue);

USHORT usCTOSS_GetCardPresent(void);
USHORT usCTOSS_EMVInitialize(void);
USHORT usCTOSS_EMV_TxnAppSelect(IN BYTE* pPreferAID, IN USHORT usPreferAIDLen, OUT BYTE* pSelectedAID, OUT USHORT* pSelectedAIDLen, OUT BYTE *pSelectedAppLabel, OUT USHORT *pSelectedAppLabelLen);
USHORT usCTOSS_EMV_TxnPerform(void);
USHORT usCTOSS_EMV_TxnCompletion(IN EMV_ONLINE_RESPONSE_DATA* pOnlineResponseData);
USHORT usCTOSS_EMV_DataGet(IN USHORT usTag, INOUT USHORT *pLen, OUT BYTE *pValue);
USHORT usCTOSS_EMV_DataSet(IN USHORT usTag, IN USHORT usLen, IN BYTE *pValue);
USHORT usCTOSS_EMV_MultiDataGet(IN BYTE *pTagString, INOUT USHORT *pLen, OUT BYTE *pValue);
USHORT usCTOSS_EMV_MultiDataSet(IN USHORT usLen, IN BYTE *pValue);

extern void vdPCIDebug_HexPrintf(char * display,char * szHexbuf,int len);


#endif  //end ___MULTI_SHARE_EMV___
