#define IPP_TDES_KEY_SIZE 16
#define IPP_DISPLAY_SIZE 25
#define IPP_PIN_BLOCK 8

typedef struct
{
	UINT HDTid;
	BYTE szPINKey[IPP_TDES_KEY_SIZE+1];
	BYTE szMACKey[IPP_TDES_KEY_SIZE+1];
	int inMinPINDigit;
	int inMaxPINDigit;
	USHORT usKeySet;
	USHORT usKeyIndex;
	BYTE szDisplayLine1[IPP_DISPLAY_SIZE + 1];
	BYTE szDisplayLine2[IPP_DISPLAY_SIZE + 1];
	BYTE szDisplayProcessing[IPP_DISPLAY_SIZE + 1];
	//gcitra
    BOOL fDebitLogonRequired;
	//gcitra
	
	UINT inMMTid;
}STRUCT_DCT;

STRUCT_DCT strDCT;

int inDCTRead(int inHDTid,int inMITid);
	int inDCTSave(int inHDTid,int inMITid);
int inDCTNumRecord(void);


