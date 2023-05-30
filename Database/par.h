

typedef struct
{
	UINT 	inPARid;
	BYTE	szPARTPDU[5+1];
	BYTE	szPARNII[4+1];
    	BYTE	szPARTID[10];
    	BYTE	szPARMID[20];
	BYTE	szPARTelNum1[30];
	BYTE	szPARTelNum2[30];
	BOOL      fPAREnable; 
	BYTE       szPARVersion[11];
	BYTE       szPARSerialNumber[14];

	BYTE szPARLastLogonDate[11];

}STRUCT_PAR;

STRUCT_PAR strPAR;

int inPARRead(int inSeekCnt);
int inPARSave(int inSeekCnt);
int inPARNumRecord(void);


