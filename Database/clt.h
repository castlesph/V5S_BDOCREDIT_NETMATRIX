

typedef struct
{
	UINT 	CLTid;
	int           HDTid;
	BOOL 	fCashLoyaltyEnable;		
	BYTE	szCashLoyaltyTPDU[5+1];
	BYTE	szCashLoyaltyNII[4+1] ;
    	BYTE	szCashLoyaltyTID[10] ;
    	BYTE	szCashLoyaltyMID[20] ;
}STRUCT_CLT;

STRUCT_CLT strCLT;

int inCLTRead(int inSeekCnt);
int inCLTSave(int inSeekCnt);
int inCLTNumRecord(void);


