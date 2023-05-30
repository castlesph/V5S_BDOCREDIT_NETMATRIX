

typedef struct
{
	UINT PASid;
	int inRetryTime;
	BOOL fEnable;
	BOOL fOnGoing;
	BYTE szSTLTime1[8];
	BYTE szSTLTime2[8];
	BYTE szSTLTime3[8];
	BYTE szWaitTime[8];
	BOOL fFirstBootUp;
	BYTE szlastSettleDate[8+1];
} STRUCT_PAS;

STRUCT_PAS strPAS;

int inPASRead(int inSeekCnt);
int inPASSave(int inSeekCnt);
int inPASNumRecord(void);


