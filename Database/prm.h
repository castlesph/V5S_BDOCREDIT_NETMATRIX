

typedef struct
{
	int PRMid;
	int HDTid;
	char szPromoLabel[21+1];
	char szPromoCode[3+1];
	char szPrintPromoLabel[21];
	int inGroup;
	BOOL fPRMEnable;
	BOOL fInstEMVEnable;
	BOOL fInstBINVerEnable;
} STRUCT_PRM;

STRUCT_PRM strPRM;
STRUCT_PRM strMultiPRM[20];

int inPRMReadbyHDTid(int inHDTid, int *inNumRecs);
int inPRMReadbyPRMid(int inPRMid);
int inPRMSave(int inSeekCnt);
int inPRMNumRecord(void);
int inPRMReadbyinInstGroup(int inGroup, int *inNumRecs);
int inPRMReadbyinInstGroupEx(int inGroup, int *inNumRecs);

