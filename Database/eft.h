
typedef struct
{
    UINT HDTid;
    BOOL fEFTSec;
    USHORT usKeySet;
    USHORT usKeyIndex;
    BYTE szSecureNII[4+1] ;	
} STRUCT_EFT ;

STRUCT_EFT strEFT;

int inEFTRead(int inSeekCnt);
int inEFTSave(int inSeekCnt);
int inEFTNumRecord(void);

