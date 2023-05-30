#define DESCRIPTOR_CODE_SIZE 2
#define DESCRIPTOR_DESC_SIZE 20

typedef struct
{
	UINT inFLTid;
	BYTE szDescriptorCode[DESCRIPTOR_CODE_SIZE + 1];
	BYTE szDescription[DESCRIPTOR_DESC_SIZE + 1];
} STRUCT_FLT;

STRUCT_FLT strFLT;

int inFLTRead(int inSeekCnt);
int inFLTSave(int inSeekCnt);
int inFLTNumRecord(void);


