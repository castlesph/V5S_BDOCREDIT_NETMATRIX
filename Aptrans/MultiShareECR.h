
#ifndef ___MULTI_SHARLS_ECR___
#define ___MULTI_SHARLS_ECR___

typedef enum
{
	d_IPC_CMD_ECR_Initialize		    = 0x02,
    d_IPC_CMD_ECR_GetPackageData		= 0x08,
    d_IPC_CMD_ECR_SetPackageData	    = 0x09,
}IPC_ECRCMD_TYPES;

USHORT usCTOSS_ECRInitialize(void);
USHORT usCTOSS_ECR_DataGet(IN USHORT usTag, INOUT USHORT *pLen, OUT BYTE *pValue);
USHORT usCTOSS_ECR_DataSet(IN USHORT usTag, IN USHORT usLen, IN BYTE *pValue);

#endif  //end ___MULTI_SHARLS_ECR___

