
#ifndef _POSCTLS_H
#define	_POSCTLS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <emv_cl.h>

typedef struct
{
	BYTE			TenantCode[8];
	BYTE			Can[8];
	BYTE			UID[8];
	unsigned long	CTC;
	unsigned long	Balance;
	unsigned long	Deposit;
	BYTE			Issued[3];	// YYMMDD BCD
	BYTE			Expiry[3];	// YYMMDD BCD
	BYTE			Mapping, LCSI;
	BYTE			Personal[64];
	BYTE			AppData[64];
}TTP_CardInfoType;


USHORT usReadMIFARECard(void);
int inDiversifyKey(BYTE *byDiversifiedOutput, int inOperation);
int inGetEncryptedKey(char *szInputData, char *szOutputData, int inOperation);
int InjectAESKey(char *MasterKey, int inOperation);
void Pack(BYTE* pData, USHORT usLen, BYTE *pResult);
BYTE ith(BYTE c);
int inGetMifareCardFields(BYTE byTransType);
void inGenerateSubKey(char *MKEY, int inOperation);
int inGetPersonalInfo(void);
int inGetMembershipInfo(void);
int inGetDemographicInfo(void);
int inGetEmploymentInfo(void);
int inWriteDatatoCard(BYTE byField, BYTE *byValue);
int inWriteCardHolderName(char *szCardHolderName);
int inDiversifyProcess(BYTE byKeyNo, int inOperation);
int inSelectAppAndGetUID(void);
int inCheckCardStatus(void);
int inDesfireWriteStdData(BYTE fid, unsigned long Offset, unsigned long Length, BYTE *p);
int inDesfireReadStdData(BYTE fid, unsigned long Offset, unsigned long Length, BYTE *p);
int inDesfireStdDebit(BYTE PurseID, long *pVal);
int inDesfireStdCredit(BYTE PurseID, long *pVal);
int inGetSessionKey(BYTE *bSessionKey);
int inGetCMAC(BYTE *bInput, int inLen, BYTE *bOutput, BYTE *bSessionKey);
void vdGenerateRandomKey(int inLen, BYTE *ptrResult);
int inReadMIFARECardEx(void);
int inWriteExpiry(void);
void vdLogPersonalInfo(char *szLog);
void vdDisplayTapCardforUpdate(void);



#ifdef	__cplusplus
}
#endif

#endif	/* _POSCTLS_H */

