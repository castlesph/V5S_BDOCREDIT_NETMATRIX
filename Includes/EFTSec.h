
#ifndef _EFT_SEC_H_H
#define _EFT_SEC_H_H



#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef INOUT
#define INOUT
#endif


#define EFT_OK                   0

#define EFT_INVALID_PARA        -100
#define EFT_CAL_MAC_ERR         -101
#define EFT_ENCRYPT_ERR         -102
#define EFT_INVALID_ISO         -103
#define EFT_DECRYPT_ERR         -104
#define EFT_WRONG_MAC           -105

#define EFT_HOST_REJECT         -200


int inCTOSS_ProcessEFTSend( IN int inHDTid,
                                      IN int inKeySet,
                                      IN int inKeyIndex,
                                      IN int inSHA1MAC, 
                                      IN char *szEncryptMode, 
                                      IN char *szEncrypBitmap,
                                      IN char *szAcquirerID,
                                      IN char *szVendorID,
                                      INOUT unsigned char *pstReqBuf, INOUT unsigned int *inReqSiz);

int inCTOSS_ProcessEFTRecv(IN int inHDTid, 
                                     IN int inKeySet,
                                     IN int inKeyIndex,
                                     IN int inSHA1MAC, 
                                     IN char *szEncryptMode, 
                                     INOUT unsigned char *pstReqBuf, INOUT unsigned int *inReqSiz, 
                                     OUT char *szErrResponse);


#endif


