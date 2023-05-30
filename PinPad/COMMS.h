

#ifndef _COMMS_H
#define	_COMMS_H

#ifdef	__cplusplus
extern "C" {
#endif


#ifndef BYTE
#define BYTE	unsigned char
#endif

#ifndef ULONG
#define ULONG	unsigned long		// 4byte
#endif


int inCTOSS_USBOpen(void);
int inCTOSS_USBSendBuf(char *szSnedBuf,int inlen);
int inCTOSS_USBRecvBuf(char *szRecvBuf,int *inlen);
int inCTOSS_USBClose(void);

int inCTOSS_RS232Open(ULONG ulBaudRate, BYTE bParity, BYTE bDataBits, BYTE bStopBits);
int inCTOSS_RS232SendBuf(char *szSnedBuf,int inlen);
int inCTOSS_RS232RecvBuf(char *szRecvBuf,int *inlen,int timeout);
int inCTOSS_RS232Close(void);



void vdCTOSS_SetRS232Port(int CommPort);

void vdDisplayErrorMsg(int inColumn, int inRow,  char *msg);
void vdCTOSS_RNG(BYTE *baResult);

//extern void vdDebug_LogPrintf(const char * fmt,...);

#ifdef	__cplusplus
}
#endif

#endif	/* _COMMS_H */

