/* 
 * File:   debug.h
 * Author: PeyJiun
 *
 */

#ifndef _DEBUG_H
#define	_DEBUG_H

#ifdef	__cplusplus
extern "C" {
#endif

/****************
* if bPort == 0xFF --> USB mode
****************/

void vdPCIDebug_LogPrintf(const char* fmt, ...);
void vdPrintPCIDebug_HexPrintf(BOOL fSend,char *display,char *szHexbuf, int len);

extern void PCI100_HEX_2_DSP(char *hex, char *dsp, int count);
extern int inPrintDebug(unsigned char *strPrint); 
extern int inPrintISOPacket(unsigned char *pucTitle,unsigned char *pucMessage, int inLen);

#ifdef	__cplusplus
}
#endif

#endif	/* _DEBUG_H */

