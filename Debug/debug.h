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
void SetDebugMode(BYTE bMode, BYTE bPort);
void DebugInit(void);
void DebugAddHEX(BYTE *title, BYTE *hex, USHORT len);
void DebugAddINT(BYTE *title, LONG value);
void DebugAddIntX(BYTE *title, LONG value);
void DebugAddSTR(BYTE *title, BYTE *baMsg, USHORT len);
//void vdDebug_LogPrintf(const char* fmt, ...);
void PrintDebugMessage(const char* filePath, int lineNumber, const char * functionName, const char* format, ...);

#define vdDebug_LogPrintf(...)  PrintDebugMessage(__FILE__, __LINE__,__FUNCTION__, __VA_ARGS__)

BYTE byGetDebugMode(void);

	
#ifdef	__cplusplus
}
#endif

#endif	/* _DEBUG_H */

