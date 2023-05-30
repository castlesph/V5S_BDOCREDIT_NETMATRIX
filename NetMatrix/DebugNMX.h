/* 
 * File:   debug.h
 * Author: PeyJiun
 *
 */

#ifndef _DEBUG_NMX_H
#define	_DEBUG_NMX_H

#ifdef	__cplusplus
extern "C" {
#endif

/****************
* if bPort == 0xFF --> USB mode
****************/

void vdNMX_DebugAddHEX(BYTE *title, BYTE *hex, USHORT len);
extern void PrintDebugMessage(const char* filePath, int lineNumber, const char * functionName, const char* format, ...);


#define vdNMX_Debug_LogPrintf(...)  PrintDebugMessage(__FILE__, __LINE__,__FUNCTION__, __VA_ARGS__)


	
#ifdef	__cplusplus
}
#endif

#endif	/* _DEBUG_ISO_ENG_H */

