/* 
 * File:   Showbmp.h
 * Author: Patrick Choon
 *
 * Created on 2014/01/22
 */

#ifndef _SHOWBMP__H
#define	_SHOWBMP__H

#ifdef	__cplusplus
extern "C" {
#endif

#include "..\Includes\POSTypedef.h"

void vdSetPrintThreadStatus(int inStatus);
void vdSetCommThreadStatus(int inStatus);

int inSetTextMode(void);
int inSetTextModeEx(BYTE *inbuf, USHORT inlen);
void vdThreadRunAppColdInit(void);
void *pvdDisplayAnimateBmp(void *pStAnimateBmp1);
void vdThreadDisplayPrintBmp(unsigned int x,unsigned int y, const char *path1, const char *path2, const char *path3, const char *path4, const char *path5);
void vdThreadDisplayCommBmp(unsigned int x,unsigned int y, const char *path1, const char *path2, const char *path3, const char *path4, const char *path5);
void vdDisplayAnimateBmp(unsigned int x,unsigned int y, const char *path1, const char *path2, const char *path3, const char *path4, const char *path5);
void displaybmpEx(unsigned int x,unsigned int y, const char *path);
void displayAppbmpDataEx(unsigned int x,unsigned int y, const char *path);
int inSetColorMenuMode(void);

#endif	/* _SHOWBMP__H */


