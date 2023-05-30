/* 
 * File:   newfile.h
 * Author: Administrator
 *
 * Created on 2012年9月18日, 下午 3:31
 */

#ifndef NEWFILE_H
#define	NEWFILE_H

#ifdef	__cplusplus
extern "C" {
#endif

extern void vdSHA1Generate(BYTE *szData, USHORT szDataLen, BYTE *szSHA1Result);
extern void vdTripleDES_CBC(BYTE Mode, BYTE *szMsg, BYTE szMsgLen, BYTE *DESResult);
extern void GET_KEY( BYTE *szClearTMK , BYTE *szClearTAK);
extern void Decrypt3Des(unsigned char *data, unsigned char *key, unsigned char *result);
extern void Encrypt3Des(unsigned char *data, unsigned char *key, unsigned char *result);
extern void vdisoOneTwo(BYTE *in, BYTE *out, short lc);
extern void vdisoTwoOne(unsigned char *in,short inInLen,unsigned char *out);
#ifdef	__cplusplus
}
#endif

#endif	/* NEWFILE_H */

