/* 
 * File:   CardUtil.h
 * Author: Administrator
 *
 * Created on 2012年8月21日, 下午 4:25
 */

#ifndef CARDUTIL_H
#define	CARDUTIL_H

#ifdef	__cplusplus
extern "C" {
#endif

extern void vdGetCardHolderName(BYTE *szTrack1, USHORT usTRack1Len);
extern void vdGetCardHolderName(BYTE *szTrack1, USHORT usTRack1Len);
extern short shAnalysisTrack2(BYTE *szTrack2, USHORT usTRack2Len); //Invalid card reading fix -- jzg
extern void vdAnalysisTrack1(BYTE *szTrack1, USHORT usTRack2Len);
extern void vdRemoveCard(void);

short chk_luhn(BYTE *szPAN);
short shChk_ExpireDate(void);


//gcitra
void  vdAnalysisTrack1(BYTE *szTrack1, USHORT usTRack1Len);
//gcitra


#ifdef	__cplusplus
}
#endif

#endif	/* CARDUTIL_H */

