/* 
 * File:   msg.h
 * Author: XYZ
 *
 * Created on 2012年8月26日, 下午 4:47
 */

#ifndef MSG_H
#define	MSG_H

#ifdef	__cplusplus
extern "C" {
#endif

/*error message*/
#define MSG_USER_CANCEL        101
#define MSG_TRANS_ERROR        102
#define MSG_EMV_INSER_CHIP     103
#define MSG_MSR_NOT_ALLOW      104
#define MSG_MANUAL_NOT_ALLOW   105
#define MSG_CONNECTION_FAILED  106
#define MSG_USER_TIMEOUT       107
#define MSG_INVALID_RECORD     108
#define MSG_CARD_EXPIRED       109
#define MSG_BATCH_EMPTY        110
#define MSG_RECORD_VOIDED      111
#define MSG_SETTLE_FIRST       112
#define MSG_SETTLE_FAILED      113
#define MSG_NO_DIAL_TONE       114
#define MSG_NO_CARRIER         115
#define MSG_LINE_BUSY          116
#define MSG_TRANS_REJECTED     117
#define MSG_TRANS_NOT_ALLOW    118
#define MSG_TIPADJ_NOT_ENABLED    119   

#define MSG_ERROR              999
    

#ifdef	__cplusplus
}
#endif

#endif	/* MSG_H */

