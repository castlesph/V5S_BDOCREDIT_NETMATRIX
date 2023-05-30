
#ifndef _POSWAVE_H
#define	_POSWAVE_H

#ifdef	__cplusplus
extern "C" {
#endif

int inCTOS_WaveFlowProcess(void);
int inCTOS_WAVE_SALE(void);
int inCTOS_WAVE_REFUND(void);
int inCTOS_MultiAPReloadWaveData(void);
void vdCTOS_InitWaveData(void);
void vdCTOSS_SetWaveTransType(int type);
int inCTOSS_GetWaveTransType(void);
void vdCTOSS_GetALLWaveSetting(void);

extern int inDisconnectIfNoPendingADVICEandUPLOAD(TRANS_DATA_TABLE *srTransPara, int inAdvCnt);
void vdSMReEnterCardDetails(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _POSCTLS_H */

