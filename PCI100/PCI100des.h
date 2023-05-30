#ifndef _PCI100DES_H
#define	_PCI100DES_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef byte
#define byte 	unsigned char
#endif

void PCI100_DSP_2_HEX(byte *dsp, byte *hex, int count);
void PCI100_HEX_2_DSP(char *hex, char *dsp, int count);
void PCI100_HEX_2_BIT(byte *inText, int *outText, int count);
void PCI100_BIT_2_HEX(int *inText, byte *outText, int count);
void TripleDes_24Key(byte *dkey, byte *tt, byte *cipher, char f);
void TripleDes_16Key(byte *dkey, byte *tt, byte *cipher, char f);
void PCI100_XOR(byte *inOut, byte *ICV, int count);
void dess(byte *dkey, byte *tt, byte *cipher, char f);

	
#ifdef	__cplusplus
}
#endif

#endif	/* _PCI100DES_H */

