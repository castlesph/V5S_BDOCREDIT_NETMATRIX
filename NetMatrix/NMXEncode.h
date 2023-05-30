#ifndef __NMX_ENCODE_H__
#define __NMX_ENCODE_H__


// EncodeLib
#define ENC250_ESCAPE_CHR			0x00
#define	ENC250_SEPARATOR_CHR		0x01
#define	ENC250_RESERVED_1_CHR		0x02
#define	ENC250_RESERVED_2_CHR		0x03
#define	ENC250_RESERVED_3_CHR		0x04
#define	ENC250_RESERVED_4_CHR		0x05


// encode
#define ERR_ENC_INSUFF_BUFFER		-1101




// LOCAL PROTOTYPE
int iEncode250 (unsigned char *pbt_Data, int i_DataLen, unsigned char *pbt_Encoded, int *pi_EncodeLen);
int iDecode250 (unsigned char *pbt_Encoded, int i_EncodeLen, unsigned char *pbt_Data, int *pi_DataLen);
int iEncode64(unsigned char *pbt_Data, int i_DataLen, char *sz_Encoded, int *pi_EncodeLen);
//int iDecode64(char *sz_Encoded, int i_EncodeLen, unsigned char *pbt_Data, int *pi_DataLen);
int iEncode16(unsigned char *pbt_Data, int i_DataLen, char *sz_Encoded, int *pi_EncodeLen);
int iDecode16(char *sz_Encoded, int i_EncodeLen, unsigned char *pbt_Data, int *pi_DataLen);

////////////////////////////////////////////////////////////////

// Base 64 encoding
//int base64_decode(char *input);
int base64_encode(char *binStr, unsigned len, char *psz_Encoded);
// Base 16 encoding
void ByteToHex(unsigned char *pbt_BytArray, int i_ByteLen, char *sz_HexStr);
void HexToByte(char *sz_HexStr, int i_HexLen, unsigned char *pbt_BytArray);



#endif //end __NMX_ENCODE_H__


