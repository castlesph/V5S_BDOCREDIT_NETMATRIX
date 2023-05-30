
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <ctosapi.h>
#include <sys/types.h>
#include <linux/errno.h>


#include "NMXEncode.h"
#include "NMXDefine.h"



/* ------------------------------------------------------------------------------------
	Desc:	Encodes the input binary stream to remove special characters.
			The caller must manage the memory allocation & deallocation of the buffers.
			This function will return an error if pbt_Encoded is not large enough; in this case,
			it will return the expected min length in pi_EncodeLen. Caller is expected to reallocate
			the pbt_Encoded buffer with sufficient space before calling this function again.
	Param:
		o pbt_Data:		Input arg containing bnary data to encode. 
						This is not a C string, so it does not have a terminating NULL.
		o i_DataLen:	Input value indicating length of pbt_data.
		o pbt_Encoded:	Output buffer containing the encoded data. This buffer must be allocated
						by the caller
		o pi_EncodeLen:	Input / Output value.
						Input the initial length of the pbt_Encoded buffer.
						Outputs the required minimum length of the pbt_Encoded buffer if error, or 
						the size of the encoded data if the function succeeds.
	Return:
					0:		OK
					-1:		internal error
					ERR_ENC_INSUFF_BUFFER:	Error - buffer not large enough
	Note: The caller is responsible for allocating & deallocating the pbt_Data & pbt_Encoded
	------------------------------------------------------------------------------------
*/
int iEncode250 (unsigned char *pbt_Data, int i_DataLen, unsigned char *pbt_Encoded, int *pi_EncodeLen)
{
	int				iExtraLen = 0;
	int				iEncodeLen = 0;
	unsigned char	pbtEncode[NMX_CARRIER_FIELD_SZ];
	int				i = 0, 
					j = 0;
	int				iRetVal = -1;

	//Calculate Encoded Byte Stream Length
	for (i = 0; i < i_DataLen; i++)
	{
		if ((ENC250_ESCAPE_CHR <= pbt_Data[i]) && (ENC250_RESERVED_4_CHR >= pbt_Data[i]))
		{
			iExtraLen++;
		}
	}
	iEncodeLen = i_DataLen + iExtraLen;
	if (iEncodeLen > *pi_EncodeLen)						//Buffer not large enough
	{
		iRetVal = ERR_ENC_INSUFF_BUFFER;
		goto ErrHandler;
	}

	//No conversion necessary
	if (0 == iExtraLen)
	{
		memcpy (pbt_Encoded, pbt_Data, i_DataLen);
		iRetVal = 0;
		goto CleanUp;
	}

	//Prepare Temporary Buffer
	memset(pbtEncode, 0x00, NMX_CARRIER_FIELD_SZ);
	
	//"Encode 250"
	for (i = 0; i < i_DataLen; i++)
	{
		if ((ENC250_ESCAPE_CHR <= pbt_Data[i]) && (ENC250_RESERVED_4_CHR >= pbt_Data[i]))
		{
			pbtEncode[j++] = ENC250_ESCAPE_CHR;			//Append ESC Character
			pbtEncode[j] = pbt_Data[i] + 48;			//Shifts to 0
		}
		else
		{
			pbtEncode[j] = pbt_Data[i];
		}
		j = j + 1;
	}
	
	memcpy (pbt_Encoded, pbtEncode, iEncodeLen);
	iRetVal = 0;

CleanUp:
	*pi_EncodeLen = iEncodeLen;
	return iRetVal;

ErrHandler:
	goto CleanUp;
}


/* ------------------------------------------------------------------------------------
	Desc:	Decodes binary stream encoded by iEncode250 into its original form.
			The caller must manage the memory allocation & deallocation of the buffers.
			This function will return an error if pbt_Data is not large enough; in this case,
			it will return the expected min length in pi_DataLen. Caller is expected to reallocate
			the pbt_Data buffer with sufficient space before calling this function again.
	Param:
		o pbt_Encoded:	Input binary that have been encoded with iEncode250						
		o i_EncodeLen:	Input value indicating length of pbt_Encoded.
		o pbt_Data	 :	Output buffer containing the decoded data. This buffer must be allocated
						by the caller
		o pi_DataLen :	Input / Output value.
						Input the initial length of the pbt_Data buffer.
						Outputs the required minimum length of the pbt_Data buffer if error, or 
						the size of the decoded data if the function succeeds.
	Return:
					 0:	OK
					-1:	system error
					 ERR_ENC_INSUFF_BUFFER:	Error - buffer not large enough
	Note: The caller is responsible for allocating & deallocating the pbt_Data & pbt_Encoded
	------------------------------------------------------------------------------------
*/
int iDecode250 (unsigned char *pbt_Encoded, int i_EncodeLen, unsigned char *pbt_Data, int *pi_DataLen)
{
	int				iExtraLen = 0;
	int				iDecodeLen = 0;
	int				i = 0, 
					j = 0;
	int				iRetVal = -1;
	
	//Calculate Decoded String Length
	for (i=0, iExtraLen=0; i < i_EncodeLen; i++)
	{
		if (ENC250_ESCAPE_CHR == pbt_Encoded[i])
		{
			iExtraLen++;
		}
	}
	iDecodeLen = i_EncodeLen - iExtraLen;
	if (iDecodeLen > *pi_DataLen)	//Buffer not large enough
	{
		iRetVal = ERR_ENC_INSUFF_BUFFER;
		goto ErrHandler;
	}

	//No conversion necessary
	if (0 == iExtraLen)
	{
		memcpy (pbt_Data, pbt_Encoded, i_EncodeLen);
		iRetVal = 0;
		goto CleanUp;
	}

	// clear pbt_Data
	memset (pbt_Data, 0x00, iDecodeLen);
	
	//"Decode 250"
	for (i=0, j=0; i < i_EncodeLen; i++, j++)
	{
		if (ENC250_ESCAPE_CHR == pbt_Encoded[i])
		{
			i++;
			pbt_Data[j] = pbt_Encoded[i] - 48;
		}
		else
		{
			pbt_Data[j] = pbt_Encoded[i];
		}
	}

	iRetVal = 0;

CleanUp:
	*pi_DataLen = iDecodeLen;
	return iRetVal;

ErrHandler:
	goto CleanUp;
}


// Encode Byte Array to Base64 Encoded String
int iEncode64(unsigned char *pbt_Data, int i_DataLen, char *sz_Encoded, int *pi_EncodeLen)
{
	char	szTmpEncode[NMX_CARRIER_FIELD_SZ];			//Temp Encoded storage
	int		iEncodeLen		= 0;
	int		iRetVal			= -1;

	base64_encode((char *)pbt_Data, (unsigned int) i_DataLen, szTmpEncode);

	//Prepare to copy encoded string to sz_Encoded
	iEncodeLen = strlen(szTmpEncode) ;
	if ((iEncodeLen+1) > *pi_EncodeLen)
	{
		iRetVal = ERR_ENC_INSUFF_BUFFER;			//Buffer not large enough
		goto ErrHandler;
	}
	memcpy(sz_Encoded, szTmpEncode, iEncodeLen);	//szTmpEncode inc. /0
	iRetVal = 0;

CleanUp:
	*pi_EncodeLen = iEncodeLen;
	return iRetVal;

ErrHandler:
	goto CleanUp;
}

#if 0
// Decode Base64 Encoded String to Byte Array
int iDecode64(char *sz_Encoded, int i_EncodeLen, unsigned char *pbt_Data, int *pi_DataLen)
{
	char szEncData[NMX_CARRIER_FIELD_SZ];			//Temporary Buffer
	int iDataLen = 0;
	int iRetVal = -1;
	
	//Copy sz_Encoded into a buffer
	memset(szEncData, 0x00, NMX_CARRIER_FIELD_SZ);	
	memcpy (szEncData, sz_Encoded, i_EncodeLen);

	iDataLen = base64_decode(szEncData);
	if (0 >= iDataLen)
	{
		goto ErrHandler;				//Failed to decode string
	}
	
	//Prepare to copy decoded bytes to pbt_Data
	if (iDataLen > *pi_DataLen)
	{
		iRetVal = ERR_ENC_INSUFF_BUFFER;		//Buffer not large enough
		goto ErrHandler;
	}
	memcpy(pbt_Data, szEncData, iDataLen); 
	iRetVal = 0;

CleanUp:
	*pi_DataLen = iDataLen;				//Return Data Len
	return iRetVal;

ErrHandler:
	goto CleanUp;
}
#endif

// Encode Byte Array to Base16 Encoded String
int iEncode16(unsigned char *pbt_Data, int i_DataLen, char *sz_Encoded, int *pi_EncodeLen)
{
	int		iEncodeLen		= 0;
	int		iRetVal			= -1;
		
	//Calculate Encoded String Length
	iEncodeLen = (i_DataLen * 2) + 1;
	
	if (iEncodeLen > *pi_EncodeLen)
	{
		iRetVal = ERR_ENC_INSUFF_BUFFER;		//Buffer not large enough
		goto ErrHandler;
	}
	ByteToHex (pbt_Data, i_DataLen, sz_Encoded);	//sz_Encoded is NULL terminated
	iRetVal = 0;

CleanUp:
	*pi_EncodeLen = iEncodeLen;
	return iRetVal;

ErrHandler:
	goto CleanUp;
}

int iDecode16(char *sz_Encoded, int i_EncodeLen, unsigned char *pbt_Data, int *pi_DataLen)
{
	int iDataLen = 0;
	int iRetVal = -1;

	//Calculate Decoded Byte Array Length
	iDataLen = (i_EncodeLen / 2);		//Exclude NULL terminator
	
	if (iDataLen > *pi_DataLen)
	{
		iRetVal = ERR_ENC_INSUFF_BUFFER;		//Buffer not large enough
		goto ErrHandler;
	}
	HexToByte (sz_Encoded, i_EncodeLen, pbt_Data);
	iRetVal = 0;

CleanUp:
	*pi_DataLen = iDataLen;				//Return Data Len	
	return iRetVal;

ErrHandler:
	goto CleanUp;
}


/****************************************************************************************

  Implementation of Base64 Encoding/Decoding & Base16 Encoding/Decoding

 ****************************************************************************************/

/*** Encode 64 Functions ***/
#define XX 127

/* Tables for encoding/decoding Base 64 */
static const char basis_64[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char index_64[256] = {
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,62, XX,XX,XX,63,
    52,53,54,55, 56,57,58,59, 60,61,XX,XX, XX,XX,XX,XX,
    XX, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,XX, XX,XX,XX,XX,
    XX,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
};
#define CHAR64(c)  (index_64[(unsigned char)(c)])

/*
 * Decode in-place the base64 data in 'input'.  Returns the length
 * of the decoded data, or -1 if there was an error.
 */
 #if 0
int base64_decode(char *input) {
    int len = 0;
    unsigned char *output = (unsigned char *)input;
    int c1, c2, c3, c4;

    while (*input) {
    c1 = *input++;
    if (CHAR64(c1) == XX) return -1;
    c2 = *input++;
    if (CHAR64(c2) == XX) return -1;
    c3 = *input++;
    if (c3 != '=' && CHAR64(c3) == XX) return -1; 
    c4 = *input++;
    if (c4 != '=' && CHAR64(c4) == XX) return -1;
    *output++ = (CHAR64(c1) << 2) | (CHAR64(c2) >> 4);
    ++len;
    if (c3 == '=') break;
    *output++ = ((CHAR64(c2) << 4) & 0xf0) | (CHAR64(c3) >> 2);
    ++len;
    if (c4 == '=') break;
    *output++ = ((CHAR64(c3) << 6) & 0xc0) | CHAR64(c4);
    ++len;
    }

    return len;
}
 #endif
    
/*
 * Encode the given binary string of length 'len' and return Base64
 * in a char buffer.  It allocates the space for buffer.
 * caller must MEM_CLEAR the space.
 */
int base64_encode(char *binStr, unsigned len, char *psz_Encoded) 
{
    char buf[NMX_CARRIER_FIELD_SZ];
    int buflen = 0;
    int c1, c2, c3;
    int maxbuf;

#ifdef RUBBISH
    maxbuf = len*4/3 + 1;  /* size after expantion */
#endif
    maxbuf = len*2 + 20;  /* size after expantion */

	memset(buf, 0x00, NMX_CARRIER_FIELD_SZ);

    while (len) {
    
    c1 = (unsigned char)*binStr++;
    buf[buflen++] = basis_64[c1>>2];

    if (--len == 0) c2 = 0;
    else c2 = (unsigned char)*binStr++;
    buf[buflen++] = basis_64[((c1 & 0x3)<< 4) | ((c2 & 0xF0) >> 4)];

    if (len == 0) {
        buf[buflen++] = '=';
        buf[buflen++] = '=';
        break;
    }

    if (--len == 0) c3 = 0;
    else c3 = (unsigned char)*binStr++;

    buf[buflen++] = basis_64[((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)];
    if (len == 0) {
        buf[buflen++] = '=';

        break;
    }

    --len;
    buf[buflen++] = basis_64[c3 & 0x3F];

    }

    buf[buflen]=0;

	strcpy(psz_Encoded, buf);

    return 0;
} 

/*** Encode 16 Functions ***/
/********************************************************************************
	Function Name    :  ByteToHex
    Purpose			 :  Converts a Byte Array to HEX String
    Input Parameter  :  pbt_BytArray [in] - pointer to Byte Array to be converted.
					 :  i_ByteLen [in] - the length of the Byte Array.  
    Output Parameter :  sz_HexStr [out] - pointer to HEX String to be returned
    Return           :  None 
    History          :  4/12/2000  Lau Weng Tat Modified
*********************************************************************************/
void ByteToHex(unsigned char *pbt_BytArray, int i_ByteLen, char *sz_HexStr)
{
	//Declare and initialize local variables.
	unsigned char *pbtTmp = pbt_BytArray;	// local pointer to a BYTE in the BYTE array
	int i;									// local loop counter
	int b;									// local variable

	//  Begin processing loop.
	for (i = 0; i < i_ByteLen; i++)
	{
		b = (*pbtTmp & 0xF0) >> 4;
		*sz_HexStr++ = (b <= 9) ? b + '0' : (b - 10) + 'A';
		b = *pbtTmp & 0x0F;
		*sz_HexStr++ = (b <= 9) ? b + '0' : (b - 10) + 'A';
		pbtTmp++;
	}
	*sz_HexStr++ = 0x00;
}

/********************************************************************************
	Function Name    :  HexToByte
	Purpose			 :  Converts a HEX String to Byte Array
	Input Parameter  :  sz_HexStr [in] - HEX String to be converted.
					 :  i_HexLen [in] - the length of the HEX String.  
	Output Parameter :  pbt_BytArray [out] - pointer to Byte Array to be returned
	Return           :  None 
	History          :  4/12/2000  Lau Weng Tat Created
*********************************************************************************/
void HexToByte(char *sz_HexStr, int i_HexLen, unsigned char *pbt_BytArray)
{
	char *szHex = sz_HexStr;		// local pointer to the HEX String
	int i;							// local loop counter
	int leftB, rightB, finalB;		// local variables

	for (i = 0; i < i_HexLen; i += 2)
	{
		leftB = (szHex[i] <= '9') ? (szHex[i] - '0') << 4 : ((szHex[i] + 10) - 'A') << 4 ; 
		rightB = (szHex[i+1] <= '9') ? szHex[i+1] - '0': (szHex[i+1] + 10) - 'A';

		finalB = leftB | rightB;

		pbt_BytArray[i/2] = finalB;
	}
	//pbt_BytArray[i_HexLen/2] = 0x00;	//Exclude NULL Terminator
}
