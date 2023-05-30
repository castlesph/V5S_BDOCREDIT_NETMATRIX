/******************************************************************************
Vega 7000 EMV Level2 Credit/Debit Card Demo Program

Source File : wub_lib.c

Description : Toolkit APIs for demo program

Released Date : 2006/11/20
******************************************************************************/

//---------------------------------------------------------------------------
// String Function
//---------------------------------------------------------------------------

/*******************
 *
 *the function can return the number of Bytes of the input string.
 *the function will stop when the Byte is 0x00.
 *[in] string
 *return: i: the last byte
 *
 ******************/
#include <string.h>
#include <stdio.h>
#include <ctosapi.h>
#include <stdlib.h>
#include <stdarg.h>

unsigned int wub_find_str_end_pt(unsigned char *str)
{
    unsigned int i;
    i = 0;
    while (str[i] != 0x00)
        i ++;
    return i;
}

/*****************
 *
 *the function can append the source string behind the destination string.
 *the function will stop when the Byte of the source string is 0x00.
 *[in/out] dest
 *[in] sour
 *
 *****************/
void wub_strcat(unsigned char *dest, unsigned char *sour)
{
    unsigned int i, j;
    i = wub_find_str_end_pt(dest);
    j = 0;
    while (sour[j] != 0x00)
    {
        dest[i ++] = sour[j ++];
    }
    dest[i] = 0x00;
}


/*******************
 *
 *the function can append the n Byte of the source string 
 *behind the destination string.
 *the function will stop when the Byte of the source string is 0x00,
 *or the append length is bigger than the n.
 *[in/out] dest
 *[in] sour
 *[in] n
 *
 ********************/
void wub_strncat(unsigned char *dest, unsigned char *sour, unsigned int n)
{
    unsigned int i, j;
    i = wub_find_str_end_pt(dest);
    j = 0;
    while ((sour[j] != 0x00) && (j <= n))
    {
        dest[i ++] = sour[j ++];
    }
    dest[i] = 0x00;
}

/************************
 *
 *the function can copy the source string to the destination string.
 *the function will stop when the Byte of the source string is 0x00.
 *[in] sour
 *[out] dest
 *
 *************************/
void wub_strcpy(unsigned char *dest, unsigned char *sour)
{
    unsigned int i;
    i = 0;
    while (sour[i] != 0x00)
    {
        dest[i] = sour[i];
        i ++;
    }
    dest[i] = 0x00;
}

/*****************
 *
 *the function can return the length of the string.
 *the function will stop when the Byte is 0x00.
 *[in] str
 *return: i: the length of the string
 ******************/
unsigned int wub_strlen(unsigned char *str)
{
    unsigned int i;
    i = 0;
    while (str[i ++] != 0x00) ;
    return i - 1;
}

//---------------------------------------------------------------------------
// Memory Function
//---------------------------------------------------------------------------
/****************
 *
 *the function can change the value of the string.
 *when the value is 0x20, it can change it to 0x00.
 *[in/out] dest
 *[in] len
 *
 ****************/
void wub_mem_20_TO_00(unsigned char *dest, unsigned int len)
{
    while (len--)
    {
        if (*dest == 0x20 )
        *dest = 0x00;
        *dest++;
    }
}

/***************
 *
 *the function can copy the source string to the destination string.
 *[in] sour
 *[in] len
 *[out] dest
 *
 **************/
void wub_memcpy(unsigned char *dest, unsigned char *sour, unsigned int len)
{
    while (len--)
    {
        *dest++ = *sour++;
    }
}

/********************
 *
 *the index of the source string is shift_len.
 *to copy the source string to the destination string.
 *the function will stop when the len is 0.
 *[in] sour
 *[in] shitt_len
 *[in] len
 *[out] dest
 *
 *********************/
void wub_memor(unsigned char *dest, unsigned char *sour, unsigned int shift_len,unsigned int len)
{
    sour += shift_len;
    
    while (len--)
    { 
        *dest++ = *sour++;
    }
}

/********************
 *
 *the index of the destination string is shift_len.
 *to copy the source string to the destination string.
 *the function will stop when the len is 0.
 *[in] sour
 *[in] shitt_len
 *[in] len
 *[out] dest
 *
 *********************/
void wub_memor_dest_len(unsigned char *dest, unsigned char *sour, unsigned int shift_len,unsigned int len)
{
    dest += shift_len;
    
    while (len--)
    {
        *dest++ = *sour++;
    }
}

/**************
 *
 *the function will set the value "dat" to each Byte of the string.
 *[in] dat
 *[in] len
 *[out] addr
 *
 *************/
void wub_memset(unsigned char *addr, unsigned char dat, unsigned int len)
{
    while (len > 0)
    {
        addr[len - 1] = dat;
        len --;
    }
}

//---------------------------------------------------------------------------
// Converter Function
//---------------------------------------------------------------------------

/******************
 *
 *convert Hex to ASC
 *[note] only one Byte
 *[in] hex
 *return ASC
 *
 ******************/
unsigned char wub_hex_2_ascii(unsigned char hex)
{
    if (hex <= 9)
        return hex + '0';
    else
        return hex - 10 + 'A';
}

/*****************
 *
 *step 1. convert Hex to ASC, and the Hex is 0x00~0xFF
 *step 2. append the Hex behind the string
 *the function will add 2 Byte behind the string
 *[in] dat
 *[out] str
 *
 *****************/
void wub_str_append_byte_hex(unsigned char *str, unsigned char dat)
{
    unsigned int i;
    i = wub_find_str_end_pt(str);
    str[i ++] = wub_hex_2_ascii(dat / 16);
    str[i ++] = wub_hex_2_ascii(dat % 16);
    str[i] = 0x00;
}
/*****************
 *
 *step 1. convert Hex to ASC, and the Hex is 0x00~0xFFFF
 *step 2. append the Hex behind the string
 *the function will add 4 Byte behind the string
 *[in] dat
 *[out] str
 *
 *****************/
void wub_str_append_short_hex(unsigned char *str, unsigned short dat)
{
    wub_str_append_byte_hex(str, (unsigned char)(dat / 256));
    wub_str_append_byte_hex(str, (unsigned char)(dat % 256));
}
/*****************
 *
 *step 1. convert Hex to ASC, and the Hex is 0x00~0xFFFFFFFF
 *step 2. append the Hex behind the string
 *the function will add 8 Byte behind the string
 *[in] dat
 *[out] str
 *
 *****************/
void wub_str_append_long_hex(unsigned char *str, unsigned long dat)
{
    wub_str_append_short_hex(str, (unsigned short)(dat / 65536));
    wub_str_append_short_hex(str, (unsigned short)(dat % 65536));
}

/*****************
 *
 *step 1. convert Hex to ASC, and the Hex is 0~100
 *step 2. append the Hex behind the string
 *the function will add 8 Byte behind the string
 *[in] dat
 *[out] str
 *
 *****************/

void wub_str_append_2d_dec(unsigned char *str, unsigned char dat)
{
    unsigned int i;
    i = wub_find_str_end_pt(str);
    str[i ++] = wub_hex_2_ascii(dat / 10);
    str[i ++] = wub_hex_2_ascii(dat % 10);;
    str[i] = 0x00;
}


/*****************
 *
 *step 1. convert Hex to ASC, and the Hex is 0~4294967295
 *step 2. append the Hex behind the string
 *the function will add 8 Byte behind the string
 *[in] dat
 *[out] str
 *
 *****************/
void wub_str_append_long_dec(unsigned char *str, unsigned long dat)
{
    //Max value of ULONG 4294967295
    unsigned char dec[10], i, j;
    i = 0;
    j = wub_find_str_end_pt(str);
    wub_memset(dec, 0, 10);
    
    if (dat == 0)
    {
    	str[j ++] = '0';
    } else
    {
	    while (dat != 0)
	    {
	        dec[i ++] = dat % 10;
	        dat = dat / 10;
	    }
	    while (i > 0)
	    {
	        str[j ++] = wub_hex_2_ascii(dec[i - 1]);
	        i --;
	    }
	}
    str[j] = 0x00;
}

//return digit length
unsigned char wub_long_2_bcd(unsigned long dat, unsigned char *buf, unsigned char *byte_len)
{
    unsigned char temp[12];
    unsigned char index, btemp;

    temp[0] = 0;
    wub_str_append_long_dec(temp, dat);

    if (wub_strlen(temp) % 2 == 1)
    {
        buf[0] = 0x00;
        buf[0] += (temp[0] & 0x0F);
        index = 1;
        btemp = 1;
        *byte_len = (wub_strlen(temp) + 1) / 2;
    }
    else
    {
        index = 0;
        btemp = 0;
        *byte_len = wub_strlen(temp) / 2;
    }

    while (temp[index] >= 0x30 && temp[index] <= 0x39)
    {
        if (!btemp)
        {
            if (index % 2)
            	buf[(index - 1) / 2] += (temp[index] & 0x0F);
            else
            {
                buf[index / 2] = 0x00;
                buf[index / 2] += (temp[index] & 0x0F) << 4;
            }
        }
        else
        {
            if (index % 2 == 0)
            	buf[(index) / 2] += (temp[index] & 0x0F);
            else
            {
                buf[(index+1) / 2] = 0x00;
                buf[(index+1) / 2] += (temp[index] & 0x0F) << 4;
            }
        }
        index++;
    }

    return index;
}

/***************
 *
 *the function can change the lowercase letter to the capital letter
 *[in] dat
 *return dat
 ***************/
unsigned char wub_toupper(unsigned char dat)
{
	//a - z = 0x61 - 0x7A
	//A - Z = 0x41 - 0x5A

	if (dat >= 0x61 && dat <= 0x7A)
		dat -= 0x20;

	return dat;
}

/****************
 *
 *Pack 2 Byte to 1 Byte
 *ex. char H is 0x41 and char I is 0x42
 *the function can pack H and I to char J, and J is 0xAB
 *[in] h
 *[in] l
 *return i
 ****************/
unsigned char wub_pack_byte(unsigned char h, unsigned char l)
{
    unsigned char i, j, k;
    short z;

    j = wub_toupper(h);
    k = wub_toupper(l);

    if ((j >= '0' && j <= '9') || (j >= 'A' && j <= 'Z'))
    	;
    else
    	j = '0';

    if ((k >= '0' && k <= '9') || (k >= 'A' && k <= 'Z'))
    	;
    else
    	k = '0';

    if ((j >= 'A') && (j <= 'F'))
    {
    	z = 10;
    	z += (short) j;
    	z -= 65;
    	i = (unsigned char) (0xFF & z);
    }
    else
    	i = j - '0';

    i <<= 4;

    if ((k >= 'A') && (k <= 'F'))
    {
    	z = 10;
    	z += (short) k;
    	z -= 65;
    	i |= (unsigned char) (0xFF & z);
    }
    else
    	i |= (k - '0');

    return i;
}
/*****************
 *
 *unpack 1 byte to 2 byte
 *ex. 0xAB -> 0x41 0x42
 *[in] hex
 *[in] len
 *[out] str
 ****************/
unsigned int wub_hex_2_str(unsigned char *hex, unsigned char *str, unsigned int len)
{
    unsigned int i;
    str[0] = 0;
    for (i = 0; i < len; i ++)
        wub_str_append_byte_hex(str, hex[i]);
    return len * 2;
}

/****************
 *
 *pack 2 byte to 1 byte
 *ex. 0x41 0x42 -> 0xAB
 *[in] str
 *[in] len
 *[out] hex
 *
 ***************/
unsigned int wub_str_2_hex(unsigned char *str, unsigned char *hex, unsigned int len)
{
    unsigned int i;
    for (i = 0; i < len / 2; i ++)
    {
        hex[i] = wub_pack_byte(str[i * 2], str[i * 2 + 1]);
    }
    return len / 2;
}

/***************
 *
 *ex. the input string is 0x31 0x32 0x33 0x30 0x30
 *    after calling the function, the return value is
 *    12300
 *[in] str
 *return k
 ***************/
unsigned long wub_str_2_long(unsigned char *str)
{
    unsigned char i;
    unsigned long k;
    i = 0;
    k = 0;
    while (str[i] != 0x00)
    {
        k += str[i ++] - '0';
        if (str[i] != 0x00)
            k *= 10;
    }
    return k;
}

/***************
 *
 *the function can only handle the 4 byte string
 *ex. the string is 0x00 0x00 0x01 0xFF
 *    after calling the function, the return value is
 *    256 + 255 = 511
 *[in] para
 *return a
 ***************/
unsigned long wub_array_2_long(unsigned char *para)
{
	unsigned long a;
	a =  (unsigned long)((unsigned long)para[0] * 256 * 256 * 256);
	a += (unsigned long)((unsigned long)para[1] * 256 * 256);
	a += (unsigned long)((unsigned long)para[2] * 256);
	a += (unsigned long)((unsigned long)para[3]);
	return a;
}

/************
 *
 *the function can only handle the 4 byte string
 *ex. the value is 1000 
 *    after calling the function, the string is
 *    0x00 0x00 0x03 0xE8
 *[in] u
 *[out] b
 ************/
void wub_long_2_array(unsigned long u, unsigned char *b)
{
    
	b[0] = (unsigned char) (u >> 24);
        b[1] = (unsigned char) (u >> 16);
	b[2] = (unsigned char) (u >> 8);
	b[3] = (unsigned char) (u);
}

unsigned long wub_bcd_2_long(unsigned char *buf, unsigned char len)
{
	unsigned char str[13];
	
	if (len > 6 || len == 0)
		return 0;
		
	wub_hex_2_str(buf, str, len);
	
	return wub_str_2_long(str);
}

//---------------------------------------------------------------------------
// Utility Function
//---------------------------------------------------------------------------

unsigned char wub_compare_bits(unsigned char *A, unsigned char *B, unsigned int len)
{
    unsigned int i;
    for (i = 0; i < len; i ++)
    {
        if ((A[i] & B[i]) > 0)
        return 1;
    }
    return 0;
}

unsigned char wub_lrc(unsigned char *buf, unsigned int len)
{
    unsigned int i;
    unsigned char lrc;
    lrc = 0;
    for (i = 0; i < len; i ++)
    {
        lrc ^= buf[i];
    }
    return lrc;
}

/******************
 *
 *compare with addr1 and addr2
 *return 0: they are the same
 *       1: the are different
 *[in] addr1
 *[in] add2
 *[in] len
 ****************/
unsigned char wub_memcmp(unsigned char *addr1, unsigned char *addr2, unsigned int len)
{
    unsigned int i;
    for (i = 0; i < len; i ++)
    {
        if (addr1[i] != addr2[i])
            break;
    }
    if (i == len)
        return 0;
    return 1;
}

//Return offset byte number of the data location
//Return 0 = Error
unsigned short TLV_Get_Value(unsigned char *buf, unsigned short *tag_value, unsigned short *len_value)
{
    short i, length_len;

    i = 0;

    if ((buf[i] & 0x1F) == 0x1F)          //2 bytes tag
    {
        *tag_value = buf[i] * 256 + buf[i + 1];
        i += 2;
    }
    else
    {
        *tag_value = buf[i];
        i += 1;
    }

    if ((buf[i] & 0x80) == 0x80)
    {
        length_len = 1 + buf[i] & 0x7F;
        if (length_len == 2)
        {
            *len_value = buf[i + 1];
        }
        else if (length_len == 3)
        {
            *len_value = buf[i + 1] * 0x100 + buf[i + 2];
        }
        else
            return 0;
    } else
    {
            length_len = 1;
            *len_value = buf[i];
    }

    i += length_len;

    return i;
}

/**************
 *
 *ex. the number is 10000
 *    the array length is 6 
 *    after calling the function, the array is
 *    0x30 0x31 0x30 0x30 0x30 0x30
 *[in] number
 *[in] array_length
 *[out] array
 *
 *************/
void wub_long_2_array_v2(unsigned short array_length, unsigned long number, unsigned char *array)
{
    unsigned short i;
    wub_memset(array, 0x30, array_length);
    array_length--;
    while(1)
    {
        array[array_length] = number % 10 + '0';
        number /= 10;
        if(number == 0  || array_length == 0)
        {
            break;
        }
        array_length--;
    }
    
    
}

int wub_ASCIIIP2hex(char *strASCIIIP, unsigned char *strHexIP)
{
	int i, j, inPrev, inIP;
	int inlen;
	char temp[10];

	memset(strHexIP,0,5);

	inlen = strlen(strASCIIIP);
	j=0;
	inPrev=0;
	
	for(i=0;i<inlen;i++)
	{
		if(strASCIIIP[i]=='.')
			j++;
	}

	if(j!=3)
		return -1;

	j=0;
	for(i=0;i<inlen;i++)
	{
		
		if(strASCIIIP[i]=='.')
		{
			
			memcpy(temp, &strASCIIIP[inPrev], i-inPrev);
			temp[i-inPrev]=0;
			
			inIP= atoi(temp);
			if(inIP>255)
				return -1;

			strHexIP[j]=inIP;
			j++;
			inPrev=i+1;

			if(j==3)
			{
				memcpy(temp, &strASCIIIP[inPrev], inlen-i);
				temp[inlen-i]=0;
				strHexIP[j]=atoi(temp);
				break;
			}

		}

	}

	if(j=3)
		return 0;

	return -1;
}


unsigned long wub_str_2_doble(unsigned char *str)
{
    unsigned char i;
    double k;
    i = 0;
    k = 0;
    while (str[i] != 0x00)
    {
        k += str[i ++] - '0';
        if (str[i] != 0x00)
            k *= 10;
    }
    return k;
}

// Remove Specific character -- sidumili
char *purge_chr(char *str, char chr)
{
	char *ptr = str;

	while((*ptr != chr) && (*ptr != '\0')) ptr++;
	if(!*ptr) return(NULL);
	strcpy(ptr,ptr+1);
	return(str);
}

