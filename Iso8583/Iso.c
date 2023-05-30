/*author: albert yap-diangco, 20140730*/
#if 1
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctosapi.h>

#include "iso.h"
#else
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <aclconio.h>
#include <svc.h>
#include "iso.h"

#include <logsys.h>
#endif

#include "..\Debug\Debug.h"
#include "..\Print\Print.h"
#include "../FileModule/myFileFunc.h"



//extern void vdDebug_LogPrintf(const char * fmt,...);

#define NUMERIC_			0x01
#define TRACKX		  	0x02
#define ALPHANUM_	  	0x03
#define ALPHANUMS	  	0x04
#define BITS		    	  	0x05

#define LLVAR	      		0x01
#define LLLVAR		  	0x02
#define MMDDhhmmss	0x03
#define MMDD		    	0x04
#define YYMM		    	0x05
#define hhmmss		  	0x06

#define BYTE_2_LEN		  	0x07

struct BITD {
	 char bitn;				/* bit number */
	 char format;			/* bit format */
	 char attrib;			/* attribute */
	 int max;				/* max width */
};

struct BITD bittab[] = {
	{ 2  ,	LLVAR     ,	TRACKX  , 20 },
	{ 3  ,	0         ,	NUMERIC_  , 6  },
	{ 4  ,	0         ,	NUMERIC_  , 12 },
	{ 6  ,	0         ,	NUMERIC_  , 12 },
	{ 7  ,	MMDDhhmmss,	NUMERIC_  , 10 },
	{ 11 ,	0         ,	NUMERIC_  , 6  },
	{ 12 ,	hhmmss    ,	NUMERIC_  , 6  },
	{ 13 ,	MMDD      ,	NUMERIC_  , 4  },
	{ 14 ,	YYMM      ,	NUMERIC_  , 4  },
	{ 15 ,	MMDD      ,	NUMERIC_  , 4  },
	{ 22 ,	0         ,	NUMERIC_  , 3  },
	{ 23 ,	0         ,	NUMERIC_  , 3  },	
	{ 24 ,	0         ,	NUMERIC_  , 3  },
	{ 25 ,	0         ,	NUMERIC_  , 2  },
	{ 35 ,	LLVAR     , TRACKX   , 37 },
	{ 37 ,	0         ,	ALPHANUM_ , 12 },
	{ 38 ,	0         ,	ALPHANUM_ , 6  },
	{ 39 ,	0         ,	ALPHANUM_ , 2  },
	{ 41 ,	0         ,	ALPHANUMS, 8  },
	{ 42 ,	0         ,	ALPHANUMS, 15 },
	{ 43 ,	0         ,	ALPHANUMS, 40 },
	{ 44 ,	LLVAR     ,	ALPHANUMS, 0  },
	{ 47 ,	LLLVAR    ,	ALPHANUMS, 0  },
	{ 48 ,	LLLVAR    ,	ALPHANUMS, 0  },
	{ 49 ,	0    	  ,	NUMERIC_, 3  }, 
	{ 51 ,	0    	  ,	NUMERIC_, 3  }, 
	{ 52 ,	0         ,	BITS     , 64 },
	{ 53 ,	0         ,	NUMERIC_ , 16 },	
	{ 54 ,	LLLVAR    ,	ALPHANUM_ , 0  },
	{ 55 ,	LLLVAR    ,	ALPHANUMS , 0  },	
	{ 57 ,	LLLVAR    ,	ALPHANUMS, 0  },
	{ 60 ,	LLLVAR    ,	ALPHANUMS, 0  },
	{ 61 ,	LLLVAR    ,	ALPHANUMS, 0  },
	{ 62 ,	LLLVAR    ,	ALPHANUMS, 0  },
	{ 63 ,	LLLVAR    ,	ALPHANUMS, 0  },
	{ 64 ,	0         ,	BITS     , 64 },
	{ 255,	0         ,	0        , 0, }
};

struct BITD bittabDCC[] = {
    { 1,     0,	   ALPHANUMS,    4},
    { 2,     BYTE_2_LEN,    ALPHANUMS,    0},
    { 3,     0,	   ALPHANUMS,    16},
    { 4,     BYTE_2_LEN,    NUMERIC_,    0},
    { 6,     0,    NUMERIC_,    16},
    { 9,     0,    NUMERIC_,    10},
    { 10,    BYTE_2_LEN,	   ALPHANUMS,    0},
    { 15,    0,	   ALPHANUMS,    3},
    { 16,    0,	   ALPHANUMS,    14},
    { 17,    0,	   ALPHANUMS,    2},
    { 18,    0,	   ALPHANUMS,    11},
    { 20,    BYTE_2_LEN,	   ALPHANUMS,    0},
    { 21,    0,	   ALPHANUMS,    16},	
    { 22,    0,	   ALPHANUMS,    6},
    { 23,    0,	   ALPHANUMS,    10},
    { 24,    0,    ALPHANUMS,    3},
    { 25,    0,	   ALPHANUMS,    2},
    { 26,    0,	   ALPHANUMS,    9},
    { 27,	 0,    ALPHANUMS,	 9},
    { 28,	 0,    NUMERIC_,	 16},
    { 29,	 0,    NUMERIC_,	 3},
    { 255,   0,	   0,    0}
};

char *bptr;
char *bitmap;
char *bitp[65];
char bitp2[65][36+1];
char bitDCC[32][36+1];
int inDCCLen[32+1];


static  int bptrlen=0;
char bit_set_bits[] = {128, 64, 32, 16, 8, 4, 2, 1 };
static CTOS_FONT_ATTRIB stgFONT_ATTRIB;

long bcd_long(char *bcd, int len)
{
	char temp[8+1];
	unsigned int index,index2=0; 
	char chTemp;

	memset(temp,0,sizeof(temp));
	for(index=0; index < len; index++)
	{
		chTemp=bcd[index];
		//cout << "chTemp = " << chTemp << endl;
		temp[index2]=((chTemp & 0xf0) >> 4) | 0x30; index2++;
		//cout << "1. temp[index2] = " << temp[index2-1] << endl;
		temp[index2]=(chTemp & 0x0f) | 0x30; index2++;
		//cout << "2. temp[index2] = " << temp[index2-1] << endl;
	}

	return atol(temp);
}

void long_bcd( char *buf,  long val, int len)
{
	char temp[8+1];
	int index,index2=0;
	char chTemp;

	memset(temp,0,sizeof(temp));
	//sprintf_s(temp,"%04ld",val);
	sprintf(temp,"%04ld",val);
	
	for(index=0; index < len; index++)
	{

	}
}

char bittest( char *bitmap,  char pbitno)
{
   char val, val2;

  val = ( char)((pbitno-1) / 8);
  val2 = ( char)((pbitno-1)%8);

  return((bitmap[val] << val2) & 0x80);
}

void bitset( char *bmap,  char bitnum)
{
   char val1, val2, val3;

  val1 = ( char)((bitnum - 1) / 8);
  val2 = ( char)((bitnum - 1) % 8);
  val3 = bit_set_bits[val2];
  bmap[val1] |= val3 ;
}

void bitreset( char *bmap,  char bitnum)
{
   	char val1, val2, val3, val4;

	if(!bittest(bitmap, bitnum))
	{
		return;
	}
		
  	val1 = ( char)((bitnum - 1) / 8);
  	val2 = ( char)((bitnum - 1) % 8);
  	val3 = bit_set_bits[val2];
  	val4 = bmap[val1];
  	val4 -= val3;
 	bmap[val1] = 0;
  	bmap[val1] |= val4 ;
  	//ntf("5. bmap[val1]=%02x\n",bmap[val1]);
}

void print_bitp(void)
{
	int i;
	char temp[256+1];

	
	for (i=1; i<65; i++)
	{
  		if (bittest(bitmap, i))
  		{
			memset(temp,0,sizeof(temp));
			//cout << "bitp[i]=" << i << endl;
			memcpy(temp,bitp[i],16);
			//print_hex("value",temp,16);
		}
	  }
}

char *Unpack( char *buf)
{
   char i, j;
   int len;

  bitmap = buf+2;
  bptr = buf+10;

  for (i=1; i<65; i++)
  {
  	if (bittest(bitmap, i))
  	{
		//printf("unpack field %d\n",i);
	  	for (j=0; bittab[j].bitn != 255; j++)
	  	  if (bittab[j].bitn == i) 
	  	    break;
	  	    
		  if (bittab[j].bitn == 255)
		    return(NULL);
		//LOG_PRINTF(("bitp[%d]",i));    
  		bitp[i] = bptr;
		switch(bittab[j].attrib)
		  {
				case NUMERIC_ :
			  	if (bittab[j].format == LLLVAR)
				  {
					  len = ( int)bcd_long(bptr, 2);
  					bptr += 2;
	  			}
		  		else if (bittab[j].format == LLVAR)
			  	{
				  	len = ( int)bcd_long(bptr, 1);
					  ++bptr;
  				}
	  			else
	  			{
					len = bittab[j].max;
	  			}
				//printf("NUMERIC_ len=%d\n",len);
		  		bptr += (len+1)/2;
			  	break;
			  	
			  case TRACKX :
				  len = ( int)bcd_long(bptr, 1);
				  ++bptr;
				  bptr += (len+1)/2;
				  break;
				  
			  case ALPHANUM_ :
			  case ALPHANUMS :
				  if (bittab[j].format == LLLVAR)
  				{
					//print_hex("len value",bptr,2);
	  				len = ( int)bcd_long(bptr, 2);
		  			bptr += 2;
			  	}
				  else
				  if (bittab[j].format == LLVAR)
				  {
					  len = ( int)bcd_long(bptr, 1);
					  ++bptr;
				  }
				  else
				  {
				  	len = bittab[j].max;
				  }
				 //printf("ALPHANUM_ len=%d\n",len);
				  bptr += len;
				  break;
				  
			  case BITS :
				  bptr += 8;
				  break;
		  }
		//print_hex("bitp[i]",bitp[i],len);
	  }else bitp[i] = NULL;
  }
  return(bptr);
}

int pack(char *dst)
{
	 int i,j;
	 int len;
	char temp[512+1];
	
	//bptr=0;
	bptrlen=0;
	//temp=(char *)bptr;
	memset(temp,0,sizeof(temp));
	
#ifdef PACK_DEBUG
	printf("Pack Field(s) ");
#endif
	
	for (i=1; i<65; i++)
	{
		if (bittest(bitmap, i))
		{
	  		for (j=0; bittab[j].bitn != 255; j++)
			{
	  			if (bittab[j].bitn == i)
	  				break;
			}
	  	    
			if (bittab[j].bitn == 255)
				return(0);//return(NULL);
			
#ifdef PACK_DEBUG
	printf("%d ",i);
#endif
			
			switch(bittab[j].attrib)
			{
				case NUMERIC_ :
					if( bittab[j].format == LLLVAR )
					{
						len = ( int)bcd_long(bitp[i], 2);
						len+=2;
					}
					else if( bittab[j].format == LLVAR )
					{
						len = ( int)bcd_long(bitp[i], 1);
						len+=1;
					}
					else
					{
						len=( int)bittab[j].max;
					}

					len=(len+1)/2;
					memcpy(temp+bptrlen,bitp[i],len);
					//print_hex("NUMERIC_",(char *)temp+bptrlen,len);
					bptrlen+=len;
					//if( bitn == 2 && (len % 2)) /*TO DO*/
					//	*(bptr-1) |= 0x0f;
					//bptrlen+=(len+1)/2;
				break;

				case TRACKX :
					len = ( int)bcd_long(bitp[i], 1);
					len=(len+1)/2;
					len+=1;
					memcpy(temp+bptrlen,bitp[i],len);
					bptrlen+=len;
				break;

				case ALPHANUM_ :
				case ALPHANUMS :
					//printf("ALPHANUM_(S)\n");
					if (bittab[j].format == LLLVAR)
					{
						len = ( int)bcd_long(bitp[i], 2);
						len+=2;
						//bintobcd(len, bptr, 4);
						//bptr += 2;
					}
					else if (bittab[j].format == LLVAR)
					{
						len = ( int)bcd_long(bitp[i], 1);
						len+=1;
						//bintobcd(len, bptr, 2);
						//++bptr;
					}
					else
					{
						len=bittab[j].max;
					}

					//len=(len+1)/2;
					memcpy(temp+bptrlen,bitp[i],len);
					//print_hex("ALPHANUM_(S)",(char *)temp+bptrlen,len);
					bptrlen+=len;
					
					//bptr+bptrlen;
					
				break;

				case BITS :
					printf("BITS\n");
					//memcpy(bptr, bitp[i], 8);
					len=8;
					memcpy(temp+bptrlen,bitp[i],len);
					//bptr=bptr+bptrlen;
					//bptr=bitp[i];
					bptrlen+=8;
				break;
			}
		}
	}

#ifdef PACK_DEBUG
		printf("\n");
#endif
	
	memcpy(dst,temp,bptrlen);
	//print_hex("bptr1",(char *)temp,bptrlen);
	return bptrlen;
}

int insert_field( char *src,  char bitnum,  char *buf, char *dst/*,  int len*/)
{	
	char *ptr;
	char temp[512+1];
	int insert_field_len=0,index=0;
	char tpdu[8+1];
	char msg_id[2+1];

	memset(temp,0,sizeof(temp));
	memset(tpdu,0,sizeof(tpdu));
	memset(msg_id,0,sizeof(msg_id));
	memset(&bitp,0,sizeof(bitp));
	//memset(bitmap,0,8);

	memcpy(tpdu,src,5); 
	memcpy(msg_id,src+5,2);
	
	Unpack(src+5);

	//print_hex("bitmap",bitmap,8);
	
	bitset(bitmap, bitnum);
	bitp[bitnum]=buf;

#ifdef PACK_DEBUG
	//print_hex("tpdu, msg_id, and bitmap",temp,index);
#endif

    index=0;
	memcpy(temp+index,tpdu,5); index+=5;
	memcpy(temp+index,msg_id,2); index+=2;
	memcpy(temp+index,bitmap,8); index+=8;

	insert_field_len=pack(&temp[index]); 
	insert_field_len+=index;

	memcpy(dst,temp,insert_field_len);

	return insert_field_len;
}

int delete_field( char *src,  char bitnum,  char *dst/*,  int len*/)
{	
	char *ptr;
	char temp[512+1];
	int insert_field_len=0,index=0;
	char tpdu[8+1];
	char msg_id[2+1];

	memset(temp,0,sizeof(temp));
	memset(tpdu,0,sizeof(tpdu));
	memset(msg_id,0,sizeof(msg_id));
	memset(&bitp,0,sizeof(bitp));
	
	memcpy(tpdu,src,5); 
	memcpy(msg_id,src+5,2);

	Unpack(src+5);

	bitreset(bitmap, bitnum);
	//bitset(bitmap, bitnum);
	//bitp[bitnum]=buf;

	index=0;
	memcpy(temp+index,tpdu,5); index+=5;
	memcpy(temp+index,msg_id,2); index+=2;
	memcpy(temp+index,bitmap,8); index+=8;

	insert_field_len=pack(&temp[index]); 
	insert_field_len+=index;

	memcpy(dst,temp,insert_field_len+insert_field_len);

	return insert_field_len;
}

char *UnpackDCC(char *ptrBitmap, char *ptrBuf)
{
    char i, j, szLen[3+1];
    int len;
    
    bitmap = ptrBitmap;
    bptr = ptrBuf;

    for (i=1; i<32; i++)
    {
        if (bittest(bitmap, i))
        {
			if(i == 17)
				bitset(bitmap, 25);
			
			memset(szLen, 0x00, sizeof(szLen));
            //printf("unpack field %d\n",i);
            for (j=0; bittabDCC[j].bitn != 255; j++)
                if (bittabDCC[j].bitn == i) 
                    break;
            
            if (bittabDCC[j].bitn == 255)
                 return(NULL);

            bitp[i] = bptr;
            switch(bittabDCC[j].attrib)
            {
                case ALPHANUMS :
                    if(bittabDCC[j].format == BYTE_2_LEN)
                    {
                        //print_hex("len value",bptr,2);
						memcpy(szLen, bptr, 2); 
						len=atoi(szLen);
                        bptr += 2;
                    }
                    else
                    {
                        len = bittabDCC[j].max;
                    }
                    //printf("ALPHANUM_ len=%d\n",len);
                    //vdDebug_LogPrintf("ALPHANUMS j:%d", j);
					//vdDebug_LogPrintf("bptr:%s", bptr);
					memcpy(bitDCC[i], bptr, len);
                    bptr += len;
					inDCCLen[i]=len;
					//bitp[i][len]=0x00;
                break;

				case NUMERIC_:
                    if(bittabDCC[j].format == BYTE_2_LEN)
                    {
                        //print_hex("len value",bptr,2);
						memcpy(szLen, bptr, 2); 
						len=atoi(szLen);
                        bptr += 2;
                    }
                    else
                    {
                        len = bittabDCC[j].max;
                    }
                    //printf("ALPHANUM_ len=%d\n",len);
                    //vdDebug_LogPrintf("NUMERIC_ j:%d", j);
					//vdDebug_LogPrintf("bptr:%s", bptr);
                    memcpy(bitDCC[i], bptr, len);
                    bptr += len;
					inDCCLen[i]=len;
					//bitp[i][len]=0x00;
                break;
            }
            //print_hex("bitp[i]",bitp[i],len);
        }
        else 
            bitDCC[i][0] = NULL;
    }
  return(bptr);
}

unsigned long bcd_to_long(unsigned char *src, unsigned int len)
{
	unsigned int in_index;
	unsigned char temp[50+1];

	memset(temp,0x00,sizeof(temp));

	for(in_index=0; in_index<len; in_index++)
	{
		temp[in_index]=((*src >> 4) & 0x0f) + 0x30;
#ifdef TEST_DEBUG
		printf("%c ",temp[in_index]);
#endif
		in_index++;
		temp[in_index]= (*src & 0x0f) + 0x30;
#ifdef TEST_DEBUG
		printf("%c \n",temp[in_index]);
#endif
		src++;
	}
	//memcpy(des,temp,len);
	return atol((const char *)temp);
}


void vdPrintParseISO(BYTE byTransType, unsigned char *pucTitle,unsigned char *buf)
{
	unsigned char i, j;
	unsigned int len;
    unsigned char szDE[12+1];
	unsigned char szDEData[256+1];
	int inDumpLen=0;
	int inAddLen=0;

	//char *bptr;
	//char *bitmap;
	//char *bitp[65];
	char szStr[44 + 4];
	BYTE baTemp[PAPER_X_SIZE * 64];   
	CTOS_FONT_ATTRIB stFONT_ATTRIB;
	BYTE szTitle[16+1];
	
	bitmap = buf+2;
	bptr = buf+10;

	szGetTransTitle(byTransType, szTitle);

	vdCTOSS_PrinterStart(100);
	CTOS_PrinterSetHeatLevel(strTCT.inPrinterHeatLevel); 

	CTOS_PrinterSetWorkTime(50000,1000);
    inCTOS_SelectFont(d_FONT_FNT_MODE,d_FONT_16x16,0," ");
	vdSetGolbFontAttrib(d_FONT_16x16, NORMAL_SIZE, DOUBLE_SIZE, 0, 0);

	//vdDebug_LogPrintf("REINER :: pucTitle[%s] :: szTitle[%s]",pucTitle,szTitle);
	sprintf(szStr,"[%s: %s] \n", szTitle, pucTitle);
    //CTOS_PrinterBufferPutString((BYTE *)baTemp, 1, 1, szStr, &stgFONT_ATTRIB);
    //CTOS_PrinterBufferOutput((BYTE *)baTemp, 3);
	//inCCTOS_PrinterBufferOutput(szStr,&stgFONT_ATTRIB,1);
	
	//CTOS_PrinterFline(d_LINE_DOT); 
	inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
	
	//vdMyEZLib_Printf2(szStr);
	inPrint(szStr);

    vdMyEZLib_HexDump("MSG ID:", buf, 2);

    vdMyEZLib_HexDump("BITMAP:", bitmap, 8);

	//CTOS_PrinterFline(d_LINE_DOT); 
	inCCTOS_PrinterBufferOutput(ONE_LINE_DOT,&stgFONT_ATTRIB,1);
	
	//vdCTOS_PrinterFline(1);
	
    for (i=1; i<65; i++)
    {

        if (bittest(bitmap, i))
        {
            for (j=0; bittab[j].bitn != 255; j++)
                if (bittab[j].bitn == i)
                    break;
            
            if (bittab[j].bitn == 255)
            {
                return(NULL);
            }
            
            bitp[i] = bptr;
			memset(szDE, 0, sizeof(szDE));
			//sprintf(szDE, "DE: %03d", i);
			sprintf(szDE, "%02d:", i);
			memset(szDEData, 0x00, sizeof(szDEData));
			inAddLen=0;
            switch(bittab[j].attrib)
            {
                case NUMERIC_:
                    if (bittab[j].format == LLLVAR)
                    {
                        len = (unsigned int)bcd_to_long(bptr, 4);
                        bptr += 2;
						inAddLen=2;
                    }
                    else if (bittab[j].format == LLVAR)
                    {
                        len = (unsigned int)bcd_to_long(bptr, 2);
                        ++bptr;
						inAddLen=1;
                    }
                    else
                        len = bittab[j].max;
                     bptr += (len+1)/2;
					vdMyEZLib_HexDump(szDE, bitp[i], ((len+1)/2)+inAddLen);
                break;
                
                case TRACKX :
                    len = (unsigned int)bcd_to_long(bptr, 2);
                    ++bptr;
                    bptr += (len+1)/2;
					inAddLen=1;
					vdMyEZLib_HexDump(szDE, bitp[i], ((len+1)/2)+inAddLen);	
                break;
                
                case ALPHANUM_:
                case ALPHANUMS:
                    if (bittab[j].format == LLLVAR)
                    {
                        len = (unsigned int)bcd_to_long(bptr, 4);
                        printf("len=%d\n",len);
                        bptr += 2;
						inAddLen=2;
                    }
                    else if (bittab[j].format == LLVAR)
                    {
                        len = (unsigned int)bcd_to_long(bptr, 2);
                        ++bptr;
						inAddLen=1;
                    }
                    else
                        len = bittab[j].max;
                    bptr += len;	
                    vdMyEZLib_HexDump(szDE, bitp[i], len+inAddLen);
                break;
                
                case BITS :
                    bptr += 8;
					vdMyEZLib_HexDump(szDE, bitp[i], 8);
                break;
            }
        }
    }

	//CTOS_PrinterFline(d_LINE_DOT*2); 
	vdCTOS_PrinterFline(2);
	vdCTOSS_PrinterEnd(); 
}


