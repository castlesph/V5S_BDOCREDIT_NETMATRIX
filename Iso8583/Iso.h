extern long bcd_long(char *bcd, int len);
extern void long_bcd( char *buf,  long val, int len);
extern char bittest( char *bitmap,  char pbitno);
extern void bitset( char *bmap,  char bitnum);
extern void bitreset( char *bmap,  char bitnum);
extern char *Unpack( char *buf);
extern int pack(char *dst);
extern int insert_field( char *src,  char bitnum,  char *buf, char *dst);
extern int delete_field( char *src,  char bitnum,  char *dst/*,  int len*/);

char *UnpackDCC(char *ptrBitmap, char *ptrBuf);
void vdPrintParseISO(BYTE byTransType, unsigned char *pucTitle,unsigned char *buf);

#define FIELD_01		1
#define FIELD_02		2
#define FIELD_03		3
#define FIELD_04		4
#define FIELD_05		5
#define FIELD_06		6
#define FIELD_07		7
#define FIELD_08		8
#define FIELD_09		9
#define FIELD_10		10
#define FIELD_11		11
#define FIELD_12		12
#define FIELD_13		13
#define FIELD_14		14
#define FIELD_15		15
#define FIELD_16		16
#define FIELD_17		17
#define FIELD_18		18
#define FIELD_19		19
#define FIELD_20		20
#define FIELD_21		21
#define FIELD_22		22
#define FIELD_23		23
#define FIELD_24		24
#define FIELD_25		25
#define FIELD_26		26
#define FIELD_27		27
#define FIELD_28		28
#define FIELD_29		29
#define FIELD_30		30
#define FIELD_31		31
#define FIELD_32		32
#define FIELD_33		33
#define FIELD_34		34
#define FIELD_35		35
#define FIELD_36		36
#define FIELD_37		37
#define FIELD_38		38
#define FIELD_39		39
#define FIELD_40		40
#define FIELD_41		41
#define FIELD_42		42
#define FIELD_43		43
#define FIELD_44		44
#define FIELD_45		45
#define FIELD_46		46
#define FIELD_47		47
#define FIELD_48		48
#define FIELD_49		49
#define FIELD_50		50
#define FIELD_51		51
#define FIELD_52		52
#define FIELD_53		53
#define FIELD_54		54
#define FIELD_55		55
#define FIELD_56		56
#define FIELD_57		57
#define FIELD_58		58
#define FIELD_59		59
#define FIELD_60		60
#define FIELD_61		61
#define FIELD_62		62
#define FIELD_63		63
#define FIELD_64		64
