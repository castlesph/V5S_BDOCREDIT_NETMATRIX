
#ifndef _BDOLOYALTY_H
#define	_BDOLOYALTY_H

#ifdef	__cplusplus
extern "C" {
#endif

//#define REQUEST_ACCESS_TOKEN 	0
//#define REDEMPTION 				1
//#define POINTS_INQUIRY 			2
//#define REVERSAL 				3

#define szContentTypeJSON	  	"application/json"
#define szContentTypeFORM	  	"application/x-www-form-urlencoded"

#define szCacheControl  		"no-cache"
#define szConnection  			"keep-alive"
#define szAccept  				"*/*"

#define CURL_OK					0
#define CURL_ERROR				1
#define CURL_RETRY				2

int inCTOS_LOYALTY(void);
int inCTOS_LoyaltyFlowProcess(void);

int inCTOS_POINSTINQ(void);
int inCTOS_PointsInqFlowProcess(void);

int inCreateBody(char *szBuffer, int inType);
int inRequestAccessToken(void);

char *b64_encode(const unsigned char *in, size_t len);
int inCurl_CommsInit(void);
int inGetCAFileSize(const char *szFileName);
int inExtractField(unsigned char *uszRecData, char *szField, char *szSearchString);
int InDisplayLoyaltyBalance(void);
int inExtractFieldEx(unsigned char *uszRecData, char *szField, char *szSearchString);



#ifdef	__cplusplus
}
#endif

#endif

