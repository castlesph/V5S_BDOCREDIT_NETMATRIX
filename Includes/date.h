#ifndef DATE_H
#define DATE_H
typedef struct my_Date{
	int year;
	int month;
	int day;
}myDate;

#include <ctosapi.h>
#ifdef __cplusplus
extern "C" {
#endif

//计算日期date1与日期date2的间隔天数
int getDateToBase(myDate *date1,myDate *date2);   

//计算日期baseDate d 天后（前）的日期
myDate getNewDate(myDate *baseDate, int d);  

//判断年份合法性
int isLegal(int y, int m, int d);
int isLeapyear(int y);

int inIsBeforeOperationEndTime(CTOS_RTC rtc, const char *szOperationEndTime);
void vdGetBusinessDate(CTOS_RTC rtc, const char *szOperationEndTime, char *pszBusinessDate);

#if defined(__cplusplus)
}
#endif

#endif