#ifdef WIN32
#include <windows.h>
void usleep(__int64 usec) 
{ 
    HANDLE timer; 
    LARGE_INTEGER ft; 

    ft.QuadPart = -(10*usec); // Convert to 100 nanosecond interval, negative value indicates relative time

    timer = CreateWaitableTimer(NULL, TRUE, NULL); 
    SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0); 
    WaitForSingleObject(timer, INFINITE); 
    CloseHandle(timer); 
}

#ifdef _MSC_VER
int gettimeofday(struct timeval* tp, struct timezone* tzp)
{
    // Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
    // This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
    // until 00:00:00 January 1, 1970 
    static const ULONGLONG EPOCH = ((ULONGLONG)116444736000000000ULL);

    SYSTEMTIME  system_time;
    FILETIME    file_time;
    ULONGLONG   t;

    GetSystemTime(&system_time);
    SystemTimeToFileTime(&system_time, &file_time);
    t = (ULONGLONG)file_time.dwHighDateTime;
    t <<= 32;
    t += (ULONGLONG)(file_time.dwLowDateTime);

    tp->tv_sec = (long)((t - EPOCH) / 10000000L);
    tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
    return 0;
}

#include <time.h>

#define _SEC_IN_MINUTE 60L
#define _SEC_IN_HOUR 3600L
#define _SEC_IN_DAY 86400L

static const int DAYS_IN_MONTH[12] =
{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

#define _DAYS_IN_MONTH(x) ((x == 1) ? days_in_feb : DAYS_IN_MONTH[x])

static const int _DAYS_BEFORE_MONTH[12] =
{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};

#define _ISLEAP(y) (((y) % 4) == 0 && (((y) % 100) != 0 || (((y)+1900) % 400) == 0))
#define _DAYS_IN_YEAR(year) (_ISLEAP(year) ? 366 : 365)

static void validate_structure(struct tm *tim_p)
{
  div_t res;
  int days_in_feb = 28;

  /* calculate time & date to account for out of range values */
  if (tim_p->tm_sec < 0 || tim_p->tm_sec > 59)
    {
      res = div (tim_p->tm_sec, 60);
      tim_p->tm_min += res.quot;
      if ((tim_p->tm_sec = res.rem) < 0)
        {
          tim_p->tm_sec += 60;
          --tim_p->tm_min;
        }
    }

  if (tim_p->tm_min < 0 || tim_p->tm_min > 59)
    {
      res = div (tim_p->tm_min, 60);
      tim_p->tm_hour += res.quot;
      if ((tim_p->tm_min = res.rem) < 0)
        {
          tim_p->tm_min += 60;
          --tim_p->tm_hour;
        }
    }

  if (tim_p->tm_hour < 0 || tim_p->tm_hour > 23)
    {
      res = div (tim_p->tm_hour, 24);
      tim_p->tm_mday += res.quot;
      if ((tim_p->tm_hour = res.rem) < 0)
        {
          tim_p->tm_hour += 24;
          --tim_p->tm_mday;
        }
    }

  if (tim_p->tm_mon > 11)
    {
      res = div (tim_p->tm_mon, 12);
      tim_p->tm_year += res.quot;
      if ((tim_p->tm_mon = res.rem) < 0)
        {
          tim_p->tm_mon += 12;
          --tim_p->tm_year;
        }
    }

  if (_DAYS_IN_YEAR (tim_p->tm_year) == 366)
    days_in_feb = 29;

  if (tim_p->tm_mday <= 0)
    {
      while (tim_p->tm_mday <= 0)
        {
          if (--tim_p->tm_mon == -1)
            {
              tim_p->tm_year--;
              tim_p->tm_mon = 11;
              days_in_feb =
                ((_DAYS_IN_YEAR (tim_p->tm_year) == 366) ?
                 29 : 28);
            }
          tim_p->tm_mday += _DAYS_IN_MONTH (tim_p->tm_mon);
        }
    }
  else
    {
      while (tim_p->tm_mday > _DAYS_IN_MONTH (tim_p->tm_mon))
        {
          tim_p->tm_mday -= _DAYS_IN_MONTH (tim_p->tm_mon);
          if (++tim_p->tm_mon == 12)
            {
              tim_p->tm_year++;
              tim_p->tm_mon = 0;
              days_in_feb =
                ((_DAYS_IN_YEAR (tim_p->tm_year) == 366) ?
                 29 : 28);
            }
        }
    }
}

time_t mkgmtime(struct tm *tim_p)
{
  time_t tim = 0;
  long days = 0;
  int year, isdst, tm_isdst;

  /* validate structure */
  validate_structure (tim_p);

  /* compute hours, minutes, seconds */
  tim += tim_p->tm_sec + (tim_p->tm_min * _SEC_IN_MINUTE) +
    (tim_p->tm_hour * _SEC_IN_HOUR);

  /* compute days in year */
  days += tim_p->tm_mday - 1;
  days += _DAYS_BEFORE_MONTH[tim_p->tm_mon];
  if (tim_p->tm_mon > 1 && _DAYS_IN_YEAR (tim_p->tm_year) == 366)
    days++;

  /* compute day of the year */
  tim_p->tm_yday = days;

  if (tim_p->tm_year > 10000
      || tim_p->tm_year < -10000)
    {
      return (time_t) -1;
    }

  /* compute days in other years */
  if (tim_p->tm_year > 70)
    {
      for (year = 70; year < tim_p->tm_year; year++)
        days += _DAYS_IN_YEAR (year);
    }
  else if (tim_p->tm_year < 70)
    {
      for (year = 69; year > tim_p->tm_year; year--)
        days -= _DAYS_IN_YEAR (year);
      days -= _DAYS_IN_YEAR (year);
    }

  /* compute day of the week */
  if ((tim_p->tm_wday = (days + 4) % 7) < 0)
    tim_p->tm_wday += 7;

  /* compute total seconds */
  tim += (days * _SEC_IN_DAY);

  /* Convert user positive into 1 */
  tm_isdst = tim_p->tm_isdst > 0  ?  1 : tim_p->tm_isdst;
  isdst = tm_isdst;

  //screw this!

 // if (_daylight)
 //   {
 //     int y = tim_p->tm_year + YEAR_BASE;
 //     if (y == tz->__tzyear || __tzcalc_limits (y))
        //{
        //  /* calculate start of dst in dst local time and 
        //     start of std in both std local time and dst local time */
 //         time_t startdst_dst = tz->__tzrule[0].change
        //    - (time_t) tz->__tzrule[1].offset;
        //  time_t startstd_dst = tz->__tzrule[1].change
        //    - (time_t) tz->__tzrule[1].offset;
        //  time_t startstd_std = tz->__tzrule[1].change
        //    - (time_t) tz->__tzrule[0].offset;
        //  /* if the time is in the overlap between dst and std local times */
        //  if (tim >= startstd_std && tim < startstd_dst)
        //    ; /* we let user decide or leave as -1 */
 //         else
        //    {
        //      isdst = (tz->__tznorth
        //               ? (tim >= startdst_dst && tim < startstd_std)
        //               : (tim >= startdst_dst || tim < startstd_std));
 //              /* if user committed and was wrong, perform correction, but not
 //               * if the user has given a negative value (which
 //               * asks mktime() to determine if DST is in effect or not) */
 //              if (tm_isdst >= 0  &&  (isdst ^ tm_isdst) == 1)
        //        {
        //          /* we either subtract or add the difference between
        //             time zone offsets, depending on which way the user got it
        //             wrong. The diff is typically one hour, or 3600 seconds,
        //             and should fit in a 16-bit int, even though offset
        //             is a long to accomodate 12 hours. */
        //          int diff = (int) (tz->__tzrule[0].offset
        //                            - tz->__tzrule[1].offset);
        //          if (!isdst)
        //            diff = -diff;
        //          tim_p->tm_sec += diff;
        //          validate_structure (tim_p);
        //          tim += diff;  /* we also need to correct our current time calculation */
        //        }
        //    }
        //}
 //   }

  //screw this also 
  /* add appropriate offset to put time in gmt format */
  //if (isdst == 1)
  //  tim += (time_t) tz->__tzrule[1].offset;
  //else /* otherwise assume std time */
  //  tim += (time_t) tz->__tzrule[0].offset;

  //and screw this too
  /* reset isdst flag to what we have calculated */
  tim_p->tm_isdst = isdst;

  return tim;
}

void timeradd(const struct timeval* tvp, const struct timeval* uvp, struct timeval* vvp)
{
    (vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;
    (vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;
    while ((vvp)->tv_usec >= 1000000) {
        (vvp)->tv_sec++;
        (vvp)->tv_usec -= 1000000;          \
    }
}

void timersub(const struct timeval* tvp, const struct timeval* uvp, struct timeval* vvp)
{
    (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;
    (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;
    while ((vvp)->tv_usec < 0) {
        (vvp)->tv_sec--;
        (vvp)->tv_usec += 1000000;
    }
}

#endif // _MSC_VER
	

#endif