// ===========================================================================
// Purpose:     wxDateTime and other time related classes and functions
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

#include "wx/utils.h"
#include "wx/timer.h"

wxString wxNow();
long wxGetLocalTime();
long wxGetUTCTime();
wxLongLong wxGetLocalTimeMillis();
%wxcompat_2_6 void wxStartTimer();                           // deprecated in 2.8 use wxStopWatch
%wxcompat_2_6 long wxGetElapsedTime(bool resetTimer = true); // deprecated in 2.8 use wxStopWatch
void wxSleep(int secs);
%wxchkver_2_6 void wxMilliSleep(unsigned long milliseconds);
%wxchkver_2_6 void wxMicroSleep(unsigned long microseconds);
!%wxchkver_2_6 void wxUsleep(unsigned long milliseconds);

// ---------------------------------------------------------------------------
// wxDateTime

#if wxLUA_USE_wxDateTime && wxUSE_DATETIME

#include "wx/datetime.h"

enum wxDateTime::TZ
{
    Local,
    GMT_12,
    GMT_11,
    GMT_10,
    GMT_9,
    GMT_8,
    GMT_7,
    GMT_6,
    GMT_5,
    GMT_4,
    GMT_3,
    GMT_2,
    GMT_1,
    GMT0,
    GMT1,
    GMT2,
    GMT3,
    GMT4,
    GMT5,
    GMT6,
    GMT7,
    GMT8,
    GMT9,
    GMT10,
    GMT11,
    GMT12,
    %wxchkver_2_8 GMT13,
    WET,
    WEST,
    CET,
    CEST,
    EET,
    EEST,
    MSK,
    MSD,
    AST,
    ADT,
    EST,
    EDT,
    CST,
    CDT,
    MST,
    MDT,
    PST,
    PDT,
    HST,
    AKST,
    AKDT,
    A_WST,
    A_CST,
    A_EST,
    A_ESST,
    %wxchkver_2_8 NZST,
    %wxchkver_2_8 NZDT,
    UTC
};

enum wxDateTime::Calendar
{
    Gregorian,
    Julian
};

enum wxDateTime::Country
{
    Country_Unknown,
    Country_Default,
    Country_WesternEurope_Start,
    Country_EEC,
    France,
    Germany,
    UK,
    Country_WesternEurope_End,
    Russia,
    USA
};

enum wxDateTime::Month
{
    Jan,
    Feb,
    Mar,
    Apr,
    May,
    Jun,
    Jul,
    Aug,
    Sep,
    Oct,
    Nov,
    Dec,
    Inv_Month
};

enum wxDateTime::WeekDay
{
    Sun,
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Inv_WeekDay
};

enum wxDateTime::Year
{
    Inv_Year
};

enum wxDateTime::NameFlags
{
    Name_Full,
    Name_Abbr
};

enum wxDateTime::WeekFlags
{
    Default_First,
    Monday_First,
    Sunday_First
};

class %delete wxDateTime::TimeZone
{
    wxDateTime::TimeZone(wxDateTime::TZ tz);

    static wxDateTime::TimeZone Make(long offset);
    long GetOffset() const;
};


typedef unsigned short wxDateTime::wxDateTime_t

class %delete wxDateTime
{
    #define_object wxDefaultDateTime

    static void SetCountry(wxDateTime::Country country);
    static wxDateTime::Country GetCountry();
    static bool IsWestEuropeanCountry(wxDateTime::Country country = wxDateTime::Country_Default);

    static int GetCurrentYear(wxDateTime::Calendar cal = wxDateTime::Gregorian);
    static int ConvertYearToBC(int year);
    static wxDateTime::Month GetCurrentMonth(wxDateTime::Calendar cal = wxDateTime::Gregorian);
    static bool IsLeapYear(int year = wxDateTime::Inv_Year, wxDateTime::Calendar cal = wxDateTime::Gregorian);
    static int GetCentury(int year);
    static wxDateTime::wxDateTime_t GetNumberOfDays(int year, wxDateTime::Calendar cal = wxDateTime::Gregorian);
    static wxDateTime::wxDateTime_t GetNumberOfDays(wxDateTime::Month month, int year = wxDateTime::Inv_Year, wxDateTime::Calendar cal = wxDateTime::Gregorian);
    static wxString GetMonthName(wxDateTime::Month month, wxDateTime::NameFlags flags = wxDateTime::Name_Full);
    static wxString GetWeekDayName(wxDateTime::WeekDay weekday, wxDateTime::NameFlags flags = wxDateTime::Name_Full);
    //static void GetAmPmStrings(wxString *am, wxString *pm);
    static bool IsDSTApplicable(int year = wxDateTime::Inv_Year, wxDateTime::Country country = wxDateTime::Country_Default);
    static wxDateTime GetBeginDST(int year = wxDateTime::Inv_Year, wxDateTime::Country country = wxDateTime::Country_Default);
    static wxDateTime GetEndDST(int year = wxDateTime::Inv_Year, wxDateTime::Country country = wxDateTime::Country_Default);
    static wxDateTime Now();
    static wxDateTime UNow();
    static wxDateTime Today();


    wxDateTime();
    wxDateTime(const wxDateTime& dateTime);
    wxDateTime(time_t dateTime); // use with Lua's os.time() on MSW, Linux, others?
    %rename wxDateTimeFromJDN wxDateTime(double dateTime);
    %rename wxDateTimeFromHMS wxDateTime(int hour, int minute, int second, int millisec);
    %rename wxDateTimeFromDMY wxDateTime(int day, wxDateTime::Month month = wxDateTime::Inv_Month, int year = wxDateTime::Inv_Year, int hour = 0, int minute = 0, int second = 0, int millisec = 0);

    wxDateTime& SetToCurrent();
    wxDateTime& Set(time_t time); // use with Lua's os.time() on MSW, Linux, others?
    %rename SetToJDN wxDateTime& Set(double dateTime);
    %rename SetToHMS wxDateTime& Set(int hour, int minute, int second, int millisec);
    %rename SetToDMY wxDateTime& Set(int day, wxDateTime::Month month = wxDateTime::Inv_Month, int year = wxDateTime::Inv_Year, int hour = 0, int minute = 0, int second = 0, int millisec = 0);
    wxDateTime& ResetTime();
    wxDateTime GetDateOnly() const;
    wxDateTime& SetYear(int year);
    wxDateTime& SetMonth(wxDateTime::Month month);
    wxDateTime& SetDay(int day);
    wxDateTime& SetHour(int hour);
    wxDateTime& SetMinute(int minute);
    wxDateTime& SetSecond(int second);
    wxDateTime& SetMillisecond(int millisecond);

    bool IsWorkDay(wxDateTime::Country country = wxDateTime::Country_Default) const;
    bool IsEqualTo(const wxDateTime& datetime) const;
    bool IsEarlierThan(const wxDateTime& datetime) const;
    bool IsLaterThan(const wxDateTime& datetime) const;
    bool IsStrictlyBetween(const wxDateTime& t1, const wxDateTime& t2) const;
    bool IsBetween(const wxDateTime& t1, const wxDateTime& t2) const;
    bool IsSameDate(const wxDateTime& dt) const;
    bool IsSameTime(const wxDateTime& dt) const;
    bool IsEqualUpTo(const wxDateTime& dt, const wxTimeSpan& ts) const;
    bool IsValid();
    long GetTicks();

    wxDateTime& SetToWeekDayInSameWeek(wxDateTime::WeekDay weekday);
    wxDateTime  GetWeekDayInSameWeek(wxDateTime::WeekDay weekday) const;
    wxDateTime& SetToNextWeekDay(wxDateTime::WeekDay weekday);
    wxDateTime GetNextWeekDay(wxDateTime::WeekDay weekday) const;
    wxDateTime& SetToPrevWeekDay(wxDateTime::WeekDay weekday);
    wxDateTime GetPrevWeekDay(wxDateTime::WeekDay weekday) const;
    bool SetToWeekDay(wxDateTime::WeekDay weekday, int n = 1, wxDateTime::Month month = wxDateTime::Inv_Month, int year = wxDateTime::Inv_Year);
    wxDateTime GetWeekDay(wxDateTime::WeekDay weekday, int n = 1, wxDateTime::Month month = wxDateTime::Inv_Month, int year = wxDateTime::Inv_Year) const;
    bool SetToLastWeekDay(wxDateTime::WeekDay weekday, wxDateTime::Month month = wxDateTime::Inv_Month, int year = wxDateTime::Inv_Year);
    wxDateTime GetLastWeekDay(wxDateTime::WeekDay weekday, wxDateTime::Month month = wxDateTime::Inv_Month, int year = wxDateTime::Inv_Year);

    !%wxchkver_2_6 bool SetToTheWeek(wxDateTime::wxDateTime_t numWeek, wxDateTime::WeekDay weekday = wxDateTime::Mon);
    !%wxchkver_2_6 wxDateTime GetWeek(wxDateTime::wxDateTime_t numWeek, wxDateTime::WeekDay weekday = wxDateTime::Mon) const;

    %wxchkver_2_6 static wxDateTime SetToWeekOfYear(int year, wxDateTime::wxDateTime_t numWeek, wxDateTime::WeekDay weekday = wxDateTime::Mon);
    wxDateTime& SetToLastMonthDay(wxDateTime::Month month = wxDateTime::Inv_Month, int year = wxDateTime::Inv_Year);
    wxDateTime GetLastMonthDay(wxDateTime::Month month = wxDateTime::Inv_Month, int year = wxDateTime::Inv_Year) const;
    wxDateTime& SetToYearDay(wxDateTime::wxDateTime_t yday);
    wxDateTime GetYearDay(wxDateTime::wxDateTime_t yday) const;
    double GetJulianDayNumber() const;
    double GetJDN() const;
    double GetModifiedJulianDayNumber() const;
    double GetMJD() const;
    double GetRataDie() const;

    wxDateTime ToTimezone(const wxDateTime::TimeZone& tz, bool noDST = false) const;
    wxDateTime& MakeTimezone(const wxDateTime::TimeZone& tz, bool noDST = false);
    wxDateTime FromTimezone(const wxDateTime::TimeZone& tz, bool noDST = false) const;
    wxDateTime& MakeFromTimezone(const wxDateTime::TimeZone& tz, bool noDST = false);

    wxDateTime ToUTC(bool noDST = false) const;
    wxDateTime& MakeUTC(bool noDST = false);
    wxDateTime ToGMT(bool noDST = false) const;
    wxDateTime& MakeGMT(bool noDST = false);
    wxDateTime FromUTC(bool noDST = false) const;
    wxDateTime& MakeFromUTC(bool noDST = false);
    int IsDST(wxDateTime::Country country = wxDateTime::Country_Default) const;

    bool IsValid() const;
    //Tm GetTm(const wxDateTime::TimeZone& tz = wxDateTime::Local) const;
    time_t GetTicks() const;
    int GetCentury(const wxDateTime::TimeZone& tz = wxLua_wxDateTime_TimeZone_Local) const;
    int GetYear(const wxDateTime::TimeZone& tz = wxLua_wxDateTime_TimeZone_Local) const;
    wxDateTime::Month GetMonth(const wxDateTime::TimeZone& tz = wxLua_wxDateTime_TimeZone_Local) const;
    wxDateTime::wxDateTime_t GetDay(const wxDateTime::TimeZone& tz = wxLua_wxDateTime_TimeZone_Local) const;
    wxDateTime::WeekDay GetWeekDay(const wxDateTime::TimeZone& tz = wxLua_wxDateTime_TimeZone_Local) const;
    wxDateTime::wxDateTime_t GetHour(const wxDateTime::TimeZone& tz = wxLua_wxDateTime_TimeZone_Local) const;
    wxDateTime::wxDateTime_t GetMinute(const wxDateTime::TimeZone& tz = wxLua_wxDateTime_TimeZone_Local) const;
    wxDateTime::wxDateTime_t GetSecond(const wxDateTime::TimeZone& tz = wxLua_wxDateTime_TimeZone_Local) const;
    wxDateTime::wxDateTime_t GetMillisecond(const wxDateTime::TimeZone& tz = wxLua_wxDateTime_TimeZone_Local) const;

    wxDateTime::wxDateTime_t GetDayOfYear(const wxDateTime::TimeZone& tz = wxLua_wxDateTime_TimeZone_Local) const;
    wxDateTime::wxDateTime_t GetWeekOfYear(wxDateTime::WeekFlags flags = wxDateTime::Monday_First, const wxDateTime::TimeZone& tz = wxLua_wxDateTime_TimeZone_Local) const;
    wxDateTime::wxDateTime_t GetWeekOfMonth(wxDateTime::WeekFlags flags = wxDateTime::Monday_First, const wxDateTime::TimeZone& tz = wxLua_wxDateTime_TimeZone_Local) const;
    bool IsWorkDay(wxDateTime::Country country = wxDateTime::Country_Default) const;
    //bool IsGregorianDate(GregorianAdoption country = Gr_Standard) const;

    wxDateTime& SetFromDOS(unsigned long ddt);
    unsigned long GetAsDOS() const;

    bool IsEqualTo(const wxDateTime& datetime) const;
    bool IsEarlierThan(const wxDateTime& datetime) const;
    bool IsLaterThan(const wxDateTime& datetime) const;
    bool IsStrictlyBetween(const wxDateTime& t1, const wxDateTime& t2) const;
    bool IsBetween(const wxDateTime& t1, const wxDateTime& t2) const;
    bool IsSameDate(const wxDateTime& dt) const;
    bool IsSameTime(const wxDateTime& dt) const;
    bool IsEqualUpTo(const wxDateTime& dt, const wxTimeSpan& ts) const;

    bool operator<(const wxDateTime& dt) const;
    bool operator<=(const wxDateTime& dt) const;
    bool operator>(const wxDateTime& dt) const;
    bool operator>=(const wxDateTime& dt) const;
    bool operator==(const wxDateTime& dt) const;
    bool operator!=(const wxDateTime& dt) const;

    wxDateTime& Add(const wxTimeSpan& diff);
    wxDateTime& Add(const wxDateSpan& diff);
    wxDateTime& Subtract(const wxTimeSpan& diff);
    wxDateTime& Subtract(const wxDateSpan& diff);

    // ALL of the ParseXXX() functions in wx29 that take a 'wxString::const_iterator *end'
    // return the remainder of the input string after the error occurred if possible or
    // the whole string. Only a bool value of true is returned on success.

    // %override [bool, lua String remainder on error] ParseRfc822Date(const wxString& date);
    // C++ Func: bool ParseRfc822Date(const wxString& date, wxString::const_iterator *end);
    %wxchkver_2_9 bool ParseRfc822Date(const wxString& date);
    // %override [bool, lua String remainder on error] ParseFormat(const wxString& date, wxString format, const wxDateTime& dateDef);
    // C++ Func: bool ParseFormat(const wxString& date, wxString format, const wxDateTime& dateDef, wxString::const_iterator *end);
    %wxchkver_2_9 bool ParseFormat(const wxString& date, wxString format, const wxDateTime& dateDef);
    // %override [bool, lua String remainder on error] ParseFormat(const wxString& date, wxString format);
    // C++ Func: bool ParseFormat(const wxString& date, wxString format, wxString::const_iterator *end);
    %wxchkver_2_9 bool ParseFormat(const wxString& date, wxString format);
    // %override [bool, lua String remainder on error] ParseFormat(const wxString& date);
    // C++ Func: bool ParseFormat(const wxString& date, wxString::const_iterator *end);
    %wxchkver_2_9 bool ParseFormat(const wxString& date);
    // %override [bool, lua String remainder on error] ParseDateTime(const wxString& date);
    // C++ Func: bool ParseDateTime(const wxString& date, wxString::const_iterator *end);
    %wxchkver_2_9 bool ParseDateTime(const wxString& datetime);
    // %override [bool, lua String remainder on error] ParseDate(const wxString& date);
    // C++ Func: bool ParseDate(const wxString& date, wxString::const_iterator *end);
    %wxchkver_2_9 bool ParseDate(const wxString& date);
    // %override [bool, lua String remainder on error] ParseTime(const wxString& date);
    // C++ Func: bool ParseTime(const wxString& date, wxString::const_iterator *end);
    %wxchkver_2_9 bool ParseTime(const wxString& time);

    !%wxchkver_2_9 wxString ParseRfc822Date(wxString date);
    !%wxchkver_2_9 wxString ParseFormat(wxString date, wxString format = "%c", const wxDateTime& dateDef = wxDefaultDateTime);
    !%wxchkver_2_9 wxString ParseDateTime(wxString datetime);
    !%wxchkver_2_9 wxString ParseDate(wxString date);
    !%wxchkver_2_9 wxString ParseTime(wxString time);

    wxString FormatDate() const;
    wxString FormatTime() const;
    wxString FormatISODate() const;
    wxString FormatISOTime() const;
    wxString Format(wxString format = "%c", wxDateTime::TZ tz = wxDateTime::Local) const;
};

// ---------------------------------------------------------------------------
// wxDateTimeArray

class %delete wxDateTimeArray
{
    wxDateTimeArray();
    wxDateTimeArray(const wxDateTimeArray& array);

    void Add(const wxDateTime& dateTime, size_t copies = 1);
    void Alloc(size_t nCount);
    void Clear();
    void Empty();
    int GetCount() const;
    void Insert(const wxDateTime& dt, int nIndex, size_t copies = 1);
    bool IsEmpty();
    wxDateTime Item(size_t nIndex) const;
    wxDateTime Last();
    void RemoveAt(size_t nIndex, size_t count = 1);
    void Shrink();
};

#endif //wxLUA_USE_wxDateTime && wxUSE_DATETIME

// ---------------------------------------------------------------------------
// wxTimeSpan

#if wxLUA_USE_wxTimeSpan && wxUSE_DATETIME

#include "wx/datetime.h"

class %delete wxTimeSpan
{
    wxTimeSpan();
    wxTimeSpan(long hours, long minutes = 0, long seconds = 0, long milliseconds = 0);

    wxTimeSpan Abs();
    wxTimeSpan Add(const wxTimeSpan& diff) const;
    static wxTimeSpan Days(long days);
    static wxTimeSpan Day();
    wxString Format(wxString format = "%H:%M:%S") const;
    int GetDays() const;
    int GetHours() const;
    wxLongLong GetMilliseconds() const;
    int GetMinutes() const;
    wxLongLong GetSeconds() const;
    wxLongLong GetValue() const;
    int GetWeeks() const;
    static wxTimeSpan  Hours(long hours);
    static wxTimeSpan  Hour();
    bool IsEqualTo(const wxTimeSpan& ts) const;
    bool IsLongerThan(const wxTimeSpan& ts) const;
    bool IsNegative() const;
    bool IsNull() const;
    bool IsPositive() const;
    bool IsShorterThan(const wxTimeSpan& ts) const;
    static wxTimeSpan  Minutes(long min);
    static wxTimeSpan  Minute();
    wxTimeSpan Multiply(int n) const;
    wxTimeSpan Negate() const;
    wxTimeSpan& Neg();
    static wxTimeSpan Seconds(long sec);
    static wxTimeSpan Second();
    wxTimeSpan Subtract(const wxTimeSpan& diff) const;
    static wxTimeSpan Weeks(long weeks);
    static wxTimeSpan Week();
};

#endif //wxLUA_USE_wxTimeSpan && wxUSE_DATETIME

// ---------------------------------------------------------------------------
// wxDateSpan

#if wxLUA_USE_wxDateSpan && wxUSE_DATETIME

#include "wx/datetime.h"

class %delete wxDateSpan
{
    wxDateSpan(int years = 0, int months = 0, int weeks = 0, int days = 0);

    wxDateSpan Add(const wxDateSpan& other) const;
    static wxDateSpan Day();
    static wxDateSpan Days(int days);
    int GetDays() const;
    int GetMonths() const;
    int GetTotalDays() const;
    int GetWeeks() const;
    int GetYears() const;
    static wxDateSpan  Month();
    static wxDateSpan  Months(int mon);
    wxDateSpan Multiply(int factor) const;
    wxDateSpan Negate() const;
    wxDateSpan& Neg();
    wxDateSpan& SetDays(int n);
    wxDateSpan& SetMonths(int n);
    wxDateSpan& SetWeeks(int n);
    wxDateSpan& SetYears(int n);
    wxDateSpan Subtract(const wxDateSpan& other) const;
    static wxDateSpan Week();
    static wxDateSpan Weeks(int weeks);
    static wxDateSpan Year();
    static wxDateSpan Years(int years);

    bool operator==(wxDateSpan& other) const;
};

#endif //wxLUA_USE_wxDateSpan && wxUSE_DATETIME

// ---------------------------------------------------------------------------
// wxDateTimeHolidayAuthority

#if wxLUA_USE_wxDateTimeHolidayAuthority && wxUSE_DATETIME

class wxDateTimeHolidayAuthority
{
    // no constructor since this class has pure virtual functions

    static bool IsHoliday(const wxDateTime& dt);
    static size_t GetHolidaysInRange(const wxDateTime& dtStart, const wxDateTime& dtEnd, wxDateTimeArray& holidays);
    static void ClearAllAuthorities();
    static void AddAuthority(wxDateTimeHolidayAuthority *auth);
};

// ---------------------------------------------------------------------------
// wxDateTimeWorkDays

class %delete wxDateTimeWorkDays : public wxDateTimeHolidayAuthority
{
    wxDateTimeWorkDays();
};

#endif //wxLUA_USE_wxDateTimeHolidayAuthority && wxUSE_DATETIME


// ---------------------------------------------------------------------------
// wxStopWatch

#if wxLUA_USE_wxStopWatch && wxUSE_STOPWATCH

#include "wx/stopwatch.h"

class %delete wxStopWatch
{
    wxStopWatch(); // ctor starts the stop watch

    void Start(long t0 = 0); // start the stop watch at the moment t0
    void Pause();
    void Resume();
    long Time() const;
};

#endif // wxLUA_USE_wxStopWatch && wxUSE_STOPWATCH
