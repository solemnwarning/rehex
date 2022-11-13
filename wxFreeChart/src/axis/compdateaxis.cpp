/////////////////////////////////////////////////////////////////////////////
// Name:    compdateaxis.cpp
// Purpose: composite date axis implementation
// Author:    Moskvichev Andrey V.
// Created:    2008/11/07
// Copyright:    (c) 2008-2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/axis/compdateaxis.h"
#include <wx/arrimpl.cpp>

WX_DEFINE_EXPORTED_OBJARRAY(wxDateSpanArray);
WX_DEFINE_EXPORTED_OBJARRAY(wxTimeSpanArray);

IMPLEMENT_CLASS(CompDateAxis, Axis)

//
// TODO initial quick and dirty. Must be cleaned up.
//


int MonthNum(wxDateTime::Month month)
{
    switch (month) {
    case wxDateTime::Jan:
        return 1;
    case wxDateTime::Feb:
        return 2;
    case wxDateTime::Mar:
        return 3;
    case wxDateTime::Apr:
        return 4;
    case wxDateTime::May:
        return 5;
    case wxDateTime::Jun:
        return 6;
    case wxDateTime::Jul:
        return 7;
    case wxDateTime::Aug:
        return 8;
    case wxDateTime::Sep:
        return 9;
    case wxDateTime::Oct:
        return 10;
    case wxDateTime::Nov:
        return 11;
    case wxDateTime::Dec:
        return 12;
    default:
        return 0;
    }
}

wxDateTime::Month MonthFromNum(int month)
{
    switch (month) {
    case 1:
        return wxDateTime::Jan;
    case 2:
        return wxDateTime::Feb;
    case 3:
        return wxDateTime::Mar;
    case 4:
        return wxDateTime::Apr;
    case 5:
        return wxDateTime::May;
    case 6:
        return wxDateTime::Jun;
    case 7:
        return wxDateTime::Jul;
    case 8:
        return wxDateTime::Aug;
    case 9:
        return wxDateTime::Sep;
    case 10:
        return wxDateTime::Oct;
    case 11:
        return wxDateTime::Nov;
    case 12:
        return wxDateTime::Dec;
    default:
        return wxDateTime::Inv_Month;
    }
}

int Mod(wxDateTime::wxDateTime_t d, int size)
{
    if (size == 0) {
        return 0;
    }
    return d % size;
}

wxDateTime RoundDateToSpan(wxDateTime date, wxDateSpan span)
{
    wxDateTime::wxDateTime_t day = date.GetDay();
    int month = MonthNum(date.GetMonth());
    wxDateTime::wxDateTime_t year = date.GetYear();

    wxDateTime::wxDateTime_t modDays = Mod(day - 1, span.GetTotalDays());
    wxDateTime::wxDateTime_t modMonths = Mod(month - 1, span.GetMonths());
    wxDateTime::wxDateTime_t modYears = Mod(year, span.GetYears());

    return wxDateTime(day - modDays, MonthFromNum(month - modMonths), year - modYears);
}

/**
 * Calculate number of spans in date interval [first, last].
 * @param first first interval date
 * @param last last interval date
 * @param span span
 * @return number of spans in date interval
 */
int NumOfSpans(wxDateTime first, wxDateTime last, wxDateSpan span)
{
    int count = 0;

    wxDateTime date = RoundDateToSpan(first, span);
    do {
        date += span;
        count++;
    } while (date <= last);

    return count;
}

wxString FormatInterval(int start, int end)
{
    if (ABS(end - start) == 1) {
        return wxString::Format(wxT("%i"), start);
    }
    else {
        return wxString::Format(wxT("%i-%i"), start, end);
    }
}

CompDateAxis::CompDateAxis(AXIS_LOCATION location)
: Axis(location)
{
    m_fillDateGaps = false;

    m_labelMargin = 2;
    m_minLabelGap = 5;

    m_spanDraw = new FillAreaDraw();
    m_labelFont = *wxNORMAL_FONT;
    m_labelColour = *wxBLACK;

    m_dateCount = 0;
}

CompDateAxis::~CompDateAxis()
{
    wxDELETE(m_spanDraw);
}

bool CompDateAxis::AcceptDataset(Dataset *dataset)
{
    // Accepts only date/time dataset
    // and only one dataset
    return (dataset->AsDateTimeDataset() != NULL)
            && (m_datasets.Count() == 0);
}

wxCoord CompDateAxis::GetExtent(wxDC &dc)
{
    return (m_dateSpans.Count()) * GetSpanExtent(dc);
}

void CompDateAxis::GetDataBounds(double &minValue, double &maxValue) const
{
    minValue = 0;
    maxValue = m_dateCount;
}

bool CompDateAxis::UpdateBounds()
{
    m_dateCount = 0;

    DateTimeDataset *dataset = m_datasets[0]->AsDateTimeDataset();
    if (dataset->GetCount() < 1) {
        return false;
    }

    if (m_dateSpans.Count() == 0) {
        return false;
    }

    time_t minDate = dataset->GetDate(0);
    time_t maxDate = dataset->GetDate(dataset->GetCount() - 1);

    wxDateSpan span = m_dateSpans[0]; // take first span as minimal

    m_dateCount = NumOfSpans(wxDateTime(minDate), wxDateTime(maxDate), span);

    FireBoundsChanged();
    
    return true;
}

void CompDateAxis::DrawGridLines(wxDC &dc, wxRect rc)
{
    wxDateTime firstDate, lastDate;
    if (!GetWindowDateBounds(firstDate, lastDate)) {
        return ;
    }

    // we will draw grid lines by minimal date span
    wxDateSpan span;
    if (!GetMinSpan(span)) {
        return ;
    }

    dc.SetPen(m_majorGridlinePen);

    wxDateTime date = RoundDateToSpan(firstDate, span);
    do {
        double value = DateToDataCoord(date);

        wxCoord x0, y0;
        wxCoord x1, y1;
        if (IsVertical()) {
            x0 = rc.x;
            x1 = rc.x + rc.width;
            y0 = y1 = Axis::ToGraphics(dc, rc.y, rc.height, value);
        }
        else {
            x0 = x1 = Axis::ToGraphics(dc, rc.x, rc.width, value);
            y0 = rc.y;
            y1 = rc.y + rc.height;
        }

        dc.DrawLine(x0, y0, x1, y1);

        date += span;
    } while (date <= lastDate);
}

void CompDateAxis::Draw(wxDC &dc, wxRect rc)
{
    DateTimeDataset *dataset = m_datasets[0]->AsDateTimeDataset();
    if (dataset == NULL) {
        return ; // BUG!
    }

    wxDateTime firstDate, lastDate;
    if (!GetWindowDateBounds(firstDate, lastDate)) {
        return ;
    }

    for (size_t nSpan = 0; nSpan < m_dateSpans.Count(); nSpan++) {
        wxDateSpan span = m_dateSpans[nSpan];

        wxDateTime dateStart = RoundDateToSpan(firstDate, span);
        do {
            double start = DateToDataCoord(dateStart);

            wxDateTime dateEnd = dateStart;
            dateEnd += span;

            double end = DateToDataCoord(dateEnd);

            DrawSpan(dc, rc, nSpan, GetSpanLabel(dateStart, span), start, end);

            dateStart += span;
        } while (dateStart <= lastDate);
    }
}

void CompDateAxis::DrawSpan(wxDC &dc, wxRect rcAxis, int spanNum, wxString spanLabel, double start, double end)
{
    double winMin, winMax;
    GetWindowBounds(winMin, winMax);

    if (end <= winMin || start >= winMax) {
        return ; // span is not visible
    }

    wxCoord spanExtent = GetSpanExtent(dc);
    wxRect rcSpan;

    wxCoord minCoord, axisSize;
    if (IsVertical()) {
        minCoord = rcAxis.y;
        axisSize = rcAxis.height;
    }
    else {
        minCoord = rcAxis.x;
        axisSize = rcAxis.width;
    }

    wxCoord gStart, gEnd;
    if (start <= winMin) {
        gStart = minCoord;
    }
    else {
        gStart = Axis::ToGraphics(dc, minCoord, axisSize, start);
    }

    if (end >= winMax) {
        gEnd = minCoord + axisSize;
    }
    else {
        gEnd = Axis::ToGraphics(dc, minCoord, axisSize, end);
    }

    // Was wxCoord gCenter = Axis::ToGraphics(dc, minCoord, axisSize, (start + end) / 2);
    // But gCenter is not used, so removed.
    Axis::ToGraphics(dc, minCoord, axisSize, (start + end) / 2);

    if (IsVertical()) {
        rcSpan.x = rcAxis.x + spanNum * spanExtent;
        rcSpan.y = gStart;
        rcSpan.width = spanExtent;
        rcSpan.height = gEnd - gStart;
    }
    else {
        rcSpan.x = gStart;
        rcSpan.y = rcAxis.y + spanNum * spanExtent;
        rcSpan.width = gEnd - gStart;
        rcSpan.height = spanExtent;
    }

    wxDCClipper clipper(dc, rcSpan);

    m_spanDraw->Draw(dc, rcSpan);

    int labelCount;
    wxCoord xIncr, yIncr;
    wxCoord size;
    wxCoord labelGap;
    wxCoord x, y;

    dc.SetFont(m_labelFont);
    dc.SetTextForeground(m_labelColour);

    wxSize textExtent = dc.GetTextExtent(spanLabel);

    if (IsVertical()) {
        size = rcSpan.height;
        labelCount = 1;//size / (textExtent.x + 2 * m_minLabelGap);
        labelGap = 3 * m_minLabelGap + size / labelCount - textExtent.x;
        xIncr = 0;
        yIncr = labelGap;
        x = rcSpan.x + m_labelMargin;
        y = rcSpan.y + rcSpan.height - labelGap;
    }
    else {
        size = rcSpan.width;
        labelCount = 1;//size / (textExtent.x + 2 * m_minLabelGap);
        labelGap = 3 * m_minLabelGap + size / labelCount - textExtent.x;
        xIncr = labelGap;
        yIncr = 0;
        x = rcSpan.x;
        y = rcSpan.y + m_labelMargin;
    }

    // draw span labels
    for (int n = 0; n < labelCount; n++) {
        if (IsVertical()) {
            dc.DrawRotatedText(spanLabel, x, y, 90);
        }
        else {
            dc.DrawText(spanLabel, x, y);
        }

        x += xIncr;
        y += yIncr;
    }
}

wxCoord CompDateAxis::ToGraphics(wxDC &dc, int minCoord, int gRange, double value)
{
    if (m_datasets.Count() == 0) {
        return 0;
    }
    DateTimeDataset *dataset = m_datasets[0]->AsDateTimeDataset();
    if (dataset == NULL) {
        return 0; // BUG
    }

    size_t index = (size_t) value;
    if (index >= dataset->GetCount()) {
        return 0;
    }

    wxDateTime date(dataset->GetDate((int) value));
    value = DateToDataCoord(date);

    return Axis::ToGraphics(dc, minCoord, gRange, value);
}

double CompDateAxis::ToData(wxDC &dc, int minCoord, int gRange, wxCoord g)
{
    double value = Axis::ToData(dc, minCoord, gRange, g);
    // TODO inverse transformation to dataset date index needed
    return value;
}

wxString CompDateAxis::GetSpanLabel(wxDateTime date, wxDateSpan span)
{
    int days = span.GetDays();
    int weeks = span.GetWeeks();
    int months = span.GetMonths();
    int years = span.GetYears();

    if (days != 0 && weeks == 0 && months == 0 && years == 0) {
        // days span
        int startDay = date.GetDay();
        int endDay = startDay + days;

        wxDateTime::wxDateTime_t maxDay = wxDateTime::GetNumberOfDays(date.GetMonth(), date.GetYear());
        if (endDay > maxDay) {
            endDay -= maxDay;
        }
        return FormatInterval(startDay, endDay);
    }
    else if (days == 0 && weeks != 0 && months == 0 && years == 0) {
        // weeks span
        int startWeek = date.GetWeekOfMonth();
        int endWeek = startWeek + weeks;

        return FormatInterval(startWeek, endWeek);
    }
    else if (days == 0 && weeks == 0 && months != 0 && years == 0) {
        // monthes span
        int startMonth = MonthNum(date.GetMonth());
        int endMonth = startMonth + months;
        if (endMonth > 12) {
            endMonth = endMonth % 12;
        }

        if (months == 1) {
            return wxDateTime::GetMonthName(MonthFromNum(startMonth));
        }
        else {
            return wxString::Format(wxT("%s-%s"),
                    wxDateTime::GetMonthName(MonthFromNum(startMonth)).c_str(),
                    wxDateTime::GetMonthName(MonthFromNum(endMonth)).c_str());
        }
    }
    else if (days == 0 && weeks == 0 && months == 0 && years != 0) {
        // years span
        int startYear = date.GetYear();
        int endYear = startYear + years;

        return FormatInterval(startYear, endYear);
    }
    else {
        // we have unaligned span, so print start-end dates
        wxDateTime endDate = date;
        endDate += span;

        return wxString::Format(wxT("%s-%s"),
                date.Format(wxT("%d-%m-%y")).c_str(),
                endDate.Format(wxT("%d-%m-%y")).c_str());
    }
}

wxCoord CompDateAxis::GetSpanExtent(wxDC &dc)
{
    dc.SetFont(m_labelFont);

    wxString str = wxT("0123456789ABCDEFG");
    wxSize textExtent = dc.GetTextExtent(str);

    wxCoord spanExtent = 2 * m_labelMargin + textExtent.y;
    return spanExtent;
}

bool CompDateAxis::GetWindowDateBounds(wxDateTime &date0, wxDateTime &date1)
{
    double winMin, winMax;
    GetWindowBounds(winMin, winMax);

    int firstDateIndex = (int) winMin;
    int lastDateIndex = RoundHigh(winMax) - 1;
    if (lastDateIndex < firstDateIndex) {
        lastDateIndex = firstDateIndex;
    }

    wxDateSpan span;
    if (!GetMinSpan(span)) {
        return false;
    }

    wxDateTime date;
    if (!GetFirstDate(date)) {
        return false;
    }

    date0 = date;
    for (int n = 0; n < firstDateIndex; n++) {
        date0 += span;
    }

    date1 = date;
    for (int n = 0; n < lastDateIndex; n++) {
        date1 += span;
    }
    return true;
}

bool CompDateAxis::GetFirstDate(wxDateTime &date)
{
    wxDateTime dummy;
    return GetFirstLastDate(date, dummy);
}

bool CompDateAxis::GetLastDate(wxDateTime &date)
{
    wxDateTime dummy;
    return GetFirstLastDate(dummy, date);
}

bool CompDateAxis::GetFirstLastDate(wxDateTime &firstDate, wxDateTime &lastDate)
{
    if (m_datasets.Count() == 0) {
        return false;
    }
    DateTimeDataset *dataset = m_datasets[0]->AsDateTimeDataset();
    if (dataset == NULL) {
        return false; // BUG
    }

    wxDateSpan span;
    if (!GetMinSpan(span)) {
        return false;
    }

    firstDate = RoundDateToSpan(dataset->GetDate(0), span);

    lastDate = dataset->GetDate(dataset->GetCount() - 1);
    wxDateTime date = RoundDateToSpan(lastDate, span);
    if (date < lastDate) {
        lastDate += span;
    }
    return true;
}

bool CompDateAxis::GetMinSpan(wxDateSpan &span)
{
    if (m_dateSpans.Count() == 0) {
        return false;
    }
    span = m_dateSpans[0];
    return true;
}

double CompDateAxis::DateToDataCoord(wxDateTime &date)
{
    wxDateTime firstDate, lastDate;
    if (!GetFirstLastDate(firstDate, lastDate)) {
        return 0;
    }

    double dataValue = m_dateCount * (double) (date.GetTicks() - firstDate.GetTicks()) / (double) (lastDate.GetTicks() - firstDate.GetTicks());
    return dataValue;
}

void CompDateAxis::AddInterval(const wxDateSpan &interval)
{
    m_dateSpans.Add(interval);
    FireAxisChanged();
}
