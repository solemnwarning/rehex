/////////////////////////////////////////////////////////////////////////////
// Name:    juliandateaxis.h
// Purpose: Axis declaration where the values are Julian Dates
// Author:    Carsten Arnholm
// Created:    2010/08/19
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef JULIANDATEAXIS_H
#define JULIANDATEAXIS_H

#include <wx/axis/numberaxis.h>

class JulianDateAxis : public NumberAxis {
public:
   JulianDateAxis(AXIS_LOCATION location);
   virtual ~JulianDateAxis();

    /**
     * Sets format for date labels.
     * @param dateFormat date format accrding to strftime
     */
   void SetDateFormat(const wxString& dateFormat);

protected:
   virtual void GetLabel(size_t step, wxString &label);

private:
   wxString m_dateFormat;
};

#endif // JULIANDATEAXIS_H

