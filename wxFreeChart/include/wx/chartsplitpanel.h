/////////////////////////////////////////////////////////////////////////////
// Name:    chartsplitpanel.h
// Purpose:
// Author:    Moskvichev Andrey V.
// Created:    28.01.2010
// RCS-ID:    $Id: wxAdvTable.h,v 1.3 2008/11/07 16:42:58 moskvichev Exp $
// Copyright:    (c) 2010 Moskvichev Andrey V.
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef CHARTSPLITPANEL_H_
#define CHARTSPLITPANEL_H_

#include <wx/aui/aui.h>

#include "wx/wxfreechartdefs.h"
#include "wx/plot.h"
#include "wx/multiplot.h" // for PlotArray

/**
 * wxChartSplitPanel is wxWidgets panel, that displays multiple plots.
 * It allows subplots adding, removing, resizing.
 */
class WXDLLIMPEXP_FREECHART wxChartSplitPanel : public wxPanel
{
public:
    wxChartSplitPanel(wxWindow *parent, wxWindowID id = wxID_ANY,
            const wxPoint &pos = wxDefaultPosition, const wxSize &size = wxDefaultSize);
    virtual ~wxChartSplitPanel();

    void AddPlot(Plot *plot, int pos, bool allowRemove);
    void RemovePlot(Plot *plot);
    void RemovePlot(size_t nPlot);

    void RemoveAllPlots();

    Plot *GetPlot(size_t index);

private:
    wxAuiManager *m_auiManager;

    PlotArray m_plots;
};

#endif /* CHARTSPLITPANEL_H_ */

