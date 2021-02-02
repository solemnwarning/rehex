// ===========================================================================
// Purpose:     XRC Resource system
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

#if wxLUA_USE_wxXRC && wxUSE_XRC

#include "wx/xrc/xmlres.h"

// ---------------------------------------------------------------------------
// wxXmlResourceHandler - wxLua shouldn't need this

//class wxXmlResourceHandler : public wxObject
//{
//};

enum wxXmlResourceFlags
{
    wxXRC_USE_LOCALE,
    wxXRC_NO_SUBCLASSING,
    wxXRC_NO_RELOADING
};

// ---------------------------------------------------------------------------
// wxXmlResource

class %delete wxXmlResource : public wxObject
{
    //wxXmlResource();
    wxXmlResource(int flags = wxXRC_USE_LOCALE, const wxString& domain = "");
    wxXmlResource(const wxString& filemask, int flags = wxXRC_USE_LOCALE, const wxString& domain = "");

    //void AddHandler(wxXmlResourceHandler* handler);
    bool AttachUnknownControl(const wxString& name, wxWindow* control, wxWindow* parent = NULL);
    void ClearHandlers();
    int CompareVersion(int major, int minor, int release, int revision) const;
    static wxXmlResource* Get();
    int GetFlags();
    long GetVersion() const;
    static int GetXRCID(const wxString &stringID, int value_if_not_found = wxID_NONE);
    void InitAllHandlers();

    bool Load(const wxString& filemask);
    wxBitmap LoadBitmap(const wxString& name);
    wxDialog* LoadDialog(wxWindow* parent, const wxString& name);
    bool LoadDialog(wxDialog* dlg, wxWindow *parent, const wxString &name);
    bool LoadFrame(wxFrame* frame, wxWindow* parent, const wxString& name);
    wxIcon LoadIcon(const wxString& name);
    wxMenu* LoadMenu(const wxString& name);
    wxMenuBar* LoadMenuBar(wxWindow* parent, const wxString& name);
    wxMenuBar* LoadMenuBar(const wxString& name);
    wxPanel* LoadPanel(wxWindow* parent, const wxString &name);
    bool LoadPanel(wxPanel *panel, wxWindow *parent, const wxString &name);
    wxToolBar* LoadToolBar(wxWindow *parent, const wxString& name);

    static %gc wxXmlResource* Set(%ungc wxXmlResource *res);
    void SetDomain(const wxString& domain);
    void SetFlags(int flags);
    bool Unload(const wxString& filename);
};

#endif //wxLUA_USE_wxXRC && wxUSE_XRC
