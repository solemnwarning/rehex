// ===========================================================================
// Purpose:     Various wxAdv library classes
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

// ---------------------------------------------------------------------------
// wxAboutDialog

#if %wxchkver_2_8 && wxUSE_ABOUTDLG && wxLUA_USE_wxAboutDialog

#include "wx/aboutdlg.h"

class %delete wxAboutDialogInfo
{
    wxAboutDialogInfo();

    void SetName(const wxString& name);
    wxString GetName() const;

    void SetVersion(const wxString& version);
    bool HasVersion() const;
    wxString GetVersion() const;

    void SetDescription(const wxString& desc);
    bool HasDescription() const;
    wxString GetDescription() const;

    void SetCopyright(const wxString& copyright);
    bool HasCopyright() const;
    wxString GetCopyright() const;

    void SetLicence(const wxString& licence);
    void SetLicense(const wxString& licence);
    bool HasLicence() const;
    wxString GetLicence() const;

    void SetIcon(const wxIcon& icon);
    bool HasIcon() const;
    wxIcon GetIcon() const;

    void SetWebSite(const wxString& url, const wxString& desc = "");
    bool HasWebSite() const;

    wxString GetWebSiteURL() const;
    wxString GetWebSiteDescription() const;

    void SetDevelopers(const wxArrayString& developers);
    void AddDeveloper(const wxString& developer);
    bool HasDevelopers() const;
    const wxArrayString& GetDevelopers() const;

    void SetDocWriters(const wxArrayString& docwriters);
    void AddDocWriter(const wxString& docwriter);
    bool HasDocWriters() const;
    wxArrayString GetDocWriters() const;

    void SetArtists(const wxArrayString& artists);
    void AddArtist(const wxString& artist);
    bool HasArtists() const;
    wxArrayString GetArtists() const;

    void SetTranslators(const wxArrayString& translators);
    void AddTranslator(const wxString& translator);
    bool HasTranslators() const;
    wxArrayString GetTranslators() const;

    // implementation only
    // -------------------
    bool IsSimple() const;
    wxString GetDescriptionAndCredits() const;
};

void wxAboutBox(const wxAboutDialogInfo& info);

#endif //%wxchkver_2_8 && wxUSE_ABOUTDLG && wxLUA_USE_wxAboutDialog


// ---------------------------------------------------------------------------
// wxAnimation

#if %wxchkver_2_8 && wxLUA_USE_wxAnimation && wxUSE_ANIMATIONCTRL

#include "wx/animate.h"

enum wxAnimationType
{
    wxANIMATION_TYPE_INVALID,
    wxANIMATION_TYPE_GIF,
    wxANIMATION_TYPE_ANI,

    wxANIMATION_TYPE_ANY
};

class %delete wxAnimation : public wxGDIObject // ignore platform independent wxAnimationBase
{
    wxAnimation();
    wxAnimation(const wxAnimation& anim);
    //wxAnimation(const wxString& name, wxAnimationType type = wxANIMATION_TYPE_ANY); // doesn't exist in 2.8.4

    virtual bool IsOk() const;
    virtual int GetDelay(unsigned int frame) const; // can be -1
    virtual unsigned int GetFrameCount() const;
    virtual wxImage GetFrame(unsigned int frame) const;
    virtual wxSize GetSize() const;

    virtual bool LoadFile(const wxString& name, wxAnimationType type = wxANIMATION_TYPE_ANY);
    virtual bool Load(wxInputStream& stream, wxAnimationType type = wxANIMATION_TYPE_ANY);
};

// ---------------------------------------------------------------------------
// wxAnimationCtrl

#define wxAC_NO_AUTORESIZE
#define wxAC_DEFAULT_STYLE // = wxNO_BORDER

class wxAnimationCtrl : public wxControl
{
    wxAnimationCtrl();
    wxAnimationCtrl(wxWindow *parent, wxWindowID id, const wxAnimation& anim, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxAC_DEFAULT_STYLE, const wxString& name = "wxAnimationCtrl");
    bool Create(wxWindow *parent, wxWindowID id, const wxAnimation& anim, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxAC_DEFAULT_STYLE, const wxString& name = "wxAnimationCtrl");

    virtual bool LoadFile(const wxString& filename, wxAnimationType type = wxANIMATION_TYPE_ANY);

    wxAnimation GetAnimation() const;
    // always return the original bitmap set in this control
    wxBitmap GetInactiveBitmap() const;
    virtual bool IsPlaying() const;
    bool LoadFile(const wxString& file, wxAnimationType  animType = wxANIMATION_TYPE_ANY);
    virtual bool Play();
    virtual void SetAnimation(const wxAnimation &anim);
    virtual void SetInactiveBitmap(const wxBitmap &bmp);
    virtual void Stop();
};

#endif // %wxchkver_2_8 && wxLUA_USE_wxAnimation && wxUSE_ANIMATIONCTRL


// ---------------------------------------------------------------------------
// wxBitmapComboBox

#if wxLUA_USE_wxBitmapComboBox && wxUSE_BITMAPCOMBOBOX

#include "wx/bmpcbox.h"

class wxBitmapComboBox : public wxControl
{
    wxBitmapComboBox();
    //wxBitmapComboBox(wxWindow* parent, wxWindowID id, const wxString& value = "", const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, int n = 0, const wxString choices[] = NULL, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "comboBox");
    wxBitmapComboBox(wxWindow* parent, wxWindowID id, const wxString& value, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, const wxArrayString& choices = wxLuaNullSmartwxArrayString, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxBitmapComboBox");
    //bool Create(wxWindow* parent, wxWindowID id, const wxString& value = "", const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, int n, const wxString choices[], long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxBitmapComboBox");
    bool Create(wxWindow* parent, wxWindowID id, const wxString& value, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, const wxArrayString& choices = wxLuaNullSmartwxArrayString, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxBitmapComboBox");

    int Append(const wxString& item, const wxBitmap& bitmap = wxNullBitmap);
    int Append(const wxString& item, const wxBitmap& bitmap, voidptr_long data); // C++ is (void *clientData) You can put a number here
    int Append(const wxString& item, const wxBitmap& bitmap, wxClientData *clientData);

    wxSize GetBitmapSize() const;
    wxBitmap GetItemBitmap(unsigned int n) const;

    int Insert(const wxString& item, const wxBitmap& bitmap, unsigned int pos);
 #if !%wxchkver_2_9_0 || %wxchkver_2_9_5 // This function body was missing so you'd get linker errors
    int Insert(const wxString& item, const wxBitmap& bitmap, unsigned int pos, voidptr_long data); // C++ is (void *clientData) You can put a number here
 #endif
    int Insert(const wxString& item, const wxBitmap& bitmap, unsigned int pos, wxClientData *clientData);

    void SetItemBitmap(unsigned int n, const wxBitmap& bitmap);

    void Clear();
    void Delete(unsigned int n);
    unsigned int GetCount() const;
    wxString GetString(unsigned int n) const;
    void SetString(unsigned int n, const wxString& s);
    int FindString(const wxString& s, bool bCase = false) const;
    void Select(int n);
    int GetSelection() const;
    //void GetSelection(long* from, long* to) const;
    void SetSelection(int n);
    //void SetSelection(long from, long to);
    //int GetWidestItemWidth();
    //int GetWidestItem();

    void SetValue(const wxString& value);
    void SetString(unsigned int n, const wxString& s);
    bool SetStringSelection(const wxString& s);
};

#endif //wxLUA_USE_wxBitmapComboBox && wxUSE_BITMAPCOMBOBOX


// ---------------------------------------------------------------------------
// wxCalendarCtrl

#if wxLUA_USE_wxCalendarCtrl && wxUSE_CALENDARCTRL

#include "wx/calctrl.h"

enum
{
    wxCAL_SUNDAY_FIRST,
    wxCAL_MONDAY_FIRST,
    wxCAL_SHOW_HOLIDAYS,
    wxCAL_NO_YEAR_CHANGE,
    wxCAL_NO_MONTH_CHANGE,
    wxCAL_SHOW_SURROUNDING_WEEKS,
    wxCAL_SEQUENTIAL_MONTH_SELECTION
};

enum wxCalendarHitTestResult
{
    wxCAL_HITTEST_NOWHERE,
    wxCAL_HITTEST_HEADER,
    wxCAL_HITTEST_DAY,
    wxCAL_HITTEST_INCMONTH,
    wxCAL_HITTEST_DECMONTH,
    wxCAL_HITTEST_SURROUNDING_WEEK
};

enum wxCalendarDateBorder
{
    wxCAL_BORDER_NONE,
    wxCAL_BORDER_SQUARE,
    wxCAL_BORDER_ROUND
};

class wxCalendarCtrl : public wxControl
{
    wxCalendarCtrl(wxWindow* parent, wxWindowID id, const wxDateTime& date = wxDefaultDateTime, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxCAL_SHOW_HOLIDAYS, const wxString& name = "wxCalendarCtrl");
    //bool Create(wxWindow* parent, wxWindowID id, const wxDateTime& date = wxDefaultDateTime, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxCAL_SHOW_HOLIDAYS, const wxString& name = "wxCalendarCtrl");

    void     SetDate(const wxDateTime& date);
    wxDateTime GetDate() const;

    #if !%wxchkver_2_9_2
        void     EnableYearChange(bool enable = true);
    #endif

    void     EnableMonthChange(bool enable = true);
    void     EnableHolidayDisplay(bool display = true);
    void     SetHeaderColours(const wxColour& colFg, const wxColour& colBg);
    wxColour GetHeaderColourFg() const;
    wxColour GetHeaderColourBg() const;
    void     SetHighlightColours(const wxColour& colFg, const wxColour& colBg);
    wxColour GetHighlightColourFg() const;
    wxColour GetHighlightColourBg() const;
    void     SetHolidayColours(const wxColour& colFg, const wxColour& colBg);
    wxColour GetHolidayColourFg() const;
    wxColour GetHolidayColourBg() const;
    wxCalendarDateAttr* GetAttr(size_t day) const;
    void     SetAttr(size_t day, %ungc wxCalendarDateAttr* attr); // will delete previously set attr as well
    void     SetHoliday(size_t day);
    void     ResetAttr(size_t day);

    // %override [wxCalendarHitTestResult, wxDateTime date, wxDateTime::WeekDay wd] wxCalendarCtrl::HitTest(const wxPoint& pos);
    // C++ Func: wxCalendarHitTestResult HitTest(const wxPoint& pos, wxDateTime* date = NULL, wxDateTime::WeekDay* wd = NULL);
    wxCalendarHitTestResult HitTest(const wxPoint& pos);
};

// ---------------------------------------------------------------------------
// wxCalendarDateAttr

class %delete wxCalendarDateAttr
{
    wxCalendarDateAttr();
    wxCalendarDateAttr(const wxColour& colText, const wxColour& colBack = wxNullColour, const wxColour& colBorder = wxNullColour, const wxFont& font = wxNullFont, wxCalendarDateBorder border = wxCAL_BORDER_NONE);
    wxCalendarDateAttr(wxCalendarDateBorder border, const wxColour& colBorder = wxNullColour);

    void SetTextColour(const wxColour& colText);
    void SetBackgroundColour(const wxColour& colBack);
    void SetBorderColour(const wxColour& col);
    void SetFont(const wxFont& font);
    void SetBorder(wxCalendarDateBorder border);
    void SetHoliday(bool holiday);
    bool HasTextColour() const;
    bool HasBackgroundColour() const;
    bool HasBorderColour() const;
    bool HasFont() const;
    bool HasBorder() const;
    bool IsHoliday() const;
    wxColour GetTextColour() const;
    wxColour GetBackgroundColour();
    wxColour GetBorderColour() const;
    wxFont GetFont() const;
    wxCalendarDateBorder GetBorder();
};

// ---------------------------------------------------------------------------
// wxDateEvent

#include "wx/dateevt.h"

class %delete wxDateEvent : public wxCommandEvent
{
    %wxEventType wxEVT_DATE_CHANGED // EVT_DATE_CHANGED(id, fn);
    %wxEventType wxEVT_TIME_CHANGED // EVT_TIME_CHANGED(id, fn);

    wxDateEvent(wxWindow *win, const wxDateTime& dt, wxEventType type);

    wxDateTime GetDate() const;
    void SetDate(const wxDateTime &date);
};

// ---------------------------------------------------------------------------
// wxCalendarEvent

#include "wx/event.h"

class %delete wxCalendarEvent : public wxDateEvent
{
    %wxEventType wxEVT_CALENDAR_SEL_CHANGED        // EVT_CALENDAR_SEL_CHANGED(id, fn);
    %wxEventType wxEVT_CALENDAR_DAY_CHANGED        // EVT_CALENDAR_DAY(id, fn);
    %wxEventType wxEVT_CALENDAR_MONTH_CHANGED      // EVT_CALENDAR_MONTH(id, fn);
    %wxEventType wxEVT_CALENDAR_YEAR_CHANGED       // EVT_CALENDAR_YEAR(id, fn);
    %wxEventType wxEVT_CALENDAR_DOUBLECLICKED      // EVT_CALENDAR(id, fn);
    %wxEventType wxEVT_CALENDAR_WEEKDAY_CLICKED    // EVT_CALENDAR_WEEKDAY_CLICKED(id, fn);

    %wxchkver_2_9_2 wxCalendarEvent(const wxCalendarEvent& event);
    !%wxchkver_2_9_2 wxCalendarEvent(wxCalendarCtrl *cal, wxEventType type);
    %wxchkver_2_9_2 wxCalendarEvent(wxWindow *win, const wxDateTime& dt, wxEventType type);

    wxDateTime::WeekDay GetWeekDay() const;
    void SetWeekDay(const wxDateTime::WeekDay wd);
};

#endif //wxLUA_USE_wxCalendarCtrl && wxUSE_CALENDARCTRL


// ---------------------------------------------------------------------------
// wxHyperlinkCtrl

#if %wxchkver_2_8 && wxUSE_HYPERLINKCTRL && wxLUA_USE_wxHyperlinkCtrl

#include "wx/hyperlink.h"

#define wxHL_CONTEXTMENU
#define wxHL_ALIGN_LEFT
#define wxHL_ALIGN_RIGHT
#define wxHL_ALIGN_CENTRE
#define wxHL_DEFAULT_STYLE  // (wxHL_CONTEXTMENU|wxNO_BORDER|wxHL_ALIGN_CENTRE);

class wxHyperlinkCtrl : public wxControl
{
    wxHyperlinkCtrl();
    wxHyperlinkCtrl(wxWindow *parent, wxWindowID id, const wxString& label, const wxString& url, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxHL_DEFAULT_STYLE, const wxString& name = "wxHyperlinkCtrl");
    bool Create(wxWindow *parent, wxWindowID id, const wxString& label, const wxString& url, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxHL_DEFAULT_STYLE, const wxString& name = "wxHyperlinkCtrl");

    wxColour GetHoverColour() const;
    wxColour GetNormalColour() const;
    wxColour GetVisitedColour() const;
    bool     GetVisited() const;
    wxString GetURL() const;

    void SetHoverColour(const wxColour &colour);
    void SetNormalColour(const wxColour &colour);
    void SetVisitedColour(const wxColour &colour);
    void SetVisited(bool visited = true);
    void SetURL (const wxString &url);
};

// ---------------------------------------------------------------------------
// wxHyperlinkEvent

class %delete wxHyperlinkEvent : public wxCommandEvent
{
    %wxEventType wxEVT_COMMAND_HYPERLINK // EVT_HYPERLINK(id, fn);
    %wxchkver_3_0_0 %wxEventType wxEVT_HYPERLINK  // wx3.0 alias for wxEVT_COMMAND_HYPERLINK

    //wxHyperlinkEvent();
    wxHyperlinkEvent(wxObject *generator, wxWindowID id, const wxString& url);

    wxString GetURL() const;
    void SetURL(const wxString &url);
};

#endif // %wxchkver_2_8 && wxUSE_HYPERLINKCTRL && wxLUA_USE_wxHyperlinkCtrl


// ---------------------------------------------------------------------------
// wxSashWindow

#if wxLUA_USE_wxSashWindow && wxUSE_SASH

#include "wx/sashwin.h"

#define wxSW_3D
#define wxSW_3DSASH
#define wxSW_3DBORDER
#define wxSW_BORDER

enum wxSashEdgePosition
{
    wxSASH_TOP,
    wxSASH_RIGHT,
    wxSASH_BOTTOM,
    wxSASH_LEFT,
    wxSASH_NONE
};

enum wxSashDragStatus
{
    wxSASH_STATUS_OK,
    wxSASH_STATUS_OUT_OF_RANGE
};

class wxSashWindow : public wxWindow
{
    wxSashWindow();
    wxSashWindow(wxWindow *parent, wxWindowID id = -1, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxSW_3D|wxCLIP_CHILDREN, const wxString& name = "wxSashWindow");

    bool GetSashVisible(wxSashEdgePosition edge) const;
    int GetMaximumSizeX() const;
    int GetMaximumSizeY() const;
    int GetMinimumSizeX() const;
    int GetMinimumSizeY() const;

    void SetMaximumSizeX(int min);
    void SetMaximumSizeY(int min);
    void SetMinimumSizeX(int min);
    void SetMinimumSizeY(int min);
    void SetSashVisible(wxSashEdgePosition edge, bool visible);

    %wxcompat_2_6 bool HasBorder(wxSashEdgePosition edge) const;
    %wxcompat_2_6 void SetSashBorder(wxSashEdgePosition edge, bool hasBorder);
};

// ---------------------------------------------------------------------------
// wxSashLayoutWindow

#include "wx/laywin.h"

enum wxLayoutAlignment
{
    wxLAYOUT_NONE,
    wxLAYOUT_TOP,
    wxLAYOUT_LEFT,
    wxLAYOUT_RIGHT,
    wxLAYOUT_BOTTOM
};

enum wxLayoutOrientation
{
    wxLAYOUT_HORIZONTAL,
    wxLAYOUT_VERTICAL
};

class wxSashLayoutWindow : public wxSashWindow
{
    wxSashLayoutWindow();
    wxSashLayoutWindow(wxWindow *parent, wxWindowID id = -1, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxSW_3D|wxCLIP_CHILDREN, const wxString& name = "wxSashLayoutWindow");
    bool Create(wxWindow *parent, wxWindowID id = -1, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxSW_3D|wxCLIP_CHILDREN, const wxString& name = "wxSashLayoutWindow");

    wxLayoutAlignment GetAlignment() const;
    wxLayoutOrientation GetOrientation() const;
    //void OnCalculateLayout(wxCalculateLayoutEvent& event);
    //void OnQueryLayoutInfo(wxQueryLayoutInfoEvent& event);
    void SetAlignment(wxLayoutAlignment alignment);
    void SetDefaultSize(const wxSize& size);
    void SetOrientation(wxLayoutOrientation orientation);
};

// ---------------------------------------------------------------------------
// wxLayoutAlgorithm - for wxSashLayoutWindow

#include "wx/laywin.h"

class %delete wxLayoutAlgorithm : public wxObject
{
    wxLayoutAlgorithm();

    bool LayoutFrame(wxFrame* frame, wxWindow* mainWindow = NULL) const;
    bool LayoutMDIFrame(wxMDIParentFrame* frame, wxRect* rect = NULL);
    bool LayoutWindow(wxWindow* frame, wxWindow* mainWindow = NULL);
};

// ---------------------------------------------------------------------------
// wxQueryLayoutInfoEvent - for wxSashLayoutWindow

#include "wx/laywin.h"

class %delete wxQueryLayoutInfoEvent : public wxEvent
{
    %wxEventType wxEVT_QUERY_LAYOUT_INFO   // EVT_QUERY_LAYOUT_INFO(func);

    wxQueryLayoutInfoEvent(wxWindowID id = 0);

    wxLayoutAlignment GetAlignment() const;
    int GetFlags() const;
    wxLayoutOrientation GetOrientation() const;
    int GetRequestedLength() const;
    wxSize GetSize() const;
    void SetAlignment(wxLayoutAlignment alignment);
    void SetFlags(int flags);
    void SetOrientation(wxLayoutOrientation orientation);
    void SetRequestedLength(int length);
    void SetSize(const wxSize& size);
};

// ---------------------------------------------------------------------------
// wxCalculateLayoutEvent - for wxSashLayoutWindow

#include "wx/laywin.h"

class %delete wxCalculateLayoutEvent : public wxEvent
{
    %wxEventType wxEVT_CALCULATE_LAYOUT    // EVT_CALCULATE_LAYOUT(func);

    wxCalculateLayoutEvent(wxWindowID id = 0);

    int GetFlags() const;
    wxRect GetRect() const;
    void SetFlags(int flags);
    void SetRect(const wxRect& rect);
};

// ---------------------------------------------------------------------------
// wxSashEvent

class %delete wxSashEvent : public wxCommandEvent
{
    %wxEventType wxEVT_SASH_DRAGGED // EVT_SASH_DRAGGED(id, fn) EVT_SASH_DRAGGED_RANGE(id1, id2, fn);

    wxSashEvent(int id = 0, wxSashEdgePosition edge = wxSASH_NONE);

    void SetEdge(wxSashEdgePosition edge);
    int GetEdge();
    void SetDragRect(const wxRect& rect);
    wxRect GetDragRect();
    void SetDragStatus(wxSashDragStatus status);
    int GetDragStatus();
};

#endif //wxLUA_USE_wxSashWindow && wxUSE_SASH


// ---------------------------------------------------------------------------
// wxSplashScreen

#if wxLUA_USE_wxSplashScreen

#include "wx/splash.h"

#define wxSPLASH_CENTRE_ON_PARENT
#define wxSPLASH_CENTRE_ON_SCREEN
#define wxSPLASH_NO_CENTRE
#define wxSPLASH_TIMEOUT
#define wxSPLASH_NO_TIMEOUT

class wxSplashScreen : public wxFrame
{
    wxSplashScreen(const wxBitmap& bitmap, long splashStyle, int milliseconds, wxWindow* parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxSIMPLE_BORDER|wxFRAME_NO_TASKBAR|wxSTAY_ON_TOP);

    long GetSplashStyle() const;
    wxSplashScreenWindow* GetSplashWindow() const;
    int GetTimeout() const;
};

class wxSplashScreenWindow : public wxWindow
{
    // don't need to create this, just get it from wxSplashScreen

    void SetBitmap(const wxBitmap& bitmap);
    wxBitmap& GetBitmap();
};

#endif //wxLUA_USE_wxSplashScreen


// ---------------------------------------------------------------------------
// wxWizard

#if wxUSE_WIZARDDLG && wxLUA_USE_wxWizard

#include "wx/wizard.h"

#define wxWIZARD_EX_HELPBUTTON

class wxWizard : public wxDialog
{
    wxWizard();
    wxWizard(wxWindow* parent, int id = -1, const wxString& title = "", const wxBitmap& bitmap = wxNullBitmap, const wxPoint& pos = wxDefaultPosition, long style = wxDEFAULT_DIALOG_STYLE);
    bool Create(wxWindow* parent, int id = -1, const wxString& title = "", const wxBitmap& bitmap = wxNullBitmap, const wxPoint& pos = wxDefaultPosition, long style = wxDEFAULT_DIALOG_STYLE);

    wxWizardPage* GetCurrentPage() const;
    virtual wxSizer* GetPageAreaSizer() const;
    wxSize GetPageSize() const;
    virtual bool HasNextPage(wxWizardPage *page);
    virtual bool HasPrevPage(wxWizardPage *page);
    bool RunWizard(wxWizardPage* firstPage);
    void SetPageSize(const wxSize& sizePage);
    void SetBorder(int border);
};

// ---------------------------------------------------------------------------
// wxWizardPage - this has virtual functions so it can't be used?

class wxWizardPage : public wxPanel
{
    //wxWizardPage(wxWizard* parent, const wxBitmap& bitmap = wxNullBitmap, const wxChar *resource = NULL);

    //virtual wxWizardPage* GetPrev() const; // FIXME not virtual for wxLua
    //virtual wxWizardPage* GetNext() const;
    wxBitmap GetBitmap() const;
};

// ---------------------------------------------------------------------------
// wxWizardPageSimple - use this

class wxWizardPageSimple : public wxWizardPage
{
    wxWizardPageSimple(wxWizard* parent = NULL, wxWizardPage* prev = NULL, wxWizardPage* next = NULL, const wxBitmap& bitmap = wxNullBitmap);

    virtual wxWizardPage* GetPrev() const;
    virtual wxWizardPage* GetNext() const;

    void SetPrev(wxWizardPage* prev);
    void SetNext(wxWizardPage* next);
    static void Chain(wxWizardPageSimple* first, wxWizardPageSimple* second);
};

// ---------------------------------------------------------------------------
// wxWizardEvent

class %delete wxWizardEvent : public wxNotifyEvent
{
    %wxEventType wxEVT_WIZARD_CANCEL           // EVT_WIZARD_CANCEL(id, fn);
    %wxEventType wxEVT_WIZARD_PAGE_CHANGED     // EVT_WIZARD_PAGE_CHANGED(id, fn);
    %wxEventType wxEVT_WIZARD_PAGE_CHANGING    // EVT_WIZARD_PAGE_CHANGING(id, fn);
    %wxEventType wxEVT_WIZARD_HELP             // EVT_WIZARD_HELP(id, fn);
    %wxEventType wxEVT_WIZARD_FINISHED         // EVT_WIZARD_FINISHED(id, fn);

    wxWizardEvent(wxEventType type = wxEVT_NULL, int id = -1, bool direction = true);

    bool GetDirection() const;
    wxWizardPage* GetPage() const;
};

#endif //wxUSE_WIZARDDLG && wxLUA_USE_wxWizard


// ---------------------------------------------------------------------------
// wxTaskBarIcon

#if wxLUA_USE_wxTaskBarIcon && defined(wxHAS_TASK_BAR_ICON);

#include "wx/taskbar.h"

class %delete wxTaskBarIcon : public wxEvtHandler
{
    wxTaskBarIcon();

    // virtual wxMenu*  CreatePopupMenu();
    bool IsIconInstalled();
    %wxchkver_2_4 bool IsOk();
    virtual bool PopupMenu(wxMenu* menu);

    // call RemoveIcon() or delete this if you want your program to exit, must have called SetIcon();
    bool RemoveIcon();
    // call SetIcon() to have the taskbar icon displayed
    bool SetIcon(const wxIcon& icon, const wxString& tooltip);
};

// ---------------------------------------------------------------------------
// wxTaskBarIconEvent

class %delete wxTaskBarIconEvent : public wxEvent
{
    %wxEventType wxEVT_TASKBAR_MOVE            // EVT_TASKBAR_MOVE(func);
    %wxEventType wxEVT_TASKBAR_LEFT_DOWN       // EVT_TASKBAR_LEFT_DOWN(func);
    %wxEventType wxEVT_TASKBAR_LEFT_UP         // EVT_TASKBAR_LEFT_UP(func);
    %wxEventType wxEVT_TASKBAR_RIGHT_DOWN      // EVT_TASKBAR_RIGHT_DOWN(func);
    %wxEventType wxEVT_TASKBAR_RIGHT_UP        // EVT_TASKBAR_RIGHT_UP(func);
    %wxEventType wxEVT_TASKBAR_LEFT_DCLICK     // EVT_TASKBAR_LEFT_DCLICK(func);
    %wxEventType wxEVT_TASKBAR_RIGHT_DCLICK    // EVT_TASKBAR_RIGHT_DCLICK(func);

    wxTaskBarIconEvent(wxEventType evtType, wxTaskBarIcon *tbIcon);
};

#endif //wxLUA_USE_wxTaskBarIcon && defined(wxHAS_TASK_BAR_ICON);


// ---------------------------------------------------------------------------
//  wxJoystick

#if wxLUA_USE_wxJoystick && wxUSE_JOYSTICK

#include "wx/joystick.h"

enum
{
    wxJOYSTICK1,
    wxJOYSTICK2
};

enum
{
    wxJOY_BUTTON_ANY,
    wxJOY_BUTTON1,
    wxJOY_BUTTON2,
    wxJOY_BUTTON3,
    wxJOY_BUTTON4
};

class %delete wxJoystick : public wxObject
{
    wxJoystick(int joystick = wxJOYSTICK1);

    int GetButtonState() const;
    int GetManufacturerId() const;
    int GetMovementThreshold() const;
    int GetNumberAxes() const;
    int GetNumberButtons() const;
    %wxchkver_2_8 static int GetNumberJoysticks() const;
    !%wxchkver_2_8 int GetNumberJoysticks() const;
    int GetPollingMax() const;
    int GetPollingMin() const;
    int GetProductId() const;
    wxString GetProductName() const;
    wxPoint GetPosition() const;
    int GetPOVPosition() const;
    int GetPOVCTSPosition() const;
    int GetRudderMax() const;
    int GetRudderMin() const;
    int GetRudderPosition() const;
    int GetUMax() const;
    int GetUMin() const;
    int GetUPosition() const;
    int GetVMax() const;
    int GetVMin() const;
    int GetVPosition() const;
    int GetXMax() const;
    int GetXMin() const;
    int GetYMax() const;
    int GetYMin() const;
    int GetZMax() const;
    int GetZMin() const;
    int GetZPosition() const;
    bool HasPOV() const;
    bool HasPOV4Dir() const;
    bool HasPOVCTS() const;
    bool HasRudder() const;
    bool HasU() const;
    bool HasV() const;
    bool HasZ() const;
    bool IsOk() const;
    bool ReleaseCapture();
    bool SetCapture(wxWindow* win, int pollingFreq = 0);
    void SetMovementThreshold(int threshold);
};

// ---------------------------------------------------------------------------
// wxJoystickEvent

#include "wx/event.h"

class %delete wxJoystickEvent : public wxEvent
{
    %wxEventType wxEVT_JOY_BUTTON_DOWN // EVT_JOY_BUTTON_DOWN(func);
    %wxEventType wxEVT_JOY_BUTTON_UP   // EVT_JOY_BUTTON_UP(func);
    %wxEventType wxEVT_JOY_MOVE        // EVT_JOY_MOVE(func);
    %wxEventType wxEVT_JOY_ZMOVE       // EVT_JOY_ZMOVE(func);

    wxJoystickEvent(wxEventType eventType = wxEVT_NULL, int state = 0, int joystick = wxJOYSTICK1, int change = 0);

    bool ButtonDown(int button = wxJOY_BUTTON_ANY) const;
    bool ButtonIsDown(int button = wxJOY_BUTTON_ANY) const;
    bool ButtonUp(int button = wxJOY_BUTTON_ANY) const;
    int GetButtonChange() const;
    int GetButtonState() const;
    int GetJoystick() const;
    wxPoint GetPosition() const;
    int GetZPosition() const;
    bool IsButton() const;
    bool IsMove() const;
    bool IsZMove() const;
};

#endif //wxLUA_USE_wxJoystick && wxUSE_JOYSTICK


// ---------------------------------------------------------------------------
//  wxSound

#if wxLUA_USE_wxWave

wxUSE_SOUND|(%msw&wxUSE_WAVE) #define wxSOUND_SYNC
wxUSE_SOUND|(%msw&wxUSE_WAVE) #define wxSOUND_ASYNC
wxUSE_SOUND|(%msw&wxUSE_WAVE) #define wxSOUND_LOOP

#if %wxchkver_2_6 && wxUSE_SOUND

#include "wx/sound.h"

class %delete wxSound : public wxObject
{
    wxSound();
    wxSound(const wxString& fileName, bool isResource = false);
    //wxSound(int size, const wxByte* data);
    bool Create(const wxString& fileName, bool isResource = false);
    //bool Create(int size, const wxByte* data);

    bool IsOk() const;
    !%win static bool IsPlaying() const;
    bool Play(unsigned int flags = wxSOUND_ASYNC) const;
    static bool Play(const wxString& filename, unsigned flags = wxSOUND_ASYNC);
    static void Stop();
};

#endif // %wxchkver_2_6 && wxUSE_SOUND

// ---------------------------------------------------------------------------
//  wxWave

#if %msw && !%wxchkver_2_6 && wxUSE_WAVE

#include "wx/wave.h"

class %delete wxWave : public wxObject
{
    wxWave();
    wxWave(const wxString& fileName, bool isResource = false);
    bool Create(const wxString& fileName, bool isResource = false);

    bool IsOk() const;
    !%wxchkver_2_6 bool Play(bool async = true, bool looped = false) const;
    %wxchkver_2_6 bool Play(unsigned int flags = wxSOUND_ASYNC) const;
};

#endif // %msw && !%wxchkver_2_6 && wxUSE_WAVE

#endif //wxLUA_USE_wxWave

