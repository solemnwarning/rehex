// ===========================================================================
// Purpose:     wxAUI library
// Author:      John Labenski
// Created:     07/03/2007
// Copyright:   (c) 2007 John Labenski. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.6
// ===========================================================================

// NOTE: This file is mostly copied from wxWidget's include/aui/*.h headers
// to make updating it easier.

#if wxLUA_USE_wxAUI && %wxchkver_2_8 && wxUSE_AUI

#include "wx/aui/aui.h"

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

//#include "wx/aui/auibar.h" // already included by aui.h


enum wxAuiToolBarStyle
{
    wxAUI_TB_TEXT,          //= 1 << 0,
    wxAUI_TB_NO_TOOLTIPS,   //= 1 << 1,
    wxAUI_TB_NO_AUTORESIZE, //= 1 << 2,
    wxAUI_TB_GRIPPER,       //= 1 << 3,
    wxAUI_TB_OVERFLOW,      //= 1 << 4,
    wxAUI_TB_VERTICAL,      //= 1 << 5,
    wxAUI_TB_HORZ_LAYOUT,   //= 1 << 6,
    wxAUI_TB_HORZ_TEXT,     //= (wxAUI_TB_HORZ_LAYOUT | wxAUI_TB_TEXT),
    wxAUI_TB_DEFAULT_STYLE  //= 0
};

enum wxAuiToolBarArtSetting
{
    wxAUI_TBART_SEPARATOR_SIZE, //= 0,
    wxAUI_TBART_GRIPPER_SIZE,   //= 1,
    wxAUI_TBART_OVERFLOW_SIZE   //= 2
};

enum wxAuiToolBarToolTextOrientation
{
    wxAUI_TBTOOL_TEXT_LEFT,   //= 0,     // unused/unimplemented
    wxAUI_TBTOOL_TEXT_RIGHT,  //= 1,
    wxAUI_TBTOOL_TEXT_TOP,    //= 2,      // unused/unimplemented
    wxAUI_TBTOOL_TEXT_BOTTOM  //= 3
};

// ---------------------------------------------------------------------------
// wxAuiToolBarEvent

class wxAuiToolBarEvent : public wxNotifyEvent
{
    %wxEventType wxEVT_COMMAND_AUITOOLBAR_TOOL_DROPDOWN   // EVT_AUITOOLBAR_TOOL_DROPDOWN(winid, fn)
    %wxEventType wxEVT_COMMAND_AUITOOLBAR_OVERFLOW_CLICK  // EVT_AUITOOLBAR_OVERFLOW_CLICK(winid, fn)
    %wxEventType wxEVT_COMMAND_AUITOOLBAR_RIGHT_CLICK     // EVT_AUITOOLBAR_RIGHT_CLICK(winid, fn)
    %wxEventType wxEVT_COMMAND_AUITOOLBAR_MIDDLE_CLICK    // EVT_AUITOOLBAR_MIDDLE_CLICK(winid, fn)
    %wxEventType wxEVT_COMMAND_AUITOOLBAR_BEGIN_DRAG      // EVT_AUITOOLBAR_BEGIN_DRAG(winid, fn)

    %wxchkver_3_0_0 %wxEventType wxEVT_AUITOOLBAR_TOOL_DROPDOWN  // wx3.0 alias for wxEVT_COMMAND_AUITOOLBAR_TOOL_DROPDOWN
    %wxchkver_3_0_0 %wxEventType wxEVT_AUITOOLBAR_OVERFLOW_CLICK // wx3.0 alias for wxEVT_COMMAND_AUITOOLBAR_OVERFLOW_CLICK
    %wxchkver_3_0_0 %wxEventType wxEVT_AUITOOLBAR_RIGHT_CLICK    // wx3.0 alias for wxEVT_COMMAND_AUITOOLBAR_RIGHT_CLICK
    %wxchkver_3_0_0 %wxEventType wxEVT_AUITOOLBAR_MIDDLE_CLICK   // wx3.0 alias for wxEVT_COMMAND_AUITOOLBAR_MIDDLE_CLICK
    %wxchkver_3_0_0 %wxEventType wxEVT_AUITOOLBAR_BEGIN_DRAG     // wx3.0 alias for wxEVT_COMMAND_AUITOOLBAR_BEGIN_DRAG

    wxAuiToolBarEvent(wxEventType command_type = wxEVT_NULL, int win_id = 0);
    wxAuiToolBarEvent(const wxAuiToolBarEvent& c);

    wxEvent *Clone() const;

    bool IsDropDownClicked() const;
    void SetDropDownClicked(bool c);

    wxPoint GetClickPoint() const;
    void SetClickPoint(const wxPoint& p);

    wxRect GetItemRect() const;
    void SetItemRect(const wxRect& r);

    int GetToolId() const;
    void SetToolId(int id);
};

// ---------------------------------------------------------------------------
// wxAuiToolBarItem

class wxAuiToolBarItem
{
    wxAuiToolBarItem();
    wxAuiToolBarItem(const wxAuiToolBarItem& c);
    wxAuiToolBarItem& operator=(const wxAuiToolBarItem& c);
    void Assign(const wxAuiToolBarItem& c);
    void SetWindow(wxWindow* w);
    wxWindow* GetWindow();
    void SetId(int new_id);
    int GetId() const;
    void SetKind(int new_kind);
    int GetKind() const;
    void SetState(int new_state);
    int GetState() const;
    void SetSizerItem(wxSizerItem* s);
    wxSizerItem* GetSizerItem() const;
    void SetLabel(const wxString& s);
    const wxString& GetLabel() const;
    void SetBitmap(const wxBitmap& bmp);
    !%wxchkver_3_2_0 const wxBitmap& GetBitmap() const;
    %wxchkver_3_2_0 wxBitmap GetBitmap() const;
    void SetDisabledBitmap(const wxBitmap& bmp);
    !%wxchkver_3_2_0 const wxBitmap& GetDisabledBitmap() const;
    %wxchkver_3_2_0 wxBitmap GetDisabledBitmap() const;
    void SetHoverBitmap(const wxBitmap& bmp);
    !%wxchkver_3_2_0 const wxBitmap& GetHoverBitmap() const;
    %wxchkver_3_2_0 wxBitmap GetHoverBitmap() const;
    void SetShortHelp(const wxString& s);
    const wxString& GetShortHelp() const;
    void SetLongHelp(const wxString& s);
    const wxString& GetLongHelp() const;
    void SetMinSize(const wxSize& s);
    const wxSize& GetMinSize() const;
    void SetSpacerPixels(int s);
    int GetSpacerPixels() const;
    void SetProportion(int p);
    int GetProportion() const;
    void SetActive(bool b);
    bool IsActive() const;
    void SetHasDropDown(bool b);
    bool HasDropDown() const;
    void SetSticky(bool b);
    bool IsSticky() const;
    void SetUserData(long l);
    long GetUserData() const;
    %wxchkver_3_0_0 void SetAlignment(int l);
    %wxchkver_3_0_0 int GetAlignment() const;
    %wxchkver_3_1_5 bool CanBeToggled() const;
};

// ---------------------------------------------------------------------------
// wxAuiToolBarItemArray

class %delete wxAuiToolBarItemArray
{
    wxAuiToolBarItemArray();
    wxAuiToolBarItemArray(const wxAuiToolBarItemArray& array);

    void Add(const wxAuiToolBarItem& item);
    void Clear();
    int  GetCount() const;
    void Insert(const wxAuiToolBarItem& item, int nIndex);
    bool IsEmpty();
    wxAuiToolBarItem Item(size_t nIndex) const;
    void RemoveAt(size_t nIndex);
};

// ---------------------------------------------------------------------------
// wxAuiToolBarArt

class wxAuiToolBarArt
{
    //wxAuiToolBarArt(); - pure virtual class see wxAuiDefaultToolBarArt
    virtual wxAuiToolBarArt* Clone();
    virtual void SetFlags(unsigned int flags);
    %wxchkver_3_0_0 unsigned int GetFlags();
    virtual void SetFont(const wxFont& font);
    %wxchkver_3_0_0 wxFont GetFont();
    virtual void SetTextOrientation(int orientation);
    %wxchkver_3_0_0 int GetTextOrientation();
    virtual void DrawBackground(wxDC& dc, wxWindow* wnd, const wxRect& rect);
    %wxchkver_3_0_0 void DrawPlainBackground(wxDC& dc, wxWindow* wnd, const wxRect& rect);
    virtual void DrawLabel(wxDC& dc, wxWindow* wnd, const wxAuiToolBarItem& item, const wxRect& rect);
    virtual void DrawButton(wxDC& dc, wxWindow* wnd, const wxAuiToolBarItem& item, const wxRect& rect);
    virtual void DrawDropDownButton(wxDC& dc, wxWindow* wnd, const wxAuiToolBarItem& item, const wxRect& rect);
    virtual void DrawControlLabel(wxDC& dc, wxWindow* wnd, const wxAuiToolBarItem& item, const wxRect& rect);
    virtual void DrawSeparator(wxDC& dc, wxWindow* wnd, const wxRect& rect);
    virtual void DrawGripper(wxDC& dc, wxWindow* wnd, const wxRect& rect);
    virtual void DrawOverflowButton(wxDC& dc, wxWindow* wnd, const wxRect& rect, int state);
    virtual wxSize GetLabelSize(wxDC& dc, wxWindow* wnd, const wxAuiToolBarItem& item);
    virtual wxSize GetToolSize(wxDC& dc, wxWindow* wnd, const wxAuiToolBarItem& item);
    virtual int  GetElementSize(int element_id);
    virtual void SetElementSize(int element_id, int size);
    virtual int ShowDropDown(wxWindow* wnd, const wxAuiToolBarItemArray& items);
};

// ---------------------------------------------------------------------------
// wxAuiDefaultToolBarArt

class wxAuiDefaultToolBarArt : public wxAuiToolBarArt
{
    wxAuiDefaultToolBarArt();
};

// ---------------------------------------------------------------------------
// wxAuiToolBar

class wxAuiToolBar : public wxControl
{
    %wxchkver_3_0_0 wxAuiToolBar();
    wxAuiToolBar(wxWindow* parent, wxWindowID id = -1, const wxPoint& position = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxAUI_TB_DEFAULT_STYLE);
    %wxchkver_3_0_0 bool Create(wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxAUI_TB_DEFAULT_STYLE);
    void SetWindowStyleFlag(long style);
    long GetWindowStyleFlag() const;
    void SetArtProvider(wxAuiToolBarArt* art);
    wxAuiToolBarArt* GetArtProvider() const;
    bool SetFont(const wxFont& font);
    void AddTool(int tool_id, const wxString& label, const wxBitmap& bitmap, const wxString& short_help_string = wxEmptyString, wxItemKind kind = wxITEM_NORMAL);
    void AddTool(int tool_id, const wxString& label, const wxBitmap& bitmap, const wxBitmap& disabled_bitmap, wxItemKind kind, const wxString& short_help_string, const wxString& long_help_string, wxObject* client_data);
    void AddTool(int tool_id, const wxBitmap& bitmap, const wxBitmap& disabled_bitmap, bool toggle = false, wxObject* client_data = NULL, const wxString& short_help_string = wxEmptyString, const wxString& long_help_string = wxEmptyString);
    void AddLabel(int tool_id, const wxString& label = wxEmptyString, const int width = -1);
    void AddControl(wxControl* control, const wxString& label = wxEmptyString);
    void AddSeparator();
    void AddSpacer(int pixels);
    void AddStretchSpacer(int proportion = 1);
    bool Realize();
    wxControl* FindControl(int window_id);
    wxAuiToolBarItem* FindToolByPosition(wxCoord x, wxCoord y) const;
    wxAuiToolBarItem* FindToolByIndex(int idx) const;
    wxAuiToolBarItem* FindTool(int tool_id) const;
    void ClearTools();
    void Clear();
    %wxchkver_3_1_4 bool DestroyTool(int toolId);
    %wxchkver_3_1_4 bool DestroyToolByIndex(int idx);
    bool DeleteTool(int tool_id);
    bool DeleteByIndex(int tool_id);
    size_t GetToolCount() const;
    int GetToolPos(int tool_id) const;
    int GetToolIndex(int tool_id) const;
    bool GetToolFits(int tool_id) const;
    wxRect GetToolRect(int tool_id) const;
    bool GetToolFitsByIndex(int tool_id) const;
    bool GetToolBarFits() const;
    void SetMargins(const wxSize& size);
    void SetMargins(int x, int y);
    void SetMargins(int left, int right, int top, int bottom);
    void SetToolBitmapSize(const wxSize& size);
    wxSize GetToolBitmapSize() const;
    bool GetOverflowVisible() const;
    void SetOverflowVisible(bool visible);
    bool GetGripperVisible() const;
    void SetGripperVisible(bool visible);
    void ToggleTool(int tool_id, bool state);
    bool GetToolToggled(int tool_id) const;
    void EnableTool(int tool_id, bool state);
    bool GetToolEnabled(int tool_id) const;
    void SetToolDropDown(int tool_id, bool dropdown);
    bool GetToolDropDown(int tool_id) const;
    void SetToolBorderPadding(int padding);
    int  GetToolBorderPadding() const;
    void SetToolTextOrientation(int orientation);
    int  GetToolTextOrientation() const;
    void SetToolPacking(int packing);
    int  GetToolPacking() const;
    void SetToolProportion(int tool_id, int proportion);
    int  GetToolProportion(int tool_id) const;
    void SetToolSeparation(int separation);
    int GetToolSeparation() const;
    void SetToolSticky(int tool_id, bool sticky);
    bool GetToolSticky(int tool_id) const;
    wxString GetToolLabel(int tool_id) const;
    void SetToolLabel(int tool_id, const wxString& label);
    wxBitmap GetToolBitmap(int tool_id) const;
    void SetToolBitmap(int tool_id, const wxBitmap& bitmap);
    wxString GetToolShortHelp(int tool_id) const;
    void SetToolShortHelp(int tool_id, const wxString& help_string);
    wxString GetToolLongHelp(int tool_id) const;
    void SetToolLongHelp(int tool_id, const wxString& help_string);
    void SetCustomOverflowItems(const wxAuiToolBarItemArray& prepend, const wxAuiToolBarItemArray& append);
};


// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

//#include "wx/aui/auibook.h" // already included by aui.h

enum wxAuiNotebookOption
{
    wxAUI_NB_TOP,
    wxAUI_NB_LEFT,                 // not implemented yet
    wxAUI_NB_RIGHT,                // not implemented yet
    wxAUI_NB_BOTTOM,               // not implemented yet
    wxAUI_NB_TAB_SPLIT,
    wxAUI_NB_TAB_MOVE,
    wxAUI_NB_TAB_EXTERNAL_MOVE,
    wxAUI_NB_TAB_FIXED_WIDTH,
    wxAUI_NB_SCROLL_BUTTONS,
    wxAUI_NB_WINDOWLIST_BUTTON,
    wxAUI_NB_CLOSE_BUTTON,
    wxAUI_NB_CLOSE_ON_ACTIVE_TAB,
    wxAUI_NB_CLOSE_ON_ALL_TABS,
    %wxchkver_2_8_6 wxAUI_NB_MIDDLE_CLICK_CLOSE,

    wxAUI_NB_DEFAULT_STYLE //= wxAUI_NB_TOP|wxAUI_NB_TAB_SPLIT|wxAUI_NB_TAB_MOVE|wxAUI_NB_SCROLL_BUTTONS|wxAUI_NB_CLOSE_ON_ACTIVE_TAB|wxAUI_NB_MIDDLE_CLICK_CLOSE
};


// ---------------------------------------------------------------------------
// wxAuiNotebookEvent

class %delete wxAuiNotebookEvent : public wxNotifyEvent
{
    %wxEventType wxEVT_COMMAND_AUINOTEBOOK_PAGE_CLOSE      // EVT_AUINOTEBOOK_PAGE_CLOSE(winid, fn);
    %wxEventType wxEVT_COMMAND_AUINOTEBOOK_PAGE_CHANGED    // EVT_AUINOTEBOOK_PAGE_CHANGED(winid, fn);
    %wxEventType wxEVT_COMMAND_AUINOTEBOOK_PAGE_CHANGING   // EVT_AUINOTEBOOK_PAGE_CHANGING(winid, fn);
    %wxEventType wxEVT_COMMAND_AUINOTEBOOK_BUTTON          // EVT_AUINOTEBOOK_BUTTON(winid, fn);
    %wxEventType wxEVT_COMMAND_AUINOTEBOOK_BEGIN_DRAG      // EVT_AUINOTEBOOK_BEGIN_DRAG(winid, fn);
    %wxEventType wxEVT_COMMAND_AUINOTEBOOK_END_DRAG        // EVT_AUINOTEBOOK_END_DRAG(winid, fn);
    %wxEventType wxEVT_COMMAND_AUINOTEBOOK_DRAG_MOTION     // EVT_AUINOTEBOOK_DRAG_MOTION(winid, fn);
    %wxEventType wxEVT_COMMAND_AUINOTEBOOK_ALLOW_DND       // EVT_AUINOTEBOOK_ALLOW_DND(winid, fn);

    %wxchkver_3_0_0 %wxEventType wxEVT_AUINOTEBOOK_PAGE_CLOSE    // wx3.0 alias for wxEVT_COMMAND_AUINOTEBOOK_PAGE_CLOSE
    %wxchkver_3_0_0 %wxEventType wxEVT_AUINOTEBOOK_PAGE_CHANGED  // wx3.0 alias for wxEVT_COMMAND_AUINOTEBOOK_PAGE_CHANGED
    %wxchkver_3_0_0 %wxEventType wxEVT_AUINOTEBOOK_PAGE_CHANGING // wx3.0 alias for wxEVT_COMMAND_AUINOTEBOOK_PAGE_CHANGING
    %wxchkver_3_0_0 %wxEventType wxEVT_AUINOTEBOOK_BUTTON        // wx3.0 alias for wxEVT_COMMAND_AUINOTEBOOK_BUTTON
    %wxchkver_3_0_0 %wxEventType wxEVT_AUINOTEBOOK_BEGIN_DRAG    // wx3.0 alias for wxEVT_COMMAND_AUINOTEBOOK_BEGIN_DRAG
    %wxchkver_3_0_0 %wxEventType wxEVT_AUINOTEBOOK_END_DRAG      // wx3.0 alias for wxEVT_COMMAND_AUINOTEBOOK_END_DRAG
    %wxchkver_3_0_0 %wxEventType wxEVT_AUINOTEBOOK_DRAG_MOTION   // wx3.0 alias for wxEVT_COMMAND_AUINOTEBOOK_DRAG_MOTION
    %wxchkver_3_0_0 %wxEventType wxEVT_AUINOTEBOOK_ALLOW_DND     // wx3.0 alias for wxEVT_COMMAND_AUINOTEBOOK_ALLOW_DND

#if %wxchkver_2_8_5
    %wxEventType wxEVT_COMMAND_AUINOTEBOOK_TAB_MIDDLE_DOWN // EVT_AUINOTEBOOK_TAB_MIDDLE_DOWN(winid, fn);
    %wxEventType wxEVT_COMMAND_AUINOTEBOOK_TAB_MIDDLE_UP   // EVT_AUINOTEBOOK_TAB_MIDDLE_UP(winid, fn);
    %wxEventType wxEVT_COMMAND_AUINOTEBOOK_TAB_RIGHT_DOWN  // EVT_AUINOTEBOOK_TAB_RIGHT_DOWN(winid, fn);
    %wxEventType wxEVT_COMMAND_AUINOTEBOOK_TAB_RIGHT_UP    // EVT_AUINOTEBOOK_TAB_RIGHT_UP(winid, fn);
    %wxEventType wxEVT_COMMAND_AUINOTEBOOK_PAGE_CLOSED     //
    %wxEventType wxEVT_COMMAND_AUINOTEBOOK_DRAG_DONE       // EVT_AUINOTEBOOK_DRAG_DONE(winid, fn);
    %wxEventType wxEVT_COMMAND_AUINOTEBOOK_BG_DCLICK       // EVT_AUINOTEBOOK_BG_DCLICK(winid, fn);
#endif //%wxchkver_2_8_5

    %wxchkver_3_0_0 %wxEventType wxEVT_AUINOTEBOOK_TAB_MIDDLE_DOWN  // wx3.0 alias for wxEVT_COMMAND_AUINOTEBOOK_TAB_MIDDLE_DOWN
    %wxchkver_3_0_0 %wxEventType wxEVT_AUINOTEBOOK_TAB_MIDDLE_UP  // wx3.0 alias for wxEVT_COMMAND_AUINOTEBOOK_TAB_MIDDLE_UP
    %wxchkver_3_0_0 %wxEventType wxEVT_AUINOTEBOOK_TAB_RIGHT_DOWN  // wx3.0 alias for wxEVT_COMMAND_AUINOTEBOOK_TAB_RIGHT_DOWN
    %wxchkver_3_0_0 %wxEventType wxEVT_AUINOTEBOOK_TAB_RIGHT_UP  // wx3.0 alias for wxEVT_COMMAND_AUINOTEBOOK_TAB_RIGHT_UP
    %wxchkver_3_0_0 %wxEventType wxEVT_AUINOTEBOOK_PAGE_CLOSED  // wx3.0 alias for wxEVT_COMMAND_AUINOTEBOOK_PAGE_CLOSED
    %wxchkver_3_0_0 %wxEventType wxEVT_AUINOTEBOOK_DRAG_DONE  // wx3.0 alias for wxEVT_COMMAND_AUINOTEBOOK_DRAG_DONE
    %wxchkver_3_0_0 %wxEventType wxEVT_AUINOTEBOOK_BG_DCLICK  // wx3.0 alias for wxEVT_COMMAND_AUINOTEBOOK_BG_DCLICK

    wxAuiNotebookEvent(wxEventType command_type = wxEVT_NULL, int win_id = 0);
    wxAuiNotebookEvent(const wxAuiNotebookEvent& c);

    void SetSelection(int s);
    int GetSelection() const;

    void SetOldSelection(int s);
    int GetOldSelection() const;

    void SetDragSource(wxAuiNotebook* s);
    wxAuiNotebook* GetDragSource() const;
};


// ---------------------------------------------------------------------------
// wxAuiNotebookPage

class %delete wxAuiNotebookPage
{
    wxWindow* window;     // page's associated window
    wxString caption;     // caption displayed on the tab
    wxBitmap bitmap;      // tab's bitmap
    wxRect rect;          // tab's hit rectangle
    bool active;          // true if the page is currently active
};


// ---------------------------------------------------------------------------
// wxAuiNotebookPageArray

class %delete wxAuiNotebookPageArray
{
    wxAuiNotebookPageArray();
    wxAuiNotebookPageArray(const wxAuiNotebookPageArray& array);

    void Add(wxAuiNotebookPage* page);
    void Clear();
    int  GetCount() const;
    void Insert(wxAuiNotebookPage* page, int nIndex);
    bool IsEmpty();
    wxAuiNotebookPage Item(size_t nIndex) const;
    void RemoveAt(size_t nIndex);
};


// ---------------------------------------------------------------------------
// wxAuiTabContainerButton

class %delete wxAuiTabContainerButton
{
    int id;               // button's id
    !%wxchkver_2_9_3 int cur_state;        // current state (normal, hover, pressed, etc.);
    %wxchkver_2_9_3  int curState;
    int location;         // buttons location (wxLEFT, wxRIGHT, or wxCENTER);
    wxBitmap bitmap;      // button's hover bitmap
    !%wxchkver_2_9_3 wxBitmap dis_bitmap;  // button's disabled bitmap
    %wxchkver_2_9_3  wxBitmap disBitmap;
    wxRect rect;          // button's hit rectangle
};

//WX_DECLARE_USER_EXPORTED_OBJARRAY(wxAuiTabContainerButton, wxAuiTabContainerButtonArray, WXDLLIMPEXP_AUI);


// ---------------------------------------------------------------------------
// wxAuiTabArt

class %delete wxAuiTabArt
{
    // wxAuiTabArt(); // no constructor as it's an abstract class
    %gc virtual wxAuiTabArt* Clone(); //= 0;
    virtual void DrawBackground(wxDC& dc, wxWindow* wnd, const wxRect& rect); //= 0;
    virtual void DrawButton(wxDC& dc, wxWindow* wnd, const wxRect& in_rect, int bitmap_id, int button_state, int orientation, wxRect* out_rect); //= 0;
    virtual int GetBestTabCtrlSize(wxWindow* wnd, const wxAuiNotebookPageArray& pages, const wxSize& required_bmp_size); //= 0;
    virtual int GetIndentSize(); //= 0;
    virtual void SetFlags(unsigned int flags); //= 0;
    virtual void SetMeasuringFont(const wxFont& font); //= 0;
    virtual void SetNormalFont(const wxFont& font); //= 0;
    virtual void SetSelectedFont(const wxFont& font); //= 0;
    %wxchkver_3_0_0 void SetColour(const wxColour& colour);
    %wxchkver_3_0_0 void SetActiveColour(const wxColour& colour);
    virtual void SetSizingInfo(const wxSize& tab_ctrl_size, size_t tab_count); //= 0;
    virtual int ShowDropDown(wxWindow* wnd, const wxAuiNotebookPageArray& items, int active_idx); // %add as it's missing from auibook.h
    virtual void DrawTab(wxDC& dc, wxWindow* wnd, const wxAuiNotebookPage& pane, const wxRect& in_rect, int close_button_state, wxRect* out_tab_rect, wxRect* out_button_rect, int* x_extent); // %add as it's missing from auibook.h
    virtual wxSize GetTabSize(wxDC& dc, wxWindow* wnd, const wxString& caption, const wxBitmap& bitmap, bool active, int close_button_state, int* x_extent); // %add as it's missing from auibook.h
};


// ---------------------------------------------------------------------------
// wxAuiDefaultTabArt

class %delete wxAuiDefaultTabArt : public wxAuiTabArt
{
    wxAuiDefaultTabArt();
};


// ---------------------------------------------------------------------------
// wxAuiGenericTabArt

class %delete wxAuiGenericTabArt : public wxAuiTabArt
{
    wxAuiGenericTabArt();
};


// ---------------------------------------------------------------------------
// wxAuiSimpleTabArt

class %delete wxAuiSimpleTabArt : public wxAuiTabArt
{
    wxAuiSimpleTabArt();
};

// ---------------------------------------------------------------------------
// wxAuiTabContainer

//class %delete wxAuiTabContainer
//{
//    wxAuiTabContainer();
//
//    All methods put into wxAuiTabCtrl since this isn't the base class of anything else
//};


// ---------------------------------------------------------------------------
// wxAuiTabCtrl

class wxAuiTabCtrl : public wxControl //, public wxAuiTabContainer
{
    wxAuiTabCtrl(wxWindow* parent,  wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = 0);

    void SetArtProvider(%ungc wxAuiTabArt* art);
    wxAuiTabArt* GetArtProvider() const;

    void SetFlags(unsigned int flags);
    unsigned int GetFlags() const;

    bool AddPage(wxWindow* page, const wxAuiNotebookPage& info);
    bool InsertPage(wxWindow* page, const wxAuiNotebookPage& info, size_t idx);
    bool MovePage(wxWindow* page, size_t new_idx);
    bool RemovePage(wxWindow* page);
    bool SetActivePage(wxWindow* page);
    bool SetActivePage(size_t page);
    void SetNoneActive();
    int GetActivePage() const;
    wxWindow* TabHitTest(int x, int y) const; // %override returns [wxWindow*]
    wxAuiTabContainerButton* ButtonHitTest(int x, int y) const; // %override returns [wxAuiTabContainerButton*]
    wxWindow* GetWindowFromIdx(size_t idx) const;
    int GetIdxFromWindow(wxWindow* page) const;
    size_t GetPageCount() const;
    wxAuiNotebookPage& GetPage(size_t idx);
    const wxAuiNotebookPage& GetPage(size_t idx) const;
    wxAuiNotebookPageArray& GetPages();
    void SetNormalFont(const wxFont& normal_font);
    void SetSelectedFont(const wxFont& selected_font);
    void SetMeasuringFont(const wxFont& measuring_font);
    void DoShowHide();
    void SetRect(const wxRect& rect);

    void RemoveButton(int id);
    void AddButton(int id, int location, const wxBitmap& normal_bitmap = wxNullBitmap, const wxBitmap& disabled_bitmap = wxNullBitmap);

    size_t GetTabOffset() const;
    void SetTabOffset(size_t offset);

    %wxchkver_2_8_6 bool IsTabVisible(int tabPage, int tabOffset, wxDC* dc, wxWindow* wnd);
    %wxchkver_2_8_6 void MakeTabVisible(int tabPage, wxWindow* win);

    %wxchkver_2_8_5 bool IsDragging() const;
};


// ---------------------------------------------------------------------------
// wxAuiNotebook

class wxAuiNotebook : public wxControl
{
    wxAuiNotebook();
    wxAuiNotebook(wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxAUI_NB_DEFAULT_STYLE);
    bool AddPage(wxWindow* page, const wxString& caption, bool select = false, const wxBitmap& bitmap = wxNullBitmap);
    %wxchkver_3_0_0 bool AddPage(wxWindow *page, const wxString &text, bool select, int imageId);
    %wxchkver_2_8_5 void AdvanceSelection(bool forward = true); // Advances the selection, generates page selection events
    %wxchkver_3_0_0 int ChangeSelection(size_t n);
    bool Create(wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = 0);
    %wxchkver_3_0_0 bool DeleteAllPages();
    bool DeletePage(size_t page);
    wxAuiTabArt* GetArtProvider() const;
    wxWindow* GetCurrentPage () const;
    %wxchkver_2_8_5 int GetHeightForPageHeight(int pageHeight); // Gets the height of the notebook for a given page height
    wxWindow* GetPage(size_t page_idx) const;
    wxBitmap GetPageBitmap(size_t page_idx) const;
    size_t GetPageCount() const;
    int GetPageIndex(wxWindow* page_wnd) const;
    wxString GetPageText(size_t page_idx) const;
    %wxchkver_2_9_4 wxString GetPageToolTip(size_t pageIdx) const;
    int GetSelection() const;
    %wxchkver_2_8_5 int GetTabCtrlHeight() const; // Gets the tab control height
    bool InsertPage(size_t page_idx, wxWindow* page, const wxString& caption, bool select = false, const wxBitmap& bitmap = wxNullBitmap);
    %wxchkver_3_0_0 bool InsertPage(size_t index, wxWindow *page, const wxString &text, bool select=false, int imageId=-1);
    bool RemovePage(size_t page);
    void SetArtProvider(%ungc wxAuiTabArt* art);
    %wxchkver_2_8_5 virtual bool SetFont(const wxFont& font); // Sets the tab font
    %wxchkver_2_8_5 void SetMeasuringFont(const wxFont& font); // Sets the measuring font
    %wxchkver_2_8_5 void SetNormalFont(const wxFont& font); // Sets the normal font
    bool SetPageBitmap(size_t page, const wxBitmap& bitmap);
    %wxchkver_3_0_0 bool SetPageImage(size_t n, int imageId);
    bool SetPageText(size_t page, const wxString& text);
    %wxchkver_2_9_4 bool SetPageToolTip(size_t page, const wxString& text);
    %wxchkver_2_8_5 void SetSelectedFont(const wxFont& font); // Sets the selected tab font
    size_t SetSelection(size_t new_page);
    virtual void SetTabCtrlHeight(int height);
    virtual void SetUniformBitmapSize(const wxSize& size);
    virtual void Split(size_t page, int direction);
    %wxchkver_2_8_5 bool ShowWindowMenu(); // Shows the window menu
    %wxchkver_3_1_1 int GetPageImage(size_t nPage) const;
    %wxchkver_3_1_4 wxAuiTabCtrl* GetTabCtrlFromPoint(const wxPoint& pt);
    %wxchkver_3_1_4 wxAuiTabCtrl* GetActiveTabCtrl();
    %wxchkver_2_8_1 const wxAuiManager& GetAuiManager() const; // %add as it's missing from auibook.h
    %wxchkver_3_0 void AssignImageList(wxImageList *imageList); // %add as it's used by SetPageImage
    %wxchkver_3_0 void SetImageList(wxImageList *imageList); // %add as it's used by SetPageImage
    %wxchkver_3_0 wxImageList* GetImageList() const; // %add as it's used by SetPageImage
    %wxchkver_3_1_4 wxAuiTabCtrl* FindTab(wxWindow* page); // %override returns [wxAuiTabCtrl*, int]
    void SetWindowStyleFlag(long style); // %add as it's missing from auibook.h
};


// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

//#include "wx/aui/dockart.h"

// ---------------------------------------------------------------------------
// wxAuiDockArt

class %delete wxAuiDockArt
{
    // wxAuiDockArt(); // no constructor as it's an abstract class
    virtual void DrawBackground(wxDC& dc, wxWindow* window, int orientation, const wxRect& rect); //= 0;
    virtual void DrawBorder(wxDC& dc, wxWindow* window, const wxRect& rect, wxAuiPaneInfo& pane); //= 0;
    virtual void DrawCaption(wxDC& dc, wxWindow* window, const wxString& text, const wxRect& rect, wxAuiPaneInfo& pane); //= 0;
    virtual void DrawGripper(wxDC& dc, wxWindow* window, const wxRect& rect, wxAuiPaneInfo& pane); //= 0;
    virtual void DrawPaneButton(wxDC& dc, wxWindow* window, int button, int button_state, const wxRect& rect, wxAuiPaneInfo& pane); //= 0;
    virtual void DrawSash(wxDC& dc, wxWindow* window, int orientation, const wxRect& rect); //= 0;
    virtual wxColour GetColour(int id); //= 0;
    virtual wxFont GetFont(int id); //= 0;
    virtual int GetMetric(int id); //= 0;
    virtual void SetColour(int id, const wxColour& colour); //= 0;
    virtual void SetFont(int id, const wxFont& font); //= 0;
    virtual void SetMetric(int id, int new_val); //= 0;
    !%wxchkver_3_0_0 void SetColor(int id, const wxColour& color);
    !%wxchkver_3_0_0 wxColour GetColor(int id);
};


// ---------------------------------------------------------------------------
// wxAuiDefaultDockArt

class %delete wxAuiDefaultDockArt : public wxAuiDockArt
{
    wxAuiDefaultDockArt();
};


// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

//#include "wx/aui/floatpane.h"

// ---------------------------------------------------------------------------
// wxAuiFloatingFrame

class wxAuiFloatingFrame : public wxFrame // wxAuiFloatingFrameBaseClass
{
    wxAuiFloatingFrame(wxWindow* parent, wxAuiManager* owner_mgr, const wxAuiPaneInfo& pane, wxWindowID id = wxID_ANY, long style = wxRESIZE_BORDER|wxSYSTEM_MENU|wxCAPTION|wxFRAME_NO_TASKBAR | wxFRAME_FLOAT_ON_PARENT|wxCLIP_CHILDREN);
    void SetPaneWindow(const wxAuiPaneInfo& pane);
    wxAuiManager* GetOwnerManager() const;
    %wxchkver_3_1_5 wxAuiManager& GetAuiManager();
};


// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

//#include "wx/aui/framemanager.h"

enum wxAuiManagerDock
{
    wxAUI_DOCK_NONE,
    wxAUI_DOCK_TOP,
    wxAUI_DOCK_RIGHT,
    wxAUI_DOCK_BOTTOM,
    wxAUI_DOCK_LEFT,
    wxAUI_DOCK_CENTER,
    wxAUI_DOCK_CENTRE //= wxAUI_DOCK_CENTER
};

enum wxAuiManagerOption
{
    wxAUI_MGR_ALLOW_FLOATING,
    wxAUI_MGR_ALLOW_ACTIVE_PANE,
    wxAUI_MGR_TRANSPARENT_DRAG,
    wxAUI_MGR_TRANSPARENT_HINT,
    wxAUI_MGR_VENETIAN_BLINDS_HINT,
    wxAUI_MGR_RECTANGLE_HINT,
    wxAUI_MGR_HINT_FADE,
    wxAUI_MGR_NO_VENETIAN_BLINDS_FADE,

    wxAUI_MGR_DEFAULT, //= wxAUI_MGR_ALLOW_FLOATING | wxAUI_MGR_TRANSPARENT_HINT | wxAUI_MGR_HINT_FADE | wxAUI_MGR_NO_VENETIAN_BLINDS_FADE
};

enum wxAuiPaneDockArtSetting
{
    wxAUI_DOCKART_SASH_SIZE,
    wxAUI_DOCKART_CAPTION_SIZE,
    wxAUI_DOCKART_GRIPPER_SIZE,
    wxAUI_DOCKART_PANE_BORDER_SIZE,
    wxAUI_DOCKART_PANE_BUTTON_SIZE,
    wxAUI_DOCKART_BACKGROUND_COLOUR,
    wxAUI_DOCKART_SASH_COLOUR,
    wxAUI_DOCKART_ACTIVE_CAPTION_COLOUR,
    wxAUI_DOCKART_ACTIVE_CAPTION_GRADIENT_COLOUR,
    wxAUI_DOCKART_INACTIVE_CAPTION_COLOUR,
    wxAUI_DOCKART_INACTIVE_CAPTION_GRADIENT_COLOUR,
    wxAUI_DOCKART_ACTIVE_CAPTION_TEXT_COLOUR,
    wxAUI_DOCKART_INACTIVE_CAPTION_TEXT_COLOUR,
    wxAUI_DOCKART_BORDER_COLOUR,
    wxAUI_DOCKART_GRIPPER_COLOUR,
    wxAUI_DOCKART_CAPTION_FONT,
    wxAUI_DOCKART_GRADIENT_TYPE
};

enum wxAuiPaneDockArtGradients
{
    wxAUI_GRADIENT_NONE,
    wxAUI_GRADIENT_VERTICAL,
    wxAUI_GRADIENT_HORIZONTAL
};

enum wxAuiPaneButtonState
{
    wxAUI_BUTTON_STATE_NORMAL,
    wxAUI_BUTTON_STATE_HOVER,
    wxAUI_BUTTON_STATE_PRESSED,
    wxAUI_BUTTON_STATE_DISABLED,
    wxAUI_BUTTON_STATE_HIDDEN,
    wxAUI_BUTTON_STATE_CHECKED
};

enum wxAuiButtonId
{
    wxAUI_BUTTON_CLOSE,
    wxAUI_BUTTON_MAXIMIZE_RESTORE,
    wxAUI_BUTTON_MINIMIZE,
    wxAUI_BUTTON_PIN,
    wxAUI_BUTTON_OPTIONS,
    wxAUI_BUTTON_WINDOWLIST,
    wxAUI_BUTTON_LEFT,
    wxAUI_BUTTON_RIGHT,
    wxAUI_BUTTON_UP,
    wxAUI_BUTTON_DOWN,
    wxAUI_BUTTON_CUSTOM1,
    wxAUI_BUTTON_CUSTOM2,
    wxAUI_BUTTON_CUSTOM3
};

enum wxAuiPaneInsertLevel
{
    wxAUI_INSERT_PANE,
    wxAUI_INSERT_ROW,
    wxAUI_INSERT_DOCK
};


//WX_DECLARE_USER_EXPORTED_OBJARRAY(wxAuiDockInfo, wxAuiDockInfoArray, WXDLLIMPEXP_AUI);
//WX_DECLARE_USER_EXPORTED_OBJARRAY(wxAuiDockUIPart, wxAuiDockUIPartArray, WXDLLIMPEXP_AUI);
//WX_DECLARE_USER_EXPORTED_OBJARRAY(wxAuiPaneButton, wxAuiPaneButtonArray, WXDLLIMPEXP_AUI);
//WX_DECLARE_USER_EXPORTED_OBJARRAY(wxAuiPaneInfo, wxAuiPaneInfoArray, WXDLLIMPEXP_AUI);
//WX_DEFINE_USER_EXPORTED_ARRAY_PTR(wxAuiPaneInfo*, wxAuiPaneInfoPtrArray, class WXDLLIMPEXP_AUI);
//WX_DEFINE_USER_EXPORTED_ARRAY_PTR(wxAuiDockInfo*, wxAuiDockInfoPtrArray, class WXDLLIMPEXP_AUI);

// ---------------------------------------------------------------------------
// wxAuiPaneInfo

// NOTE: You can add and subtract flags from this list,
// but do not change the values of the flags, because
// they are stored in a binary integer format in the
// perspective string.  If you really need to change the
// values around, you'll have to ensure backwards-compatibility
// in the perspective loading code.
enum wxAuiPaneInfo::wxAuiPaneState
{
    optionFloating,
    optionHidden,
    optionLeftDockable,
    optionRightDockable,
    optionTopDockable,
    optionBottomDockable,
    optionFloatable,
    optionMovable,
    optionResizable,
    optionPaneBorder,
    optionCaption,
    optionGripper,
    optionDestroyOnClose,
    optionToolbar,
    optionActive,
    optionGripperTop,
    optionMaximized,

    buttonClose,
    buttonMaximize,
    buttonMinimize,
    buttonPin,

    buttonCustom1,
    buttonCustom2,
    buttonCustom3,

    savedHiddenState,       // used internally
    actionPane             // used internally
};


class %delete wxAuiPaneInfo
{
    #define_object wxAuiNullPaneInfo

    wxAuiPaneInfo();
    wxAuiPaneInfo(const wxAuiPaneInfo& c);

    wxAuiPaneInfo& operator=(const wxAuiPaneInfo& c);

    // Write the safe parts of a newly loaded PaneInfo structure "source" into "this"
    // used on loading perspectives etc.
    void SafeSet(wxAuiPaneInfo source);

    bool IsOk() const;
    bool IsFixed() const;
    bool IsResizable() const;
    bool IsShown() const;
    bool IsFloating() const;
    bool IsDocked() const;
    bool IsToolbar() const;
    bool IsTopDockable() const;
    bool IsBottomDockable() const;
    %wxchkver_2_9_2 bool IsDockable() const;
    bool IsLeftDockable() const;
    bool IsRightDockable() const;
    bool IsFloatable() const;
    bool IsMovable() const;
    bool IsDestroyOnClose() const;
    bool IsMaximized() const;
    bool HasCaption() const;
    bool HasGripper() const;
    bool HasBorder() const;
    bool HasCloseButton() const;
    bool HasMaximizeButton() const;
    bool HasMinimizeButton() const;
    bool HasPinButton() const;
    bool HasGripperTop() const;

    wxAuiPaneInfo& Window(wxWindow* w);
    wxAuiPaneInfo& Name(const wxString& n);
    wxAuiPaneInfo& Caption(const wxString& c);
    wxAuiPaneInfo& Left();
    wxAuiPaneInfo& Right();
    wxAuiPaneInfo& Top();
    wxAuiPaneInfo& Bottom();
    wxAuiPaneInfo& Center();
    wxAuiPaneInfo& Centre();
    wxAuiPaneInfo& Direction(int direction);
    wxAuiPaneInfo& Layer(int layer);
    wxAuiPaneInfo& Row(int row);
    wxAuiPaneInfo& Position(int pos);
    wxAuiPaneInfo& BestSize(const wxSize& size);
    wxAuiPaneInfo& MinSize(const wxSize& size);
    wxAuiPaneInfo& MaxSize(const wxSize& size);
    wxAuiPaneInfo& BestSize(int x, int y);
    wxAuiPaneInfo& MinSize(int x, int y);
    wxAuiPaneInfo& MaxSize(int x, int y);
    wxAuiPaneInfo& FloatingPosition(const wxPoint& pos);
    wxAuiPaneInfo& FloatingPosition(int x, int y);
    wxAuiPaneInfo& FloatingSize(const wxSize& size);
    wxAuiPaneInfo& FloatingSize(int x, int y);
    wxAuiPaneInfo& Fixed();
    wxAuiPaneInfo& Resizable(bool resizable = true);
    wxAuiPaneInfo& Dock();
    wxAuiPaneInfo& DockFixed(bool b = true);
    wxAuiPaneInfo& Float();
    wxAuiPaneInfo& Hide();
    %wxchkver_2_9_2 wxAuiPaneInfo& Icon(const wxBitmap& b);
    wxAuiPaneInfo& Show(bool show = true);
    wxAuiPaneInfo& CaptionVisible(bool visible = true);
    wxAuiPaneInfo& Maximize();
    wxAuiPaneInfo& Restore();
    wxAuiPaneInfo& PaneBorder(bool visible = true);
    wxAuiPaneInfo& Gripper(bool visible = true);
    wxAuiPaneInfo& GripperTop(bool attop = true);
    wxAuiPaneInfo& CloseButton(bool visible = true);
    wxAuiPaneInfo& MaximizeButton(bool visible = true);
    wxAuiPaneInfo& MinimizeButton(bool visible = true);
    wxAuiPaneInfo& PinButton(bool visible = true);
    wxAuiPaneInfo& DestroyOnClose(bool b = true);
    wxAuiPaneInfo& TopDockable(bool b = true);
    wxAuiPaneInfo& BottomDockable(bool b = true);
    wxAuiPaneInfo& LeftDockable(bool b = true);
    wxAuiPaneInfo& RightDockable(bool b = true);
    wxAuiPaneInfo& Floatable(bool b = true);
    wxAuiPaneInfo& Movable(bool b = true);

    wxAuiPaneInfo& Dockable(bool b = true);
    wxAuiPaneInfo& DefaultPane();

    wxAuiPaneInfo& CentrePane();
    wxAuiPaneInfo& CenterPane();

    wxAuiPaneInfo& ToolbarPane();
    wxAuiPaneInfo& SetFlag(unsigned int flag, bool option_state);
    bool HasFlag(unsigned int flag) const;

    wxString name;        // name of the pane
    wxString caption;     // caption displayed on the window

    wxWindow* window;     // window that is in this pane
    wxFrame* frame;       // floating frame window that holds the pane
    unsigned int state;   // a combination of wxPaneState values

    int dock_direction;   // dock direction (top, bottom, left, right, center);
    int dock_layer;       // layer number (0 = innermost layer);
    int dock_row;         // row number on the docking bar (0 = first row);
    int dock_pos;         // position inside the row (0 = first position);

    wxSize best_size;     // size that the layout engine will prefer
    wxSize min_size;      // minimum size the pane window can tolerate
    wxSize max_size;      // maximum size the pane window can tolerate

    wxPoint floating_pos; // position while floating
    wxSize floating_size; // size while floating
    int dock_proportion;  // proportion while docked

    //wxAuiPaneButtonArray buttons; // buttons on the pane

    wxRect rect;              // current rectangle (populated by wxAUI);
};


// ---------------------------------------------------------------------------
// wxAuiPaneInfoArray

class %delete wxAuiPaneInfoArray
{
    wxAuiPaneInfoArray();
    wxAuiPaneInfoArray(const wxAuiPaneInfoArray& array);

    void Add(wxAuiPaneInfo pi);
    void Clear();
    int  GetCount() const;
    //int  Index(wxAuiPaneInfo* page);
    void Insert(wxAuiPaneInfo pi, int nIndex);
    bool IsEmpty();
    wxAuiPaneInfo Item(size_t nIndex) const;
    void RemoveAt(size_t nIndex);
};


// ---------------------------------------------------------------------------
// wxAuiManager

class %delete wxAuiManager : public wxEvtHandler
{
    wxAuiManager(wxWindow* managed_wnd = NULL, unsigned int flags = wxAUI_MGR_DEFAULT);
    bool AddPane(wxWindow* window, const wxAuiPaneInfo& pane_info);
    bool AddPane(wxWindow* window, int direction = wxLEFT, const wxString& caption = wxEmptyString);
    bool AddPane(wxWindow* window, const wxAuiPaneInfo& pane_info, const wxPoint& drop_pos);
    %wxchkver_3_1_4 static bool AlwaysUsesLiveResize();
    wxRect CalculateHintRect(wxWindow* pane_window, const wxPoint& pt, const wxPoint& offset);
    %wxchkver_3_0_0 bool CanDockPanel(const wxAuiPaneInfo & p);
    void ClosePane(wxAuiPaneInfo& pane_info);
    virtual wxAuiFloatingFrame* CreateFloatingFrame(wxWindow* parent, const wxAuiPaneInfo& p);
    bool DetachPane(wxWindow* window);
    void DrawHintRect(wxWindow* pane_window, const wxPoint& pt, const wxPoint& offset);
    wxAuiPaneInfoArray& GetAllPanes();
    wxAuiDockArt* GetArtProvider() const;
    void GetDockSizeConstraint(double* width_pct, double* height_pct) const;
    unsigned int GetFlags() const;
    wxWindow* GetManagedWindow() const;
    static wxAuiManager* GetManager(wxWindow* window);
    wxAuiPaneInfo& GetPane(wxWindow* window);
    wxAuiPaneInfo& GetPane(const wxString& name);
    %wxchkver_3_1_4 bool HasLiveResize() const;
    virtual void HideHint();
    bool InsertPane(wxWindow* window, const wxAuiPaneInfo& insert_location, int insert_level = wxAUI_INSERT_PANE);
    void LoadPaneInfo(wxString pane_part, wxAuiPaneInfo &pane);
    bool LoadPerspective(const wxString& perspective, bool update = true);
    void MaximizePane(wxAuiPaneInfo& pane_info);
    void RestorePane(wxAuiPaneInfo& pane_info);
    void RestoreMaximizedPane();
    %wxchkver_3_1_1 wxString SavePaneInfo(const wxAuiPaneInfo& pane);
    wxString SavePerspective();
    void SetArtProvider(%ungc wxAuiDockArt* art_provider);
    void SetDockSizeConstraint(double width_pct, double height_pct);
    void SetFlags(unsigned int flags);
    void SetManagedWindow(wxWindow* managed_wnd);
    virtual void ShowHint(const wxRect& rect);
    void StartPaneDrag(wxWindow* pane_window, const wxPoint& offset);
    void UnInit();
    void Update();
    !%wxchkver_3_1_1 wxString SavePaneInfo(wxAuiPaneInfo& pane);
    void OnPaneButton(wxAuiManagerEvent& evt); // %add as it's missing from framemanager.h
    void OnRender(wxAuiManagerEvent& evt); // %add as it's missing from framemanager.h
};


// ---------------------------------------------------------------------------
// wxAuiManagerEvent

class %delete wxAuiManagerEvent : public wxEvent
{
    %wxEventType wxEVT_AUI_PANE_BUTTON     // EVT_AUI_PANE_BUTTON(func);
    %wxEventType wxEVT_AUI_PANE_CLOSE      // EVT_AUI_PANE_CLOSE(func);
    %wxEventType wxEVT_AUI_PANE_MAXIMIZE   // EVT_AUI_PANE_MAXIMIZE(func);
    %wxEventType wxEVT_AUI_PANE_RESTORE    // EVT_AUI_PANE_RESTORE(func);
    %wxchkver_2_9_4 %wxEventType wxEVT_AUI_PANE_ACTIVATED  // wxEVT_AUI_PANE_ACTIVATED(func);
    %wxEventType wxEVT_AUI_RENDER          // EVT_AUI_RENDER(func);
    %wxEventType wxEVT_AUI_FIND_MANAGER    // EVT_AUI_FIND_MANAGER(func);

    wxAuiManagerEvent(wxEventType type=wxEVT_NULL);
    wxAuiManagerEvent(const wxAuiManagerEvent& c);

    void SetManager(wxAuiManager* mgr);
    void SetPane(wxAuiPaneInfo* p);
    void SetButton(int b);
    void SetDC(wxDC* pdc);

    wxAuiManager* GetManager() const;
    wxAuiPaneInfo* GetPane() const;
    int GetButton() const;
    wxDC* GetDC() const;

    void Veto(bool veto = true);
    bool GetVeto() const;
    void SetCanVeto(bool can_veto);
    bool CanVeto() const;
};


// ---------------------------------------------------------------------------
// wxAuiDockInfo

class %delete wxAuiDockInfo
{
    #define_object wxAuiNullDockInfo

    wxAuiDockInfo();
    wxAuiDockInfo(const wxAuiDockInfo& c);

    wxAuiDockInfo& operator=(const wxAuiDockInfo& c);

    bool IsOk() const;
    bool IsHorizontal() const;
    bool IsVertical() const;


    //wxAuiPaneInfoPtrArray panes; // array of panes - FIXME
    wxRect rect;              // current rectangle
    int dock_direction;       // dock direction (top, bottom, left, right, center);
    int dock_layer;           // layer number (0 = innermost layer);
    int dock_row;             // row number on the docking bar (0 = first row);
    int size;                 // size of the dock
    int min_size;             // minimum size of a dock (0 if there is no min);
    bool resizable;           // flag indicating whether the dock is resizable
    bool toolbar;             // flag indicating dock contains only toolbars
    bool fixed;               // flag indicating that the dock operates on
                              // absolute coordinates as opposed to proportional
    bool reserved1;
};


// ---------------------------------------------------------------------------
// wxAuiDockUIPart

enum wxAuiDockUIPart::dummy
{
    typeCaption,
    typeGripper,
    typeDock,
    typeDockSizer,
    typePane,
    typePaneSizer,
    typeBackground,
    typePaneBorder,
    typePaneButton
};

class %delete wxAuiDockUIPart
{
    int type;                // ui part type (see enum above);
    int orientation;         // orientation (either wxHORIZONTAL or wxVERTICAL);
    wxAuiDockInfo* dock;     // which dock the item is associated with
    wxAuiPaneInfo* pane;     // which pane the item is associated with
    %wxchkver_3_1_4 int button;               // which pane button the item is associated with
    !%wxchkver_3_1_4 wxAuiPaneButton* button; // which pane button the item is associated with
    wxSizer* cont_sizer;     // the part's containing sizer
    wxSizerItem* sizer_item; // the sizer item of the part
    wxRect rect;             // client coord rectangle of the part itself
};


// ---------------------------------------------------------------------------
// wxAuiPaneButton
#if !%wxchkver_3_1_4
class %delete wxAuiPaneButton
{
    int button_id;        // id of the button (e.g. buttonClose);
};
#endif

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

//#include "wx/aui/tabmdi.h"

//-----------------------------------------------------------------------------
// wxAuiMDIParentFrame
//-----------------------------------------------------------------------------

class wxAuiMDIParentFrame : public wxFrame
{
    wxAuiMDIParentFrame();
    wxAuiMDIParentFrame(wxWindow *parent, wxWindowID winid, const wxString& title, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_FRAME_STYLE | wxVSCROLL | wxHSCROLL, const wxString& name = "wxAuiMDIParentFrame");

    bool Create(wxWindow *parent, wxWindowID winid, const wxString& title, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_FRAME_STYLE | wxVSCROLL | wxHSCROLL,const wxString& name = "wxAuiMDIParentFrame");

    void SetArtProvider(%ungc wxAuiTabArt* provider);
    wxAuiTabArt* GetArtProvider();
    wxAuiNotebook* GetNotebook() const;

    wxMenu* GetWindowMenu() const;
    void SetWindowMenu(wxMenu* pMenu);

    virtual void SetMenuBar(wxMenuBar *pMenuBar);

    void SetChildMenuBar(wxAuiMDIChildFrame *pChild);

    !%wxchkver_2_9_2 virtual bool ProcessEvent(wxEvent& event);

    wxAuiMDIChildFrame *GetActiveChild() const;
    void SetActiveChild(wxAuiMDIChildFrame* pChildFrame);

    wxAuiMDIClientWindow *GetClientWindow() const;
    virtual wxAuiMDIClientWindow *OnCreateClient();

    virtual void Cascade();      //{ /* Has no effect */ }
    virtual void Tile(wxOrientation orient = wxHORIZONTAL);
    virtual void ArrangeIcons(); //{ /* Has no effect */ }
    virtual void ActivateNext();
    virtual void ActivatePrevious();
};

//-----------------------------------------------------------------------------
// wxAuiMDIChildFrame
//-----------------------------------------------------------------------------

class wxAuiMDIChildFrame : public wxPanel
{
    wxAuiMDIChildFrame();
    wxAuiMDIChildFrame(wxAuiMDIParentFrame *parent, wxWindowID winid, const wxString& title, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_FRAME_STYLE, const wxString& name = "wxAuiMDIChildFrame");
    bool Create(wxAuiMDIParentFrame *parent, wxWindowID winid, const wxString& title, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_FRAME_STYLE, const wxString& name = "wxAuiMDIChildFrame");
    virtual void SetMenuBar(wxMenuBar *menu_bar);
    virtual wxMenuBar *GetMenuBar() const;
    virtual void SetTitle(const wxString& title);
    virtual wxString GetTitle() const;
    virtual void SetIcons(const wxIconBundle& icons);
    virtual const wxIconBundle& GetIcons() const;
    virtual void SetIcon(const wxIcon& icon);
    virtual const wxIcon& GetIcon() const;
    virtual void Activate();
    virtual bool Destroy();
    %wxchkver_3_1_1 bool Show(bool show = true);
    virtual wxStatusBar* CreateStatusBar(int number = 1, long style = 1, wxWindowID winid = 1, const wxString& name = "");
    virtual wxStatusBar *GetStatusBar() const;
    void SetStatusText(const wxString &text, int number=0);
    void SetStatusWidths(int n, const int widths_field[]);
    wxToolBar* CreateToolBar(long style, wxWindowID winid, const wxString& name);
    virtual wxToolBar *GetToolBar() const;
    %wxchkver_3_1_1 void Maximize(bool maximize = true);
    %wxchkver_3_1_1 void Restore();
    %wxchkver_3_1_1 void Iconize(bool iconize = true);
    virtual bool IsMaximized() const;
    virtual bool IsIconized() const;
    bool ShowFullScreen(bool show, long style);
    virtual bool IsFullScreen() const;
    virtual bool IsTopLevel() const;
    void SetMDIParentFrame(wxAuiMDIParentFrame* parent);
    wxAuiMDIParentFrame* GetMDIParentFrame() const;
    !%wxchkver_3_1_1 void ApplyMDIChildFrameRect();
    !%wxchkver_3_1_1 void DoShow(bool show);
    //void OnActivate(wxActivateEvent& evt);
    //void OnCloseWindow(wxCloseEvent& evt);
    //void OnMenuHighlight(wxMenuEvent& evt);
};

//-----------------------------------------------------------------------------
// wxAuiMDIClientWindow
//-----------------------------------------------------------------------------

class wxAuiMDIClientWindow : public wxAuiNotebook
{
    wxAuiMDIClientWindow();
    wxAuiMDIClientWindow(wxAuiMDIParentFrame *parent, long style = 0);

    virtual bool CreateClient(wxAuiMDIParentFrame *parent, long style = wxVSCROLL | wxHSCROLL);

    virtual int SetSelection(size_t page);
};

#endif // wxLUA_USE_wxAUI && %wxchkver_2_8 && wxUSE_AUI
