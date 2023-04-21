// ===========================================================================
// Purpose:     wxMenu and wxToolbar classes
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

// ---------------------------------------------------------------------------
// wxMenu

#if wxLUA_USE_wxMenu && wxUSE_MENUS

#include "wx/menu.h"

enum wxItemKind
{
   wxITEM_SEPARATOR,
   wxITEM_NORMAL,
   wxITEM_CHECK,
   wxITEM_RADIO,
   wxITEM_MAX
};

#define wxMB_DOCKABLE
#define wxMENU_TEAROFF

class %delete wxMenu : public wxEvtHandler
{
    %wxchkver_3_0_0 wxMenu();
    %wxchkver_3_0_0 wxMenu(long style);
    wxMenu(const wxString& title = "", long style = 0);
    wxMenuItem* Append(int id, const wxString& item, const wxString& helpString = "", wxItemKind kind = wxITEM_NORMAL);
    wxMenuItem* Append(int id, const wxString& item, %ungc wxMenu *subMenu, const wxString& helpString = "");
    wxMenuItem* Append(%ungc wxMenuItem* menuItem);
    wxMenuItem* AppendCheckItem(int id, const wxString& item, const wxString& help = "");
    wxMenuItem* AppendRadioItem(int id, const wxString& item, const wxString& help = "");
    wxMenuItem* AppendSeparator();
    wxMenuItem* AppendSubMenu(%ungc wxMenu *submenu, const wxString& text, const wxString& help = "");
    void Break();
    void Check(int id, bool check);
    void Delete(int id);
    void Delete(wxMenuItem *item);
    void Destroy(int id);
    void Destroy(wxMenuItem *item);
    void Enable(int id, bool enable);
    %wxchkver_3_0_0 wxMenuItem *FindChildItem(int id, size_t *pos = NULL) const;
    int FindItem(const wxString& itemString) const;
    // C++ Func: wxMenuItem* FindItem(int id, wxMenu **menu = NULL) const;
    wxMenuItem* FindItemByPosition(size_t position) const;
    wxString GetHelpString(int id) const;
    wxString GetLabel(int id) const;
    %wxchkver_3_0_0 wxString GetLabelText(int id) const;
    size_t GetMenuItemCount() const;
    wxMenuItemList& GetMenuItems() const;
    wxString GetTitle() const;
    wxMenuItem* Insert(size_t pos, %ungc wxMenuItem *menuItem);
    wxMenuItem* Insert(size_t pos, int id, const wxString& item, const wxString& helpString = "", wxItemKind kind = wxITEM_NORMAL);
    %wxchkver_3_0_0 wxMenuItem* Insert(size_t pos, int id, const wxString& text, wxMenu* submenu, const wxString& help = wxEmptyString);
    wxMenuItem* InsertCheckItem(size_t pos, int id, const wxString& item, const wxString& helpString = "");
    wxMenuItem* InsertRadioItem(size_t pos, int id, const wxString& item, const wxString& helpString = "");
    wxMenuItem* InsertSeparator(size_t pos);
    bool IsChecked(int id) const;
    bool IsEnabled(int id) const;
    wxMenuItem* Prepend(%ungc wxMenuItem *item);
    wxMenuItem* Prepend(int id, const wxString& item, const wxString& helpString = "", wxItemKind kind = wxITEM_NORMAL);
    %wxchkver_3_0_0 wxMenuItem* Prepend(int id, const wxString& text, wxMenu* submenu, const wxString& help = wxEmptyString);
    wxMenuItem* PrependCheckItem(int id, const wxString& item, const wxString& helpString = "");
    wxMenuItem* PrependRadioItem(int id, const wxString& item, const wxString& helpString = "");
    wxMenuItem* PrependSeparator();
    %gc wxMenuItem* Remove(int id);
    %gc wxMenuItem* Remove(wxMenuItem *item);
    void SetHelpString(int id, const wxString& helpString);
    void SetLabel(int id, const wxString& label);
    void SetTitle(const wxString& title);
    void UpdateUI(wxEvtHandler* source = NULL);
    %wxchkver_3_0_0 void SetInvokingWindow(wxWindow *win);
    %wxchkver_3_0_0 wxWindow *GetInvokingWindow() const;
    %wxchkver_3_0_0 wxWindow *GetWindow() const;
    %wxchkver_3_0_0 long GetStyle() const;
    %wxchkver_3_0_0 void SetParent(wxMenu *parent);
    %wxchkver_3_0_0 wxMenu *GetParent() const;
    %wxchkver_3_0_0 virtual void Attach(wxMenuBar *menubar);
    %wxchkver_3_0_0 virtual void Detach();
    %wxchkver_3_0_0 bool IsAttached() const;
    %override_name wxLua_wxCreateMenu_constructor wxMenu(LuaTable, const wxString& title = "", long style = 0);
    %override_name wxLua_wxMenu_FindItemById wxMenuItem* FindItem(int id) const;
    // %override [wxMenuItem* menuItem, wxMenu* ownerMenu] wxMenu::FindItem(int id);
};

// ---------------------------------------------------------------------------
// wxMenuBar

class wxMenuBar : public wxWindow
{
    wxMenuBar(long style = 0);
    // wxMenuBar(size_t n, wxMenu* menus[], const wxString titles[], long style = 0); // not implemented
    bool Append(%ungc wxMenu *menu, const wxString& title);
    void Check(int id, bool check);
    void Enable(int id, bool enable);
    %wxchkver_2_9_4 bool IsEnabledTop(size_t pos) const;
    void EnableTop(size_t pos, bool enable);
    wxMenuItem* FindItem(int id, wxMenu **menu = NULL) const;
    int FindMenu(const wxString& title) const;
    int FindMenuItem(const wxString& menuString, const wxString& itemString) const;
    wxString GetHelpString(int id) const;
    wxString GetLabel(int id) const;
    // wxString GetLabelTop(size_t pos) const; // deprecated
    %wxchkver_2_9_4 wxMenu* GetMenu(size_t menuIndex) const;
    int GetMenuCount() const;
    %wxchkver_3_0 wxString GetMenuLabel(size_t pos) const;
    %wxchkver_3_0 wxString GetMenuLabelText(size_t pos) const;
    bool Insert(size_t pos, %ungc wxMenu *menu, const wxString& title);
    bool IsChecked(int id) const;
    bool IsEnabled(int id) const;
    void Refresh(bool eraseBackground = true, const wxRect* rect = NULL);
    %gc wxMenu* Remove(size_t pos);
    %gc wxMenu* Replace(size_t pos, %ungc wxMenu *menu, const wxString& title);
    void SetHelpString(int id, const wxString& helpString);
    void SetLabel(int id, const wxString& label);
    // SetLabelTop(size_t pos, const wxString& label); // deprecated
    %wxchkver_3_0 void SetMenuLabel(size_t pos, const wxString& label);
    %mac static void SetAutoWindowMenu(bool enable);
    %mac static bool GetAutoWindowMenu();
    %wxchkver_3_1 && %mac void MacUninstallMenuBar();
    %mac void MacInstallMenuBar();
    %mac static wxMenuBar* MacGetInstalledMenuBar();
    %mac static void MacSetCommonMenuBar(wxMenuBar* menubar);
    %mac static wxMenuBar* MacGetCommonMenuBar();
    %wxchkver_3_0_1 && %mac wxMenu *OSXGetAppleMenu() const;
    wxFrame *GetFrame() const;
    bool IsAttached() const;
    void Attach(wxFrame *frame);
    void Detach();
    !%wxchkver_2_9_4 && %wxchkver_2_8 virtual void UpdateMenus();
    !%wxchkver_2_9_4 || %wxcompat_2_8 void SetLabelTop(int pos, const wxString& label);
    !%wxchkver_2_9_4 || %wxcompat_2_8 wxString GetLabelTop(int pos) const;
};

// ---------------------------------------------------------------------------
// wxMenuItem
//
// Note: this is almost always owned by a wxMenu, however you can get an
// unattached one from wxMenu::Remove() so that's why we gc collect it.


#include "wx/menuitem.h"

class %delete wxMenuItem : public wxObject
{
    %ungc_this wxMenuItem(wxMenu *parentMenu = NULL, int id = wxID_SEPARATOR, const wxString& text = "", const wxString& help = "", wxItemKind kind = wxITEM_NORMAL, wxMenu *subMenu = NULL);
    virtual void Check(bool check = true);
    virtual void Enable(bool enable = true);
    !%wxchkver_3_0 || %wxcompat_2_8 static wxString GetLabelFromText(const wxString& text);
    %wxchkver_2_8 static wxString GetLabelText(const wxString& text);
    %win wxColour GetBackgroundColour() const;
    %win wxBitmap GetBitmap(bool checked = true) const;
    %win wxBitmap GetDisabledBitmap() const;
    %win wxFont GetFont() const;
    wxString GetHelp() const;
    int GetId() const;
    %wxchkver_2_8 wxString GetItemLabel() const;
    %wxchkver_2_8 wxString GetItemLabelText() const;
    wxItemKind GetKind() const;
    !%wxchkver_3_0 || %wxcompat_2_8 wxString GetLabel() const;
    %win int GetMarginWidth() const;
    wxMenu* GetMenu() const;
    !%wxchkver_3_0 || %wxcompat_2_8 wxString GetName() const;
    wxMenu* GetSubMenu() const;
    !%wxchkver_3_0 || %wxcompat_2_8 wxString GetText() const;
    %win wxColour& GetTextColour() const;
    // static wxAcceleratorEntry *GetAccelFromString(const wxString& label);
    wxUSE_ACCEL virtual wxAcceleratorEntry *GetAccel() const;
    %wxchkver_3_0_0 bool IsCheck() const;
    bool IsCheckable() const;
    bool IsChecked() const;
    bool IsEnabled() const;
    %wxchkver_3_0_0 bool IsRadio() const;
    bool IsSeparator() const;
    bool IsSubMenu() const;
    %win void SetBackgroundColour(const wxColour& colour) const;
    %win void SetBitmaps(const wxBitmap& checked, const wxBitmap& unchecked = wxNullBitmap) const;
    %win void SetDisabledBitmap(const wxBitmap& disabled);
    %win void SetFont(const wxFont& font) const;
    void SetHelp(const wxString& helpString) const;
    %wxchkver_2_8 void SetItemLabel(const wxString& label);
    %win void SetMarginWidth(int width) const;
    void SetMenu(wxMenu* menu);
    void SetSubMenu(wxMenu* menu);
    !%wxchkver_3_0 || %wxcompat_2_8 void SetText(const wxString& text);
    %win void SetTextColour(const wxColour& colour) const;
    wxUSE_ACCEL virtual void SetAccel(wxAcceleratorEntry *accel);
    virtual void SetCheckable(bool checkable); // %add as it's missing from the interface files
    void SetBitmap(const wxBitmap& bmp); // %override use one parameter as "bool checked = true" doesn't exist on OSX/Linux
    void SetId(int itemid); // %add as it's missing from the interface files
    void SetKind(wxItemKind kind); // %add as it's missing from the interface files
};

// ---------------------------------------------------------------------------
// wxMenuItemList

class wxMenuItemList : public wxList
{
    // no constructor, you only get this back from wxMenu::GetMenuItems

    // Use the wxList methods, see also wxNode
};

// ---------------------------------------------------------------------------
// wxMenuEvent

#include "wx/event.h"

class %delete wxMenuEvent : public wxEvent
{
    %wxEventType wxEVT_MENU_HIGHLIGHT  // EVT_MENU_HIGHLIGHT(winid, func) EVT_MENU_HIGHLIGHT_ALL(func);
    %wxEventType wxEVT_MENU_OPEN       // EVT_MENU_OPEN(func);
    %wxEventType wxEVT_MENU_CLOSE      // EVT_MENU_CLOSE(func);

    wxMenuEvent(wxEventType type = wxEVT_NULL, int id = 0, wxMenu* menu = NULL);
    wxMenu* GetMenu() const;
    int GetMenuId() const;
    bool IsPopup() const;
};

#endif //wxLUA_USE_wxMenu && wxUSE_MENUS

// ---------------------------------------------------------------------------
// wxToolBarBase

#if wxLUA_USE_wxToolbar

#include "wx/tbarbase.h"

#define wxTB_FLAT
#define wxTB_DOCKABLE
#define wxTB_HORIZONTAL
#define wxTB_VERTICAL
!%wxchkver_3_1 #define wxTB_3DBUTTONS
#define wxTB_TEXT
#define wxTB_NOICONS
#define wxTB_NODIVIDER
#define wxTB_NOALIGN
#define wxTB_HORZ_LAYOUT
#define wxTB_HORZ_TEXT

class wxToolBarBase : public wxControl
{
    // no constructors base class

    wxToolBarToolBase* AddControl(wxControl *control);
    wxToolBarToolBase* AddSeparator();
    wxToolBarToolBase* AddTool(int toolId, const wxString& label, const wxBitmap& bitmap1, const wxBitmap& bitmap2 = wxNullBitmap, wxItemKind kind = wxITEM_NORMAL, const wxString& shortHelpString = "", const wxString& longHelpString = "", wxObject* clientData = NULL);
    wxToolBarToolBase* AddTool(int toolId, const wxString& label, const wxBitmap& bitmap1, const wxString& shortHelpString = "", wxItemKind kind = wxITEM_NORMAL);
    //wxToolBarToolBase* AddTool(wxToolBarToolBase* tool);
    wxToolBarToolBase *AddCheckTool(int toolid, const wxString& label, const wxBitmap& bitmap, const wxBitmap& bmpDisabled = wxNullBitmap, const wxString& shortHelp = "", const wxString& longHelp = "", wxObject *data = NULL);
    wxToolBarToolBase *AddRadioTool(int toolid, const wxString& label, const wxBitmap& bitmap, const wxBitmap& bmpDisabled = wxNullBitmap, const wxString& shortHelp = "", const wxString& longHelp = "", wxObject *data = NULL);
    void ClearTools();
    bool DeleteTool(int toolId);
    bool DeleteToolByPos(size_t pos);
    void EnableTool(int toolId, const bool enable);
    wxToolBarToolBase* FindById(int id);
    wxControl* FindControl(int id);
    wxToolBarToolBase *FindToolForPosition(wxCoord x, wxCoord y) const;
    int     GetMaxRows();
    int     GetMaxCols();
    wxSize  GetToolSize();
    wxSize  GetToolBitmapSize();
    wxObject* GetToolClientData(int toolId) const;
    bool    GetToolEnabled(int toolId) const;
    wxString GetToolLongHelp(int toolId) const;
    wxSize  GetToolMargins(); // GetMargins is deprecated
    int     GetToolPacking();
    int     GetToolPos(int toolId) const;
    int     GetToolSeparation() const;
    wxString GetToolShortHelp(int toolId) const;
    bool    GetToolState(int id);
    wxToolBarToolBase* InsertControl(size_t pos, wxControl *control);
    wxToolBarToolBase* InsertSeparator(size_t pos);

    !%wxchkver_3_0 || %wxcompat_2_8 wxToolBarToolBase* InsertTool(size_t pos, int id, const wxBitmap& bitmap, const wxBitmap& pushedBitmap = wxNullBitmap, bool isToggle = false, wxObject *clientData = NULL, const wxString& shortHelpString = "", const wxString& longHelpString = "");

    wxToolBarToolBase* InsertTool(size_t pos, int toolid, const wxString& label, const wxBitmap& bitmap, const wxBitmap& bmpDisabled = wxNullBitmap, wxItemKind kind = wxITEM_NORMAL, const wxString& shortHelp = "", const wxString& longHelp = "", wxObject *clientData = NULL);

    //wxToolBarToolBase * InsertTool(size_t pos, wxToolBarToolBase* tool);
    wxToolBarToolBase* RemoveTool(int id);
    bool    Realize();
    void    SetMargins(int x, int y);
    void    SetMargins(const wxSize& size);
    void    SetToolBitmapSize(const wxSize& size);
    void    SetToolClientData(int id, wxObject* clientData);
    void    SetToolLongHelp(int toolId, const wxString& helpString);
    void    SetToolPacking(int packing);
    void    SetToolShortHelp(int id, const wxString& helpString);
    void    SetToolSeparation(int separation);
    void    SetToggle(int id, bool toggle);
    void    SetRows(int nRows);
    void    SetMaxRowsCols(int rows, int cols);
    void    ToggleTool(int toolId, const bool toggle);
};

// ---------------------------------------------------------------------------
// wxToolBar

#include "wx/toolbar.h"

class wxToolBar : public wxToolBarBase
{
    wxToolBar();
    wxToolBar(wxWindow *parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxNO_BORDER | wxTB_HORIZONTAL, const wxString &name = "wxToolBar");
    bool Create(wxWindow *parent,wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxNO_BORDER | wxTB_HORIZONTAL, const wxString &name = "wxToolBar");
};

// ---------------------------------------------------------------------------
// wxToolBarSimple

#if !%wxchkver_2_6

#include "wx/tbarsmpl.h"

class wxToolBarSimple : public wxToolBarBase
{
    wxToolBarSimple();
    wxToolBarSimple(wxWindow *parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxNO_BORDER | wxTB_HORIZONTAL, const wxString &name = wxToolBarNameStr);
    bool Create(wxWindow *parent,wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxNO_BORDER | wxTB_HORIZONTAL, const wxString &name = wxToolBarNameStr);
};

#endif // !%wxchkver_2_6

// ---------------------------------------------------------------------------
// wxToolBarToolBase

// these are unused
//#define wxTOOL_BOTTOM
//#define wxTOOL_LEFT
//#define wxTOOL_RIGHT
//#define wxTOOL_TOP

enum wxToolBarToolStyle
{
    wxTOOL_STYLE_BUTTON,
    wxTOOL_STYLE_SEPARATOR,
    wxTOOL_STYLE_CONTROL
};

class wxToolBarToolBase : public wxObject
{
    // no constructors

    int     GetId();
    wxControl *GetControl();
    wxToolBarBase *GetToolBar();
    int     IsButton();
    int     IsControl();
    int     IsSeparator();
    int     GetStyle();
    wxItemKind GetKind() const;
    bool    IsEnabled();
    bool    IsToggled();
    bool    CanBeToggled();
    wxBitmap GetNormalBitmap();
    wxBitmap GetDisabledBitmap();
    wxBitmap GetBitmap();
    wxString GetLabel();
    wxString GetShortHelp();
    wxString GetLongHelp();
    bool    Enable(bool enable);
    bool    Toggle(bool toggle);
    bool    SetToggle(bool toggle);
    bool    SetShortHelp(const wxString& help);
    bool    SetLongHelp(const wxString& help);
    void    SetNormalBitmap(const wxBitmap& bmp);
    void    SetDisabledBitmap(const wxBitmap& bmp);
    void    SetLabel(const wxString& label);
    void    Detach();
    void    Attach(wxToolBarBase *tbar);
    wxObject *GetClientData();
    void    SetClientData(wxObject* clientData);
};

// ---------------------------------------------------------------------------
// wxToolBarTool - This class doesn't exist!

//class wxToolBarTool : public wxToolBarToolBase
//{
//};

#endif //wxLUA_USE_wxToolbar


// ---------------------------------------------------------------------------
// wxAcceleratorTable

#if wxLUA_USE_wxAcceleratorTable && wxUSE_ACCEL

#include "wx/accel.h"

class %delete wxAcceleratorTable : public wxObject
{
    #define_object wxNullAcceleratorTable
    %wxchkver_2_8 bool IsOk() const;
    bool Ok() const; // %add for compatibility with earlier versions of wxlua
    wxAcceleratorTable(LuaTable accelTable); // %override wxAcceleratorTable(Lua table)
    wxAcceleratorTable(const wxAcceleratorTable& accel);
};

// ---------------------------------------------------------------------------
// wxAcceleratorEntry

%wxcompat_2_6 wxAcceleratorEntry* wxGetAccelFromString(const wxString& label); // deprecated in 2.8 use wxAcceleratorEntry::Create() or FromString();

#include "wx/accel.h"

enum
{
    wxACCEL_NORMAL,
    wxACCEL_ALT,
    wxACCEL_CTRL,
    wxACCEL_SHIFT,
    %wxchkver_2_8 wxACCEL_CMD // Command key on OS X else wxACCEL_CTRL
};

class %delete wxAcceleratorEntry
{
    wxAcceleratorEntry(int flags = 0, int keyCode = 0, int cmd = 0, wxMenuItem *item = NULL);
    wxAcceleratorEntry(const wxAcceleratorEntry& entry);
    int GetCommand() const;
    int GetFlags() const;
    int GetKeyCode() const;
    %wxchkver_2_8 wxMenuItem *GetMenuItem() const;
    void Set(int flags, int keyCode, int Cmd, wxMenuItem *item = NULL);
    %wxchkver_2_8 bool IsOk() const;
    %wxchkver_2_8 wxString ToString() const;
    %wxchkver_2_9_4 wxString ToRawString() const;
    %wxchkver_2_8 bool FromString(const wxString& str);
    wxAcceleratorEntry& operator=(const wxAcceleratorEntry& entry);
    bool operator==(const wxAcceleratorEntry& entry) const;
    bool operator!=(const wxAcceleratorEntry& entry) const;
    %wxchkver_2_8 static %gc wxAcceleratorEntry *Create(const wxString& str);
};

#endif //wxLUA_USE_wxAcceleratorTable && wxUSE_ACCEL
