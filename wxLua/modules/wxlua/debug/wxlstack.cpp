/////////////////////////////////////////////////////////////////////////////
// Name:        StackTree.cpp
// Purpose:     Display the Lua stack in a dialog.
// Author:      J. Winwood, John Labenski
// Created:     February 2002
// Copyright:   (c) 2012 John Labenski, 2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/wxprec.h>

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

#include <wx/imaglist.h>
#include <wx/artprov.h>
#include <wx/listctrl.h>
#include <wx/splitter.h>
#include <wx/progdlg.h>
#include <wx/clipbrd.h>

#include "wxlua/debug/wxlstack.h"
#include "wxlua/wxlua.h"
#include "wxlua/wxlcallb.h"
#include "wxlua/debug/wxldebug.h"

#if defined(__WXGTK__) || defined(__WXMAC__) || defined(__WXMOTIF__)
    #include "art/wxlua.xpm"
#endif

// Define our own flag to help track down where we've hacked thing to work
// equally well with the treectrl for MSW
#if defined(__WXMSW__)
    #define WXLUA_STACK_MSWTREE
#endif //defined(__WXMSW__)

#define DUMMY_TREEITEM wxT("  ")

// ----------------------------------------------------------------------------
// wxLuaStackListCtrl
// ----------------------------------------------------------------------------

class wxLuaStackListCtrl : public wxListCtrl
{
public:
    wxLuaStackListCtrl( wxLuaStackDialog* stkDialog,
                        wxWindow *parent,
                        wxWindowID winid = wxID_ANY,
                        const wxPoint& pos = wxDefaultPosition,
                        const wxSize& size = wxDefaultSize,
                        long style = wxLC_REPORT,
                        const wxValidator& validator = wxDefaultValidator,
                        const wxString &name = wxT("wxLuaStackListCtrl"))
        : wxListCtrl(parent, winid, pos, size, style, validator, name)
    {
        m_stkDlg = stkDialog;
    }

    // overridden wxListCtrl virtual functions
    virtual wxString OnGetItemText(long item, long column) const;
    virtual int OnGetItemImage(long item) const;
    virtual int OnGetItemColumnImage(long item, long column) const;
    virtual wxListItemAttr *OnGetItemAttr(long item) const;

    wxLuaStackDialog* m_stkDlg;
};

wxString wxLuaStackListCtrl::OnGetItemText(long item, long column) const
{
    return m_stkDlg->GetItemText(item, column);
}
int wxLuaStackListCtrl::OnGetItemImage(long item) const
{
    return -1; // use OnGetItemColumnImage()
}
int wxLuaStackListCtrl::OnGetItemColumnImage(long item, long column) const
{
    return m_stkDlg->GetItemColumnImage(item, column);
}
wxListItemAttr *wxLuaStackListCtrl::OnGetItemAttr(long item) const
{
    return m_stkDlg->GetItemAttr(item);
}

// ----------------------------------------------------------------------------
// wxLuaStackDialog
// ----------------------------------------------------------------------------
IMPLEMENT_ABSTRACT_CLASS(wxLuaStackDialog, wxDialog)

wxSize wxLuaStackDialog::sm_defaultSize(500, 300);
bool   wxLuaStackDialog::sm_maximized = false;

BEGIN_EVENT_TABLE(wxLuaStackDialog, wxDialog)
    EVT_CHOICE( ID_WXLUA_STACK_CHOICE, wxLuaStackDialog::OnSelectStack)

    EVT_BUTTON( ID_WXLUA_STACK_COLLAPSE_BUTTON, wxLuaStackDialog::OnExpandButton)
    EVT_BUTTON( ID_WXLUA_STACK_EXPAND_BUTTON,   wxLuaStackDialog::OnExpandButton)

    EVT_MENU( wxID_ANY, wxLuaStackDialog::OnMenu)

    EVT_TEXT_ENTER( ID_WXLUA_STACK_FIND_COMBO,  wxLuaStackDialog::OnFind)
    EVT_BUTTON( ID_WXLUA_STACK_FINDNEXT_BUTTON, wxLuaStackDialog::OnFind)
    EVT_BUTTON( ID_WXLUA_STACK_FINDPREV_BUTTON, wxLuaStackDialog::OnFind)
    EVT_BUTTON( ID_WXLUA_STACK_FINDMENU_BUTTON, wxLuaStackDialog::OnFind)

    EVT_TREE_ITEM_COLLAPSED(ID_WXLUA_STACK_TREECTRL, wxLuaStackDialog::OnTreeItem)
    EVT_TREE_ITEM_EXPANDED( ID_WXLUA_STACK_TREECTRL, wxLuaStackDialog::OnTreeItem)
    EVT_TREE_SEL_CHANGED(   ID_WXLUA_STACK_TREECTRL, wxLuaStackDialog::OnTreeItem)

    EVT_LIST_ITEM_SELECTED(    ID_WXLUA_STACK_LISTCTRL, wxLuaStackDialog::OnListItem)
    EVT_LIST_ITEM_ACTIVATED(   ID_WXLUA_STACK_LISTCTRL, wxLuaStackDialog::OnListItem)
    EVT_LIST_ITEM_RIGHT_CLICK( ID_WXLUA_STACK_LISTCTRL, wxLuaStackDialog::OnListRightClick)
END_EVENT_TABLE()

void wxLuaStackDialog::Init()
{
    m_listCtrl          = NULL;
    m_treeCtrl          = NULL;
    m_listMenu          = NULL;
    m_stackChoice       = NULL;
    m_stack_sel         = -1;
    m_findComboBox      = NULL;
    m_findMenu          = NULL;

    m_imageList         = NULL;
    m_img_font_size     = 15;   // largest font size we'll use is 14

    m_show_dup_expand_msg = true;
    m_batch_count         = 0;
}

bool wxLuaStackDialog::Create(const wxLuaState& wxlState,
                              wxWindow* parent, wxWindowID id,
                              const wxString& title,
                              const wxPoint& pos, const wxSize& size_)
{
    m_wxlState = wxlState;

    wxSize size(size_);

    if (!wxDialog::Create(parent, id, title, pos, size,
            wxDEFAULT_DIALOG_STYLE | wxMAXIMIZE_BOX | wxMINIMIZE_BOX | wxRESIZE_BORDER,
            wxT("wxLuaStackDialog")))
        return false;

    if (size == wxDefaultSize) size = sm_defaultSize;

    SetIcon(wxICON(LUA)); // set the frame icon

    // -----------------------------------------------------------------------

    m_imageList = new wxImageList(16, 16, true);

    wxBitmap bmp(wxArtProvider::GetIcon(wxART_NORMAL_FILE, wxART_TOOLBAR, wxSize(16,16)));
    m_imageList->Add(bmp); // IMG_NONE
    m_imageList->Add(bmp); // IMG_UNKNOWN
    m_imageList->Add(CreateBmpString(bmp, wxT("0"))); // IMG_NIL
    m_imageList->Add(CreateBmpString(bmp, wxT("b"))); // IMG_BOOLEAN
    m_imageList->Add(CreateBmpString(bmp, wxT("u"))); // IMG_LIGHTUSERDATA
    m_imageList->Add(CreateBmpString(bmp, wxT("1"))); // IMG_NUMBER
    m_imageList->Add(CreateBmpString(bmp, wxT("s"))); // IMG_STRING
    m_imageList->Add(wxArtProvider::GetIcon(wxART_FOLDER, wxART_TOOLBAR, wxSize(16,16))); // IMG_TABLE
    m_imageList->Add(CreateBmpString(bmp, wxT("f"))); // IMG_LUAFUNCTION
    m_imageList->Add(CreateBmpString(bmp, wxT("u"))); // IMG_USERDATA
    m_imageList->Add(CreateBmpString(bmp, wxT("t"))); // IMG_THREAD
    m_imageList->Add(CreateBmpString(bmp, wxT("1"))); // IMG_INTEGER
    m_imageList->Add(CreateBmpString(bmp, wxT("c"))); // IMG_CFUNCTION
    m_imageList->Add(wxArtProvider::GetIcon(wxART_NEW_DIR, wxART_TOOLBAR, wxSize(16,16))); // IMG_TABLE_OPEN

    // -----------------------------------------------------------------------

    m_typeColours[IMG_NONE]         = wxColour(wxT("DARK TURQUOISE"));
    m_typeColours[IMG_UNKNOWN]      = wxColour(wxT("DARK TURQUOISE"));
    m_typeColours[IMG_NIL]          = wxColour(wxT("BLACK"));
    m_typeColours[IMG_BOOLEAN]      = wxColour(wxT("FIREBRICK"));
    m_typeColours[IMG_LIGHTUSERDATA]= wxColour(wxT("CORNFLOWER BLUE"));
    m_typeColours[IMG_NUMBER]       = wxColour(wxT("DARK ORCHID"));
    m_typeColours[IMG_STRING]       = wxColour(wxT("RED"));
    m_typeColours[IMG_TABLE]        = wxColour(wxT("BLUE"));
    m_typeColours[IMG_LUAFUNCTION]  = wxColour(wxT("MEDIUM FOREST GREEN"));
    m_typeColours[IMG_USERDATA]     = wxColour(wxT("CORNFLOWER BLUE"));
    m_typeColours[IMG_THREAD]       = wxColour(wxT("BLACK"));
    m_typeColours[IMG_INTEGER]      = wxColour(wxT("DARK ORCHID"));
    m_typeColours[IMG_CFUNCTION]    = wxColour(wxT("FOREST GREEN"));
    m_typeColours[IMG_TABLE_OPEN]   = wxColour(wxT("BLUE"));

    // -----------------------------------------------------------------------

    wxPanel* panel = new wxPanel(this, wxID_ANY);

    // -----------------------------------------------------------------------

    wxStaticText* stackText = new wxStaticText( panel, wxID_ANY, wxT("Stack : "));

    m_stackChoice = new wxChoice( panel, ID_WXLUA_STACK_CHOICE,
                                  wxDefaultPosition, wxDefaultSize,
                                  0, NULL, 0, wxDefaultValidator ); // help GCC find which fn to call
    m_stackChoice->SetToolTip(wxT("Select Lua stack frame to display."));

    wxBitmapButton* expandButton = new wxBitmapButton(panel, ID_WXLUA_STACK_EXPAND_BUTTON,
                                          wxArtProvider::GetBitmap(wxART_ADD_BOOKMARK, wxART_BUTTON));
    expandButton->SetToolTip(wxT("Expand selected item's children (may take awhile)"));

    wxBitmapButton* collapseButton = new wxBitmapButton(panel, ID_WXLUA_STACK_COLLAPSE_BUTTON,
                                          wxArtProvider::GetBitmap(wxART_DEL_BOOKMARK, wxART_BUTTON));
    collapseButton->SetToolTip(wxT("Collapse selected item's children (may take awhile)"));

    // -----------------------------------------------------------------------

    wxStaticText* findText = new wxStaticText( panel, wxID_ANY, wxT("Find : "));
    m_findComboBox = new  wxComboBox( panel, ID_WXLUA_STACK_FIND_COMBO,
                                      wxEmptyString,
                                      wxDefaultPosition, wxDefaultSize,
                                      0, NULL, wxCB_DROPDOWN | wxTE_PROCESS_ENTER);
    m_findComboBox->SetToolTip(wxT("Enter string to find"));

    wxBitmapButton* findPrev = new wxBitmapButton( panel, ID_WXLUA_STACK_FINDPREV_BUTTON,
                                           wxArtProvider::GetBitmap(wxART_GO_BACK, wxART_BUTTON));
    wxBitmapButton* findNext = new wxBitmapButton( panel, ID_WXLUA_STACK_FINDNEXT_BUTTON,
                                           wxArtProvider::GetBitmap(wxART_GO_FORWARD, wxART_BUTTON));
    findPrev->SetToolTip(wxT("Find previous instance"));
    findNext->SetToolTip(wxT("Find next instance"));

    wxBitmapButton* findMenuButton = new wxBitmapButton(panel, ID_WXLUA_STACK_FINDMENU_BUTTON,
                                            wxArtProvider::GetBitmap(wxART_HELP_SETTINGS, wxART_BUTTON));
    findMenuButton->SetToolTip(wxT("Select find options"));

    m_findMenu = new wxMenu(wxT("Find Options"), 0);
    m_findMenu->Append(ID_WXLUA_STACK_FINDMENU_CASE,         wxT("&Case sensitive"),    wxT("Case sensitive searching"), wxITEM_CHECK);
    m_findMenu->Append(ID_WXLUA_STACK_FINDMENU_WHOLE_STRING, wxT("Match whole string"), wxT("Search for a string with an exact match"), wxITEM_CHECK);
    m_findMenu->AppendSeparator();
    m_findMenu->Append(ID_WXLUA_STACK_FINDMENU_ALL,       wxT("Search &everywhere"), wxT("Search in all columns"), wxITEM_CHECK);
    m_findMenu->Append(ID_WXLUA_STACK_FINDMENU_NAME,      wxT("Search &names"),      wxT("Search in name column"), wxITEM_CHECK);
    m_findMenu->Append(ID_WXLUA_STACK_FINDMENU_LEVEL,     wxT("Search &level"),      wxT("Search in level column"), wxITEM_CHECK);
    m_findMenu->Append(ID_WXLUA_STACK_FINDMENU_KEYTYPE,   wxT("Search &key type"),   wxT("Search in key type column"), wxITEM_CHECK);
    m_findMenu->Append(ID_WXLUA_STACK_FINDMENU_VALUETYPE, wxT("Search v&alue type"), wxT("Search in value type column"), wxITEM_CHECK);
    m_findMenu->Append(ID_WXLUA_STACK_FINDMENU_VALUE,     wxT("Search &values"),     wxT("Search in value column"), wxITEM_CHECK);

    m_findMenu->Check(ID_WXLUA_STACK_FINDMENU_NAME, true);

    // -----------------------------------------------------------------------

    wxFlexGridSizer* topSizer = new wxFlexGridSizer(2, 0, 0);
    topSizer->AddGrowableCol(1);

    topSizer->Add(stackText, wxSizerFlags().Expand().Border().Align(wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL));

    wxFlexGridSizer* stackSizer = new wxFlexGridSizer(3, 0, 0);
    stackSizer->AddGrowableCol(0);
    stackSizer->Add(m_stackChoice, wxSizerFlags().Expand().Border());
    stackSizer->Add(collapseButton, wxSizerFlags().Border());
    stackSizer->Add(expandButton, wxSizerFlags().Border());
    topSizer->Add(stackSizer, wxSizerFlags().Expand());

    topSizer->Add(findText, wxSizerFlags().Expand().Border().Align(wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL));

    wxFlexGridSizer* findSizer = new wxFlexGridSizer(4, 0, 0);
    findSizer->AddGrowableCol(0);
    findSizer->Add(m_findComboBox, wxSizerFlags().Expand().Border());
    findSizer->Add(findPrev, wxSizerFlags().Expand().Border());
    findSizer->Add(findNext, wxSizerFlags().Expand().Border());

    findSizer->Add(findMenuButton, wxSizerFlags().Expand().Border());

    topSizer->Add(findSizer, wxSizerFlags().Expand());

    // -----------------------------------------------------------------------

    m_splitterWin = new wxSplitterWindow(panel, ID_WXLUA_STACK_SPLITTERWIN,
                                         wxDefaultPosition, wxDefaultSize,
                                         wxSP_3D);
    m_splitterWin->SetSashGravity(0.1);
    m_splitterWin->SetMinimumPaneSize(20);

    m_treeCtrl = new wxTreeCtrl(m_splitterWin, ID_WXLUA_STACK_TREECTRL,
                                wxDefaultPosition, wxDefaultSize,
                                wxTR_HAS_BUTTONS|wxTR_SINGLE|wxTR_HIDE_ROOT|wxTR_LINES_AT_ROOT);

    m_treeCtrl->SetImageList(m_imageList);

    m_listCtrl = new wxLuaStackListCtrl(this, m_splitterWin, ID_WXLUA_STACK_LISTCTRL,
                                wxDefaultPosition, wxDefaultSize,
                                wxLC_REPORT|wxLC_HRULES|wxLC_VRULES|wxLC_VIRTUAL ); // wxLC_SINGLE_SEL

    m_listCtrl->SetImageList(m_imageList,          wxIMAGE_LIST_SMALL);
    m_listCtrl->InsertColumn(LIST_COL_KEY,        wxT("Name"),       wxLIST_FORMAT_LEFT, -1);
    m_listCtrl->InsertColumn(LIST_COL_LEVEL,      wxT("Level"),      wxLIST_FORMAT_LEFT, -1);
    m_listCtrl->InsertColumn(LIST_COL_KEY_TYPE,   wxT("Key Type"),   wxLIST_FORMAT_LEFT, -1);
    m_listCtrl->InsertColumn(LIST_COL_VALUE_TYPE, wxT("Value Type"), wxLIST_FORMAT_LEFT, -1);
    m_listCtrl->InsertColumn(LIST_COL_VALUE,      wxT("Value"),      wxLIST_FORMAT_LEFT, -1);

    int txt_width = 0, txt_height = 0;

    m_listCtrl->GetTextExtent(wxString(wxT('W'), 25), &txt_width, &txt_height);


    m_listCtrl->SetColumnWidth(0, txt_width);
    m_listCtrl->SetColumnWidth(4, txt_width); // we'll make it wider later since it's the last
    m_listCtrl->GetTextExtent(wxT("555:5555"), &txt_width, &txt_height);
    m_listCtrl->SetColumnWidth(1, txt_width);
    m_listCtrl->GetTextExtent(wxT("Light User DataX"), &txt_width, &txt_height);
    m_listCtrl->SetColumnWidth(2, txt_width);
    m_listCtrl->SetColumnWidth(3, txt_width);

    m_listMenu = new wxMenu(wxEmptyString, 0);
    m_listMenu->Append(ID_WXLUA_STACK_LISTMENU_COPY_ROW,  wxT("Copy row"),        wxT("Copy whole row clipboard"), wxITEM_NORMAL);
    m_listMenu->Append(ID_WXLUA_STACK_LISTMENU_COPY_COL0, wxT("Copy name"),       wxT("Copy name to clipboard"), wxITEM_NORMAL);
    m_listMenu->Append(ID_WXLUA_STACK_LISTMENU_COPY_COL1, wxT("Copy level"),      wxT("Copy level to clipboard"), wxITEM_NORMAL);
    m_listMenu->Append(ID_WXLUA_STACK_LISTMENU_COPY_COL2, wxT("Copy key type"),   wxT("Copy key type to clipboard"), wxITEM_NORMAL);
    m_listMenu->Append(ID_WXLUA_STACK_LISTMENU_COPY_COL3, wxT("Copy value type"), wxT("Copy value type to clipboard"), wxITEM_NORMAL);
    m_listMenu->Append(ID_WXLUA_STACK_LISTMENU_COPY_COL4, wxT("Copy value"),      wxT("Copy value to clipboard"), wxITEM_NORMAL);

    // -----------------------------------------------------------------------

    m_splitterWin->SplitVertically(m_treeCtrl, m_listCtrl, 160);

    // use sizers to layout the windows in the panel of the dialog
    wxBoxSizer* rootSizer = new wxBoxSizer(wxVERTICAL);
    rootSizer->Add(topSizer, 0, wxEXPAND|wxBOTTOM, 5);
    rootSizer->Add(m_splitterWin, 1, wxEXPAND);
    rootSizer->SetMinSize(200, 150);
    panel->SetSizer(rootSizer);
    rootSizer->SetSizeHints(this);

    // We want the last col wide since it's hard to drag the col width of a listctrl
    // however, we don't want the sizer to take the extra width into account
    m_listCtrl->SetColumnWidth(4, m_listCtrl->GetColumnWidth(4)*4);
    // Allow people to shrink it down pretty small
    SetMinSize(wxSize(200, 200));

    SetSize(size); // force last good/known size
    if (sm_maximized)
        Maximize();

    EnumerateStack();

    return true;
}

wxLuaStackDialog::~wxLuaStackDialog()
{
    if (!IsFullScreen() && !IsIconized() && !IsMaximized())
        sm_defaultSize = GetSize();

    sm_maximized = IsMaximized();

    RemoveAllLuaReferences();
    DeleteAllListItemData();

    delete m_listMenu;
    delete m_findMenu;

    if (m_listCtrl) m_listCtrl->SetImageList(NULL, wxIMAGE_LIST_SMALL);
    if (m_treeCtrl) m_treeCtrl->SetImageList(NULL);
    delete m_imageList;
}

wxBitmap wxLuaStackDialog::CreateBmpString(const wxBitmap& bmp_, const wxString& s)
{
    wxBitmap bmp(bmp_); // unconst it
    int bmp_w = bmp.GetWidth();
    int bmp_h = bmp.GetHeight();

    wxMemoryDC dc;
    dc.SelectObject(bmp);

    wxFont font(m_img_font_size, wxFONTFAMILY_SWISS, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL);
    wxCoord w = 0, h = 0;

    // after first time to find font size, run once to get the text extent
    for ( ; m_img_font_size > 3; --m_img_font_size)
    {
        dc.GetTextExtent(s, &w, &h, NULL, NULL, &font);

        if ((w < bmp_w) && (h < bmp_h))
            break;

        font.SetPointSize(m_img_font_size);
    }

    dc.SetFont(font);
    dc.DrawText(s, (bmp_w-w)/2, (bmp_h-h)/2);
    dc.SelectObject(wxNullBitmap);

    return bmp;
}

int wxLuaStackDialog::GetItemImage(const wxLuaDebugItem *dbgItem) const
{
    wxCHECK_MSG(dbgItem, IMG_UNKNOWN, wxT("Invalid wxLuaDebugItem"));

    int img = IMG_NONE;

    // Expanded nodes all use the open table icon
    if (dbgItem->GetFlagBit(WXLUA_DEBUGITEM_EXPANDED))
        img = IMG_TABLE_OPEN;
    else if (dbgItem->GetFlagBit(WXLUA_DEBUGITEM_LOCALS))
        img = IMG_TABLE;
    else
    {
        switch (dbgItem->GetValueType())
        {
            case WXLUA_TUNKNOWN        : img = IMG_UNKNOWN; break;
            case WXLUA_TNONE           : img = IMG_NONE; break;
            case WXLUA_TNIL            : img = IMG_NIL; break;
            case WXLUA_TBOOLEAN        : img = IMG_BOOLEAN; break;
            case WXLUA_TLIGHTUSERDATA  : img = IMG_LIGHTUSERDATA; break;
            case WXLUA_TNUMBER         : img = IMG_NUMBER; break;
            case WXLUA_TSTRING         : img = IMG_STRING; break;
            case WXLUA_TTABLE          : img = IMG_TABLE; break;
            case WXLUA_TFUNCTION       : img = IMG_LUAFUNCTION; break;
            case WXLUA_TUSERDATA       : img = IMG_USERDATA; break;
            case WXLUA_TTHREAD         : img = IMG_THREAD; break;
            case WXLUA_TINTEGER        : img = IMG_INTEGER; break;
            case WXLUA_TCFUNCTION      : img = IMG_CFUNCTION; break;
        }
    }

    return img;
}

wxString wxLuaStackDialog::GetItemText(long item, long column, bool exact_value)
{
    wxLuaStackListData* stkListData = (wxLuaStackListData*)m_listData[item];
    wxCHECK_MSG(stkListData, wxEmptyString, wxT("Invalid wxLuaStackListData item"));
    wxLuaDebugItem* debugItem = stkListData->GetDebugItem();
    wxCHECK_MSG(debugItem, wxEmptyString, wxT("Invalid wxLuaDebugItem item"));

    switch (column)
    {
        case LIST_COL_KEY:
        {
            if (exact_value)
                return debugItem->GetKey();

            if (stkListData->m_level > 0)
            {
                //wxString s(wxT("-->"));
                //for (int i = 1; i < stkListData->m_level; ++i) s += wxT("-->");

                return wxString(wxT(' '), stkListData->m_level*4) + debugItem->GetKey();
            }
            else
                return debugItem->GetKey();
        }
        case LIST_COL_LEVEL:
            return wxString::Format(wxT("%d:%d"), stkListData->m_level+1, stkListData->m_item_idx+1);
        case LIST_COL_KEY_TYPE:
            return debugItem->GetKeyTypeString();
        case LIST_COL_VALUE_TYPE:
            return debugItem->GetValueTypeString();
        case LIST_COL_VALUE:
        {
            if (exact_value)
                return debugItem->GetValue();

            wxString value(debugItem->GetValue());
            if (value.Length() > 200) value = value.Mid(0, 200) + wxT("... <snip>");
            value.Replace(wxT("\n"), wxT("\\n"));
            value.Replace(wxT("\r"), wxT("\\r"));
            return value;
        }
    }

    return wxEmptyString;
}

int wxLuaStackDialog::GetItemColumnImage(long item, long column) const
{
    if ((column == LIST_COL_KEY) ||
        (column == LIST_COL_KEY_TYPE) ||
        (column == LIST_COL_VALUE_TYPE))
    {
        wxLuaStackListData* stkListData = (wxLuaStackListData*)m_listData[item];
        wxCHECK_MSG(stkListData, -1, wxT("Invalid wxLuaStackListData item"));
        wxLuaDebugItem* debugItem = stkListData->GetDebugItem();
        wxCHECK_MSG(debugItem, -1, wxT("Invalid wxLuaDebugItem item"));

        switch (column)
        {
            case LIST_COL_KEY :
            {
                return GetItemImage(debugItem);
            }
            case LIST_COL_KEY_TYPE :
            {
                if (debugItem->GetFlagBit(WXLUA_DEBUGITEM_KEY_REF))
                {
                    if (debugItem->GetFlagBit(WXLUA_DEBUGITEM_EXPANDED))
                        return IMG_TABLE_OPEN;
                    else
                        return IMG_TABLE;
                }
                break;
            }
            case LIST_COL_VALUE_TYPE :
            {
                if (debugItem->GetFlagBit(WXLUA_DEBUGITEM_VALUE_REF))
                {
                    if (debugItem->GetFlagBit(WXLUA_DEBUGITEM_EXPANDED))
                        return IMG_TABLE_OPEN;
                    else
                        return IMG_TABLE;
                }
                break;
            }
        }
    }

    return -1;
}

wxListItemAttr *wxLuaStackDialog::GetItemAttr(long item) const
{
    wxLuaStackListData* stkListData = (wxLuaStackListData*)m_listData[item];
    wxCHECK_MSG(stkListData, NULL, wxT("Invalid wxLuaStackListData item"));
    wxLuaDebugItem* debugItem = stkListData->GetDebugItem();
    wxCHECK_MSG(debugItem, NULL, wxT("Invalid wxLuaDebugItem item"));

    int img = GetItemImage(debugItem);

    wxLuaStackDialog* stkDlg = (wxLuaStackDialog*)this; // unconst this

    stkDlg->m_itemAttr.SetTextColour(m_typeColours[img]);

    //unsigned char c = 255 - (stkListData->m_level % 5)*22;
    //stkDlg->m_itemAttr.SetBackgroundColour(wxColour(c,c,c));

    return &stkDlg->m_itemAttr;
}

void wxLuaStackDialog::SelectStack(int stack_sel)
{
    wxCHECK_RET((stack_sel >= 0) && (stack_sel < (int)m_stackEntries.GetCount()), wxT("Invalid stack index"));

    RemoveAllLuaReferences(); // remove them now since we're starting from scratch

    m_stack_sel = stack_sel;
    int n_entry = m_stackEntries[m_stack_sel];
    EnumerateStackEntry(n_entry);
}

void wxLuaStackDialog::EnumerateStack()
{
    wxCHECK_RET(m_wxlState.Ok(), wxT("Invalid wxLuaState"));
    wxBusyCursor wait;
    wxLuaDebugData debugData(true);
    debugData.EnumerateStack(m_wxlState.GetLuaState());
    FillStackCombobox(debugData);
}
void wxLuaStackDialog::EnumerateStackEntry(int nEntry)
{
    wxCHECK_RET(m_wxlState.Ok(), wxT("Invalid wxLuaState"));
    wxBusyCursor wait;
    wxLuaDebugData debugData(true);
    debugData.EnumerateStackEntry(m_wxlState.GetLuaState(), nEntry, m_luaReferences);
    FillStackEntry(nEntry, debugData);
}
void wxLuaStackDialog::EnumerateTable(int nRef, int nEntry, long lc_item)
{
    wxCHECK_RET(m_wxlState.Ok(), wxT("Invalid wxLuaState"));
    wxBusyCursor wait;
    wxLuaDebugData debugData(true);
    debugData.EnumerateTable(m_wxlState.GetLuaState(), nRef, nEntry, m_luaReferences);
    FillTableEntry(lc_item, debugData);
}

void wxLuaStackDialog::FillStackCombobox(const wxLuaDebugData& debugData)
{
    wxCHECK_RET(debugData.Ok(), wxT("Invalid wxLuaDebugData in FillStackCombobox"));

    m_stackChoice->Clear();
    m_stackEntries.Clear();

    size_t n, count = debugData.GetCount();
    for (n = 0; n < count; ++n)
    {
        const wxLuaDebugItem *item = debugData.Item(n);
        m_stackEntries.Add(item->GetIndex());
        wxString name(item->GetKey());
        if (n == count - 1) name += wxT(" (Globals)");
        m_stackChoice->Append(name);
    }

    if (count > 0)
    {
        m_stackChoice->SetSelection(0);
        SelectStack(0);
    }
}

void wxLuaStackDialog::FillStackEntry(int WXUNUSED(nEntry), const wxLuaDebugData& debugData)
{
    wxCHECK_RET(debugData.Ok(), wxT("Invalid wxLuaDebugData in FillStackEntry"));

    DeleteAllListItemData();
    m_expandedItems.clear();
    m_listCtrl->SetItemCount(0);

    m_treeCtrl->DeleteAllItems();
    m_treeCtrl->AddRoot(wxT("wxLua Data"), -1, -1, NULL);
    m_treeCtrl->SetItemHasChildren(m_treeCtrl->GetRootItem());

    // Add the locals, fake a debug item to get it setup right
    wxLuaDebugItem* localItem  = new wxLuaDebugItem(_("Locals"), WXLUA_TNONE,
                    wxString::Format(wxT("%d Items"), (int)debugData.GetCount()), WXLUA_TNONE,
                    wxEmptyString, LUA_NOREF, 0, WXLUA_DEBUGITEM_EXPANDED|WXLUA_DEBUGITEM_LOCALS|WXLUA_DEBUGITEM_VALUE_REF);
    wxLuaDebugData localData(true); // this deletes the items
    localData.Add(localItem);
    FillTableEntry(m_listCtrl->GetItemCount(), localData);

    if (debugData.GetCount() > 0u)
        FillTableEntry(m_listCtrl->GetItemCount()-1, debugData);

    //  If at global scope, process globals
    //if (m_stack_sel == (int)m_stackEntries.GetCount() - 1)
    {
        // When used with the wxLuaDebuggerServer we get delayed responses
        // from the debuggee so we can't expect that the item has been added
        // to the listctrl yet, but we assume they eventually will be, hence n+x.
        int n = m_listCtrl->GetItemCount();
        EnumerateTable(LUA_GLOBALSINDEX,  -1, n++);
#if LUA_VERSION_NUM < 502
        // LUA_ENVIRONINDEX is no longer in 5.2
        EnumerateTable(LUA_ENVIRONINDEX,  -1, n++);
#endif // LUA_VERSION_NUM < 502
        EnumerateTable(LUA_REGISTRYINDEX, -1, n++);
    }
}

void wxLuaStackDialog::FillTableEntry(long lc_item_, const wxLuaDebugData& debugData)
{
    wxCHECK_RET(debugData.Ok(), wxT("Invalid wxLuaDebugData in FillTableEntry"));

    wxCHECK_RET(lc_item_ <= m_listCtrl->GetItemCount(), wxT("Attempting to add list item past end"));

    if (debugData.GetCount() > 0)
    {
        wxTreeItemId treeId;
        wxString levelStr;
        int level = 0;

        // If less than the count we're expanding a item, else adding a new root
        if (lc_item_ < (long)m_listData.GetCount())
        {
            // Set the children data for the parent
            wxLuaStackListData* stkListData = (wxLuaStackListData*)m_listData[lc_item_];
            wxCHECK_RET((stkListData != NULL), wxT("The wxLuaStackDialog does have stack data!"));
            // sanity check, either add new children data or we're expanding using the old data
            wxCHECK_RET(!stkListData->m_childrenDebugData.Ok() || (stkListData->m_childrenDebugData == debugData), wxT("Replacing the child data?"));
            if (!stkListData->m_childrenDebugData.Ok())
                stkListData->m_childrenDebugData = debugData;

            treeId = stkListData->m_treeId;
            if (!treeId) treeId = m_treeCtrl->GetRootItem();

            level = stkListData->m_level+1;
        }
        else
        {
            treeId = m_treeCtrl->GetRootItem();
            lc_item_--;
        }

        m_treeCtrl->SetItemHasChildren(treeId);

        BeginBatch();

        bool removed_tree_dummy = false;
        size_t n, count = debugData.GetCount();

        long lc_item = lc_item_;
        for (n = 0; n < count; ++n)
        {
            wxLuaStackListData* stkListData = new wxLuaStackListData(n, level, debugData);
            m_listData.Insert(stkListData, lc_item+n+1);

            wxLuaDebugItem* debugItem = debugData.Item(n);

            //int img = GetItemImage(debugItem);

            if ((debugItem->GetRef() != LUA_NOREF) ||
                 debugItem->GetFlagBit(WXLUA_DEBUGITEM_LOCALS))
            {
                wxTreeItemId id = m_treeCtrl->AppendItem(treeId, debugItem->GetKey(), -1, -1, new wxLuaStackTreeData(stkListData));
                m_treeCtrl->SetItemHasChildren(id);
                stkListData->m_treeId = id;

                // add dummy item for MSW to expand properly, also it shows that
                // there's nothing in this level if they try to expand it and there
                // aren't any real items (see below)
                m_treeCtrl->AppendItem(id, DUMMY_TREEITEM);

                // now that we've added something, remove the first dummy " " item from parent
                if (!removed_tree_dummy)
                {
                    removed_tree_dummy = true;

                    wxTreeItemIdValue dummyCookie;
                    wxTreeItemId dummyId = m_treeCtrl->GetFirstChild(treeId, dummyCookie);
                    if ((m_treeCtrl->GetItemText(dummyId) == DUMMY_TREEITEM) &&
                        (m_treeCtrl->GetItemData(dummyId) == NULL))
                    {
                        m_treeCtrl->Delete(dummyId);
                    }
                }
            }
        }

        m_listCtrl->SetItemCount(m_listData.GetCount());

        EndBatch();

        // NOTE : The MSW treectrl will expand and immediately collapse a node if you call Expand()
        // from within a handler, don't do anything and it works...
#if !defined(WXLUA_STACK_MSWTREE)
        // Cannot expand hidden root, nor can you check it
        if (treeId && !m_treeCtrl->IsExpanded(treeId) &&
            ((treeId != m_treeCtrl->GetRootItem()) || ((m_treeCtrl->GetWindowStyle() & wxTR_HIDE_ROOT) == 0)))
            m_treeCtrl->Expand(treeId);
#endif //!defined(WXLUA_STACK_MSWTREE)
    }
}

void wxLuaStackDialog::BeginBatch()
{
    if (m_batch_count == 0)
    {
        m_listCtrl->Freeze();
        m_treeCtrl->Freeze();
    }

    ++m_batch_count;
}

void wxLuaStackDialog::EndBatch()
{
    if (m_batch_count == 1)
    {
        m_listCtrl->Thaw();
        m_treeCtrl->Thaw();
    }

    if (m_batch_count > 0)
        m_batch_count--;
}

long wxLuaStackDialog::FindListItem(wxLuaStackListData* stkListData, bool get_parent) const
{
    long n, count = m_listCtrl->GetItemCount();
    wxLuaStackListData* stkListData_n = NULL;

    for (n = 0; n < count; ++n)
    {
        stkListData_n = (wxLuaStackListData*)m_listData[n];

        if (!get_parent && (stkListData_n == stkListData))
            return n;
        else if (get_parent && (stkListData_n->m_childrenDebugData == stkListData->m_parentDebugData))
            return n;
    }

    return wxNOT_FOUND;
}

void wxLuaStackDialog::OnExpandButton(wxCommandEvent &event)
{
    long start_item = m_listCtrl->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    // they must select an item
    if (start_item < 0) return;

    if (event.GetId() == ID_WXLUA_STACK_EXPAND_BUTTON)
        ExpandItemChildren(start_item);
    else
    {
        wxLuaStackListData* stkListData = (wxLuaStackListData*)m_listData[start_item];
        wxCHECK_RET(stkListData != NULL, wxT("Invalid wxLuaStack data"));

        // Hack for WXLUA_STACK_MSWTREE, collapse tree first
        if (stkListData->m_treeId && m_treeCtrl->IsExpanded(stkListData->m_treeId))
            m_treeCtrl->Collapse(stkListData->m_treeId);

        CollapseItem(start_item);
    }
}

// This code is copied from wxStEdit's function wxSTEPrependComboBoxString
void wxLuaPrependComboBoxString(const wxString &str, int max_strings, wxComboBox *combo)
{
    wxCHECK_RET(combo, wxT("Invalid combobox in wxLuaPrependComboBoxString"));

    int pos = combo->FindString(str);
    if (pos == 0)
        return;
    if (pos != wxNOT_FOUND)
        combo->Delete(pos);

    combo->Insert(str, 0);
    combo->SetSelection(0);

    while ((max_strings > 0) && ((int)combo->GetCount() > max_strings))
        combo->Delete(combo->GetCount()-1);
}

void wxLuaStackDialog::OnMenu(wxCommandEvent& event)
{
    int id = event.GetId();
    bool checked = event.IsChecked();

    if (id == ID_WXLUA_STACK_FINDMENU_ALL)
    {
        m_findMenu->Check(ID_WXLUA_STACK_FINDMENU_NAME,      checked);
        m_findMenu->Check(ID_WXLUA_STACK_FINDMENU_LEVEL,     checked);
        m_findMenu->Check(ID_WXLUA_STACK_FINDMENU_KEYTYPE,   checked);
        m_findMenu->Check(ID_WXLUA_STACK_FINDMENU_VALUETYPE, checked);
        m_findMenu->Check(ID_WXLUA_STACK_FINDMENU_VALUE,     checked);
    }
    else if ((id >= ID_WXLUA_STACK_FINDMENU_NAME) && (id <= ID_WXLUA_STACK_FINDMENU_VALUE))
    {
        bool all_checked = m_findMenu->IsChecked(ID_WXLUA_STACK_FINDMENU_NAME) &&
                           m_findMenu->IsChecked(ID_WXLUA_STACK_FINDMENU_LEVEL) &&
                           m_findMenu->IsChecked(ID_WXLUA_STACK_FINDMENU_KEYTYPE) &&
                           m_findMenu->IsChecked(ID_WXLUA_STACK_FINDMENU_VALUETYPE) &&
                           m_findMenu->IsChecked(ID_WXLUA_STACK_FINDMENU_VALUE);

        if (m_findMenu->IsChecked(ID_WXLUA_STACK_FINDMENU_ALL) != checked)
            m_findMenu->Check(ID_WXLUA_STACK_FINDMENU_ALL, all_checked);
    }
    else if ((id >= ID_WXLUA_STACK_LISTMENU_COPY_ROW) && (id <= ID_WXLUA_STACK_LISTMENU_COPY_COL4))
    {
        wxString s;

        long list_item = m_listCtrl->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        // iterate all selected items, separated by \n
        while (list_item >= 0)
        {
            if (!s.IsEmpty()) s += wxT("\n");

            if (id == ID_WXLUA_STACK_LISTMENU_COPY_ROW)
            {
                s += GetItemText(list_item, 0, true);

                for (int i = 1; i < LIST_COL__MAX; ++i)
                    s += wxT("\t") + GetItemText(list_item, i, true);
            }
            else // ((id >= ID_WXLUA_STACK_LISTMENU_COPY_COL0) && (id <= ID_WXLUA_STACK_LISTMENU_COPY_COL4))
            {
                s += GetItemText(list_item, id - ID_WXLUA_STACK_LISTMENU_COPY_COL0, true);
            }

            list_item = m_listCtrl->GetNextItem(list_item, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        }

        if (wxTheClipboard->Open())
        {
            // These data objects are held by the clipboard,
            // so do not delete them in the app.
            wxTheClipboard->SetData( new wxTextDataObject(s) );
            wxTheClipboard->Close();
        }
    }
}

void wxLuaStackDialog::OnFind(wxCommandEvent &event)
{
    if (event.GetId() == ID_WXLUA_STACK_FINDMENU_BUTTON)
    {
        wxWindow* button = ((wxWindow*)event.GetEventObject());
        wxSize s(button->GetSize());
        button->PopupMenu(m_findMenu, 0, s.GetHeight());

        return;
    }

    // Remaining events we handle are for finding

    bool find_col[LIST_COL__MAX] = {
        m_findMenu->IsChecked(ID_WXLUA_STACK_FINDMENU_NAME),
        m_findMenu->IsChecked(ID_WXLUA_STACK_FINDMENU_LEVEL),
        m_findMenu->IsChecked(ID_WXLUA_STACK_FINDMENU_KEYTYPE),
        m_findMenu->IsChecked(ID_WXLUA_STACK_FINDMENU_VALUETYPE),
        m_findMenu->IsChecked(ID_WXLUA_STACK_FINDMENU_VALUE),
    };

    // Send warning instead of silently doing nothing
    if (!find_col[0] && !find_col[1] && !find_col[2] && !find_col[3] && !find_col[4])
    {
        wxMessageBox(wxT("Please select at least one column to search with the find options button"),
                     wxT("wxLua Stack Find Error"),
                     wxOK|wxICON_EXCLAMATION|wxCENTRE, this);
        return;
    }

    wxString findStr = m_findComboBox->GetValue();
    if (findStr.IsEmpty())
        return;

    wxBusyCursor busy;
    wxLuaPrependComboBoxString(findStr, 10, m_findComboBox);

    bool match_case = m_findMenu->IsChecked(ID_WXLUA_STACK_FINDMENU_CASE);
    if (!match_case) findStr = findStr.Lower();

    bool whole_string = m_findMenu->IsChecked(ID_WXLUA_STACK_FINDMENU_WHOLE_STRING);

    long direction = (event.GetId() == ID_WXLUA_STACK_FINDPREV_BUTTON) ? -1 : 1;

    long list_count = m_listCtrl->GetItemCount();
    long start_item = m_listCtrl->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);

    int wrap_count = 0; // start at current item and wrap back around

    bool found = false;
    wxString txt;

    while ((wrap_count < 2) && !found)
    {
        long i = 0;
        found = false;

        if (wrap_count == 0)
        {
            i = start_item + direction;

            // tweak up the starting item
            if (start_item < 0)
            {
                i = (direction > 0) ? 0 : list_count - 1;
                ++wrap_count; // we're looking at all the elements
            }
            else if ((direction > 0) && (start_item == list_count - 1))
            {
                i = 0;
                ++wrap_count; // we're looking at all the elements
            }
        }
        else
        {
            i = (direction > 0) ? 0 : list_count - 1;
        }

        for ( ; (i >= 0) && (i < list_count) && !found; i = i + direction)
        {
            for (int col = 0; (col < LIST_COL__MAX) && !found; ++col)
            {
                if (!find_col[col]) continue;

                txt = GetItemText(i, col, true);
                if (!match_case) txt.MakeLower();

                if ((whole_string && (txt == findStr)) ||
                    (!whole_string && (txt.Find(findStr) != wxNOT_FOUND)))
                {
                    m_listCtrl->SetItemState(i, wxLIST_STATE_FOCUSED, wxLIST_STATE_FOCUSED);
                    m_listCtrl->SetItemState(i, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                    m_listCtrl->EnsureVisible(i);
                    found = true;
                    break;
                }
            }
        }

        ++wrap_count;
    }
}

void wxLuaStackDialog::OnSelectStack(wxCommandEvent &event)
{
    if (event.GetSelection() >= 0)
        SelectStack(event.GetSelection());
}

void wxLuaStackDialog::OnTreeItem(wxTreeEvent &event)
{
    if (m_batch_count > 0) return;

    wxTreeItemId id = event.GetItem();
    wxLuaStackTreeData* stkTreeData = (wxLuaStackTreeData*)m_treeCtrl->GetItemData(id);
    if (stkTreeData == NULL) return; // root has no data

    long list_item = FindListItem(stkTreeData->m_stkListData);

    if (list_item < 0) return; // not an item that we can do anything with

    int evt_type = event.GetEventType();

    if (evt_type == wxEVT_COMMAND_TREE_ITEM_EXPANDED)
    {
        wxBusyCursor busy;
        ExpandItem(list_item);
        m_listCtrl->RefreshItem(list_item);
    }
    else if (evt_type == wxEVT_COMMAND_TREE_ITEM_COLLAPSED)
    {
        wxBusyCursor busy;
        CollapseItem(list_item);
        m_listCtrl->RefreshItem(list_item);
    }
    else if (evt_type == wxEVT_COMMAND_TREE_SEL_CHANGED)
    {
        long last_item = m_listCtrl->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);

        m_listCtrl->SetItemState(list_item, wxLIST_STATE_SELECTED|wxLIST_STATE_FOCUSED,
                                            wxLIST_STATE_SELECTED|wxLIST_STATE_FOCUSED);
        m_listCtrl->EnsureVisible(list_item);

        if ((last_item >= 0) && (last_item != list_item))
        {
            m_listCtrl->SetItemState(last_item, 0, wxLIST_STATE_SELECTED|wxLIST_STATE_FOCUSED);
            m_listCtrl->RefreshItem(last_item);
        }
    }
}

void wxLuaStackDialog::OnListItem(wxListEvent &event)
{
    if (m_batch_count > 0) return;

    long list_item = event.GetIndex();

    wxLuaStackListData* stkListData = (wxLuaStackListData*)m_listData[list_item];
    wxCHECK_RET(stkListData != NULL, wxT("Invalid wxLuaStack data"));
    wxLuaDebugItem* debugItem = stkListData->GetDebugItem();
    wxCHECK_RET(debugItem != NULL, wxT("Invalid debug item"));

    if (event.GetEventType() == wxEVT_COMMAND_LIST_ITEM_SELECTED)
    {
        if (stkListData->m_treeId)
        {
            m_treeCtrl->SelectItem(stkListData->m_treeId, true);
            m_treeCtrl->EnsureVisible(stkListData->m_treeId);
        }
    }
    else if (event.GetEventType() == wxEVT_COMMAND_LIST_ITEM_ACTIVATED)
    {
        if (!debugItem->GetFlagBit(WXLUA_DEBUGITEM_EXPANDED))
        {
            if (ExpandItem(list_item))
            {
                // Hack for WXLUA_STACK_MSWTREE, need children to expand
                if (stkListData->m_treeId && !m_treeCtrl->IsExpanded(stkListData->m_treeId))
                    m_treeCtrl->Expand(stkListData->m_treeId);
            }
        }
        else
        {
            // Hack for WXLUA_STACK_MSWTREE, collapse tree first
            if (stkListData->m_treeId && m_treeCtrl->IsExpanded(stkListData->m_treeId))
                m_treeCtrl->Collapse(stkListData->m_treeId);

            CollapseItem(list_item);
        }

        // refresh here and not in Expand/CollapseItem() to make ExpandItemChildren() faster.
        m_listCtrl->RefreshItem(list_item);
    }
}

void wxLuaStackDialog::OnListRightClick(wxListEvent &event) // FIXME for easy debugging of mem addresses
{
    event.Skip();

    if (event.GetIndex() >= 0)
        m_listCtrl->PopupMenu(m_listMenu);
}

bool wxLuaStackDialog::ExpandItem(long lc_item)
{
    wxCHECK_MSG((lc_item >= 0) && (lc_item < (long)m_listData.GetCount()), false,
                wxT("Invalid list item to expand"));

    bool expanded = false;

    wxLuaStackListData* stkListData = (wxLuaStackListData*)m_listData[lc_item];
    wxCHECK_MSG(stkListData != NULL, false, wxT("Invalid wxLuaStack data"));
    wxLuaDebugItem* debugItem = stkListData->GetDebugItem();
    wxCHECK_MSG(debugItem != NULL, false, wxT("Invalid debug item"));

    if (!debugItem->GetFlagBit(WXLUA_DEBUGITEM_EXPANDED))
    {
        // re-expand the item that was previously collapsed
        if (stkListData->m_childrenDebugData.Ok())
        {
            debugItem->SetFlagBit(WXLUA_DEBUGITEM_EXPANDED, true);

            wxUIntPtr long_key = 0;
            if (debugItem->GetRefPtr(long_key))
                m_expandedItems[long_key] = (wxUIntPtr)stkListData;

            FillTableEntry(lc_item, stkListData->m_childrenDebugData);

            expanded = true;
        }
        else if (debugItem->GetRef() != LUA_NOREF)
        {
            wxUIntPtr long_key = 0;
            wxCHECK_MSG(debugItem->GetRefPtr(long_key), false, wxT("Invalid table item"));

            // Check and block linked tables already shown, select it and return
            if (m_expandedItems[long_key]) // linked tables
            {
                if (m_show_dup_expand_msg) // don't bother when expanding all children
                {
                    int ret = wxMessageBox(wxString::Format(wxT("Cannot expand linked tables %lx,\nselect Ok to see the previously expanded table."), long_key),
                                           wxT("wxLua Stack"), wxOK | wxCANCEL | wxCENTRE, this);
                    if (ret == wxOK)
                    {
                        int n = m_listData.Index((void*)m_expandedItems[long_key]);
                        wxCHECK_MSG(n != wxNOT_FOUND, false, wxT("Unable to find hash of expanded items."));

                        m_listCtrl->SetItemState(n, wxLIST_STATE_FOCUSED,  wxLIST_STATE_FOCUSED);
                        m_listCtrl->SetItemState(n, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                        m_listCtrl->EnsureVisible(n);
                    }
                }
            }
            else // new item to enumerate and expand
            {
                debugItem->SetFlagBit(WXLUA_DEBUGITEM_EXPANDED, true);

                m_expandedItems[long_key] = (wxUIntPtr)stkListData;

                EnumerateTable(debugItem->GetRef(), debugItem->GetIndex() + 1, lc_item);
                expanded = true;
            }
        }
    }

    return expanded;
}

bool wxLuaStackDialog::ExpandItemChildren(long lc_item)
{
    wxCHECK_MSG((lc_item >= 0) && (lc_item < (long)m_listData.GetCount()), false,
                wxT("Invalid list item to expand"));

    bool expanded = false;

    wxProgressDialog* dlg =
        new wxProgressDialog(wxT("wxLua Stack Expanding node"), wxEmptyString, 100, this,
                             wxPD_AUTO_HIDE | wxPD_APP_MODAL | wxPD_CAN_ABORT);

    BeginBatch();

    // Note: Iterating through all of the listctrl items, even though most of
    // them are not expandable, is MUCH faster than using the far fewer
    // wxTreeCtrl items and calling Expand() on them.

    wxLuaStackListData* stkListData = (wxLuaStackListData*)m_listData[lc_item];

    int counter = 0;
    int n = lc_item, level = stkListData->m_level;
    while (n < (int)m_listData.GetCount())
    {
        // show message for first item only so it doesn't silently fail
        if (n > lc_item) m_show_dup_expand_msg = false;

        wxLuaStackListData* stkListData_n = (wxLuaStackListData*)m_listData[n];

        if ((n > lc_item) && (stkListData_n->m_level <= level))
            break;

        if (counter % 50 == 0)
        {
            if (!dlg->Pulse(wxString::Format(wxT("Expanding nodes : %d"), counter)))
                break;
        }

        if (!stkListData_n->GetDebugItem()->GetFlagBit(WXLUA_DEBUGITEM_EXPANDED))
            expanded |= ExpandItem(n);

        ++counter;
        ++n;
    }

    dlg->Destroy();

    EndBatch();
    m_show_dup_expand_msg = true;

    return expanded;
}

bool wxLuaStackDialog::CollapseItem(long lc_item)
{
    wxCHECK_MSG((lc_item >= 0) && (lc_item < m_listCtrl->GetItemCount()), false,
                wxT("Invalid list item to collapse"));

    bool collapsed = false;

    wxLuaStackListData* stkListData = (wxLuaStackListData*)m_listData[lc_item];
    wxCHECK_MSG(stkListData != NULL, false, wxT("Invalid wxLuaStack data"));
    wxLuaDebugItem* debugItem = stkListData->GetDebugItem();
    wxCHECK_MSG((debugItem != NULL), false, wxT("Invalid debug item"));

    // Collapse the item, remove children
    if (debugItem->GetFlagBit(WXLUA_DEBUGITEM_EXPANDED))
    {
        BeginBatch();
        wxLuaDebugData childData = stkListData->m_childrenDebugData;

        if (childData.Ok())
        {
            int level     = stkListData->m_level;
            long n, count = m_listCtrl->GetItemCount();

            for (n = lc_item+1; n < count; ++n)
            {
                wxLuaStackListData* stkListData_n = (wxLuaStackListData*)m_listData[n];
                wxCHECK_MSG(stkListData_n != NULL, false, wxT("Invalid wxLuaStack data n"));
                wxLuaDebugItem* debugItem_n = stkListData_n->GetDebugItem();
                wxCHECK_MSG((debugItem_n != NULL), false, wxT("Invalid debug item n"));

                // are we finished with the original expanded item
                if (stkListData_n->m_level <= level)
                    break;

                collapsed = true; // only if we removed anything

                // remove all expanded children items
                if (debugItem_n->GetFlagBit(WXLUA_DEBUGITEM_EXPANDED))
                {
                    wxUIntPtr long_key = 0;
                    if (debugItem_n->GetRefPtr(long_key))
                        m_expandedItems.erase(long_key);
                }

                // note that the debug item is a member of the parent debug data array
                debugItem_n->SetFlagBit(WXLUA_DEBUGITEM_EXPANDED, false);

                //m_listData.RemoveAt(n); // we remove them all at once for speed, see below
                //n--;
                //count = m_listData.GetCount();
                delete stkListData_n;
            }

            m_listData.RemoveAt(lc_item+1, n-lc_item-1);
        }

        wxUIntPtr long_key = 0;
        if (debugItem->GetRefPtr(long_key))
            m_expandedItems.erase(long_key);

        debugItem->SetFlagBit(WXLUA_DEBUGITEM_EXPANDED, false);

        m_listCtrl->SetItemCount(m_listData.GetCount());

        // don't call collapse here, let MSW do it if this is called from OnTreeItem
        // else we've already collapsed it in OnListActivated
        m_treeCtrl->DeleteChildren(stkListData->m_treeId);
        // Add back our dummy item for MSW to allow it to be reexpanded
        m_treeCtrl->AppendItem(stkListData->m_treeId, DUMMY_TREEITEM);

        EndBatch();
    }

    return collapsed;
}

void wxLuaStackDialog::DeleteAllListItemData()
{
    m_expandedItems.clear();

    int i, count = m_listData.GetCount();

    for (i = 0; i < count; ++i)
    {
        wxLuaStackListData* stkListData = (wxLuaStackListData*)m_listData[i];

        delete stkListData;
    }

    m_listData.Clear();
}

void wxLuaStackDialog::RemoveAllLuaReferences()
{
    if (!m_wxlState.Ok()) return; // doesn't have to be ok

    int i;

    lua_State* L = m_wxlState.GetLuaState();

    // remove the last to so we don't make any holes
    for (i = (int)m_luaReferences.GetCount()-1; i >= 0; --i)
    {
        bool ok = wxluaR_unref(L, m_luaReferences[i], &wxlua_lreg_debug_refs_key);
        wxCHECK_RET(ok, wxT("Unable to remove a reference in Lua"));
        //wxPrintf(wxT("Extra Lua reference in listctrl #%d ok %d ref %d count %d\n"), i, ok, m_luaReferences[i], m_luaReferences.GetCount());
    }

    m_luaReferences.Clear();


    // ----------------------------------------------------------------------
    // Sanity check to make sure that we've cleared all the references
    // There should be only one of us created at any time.
    if (1) {
    //wxLuaCheckStack cs(L, wxT("wxLuaStackDialog::RemoveAllLuaReferences"));
    lua_pushlightuserdata(L, &wxlua_lreg_debug_refs_key); // push name of table to get as key
    lua_rawget(L, LUA_REGISTRYINDEX);   // pop key, push result (the refs table)

    lua_pushnil(L);
    while (lua_next(L, -2) != 0)      // ref table can have holes in it
    {
        // value = -1, key = -2, table = -3
        if (!lua_isnumber(L, -2))
            wxPrintf(wxT("wxLuaStackDialog::RemoveAllLuaReferences refs not empty key=%d value=%d\n"), lua_type(L, -2), lua_type(L, -1));
        else if ((lua_tonumber(L, -2) == 0) && (lua_tonumber(L, -1) != 1))
            wxPrintf(wxT("wxLuaStackDialog::RemoveAllLuaReferences refs not empty key=%lf value=%lg\n"), lua_tonumber(L, -2), lua_tonumber(L, -1));

        lua_pop(L, 1); // pop value, lua_next will pop key at end
    }

    lua_pop(L, 1); // pop ref table
    }

    // Clear out the old numeric references since it should be "empty"
    // though full of dead table[idx]=next_idx, where table[0] = 1;
    wxlua_lreg_createtable(L, &wxlua_lreg_debug_refs_key);

    lua_gc(L, LUA_GCCOLLECT, 0); // full garbage collection to cleanup after ourselves
}
