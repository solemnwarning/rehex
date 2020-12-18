/////////////////////////////////////////////////////////////////////////////
// Name:         wxLuaStackTree.h
// Purpose:      Interface to display the Lua stack in wxLua
// Author:       J. Winwood, John Labenski
// Created:      April 2002
// Copyright:    (c) 2012 John Labenski, 2002. Lomtick Software. All rights reserved.
// Licence:      wxWidgets license.
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_LUA_STACKTREE_H_
#define _WX_LUA_STACKTREE_H_

#include <wx/dialog.h>
#include <wx/listctrl.h>
#include <wx/treectrl.h>

class WXDLLIMPEXP_FWD_CORE wxListCtrl;
class WXDLLIMPEXP_FWD_CORE wxListEvent;
class WXDLLIMPEXP_FWD_CORE wxSplitterWindow;
class WXDLLIMPEXP_FWD_CORE wxProgressDialog;

#include "wxlua/debug/wxluadebugdefs.h"
#include "wxlua/debug/wxldebug.h"

class WXDLLIMPEXP_FWD_WXLUADEBUG wxLuaDebugData;

WX_DECLARE_HASH_MAP( wxUIntPtr, wxUIntPtr, wxIntegerHash, wxIntegerEqual,
                     wxUIntPtrToUIntPtrHashMap );

// ----------------------------------------------------------------------------
// wxWindowIds for the wxLuaStackDialog
// ----------------------------------------------------------------------------

enum
{
    ID_WXLUA_STACK_CHOICE = 2000,
    ID_WXLUA_STACK_EXPAND_BUTTON,
    ID_WXLUA_STACK_COLLAPSE_BUTTON,

    ID_WXLUA_STACK_FIND_COMBO,
    ID_WXLUA_STACK_FINDNEXT_BUTTON,
    ID_WXLUA_STACK_FINDPREV_BUTTON,
    ID_WXLUA_STACK_FINDMENU_BUTTON,

    ID_WXLUA_STACK_SPLITTERWIN,
    ID_WXLUA_STACK_LISTCTRL,
    ID_WXLUA_STACK_TREECTRL,

    ID_WXLUA_STACK_LISTMENU_COPY_ROW,
    ID_WXLUA_STACK_LISTMENU_COPY_COL0,
    ID_WXLUA_STACK_LISTMENU_COPY_COL1,
    ID_WXLUA_STACK_LISTMENU_COPY_COL2,
    ID_WXLUA_STACK_LISTMENU_COPY_COL3,
    ID_WXLUA_STACK_LISTMENU_COPY_COL4,

    ID_WXLUA_STACK_FINDMENU_CASE,
    ID_WXLUA_STACK_FINDMENU_WHOLE_STRING,
    ID_WXLUA_STACK_FINDMENU_ALL,
    ID_WXLUA_STACK_FINDMENU_NAME,
    ID_WXLUA_STACK_FINDMENU_LEVEL,
    ID_WXLUA_STACK_FINDMENU_KEYTYPE,
    ID_WXLUA_STACK_FINDMENU_VALUETYPE,
    ID_WXLUA_STACK_FINDMENU_VALUE
};

// ----------------------------------------------------------------------------
// wxLuaStackListData - the data we store for the listctrl.
//
// Note: We do not use a tree structure for speed at the expense of memory.
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUADEBUG wxLuaStackListData
{
public:
    wxLuaStackListData(int item_idx, int level,
                       const wxLuaDebugData& parentDebugData,
                       const wxLuaDebugData& childrenDebugData = wxNullLuaDebugData) :
                       m_item_idx(item_idx), m_level(level),
                       m_parentDebugData(parentDebugData),
                       m_childrenDebugData(childrenDebugData) {}

    wxLuaDebugItem* GetDebugItem() { return m_parentDebugData.Item(m_item_idx); }

    int             m_item_idx;          // this item # in m_parentDebugData
    int             m_level;             // depth into the Lua tables
    wxLuaDebugData  m_parentDebugData;   // ref of parent's data
    wxLuaDebugData  m_childrenDebugData; // valid if this item has children, e.g. a table
    wxTreeItemId    m_treeId;            // valid if this item is in the treectrl, e.g. a table
};

// ----------------------------------------------------------------------------
// wxLuaStackTreeData - the data we store in the wxTreeCtrl item's data
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUADEBUG wxLuaStackTreeData : public wxTreeItemData
{
public:
    wxLuaStackTreeData(wxLuaStackListData* stkData) : m_stkListData(stkData) {}

    wxLuaStackListData*  m_stkListData; // we don't delete this
};

// ----------------------------------------------------------------------------
// wxLuaStackDialog
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUADEBUG wxLuaStackDialog : public wxDialog
{
public:
    wxLuaStackDialog() { Init(); }

    wxLuaStackDialog(const wxLuaState& wxlState,
                     wxWindow* parent, wxWindowID id = wxID_ANY,
                     const wxString& title = wxT("wxLua Stack"),
                     const wxPoint& pos = wxDefaultPosition,
                     const wxSize& size = wxDefaultSize)
    {
        Init();
        Create(wxlState, parent, id, title, pos, size);
    }

    virtual ~wxLuaStackDialog();

    bool Create(const wxLuaState& wxlState,
                wxWindow* parent, wxWindowID id = wxID_ANY,
                const wxString& title = wxT("wxLua Stack"),
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize);

    // Icon indexes for image list used in the listctrl
    enum
    {
        IMG_UNKNOWN,
        IMG_NONE,
        IMG_NIL,
        IMG_BOOLEAN,
        IMG_LIGHTUSERDATA,
        IMG_NUMBER,
        IMG_STRING,
        IMG_TABLE,
        IMG_LUAFUNCTION,
        IMG_USERDATA,
        IMG_THREAD,
        IMG_INTEGER,
        IMG_CFUNCTION,

        IMG_TABLE_OPEN,
        IMG__COUNT
    };

    // Columns in the wxListCtrl
    enum
    {
        LIST_COL_KEY,
        LIST_COL_LEVEL,
        LIST_COL_KEY_TYPE,
        LIST_COL_VALUE_TYPE,
        LIST_COL_VALUE,

        LIST_COL__MAX
    };

    // Draw the string centered in the bitmap
    virtual wxBitmap CreateBmpString(const wxBitmap& bmp, const wxString& s);
    // Get the IMG_XXX enum to use for this dataitem
    virtual int GetItemImage(const wxLuaDebugItem *dbgItem) const;
    // Get the string to show in the wxListCtrl
    virtual wxString GetItemText(long item, long column, bool exact_value = false);
    // Get the image to show for the column in the wxListCtrl
    virtual int GetItemColumnImage(long item, long column) const;
    // Get the attribute to use for the wxListCtrl
    virtual wxListItemAttr* GetItemAttr(long item) const;

    // Select one of the stack levels after calling EnumerateStack()
    void SelectStack(int stack_sel);

    // Override these functions if you need to provide an alternate way to get
    //   the wxLuaDebugData. See wxluadebugger lib and wxLuaDebuggerStackDialog
    virtual void EnumerateStack();
    virtual void EnumerateStackEntry(int nEntry);
    virtual void EnumerateTable(int nRef, int nEntry, long lc_item);

    // Fill the combobox with the stack entries in the debug data and select
    //  the first stack item.
    void FillStackCombobox(const wxLuaDebugData& debugData);
    // Clear the listctrl and add debug data into tree root. If at the top of
    //  the stack, enumerate the global stack data.
    void FillStackEntry(int nEntry, const wxLuaDebugData& debugData);
    // Fill a listctrl item with children from the debug data
    void FillTableEntry(long lc_item, const wxLuaDebugData& debugData);

    // implementation

    // Put BeginBatch() before adding/removing items and EndBatch() afterwards for speed.
    void BeginBatch();
    void EndBatch();

    long FindListItem(wxLuaStackListData* stkListData, bool get_parent = false) const;

    void OnExpandButton(wxCommandEvent& event);
    void OnMenu(wxCommandEvent& event);
    void OnFind(wxCommandEvent& event);

    // Handle and set the stack from the stack combo selection
    void OnSelectStack(wxCommandEvent &event);
    // Handle all wxTreeCtrl events
    void OnTreeItem(wxTreeEvent &event);
    // Handle and expand/collapse a listctrl item
    void OnListItem(wxListEvent &event);
    // Popup menu on right click
    void OnListRightClick(wxListEvent &event);

    // Expand a single list item
    bool ExpandItem(long lc_item);
    // Expand a list item and all its children
    bool ExpandItemChildren(long lc_item);
    // Collapse an item and its children
    bool CollapseItem(long lc_item);

    // Don't warn about expanding duplicate tables
    void SetShowDuplicateExpandMessage(bool show) { m_show_dup_expand_msg = show; }

//protected:
    void DeleteAllListItemData();
    void RemoveAllLuaReferences();

    wxSplitterWindow* m_splitterWin;
    wxListCtrl*       m_listCtrl;
    wxTreeCtrl*       m_treeCtrl;
    wxMenu*           m_listMenu;

    wxChoice*    m_stackChoice;   // display stack entries
    int          m_stack_sel;     // current stack selection
    wxArrayInt   m_stackEntries;  // stack entry references

    wxComboBox*  m_findComboBox;  // Find string combobox
    wxMenu*      m_findMenu;

    wxLuaState   m_wxlState;      // lua_State to show stack for
    wxArrayInt   m_luaReferences; // references from m_wxlState.wxluaR_Ref()

    wxImageList* m_imageList;     // image list for listctrl
    wxColour     m_typeColours[IMG__COUNT];
    int          m_img_font_size;

    wxListItemAttr m_itemAttr;    // reusable attr for the wxListCtrl

    bool m_show_dup_expand_msg;
    int  m_batch_count;

    wxUIntPtrToUIntPtrHashMap m_expandedItems; // map[long Lua table ptr] = &wxLuaStackListData

    wxArrayPtrVoid m_listData;    // array of wxLuaStackListData

    static wxSize sm_defaultSize;  // remember last dialog size
    static bool   sm_maximized;    // remember if maximized

private:
    void Init();

    DECLARE_ABSTRACT_CLASS(wxLuaStackDialog)
    DECLARE_EVENT_TABLE()
};

#endif //_WX_LUA_STACKTREE_H_
