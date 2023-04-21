// ===========================================================================
// Purpose:     GUI controls like buttons, combos, etc
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

// FIXME - handle WX_DECLARE_CONTROL_CONTAINER ?

// ---------------------------------------------------------------------------
// wxButton

#if wxLUA_USE_wxButton && wxUSE_BUTTON

#include "wx/button.h"

#define wxBU_LEFT
#define wxBU_RIGHT
#define wxBU_TOP
#define wxBU_BOTTOM
#define wxBU_ALIGN_MASK
#define wxBU_EXACTFIT
%wxchkver_2_6 #define wxBU_AUTODRAW
%wxchkver_3_0 #define wxBU_NOTEXT

class wxAnyButton : public wxControl
{
    %wxchkver_3_0_0 wxAnyButton();
    %wxchkver_3_0_0 wxBitmap GetBitmap() const;
    %wxchkver_3_0_0 wxBitmap GetBitmapCurrent() const;
    %wxchkver_3_0_0 wxBitmap GetBitmapDisabled() const;
    %wxchkver_3_0_0 wxBitmap GetBitmapFocus() const;
    %wxchkver_3_0_0 wxBitmap GetBitmapLabel() const;
    %wxchkver_3_0_0 wxBitmap GetBitmapPressed() const;
    %wxchkver_3_0_0 void SetBitmap(const wxBitmap& bitmap, wxDirection dir = wxLEFT);
    %wxchkver_3_0_0 void SetBitmapCurrent(const wxBitmap& bitmap);
    %wxchkver_3_0_0 void SetBitmapDisabled(const wxBitmap& bitmap);
    %wxchkver_3_0_0 void SetBitmapFocus(const wxBitmap& bitmap);
    %wxchkver_3_0_0 void SetBitmapLabel(const wxBitmap& bitmap);
    %wxchkver_3_0_0 void SetBitmapPressed(const wxBitmap& bitmap);
    %wxchkver_3_0_0 wxSize GetBitmapMargins();
    %wxchkver_3_0_0 void SetBitmapMargins(wxCoord x, wxCoord y);
    %wxchkver_3_0_0 void SetBitmapMargins(const wxSize& sz);
    %wxchkver_3_0_0 void SetBitmapPosition(wxDirection dir);
};

#if wxUSE_HEADERCTRL

#include "wx/headerctrl.h"

// class wxHeaderCtrlEvent
class %delete wxHeaderCtrlEvent : public wxNotifyEvent
{
    %wxEventType wxEVT_HEADER_CLICK
    %wxEventType wxEVT_HEADER_RIGHT_CLICK
    %wxEventType wxEVT_HEADER_MIDDLE_CLICK
    %wxEventType wxEVT_HEADER_DCLICK
    %wxEventType wxEVT_HEADER_RIGHT_DCLICK
    %wxEventType wxEVT_HEADER_MIDDLE_DCLICK
    %wxEventType wxEVT_HEADER_SEPARATOR_DCLICK
    %wxEventType wxEVT_HEADER_BEGIN_RESIZE
    %wxEventType wxEVT_HEADER_RESIZING
    %wxEventType wxEVT_HEADER_END_RESIZE
    %wxEventType wxEVT_HEADER_BEGIN_REORDER
    %wxEventType wxEVT_HEADER_END_REORDER
    %wxEventType wxEVT_HEADER_DRAGGING_CANCELLED

    wxHeaderCtrlEvent(wxEventType commandType = wxEVT_NULL, int winid = 0);
    wxHeaderCtrlEvent(const wxHeaderCtrlEvent& event);

    int GetColumn() const;
    void SetColumn(int col);
    int GetWidth() const;
    void SetWidth(int width);
    unsigned int GetNewOrder() const;
    void SetNewOrder(unsigned int order);
};

class wxHeaderCtrl : public wxControl
{
public:
    // wxHeaderCtrl();

    // wxHeaderCtrl(wxWindow *parent,
    //              wxWindowID winid = wxID_ANY,
    //              const wxPoint& pos = wxDefaultPosition,
    //              const wxSize& size = wxDefaultSize,
    //              long style = wxHD_DEFAULT_STYLE,
    //              const wxString& name = wxHeaderCtrlNameStr);

    // bool Create(wxWindow *parent,
    //             wxWindowID winid = wxID_ANY,
    //             const wxPoint& pos = wxDefaultPosition,
    //             const wxSize& size = wxDefaultSize,
    //             long style = wxHD_DEFAULT_STYLE,
    //             const wxString& name = wxHeaderCtrlNameStr);

    void SetColumnCount(unsigned int count);
    unsigned int GetColumnCount() const;
    bool IsEmpty() const;
    void UpdateColumn(unsigned int idx);
    void SetColumnsOrder(const wxArrayInt& order);
    wxArrayInt GetColumnsOrder() const;
    unsigned int GetColumnAt(unsigned int pos) const;
    unsigned int GetColumnPos(unsigned int idx) const;
    void ResetColumnsOrder();

    static void MoveColumnInOrderArray(const wxArrayInt& order, unsigned int idx, unsigned int pos);

    bool ShowColumnsMenu(const wxPoint& pt, const wxString& title = wxEmptyString);
    void AddColumnsItems(wxMenu& menu, int idColumnsBase = 0);
    bool ShowCustomizeDialog();
    // %wxchkver_2_9_4 int GetColumnTitleWidth(const wxHeaderColumn& col);
    %wxchkver_3_1_3 int GetColumnTitleWidth(unsigned int idx);
};

class wxHeaderCtrlSimple : public wxHeaderCtrl
{
public:
    wxHeaderCtrlSimple();

    wxHeaderCtrlSimple(wxWindow *parent,
                       wxWindowID winid = wxID_ANY,
                       const wxPoint& pos = wxDefaultPosition,
                       const wxSize& size = wxDefaultSize,
                       long style = wxHD_DEFAULT_STYLE,
                       const wxString& name = wxHeaderCtrlNameStr);

    // void InsertColumn(const wxHeaderColumnSimple& col, unsigned int idx);
    // void AppendColumn(const wxHeaderColumnSimple& col);
    void DeleteColumn(unsigned int idx);
    void ShowColumn(unsigned int idx, bool show = true);
    void HideColumn(unsigned int idx);
    void ShowSortIndicator(unsigned int idx, bool sortOrder = true);
    void RemoveSortIndicator();
};

#endif //wxUSE_HEADERCTRL

class wxButton : public wxAnyButton
{
    wxButton();
    wxButton(wxWindow *parent, wxWindowID id, const wxString& label, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxButton");
    bool Create(wxWindow *parent, wxWindowID id, const wxString& label, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxButton");
    %wxchkver_3_0_0 bool GetAuthNeeded() const;
    %wxchkver_3_1_3 static wxSize GetDefaultSize(wxWindow* win = NULL);
    %wxchkver_3_0_0 wxString GetLabel() const;
    %wxchkver_3_0_0 void SetAuthNeeded(bool needed = true);
    void     SetDefault();
    %wxchkver_3_0_0 void SetLabel(const wxString& label);
    !%wxchkver_3_1_3 static wxSize GetDefaultSize();
};

// ---------------------------------------------------------------------------
// wxBitmapButton

#if wxLUA_USE_wxBitmapButton && wxUSE_BMPBUTTON

#include "wx/bmpbuttn.h"

class wxBitmapButton : public wxAnyButton
{
    wxBitmapButton();
    wxBitmapButton(wxWindow* parent, wxWindowID id, const wxBitmap& bitmap, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxBU_AUTODRAW, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxBitmapButton");
    bool Create(wxWindow* parent, wxWindowID id, const wxBitmap& bitmap, const wxPoint& pos, const wxSize& size = wxDefaultSize, long style = wxBU_AUTODRAW, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxBitmapButton");
    %wxchkver_3_0_0 static wxBitmapButton* NewCloseButton(wxWindow* parent, wxWindowID winid);
    !%wxchkver_3_0_0 && %wxchkver_2_8 void SetBitmapHover(const wxBitmap& hover);
    !%wxchkver_3_0_0 && %wxchkver_2_8 wxBitmap GetBitmapHover() const;
    !%wxchkver_3_0_0 void     SetBitmapDisabled(const wxBitmap& bitmap);
    !%wxchkver_3_0_0 void     SetBitmapFocus(const wxBitmap& bitmap);
    !%wxchkver_3_0_0 void     SetBitmapLabel(const wxBitmap& bitmap);
    !%wxchkver_3_0_0 void     SetBitmapSelected(const wxBitmap& bitmap);
    !%wxchkver_3_0_0 wxBitmap GetBitmapDisabled() const;
    !%wxchkver_3_0_0 wxBitmap GetBitmapFocus() const;
    !%wxchkver_3_0_0 wxBitmap GetBitmapLabel() const;
    !%wxchkver_3_0_0 wxBitmap GetBitmapSelected() const;
};

#endif //wxLUA_USE_wxBitmapButton && wxUSE_BMPBUTTON
#endif //wxLUA_USE_wxButton && wxUSE_BUTTON

// ---------------------------------------------------------------------------
// wxToggleButton

#if wxLUA_USE_wxToggleButton && wxUSE_TOGGLEBTN

#include "wx/tglbtn.h"

class wxToggleButton : public wxAnyButton
{
    wxToggleButton();
    wxToggleButton(wxWindow *parent, wxWindowID id, const wxString& label, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxToggleButton");
    bool Create(wxWindow *parent, wxWindowID id, const wxString& label, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxToggleButton");
    bool GetValue() const;
    void SetValue(bool state);
};

class wxBitmapToggleButton : public wxToggleButton
{
    %wxchkver_3_0_0 wxBitmapToggleButton();
    %wxchkver_3_0_0 wxBitmapToggleButton(wxWindow* parent, wxWindowID id, const wxBitmap& label, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = 0, const wxValidator& val = wxDefaultValidator, const wxString& name = wxCheckBoxNameStr);
    %wxchkver_3_0_0 bool Create(wxWindow* parent, wxWindowID id, const wxBitmap& label, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = 0, const wxValidator& val = wxDefaultValidator, const wxString& name = wxCheckBoxNameStr);
    %wxchkver_3_0_0 bool GetValue() const;
    %wxchkver_3_0_0 void SetValue(bool state);
};

#endif //wxLUA_USE_wxToggleButton && wxUSE_TOGGLEBTN

// ---------------------------------------------------------------------------
// wxCheckBox

#if wxLUA_USE_wxCheckBox && wxUSE_CHECKBOX

#include "wx/checkbox.h"

#define wxCHK_2STATE
#define wxCHK_3STATE
#define wxCHK_ALLOW_3RD_STATE_FOR_USER

enum wxCheckBoxState
{
    wxCHK_UNCHECKED,
    wxCHK_CHECKED,
    wxCHK_UNDETERMINED
};

class wxCheckBox : public wxControl
{
    wxCheckBox();
    wxCheckBox(wxWindow* parent, wxWindowID id, const wxString& label, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = 0, const wxValidator& val = wxDefaultValidator, const wxString& name = "wxCheckBox");
    bool Create(wxWindow* parent, wxWindowID id, const wxString& label, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = 0, const wxValidator& val = wxDefaultValidator, const wxString& name = "wxCheckBox");

    bool GetValue() const;
    wxCheckBoxState Get3StateValue() const;
    bool Is3rdStateAllowedForUser() const;
    bool Is3State() const;
    bool IsChecked() const;
    void SetValue(const bool state);
    void Set3StateValue(const wxCheckBoxState state);
};

#endif //wxLUA_USE_wxCheckBox && wxUSE_CHECKBOX

// ---------------------------------------------------------------------------
// wxItemContainerImmutable

#if (wxLUA_USE_wxChoice|wxLUA_USE_wxComboBox|wxLUA_USE_wxListBox) && wxUSE_CONTROLS

#include "wx/ctrlsub.h"

class wxItemContainerImmutable
{
    // no constructor, used only as a base class

    virtual unsigned int GetCount() const;
    virtual bool IsEmpty() const;

    virtual wxString GetString(unsigned int n); // = 0;
    wxArrayString GetStrings() const;
    virtual void SetString(unsigned int n, const wxString& s); // = 0;

    virtual int FindString(const wxString& s, bool bCase = false) const;

    virtual void SetSelection(int n); //= 0;
    virtual int GetSelection() const; //= 0;

    bool SetStringSelection(const wxString& s);
    wxString GetStringSelection() const;

    void Select(int n);
};

// ---------------------------------------------------------------------------
// wxItemContainer

#include "wx/ctrlsub.h"

class wxItemContainer : public wxItemContainerImmutable
{
    // no constructor, used only as base class

    int Append(const wxString& item);
    int Append(const wxString& item, voidptr_long number); // C++ is (void *clientData) You can put a number here
    int Append(const wxString& item, wxClientData *clientData);

    void AppendString(const wxString& item);

    void Append(const wxArrayString& strings);

    int Insert(const wxString& item, unsigned int pos);
    int Insert(const wxString& item, unsigned int pos, voidptr_long number); // C++ is (void *clientData) You can put a number here
    int Insert(const wxString& item, unsigned int pos, wxClientData *clientData);

    void Set(const wxArrayString &items);

    virtual void Clear(); //= 0;
    virtual void Delete(unsigned int n); //= 0;

    void SetClientData(unsigned int n, voidptr_long number); // C++ is (void *clientData) You can put a number here
    voidptr_long GetClientData(unsigned int n) const; // C++ returns (void *) You get a number here

    void SetClientObject(unsigned int n, wxClientData* clientData);
    wxClientData* GetClientObject(unsigned int n) const;

    bool HasClientObjectData() const;
    bool HasClientUntypedData() const;
};

#endif

// ---------------------------------------------------------------------------
// wxControlWithItems

#include "wx/ctrlsub.h"

class wxControlWithItems : public wxControl, public wxItemContainer
{
    // no constructor, this is just a base class

    virtual bool ShouldInheritColours() const;
};

#endif //(wxLUA_USE_wxChoice|wxLUA_USE_wxComboBox|wxLUA_USE_wxListBox) && wxUSE_CONTROLS

// ---------------------------------------------------------------------------
// wxChoice

#if wxLUA_USE_wxChoice && wxUSE_CHOICE

#include "wx/choice.h"

class wxChoice : public wxControlWithItems
{
    wxChoice();
    wxChoice(wxWindow *parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, const wxArrayString& choices = wxLuaNullSmartwxArrayString, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxChoice");
    bool Create(wxWindow *parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, const wxArrayString& choices = wxLuaNullSmartwxArrayString, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxChoice");

    int    GetCurrentSelection() const;
    //int  GetColumns() const;       // Motif only but returns 1 otherwise
    //void SetColumns(int n = 1);

    void Command(wxCommandEvent& event);
};

#endif //wxLUA_USE_wxChoice && wxUSE_CHOICE

// ---------------------------------------------------------------------------
// wxComboBox

#if wxLUA_USE_wxComboBox && wxUSE_COMBOBOX

#include "wx/combobox.h"

#define wxCB_DROPDOWN
#define wxCB_READONLY
#define wxCB_SIMPLE
#define wxCB_SORT

class wxComboBox : public wxControl, public wxItemContainer
{
    wxComboBox();
    wxComboBox(wxWindow* parent, wxWindowID id, const wxString& value = "", const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, const wxArrayString& choices = wxLuaNullSmartwxArrayString, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxComboBox");
    bool Create(wxWindow* parent, wxWindowID id, const wxString& value = "", const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, const wxArrayString& choices = wxLuaNullSmartwxArrayString, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxComboBox");

    bool     CanCopy() const;
    bool     CanCut() const;
    bool     CanPaste() const;
    bool     CanRedo() const;
    bool     CanUndo() const;
    void     Copy();
    void     Cut();
    %wxchkver_2_8 virtual int GetCurrentSelection() const;
    long     GetInsertionPoint() const;
    long     GetLastPosition() const;
    wxString GetValue() const;
    void     Paste();
    void     Redo();
    void     Replace(long from, long to, const wxString& text);
    void     Remove(long from, long to);
    void     SetInsertionPoint(long pos);
    void     SetInsertionPointEnd();
    void     SetSelection(long from, long to);
    void     SetValue(const wxString& text);
    void     Undo();
};

#endif //wxLUA_USE_wxComboBox && wxUSE_COMBOBOX


#if wxUSE_COMBOCTRL

#include "wx/combo.h"

enum
{
    wxCC_SPECIAL_DCLICK             = 0x0100,
    wxCC_STD_BUTTON                 = 0x0200
};
enum
{
    wxCC_BUTTON_OUTSIDE_BORDER      = 0x0001,
    wxCC_POPUP_ON_MOUSE_UP          = 0x0002,
    wxCC_NO_TEXT_AUTO_SELECT        = 0x0004,
    wxCC_BUTTON_STAYS_DOWN          = 0x0008,
    wxCC_FULL_BUTTON                = 0x0010,
    wxCC_BUTTON_COVERS_BORDER       = 0x0020,

    wxCC_IFLAG_CREATED              = 0x0100,
    wxCC_IFLAG_BUTTON_OUTSIDE       = 0x0200,
    wxCC_IFLAG_LEFT_MARGIN_SET      = 0x0400,
    wxCC_IFLAG_PARENT_TAB_TRAVERSAL = 0x0800,
    wxCC_IFLAG_USE_ALT_POPUP        = 0x1000,
    wxCC_IFLAG_DISABLE_POPUP_ANIM   = 0x2000,
    wxCC_IFLAG_HAS_NONSTANDARD_BUTTON   = 0x4000
};
enum
{
    wxCC_MF_ON_BUTTON               =   0x0001, // cursor is on dropbutton area
    wxCC_MF_ON_CLICK_AREA           =   0x0002  // cursor is on dropbutton or other area
                                                // that can be clicked to show the popup.
};


// Namespace for wxComboCtrl feature flags
struct wxComboCtrlFeatures
{
    enum
    {
        MovableButton       = 0x0001, // Button can be on either side of control
        BitmapButton        = 0x0002, // Button may be replaced with bitmap
        ButtonSpacing       = 0x0004, // Button can have spacing from the edge
                                      // of the control
        TextIndent          = 0x0008, // SetMargins can be used to control
                                      // left margin.
        PaintControl        = 0x0010, // Combo control itself can be custom painted
        PaintWritable       = 0x0020, // A variable-width area in front of writable
                                      // combo control's textctrl can be custom
                                      // painted
        Borderless          = 0x0040, // wxNO_BORDER window style works
        All                 = MovableButton|BitmapButton|
                              ButtonSpacing|TextIndent|
                              PaintControl|PaintWritable|
                              Borderless
    };
};


class %delete wxComboCtrl : public wxControl, public wxTextEntry
{
public:
    wxComboCtrl();

    bool Create(wxWindow *parent,
                wxWindowID id,
                const wxString& value,
                const wxPoint& pos,
                const wxSize& size,
                long style,
                const wxValidator& validator,
                const wxString& name);
    virtual void Popup();
    virtual void Dismiss();
    virtual void ShowPopup();
    virtual void HidePopup(bool generateEvent=false);
    virtual void OnButtonClick();
    bool IsPopupShown() const;
    void SetPopupControl( wxComboPopup* popup );
    wxComboPopup* GetPopupControl();
    wxWindow *GetPopupWindow() const;
    wxTextCtrl *GetTextCtrl() const;
    wxWindow *GetButton() const;
    virtual bool Enable(bool enable = true);
    virtual bool Show(bool show = true);
    virtual bool SetFont(const wxFont& font);
    virtual void SetValue(const wxString& value);
    virtual void ChangeValue(const wxString& value);
    virtual void WriteText(const wxString& text);
    virtual void AppendText(const wxString& text);
    virtual wxString GetValue() const;
    virtual wxString GetRange(long from, long to) const;
    virtual void Replace(long from, long to, const wxString& value);
    virtual void Remove(long from, long to);
    virtual void Copy();
    virtual void Cut();
    virtual void Paste();
    virtual void Undo();
    virtual void Redo();
    virtual bool CanUndo() const;
    virtual bool CanRedo() const;
    virtual void SetInsertionPoint(long pos);
    virtual long GetInsertionPoint() const;
    virtual long GetLastPosition() const;
    virtual void SetSelection(long from, long to);
    virtual void GetSelection(long *from, long *to) const;
    virtual bool IsEditable() const;
    virtual void SetEditable(bool editable);
    virtual bool SetHint(const wxString& hint);
    virtual wxString GetHint() const;
    void SetText(const wxString& value);
    void SetValueByUser(const wxString& value);
    void SetPopupMinWidth( int width );
    void SetPopupMaxHeight( int height );
    void SetPopupExtents( int extLeft, int extRight );
    void SetCustomPaintWidth( int width );
    int GetCustomPaintWidth() const;
    void SetPopupAnchor( int anchorSide );
    void SetButtonPosition( int width = -1, int height = -1, int side = wxRIGHT, int spacingX = 0 );
    wxSize GetButtonSize();
    void SetButtonBitmaps( const wxBitmap& bmpNormal, bool pushButtonBg = false, const wxBitmap& bmpPressed = wxNullBitmap, const wxBitmap& bmpHover = wxNullBitmap, const wxBitmap& bmpDisabled = wxNullBitmap );
    const wxRect& GetTextRect() const;
    void UseAltPopupWindow( bool enable = true );
    void EnablePopupAnimation( bool enable = true );
    virtual bool IsKeyPopupToggle(const wxKeyEvent& event) const;
    virtual void PrepareBackground( wxDC& dc, const wxRect& rect, int flags ) const;
    bool ShouldDrawFocus() const;
    !%wxchkver_3_2_0 const wxBitmap& GetBitmapNormal() const;
    !%wxchkver_3_2_0 const wxBitmap& GetBitmapPressed() const;
    !%wxchkver_3_2_0 const wxBitmap& GetBitmapHover() const;
    !%wxchkver_3_2_0 const wxBitmap& GetBitmapDisabled() const;
    %wxchkver_3_2_0 wxBitmap GetBitmapNormal() const;
    %wxchkver_3_2_0 wxBitmap GetBitmapPressed() const;
    %wxchkver_3_2_0 wxBitmap GetBitmapHover() const;
    %wxchkver_3_2_0 wxBitmap GetBitmapDisabled() const;
    void SetTextCtrlStyle( int style );
    wxUint32 GetInternalFlags() const;
    bool IsCreated() const;
    wxColour GetBackgroundColour() const;
    void OnPopupDismiss(bool generateEvent);
    enum
    {
        Hidden       = 0,
        //Closing      = 1,
        Animating    = 2,
        Visible      = 3
    };
    bool IsPopupWindowState( int state );
    wxByte GetPopupWindowState() const;
    void SetCtrlMainWnd( wxWindow* wnd );
    virtual wxWindow *GetMainWindowOfCompositeControl();
    virtual bool SetForegroundColour(const wxColour& colour);
    virtual bool SetBackgroundColour(const wxColour& colour);
};

// ----------------------------------------------------------------------------
// wxComboPopup is the interface which must be implemented by a control to be
// used as a popup by wxComboCtrl
// ----------------------------------------------------------------------------


// wxComboPopup internal flags
enum
{
    wxCP_IFLAG_CREATED      = 0x0001 // Set by wxComboCtrlBase after Create is called
};

class %delete wxComboPopup
{
public:
    //wxComboPopup();
    virtual void Init();
    //virtual ~wxComboPopup();
    virtual bool Create(wxWindow* parent); // = 0;
    virtual void DestroyPopup();
    virtual wxWindow *GetControl(); // = 0;
    virtual void OnPopup();
    virtual void OnDismiss();
    virtual void SetStringValue( const wxString& value );
    virtual wxString GetStringValue() const; // = 0;
    virtual bool FindItem(const wxString& item, wxString* trueItem=NULL);
    virtual void PaintComboControl( wxDC& dc, const wxRect& rect );
    virtual void OnComboKeyEvent( wxKeyEvent& event );
    virtual void OnComboCharEvent( wxKeyEvent& event );
    virtual void OnComboDoubleClick();
    virtual wxSize GetAdjustedSize( int minWidth, int prefHeight, int maxHeight );
    virtual bool LazyCreate();
    void Dismiss();
    bool IsCreated() const;
    wxComboCtrl* GetComboCtrl() const;
};

#endif // wxUSE_COMBOCTRL

// ---------------------------------------------------------------------------
// wxGauge

#if wxLUA_USE_wxGauge && wxUSE_GAUGE

#include "wx/gauge.h"

%wxcompat_2_6 #define wxGA_PROGRESSBAR
#define wxGA_HORIZONTAL
#define wxGA_VERTICAL
%wxchkver_3_1_0 #define wxGA_PROGRESS
#define wxGA_SMOOTH
%wxchkver_3_1_0 #define wxGA_TEXT

class wxGauge : public wxControl
{
    wxGauge();
    wxGauge(wxWindow* parent, wxWindowID id, int range, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxGA_HORIZONTAL, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxGauge");
    bool Create(wxWindow* parent, wxWindowID id, int range, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxGA_HORIZONTAL, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxGauge");

    !%wxchkver_3_1_0 int GetBezelFace() const;
    int GetRange() const;
    !%wxchkver_3_1_0 int GetShadowWidth() const;
    int GetValue() const;
    bool IsVertical() const;
    %wxchkver_2_8 void Pulse();
    !%wxchkver_3_1_0 void SetBezelFace(int width);
    void SetRange(int range);
    !%wxchkver_3_1_0 void SetShadowWidth(int width);
    void SetValue(int pos);
};

#endif //wxLUA_USE_wxGauge && wxUSE_GAUGE

// ---------------------------------------------------------------------------
// wxListBox

#if wxLUA_USE_wxListBox && wxUSE_LISTBOX

#include "wx/listbox.h"

#define wxLB_SINGLE
#define wxLB_MULTIPLE
#define wxLB_EXTENDED
#define wxLB_HSCROLL
#define wxLB_ALWAYS_SB
#define wxLB_NEEDED_SB
#define wxLB_SORT
#define wxLB_OWNERDRAW

class wxListBox : public wxControlWithItems
{
    wxListBox();
    wxListBox(wxWindow* parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, const wxArrayString& choices = wxLuaNullSmartwxArrayString, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxListBox");
    bool Create(wxWindow* parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, const wxArrayString& choices = wxLuaNullSmartwxArrayString, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxListBox");

    void     Deselect(int n);

    // %override [Lua table of int selections] wxListBox::GetSelections();
    // C++ Func: int GetSelections(wxArrayInt& selections) const;
    int GetSelections() const;

    %wxchkver_2_8 int HitTest(const wxPoint& point) const;
    //void     InsertItems(int nItems, const wxString items[], int pos);
    void     InsertItems(const wxArrayString& items, int pos);
    bool     IsSelected(int n) const;
    //void     Set(int n, const wxString* choices);
    void     Set(const wxArrayString& choices);
    void     SetFirstItem(int n);
    void     SetSelection(int n, bool select = true);
    void     SetStringSelection(const wxString& string, bool select = true);
};

// ---------------------------------------------------------------------------
// wxCheckListBox

#if wxLUA_USE_wxCheckListBox && wxUSE_CHECKLISTBOX

#include "wx/checklst.h"

class wxCheckListBox : public wxListBox
{
    wxCheckListBox();
    wxCheckListBox(wxWindow* parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, const wxArrayString& choices = wxLuaNullSmartwxArrayString, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxCheckListBox");
    bool Create(wxWindow* parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, const wxArrayString& choices = wxLuaNullSmartwxArrayString, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxCheckListBox");

    void     Check(int item, bool check = true);
    bool     IsChecked(int item) const;
};

#endif //wxLUA_USE_wxCheckListBox && wxUSE_CHECKLISTBOX
#endif //wxLUA_USE_wxListBox && wxUSE_LISTBOX

// ---------------------------------------------------------------------------
// wxListCtrl - See wxLuaListCtrl to use the wxLC_VIRTUAL style.

#if wxLUA_USE_wxListCtrl && wxUSE_LISTCTRL

#include "wx/listctrl.h"

#define wxLC_ALIGN_LEFT
#define wxLC_ALIGN_TOP
#define wxLC_AUTOARRANGE
#define wxLC_EDIT_LABELS
#define wxLC_HRULES
#define wxLC_ICON
#define wxLC_LIST
#define wxLC_NO_HEADER
#define wxLC_NO_SORT_HEADER
#define wxLC_REPORT
#define wxLC_SINGLE_SEL
#define wxLC_SMALL_ICON
#define wxLC_SORT_ASCENDING
#define wxLC_SORT_DESCENDING
//#define wxLC_USER_TEXT - deprecated - use wxLC_VIRTUAL
#define wxLC_VIRTUAL
#define wxLC_VRULES

#define wxLC_MASK_TYPE     //  (wxLC_ICON | wxLC_SMALL_ICON | wxLC_LIST | wxLC_REPORT);
#define wxLC_MASK_ALIGN    //  (wxLC_ALIGN_TOP | wxLC_ALIGN_LEFT);
#define wxLC_MASK_SORT     //  (wxLC_SORT_ASCENDING | wxLC_SORT_DESCENDING);

#define wxLIST_ALIGN_DEFAULT
#define wxLIST_ALIGN_LEFT
#define wxLIST_ALIGN_SNAP_TO_GRID
#define wxLIST_ALIGN_TOP
#define wxLIST_AUTOSIZE
#define wxLIST_AUTOSIZE_USEHEADER
#define wxLIST_FIND_DOWN
#define wxLIST_FIND_LEFT
#define wxLIST_FIND_RIGHT
#define wxLIST_FIND_UP
#define wxLIST_HITTEST_ABOVE
#define wxLIST_HITTEST_BELOW
#define wxLIST_HITTEST_NOWHERE
#define wxLIST_HITTEST_ONITEM
#define wxLIST_HITTEST_ONITEMICON
#define wxLIST_HITTEST_ONITEMLABEL
#define wxLIST_HITTEST_ONITEMRIGHT
#define wxLIST_HITTEST_ONITEMSTATEICON
#define wxLIST_HITTEST_TOLEFT
#define wxLIST_HITTEST_TORIGHT
#define wxLIST_MASK_DATA
#define wxLIST_MASK_FORMAT
#define wxLIST_MASK_IMAGE
#define wxLIST_MASK_STATE
#define wxLIST_MASK_TEXT
#define wxLIST_MASK_WIDTH
#define wxLIST_NEXT_ABOVE
#define wxLIST_NEXT_ALL
#define wxLIST_NEXT_BELOW
#define wxLIST_NEXT_LEFT
#define wxLIST_NEXT_RIGHT
#define wxLIST_RECT_BOUNDS
#define wxLIST_RECT_ICON
#define wxLIST_RECT_LABEL
#define wxLIST_SET_ITEM
#define wxLIST_STATE_CUT
#define wxLIST_STATE_DONTCARE
#define wxLIST_STATE_DROPHILITED
#define wxLIST_STATE_FOCUSED
#define wxLIST_STATE_SELECTED

%wxchkver_2_8 #define wxLIST_GETSUBITEMRECT_WHOLEITEM

class wxListCtrl : public wxControl
{
    wxListCtrl();
    wxListCtrl(wxWindow* parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxLC_ICON, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxListCtrl");
    bool Create(wxWindow* parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxLC_ICON, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxListCtrl");

    bool     Arrange(int flag = wxLIST_ALIGN_DEFAULT);
    void     AssignImageList(%ungc wxImageList *imageList, int which);
    void     ClearAll();
    bool     DeleteAllItems();
    bool     DeleteColumn(int col);
    bool     DeleteItem(long item);
    void     EditLabel(long item);
    bool     EnsureVisible(long item);
    long     FindItem(long start, const wxString& str, const bool partial = false);
    long     FindItem(long start, long data);
    long     FindItem(long start, const wxPoint& pt, int direction);
    bool     GetColumn(int col, wxListItem& item) const;
    int      GetColumnCount() const;
    int      GetColumnWidth(int col) const;
    int      GetCountPerPage() const;
    %win|%wxchkver_2_8 wxTextCtrl* GetEditControl() const;
    wxImageList* GetImageList(int which) const;
    bool     GetItem(wxListItem& info) const;
    int      GetItemCount() const;
    long     GetItemData(long item) const;
    wxFont   GetItemFont(long item) const;
    bool     GetItemPosition(long item, wxPoint& pos) const;
    bool     GetItemRect(long item, wxRect& rect, int code = wxLIST_RECT_BOUNDS) const;
    !%wxchkver_2_6 int   GetItemSpacing(bool isSmall) const;
    %wxchkver_2_6 wxSize GetItemSpacing() const;
    int      GetItemState(long item, long stateMask) const;
    wxString GetItemText(long item) const;
    long     GetNextItem(long item, int geometry = wxLIST_NEXT_ALL, int state = wxLIST_STATE_DONTCARE) const;
    int      GetSelectedItemCount() const;
    wxColour GetTextColour() const;
    long     GetTopItem() const;
    wxRect   GetViewRect() const;

    // %override [long, int flags] wxListCtrl::HitTest(const wxPoint& point);
    // C++ Func: long HitTest(const wxPoint& point, int& flags);
    long     HitTest(const wxPoint& point);

    long     InsertColumn(long col, wxListItem& info);
    long     InsertColumn(long col, const wxString& heading, int format = wxLIST_FORMAT_LEFT, int width = -1);
    long     InsertItem(wxListItem& info);
    long     InsertItem(long index, const wxString& label);
    long     InsertItem(long index, int imageIndex);
    long     InsertItem(long index, const wxString& label, int imageIndex);
    //virtual wxListItemAttr * OnGetItemAttr(long item) const;
    //virtual int OnGetItemImage(long item);
    //virtual wxString OnGetItemText(long item, long column) const;
    //void RefreshItem(long item);
    //void RefreshItems(long itemFrom, long itemTo);
    bool     ScrollList(int dx, int dy);
    //void     SetBackgroundColour(const wxColour& col) - see wxWindow
    bool     SetColumn(int col, wxListItem& item);
    bool     SetColumnWidth(int col, int width);
    void     SetImageList(wxImageList* imageList, int which);
    bool     SetItem(wxListItem& info);
    long     SetItem(long index, int col, const wxString& label, int imageId = -1);
    void     SetItemBackgroundColour(long item, const wxColour& col);
    bool     SetItemColumnImage(long item, long column, int image);
    //void SetItemCount(long count);
    bool     SetItemData(long item, long data);
    bool     SetItemImage(long item, int image); // int selImage) selImage is deprecated and isn't used anyway
    bool     SetItemPosition(long item, const wxPoint& pos);
    bool     SetItemState(long item, long state, long stateMask);
    void     SetItemText(long item, const wxString& text);
    void     SetItemTextColour(long item, const wxColour& col);
    void     SetSingleStyle(long style, const bool add = true);
    void     SetTextColour(const wxColour& col);
    //void     SetWindowStyleFlag(long style) - see wxWindow

    // %override bool SortItems(Lua function(long item1, long item2, long data) returning int, long data);
    // C++ Func: bool SortItems(wxListCtrlCompare fnSortCallBack, long data);
    // Note: the data can only be a number, but you can create a table where the data is
    // an index of it if you need more information.
    // Also, the item1 and item2 are NOT the indexes in the wxListCtrl, but are the
    // client data associated with the item. see SetItemData(item, data) and again
    // you may want to make this "data" equal to an index in a table where you
    // store more information needed for sorting.
    // Your Lua function should return 1, 0, -1 for item1 > item2, item1 == item2, item1 < item2
    bool SortItems(LuaFunction fnSortCallBack, long data);
};


// ---------------------------------------------------------------------------
// wxLuaListCtrl - A wxListCtrl for the wxLC_VIRTUAL style.

class wxLuaListCtrl : public wxListCtrl
{
    // %override - the C++ function takes the wxLuaState as the first param
    wxLuaListCtrl(wxWindow* parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxLC_REPORT|wxLC_VIRTUAL, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxLuaListCtrl");

    // SetItemCount is needed for wxLC_VIRTUAL
    void SetItemCount(long count);

    // This function must be overridden
    // virtual wxString OnGetItemText (long item, long column) const;

    // This function must be overridden if there is an image list
    // virtual int OnGetItemImage (long item) const;

    // These functions may be overridden
    // virtual wxListItemAttr * OnGetItemAttr(long item) const;
    // virtual wxListItemAttr * OnGetItemColumnAttr(long item, long column) const;
    // virtual int OnGetItemColumnImage(long item, long column) const;
    // %wxchkver_3_0 && %msw virtual int OnGetItemColumnAttr(long item, long column) const;
};

// ---------------------------------------------------------------------------
// wxListItemAttr - wxListCtrl

class %delete wxListItemAttr
{
    wxListItemAttr(const wxColour& colText = wxNullColour, const wxColour& colBack = wxNullColour, const wxFont& font = wxNullFont);

    %wxchkver_2_8 void AssignFrom(const wxListItemAttr& source);
    wxColour GetBackgroundColour();
    wxFont GetFont();
    wxColour GetTextColour();
    bool HasBackgroundColour();
    bool HasFont();
    bool HasTextColour();
    void SetBackgroundColour(const wxColour& colBack);
    void SetFont(const wxFont& font);
    void SetTextColour(const wxColour& colText);
};

// ---------------------------------------------------------------------------
// wxListItem - wxListCtrl

enum wxListColumnFormat
{
    wxLIST_FORMAT_LEFT,
    wxLIST_FORMAT_RIGHT,
    wxLIST_FORMAT_CENTRE,
    wxLIST_FORMAT_CENTER
};

class %delete wxListItem : public wxObject
{
    wxListItem();
    wxListItem(const wxListItem& item);

    void     Clear();
    void     ClearAttributes();
    wxListColumnFormat GetAlign();
    wxListItemAttr *GetAttributes();
    wxColour GetBackgroundColour() const;
    int      GetColumn();
    long     GetData();
    wxFont   GetFont() const;
    long     GetId();
    int      GetImage();
    long     GetMask();
    long     GetState();
    wxString GetText();
    wxColour GetTextColour() const;
    int      GetWidth();
    bool     HasAttributes();
    void     SetAlign(wxListColumnFormat align);
    void     SetBackgroundColour(const wxColour& colBack);
    void     SetColumn(int col);
    void     SetData(long data);
    void     SetFont(const wxFont& font);
    void     SetId(long id);
    void     SetImage(int image);
    void     SetMask(long mask);
    void     SetState(long state);
    void     SetStateMask(long stateMask);
    void     SetText(const wxString& text);
    void     SetTextColour(const wxColour& colText);
    void     SetWidth(int width);
};

// ---------------------------------------------------------------------------
// wxListEvent - wxListCtrl

class %delete wxListEvent : public wxNotifyEvent
{
    %wxEventType wxEVT_COMMAND_LIST_BEGIN_DRAG             // EVT_LIST_BEGIN_DRAG(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_BEGIN_RDRAG            // EVT_LIST_BEGIN_RDRAG(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_BEGIN_LABEL_EDIT       // EVT_LIST_BEGIN_LABEL_EDIT(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_COL_CLICK              // EVT_LIST_COL_CLICK(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_DELETE_ALL_ITEMS       // EVT_LIST_DELETE_ALL_ITEMS(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_DELETE_ITEM            // EVT_LIST_DELETE_ITEM(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_END_LABEL_EDIT         // EVT_LIST_END_LABEL_EDIT(id, fn);
    !%wxchkver_2_6 %wxEventType wxEVT_COMMAND_LIST_GET_INFO // EVT_LIST_GET_INFO(id, fn);
    !%wxchkver_2_6 %wxEventType wxEVT_COMMAND_LIST_SET_INFO // EVT_LIST_SET_INFO(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_INSERT_ITEM            // EVT_LIST_INSERT_ITEM(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_ITEM_ACTIVATED         // EVT_LIST_ITEM_ACTIVATED(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_ITEM_DESELECTED        // EVT_LIST_ITEM_DESELECTED(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_ITEM_MIDDLE_CLICK      // EVT_LIST_ITEM_MIDDLE_CLICK(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_ITEM_RIGHT_CLICK       // EVT_LIST_ITEM_RIGHT_CLICK(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_ITEM_SELECTED          // EVT_LIST_ITEM_SELECTED(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_KEY_DOWN               // EVT_LIST_KEY_DOWN(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_CACHE_HINT             // EVT_LIST_CACHE_HINT(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_COL_RIGHT_CLICK        // EVT_LIST_COL_RIGHT_CLICK(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_COL_BEGIN_DRAG         // EVT_LIST_COL_BEGIN_DRAG(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_COL_DRAGGING           // EVT_LIST_COL_DRAGGING(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_COL_END_DRAG           // EVT_LIST_COL_END_DRAG(id, fn);
    %wxEventType wxEVT_COMMAND_LIST_ITEM_FOCUSED           // EVT_LIST_ITEM_FOCUSED(id, fn);

    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_BEGIN_DRAG       // wx3.0 alias for wxEVT_COMMAND_LIST_BEGIN_DRAG
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_BEGIN_RDRAG      // wx3.0 alias for wxEVT_COMMAND_LIST_BEGIN_RDRAG
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_BEGIN_LABEL_EDIT // wx3.0 alias for wxEVT_COMMAND_LIST_BEGIN_LABEL_EDIT
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_COL_CLICK        // wx3.0 alias for wxEVT_COMMAND_LIST_COL_CLICK
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_DELETE_ALL_ITEMS // wx3.0 alias for wxEVT_COMMAND_LIST_DELETE_ALL_ITEMS
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_DELETE_ITEM      // wx3.0 alias for wxEVT_COMMAND_LIST_DELETE_ITEM
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_END_LABEL_EDIT   // wx3.0 alias for wxEVT_COMMAND_LIST_END_LABEL_EDIT
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_INSERT_ITEM      // wx3.0 alias for wxEVT_COMMAND_LIST_INSERT_ITEM
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_ITEM_ACTIVATED   // wx3.0 alias for wxEVT_COMMAND_LIST_ITEM_ACTIVATED
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_ITEM_DESELECTED  // wx3.0 alias for wxEVT_COMMAND_LIST_ITEM_DESELECTED
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_ITEM_SELECTED    // wx3.0 alias for wxEVT_COMMAND_LIST_ITEM_SELECTED
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_KEY_DOWN         // wx3.0 alias for wxEVT_COMMAND_LIST_KEY_DOWN
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_CACHE_HINT       // wx3.0 alias for wxEVT_COMMAND_LIST_CACHE_HINT
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_COL_RIGHT_CLICK  // wx3.0 alias for wxEVT_COMMAND_LIST_COL_RIGHT_CLICK
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_COL_BEGIN_DRAG   // wx3.0 alias for wxEVT_COMMAND_LIST_COL_BEGIN_DRAG
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_COL_DRAGGING     // wx3.0 alias for wxEVT_COMMAND_LIST_COL_DRAGGING
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_COL_END_DRAG     // wx3.0 alias for wxEVT_COMMAND_LIST_COL_END_DRAG
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_ITEM_FOCUSED     // wx3.0 alias for wxEVT_COMMAND_LIST_ITEM_FOCUSED
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_ITEM_MIDDLE_CLICK // wx3.0 alias for wxEVT_COMMAND_LIST_ITEM_MIDDLE_CLICK
    %wxchkver_3_0_0 %wxEventType wxEVT_LIST_ITEM_RIGHT_CLICK // wx3.0 alias for wxEVT_COMMAND_LIST_ITEM_RIGHT_CLICK

    wxListEvent(wxEventType commandType = 0, int id = 0);

    //long GetCacheFrom() const; // - only useful for virtual controls
    //long GetCacheTo() const;
    int GetKeyCode() const;
    long GetIndex() const;
    int GetColumn() const;
    wxPoint GetPoint() const;
    const wxString& GetLabel() const;
    const wxString& GetText() const;
    int GetImage() const;
    long GetData() const;
    long GetMask() const;
    const wxListItem& GetItem() const;
    bool IsEditCancelled() const;
};

// ---------------------------------------------------------------------------
// wxListView

class wxListView : public wxListCtrl
{
    wxListView();
    wxListView(wxWindow* parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxLC_ICON, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxListView");
    bool Create(wxWindow* parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxLC_ICON, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxListView");

    void ClearColumnImage(int col);
    void Focus(long index);
    long GetFirstSelected() const;
    long GetFocusedItem() const;
    long GetNextSelected(long item) const;
    bool IsSelected(long index);
    void Select(long n, bool on = true);
    void SetColumnImage(int col, int image);
};

#endif //wxLUA_USE_wxListCtrl && wxUSE_LISTCTRL

// ---------------------------------------------------------------------------
// wxRadioBox

#if wxLUA_USE_wxRadioBox && wxUSE_RADIOBOX

#include "wx/radiobox.h"

#define wxRA_VERTICAL
#define wxRA_HORIZONTAL
#define wxRA_SPECIFY_COLS
#define wxRA_SPECIFY_ROWS
// #define wxRA_USE_CHECKBOX - only for palm os

class wxRadioBox : public wxControl
{
    wxRadioBox();
    wxRadioBox(wxWindow* parent, wxWindowID id, const wxString& label, const wxPoint& point = wxDefaultPosition, const wxSize& size = wxDefaultSize, const wxArrayString& choices = wxLuaNullSmartwxArrayString, int majorDimension = 0, long style = wxRA_SPECIFY_COLS, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxRadioBox");
    bool Create(wxWindow* parent, wxWindowID id, const wxString& label, const wxPoint& point = wxDefaultPosition, const wxSize& size = wxDefaultSize, const wxArrayString& choices = wxLuaNullSmartwxArrayString, int majorDimension = 0, long style = wxRA_SPECIFY_COLS, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxRadioBox");

    // these are marked deprecated in 2.6, use wxWindow::Get/SetLabel and Get/SetString below
    // wxString GetLabel() const; // - see wxWindow
    // void SetLabel(const wxString& label); // - see wxWindow
    // wxString GetLabel(int n) const;
    // void SetLabel(int n, const wxString& label);

    void Enable(bool enable);
    void Enable(int n, bool enable);
    int FindString(const wxString& string) const;
    int GetCount() const;
    int GetSelection() const;
    wxString GetStringSelection() const;
    wxString GetString(int n) const;
    void SetString(int n, const wxString &label);
    void SetSelection(int n);
    void SetStringSelection(const wxString& string);
    //bool Show(bool show = true); // see wxWindow
    bool Show(int item, bool show); // must specify both for overload
};

#endif //wxLUA_USE_wxRadioBox && wxUSE_RADIOBOX

// ---------------------------------------------------------------------------
// wxRadioButton

#if wxLUA_USE_wxRadioButton && wxUSE_RADIOBTN

#include "wx/radiobut.h"

#define wxRB_GROUP
#define wxRB_SINGLE
// #define wxRB_USE_CHECKBOX - only for palm os

class wxRadioButton : public wxControl
{
    wxRadioButton();
    wxRadioButton(wxWindow* parent, wxWindowID id, const wxString& label, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxRadioButton");
    bool Create(wxWindow* parent, wxWindowID id, const wxString& label, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxRadioButton");

    bool GetValue() const;
    void SetValue(const bool value);
};

#endif //wxLUA_USE_wxRadioButton && wxUSE_RADIOBTN

// ---------------------------------------------------------------------------
// wxScrollBar

#if wxLUA_USE_wxScrollBar && wxUSE_SCROLLBAR

#include "wx/scrolbar.h"

#define wxSB_HORIZONTAL
#define wxSB_VERTICAL

class wxScrollBar : public wxControl
{
    wxScrollBar();
    wxScrollBar(wxWindow* parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxSB_HORIZONTAL, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxScrollBar");
    bool Create(wxWindow* parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxSB_HORIZONTAL, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxScrollBar");

    int GetRange() const;
    int GetPageSize() const;
    int GetThumbPosition() const;
    int GetThumbSize() const;
    void SetThumbPosition(int viewStart);
    virtual void SetScrollbar(int position, int thumbSize, int range, int pageSize, const bool refresh = true);
};

#endif //wxLUA_USE_wxScrollBar && wxUSE_SCROLLBAR

// ---------------------------------------------------------------------------
// wxSlider

#if wxLUA_USE_wxSlider && wxUSE_SLIDER

#include "wx/slider.h"

#define wxSL_AUTOTICKS
#define wxSL_BOTH
#define wxSL_BOTTOM
#define wxSL_HORIZONTAL
#define wxSL_LABELS
#define wxSL_LEFT
#define wxSL_RIGHT
#define wxSL_SELRANGE
#define wxSL_TOP
#define wxSL_VERTICAL

class wxSlider : public wxControl
{
    wxSlider();
    wxSlider(wxWindow* parent, wxWindowID id, int value , int minValue, int maxValue, const wxPoint& point = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxSL_HORIZONTAL, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxSlider");
    bool Create(wxWindow* parent, wxWindowID id, int value , int minValue, int maxValue, const wxPoint& point = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxSL_HORIZONTAL, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxSlider");

    void ClearSel();
    void ClearTicks();
    int GetLineSize() const;
    int GetMax() const;
    int GetMin() const;
    int GetPageSize() const;
    int GetSelEnd() const;
    int GetSelStart() const;
    int GetThumbLength() const;
    int GetTickFreq() const;
    int GetValue() const;
    void SetLineSize(int lineSize);
    void SetPageSize(int pageSize);
    void SetRange(int minValue, int maxValue);
    void SetSelection(int startPos, int endPos);
    void SetThumbLength(int len);
    void SetTick(int tickPos);
    !%wxchkver_2_9 || %wxcompat_2_8 void SetTickFreq(int n, int pos);
    %wxchkver_2_8 && %win void SetTickFreq(int n);
    void SetValue(int value);
};

#endif //wxLUA_USE_wxSlider && wxUSE_SLIDER

// ---------------------------------------------------------------------------
// wxSpinButton

#if wxLUA_USE_wxSpinButton && wxUSE_SPINBTN

#include "wx/spinbutt.h"

#define wxSP_HORIZONTAL
#define wxSP_VERTICAL
#define wxSP_ARROW_KEYS
#define wxSP_WRAP

class wxSpinButton : public wxControl
{
    wxSpinButton();
    wxSpinButton(wxWindow *parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxSP_VERTICAL | wxSP_ARROW_KEYS, const wxString& name = "wxSpinButton");
    bool Create(wxWindow *parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxSP_VERTICAL | wxSP_ARROW_KEYS, const wxString& name = "wxSpinButton");

    int GetMax() const;
    int GetMin() const;
    int GetValue() const;
    void SetRange(int min, int max);
    void SetValue(int value);
};

// ---------------------------------------------------------------------------
// wxSpinEvent - for wxSpinButton

#include "wx/spinbutt.h"
#include "wx/spinctrl.h"

class %delete wxSpinEvent : public wxNotifyEvent
{
    %wxEventType wxEVT_SCROLL_LINEUP     // EVT_SPIN_UP(winid, func);
    %wxEventType wxEVT_SCROLL_LINEDOWN   // EVT_SPIN_DOWN(winid, func);
    %wxEventType wxEVT_SCROLL_THUMBTRACK // EVT_SPIN(winid, func);
    //%wxEventType wxEVT_COMMAND_SPINCTRL_UPDATED - actually a wxCommandEvent is sent

    wxSpinEvent(wxEventType commandType = wxEVT_NULL, int id = 0);

    int GetPosition() const;
    void SetPosition(int pos);
};

#endif //wxLUA_USE_wxSpinButton && wxUSE_SPINBTN

// ---------------------------------------------------------------------------
// wxSpinCtrl

#if wxLUA_USE_wxSpinCtrl && wxUSE_SPINCTRL

#include "wx/spinctrl.h"

//#define wxSP_ARROW_KEYS   see wxSpinButton
//#define wxSP_WRAP         see wxSpinButton

class wxSpinCtrl : public wxControl
{
    wxSpinCtrl();
    wxSpinCtrl(wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& value = wxEmptyString, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxSP_ARROW_KEYS, int min = 0, int max = 100, int initial = 0, const wxString& name = "wxSpinCtrl");
    bool Create(wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& value = wxEmptyString, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxSP_ARROW_KEYS, int min = 0, int max = 100, int initial = 0, const wxString& name = "wxSpinCtrl");

    %wxchkver_2_9_5 int GetBase() const;
    int GetMax() const;
    int GetMin() const;
    int GetValue() const;
    %wxchkver_2_9_5 bool SetBase(int base);
    void SetRange(int minVal, int maxVal);
    void SetSelection(long from, long to);
    void SetValue(const wxString& text);
    void SetValue(int iValue);
};

#endif //wxLUA_USE_wxSpinCtrl && wxUSE_SPINCTRL

// ---------------------------------------------------------------------------
// wxSpinDoubleCtrl

#if wxLUA_USE_wxSpinCtrlDouble && wxUSE_SPINCTRL

#include "wx/spinctrl.h"

//#define wxSP_ARROW_KEYS   see wxSpinButton
//#define wxSP_WRAP         see wxSpinButton

class %delete wxSpinDoubleEvent : public wxNotifyEvent
{
    %wxEventType wxEVT_SPINCTRLDOUBLE     // EVT_SPINCTRLDOUBLE(id, func);

    wxSpinDoubleEvent(wxEventType commandType = wxEVT_NULL, int winid=0, double value=0);

    double GetValue() const;
    void SetValue(double value);
};

class wxSpinCtrlDouble : public wxControl
{
    wxSpinCtrlDouble();
    wxSpinCtrlDouble(wxWindow *parent, wxWindowID id = wxID_ANY, const wxString& value = wxEmptyString, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxSP_ARROW_KEYS, double min = 0, double max = 100, double initial = 0, double inc = 1, const wxString& name = "wxSpinCtrlDouble");

    bool Create(wxWindow *parent, wxWindowID id = wxID_ANY, const wxString& value = wxEmptyString, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxSP_ARROW_KEYS, double min = 0, double max = 100, double initial = 0, double inc = 1, const wxString& name = "wxSpinCtrlDouble");

    // accessors
    double GetValue(wxSPINCTRL_GETVALUE_FIX);
    double GetMin() const;
    double GetMax() const;
    double GetIncrement();
    unsigned int GetDigits();

    // operations
    void SetValue(const wxString& value);
    void SetValue(double value);
    void SetRange(double minVal, double maxVal);
    void SetIncrement(double inc);
    void SetDigits(unsigned int digits);
};

#endif //wxLUA_USE_wxSpinCtrlDouble && wxUSE_SPINCTRL


// ---------------------------------------------------------------------------
// wxTextCtrl

#if wxLUA_USE_wxTextCtrl && wxUSE_TEXTCTRL

#include "wx/textctrl.h"

#define wxTE_PROCESS_ENTER
#define wxTE_PROCESS_TAB
#define wxTE_MULTILINE
#define wxTE_PASSWORD
#define wxTE_READONLY
#define wxTE_RICH
#define wxTE_RICH2
#define wxTE_AUTO_URL
#define wxTE_NOHIDESEL
#define wxTE_LEFT
#define wxTE_CENTRE
#define wxTE_RIGHT
#define wxTE_DONTWRAP
#define wxTE_CHARWRAP
#define wxTE_WORDWRAP
#define wxTE_BESTWRAP
#define wxTE_CAPITALIZE
!%wxchkver_2_9 || %wxcompat_2_8 #define wxTE_AUTO_SCROLL
#define wxTE_NO_VSCROLL

enum wxTextCtrlHitTestResult
{
    wxTE_HT_UNKNOWN,
    wxTE_HT_BEFORE,
    wxTE_HT_ON_TEXT,
    wxTE_HT_BELOW,
    wxTE_HT_BEYOND
};

typedef long wxTextCoord
#define wxOutOfRangeTextCoord
#define wxInvalidTextCoord

typedef long wxTextPos;

class wxTextEntry
{
    %wxchkver_3_0_0 void AppendText(const wxString& text);
    %wxchkver_3_0_0 bool AutoComplete(const wxArrayString& choices);
    // bool AutoComplete(wxTextCompleter *completer);
    %wxchkver_3_0_0 bool AutoCompleteFileNames();
    %wxchkver_3_0_0 bool AutoCompleteDirectories();
    %wxchkver_3_0_0 bool CanCopy() const;
    %wxchkver_3_0_0 bool CanCut() const;
    %wxchkver_3_0_0 bool CanPaste() const;
    %wxchkver_3_0_0 bool CanRedo() const;
    %wxchkver_3_0_0 bool CanUndo() const;
    %wxchkver_3_0_0 void ChangeValue(const wxString& value);
    %wxchkver_3_0_0 void Clear();
    %wxchkver_3_0_0 void Copy();
    %wxchkver_3_0_0 void Cut();
    %wxchkver_3_1_0 void ForceUpper();
    %wxchkver_3_0_0 long GetInsertionPoint() const;
    %wxchkver_3_0_0 wxTextPos GetLastPosition() const;
    %wxchkver_3_0_0 wxString GetRange(long from, long to) const;
    %wxchkver_3_0_0 wxString GetStringSelection() const;
    %wxchkver_3_0_0 wxString GetValue() const;
    %wxchkver_3_0_0 bool IsEditable() const;
    %wxchkver_3_0_0 bool IsEmpty() const;
    %wxchkver_3_0_0 void Paste();
    %wxchkver_3_0_0 void Redo();
    %wxchkver_3_0_0 void Remove(long from, long to);
    %wxchkver_3_0_0 void Replace(long from, long to, const wxString& value);
    %wxchkver_3_0_0 void SetEditable(bool editable);
    %wxchkver_3_0_0 void SetInsertionPoint(long pos);
    %wxchkver_3_0_0 void SetInsertionPointEnd();
    %wxchkver_3_0_0 void SetMaxLength(unsigned long len);
    %wxchkver_3_0_0 void SetSelection(long from, long to);
    %wxchkver_3_0_0 void SelectAll();
    %wxchkver_3_0_0 void SelectNone();
    %wxchkver_3_0_0 bool SetHint(const wxString& hint);
    %wxchkver_3_0_0 wxString GetHint() const;
    %wxchkver_3_0_0 bool SetMargins(const wxPoint& pt);
    %wxchkver_3_0_0 bool SetMargins(wxCoord left, wxCoord top = -1);
    %wxchkver_3_0_0 wxPoint GetMargins() const;
    %wxchkver_3_0_0 void SetValue(const wxString& value);
    %wxchkver_3_0_0 void Undo();
    %wxchkver_3_0_0 void WriteText(const wxString& text);
    %wxchkver_3_0_0 void GetSelection() const; // %override return [long from, long to]
};

class wxTextAreaBase
{
#if %wxchkver_3_0_0
    virtual int GetLineLength(long lineNo) const;
    virtual wxString GetLineText(long lineNo) const;
    virtual int GetNumberOfLines() const;
    bool LoadFile(const wxString& file, int fileType = wxTEXT_TYPE_ANY);
    bool SaveFile(const wxString& file = wxEmptyString, int fileType = wxTEXT_TYPE_ANY);
    virtual bool IsModified() const;
    virtual void MarkDirty();
    virtual void DiscardEdits();
    void SetModified(bool modified);
    virtual bool SetStyle(long start, long end, const wxTextAttr& style);
    virtual bool GetStyle(long position, wxTextAttr& style);
    virtual bool SetDefaultStyle(const wxTextAttr& style);
    virtual const wxTextAttr& GetDefaultStyle() const;
    virtual long XYToPosition(long x, long y) const;
    wxPoint PositionToCoords(long pos) const;
    virtual void ShowPosition(long pos);
    virtual wxString GetValue() const;
    virtual void SetValue(const wxString& value);
    %rename HitTestPos wxTextCtrlHitTestResult HitTest(const wxPoint& pt) const; // return [wxTextCtrlHitTestResult, int pos]
    virtual wxTextCtrlHitTestResult HitTest(const wxPoint& pt) const; // %override return [wxTextCtrlHitTestResult, int col, int row]
    virtual bool PositionToXY(long pos) const; // %override return [bool, int x, int y]
#endif // %wxchkver_3_0_0
};

class wxTextCtrlIface : public wxTextAreaBase, public wxTextEntry
{
    virtual wxString GetValue() const;
    virtual void SetValue(const wxString& value);
};

class wxTextCtrl : public wxControl, public wxTextEntry, public wxTextAreaBase
{
    wxTextCtrl();
    wxTextCtrl(wxWindow *parent, wxWindowID id, const wxString& value = "", const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxTextCtrl");
    bool Create(wxWindow* parent, wxWindowID id, const wxString& value = "", const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = 0, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxTextCtrl");
    !%wxchkver_3_0_0 void DiscardEdits();
    bool EmulateKeyPress(const wxKeyEvent& event);
    const wxTextAttr&  GetDefaultStyle() const;
    !%wxchkver_3_0_0 int GetLineLength(long lineNo) const;
    !%wxchkver_3_0_0 wxString GetLineText(long lineNo) const;
    !%wxchkver_3_0_0 int GetNumberOfLines() const;
    !%wxchkver_3_0_0 bool GetStyle(long position, wxTextAttr& style);
    !%wxchkver_3_0_0 bool IsModified() const;
    bool IsMultiLine() const;
    bool IsSingleLine() const;
    !%wxchkver_3_0_0 void MarkDirty();
    // void OnDropFiles(wxDropFilesEvent& event);
    !%wxchkver_3_0_0 bool SetDefaultStyle(const wxTextAttr& style);
    !%wxchkver_3_0_0 bool SetStyle(long start, long end, const wxTextAttr& style);
    !%wxchkver_3_0_0 void ShowPosition(long pos);
    !%wxchkver_3_0_0 long XYToPosition(long x, long y);
    !%wxchkver_3_0_0 bool IsEditable() const;
    !%wxchkver_3_0_0 bool LoadFile(const wxString& filename);
    !%wxchkver_3_0_0 bool SaveFile(const wxString& filename);
    !%wxchkver_3_0_0 virtual bool CanCopy();
    !%wxchkver_3_0_0 virtual bool CanCut();
    !%wxchkver_3_0_0 virtual bool CanPaste();
    !%wxchkver_3_0_0 virtual bool CanRedo();
    !%wxchkver_3_0_0 virtual bool CanUndo();
    !%wxchkver_3_0_0 virtual long GetInsertionPoint() const;
    !%wxchkver_3_0_0 virtual long GetLastPosition() const;
    !%wxchkver_3_0_0 virtual void ChangeValue(const wxString& value);
    !%wxchkver_3_0_0 virtual void Clear();
    !%wxchkver_3_0_0 virtual void Copy();
    !%wxchkver_3_0_0 virtual void Cut();
    !%wxchkver_3_0_0 virtual void Paste();
    !%wxchkver_3_0_0 virtual void Redo();
    !%wxchkver_3_0_0 virtual void Remove(long from, long to);
    !%wxchkver_3_0_0 virtual void Replace(long from, long to, const wxString& value);
    !%wxchkver_3_0_0 virtual void SetEditable(bool editable);
    !%wxchkver_3_0_0 virtual void SetInsertionPoint(long pos);
    !%wxchkver_3_0_0 virtual void SetInsertionPointEnd();
    !%wxchkver_3_0_0 virtual void SetMaxLength(unsigned long value);
    !%wxchkver_3_0_0 virtual void SetSelection(long from, long to);
    !%wxchkver_3_0_0 virtual void SetValue(const wxString& value);
    !%wxchkver_3_0_0 virtual void Undo();
    !%wxchkver_3_0_0 virtual wxString GetRange(long from, long to) const;
    !%wxchkver_3_0_0 virtual wxString GetStringSelection();
    !%wxchkver_3_0_0 void AppendText(const wxString& text);
    !%wxchkver_3_0_0 void GetSelection() const;
    !%wxchkver_3_0_0 void WriteText(const wxString& text);
    !%wxchkver_3_0_0 wxString GetValue() const;
    !%wxchkver_3_0_0 %rename HitTestPos wxTextCtrlHitTestResult HitTest(const wxPoint& pt) const; // return [wxTextCtrlHitTestResult, int pos]
    !%wxchkver_3_0_0 bool PositionToXY(long pos) const; // %override return [bool, int x, int y]
    !%wxchkver_3_0_0 wxTextCtrlHitTestResult HitTest(const wxPoint& pt) const; // %override return [wxTextCtrlHitTestResult, int col, int row]
};

enum wxTextAttrAlignment
{
    wxTEXT_ALIGNMENT_DEFAULT,
    wxTEXT_ALIGNMENT_LEFT,
    wxTEXT_ALIGNMENT_CENTRE,
    wxTEXT_ALIGNMENT_CENTER,
    wxTEXT_ALIGNMENT_RIGHT,
    wxTEXT_ALIGNMENT_JUSTIFIED
};

#define wxTEXT_ATTR_TEXT_COLOUR
#define wxTEXT_ATTR_BACKGROUND_COLOUR
#define wxTEXT_ATTR_FONT_FACE
#define wxTEXT_ATTR_FONT_SIZE
#define wxTEXT_ATTR_FONT_WEIGHT
#define wxTEXT_ATTR_FONT_ITALIC
#define wxTEXT_ATTR_FONT_UNDERLINE
#define wxTEXT_ATTR_FONT
#define wxTEXT_ATTR_ALIGNMENT
#define wxTEXT_ATTR_LEFT_INDENT
#define wxTEXT_ATTR_RIGHT_INDENT
#define wxTEXT_ATTR_TABS

#if %wxchkver_3_0_0

#define wxTEXT_ATTR_FONT_POINT_SIZE
#define wxTEXT_ATTR_FONT_PIXEL_SIZE
#define wxTEXT_ATTR_FONT_STRIKETHROUGH
#define wxTEXT_ATTR_FONT_ENCODING
#define wxTEXT_ATTR_FONT_FAMILY
#define wxTEXT_ATTR_TABS
#define wxTEXT_ATTR_PARA_SPACING_AFTER
#define wxTEXT_ATTR_PARA_SPACING_BEFORE
#define wxTEXT_ATTR_LINE_SPACING
#define wxTEXT_ATTR_CHARACTER_STYLE_NAME
#define wxTEXT_ATTR_PARAGRAPH_STYLE_NAME
#define wxTEXT_ATTR_LIST_STYLE_NAME
#define wxTEXT_ATTR_BULLET_STYLE
#define wxTEXT_ATTR_BULLET_NUMBER
#define wxTEXT_ATTR_BULLET_TEXT
#define wxTEXT_ATTR_BULLET_NAME
#define wxTEXT_ATTR_BULLET
#define wxTEXT_ATTR_URL
#define wxTEXT_ATTR_PAGE_BREAK
#define wxTEXT_ATTR_EFFECTS
#define wxTEXT_ATTR_OUTLINE_LEVEL
#define wxTEXT_ATTR_CHARACTER
#define wxTEXT_ATTR_PARAGRAPH
#define wxTEXT_ATTR_ALL

enum wxTextAttrBulletStyle
{
    wxTEXT_ATTR_BULLET_STYLE_NONE            = 0x00000000,
    wxTEXT_ATTR_BULLET_STYLE_ARABIC          = 0x00000001,
    wxTEXT_ATTR_BULLET_STYLE_LETTERS_UPPER   = 0x00000002,
    wxTEXT_ATTR_BULLET_STYLE_LETTERS_LOWER   = 0x00000004,
    wxTEXT_ATTR_BULLET_STYLE_ROMAN_UPPER     = 0x00000008,
    wxTEXT_ATTR_BULLET_STYLE_ROMAN_LOWER     = 0x00000010,
    wxTEXT_ATTR_BULLET_STYLE_SYMBOL          = 0x00000020,
    wxTEXT_ATTR_BULLET_STYLE_BITMAP          = 0x00000040,
    wxTEXT_ATTR_BULLET_STYLE_PARENTHESES     = 0x00000080,
    wxTEXT_ATTR_BULLET_STYLE_PERIOD          = 0x00000100,
    wxTEXT_ATTR_BULLET_STYLE_STANDARD        = 0x00000200,
    wxTEXT_ATTR_BULLET_STYLE_RIGHT_PARENTHESIS = 0x00000400,
    wxTEXT_ATTR_BULLET_STYLE_OUTLINE         = 0x00000800,

    wxTEXT_ATTR_BULLET_STYLE_ALIGN_LEFT      = 0x00000000,
    wxTEXT_ATTR_BULLET_STYLE_ALIGN_RIGHT     = 0x00001000,
    wxTEXT_ATTR_BULLET_STYLE_ALIGN_CENTRE    = 0x00002000,

    wxTEXT_ATTR_BULLET_STYLE_CONTINUATION    = 0x00004000
};

enum wxTextAttrEffects
{
    wxTEXT_ATTR_EFFECT_NONE                  = 0x00000000,
    wxTEXT_ATTR_EFFECT_CAPITALS              = 0x00000001,
    wxTEXT_ATTR_EFFECT_SMALL_CAPITALS        = 0x00000002,
    wxTEXT_ATTR_EFFECT_STRIKETHROUGH         = 0x00000004,
    wxTEXT_ATTR_EFFECT_DOUBLE_STRIKETHROUGH  = 0x00000008,
    wxTEXT_ATTR_EFFECT_SHADOW                = 0x00000010,
    wxTEXT_ATTR_EFFECT_EMBOSS                = 0x00000020,
    wxTEXT_ATTR_EFFECT_OUTLINE               = 0x00000040,
    wxTEXT_ATTR_EFFECT_ENGRAVE               = 0x00000080,
    wxTEXT_ATTR_EFFECT_SUPERSCRIPT           = 0x00000100,
    wxTEXT_ATTR_EFFECT_SUBSCRIPT             = 0x00000200
};

enum wxTextAttrLineSpacing
{
    wxTEXT_ATTR_LINE_SPACING_NORMAL         = 10,
    wxTEXT_ATTR_LINE_SPACING_HALF           = 15,
    wxTEXT_ATTR_LINE_SPACING_TWICE          = 20
};

#endif // %wxchkver_3_0_0

class %delete wxTextAttr
{
    //wxTextAttr();
    wxTextAttr(const wxColour& colText = wxNullColour, const wxColour& colBack = wxNullColour, const wxFont& font = wxNullFont, wxTextAttrAlignment alignment = wxTEXT_ALIGNMENT_DEFAULT);

    wxTextAttrAlignment GetAlignment() const;
    wxColour GetBackgroundColour() const;
    long GetFlags() const;
    wxFont GetFont() const;
    long GetLeftIndent() const;
    long GetLeftSubIndent() const;
    long GetRightIndent() const;
    const wxArrayInt& GetTabs() const;
    wxColour GetTextColour() const;
    bool HasAlignment() const;
    bool HasBackgroundColour() const;
    bool HasFlag(long flag) const;
    bool HasFont() const;
    bool HasLeftIndent() const;
    bool HasRightIndent() const;
    bool HasTabs() const;
    bool HasTextColour() const;
    bool IsDefault() const;
    void SetAlignment(wxTextAttrAlignment alignment);
    void SetBackgroundColour(const wxColour& colBack);
    void SetFlags(long flags);
    void SetFont(const wxFont& font, long flags = wxTEXT_ATTR_FONT);
    void SetLeftIndent(int indent, int subIndent = 0);
    void SetRightIndent(int indent);
    void SetTabs(const wxArrayInt& tabs);
    void SetTextColour(const wxColour& colText);
    
#if %wxchkver_3_0_0
    bool EqPartial(const wxTextAttr& attr, bool weakTest = true) const;
    bool GetFontAttributes(const wxFont& font, int flags = wxTEXT_ATTR_FONT);
    void SetFontSize(int pointSize);
    void SetFontPointSize(int pointSize);
    void SetFontPixelSize(int pixelSize);
    void SetFontStyle(wxFontStyle fontStyle);
    void SetFontWeight(wxFontWeight fontWeight);
    void SetFontFaceName(const wxString& faceName);
    void SetFontUnderlined(bool underlined);
    void SetFontStrikethrough(bool strikethrough);
    void SetFontEncoding(wxFontEncoding encoding);
    void SetFontFamily(wxFontFamily family);
    void SetCharacterStyleName(const wxString& name);
    void SetParagraphStyleName(const wxString& name);
    void SetListStyleName(const wxString& name);
    void SetParagraphSpacingAfter(int spacing);
    void SetParagraphSpacingBefore(int spacing);
    void SetLineSpacing(int spacing);
    void SetBulletStyle(int style);
    void SetBulletNumber(int n);
    void SetBulletText(const wxString& text);
    void SetBulletFont(const wxString& bulletFont);
    void SetBulletName(const wxString& name);
    void SetURL(const wxString& url);
    void SetPageBreak(bool pageBreak = true);
    void SetTextEffects(int effects);
    void SetTextEffectFlags(int effects);
    void SetOutlineLevel(int level);
    int GetFontSize() const;
    wxFontStyle GetFontStyle() const;
    wxFontWeight GetFontWeight() const;
    bool GetFontUnderlined() const;
    bool GetFontStrikethrough() const;
    const wxString& GetFontFaceName() const;
    wxFontEncoding GetFontEncoding() const;
    wxFontFamily GetFontFamily() const;
    const wxString& GetCharacterStyleName() const;
    const wxString& GetParagraphStyleName() const;
    const wxString& GetListStyleName() const;
    int GetParagraphSpacingAfter() const;
    int GetParagraphSpacingBefore() const;

    int GetLineSpacing() const;
    int GetBulletStyle() const;
    int GetBulletNumber() const;
    const wxString& GetBulletText() const;
    const wxString& GetBulletFont() const;
    const wxString& GetBulletName() const;
    const wxString& GetURL() const;
    int GetTextEffects() const;
    int GetTextEffectFlags() const;
    int GetOutlineLevel() const;
    bool HasFontWeight() const;
    bool HasFontSize() const;
    bool HasFontPointSize() const;
    bool HasFontPixelSize() const;
    bool HasFontItalic() const;
    bool HasFontUnderlined() const;
    bool HasFontStrikethrough() const;
    bool HasFontFaceName() const;
    bool HasFontEncoding() const;
    bool HasFontFamily() const;
    bool HasParagraphSpacingAfter() const;
    bool HasParagraphSpacingBefore() const;
    bool HasLineSpacing() const;
    bool HasCharacterStyleName() const;
    bool HasParagraphStyleName() const;
    bool HasListStyleName() const;
    bool HasBulletStyle() const;
    bool HasBulletNumber() const;
    bool HasBulletText() const;
    bool HasBulletName() const;
    bool HasURL() const;
    bool HasPageBreak() const;
    bool HasTextEffects() const;
    bool HasTextEffect(int effect) const;
    bool HasOutlineLevel() const;
    void RemoveFlag(long flag);
    void AddFlag(long flag);

    // Is this a character style?
    bool IsCharacterStyle() const;
    bool IsParagraphStyle() const;
    bool Apply(const wxTextAttr& style, const wxTextAttr* compareWith = NULL);
    static wxTextAttr Merge(const wxTextAttr& base, const wxTextAttr& overlay);
    void Merge(const wxTextAttr& overlay)
    static wxTextAttr Combine(const wxTextAttr& attr, const wxTextAttr& attrDef, const wxTextCtrl *text);

    // Compare tabs
    static bool TabsEq(const wxArrayInt& tabs1, const wxArrayInt& tabs2);

    // Remove attributes
    static bool RemoveStyle(wxTextAttr& destStyle, const wxTextAttr& style);

    // Combine two bitlists, specifying the bits of interest with separate flags.
    static bool CombineBitlists(int& valueA, int valueB, int& flagsA, int flagsB);

    // Compare two bitlists
    static bool BitlistsEqPartial(int valueA, int valueB, int flags);

    // Split into paragraph and character styles
    static bool SplitParaCharStyles(const wxTextAttr& style, wxTextAttr& parStyle, wxTextAttr& charStyle);

#endif // %wxchkver_3_0_0

};

// ---------------------------------------------------------------------------
// wxTextUrlEvent

class %delete wxTextUrlEvent : public wxCommandEvent
{
    %wxchkver_2_8_0 %wxEventType wxEVT_COMMAND_TEXT_URL        // EVT_TEXT_URL(id, fn);
    %wxchkver_3_0_0 %wxEventType wxEVT_TEXT_URL  // wx3.0 alias for wxEVT_COMMAND_TEXT_URL

    wxTextUrlEvent(int winid, const wxMouseEvent& evtMouse, long start, long end);

    const wxMouseEvent& GetMouseEvent() const;
    long GetURLStart() const;
    long GetURLEnd() const;
};

#endif //wxLUA_USE_wxTextCtrl && wxUSE_TEXTCTRL

// ---------------------------------------------------------------------------
// wxTreeCtrl

#if wxLUA_USE_wxTreeCtrl && wxUSE_TREECTRL

#include "wx/treectrl.h"

#define wxTR_NO_BUTTONS
#define wxTR_HAS_BUTTONS
#define wxTR_TWIST_BUTTONS
#define wxTR_NO_LINES
#define wxTR_SINGLE
#define wxTR_MULTIPLE
!%wxchkver_2_9 || %wxcompat_2_8 #define wxTR_EXTENDED
#define wxTR_EDIT_LABELS
#define wxTR_LINES_AT_ROOT
#define wxTR_HIDE_ROOT
#define wxTR_ROW_LINES
#define wxTR_HAS_VARIABLE_ROW_HEIGHT
#define wxTR_FULL_ROW_HIGHLIGHT
#define wxTR_DEFAULT_STYLE

enum wxTreeItemIcon
{
    wxTreeItemIcon_Normal,
    wxTreeItemIcon_Selected,
    wxTreeItemIcon_Expanded,
    wxTreeItemIcon_SelectedExpanded,
    wxTreeItemIcon_Max
};

#define wxTREE_HITTEST_ABOVE
#define wxTREE_HITTEST_BELOW
#define wxTREE_HITTEST_NOWHERE
#define wxTREE_HITTEST_ONITEMBUTTON
#define wxTREE_HITTEST_ONITEMICON
#define wxTREE_HITTEST_ONITEMINDENT
#define wxTREE_HITTEST_ONITEMLABEL
#define wxTREE_HITTEST_ONITEMRIGHT
#define wxTREE_HITTEST_ONITEMSTATEICON
#define wxTREE_HITTEST_TOLEFT
#define wxTREE_HITTEST_TORIGHT
#define wxTREE_HITTEST_ONITEMUPPERPART
#define wxTREE_HITTEST_ONITEMLOWERPART
#define wxTREE_HITTEST_ONITEM

%wxchkver_2_9 #define wxTREE_ITEMSTATE_NONE // not state (no display state image)
%wxchkver_2_9 #define wxTREE_ITEMSTATE_NEXT // cycle to the next state
%wxchkver_2_9 #define wxTREE_ITEMSTATE_PREV // cycle to the previous state

class wxTreeCtrl : public wxControl
{
    wxTreeCtrl();
    wxTreeCtrl(wxWindow* parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxTR_DEFAULT_STYLE, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxTreeCtrl");
    wxTreeItemId AddRoot(const wxString& text, int image = -1, int selImage = -1, %ungc wxLuaTreeItemData* data = NULL);
    wxTreeItemId AppendItem(const wxTreeItemId& parent, const wxString& text, int image = -1, int selImage = -1, %ungc wxLuaTreeItemData* data = NULL);
    // void AssignButtonsImageList(%ungc wxImageList* imageList); // This function is only available in the generic version.
    void AssignImageList(%ungc wxImageList* imageList);
    void AssignStateImageList(%ungc wxImageList* imageList);
    void Collapse(const wxTreeItemId& item);
    void CollapseAll();
    void CollapseAllChildren(const wxTreeItemId& item);
    void CollapseAndReset(const wxTreeItemId& item);
    bool Create(wxWindow* parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxTR_HAS_BUTTONS, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxTreeCtrl");
    void Delete(const wxTreeItemId& item);
    void DeleteAllItems();
    void DeleteChildren(const wxTreeItemId& item);
    %wxchkver_3_0_0 void EnableBellOnNoMatch(bool on = true);
    %win void EndEditLabel(const wxTreeItemId& item, bool discardChanges = false);
    void EnsureVisible(const wxTreeItemId& item);
    void Expand(const wxTreeItemId& item);
    void ExpandAll();
    void ExpandAllChildren(const wxTreeItemId& item);
    bool GetBoundingRect(const wxTreeItemId& item, wxRect& rect, bool textOnly = false) const;
    // wxImageList* GetButtonsImageList() const; // This function is only available in the generic version.
    size_t GetChildrenCount(const wxTreeItemId& item, bool recursively = true) const;
    int GetCount() const;
    %win wxTextCtrl* GetEditControl() const;
    wxTreeItemId GetFirstVisibleItem() const;
    %wxchkver_3_0_0 wxTreeItemId GetFocusedItem() const;
    %wxchkver_3_0_0 void ClearFocusedItem();
    %wxchkver_3_0_0 void SetFocusedItem(const wxTreeItemId& item);
    wxImageList* GetImageList() const;
    int GetIndent() const;
    unsigned int GetSpacing() const;
    wxColour GetItemBackgroundColour(const wxTreeItemId& item) const;
    wxLuaTreeItemData* GetItemData(const wxTreeItemId& item) const;
    wxFont GetItemFont(const wxTreeItemId& item) const;
    int GetItemImage(const wxTreeItemId& item, wxTreeItemIcon which = wxTreeItemIcon_Normal) const;
    %wxchkver_2_4 wxTreeItemId GetItemParent(const wxTreeItemId& item) const;
    %wxchkver_3_0_0 int GetItemState(const wxTreeItemId& item) const;
    wxString GetItemText(const wxTreeItemId& item) const;
    wxColour GetItemTextColour(const wxTreeItemId& item) const;
    wxTreeItemId GetLastChild(const wxTreeItemId& item) const;
    wxTreeItemId GetNextChild(const wxTreeItemId& item, wxTreeItemIdValue& cookie) const; // %override return [wxTreeItemId, wxTreeItemIdValue cookie]
    wxTreeItemId GetNextSibling(const wxTreeItemId& item) const;
    wxTreeItemId GetNextVisible(const wxTreeItemId& item) const;
    wxTreeItemId GetPrevSibling(const wxTreeItemId& item) const;
    wxTreeItemId GetPrevVisible(const wxTreeItemId& item) const;
    bool GetQuickBestSize() const;
    wxTreeItemId GetRootItem() const;
    wxTreeItemId GetSelection() const;
    wxImageList* GetStateImageList() const;
    wxTreeItemId InsertItem(const wxTreeItemId& parent, const wxTreeItemId& previous, const wxString& text, int image = -1, int selImage = -1, %ungc wxLuaTreeItemData* data = NULL);
    wxTreeItemId InsertItem(const wxTreeItemId& parent, size_t before, const wxString& text, int image = -1, int selImage = -1, %ungc wxLuaTreeItemData* data = NULL);
    bool IsBold(const wxTreeItemId& item) const;
    bool IsEmpty() const;
    bool IsExpanded(const wxTreeItemId& item) const;
    bool IsSelected(const wxTreeItemId& item) const;
    bool IsVisible(const wxTreeItemId& item) const;
    bool ItemHasChildren(const wxTreeItemId& item) const;
    // int OnCompareItems(const wxTreeItemId& item1, const wxTreeItemId& item2); // Not available in wxlua
    wxTreeItemId PrependItem(const wxTreeItemId& parent, const wxString& text, int image = -1, int selImage = -1, %ungc wxLuaTreeItemData* data = NULL);
    void ScrollTo(const wxTreeItemId& item);
    void SelectItem(const wxTreeItemId& item, bool select = true);
    // void SetButtonsImageList(wxImageList* imageList); // This function is only available in the generic version.
    void SetImageList(wxImageList* imageList);
    %wxchkver_3_0_0 void SetIndent(unsigned int indent);
    void SetSpacing(unsigned int spacing);
    void SetItemBackgroundColour(const wxTreeItemId& item, const wxColour& col);
    void SetItemBold(const wxTreeItemId& item, bool bold = true);
    void SetItemData(const wxTreeItemId& item, %ungc wxLuaTreeItemData* data);
    void SetItemDropHighlight(const wxTreeItemId& item, bool highlight = true);
    void SetItemFont(const wxTreeItemId& item, const wxFont& font);
    void SetItemHasChildren(const wxTreeItemId& item, bool hasChildren = true);
    void SetItemImage(const wxTreeItemId& item, int image, wxTreeItemIcon which = wxTreeItemIcon_Normal);
    %wxchkver_2_9 void SetItemState(const wxTreeItemId& item, int state);
    void SetItemText(const wxTreeItemId& item, const wxString& text);
    void SetItemTextColour(const wxTreeItemId& item, const wxColour& col);
    void SetQuickBestSize(bool quickBestSize);
    void SetStateImageList(wxImageList* imageList);
    void SetWindowStyle(long styles);
    void SortChildren(const wxTreeItemId& item);
    void Toggle(const wxTreeItemId& item);
    void ToggleItemSelection(const wxTreeItemId& item);
    void Unselect();
    void UnselectAll();
    void UnselectItem(const wxTreeItemId& item);
    %wxchkver_3_0_0 void SelectChildren(const wxTreeItemId& parent);
    !%wxchkver_3_0_0 void SetIndent(int indent);
    size_t GetSelections() const; // %override return [size_t, Lua table of wxTreeItemIds]
    wxTextCtrl *EditLabel(const wxTreeItemId& item); // %override , wxClassInfo* textCtrlClass = wxCLASSINFO(wxTextCtrl));
    wxTreeItemId GetFirstChild(const wxTreeItemId& item) const; // %override return [wxTreeItemId, wxTreeItemIdValue cookie]
    wxTreeItemId HitTest(const wxPoint& point); // %override return [wxTreeItemId, int flags]
};

// ---------------------------------------------------------------------------
// wxTreeItemAttr - wxTreeCtrl
// This is only used internally in wxWidgets with no public accessors to them.

/*
class %delete wxTreeItemAttr
{
    wxTreeItemAttr(const wxColour& colText = wxNullColour, const wxColour& colBack = wxNullColour, const wxFont& font = wxNullFont);

    wxColour GetBackgroundColour() const;
    wxFont   GetFont() const;
    wxColour GetTextColour() const;
    bool     HasBackgroundColour();
    bool     HasFont();
    bool     HasTextColour();
    void     SetBackgroundColour(const wxColour& colBack);
    void     SetFont(const wxFont& font);
    void     SetTextColour(const wxColour& colText);
};
*/

// ---------------------------------------------------------------------------
// wxTreeItemIdValue - wxTreeCtrl

// FAKE typedef, actually typedef void* wxTreeItemIdValue
// Since we override the functions that use it we handle it as a pointer.
typedef double wxTreeItemIdValue

// ---------------------------------------------------------------------------
// wxTreeItemId - wxTreeCtrl

class %delete wxTreeItemId
{
    wxTreeItemId();
    wxTreeItemId(const wxTreeItemId& id);

    bool IsOk();
    wxTreeItemIdValue GetValue() const; // get a pointer to the internal data to use as a reference in a Lua table

    wxTreeItemId& operator=(const wxTreeItemId& otherId);
    bool operator==(const wxTreeItemId& otherId) const;
};

// ---------------------------------------------------------------------------
// wxArrayTreeItemIds - wxTreeCtrl
// This is only used by the function wxTreeCtrl::GetSelections(wxArrayTreeItemIds& arr);
//    which we have overridden to return a table. This is not necessary.
//
// Note: This is actually an array of the internal wxTreeItemIdValue data
//       which is a void* pointer. This is why we use long.
//       See wxLua's wxTreeItemId::GetValue() function

/*
class %delete wxArrayTreeItemIds
{
    wxArrayTreeItemIds();
    wxArrayTreeItemIds(const wxArrayTreeItemIds& array);

    void Add(const wxTreeItemId& id);
    void Alloc(size_t nCount);
    void Clear();
    void Empty();
    int GetCount() const;
    int Index(wxTreeItemIdValue treeItemIdValue, bool bFromEnd = false);
    //void Insert(wxTreeItemId& str, int nIndex, size_t copies = 1);
    bool IsEmpty();
    wxTreeItemId Item(size_t nIndex) const;
    wxTreeItemId Last();
    void Remove(wxTreeItemIdValue treeItemIdValue);
    void RemoveAt(size_t nIndex, size_t count = 1);
    void Shrink();
};
*/

// ---------------------------------------------------------------------------
// wxTreeItemData - wxTreeCtrl, see also wxLuaTreeItemData
//
// No %delete since the wxTreeCtrl will delete it when set as the data for an item.
// Only create a wxTreeItemData if you're going to attach it to a wxTreeCtrl item to avoid memory leaks.

class %delete wxTreeItemData : public wxClientData
{
    wxTreeItemData();

    wxTreeItemId GetId();
    void         SetId(const wxTreeItemId& id);
};

// ---------------------------------------------------------------------------
// wxLuaTreeItemData -
//
// No %delete since the wxTreeCtrl will delete it when set as the data for an item.
// Only create a wxLuaTreeItemData if you're going to attach it to a wxTreeCtrl item to avoid memory leaks.

#include "wxbind/include/wxcore_wxlcore.h"

class %delete wxLuaTreeItemData : public wxTreeItemData
{
    wxLuaTreeItemData();

    // %override wxLuaTreeItemData(any);
    // C++ Func: wxLuaTreeItemData(wxLuaObject* obj);
    wxLuaTreeItemData(any);

    // %override any wxLuaTreeItemData::GetData() const;
    // C++ Func: wxLuaObject* GetData() const;
    any  GetData() const;
    // %override void wxLuaTreeItemData::SetData(any);
    // C++ Func: void SetData(wxLuaObject* obj);
    void SetData(any);
};


// ---------------------------------------------------------------------------
// wxTreeEvent - wxTreeCtrl

class %delete wxTreeEvent : public wxNotifyEvent
{
    %wxEventType wxEVT_COMMAND_TREE_BEGIN_DRAG        // EVT_TREE_BEGIN_DRAG(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_BEGIN_LABEL_EDIT  // EVT_TREE_BEGIN_LABEL_EDIT(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_BEGIN_RDRAG       // EVT_TREE_BEGIN_RDRAG(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_DELETE_ITEM       // EVT_TREE_DELETE_ITEM(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_END_DRAG          // EVT_TREE_END_DRAG(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_END_LABEL_EDIT    // EVT_TREE_END_LABEL_EDIT(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_GET_INFO          // EVT_TREE_GET_INFO(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_ITEM_ACTIVATED    // EVT_TREE_ITEM_ACTIVATED(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_ITEM_COLLAPSED    // EVT_TREE_ITEM_COLLAPSED(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_ITEM_COLLAPSING   // EVT_TREE_ITEM_COLLAPSING(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_ITEM_EXPANDED     // EVT_TREE_ITEM_EXPANDED(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_ITEM_EXPANDING    // EVT_TREE_ITEM_EXPANDING(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_ITEM_MIDDLE_CLICK // EVT_TREE_ITEM_MIDDLE_CLICK(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_ITEM_RIGHT_CLICK  // EVT_TREE_ITEM_RIGHT_CLICK(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_KEY_DOWN          // EVT_TREE_KEY_DOWN(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_SEL_CHANGED       // EVT_TREE_SEL_CHANGED(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_SEL_CHANGING      // EVT_TREE_SEL_CHANGING(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_SET_INFO          // EVT_TREE_SET_INFO(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_ITEM_MENU         // EVT_TREE_ITEM_MENU(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_STATE_IMAGE_CLICK // EVT_TREE_STATE_IMAGE_CLICK(id, fn);
    %wxEventType wxEVT_COMMAND_TREE_ITEM_GETTOOLTIP   // EVT_TREE_ITEM_GETTOOLTIP(id, fn);

    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_BEGIN_DRAG        // wx3.0 alias for wxEVT_COMMAND_TREE_BEGIN_DRAG
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_BEGIN_LABEL_EDIT  // wx3.0 alias for wxEVT_COMMAND_TREE_BEGIN_LABEL_EDIT
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_BEGIN_RDRAG       // wx3.0 alias for wxEVT_COMMAND_TREE_BEGIN_RDRAG
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_DELETE_ITEM       // wx3.0 alias for wxEVT_COMMAND_TREE_DELETE_ITEM
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_END_DRAG          // wx3.0 alias for wxEVT_COMMAND_TREE_END_DRAG
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_END_LABEL_EDIT    // wx3.0 alias for wxEVT_COMMAND_TREE_END_LABEL_EDIT
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_GET_INFO          // wx3.0 alias for wxEVT_COMMAND_TREE_GET_INFO
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_ITEM_ACTIVATED    // wx3.0 alias for wxEVT_COMMAND_TREE_ITEM_ACTIVATED
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_ITEM_COLLAPSED    // wx3.0 alias for wxEVT_COMMAND_TREE_ITEM_COLLAPSED
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_ITEM_COLLAPSING   // wx3.0 alias for wxEVT_COMMAND_TREE_ITEM_COLLAPSING
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_ITEM_EXPANDED     // wx3.0 alias for wxEVT_COMMAND_TREE_ITEM_EXPANDED
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_ITEM_EXPANDING    // wx3.0 alias for wxEVT_COMMAND_TREE_ITEM_EXPANDING
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_ITEM_MIDDLE_CLICK // wx3.0 alias for wxEVT_COMMAND_TREE_ITEM_MIDDLE_CLICK
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_ITEM_RIGHT_CLICK  // wx3.0 alias for wxEVT_COMMAND_TREE_ITEM_RIGHT_CLICK
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_KEY_DOWN          // wx3.0 alias for wxEVT_COMMAND_TREE_KEY_DOWN
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_SEL_CHANGED       // wx3.0 alias for wxEVT_COMMAND_TREE_SEL_CHANGED
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_SEL_CHANGING      // wx3.0 alias for wxEVT_COMMAND_TREE_SEL_CHANGING
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_SET_INFO          // wx3.0 alias for wxEVT_COMMAND_TREE_SET_INFO
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_ITEM_MENU         // wx3.0 alias for wxEVT_COMMAND_TREE_ITEM_MENU
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_STATE_IMAGE_CLICK // wx3.0 alias for wxEVT_COMMAND_TREE_STATE_IMAGE_CLICK
    %wxchkver_3_0_0 %wxEventType wxEVT_TREE_ITEM_GETTOOLTIP   // wx3.0 alias for wxEVT_COMMAND_TREE_ITEM_GETTOOLTIP

    wxTreeEvent(wxEventType commandType = wxEVT_NULL, int id = 0);

    int GetKeyCode() const;
    wxTreeItemId GetItem() const;
    wxKeyEvent GetKeyEvent() const;
    const wxString& GetLabel() const;
    wxTreeItemId GetOldItem() const;
    wxPoint GetPoint() const;
    bool IsEditCancelled() const;
    void SetToolTip(const wxString& tooltip);
};

#endif //wxLUA_USE_wxTreeCtrl && wxUSE_TREECTRL

// ---------------------------------------------------------------------------
// wxGenericDirCtrl

#if wxLUA_USE_wxGenericDirCtrl && wxUSE_DIRDLG

#include "wx/dirctrl.h"

enum
{
    wxDIRCTRL_DIR_ONLY,
    wxDIRCTRL_SELECT_FIRST,
    wxDIRCTRL_SHOW_FILTERS,
    wxDIRCTRL_3D_INTERNAL,
    wxDIRCTRL_EDIT_LABELS
};

%wxchkver_2_9_0 #define_string wxDirDialogDefaultFolderStr
!%wxchkver_2_9_0 #define_wxstring wxDirDialogDefaultFolderStr

class wxGenericDirCtrl : public wxControl
{
    wxGenericDirCtrl();
    wxGenericDirCtrl(wxWindow *parent, const wxWindowID id = wxID_ANY, const wxString &dir = wxDirDialogDefaultFolderStr, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDIRCTRL_3D_INTERNAL|wxSUNKEN_BORDER, const wxString& filter = "", int defaultFilter = 0, const wxString& name = "wxGenericDirCtrl");
    bool Create(wxWindow *parent, const wxWindowID id = wxID_ANY, const wxString &dir = wxDirDialogDefaultFolderStr, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDIRCTRL_3D_INTERNAL|wxSUNKEN_BORDER, const wxString& filter = "", int defaultFilter = 0, const wxString& name = "wxGenericDirCtrl");

    void CollapseTree();
    bool ExpandPath(const wxString& path);
    wxString GetDefaultPath() const;
    wxString GetPath() const;
    wxString GetFilePath() const;
    wxString GetFilter() const;
    int GetFilterIndex() const;
    //wxDirFilterListCtrl* GetFilterListCtrl() const;
    wxTreeItemId GetRootId();
    wxTreeCtrl* GetTreeCtrl() const;
    void ReCreateTree();
    void SetDefaultPath(const wxString& path);
    void SetFilter(const wxString& filter);
    void SetFilterIndex(int n);
    void SetPath(const wxString& path);
    void ShowHidden(bool show);
    bool GetShowHidden();

    //wxTreeItemId FindChild(wxTreeItemId parentId, const wxString& path, bool& done);
};

#endif //wxLUA_USE_wxGenericDirCtrl && wxUSE_DIRDLG


// ---------------------------------------------------------------------------
// wxInfoBar

#if wxUSE_INFOBAR && %wxchkver_2_9_1

#include "wx/infobar.h"

class wxInfoBar : public wxControl
{
    wxInfoBar();
    wxInfoBar(wxWindow *parent, wxWindowID id);
    bool Create(wxWindow *parent, wxWindowID id);

    void AddButton(wxWindowID btnid, const wxString &label = wxEmptyString);
    void Dismiss();
    void RemoveButton(wxWindowID btnid);
    void ShowMessage(const wxString &msg, int flags = wxICON_INFORMATION);
};

#endif //wxUSE_INFOBAR && %wxchkver_2_9_1

// ---------------------------------------------------------------------------
// wxTreeListCtrl

#if wxLUA_USE_wxTreeListCtrl && wxUSE_TREELISTCTRL && %wxchkver_2_9_3

#include "wx/treelist.h"

enum
{
    wxTL_SINGLE         = 0x0000,       /// This is the default anyhow.
    wxTL_MULTIPLE       = 0x0001,       /// Allow multiple selection.
    wxTL_CHECKBOX       = 0x0002,       /// Show checkboxes in the first column.
    wxTL_3STATE         = 0x0004,       /// Allow 3rd state in checkboxes.
    wxTL_USER_3STATE    = 0x0008,       /// Allow user to set 3rd state.
    /**
        Don't show the column headers.

        By default this control shows the column headers, using this class
        allows avoiding this and showing only the data.

        @since 2.9.5
     */
    %wxchkver_2_9_5 wxTL_NO_HEADER      = 0x0010,

    wxTL_DEFAULT_STYLE  = wxTL_SINGLE,
    wxTL_STYLE_MASK     = wxTL_SINGLE |
                          wxTL_MULTIPLE |
                          wxTL_CHECKBOX |
                          wxTL_3STATE |
                          wxTL_USER_3STATE
};

class %delete wxTreeListItem
{
    wxTreeListItem();
    wxTreeListItem(const wxTreeListItem& id);

    bool IsOk() const;
    wxUIntPtr GetValue() const; // get a pointer to the internal data to use as a reference in a Lua table
};

/// A constant indicating that no image should be used for an item.
static const int wxTreeListCtrl::NO_IMAGE = -1;

class wxTreeListCtrl : public wxWindow
{
    /**
        Default constructor, call Create() later.

        This constructor is used during two-part construction process when it
        is impossible or undesirable to create the window when constructing the
        object.
     */
    wxTreeListCtrl();

    /**
        Full constructing, creating the object and its window.

        See Create() for the parameters description.
     */
    wxTreeListCtrl(wxWindow* parent,
                   wxWindowID id,
                   const wxPoint& pos = wxDefaultPosition,
                   const wxSize& size = wxDefaultSize,
                   long style = wxTL_DEFAULT_STYLE,
                   const wxString& name = wxTreeListCtrlNameStr);

    /**
        Create the control window.

        Can be only called for the objects created using the default
        constructor and exactly once.

        @param parent
            The parent window, must be non-NULL.
        @param id
            The window identifier, may be ::wxID_ANY.
        @param pos
            The initial window position, usually unused.
        @param size
            The initial window size, usually unused.
        @param style
            The window style, see their description in the class documentation.
        @param name
            The name of the window.
     */
    bool Create(wxWindow* parent,
                wxWindowID id,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = wxTL_DEFAULT_STYLE,
                const wxString& name = wxTreeListCtrlNameStr);

    /**
        @name Image list methods.

        Like wxTreeCtrl and wxListCtrl this class uses wxImageList so if you
        intend to use item icons with it, you must construct wxImageList
        containing them first and then specify the indices of the icons in this
        image list when adding the items later.
     */
    //@{

    /**
        Sets the image list and gives its ownership to the control.

        The image list assigned with this method will be automatically deleted
        by wxTreeCtrl as appropriate (i.e. it takes ownership of the list).

        @see SetImageList().
    */
    void AssignImageList(wxImageList* imageList);

    /**
        Sets the image list.

        The image list assigned with this method will @b not be deleted by the
        control itself and you will need to delete it yourself, use
        AssignImageList() to give the image list ownership to the control.

        @param imageList
            Image list to use, may be @NULL to not show any images any more.
    */
    void SetImageList(wxImageList* imageList);

    //@}


    /**
        @name Column methods.
     */
    //@{

    /**
        Add a column with the given title and attributes.

        @param title
            The column label.
        @param width
            The width of the column in pixels or the special
            wxCOL_WIDTH_AUTOSIZE value indicating that the column should adjust
            to its contents. Notice that the last column is special and will
            be always resized to fill all the space not taken by the other
            columns, i.e. the width specified here is ignored for it.
        @param align
            Alignment of both the column header and its items.
        @param flags
            Column flags, currently can include wxCOL_RESIZABLE to allow the
            user to resize the column and wxCOL_SORTABLE to allow the user to
            resort the control contents by clicking on this column.
        @return
            Index of the new column or -1 on failure.
     */
    int AppendColumn(const wxString& title,
                     int width = wxCOL_WIDTH_AUTOSIZE,
                     wxAlignment align = wxALIGN_LEFT,
                     int flags = wxCOL_RESIZABLE);

    /// Return the total number of columns.
    unsigned int GetColumnCount() const;

    /**
        Delete the column with the given index.

        @param col
            Column index in 0 to GetColumnCount() (exclusive) range.
        @return
            True if the column was deleted, false if index is invalid or
            deleting the column failed for some other reason.
     */
    bool DeleteColumn(unsigned int col);

    /**
        Delete all columns.

        @see DeleteAllItems()
     */
    void ClearColumns();

    /**
        Change the width of the given column.

        Set column width to either the given value in pixels or to the value
        large enough to fit all of the items if width is wxCOL_WIDTH_AUTOSIZE.

        Notice that setting the width of the last column is ignored as this
        column is always resized to fill the space left by the other columns.
     */
    void SetColumnWidth(unsigned int col, int width);

    /// Get the current width of the given column in pixels.
    int GetColumnWidth(unsigned int col) const;

    /**
        Get the width appropriate for showing the given text.

        This is typically used as second argument for AppendColumn() or with
        SetColumnWidth().
     */
    int WidthFor(const wxString& text) const;

    //@}


    /**
        @name Adding and removing items.

        When adding items, the parent and text of the first column of the new item
        must always be specified, the rest is optional.

        Each item can have two images: one used for closed state and another
        for opened one. Only the first one is ever used for the items that
        don't have children. And both are not set by default.

        It is also possible to associate arbitrary client data pointer with the
        new item. It will be deleted by the control when the item is deleted
        (either by an explicit DeleteItem() call or because the entire control
        is destroyed).
     */
    //@{

    /// Same as InsertItem() with wxTLI_LAST.
    wxTreeListItem AppendItem(wxTreeListItem parent,
                              const wxString& text,
                              int imageClosed = wxTreeListCtrl::NO_IMAGE,
                              int imageOpened = wxTreeListCtrl::NO_IMAGE,
                              wxClientData* data = NULL);

    /**
        Insert a new item into the tree.

        @param parent
            The item parent. Must be valid, may be GetRootItem().
        @param previous
            The previous item that this one should be inserted immediately
            after. It must be valid but may be one of the special values
            wxTLI_FIRST or wxTLI_LAST indicating that the item should be either
            inserted before the first child of its parent (if any) or after the
            last one.
        @param text
            The item text.
        @param imageClosed
            The normal item image, may be NO_IMAGE to not show any image.
        @param imageOpened
            The item image shown when it's in the expanded state.
        @param data
            Optional client data pointer that can be later retrieved using
            GetItemData() and will be deleted by the tree when the item itself
            is deleted.
     */
    wxTreeListItem InsertItem(wxTreeListItem parent,
                              wxTreeListItem previous,
                              const wxString& text,
                              int imageClosed = wxTreeListCtrl::NO_IMAGE,
                              int imageOpened = wxTreeListCtrl::NO_IMAGE,
                              wxClientData* data = NULL);

    /// Same as InsertItem() with wxTLI_FIRST.
    wxTreeListItem PrependItem(wxTreeListItem parent,
                               const wxString& text,
                               int imageClosed = wxTreeListCtrl::NO_IMAGE,
                               int imageOpened = wxTreeListCtrl::NO_IMAGE,
                               wxClientData* data = NULL);

    /// Delete the specified item.
    void DeleteItem(wxTreeListItem item);

    /// Delete all tree items.
    void DeleteAllItems();

    //@}


    /**
        @name Methods for the tree navigation.

        The tree has an invisible root item which is the hidden parent of all
        top-level items in the tree. Starting from it it is possible to iterate
        over all tree items using GetNextItem().

        It is also possible to iterate over just the children of the given item
        by using GetFirstChild() to get the first of them and then calling
        GetNextSibling() to retrieve all the others.
     */
    //@{

    /// Return the (never shown) root item.
    wxTreeListItem GetRootItem() const;

    /**
        Return the parent of the given item.

        All the tree items visible in the tree have valid parent items, only
        the never shown root item has no parent.
     */
    wxTreeListItem GetItemParent(wxTreeListItem item) const;

    /**
        Return the first child of the given item.

        Item may be the root item.

        Return value may be invalid if the item doesn't have any children.
     */
    wxTreeListItem GetFirstChild(wxTreeListItem item) const;

    /**
        Return the next sibling of the given item.

        Return value may be invalid if there are no more siblings.
     */
    wxTreeListItem GetNextSibling(wxTreeListItem item) const;

    /**
        Return the first item in the tree.

        This is the first child of the root item.

        @see GetNextItem()
     */
    wxTreeListItem GetFirstItem() const;

    /**
        Get item after the given one in the depth-first tree-traversal order.

        Calling this function starting with the result of GetFirstItem() allows
        iterating over all items in the tree.

        The iteration stops when this function returns an invalid item, i.e.
        @code
            for ( wxTreeListItem item = tree->GetFirstItem();
                  item.IsOk();
                  item = tree->GetNextItem(item) )
            {
                ... Do something with every tree item ...
            }
        @endcode
     */
    wxTreeListItem GetNextItem(wxTreeListItem item) const;

    //@}


    /**
        @name Items attributes
     */
    //@{

    /**
        Return the text of the given item.

        By default, returns the text of the first column but any other one can
        be specified using @a col argument.
     */
    const wxString& GetItemText(wxTreeListItem item, unsigned int col = 0) const;

    /**
        Set the text of the specified column of the given item.
     */
    void SetItemText(wxTreeListItem item, unsigned int col, const wxString& text);

    /**
        Set the text of the first column of the given item.
     */
    void SetItemText(wxTreeListItem item, const wxString& text);

    /**
        Set the images for the given item.

        See InsertItem() for the images parameters descriptions.
     */
    void SetItemImage(wxTreeListItem item, int closed, int opened = wxTreeListCtrl::NO_IMAGE);

    /**
        Get the data associated with the given item.

        The returned pointer may be @NULL.

        It must not be deleted by the caller as this will be done by the
        control itself.
     */
    wxClientData* GetItemData(wxTreeListItem item) const;

    /**
        Set the data associated with the given item.

        Previous client data, if any, is deleted when this function is called
        so it may be used to delete the current item data object and reset it
        by passing @NULL as @a data argument.
     */
    void SetItemData(wxTreeListItem item, wxClientData* data);

    //@}


    /**
        @name Expanding and collapsing tree branches.

        Notice that calling neither Expand() nor Collapse() method generates
        any events.
     */
    //@{

    /**
        Expand the given tree branch.
     */
    void Expand(wxTreeListItem item);

    /**
        Collapse the given tree branch.
     */
    void Collapse(wxTreeListItem item);

    /**
        Return whether the given item is expanded.
     */
    bool IsExpanded(wxTreeListItem item) const;

    //@}


    /**
        @name Selection methods.

        The behaviour of the control is different in single selection mode (the
        default) and multi-selection mode (if @c wxTL_MULTIPLE was specified
        when creating it). Not all methods can be used in both modes and some
        of those that can don't behave in the same way in two cases.
     */
    //@{

    /**
        Return the currently selected item.

        This method can't be used with multi-selection controls, use
        GetSelections() instead.

        The return value may be invalid if no item has been selected yet. Once
        an item in a single selection control was selected, it will keep a
        valid selection.
     */
    wxTreeListItem GetSelection() const;

    /**
        Fill in the provided array with all the selected items.

        This method can be used in both single and multi-selection case.

        The previous array contents is destroyed.

        Returns the number of selected items.
     */
    // unsigned int GetSelections(wxTreeListItems& selections) const;
    size_t GetSelections() const; // %override return [size_t, Lua table of wxTreeListItemIds]

    /**
        Select the given item.

        In single selection mode, deselects any other selected items, in
        multi-selection case it adds to the selection.
     */
    void Select(wxTreeListItem item);

    /**
        Deselect the given item.

        This method can be used in multiple selection mode only.
     */
    void Unselect(wxTreeListItem item);

    /**
        Return true if the item is selected.

        This method can be used in both single and multiple selection modes.
     */
    bool IsSelected(wxTreeListItem item) const;

    /**
        Select all the control items.

        Can be only used in multi-selection mode.
     */
    void SelectAll();

    /**
        Deselect all the control items.

        Can be only used in multi-selection mode.
     */
    void UnselectAll();

    /**
        Call this to ensure that the given item is visible.

        @since 3.1.0
     */
    %wxchkver_3_1_0 void EnsureVisible(wxTreeListItem item);

    //@}


    /**
        @name Checkbox handling

        Methods in this section can only be used with the controls created with
        wxTL_CHECKBOX style.
     */
    //@{

    /**
        Change the item checked state.

        @param item
            Valid non-root tree item.
        @param state
            One of wxCHK_CHECKED, wxCHK_UNCHECKED or, for the controls with
            wxTL_3STATE or wxTL_USER_3STATE styles, wxCHK_UNDETERMINED.
     */
    void CheckItem(wxTreeListItem item, wxCheckBoxState state = wxCHK_CHECKED);

    /**
        Change the checked state of the given item and all its children.

        This is the same as CheckItem() but checks or unchecks not only this
        item itself but all its children recursively as well.
     */
    void CheckItemRecursively(wxTreeListItem item,
                              wxCheckBoxState state = wxCHK_CHECKED);

    /**
        Uncheck the given item.

        This is synonymous with CheckItem(wxCHK_UNCHECKED).
     */
    void UncheckItem(wxTreeListItem item);

    /**
        Update the state of the parent item to reflect the checked state of its
        children.

        This method updates the parent of this item recursively: if this item
        and all its siblings are checked, the parent will become checked as
        well. If this item and all its siblings are unchecked, the parent will
        be unchecked. And if the siblings of this item are not all in the same
        state, the parent will be switched to indeterminate state. And then the
        same logic will be applied to the parents parent and so on recursively.

        This is typically called when the state of the given item has changed
        from EVT_TREELIST_ITEM_CHECKED() handler in the controls which have
        wxTL_3STATE flag. Notice that without this flag this function can't
        work as it would be unable to set the state of a parent with both
        checked and unchecked items so it's only allowed to call it when this
        flag is set.
     */
    void UpdateItemParentStateRecursively(wxTreeListItem item);

    /**
        Return the checked state of the item.

        The return value can be wxCHK_CHECKED, wxCHK_UNCHECKED or
        wxCHK_UNDETERMINED.
     */
    wxCheckBoxState GetCheckedState(wxTreeListItem item) const;

    /**
        Return true if all children of the given item are in the specified
        state.

        This is especially useful for the controls with @c wxTL_3STATE style to
        allow to decide whether the parent effective state should be the same
        @a state, if all its children are in it, or ::wxCHK_UNDETERMINED.

        @see UpdateItemParentStateRecursively()
     */
    bool AreAllChildrenInState(wxTreeListItem item,
                               wxCheckBoxState state) const;

    //@}

    /**
        @name Sorting.

        If some control columns were added with wxCOL_SORTABLE flag, clicking
        on them will automatically resort the control using the custom
        comparator set by SetItemComparator() or by doing alphabetical
        comparison by default.

        In any case, i.e. even if the user can't sort the control by clicking
        on its header, you may call SetSortColumn() to sort it programmatically
        and call GetSortColumn() to determine whether it's sorted now and, if
        so, by which column and in which order.
     */
    //@{

    /**
        Set the column to use for sorting and the order in which to sort.

        Calling this method resorts the control contents using the values of
        the items in the specified column. Sorting uses custom comparator set
        with SetItemComparator() or alphabetical comparison of items texts if
        none was specified.

        Notice that currently there is no way to reset sort order.

        @param col
            A valid column index.
        @param ascendingOrder
            Indicates whether the items should be sorted in ascending (A to Z)
            or descending (Z to A) order.
     */
    void SetSortColumn(unsigned int col, bool ascendingOrder = true);

    /**
        Return the column currently used for sorting, if any.

        If the control is currently unsorted, the function simply returns
        @false and doesn't modify any of its output parameters.

        @param col
            Receives the index of the column used for sorting if non-@NULL.
        @param ascendingOrder
            Receives @true or @false depending on whether the items are sorted
            in ascending or descending order.
        @return
            @true if the control is sorted or @false if it isn't sorted at all.
     */
    bool GetSortColumn(unsigned int* col, bool* ascendingOrder = NULL);

    /**
        Set the object to use for comparing the items.

        This object will be used when the control is being sorted because the
        user clicked on a sortable column or SetSortColumn() was called.

        The provided pointer is stored by the control so the object it points
        to must have a life-time equal or greater to that of the control
        itself. In addition, the pointer can be @NULL to stop using custom
        comparator and revert to the default alphabetical comparison.
     */
    //void SetItemComparator(wxTreeListItemComparator* comparator);

    //@}


    /**
        @name View window.

        This control itself is entirely covered by the "view window" which is
        currently a wxDataViewCtrl but if you want to avoid relying on this to
        allow your code to work with later versions which might not be
        wxDataViewCtrl-based, use GetView() function only and only use
        GetDataView() if you really need to call wxDataViewCtrl methods on it.
     */
    //@{

    /**
        Return the view part of this control as a wxWindow.

        This method always returns non-@NULL pointer once the window was
        created.
     */
    wxWindow* GetView() const;

    /**
        Return the view part of this control as wxDataViewCtrl.

        This method may return @NULL in the future, non wxDataViewCtrl-based,
        versions of this class, use GetView() unless you really need to use
        wxDataViewCtrl methods on the returned object.
     */
    // wxDataViewCtrl* GetDataView() const;

    //@}
};

class %delete wxTreeListEvent : public wxNotifyEvent
{
    %wxEventType wxEVT_TREELIST_SELECTION_CHANGED;
    %wxEventType wxEVT_TREELIST_ITEM_EXPANDING;
    %wxEventType wxEVT_TREELIST_ITEM_EXPANDED;
    %wxEventType wxEVT_TREELIST_ITEM_CHECKED;
    %wxEventType wxEVT_TREELIST_ITEM_ACTIVATED;
    %wxEventType wxEVT_TREELIST_ITEM_CONTEXT_MENU;
    %wxEventType wxEVT_TREELIST_COLUMN_SORTED;

    wxTreeListEvent();

    /**
        Return the item affected by the event.

        This is the item being selected, expanded, checked or activated
        (depending on the event type).
     */
    wxTreeListItem GetItem() const;

    /**
        Return the previous state of the item checkbox.

        This method can be used with @c wxEVT_TREELIST_ITEM_CHECKED
        events only.

        Notice that the new state of the item can be retrieved using
        wxTreeListCtrl::GetCheckedState().
     */
    wxCheckBoxState GetOldCheckedState() const;

    /**
        Return the column affected by the event.

        This is currently only used with @c wxEVT_TREELIST_COLUMN_SORTED
        event.
     */
    unsigned int GetColumn() const;
};

#endif //wxLUA_USE_wxTreeListCtrl && wxUSE_TREELISTCTRL && %wxchkver_2_9_3

#if wxUSE_SEARCHCTRL

#include "wx/srchctrl.h"

class wxSearchCtrl : public wxTextCtrl
{
public:
    wxSearchCtrl();

    wxSearchCtrl(wxWindow* parent, wxWindowID id,
                 const wxString& value = wxEmptyString,
                 const wxPoint& pos = wxDefaultPosition,
                 const wxSize& size = wxDefaultSize,
                 long style = 0,
                 const wxValidator& validator = wxDefaultValidator,
                 const wxString& name = wxSearchCtrlNameStr);

    bool Create(wxWindow* parent, wxWindowID id,
                 const wxString& value = wxEmptyString,
                 const wxPoint& pos = wxDefaultPosition,
                 const wxSize& size = wxDefaultSize,
                 long style = 0,
                 const wxValidator& validator = wxDefaultValidator,
                 const wxString& name = wxSearchCtrlNameStr);

    virtual wxMenu* GetMenu();
    virtual bool IsSearchButtonVisible() const;
    virtual bool IsCancelButtonVisible() const;
    // wxLua Note: menu will delete the control when it is destroyed.
    virtual void SetMenu(%ungc wxMenu* menu);
    virtual void ShowCancelButton(bool show);
    virtual void ShowSearchButton(bool show);
    void        SetDescriptiveText(const wxString& text);
    wxString    GetDescriptiveText() const;

    virtual void SetValue(const wxString& value);
    wxString GetValue() const;
};

#endif
