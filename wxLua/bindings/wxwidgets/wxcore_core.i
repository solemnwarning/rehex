// ===========================================================================
// Purpose:     Various wxCore classes
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

#if wxLUA_USE_wxLog && wxUSE_LOG

// C++ Func: void wxLogStatus(wxFrame *frame, const char *formatString, ...);
// void wxLogStatus(const char *formatString, ...); // this just uses the toplevel frame, use wx.NULL for the frame
void wxLogStatus(wxFrame *frame, const wxString& message);

// ---------------------------------------------------------------------------
// wxLogGui - wxWidgets creates and installs one of these at startup,
//            just treat it as a wxLog.

#if wxUSE_LOGGUI

class %delete wxLogGui : public wxLog
{
    wxLogGui();
};

#endif // wxUSE_LOGGUI

// ---------------------------------------------------------------------------
// wxLogTextCtrl

#if wxLUA_USE_wxTextCtrl && wxUSE_TEXTCTRL

class %delete wxLogTextCtrl : public wxLog
{
    wxLogTextCtrl(wxTextCtrl* textCtrl);
};

#endif // wxLUA_USE_wxTextCtrl && wxUSE_TEXTCTRL

// ---------------------------------------------------------------------------
// wxLogWindow

#if wxLUA_USE_wxLogWindow && wxUSE_LOGWINDOW

class %delete wxLogWindow : public wxLogPassThrough
{
    wxLogWindow(wxWindow *pParent, const wxString& szTitle, bool bShow = true, bool bPassToOld = true);

    void Show(bool show = true);
    wxFrame* GetFrame() const;

    //virtual void OnFrameCreate(wxFrame *frame);
    //virtual bool OnFrameClose(wxFrame *frame);
    //virtual void OnFrameDelete(wxFrame *frame);
};

#endif // wxLUA_USE_wxLogWindow && wxUSE_LOGWINDOW

#endif // wxLUA_USE_wxLog && wxUSE_LOG


// ---------------------------------------------------------------------------
// wxSystemSettings

#if wxLUA_USE_wxSystemSettings

#include "wx/settings.h"

enum wxSystemScreenType
{
    wxSYS_SCREEN_NONE,
    wxSYS_SCREEN_TINY,
    wxSYS_SCREEN_PDA,
    wxSYS_SCREEN_SMALL,
    wxSYS_SCREEN_DESKTOP
};

enum wxSystemMetric
{
    wxSYS_MOUSE_BUTTONS,
    wxSYS_BORDER_X,
    wxSYS_BORDER_Y,
    wxSYS_CURSOR_X,
    wxSYS_CURSOR_Y,
    wxSYS_DCLICK_X,
    wxSYS_DCLICK_Y,
    wxSYS_DRAG_X,
    wxSYS_DRAG_Y,
    wxSYS_EDGE_X,
    wxSYS_EDGE_Y,
    wxSYS_HSCROLL_ARROW_X,
    wxSYS_HSCROLL_ARROW_Y,
    wxSYS_HTHUMB_X,
    wxSYS_ICON_X,
    wxSYS_ICON_Y,
    wxSYS_ICONSPACING_X,
    wxSYS_ICONSPACING_Y,
    wxSYS_WINDOWMIN_X,
    wxSYS_WINDOWMIN_Y,
    wxSYS_SCREEN_X,
    wxSYS_SCREEN_Y,
    wxSYS_FRAMESIZE_X,
    wxSYS_FRAMESIZE_Y,
    wxSYS_SMALLICON_X,
    wxSYS_SMALLICON_Y,
    wxSYS_HSCROLL_Y,
    wxSYS_VSCROLL_X,
    wxSYS_VSCROLL_ARROW_X,
    wxSYS_VSCROLL_ARROW_Y,
    wxSYS_VTHUMB_Y,
    wxSYS_CAPTION_Y,
    wxSYS_MENU_Y,
    wxSYS_NETWORK_PRESENT,
    wxSYS_PENWINDOWS_PRESENT,
    wxSYS_SHOW_SOUNDS,
    wxSYS_SWAP_BUTTONS
};

enum wxSystemFeature
{
     wxSYS_CAN_DRAW_FRAME_DECORATIONS,
     wxSYS_CAN_ICONIZE_FRAME
};

enum wxSystemColour
{
    wxSYS_COLOUR_SCROLLBAR,
    wxSYS_COLOUR_BACKGROUND,
    wxSYS_COLOUR_DESKTOP,
    wxSYS_COLOUR_ACTIVECAPTION,
    wxSYS_COLOUR_INACTIVECAPTION,
    wxSYS_COLOUR_MENU,
    wxSYS_COLOUR_WINDOW,
    wxSYS_COLOUR_WINDOWFRAME,
    wxSYS_COLOUR_MENUTEXT,
    wxSYS_COLOUR_WINDOWTEXT,
    wxSYS_COLOUR_CAPTIONTEXT,
    wxSYS_COLOUR_ACTIVEBORDER,
    wxSYS_COLOUR_INACTIVEBORDER,
    wxSYS_COLOUR_APPWORKSPACE,
    wxSYS_COLOUR_HIGHLIGHT,
    wxSYS_COLOUR_HIGHLIGHTTEXT,
    wxSYS_COLOUR_BTNFACE,
    wxSYS_COLOUR_3DFACE,
    wxSYS_COLOUR_BTNSHADOW,
    wxSYS_COLOUR_3DSHADOW,
    wxSYS_COLOUR_GRAYTEXT,
    wxSYS_COLOUR_BTNTEXT,
    wxSYS_COLOUR_INACTIVECAPTIONTEXT,
    wxSYS_COLOUR_BTNHIGHLIGHT,
    wxSYS_COLOUR_BTNHILIGHT,
    wxSYS_COLOUR_3DHIGHLIGHT,
    wxSYS_COLOUR_3DHILIGHT,
    wxSYS_COLOUR_3DDKSHADOW,
    wxSYS_COLOUR_3DLIGHT,
    wxSYS_COLOUR_INFOTEXT,
    wxSYS_COLOUR_INFOBK,
    wxSYS_COLOUR_LISTBOX,
    wxSYS_COLOUR_HOTLIGHT,
    wxSYS_COLOUR_GRADIENTACTIVECAPTION,
    wxSYS_COLOUR_GRADIENTINACTIVECAPTION,
    wxSYS_COLOUR_MENUHILIGHT,
    wxSYS_COLOUR_MENUBAR,
    wxSYS_COLOUR_MAX
};

enum wxSystemFont
{
    wxSYS_OEM_FIXED_FONT,
    wxSYS_ANSI_FIXED_FONT,
    wxSYS_ANSI_VAR_FONT,
    wxSYS_SYSTEM_FONT,
    wxSYS_DEVICE_DEFAULT_FONT,
    wxSYS_DEFAULT_PALETTE,
    wxSYS_SYSTEM_FIXED_FONT,
    wxSYS_DEFAULT_GUI_FONT
};

#if %wxchkver_3_1_3
class wxSystemAppearance
{
    wxString GetName() const;
    bool IsDark() const;
    bool IsUsingDarkBackground() const;
};
#endif //%wxchkver_3_1_3

class wxSystemSettings
{
    //wxSystemSettings(); // No constructor, all members static

    static wxColour GetColour(wxSystemColour index);
    static wxFont   GetFont(wxSystemFont index);
    static int      GetMetric(wxSystemMetric index, wxWindow* win = NULL);
    static bool     HasFeature(wxSystemFeature index);
    %wxchkver_3_1_3 static wxSystemAppearance GetAppearance();

    static wxSystemScreenType GetScreenType();
    static void     SetScreenType(wxSystemScreenType screen);
};

#endif //wxLUA_USE_wxSystemSettings


// ---------------------------------------------------------------------------
// wxValidator

#if wxLUA_USE_wxValidator && wxUSE_VALIDATORS

#include "wx/validate.h"

class wxValidator : public wxEvtHandler
{
    #define_object wxDefaultValidator

    // No constructor as this is a base class

    static bool IsSilent();
    wxWindow* GetWindow() const;
    !%wxchkver_2_9 || %wxcompat_2_8 static void SetBellOnError(bool doIt = true);
    void SetWindow(wxWindow* window);
    virtual bool TransferFromWindow();
    virtual bool TransferToWindow();
    virtual bool Validate(wxWindow* parent);
};

// ---------------------------------------------------------------------------
// wxTextValidator

#if wxLUA_USE_wxTextValidator

#include "wx/valtext.h"

#define wxFILTER_NONE
#define wxFILTER_EMPTY
#define wxFILTER_ASCII
#define wxFILTER_ALPHA
#define wxFILTER_ALPHANUMERIC
#define wxFILTER_DIGITS
#define wxFILTER_NUMERIC
#define wxFILTER_INCLUDE_LIST
#define wxFILTER_EXCLUDE_LIST
#define wxFILTER_INCLUDE_CHAR_LIST
#define wxFILTER_EXCLUDE_CHAR_LIST
%wxchkver_3_1_3 #define wxFILTER_XDIGITS
%wxchkver_3_1_3 #define wxFILTER_SPACE

class %delete wxTextValidator : public wxValidator
{
    // %override wxTextValidator(long style = wxFILTER_NONE, wxLuaObject* obj);
    // C++ Func: wxTextValidator(long style = wxFILTER_NONE, wxString *valPtr = NULL);
    wxTextValidator(long style = wxFILTER_NONE, wxLuaObject* stringObj = NULL);

    %wxchkver_2_6 wxArrayString& GetExcludes();
    %wxchkver_2_6 wxArrayString& GetIncludes();
    long GetStyle() const;
    void SetStyle(long style);
    %wxchkver_2_6 void SetIncludes(const wxArrayString& includes);
    %wxchkver_2_6 void SetExcludes(const wxArrayString& excludes);
};

#endif //wxLUA_USE_wxTextValidator

// ---------------------------------------------------------------------------
// wxGenericValidator

#if wxLUA_USE_wxGenericValidator

#include "wx/valgen.h"

class %delete wxGenericValidator : public wxValidator
{
    // See the validator.wx.Lua sample for usage of this class

    // %override wxGenericValidatorBool(wxLuaObject* boolObj);
    // C++ Func: wxGenericValidator(bool *boolPtr);
    // for wxCheckBox and wxRadioButton
    %rename wxGenericValidatorBool wxGenericValidator(wxLuaObject* boolObj);

    // %override wxGenericValidatorString(wxLuaObject* stringObj);
    // C++ Func: wxGenericValidator(wxString *valPtr);
    // for wxButton and wxComboBox, wxStaticText and wxTextCtrl
    %rename wxGenericValidatorString wxGenericValidator(wxLuaObject* stringObj);

    // %override wxGenericValidatorInt(wxLuaObject* intObj);
    // C++ Func: wxGenericValidator(int *valPtr);
    // for wxGauge, wxScrollBar, wxRadioBox, wxSpinButton, wxChoice
    %rename wxGenericValidatorInt wxGenericValidator(wxLuaObject* intObj);

    // %override wxGenericValidatorArrayInt(wxLuaObject* intTableObj);
    // C++ Func: wxGenericValidator(wxArrayInt *valPtr);
    // for wxListBox and wxCheckListBox
    %rename wxGenericValidatorArrayInt wxGenericValidator(wxLuaObject* intTableObj);
};

#endif //wxLUA_USE_wxGenericValidator
#endif //wxLUA_USE_wxValidator && wxUSE_VALIDATORS


// ---------------------------------------------------------------------------
//  wxMemoryFSHandler - See also wxbase_file.i for other wxFileSystemHandlers

#if wxUSE_STREAMS && wxUSE_FILESYSTEM

#include "wx/fs_mem.h"

class %delete wxMemoryFSHandler : public wxFileSystemHandler
{
    wxMemoryFSHandler();

    // Remove file from memory FS and free occupied memory
    static void RemoveFile(const wxString& filename);

    static void AddFile(const wxString& filename, const wxString& textdata);
    //static void AddFile(const wxString& filename, const void *binarydata, size_t size);

#if %wxchkver_2_8_5
    static void AddFileWithMimeType(const wxString& filename, const wxString& textdata, const wxString& mimetype);
    //static void AddFileWithMimeType(const wxString& filename, const void *binarydata, size_t size, const wxString& mimetype);
#endif // %wxchkver_2_8_5

#if wxUSE_IMAGE
    static void AddFile(const wxString& filename, const wxImage& image, wxBitmapType type);
    static void AddFile(const wxString& filename, const wxBitmap& bitmap, wxBitmapType type);
#endif // wxUSE_IMAGE
};


#endif // wxUSE_STREAMS && wxUSE_FILESYSTEM
