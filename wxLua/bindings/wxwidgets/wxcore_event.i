// ===========================================================================
// Purpose:     wxEvent and other generic event classes and types
//              events specific to a single control are with that control
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

// Note: wxEvtHandler and wxEvent in wxBase bindings.

// ---------------------------------------------------------------------------
// wxPropagationDisabler

#include "wx/event.h"

class %delete wxPropagationDisabler
{
    // NOTE: ALWAYS delete() this when done since Lua's gc may not delete it soon enough
    wxPropagationDisabler(wxEvent& event);
};

// ---------------------------------------------------------------------------
// wxPropagateOnce

#include "wx/event.h"

class %delete wxPropagateOnce
{
    // NOTE: ALWAYS delete() this when done since Lua's gc may not delete it soon enough
    wxPropagateOnce(wxEvent& event);
};

// ---------------------------------------------------------------------------
// wxCommandEvent

#include "wx/event.h"
%wxchkver_2_4 #include "wx/tglbtn.h"  // for wxEVT_COMMAND_TOGGLEBUTTON_CLICKED

class %delete wxCommandEvent : public wxEvent
{
    %wxEventType wxEVT_NULL // dummy placeholder nobody sends this event

    %wxEventType wxEVT_COMMAND_ENTER               // EVT_COMMAND_ENTER(winid, func);
    %wxEventType wxEVT_COMMAND_KILL_FOCUS          // EVT_COMMAND_KILL_FOCUS(winid, func);
    %wxEventType wxEVT_COMMAND_LEFT_CLICK          // EVT_COMMAND_LEFT_CLICK(winid, func);
    %wxEventType wxEVT_COMMAND_LEFT_DCLICK         // EVT_COMMAND_LEFT_DCLICK(winid, func);
    %wxEventType wxEVT_COMMAND_RIGHT_CLICK         // EVT_COMMAND_RIGHT_CLICK(winid, func);
    %wxEventType wxEVT_COMMAND_RIGHT_DCLICK        // EVT_COMMAND_RIGHT_DCLICK(winid, func);
    //%wxEventType wxEVT_COMMAND_SCROLLBAR_UPDATED // EVT_SCROLLBAR(winid, func) obsolete use wxEVT_SCROLL...
    %wxchkver_3_0_0 %wxEventType wxEVT_SCROLLBAR   // wx3.0 alias for wxEVT_COMMAND_SCROLLBAR_UPDATED
    %wxEventType wxEVT_COMMAND_SET_FOCUS           // EVT_COMMAND_SET_FOCUS(winid, func);
    //%wxEventType wxEVT_COMMAND_VLBOX_SELECTED    // EVT_VLBOX(winid, func) unused?
    %wxchkver_3_0_0 %wxEventType wxEVT_VLBOX       // wx3.0 alias for wxEVT_COMMAND_VLBOX_SELECTED

    %wxEventType wxEVT_COMMAND_MENU_SELECTED   // EVT_MENU(winid, func) EVT_MENU_RANGE(id1, id2, func);
    %wxchkver_3_0_0 %wxEventType wxEVT_MENU    // wx3.0 alias for wxEVT_COMMAND_MENU_SELECTED

    %wxEventType wxEVT_COMMAND_TOOL_CLICKED    // EVT_TOOL(winid, func) EVT_TOOL_RANGE(id1, id2, func);
    %wxEventType wxEVT_COMMAND_TOOL_ENTER      // EVT_TOOL_ENTER(winid, func);
    %wxEventType wxEVT_COMMAND_TOOL_RCLICKED   // EVT_TOOL_RCLICKED(winid, func) EVT_TOOL_RCLICKED_RANGE(id1, id2, func);
    %wxchkver_3_0_0 %wxEventType wxEVT_TOOL           // wx3.0 alias for wxEVT_COMMAND_TOOL_CLICKED
    %wxchkver_3_0_0 %wxEventType wxEVT_TOOL_ENTER     // wx3.0 alias for wxEVT_COMMAND_TOOL_ENTER
    %wxchkver_3_0_0 %wxEventType wxEVT_TOOL_RCLICKED  // wx3.0 alias for wxEVT_COMMAND_TOOL_RCLICKED

    %wxEventType wxEVT_COMMAND_TEXT_ENTER      // EVT_TEXT_ENTER(id, fn);
    %wxEventType wxEVT_COMMAND_TEXT_UPDATED    // EVT_TEXT(id, fn);
    %wxEventType wxEVT_COMMAND_TEXT_MAXLEN     // EVT_TEXT_MAXLEN(id, fn);
    %wxchkver_3_0_0 %wxEventType wxEVT_TEXT_ENTER  // wx3.0 alias for wxEVT_COMMAND_TEXT_ENTER
    %wxchkver_3_0_0 %wxEventType wxEVT_TEXT        // wx3.0 alias for wxEVT_COMMAND_TEXT_UPDATED
    %wxchkver_3_0_0 %wxEventType wxEVT_TEXT_MAXLEN // wx3.0 alias for wxEVT_COMMAND_TEXT_MAXLEN
    !%wxchkver_2_8_0 %wxEventType wxEVT_COMMAND_TEXT_URL        // EVT_TEXT_URL(id, fn);

    %wxEventType wxEVT_COMMAND_SPINCTRL_UPDATED        // EVT_SPINCTRL(id, fn);
    %wxEventType wxEVT_COMMAND_SLIDER_UPDATED          // EVT_SLIDER(winid, func);
    %wxEventType wxEVT_COMMAND_RADIOBUTTON_SELECTED    // EVT_RADIOBUTTON(winid, func);
    %wxEventType wxEVT_COMMAND_RADIOBOX_SELECTED       // EVT_RADIOBOX(winid, func);
    %wxEventType wxEVT_COMMAND_CHECKLISTBOX_TOGGLED    // EVT_CHECKLISTBOX(winid, func);
    %wxEventType wxEVT_COMMAND_LISTBOX_DOUBLECLICKED   // EVT_LISTBOX_DCLICK(winid, func);
    %wxEventType wxEVT_COMMAND_LISTBOX_SELECTED        // EVT_LISTBOX(winid, func);
    %wxEventType wxEVT_COMMAND_COMBOBOX_SELECTED       // EVT_COMBOBOX(winid, func);
    %wxEventType wxEVT_COMMAND_CHOICE_SELECTED         // EVT_CHOICE(winid, func);
    %wxEventType wxEVT_COMMAND_CHECKBOX_CLICKED        // EVT_CHECKBOX(winid, func);
    %wxEventType wxEVT_COMMAND_BUTTON_CLICKED          // EVT_BUTTON(winid, func);
    %wxchkver_2_4 %wxEventType wxEVT_COMMAND_TOGGLEBUTTON_CLICKED // EVT_TOGGLEBUTTON(id, fn);
    %wxchkver_3_0_0 %wxEventType wxEVT_SPINCTRL          // wx3.0 alias for wxEVT_COMMAND_SPINCTRL_UPDATED
    %wxchkver_3_0_0 %wxEventType wxEVT_SLIDER            // wx3.0 alias for wxEVT_COMMAND_SLIDER_UPDATED
    %wxchkver_3_0_0 %wxEventType wxEVT_RADIOBUTTON       // wx3.0 alias for wxEVT_COMMAND_RADIOBUTTON_SELECTED
    %wxchkver_3_0_0 %wxEventType wxEVT_RADIOBOX          // wx3.0 alias for wxEVT_COMMAND_RADIOBOX_SELECTED
    %wxchkver_3_0_0 %wxEventType wxEVT_CHECKLISTBOX      // wx3.0 alias for wxEVT_COMMAND_CHECKLISTBOX_TOGGLED
    %wxchkver_3_0_0 %wxEventType wxEVT_LISTBOX_DCLICK    // wx3.0 alias for wxEVT_COMMAND_LISTBOX_DOUBLECLICKED
    %wxchkver_3_0_0 %wxEventType wxEVT_LISTBOX           // wx3.0 alias for wxEVT_COMMAND_LISTBOX_SELECTED
    %wxchkver_3_0_0 %wxEventType wxEVT_COMBOBOX          // wx3.0 alias for wxEVT_COMMAND_COMBOBOX_SELECTED
    %wxchkver_3_0_0 %wxEventType wxEVT_CHOICE            // wx3.0 alias for wxEVT_COMMAND_CHOICE_SELECTED
    %wxchkver_3_0_0 %wxEventType wxEVT_CHECKBOX          // wx3.0 alias for wxEVT_COMMAND_CHECKBOX_CLICKED
    %wxchkver_3_0_0 %wxEventType wxEVT_BUTTON            // wx3.0 alias for wxEVT_COMMAND_BUTTON_CLICKED
    %wxchkver_3_0_0 %wxEventType wxEVT_TOGGLEBUTTON      // wx3.0 alias for wxEVT_COMMAND_TOGGLEBUTTON_CLICKED

    %wxchkver_3_1_1 %wxEventType wxEVT_SEARCH_CANCEL        // EVT_SEARCH_CANCEL(winid, func);
    %wxchkver_3_1_1 %wxEventType wxEVT_SEARCH               // EVT_SEARCH(winid, func);

    wxCommandEvent(wxEventType commandEventType = wxEVT_NULL, int id = 0);

    voidptr_long GetClientData(); // C++ returns (void *) You get a number here
    wxClientData* GetClientObject();
    %rename GetStringClientObject wxStringClientData* GetClientObject();
    long GetExtraLong();
    int GetInt();
    int GetSelection();
    wxString GetString();
    bool IsChecked() const;
    bool IsSelection();
    void SetClientData(voidptr_long number); // C++ is (void *clientData) You can put a number here
    void SetClientObject(wxClientData* clientObject);
    void SetExtraLong(int extraLong);
    void SetInt(int intCommand);
    void SetString(const wxString &string);
};

// ---------------------------------------------------------------------------
// wxNotifyEvent

#include "wx/event.h"

class %delete wxNotifyEvent : public wxCommandEvent
{
    wxNotifyEvent(wxEventType eventType = wxEVT_NULL, int id = 0);

    void Allow();
    bool IsAllowed() const;
    void Veto();
};

// ---------------------------------------------------------------------------
// wxActivateEvent

#include "wx/event.h"

class %delete wxActivateEvent : public wxEvent
{
    %wxEventType wxEVT_ACTIVATE        // EVT_ACTIVATE(func);
    %wxEventType wxEVT_ACTIVATE_APP    // EVT_ACTIVATE_APP(func);
    %wxEventType wxEVT_HIBERNATE       // EVT_HIBERNATE(func);

    wxActivateEvent(wxEventType eventType = wxEVT_NULL, bool active = true, int id = 0);

    bool GetActive() const;
};

// ---------------------------------------------------------------------------
// wxCloseEvent

#include "wx/event.h"

class %delete wxCloseEvent : public wxEvent
{
    %wxEventType wxEVT_CLOSE_WINDOW        // EVT_CLOSE(func);
    %wxEventType wxEVT_QUERY_END_SESSION   // EVT_QUERY_END_SESSION(func);
    %wxEventType wxEVT_END_SESSION         // EVT_END_SESSION(func);

    wxCloseEvent(wxEventType commandEventType = wxEVT_NULL, int id = 0);

    bool CanVeto();
    bool GetLoggingOff() const;
    void SetCanVeto(bool canVeto);
    void SetLoggingOff(bool loggingOff) const;
    void Veto(bool veto = true);
};

// ---------------------------------------------------------------------------
// wxDialUpEvent - TODO - the rest of wxDialUp is missing, anyone care?

//#if !%mac
//%include "wx/dialup.h"

//class %delete wxDialUpEvent : public wxCommandEvent
//{
//    %wxEventType wxEVT_DIALUP_CONNECTED      // EVT_DIALUP_CONNECTED(func);
//    %wxEventType wxEVT_DIALUP_DISCONNECTED   // EVT_DIALUP_DISCONNECTED(func);

//    wxDialUpEvent(bool isConnected, bool isOwnEvent);
//    bool IsConnectedEvent() const;
//    bool IsOwnEvent() const;
//};
//#endif

// ---------------------------------------------------------------------------
// wxEraseEvent

#include "wx/event.h"

class %delete wxEraseEvent : public wxEvent
{
    %wxEventType wxEVT_ERASE_BACKGROUND // EVT_ERASE_BACKGROUND(func);

    wxEraseEvent(int id = 0, wxDC* dc = NULL);

    wxDC* GetDC() const;
};

// ---------------------------------------------------------------------------
// wxFocusEvent

#include "wx/event.h"

class %delete wxFocusEvent : public wxEvent
{
    %wxEventType wxEVT_SET_FOCUS   // EVT_SET_FOCUS(func);
    %wxEventType wxEVT_KILL_FOCUS  // EVT_KILL_FOCUS(func);

    wxFocusEvent(wxEventType eventType = wxEVT_NULL, int id = 0);

    wxWindow* GetWindow();
    void SetWindow(wxWindow *win);
};

// ---------------------------------------------------------------------------
// wxChildFocusEvent

#include "wx/event.h"

class %delete wxChildFocusEvent : public wxCommandEvent
{
    %wxEventType wxEVT_CHILD_FOCUS // EVT_CHILD_FOCUS(func);

    wxChildFocusEvent(wxWindow *win = NULL);

    wxWindow *GetWindow() const;
};

// ---------------------------------------------------------------------------
// wxQueryNewPaletteEvent

#include "wx/event.h"

class %delete wxQueryNewPaletteEvent : public wxEvent
{
    %wxEventType wxEVT_QUERY_NEW_PALETTE // EVT_QUERY_NEW_PALETTE(func);

    wxQueryNewPaletteEvent(wxWindowID winid = 0);

    void SetPaletteRealized(bool realized);
    bool GetPaletteRealized() const;
};

// ---------------------------------------------------------------------------
// wxPaletteChangedEvent

#include "wx/event.h"

class %delete wxPaletteChangedEvent : public wxEvent
{
    %wxEventType wxEVT_PALETTE_CHANGED // EVT_PALETTE_CHANGED(func);

    wxPaletteChangedEvent(wxWindowID winid = 0);

    void SetChangedWindow(wxWindow* win);
    wxWindow* GetChangedWindow() const;
};

// ---------------------------------------------------------------------------
// wxKeyEvent

enum wxKeyCode
{
    WXK_ADD,
    WXK_ALT,
    WXK_BACK,
    WXK_CANCEL,
    WXK_CAPITAL,
    WXK_CLEAR,
    WXK_CONTROL,
    WXK_DECIMAL,
    WXK_DELETE,
    WXK_DIVIDE,
    WXK_DOWN,
    WXK_END,
    WXK_ESCAPE,
    WXK_EXECUTE,
    WXK_F1,
    WXK_F10,
    WXK_F11,
    WXK_F12,
    WXK_F13,
    WXK_F14,
    WXK_F15,
    WXK_F16,
    WXK_F17,
    WXK_F18,
    WXK_F19,
    WXK_F2,
    WXK_F20,
    WXK_F21,
    WXK_F22,
    WXK_F23,
    WXK_F24,
    WXK_F3,
    WXK_F4,
    WXK_F5,
    WXK_F6,
    WXK_F7,
    WXK_F8,
    WXK_F9,
    WXK_HELP,
    WXK_HOME,
    WXK_INSERT,
    WXK_LBUTTON,
    WXK_LEFT,
    WXK_MBUTTON,
    WXK_MENU,
    WXK_MULTIPLY,
    //WXK_NEXT = WXK_PAGEDOWN since 2.6
    WXK_NUMLOCK,
    WXK_NUMPAD_ADD,
    WXK_NUMPAD_BEGIN,
    WXK_NUMPAD_DECIMAL,
    WXK_NUMPAD_DELETE,
    WXK_NUMPAD_DIVIDE,
    WXK_NUMPAD_DOWN,
    WXK_NUMPAD_END,
    WXK_NUMPAD_ENTER,
    WXK_NUMPAD_EQUAL,
    WXK_NUMPAD_F1,
    WXK_NUMPAD_F2,
    WXK_NUMPAD_F3,
    WXK_NUMPAD_F4,
    WXK_NUMPAD_HOME,
    WXK_NUMPAD_INSERT,
    WXK_NUMPAD_LEFT,
    WXK_NUMPAD_MULTIPLY,
    // WXK_NUMPAD_NEXT = WXK_NUMPAD_PAGEDOWN since 2.6
    WXK_NUMPAD_PAGEDOWN,
    WXK_NUMPAD_PAGEUP,
    // WXK_NUMPAD_PRIOR = WXK_NUMPAD_PAGEUP since 2.6
    WXK_NUMPAD_RIGHT,
    WXK_NUMPAD_SEPARATOR,
    WXK_NUMPAD_SPACE,
    WXK_NUMPAD_SUBTRACT,
    WXK_NUMPAD_TAB,
    WXK_NUMPAD_UP,
    WXK_NUMPAD0,
    WXK_NUMPAD1,
    WXK_NUMPAD2,
    WXK_NUMPAD3,
    WXK_NUMPAD4,
    WXK_NUMPAD5,
    WXK_NUMPAD6,
    WXK_NUMPAD7,
    WXK_NUMPAD8,
    WXK_NUMPAD9,
    WXK_PAGEDOWN,
    WXK_PAGEUP,
    WXK_PAUSE,
    WXK_PRINT,
    // WXK_PRIOR = WXK_PAGEUP since 2.6
    WXK_RBUTTON,
    WXK_RETURN,
    WXK_RIGHT,
    WXK_SCROLL,
    WXK_SELECT,
    WXK_SEPARATOR,
    WXK_SHIFT,
    WXK_SNAPSHOT,
    WXK_SPACE,
    WXK_START,
    WXK_SUBTRACT,
    WXK_TAB,
    WXK_UP
};

#include "wx/event.h"

class %delete wxKeyEvent : public wxEvent
{
    %wxEventType wxEVT_KEY_DOWN            // EVT_KEY_DOWN(func);
    %wxEventType wxEVT_KEY_UP              // EVT_KEY_UP(func);
    %wxEventType wxEVT_CHAR                // EVT_CHAR(func);
    %wxEventType wxEVT_CHAR_HOOK           // EVT_CHAR_HOOK(func);
    wxUSE_HOTKEY %wxEventType wxEVT_HOTKEY // EVT_HOTKEY(winid, func);

    wxKeyEvent(wxEventType keyEventType);

    bool AltDown() const;
    bool CmdDown() const;
    bool ControlDown() const;
    int GetKeyCode() const;
    %wxchkver_2_8 int GetModifiers() const;
    wxPoint GetPosition() const;

    // %override [long x, long y] wxKeyEvent::GetPositionXY();
    // C++ Func: void GetPosition(long *x, long *y) const;
    %rename GetPositionXY void GetPosition() const;

    wxUint32 GetRawKeyCode() const;
    wxUint32 GetRawKeyFlags() const;
    wxChar GetUnicodeKey() const;
    long GetX();
    long GetY() const;
    bool HasModifiers() const;
    bool MetaDown() const;
    bool ShiftDown() const;
};

// ---------------------------------------------------------------------------
// wxNavigationKeyEvent

#include "wx/event.h"

enum wxNavigationKeyEvent::dummy
{
    IsBackward,
    IsForward,
    WinChange,
    FromTab
};

class %delete wxNavigationKeyEvent : public wxEvent
{
    %wxEventType wxEVT_NAVIGATION_KEY // EVT_NAVIGATION_KEY(func);

    wxNavigationKeyEvent();

    bool GetDirection() const;
    void SetDirection(bool bForward);
    bool IsWindowChange() const;
    void SetWindowChange(bool bIs);
    bool IsFromTab() const;
    void SetFromTab(bool bIs);
    wxWindow* GetCurrentFocus() const;
    void SetCurrentFocus(wxWindow *win);
    void SetFlags(long flags);
};

// ---------------------------------------------------------------------------
// wxIdleEvent

#include "wx/event.h"

enum wxIdleMode
{
    wxIDLE_PROCESS_ALL,
    wxIDLE_PROCESS_SPECIFIED
};

class %delete wxIdleEvent : public wxEvent
{
    %wxEventType wxEVT_IDLE // EVT_IDLE(func);

    wxIdleEvent();

    !%wxchkver_2_9_2 static bool CanSend(wxWindow* window);
    static wxIdleMode GetMode();
    void RequestMore(bool needMore = true);
    bool MoreRequested() const;
    static void SetMode(wxIdleMode mode);
};

// ---------------------------------------------------------------------------
// wxInitDialogEvent - for dialogs and panels

#include "wx/event.h"

class %delete wxInitDialogEvent : public wxEvent
{
    %wxEventType wxEVT_INIT_DIALOG // EVT_INIT_DIALOG(func);

    wxInitDialogEvent(int id = 0);
};

// ---------------------------------------------------------------------------
// wxContextMenuEvent

class %delete wxContextMenuEvent : public wxCommandEvent
{
    %wxEventType wxEVT_CONTEXT_MENU    // EVT_CONTEXT_MENU(func) EVT_COMMAND_CONTEXT_MENU(winid, func);

    wxContextMenuEvent(wxEventType type = wxEVT_NULL, wxWindowID winid = 0, const wxPoint& pt = wxDefaultPosition);
    //wxContextMenuEvent(const wxContextMenuEvent& event);

    wxPoint GetPosition() const;
    void SetPosition(const wxPoint& pos);
};

// ---------------------------------------------------------------------------
// wxMouseEvent

#include "wx/event.h"

enum
{
    wxMOUSE_BTN_ANY,
    wxMOUSE_BTN_NONE,
    wxMOUSE_BTN_LEFT,
    wxMOUSE_BTN_MIDDLE,
    wxMOUSE_BTN_RIGHT
};

#if %wxchkver_2_9_4
enum wxMouseWheelAxis
{
    wxMOUSE_WHEEL_VERTICAL,
    wxMOUSE_WHEEL_HORIZONTAL
};
#endif // %wxchkver_2_9_4

class %delete wxMouseEvent : public wxEvent
{
    %wxEventType wxEVT_ENTER_WINDOW    // EVT_ENTER_WINDOW(func);
    %wxEventType wxEVT_LEAVE_WINDOW    // EVT_LEAVE_WINDOW(func);
    %wxEventType wxEVT_LEFT_DCLICK     // EVT_LEFT_DCLICK(func);
    %wxEventType wxEVT_LEFT_DOWN       // EVT_LEFT_DOWN(func);
    %wxEventType wxEVT_LEFT_UP         // EVT_LEFT_UP(func);
    %wxEventType wxEVT_MIDDLE_DCLICK   // EVT_MIDDLE_DCLICK(func);
    %wxEventType wxEVT_MIDDLE_DOWN     // EVT_MIDDLE_DOWN(func);
    %wxEventType wxEVT_MIDDLE_UP       // EVT_MIDDLE_UP(func);
    %wxEventType wxEVT_MOTION          // EVT_MOTION(func);
    %wxEventType wxEVT_MOUSEWHEEL      // EVT_MOUSEWHEEL(func);
    %wxEventType wxEVT_RIGHT_DCLICK    // EVT_RIGHT_DCLICK(func);
    %wxEventType wxEVT_RIGHT_DOWN      // EVT_RIGHT_DOWN(func);
    %wxEventType wxEVT_RIGHT_UP        // EVT_RIGHT_UP(func);

    %wxchkver_3_0_0 %wxEventType wxEVT_AUX1_DOWN       // EVT_MOUSE_AUX1_DOWN(func);
    %wxchkver_3_0_0 %wxEventType wxEVT_AUX1_UP         // EVT_MOUSE_AUX1_UP(func);
    %wxchkver_3_0_0 %wxEventType wxEVT_AUX1_DCLICK     // EVT_MOUSE_AUX1_DCLICK(func);
    %wxchkver_3_0_0 %wxEventType wxEVT_AUX2_DOWN       // EVT_MOUSE_AUX2_DOWN(func);
    %wxchkver_3_0_0 %wxEventType wxEVT_AUX2_UP         // EVT_MOUSE_AUX2_UP(func);
    %wxchkver_3_0_0 %wxEventType wxEVT_AUX2_DCLICK     // EVT_MOUSE_AUX2_DCLICK(func);
    %wxchkver_3_1_0 %wxEventType wxEVT_MAGNIFY         // EVT_MAGNIFY (func);

    //%wxEventType wxEVT_NC_ENTER_WINDOW // FIXME - these are not used in wxWidgets
    //%wxEventType wxEVT_NC_LEAVE_WINDOW
    //%wxEventType wxEVT_NC_LEFT_DCLICK
    //%wxEventType wxEVT_NC_LEFT_DOWN
    //%wxEventType wxEVT_NC_LEFT_UP
    //%wxEventType wxEVT_NC_MIDDLE_DCLICK
    //%wxEventType wxEVT_NC_MIDDLE_DOWN
    //%wxEventType wxEVT_NC_MIDDLE_UP
    //%wxEventType wxEVT_NC_MOTION
    //%wxEventType wxEVT_NC_RIGHT_DCLICK
    //%wxEventType wxEVT_NC_RIGHT_DOWN
    //%wxEventType wxEVT_NC_RIGHT_UP

    wxMouseEvent(wxEventType mouseEventType = wxEVT_NULL);

    bool AltDown();
    bool Button(int button);
    bool ButtonDClick(int but = wxMOUSE_BTN_ANY);
    bool ButtonDown(int but = wxMOUSE_BTN_ANY);
    bool ButtonUp(int but = wxMOUSE_BTN_ANY);
    bool CmdDown() const;
    bool ControlDown();
    bool Dragging();
    bool Entering();
    wxPoint GetPosition() const;

    // %override [long x, long y] wxMouseEvent::GetPositionXY();
    // C++ Func: void GetPosition(wxCoord* x, wxCoord* y) const;
    %rename GetPositionXY void GetPosition() const;

    wxPoint GetLogicalPosition(const wxDC& dc) const;
    int GetLinesPerAction() const;
    int GetWheelRotation() const;
    int GetWheelDelta() const;
    long GetX() const;
    long GetY();
    bool IsButton() const;
    bool IsPageScroll() const;
    bool Leaving() const;
    bool LeftDClick() const;
    bool LeftDown() const;
    bool LeftIsDown() const;
    bool LeftUp() const;
    bool MetaDown() const;
    bool MiddleDClick() const;
    bool MiddleDown() const;
    bool MiddleIsDown() const;
    bool MiddleUp() const;
    bool Moving() const;
    bool RightDClick() const;
    bool RightDown() const;
    bool RightIsDown() const;
    bool RightUp() const;
    bool ShiftDown() const;

    %wxchkver_2_9_0 int GetClickCount() const;
    %wxchkver_2_9_5 int GetColumnsPerAction() const;
    %wxchkver_3_1_0 float GetMagnification() const;
    %wxchkver_2_9_4 wxMouseWheelAxis GetWheelAxis() const;
    %wxchkver_3_1_3 bool IsWheelInverted() const;
    %wxchkver_3_1_0 bool Magnify() const;
    %wxchkver_3_0_0 bool Aux1DClick() const;
    %wxchkver_3_0_0 bool Aux1Down() const;
    %wxchkver_3_0_0 bool Aux1Up() const;
    %wxchkver_3_0_0 bool Aux2DClick() const;
    %wxchkver_3_0_0 bool Aux2Down() const;
    %wxchkver_3_0_0 bool Aux2Up() const;
};

// ---------------------------------------------------------------------------
// wxMouseCaptureChangedEvent

#include "wx/event.h"

class %delete wxMouseCaptureChangedEvent : public wxEvent
{
    %wxEventType wxEVT_MOUSE_CAPTURE_CHANGED // EVT_MOUSE_CAPTURE_CHANGED(func);

    wxMouseCaptureChangedEvent(wxWindowID winid = 0, wxWindow* gainedCapture = NULL);

    wxWindow* GetCapturedWindow() const;
};

// ---------------------------------------------------------------------------
// wxMouseCaptureLostEvent

#if %wxchkver_2_8

#include "wx/event.h"

class %delete wxMouseCaptureLostEvent : public wxEvent
{
    %wxEventType wxEVT_MOUSE_CAPTURE_LOST // EVT_MOUSE_CAPTURE_LOST(func);

    wxMouseCaptureLostEvent(wxWindowID winid = 0);
};

#endif //%wxchkver_2_8

// ---------------------------------------------------------------------------
// wxMoveEvent

#include "wx/event.h"

class %delete wxMoveEvent : public wxEvent
{
    %wxEventType wxEVT_MOVE                    // EVT_MOVE(func);
    %wxchkver_2_6 %wxEventType wxEVT_MOVING    // EVT_MOVING(func);

    wxMoveEvent(const wxPoint& pt, int id = 0);

    wxPoint GetPosition() const;
};

// ---------------------------------------------------------------------------
// wxPaintEvent -
//
// Note: You must ALWAYS create a wxPaintDC for the window and delete() when
// done to have the exposed area marked as painted, otherwise you'll continue
// to get endless paint events.
// Tip: local dc = wx.wxPaintDC(event:GetEventObject():DynamicCast("wxWindow"));
//      do stuff with dc...
//      dc:delete()  -- Absolutely necessary since the garbage collector may
//                   -- not immediatelly run.

#include "wx/event.h"

class %delete wxPaintEvent : public wxEvent
{
    %wxEventType wxEVT_PAINT // EVT_PAINT(func);

    !%wxchkver_3_1_4 wxPaintEvent(int id = 0);
};

// ---------------------------------------------------------------------------
// wxNcPaintEvent - this is not sent from anything in wxWidgets

//#include "wx/event.h"

//class %delete wxNcPaintEvent : public wxEvent
//{
//    %wxEventType wxEVT_NC_PAINT // EVT_NC_PAINT(func);
//    wxNcPaintEvent(int winid = 0);
//};

// ---------------------------------------------------------------------------
// wxProcessEvent

#include "wx/process.h"

class %delete wxProcessEvent : public wxEvent
{
    %wxEventType wxEVT_END_PROCESS // EVT_END_PROCESS(id, func);

    !%wxchkver_2_6 wxProcessEvent(int id = 0, int pid = 0);
    %wxchkver_2_6 wxProcessEvent(int nId = 0, int pid = 0, int exitcode = 0);
    int GetPid() const;
    %wxchkver_2_6 int GetExitCode();
};

// ---------------------------------------------------------------------------
// wxScrollEvent - for independent scrollbars and sliders

#include "wx/event.h"

class %delete wxScrollEvent : public wxCommandEvent
{
    %wxEventType wxEVT_SCROLL_TOP          // EVT_SCROLL_TOP(func);
    %wxEventType wxEVT_SCROLL_BOTTOM       // EVT_SCROLL_BOTTOM(func);
    %wxEventType wxEVT_SCROLL_LINEUP       // EVT_SCROLL_LINEUP(func);
    %wxEventType wxEVT_SCROLL_LINEDOWN     // EVT_SCROLL_LINEDOWN(func);
    %wxEventType wxEVT_SCROLL_PAGEUP       // EVT_SCROLL_PAGEUP(func);
    %wxEventType wxEVT_SCROLL_PAGEDOWN     // EVT_SCROLL_PAGEDOWN(func);
    %wxEventType wxEVT_SCROLL_THUMBTRACK   // EVT_SCROLL_THUMBTRACK(func);
    %wxEventType wxEVT_SCROLL_THUMBRELEASE // EVT_SCROLL_THUMBRELEASE(func);
    %wxcompat_2_6 %wxEventType wxEVT_SCROLL_ENDSCROLL // EVT_SCROLL_ENDSCROLL(func) FIXME called wxEVT_SCROLL_CHANGED in 2.8
    %wxchkver_2_8 %wxEventType wxEVT_SCROLL_CHANGED   // EVT_SCROLL_CHANGED(func);

    wxScrollEvent(wxEventType commandType = wxEVT_NULL, int id = 0, int pos = 0, int orientation = 0);

    int GetOrientation() const;
    int GetPosition() const;
};

// ---------------------------------------------------------------------------
// wxScrollWinEvent - for wxScrolledWindows only

#include "wx/event.h"

class %delete wxScrollWinEvent : public wxEvent
{
    %wxEventType wxEVT_SCROLLWIN_BOTTOM        // EVT_SCROLLWIN_BOTTOM(func);
    %wxEventType wxEVT_SCROLLWIN_LINEDOWN      // EVT_SCROLLWIN_LINEDOWN(func);
    %wxEventType wxEVT_SCROLLWIN_LINEUP        // EVT_SCROLLWIN_LINEUP(func);
    %wxEventType wxEVT_SCROLLWIN_PAGEDOWN      // EVT_SCROLLWIN_PAGEDOWN(func);
    %wxEventType wxEVT_SCROLLWIN_PAGEUP        // EVT_SCROLLWIN_PAGEUP(func);
    %wxEventType wxEVT_SCROLLWIN_THUMBRELEASE  // EVT_SCROLLWIN_THUMBRELEASE(func);
    %wxEventType wxEVT_SCROLLWIN_THUMBTRACK    // EVT_SCROLLWIN_THUMBTRACK(func);
    %wxEventType wxEVT_SCROLLWIN_TOP           // EVT_SCROLLWIN_TOP(func);

    wxScrollWinEvent(wxEventType commandType = wxEVT_NULL, int pos = 0, int orientation = 0);

    int GetOrientation() const;
    int GetPosition() const;
};

// ---------------------------------------------------------------------------
// wxSizeEvent

#include "wx/event.h"

class %delete wxSizeEvent : public wxEvent
{
    %wxEventType wxEVT_SIZE                    // EVT_SIZE(func);
    %wxchkver_2_6 %wxEventType wxEVT_SIZING    // EVT_SIZING(func);

    wxSizeEvent(const wxSize& sz, int id = 0);

    wxSize GetSize() const;
};

// ---------------------------------------------------------------------------
// wxShowEvent

#include "wx/event.h"

class %delete wxShowEvent : public wxEvent
{
    %wxEventType wxEVT_SHOW // EVT_SHOW(func);

    wxShowEvent(int winid = 0, bool show = false);

    void SetShow(bool show);
    !%wxchkver_2_9 || %wxcompat_2_8 bool GetShow() const;
    %wxchkver_2_8 bool IsShown() const
};

// ---------------------------------------------------------------------------
// wxIconizeEvent

#include "wx/event.h"

class %delete wxIconizeEvent : public wxEvent
{
    %wxEventType wxEVT_ICONIZE // EVT_ICONIZE(func);

    wxIconizeEvent(int winid = 0, bool iconized = true);

    !%wxchkver_2_9 || %wxcompat_2_8 bool Iconized() const;
    %wxchkver_2_8 bool IsIconized() const;
};

// ---------------------------------------------------------------------------
// wxMaximizeEvent

#include "wx/event.h"

class %delete wxMaximizeEvent : public wxEvent
{
    %wxEventType wxEVT_MAXIMIZE // EVT_MAXIMIZE(func);

    wxMaximizeEvent(int winid = 0);
};

// ---------------------------------------------------------------------------
// wxWindowCreateEvent

#include "wx/event.h"

class %delete wxWindowCreateEvent : public wxEvent
{
    %wxEventType wxEVT_CREATE // EVT_WINDOW_CREATE(func);

    wxWindowCreateEvent(wxWindow *win = NULL);

    wxWindow *GetWindow() const;
};

// ---------------------------------------------------------------------------
// wxWindowDestroyEvent

#include "wx/event.h"

class %delete wxWindowDestroyEvent : public wxEvent
{
    %wxEventType wxEVT_DESTROY // EVT_WINDOW_DESTROY(func);

    wxWindowDestroyEvent(wxWindow *win = NULL);

    wxWindow *GetWindow() const;
};

// ---------------------------------------------------------------------------
// wxSysColourChangedEvent

#include "wx/event.h"

class %delete wxSysColourChangedEvent : public wxEvent
{
    %wxEventType wxEVT_SYS_COLOUR_CHANGED // EVT_SYS_COLOUR_CHANGED(func);

    wxSysColourChangedEvent();
};

// ---------------------------------------------------------------------------
// wxDisplayChangedEvent

#include "wx/event.h"

class %delete wxDisplayChangedEvent : public wxEvent
{
    %wxEventType wxEVT_DISPLAY_CHANGED // EVT_DISPLAY_CHANGED(func);

    wxDisplayChangedEvent();
};

// ---------------------------------------------------------------------------
// wxDPIChangedEvent

#if %wxchkver_3_1_3

#include "wx/event.h"

class %delete wxDPIChangedEvent  : public wxEvent
{
    %wxEventType wxEVT_DPI_CHANGED // EVT_DPI_CHANGED(func);

    wxDPIChangedEvent();

    wxSize GetOldDPI () const;
    wxSize GetNewDPI () const;
};

#endif // %wxchkver_3_1_3

// ---------------------------------------------------------------------------
// wxPowerEvent

#if %wxchkver_2_8

#include "wx/power.h"

enum wxPowerType
{
    wxPOWER_SOCKET,
    wxPOWER_BATTERY,
    wxPOWER_UNKNOWN
};

enum wxBatteryState
{
    wxBATTERY_NORMAL_STATE,     // system is fully usable
    wxBATTERY_LOW_STATE,        // start to worry
    wxBATTERY_CRITICAL_STATE,   // save quickly
    wxBATTERY_SHUTDOWN_STATE,   // too late
    wxBATTERY_UNKNOWN_STATE
};

wxPowerType wxGetPowerType();
wxBatteryState wxGetBatteryState();

#if wxHAS_POWER_EVENTS

class %delete wxPowerEvent : public wxEvent
{
    %wxEventType wxEVT_POWER_SUSPENDING        // EVT_POWER_SUSPENDING(func);
    %wxEventType wxEVT_POWER_SUSPENDED         // EVT_POWER_SUSPENDED(func);
    %wxEventType wxEVT_POWER_SUSPEND_CANCEL    // EVT_POWER_SUSPEND_CANCEL(func);
    %wxEventType wxEVT_POWER_RESUME            // EVT_POWER_RESUME(func);

    wxPowerEvent(wxEventType evtType);

    void Veto();
    bool IsVetoed() const;
};

#endif // wxHAS_POWER_EVENTS

#endif // %wxchkver_2_8


// ---------------------------------------------------------------------------
// wxSetCursorEvent

#include "wx/event.h"

class %delete wxSetCursorEvent : public wxEvent
{
    %wxEventType wxEVT_SET_CURSOR // EVT_SET_CURSOR(func);

    wxSetCursorEvent(wxCoord x = 0, wxCoord y = 0);

    wxCoord GetX() const;
    wxCoord GetY() const;
    void SetCursor(const wxCursor& cursor);
    wxCursor GetCursor() const;
    bool HasCursor() const;
};

// ---------------------------------------------------------------------------
// wxUpdateUIEvent

#include "wx/event.h"

enum wxUpdateUIMode
{
    wxUPDATE_UI_PROCESS_ALL,
    wxUPDATE_UI_PROCESS_SPECIFIED
};

class %delete wxUpdateUIEvent : public wxCommandEvent
{
    %wxEventType wxEVT_UPDATE_UI // EVT_UPDATE_UI(winid, func) EVT_UPDATE_UI_RANGE(id1, id2, func);

    wxUpdateUIEvent(wxWindowID commandId = wxID_ANY);

    static bool CanUpdate(wxWindow* window);
    void Check(bool check);
    void Enable(bool enable);
    bool GetChecked() const;
    bool GetEnabled() const;
    %wxchkver_2_8 bool GetShown() const;
    bool GetSetChecked() const;
    bool GetSetEnabled() const;
    %wxchkver_2_8 bool GetSetShown() const;
    bool GetSetText() const;
    wxString GetText() const;
    static wxUpdateUIMode GetMode();
    static long GetUpdateInterval();
    static void ResetUpdateTime();
    static void SetMode(wxUpdateUIMode mode);
    void SetText(const wxString& text);
    static void SetUpdateInterval(long updateInterval);
    %wxchkver_2_8 void Show(bool show);
};

// ---------------------------------------------------------------------------
// wxHelpEvent

#include "wx/event.h"

#if %wxchkver_2_8
enum wxHelpEvent::Origin
{
    Origin_Unknown,    // unrecognized event source
    Origin_Keyboard,   // event generated from F1 key press
    Origin_HelpButton // event from [?] button on the title bar (Windows);
};
#endif //%wxchkver_2_8

class %delete wxHelpEvent : public wxCommandEvent
{
    %wxEventType wxEVT_HELP            // EVT_HELP(winid, func) EVT_HELP_RANGE(id1, id2, func);
    %wxEventType wxEVT_DETAILED_HELP   // EVT_DETAILED_HELP(winid, func) EVT_DETAILED_HELP_RANGE(id1, id2, func);

    !%wxchkver_2_8 wxHelpEvent(wxEventType type = wxEVT_NULL, wxWindowID id = 0, const wxPoint& pt = wxDefaultPosition);
    %wxchkver_2_8 wxHelpEvent(wxEventType type = wxEVT_NULL, wxWindowID id = 0, const wxPoint& pt = wxDefaultPosition, wxHelpEvent::Origin origin = wxHelpEvent::Origin_Unknown);

    wxString GetLink();
    %wxchkver_2_8 wxHelpEvent::Origin GetOrigin() const;
    wxPoint  GetPosition();
    wxString GetTarget();
    void SetLink(const wxString& link);
    %wxchkver_2_8 void SetOrigin(wxHelpEvent::Origin origin);
    void SetPosition(const wxPoint& pos);
    void SetTarget(const wxString& target);
};
