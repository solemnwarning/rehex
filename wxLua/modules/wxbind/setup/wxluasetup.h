/////////////////////////////////////////////////////////////////////////////
// Name:        wxluasetup.h
// Purpose:     Control what wxLua bindings for wxWidgets are built
// Author:      John Labenski
// Created:     1/10/2008
// Copyright:   (c) 2008 John Labenski
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////


#ifndef __WXLUA_SETUP__
#define __WXLUA_SETUP__


// Enable or disable single or small groups of classes, see bindings/*.i

// This file is separate from the wxbind includes to allow you to modify it
// or put a -Iother/path/to/wxluasetup/ to allow your own wxluasetup file
// to be included since wxLua only includes it as "#include "wxluasetup.h"
// without any path.

#ifndef wxLUA_USE_Geometry
#define wxLUA_USE_Geometry                      1
#endif

#ifndef wxLUA_USE_MDI
#define wxLUA_USE_MDI                           1
#endif

#ifndef wxLUA_USE_wxAboutDialog
#define wxLUA_USE_wxAboutDialog                 1
#endif

#ifndef wxLUA_USE_wxAcceleratorTable
#define wxLUA_USE_wxAcceleratorTable            1
#endif

#ifndef wxLUA_USE_wxAnimation
#define wxLUA_USE_wxAnimation                   1
#endif

#ifndef wxLUA_USE_wxApp
#define wxLUA_USE_wxApp                         1
#endif

#ifndef wxLUA_USE_wxArrayInt
#define wxLUA_USE_wxArrayInt                    1
#endif

#ifndef wxLUA_USE_wxArrayDouble
#define wxLUA_USE_wxArrayDouble                 1
#endif

#ifndef wxLUA_USE_wxArrayString
#define wxLUA_USE_wxArrayString                 1
#endif

#ifndef wxLUA_USE_wxArtProvider
#define wxLUA_USE_wxArtProvider                 1
#endif

#ifndef wxLUA_USE_wxAUI
#define wxLUA_USE_wxAUI                         1
#endif

#ifndef wxLUA_USE_wxBitmap
#define wxLUA_USE_wxBitmap                      1
#endif

#ifndef wxLUA_USE_wxBitmapComboBox
#define wxLUA_USE_wxBitmapComboBox              1
#endif

#ifndef wxLUA_USE_wxBitmapButton
#define wxLUA_USE_wxBitmapButton                1
#endif

#ifndef wxLUA_USE_wxBrushList
#define wxLUA_USE_wxBrushList                   1
#endif

#ifndef wxLUA_USE_wxBusyCursor
#define wxLUA_USE_wxBusyCursor                  1
#endif

#ifndef wxLUA_USE_wxBusyInfo
#define wxLUA_USE_wxBusyInfo                    1
#endif

#ifndef wxLUA_USE_wxButton
#define wxLUA_USE_wxButton                      1
#endif

#ifndef wxLUA_USE_wxCalendarCtrl
#define wxLUA_USE_wxCalendarCtrl                1
#endif

#ifndef wxLUA_USE_wxCaret
#define wxLUA_USE_wxCaret                       1
#endif

#ifndef wxLUA_USE_wxCheckBox
#define wxLUA_USE_wxCheckBox                    1
#endif

#ifndef wxLUA_USE_wxCheckListBox
#define wxLUA_USE_wxCheckListBox                1
#endif

#ifndef wxLUA_USE_wxChoice
#define wxLUA_USE_wxChoice                      1
#endif

#ifndef wxLUA_USE_wxClassInfo
#define wxLUA_USE_wxClassInfo                   1
#endif

#ifndef wxLUA_USE_wxClipboard
#define wxLUA_USE_wxClipboard                   1
#endif

#ifndef wxLUA_USE_wxCollapsiblePane
#define wxLUA_USE_wxCollapsiblePane             1
#endif

#ifndef wxLUA_USE_wxColourDialog
#define wxLUA_USE_wxColourDialog                1
#endif

#ifndef wxLUA_USE_wxColourPenBrush
#define wxLUA_USE_wxColourPenBrush              1
#endif

#ifndef wxLUA_USE_wxColourPickerCtrl
#define wxLUA_USE_wxColourPickerCtrl            1
#endif

#ifndef wxLUA_USE_wxComboBox
#define wxLUA_USE_wxComboBox                    1
#endif

#ifndef wxLUA_USE_wxCommandProcessor
#define wxLUA_USE_wxCommandProcessor            1
#endif

#ifndef wxLUA_USE_wxConfig
#define wxLUA_USE_wxConfig                      1
#endif

#ifndef wxLUA_USE_wxCursor
#define wxLUA_USE_wxCursor                      1
#endif

#ifndef wxLUA_USE_wxCriticalSection
#define wxLUA_USE_wxCriticalSection             1
#endif

#ifndef wxLUA_USE_wxCriticalSectionLocker
#define wxLUA_USE_wxCriticalSectionLocker       1
#endif

#ifndef wxLUA_USE_wxDataObject
#define wxLUA_USE_wxDataObject                  1
#endif

#ifndef wxLUA_USE_wxDataViewCtrl
#define wxLUA_USE_wxDataViewCtrl                1
#endif

#ifndef wxLUA_USE_wxDatePickerCtrl
#define wxLUA_USE_wxDatePickerCtrl              1
#endif

#ifndef wxLUA_USE_wxTimePickerCtrl
#define wxLUA_USE_wxTimePickerCtrl              1
#endif

#ifndef wxLUA_USE_wxDateSpan
#define wxLUA_USE_wxDateSpan                    1
#endif

#ifndef wxLUA_USE_wxDateTime
#define wxLUA_USE_wxDateTime                    1
#endif

#ifndef wxLUA_USE_wxDateTimeHolidayAuthority
#define wxLUA_USE_wxDateTimeHolidayAuthority    1
#endif

#ifndef wxLUA_USE_wxDC
#define wxLUA_USE_wxDC                          1
#endif

#ifndef wxLUA_USE_wxDialog
#define wxLUA_USE_wxDialog                      1
#endif

#ifndef wxLUA_USE_wxDir
#define wxLUA_USE_wxDir                         1
#endif

#ifndef wxLUA_USE_wxDirDialog
#define wxLUA_USE_wxDirDialog                   1
#endif

#ifndef wxLUA_USE_wxDirPickerCtrl
#define wxLUA_USE_wxDirPickerCtrl               1
#endif

#ifndef wxLUA_USE_wxDisplay
#define wxLUA_USE_wxDisplay                     1
#endif

#ifndef wxLUA_USE_wxDragDrop
#define wxLUA_USE_wxDragDrop                    1
#endif

#ifndef wxLUA_USE_wxDynamicLibrary
#define wxLUA_USE_wxDynamicLibrary              1
#endif

#ifndef wxLUA_USE_wxFile
#define wxLUA_USE_wxFile                        1
#endif

#ifndef wxLUA_USE_wxFileDialog
#define wxLUA_USE_wxFileDialog                  1
#endif

#ifndef wxLUA_USE_wxFileHistory
#define wxLUA_USE_wxFileHistory                 1
#endif

#ifndef wxLUA_USE_wxFileName
#define wxLUA_USE_wxFileName                    1
#endif

#ifndef wxLUA_USE_wxFilePickerCtrl
#define wxLUA_USE_wxFilePickerCtrl              1
#endif

#ifndef wxLUA_USE_wxFindReplaceDialog
#define wxLUA_USE_wxFindReplaceDialog           1
#endif

#ifndef wxLUA_USE_wxFont
#define wxLUA_USE_wxFont                        1
#endif

#ifndef wxLUA_USE_wxFontDialog
#define wxLUA_USE_wxFontDialog                  1
#endif

#ifndef wxLUA_USE_wxFontEnumerator
#define wxLUA_USE_wxFontEnumerator              1
#endif

#ifndef wxLUA_USE_wxFontList
#define wxLUA_USE_wxFontList                    1
#endif

#ifndef wxLUA_USE_wxFontMapper
#define wxLUA_USE_wxFontMapper                  1
#endif

#ifndef wxLUA_USE_wxFontPickerCtrl
#define wxLUA_USE_wxFontPickerCtrl              1
#endif

#ifndef wxLUA_USE_wxFrame
#define wxLUA_USE_wxFrame                       1
#endif

#ifndef wxLUA_USE_wxGauge
#define wxLUA_USE_wxGauge                       1
#endif

#ifndef wxLUA_USE_wxGenericDirCtrl
#define wxLUA_USE_wxGenericDirCtrl              1
#endif

#ifndef wxLUA_USE_wxGenericValidator
#define wxLUA_USE_wxGenericValidator            1
#endif

#ifndef wxLUA_USE_wxGLCanvas
#define wxLUA_USE_wxGLCanvas                    1 // must link to lib, also wxUSE_GLCANVAS
#endif

#ifndef wxLUA_USE_wxGrid
#define wxLUA_USE_wxGrid                        1
#endif

#ifndef wxLUA_USE_wxHashTable
#define wxLUA_USE_wxHashTable                   1
#endif

#ifndef wxLUA_USE_wxHelpController
#define wxLUA_USE_wxHelpController              1
#endif

#ifndef wxLUA_USE_wxHTML
#define wxLUA_USE_wxHTML                        1
#endif

#ifndef wxLUA_USE_wxHtmlHelpController
#define wxLUA_USE_wxHtmlHelpController          1
#endif

#ifndef wxLUA_USE_wxHyperlinkCtrl
#define wxLUA_USE_wxHyperlinkCtrl               1
#endif

#ifndef wxLUA_USE_wxIcon
#define wxLUA_USE_wxIcon                        1
#endif

#ifndef wxLUA_USE_wxID_XXX
#define wxLUA_USE_wxID_XXX                      1
#endif

#ifndef wxLUA_USE_wxImage
#define wxLUA_USE_wxImage                       1
#endif

#ifndef wxLUA_USE_wxImageList
#define wxLUA_USE_wxImageList                   1
#endif

#ifndef wxLUA_USE_wxJoystick
#define wxLUA_USE_wxJoystick                    1
#endif

#ifndef wxLUA_USE_wxLayoutConstraints
#define wxLUA_USE_wxLayoutConstraints           1
#endif

#ifndef wxLUA_USE_wxList
#define wxLUA_USE_wxList                        1
#endif

#ifndef wxLUA_USE_wxListBox
#define wxLUA_USE_wxListBox                     1
#endif

#ifndef wxLUA_USE_wxListCtrl
#define wxLUA_USE_wxListCtrl                    1
#endif

#ifndef wxLUA_USE_wxLog
#define wxLUA_USE_wxLog                         1
#endif

#ifndef wxLUA_USE_wxLogWindow
#define wxLUA_USE_wxLogWindow                   1
#endif

#ifndef wxLUA_USE_wxLuaHtmlWindow
#define wxLUA_USE_wxLuaHtmlWindow               1
#endif

#ifndef wxLUA_USE_wxLuaPrintout
#define wxLUA_USE_wxLuaPrintout                 1
#endif

#ifndef wxLUA_USE_wxMask
#define wxLUA_USE_wxMask                        1
#endif

#ifndef wxLUA_USE_wxMediaCtrl
#define wxLUA_USE_wxMediaCtrl                   1 // must link to lib, also wxUSE_MEDIACTRL
#endif

#ifndef wxLUA_USE_wxMemoryBuffer
#define wxLUA_USE_wxMemoryBuffer                1
#endif

#ifndef wxLUA_USE_wxMenu
#define wxLUA_USE_wxMenu                        1
#endif

#ifndef wxLUA_USE_wxMessageDialog
#define wxLUA_USE_wxMessageDialog               1
#endif

#ifndef wxLUA_USE_wxMetafile
#define wxLUA_USE_wxMetafile                    1
#endif

#ifndef wxLUA_USE_wxMiniFrame
#define wxLUA_USE_wxMiniFrame                   1
#endif

#ifndef wxLUA_USE_wxMultiChoiceDialog
#define wxLUA_USE_wxMultiChoiceDialog           1
#endif

#ifndef wxLUA_USE_wxNotebook
#define wxLUA_USE_wxNotebook                    1
#endif

#ifndef wxLUA_USE_wxNumberEntryDialog
#define wxLUA_USE_wxNumberEntryDialog           1
#endif

#ifndef wxLUA_USE_wxObject
#define wxLUA_USE_wxObject                      1
#endif

#ifndef wxLUA_USE_wxPicker
#define wxLUA_USE_wxPicker                      1
#endif

#ifndef wxLUA_USE_wxPalette
#define wxLUA_USE_wxPalette                     1
#endif

#ifndef wxLUA_USE_wxPenList
#define wxLUA_USE_wxPenList                     1
#endif

#ifndef wxLUA_USE_wxPointSizeRect
#define wxLUA_USE_wxPointSizeRect               1
#endif

#ifndef wxLUA_USE_wxPopupWindow
#define wxLUA_USE_wxPopupWindow                 1
#endif

#ifndef wxLUA_USE_wxPopupTransientWindow
#define wxLUA_USE_wxPopupTransientWindow        1
#endif

#ifndef wxLUA_USE_wxPrint
#define wxLUA_USE_wxPrint                       1
#endif

#ifndef wxLUA_USE_wxProcess
#define wxLUA_USE_wxProcess                     1
#endif

#ifndef wxLUA_USE_wxProgressDialog
#define wxLUA_USE_wxProgressDialog              1
#endif

#ifndef wxLUA_USE_wxPropertyGrid
#define wxLUA_USE_wxPropertyGrid                1
#endif

#ifndef wxLUA_USE_wxRadioBox
#define wxLUA_USE_wxRadioBox                    1
#endif

#ifndef wxLUA_USE_wxRadioButton
#define wxLUA_USE_wxRadioButton                 1
#endif

#ifndef wxLUA_USE_wxRegEx
#define wxLUA_USE_wxRegEx                       1
#endif

#ifndef wxLUA_USE_wxRegion
#define wxLUA_USE_wxRegion                      1
#endif

#ifndef wxLUA_USE_wxRenderer
#define wxLUA_USE_wxRenderer                    1
#endif

#ifndef wxLUA_USE_wxRichText
#define wxLUA_USE_wxRichText                    1
#endif

#ifndef wxLUA_USE_wxSashWindow
#define wxLUA_USE_wxSashWindow                  1
#endif

#ifndef wxLUA_USE_wxScrollBar
#define wxLUA_USE_wxScrollBar                   1
#endif

#ifndef wxLUA_USE_wxScrolledWindow
#define wxLUA_USE_wxScrolledWindow              1
#endif

#ifndef wxLUA_USE_wxSingleChoiceDialog
#define wxLUA_USE_wxSingleChoiceDialog          1
#endif

#ifndef wxLUA_USE_wxSizer
#define wxLUA_USE_wxSizer                       1
#endif

#ifndef wxLUA_USE_wxSlider
#define wxLUA_USE_wxSlider                      1
#endif

#ifndef wxLUA_USE_wxSocket
#define wxLUA_USE_wxSocket                      1
#endif

#ifndef wxLUA_USE_wxSpinButton
#define wxLUA_USE_wxSpinButton                  1
#endif

#ifndef wxLUA_USE_wxSpinCtrl
#define wxLUA_USE_wxSpinCtrl                    1
#endif

#ifndef wxLUA_USE_wxSpinCtrlDouble
#define wxLUA_USE_wxSpinCtrlDouble              1
#endif

#ifndef wxLUA_USE_wxSplashScreen
#define wxLUA_USE_wxSplashScreen                1
#endif

#ifndef wxLUA_USE_wxSplitterWindow
#define wxLUA_USE_wxSplitterWindow              1
#endif

#ifndef wxLUA_USE_wxStandardPaths
#define wxLUA_USE_wxStandardPaths               1
#endif

#ifndef wxLUA_USE_wxStaticBitmap
#define wxLUA_USE_wxStaticBitmap                1
#endif

#ifndef wxLUA_USE_wxStaticBox
#define wxLUA_USE_wxStaticBox                   1
#endif

#ifndef wxLUA_USE_wxStaticLine
#define wxLUA_USE_wxStaticLine                  1
#endif

#ifndef wxLUA_USE_wxStaticText
#define wxLUA_USE_wxStaticText                  1
#endif

#ifndef wxLUA_USE_wxStatusBar
#define wxLUA_USE_wxStatusBar                   1
#endif

#ifndef wxLUA_USE_wxStopWatch
#define wxLUA_USE_wxStopWatch                   1
#endif

#ifndef wxLUA_USE_wxStringList
#define wxLUA_USE_wxStringList                  1
#endif

#ifndef wxLUA_USE_wxSystemOptions
#define wxLUA_USE_wxSystemOptions               1
#endif

#ifndef wxLUA_USE_wxSystemSettings
#define wxLUA_USE_wxSystemSettings              1
#endif

#ifndef wxLUA_USE_wxTabCtrl
#define wxLUA_USE_wxTabCtrl                     0 // deprecated MSW only control
#endif

#ifndef wxLUA_USE_wxTaskBarIcon
#define wxLUA_USE_wxTaskBarIcon                 1
#endif

#ifndef wxLUA_USE_wxTextCtrl
#define wxLUA_USE_wxTextCtrl                    1
#endif

#ifndef wxLUA_USE_wxTextEntryDialog
#define wxLUA_USE_wxTextEntryDialog             1
#endif

#ifndef wxLUA_USE_wxTextValidator
#define wxLUA_USE_wxTextValidator               1
#endif

#ifndef wxLUA_USE_wxTimer
#define wxLUA_USE_wxTimer                       1
#endif

#ifndef wxLUA_USE_wxTimeSpan
#define wxLUA_USE_wxTimeSpan                    1
#endif

#ifndef wxLUA_USE_wxToggleButton
#define wxLUA_USE_wxToggleButton                1
#endif

#ifndef wxLUA_USE_wxToolbar
#define wxLUA_USE_wxToolbar                     1
#endif

#ifndef wxLUA_USE_wxToolbook
#define wxLUA_USE_wxToolbook                    1
#endif

#ifndef wxLUA_USE_wxTooltip
#define wxLUA_USE_wxTooltip                     1
#endif

#ifndef wxLUA_USE_wxTranslations
#define wxLUA_USE_wxTranslations                0 // exclude by default due to build issues with undef reference to wxPluralFormsCalculatorPtr destructor
#endif

#ifndef wxLUA_USE_wxTreebook
#define wxLUA_USE_wxTreebook                    1
#endif

#ifndef wxLUA_USE_wxTreeCtrl
#define wxLUA_USE_wxTreeCtrl                    1
#endif

#ifndef wxLUA_USE_wxTreeListCtrl
#define wxLUA_USE_wxTreeListCtrl                1
#endif

#ifndef wxLUA_USE_wxValidator
#define wxLUA_USE_wxValidator                   1
#endif

#ifndef wxLUA_USE_wxWave
#define wxLUA_USE_wxWave                        1
#endif

#ifndef wxLUA_USE_wxWebView
#define wxLUA_USE_wxWebView                     1 // must link to lib, also wxUSE_WEBVIEW
#endif

#ifndef wxLUA_USE_wxWindowList
#define wxLUA_USE_wxWindowList                  1
#endif

#ifndef wxLUA_USE_wxWizard
#define wxLUA_USE_wxWizard                      1
#endif

#ifndef wxLUA_USE_wxXML
#define wxLUA_USE_wxXML                         1
#endif

#ifndef wxLUA_USE_wxXRC
#define wxLUA_USE_wxXRC                         1
#endif


#endif // __WXLUA_SETUP__
