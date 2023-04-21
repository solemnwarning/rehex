// ===========================================================================
// Purpose:     wxRichText library
// Author:      John Labenski
// Created:     07/03/2007
// Copyright:   (c) 2007 John Labenski. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

// NOTE: This file is mostly copied from wxWidget's include/richtext/*.h headers
// to make updating it easier.

#if wxLUA_USE_wxRichText && %wxchkver_3_0 && wxUSE_RICHTEXT

#include "wx/richtext/richtextsymboldlg.h"

/*!
 * Symbols
 */

#define SYMBOL_WXSYMBOLPICKERDIALOG_STYLE (wxDEFAULT_DIALOG_STYLE|wxRESIZE_BORDER|wxCLOSE_BOX)
//#define SYMBOL_WXSYMBOLPICKERDIALOG_TITLE wxGetTranslation("Symbols")
//#define SYMBOL_WXSYMBOLPICKERDIALOG_IDNAME ID_SYMBOLPICKERDIALOG
//#define SYMBOL_WXSYMBOLPICKERDIALOG_SIZE wxSize(400, 300)
//#define SYMBOL_WXSYMBOLPICKERDIALOG_POSITION wxDefaultPosition

/*!
 * wxSymbolPickerDialog class declaration
 */

class %delete wxSymbolPickerDialog: public wxDialog
{
    //DECLARE_DYNAMIC_CLASS( wxSymbolPickerDialog )
    //DECLARE_EVENT_TABLE()
    //DECLARE_HELP_PROVISION()

public:
    /// Constructors
    wxSymbolPickerDialog( );
    wxSymbolPickerDialog( const wxString& symbol, const wxString& fontName, const wxString& normalTextFont,
        wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& caption = "Symbols", const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = SYMBOL_WXSYMBOLPICKERDIALOG_STYLE );

    /// Creation
    bool Create( const wxString& symbol, const wxString& fontName, const wxString& normalTextFont,
        wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& caption = "Symbols", const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = SYMBOL_WXSYMBOLPICKERDIALOG_STYLE );

    /// Initialises members variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

    /// Update the display
    void UpdateSymbolDisplay(bool updateSymbolList = true, bool showAtSubset = true);

    /// Respond to symbol selection
    void OnSymbolSelected( wxCommandEvent& event );

    /// Set Unicode mode
    void SetUnicodeMode(bool unicodeMode);

    /// Show at the current subset selection
    void ShowAtSubset();

    /// Get the selected symbol character
    int GetSymbolChar() const;

    /// Is there a selection?
    bool HasSelection() const;

    /// Specifying normal text?
    bool UseNormalFont() const;

    /// Should we show tooltips?
    static bool ShowToolTips();

    /// Determines whether tooltips will be shown
    static void SetShowToolTips(bool show);

    /// Data transfer
    virtual bool TransferDataToWindow();

////@begin wxSymbolPickerDialog event handler declarations

    /// wxEVT_COMBOBOX event handler for ID_SYMBOLPICKERDIALOG_FONT
    void OnFontCtrlSelected( wxCommandEvent& event );

#if defined(__UNICODE__)
    /// wxEVT_COMBOBOX event handler for ID_SYMBOLPICKERDIALOG_SUBSET
    void OnSubsetSelected( wxCommandEvent& event );

    /// wxEVT_UPDATE_UI event handler for ID_SYMBOLPICKERDIALOG_SUBSET
    void OnSymbolpickerdialogSubsetUpdate( wxUpdateUIEvent& event );

#endif
#if defined(__UNICODE__)
    /// wxEVT_COMBOBOX event handler for ID_SYMBOLPICKERDIALOG_FROM
    void OnFromUnicodeSelected( wxCommandEvent& event );

#endif
    /// wxEVT_UPDATE_UI event handler for wxID_OK
    void OnOkUpdate( wxUpdateUIEvent& event );

    /// wxEVT_BUTTON event handler for wxID_HELP
    void OnHelpClick( wxCommandEvent& event );

    /// wxEVT_UPDATE_UI event handler for wxID_HELP
    void OnHelpUpdate( wxUpdateUIEvent& event );

////@end wxSymbolPickerDialog event handler declarations

////@begin wxSymbolPickerDialog member function declarations

    wxString GetFontName() const;
    void SetFontName(wxString value);

    bool GetFromUnicode() const;
    void SetFromUnicode(bool value);

    wxString GetNormalTextFontName() const;
    void SetNormalTextFontName(wxString value);

    wxString GetSymbol() const;
    void SetSymbol(wxString value);

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end wxSymbolPickerDialog member function declarations

////@begin wxSymbolPickerDialog member variables
    wxComboBox* m_fontCtrl;
#if defined(__UNICODE__)
    wxComboBox* m_subsetCtrl;
#endif
    wxSymbolListCtrl* m_symbolsCtrl;
    wxStaticText* m_symbolStaticCtrl;
    wxTextCtrl* m_characterCodeCtrl;
#if defined(__UNICODE__)
    wxComboBox* m_fromUnicodeCtrl;
#endif
    wxStdDialogButtonSizer* m_stdButtonSizer;
    wxString m_fontName;
    bool m_fromUnicode;
    wxString m_normalTextFontName;
    wxString m_symbol;
    /// Control identifiers
    enum {
        ID_SYMBOLPICKERDIALOG = 10600,
        ID_SYMBOLPICKERDIALOG_FONT = 10602,
        ID_SYMBOLPICKERDIALOG_SUBSET = 10605,
        ID_SYMBOLPICKERDIALOG_LISTCTRL = 10608,
        ID_SYMBOLPICKERDIALOG_CHARACTERCODE = 10601,
        ID_SYMBOLPICKERDIALOG_FROM = 10603
    };
////@end wxSymbolPickerDialog member variables

    bool m_dontUpdate;
    static bool             sm_showToolTips;
};

/*!
 * The scrolling symbol list.
 */

class %delete wxSymbolListCtrl : public wxVScrolledWindow
{
public:
    // constructors and such
    // ---------------------

    // default constructor, you must call Create() later
    wxSymbolListCtrl();

    // normal constructor which calls Create() internally
    wxSymbolListCtrl(wxWindow *parent,
               wxWindowID id = wxID_ANY,
               const wxPoint& pos = wxDefaultPosition,
               const wxSize& size = wxDefaultSize,
               long style = 0,
               const wxString& name = wxPanelNameStr);

    // really creates the control and sets the initial number of items in it
    // (which may be changed later with SetItemCount())
    //
    // returns true on success or false if the control couldn't be created
    bool Create(wxWindow *parent,
                wxWindowID id = wxID_ANY,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = 0,
                const wxString& name = wxPanelNameStr);

    // dtor does some internal cleanup
    //virtual ~wxSymbolListCtrl();


    // accessors
    // ---------

    // set the current font
    virtual bool SetFont(const wxFont& font);

    // set Unicode/ASCII mode
    void SetUnicodeMode(bool unicodeMode);

    // get the index of the currently selected item or wxNOT_FOUND if there is no selection
    // int GetSelection() const;  // Not implemented

    // is this item selected?
    bool IsSelected(int item) const;

    // is this item the current one?
    bool IsCurrentItem(int item) const;

    // get the margins around each cell
    wxPoint GetMargins() const;

    // get the background colour of selected cells
    const wxColour& GetSelectionBackground() const;

    // operations
    // ----------

    // set the selection to the specified item, if it is wxNOT_FOUND the
    // selection is unset
    void SetSelection(int selection);

    // make this item visible
    void EnsureVisible(int item);

    // set the margins: horizontal margin is the distance between the window
    // border and the item contents while vertical margin is half of the
    // distance between items
    //
    // by default both margins are 0
    void SetMargins(const wxPoint& pt);
    void SetMargins(wxCoord x, wxCoord y);

    // set the cell size
    void SetCellSize(const wxSize& sz);
    const wxSize& GetCellSize() const;

    // change the background colour of the selected cells
    void SetSelectionBackground(const wxColour& col);

    virtual wxVisualAttributes GetDefaultAttributes() const;

    static wxVisualAttributes GetClassDefaultAttributes(wxWindowVariant variant = wxWINDOW_VARIANT_NORMAL);

    // Get min/max symbol values
    int GetMinSymbolValue() const;
    int GetMaxSymbolValue() const;

    // Respond to size change
    void OnSize(wxSizeEvent& event);

protected:

    // draws a line of symbols
    virtual void OnDrawItem(wxDC& dc, const wxRect& rect, size_t n) const;

    // gets the line height
    virtual wxCoord OnGetRowHeight(size_t line) const;

    // event handlers
    void OnPaint(wxPaintEvent& event);
    void OnKeyDown(wxKeyEvent& event);
    void OnLeftDown(wxMouseEvent& event);
    void OnLeftDClick(wxMouseEvent& event);

    // common part of all ctors
    void Init();

    // send the wxEVT_LISTBOX event
    void SendSelectedEvent();

    // change the current item (in single selection listbox it also implicitly
    // changes the selection); current may be wxNOT_FOUND in which case there
    // will be no current item any more
    //
    // return true if the current item changed, false otherwise
    bool DoSetCurrent(int current);

    // flags for DoHandleItemClick
/*    enum
    {
        ItemClick_Shift = 1,        // item shift-clicked
        ItemClick_Ctrl  = 2,        //       ctrl
        ItemClick_Kbd   = 4         // item selected from keyboard
    };
*/

    // common part of keyboard and mouse handling processing code
    void DoHandleItemClick(int item, int flags);

    // calculate line number from symbol value
    int SymbolValueToLineNumber(int item);

    // initialise control from current min/max values
    void SetupCtrl(bool scrollToSelection = true);

    // hit testing
    int HitTest(const wxPoint& pt);

private:
    // the current item or wxNOT_FOUND
    int m_current;

    // margins
    wxPoint     m_ptMargins;

    // the selection bg colour
    wxColour    m_colBgSel;

    // double buffer
    wxBitmap*   m_doubleBuffer;

    // cell size
    wxSize      m_cellSize;

    // minimum and maximum symbol value
    int         m_minSymbolValue;

    // minimum and maximum symbol value
    int         m_maxSymbolValue;

    // number of items per line
    int         m_symbolsPerLine;

    // Unicode/ASCII mode
    bool        m_unicodeMode;

    //DECLARE_EVENT_TABLE()
    //wxDECLARE_NO_COPY_CLASS(wxSymbolListCtrl);
    //DECLARE_ABSTRACT_CLASS(wxSymbolListCtrl)
};


//  End richtextsymboldlg.h
#endif // wxLUA_USE_wxRichText && %wxchkver_3_0 && wxUSE_RICHTEXT
