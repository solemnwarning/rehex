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

#include "wx/richtext/richtextstyledlg.h"

/*!
 * Control identifiers
 */

#define SYMBOL_WXRICHTEXTSTYLEORGANISERDIALOG_STYLE wxDEFAULT_DIALOG_STYLE|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX
//#define SYMBOL_WXRICHTEXTSTYLEORGANISERDIALOG_TITLE wxGetTranslation("Style Organiser")
//#define SYMBOL_WXRICHTEXTSTYLEORGANISERDIALOG_IDNAME ID_RICHTEXTSTYLEORGANISERDIALOG
//#define SYMBOL_WXRICHTEXTSTYLEORGANISERDIALOG_SIZE wxSize(400, 300)
//#define SYMBOL_WXRICHTEXTSTYLEORGANISERDIALOG_POSITION wxDefaultPosition

/*!
 * Flags for specifying permitted operations
 */

#define wxRICHTEXT_ORGANISER_DELETE_STYLES  0x0001
#define wxRICHTEXT_ORGANISER_CREATE_STYLES  0x0002
#define wxRICHTEXT_ORGANISER_APPLY_STYLES   0x0004
#define wxRICHTEXT_ORGANISER_EDIT_STYLES    0x0008
#define wxRICHTEXT_ORGANISER_RENAME_STYLES  0x0010
#define wxRICHTEXT_ORGANISER_OK_CANCEL      0x0020
#define wxRICHTEXT_ORGANISER_RENUMBER       0x0040

// The permitted style types to show
#define wxRICHTEXT_ORGANISER_SHOW_CHARACTER 0x0100
#define wxRICHTEXT_ORGANISER_SHOW_PARAGRAPH 0x0200
#define wxRICHTEXT_ORGANISER_SHOW_LIST      0x0400
#define wxRICHTEXT_ORGANISER_SHOW_BOX       0x0800
#define wxRICHTEXT_ORGANISER_SHOW_ALL       0x1000

// Common combinations
#define wxRICHTEXT_ORGANISER_ORGANISE (wxRICHTEXT_ORGANISER_SHOW_ALL|wxRICHTEXT_ORGANISER_DELETE_STYLES|wxRICHTEXT_ORGANISER_CREATE_STYLES|wxRICHTEXT_ORGANISER_APPLY_STYLES|wxRICHTEXT_ORGANISER_EDIT_STYLES|wxRICHTEXT_ORGANISER_RENAME_STYLES)
#define wxRICHTEXT_ORGANISER_BROWSE (wxRICHTEXT_ORGANISER_SHOW_ALL|wxRICHTEXT_ORGANISER_OK_CANCEL)
#define wxRICHTEXT_ORGANISER_BROWSE_NUMBERING (wxRICHTEXT_ORGANISER_SHOW_LIST|wxRICHTEXT_ORGANISER_OK_CANCEL|wxRICHTEXT_ORGANISER_RENUMBER)

/*!
 * wxRichTextStyleOrganiserDialog class declaration
 */

class %delete wxRichTextStyleOrganiserDialog: public wxDialog
{
    //DECLARE_DYNAMIC_CLASS( wxRichTextStyleOrganiserDialog )
    //DECLARE_EVENT_TABLE()
    //DECLARE_HELP_PROVISION()

public:
    /// Constructors
    wxRichTextStyleOrganiserDialog( );
    wxRichTextStyleOrganiserDialog( int flags, wxRichTextStyleSheet* sheet, wxRichTextCtrl* ctrl, wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& caption = "Style Organiser", const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = SYMBOL_WXRICHTEXTSTYLEORGANISERDIALOG_STYLE );

    /// Creation
    bool Create( int flags, wxRichTextStyleSheet* sheet, wxRichTextCtrl* ctrl, wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& caption = "Style Organiser", const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = SYMBOL_WXRICHTEXTSTYLEORGANISERDIALOG_STYLE );

    /// Creates the controls and sizers
    void CreateControls();

    /// Initialise member variables
    void Init();

    /// Transfer data from/to window
    virtual bool TransferDataFromWindow();
    virtual bool TransferDataToWindow();

    /// Set/get style sheet
    void SetStyleSheet(wxRichTextStyleSheet* sheet);
    wxRichTextStyleSheet* GetStyleSheet() const;

    /// Set/get control
    void SetRichTextCtrl(wxRichTextCtrl* ctrl);
    wxRichTextCtrl* GetRichTextCtrl() const;

    /// Set/get flags
    void SetFlags(int flags);
    int GetFlags() const;

    /// Show preview for given or selected preview
    void ShowPreview(int sel = -1);

    /// Clears the preview
    void ClearPreview();

    /// List selection
    void OnListSelection(wxCommandEvent& event);

    /// Get/set restart numbering boolean
    bool GetRestartNumbering() const;
    void SetRestartNumbering(bool restartNumbering);

    /// Get selected style name or definition
    wxString GetSelectedStyle() const;
    wxRichTextStyleDefinition* GetSelectedStyleDefinition() const;

    /// Apply the style
    bool ApplyStyle(wxRichTextCtrl* ctrl = NULL);

    /// Should we show tooltips?
    static bool ShowToolTips();

    /// Determines whether tooltips will be shown
    static void SetShowToolTips(bool show);

////@begin wxRichTextStyleOrganiserDialog event handler declarations

    /// wxEVT_BUTTON event handler for ID_RICHTEXTSTYLEORGANISERDIALOG_NEW_CHAR
    void OnNewCharClick( wxCommandEvent& event );

    /// wxEVT_UPDATE_UI event handler for ID_RICHTEXTSTYLEORGANISERDIALOG_NEW_CHAR
    void OnNewCharUpdate( wxUpdateUIEvent& event );

    /// wxEVT_BUTTON event handler for ID_RICHTEXTSTYLEORGANISERDIALOG_NEW_PARA
    void OnNewParaClick( wxCommandEvent& event );

    /// wxEVT_UPDATE_UI event handler for ID_RICHTEXTSTYLEORGANISERDIALOG_NEW_PARA
    void OnNewParaUpdate( wxUpdateUIEvent& event );

    /// wxEVT_BUTTON event handler for ID_RICHTEXTSTYLEORGANISERDIALOG_NEW_LIST
    void OnNewListClick( wxCommandEvent& event );

    /// wxEVT_UPDATE_UI event handler for ID_RICHTEXTSTYLEORGANISERDIALOG_NEW_LIST
    void OnNewListUpdate( wxUpdateUIEvent& event );

    /// wxEVT_BUTTON event handler for ID_RICHTEXTSTYLEORGANISERDIALOG_NEW_BOX
    void OnNewBoxClick( wxCommandEvent& event );

    /// wxEVT_UPDATE_UI event handler for ID_RICHTEXTSTYLEORGANISERDIALOG_NEW_BOX
    void OnNewBoxUpdate( wxUpdateUIEvent& event );

    /// wxEVT_BUTTON event handler for ID_RICHTEXTSTYLEORGANISERDIALOG_APPLY
    void OnApplyClick( wxCommandEvent& event );

    /// wxEVT_UPDATE_UI event handler for ID_RICHTEXTSTYLEORGANISERDIALOG_APPLY
    void OnApplyUpdate( wxUpdateUIEvent& event );

    /// wxEVT_BUTTON event handler for ID_RICHTEXTSTYLEORGANISERDIALOG_RENAME
    void OnRenameClick( wxCommandEvent& event );

    /// wxEVT_UPDATE_UI event handler for ID_RICHTEXTSTYLEORGANISERDIALOG_RENAME
    void OnRenameUpdate( wxUpdateUIEvent& event );

    /// wxEVT_BUTTON event handler for ID_RICHTEXTSTYLEORGANISERDIALOG_EDIT
    void OnEditClick( wxCommandEvent& event );

    /// wxEVT_UPDATE_UI event handler for ID_RICHTEXTSTYLEORGANISERDIALOG_EDIT
    void OnEditUpdate( wxUpdateUIEvent& event );

    /// wxEVT_BUTTON event handler for ID_RICHTEXTSTYLEORGANISERDIALOG_DELETE
    void OnDeleteClick( wxCommandEvent& event );

    /// wxEVT_UPDATE_UI event handler for ID_RICHTEXTSTYLEORGANISERDIALOG_DELETE
    void OnDeleteUpdate( wxUpdateUIEvent& event );

    /// wxEVT_BUTTON event handler for wxID_HELP
    void OnHelpClick( wxCommandEvent& event );

////@end wxRichTextStyleOrganiserDialog event handler declarations

////@begin wxRichTextStyleOrganiserDialog member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end wxRichTextStyleOrganiserDialog member function declarations

////@begin wxRichTextStyleOrganiserDialog member variables
    wxBoxSizer* m_innerSizer;
    wxBoxSizer* m_buttonSizerParent;
    wxRichTextStyleListCtrl* m_stylesListBox;
    wxRichTextCtrl* m_previewCtrl;
    wxBoxSizer* m_buttonSizer;
    wxButton* m_newCharacter;
    wxButton* m_newParagraph;
    wxButton* m_newList;
    wxButton* m_newBox;
    wxButton* m_applyStyle;
    wxButton* m_renameStyle;
    wxButton* m_editStyle;
    wxButton* m_deleteStyle;
    wxButton* m_closeButton;
    wxBoxSizer* m_bottomButtonSizer;
    wxCheckBox* m_restartNumberingCtrl;
    wxStdDialogButtonSizer* m_stdButtonSizer;
    wxButton* m_okButton;
    wxButton* m_cancelButton;
    /// Control identifiers
    enum {
        ID_RICHTEXTSTYLEORGANISERDIALOG = 10500,
        ID_RICHTEXTSTYLEORGANISERDIALOG_STYLES = 10501,
        ID_RICHTEXTSTYLEORGANISERDIALOG_CURRENT_STYLE = 10510,
        ID_RICHTEXTSTYLEORGANISERDIALOG_PREVIEW = 10509,
        ID_RICHTEXTSTYLEORGANISERDIALOG_NEW_CHAR = 10504,
        ID_RICHTEXTSTYLEORGANISERDIALOG_NEW_PARA = 10505,
        ID_RICHTEXTSTYLEORGANISERDIALOG_NEW_LIST = 10508,
        ID_RICHTEXTSTYLEORGANISERDIALOG_NEW_BOX = 10512,
        ID_RICHTEXTSTYLEORGANISERDIALOG_APPLY = 10503,
        ID_RICHTEXTSTYLEORGANISERDIALOG_RENAME = 10502,
        ID_RICHTEXTSTYLEORGANISERDIALOG_EDIT = 10506,
        ID_RICHTEXTSTYLEORGANISERDIALOG_DELETE = 10507,
        ID_RICHTEXTSTYLEORGANISERDIALOG_RESTART_NUMBERING = 10511
    };
////@end wxRichTextStyleOrganiserDialog member variables

private:

    wxRichTextCtrl*         m_richTextCtrl;
    wxRichTextStyleSheet*   m_richTextStyleSheet;

    bool                    m_dontUpdate;
    int                     m_flags;
    static bool             sm_showToolTips;
    bool                    m_restartNumbering;
};

//  End richtextstyledlg.h
#endif // wxLUA_USE_wxRichText && %wxchkver_3_0 && wxUSE_RICHTEXT

#if wxLUA_USE_wxRichText && %wxchkver_3_0 && wxUSE_RICHTEXT

#include "wx/richtext/richtextstyles.h"

class %delete wxRichTextStyleDefinition: public wxObject
{
    //DECLARE_CLASS(wxRichTextStyleDefinition)
public:

    /// Copy constructors
    //wxRichTextStyleDefinition(const wxRichTextStyleDefinition& def);

    /// Default constructor
    //wxRichTextStyleDefinition(const wxString& name = wxEmptyString);

    /// Destructor
    //virtual ~wxRichTextStyleDefinition() {}

    /// Initialises members
    void Init();

    /// Copies from def
    void Copy(const wxRichTextStyleDefinition& def);

    /// Equality test
    bool Eq(const wxRichTextStyleDefinition& def) const;

    /// Assignment operator
    void operator =(const wxRichTextStyleDefinition& def);

    /// Equality operator
    bool operator ==(const wxRichTextStyleDefinition& def) const;

    /// Override to clone the object
    virtual wxRichTextStyleDefinition* Clone() const;

    /// Sets and gets the name of the style
    void SetName(const wxString& name);
    const wxString& GetName() const;

    /// Sets and gets the style description
    void SetDescription(const wxString& descr);
    const wxString& GetDescription() const;

    /// Sets and gets the name of the style that this style is based on
    void SetBaseStyle(const wxString& name);
    const wxString& GetBaseStyle() const;

    /// Sets and gets the style
    void SetStyle(const wxRichTextAttr& style);
    const wxRichTextAttr& GetStyle() const;
    wxRichTextAttr& GetStyle();

    /// Gets the style combined with the base style
    virtual wxRichTextAttr GetStyleMergedWithBase(const wxRichTextStyleSheet* sheet) const;

    /**
        Returns the definition's properties.
    */
    wxRichTextProperties& GetProperties();

    /**
        Returns the definition's properties.
    */
    const wxRichTextProperties& GetProperties() const;

    /**
        Sets the definition's properties.
    */
    void SetProperties(const wxRichTextProperties& props);

protected:
    wxString                m_name;
    wxString                m_baseStyle;
    wxString                m_description;
    wxRichTextAttr          m_style;
    wxRichTextProperties    m_properties;
};

/*!
 * wxRichTextCharacterStyleDefinition class declaration
 */

class %delete wxRichTextCharacterStyleDefinition: public wxRichTextStyleDefinition
{
    //DECLARE_DYNAMIC_CLASS(wxRichTextCharacterStyleDefinition)
public:

    /// Copy constructor
    wxRichTextCharacterStyleDefinition(const wxRichTextCharacterStyleDefinition& def);

    /// Default constructor
    wxRichTextCharacterStyleDefinition(const wxString& name = wxEmptyString);

    /// Destructor
    //virtual ~wxRichTextCharacterStyleDefinition() {}

    /// Clones the object
    virtual wxRichTextStyleDefinition* Clone() const;

protected:
};

/*!
 * wxRichTextParagraphStyleDefinition class declaration
 */

class %delete wxRichTextParagraphStyleDefinition: public wxRichTextStyleDefinition
{
    //DECLARE_DYNAMIC_CLASS(wxRichTextParagraphStyleDefinition)
public:

    /// Copy constructor
    wxRichTextParagraphStyleDefinition(const wxRichTextParagraphStyleDefinition& def);

    /// Default constructor
    wxRichTextParagraphStyleDefinition(const wxString& name = wxEmptyString);

    // Destructor
    //virtual ~wxRichTextParagraphStyleDefinition() {}

    /// Sets and gets the next style
    void SetNextStyle(const wxString& name);
    const wxString& GetNextStyle() const;

    /// Copies from def
    void Copy(const wxRichTextParagraphStyleDefinition& def);

    /// Assignment operator
    void operator =(const wxRichTextParagraphStyleDefinition& def);

    /// Equality operator
    bool operator ==(const wxRichTextParagraphStyleDefinition& def) const;

    /// Clones the object
    virtual wxRichTextStyleDefinition* Clone() const;

protected:

    /// The next style to use when adding a paragraph after this style.
    wxString    m_nextStyle;
};

/*!
 * wxRichTextListStyleDefinition class declaration
 */

class %delete wxRichTextListStyleDefinition: public wxRichTextParagraphStyleDefinition
{
    //DECLARE_DYNAMIC_CLASS(wxRichTextListStyleDefinition)
public:

    /// Copy constructor
    wxRichTextListStyleDefinition(const wxRichTextListStyleDefinition& def);

    /// Default constructor
    wxRichTextListStyleDefinition(const wxString& name = wxEmptyString);

    /// Destructor
    //virtual ~wxRichTextListStyleDefinition() {}

    /// Copies from def
    void Copy(const wxRichTextListStyleDefinition& def);

    /// Assignment operator
    void operator =(const wxRichTextListStyleDefinition& def);

    /// Equality operator
    bool operator ==(const wxRichTextListStyleDefinition& def) const;

    /// Clones the object
    virtual wxRichTextStyleDefinition* Clone() const;

    /// Sets/gets the attributes for the given level
    void SetLevelAttributes(int i, const wxRichTextAttr& attr);
    wxRichTextAttr* GetLevelAttributes(int i);
    const wxRichTextAttr* GetLevelAttributes(int i) const;

    /// Convenience function for setting the major attributes for a list level specification
    void SetAttributes(int i, int leftIndent, int leftSubIndent, int bulletStyle, const wxString& bulletSymbol = wxEmptyString);

    /// Finds the level corresponding to the given indentation
    int FindLevelForIndent(int indent) const;

    /// Combine the base and list style with a paragraph style, using the given indent (from which
    /// an appropriate level is found)
    wxRichTextAttr CombineWithParagraphStyle(int indent, const wxRichTextAttr& paraStyle, wxRichTextStyleSheet* styleSheet = NULL);

    /// Combine the base and list style, using the given indent (from which
    /// an appropriate level is found)
    wxRichTextAttr GetCombinedStyle(int indent, wxRichTextStyleSheet* styleSheet = NULL);

    /// Combine the base and list style, using the given level from which
    /// an appropriate level is found)
    wxRichTextAttr GetCombinedStyleForLevel(int level, wxRichTextStyleSheet* styleSheet = NULL);

    /// Gets the number of available levels
    int GetLevelCount() const;

    /// Is this a numbered list?
    bool IsNumbered(int i) const;

protected:

    /// The styles for each level (up to 10)
    wxRichTextAttr m_levelStyles[10];
};

/*!
 * wxRichTextBoxStyleDefinition class declaration, for box attributes in objects such as wxRichTextBox.
 */

class %delete wxRichTextBoxStyleDefinition: public wxRichTextStyleDefinition
{
    //DECLARE_DYNAMIC_CLASS(wxRichTextBoxStyleDefinition)
public:

    /// Copy constructor
    wxRichTextBoxStyleDefinition(const wxRichTextBoxStyleDefinition& def);

    /// Default constructor
    wxRichTextBoxStyleDefinition(const wxString& name = wxEmptyString);

    // Destructor
    //virtual ~wxRichTextBoxStyleDefinition() {}

    /// Copies from def
    void Copy(const wxRichTextBoxStyleDefinition& def);

    /// Assignment operator
    void operator =(const wxRichTextBoxStyleDefinition& def);

    /// Equality operator
    bool operator ==(const wxRichTextBoxStyleDefinition& def) const;

    /// Clones the object
    virtual wxRichTextStyleDefinition* Clone() const;

protected:
};

/*!
 * The style sheet
 */

class %delete wxRichTextStyleSheet: public wxObject
{
    //DECLARE_CLASS( wxRichTextStyleSheet )

public:
    /// Constructors
    wxRichTextStyleSheet(const wxRichTextStyleSheet& sheet);
    wxRichTextStyleSheet();
    //virtual ~wxRichTextStyleSheet();

    /// Initialisation
    void Init();

    /// Copy
    void Copy(const wxRichTextStyleSheet& sheet);

    /// Assignment
    void operator=(const wxRichTextStyleSheet& sheet);

    /// Equality
    bool operator==(const wxRichTextStyleSheet& sheet) const;

    /// Add a definition to the character style list
    bool AddCharacterStyle(wxRichTextCharacterStyleDefinition* def);

    /// Add a definition to the paragraph style list
    bool AddParagraphStyle(wxRichTextParagraphStyleDefinition* def);

    /// Add a definition to the list style list
    bool AddListStyle(wxRichTextListStyleDefinition* def);

    /// Add a definition to the box style list
    bool AddBoxStyle(wxRichTextBoxStyleDefinition* def);

    /// Add a definition to the appropriate style list
    bool AddStyle(wxRichTextStyleDefinition* def);

    /// Remove a character style
    bool RemoveCharacterStyle(wxRichTextStyleDefinition* def, bool deleteStyle = false);

    /// Remove a paragraph style
    bool RemoveParagraphStyle(wxRichTextStyleDefinition* def, bool deleteStyle = false);

    /// Remove a list style
    bool RemoveListStyle(wxRichTextStyleDefinition* def, bool deleteStyle = false);

    /// Remove a box style
    bool RemoveBoxStyle(wxRichTextStyleDefinition* def, bool deleteStyle = false);

    /// Remove a style
    bool RemoveStyle(wxRichTextStyleDefinition* def, bool deleteStyle = false);

    /// Find a character definition by name
    wxRichTextCharacterStyleDefinition* FindCharacterStyle(const wxString& name, bool recurse = true) const;

    /// Find a paragraph definition by name
    wxRichTextParagraphStyleDefinition* FindParagraphStyle(const wxString& name, bool recurse = true) const;

    /// Find a list definition by name
    wxRichTextListStyleDefinition* FindListStyle(const wxString& name, bool recurse = true) const;

    /// Find a box definition by name
    wxRichTextBoxStyleDefinition* FindBoxStyle(const wxString& name, bool recurse = true) const;

    /// Find any definition by name
    wxRichTextStyleDefinition* FindStyle(const wxString& name, bool recurse = true) const;

    /// Return the number of character styles
    size_t GetCharacterStyleCount() const;

    /// Return the number of paragraph styles
    size_t GetParagraphStyleCount() const;

    /// Return the number of list styles
    size_t GetListStyleCount() const;

    /// Return the number of box styles
    size_t GetBoxStyleCount() const;

    /// Return the nth character style
    wxRichTextCharacterStyleDefinition* GetCharacterStyle(size_t n) const;

    /// Return the nth paragraph style
    wxRichTextParagraphStyleDefinition* GetParagraphStyle(size_t n) const;

    /// Return the nth list style
    wxRichTextListStyleDefinition* GetListStyle(size_t n) const;

    /// Return the nth box style
    wxRichTextBoxStyleDefinition* GetBoxStyle(size_t n) const;

    /// Delete all styles
    void DeleteStyles();

    /// Insert into list of style sheets
    bool InsertSheet(wxRichTextStyleSheet* before);

    /// Append to list of style sheets
    bool AppendSheet(wxRichTextStyleSheet* after);

    /// Unlink from the list of style sheets
    void Unlink();

    /// Get/set next sheet
    wxRichTextStyleSheet* GetNextSheet() const;
    void SetNextSheet(wxRichTextStyleSheet* sheet);

    /// Get/set previous sheet
    wxRichTextStyleSheet* GetPreviousSheet() const;
    void SetPreviousSheet(wxRichTextStyleSheet* sheet);

    /// Sets and gets the name of the style sheet
    void SetName(const wxString& name);
    const wxString& GetName() const;

    /// Sets and gets the style description
    void SetDescription(const wxString& descr);
    const wxString& GetDescription() const;

    /**
        Returns the sheet's properties.
    */
    wxRichTextProperties& GetProperties();

    /**
        Returns the sheet's properties.
    */
    const wxRichTextProperties& GetProperties() const;

    /**
        Sets the sheet's properties.
    */
    void SetProperties(const wxRichTextProperties& props);

/// Implementation

    /// Add a definition to one of the style lists
    bool AddStyle(wxList& list, wxRichTextStyleDefinition* def);

    /// Remove a style
    bool RemoveStyle(wxList& list, wxRichTextStyleDefinition* def, bool deleteStyle);

    /// Find a definition by name
    wxRichTextStyleDefinition* FindStyle(const wxList& list, const wxString& name, bool recurse = true) const;

protected:

    wxString                m_description;
    wxString                m_name;

    wxList                  m_characterStyleDefinitions;
    wxList                  m_paragraphStyleDefinitions;
    wxList                  m_listStyleDefinitions;
    wxList                  m_boxStyleDefinitions;

    wxRichTextStyleSheet*   m_previousSheet;
    wxRichTextStyleSheet*   m_nextSheet;
    wxRichTextProperties    m_properties;
};

#if wxUSE_HTML

//  This is defined inside wxRichTextStyleListBox, but here we move to outside
//  (and modify 'wxRichTextStyleListBox::wxRichTextStyleType' to 'wxRichTextStyleType')
/*!
 * wxRichTextStyleListBox class declaration
 * A listbox to display styles.
 */

class %delete wxRichTextStyleListBox: public wxHtmlListBox
{
    //DECLARE_CLASS(wxRichTextStyleListBox)
    //DECLARE_EVENT_TABLE()

    enum wxRichTextStyleType
{
    wxRICHTEXT_STYLE_ALL,
    wxRICHTEXT_STYLE_PARAGRAPH,
    wxRICHTEXT_STYLE_CHARACTER,
    wxRICHTEXT_STYLE_LIST,
    wxRICHTEXT_STYLE_BOX
};


public:
    /// Which type of style definition is currently showing?

    wxRichTextStyleListBox();
    wxRichTextStyleListBox(wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition,
        const wxSize& size = wxDefaultSize, long style = 0);
    //virtual ~wxRichTextStyleListBox();

    void Init();

    bool Create(wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition,
        const wxSize& size = wxDefaultSize, long style = 0);

    /// Creates a suitable HTML fragment for a definition
    wxString CreateHTML(wxRichTextStyleDefinition* def) const;

    /// Associates the control with a style sheet
    void SetStyleSheet(wxRichTextStyleSheet* styleSheet);
    wxRichTextStyleSheet* GetStyleSheet() const;

    /// Associates the control with a wxRichTextCtrl
    void SetRichTextCtrl(wxRichTextCtrl* ctrl);
    wxRichTextCtrl* GetRichTextCtrl() const;

    /// Get style for index
    wxRichTextStyleDefinition* GetStyle(size_t i) const ;

    /// Get index for style name
    int GetIndexForStyle(const wxString& name) const ;

    /// Set selection for string, returning the index.
    int SetStyleSelection(const wxString& name);

    /// Updates the list
    void UpdateStyles();

    /// Apply the style
    void ApplyStyle(int i);

    /// Left click
    void OnLeftDown(wxMouseEvent& event);

    /// Left double-click
    void OnLeftDoubleClick(wxMouseEvent& event);

    /// Auto-select from style under caret in idle time
    void OnIdle(wxIdleEvent& event);

    /// Convert units in tends of a millimetre to device units
    int ConvertTenthsMMToPixels(wxDC& dc, int units) const;

    /// Can we set the selection based on the editor caret position?
    /// Need to override this if being used in a combobox popup
    virtual bool CanAutoSetSelection();
    virtual void SetAutoSetSelection(bool autoSet);

    /// Set whether the style should be applied as soon as the item is selected (the default)
    void SetApplyOnSelection(bool applyOnSel);
    bool GetApplyOnSelection() const;

    /// Set the style type to display
    void SetStyleType(wxRichTextStyleListBox::wxRichTextStyleType styleType);
    wxRichTextStyleListBox::wxRichTextStyleType GetStyleType() const;

    /// Helper for listbox and combo control
    static wxString GetStyleToShowInIdleTime(wxRichTextCtrl* ctrl, wxRichTextStyleListBox::wxRichTextStyleType styleType);

protected:
    /// Returns the HTML for this item
    virtual wxString OnGetItem(size_t n) const;

private:

    wxRichTextStyleSheet*   m_styleSheet;
    wxRichTextCtrl*         m_richTextCtrl;
    bool                    m_applyOnSelection; // if true, applies style on selection
    wxRichTextStyleType     m_styleType; // style type to display
    bool                    m_autoSetSelection;
    wxArrayString           m_styleNames;
};

/*!
 * wxRichTextStyleListCtrl class declaration
 * This is a container for the list control plus a combobox to switch between
 * style types.
 */

#define wxRICHTEXTSTYLELIST_HIDE_TYPE_SELECTOR     0x1000

class %delete wxRichTextStyleListCtrl: public wxControl
{
    //DECLARE_CLASS(wxRichTextStyleListCtrl)
    //DECLARE_EVENT_TABLE()

public:

    /// Constructors
    wxRichTextStyleListCtrl();

    wxRichTextStyleListCtrl(wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition,
        const wxSize& size = wxDefaultSize, long style = 0);

    /// Constructors
    //virtual ~wxRichTextStyleListCtrl();

    /// Member initialisation
    void Init();

    /// Creates the windows
    bool Create(wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition,
        const wxSize& size = wxDefaultSize, long style = 0);

    /// Updates the style list box
    void UpdateStyles();

    /// Associates the control with a style sheet
    void SetStyleSheet(wxRichTextStyleSheet* styleSheet);
    wxRichTextStyleSheet* GetStyleSheet() const;

    /// Associates the control with a wxRichTextCtrl
    void SetRichTextCtrl(wxRichTextCtrl* ctrl);
    wxRichTextCtrl* GetRichTextCtrl() const;

    /// Set/get the style type to display
    void SetStyleType(wxRichTextStyleListBox::wxRichTextStyleType styleType);
    wxRichTextStyleListBox::wxRichTextStyleType GetStyleType() const;

    /// Get the choice index for style type
    int StyleTypeToIndex(wxRichTextStyleListBox::wxRichTextStyleType styleType);

    /// Get the style type for choice index
    wxRichTextStyleListBox::wxRichTextStyleType StyleIndexToType(int i);

    /// Get the listbox
    wxRichTextStyleListBox* GetStyleListBox() const;

    /// Get the choice
    wxChoice* GetStyleChoice() const;

    /// React to style type choice
    void OnChooseType(wxCommandEvent& event);

    /// Lay out the controls
    void OnSize(wxSizeEvent& event);

private:

    wxRichTextStyleListBox* m_styleListBox;
    wxChoice*               m_styleChoice;
    bool                    m_dontUpdate;
};

#if wxUSE_COMBOCTRL

/*!
 * wxRichTextStyleComboCtrl
 * A combo for applying styles.
 */

class %delete wxRichTextStyleComboCtrl: public wxComboCtrl
{
    //DECLARE_CLASS(wxRichTextStyleComboCtrl)
    //DECLARE_EVENT_TABLE()

public:
    wxRichTextStyleComboCtrl();

    wxRichTextStyleComboCtrl(wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition,
        const wxSize& size = wxDefaultSize, long style = wxCB_READONLY);

    //virtual ~wxRichTextStyleComboCtrl() {}

    void Init();

    bool Create(wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition,
        const wxSize& size = wxDefaultSize, long style = 0);

    /// Updates the list
    void UpdateStyles();

    /// Associates the control with a style sheet
    void SetStyleSheet(wxRichTextStyleSheet* styleSheet);
    wxRichTextStyleSheet* GetStyleSheet() const;

    /// Associates the control with a wxRichTextCtrl
    void SetRichTextCtrl(wxRichTextCtrl* ctrl);
    wxRichTextCtrl* GetRichTextCtrl() const;

    /// Auto-select from style under caret in idle time
    void OnIdle(wxIdleEvent& event);
};

#endif
    // wxUSE_COMBOCTRL

#endif
    // wxUSE_HTML

//  End richtextstyles.h
#endif // wxLUA_USE_wxRichText && %wxchkver_3_0 && wxUSE_RICHTEXT
