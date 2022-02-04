// ===========================================================================
// Purpose:     wxHtml library
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

#if wxLUA_USE_wxHTML && wxUSE_HTML

// ---------------------------------------------------------------------------
// wxHtmlCell

#include "wx/html/htmlcell.h"

#define wxHTML_COND_ISANCHOR
#define wxHTML_COND_ISIMAGEMAP
#define wxHTML_COND_USER

#if %wxchkver_3_1_2
enum wxHtmlSelectionState
{
    wxHTML_SEL_OUT,     // currently rendered cell is outside the selection
    wxHTML_SEL_IN,      // ... is inside selection
    wxHTML_SEL_CHANGING // ... is the cell on which selection state changes
};

class wxHtmlRenderingInfo
{
public:
    wxHtmlRenderingInfo();

    void SetSelection(wxHtmlSelection *s);
    wxHtmlSelection *GetSelection() const;
    void SetStyle(wxHtmlRenderingStyle *style);
    wxHtmlRenderingStyle& GetStyle();
    wxHtmlRenderingState& GetState();
};

class wxHtmlRenderingStyle
{
public:
    virtual wxColour GetSelectedTextColour(const wxColour& clr);
    virtual wxColour GetSelectedTextBgColour(const wxColour& clr);
};

class wxHtmlSelection
{
public:
    wxHtmlSelection();

    void Set(const wxPoint& fromPos, const wxHtmlCell *fromCell, const wxPoint& toPos, const wxHtmlCell *toCell);
    void Set(const wxHtmlCell *fromCell, const wxHtmlCell *toCell);

    const wxHtmlCell *GetFromCell() const;
    const wxHtmlCell *GetToCell() const;
    const wxPoint& GetFromPos() const;
    const wxPoint& GetToPos() const;
    void ClearFromToCharacterPos();
    bool AreFromToCharacterPosSet() const;
    void SetFromCharacterPos (wxCoord pos);
    void SetToCharacterPos (wxCoord pos);
    wxCoord GetFromCharacterPos () const;
    wxCoord GetToCharacterPos () const;
    bool IsEmpty() const;
};

class wxHtmlRenderingState
{
public:
    wxHtmlRenderingState();

    void SetSelectionState(wxHtmlSelectionState s);
    wxHtmlSelectionState GetSelectionState() const;

    void SetFgColour(const wxColour& c);
    const wxColour& GetFgColour() const;
    void SetBgColour(const wxColour& c);
    const wxColour& GetBgColour() const;
    void SetBgMode(int m);
    int GetBgMode() const;
};
#endif // %wxchkver_3_1_2

class %delete wxHtmlCell : public wxObject
{
    wxHtmlCell();
    %wxchkver_3_1_2 void Draw(wxDC& dc, int x, int y, int view_y1, int view_y2, wxHtmlRenderingInfo& info);
    %wxchkver_3_1_2 void DrawInvisible(wxDC& dc, int x , int y, wxHtmlRenderingInfo& info);
    %wxchkver_3_1_2 const wxHtmlCell* Find(int condition, const void* param) const;
    %wxchkver_3_1_2 wxHtmlCell *FindCellByPos(wxCoord x, wxCoord y, unsigned flags = wxHTML_FIND_EXACT) const;
    int GetDescent() const;
    wxHtmlCell* GetFirstChild();
    int GetHeight() const;
    virtual wxString GetId() const;
    virtual wxHtmlLinkInfo* GetLink(int x = 0, int y = 0) const;
    %wxchkver_3_1_2 wxCursor GetMouseCursor(wxHtmlWindowInterface* window) const;
    %wxchkver_3_1_2 wxCursor GetMouseCursorAt(wxHtmlWindowInterface* window, const wxPoint& rePos) const;
    wxHtmlCell* GetNext() const;
    wxHtmlContainerCell* GetParent() const;
    int GetPosX() const;
    int GetPosY() const;
    int GetWidth() const;
    virtual void Layout(int w);
    bool ProcessMouseClick(wxHtmlWindowInterface* window, const wxPoint& pos, const wxMouseEvent& event);
    void SetId(const wxString& id);
    void SetLink(const wxHtmlLinkInfo& link);
    void SetNext(wxHtmlCell* cell);
    void SetParent(wxHtmlContainerCell* p);
    void SetPos(int x, int y);
    %wxchkver_3_1_2 wxString ConvertToText(wxHtmlSelection* sel) const;
    %wxchkver_2_8 && !%wxchkver_2_9_4 virtual bool AdjustPagebreak(int pagebreak, wxArrayInt& known_pagebreaks);
    %wxchkver_2_9_4 && !%wxchkver_3_1_2 virtual bool AdjustPagebreak(int* pagebreak, wxArrayInt& known_pagebreaks, int pageHeight);
    %wxchkver_3_1_2 virtual bool AdjustPagebreak(int* pagebreak, int pageHeight); // %override parameters
    //virtual void DrawInvisible(wxDC& dc, int x, int y, wxHtmlRenderingInfo& info);
    //virtual void OnMouseClick(wxWindow* parent, int x, int y, const wxMouseEvent& event);
};

// ---------------------------------------------------------------------------
// wxHtmlWidgetCell

#include "wx/html/htmlcell.h"

class wxHtmlWidgetCell : public wxHtmlCell
{
    wxHtmlWidgetCell(wxWindow* wnd, int w = 0);
};


// ---------------------------------------------------------------------------
// wxHtmlContainerCell

#include "wx/html/htmlcell.h"

#define wxHTML_UNITS_PIXELS
#define wxHTML_UNITS_PERCENT
#define wxHTML_INDENT_TOP
#define wxHTML_INDENT_BOTTOM
#define wxHTML_INDENT_LEFT
#define wxHTML_INDENT_RIGHT
#define wxHTML_INDENT_HORIZONTAL
#define wxHTML_INDENT_VERTICAL
#define wxHTML_INDENT_ALL
#define wxHTML_ALIGN_LEFT
#define wxHTML_ALIGN_JUSTIFY
#define wxHTML_ALIGN_CENTER
#define wxHTML_ALIGN_RIGHT
#define wxHTML_ALIGN_BOTTOM
#define wxHTML_ALIGN_TOP

class wxHtmlContainerCell : public wxHtmlCell
{
    wxHtmlContainerCell(wxHtmlContainerCell *parent);

    int GetAlignHor() const;
    int GetAlignVer() const;
    wxColour GetBackgroundColour();
    int GetIndent(int ind) const;
    int GetIndentUnits(int ind) const;
    void InsertCell(wxHtmlCell *cell);
    void SetAlign(const wxHtmlTag& tag);
    void SetAlignHor(int al);
    void SetAlignVer(int al);
    void SetBackgroundColour(const wxColour& clr);
    void SetBorder(const wxColour& clr1, const wxColour& clr2);
    void SetIndent(int i, int what, int units = wxHTML_UNITS_PIXELS);
    void SetMinHeight(int h, int align = wxHTML_ALIGN_TOP);
    void SetWidthFloat(int w, int units);
    void SetWidthFloat(const wxHtmlTag& tag, double pixel_scale = 1.0);

    // %wxchkver_2_6 wxHtmlCell* GetFirstChild() see wxHtmlCell
    // !%wxchkver_2_6 wxHtmlCell* GetFirstCell() - nobody probably uses this
};

// ---------------------------------------------------------------------------
// wxHtmlColourCell

#if %wxchkver_2_8

#include "wx/html/htmlcell.h"

class wxHtmlColourCell : public wxHtmlCell
{
    wxHtmlColourCell(const wxColour& clr, int flags = wxHTML_CLR_FOREGROUND);

    //virtual void Draw(wxDC& dc, int x, int y, int view_y1, int view_y2, wxHtmlRenderingInfo& info);
    //virtual void DrawInvisible(wxDC& dc, int x, int y, wxHtmlRenderingInfo& info);
};

#endif // %wxchkver_2_8

// ---------------------------------------------------------------------------
// wxHtmlFontCell

#if %wxchkver_2_8

#include "wx/html/htmlcell.h"

class wxHtmlFontCell : public wxHtmlCell
{
    wxHtmlFontCell(wxFont *font);

    //virtual void Draw(wxDC& dc, int x, int y, int view_y1, int view_y2, wxHtmlRenderingInfo& info);
    //virtual void DrawInvisible(wxDC& dc, int x, int y, wxHtmlRenderingInfo& info);
};

#endif // %wxchkver_2_8

// ---------------------------------------------------------------------------
// wxHtmlCellEvent

#if %wxchkver_2_8

#include "wx/html/htmlwin.h"

class %delete wxHtmlCellEvent : public wxCommandEvent
{
    %wxEventType wxEVT_HTML_CELL_HOVER  // EVT_HTML_CELL_HOVER(id, fn);
    %wxEventType wxEVT_HTML_CELL_CLICKED // EVT_HTML_CELL_CLICKED(id, fn);

    wxHtmlCellEvent();
    wxHtmlCellEvent(wxEventType commandType, int id, wxHtmlCell *cell, const wxPoint &pt, const wxMouseEvent &ev);

    wxHtmlCell* GetCell() const;
    wxPoint GetPoint() const;
    wxMouseEvent GetMouseEvent() const;

    void SetLinkClicked(bool linkclicked);
    bool GetLinkClicked() const;
};

#endif // %wxchkver_2_8

// ---------------------------------------------------------------------------
// wxHtmlLinkEvent

#if %wxchkver_2_8

#include "wx/html/htmlwin.h"

class %delete wxHtmlLinkEvent : public wxCommandEvent
{
    %wxEventType wxEVT_HTML_LINK_CLICKED // EVT_HTML_LINK_CLICKED(id, fn);

    wxHtmlLinkEvent(int id, const wxHtmlLinkInfo &linkinfo);

    const wxHtmlLinkInfo& GetLinkInfo() const;
};

#endif // %wxchkver_2_8


// ---------------------------------------------------------------------------
// wxHtmlLinkInfo

#include "wx/html/htmlcell.h"

class %delete wxHtmlLinkInfo
{
    wxHtmlLinkInfo(const wxString& href, const wxString& target = "");

    const wxMouseEvent * GetEvent();
    const wxHtmlCell * GetHtmlCell();
    wxString GetHref();
    wxString GetTarget();
};

// ---------------------------------------------------------------------------
// wxHtmlTag

#include "wx/html/htmltag.h"

class wxHtmlTag // !%wxchkver_2_9_2 wxObject
{
    //wxHtmlTag(const wxString& source, int pos, int end_pos, wxHtmlTagsCache* cache);

    const wxString GetAllParams() const;
    
#if !%wxchkver_3_0 || WXWIN_COMPATIBILITY_2_8
    int GetBeginPos() const;
    int GetEndPos1() const;
    int GetEndPos2() const;
#endif // !%wxchkver_3_0 || WXWIN_COMPATIBILITY_2_8
    
    wxString GetName() const;
    wxString GetParam(const wxString& par, bool with_commas = false) const;

    // %override [bool, wxColour] wxHtmlTag::GetParamAsColour(const wxString& par) const;
    // C++ Func: bool GetParamAsColour(const wxString& par, wxColour *clr) const;
    bool GetParamAsColour(const wxString& par) const;

    // %override [bool, int value] wxHtmlTag::GetParamAsInt(const wxString& par) const;
    // C++ Func: bool GetParamAsInt(const wxString& par, int *value) const;
    bool GetParamAsInt(const wxString& par) const;

    bool HasEnding() const;
    bool HasParam(const wxString& par) const;
    //bool IsEnding() const;
    //wxString ScanParam(const wxString& par, const wxString &format, void *value) const;
};

// ---------------------------------------------------------------------------
// wxHtmlWindow

#include "wx/wxhtml.h"

#define wxHW_SCROLLBAR_NEVER
#define wxHW_SCROLLBAR_AUTO

class wxHtmlWindow : public wxScrolledWindow
{
    wxHtmlWindow(wxWindow *parent, wxWindowID id = -1, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxHW_SCROLLBAR_AUTO, const wxString& name = "wxHtmlWindow");

    //static void AddFilter(wxHtmlFilter *filter);
    bool AppendToPage(const wxString& source);
    wxHtmlContainerCell* GetInternalRepresentation() const;
    wxString GetOpenedAnchor();
    wxString GetOpenedPage();
    wxString GetOpenedPageTitle();
    wxFrame* GetRelatedFrame() const;
    bool HistoryBack();
    bool HistoryCanBack();
    bool HistoryCanForward();
    void HistoryClear();
    bool HistoryForward();
    virtual bool LoadFile(const wxFileName& filename);
    bool LoadPage(const wxString& location);
    void ReadCustomization(wxConfigBase *cfg, wxString path = wxEmptyString);
    void SelectAll();
    wxString SelectionToText();
    void SelectLine(const wxPoint& pos);
    void SelectWord(const wxPoint& pos);
    void SetBorders(int b);

    // %override void wxHtmlWindow::SetFonts(wxString normal_face, wxString fixed_face, Lua int table);
    // C++ Func: void SetFonts(wxString normal_face, wxString fixed_face, const int *sizes);
    void SetFonts(wxString normal_face, wxString fixed_face, LuaTable intTable);

    bool SetPage(const wxString& source);
    void SetRelatedFrame(wxFrame* frame, const wxString& format);
    void SetRelatedStatusBar(int bar);
    wxString ToText();
    void WriteCustomization(wxConfigBase *cfg, wxString path = wxEmptyString);
};


// ---------------------------------------------------------------------------
// wxLuaHtmlWindow

#if wxLUA_USE_wxLuaHtmlWindow

#include "wxbind/include/wxhtml_wxlhtml.h"

class wxLuaHtmlWindow : public wxHtmlWindow
{
    wxLuaHtmlWindow(wxWindow *parent, wxWindowID id = -1, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxHW_SCROLLBAR_AUTO, const wxString& name = "wxLuaHtmlWindow");

    // The functions below are all virtual functions that you can override in Lua.
    // See the html sample and wxHtmlWindow for proper parameters and usage.
    //bool OnCellClicked(wxHtmlCell *cell, wxCoord x, wxCoord y, const wxMouseEvent& event);
    //void OnCellMouseHover(wxHtmlCell *cell, wxCoord x, wxCoord y);
    //void OnLinkClicked(const wxHtmlLinkInfo& link);
    //void OnSetTitle(const wxString& title);
};

// ---------------------------------------------------------------------------
// wxLuaHtmlWinTagEvent

class %delete wxLuaHtmlWinTagEvent : public wxEvent
{
    %wxEventType wxEVT_HTML_TAG_HANDLER // EVT_HTML_TAG_HANDLER(id, fn);

    const wxHtmlTag      *GetHtmlTag() const;
    wxHtmlWinParser      *GetHtmlParser() const;
    void                  SetParseInnerCalled(bool fParseInnerCalled = true);
    bool                  GetParseInnerCalled() const;
};

#endif //wxLUA_USE_wxLuaHtmlWindow


// ---------------------------------------------------------------------------
// wxHtmlParser

//enum wxHtmlURLType
//{
//    wxHTML_URL_PAGE,
//    wxHTML_URL_IMAGE,
//    wxHTML_URL_OTHER
//};

class wxHtmlParser : public wxObject
{
    //wxHtmlParser();

    //void AddTag(const wxHtmlTag& tag);
    //void AddTagHandler(wxHtmlTagHandler *handler);
    //void AddWord(const wxString &txt) - not in 2.6?
    %wxchkver_2_9_2 void DoParsing(const wxString::const_iterator& begin_pos, const wxString::const_iterator& end_pos);
    !%wxchkver_2_9_2 void DoParsing(int begin_pos, int end_pos);
    void DoParsing();
    virtual void DoneParser();
    //virtual wxObject* GetProduct();
    //wxString* GetSource();
    void InitParser(const wxString& source);
    //virtual wxFSFile* OpenURL(wxHtmlURLType type, const wxString& url);
    //wxObject* Parse(const wxString& source);
    //void PushTagHandler(wxHtmlTagHandler* handler, wxString tags);
    //void PopTagHandler();
    //void SetFS(wxFileSystem *fs);
    //void StopParsing();
};

// ---------------------------------------------------------------------------
// wxHtmlWinParser

class wxHtmlWinParser : public wxHtmlParser
{
    wxHtmlWinParser(wxHtmlWindow *wnd);

    wxHtmlContainerCell* CloseContainer();
    wxFont* CreateCurrentFont();
    wxColour GetActualColor() const;
    int GetAlign() const;
    int GetCharHeight() const;
    int GetCharWidth() const;
    wxHtmlContainerCell* GetContainer() const;
    wxDC* GetDC();
    //wxEncodingConverter * GetEncodingConverter() const;
    int GetFontBold() const;
    wxString GetFontFace() const;
    int GetFontFixed() const;
    int GetFontItalic() const;
    int GetFontSize() const;
    int GetFontUnderlined() const;
    //wxFontEncoding GetInputEncoding() const;
    const wxHtmlLinkInfo& GetLink() const;
    wxColour GetLinkColor() const;
    //wxFontEncoding GetOutputEncoding() const;
    %wxchkver_2_8 wxHtmlWindowInterface *GetWindowInterface();
    !%wxchkver_2_8 wxWindow* GetWindow();
    wxHtmlContainerCell* OpenContainer();
    void SetActualColor(const wxColour& clr);
    void SetAlign(int a);
    wxHtmlContainerCell* SetContainer(wxHtmlContainerCell *c);
    void SetDC(wxDC *dc, double pixel_scale = 1.0);
    void SetFontBold(int x);
    void SetFontFace(const wxString& face);
    void SetFontFixed(int x);
    void SetFontItalic(int x);
    void SetFontSize(int s);
    void SetFontUnderlined(int x);

    // %override void wxHtmlWinParser::SetFonts(wxString normal_face, wxString fixed_face, Lua int table);
    // C++ Func: void SetFonts(wxString normal_face, wxString fixed_face, const int *sizes);
    void SetFonts(wxString normal_face, wxString fixed_face, LuaTable intTable);

    void SetLink(const wxHtmlLinkInfo& link);
    void SetLinkColor(const wxColour& clr);
};

// ---------------------------------------------------------------------------
// wxHtmlWindowInterface

#if %wxchkver_2_8

enum wxHtmlWindowInterface::HTMLCursor
{
    HTMLCursor_Default,
    HTMLCursor_Link,
    HTMLCursor_Text
};

class wxHtmlWindowInterface
{
    virtual void SetHTMLWindowTitle(const wxString& title);
    virtual void OnHTMLLinkClicked(const wxHtmlLinkInfo& link);
    //virtual wxHtmlOpeningStatus OnHTMLOpeningURL(wxHtmlURLType type, const wxString& url, wxString *redirect) const;
    virtual wxPoint HTMLCoordsToWindow(wxHtmlCell *cell, const wxPoint& pos) const;
    virtual wxWindow* GetHTMLWindow();
    virtual wxColour GetHTMLBackgroundColour() const;
    virtual void SetHTMLBackgroundColour(const wxColour& clr);
    virtual void SetHTMLBackgroundImage(const wxBitmap& bmpBg);
    virtual void SetHTMLStatusText(const wxString& text);
    virtual wxCursor GetHTMLCursor(wxHtmlWindowInterface::HTMLCursor type) const;
};

// ----------------------------------------------------------------------------
// wxSimpleHtmlListBox - Use this instead of having to override virtual functions in wxHtmlListBox

#include "wx/htmllbox.h"

#define wxHLB_DEFAULT_STYLE
#define wxHLB_MULTIPLE

class wxSimpleHtmlListBox : public wxPanel, public wxHtmlWindowInterface //: public wxHtmlListBox, public wxItemContainer
{
    wxSimpleHtmlListBox();
    wxSimpleHtmlListBox(wxWindow *parent, wxWindowID id, const wxPoint& pos, const wxSize& size, const wxArrayString& choices, long style = wxHLB_DEFAULT_STYLE, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxSimpleHtmlListBox");
    bool Create(wxWindow *parent, wxWindowID id, const wxPoint& pos, const wxSize& size, const wxArrayString& choices, long style = wxHLB_DEFAULT_STYLE, const wxValidator& validator = wxDefaultValidator, const wxString& name = "wxSimpleHtmlListBox");

    void SetSelection(int n);
    int GetSelection() const;
    virtual unsigned int GetCount() const;
    virtual wxString GetString(unsigned int n) const;
    wxArrayString GetStrings() const;
    virtual void SetString(unsigned int n, const wxString& s);
    virtual void Clear();
    virtual void Delete(unsigned int n);
    void Append(const wxArrayString& strings);
    int Append(const wxString& item);
    int Append(const wxString& item, voidptr_long number); // C++ is (void *clientData) You can put a number here
    int Append(const wxString& item, wxClientData *clientData);
};

#endif //%wxchkver_2_8

// ---------------------------------------------------------------------------
// wxHtmlDCRenderer

#include "wx/html/htmprint.h"

class %delete wxHtmlDCRenderer : public wxObject
{
    wxHtmlDCRenderer();
    int GetTotalWidth() const;
    int GetTotalHeight() const;
    %wxchkver_3_1_2 int FindNextPageBreak(int pos) const;
    %wxchkver_3_1_2 void Render(int x, int y, int from = 0, int to = INT_MAX);
    void SetDC(wxDC* dc, double pixel_scale = 1.0);
    %wxchkver_3_1_2 void SetStandardFonts(int size = -1, const wxString& normal_face = wxEmptyString, const wxString& fixed_face = wxEmptyString);
    void SetHtmlText(const wxString& html, const wxString& basepath = wxEmptyString, bool isdir = true);
    %wxchkver_3_1_2 void SetHtmlCell(wxHtmlContainerCell& cell);
    void SetSize(int width, int height);
    !%wxchkver_3_1_2 && %wxchkver_2_8 int Render(int x, int y, wxArrayInt& known_pagebreaks, int from = 0, int dont_render = false, int to = INT_MAX);
};

// ---------------------------------------------------------------------------
// wxHtmlEasyPrinting

#include "wx/html/htmprint.h"

class %delete wxHtmlEasyPrinting : public wxObject
{
    wxHtmlEasyPrinting(const wxString& name = "Printing", wxFrame* parent_frame = NULL);

    bool PreviewFile(const wxString& htmlfile);
    bool PreviewText(const wxString& htmltext, const wxString& basepath = "");
    bool PrintFile(const wxString& htmlfile);
    bool PrintText(const wxString& htmltext, const wxString& basepath = "");
    %wxchkver_2_4&!%wxchkver_2_6 void PrinterSetup();
    void PageSetup();
    //void SetFonts(wxString normal_face, wxString fixed_face, const int *sizes = NULL);
    void SetHeader(const wxString& header, int pg = wxPAGE_ALL);
    void SetFooter(const wxString& footer, int pg = wxPAGE_ALL);
    wxPrintData* GetPrintData();
    wxPageSetupDialogData* GetPageSetupData();
};

// ---------------------------------------------------------------------------
// wxHtmlPrintout

#include "wx/html/htmprint.h"

class %delete wxHtmlPrintout : public wxPrintout
{
    wxHtmlPrintout(const wxString& title = "Printout");

    //void SetFonts(wxString normal_face, wxString fixed_face, const int *sizes = NULL);
    void SetFooter(const wxString& footer, int pg = wxPAGE_ALL);
    void SetHeader(const wxString& header, int pg = wxPAGE_ALL);
    void SetHtmlFile(const wxString& htmlfile);
    void SetHtmlText(const wxString& html, const wxString& basepath = "", bool isdir = true);
    void SetMargins(float top = 25.2, float bottom = 25.2, float left = 25.2, float right = 25.2, float spaces = 5);
};

// ---------------------------------------------------------------------------
// wxHtmlHelpData

#if wxLUA_USE_wxHtmlHelpController && wxUSE_WXHTML_HELP

//#if !%wxchkver_2_6|%wxcompat_2_4
//struct wxHtmlContentsItem
//{
//    // needs access functions
//};
//#endif

#include "wx/html/helpdata.h"

//class %delete wxHtmlBookRecord
//{
//    wxHtmlBookRecord(const wxString& bookfile, const wxString& basepath, const wxString& title, const wxString& start);
//
//    wxString GetBookFile() const;
//    wxString GetTitle() const;
//    wxString GetStart() const;
//    wxString GetBasePath() const;
//    void SetContentsRange(int start, int end);
//    int GetContentsStart() const;
//    int GetContentsEnd() const;
//
//    void SetTitle(const wxString& title);
//    void SetBasePath(const wxString& path);
//    void SetStart(const wxString& start);
//    wxString GetFullPath(const wxString &page) const;
//};
//
//class %delete wxHtmlBookRecArray
//{
//    wxHtmlBookRecArray();
//
//    size_t Add(const wxHtmlBookRecord& book, size_t copies = 1);
//    void Clear();
//    int GetCount() const;
//    void Insert(const wxHtmlBookRecord& book, int nIndex, size_t copies = 1);
//    wxHtmlBookRecord Item(size_t nIndex) const;
//    void Remove(const wxString &sz);
//    void RemoveAt(size_t nIndex, size_t count = 1);
//};

class %delete wxHtmlHelpData : public wxObject
{
    wxHtmlHelpData();

    bool AddBook(const wxString& book);
    wxString FindPageById(int id);
    wxString FindPageByName(const wxString& page);
    //wxHtmlBookRecArray GetBookRecArray();
    //wxHtmlHelpDataItems GetContentsArray();
    //wxHtmlHelpDataItems GetIndexArray();
    void SetTempDir(const wxString& path);

    // rem these out to get rid of deprecated warnings
    //!%wxchkver_2_6|%wxcompat_2_4 wxHtmlContentsItem* GetContents();
    //!%wxchkver_2_6|%wxcompat_2_4 int GetContentsCnt();
    //!%wxchkver_2_6|%wxcompat_2_4 wxHtmlContentsItem* GetIndex();
    //!%wxchkver_2_6|%wxcompat_2_4 int GetIndexCnt();
};

// ---------------------------------------------------------------------------
// wxHtmlHelpController

#include "wx/html/helpctrl.h"

#define wxHF_TOOLBAR
#define wxHF_FLAT_TOOLBAR
#define wxHF_CONTENTS
#define wxHF_INDEX
#define wxHF_SEARCH
#define wxHF_BOOKMARKS
#define wxHF_OPEN_FILES
#define wxHF_PRINT
#define wxHF_MERGE_BOOKS
#define wxHF_ICONS_BOOK
#define wxHF_ICONS_FOLDER
#define wxHF_ICONS_BOOK_CHAPTER
#define wxHF_DEFAULT_STYLE

class %delete wxHtmlHelpController : public wxHelpControllerBase
{
    wxHtmlHelpController(int style = wxHF_DEFAULT_STYLE);

    bool AddBook(const wxString& book, bool show_wait_msg);
    bool AddBook(const wxFileName& book_file, bool show_wait_msg);
    //virtual wxHtmlHelpFrame* CreateHelpFrame(wxHtmlHelpData * data);
    void Display(const wxString& x);
    void Display(const int id);
    //void DisplayContents() - see wxHelpControllerBase
    void DisplayIndex();
    // bool KeywordSearch(const wxString& keyword, wxHelpSearchMode mode = wxHELP_SEARCH_ALL); // see base
    void ReadCustomization(wxConfigBase* cfg, wxString path = "");
    void SetTempDir(const wxString& path);
    void SetTitleFormat(const wxString& format);
    void UseConfig(wxConfigBase* config, const wxString& rootpath = "");
    void WriteCustomization(wxConfigBase* cfg, wxString path = "");
};

#endif //wxLUA_USE_wxHtmlHelpController && wxUSE_WXHTML_HELP

#endif //wxLUA_USE_wxHTML && wxUSE_HTML
