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

#include "wx/richtext/richtextprint.h"

#define wxRICHTEXT_PRINT_MAX_PAGES 99999

// Header/footer page identifiers
enum wxRichTextOddEvenPage {
    wxRICHTEXT_PAGE_ODD,
    wxRICHTEXT_PAGE_EVEN,
    wxRICHTEXT_PAGE_ALL
};

// Header/footer text locations
enum wxRichTextPageLocation {
    wxRICHTEXT_PAGE_LEFT,
    wxRICHTEXT_PAGE_CENTRE,
    wxRICHTEXT_PAGE_RIGHT
};

/*!
 * Header/footer data
 */

class %delete wxRichTextHeaderFooterData: public wxObject
{
public:
    wxRichTextHeaderFooterData();
    wxRichTextHeaderFooterData(const wxRichTextHeaderFooterData& data);

    /// Initialise
    void Init();

    /// Copy
    void Copy(const wxRichTextHeaderFooterData& data);

    /// Assignment
    void operator= (const wxRichTextHeaderFooterData& data);

    /// Set/get header text, e.g. wxRICHTEXT_PAGE_ODD, wxRICHTEXT_PAGE_LEFT
    void SetHeaderText(const wxString& text, wxRichTextOddEvenPage page = wxRICHTEXT_PAGE_ALL, wxRichTextPageLocation location = wxRICHTEXT_PAGE_CENTRE);
    wxString GetHeaderText(wxRichTextOddEvenPage page = wxRICHTEXT_PAGE_EVEN, wxRichTextPageLocation location = wxRICHTEXT_PAGE_CENTRE) const;

    /// Set/get footer text, e.g. wxRICHTEXT_PAGE_ODD, wxRICHTEXT_PAGE_LEFT
    void SetFooterText(const wxString& text, wxRichTextOddEvenPage page = wxRICHTEXT_PAGE_ALL, wxRichTextPageLocation location = wxRICHTEXT_PAGE_CENTRE);
    wxString GetFooterText(wxRichTextOddEvenPage page = wxRICHTEXT_PAGE_EVEN, wxRichTextPageLocation location = wxRICHTEXT_PAGE_CENTRE) const;

    /// Set/get text
    void SetText(const wxString& text, int headerFooter, wxRichTextOddEvenPage page, wxRichTextPageLocation location);
    wxString GetText(int headerFooter, wxRichTextOddEvenPage page, wxRichTextPageLocation location) const;

    /// Set/get margins between text and header or footer, in tenths of a millimeter
    void SetMargins(int headerMargin, int footerMargin);
    int GetHeaderMargin() const;
    int GetFooterMargin() const;

    /// Set/get whether to show header or footer on first page
    void SetShowOnFirstPage(bool showOnFirstPage);
    bool GetShowOnFirstPage() const;

    /// Clear all text
    void Clear();

    /// Set/get font
    void SetFont(const wxFont& font);
    const wxFont& GetFont() const;

    /// Set/get colour
    void SetTextColour(const wxColour& col);
    const wxColour& GetTextColour() const;

    //DECLARE_CLASS(wxRichTextHeaderFooterData)

private:

    // Strings for left, centre, right, top, bottom, odd, even
    wxString    m_text[12];
    wxFont      m_font;
    wxColour    m_colour;
    int         m_headerMargin;
    int         m_footerMargin;
    bool        m_showOnFirstPage;
};

/*!
 * wxRichTextPrintout
 */

class %delete wxRichTextPrintout : public wxPrintout
{
public:
    wxRichTextPrintout(const wxString& title);
    //virtual ~wxRichTextPrintout();

    /// The buffer to print
    void SetRichTextBuffer(wxRichTextBuffer* buffer);
    wxRichTextBuffer* GetRichTextBuffer() const;

    /// Set/get header/footer data
    void SetHeaderFooterData(const wxRichTextHeaderFooterData& data);
    const wxRichTextHeaderFooterData& GetHeaderFooterData() const;

    /// Sets margins in 10ths of millimetre. Defaults to 1 inch for margins.
    void SetMargins(int top = 254, int bottom = 254, int left = 254, int right = 254);

    /// Calculate scaling and rectangles, setting the device context scaling
    void CalculateScaling(wxDC* dc, wxRect& textRect, wxRect& headerRect, wxRect& footerRect);

    // wxPrintout virtual functions
    virtual bool OnPrintPage(int page);
    virtual bool HasPage(int page);
    virtual void GetPageInfo(int *minPage, int *maxPage, int *selPageFrom, int *selPageTo);
    virtual bool OnBeginDocument(int startPage, int endPage);
    virtual void OnPreparePrinting();

private:

    /// Renders one page into dc
    void RenderPage(wxDC *dc, int page);

    /// Substitute keywords
    static bool SubstituteKeywords(wxString& str, const wxString& title, int pageNum, int pageCount);

private:

    wxRichTextBuffer*           m_richTextBuffer;
    int                         m_numPages;
    wxArrayInt                  m_pageBreaksStart;
    wxArrayInt                  m_pageBreaksEnd;
    wxArrayInt                  m_pageYOffsets;
    int                         m_marginLeft, m_marginTop, m_marginRight, m_marginBottom;

    wxRichTextHeaderFooterData  m_headerFooterData;

    //wxDECLARE_NO_COPY_CLASS(wxRichTextPrintout);
};

/*
 *! wxRichTextPrinting
 * A simple interface to perform wxRichTextBuffer printing.
 */

class %delete wxRichTextPrinting : public wxObject
{
public:
    wxRichTextPrinting(const wxString& name, wxWindow *parentWindow = NULL);
    //virtual ~wxRichTextPrinting();

    /// Preview the file or buffer
#if wxUSE_FFILE && wxUSE_STREAMS
    bool PreviewFile(const wxString& richTextFile);
#endif
    bool PreviewBuffer(const wxRichTextBuffer& buffer);

    /// Print the file or buffer
#if wxUSE_FFILE && wxUSE_STREAMS
    bool PrintFile(const wxString& richTextFile, bool showPrintDialog = true);
#endif
    bool PrintBuffer(const wxRichTextBuffer& buffer, bool showPrintDialog = true);

    /// Shows page setup dialog
    void PageSetup();

    /// Set/get header/footer data
    void SetHeaderFooterData(const wxRichTextHeaderFooterData& data);
    const wxRichTextHeaderFooterData& GetHeaderFooterData() const;

    /// Set/get header text, e.g. wxRICHTEXT_PAGE_ODD, wxRICHTEXT_PAGE_LEFT
    void SetHeaderText(const wxString& text, wxRichTextOddEvenPage page = wxRICHTEXT_PAGE_ALL, wxRichTextPageLocation location = wxRICHTEXT_PAGE_CENTRE);
    wxString GetHeaderText(wxRichTextOddEvenPage page = wxRICHTEXT_PAGE_EVEN, wxRichTextPageLocation location = wxRICHTEXT_PAGE_CENTRE) const;

    /// Set/get footer text, e.g. wxRICHTEXT_PAGE_ODD, wxRICHTEXT_PAGE_LEFT
    void SetFooterText(const wxString& text, wxRichTextOddEvenPage page = wxRICHTEXT_PAGE_ALL, wxRichTextPageLocation location = wxRICHTEXT_PAGE_CENTRE);
    wxString GetFooterText(wxRichTextOddEvenPage page = wxRICHTEXT_PAGE_EVEN, wxRichTextPageLocation location = wxRICHTEXT_PAGE_CENTRE) const;

    /// Show header/footer on first page, or not
    void SetShowOnFirstPage(bool show);

    /// Set the font
    void SetHeaderFooterFont(const wxFont& font);

    /// Set the colour
    void SetHeaderFooterTextColour(const wxColour& font);

    /// Get print and page setup data
    wxPrintData *GetPrintData();
    wxPageSetupDialogData *GetPageSetupData();

    /// Set print and page setup data
    void SetPrintData(const wxPrintData& printData);
    void SetPageSetupData(const wxPageSetupDialogData& pageSetupData);

    /// Set the rich text buffer pointer, deleting the existing object if present
    void SetRichTextBufferPreview(wxRichTextBuffer* buf);
    wxRichTextBuffer* GetRichTextBufferPreview() const;

    void SetRichTextBufferPrinting(wxRichTextBuffer* buf);
    wxRichTextBuffer* GetRichTextBufferPrinting() const;

    /// Set/get the parent window
    void SetParentWindow(wxWindow* parent);
    wxWindow* GetParentWindow() const;

    /// Set/get the title
    void SetTitle(const wxString& title);
    const wxString& GetTitle() const;

    /// Set/get the preview rect
    void SetPreviewRect(const wxRect& rect);
    const wxRect& GetPreviewRect() const ;

protected:
    virtual wxRichTextPrintout *CreatePrintout();
    virtual bool DoPreview(wxRichTextPrintout *printout1, wxRichTextPrintout *printout2);
    virtual bool DoPrint(wxRichTextPrintout *printout, bool showPrintDialog);

private:
    wxPrintData*                m_printData;
    wxPageSetupDialogData*      m_pageSetupData;

    wxRichTextHeaderFooterData  m_headerFooterData;
    wxString                    m_title;
    wxWindow*                   m_parentWindow;
    wxRichTextBuffer*           m_richTextBufferPreview;
    wxRichTextBuffer*           m_richTextBufferPrinting;
    wxRect                      m_previewRect;

    //wxDECLARE_NO_COPY_CLASS(wxRichTextPrinting);
};

//  End richtextprint.h
#endif // wxLUA_USE_wxRichText && %wxchkver_3_0 && wxUSE_RICHTEXT
