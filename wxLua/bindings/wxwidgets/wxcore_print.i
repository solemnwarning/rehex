// ===========================================================================
// Purpose:     printing related classes
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

#if wxLUA_USE_wxPrint && wxUSE_PRINTING_ARCHITECTURE

typedef wxScrolledWindow wxPreviewWindow

#include "wx/print.h"

// ---------------------------------------------------------------------------
// wxPrintout

class wxPrintout : public wxObject
{
    // virtual class, use wxLuaPrintout

    wxDC * GetDC();

    // %override [int minPage, int maxPage, int pageFrom, int pageTo] wxPrintout::GetPageInfo();
    // C++ Func: void GetPageInfo(int *minPage, int *maxPage, int *pageFrom, int *pageTo);
    void GetPageInfo();

    // %override [int w, int h] wxPrintout::GetPageSizeMM();
    // C++ Func: void GetPageSizeMM(int *w, int *h);
    void GetPageSizeMM();

    // %override [int w, int h] wxPrintout::GetPageSizePixels();
    // C++ Func: void GetPageSizePixels(int *w, int *h);
    void GetPageSizePixels();

    // %override [int w, int h] wxPrintout::GetPPIPrinter();
    // C++ Func: void GetPPIPrinter(int *w, int *h);
    void GetPPIPrinter();

    // %override [int w, int h] wxPrintout::GetPPIScreen();
    // C++ Func: void GetPPIScreen(int *w, int *h);
    void GetPPIScreen();

    wxString  GetTitle();
    bool HasPage(int pageNum);
    bool IsPreview();
    bool OnBeginDocument(int startPage, int endPage);
    void OnEndDocument();
    void OnBeginPrinting();
    void OnEndPrinting();
    void OnPreparePrinting();
    bool OnPrintPage(int pageNum);
};

// ---------------------------------------------------------------------------
// wxLuaPrintout

#if wxLUA_USE_wxLuaPrintout

#include "wxlua/wxlua_bind.h" // for wxLuaObject tag
#include "wxbind/include/wxcore_wxlcore.h"

class %delete wxLuaPrintout : public wxPrintout
{
    // %override - the C++ function takes the wxLuaState as the first param
    wxLuaPrintout(const wxString& title = "Printout", wxLuaObject *pObject = NULL);

    wxLuaObject *GetID();

    // This is an added function to wxPrintout so you don't have to override GetPageInfo
    void SetPageInfo(int minPage, int maxPage, int pageFrom = 0, int pageTo = 0);

    // The functions below are all virtual functions that you can override in Lua.
    // See the printing sample and wxPrintout for proper parameters and usage.
    //void GetPageInfo(int *minPage, int *maxPage, int *pageFrom, int *pageTo);
    //bool HasPage(int pageNum);
    //bool OnBeginDocument(int startPage, int endPage);
    //void OnEndDocument();
    //void OnBeginPrinting();
    //void OnEndPrinting();
    //void OnPreparePrinting();
    //bool OnPrintPage(int pageNum);

    // Dummy test function to directly verify that the binding virtual functions really work.
    // This base class function appends "-Base" to the val string and returns it.
    virtual wxString TestVirtualFunctionBinding(const wxString& val); // { return val + wxT("-Base"); }

    static int ms_test_int;
};


// ---------------------------------------------------------------------------
// wxPrinter

enum wxPrinterError
{
    wxPRINTER_NO_ERROR,
    wxPRINTER_CANCELLED,
    wxPRINTER_ERROR
};

class %delete wxPrinter : public wxObject
{
    wxPrinter(wxPrintDialogData* data = NULL);

    //bool Abort();
    virtual void CreateAbortWindow(wxWindow* parent, wxPrintout* printout);
    bool GetAbort() const;
    static wxPrinterError GetLastError();
    wxPrintDialogData& GetPrintDialogData();
    bool Print(wxWindow *parent, wxPrintout *printout, bool prompt=true);
    wxDC* PrintDialog(wxWindow *parent);
    void ReportError(wxWindow *parent, wxPrintout *printout, const wxString& message);
    bool Setup(wxWindow *parent);
};

#endif //wxLUA_USE_wxLuaPrintout

// ---------------------------------------------------------------------------
// wxPrintData

#define wxPORTRAIT
#define wxLANDSCAPE

enum wxDuplexMode
{
    wxDUPLEX_HORIZONTAL,
    wxDUPLEX_SIMPLEX,
    wxDUPLEX_VERTICAL
};

enum wxPaperSize
{
    wxPAPER_NONE,
    wxPAPER_LETTER,
    wxPAPER_LEGAL,
    wxPAPER_A4,
    wxPAPER_CSHEET,
    wxPAPER_DSHEET,
    wxPAPER_ESHEET,
    wxPAPER_LETTERSMALL,
    wxPAPER_TABLOID,
    wxPAPER_LEDGER,
    wxPAPER_STATEMENT,
    wxPAPER_EXECUTIVE,
    wxPAPER_A3,
    wxPAPER_A4SMALL,
    wxPAPER_A5,
    wxPAPER_B4,
    wxPAPER_B5,
    wxPAPER_FOLIO,
    wxPAPER_QUARTO,
    wxPAPER_10X14,
    wxPAPER_11X17,
    wxPAPER_NOTE,
    wxPAPER_ENV_9,
    wxPAPER_ENV_10,
    wxPAPER_ENV_11,
    wxPAPER_ENV_12,
    wxPAPER_ENV_14,
    wxPAPER_ENV_DL,
    wxPAPER_ENV_C5,
    wxPAPER_ENV_C3,
    wxPAPER_ENV_C4,
    wxPAPER_ENV_C6,
    wxPAPER_ENV_C65,
    wxPAPER_ENV_B4,
    wxPAPER_ENV_B5,
    wxPAPER_ENV_B6,
    wxPAPER_ENV_ITALY,
    wxPAPER_ENV_MONARCH,
    wxPAPER_ENV_PERSONAL,
    wxPAPER_FANFOLD_US,
    wxPAPER_FANFOLD_STD_GERMAN,
    wxPAPER_FANFOLD_LGL_GERMAN,

    wxPAPER_ISO_B4,
    wxPAPER_JAPANESE_POSTCARD,
    wxPAPER_9X11,
    wxPAPER_10X11,
    wxPAPER_15X11,
    wxPAPER_ENV_INVITE,
    wxPAPER_LETTER_EXTRA,
    wxPAPER_LEGAL_EXTRA,
    wxPAPER_TABLOID_EXTRA,
    wxPAPER_A4_EXTRA,
    wxPAPER_LETTER_TRANSVERSE,
    wxPAPER_A4_TRANSVERSE,
    wxPAPER_LETTER_EXTRA_TRANSVERSE,
    wxPAPER_A_PLUS,
    wxPAPER_B_PLUS,
    wxPAPER_LETTER_PLUS,
    wxPAPER_A4_PLUS,
    wxPAPER_A5_TRANSVERSE,
    wxPAPER_B5_TRANSVERSE,
    wxPAPER_A3_EXTRA,
    wxPAPER_A5_EXTRA,
    wxPAPER_B5_EXTRA,
    wxPAPER_A2,
    wxPAPER_A3_TRANSVERSE,
    wxPAPER_A3_EXTRA_TRANSVERSE,

    wxPAPER_DBL_JAPANESE_POSTCARD,
    wxPAPER_A6,
    wxPAPER_JENV_KAKU2,
    wxPAPER_JENV_KAKU3,
    wxPAPER_JENV_CHOU3,
    wxPAPER_JENV_CHOU4,
    wxPAPER_LETTER_ROTATED,
    wxPAPER_A3_ROTATED,
    wxPAPER_A4_ROTATED,
    wxPAPER_A5_ROTATED,
    wxPAPER_B4_JIS_ROTATED,
    wxPAPER_B5_JIS_ROTATED,
    wxPAPER_JAPANESE_POSTCARD_ROTATED,
    wxPAPER_DBL_JAPANESE_POSTCARD_ROTATED,
    wxPAPER_A6_ROTATED,
    wxPAPER_JENV_KAKU2_ROTATED,
    wxPAPER_JENV_KAKU3_ROTATED,
    wxPAPER_JENV_CHOU3_ROTATED,
    wxPAPER_JENV_CHOU4_ROTATED,
    wxPAPER_B6_JIS,
    wxPAPER_B6_JIS_ROTATED,
    wxPAPER_12X11,
    wxPAPER_JENV_YOU4,
    wxPAPER_JENV_YOU4_ROTATED,
    wxPAPER_P16K,
    wxPAPER_P32K,
    wxPAPER_P32KBIG,
    wxPAPER_PENV_1,
    wxPAPER_PENV_2,
    wxPAPER_PENV_3,
    wxPAPER_PENV_4,
    wxPAPER_PENV_5,
    wxPAPER_PENV_6,
    wxPAPER_PENV_7,
    wxPAPER_PENV_8,
    wxPAPER_PENV_9,
    wxPAPER_PENV_10,
    wxPAPER_P16K_ROTATED,
    wxPAPER_P32K_ROTATED,
    wxPAPER_P32KBIG_ROTATED,
    wxPAPER_PENV_1_ROTATED,
    wxPAPER_PENV_2_ROTATED,
    wxPAPER_PENV_3_ROTATED,
    wxPAPER_PENV_4_ROTATED,
    wxPAPER_PENV_5_ROTATED,
    wxPAPER_PENV_6_ROTATED,
    wxPAPER_PENV_7_ROTATED,
    wxPAPER_PENV_8_ROTATED,
    wxPAPER_PENV_9_ROTATED,
    wxPAPER_PENV_10_ROTATED
};

enum wxPrintQuality // actually not an enum, but a typedef int
{
    wxPRINT_QUALITY_DRAFT,
    wxPRINT_QUALITY_HIGH,
    wxPRINT_QUALITY_LOW,
    wxPRINT_QUALITY_MEDIUM
};

enum wxPrintMode
{
    wxPRINT_MODE_FILE,
    wxPRINT_MODE_NONE,
    wxPRINT_MODE_PREVIEW,
    wxPRINT_MODE_PRINTER
};

#if %wxchkver_2_6
enum wxPrintBin
{
    wxPRINTBIN_DEFAULT,

    wxPRINTBIN_ONLYONE,
    wxPRINTBIN_LOWER,
    wxPRINTBIN_MIDDLE,
    wxPRINTBIN_MANUAL,
    wxPRINTBIN_ENVELOPE,
    wxPRINTBIN_ENVMANUAL,
    wxPRINTBIN_AUTO,
    wxPRINTBIN_TRACTOR,
    wxPRINTBIN_SMALLFMT,
    wxPRINTBIN_LARGEFMT,
    wxPRINTBIN_LARGECAPACITY,
    wxPRINTBIN_CASSETTE,
    wxPRINTBIN_FORMSOURCE,

    wxPRINTBIN_USER
};
#endif

#if %wxchkver_3_0
enum wxPrintOrientation
{
   wxPORTRAIT = 1,
   wxLANDSCAPE
};
#endif

class %delete wxPrintData : public wxObject
{
    wxPrintData();
    wxPrintData(const wxPrintData& data);

    wxPrintData *Copy();

    // copied straight from cmndata.h not docs
    int  GetNoCopies() const;
    bool GetCollate() const;
    int  GetOrientation() const;
    bool Ok() const;
    wxString GetPrinterName() const;
    bool GetColour() const;
    wxDuplexMode GetDuplex() const;
    %wxchkver_2_8 int GetMedia() const;
    wxPaperSize GetPaperId() const;
    wxSize GetPaperSize() const;
    wxPrintQuality GetQuality() const;
    wxPrintBin GetBin() const;
    wxPrintMode GetPrintMode() const;
    %wxchkver_2_8 bool IsOrientationReversed() const;
    void SetNoCopies(int v);
    void SetCollate(bool flag);
    !%wxchkver_3_0 void SetOrientation(int orient);
    %wxchkver_3_0 void SetOrientation(wxPrintOrientation orient);
    void SetPrinterName(const wxString& name);
    void SetColour(bool colour);
    void SetDuplex(wxDuplexMode duplex);
    %wxchkver_2_8 void SetOrientationReversed(bool reversed);
    %wxchkver_2_8 void SetMedia(int media);
    void SetPaperId(wxPaperSize sizeId);
    void SetPaperSize(const wxSize& sz);
    void SetQuality(wxPrintQuality quality);
    void SetBin(wxPrintBin bin);
    void SetPrintMode(wxPrintMode printMode);
    wxString GetFilename() const;
    void SetFilename(const wxString &filename);

    void operator=(const wxPrintData& data);
};

// ---------------------------------------------------------------------------
// wxPageSetupDialogData

class %delete wxPageSetupDialogData : public wxObject
{
    wxPageSetupDialogData();
    wxPageSetupDialogData(const wxPageSetupDialogData& data);

    wxPageSetupDialogData *Copy();

    // copied straight from cmndata.h not docs
    wxSize GetPaperSize() const;
    wxPaperSize GetPaperId() const;
    wxPoint GetMinMarginTopLeft() const;
    wxPoint GetMinMarginBottomRight() const;
    wxPoint GetMarginTopLeft() const;
    wxPoint GetMarginBottomRight() const;
    bool GetDefaultMinMargins() const;
    bool GetEnableMargins() const;
    bool GetEnableOrientation() const;
    bool GetEnablePaper() const;
    bool GetEnablePrinter() const;
    bool GetDefaultInfo() const;
    bool GetEnableHelp() const;
    bool Ok() const;
    void SetPaperSize(const wxSize& sz);
    void SetPaperSize(wxPaperSize id);
    void SetPaperId(wxPaperSize id);
    void SetMinMarginTopLeft(const wxPoint& pt);
    void SetMinMarginBottomRight(const wxPoint& pt);
    void SetMarginTopLeft(const wxPoint& pt);
    void SetMarginBottomRight(const wxPoint& pt);
    void SetDefaultMinMargins(bool flag);
    void SetDefaultInfo(bool flag);
    void EnableMargins(bool flag);
    void EnableOrientation(bool flag);
    void EnablePaper(bool flag);
    void EnablePrinter(bool flag);
    void EnableHelp(bool flag);
    void CalculateIdFromPaperSize();
    void CalculatePaperSizeFromId();
    wxPrintData& GetPrintData();
    void SetPrintData(const wxPrintData& printData);

    //wxPageSetupDialogData& operator=(const wxPageSetupData& data);
    //wxPageSetupDialogData& operator=(const wxPrintData& data);
};

// ---------------------------------------------------------------------------
// wxPageSetupDialog

#include "wx/printdlg.h"

//typedef wxPageSetupDialogBase wxPageSetupDialog

class %delete wxPageSetupDialog : public wxObject // NOT a wxDialog in 2.8
{
    wxPageSetupDialog(wxWindow* parent, wxPageSetupDialogData* data = NULL);

    wxPageSetupDialogData& GetPageSetupDialogData();
    int ShowModal();
};

// ---------------------------------------------------------------------------
// wxPrintDialog

class %delete wxPrintDialog : public wxObject // NOT a wxDialog in 2.8
{
    wxPrintDialog(wxWindow* parent, wxPrintDialogData* data = NULL);

    wxPrintDialogData& GetPrintDialogData();
    wxPrintData& GetPrintData();
    wxDC* GetPrintDC();
    int ShowModal();
};

// ---------------------------------------------------------------------------
// wxPrintDialogData

class %delete wxPrintDialogData : public wxObject
{
    wxPrintDialogData();
    wxPrintDialogData(const wxPrintDialogData& dialogData);
    wxPrintDialogData(const wxPrintData& data);

    // copied straight from cmndata.h not docs
    int GetFromPage() const;
    int GetToPage() const;
    int GetMinPage() const;
    int GetMaxPage() const;
    int GetNoCopies() const;
    bool GetAllPages() const;
    bool GetSelection() const;
    bool GetCollate() const;
    bool GetPrintToFile() const;
    // WXWIN_COMPATIBILITY_2_4 //bool GetSetupDialog() const;
    void SetFromPage(int v);
    void SetToPage(int v);
    void SetMinPage(int v);
    void SetMaxPage(int v);
    void SetNoCopies(int v);
    void SetAllPages(bool flag);
    void SetSelection(bool flag);
    void SetCollate(bool flag);
    void SetPrintToFile(bool flag);
    // WXWIN_COMPATIBILITY_2_4 //void SetSetupDialog(bool flag) { m_printSetupDialog = flag; };
    void EnablePrintToFile(bool flag);
    void EnableSelection(bool flag);
    void EnablePageNumbers(bool flag);
    void EnableHelp(bool flag);
    bool GetEnablePrintToFile() const;
    bool GetEnableSelection() const;
    bool GetEnablePageNumbers() const;
    bool GetEnableHelp() const;
    bool Ok() const;
    wxPrintData& GetPrintData();
    void SetPrintData(const wxPrintData& printData);

    void operator=(const wxPrintDialogData& data);
};

// ---------------------------------------------------------------------------
// wxPreviewCanvas

class wxPreviewCanvas : public wxWindow
{
    wxPreviewCanvas(wxPrintPreview *preview, wxWindow *parent, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = 0, const wxString& name = "wxPreviewCanvas");
};

// ---------------------------------------------------------------------------
// wxPreviewControlBar

#define wxPREVIEW_PRINT
#define wxPREVIEW_PREVIOUS
#define wxPREVIEW_NEXT
#define wxPREVIEW_ZOOM
#define wxPREVIEW_FIRST
#define wxPREVIEW_LAST
#define wxPREVIEW_GOTO

#define wxID_PREVIEW_CLOSE
#define wxID_PREVIEW_NEXT
#define wxID_PREVIEW_PREVIOUS
#define wxID_PREVIEW_PRINT
#define wxID_PREVIEW_ZOOM
#define wxID_PREVIEW_FIRST
#define wxID_PREVIEW_LAST
#define wxID_PREVIEW_GOTO

class wxPreviewControlBar : public wxWindow
{
    wxPreviewControlBar(wxPrintPreview* preview, long buttons, wxWindow* parent, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = 0, const wxString& name = "wxPreviewControlBar");

    //void CreateButtons();
    virtual void SetZoomControl(int zoom);
    virtual int GetZoomControl();
    //virtual wxPrintPreviewBase *GetPrintPreview() const;
};

// ---------------------------------------------------------------------------
// wxPrintPreview
#if wxLUA_USE_wxLuaPrintout

class wxPrintPreview : public wxObject
{
    wxPrintPreview(wxPrintout* printout, wxPrintout* printoutForPrinting, wxPrintData* data=NULL);

    bool DrawBlankPage(wxPreviewCanvas* window, wxDC& dc);
    wxPreviewCanvas* GetCanvas();
    int GetCurrentPage();
    wxFrame * GetFrame();
    int GetMaxPage();
    int GetMinPage();
    wxPrintout* GetPrintout();
    wxPrintout* GetPrintoutForPrinting();
    bool Ok();
    bool PaintPage(wxPreviewCanvas* window, wxDC &dc);
    bool Print(bool prompt);
    bool RenderPage(int pageNum);
    void SetCanvas(wxPreviewCanvas* window);
    void SetCurrentPage(int pageNum);
    void SetFrame(wxFrame *frame);
    void SetPrintout(wxPrintout *printout);
    void SetZoom(int percent);
};

// ---------------------------------------------------------------------------
// wxPreviewFrame

class wxPreviewFrame : public wxFrame
{
    wxPreviewFrame(wxPrintPreview *preview, wxFrame *parent, const wxString &title, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_FRAME_STYLE, const wxString &name = "wxPreviewFrame");

    void CreateControlBar();
    void CreateCanvas();
    void Initialize();
    wxPreviewControlBar* GetControlBar() const;
};

#endif //wxLUA_USE_wxLuaPrintout

// ---------------------------------------------------------------------------
// wxPostScriptDC

#if wxUSE_POSTSCRIPT

#include "wx/dcps.h"

class %delete wxPostScriptDC : public wxDC
{
    wxPostScriptDC(const wxPrintData& printData);

    !%wxchkver_2_9_2 static void SetResolution(int ppi);
    !%wxchkver_2_9_2 static int GetResolution();
    %wxchkver_2_9_2 int GetResolution();
};

#endif //wxUSE_POSTSCRIPT

// ---------------------------------------------------------------------------
// wxPrinterDC

#if %msw|%mac
#include "wx/dcprint.h"

class %delete wxPrinterDC : public wxDC
{
    wxPrinterDC(const wxPrintData& printData);
};
#endif // %msw|%mac

#endif //wxLUA_USE_wxPrint && wxUSE_PRINTING_ARCHITECTURE

