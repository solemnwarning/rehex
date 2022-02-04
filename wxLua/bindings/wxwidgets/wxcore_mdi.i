// ===========================================================================
// Purpose:     wxMDI classes
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

#if wxLUA_USE_MDI && wxUSE_MDI && wxUSE_DOC_VIEW_ARCHITECTURE

#include "wx/cmdproc.h"

// ---------------------------------------------------------------------------
// wxMDIClientWindow

class wxMDIClientWindow : public wxWindow
{
};

// ---------------------------------------------------------------------------
// wxMDIParentFrame

class wxMDIParentFrame : public wxFrame
{
    wxMDIParentFrame();
    wxMDIParentFrame(wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_FRAME_STYLE | wxVSCROLL | wxHSCROLL, const wxString& name = "wxMDIParentFrame");
    bool Create(wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_FRAME_STYLE | wxVSCROLL | wxHSCROLL, const wxString& name = "wxMDIParentFrame");

    void ActivateNext();
    void ActivatePrevious();
    void ArrangeIcons();
    void Cascade();
    wxMDIChildFrame* GetActiveChild() const;
    wxMDIClientWindow* GetClientWindow() const;
    // virtual wxToolBar* GetToolBar() const; - see wxFrame
    %win wxMenu* GetWindowMenu() const;
    // virtual void SetToolBar(wxToolBar* toolbar) - see wxFrame
    %win void SetWindowMenu(%ungc wxMenu* menu);
    void Tile(wxOrientation orient = wxHORIZONTAL);
};

// ---------------------------------------------------------------------------
// wxMDIChildFrame

class wxMDIChildFrame : public wxFrame
{
    wxMDIChildFrame();
    wxMDIChildFrame(wxMDIParentFrame* parent, wxWindowID id, const wxString& title, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_FRAME_STYLE, const wxString& name = "wxMDIChildFrame");
    bool Create(wxMDIParentFrame* parent, wxWindowID id, const wxString& title, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_FRAME_STYLE, const wxString& name = "wxMDIChildFrame");

    void Activate();
    %win void Maximize();
    void Restore();
};

// ---------------------------------------------------------------------------
// wxDocMDIParentFrame

#include "wx/docmdi.h"

class wxDocMDIParentFrame : public wxMDIParentFrame
{
    wxDocMDIParentFrame();
    wxDocMDIParentFrame(wxDocManager *manager, wxFrame *parent, wxWindowID id, const wxString& title, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_FRAME_STYLE, const wxString& name = "wxDocMDIParentFrame");
    bool Create(wxDocManager *manager, wxFrame *parent, wxWindowID id, const wxString& title, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_FRAME_STYLE, const wxString& name = "wxDocMDIParentFrame");

    wxDocManager *GetDocumentManager() const;
};

// ---------------------------------------------------------------------------
// wxDocMDIChildFrame

class wxDocMDIChildFrame : public wxMDIChildFrame
{
    wxDocMDIChildFrame();
    wxDocMDIChildFrame(wxDocument *doc, wxView *view, wxMDIParentFrame *frame, wxWindowID id, const wxString& title, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize,long type = wxDEFAULT_FRAME_STYLE, const wxString& name = "wxDocMDIChildFrame");
    bool Create(wxDocument *doc, wxView *view, wxMDIParentFrame *frame, wxWindowID id, const wxString& title, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long type = wxDEFAULT_FRAME_STYLE, const wxString& name = "wxDocMDIChildFrame");

    wxDocument *GetDocument() const;
    wxView *GetView() const;
    void SetDocument(wxDocument *doc);
    void SetView(wxView *view);
};

// ---------------------------------------------------------------------------
// wxDocChildFrame

#include "wx/docview.h"

class wxDocChildFrame : public wxFrame
{
    wxDocChildFrame(wxDocument* doc, wxView* view, wxFrame* parent, wxWindowID id, const wxString& title, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_FRAME_STYLE, const wxString& name = "wxDocChildFrame");

    wxDocument* GetDocument() const;
    wxView* GetView() const;
    void SetDocument(wxDocument *doc);
    void SetView(wxView *view);
};

// ---------------------------------------------------------------------------
// wxDocManager

#if !%wxchkver_2_9 || %wxcompat_2_8
#define wxDEFAULT_DOCMAN_FLAGS
#endif //!%wxchkver_2_9 || %wxcompat_2_8
#define wxDOC_NEW
#define wxDOC_SILENT

class wxDocManager : public wxEvtHandler
{
    wxDocManager(long flags = 0, bool initialize = true);

    %wxchkver_2_6 void ActivateView(wxView* view, bool activate);
    !%wxchkver_2_6 void ActivateView(wxView* view, bool activate, bool deleting);
    void AddDocument(wxDocument *doc);
    void AddFileToHistory(const wxString& filename);
    void AssociateTemplate(wxDocTemplate *temp);
    bool CloseDocuments(bool force = true);
    wxDocument* CreateDocument(const wxString& path, long flags);
    wxView* CreateView(wxDocument*doc, long flags);
    void DisassociateTemplate(wxDocTemplate *temp);
    void FileHistoryAddFilesToMenu();
    void FileHistoryAddFilesToMenu(wxMenu* menu);
    void FileHistoryLoad(wxConfigBase& config);
    void FileHistoryRemoveMenu(wxMenu* menu);
    void FileHistorySave(wxConfigBase& resourceFile);
    void FileHistoryUseMenu(wxMenu* menu);
    wxDocTemplate * FindTemplateForPath(const wxString& path);
    wxDocument * GetCurrentDocument();
    wxView * GetCurrentView();
    // %overide wxList& wxDocManager::GetDocuments() - returns a copied list
    wxList& GetDocuments();
    wxFileHistory * GetFileHistory();
    wxString GetLastDirectory() const;
    int GetMaxDocsOpen();
    !%wxchkver_2_6 int GetNoHistoryFiles();
    %wxchkver_2_6 size_t GetHistoryFilesCount() const;
    // %overide wxList& wxDocManager::GetTemplates() - returns a copied list
    wxList& GetTemplates();
    bool Initialize();

    // %override [bool, string buf] wxDocManager::MakeDefaultName(wxString& buf);
    // C++ Func: bool MakeDefaultName(wxString& buf);
    !%wxchkver_2_9 || %wxcompat_2_8 bool MakeDefaultName(wxString& buf);

    wxFileHistory* OnCreateFileHistory();
    void OnFileClose(wxCommandEvent &event);
    void OnFileCloseAll(wxCommandEvent& event);
    void OnFileNew(wxCommandEvent &event);
    void OnFileOpen(wxCommandEvent &event);
    void OnFileRevert(wxCommandEvent& event);
    void OnFileSave(wxCommandEvent &event);
    void OnFileSaveAs(wxCommandEvent &event);
    //void OnMenuCommand(int cmd);
    void RemoveDocument(wxDocument *doc);
    //wxDocTemplate * SelectDocumentPath(wxDocTemplate **templates, int noTemplates, const wxString& path, const wxString& bufSize, long flags, bool save);
    //wxDocTemplate * SelectDocumentType(wxDocTemplate **templates, int noTemplates, bool sort = false);
    //wxDocTemplate * SelectViewType(wxDocTemplate **templates, int noTemplates, bool sort = false);
    void SetLastDirectory(const wxString& dir);
    void SetMaxDocsOpen(int n);
};

// ---------------------------------------------------------------------------
// wxDocMDIChildFrame

//%include "wx/docmdi.h"

//class wxDocMDIChildFrame : public wxMDIChildFrame FIXME
//{
//  wxDocMDIChildFrame(wxDocument* doc, wxView* view, wxFrame* parent, wxWindowID id, const wxString& title, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_FRAME_STYLE, const wxString& name = "wxDocMDIChildFrame");
//
//  wxDocument* GetDocument() const;
//  wxView* GetView() const;
//  void OnActivate(wxActivateEvent event);
//  void OnCloseWindow(wxCloseEvent& event);
//  void SetDocument(wxDocument *doc);
//  void SetView(wxView *view);
//}

// ---------------------------------------------------------------------------
// wxDocMDIParentFrame

//%include "wx/docmdi.h"

//class wxDocMDIParentFrame : public wxMDIParentFrame FIXME
//{
//  wxDocMDIParentFrame(wxDocManager* manager, wxFrame *parent, wxWindowID id, const wxString& title, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_FRAME_STYLE, const wxString& name = "wxDocMDIParentFrame");
//
//  void OnCloseWindow(wxCloseEvent& event);
//}

// ---------------------------------------------------------------------------
// wxDocParentFrame

class wxDocParentFrame : public wxFrame
{
    wxDocParentFrame(wxDocManager* manager, wxFrame *parent, wxWindowID id, const wxString& title, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_FRAME_STYLE, const wxString& name = "wxDocParentFrame");

    //void OnCloseWindow(wxCloseEvent& event);
};

// ---------------------------------------------------------------------------
// wxDocTemplate

#define wxTEMPLATE_VISIBLE
#define wxTEMPLATE_INVISIBLE
#define wxDEFAULT_TEMPLATE_FLAGS

class wxDocTemplate : public wxObject
{
    wxDocTemplate(wxDocManager* manager, const wxString& descr, const wxString& filter, const wxString& dir, const wxString& ext, const wxString& docTypeName, const wxString& viewTypeName, wxClassInfo* docClassInfo = NULL, wxClassInfo* viewClassInfo = NULL, long flags = wxDEFAULT_TEMPLATE_FLAGS);

    wxDocument* CreateDocument(const wxString& path, long flags = 0);
    wxView* CreateView(wxDocument *doc, long flags = 0);
    wxString GetDefaultExtension();
    wxString GetDescription();
    wxString GetDirectory();
    wxDocManager * GetDocumentManager();
    wxString GetDocumentName();
    wxString GetFileFilter();
    long GetFlags();
    wxString GetViewName();
    bool InitDocument(wxDocument* doc, const wxString& path, long flags = 0);
    bool IsVisible();
    void SetDefaultExtension(const wxString& ext);
    void SetDescription(const wxString& descr);
    void SetDirectory(const wxString& dir);
    void SetDocumentManager(wxDocManager *manager);
    void SetFileFilter(const wxString& filter);
    void SetFlags(long flags);
};

// ---------------------------------------------------------------------------
// wxDocument

class wxDocument : public wxEvtHandler
{
    wxDocument();

    virtual bool AddView(wxView *view);
    virtual bool Close();
    virtual bool DeleteAllViews();
    wxCommandProcessor* GetCommandProcessor() const;
    wxDocTemplate* GetDocumentTemplate() const;
    wxDocManager* GetDocumentManager() const;
    wxString GetDocumentName() const;
    wxWindow* GetDocumentWindow() const;
    wxString GetFilename() const;
    wxView* GetFirstView() const;

    virtual wxString GetUserReadableName() const;

    // %override [string name] wxDocument::GetPrintableName(wxString& name) const;
    // C++ Func: virtual void GetPrintableName(wxString& name) const;
    !%wxchkver_2_9 || %wxcompat_2_8 virtual void GetPrintableName(wxString& name) const;

    wxString GetTitle() const;
    wxList& GetViews() const;
    virtual bool IsModified() const;
    //virtual istream& LoadObject(istream& stream);
    //virtual wxInputStream& LoadObject(wxInputStream& stream);
    virtual void Modify(bool modify);
    virtual void OnChangedViewList();
    virtual bool OnCloseDocument();
    virtual bool OnCreate(const wxString& path, long flags);
    virtual wxCommandProcessor* OnCreateCommandProcessor();
    virtual bool OnNewDocument();
    virtual bool OnOpenDocument(const wxString& filename);
    virtual bool OnSaveDocument(const wxString& filename);
    virtual bool OnSaveModified();
    virtual bool RemoveView(wxView* view);
    virtual bool Save();
    virtual bool SaveAs();
    bool IsChildDocument() const;
    //virtual ostream& SaveObject(ostream& stream);
    //virtual wxOutputStream& SaveObject(wxOutputStream& stream);
    virtual void SetCommandProcessor(wxCommandProcessor *processor);
    void SetDocumentName(const wxString& name);
    void SetDocumentTemplate(wxDocTemplate* templ);
    void SetFilename(const wxString& filename, bool notifyViews = false);
    void SetTitle(const wxString& title);
    void UpdateAllViews(wxView* sender = NULL, wxObject* hint = NULL);
};

// ---------------------------------------------------------------------------
// wxView

class wxView : public wxEvtHandler
{
    //wxView();

    virtual void Activate(bool activate);
    virtual bool Close(bool deleteWindow = true);
    wxDocument* GetDocument() const;
    wxDocManager* GetDocumentManager() const;
    wxWindow * GetFrame();
    wxString GetViewName() const;
    virtual void OnActivateView(bool activate, wxView *activeView, wxView *deactiveView);
    virtual void OnChangeFilename();
    virtual bool OnClose(bool deleteWindow);
    //virtual void OnClosingDoocument();
    virtual bool OnCreate(wxDocument* doc, long flags);
    virtual wxPrintout* OnCreatePrintout();
    //virtual void OnDraw(wxDC& dc);
    virtual void OnUpdate(wxView* sender, wxObject* hint);
    void SetDocument(wxDocument* doc);
    void SetFrame(wxFrame* frame);
    void SetViewName(const wxString& name);
};

#endif //wxLUA_USE_MDI && wxUSE_MDI && wxUSE_DOC_VIEW_ARCHITECTURE

// ---------------------------------------------------------------------------
//  wxCommandProcessor

#if wxLUA_USE_wxCommandProcessor

#include "wx/cmdproc.h"

class wxCommandProcessor : public wxObject
{
    wxCommandProcessor(int maxCommands = -1);

    virtual bool CanRedo() const;
    virtual bool CanUndo() const;
    virtual bool Redo();
    virtual bool Undo();
    virtual void ClearCommands();
    wxList& GetCommands() const;
    int GetMaxCommands() const;
    wxMenu *GetEditMenu() const;
    wxString GetRedoAccelerator() const;
    wxString GetRedoMenuLabel() const;
    wxString GetUndoAccelerator() const;
    wxString GetUndoMenuLabel() const;
    virtual void Initialize();
    virtual bool IsDirty();
    virtual void MarkAsSaved();
    void SetEditMenu(wxMenu *menu);
    virtual void SetMenuStrings();
    void SetRedoAccelerator(const wxString& accel);
    void SetUndoAccelerator(const wxString& accel);
    virtual bool Submit(wxCommand *command, bool storeIt = true);
    virtual void Store(wxCommand *command);
    wxCommand *GetCurrentCommand() const;
};

// ---------------------------------------------------------------------------
//  wxCommand

class wxCommand : public wxObject
{
    //wxCommand(bool canUndo = false, const wxString& name = "");

    virtual bool CanUndo();
    virtual bool Do(); // pure virtual
    virtual wxString GetName();
    virtual bool Undo(); // pure virtual
};

#endif //wxLUA_USE_wxCommandProcessor

// ---------------------------------------------------------------------------
// wxFileHistory

#if wxLUA_USE_wxFileHistory && wxUSE_DOC_VIEW_ARCHITECTURE

#include "wx/docview.h"

class %delete wxFileHistory : public wxObject
{
    wxFileHistory(int maxFiles = 9, wxWindowID idBase = wxID_FILE1);

    void AddFileToHistory(const wxString& filename);
    void AddFilesToMenu();
    void AddFilesToMenu(wxMenu* menu);
    wxString GetHistoryFile(int index) const;
    int GetMaxFiles() const;
    size_t GetCount() const;
    void Load(wxConfigBase& config);
    void RemoveFileFromHistory(size_t i);
    void RemoveMenu(wxMenu* menu);
    void Save(wxConfigBase& config);
    void UseMenu(wxMenu* menu);
};

#endif //wxLUA_USE_wxFileHistory && wxUSE_DOC_VIEW_ARCHITECTURE

