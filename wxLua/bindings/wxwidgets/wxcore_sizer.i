// ===========================================================================
// Purpose:     wxSizers and wxLayoutConstraints
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

#if wxLUA_USE_wxSizer

#if %wxchkver_2_8

// ---------------------------------------------------------------------------
// wxSizerFlags

class %delete wxSizerFlags
{
    wxSizerFlags(int proportion = 0);

    // setters for all sizer flags, they all return the object itself so that
    // calls to them can be chained

    wxSizerFlags& Proportion(int proportion);
    wxSizerFlags& Align(int alignment); // combination of wxAlignment values
    wxSizerFlags& Expand(); // wxEXPAND

    // some shortcuts for Align();
    wxSizerFlags& Centre(); // { return Align(wxCENTRE); }
    wxSizerFlags& Center(); // { return Centre(); }
    wxSizerFlags& Left();   // { return Align(wxALIGN_LEFT); }
    wxSizerFlags& Right();  // { return Align(wxALIGN_RIGHT); }
    wxSizerFlags& Top();    // { return Align(wxALIGN_TOP); }
    wxSizerFlags& Bottom(); // { return Align(wxALIGN_BOTTOM); }

    static int GetDefaultBorder(); // default border size used by Border() below
    wxSizerFlags& Border(int direction, int borderInPixels);
    wxSizerFlags& Border(int direction = wxALL);
    wxSizerFlags& DoubleBorder(int direction = wxALL);

    wxSizerFlags& TripleBorder(int direction = wxALL);
    wxSizerFlags& HorzBorder();
    wxSizerFlags& DoubleHorzBorder();
    wxSizerFlags& Shaped();
    wxSizerFlags& FixedMinSize();

#if (wxABI_VERSION >= 20808);
    wxSizerFlags& ReserveSpaceEvenIfHidden();
#endif

    // accessors for wxSizer only
    int GetProportion() const;
    int GetFlags() const;
    int GetBorderInPixels() const;
};

// ----------------------------------------------------------------------------
// wxSizerSpacer - No real need to create one of these in wxLua

//class wxSizerSpacer
//{
//    wxSizerSpacer(const wxSize& size);
//    void SetSize(const wxSize& size);
//    const wxSize& GetSize() const;
//    void Show(bool show);
//    bool IsShown() const;
//};

// ---------------------------------------------------------------------------
// wxSizerItem

class wxSizerItem : public wxObject
{
    wxSizerItem(int width, int height, int proportion, int flag, int border, %ungc wxObject* userData);
    wxSizerItem(wxWindow* window, int proportion, int flag, int border, %ungc wxObject* userData);
    wxSizerItem(wxSizer* sizer, int proportion, int flag, int border, %ungc wxObject* userData);
    wxSizerItem(wxWindow* window, const wxSizerFlags& flags);
    wxSizerItem(wxSizer* window, const wxSizerFlags& flags);

    wxSize CalcMin();
    void DeleteWindows();
    void DetachSizer();
    int GetBorder() const;
    int GetFlag() const;
    wxSize GetMinSize() const;
    wxSize GetMinSizeWithBorder() const;
    wxPoint GetPosition() const;
    int GetProportion() const;
    float GetRatio() const;
    wxRect GetRect();
    wxSize GetSize() const;
    wxSizer* GetSizer() const;
    wxSize GetSpacer() const;
    wxObject* GetUserData() const;
    wxWindow* GetWindow() const;
    bool IsShown() const;
    bool IsSizer() const;
    bool IsSpacer() const;
    bool IsWindow() const;
    void SetBorder(int border);
    void SetDimension(const wxPoint& pos, const wxSize& size);
    void SetFlag(int flag);
    void SetInitSize(int x, int y);
    void SetMinSize(const wxSize& size);
    void SetMinSize(int x, int y);
    void SetProportion(int proportion);
    void SetRatio(int width, int height);
    void SetRatio(const wxSize& size);
    void SetRatio(float ratio);
    void SetUserData(%ungc wxObject* userData);
    !%wxchkver_2_9 || %wxcompat_2_8 void SetSizer(wxSizer* sizer);
    !%wxchkver_2_9 || %wxcompat_2_8 void SetSpacer(const wxSize& size);
    !%wxchkver_2_9 || %wxcompat_2_8 void SetSpacer(int width, int height);
    !%wxchkver_2_9 || %wxcompat_2_8 void SetWindow(wxWindow* window);
    void AssignWindow(wxWindow *window);
    void AssignSizer(wxSizer *sizer);
    void AssignSpacer(const wxSize& size);
    void AssignSpacer(int w, int h);
    void Show(bool show);
};

// ---------------------------------------------------------------------------
// wxSizer

class wxSizer : public wxObject
{
    // base class no constructors

    wxSizerItem* Add(wxWindow* window, int proportion = 0,int flag = 0, int border = 0, %ungc wxObject* userData = NULL);
    wxSizerItem* Add(wxSizer* sizer, int proportion = 0, int flag = 0, int border = 0, %ungc wxObject* userData = NULL);
    wxSizerItem* Add(int width, int height, int proportion = 0, int flag = 0, int border = 0, %ungc wxObject* userData = NULL);
    wxSizerItem* Add(wxWindow* window, const wxSizerFlags& flags);
    wxSizerItem* Add(wxSizer* sizer, const wxSizerFlags& flags);
    wxSizerItem* Add(wxSizerItem *item);
    wxSizerItem* AddSpacer(int size);
    wxSizerItem* AddStretchSpacer(int prop = 1);
    wxSize CalcMin();
    virtual void Clear(bool delete_windows = false);

#if (wxABI_VERSION >= 20808);
    wxSize ComputeFittingClientSize(wxWindow *window);
    wxSize ComputeFittingWindowSize(wxWindow *window);
#endif

    virtual void DeleteWindows();
    bool Detach(wxWindow* window);
    bool Detach(wxSizer* sizer);
    bool Detach(size_t index);
    void Fit(wxWindow* window);
    void FitInside(wxWindow* window);
    wxSizerItemList& GetChildren();
    wxWindow *GetContainingWindow() const;
    size_t GetItemCount() const;
    bool IsEmpty() const;
    wxSizerItem* GetItem(wxWindow* window, bool recursive = false);
    wxSizerItem* GetItem(wxSizer* sizer, bool recursive = false);
    wxSizerItem* GetItem(size_t index);
    wxSize GetSize();
    wxPoint GetPosition();
    wxSize GetMinSize();
    bool Hide(wxSizer *sizer, bool recursive = false);
    bool Hide(wxWindow *window, bool recursive = false);
    bool Hide(size_t index);
    wxSizerItem* Insert(size_t index, wxWindow* window, int proportion = 0,int flag = 0, int border = 0, %ungc wxObject* userData = NULL);
    wxSizerItem* Insert(size_t index, wxSizer* sizer, int proportion = 0, int flag = 0, int border = 0, %ungc wxObject* userData = NULL);
    wxSizerItem* Insert(size_t index, int width, int height, int proportion = 0, int flag = 0, int border = 0, %ungc wxObject* userData = NULL);
    wxSizerItem* Insert(size_t index, wxWindow* window, const wxSizerFlags& flags);
    wxSizerItem* Insert(size_t index, wxSizer* sizer, const wxSizerFlags& flags);
    virtual wxSizerItem* Insert(size_t index, wxSizerItem *item);
    wxSizerItem* InsertSpacer(size_t index, int size);
    wxSizerItem* InsertStretchSpacer(size_t index, int prop = 1);
    bool IsShown(wxWindow *window) const;
    bool IsShown(wxSizer *sizer) const;
    bool IsShown(size_t index) const;
    void Layout();
    void Prepend(wxWindow* window, int proportion = 0, int flag = 0, int border = 0, %ungc wxObject* userData = NULL);
    void Prepend(wxSizer* sizer, int proportion = 0, int flag = 0, int border = 0, %ungc wxObject* userData = NULL);
    void Prepend(int width, int height, int proportion = 0, int flag = 0, int border= 0, %ungc wxObject* userData = NULL);
    wxSizerItem* Prepend(wxWindow* window, const wxSizerFlags& flags);
    wxSizerItem* Prepend(wxSizer* sizer, const wxSizerFlags& flags);
    wxSizerItem* Prepend(wxSizerItem *item);
    wxSizerItem* PrependSpacer(int size);
    wxSizerItem* PrependStretchSpacer(int prop = 1);
    void RecalcSizes();
    //bool Remove(wxWindow* window) - deprecated use Detach
    //bool Remove(wxSizer* sizer);
    //bool Remove(size_t index);
    virtual bool Replace(wxWindow *oldwin, wxWindow *newwin, bool recursive = false);
    virtual bool Replace(wxSizer *oldsz, wxSizer *newsz, bool recursive = false);
    virtual bool Replace(size_t index, wxSizerItem *newitem);
    void SetContainingWindow(wxWindow *window);
    void SetDimension(int x, int y, int width, int height);
    void SetMinSize(int width, int height);
    void SetMinSize(const wxSize& size);
    void SetItemMinSize(wxWindow* window, int width, int height);
    void SetItemMinSize(wxSizer* sizer, int width, int height);
    void SetItemMinSize(int pos, int width, int height);
    void SetSizeHints(wxWindow* window);
    !%wxchkver_2_9 || %wxcompat_2_8 void SetVirtualSizeHints(wxWindow* window);
    bool Show(wxWindow* window, bool show = true, bool recursive = false);
    bool Show(wxSizer* sizer, bool show = true, bool recursive = false);
    bool Show(size_t index, bool show = true);
    //void Show(bool show) - simply calls ShowItems();
    virtual void ShowItems (bool show);
};

// ---------------------------------------------------------------------------
// wxSizerItemList

//#if wxLUA_USE_wxSizerItemList && !wxUSE_STL

class wxSizerItemList : public wxList
{
    //wxSizerItemList() - no constructor, just get this from wxSizer::GetChildren();

    // This is returned from wxSizer::GetChildren(), use wxList methods and
    //   wxNode::GetData():DynamicCast("wxSizer") to retrieve the wxSizer

    // Use the wxList methods, see also wxNode
};

//#endif //wxLUA_USE_wxSizerItemList && !wxUSE_STL

// ---------------------------------------------------------------------------
// wxBoxSizer

class wxBoxSizer : public wxSizer
{
    wxBoxSizer(int orient);

    //void RecalcSizes();
    //wxSize CalcMin();
    int GetOrientation();
};

// ---------------------------------------------------------------------------
// wxGridSizer

class wxGridSizer : public wxSizer
{
    wxGridSizer(int cols, int rows, int vgap, int hgap);
    // wxGridSizer(int cols, int vgap = 0, int hgap = 0);

    int GetCols();
    int GetHGap();
    int GetRows();
    int GetVGap();
    void SetCols(int cols);
    void SetHGap(int gap);
    void SetRows(int rows);
    void SetVGap(int gap);
};

// ---------------------------------------------------------------------------
// wxFlexGridSizer

enum wxFlexSizerGrowMode
{
    wxFLEX_GROWMODE_NONE,
    wxFLEX_GROWMODE_SPECIFIED,
    wxFLEX_GROWMODE_ALL
};

class wxFlexGridSizer : public wxGridSizer
{
    wxFlexGridSizer(int rows, int cols, int vgap=0, int hgap=0);
    // wxFlexGridSizer(int cols, int vgap = 0, int hgap = 0); // just use the above constructor

    void AddGrowableCol(size_t idx, int proportion = 0);
    void AddGrowableRow(size_t idx, int proportion = 0);
    int GetFlexibleDirection() const;
    wxFlexSizerGrowMode GetNonFlexibleGrowMode() const;
    void RemoveGrowableCol(size_t idx);
    void RemoveGrowableRow(size_t idx);
    void SetFlexibleDirection(int direction);
    void SetNonFlexibleGrowMode(wxFlexSizerGrowMode mode);
};

// ---------------------------------------------------------------------------
// wxGridBagSizer

#include "wx/gbsizer.h"

class wxGridBagSizer : public wxFlexGridSizer
{
    wxGridBagSizer(int vgap=0, int hgap=0);

    wxSizerItem* Add(wxWindow* window, const wxGBPosition& pos, const wxGBSpan& span = wxDefaultSpan, int flag = 0, int border = 0, %ungc wxObject* userData = NULL);
    wxSizerItem* Add(wxSizer* sizer, const wxGBPosition& pos, const wxGBSpan& span = wxDefaultSpan, int flag = 0, int border = 0, %ungc wxObject* userData = NULL);
    wxSizerItem* Add(int width, int height, const wxGBPosition& pos, const wxGBSpan& span = wxDefaultSpan, int flag = 0, int border = 0, %ungc wxObject* userData = NULL);
    wxSizerItem* Add(wxGBSizerItem* item);

    bool CheckForIntersection(wxGBSizerItem* item, wxGBSizerItem* excludeItem = NULL);
    bool CheckForIntersection(const wxGBPosition& pos, const wxGBSpan& span, wxGBSizerItem* excludeItem = NULL);

    wxGBSizerItem* FindItem(wxWindow* window);
    wxGBSizerItem* FindItem(wxSizer* sizer);
    wxGBSizerItem*  FindItemAtPoint(const wxPoint& pt);
    wxGBSizerItem*  FindItemAtPosition(const wxGBPosition& pos);
    wxGBSizerItem*  FindItemWithData(const wxObject* userData);
    wxSize GetCellSize(int row, int col) const;
    wxSize GetEmptyCellSize() const;

    wxGBPosition  GetItemPosition(wxWindow* window);
    wxGBPosition  GetItemPosition(wxSizer* sizer);
    wxGBPosition  GetItemPosition(size_t index);

    wxGBSpan GetItemSpan(wxWindow* window);
    wxGBSpan GetItemSpan(wxSizer* sizer);
    wxGBSpan GetItemSpan(size_t index);
    //void RecalcSizes();
    void SetEmptyCellSize(const wxSize& sz);
    bool SetItemPosition(wxWindow* window, const wxGBPosition& pos);
    bool SetItemPosition(wxSizer* sizer, const wxGBPosition& pos);
    bool SetItemPosition(size_t index, const wxGBPosition& pos);
    bool SetItemSpan(wxWindow* window, const wxGBSpan& span);
    bool SetItemSpan(wxSizer* sizer, const wxGBSpan& span);
    bool SetItemSpan(size_t index, const wxGBSpan& span);
};

// ---------------------------------------------------------------------------
// wxGBPosition

class %delete wxGBPosition
{
    wxGBPosition(int row=0, int col=0);
    wxGBPosition(const wxGBPosition& pos);

    int GetRow() const;
    int GetCol() const;
    void SetRow(int row);
    void SetCol(int col);

    bool operator==(const wxGBPosition& p) const;
};

// ---------------------------------------------------------------------------
// wxGBSpan

class %delete wxGBSpan
{
    wxGBSpan(int rowspan=1, int colspan=1);
    wxGBSpan(const wxGBSpan& span);

    int GetRowspan() const;
    int GetColspan() const;
    void SetRowspan(int rowspan);
    void SetColspan(int colspan);

    bool operator==(const wxGBSpan& o) const;
};

// ---------------------------------------------------------------------------
// wxGBSizerItem

class wxGBSizerItem : public wxSizerItem
{
    wxGBSizerItem();
    wxGBSizerItem(int width, int height, const wxGBPosition& pos, const wxGBSpan& span, int flag, int border, %ungc wxObject* userData);
    wxGBSizerItem(wxWindow *window, const wxGBPosition& pos, const wxGBSpan& span, int flag, int border, %ungc wxObject* userData);
    wxGBSizerItem(wxSizer *sizer, const wxGBPosition& pos, const wxGBSpan& span, int flag, int border, %ungc wxObject* userData);

    wxGBPosition GetPos() const;
    //void GetPos(int& row, int& col) const;
    wxGBSpan GetSpan() const;
    //void GetSpan(int& rowspan, int& colspan) const;
    bool SetPos(const wxGBPosition& pos);
    bool SetSpan(const wxGBSpan& span);
    bool Intersects(const wxGBSizerItem& other);
    bool Intersects(const wxGBPosition& pos, const wxGBSpan& span);

    // %override [row, col] wxGBSizerItem::GetEndPos();
    // C++ Func: void GetEndPos(int& row, int& col);
    void GetEndPos();

    wxGridBagSizer* GetGBSizer() const;
    void SetGBSizer(wxGridBagSizer* sizer);
};

// ---------------------------------------------------------------------------
// wxWrapSizer

#if %wxchkver_2_9

#include "wx/wrapsizer.h"

enum
{
    wxEXTEND_LAST_ON_EACH_LINE,
    wxREMOVE_LEADING_SPACES,
    wxWRAPSIZER_DEFAULT_FLAGS
};

class wxWrapSizer : public wxBoxSizer
{
    wxWrapSizer(int orient = wxHORIZONTAL, int flags = wxWRAPSIZER_DEFAULT_FLAGS);
    
    // This will probably not be needed to be called by user code.
    bool InformFirstDirection(int direction, int size, int availableOtherDir);
};

#endif

// ---------------------------------------------------------------------------
// wxNotebookSizer - deprecated

#if wxUSE_NOTEBOOK && (!%wxchkver_2_6);

class wxNotebookSizer : public wxSizer
{
    wxNotebookSizer(wxNotebook* notebook);
    wxNotebook* GetNotebook();
};

#endif //wxUSE_NOTEBOOK && (!%wxchkver_2_6);

// ---------------------------------------------------------------------------
// wxBookCtrlSizer - also depricated since 2.6

// ---------------------------------------------------------------------------
// wxStaticBoxSizer

#if wxUSE_STATBOX

class wxStaticBoxSizer : public wxBoxSizer
{
    wxStaticBoxSizer(wxStaticBox* box, int orient);
    wxStaticBoxSizer(int orient, wxWindow *parent, const wxString& label = "");

    wxStaticBox* GetStaticBox();
};

#endif //wxUSE_STATBOX

// ---------------------------------------------------------------------------
// wxStdDialogButtonSizer

#if wxUSE_BUTTON

class wxStdDialogButtonSizer : public wxBoxSizer
{
    wxStdDialogButtonSizer();

    void AddButton(wxButton *button);
    void SetAffirmativeButton(wxButton *button);
    void SetNegativeButton(wxButton *button);
    void SetCancelButton(wxButton *button);

    void Realize();

    wxButton *GetAffirmativeButton() const;
    wxButton *GetApplyButton() const;
    wxButton *GetNegativeButton() const;
    wxButton *GetCancelButton() const;
    wxButton *GetHelpButton() const;
};

#endif //wxUSE_BUTTON

#endif //wxLUA_USE_wxSizer

// ---------------------------------------------------------------------------
// wxLayoutConstraints - deprecated since 2.2, not updated to 2.6

#if wxLUA_USE_wxLayoutConstraints && (!%wxchkver_2_6);

#include "wx/layout.h"

enum wxRelationship
{
    wxUnconstrained,
    wxAsIs,
    wxPercentOf,
    wxAbove,
    wxBelow,
    wxLeftOf,
    wxRightOf,
    wxSameAs,
    wxAbsolute
};

enum wxEdge
{
    wxLeft,
    wxTop,
    wxRight,
    wxBottom,
    wxWidth,
    wxHeight,
    wxCentre,
    wxCenter,
    wxCentreX,
    wxCentreY
};

class wxLayoutConstraints : public wxObject
{
    wxLayoutConstraints();
};

// ---------------------------------------------------------------------------
// wxIndividualLayoutConstraint

#include "wx/layout.h"

class wxIndividualLayoutConstraint : public wxObject
{
    wxIndividualLayoutConstraint();
    void Above(wxWindow *otherWin, int margin = 0);
    void Absolute(int value);
    void AsIs();
    void Below(wxWindow *otherWin, int margin = 0);
    void Unconstrained();
    void LeftOf(wxWindow *otherWin, int margin = 0);
    void PercentOf(wxWindow *otherWin, wxEdge edge, int per);
    void RightOf(wxWindow *otherWin, int margin = 0);
    void SameAs(wxWindow *otherWin, wxEdge edge, int margin = 0);
    void Set(wxRelationship rel, wxWindow *otherWin, wxEdge otherEdge, int value = 0, int margin = 0);
};

#endif //wxLUA_USE_wxLayoutConstraints && (!%wxchkver_2_6);

