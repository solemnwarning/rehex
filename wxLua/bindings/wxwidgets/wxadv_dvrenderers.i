// ===========================================================================
// Purpose:     wxDataView classes
// Author:      Konstantin S. Matveyev
// Created:     28/03/2020
// Copyright:   (c) 2020 EligoVision. Interactive Technologies
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 3.1.4
// ===========================================================================

#include "wx/dvrenderers.h"

#if %wxchkver_3_1 && wxUSE_DATAVIEWCTRL && wxLUA_USE_wxDataViewCtrl


// ----------------------------------------------------------------------------
// wxDataViewIconText: helper class used by wxDataViewIconTextRenderer
// ----------------------------------------------------------------------------

class wxDataViewIconText : public wxObject
{
    wxDataViewIconText(const wxString &text = wxEmptyString, const wxIcon& icon = wxNullIcon );

    void SetText( const wxString &text );
    wxString GetText() const;
    void SetIcon( const wxIcon &icon );
    !%wxchkver_3_2_0 const wxIcon &GetIcon() const;
    %wxchkver_3_2_0 wxIcon GetIcon() const;
};


// ----------------------------------------------------------------------------
// wxDataViewCheckIconText: value class used by wxDataViewCheckIconTextRenderer
// ----------------------------------------------------------------------------

class wxDataViewCheckIconText : public wxDataViewIconText
{
	wxDataViewCheckIconText()
    wxDataViewCheckIconText(const wxString& text,
                            const wxIcon& icon = wxNullIcon,
                            wxCheckBoxState checkedState = wxCHK_UNDETERMINED);

    wxCheckBoxState GetCheckedState() const;
    void SetCheckedState(wxCheckBoxState state);
};


// ----------------------------------------------------------------------------
// wxDataViewRendererBase
// ----------------------------------------------------------------------------

enum wxDataViewCellMode
{
    wxDATAVIEW_CELL_INERT,
    wxDATAVIEW_CELL_ACTIVATABLE,
    wxDATAVIEW_CELL_EDITABLE
};

enum wxDataViewCellRenderState
{
    wxDATAVIEW_CELL_SELECTED    = 1,
    wxDATAVIEW_CELL_PRELIT      = 2,
    wxDATAVIEW_CELL_INSENSITIVE = 4,
    wxDATAVIEW_CELL_FOCUSED     = 8
};

class wxDataViewValueAdjuster
{
//   virtual wxVariant MakeHighlighted(const wxVariant& value) const;
};

class wxDataViewRendererBase : public wxObject
{
    wxDataViewRendererBase( const wxString &varianttype,
                            wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT,
                            int alignment = wxDVR_DEFAULT_ALIGNMENT );

//    virtual bool Validate( wxVariant& value );

    void SetOwner(wxDataViewColumn *owner);
    wxDataViewColumn* GetOwner() const;

    // renderer value and attributes: SetValue() and SetAttr() are called
    // before a cell is rendered using this renderer
//    virtual bool SetValue(const wxVariant& value) = 0;*/
//    virtual bool GetValue(wxVariant& value) const = 0;

#if wxUSE_ACCESSIBILITY
    virtual wxString GetAccessibleDescription() const = 0;
#endif // wxUSE_ACCESSIBILITY

    wxString GetVariantType() const;

//    bool PrepareForItem(const wxDataViewModel *model, const wxDataViewItem& item, unsigned column);

    virtual void SetMode( wxDataViewCellMode mode ) = 0;
    virtual wxDataViewCellMode GetMode() const = 0;

    virtual void SetAlignment( int align ) = 0;
    virtual int GetAlignment() const = 0;

//    virtual void EnableEllipsize(wxEllipsizeMode mode = wxELLIPSIZE_MIDDLE) = 0;
//    void DisableEllipsize() { EnableEllipsize(wxELLIPSIZE_NONE); }

//    virtual wxEllipsizeMode GetEllipsizeMode() const = 0;

    // in-place editing
    virtual bool HasEditorCtrl() const;
//    virtual wxWindow* CreateEditorCtrl(wxWindow * parent, wxRect labelRect, const wxVariant& value);
//    virtual bool GetValueFromEditorCtrl(wxWindow * editor, wxVariant& value);

    virtual bool StartEditing( const wxDataViewItem &item, wxRect labelRect );
    virtual void CancelEditing();
    virtual bool FinishEditing();

    wxWindow *GetEditorCtrl() const;

    virtual bool IsCustomRenderer() const;

    int GetEffectiveAlignment() const;
    int GetEffectiveAlignmentIfKnown() const;
    void NotifyEditingStarted(const wxDataViewItem& item);
    void SetValueAdjuster(wxDataViewValueAdjuster *transformer)
};


// ----------------------------------------------------------------------------
// wxDataViewCustomRendererBase
// ----------------------------------------------------------------------------
// TODO: inherit from wxDataViewCustomRendererRealBase

class wxDataViewCustomRendererBase : public wxDataViewRendererBase
{
    wxDataViewCustomRendererBase(const wxString& varianttype = "string",
                                 wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT,
                                 int align = wxDVR_DEFAULT_ALIGNMENT);

    virtual bool Render(wxRect cell, wxDC *dc, int state) = 0;
    virtual wxSize GetSize() const = 0;

    virtual bool ActivateCell(const wxRect& cell, wxDataViewModel *model, const wxDataViewItem & item, unsigned int col, const wxMouseEvent* mouseEvent);

    virtual bool StartDrag(const wxPoint& cursor, const wxRect& cell, wxDataViewModel *model, const wxDataViewItem &item, unsigned int col);

    virtual void RenderText(const wxString& text, int xoffset, wxRect cell, wxDC *dc, int state);

    virtual void SetAttr(const wxDataViewItemAttr& attr);
    const wxDataViewItemAttr& GetAttr() const;
    virtual void SetEnabled(bool enabled);
    bool GetEnabled() const;

    virtual wxDC *GetDC() = 0;
    virtual void RenderBackground(wxDC* dc, const wxRect& rect);
    void WXCallRender(wxRect rect, wxDC *dc, int state);

    virtual bool IsCustomRenderer() const;
};


// ----------------------------------------------------------------------------
// wxDataViewSpinRenderer
// ----------------------------------------------------------------------------

#if wxUSE_SPINCTRL
class wxDataViewSpinRenderer: public wxDataViewRenderer	// TODO: wxDataViewCustomRenderer
{
    wxDataViewSpinRenderer( int min, int max,
                            wxDataViewCellMode mode = wxDATAVIEW_CELL_EDITABLE,
                            int alignment = wxDVR_DEFAULT_ALIGNMENT );
};
#endif // wxUSE_SPINCTRL


// TODO:
// class wxDataViewDateRenderer
// wxDataViewCheckIconTextRenderer


// ---------------------------------------------------------
// Implementations
// ---------------------------------------------------------


// ---------------------------------------------------------
// wxDataViewTextRenderer
// ---------------------------------------------------------

class wxDataViewTextRenderer : public wxDataViewRenderer
{
    static wxString GetDefaultType();

    wxDataViewTextRenderer( const wxString &varianttype = "string",
                            wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT,
                            int align = wxDVR_DEFAULT_ALIGNMENT );

#if wxUSE_MARKUP
    void EnableMarkup(bool enable = true);
#endif // wxUSE_MARKUP
};


// ---------------------------------------------------------
// wxDataViewBitmapRenderer
// ---------------------------------------------------------

class wxDataViewBitmapRenderer : public wxDataViewRenderer
{
    static wxString GetDefaultType();

    wxDataViewBitmapRenderer( const wxString &varianttype = "wxBitmap",
                              wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT,
                              int align = wxDVR_DEFAULT_ALIGNMENT );
};


// ---------------------------------------------------------
// wxDataViewToggleRenderer
// ---------------------------------------------------------

class wxDataViewToggleRenderer : public wxDataViewRenderer
{
    static wxString GetDefaultType();

    wxDataViewToggleRenderer( const wxString &varianttype = "bool",
                              wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT,
                              int align = wxDVR_DEFAULT_ALIGNMENT );

    void ShowAsRadio();
};


// ---------------------------------------------------------
// wxDataViewCustomRenderer
// ---------------------------------------------------------

// TODO: Override Render method
/*
class wxDataViewCustomRenderer : public wxDataViewCustomRendererBase
{
    static wxString GetDefaultType();

    wxDataViewCustomRenderer( const wxString &varianttype = "string",
                              wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT,
                              int align = wxDVR_DEFAULT_ALIGNMENT,
                              bool no_init = false );
};
*/


// ---------------------------------------------------------
// wxDataViewProgressRenderer
// ---------------------------------------------------------

class wxDataViewProgressRenderer : public wxDataViewRenderer
{
    static wxString GetDefaultType();

    wxDataViewProgressRenderer( const wxString &label = wxEmptyString,
                                const wxString &varianttype = "long",
                                wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT,
                                int align = wxDVR_DEFAULT_ALIGNMENT );
};


// ---------------------------------------------------------
// wxDataViewIconTextRenderer
// ---------------------------------------------------------

class wxDataViewIconTextRenderer: public wxDataViewTextRenderer
{
    static wxString GetDefaultType();

    wxDataViewIconTextRenderer( const wxString &varianttype = "wxDataViewIconText",
                                wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT,
                                int align = wxDVR_DEFAULT_ALIGNMENT );
};


// -------------------------------------
// wxDataViewChoiceRenderer
// -------------------------------------

class wxDataViewChoiceRenderer : public wxDataViewRenderer
{
    wxDataViewChoiceRenderer(const wxArrayString &choices,
                             wxDataViewCellMode mode = wxDATAVIEW_CELL_EDITABLE,
                             int alignment = wxDVR_DEFAULT_ALIGNMENT );

    wxString GetChoice(size_t index) const;
    const wxArrayString& GetChoices() const;
};


// ----------------------------------------------------------------------------
// wxDataViewChoiceByIndexRenderer
// ----------------------------------------------------------------------------

class wxDataViewChoiceByIndexRenderer : public wxDataViewChoiceRenderer
{
    wxDataViewChoiceByIndexRenderer( const wxArrayString &choices,
                                     wxDataViewCellMode mode = wxDATAVIEW_CELL_EDITABLE,
                                     int alignment = wxDVR_DEFAULT_ALIGNMENT );
};

#endif
