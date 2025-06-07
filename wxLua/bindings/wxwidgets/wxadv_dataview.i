// ===========================================================================
// Purpose:     wxDataView classes
// Author:      Konstantin S. Matveyev
// Created:     28/03/2020
// Copyright:   (c) 2020 EligoVision. Interactive Technologies
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 3.1.4
// ===========================================================================

#include "wx/dataview.h"

#if %wxchkver_3_1 && wxUSE_DATAVIEWCTRL && wxLUA_USE_wxDataViewCtrl

#define wxDVC_DEFAULT_RENDERER_SIZE
#define wxDVC_DEFAULT_WIDTH
#define wxDVC_TOGGLE_DEFAULT_WIDTH
#define wxDVC_DEFAULT_MINWIDTH
#define wxDVR_DEFAULT_ALIGNMENT

enum wxDataViewColumnFlags
{
    wxDATAVIEW_COL_RESIZABLE,
    wxDATAVIEW_COL_SORTABLE,
    wxDATAVIEW_COL_REORDERABLE,
    wxDATAVIEW_COL_HIDDEN
};


// class wxDataViewItem
class %delete wxDataViewItem
{
    wxDataViewItem();
	wxDataViewItem(const wxDataViewItem &item);
	wxDataViewItem(void *id);

	void* 	GetID() const;
	bool 	IsOk() const;
};


// class wxDataViewItemArray
class %delete wxDataViewItemArray
{
    wxDataViewItemArray();
    wxDataViewItemArray(const wxDataViewItemArray& array);

	// TODO:
    // %override [Lua table] wxDataViewItemArray::ToLuaTable() const;
    // returns a table array of the wxDataViewItem
//    int ToLuaTable() const;

    void Add(wxDataViewItem num);
    void Alloc(size_t count);
    void Clear();
    void Empty();
    int  GetCount() const;
    bool IsEmpty() const;
    int  Index(wxDataViewItem n, bool searchFromEnd = false);
    void Insert(wxDataViewItem num, int n, int copies = 1);
    wxDataViewItem Item(int n);
    void Remove(wxDataViewItem n);
    void RemoveAt(size_t index);
    void Shrink();

    wxDataViewItem operator[](size_t nIndex);
};


// class wxDataViewModelNotifier
class %delete wxDataViewModelNotifier
{
    wxDataViewModelNotifier();

    virtual bool ItemAdded( const wxDataViewItem &parent, const wxDataViewItem &item ) = 0;
    virtual bool ItemDeleted( const wxDataViewItem &parent, const wxDataViewItem &item ) = 0;
    virtual bool ItemChanged( const wxDataViewItem &item ) = 0;
    virtual bool ItemsAdded( const wxDataViewItem &parent, const wxDataViewItemArray &items );
    virtual bool ItemsDeleted( const wxDataViewItem &parent, const wxDataViewItemArray &items );
    virtual bool ItemsChanged( const wxDataViewItemArray &items );
    virtual bool ValueChanged( const wxDataViewItem &item, unsigned int col ) = 0;
    virtual bool Cleared() = 0;

    virtual bool BeforeReset();
    virtual bool AfterReset();

    virtual void Resort() = 0;

    void SetOwner(wxDataViewModel *owner) %ungc_this;	// NOTE: valid owner must be presented
    wxDataViewModel *GetOwner() const;
};


// class wxDataViewItemAttr
class %delete wxDataViewItemAttr
{
    wxDataViewItemAttr();

    // setters
    void SetColour(const wxColour& colour);
    void SetBold( bool set );
    void SetItalic( bool set );
    void SetStrikethrough( bool set );
    void SetBackgroundColour(const wxColour& colour);

    // accessors
    bool HasColour() const;
    const wxColour& GetColour() const;

    bool HasFont() const;
    bool GetBold() const;
    bool GetItalic() const;
    bool GetStrikethrough() const;

    bool HasBackgroundColour() const;
    const wxColour& GetBackgroundColour();

    bool IsDefault() const;

    // Return the font based on the given one with this attribute applied to it.
    wxFont GetEffectiveFont(const wxFont& font) const;
};


/*typedef wxVector<wxDataViewModelNotifier*> wxDataViewModelNotifiers;*/

// class wxDataViewModel
class %delete wxDataViewModel // : public wxRefCounter
{
	// wxRefCounter memory managment
    void DecRef();
    int GetRefCount() const;
    void IncRef();

    virtual unsigned int GetColumnCount();

    // return type as reported by wxVariant
    virtual wxString GetColumnType( unsigned int col ) const = 0;

    // get value into a wxVariant
    // virtual void GetValue( wxVariant &variant, const wxDataViewItem &item, unsigned int col ) const = 0;
    bool HasValue(const wxDataViewItem& item, unsigned int col) const;
    // virtual bool SetValue(const wxVariant &variant, const wxDataViewItem &item, unsigned int col) = 0;

    // bool ChangeValue(const wxVariant& variant, const wxDataViewItem& item, unsigned int col);
    virtual bool GetAttr(const wxDataViewItem &item, unsigned int col, wxDataViewItemAttr &attr) const;
    virtual bool IsEnabled(const wxDataViewItem &item, unsigned int col) const;

    virtual wxDataViewItem GetParent( const wxDataViewItem &item ) const = 0;
    virtual bool IsContainer( const wxDataViewItem &item ) const = 0;

    virtual bool HasContainerColumns(const wxDataViewItem& item) const;
    virtual unsigned int GetChildren( const wxDataViewItem &item, wxDataViewItemArray &children ) const = 0;

    bool ItemAdded( const wxDataViewItem &parent, const wxDataViewItem &item );
    bool ItemsAdded( const wxDataViewItem &parent, const wxDataViewItemArray &items );
    bool ItemDeleted( const wxDataViewItem &parent, const wxDataViewItem &item );
    bool ItemsDeleted( const wxDataViewItem &parent, const wxDataViewItemArray &items );
    bool ItemChanged( const wxDataViewItem &item );
    bool ItemsChanged( const wxDataViewItemArray &items );
    bool ValueChanged( const wxDataViewItem &item, unsigned int col );
    bool Cleared();

    // some platforms, such as GTK+, may need a two step procedure for ::Reset()
    bool BeforeReset();
    bool AfterReset();

    // delegated action
    virtual void Resort();

    void AddNotifier( wxDataViewModelNotifier *notifier );
    void RemoveNotifier( wxDataViewModelNotifier *notifier );

    // default compare function
    virtual int Compare( const wxDataViewItem &item1, const wxDataViewItem &item2,
                         unsigned int column, bool ascending ) const;
    virtual bool HasDefaultCompare() const;

    // internal
    virtual bool IsListModel() const;
    virtual bool IsVirtualListModel() const;
};


// class wxDataViewListModel
class %delete wxDataViewListModel : public wxDataViewModel
{
//    virtual void GetValueByRow(wxVariant &variant, unsigned row, unsigned col) const = 0;
//    virtual bool SetValueByRow(const wxVariant &variant, unsigned row, unsigned col) = 0;
    virtual bool GetAttrByRow(unsigned int row, unsigned int col, wxDataViewItemAttr &attr) const;
    virtual bool IsEnabledByRow(unsigned int row, unsigned int col) const;
    virtual unsigned int GetRow( const wxDataViewItem &item ) const = 0;
    virtual unsigned int GetCount() const = 0;
};


// class wxDataViewIndexListModel
class %delete wxDataViewIndexListModel : public wxDataViewListModel
{
    void RowPrepended();
    void RowInserted( unsigned int before );
    void RowAppended();
    void RowDeleted( unsigned int row );
    void RowsDeleted( const wxArrayInt &rows );
    void RowChanged( unsigned int row );
    void RowValueChanged( unsigned int row, unsigned int col );
    void Reset( unsigned int new_size );

    wxDataViewItem GetItem( unsigned int row ) const;
};


// class wxDataViewListStore
class %delete wxDataViewListStoreLine
{
    wxDataViewListStoreLine( wxUIntPtr data = 0 );

    void SetData( wxUIntPtr data );
    wxUIntPtr GetData() const;

//    wxVector<wxVariant>  m_values;
};


// class wxDataViewListStore
class %delete wxDataViewListStore : public wxDataViewIndexListModel
{
public:
    wxDataViewListStore();

    void PrependColumn( const wxString &varianttype );
    void InsertColumn( unsigned int pos, const wxString &varianttype );
    void AppendColumn( const wxString &varianttype );

//    void AppendItem( const wxVector<wxVariant> &values, wxUIntPtr data = 0 );
//    void PrependItem( const wxVector<wxVariant> &values, wxUIntPtr data = 0 );
//    void InsertItem(  unsigned int row, const wxVector<wxVariant> &values, wxUIntPtr data = 0 );
    void DeleteItem( unsigned int pos );
    void DeleteAllItems();
    void ClearColumns();

    unsigned int GetItemCount() const;

    void SetItemData( const wxDataViewItem& item, wxUIntPtr data );
    wxUIntPtr GetItemData( const wxDataViewItem& item ) const;
};



// TODO: wxDataViewVirtualListModel


// class wxDataViewTreeStoreNode
class %delete wxDataViewTreeStoreNode
{
public:
    wxDataViewTreeStoreNode(wxDataViewTreeStoreNode *parent, const wxString &text, const wxIcon &icon = wxNullIcon, wxClientData *data = NULL );

    void SetText( const wxString &text );
    wxString GetText() const;
    void SetIcon( const wxIcon &icon );
    !%wxchkver_3_1_6 const wxIcon &GetIcon() const;
    %wxchkver_3_1_6 wxIcon GetIcon() const;
    void SetData( wxClientData *data );
    wxClientData *GetData() const;

    wxDataViewItem GetItem() const;

    virtual bool IsContainer();

    wxDataViewTreeStoreNode *GetParent();
};
// typedef wxVector<wxDataViewTreeStoreNode*> wxDataViewTreeStoreNodes;


// class wxDataViewTreeStoreContainerNode
class %delete wxDataViewTreeStoreContainerNode : public wxDataViewTreeStoreNode
{
    wxDataViewTreeStoreContainerNode( wxDataViewTreeStoreNode *parent, const wxString &text,
		const wxIcon &icon = wxNullIcon, const wxIcon &expanded = wxNullIcon, wxClientData *data = NULL );

//    const wxDataViewTreeStoreNodes &GetChildren() const
//    wxDataViewTreeStoreNodes &GetChildren()

//	wxDataViewTreeStoreNodes::iterator FindChild(wxDataViewTreeStoreNode* node);

    void SetExpandedIcon( const wxIcon &icon );
    !%wxchkver_3_1_6 const wxIcon &GetExpandedIcon() const;
    %wxchkver_3_1_6 wxIcon GetExpandedIcon() const;

    void SetExpanded( bool expanded = true );
    bool IsExpanded() const;

    void DestroyChildren();
};


// class wxDataViewTreeStore
class %delete wxDataViewTreeStore : public wxDataViewModel
{
    wxDataViewTreeStore();

    wxDataViewItem AppendItem( const wxDataViewItem& parent,
        const wxString &text, const wxIcon &icon = wxNullIcon, wxClientData *data = NULL );
    wxDataViewItem PrependItem( const wxDataViewItem& parent,
        const wxString &text, const wxIcon &icon = wxNullIcon, wxClientData *data = NULL );
    wxDataViewItem InsertItem( const wxDataViewItem& parent, const wxDataViewItem& previous,
        const wxString &text, const wxIcon &icon = wxNullIcon, wxClientData *data = NULL );

    wxDataViewItem PrependContainer( const wxDataViewItem& parent,
        const wxString &text, const wxIcon &icon = wxNullIcon, const wxIcon &expanded = wxNullIcon,
        wxClientData *data = NULL );
    wxDataViewItem AppendContainer( const wxDataViewItem& parent,
        const wxString &text, const wxIcon &icon = wxNullIcon, const wxIcon &expanded = wxNullIcon,
        wxClientData *data = NULL );
    wxDataViewItem InsertContainer( const wxDataViewItem& parent, const wxDataViewItem& previous,
        const wxString &text, const wxIcon &icon = wxNullIcon, const wxIcon &expanded = wxNullIcon,
        wxClientData *data = NULL );

    wxDataViewItem GetNthChild( const wxDataViewItem& parent, unsigned int pos ) const;
    int GetChildCount( const wxDataViewItem& parent ) const;

    void SetItemText( const wxDataViewItem& item, const wxString &text );
    wxString GetItemText( const wxDataViewItem& item ) const;
    void SetItemIcon( const wxDataViewItem& item, const wxIcon &icon );
    !%wxchkver_3_1_6 const wxIcon &GetItemIcon( const wxDataViewItem& item ) const;
    %wxchkver_3_1_6 wxIcon GetItemIcon( const wxDataViewItem& item ) const;
    void SetItemExpandedIcon( const wxDataViewItem& item, const wxIcon &icon );
    !%wxchkver_3_1_6 const wxIcon &GetItemExpandedIcon( const wxDataViewItem& item ) const;
    %wxchkver_3_1_6 wxIcon GetItemExpandedIcon( const wxDataViewItem& item ) const;
    void SetItemData( const wxDataViewItem& item, wxClientData *data );
    wxClientData *GetItemData( const wxDataViewItem& item ) const;

    void DeleteItem( const wxDataViewItem& item );
    void DeleteChildren( const wxDataViewItem& item );
    void DeleteAllItems();		// FIXME: segfault

    wxDataViewTreeStoreNode *FindNode( const wxDataViewItem &item ) const;
    wxDataViewTreeStoreContainerNode *FindContainerNode( const wxDataViewItem &item ) const;
    wxDataViewTreeStoreNode *GetRoot() const;

//    wxDataViewTreeStoreNode *m_root;
};


// class wxDataViewRenderer and related classes
class wxDataViewRenderer : public wxDataViewCustomRendererBase
{
//    wxDataViewRenderer( const wxString &varianttype,
//                        wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT,
//                        int align = wxDVR_DEFAULT_ALIGNMENT );
};


// From wx/headercol.h [begin]

enum
{
    wxCOL_WIDTH_DEFAULT,
    wxCOL_WIDTH_AUTOSIZE
};

enum
{
    wxCOL_RESIZABLE,
    wxCOL_SORTABLE,
    wxCOL_REORDERABLE,
    wxCOL_HIDDEN,
    wxCOL_DEFAULT_FLAGS
};


// class wxHeaderColumn
class %delete wxHeaderColumn
{
    virtual wxString GetTitle() const = 0;
    virtual wxBitmap GetBitmap() const = 0;
    virtual int GetWidth() const = 0;
    virtual int GetMinWidth() const = 0;
    virtual wxAlignment GetAlignment() const = 0;

    virtual int GetFlags() const = 0;
    bool HasFlag(int flag) const;

    virtual bool IsResizeable() const;
    virtual bool IsSortable() const
    virtual bool IsReorderable() const;
    virtual bool IsHidden() const;
    bool IsShown() const;

    virtual bool IsSortKey() const;
    virtual bool IsSortOrderAscending() const;
};


// class wxSettableHeaderColumn
class wxSettableHeaderColumn : public wxHeaderColumn
{
    virtual void SetTitle(const wxString& title) = 0;
    virtual void SetBitmap(const wxBitmap& bitmap) = 0;
    virtual void SetWidth(int width) = 0;
    virtual void SetMinWidth(int minWidth) = 0;
    virtual void SetAlignment(wxAlignment align) = 0;

    virtual void SetFlags(int flags) = 0;
    void ChangeFlag(int flag, bool set);
    void SetFlag(int flag);
    void ClearFlag(int flag);
    void ToggleFlag(int flag);

    virtual void SetResizeable(bool resizable);
    virtual void SetSortable(bool sortable);
    virtual void SetReorderable(bool reorderable);
    virtual void SetHidden(bool hidden);

    virtual void UnsetAsSortKey();

    virtual void SetSortOrder(bool ascending) = 0;
    void ToggleSortOrder();
};

// From wx/headercol.h [end]


// class wxDataViewColumnBase
class wxDataViewColumnBase : public wxSettableHeaderColumn
{
    virtual void SetOwner(wxDataViewCtrl *owner) %ungc_this;	// NOTE: valid owner must be presented

    unsigned int GetModelColumn() const;
    wxDataViewCtrl *GetOwner() const;
    wxDataViewRenderer* GetRenderer() const;

    virtual void SetBitmap(const wxBitmap& bitmap);
    virtual wxBitmap GetBitmap() const;
};


// class wxDataViewColumn
class wxDataViewColumn : public wxDataViewColumnBase
{
    wxDataViewColumn( const wxString &title, wxDataViewRenderer *renderer,
                      unsigned int model_column, int width = wxDVC_DEFAULT_WIDTH,
                      wxAlignment align = wxALIGN_CENTER,
                      int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn( const wxBitmap &bitmap, wxDataViewRenderer *renderer,
                      unsigned int model_column, int width = wxDVC_DEFAULT_WIDTH,
                      wxAlignment align = wxALIGN_CENTER,
                      int flags = wxDATAVIEW_COL_RESIZABLE );
};


#define wxDV_SINGLE
#define wxDV_MULTIPLE

#define wxDV_NO_HEADER
#define wxDV_HORIZ_RULES
#define wxDV_VERT_RULES

#define wxDV_ROW_LINES
#define wxDV_VARIABLE_LINE_HEIGHT


// class wxDataViewCtrlBase
class wxDataViewCtrlBase : public wxControl	//: public wxSystemThemedControl<wxControl>
{
    virtual bool AssociateModel( wxDataViewModel *model );
    wxDataViewModel* GetModel();

    wxDataViewColumn *PrependTextColumn( const wxString &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = -1,
                    wxAlignment align = wxALIGN_NOT,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *PrependIconTextColumn( const wxString &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = -1,
                    wxAlignment align = wxALIGN_NOT,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *PrependToggleColumn( const wxString &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = wxDVC_TOGGLE_DEFAULT_WIDTH,
                    wxAlignment align = wxALIGN_CENTER,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *PrependProgressColumn( const wxString &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = wxDVC_DEFAULT_WIDTH,
                    wxAlignment align = wxALIGN_CENTER,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *PrependDateColumn( const wxString &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_ACTIVATABLE, int width = -1,
                    wxAlignment align = wxALIGN_NOT,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *PrependBitmapColumn( const wxString &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = -1,
                    wxAlignment align = wxALIGN_CENTER,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *PrependTextColumn( const wxBitmap &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = -1,
                    wxAlignment align = wxALIGN_NOT,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *PrependIconTextColumn( const wxBitmap &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = -1,
                    wxAlignment align = wxALIGN_NOT,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *PrependToggleColumn( const wxBitmap &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = wxDVC_TOGGLE_DEFAULT_WIDTH,
                    wxAlignment align = wxALIGN_CENTER,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *PrependProgressColumn( const wxBitmap &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = wxDVC_DEFAULT_WIDTH,
                    wxAlignment align = wxALIGN_CENTER,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *PrependDateColumn( const wxBitmap &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_ACTIVATABLE, int width = -1,
                    wxAlignment align = wxALIGN_NOT,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *PrependBitmapColumn( const wxBitmap &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = -1,
                    wxAlignment align = wxALIGN_CENTER,
                    int flags = wxDATAVIEW_COL_RESIZABLE );

    wxDataViewColumn *AppendTextColumn( const wxString &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = -1,
                    wxAlignment align = wxALIGN_NOT,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *AppendIconTextColumn( const wxString &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = -1,
                    wxAlignment align = wxALIGN_NOT,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *AppendToggleColumn( const wxString &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = wxDVC_TOGGLE_DEFAULT_WIDTH,
                    wxAlignment align = wxALIGN_CENTER,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *AppendProgressColumn( const wxString &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = wxDVC_DEFAULT_WIDTH,
                    wxAlignment align = wxALIGN_CENTER,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *AppendDateColumn( const wxString &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_ACTIVATABLE, int width = -1,
                    wxAlignment align = wxALIGN_NOT,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *AppendBitmapColumn( const wxString &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = -1,
                    wxAlignment align = wxALIGN_CENTER,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *AppendTextColumn( const wxBitmap &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = -1,
                    wxAlignment align = wxALIGN_NOT,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *AppendIconTextColumn( const wxBitmap &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = -1,
                    wxAlignment align = wxALIGN_NOT,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *AppendToggleColumn( const wxBitmap &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = wxDVC_TOGGLE_DEFAULT_WIDTH,
                    wxAlignment align = wxALIGN_CENTER,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *AppendProgressColumn( const wxBitmap &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = wxDVC_DEFAULT_WIDTH,
                    wxAlignment align = wxALIGN_CENTER,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *AppendDateColumn( const wxBitmap &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_ACTIVATABLE, int width = -1,
                    wxAlignment align = wxALIGN_NOT,
                    int flags = wxDATAVIEW_COL_RESIZABLE );
    wxDataViewColumn *AppendBitmapColumn( const wxBitmap &label, unsigned int model_column,
                    wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT, int width = -1,
                    wxAlignment align = wxALIGN_CENTER,
                    int flags = wxDATAVIEW_COL_RESIZABLE );

    virtual bool PrependColumn(%ungc wxDataViewColumn *col );
    virtual bool InsertColumn(unsigned int pos, %ungc wxDataViewColumn *col);
    virtual bool AppendColumn(%ungc wxDataViewColumn *col );

    virtual unsigned int GetColumnCount() const = 0;
    virtual wxDataViewColumn* GetColumn( unsigned int pos ) const = 0;
    virtual int GetColumnPosition(const wxDataViewColumn *column ) const = 0;

    virtual bool DeleteColumn( wxDataViewColumn *column ) = 0;
    virtual bool ClearColumns() = 0;

    void SetExpanderColumn( wxDataViewColumn *col );
    wxDataViewColumn *GetExpanderColumn() const;

    virtual wxDataViewColumn *GetSortingColumn() const = 0;
//    virtual wxVector<wxDataViewColumn *> GetSortingColumns() const;

    virtual bool AllowMultiColumnSort(bool allow);
    virtual bool IsMultiColumnSortAllowed() const;
    virtual void ToggleSortByColumn(int column);

    void SetIndent( int indent );
    int GetIndent() const;

    wxDataViewItem GetCurrentItem() const;
    void SetCurrentItem(const wxDataViewItem& item);

    virtual wxDataViewItem GetTopItem() const;
    virtual int GetCountPerPage() const;

    virtual wxDataViewColumn *GetCurrentColumn() const = 0;

    virtual int GetSelectedItemsCount() const = 0;
    bool HasSelection() const;
    wxDataViewItem GetSelection() const;
    virtual int GetSelections( wxDataViewItemArray & sel ) const = 0;
    virtual void SetSelections( const wxDataViewItemArray & sel ) = 0;
    virtual void Select( const wxDataViewItem & item ) = 0;
    virtual void Unselect( const wxDataViewItem & item ) = 0;
    virtual bool IsSelected( const wxDataViewItem & item ) const = 0;

    virtual void SelectAll() = 0;
    virtual void UnselectAll() = 0;

    void Expand( const wxDataViewItem & item );
    void ExpandAncestors( const wxDataViewItem & item );
    %wxchkver_3_1_5 void ExpandChildren( const wxDataViewItem & item );
    virtual void Collapse( const wxDataViewItem & item ) = 0;
    virtual bool IsExpanded( const wxDataViewItem & item ) const = 0;

    virtual void EnsureVisible( const wxDataViewItem & item, const wxDataViewColumn *column = NULL ) = 0;
//    virtual void HitTest( const wxPoint & point, wxDataViewItem &item, wxDataViewColumn* &column ) const = 0;
    virtual wxRect GetItemRect( const wxDataViewItem & item, const wxDataViewColumn *column = NULL ) const = 0;

    virtual bool SetRowHeight( int rowHeight );

    virtual void EditItem(const wxDataViewItem& item, const wxDataViewColumn *column) = 0;

#if wxUSE_DRAG_AND_DROP
    virtual bool EnableDragSource(const wxDataFormat& format);
    virtual bool EnableDropTarget(const wxDataFormat& format);
#endif // wxUSE_DRAG_AND_DROP

//    virtual bool SetHeaderAttr(const wxItemAttr& attr);
    virtual bool SetAlternateRowColour(const wxColour& colour);

    virtual wxVisualAttributes GetDefaultAttributes() const;

    static wxVisualAttributes GetClassDefaultAttributes(wxWindowVariant variant = wxWINDOW_VARIANT_NORMAL);
};


// class wxDataViewCtrl
class wxDataViewCtrl : public wxDataViewCtrlBase
{
    wxDataViewCtrl(wxWindow *parent, wxWindowID id,
           const wxPoint& pos = wxDefaultPosition,
           const wxSize& size = wxDefaultSize, long style = 0,
           const wxValidator& validator = wxDefaultValidator,
           const wxString& name = wxDataViewCtrlNameStr );

    bool Create(wxWindow *parent, wxWindowID id,
           const wxPoint& pos = wxDefaultPosition,
           const wxSize& size = wxDefaultSize, long style = 0,
           const wxValidator& validator = wxDefaultValidator,
           const wxString& name = wxDataViewCtrlNameStr);

    virtual unsigned int GetColumnCount() const;
    virtual wxDataViewColumn* GetColumn( unsigned int pos ) const;
    virtual int GetColumnPosition( const wxDataViewColumn *column );

    virtual bool DeleteColumn( wxDataViewColumn *column );
    virtual bool ClearColumns();

    virtual wxDataViewColumn *GetSortingColumn() const;
    virtual wxDataViewColumn *GetCurrentColumn() const;

    virtual int GetSelectedItemsCount() const;
    virtual int GetSelections( wxDataViewItemArray & sel ) const;
    virtual void SetSelections( const wxDataViewItemArray & sel );
    virtual void Select( const wxDataViewItem & item );
    virtual void Unselect( const wxDataViewItem & item );
    virtual bool IsSelected( const wxDataViewItem & item ) const;

    virtual void SelectAll();
    virtual void UnselectAll();

    virtual void Collapse( const wxDataViewItem & item );
    virtual bool IsExpanded( const wxDataViewItem & item ) const;

    virtual void EnsureVisible( const wxDataViewItem & item, const wxDataViewColumn *column = NULL );
//    virtual void HitTest( const wxPoint & point, wxDataViewItem &item, wxDataViewColumn* &column );
    virtual wxRect GetItemRect( const wxDataViewItem & item, const wxDataViewColumn *column = NULL );
    virtual void EditItem(const wxDataViewItem& item, const wxDataViewColumn *column);

#if defined(wxHAS_GENERIC_DATAVIEWCTRL)
    // The returned pointer is null if the control has wxDV_NO_HEADER style.
    //
    // This method is only available in the generic versions.
    %wxchkver_3_1_1 wxHeaderCtrl* GenericGetHeader() const;
#endif
};

// class wxDataViewListCtrl
class wxDataViewListCtrl: public wxDataViewCtrl
{
public:
    wxDataViewListCtrl();

    wxDataViewListCtrl( wxWindow *parent, wxWindowID id,
           const wxPoint& pos = wxDefaultPosition,
           const wxSize& size = wxDefaultSize, long style = wxDV_ROW_LINES,
           const wxValidator& validator = wxDefaultValidator );

    bool Create( wxWindow *parent, wxWindowID id,
           const wxPoint& pos = wxDefaultPosition,
           const wxSize& size = wxDefaultSize, long style = wxDV_ROW_LINES,
           const wxValidator& validator = wxDefaultValidator );

    wxDataViewListStore *GetStore();
    const wxDataViewListStore *GetStore() const;

    int ItemToRow(const wxDataViewItem &item) const;
    wxDataViewItem RowToItem(int row) const;

    int GetSelectedRow() const;
    void SelectRow(unsigned int row);
    void UnselectRow(unsigned int row);
    bool IsRowSelected(unsigned int row) const;

    virtual bool AppendColumn( wxDataViewColumn *column );
    void AppendColumn( wxDataViewColumn *column, const wxString &varianttype );

    wxDataViewColumn *AppendTextColumn( const wxString &label,
          wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT,
          int width = -1, wxAlignment align = wxALIGN_LEFT,
          int flags = wxDATAVIEW_COL_RESIZABLE );

    wxDataViewColumn *AppendToggleColumn( const wxString &label,
          wxDataViewCellMode mode = wxDATAVIEW_CELL_ACTIVATABLE,
          int width = -1, wxAlignment align = wxALIGN_LEFT,
          int flags = wxDATAVIEW_COL_RESIZABLE );

    wxDataViewColumn *AppendProgressColumn( const wxString &label,
          wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT,
          int width = -1, wxAlignment align = wxALIGN_LEFT,
          int flags = wxDATAVIEW_COL_RESIZABLE );

    wxDataViewColumn *AppendIconTextColumn( const wxString &label,
          wxDataViewCellMode mode = wxDATAVIEW_CELL_INERT,
          int width = -1, wxAlignment align = wxALIGN_LEFT,
          int flags = wxDATAVIEW_COL_RESIZABLE );

    virtual bool InsertColumn( unsigned int pos, wxDataViewColumn *column );
    void InsertColumn( unsigned int pos, wxDataViewColumn *column, const wxString &varianttype );
    virtual bool PrependColumn( wxDataViewColumn *column );
    void PrependColumn( wxDataViewColumn *column, const wxString &varianttype );
    // void AppendItem( const wxVector<wxVariant> &values, wxUIntPtr data = NULL );
    // void PrependItem( const wxVector<wxVariant> &values, wxUIntPtr data = NULL );
    void InsertItem(unsigned int row, LuaTable wxVariantTable, wxUIntPtr data = NULL );
    void AppendItem(LuaTable wxVariantTable, wxUIntPtr data = NULL );
    void DeleteItem( unsigned int row );
    void DeleteAllItems();
    unsigned int GetItemCount() const;
    wxUIntPtr GetItemData(const wxDataViewItem& item) const;
    // void SetValue( const wxVariant &value, unsigned int row, unsigned int col );
    // void GetValue( wxVariant &value, unsigned int row, unsigned int col );
    void SetTextValue( const wxString &value, unsigned int row, unsigned int col );
    wxString GetTextValue( unsigned int row, unsigned int col ) const;
    void SetToggleValue( bool value, unsigned int row, unsigned int col );
    bool GetToggleValue( unsigned int row, unsigned int col ) const;
    void SetItemData(const wxDataViewItem& item, wxUIntPtr data);
};

// class wxDataViewEvent
class %delete wxDataViewEvent : public wxNotifyEvent
{
    %wxEventType wxEVT_DATAVIEW_SELECTION_CHANGED

    %wxEventType wxEVT_DATAVIEW_ITEM_ACTIVATED
    %wxEventType wxEVT_DATAVIEW_ITEM_COLLAPSED
    %wxEventType wxEVT_DATAVIEW_ITEM_EXPANDED
    %wxEventType wxEVT_DATAVIEW_ITEM_COLLAPSING
    %wxEventType wxEVT_DATAVIEW_ITEM_EXPANDING
    %wxEventType wxEVT_DATAVIEW_ITEM_START_EDITING
    %wxEventType wxEVT_DATAVIEW_ITEM_EDITING_STARTED
    %wxEventType wxEVT_DATAVIEW_ITEM_EDITING_DONE
    %wxEventType wxEVT_DATAVIEW_ITEM_VALUE_CHANGED

    %wxEventType wxEVT_DATAVIEW_ITEM_CONTEXT_MENU

    %wxEventType wxEVT_DATAVIEW_COLUMN_HEADER_CLICK
    %wxEventType wxEVT_DATAVIEW_COLUMN_HEADER_RIGHT_CLICK
    %wxEventType wxEVT_DATAVIEW_COLUMN_SORTED
    %wxEventType wxEVT_DATAVIEW_COLUMN_REORDERED

    %wxEventType wxEVT_DATAVIEW_CACHE_HINT

    %wxEventType wxEVT_DATAVIEW_ITEM_BEGIN_DRAG
    %wxEventType wxEVT_DATAVIEW_ITEM_DROP_POSSIBLE
    %wxEventType wxEVT_DATAVIEW_ITEM_DROP


    wxDataViewEvent();
    wxDataViewEvent(wxEventType evtType,  wxDataViewCtrlBase* dvc, wxDataViewColumn* column);
    wxDataViewEvent(wxEventType evtType,  wxDataViewCtrlBase* dvc, wxDataViewColumn* column, const wxDataViewItem& item);
    wxDataViewEvent(wxEventType evtType, wxDataViewCtrlBase* dvc, const wxDataViewItem& item);

    wxDataViewEvent(const wxDataViewEvent& event);

    wxDataViewItem GetItem() const;
    int GetColumn() const;
    wxDataViewModel* GetModel() const;

//    const wxVariant &GetValue() const;
//    void SetValue( const wxVariant &value );

    bool IsEditCancelled() const;

    wxDataViewColumn *GetDataViewColumn() const;

    wxPoint GetPosition() const;
    void SetPosition( int x, int y );

    // For wxEVT_DATAVIEW_CACHE_HINT
    int GetCacheFrom() const;
    int GetCacheTo() const;
    void SetCache(int from, int to);


#if wxUSE_DRAG_AND_DROP
    void SetDataObject(%ungc wxDataObject *obj);
    wxDataObject *GetDataObject() const;

    void SetDataFormat( const wxDataFormat &format );
    wxDataFormat GetDataFormat() const;
    void SetDataSize( size_t size );
    size_t GetDataSize() const;
    void SetDataBuffer( void* buf );
    void *GetDataBuffer() const;
    void SetDragFlags( int flags );
    int GetDragFlags() const;
    void SetDropEffect( wxDragResult effect );
    wxDragResult GetDropEffect() const;
    void SetProposedDropIndex(int index);
    int GetProposedDropIndex() const;
#endif // wxUSE_DRAG_AND_DROP

    virtual wxEvent *Clone() const;

    void SetColumn( int col );
    void SetEditCancelled();
};

#endif
