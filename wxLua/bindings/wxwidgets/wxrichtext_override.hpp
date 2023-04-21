// ----------------------------------------------------------------------------
// Overridden functions for the wxWidgets binding for wxLua
//
// Please keep these functions in the same order as the .i file and in the
// same order as the listing of the functions in that file.
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Overrides for wxrichtext_richtext.i
// ----------------------------------------------------------------------------

%override wxLua_wxRichTextParagraphLayoutBox_GetFloatingObjects
// C++: bool GetFloatingObjects(wxRichTextObjectList& objects) const;
// Lua: %override [bool, wxRichTextObjectList]GetFloatingObjects();
static int LUACALL wxLua_wxRichTextParagraphLayoutBox_GetFloatingObjects(lua_State *L)
{
    // get this
    wxRichTextParagraphLayoutBox * self = (wxRichTextParagraphLayoutBox *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRichTextParagraphLayoutBox);
    // allocate a new object
    wxRichTextObjectList *objects = new wxRichTextObjectList();
    // call GetFloatingObjects
    bool returns = (self->GetFloatingObjects(*objects));
    // push the result flag
    lua_pushboolean(L, returns);
    // add the new object to the tracked memory list
    wxluaO_addgcobject(L, objects, wxluatype_wxRichTextObjectList);
    // push the result datatype
    wxluaT_pushuserdatatype(L, objects, wxluatype_wxRichTextObjectList);

    return 2;
}
%end

%override wxLua_wxRichTextParagraphLayoutBox_GetStyle
// C++: bool GetStyle(long position, wxRichTextAttr& style);
// Lua: %override [bool, wxRichTextAttr] GetStyle(long position)
static int LUACALL wxLua_wxRichTextParagraphLayoutBox_GetStyle(lua_State *L)
{
    // long position
    long position = (long)wxlua_getnumbertype(L, 2);
    // get this
    wxRichTextParagraphLayoutBox * self = (wxRichTextParagraphLayoutBox *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRichTextParagraphLayoutBox);
    // allocate a new object
    wxRichTextAttr *stylep = new wxRichTextAttr();
    // call GetStyle
    bool returns = (self->GetStyle(position, *stylep));
    // push the result flag
    lua_pushboolean(L, returns);
    // add the new object to the tracked memory list
    wxluaO_addgcobject(L, stylep, wxluatype_wxRichTextAttr);
    // push the result datatype
    wxluaT_pushuserdatatype(L, stylep, wxluatype_wxRichTextAttr);

    return 2;
}
%end

%override wxLua_wxRichTextParagraphLayoutBox_GetStyleForRange
// C++: bool GetStyleForRange(const wxRichTextRange& range, wxRichTextAttr& style);
// Lua: %override [bool, wxRichTextAttr] GetStyleForRange(const wxRichTextRange& range);
static int LUACALL wxLua_wxRichTextParagraphLayoutBox_GetStyleForRange(lua_State *L)
{
    // const wxRichTextRange range
    const wxRichTextRange * range = (const wxRichTextRange *)wxluaT_getuserdatatype(L, 2, wxluatype_wxRichTextRange);
    // get this
    wxRichTextParagraphLayoutBox * self = (wxRichTextParagraphLayoutBox *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRichTextParagraphLayoutBox);
    // allocate a new object
    wxRichTextAttr *stylep = new wxRichTextAttr();
    // call GetStyleForRange
    bool returns = (self->GetStyleForRange(*range, *stylep));
    // push the result flag
    lua_pushboolean(L, returns);
    // add the new object to the tracked memory list
    wxluaO_addgcobject(L, stylep, wxluatype_wxRichTextAttr);
    // push the result datatype
    wxluaT_pushuserdatatype(L, stylep, wxluatype_wxRichTextAttr);

    return 2;
}
%end

%override wxLua_wxRichTextParagraphLayoutBox_GetUncombinedStyle
// C++: bool GetUncombinedStyle(long position, wxRichTextAttr& style);
// Lua: %override [bool, wxRichTextAttr] GetUncombinedStyle(long position);
static int LUACALL wxLua_wxRichTextParagraphLayoutBox_GetUncombinedStyle(lua_State *L)
{
    // long position
    long position = (long)wxlua_getnumbertype(L, 2);
    // get this
    wxRichTextParagraphLayoutBox * self = (wxRichTextParagraphLayoutBox *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRichTextParagraphLayoutBox);
    // allocate a new object
    wxRichTextAttr *stylep = new wxRichTextAttr();
    // call GetUncombinedStyle
    bool returns = (self->GetUncombinedStyle(position, *stylep));
    // push the result flag
    lua_pushboolean(L, returns);
    // add the new object to the tracked memory list
    wxluaO_addgcobject(L, stylep, wxluatype_wxRichTextAttr);
    // push the result datatype
    wxluaT_pushuserdatatype(L, stylep, wxluatype_wxRichTextAttr);

    return 2;
}
%end

%override wxLua_wxRichTextFieldTypeHashMap_iterator_Get_first
//  For implementation of HashMap related methods, see wxImageHistogram in wxcore_override.hpp.i
//     wxString first;
static int LUACALL wxLua_wxRichTextFieldTypeHashMap_iterator_Get_first(lua_State *L)
{
    // get this
    wxRichTextFieldTypeHashMap::iterator *self = (wxRichTextFieldTypeHashMap::iterator *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRichTextFieldTypeHashMap_iterator);
    // push the result string
    wxlua_pushwxString(L, (*self)->first); // *** need to cast self to object from pointer
    // return the number of values
    return 1;
}
%end

%override wxLua_wxRichTextFieldTypeHashMap_iterator_Get_second
//     wxRichTextFieldType *second;
static int LUACALL wxLua_wxRichTextFieldTypeHashMap_iterator_Get_second(lua_State *L)
{
    // get this
    wxRichTextFieldTypeHashMap::iterator *self = (wxRichTextFieldTypeHashMap::iterator *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRichTextFieldTypeHashMap_iterator);
    // push the result datatype
    wxluaT_pushuserdatatype(L, (*self)->second, wxluatype_wxRichTextFieldType); // *** need to cast self to object from pointer
    // return the number of values
    return 1;
}
%end

%override wxLua_wxRichTextFieldTypeHashMap_iterator_Set_first
//     wxString first;
static int LUACALL wxLua_wxRichTextFieldTypeHashMap_iterator_Set_first(lua_State *L)
{
    wxlua_argerrormsg(L, wxT("You cannot set the first element of a wxHashMap. do not use wxRichTextFieldTypeHashMap::iterator::SetFirst()."));
    return 0;
}
%end

%override wxLua_wxRichTextFieldTypeHashMap_iterator_Set_second
//     wxRichTextFieldType *second;
static int LUACALL wxLua_wxRichTextFieldTypeHashMap_iterator_Set_second(lua_State *L)
{
    // get the data type value
    wxRichTextFieldType* val = (wxRichTextFieldType*)wxluaT_getuserdatatype(L, 2, wxluatype_wxRichTextFieldType);
    // get this
    wxRichTextFieldTypeHashMap::iterator *self = (wxRichTextFieldTypeHashMap::iterator *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRichTextFieldTypeHashMap_iterator);
    (*self)->second = val; // *** need to cast self to object from pointer
    // return the number of values
    return 0;
}
%end

%override wxLua_wxRichTextCtrl_DeleteSelectedContent
// C++: bool DeleteSelectedContent(long* newPos= NULL);
// Lua: %override [bool, long] DeleteSelectedContent();
static int LUACALL wxLua_wxRichTextCtrl_DeleteSelectedContent(lua_State *L)
{
    // long *newPos = NULL
    long newPos;
    // get this
    wxRichTextCtrl * self = (wxRichTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRichTextCtrl);
    // call DeleteSelectedContent
    bool returns = (self->DeleteSelectedContent(&newPos));
    // push the result flag
    lua_pushboolean(L, returns);
    // push the newPos number
#if LUA_VERSION_NUM >= 503
if ((double)(lua_Integer)newPos == (double)newPos) {
    // Exactly representable as lua_Integer
    lua_pushinteger(L, newPos);
} else
#endif
{
    lua_pushnumber(L, newPos);
}

    return 2;
}
%end

%override wxLua_wxRichTextCtrl_GetCaretPositionForIndex
// C++: bool GetCaretPositionForIndex(long position, wxRect& rect, wxRichTextParagraphLayoutBox* container = NULL);
// Lua: %override [bool, wxRect] GetCaretPositionForIndex(long position, wxRect& rect, wxRichTextParagraphLayoutBox* container = NULL);
static int LUACALL wxLua_wxRichTextCtrl_GetCaretPositionForIndex(lua_State *L)
{
    // get number of arguments
    int argCount = lua_gettop(L);
    // wxRichTextParagraphLayoutBox container = NULL
    wxRichTextParagraphLayoutBox * container = (argCount >= 3 ? (wxRichTextParagraphLayoutBox *)wxluaT_getuserdatatype(L, 3, wxluatype_wxRichTextParagraphLayoutBox) : NULL);
    // long position
    long position = (long)wxlua_getnumbertype(L, 2);
    // get this
    wxRichTextCtrl * self = (wxRichTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRichTextCtrl);
    // allocate a new object
    wxRect *rectp = new wxRect();
    // call GetCaretPositionForIndex
    bool returns = (self->GetCaretPositionForIndex(position, *rectp, container));
    // push the result flag
    lua_pushboolean(L, returns);
    // add the new object to the tracked memory list
    wxluaO_addgcobject(L, rectp, wxluatype_wxRect);
    // push the result datatype
    wxluaT_pushuserdatatype(L, rectp, wxluatype_wxRect);

    return 2;
}
%end

%override wxLua_wxRichTextCtrl_GetStyle1
// C++: bool GetStyle(long position, wxRichTextAttr& style, wxRichTextParagraphLayoutBox* container);
// Lua: [bool, wxRichTextAttr] GetStyle(long position, wxRichTextParagraphLayoutBox* container);
static int LUACALL wxLua_wxRichTextCtrl_GetStyle1(lua_State *L)
{
    // wxRichTextParagraphLayoutBox container
    wxRichTextParagraphLayoutBox * container = (wxRichTextParagraphLayoutBox *)wxluaT_getuserdatatype(L, 3, wxluatype_wxRichTextParagraphLayoutBox);
    // long position
    long position = (long)wxlua_getnumbertype(L, 2);
    // get this
    wxRichTextCtrl * self = (wxRichTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRichTextCtrl);
    // allocate a new object
    wxRichTextAttr *stylep = new wxRichTextAttr();
    //  Call GetStyle
    bool returns = self->GetStyle(position, *stylep, container);
    // push the result flag
    lua_pushboolean(L, returns);
    // add the new object to the tracked memory list
    wxluaO_addgcobject(L, stylep, wxluatype_wxRichTextAttr);
    // push the result datatype
    wxluaT_pushuserdatatype(L, stylep, wxluatype_wxRichTextAttr);

    return 2;
}
%end

%override wxLua_wxRichTextCtrl_GetStyle
// C++: bool GetStyle(long position, wxRichTextAttr& style);
// Lua: [bool, wxRichTextAttr] GetStyle(long position);
static int LUACALL wxLua_wxRichTextCtrl_GetStyle(lua_State *L)
{
    // long position
    long position = (long)wxlua_getnumbertype(L, 2);
    // get this
    wxRichTextCtrl * self = (wxRichTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRichTextCtrl);
    // allocate a new object
    wxRichTextAttr *stylep = new wxRichTextAttr();
    //  Call GetStyle
    bool returns = self->GetStyle(position, *stylep);
    // push the result flag
    lua_pushboolean(L, returns);
    // add the new object to the tracked memory list
    wxluaO_addgcobject(L, stylep, wxluatype_wxRichTextAttr);
    // push the result datatype
    wxluaT_pushuserdatatype(L, stylep, wxluatype_wxRichTextAttr);

    return 2;
}
%end

%override wxLua_wxRichTextCtrl_GetStyleForRange1
// C++: bool GetStyleForRange(const wxRichTextRange& range, wxRichTextAttr& style, wxRichTextParagraphLayoutBox* container);
// Lua: [bool, wxRichTextAttr] GetStyleForRange(const wxRichTextRange& range, wxRichTextParagraphLayoutBox* container);
static int LUACALL wxLua_wxRichTextCtrl_GetStyleForRange1(lua_State *L)
{
    // wxRichTextParagraphLayoutBox container
    wxRichTextParagraphLayoutBox * container = (wxRichTextParagraphLayoutBox *)wxluaT_getuserdatatype(L, 3, wxluatype_wxRichTextParagraphLayoutBox);
    // const wxRichTextRange range
    const wxRichTextRange * range = (const wxRichTextRange *)wxluaT_getuserdatatype(L, 2, wxluatype_wxRichTextRange);
    // get this
    wxRichTextCtrl * self = (wxRichTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRichTextCtrl);
    // allocate a new object
    wxRichTextAttr *stylep = new wxRichTextAttr();
    // call GetStyleForRange
    bool returns = (self->GetStyleForRange(*range, *stylep, container));
    // push the result flag
    lua_pushboolean(L, returns);
    // add the new object to the tracked memory list
    wxluaO_addgcobject(L, stylep, wxluatype_wxRichTextAttr);
    // push the result datatype
    wxluaT_pushuserdatatype(L, stylep, wxluatype_wxRichTextAttr);

    return 2;
}
%end

%override wxLua_wxRichTextCtrl_GetStyleForRange
// C++: bool GetStyleForRange(const wxRichTextRange& range, wxRichTextAttr& style);
// Lua: [bool, wxRichTextAttr] GetStyleForRange(const wxRichTextRange& range);
static int LUACALL wxLua_wxRichTextCtrl_GetStyleForRange(lua_State *L)
{
    // const wxRichTextRange range
    const wxRichTextRange * range = (const wxRichTextRange *)wxluaT_getuserdatatype(L, 2, wxluatype_wxRichTextRange);
    // get this
    wxRichTextCtrl * self = (wxRichTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRichTextCtrl);
    // allocate a new object
    wxRichTextAttr *stylep = new wxRichTextAttr();
    // call GetStyleForRange
    bool returns = (self->GetStyleForRange(*range, *stylep));
    // push the result flag
    lua_pushboolean(L, returns);
    // add the new object to the tracked memory list
    wxluaO_addgcobject(L, stylep, wxluatype_wxRichTextAttr);
    // push the result datatype
    wxluaT_pushuserdatatype(L, stylep, wxluatype_wxRichTextAttr);

    return 2;
}
%end

%override wxLua_wxRichTextCtrl_GetUncombinedStyle1
// C++: bool GetUncombinedStyle(long position, wxRichTextAttr& style, wxRichTextParagraphLayoutBox* container);
// Lua: [bool, wxRichTextAttr] GetUncombinedStyle(long position, wxRichTextParagraphLayoutBox* container);
static int LUACALL wxLua_wxRichTextCtrl_GetUncombinedStyle1(lua_State *L)
{
    // wxRichTextParagraphLayoutBox container
    wxRichTextParagraphLayoutBox * container = (wxRichTextParagraphLayoutBox *)wxluaT_getuserdatatype(L, 3, wxluatype_wxRichTextParagraphLayoutBox);
    // long position
    long position = (long)wxlua_getnumbertype(L, 2);
    // get this
    wxRichTextCtrl * self = (wxRichTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRichTextCtrl);
    // allocate a new object
    wxRichTextAttr *stylep = new wxRichTextAttr();
    // call GetUncombinedStyle
    bool returns = (self->GetUncombinedStyle(position, *stylep, container));
    // push the result flag
    lua_pushboolean(L, returns);
    // add the new object to the tracked memory list
    wxluaO_addgcobject(L, stylep, wxluatype_wxRichTextAttr);
    // push the result datatype
    wxluaT_pushuserdatatype(L, stylep, wxluatype_wxRichTextAttr);

    return 2;
}

%end

%override wxLua_wxRichTextCtrl_GetUncombinedStyle
// C++: bool GetUncombinedStyle(long position, wxRichTextAttr& style);
// Lua: [bool, wxRichTextAttr] GetUncombinedStyle(long position);
static int LUACALL wxLua_wxRichTextCtrl_GetUncombinedStyle(lua_State *L)
{
    // long position
    long position = (long)wxlua_getnumbertype(L, 2);
    // get this
    wxRichTextCtrl * self = (wxRichTextCtrl *)wxluaT_getuserdatatype(L, 1, wxluatype_wxRichTextCtrl);
    // allocate a new object
    wxRichTextAttr *stylep = new wxRichTextAttr();
    // call GetUncombinedStyle
    bool returns = (self->GetUncombinedStyle(position, *stylep));
    // push the result flag
    lua_pushboolean(L, returns);
    // add the new object to the tracked memory list
    wxluaO_addgcobject(L, stylep, wxluatype_wxRichTextAttr);
    // push the result datatype
    wxluaT_pushuserdatatype(L, stylep, wxluatype_wxRichTextAttr);

    return 2;
}
%end

// ----------------------------------------------------------------------------
// Overrides for wxrichtext_xml.i
// ----------------------------------------------------------------------------

%override wxLua_wxRichTextXMLHelper_OutputString
//     static void OutputString(wxOutputStream& stream, const wxString& str); // , wxMBConv *convMem, wxMBConv *convFile);
static int LUACALL wxLua_wxRichTextXMLHelper_OutputString(lua_State *L)
{
    // const wxString str
    const wxString str = wxlua_getwxStringtype(L, 2);
    // wxOutputStream stream
    wxOutputStream * stream = (wxOutputStream *)wxluaT_getuserdatatype(L, 1, wxluatype_wxOutputStream);
    // call OutputString
    wxRichTextXMLHelper::OutputString(*stream, str, &wxConvUTF8, &wxConvUTF8);  //  Explicitly designate UTF-8

    return 0;
}
%end

%override wxLua_wxRichTextXMLHelper_OutputStringEnt
//     static void OutputStringEnt(wxOutputStream& stream, const wxString& str); // , wxMBConv *convMem, wxMBConv *convFile);
static int LUACALL wxLua_wxRichTextXMLHelper_OutputStringEnt(lua_State *L)
{
    // const wxString str
    const wxString str = wxlua_getwxStringtype(L, 2);
    // wxOutputStream stream
    wxOutputStream * stream = (wxOutputStream *)wxluaT_getuserdatatype(L, 1, wxluatype_wxOutputStream);
    // call OutputStringEnt
    wxRichTextXMLHelper::OutputStringEnt(*stream, str, &wxConvUTF8, &wxConvUTF8);  //  Explicitly designate UTF-8

    return 0;
}
%end

