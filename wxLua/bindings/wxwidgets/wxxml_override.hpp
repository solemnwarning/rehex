// ----------------------------------------------------------------------------
// Overridden functions for the wxWidgets binding for wxLua
//
// Please keep these functions in the same order as the .i file and in the
// same order as the listing of the functions in that file.
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Overrides for wxxml_xml.i
// ----------------------------------------------------------------------------

%override wxLua_wxXmlNode_constructor4
//     wxXmlNode(wxXmlNode *parent, wxXmlNodeType type, const wxString& name, const wxString& content, wxXmlProperty *props, wxXmlNode *next)
static int LUACALL wxLua_wxXmlNode_constructor4(lua_State *L)
{
    // wxXmlNode next
    wxXmlNode * next = (wxXmlNode *)wxluaT_getuserdatatype(L, 6, wxluatype_wxXmlNode);
    // wxXmlProperty props
    wxXmlProperty * props = (wxXmlProperty *)wxluaT_getuserdatatype(L, 5, wxluatype_wxXmlProperty);
    // const wxString content
    const wxString content = wxlua_getwxStringtype(L, 4);
    // const wxString name
    const wxString name = wxlua_getwxStringtype(L, 3);
    // wxXmlNodeType type
    wxXmlNodeType type = (wxXmlNodeType)wxlua_getenumtype(L, 2);
    // wxXmlNode parent
    wxXmlNode * parent = (wxXmlNode *)wxluaT_getuserdatatype(L, 1, wxluatype_wxXmlNode);
    // call constructor
    wxXmlNode *returns = new wxXmlNode(parent, type, name, content, props, next);
    // add to tracked memory list
    if (parent == NULL)
        wxluaO_addgcobject(L, returns, wxluatype_wxXmlNode);
    // push the constructed class pointer
    wxluaT_pushuserdatatype(L, returns, wxluatype_wxXmlNode);

    return 1;
}
%end

%override wxLua_wxXmlNode_RemoveChild
//     bool RemoveChild(%gc wxXmlNode *child)
static int LUACALL wxLua_wxXmlNode_RemoveChild(lua_State *L)
{
    // wxXmlNode child
    wxXmlNode * child = (wxXmlNode *)wxluaT_getuserdatatype(L, 2, wxluatype_wxXmlNode);
    // get this
    wxXmlNode * self = (wxXmlNode *)wxluaT_getuserdatatype(L, 1, wxluatype_wxXmlNode);
    // call RemoveChild
    bool returns = (self->RemoveChild(child));

    if (returns && !wxluaO_isgcobject(L, child))
        wxluaO_addgcobject(L, child, wxluatype_wxXmlNode);

    // push the result flag
    lua_pushboolean(L, returns);

    return 1;
}
%end

%override wxLua_wxXmlNode_GetPropValPtr
// %rename GetPropValPtr bool GetPropVal(const wxString& propName, wxString *value) const;
static int LUACALL wxLua_wxXmlNode_GetPropValPtr(lua_State *L)
{
    // wxString *value
    wxString value;
    // const wxString& propName
    wxString propName = wxlua_getwxStringtype(L, 2);
    // get this
    wxXmlNode *self = (wxXmlNode *)wxluaT_getuserdatatype(L, 1, wxluatype_wxXmlNode);
    // call GetPropVal
    bool returns = self->GetPropVal(propName, &value);
    // push the result number
    lua_pushboolean(L, returns);
    // push the result string
    wxlua_pushwxString(L, value);
    // return the number of parameters
    return 2;
}
%end
