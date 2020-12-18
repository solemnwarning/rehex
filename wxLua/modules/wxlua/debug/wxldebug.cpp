/////////////////////////////////////////////////////////////////////////////
// Name:        wxLuaDebug.cpp
// Purpose:     Debugging I/O functions for wxLua
// Author:      J. Winwood, Ray Gilbert, John Labenski
// Created:     May 2002
// Copyright:   (c) 2012 John Labenski, 2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/wx.h"
#endif

#include "wxlua/debug/wxldebug.h"
#include "wxlua/wxlcallb.h"

wxLuaDebugData wxNullLuaDebugData(false);

// ----------------------------------------------------------------------------
// wxLuaDebugItem
// ----------------------------------------------------------------------------
wxLuaDebugItem::wxLuaDebugItem(const wxString &itemKey, int itemKeyType,
                               const wxString &itemValue, int itemValueType,
                               const wxString &itemSource,
                               int lua_ref, int idx, int flag)
                   :m_itemKey(itemKey), m_itemKeyType(itemKeyType),
                    m_itemValue(itemValue), m_itemValueType(itemValueType),
                    m_itemSource(itemSource),
                    m_lua_ref(lua_ref), m_index(idx), m_flag(flag)
{
}

wxLuaDebugItem::wxLuaDebugItem(const wxLuaDebugItem &dataItem)
               :m_itemKey(dataItem.m_itemKey), m_itemKeyType(dataItem.m_itemKeyType),
                m_itemValue(dataItem.m_itemValue), m_itemValueType(dataItem.m_itemValueType),
                m_itemSource(dataItem.m_itemSource),
                m_lua_ref(dataItem.m_lua_ref), m_index(dataItem.m_index),
                m_flag(dataItem.m_flag)
{
}

bool wxLuaDebugItem::GetRefPtr(wxUIntPtr& ptr) const
{
    bool key_ref = GetFlagBit(WXLUA_DEBUGITEM_KEY_REF);
    bool val_ref = GetFlagBit(WXLUA_DEBUGITEM_VALUE_REF);

    // sanity checks
    wxCHECK_MSG((key_ref || val_ref), false, wxT("wxLuaDebugItem has neither key or value reference"));
    wxCHECK_MSG(!(key_ref && val_ref), false, wxT("wxLuaDebugItem has both key and value reference"));

    return wxString(key_ref ? m_itemKey: m_itemValue).BeforeFirst(wxT(' ')).ToULongLong((wxULongLong_t*)&ptr, 16);
}

// ----------------------------------------------------------------------------
// wxLuaDebugData - Debug Info sent via socket to debugger client
// ----------------------------------------------------------------------------

class wxLuaDebugDataRefData : public wxObjectRefData
{
public:
    wxLuaDebugDataRefData() : m_dataArray(wxLuaDebugData::SortFunction) {}

    virtual ~wxLuaDebugDataRefData()
    {
        size_t idx, count = m_dataArray.GetCount();
        for (idx = 0; idx < count; ++idx)
        {
            const wxLuaDebugItem *pData = m_dataArray.Item(idx);
            delete pData;
        }
    }

    wxLuaDebugItemArray m_dataArray;
};

#define M_DEBUGREFDATA ((wxLuaDebugDataRefData*)m_refData)

wxLuaDebugData::wxLuaDebugData(bool create) : wxObject()
{
    if (create)
        m_refData = new wxLuaDebugDataRefData;
}

wxLuaDebugItemArray* wxLuaDebugData::GetArray()
{
    wxCHECK_MSG(M_DEBUGREFDATA != NULL, NULL, wxT("Invalid ref data"));
    return &(M_DEBUGREFDATA->m_dataArray);
}
const wxLuaDebugItemArray* wxLuaDebugData::GetArray() const
{
    wxCHECK_MSG(M_DEBUGREFDATA != NULL, NULL, wxT("Invalid ref data"));
    return &(M_DEBUGREFDATA->m_dataArray);
}

size_t wxLuaDebugData::GetCount() const
{
    wxCHECK_MSG(M_DEBUGREFDATA != NULL, 0, wxT("Invalid ref data"));
    return M_DEBUGREFDATA->m_dataArray.GetCount();
}
wxLuaDebugItem* wxLuaDebugData::Item(size_t index) const
{
    wxCHECK_MSG(M_DEBUGREFDATA != NULL, NULL, wxT("Invalid ref data"));
    return M_DEBUGREFDATA->m_dataArray.Item(index);
}
void wxLuaDebugData::Add(wxLuaDebugItem* item)
{
    wxCHECK_RET(M_DEBUGREFDATA != NULL, wxT("Invalid ref data"));
    wxCHECK_RET(item != NULL, wxT("Invalid wxLuaDebugItem"));
    M_DEBUGREFDATA->m_dataArray.Add(item);
}

wxLuaDebugData wxLuaDebugData::Copy() const
{
    wxCHECK_MSG(M_DEBUGREFDATA != NULL, wxNullLuaDebugData, wxT("Invalid ref data"));

    wxLuaDebugData copyData(true);

    size_t idx, count = GetCount();
    for (idx = 0; idx < count; ++idx)
    {
        const wxLuaDebugItem *pOldData = M_DEBUGREFDATA->m_dataArray.Item(idx);
        if (pOldData != NULL)
            copyData.Add(new wxLuaDebugItem(*pOldData));
    }

    return copyData;
}

int wxLuaDebugData::SortFunction(wxLuaDebugItem *elem1, wxLuaDebugItem *elem2 )
{
    int ret = 0;

    long l1 = 0, l2 = 0;

    // Don't sort numbers by their string representation, but by their value
    if ((elem1->m_itemKeyType == WXLUA_TNUMBER) &&
        (elem2->m_itemKeyType == WXLUA_TNUMBER) &&
        elem1->m_itemKey.BeforeFirst(wxT(' ')).ToLong(&l1) &&
        elem2->m_itemKey.BeforeFirst(wxT(' ')).ToLong(&l2))
        ret = l1 - l2;
    else
        ret = elem1->m_itemKey.Cmp(elem2->m_itemKey);

    if (ret == 0) // can be true for unnamed "(*temporary)" vars
    {
        ret = elem1->m_itemKeyType - elem2->m_itemKeyType;

        if (ret == 0)
        {
            ret = elem1->m_itemValueType - elem2->m_itemValueType;

            if (ret == 0)
            {
                ret = elem1->m_itemValue.Cmp(elem2->m_itemValue);

                if (ret == 0)
                    ret = int(elem2->GetFlagBit(WXLUA_DEBUGITEM_KEY_REF)) -
                          int(elem1->GetFlagBit(WXLUA_DEBUGITEM_KEY_REF));
            }
        }
    }

    return ret;
}

int wxLuaDebugData::EnumerateStack(lua_State* L)
{
    wxCHECK_MSG(L, 0, wxT("Invalid lua_State"));
    wxCHECK_MSG(M_DEBUGREFDATA != NULL, 0, wxT("Invalid ref data"));

    lua_Debug luaDebug = INIT_LUA_DEBUG;
    int       stack_frame = 0;
    int       count = 0;

    while (lua_getstack(L, stack_frame, &luaDebug) != 0)
    {
        if (lua_getinfo(L, "Sln", &luaDebug))
        {
            //wxPrintf(wxT("%s\n"), lua_Debug_to_wxString(luaDebug).c_str());

            // skip stack frames that do not have line number, always add first
            int  currentLine = luaDebug.currentline;
            if ((count == 0) || (currentLine != -1))
            {
                wxString name;
                wxString source(lua2wx(luaDebug.source));

                if (currentLine == -1)
                    currentLine = 0;

                if (luaDebug.name != NULL)
                    name.Printf(_("function %s line %d"), lua2wx(luaDebug.name).c_str(), currentLine);
                else
                    name.Printf(_("line %d"), currentLine);

                Add(new wxLuaDebugItem(name, WXLUA_TNONE, wxEmptyString, WXLUA_TNONE, source, LUA_NOREF, stack_frame, WXLUA_DEBUGITEM_LOCALS));
                ++count;
            }
        }

        ++stack_frame;
    }

    return count;
}

int wxLuaDebugData::EnumerateStackEntry(lua_State* L, int stack_frame, wxArrayInt& references)
{
    wxCHECK_MSG(L, 0, wxT("Invalid lua_State"));
    wxCHECK_MSG(M_DEBUGREFDATA != NULL, 0, wxT("Invalid ref data"));

    lua_Debug luaDebug = INIT_LUA_DEBUG;
    int count = 0;

    if (lua_getstack(L, stack_frame, &luaDebug) != 0)
    {
        int stack_idx  = 1;
        wxString name(lua2wx(lua_getlocal(L, &luaDebug, stack_idx)));

        while (!name.IsEmpty())
        {
            //wxPrintf(wxT("%s lua_getlocal :%s\n"), lua_Debug_to_wxString(luaDebug).c_str(), name.c_str());

            int wxl_valuetype = WXLUA_TNONE;
            wxString value;
            wxString source(lua2wx(luaDebug.source));

            int lua_value_type = GetTypeValue(L, -1, &wxl_valuetype, value);

            int val_flag_type = 0;
            int val_ref = LUA_NOREF;

            if (lua_value_type == LUA_TTABLE)
            {
                val_ref = RefTable(L, -1, &val_flag_type, WXLUA_DEBUGITEM_VALUE_REF, references);
            }
            else if (lua_value_type == LUA_TUSERDATA)
            {
                if (lua_getmetatable(L, -1)) // doesn't push anything if nil
                {
                    val_ref = RefTable(L, -1, &val_flag_type, WXLUA_DEBUGITEM_VALUE_REF, references);
                    lua_pop(L, 1);
                }
            }

            Add(new wxLuaDebugItem(name, WXLUA_TNONE, value, wxl_valuetype, source, val_ref, 0, val_flag_type));
            ++count;

            lua_pop(L, 1); // remove variable value

            name = lua2wx(lua_getlocal(L, &luaDebug, ++stack_idx));
        }
    }

    return count;
}

wxString wxLuaBindClassString(wxLuaBindClass* wxlClass)
{
    wxCHECK_MSG(wxlClass, wxEmptyString, wxT("Invalid wxLuaBindClass"));
    wxString baseClasses;
    if (wxlClass->baseclassNames)
    {
        for (size_t i = 0; wxlClass->baseclassNames[i]; ++i)
            baseClasses += lua2wx(wxlClass->baseclassNames[i]) + wxT(",");
    }

    return wxString::Format(wxT(" (%s, wxluatype=%d, classinfo=%s, baseclass=%s, methods=%d, enums=%d)"),
                            lua2wx(wxlClass->name).c_str(), *wxlClass->wxluatype,
                            wxString(wxlClass->classInfo ? wxlClass->classInfo->GetClassName() : wxEmptyString).c_str(),
                            baseClasses.c_str(),
                            wxlClass->wxluamethods_n, wxlClass->enums_n);
}

int wxLuaDebugData::EnumerateTable(lua_State* L, int tableRef, int nIndex, wxArrayInt& references)
{
    wxCHECK_MSG(L, 0, wxT("Invalid lua_State"));
    wxCHECK_MSG(M_DEBUGREFDATA != NULL, 0, wxT("Invalid ref data"));

    int count = 0;

    int wxl_keytype   = WXLUA_TNONE;
    int wxl_valuetype = WXLUA_TNONE;
    wxString value;
    wxString name;

    if (tableRef == LUA_GLOBALSINDEX)
    {
        lua_pushglobaltable(L);
        GetTypeValue(L, -1, &wxl_valuetype, value);

        int flag_type = 0;
        int val_ref = RefTable(L, -1, &flag_type, WXLUA_DEBUGITEM_VALUE_REF, references);
        lua_pop(L, 1); // pop globals table

        Add(new wxLuaDebugItem(wxT("Globals"), WXLUA_TNONE, value, WXLUA_TTABLE, wxEmptyString, val_ref, 0, flag_type));
    }
#if LUA_VERSION_NUM < 502
    // LUA_ENVIRONINDEX is no longer in 5.2
    else if (tableRef == LUA_ENVIRONINDEX)
    {
        lua_pushvalue(L, LUA_ENVIRONINDEX);
        GetTypeValue(L, -1, &wxl_valuetype, value);

        int flag_type = 0;
        int val_ref = RefTable(L, -1, &flag_type, WXLUA_DEBUGITEM_VALUE_REF, references);
        lua_pop(L, 1); // pop environment table

        Add(new wxLuaDebugItem(wxT("Environment"), WXLUA_TNONE, value, WXLUA_TTABLE, wxEmptyString, val_ref, 0, flag_type));
    }
#endif // LUA_VERSION_NUM < 502
    else if (tableRef == LUA_REGISTRYINDEX)
    {
        lua_pushvalue(L, LUA_REGISTRYINDEX);
        GetTypeValue(L, -1, &wxl_valuetype, value);

        int flag_type = 0;
        int val_ref = RefTable(L, -1, &flag_type, WXLUA_DEBUGITEM_VALUE_REF, references);
        lua_pop(L, 1); // pop registry table

        Add(new wxLuaDebugItem(wxT("Registry"), WXLUA_TNONE, value, WXLUA_TTABLE, wxEmptyString, val_ref, 0, flag_type));
    }
    else
    {
        // push the table onto the stack to iterate through
        if (wxluaR_getref(L, tableRef, &wxlua_lreg_debug_refs_key))
        {
            if (lua_isnil(L, -1))
            {
                // assert so we don't crash mysteriously inside Lua on nil
                lua_pop(L, 1); // pop nil
                wxFAIL_MSG(wxT("Invalid wxLua debug reference"));
                return count;
            }

            // Check to see if this is a wxLua LUA_REGISTRYINDEX table
            void *lightuserdata_reg_key = NULL;
            lua_pushlightuserdata(L, &wxlua_lreg_regtable_key); // push key
            lua_rawget(L, LUA_REGISTRYINDEX);
            lua_pushvalue(L, -2); // push value (table we're iterating)
            lua_rawget(L, -2);
            lightuserdata_reg_key = lua_touserdata(L, -1); // returns NULL for nil
            lua_pop(L, 2); // pop wxlua_lreg_regtable_key table and (nil or lightuserdata)

            // Check if this table/userdata has a metatable
            if (lua_getmetatable(L, -1)) // if no metatable then nothing is pushed
            {
                // get the type and value
                GetTypeValue(L, -1, &wxl_valuetype, value);

                int flag_type = 0;
                int val_ref = RefTable(L, -1, &flag_type, WXLUA_DEBUGITEM_VALUE_REF, references);

                // leading space so it's first when sorted
                Add(new wxLuaDebugItem(wxT(" __metatable"), WXLUA_TTABLE, value, wxl_valuetype, wxEmptyString, val_ref, nIndex, flag_type));
                ++count;

                lua_pop(L, 1); // pop metatable
            }

            // start iterating
            if (lua_istable(L, -1))
            {
            lua_pushnil(L);
            while (lua_next(L, -2) != 0)
            {
                // value at -1, key at -2, table at -3

                // get the key type and value
                int lua_key_type = GetTypeValue(L, -2, &wxl_keytype, name);
                // get the value type and value
                int lua_value_type = GetTypeValue(L, -1, &wxl_valuetype, value);

                // Handle items within the wxLua LUA_REGISTRYINDEX tables to give more information
                if (lightuserdata_reg_key != NULL)
                {
                    if (lightuserdata_reg_key == &wxlua_lreg_types_key)
                    {
                        value += wxString::Format(wxT(" (%s)"), wxluaT_typename(L, (int)lua_tonumber(L, -2)).c_str());
                    }
                    else if (lightuserdata_reg_key == &wxlua_lreg_classes_key)
                    {
                        wxLuaBindClass* wxlClass = (wxLuaBindClass*)lua_touserdata(L, -1);
                        value += wxLuaBindClassString(wxlClass);
                    }
                    else if (lightuserdata_reg_key == &wxlua_lreg_wxluabindings_key)
                    {
                        wxLuaBinding* binding = (wxLuaBinding*)lua_touserdata(L, -2);
                        name = wxString::Format(wxT("wxLuaBinding(%s) -> %s"), name.c_str(), binding->GetBindingName().c_str());
                        value += wxT(" = ") + binding->GetLuaNamespace();
                    }
                    else if (lightuserdata_reg_key == &wxlua_lreg_evtcallbacks_key)
                    {
                        wxLuaEventCallback* wxlCallback = (wxLuaEventCallback*)lua_touserdata(L, -2);
                        wxCHECK_MSG(wxlCallback, count, wxT("Invalid wxLuaEventCallback"));

                        wxString s(wxlCallback->GetInfo());
                        name  = s.BeforeFirst(wxT('|'));
                        value = s.AfterFirst(wxT('|'));
                    }
                    else if (lightuserdata_reg_key == &wxlua_lreg_windestroycallbacks_key)
                    {
                        // only handle t[wxWindow*] = wxLuaWinDestroyCallback*
                        wxLuaWinDestroyCallback* wxlDestroyCallBack = (wxLuaWinDestroyCallback*)lua_touserdata(L, -1);
                        wxCHECK_MSG(wxlDestroyCallBack, count, wxT("Invalid wxLuaWinDestroyCallback"));

                        wxString s(wxlDestroyCallBack->GetInfo());
                        name  = s.BeforeFirst(wxT('|'));
                        value = s.AfterFirst(wxT('|'));
                    }
                    else if (lightuserdata_reg_key == &wxlua_lreg_topwindows_key)
                    {
                        wxWindow* win = (wxWindow*)lua_touserdata(L, -2);
                        name += wxT(" ") + wxString(win->GetClassInfo()->GetClassName());
                    }
                    else if (lightuserdata_reg_key == &wxlua_lreg_gcobjects_key)
                    {
                        int wxl_type_ = (int)lua_tonumber(L, -1);
                        name = wxString::Format(wxT("%s(%s)"), wxluaT_typename(L, wxl_type_).c_str(), name.c_str());
                    }
                    else if (lightuserdata_reg_key == &wxlua_lreg_weakobjects_key)
                    {
                        wxString names_weak;

                        // iterate the table of userdata
                        lua_pushnil(L);
                        while (lua_next(L, -2) != 0)
                        {
                            // value = -1, key = -2, table = -3
                            int wxl_type_weak = (int)lua_tonumber(L, -2);
                            if (!names_weak.IsEmpty()) names_weak += wxT(", ");
                            names_weak += wxString::Format(wxT("%s(%d)"), wxluaT_typename(L, wxl_type_weak).c_str(), wxl_type_weak);
                            lua_pop(L, 1); // pop value, lua_next will pop key at end
                        }

                        name = wxString::Format(wxT("%s (%s)"), names_weak.c_str(), name.c_str());
                    }
                }

                // For these keys we know what is in the value to give more information
                if (lua_key_type == LUA_TLIGHTUSERDATA)
                {
                    void* key = lua_touserdata(L, -2);

                    if (key == &wxlua_lreg_wxeventtype_key)
                    {
                        wxEventType eventType = (wxEventType)lua_tonumber(L, -1);
                        const wxLuaBindEvent* wxlEvent = wxLuaBinding::FindBindEvent(eventType);

                        if (wxlEvent != NULL)
                        {
                            value = wxString::Format(wxT("%d = %s : %s"), eventType, lua2wx(wxlEvent->name).c_str(), wxluaT_typename(L, *wxlEvent->wxluatype).c_str());
                        }
                    }
                    else if (key == &wxlua_metatable_type_key)
                    {
                        value += wxString::Format(wxT(" (%s)"), wxluaT_typename(L, (int)lua_tonumber(L, -1)).c_str());
                    }
                    else if (key == &wxlua_metatable_wxluabindclass_key)
                    {
                        wxLuaBindClass* wxlClass = (wxLuaBindClass*)lua_touserdata(L, -1);
                        value += wxLuaBindClassString(wxlClass);
                    }
                    else if (key == &wxlua_lreg_debug_refs_key)
                    {
                        value += wxT(" Note: You cannot traverse refed tables");
                    }
                }

                // ----------------------------------------------------------
                // Handle the key

                int key_flag_type = 0;
                int key_ref = LUA_NOREF;

                // don't ref anything in this table since it's already refed
                if ((lua_key_type == LUA_TTABLE) && (lightuserdata_reg_key != &wxlua_lreg_debug_refs_key))
                {
                    key_ref = RefTable(L, -2, &key_flag_type, WXLUA_DEBUGITEM_KEY_REF, references);
                }
                else if (lua_key_type == LUA_TUSERDATA)
                {
                    if (lua_getmetatable(L, -2)) // doesn't push anything if nil
                    {
                        key_ref = RefTable(L, -2, &key_flag_type, WXLUA_DEBUGITEM_KEY_REF, references);
                        lua_pop(L, 1);
                    }
                }

                // only add the key if we refed it so it can be viewed in the stack dialog
                if (key_flag_type != 0)
                {
                    Add(new wxLuaDebugItem(name, wxl_keytype, value, wxl_valuetype, wxEmptyString, key_ref, nIndex, key_flag_type));
                    ++count;
                }

                // ----------------------------------------------------------
                // Handle the value

                int val_flag_type = 0;
                int val_ref = LUA_NOREF;

                // don't ref anything in this table since it's already refed
                if ((lua_value_type == LUA_TTABLE) && (lightuserdata_reg_key != &wxlua_lreg_debug_refs_key))
                {
                    val_ref = RefTable(L, -1, &val_flag_type, WXLUA_DEBUGITEM_VALUE_REF, references);
                }
                else if (lua_value_type == LUA_TUSERDATA)
                {
                    if (lua_getmetatable(L, -1)) // doesn't push anything if nil
                    {
                        val_ref = RefTable(L, -1, &val_flag_type, WXLUA_DEBUGITEM_VALUE_REF, references);
                        lua_pop(L, 1);
                    }
                }

                // Add the value, but not if the value doesn't expand and the key was already added
                if ((key_flag_type == 0) || ((key_flag_type != 0) && (val_flag_type != 0)))
                {
                    Add(new wxLuaDebugItem(name, wxl_keytype, value, wxl_valuetype, wxEmptyString, val_ref, nIndex, val_flag_type));
                    ++count;
                }

                lua_pop(L, 1); // pop value, leave key
            }
            }

            lua_pop(L, 1); // remove reference
        }
    }

    return count;
}

int wxLuaDebugData::RefTable(lua_State* L, int stack_idx, int* flag_type, int extra_flag, wxArrayInt& references)
{
    wxCHECK_MSG(L, LUA_NOREF, wxT("Invalid lua_State"));

    int lua_ref = LUA_NOREF;

    if (lua_istable(L, stack_idx))
    {
        if (flag_type) *flag_type |= (WXLUA_DEBUGITEM_IS_REFED | extra_flag);

        lua_ref = wxluaR_isrefed(L, stack_idx, &wxlua_lreg_debug_refs_key); // don't duplicate refs

        if (lua_ref == LUA_NOREF)
        {
            lua_ref = wxluaR_ref(L, stack_idx, &wxlua_lreg_debug_refs_key);
            references.Add(lua_ref);
        }
    }

    return lua_ref;
}

int wxLuaDebugData::GetTypeValue(lua_State *L, int stack_idx, int* wxl_type_, wxString& value)
{
    wxCHECK_MSG(L, 0, wxT("Invalid lua_State"));

    int l_type    = lua_type(L, stack_idx);
    int wxl_type  = wxlua_luatowxluatype(l_type);

    switch (l_type)
    {
        case LUA_TNONE:
        {
            value = wxEmptyString;
            break;
        }
        case LUA_TNIL:
        {
            value = wxT("nil");
            break;
        }
        case LUA_TBOOLEAN:
        {
            value = (lua_toboolean(L, stack_idx) != 0) ? wxT("true") : wxT("false");
            break;
        }
        case LUA_TLIGHTUSERDATA:
        {
            value = GetUserDataInfo(L, stack_idx, false);
            break;
        }
        case LUA_TNUMBER:
        {
            double num = lua_tonumber(L, stack_idx);

            if ((long)num == num)
                value.Printf(wxT("%ld (0x%lx)"), (long)num, (unsigned long)num);
            else
                value.Printf(wxT("%g"), num);

            break;
        }
        case LUA_TSTRING:
        {
            value = lua2wx(lua_tostring(L, stack_idx));
            break;
        }
        case LUA_TTABLE:
        {
            value = GetTableInfo(L, stack_idx);
            break;
        }
        case LUA_TFUNCTION:
        {
            value.Printf(wxT("%p"), lua_topointer(L, stack_idx));

            if (lua_iscfunction(L, stack_idx))
                wxl_type = WXLUA_TCFUNCTION;

            break;
        }
        case LUA_TUSERDATA:
        {
            value = GetUserDataInfo(L, stack_idx, true);
            break;
        }
        case LUA_TTHREAD:
        {
            value.Printf(wxT("%p"), lua_topointer(L, stack_idx));
            break;
        }
        default :
        {
            value = wxEmptyString;
            break;
        }
    }

    if (wxl_type_) *wxl_type_ = wxl_type;

    return l_type;
}

wxString wxLuaDebugData::GetTableInfo(lua_State *L, int stack_idx)
{
    wxCHECK_MSG(L, wxEmptyString, wxT("Invalid lua_State"));

    int         nItems   = luaL_getn(L, stack_idx);
    const void *pItem    = lua_topointer(L, stack_idx);

    if (nItems > 0)
        return wxString::Format(wxT("%p (%d array items)"), pItem, nItems);

    return wxString::Format(wxT("%p"), pItem);
}

wxString wxLuaDebugData::GetUserDataInfo(lua_State *L, int stack_idx, bool full_userdata)
{
    wxCHECK_MSG(L, wxEmptyString, wxT("Invalid lua_State"));

    void* udata = lua_touserdata(L, stack_idx);

    wxString s(wxString::Format(wxT("%p"), udata));

    if (!full_userdata)
    {
        // Convert our known keys to something more readable
        if ((udata == &wxlua_lreg_types_key) ||
            (udata == &wxlua_lreg_refs_key) ||
            (udata == &wxlua_lreg_debug_refs_key) ||
            (udata == &wxlua_lreg_classes_key) ||
            (udata == &wxlua_lreg_derivedmethods_key) ||
            (udata == &wxlua_lreg_wxluastate_key) ||
            (udata == &wxlua_lreg_wxluabindings_key) ||
            (udata == &wxlua_lreg_weakobjects_key) ||
            (udata == &wxlua_lreg_gcobjects_key) ||
            (udata == &wxlua_lreg_evtcallbacks_key) ||
            (udata == &wxlua_lreg_windestroycallbacks_key) ||
            (udata == &wxlua_lreg_callbaseclassfunc_key) ||
            (udata == &wxlua_lreg_wxeventtype_key) ||
            (udata == &wxlua_lreg_wxluastatedata_key) ||
            (udata == &wxlua_lreg_regtable_key) ||

            (udata == &wxlua_metatable_type_key) ||
            (udata == &wxlua_lreg_topwindows_key) ||
            (udata == &wxlua_metatable_wxluabindclass_key))
        {
            const char* ss = *(const char**)udata;
            s += wxString::Format(wxT(" (%s)"), lua2wx(ss).c_str());
        }
    }
    else // is full userdata
    {
        int wxl_type = wxluaT_type(L, stack_idx);

        if (wxlua_iswxuserdatatype(wxl_type))
        {
            s += wxString::Format(wxT(" (wxltype %d)"), wxl_type);

            wxString wxltypeName(wxluaT_typename(L, wxl_type));
            if (!wxltypeName.IsEmpty())
                s += wxString::Format(wxT(" '%s'"), wxltypeName.c_str());
        }
    }

    return s;
}

// ----------------------------------------------------------------------------
// wxLuaCheckStack - dumps the contents of the lua_State
// ----------------------------------------------------------------------------

wxLuaCheckStack::wxLuaCheckStack(lua_State *L, const wxString &msg, bool print_to_console)
{
    m_luaState = L;
    m_msg      = msg;
    m_top      = lua_gettop(m_luaState);
    m_print_to_console = print_to_console;
}

wxLuaCheckStack::~wxLuaCheckStack()
{
    if (m_print_to_console)
        TestStack(wxT("~wxLuaCheckStack"));
}

wxString wxLuaCheckStack::TestStack(const wxString &msg)
{
    wxString s;
    s.Printf(wxT("wxLuaCheckStack::TestStack(L=%p) '%s':'%s': starting top %d ending top %d\n"),
                    m_luaState, m_msg.c_str(), msg.c_str(), m_top, lua_gettop(m_luaState));

    if (m_top != lua_gettop(m_luaState)) s += wxT(" **********"); // easy to find

    OutputMsg(s);

    return s;
}

wxString wxLuaCheckStack::DumpStack(const wxString& msg)
{
    wxCHECK_MSG(m_luaState, wxEmptyString, wxT("Invalid lua_State"));

    lua_State* L = m_luaState;
    int i, count = lua_gettop(L);
    wxString str;
    wxString retStr;

    str.Printf(wxT("wxLuaCheckStack::DumpStack(L=%p), '%s':'%s', items %d, starting top %d\n"), L, m_msg.c_str(), msg.c_str(), count, m_top);
    retStr += str;
    OutputMsg(str);

    wxLuaState wxlState(L);

    for (i = 1; i <= count; i++)
    {
        int wxl_type = 0;
        wxString value;
        int l_type = wxLuaDebugData::GetTypeValue(L, i, &wxl_type, value);

        str.Printf(wxT("  idx %d: l_type = %d, wxl_type = %d : '%s'='%s'\n"),
                i, l_type, wxl_type, wxluaT_typename(L, wxl_type).c_str(), value.c_str());
        retStr += str;
        OutputMsg(str);
    }

    return retStr;
}

wxString wxLuaCheckStack::DumpGlobals(const wxString& msg)
{
    wxCHECK_MSG(m_luaState, wxEmptyString, wxT("Invalid lua_State"));

    wxSortedArrayString tableArray;

    return DumpTable(LUA_GLOBALSINDEX, wxT("Globals"), msg, tableArray, 0);
}

wxString wxLuaCheckStack::DumpTable(const wxString &tablename, const wxString& msg)
{
    wxCHECK_MSG(m_luaState, wxEmptyString, wxT("Invalid lua_State"));

    lua_State* L = m_luaState;
    wxSortedArrayString tableArray;
    wxString s;

    // Allow iteration through table1.table2.table3...
    wxString tname(tablename);
    lua_pushglobaltable(L);

    do {
        lua_pushstring(L, wx2lua(tname.BeforeFirst(wxT('.'))));
        lua_rawget(L, -2);

        if (lua_isnil(L, -1) || !lua_istable(L, -1))
        {
            lua_pop(L, 2);  // remove table and value

            s.Printf(wxT("wxLuaCheckStack::DumpTable(L=%p) Table: '%s' cannot be found!\n"), L, tablename.c_str());
            OutputMsg(s);
            return s;
        }

        lua_remove(L, -2);  // remove previous table
        tname = tname.AfterFirst(wxT('.'));
    } while (tname.Len() > 0);

    s = DumpTable(lua_gettop(L), tablename, msg, tableArray, 0);
    lua_pop(L, 1);

    return s;
}

wxString wxLuaCheckStack::DumpTable(int stack_idx, const wxString& msg)
{
    wxCHECK_MSG(m_luaState, wxEmptyString, wxT("Invalid lua_State"));

    wxSortedArrayString tableArray;

    return DumpTable(stack_idx, wxString::Format(wxT("StackIdx=%d"), stack_idx), msg, tableArray, 0);
}

wxString wxLuaCheckStack::DumpTable(int stack_idx, const wxString& tablename, const wxString& msg, wxSortedArrayString& tableArray, int indent)
{
    wxCHECK_MSG(m_luaState, wxEmptyString, wxT("Invalid lua_State"));

    lua_State* L = m_luaState;
    wxLuaState wxlState(L);
    wxString indentStr;
    wxString s;

    // We only do tables, return error message
    if (!lua_istable(L, stack_idx))
    {
        s.Printf(wxT("wxLuaCheckStack::DumpTable(L=%p) stack idx %d is not a table.\n"), L, stack_idx);
        OutputMsg(s);
        return s;
    }

    if (indent == 0)
    {
        // First time through print header
        s.Printf(wxT("wxLuaCheckStack::DumpTable(L=%p) Table: '%s'\n"), L, tablename.c_str());
        OutputMsg(s);
    }
    else if (indent > 10)
    {
        // Don't let things get out of hand...
        s.Printf(wxT("wxLuaCheckStack::DumpTable(L=%p) Table depth > 10! Truncating: '%s'\n"), L, tablename.c_str());
        OutputMsg(s);
        return s;
    }
    else
    {
        indentStr = wxString(wxT(' '), indent*2) + wxT(">");
    }

    wxString title = wxString::Format(wxT("%sTable Level %d : name '%s'\n"), indentStr.c_str(), indent, tablename.c_str());
    s += title;
    OutputMsg(title);

    lua_pushvalue(L, stack_idx); // push the table to read the top of the stack

    lua_pushnil(L);
    while (lua_next(L, -2) != 0)
    {
        int keyType = 0, valueType = 0;
        wxString key, value;

        wxLuaDebugData::GetTypeValue(L, -2, &keyType,   key);
        wxLuaDebugData::GetTypeValue(L, -1, &valueType, value);

        wxString info = wxString::Format(wxT("%s%-32s\t%-16s\t%-20s\t%-16s\n"),
                indentStr.c_str(), key.c_str(), wxluaT_typename(L, keyType).c_str(), value.c_str(), wxluaT_typename(L, valueType).c_str());
        s += info;
        OutputMsg(info);

        if (tableArray.Index(value) == wxNOT_FOUND)
        {
            if (valueType == WXLUA_TTABLE)
            {
                tableArray.Add(value);
                s += DumpTable(lua_gettop(L), tablename + wxT(".") + key, msg, tableArray, indent+1);
            }
            else
            {
                tableArray.Add(value);
            }
        }

        lua_pop(L, 1); // pop value
    }

    lua_pop(L, 1); // pop pushed table

    return s;
}

void wxLuaCheckStack::OutputMsg(const wxString& msg) const
{
    if (m_print_to_console)
    {
#if  defined(__WXMSW__)
    //OutputDebugString(msg.c_str());
    wxPrintf(wxT("%s"), msg.c_str()); fflush(stdout);
#else //if defined(__WXGTK__) || defined(__WXMAC__)
    wxPrintf(wxT("%s"), msg.c_str());
#endif
    }
}
