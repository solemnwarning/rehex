// ----------------------------------------------------------------------------
// Overridden functions for the wxWidgets binding for wxLua
//
// Please keep these functions in the same order as the .i file and in the
// same order as the listing of the functions in that file.
// ----------------------------------------------------------------------------

%override wxLua_REHex_ByteRangeSet_set_ranges
static int LUACALL wxLua_REHex_ByteRangeSet_set_ranges(lua_State *L)
{
	// const REHex::ByteRangeSet set
	const REHex::ByteRangeSet * set = (const REHex::ByteRangeSet *)wxluaT_getuserdatatype(L, 2, wxluatype_REHex_ByteRangeSet);
	// get this
	REHex::ByteRangeSet * self = (REHex::ByteRangeSet *)wxluaT_getuserdatatype(L, 1, wxluatype_REHex_ByteRangeSet);
	// call set_ranges
	self->set_ranges(set->begin(), set->end());

	return 0;
}
%end

%override wxLua_REHex_ByteRangeSet_clear_ranges
static int LUACALL wxLua_REHex_ByteRangeSet_clear_ranges(lua_State *L)
{
	// const REHex::ByteRangeSet set
	const REHex::ByteRangeSet * set = (const REHex::ByteRangeSet *)wxluaT_getuserdatatype(L, 2, wxluatype_REHex_ByteRangeSet);
	// get this
	REHex::ByteRangeSet * self = (REHex::ByteRangeSet *)wxluaT_getuserdatatype(L, 1, wxluatype_REHex_ByteRangeSet);
	// call clear_ranges
	self->clear_ranges(set->begin(), set->end());

	return 0;
}
%end

%override wxLua_REHex_ByteRangeSet_get_ranges
static int LUACALL wxLua_REHex_ByteRangeSet_get_ranges(lua_State *L)
{
	const REHex::ByteRangeSet *self = (const REHex::ByteRangeSet*)(wxluaT_getuserdatatype(L, 1, wxluatype_REHex_ByteRangeSet));
	
	lua_newtable(L);            /* Table to return */
	lua_Integer table_idx = 1;  /* Next index to use in return table */
	
	for(auto r = self->begin(); r != self->end(); ++r)
	{
		lua_pushinteger(L, table_idx++);
		
		lua_newtable(L);  /* Table for range. */
		
		lua_pushstring(L, "offset");
		lua_pushinteger(L, r->offset);
		lua_settable(L, -3);
		
		lua_pushstring(L, "length");
		lua_pushinteger(L, r->length);
		lua_settable(L, -3);
		
		/* Push range table onto return table */
		lua_settable(L, -3);
	}

    return 1;
}
%end
