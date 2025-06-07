-- Binary Template plugin for REHex
-- Copyright (C) 2021-2025 Daniel Collins <solemnwarning@solemnwarning.net>
--
-- This program is free software; you can redistribute it and/or modify it
-- under the terms of the GNU General Public License version 2 as published by
-- the Free Software Foundation.
--
-- This program is distributed in the hope that it will be useful, but WITHOUT
-- ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
-- FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
-- more details.
--
-- You should have received a copy of the GNU General Public License along with
-- this program; if not, write to the Free Software Foundation, Inc., 51
-- Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

local ArrayIndexValue = require 'executor.arrayindexvalue'
local ArrayValue      = require 'executor.arrayvalue'
local FileArrayValue  = require 'executor.filearrayvalue'
local FileValue       = require 'executor.filevalue'
local ImmediateValue  = require 'executor.immediatevalue'
local PlainValue      = require 'executor.plainvalue'
local StructValue     = require 'executor.structvalue'
local TypeMapper      = require 'executor.typemapper'
local util            = require 'executor.util'
local VarAllocator    = require 'executor.varallocator'

local M = {}

local FRAME_TYPE_BASE     = "base"
local FRAME_TYPE_STRUCT   = "struct"
local FRAME_TYPE_FUNCTION = "function"
local FRAME_TYPE_SCOPE    = "scope"

local FLOWCTRL_TYPE_RETURN   = 1
local FLOWCTRL_TYPE_BREAK    = 2
local FLOWCTRL_TYPE_CONTINUE = 4

local _find_type;
local _builtin_types

local _eval_number;
local _eval_string;
local _eval_ref;
local _eval_add;
local _numeric_op_func;
local _eval_equal
local _eval_not_equal
local _eval_bitwise_not
local _eval_logical_not
local _eval_logical_and;
local _eval_logical_or;
local _eval_postfix_increment
local _eval_postfix_decrement
local _eval_unary_plus
local _eval_unary_minus
local expand_value
local _eval_variable;
local _eval_local_variable
local _eval_assign
local _eval_call;
local _eval_return
local _eval_func_defn;
local _eval_struct_defn
local _eval_typedef
local _eval_enum
local _eval_if
local _eval_for
local _eval_switch
local _eval_block
local _eval_break
local _eval_continue
local _eval_cast
local _eval_ternary
local _eval_statement;
local _exec_statements;

local _ops

local function _map(src_table, func)
	local dst_table = {}
	
	for k,v in pairs(src_table)
	do
		dst_table[k] = func(src_table[k])
	end
	
	return dst_table
end

local function _sorted_pairs(t)
	local keys_sorted = {}
	
	for k in pairs(t)
	do
		table.insert(keys_sorted, k)
	end
	
	table.sort(keys_sorted)
	
	local i = 0
	
	return function()
		i = i + 1
		return keys_sorted[i], t[ keys_sorted[i] ]
	end
end

local function _topmost_frame_of_type(context, type)
	for i = #context.stack, 1, -1
	do
		if context.stack[i].frame_type == type
		then
			return context.stack[i]
		end
	end
	
	return nil
end

local function _can_do_flowctrl_here(context, flowctrl_type)
	for i = #context.stack, 1, -1
	do
		local frame = context.stack[i]
		
		if frame.handles_flowctrl_types ~= nil and (frame.handles_flowctrl_types & flowctrl_type) == flowctrl_type
		then
			return true
		end
		
		if frame.blocks_flowctrl_types ~= nil and (frame.blocks_flowctrl_types & flowctrl_type) == flowctrl_type
		then
			return false
		end
	end
	
	return false
end

local function _template_error(context, error_message, filename, line_num)
	local statement = context.st_stack[#context.st_stack];
	
	if filename == nil then filename = statement[1] end
	if line_num == nil then line_num = statement[2] end
	
	error(error_message .. " at " .. filename .. ":" .. line_num, 0)
end

--
-- Type system
--

-- Placeholder for ... in builtin function parameters. Not a valid type in most contexts but the
-- _eval_call() function handles this specific object specially.
local _variadic_placeholder = {}

local _allocated_variable_placeholder = {}
local _initialised_variable_placeholder = {}

local function _get_type_name(type)
	if type == _variadic_placeholder
	then
		return "..."
	elseif type == nil
	then
		return "void"
	end
	
	local type_name
	
	if type.name ~= nil
	then
		type_name = type.name
	elseif type.base == "struct"
	then
		if type.struct_name ~= nil
		then
			type_name = "struct " .. type.struct_name
		else
			type_name = "<anonymous struct>"
		end
	else
		error("Internal error: unknown type in _get_type_name()" .. "\n" .. debug.traceback())
	end
	
	if type.is_const
	then
		type_name = "const " .. type_name
	end
	
	if type.is_array
	then
		if type.array_size ~= nil
		then
			assert(#type.array_size >= 1)
			type_name = type_name .. "[" .. type.array_size[#type.array_size] .. "]"
		else
			type_name = type_name .. "[]"
		end
	end
	
	if type.is_ref
	then
		type_name = type_name .. "&"
	end
	
	return type_name
end

local function _type_is_string(type_info)
	return type_info ~= nil and not type_info.is_array and type_info.base == "string"
end

local function _type_is_char_array(type_info)
	return type_info ~= nil and type_info.is_array and type_info.type_key == _builtin_types.char.type_key
end

local function _type_is_number(type_info)
	return type_info ~= nil and not type_info.is_array and type_info.base == "number"
end

local function _type_is_stringish(type_info)
	return _type_is_string(type_info) or _type_is_char_array(type_info)
end

local function _stringify_value(type_info, value)
	if _type_is_string(type_info)
	then
		return value:get()
	elseif _type_is_char_array(type_info)
	then
		local bytes = {}
		
		for i = 1, #value
		do
			local byte = value[i]:get()
			if byte == 0
			then
				break
			end
			
			table.insert(bytes, byte)
		end
		
		return string.char(table.unpack(bytes))
	elseif _type_is_number(type_info)
	then
		return value:get() .. ""
	else
		error("Internal error: Unexpected type '" .. _get_type_name(type_info) .. "' passed to _stringify_value()")
	end
end

local function _type_assignable(dst_t, src_t)
	if dst_t == nil or src_t == nil
	then
		-- "void" can't be assigned anywhere
		return false
	end
	
	if dst_t.is_ref
	then
		-- References can only be made when src/dst are EXACTLY the same type
		-- (typedef aliases match too)
		
		return dst_t.type_key == src_t.type_key
	end
	
	if (_type_is_string(dst_t) and _type_is_char_array(src_t)) or (_type_is_char_array(dst_t) and _type_is_string(src_t))
	then
		-- can assign between char[] and string
		return true
	end
	
	if (not not dst_t.is_array) ~= (not not src_t.is_array)
	then
		-- can't assign array to non-array or vice-versa
		return false
	end
	
	if dst_t.base == "struct" and src_t.base == "struct"
	then
		-- can assign structs if the same root type
		return dst_t.type_key == src_t.type_key
	end
	
	if dst_t.base == src_t.base
	then
		-- can assign the same base types (numeric to numeric and string to string)
		return true
	end
	
	-- unsupported conversion
	return false
end

local function _assign_value(context, dst_type, dst_val, src_type, src_val)
	if dst_type == nil or src_type == nil
	then
		_template_error(context, "can't assign '" .. _get_type_name(src_type) .. "' to type '" .. _get_type_name(dst_type) .. "'")
	end
	
	if _type_is_string(dst_type) and _type_is_char_array(src_type)
	then
		-- Assignment from char[] to string - set the string to the chars from the array
		dst_val:set(_stringify_value(src_type, src_val))
		
		return
	elseif _type_is_char_array(dst_type) and _type_is_string(src_type)
	then
		-- Assignment from string to char[] - copy characters into the string up to the
		-- end of the array/string and fill any remaining space with zeros.
		
		local src_str = src_val:get()
		local src_len = src_str:len()
		
		local i = 1
		
		while i <= #dst_val and i <= src_len
		do
			dst_val[i]:set(src_str:byte(i))
			i = i + 1
		end
		
		while i <= #dst_val
		do
			dst_val[i]:set(0)
			i = i + 1
		end
		
		return
	end
	
	if (not not dst_type.is_array) ~= (not not src_type.is_array)
	then
		_template_error(context, "can't assign '" .. _get_type_name(src_type) .. "' to type '" .. _get_type_name(dst_type) .. "'")
	end
	
	local do_assignment = function(dst_val, src_val)
		if dst_type.base == "struct" and src_type.base == "struct" and dst_type.type_key == src_type.type_key
		then
			for name,src_pair in pairs(src_val)
			do
				local member_type = src_pair[1]
				local src_member = src_pair[2]
				local dst_member = dst_val[name][2]
				
				_assign_value(context, member_type, dst_member, member_type, src_member)
			end
		elseif dst_type.base ~= "struct" and dst_type.base == src_type.base
		then
			local v = src_val:get()
			
			if dst_type.int_mask ~= nil
			then
				v = math.floor(v) & dst_type.int_mask
			end
			
			dst_val:set(v)
		else
			_template_error(context, "can't assign '" .. _get_type_name(src_type) .. "' to type '" .. _get_type_name(dst_type) .. "'")
		end
	end
	
	if dst_type.is_array
	then
		if #dst_val ~= #src_val
		then
			
		end
		
		for i = 1, #dst_val
		do
			do_assignment(dst_val[i], src_val[i])
		end
	else
		do_assignment(dst_val, src_val)
	end
end

local function _make_value_from_value(context, dst_type, src_type, src_val, move_if_possible)
	if _type_is_string(dst_type) and _type_is_char_array(src_type)
	then
		-- Assignment from char[] to string - set the string to the chars from the array
		return PlainValue:new(_stringify_value(src_type, src_val))
	elseif _type_is_char_array(dst_type) and _type_is_string(src_type)
	then
		-- Assignment from string to char[] - copy characters into the string up to the
		-- end of the array/string and fill any remaining space with zeros.
		
		local dst_val = ArrayValue:new()
		
		local src_str = src_val:get()
		local src_len = src_str:len()
		
		for i = 1, src_len
		do
			dst_val[i] = PlainValue:new(src_str:byte(i))
		end
		
		return dst_val
	end
	
	if (not dst_type.is_array) ~= (not src_type.is_array)
		or dst_type.base ~= src_type.base
		or (dst_type.base == "struct" and dst_type.type_key ~= src_type.type_key)
	then
		_template_error(context, "can't convert '" .. _get_type_name(src_type) .. "' to type '" .. _get_type_name(dst_type) .. "'")
	end
	
	if src_type.is_array
	then
		local dst_elem_type = util.make_nonarray_type(dst_type)
		local src_elem_type = util.make_nonarray_type(src_type)
		
		local dst_val = ArrayValue:new()
		
		for i = 1, #src_val
		do
			dst_val[i] = _make_value_from_value(context, dst_elem_type, src_elem_type, src_val[i], move_if_possible)
		end
		
		return dst_val
	end
	
	if src_type.base == "struct"
	then
		local dst_val = StructValue:new()
		
		for k,src_pair in pairs(src_val)
		do
			local src_elem_type, src_elem = table.unpack(src_pair)
			local dst_elem_type = src_elem_type
			
			dst_val[k] = {
				dst_elem_type,
				_make_value_from_value(context, dst_elem_type, src_elem_type, src_elem, move_if_possible)
			}
		end
		
		return dst_val
	end
	
	if dst_type.int_mask ~= nil and (src_type.int_mask == nil or src_type.int_mask ~= dst_type.int_mask)
	then
		return PlainValue:new(math.floor(src_val:get()) & dst_type.int_mask)
	end
	
	if move_if_possible
	then
		return src_val
	else
		return PlainValue:new(src_val:get())
	end
end

local INT8_MIN  = -128
local INT8_MAX  = 127
local INT16_MIN = -32768
local INT16_MAX = 32767
local INT32_MIN = -2147483648
local INT32_MAX = 2147483647
local INT64_MIN = -0x8000000000000000
local INT64_MAX = 0x7FFFFFFFFFFFFFFF

local UINT8_MAX  = 0xFF
local UINT16_MAX = 0xFFFF
local UINT32_MAX = 0xFFFFFFFF
local UINT64_MAX = 0xFFFFFFFFFFFFFFFF

local _builtin_type_int8    = { rehex_type_le = "s8",    rehex_type_be = "s8",    length = 1, base = "number", string_fmt = "i1", type_key = {}, int_mask = (INT8_MIN | INT8_MAX) }
local _builtin_type_uint8   = { rehex_type_le = "u8",    rehex_type_be = "u8",    length = 1, base = "number", string_fmt = "I1", type_key = {}, int_mask = UINT8_MAX }
local _builtin_type_int16   = { rehex_type_le = "s16le", rehex_type_be = "s16be", length = 2, base = "number", string_fmt = "i2", type_key = {}, int_mask = (INT16_MIN | INT16_MAX) }
local _builtin_type_uint16  = { rehex_type_le = "u16le", rehex_type_be = "u16be", length = 2, base = "number", string_fmt = "I2", type_key = {}, int_mask = UINT16_MAX }
local _builtin_type_int32   = { rehex_type_le = "s32le", rehex_type_be = "s32be", length = 4, base = "number", string_fmt = "i4", type_key = {}, int_mask = (INT32_MIN | INT32_MAX) }
local _builtin_type_uint32  = { rehex_type_le = "u32le", rehex_type_be = "u32be", length = 4, base = "number", string_fmt = "I4", type_key = {}, int_mask = UINT32_MAX }
local _builtin_type_int64   = { rehex_type_le = "s64le", rehex_type_be = "s64be", length = 8, base = "number", string_fmt = "i8", type_key = {}, int_mask = (INT64_MIN | INT64_MAX) }
local _builtin_type_uint64  = { rehex_type_le = "u64le", rehex_type_be = "u64be", length = 8, base = "number", string_fmt = "I8", type_key = {}, int_mask = UINT64_MAX }
local _builtin_type_float32 = { rehex_type_le = "f32le", rehex_type_be = "f32be", length = 4, base = "number", string_fmt = "f",  type_key = {} }
local _builtin_type_float64 = { rehex_type_le = "f64le", rehex_type_be = "f64be", length = 8, base = "number", string_fmt = "d",  type_key = {} }

_builtin_type_int8  .signed_overlay   = _builtin_type_int8
_builtin_type_int8  .unsigned_overlay = _builtin_type_uint8
_builtin_type_uint8 .signed_overlay   = _builtin_type_int8
_builtin_type_uint8 .unsigned_overlay = _builtin_type_uint8

_builtin_type_int16  .signed_overlay   = _builtin_type_int16
_builtin_type_int16  .unsigned_overlay = _builtin_type_uint16
_builtin_type_uint16 .signed_overlay   = _builtin_type_int16
_builtin_type_uint16 .unsigned_overlay = _builtin_type_uint16

_builtin_type_int32  .signed_overlay   = _builtin_type_int32
_builtin_type_int32  .unsigned_overlay = _builtin_type_uint32
_builtin_type_uint32 .signed_overlay   = _builtin_type_int32
_builtin_type_uint32 .unsigned_overlay = _builtin_type_uint32

_builtin_type_int64  .signed_overlay   = _builtin_type_int64
_builtin_type_int64  .unsigned_overlay = _builtin_type_uint64
_builtin_type_uint64 .signed_overlay   = _builtin_type_int64
_builtin_type_uint64 .unsigned_overlay = _builtin_type_uint64

_builtin_types = {
	char   = util.make_named_type("char",   _builtin_type_int8),
	int8_t = util.make_named_type("int8_t", _builtin_type_int8),
	
	uint8_t = util.make_named_type("uint8_t", _builtin_type_uint8),
	
	int16_t  = util.make_named_type("int16_t",  _builtin_type_int16),
	uint16_t = util.make_named_type("uint16_t", _builtin_type_uint16),
	
	int     = util.make_named_type("int",     _builtin_type_int32),
	int32_t = util.make_named_type("int32_t", _builtin_type_int32),
	
	uint32_t = util.make_named_type("uint32_t", _builtin_type_uint32),
	
	int64_t = util.make_named_type("int64_t", _builtin_type_int64),
	
	uint64_t = util.make_named_type("uint64_t", _builtin_type_uint64),
	
	float = util.make_named_type("float", _builtin_type_float32),
	
	double = util.make_named_type("double", _builtin_type_float64),
	
	string = { name = "string", base = "string" },
}

local _builtin_variables = {
	["true"]  = function(context) return { _builtin_types.int, ImmediateValue:new(1) } end,
	["false"] = function(context) return { _builtin_types.int, ImmediateValue:new(0) } end,
	
	["ArrayIndex"] = function(context) return { _builtin_types.int64_t, ArrayIndexValue:new(context) } end,
}

local function _builtin_function_BigEndian(context, argv)
	context.big_endian = true
end

local function _builtin_function_LittleEndian(context, argv)
	context.big_endian = false
end

local function _builtin_function_IsBigEndian(context, argv)
	return _builtin_types.int, ImmediateValue:new(context.big_endian and 1 or 0)
end

local function _builtin_function_IsLittleEndian(context, argv)
	return _builtin_types.int, ImmediateValue:new(context.big_endian and 0 or 1)
end

local function _builtin_function_FEof(context, argv)
	return _builtin_types.int, ImmediateValue:new(context.next_variable >= context.interface.file_length() and 1 or 0)
end

local function _builtin_function_FileSize(context, argv)
	return _builtin_types.int64_t, ImmediateValue:new(context.interface.file_length())
end

local function _builtin_function_FSeek(context, argv)
	local seek_to = argv[1][2]:get()
	
	if seek_to < 0 or seek_to > context.interface.file_length()
	then
		return _builtin_types.int, ImmediateValue:new(-1)
	end
	
	context.next_variable = seek_to
	return _builtin_types.int, ImmediateValue:new(0)
end

local function _builtin_function_FSkip(context, argv)
	local seek_to = context.next_variable + argv[1][2]:get()
	
	if seek_to < 0 or seek_to > context.interface.file_length()
	then
		return _builtin_types.int, ImmediateValue:new(-1)
	end
	
	context.next_variable = seek_to
	return _builtin_types.int, ImmediateValue:new(0)
end

local function _builtin_function_FTell(context, argv)
	return _builtin_types.int64_t, ImmediateValue:new(context.next_variable)
end

local function _render_format_string(context, argv)
	local fmt = argv[1][2]:get()
	
	local format_params = { fmt }
	local next_param = 2
	
	local flags = "" --"[ 0'+-]*"
	local width = "" --"%d*"
	local precision = "%.?%d*"
	
	local fmt_patterns = {
		{ "%%%%", function(fmt_fragment) end },
		
		{ "%%" .. width .. "s", function(fmt_fragment)
			if next_param > #argv
			then
				_template_error(context, "Too few parameters for format string '" .. fmt .. "'")
			end
			
			if not _type_is_stringish(argv[next_param][1])
			then
				_template_error(context, "Expected a string for format '" .. fmt_fragment .. "' but passed a '" .. _get_type_name(argv[next_param][1]) .. "'")
			end
			
			table.insert(format_params, _stringify_value(argv[next_param][1], argv[next_param][2]))
			next_param = next_param + 1
		end },
		
		{ "%%" .. flags .. width .. precision .. "[diufFeEgGxXoc]", function(fmt_fragment)
			if next_param > #argv
			then
				_template_error(context, "Too few parameters for format string '" .. fmt .. "'")
			end
			
			if not _type_is_number(argv[next_param][1])
			then
				_template_error(context, "Expected a number for format '" .. fmt_fragment .. "' but passed a '" .. _get_type_name(argv[next_param][1]) .. "'")
			end
			
			local n = argv[next_param][2]:get()
			table.insert(format_params, n)
			next_param = next_param + 1
		end },
		
		{ "[^%%]+", function(fmt_fragment) end },
	}
	
	local i = 1
	while i <= fmt:len()
	do
		local matched = false
		
		for j = 1, #fmt_patterns
		do
			local _, match_end, match = fmt:find("^(" .. fmt_patterns[j][1] .. ")", i)
			
			if match_end ~= nil
			then
				fmt_patterns[j][2](match)
				matched = true
				i = match_end + 1
				break
			end
		end
		
		if not matched
		then
			_template_error(context, "Unable to parse format string '" .. fmt .. "' i = " .. i)
		end
	end
	
	return string.format(table.unpack(format_params))
end

local function _builtin_function_Printf(context, argv)
	local s = _render_format_string(context, argv)
	context.interface.print(s)
end

local function _builtin_function_SPrintf(context, argv)
	local s = _render_format_string(context, argv)
	return _builtin_types.string, ImmediateValue:new(s)
end

local function _builtin_function_Error(context, argv)
	local s = _render_format_string(context, argv)
	_template_error(context, string.format(s))
end

local function _builtin_function_defn_ReadXXX(type_info, name)
	local impl = function(context, argv)
		local pos = argv[1][2]:get()
		
		if pos < 0 or (pos + type_info.length) > context.interface.file_length()
		then
			_template_error(context, "Attempt to read past end of file in " .. name .. " function")
		end
		
		local fmt = (context.big_endian and ">" or "<") .. type_info.string_fmt
		return type_info, FileValue:new(context, pos, type_info.length, fmt)
	end
	
	return {
		arguments = { _builtin_types.int64_t },
		defaults  = {
			-- FTell()
			{ debug.getinfo(1,'S').source, debug.getinfo(1, 'l').currentline, "call", "FTell", {} }
		},
		impl = impl,
	}
end

local function _builtin_function_ReadString(context, argv)
	local pos = argv[1][2]:get()
	local term_char = argv[2][2]:get()
	local max_len = argv[3][2]:get()
	
	local str = ""
	local str_length = 0
	
	while true
	do
		if max_len >= 0 and str_length == max_len
		then
			return _builtin_types.string, ImmediateValue:new(str:sub(1, str_length))
		end
		
		if str_length == str:len()
		then
			local str_more = context.interface.read_data(pos + str_length, 128)
			if str_more:len() < 1
			then
				_template_error(context, "Attempt to read past end of file in ReadString function")
			end
			
			str = str .. str_more
		end
		
		if str:byte(str_length + 1) == term_char
		then
			return _builtin_types.string, ImmediateValue:new(str:sub(1, str_length))
		end
		
		str_length = str_length + 1
	end
end

local function _builtin_function_ArrayLength(context, argv)
	if #argv ~= 1 or argv[1][1] == nil or not argv[1][1].is_array
	then
		local got_types = table.concat(_map(argv, function(v) return _get_type_name(v[1]) end), ", ")
		_template_error(context, "Attempt to call function ArrayLength(<any array type>) with incompatible argument types (" .. got_types .. ")")
	end
	
	return _builtin_types.int, ImmediateValue:new(#(argv[1][2]))
end

local function _resize_array(context, array_type, array_value, new_length, struct_arg_values)
	local data_start, data_end = array_value:data_range()
	if data_start ~= nil
	then
		if new_length < #array_value
		then
			_template_error(context, "Invalid attempt to shrink non-local array")
		end
		
		if data_end ~= context.next_variable
		then
			_template_error(context, "Invalid attempt to grow non-local array after declaring other variables")
		end
	end
	
	if new_length < 0
	then
		_template_error(context, "Invalid array length (" .. new_length .. ")")
	end
	
	if array_value.resize ~= nil
	then
		local old_length = #array_value
		
		array_value:resize(new_length)
		context.next_variable = data_start + (new_length * array_type.length)
	else
		local was_declaring_local_var = context.declaring_local_var
		context.declaring_local_var = (data_start == nil)
		
		if #array_value < new_length
		then
			local element_type = util.make_nonarray_type(array_type)
			
			for i = #array_value, new_length - 1
			do
				table.insert(array_value, expand_value(context, element_type, struct_arg_values, i))
				context.interface.yield()
			end
		end
		
		for i = #array_value, new_length + 1, -1
		do
			table.remove(array_value)
		end
		
		context.declaring_local_var = was_declaring_local_var
	end
end

local function _builtin_function_ArrayResize(context, argv)
	if #argv < 2 or argv[1][1] == nil or not argv[1][1].is_array or not _type_is_number(argv[2][1])
	then
		local got_types = table.concat(_map(argv, function(v) return _get_type_name(v[1]) end), ", ")
		_template_error(context, "Attempt to call function ArrayResize(<any array type>, <number>, ...) with incompatible argument types (" .. got_types .. ")")
	end
	
	local array_type = argv[1][1]
	local array_value = argv[1][2]
	
	local new_length = argv[2][2]:get()
	
	local struct_arg_values = {}
	if #argv > 2
	then
		if array_type.base ~= "struct"
		then
			_template_error(context, "Struct arguments passed to ArrayResize() for non-struct array element type '" .. _get_type_name(array_type) .. "'")
		end
		
		for i = 3, #argv
		do
			table.insert(struct_arg_values, argv[i])
		end
	end
	
	if array_type.is_const
	then
		_template_error(context, "Attempt to modify 'const' array")
	end
	
	_resize_array(context, array_type, array_value, new_length, struct_arg_values)
end

local function _builtin_function_ArrayExtend(context, argv)
	if #argv < 1 or argv[1][1] == nil or not argv[1][1].is_array or (#argv >= 2 and not _type_is_number(argv[2][1]))
	then
		local got_types = table.concat(_map(argv, function(v) return _get_type_name(v[1]) end), ", ")
		_template_error(context, "Attempt to call function ArrayExtend(<any array type>, <number>, ...) with incompatible argument types (" .. got_types .. ")")
	end
	
	local array_type = argv[1][1]
	local array_value = argv[1][2]
	
	local rel_length = #argv >= 2 and argv[2][2]:get() or 1
	local new_length = #array_value + rel_length
	
	local struct_arg_values = {}
	if #argv > 2
	then
		if array_type.base ~= "struct"
		then
			_template_error(context, "Struct arguments passed to ArrayExtend() for non-struct array element type '" .. _get_type_name(array_type) .. "'")
		end
		
		for i = 3, #argv
		do
			table.insert(struct_arg_values, argv[i])
		end
	end
	
	if array_type.is_const
	then
		_template_error(context, "Attempt to modify 'const' array")
	end
	
	_resize_array(context, array_type, array_value, new_length, struct_arg_values)
end

local function _builtin_function_ArrayPush(context, argv)
	if #argv ~= 2 or argv[1][1] == nil or not argv[1][1].is_array
	then
		local got_types = table.concat(_map(argv, function(v) return _get_type_name(v[1]) end), ", ")
		_template_error(context, "Attempt to call function ArrayPush(<any array type>, <array value type>) with incompatible argument types (" .. got_types .. ")")
	end
	
	if not _type_assignable(util.make_nonarray_type(argv[1][1]), argv[2][1])
	then
		local got_types = table.concat(_map(argv, function(v) return _get_type_name(v[1]) end), ", ")
		_template_error(context, "Attempt to push incompatible value type '" .. _get_type_name(argv[2][1]) .. "' into array type '"  .. _get_type_name(argv[1][1]) .. "'")
	end
	
	local array_type = argv[1][1]
	local array_value = argv[1][2]
	
	local data_start, data_end = array_value:data_range()
	if data_start ~= nil
	then
		_template_error(context, "Attempt to modify non-local array")
	end
	
	local new_value = _make_value_from_value(context, util.make_nonarray_type(array_type), argv[2][1], argv[2][2], false)
	table.insert(array_value, new_value);
end

local function _builtin_function_ArrayPop(context, argv)
	if #argv ~= 1 or argv[1][1] == nil or not argv[1][1].is_array
	then
		local got_types = table.concat(_map(argv, function(v) return _get_type_name(v[1]) end), ", ")
		_template_error(context, "Attempt to call function ArrayPop(<any array type>) with incompatible argument types (" .. got_types .. ")")
	end
	
	local array_type = argv[1][1]
	local array_value = argv[1][2]
	
	local data_start, data_end = array_value:data_range()
	if data_start ~= nil
	then
		_template_error(context, "Attempt to modify non-local array")
	end
	
	if #array_value == 0
	then
		_template_error(context, "Attempt to pop value from empty array")
	end
	
	return util.make_nonarray_type(array_type), table.remove(array_value)
end

local function _builtin_function_OffsetOf(context, argv)
	if #argv ~= 1 or argv[1][1] == nil
	then
		local got_types = table.concat(_map(argv, function(v) return _get_type_name(v[1]) end), ", ")
		_template_error(context, "Attempt to call function OffsetOf(<any type>) with incompatible argument types (" .. got_types .. ")")
	end
	
	local data_start, data_end = argv[1][2]:data_range()
	if data_start == nil
	then
		_template_error(context, "Attempt to get file offset of a local variable")
	end
	
	return _builtin_types.int64_t, ImmediateValue:new(data_start)
end

local function _builtin_function_StringLengthBytes(context, argv)
	return _builtin_types.int64_t, ImmediateValue:new(argv[1][2]:get():len())
end

local function _builtin_function_SetComment(context, argv)
	context.interface.set_comment(argv[1][2]:get(), argv[2][2]:get(), argv[3][2]:get())
end

local function _builtin_function_AllocateHighlightColour(context, argv)
	local primary_colour
	local secondary_colour
	
	if #argv == 1
	then
		primary_colour = wx.wxNullColour
		secondary_colour = wx.wxNullColour
	elseif #argv == 3 and _type_is_number(argv[2][1]) and _type_is_number(argv[3][1])
	then
		local parse_colour_argument = function(n)
			local val = argv[n][2]:get()
			
			if val < 0 or val > 0xFFFFFF
			then
				_template_error(context, "Invalid colour value passed to AllocateHighlightColour")
			end
			
			return wx.wxColour(
				((val & 0xFF0000) >> 16),
				((val & 0x00FF00) >> 8),
				(val & 0x0000FF))
		end
		
		primary_colour = parse_colour_argument(2)
		secondary_colour = parse_colour_argument(3)
	else
		local got_types = table.concat(_map(argv, function(v) return _get_type_name(v[1]) end), ", ")
		_template_error(context, "Attempt to call function AllocateHighlightColour(<string>, [<int>, <int>]) with incompatible argument types (" .. got_types .. ")")
	end
	
	local idx = context.interface.allocate_highlight_colour(argv[1][2]:get(), primary_colour, secondary_colour)
	return _builtin_types.int, ImmediateValue:new(idx)
end

local function _builtin_function_SetHighlight(context, argv)
	context.interface.set_highlight(argv[1][2]:get(), argv[2][2]:get(), argv[3][2]:get())
end

-- Table of builtin functions - gets copied into new interpreter contexts
--
-- Each key is a function name, the value is a table with the following values:
--
-- Table of argument types (arguments)
-- Table of default argument expressions (defaults)
-- Function implementation (impl)

local _builtin_functions = {
	BigEndian      = { arguments = {}, defaults = {}, impl = _builtin_function_BigEndian },
	LittleEndian   = { arguments = {}, defaults = {}, impl = _builtin_function_LittleEndian },
	IsBigEndian    = { arguments = {}, defaults = {}, impl = _builtin_function_IsBigEndian },
	IsLittleEndian = { arguments = {}, defaults = {}, impl = _builtin_function_IsLittleEndian },
	
	FEof     = { arguments = {},                       defaults = {}, impl = _builtin_function_FEof },
	FileSize = { arguments = {},                       defaults = {}, impl = _builtin_function_FileSize },
	FSeek    = { arguments = { _builtin_types.int64_t }, defaults = {}, impl = _builtin_function_FSeek },
	FSkip    = { arguments = { _builtin_types.int64_t }, defaults = {}, impl = _builtin_function_FSkip },
	FTell    = { arguments = {},                       defaults = {}, impl = _builtin_function_FTell },
	
	ReadI8  = _builtin_function_defn_ReadXXX(_builtin_types.int8_t,   "ReadI8"),
	ReadU8  = _builtin_function_defn_ReadXXX(_builtin_types.uint8_t,  "ReadU8"),
	ReadI16 = _builtin_function_defn_ReadXXX(_builtin_types.int16_t,  "ReadI16"),
	ReadU16 = _builtin_function_defn_ReadXXX(_builtin_types.uint16_t, "ReadU16"),
	ReadI32 = _builtin_function_defn_ReadXXX(_builtin_types.int32_t,  "ReadI32"),
	ReadU32 = _builtin_function_defn_ReadXXX(_builtin_types.uint32_t, "ReadU32"),
	ReadI64 = _builtin_function_defn_ReadXXX(_builtin_types.int64_t,  "ReadI64"),
	ReadU64 = _builtin_function_defn_ReadXXX(_builtin_types.uint64_t, "ReadU64"),
	
	ReadDouble = _builtin_function_defn_ReadXXX(_builtin_types.double, "ReadDouble"),
	ReadFloat  = _builtin_function_defn_ReadXXX(_builtin_types.float,  "ReadFloat"),
	
	ReadString = {
		arguments = {
			_builtin_types.int64_t,
			_builtin_types.uint8_t,
			_builtin_types.int64_t,
		},
		
		defaults  = {
			-- FTell()
			{ debug.getinfo(1,'S').source, debug.getinfo(1, 'l').currentline, "call", "FTell", {} },
			
			-- '\0'
			{ debug.getinfo(1,'S').source, debug.getinfo(1, 'l').currentline, "num", 0 },
			
			-- -1
			{ debug.getinfo(1,'S').source, debug.getinfo(1, 'l').currentline, "num", -1 },
		},
		
		impl = _builtin_function_ReadString,
	},
	
	Printf  = { arguments = { _builtin_types.string, _variadic_placeholder }, defaults = {}, impl = _builtin_function_Printf },
	SPrintf = { arguments = { _builtin_types.string, _variadic_placeholder }, defaults = {}, impl = _builtin_function_SPrintf },
	Error   = { arguments = { _builtin_types.string, _variadic_placeholder }, defaults = {}, impl = _builtin_function_Error  },
	
	ArrayLength = { arguments = { _variadic_placeholder }, defaults = {}, impl = _builtin_function_ArrayLength },
	ArrayResize = { arguments = { _variadic_placeholder }, defaults = {}, impl = _builtin_function_ArrayResize },
	ArrayExtend = { arguments = { _variadic_placeholder }, defaults = {}, impl = _builtin_function_ArrayExtend },
	ArrayPush   = { arguments = { _variadic_placeholder }, defaults = {}, impl = _builtin_function_ArrayPush },
	ArrayPop    = { arguments = { _variadic_placeholder }, defaults = {}, impl = _builtin_function_ArrayPop },
	
	OffsetOf = { arguments = { _variadic_placeholder }, defaults = {}, impl = _builtin_function_OffsetOf },
	
	StringLengthBytes = { arguments = { _builtin_types.string }, defaults = {}, impl = _builtin_function_StringLengthBytes },
	
	SetComment = { arguments = { _builtin_types.int64_t, _builtin_types.int64_t, _builtin_types.string }, defaults = {}, impl = _builtin_function_SetComment },
	
	AllocateHighlightColour = { arguments = { _builtin_types.string, _variadic_placeholder }, defaults = {}, impl = _builtin_function_AllocateHighlightColour },
	SetHighlight = { arguments = { _builtin_types.int64_t, _builtin_types.int64_t, _builtin_types.int }, defaults = {}, impl = _builtin_function_SetHighlight },
}

--
-- The _eval_XXX functions are what actually take the individual statements
-- from the AST and execute them.
--
-- All _eval_XXX functions take the context and a single statement and return
-- the type and value of their result (or nothing if void).
--
-- Most _eval_XXX functions are called indirectly via the _eval_statement()
-- function and the _ops table.
---

_eval_number = function(context, statement)
	return util.make_const_type(_builtin_types.int), ImmediateValue:new(statement[4])
end

_eval_string = function(context, statement)
	return util.make_const_type(_builtin_types.string), ImmediateValue:new(statement[4])
end

-- Resolves a variable reference to an actual value.
_eval_ref = function(context, statement)
	local path = statement[4]
	
	-- This function walks along from the second element of path, resolving any array and/or
	-- struct dereferences before returning the final type+value pair.
	
	local _walk_path = function(rvalue)
		local rv_type = rvalue[1]
		local rv_val  = rvalue[2]
		
		local force_const = rv_type.is_const
		
		for i = 2, #path
		do
			if type(path[i]) == "table"
			then
				-- This is a statement to be evalulated and used as an array index.
				
				local array_idx_t, array_idx_v = _eval_statement(context, path[i])
				
				if array_idx_t == nil or array_idx_t.base ~= "number"
				then
					_template_error(context, "Invalid '" .. _get_type_name(array_idx_t) .. "' operand to '[]' operator - expected a number")
				end
				
				if rv_type.is_array
				then
					local array_idx = array_idx_v:get();
					
					if array_idx < 0 or array_idx >= #rv_val
					then
						_template_error(context, "Attempt to access out-of-range array index " .. array_idx)
					else
						rv_type = util.make_nonarray_type(rv_type)
						rv_val = rv_val[array_idx_v:get() + 1]
					end
				else
					_template_error(context, "Attempt to access non-array variable as array")
				end
			else
				-- This is a string to be used as a struct member
				
				local member = path[i]
				
				if rv_type.base ~= "struct"
				then
					_template_error(context, "Attempt to access '" .. _get_type_name(rv_type) .. "' as a struct")
				end
				
				if rv_val[member] == nil
				then
					_template_error(context, "Attempt to access undefined struct member '" .. member .. "'")
				end
				
				rv_type = rv_val[member][1]
				rv_val  = rv_val[member][2]
			end
			
			force_const = force_const or rv_type.is_const
		end
		
		if force_const
		then
			rv_type = util.make_const_type(rv_type)
		end
		
		return rv_type, rv_val
	end
	
	local var_slot = statement.var_slot
	if var_slot <= 0
	then
		var_slot = context.func_var_base - var_slot
	end
	
	return _walk_path(context.var_stack[var_slot])
end

_eval_add = function(context, statement)
	local v1_t, v1_v = _eval_statement(context, statement[4])
	local v2_t, v2_v = _eval_statement(context, statement[5])
	
	if _type_is_number(v1_t) and _type_is_number(v2_t)
	then
		return v1_t, ImmediateValue:new(v1_v:get() + v2_v:get())
	elseif _type_is_stringish(v1_t) and _type_is_stringish(v2_t)
	then
		local v1_s = _stringify_value(v1_t, v1_v)
		local v2_s = _stringify_value(v2_t, v2_v)
		
		return _builtin_types.string, ImmediateValue:new(v1_s .. v2_s)
	else
		_template_error(context, "Invalid operands to '+' operator - '" .. _get_type_name(v1_t) .. "' and '" .. _get_type_name(v2_t) .. "'")
	end
end

_numeric_op_func = function(func, sym)
	return function(context, statement)
		local v1_t, v1_v = _eval_statement(context, statement[4])
		local v2_t, v2_v = _eval_statement(context, statement[5])
		
		if (v1_t and v1_t.base) ~= "number" or (v2_t and v2_t.base) ~= "number"
		then
			_template_error(context, "Invalid operands to '" .. sym .. "' operator - '" .. _get_type_name(v1_t) .. "' and '" .. _get_type_name(v2_t) .. "'")
		end
		
		return v1_t, ImmediateValue:new(func(v1_v:get(), v2_v:get()))
	end
end

_eval_equal = function(context, statement)
	local v1_t, v1_v = _eval_statement(context, statement[4])
	local v2_t, v2_v = _eval_statement(context, statement[5])
	
	if _type_is_number(v1_t) and _type_is_number(v2_t)
	then
		local v1_n = v1_v:get()
		local v2_n = v2_v:get()
		
		return _builtin_types.int, ImmediateValue:new(v1_n == v2_n and 1 or 0)
	elseif _type_is_stringish(v1_t) and _type_is_stringish(v2_t)
	then
		local v1_s = _stringify_value(v1_t, v1_v)
		local v2_s = _stringify_value(v2_t, v2_v)
		
		return _builtin_types.int, ImmediateValue:new(v1_s == v2_s and 1 or 0)
	else
		_template_error(context, "Invalid operands to '==' operator - '" .. _get_type_name(v1_t) .. "' and '" .. _get_type_name(v2_t) .. "'")
	end
end

_eval_not_equal = function(context, statement)
	local v1_t, v1_v = _eval_statement(context, statement[4])
	local v2_t, v2_v = _eval_statement(context, statement[5])
	
	if _type_is_number(v1_t) and _type_is_number(v2_t)
	then
		local v1_n = v1_v:get()
		local v2_n = v2_v:get()
		
		return _builtin_types.int, ImmediateValue:new(v1_n ~= v2_n and 1 or 0)
	elseif _type_is_stringish(v1_t) and _type_is_stringish(v2_t)
	then
		local v1_s = _stringify_value(v1_t, v1_v)
		local v2_s = _stringify_value(v2_t, v2_v)
		
		return _builtin_types.int, ImmediateValue:new(v1_s ~= v2_s and 1 or 0)
	else
		_template_error(context, "Invalid operands to '!=' operator - '" .. _get_type_name(v1_t) .. "' and '" .. _get_type_name(v2_t) .. "'")
	end
end

_eval_bitwise_not = function(context, statement)
	local operand_t, operand_v = _eval_statement(context, statement[4])
	
	if operand_t == nil or operand_t.base ~= "number"
	then
		_template_error(context, "Invalid operand to '~' operator - expected numeric, got '" .. _get_type_name(operand_t) .. "'")
	end
	
	return operand_t, ImmediateValue:new(~operand_v:get())
end

_eval_logical_not = function(context, statement)
	local operand_t, operand_v = _eval_statement(context, statement[4])
	
	if operand_t == nil or operand_t.base ~= "number"
	then
		_template_error(context, "Invalid operand to '!' operator - expected numeric, got '" .. _get_type_name(operand_t) .. "'")
	end
	
	return _builtin_types.int, ImmediateValue:new(operand_v:get() == 0 and 1 or 0)
end

_eval_logical_and = function(context, statement)
	local v1_t, v1_v = _eval_statement(context, statement[4])
	
	if v1_t == nil or v1_t.base ~= "number"
	then
		_template_error(context, "Invalid left operand to '&&' operator - expected numeric, got '" .. _get_type_name(v1_t) .. "'")
	end
	
	if v1_v:get() == 0
	then
		return _builtin_types.int, ImmediateValue:new(0)
	end
	
	local v2_t, v2_v = _eval_statement(context, statement[5])
	
	if v2_t == nil or v2_t.base ~= "number"
	then
		_template_error(context, "Invalid right operand to '&&' operator - expected numeric, got '" .. _get_type_name(v2_t) .. "'")
	end
	
	if v2_v:get() == 0
	then
		return _builtin_types.int, ImmediateValue:new(0)
	end
	
	return _builtin_types.int, ImmediateValue:new(1)
end

_eval_logical_or = function(context, statement)
	local v1_t, v1_v = _eval_statement(context, statement[4])
	
	if v1_t == nil or v1_t.base ~= "number"
	then
		_template_error(context, "Invalid left operand to '||' operator - expected numeric, got '" .. _get_type_name(v1_t) .. "'")
	end
	
	if v1_v:get() ~= 0
	then
		return _builtin_types.int, ImmediateValue:new(1)
	end
	
	local v2_t, v2_v = _eval_statement(context, statement[5])
	
	if v2_t == nil or v2_t.base ~= "number"
	then
		_template_error(context, "Invalid right operand to '||' operator - expected numeric, got '" .. _get_type_name(v2_t) .. "'")
	end
	
	if v2_v:get() ~= 0
	then
		return _builtin_types.int, ImmediateValue:new(1)
	end
	
	return _builtin_types.int, ImmediateValue:new(0)
end

_eval_postfix_increment = function(context, statement)
	local value = statement[4]
	
	local value_t, value_v = _eval_statement(context, value)
	if value_t == nil or value_t.base ~= "number"
	then
		_template_error(context, "Invalid operand to postfix '++' operator - expected numeric, got '" .. _get_type_name(value_t) .. "'")
	end
	
	local old_value = value_v:get()
	
	local new_value = old_value + 1
	
	if value_t.int_mask ~= nil
	then
		new_value = new_value & value_t.int_mask
	end
	
	value_v:set(new_value)
	return value_t, ImmediateValue:new(old_value)
end

_eval_postfix_decrement = function(context, statement)
	local value = statement[4]
	
	local value_t, value_v = _eval_statement(context, value)
	if value_t == nil or value_t.base ~= "number"
	then
		_template_error(context, "Invalid operand to postfix '--' operator - expected numeric, got '" .. _get_type_name(value_t) .. "'")
	end
	
	local old_value = value_v:get()
	
	local new_value = old_value - 1
	
	if value_t.int_mask ~= nil
	then
		new_value = new_value & value_t.int_mask
	end
	
	value_v:set(new_value)
	return value_t, ImmediateValue:new(old_value)
end

_eval_unary_plus = function(context, statement)
	local value = statement[4]
	
	local value_t, value_v = _eval_statement(context, value)
	if value_t == nil or value_t.base ~= "number"
	then
		_template_error(context, "Invalid operand to unary '+' operator - expected numeric, got '" .. _get_type_name(value_t) .. "'")
	end
	
	return value_t, ImmediateValue:new(value_v:get())
end

_eval_unary_minus = function(context, statement)
	local value = statement[4]
	
	local value_t, value_v = _eval_statement(context, value)
	if value_t == nil or value_t.base ~= "number"
	then
		_template_error(context, "Invalid operand to unary '-' operator - expected numeric, got '" .. _get_type_name(value_t) .. "'")
	end
	
	return value_t, ImmediateValue:new(-1 * value_v:get())
end

expand_value = function(context, type_info, struct_arg_values, array_element_idx)
	if type_info.base == "struct"
	then
		local args_ok = true
		
		if struct_arg_values == nil
		then
			struct_arg_values = {}
		end
		
		for i = 1, math.max(#struct_arg_values, #type_info.arguments)
		do
			if i > #struct_arg_values or i > #type_info.arguments
			then
				args_ok = false
			else
				local dst_type = type_info.arguments[i][2]
				local got_type = struct_arg_values[i][1]
				
				if dst_type.is_ref
				then
					if dst_type.type_key ~= got_type.type_key
						or ((not got_type.is_array) ~= (not dst_type.is_array))
						or (got_type.is_const and not dst_type.is_const)
					then
						args_ok = false
					end
				else
					if not _type_assignable(dst_type, struct_arg_values[i][1])
					then
						args_ok = false
					end
				end
			end
		end
		
		if not args_ok
		then
			local got_types = table.concat(_map(struct_arg_values, function(v) return _get_type_name(v[1]) end), ", ")
			local expected_types = table.concat(_map(type_info.arguments, function(v) return _get_type_name(v[2]) end), ", ")
			
			_template_error(context, "Attempt to declare struct type '" .. _get_type_name(type_info) .. "' with incompatible argument types (" .. got_types .. ") - expected (" .. expected_types .. ")")
		end
		
		for i = 1, #struct_arg_values
		do
			local dst_type = type_info.arguments[i][2]
			
			if dst_type.is_ref
			then
				struct_arg_values[i] = { dst_type, struct_arg_values[i][2] }
			else
				struct_arg_values[i] = { dst_type, _make_value_from_value(context, dst_type, struct_arg_values[i][1], struct_arg_values[i][2], false) }
			end
		end
		
		local members = StructValue:new()
		
		local frame = {
			frame_type = FRAME_TYPE_STRUCT,
			struct_members = members,
			array_element_idx = array_element_idx,
			
			blocks_flowctrl_types = (FLOWCTRL_TYPE_RETURN | FLOWCTRL_TYPE_BREAK | FLOWCTRL_TYPE_CONTINUE),
		}
		
		table.insert(context.stack, frame)
		
		local old_func_var_base = context.func_var_base
		context.func_var_base = #context.var_stack + 1
		
		for i = 1, type_info.allocate_slots
		do
			table.insert(context.var_stack, _initialised_variable_placeholder)
		end
		
		for idx, arg in ipairs(type_info.arguments)
		do
			local arg_slot = type_info.arguments[idx].var_slot
			assert(arg_slot <= 0)
			
			assert(context.var_stack[context.func_var_base - arg_slot] == _initialised_variable_placeholder)
			context.var_stack[context.func_var_base - arg_slot] = struct_arg_values[idx]
		end
		
		_exec_statements(context, type_info.code)
		
		for i = 1, type_info.allocate_slots
		do
			table.remove(context.var_stack)
		end
		
		context.func_var_base = old_func_var_base
		
		table.remove(context.stack)
		
		return members
	else
		if context.declaring_local_var
		then
			if type_info.base == "number"
			then
				return PlainValue:new(0)
			elseif type_info.base == "string"
			then
				return PlainValue:new("")
			else
				error("Internal error: Unexpected base type '" .. type_info.base .. "' at " .. filename .. ":" .. line_num)
			end
		else
			if type_info.length == nil
			then
				_template_error(context, "Cannot use type '" .. _get_type_name(type_info) .. "' to declare a file variable")
			end
			
			if (context.next_variable + type_info.length) > context.interface:file_length()
			then
				_template_error(context, "Hit end of file when declaring variable")
			end
			
			local base_off = context.next_variable
			context.next_variable = base_off + type_info.length
			
			local data_type_fmt = (context.big_endian and ">" or "<") .. type_info.string_fmt
			return FileValue:new(context, base_off, type_info.length, data_type_fmt)
		end
	end
end

local function _decl_variable(context, statement, var_type, var_name, struct_arg_values, array_size, attributes, initial_value, is_local, is_private)
	local filename = statement[1]
	local line_num = statement[2]
	
	local iv_type, iv_value
	if initial_value ~= nil
	then
		iv_type, iv_value = _eval_statement(context, initial_value)
	end
	
	assert(type(var_type) == "table")
	local type_info = var_type
	
	if struct_arg_values ~= nil and type_info.base ~= "struct"
	then
		_template_error(context, "Variable declaration with parameters for non-struct type '" .. _get_type_name(type_info) .. "'")
	end
	
	local dest_tables
	
	if not (is_local or is_private) and _can_do_flowctrl_here(context, FLOWCTRL_TYPE_RETURN)
	then
		_template_error(context, "Attempt to declare non-local variable inside function")
	end
	
	local struct_frame = _topmost_frame_of_type(context, FRAME_TYPE_STRUCT)
	if is_local or is_private
	then
		dest_tables = {}
		
	elseif struct_frame ~= nil and not is_local and not is_private
	then
		dest_tables = { struct_frame.struct_members }
		
		if struct_frame.struct_members[var_name] ~= nil
		then
			_template_error(context, "Attempt to redefine struct member '" .. var_name .. "'")
		end
		
	else
		dest_tables = { context.global_vars }
	end
	
	local var_slot = statement.var_slot
	if var_slot == nil
	then
		local inspect = require 'inspect'
		error(inspect(statement))
	end
	
	assert(var_slot ~= nil)
	
	if var_slot <= 0
	then
		assert(context.func_var_base ~= nil)
		var_slot = context.func_var_base - var_slot
	end
	
	if context.var_stack[var_slot] ~= _initialised_variable_placeholder
	then
		_template_error(context, "Attempt to redefine variable '" .. var_name .. "' (previously defined at " .. context.var_stack[var_slot].def_filename .. ":" .. context.var_stack[var_slot].def_line .. ")")
	end
	
	if type_info.is_ref
	then
		if not is_local
		then
			_template_error(context, "Attempt to define non-local reference '" .. var_name .. "'")
		end
		
		if initial_value == nil
		then
			_template_error(context, "Attempt to define uninitialised reference '" .. var_name .. "'")
		end
		
		if iv_type == nil
			or type_info.type_key ~= iv_type.type_key
			or ((not type_info.is_const) and iv_type.is_const)
		then
			_template_error(context, "can't assign '" .. _get_type_name(iv_type) .. "' to type '" .. _get_type_name(type_info) .. "'")
		end
		
		for _,t in ipairs(dest_tables)
		do
			t[var_name] = { type_info, iv_value }
		end
		
		context.var_stack[var_slot] = { type_info, iv_value, def_filename = statement[1], def_line = statement[2] }
		
		return
	end
	
	if context.big_endian
	then
		type_info = util.make_big_endian_type(type_info)
	else
		type_info = util.make_little_endian_type(type_info)
	end
	
	local array_type_info = type_info
	
	if type_info.array_size ~= nil
	then
		assert(#type_info.array_size >= 1)
		
		if array_size ~= nil
		then
			_template_error(context, "Multidimensional arrays are not supported")
		end
		
		-- Filthy filthy filthy...
		array_size = { debug.getinfo(1,'S').source, debug.getinfo(1, 'l').currentline, "num", type_info.array_size[#type_info.array_size] }
	elseif array_size ~= nil
	then
		array_type_info = util.make_array_type(type_info)
	end
	
	-- Variable attributes (so far) are only used for defining encoding on character arrays, so
	-- we check for that attribute in this lovely kludge here.
	
	local string_charset
	local highlight_idx
	
	if attributes ~= nil
	then
		for i = 1, #attributes
		do
			local attr_name = attributes[i][1]
			local attr_value_type = attributes[i][2] and attributes[i][2][1]
			local attr_value = attributes[i][2] and attributes[i][2][2]
			
			if attr_name == "charset" and _type_is_char_array(array_type_info)
			then
				if string_charset ~= nil
				then
					_template_error(context, "Attribute 'charset' specified multiple times")
				end
				
				if not _type_is_stringish(attr_value_type)
				then
					_template_error(context, "Unexpected type '" .. _get_type_name(attr_value_type) .. "' used as value for 'charset' attribute (expected string)")
				end
				
				local charset_name = _stringify_value(attr_value_type, attr_value)
				local charset_valid = false
				
				for j = 1, #context.valid_charsets
				do
					if context.valid_charsets[j] == charset_name
					then
						charset_valid = true
						break
					end
				end
				
				if not charset_valid
				then
					_template_error(context, "Unrecognised character set '" .. charset_name .. "' specified")
				end
				
				string_charset = charset_name
			elseif attr_name == "highlight"
			then
				if highlight_idx ~= nil
				then
					_template_error(context, "Attribute 'highlight' specified multiple times")
				end
				
				if not _type_is_number(attr_value_type)
				then
					_template_error(context, "Unexpected type '" .. _get_type_name(attr_value_type) .. "' used as value for 'highlight' attribute (expected int)")
				end
				
				highlight_idx = attr_value:get()
			else
				_template_error(context, "Invalid variable attribute '" .. attr_name .. "' used with type '" .. _get_type_name(array_type_info) .. "'")
			end
		end
	end
	
	local root_value
	
	if array_size == nil
	then
		local base_off = context.next_variable
		
		root_value = expand_value(context, type_info, struct_arg_values, nil)
		
		for _,t in ipairs(dest_tables)
		do
			t[var_name] = { type_info, root_value }
		end
	else
		local ArrayLength_type, ArrayLength_val = _eval_statement(context, array_size)
		if ArrayLength_type == nil or ArrayLength_type.base ~= "number"
		then
			_template_error(context, "Expected numeric type for array size, got '" .. _get_type_name(ArrayLength_type) .. "'")
		end
		
		if type_info.base ~= "struct" and not context.declaring_local_var
		then
			local data_type_fmt = (context.big_endian and ">" or "<") .. type_info.string_fmt
			root_value = FileArrayValue:new(context, context.next_variable, ArrayLength_val:get(), type_info.length, data_type_fmt)
			root_value.charset = string_charset
			
			context.next_variable = context.next_variable + (ArrayLength_val:get() * type_info.length)
			
			for _,t in ipairs(dest_tables)
			do
				t[var_name] = {
					array_type_info,
					root_value
				}
			end
		else
			root_value = ArrayValue:new()
			
			if not context.declaring_local_var
			then
				root_value.offset = context.next_variable
			end
			
			for _,t in ipairs(dest_tables)
			do
				t[var_name] = {
					array_type_info,
					root_value
				}
			end
			
			for i = 0, ArrayLength_val:get() - 1
			do
				local value = expand_value(context, type_info, struct_arg_values, i)
				table.insert(root_value, value)
				
				context.interface.yield()
			end
		end
		
		type_info = array_type_info
	end
	
	root_value.__INTERNAL_highlight_idx = highlight_idx
	
	if initial_value ~= nil
	then
		_assign_value(context, type_info, root_value, iv_type, iv_value)
	end
	
	context.var_stack[var_slot] = { array_type_info, root_value, def_filename = statement[1], def_line = statement[2] }
end

_eval_variable = function(context, statement)
	local var_type = statement[4]
	local var_name = statement[5]
	local struct_args = statement[6]
	local array_size = statement[7]
	local attributes = statement[8]
	
	local struct_arg_values = nil
	if struct_args ~= nil
	then
		struct_arg_values = {}
		
		for i = 1, #struct_args
		do
			struct_arg_values[i] = { _eval_statement(context, struct_args[i]) }
		end
	end
	
	local attributes_evaluated = nil
	if attributes ~= nil
	then
		attributes_evaluated = {}
		
		for i = 1, #attributes
		do
			local attr_name = attributes[i][3]
			local attr_value = attributes[i][4]
			
			if attr_value ~= nil
			then
				attr_value = { _eval_statement(context, attr_value) }
			end
			
			attributes_evaluated[i] = { attr_name, attr_value }
		end
	end
	
	local was_declaring_local_var = context.declaring_local_var
	
	if statement.private
	then
		context.declaring_local_var = false
	end
	
	_decl_variable(context, statement, statement.type_info, var_name, struct_arg_values, array_size, attributes_evaluated, nil, false, statement.private)
	
	context.declaring_local_var = was_declaring_local_var
end

_eval_local_variable = function(context, statement)
	local var_type = statement[4]
	local var_name = statement[5]
	local struct_args = statement[6]
	local array_size = statement[7]
	local initial_value = statement[8]
	
	local struct_arg_values = nil
	if struct_args ~= nil
	then
		struct_arg_values = {}
		
		for i = 1, #struct_args
		do
			struct_arg_values[i] = { _eval_statement(context, struct_args[i]) }
		end
	end
	
	local was_declaring_local_var = context.declaring_local_var
	context.declaring_local_var = true
	
	_decl_variable(context, statement, statement.type_info, var_name, struct_arg_values, array_size, nil, initial_value, true)
	
	context.declaring_local_var = was_declaring_local_var
end

_eval_assign = function(context, statement)
	local dst_expr = statement[4]
	local src_expr = statement[5]
	
	local dst_type, dst_val = _eval_statement(context, dst_expr)
	local src_type, src_val = _eval_statement(context, src_expr)
	
	if dst_type.is_const
	then
		_template_error(context, "Attempted modification of const type '" .. _get_type_name(dst_type) .. "'")
	end
	
	_assign_value(context, dst_type, dst_val, src_type, src_val)
	
	return dst_type, dst_val
end

_eval_call = function(context, statement)
	local func_name = statement[4]
	local func_args = statement[5]
	
	local func_defn = context.functions[func_name]
	if func_defn == nil
	then
		_template_error(context, "Attempt to call undefined function '" .. func_name .. "'")
	end
	
	local func_arg_values = {}
	local args_ok = true
	
	for i = 1, #func_args
	do
		func_arg_values[i] = { _eval_statement(context, func_args[i]) }
	end
	
	for i = #func_arg_values + 1, #func_defn.defaults
	do
		func_arg_values[i] = { _eval_statement(context, func_defn.defaults[i]) }
	end
	
	for i = 1, math.max(#func_arg_values, #func_defn.arguments)
	do
		if func_defn.arguments[i] == _variadic_placeholder
		then
			break
		end
		
		if i > #func_arg_values or i > #func_defn.arguments
		then
			args_ok = false
		else
			local dst_type = func_defn.arguments[i]
			local got_type = func_arg_values[i][1]
			
			if dst_type.is_ref
			then
				if dst_type.type_key ~= got_type.type_key
					or ((not got_type.is_array) ~= (not dst_type.is_array))
					or (got_type.is_const and not dst_type.is_const)
				then
					args_ok = false
				end
			else
				if not _type_assignable(dst_type, func_arg_values[i][1])
				then
					args_ok = false
				end
			end
		end
	end
	
	if not args_ok
	then
		local got_types = table.concat(_map(func_arg_values, function(v) return _get_type_name(v[1]) end), ", ")
		local expected_types = table.concat(_map(func_defn.arguments, function(v) return _get_type_name(v) end), ", ")
		
		_template_error(context, "Attempt to call function " .. func_name .. "(" .. expected_types .. ") with incompatible argument types (" .. got_types .. ")")
	end
	
	for i = 1, #func_arg_values
	do
		local dst_type = func_defn.arguments[i]
		
		if dst_type == _variadic_placeholder
		then
			break
		end
		
		if dst_type.is_ref
		then
			func_arg_values[i] = { dst_type, func_arg_values[i][2] }
		else
			func_arg_values[i] = { dst_type, _make_value_from_value(context, dst_type, func_arg_values[i][1], func_arg_values[i][2], false) }
		end
	end
	
	return func_defn.impl(context, func_arg_values)
end

_eval_return = function(context, statement)
	local retval = statement[4]
	
	if not _can_do_flowctrl_here(context, FLOWCTRL_TYPE_RETURN)
	then
		_template_error(context, "'return' statement not allowed here")
	end
	
	local func_frame = _topmost_frame_of_type(context, FRAME_TYPE_FUNCTION)
	
	if retval
	then
		local retval_t, retval_v = _eval_statement(context, retval)
		
		if not _type_assignable(func_frame.return_type, retval_t)
		then
			_template_error(context, "return operand type '" .. _get_type_name(retval_t) .. "' not compatible with function return type '" .. _get_type_name(func_frame.return_type) .. "'")
		end
		
		if retval_t
		then
			retval = { retval_t, retval_v }
		else
			retval = nil
		end
	elseif func_frame.return_type ~= nil
	then
		_template_error(context, "return without an operand in function that returns type '" .. _get_type_name(func_frame.return_type) .. "'")
	end
	
	return { flowctrl = FLOWCTRL_TYPE_RETURN }, retval
end

_eval_func_defn = function(context, statement)
	local func_ret_type   = statement[4]
	local func_name       = statement[5]
	local func_args       = statement[6]
	local func_statements = statement[7]
	
	if #context.stack > 1
	then
		_template_error(context, "Attempt to define function inside another block")
	end
	
	if context.functions[func_name] ~= nil
	then
		_template_error(context, "Attempt to redefine function '" .. func_name .. "'")
	end
	
	local ret_type = statement.return_type_info
	
	local arg_types = {}
	for i = 1, #func_args
	do
		table.insert(arg_types, func_args[i].type_info)
	end
	
	local impl_func = function(context, arguments)
		local frame = {
			frame_type = FRAME_TYPE_FUNCTION,
			
			handles_flowctrl_types = FLOWCTRL_TYPE_RETURN,
			blocks_flowctrl_types  = (FLOWCTRL_TYPE_BREAK | FLOWCTRL_TYPE_CONTINUE),
			
			return_type = ret_type,
		}
		
		if #arguments ~= #func_args
		then
			error("Internal error: wrong number of function arguments")
		end
		
		table.insert(context.stack, frame)
		
		local old_func_var_base = context.func_var_base
		context.func_var_base = #context.var_stack + 1
		
		for i = 1, statement.allocate_slots
		do
			table.insert(context.var_stack, _initialised_variable_placeholder)
		end
		
		for i = 1, #arguments
		do
			local arg_type = arg_types[i]
			local arg_name = func_args[i][2]
			local arg_slot = func_args[i].var_slot
			
			if not _type_assignable(arg_type, arguments[i][1])
			then
				error("Internal error: incompatible function arguments")
			end
			
			assert(arg_slot <= 0)
			arg_slot = context.func_var_base - arg_slot
			
			assert(context.var_stack[arg_slot] == _initialised_variable_placeholder)
			context.var_stack[arg_slot] = arguments[i]
		end
		
		local retval
		
		for _, statement in ipairs(func_statements)
		do
			local sr_t, sr_v = _eval_statement(context, statement)
			
			if sr_t and sr_t.flowctrl ~= nil
			then
				if sr_t.flowctrl == FLOWCTRL_TYPE_RETURN
				then
					retval = sr_v
					break
				else
					error("Internal error: unexpected flowctrl type '" .. sr_t.flowctrl .. "'")
				end
			end
		end
		
		for i = 1, statement.allocate_slots
		do
			table.remove(context.var_stack)
		end
		
		context.func_var_base = old_func_var_base
		
		table.remove(context.stack)
		
		if retval == nil and ret_type ~= nil
		then
			_template_error(context, "No return statement in function returning non-void")
		end
		
		if retval ~= nil
		then
			return table.unpack(retval)
		end
	end
	
	context.functions[func_name] = {
		arguments = arg_types,
		defaults  = {},
		impl      = impl_func,
	}
end

_eval_struct_defn = function(context, statement)
	local struct_name       = statement[4]
	local struct_args       = statement[5]
	local struct_statements = statement[6]
	local typedef_name      = statement[7]
	local var_decl          = statement[8]
	
	if var_decl ~= nil
	then
		local var_name   = var_decl[1]
		local var_args   = var_decl[2]
		local array_size = var_decl[3]
		
		_decl_variable(context, statement, statement.type_info, var_name, var_args, array_size, nil, nil, false)
	end
end

_eval_typedef = function(context, statement)
	local type_name    = statement[4]
	local typedef_name = statement[5]
	local array_size   = statement[6]
	
	assert(statement.type_info ~= nil)
	
	local type_info = statement.type_info
	
	if array_size ~= nil
	then
		local ArrayLength_type, ArrayLength_val = _eval_statement(context, array_size)
		if ArrayLength_type == nil or ArrayLength_type.base ~= "number"
		then
			_template_error(context, "Expected numeric type for array size, got '" .. _get_type_name(ArrayLength_type) .. "'")
		end
		
		table.insert(type_info.array_size, ArrayLength_val:get())
	end
end

_eval_enum = function(context, statement)
	local type_name    = statement[4]
	local enum_name    = statement[5]
	local members      = statement[6]
	local typedef_name = statement[7]
	local var_decl     = statement[8]
	
	local type_info = statement.type_info
	
	-- Define each member as a const variable of the base type in the current scope.
	
	local next_member_val = 0
	
	for _, member_pair in pairs(members)
	do
		local member_name, member_expr = table.unpack(member_pair)
		local member_slot = member_pair.var_slot
		
		if member_expr ~= nil
		then
			local member_t, member_v = _eval_statement(context, member_expr)
			
			if member_t == nil or member_t.base ~= "number"
			then
				_template_error(context, "Invalid type '" .. _get_type_name(member_t) .. "' for enum member '" .. member_name .. "'", member_expr[1], member_expr[2])
			end
			
			next_member_val = member_v:get()
		end
		
		if member_slot <= 0
		then
			member_slot = context.func_var_base - member_slot
		end
		
		assert(context.var_stack[member_slot] == _initialised_variable_placeholder)
		context.var_stack[member_slot] = { type_info, ImmediateValue:new(next_member_val) }
		
		next_member_val = next_member_val + 1
	end
	
	-- Define the enum type as a copy of its base type
	
	if var_decl ~= nil
	then
		local var_name   = var_decl[1]
		local array_size = var_decl[3]
		
		_decl_variable(context, statement, type_info, var_name, nil, array_size, nil, nil, false)
	end
end

_eval_if = function(context, statement)
	for i = 4, #statement
	do
		local cond = statement[i][2] and statement[i][1] or { "BUILTIN", 0, "num", 1 }
		local code = statement[i][2] or statement[i][1]
		
		local cond_t, cond_v = _eval_statement(context, cond)
		
		if (cond_t and cond_t.base) ~= "number"
		then
			_template_error(context, "Expected numeric expression to if/else if", cond[1], cond[2])
		end
		
		if cond_v:get() ~= 0
		then
			local frame = {
				frame_type = FRAME_TYPE_SCOPE,
			}
			
			table.insert(context.stack, frame)
			
			for _, statement in ipairs(code)
			do
				local sr_t, sr_v = _eval_statement(context, statement)
				
				if sr_t and sr_t.flowctrl ~= nil
				then
					table.remove(context.stack)
					return sr_t, sr_v
				end
			end
			
			table.remove(context.stack)
			
			break
		end
	end
end

local function _clear_borrow_slots(context, borrow_slots_base, borrow_slots_num)
	local borrow_slot_base = borrow_slots_base <= 0
		and context.func_var_base - borrow_slots_base
		or borrow_slots_base
	
	for i = 0, borrow_slots_num - 1
	do
		local borrow_slot = borrow_slot_base + i
		context.var_stack[borrow_slot] = _initialised_variable_placeholder
	end
end

_eval_for = function(context, statement)
	local init_expr = statement[4]
	local cond_expr = statement[5]
	local iter_expr = statement[6]
	local body      = statement[7]
	
	local outer_borrow_slots_base = statement.outer_borrow_slots_base
	local outer_borrow_slots_num = statement.outer_borrow_slots_num
	
	local inner_borrow_slots_base = statement.inner_borrow_slots_base
	local inner_borrow_slots_num = statement.inner_borrow_slots_num
	
	local frame = {
		frame_type = FRAME_TYPE_SCOPE,
		handles_flowctrl_types = (FLOWCTRL_TYPE_BREAK | FLOWCTRL_TYPE_CONTINUE),
	}
	
	table.insert(context.stack, frame)
	
	if init_expr
	then
		_eval_statement(context, init_expr)
	end
	
	while true
	do
		if cond_expr
		then
			local cond_t, cond_v = _eval_statement(context, cond_expr)
			
			if (cond_t and cond_t.base) ~= "number"
			then
				_template_error(context, "Unexpected type '" .. _get_type_name(cond_t) .. "' used as for loop condition", cond_expr[1], cond_expr[2])
			end
			
			if cond_v:get() == 0
			then
				break
			end
		else
			context.interface.yield()
		end
		
		-- Define another scope inside the loop's outer scope so any variables defined
		-- inside the loop are cleaned up on each iteration.
		
		local frame = {
			frame_type = FRAME_TYPE_SCOPE,
		}
		
		table.insert(context.stack, frame)
		
		for _, statement in ipairs(body)
		do
			local sr_t, sr_v = _eval_statement(context, statement)
			
			if sr_t and sr_t.flowctrl ~= nil
			then
				if sr_t.flowctrl == FLOWCTRL_TYPE_BREAK
				then
					_clear_borrow_slots(context, inner_borrow_slots_base, inner_borrow_slots_num)
					_clear_borrow_slots(context, outer_borrow_slots_base, outer_borrow_slots_num)
					
					table.remove(context.stack)
					table.remove(context.stack)
					return
				elseif sr_t.flowctrl == FLOWCTRL_TYPE_CONTINUE
				then
					break
				else
					_clear_borrow_slots(context, inner_borrow_slots_base, inner_borrow_slots_num)
					_clear_borrow_slots(context, outer_borrow_slots_base, outer_borrow_slots_num)
					
					table.remove(context.stack)
					table.remove(context.stack)
					return sr_t, sr_v
				end
			end
		end
		
		table.remove(context.stack)
		
		_clear_borrow_slots(context, inner_borrow_slots_base, inner_borrow_slots_num)
		
		if iter_expr
		then
			_eval_statement(context, iter_expr)
		end
	end
	
	_clear_borrow_slots(context, outer_borrow_slots_base, outer_borrow_slots_num)
	
	table.remove(context.stack)
end

_eval_switch = function(context, statement)
	local expr = statement[4]
	local cases = statement[5]
	
	local expr_t, expr_v = _eval_statement(context, expr)
	
	if expr_t == nil or (expr_t.base ~= "number" and expr_t.base ~= "string")
	then
		_template_error(context, "Unexpected type '" .. _get_type_name(expr_t) .. "' passed to 'switch' statement (expected number or string)")
	end
	
	local found_match = false
	local case_match = {}
	
	for _, case in ipairs(cases)
	do
		local case_expr = case[1]
		local case_body = case[2]
		
		if case_expr ~= nil
		then
			local case_expr_t, case_expr_v = _eval_statement(context, case_expr)
			
			if case_expr_t == nil or case_expr_t.base ~= expr_t.base
			then
				_template_error(context, "Unexpected type '" .. _get_type_name(case_expr_t) .. "' passed to 'case' statement (expected '" .. _get_type_name(expr_t) .. "')", case_expr[1], case_expr[2])
			end
			
			if expr_v:get() == case_expr_v:get()
			then
				table.insert(case_match, true)
				found_match = true
			else
				table.insert(case_match, false)
			end
		else
			table.insert(case_match, false)
		end
	end
	
	if not found_match
	then
		for idx, case in ipairs(cases)
		do
			local case_expr = case[1]
			local case_body = case[2]
			
			if case_expr == nil
			then
				case_match[idx] = true
			end
		end
	end
	
	local frame = {
		frame_type = FRAME_TYPE_SCOPE,
		handles_flowctrl_types = FLOWCTRL_TYPE_BREAK,
	}
	
	table.insert(context.stack, frame)
	
	found_match = false
	
	for idx, case in ipairs(cases)
	do
		local case_body = case[2]
		
		if not found_match and case_match[idx]
		then
			found_match = true
		end
		
		if found_match
		then
			for _, statement in ipairs(case_body)
			do
				local sr_t, sr_v = _eval_statement(context, statement)
				
				if sr_t and sr_t.flowctrl ~= nil
				then
					if sr_t.flowctrl == FLOWCTRL_TYPE_BREAK
					then
						table.remove(context.stack)
						return
					else
						table.remove(context.stack)
						return sr_t, sr_v
					end
				end
			end
		end
	end
	
	table.remove(context.stack)
end

_eval_block = function(context, statement)
	local body = statement[4]
	
	local borrow_slots_base = statement.borrow_slots_base
	local borrow_slots_num = statement.borrow_slots_num
	
	local frame = {
		frame_type = FRAME_TYPE_SCOPE,
	}
	
	table.insert(context.stack, frame)
	
	for _, statement in ipairs(body)
	do
		local sr_t, sr_v = _eval_statement(context, statement)
		
		if sr_t and sr_t.flowctrl ~= nil
		then
			_clear_borrow_slots(context, borrow_slots_base, borrow_slots_num)
			
			table.remove(context.stack)
			return sr_t, sr_v
		end
	end
	
	_clear_borrow_slots(context, borrow_slots_base, borrow_slots_num)
	
	table.remove(context.stack)
end

_eval_break = function(context, statement)
	if not _can_do_flowctrl_here(context, FLOWCTRL_TYPE_BREAK)
	then
		_template_error(context, "'break' statement not allowed here")
	end
	
	return { flowctrl = FLOWCTRL_TYPE_BREAK }, retval
end

_eval_continue = function(context, statement)
	if not _can_do_flowctrl_here(context, FLOWCTRL_TYPE_CONTINUE)
	then
		_template_error(context, "'continue' statement not allowed here")
	end
	
	return { flowctrl = FLOWCTRL_TYPE_CONTINUE }, retval
end

_eval_cast = function(context, statement)
	local type_name = statement[4]
	local value_expr = statement[5]
	
	local type_info = statement.type_info
	
	local value_t, value_v = _eval_statement(context, value_expr)
	if not _type_assignable(type_info, value_t)
	then
		_template_error(context, "Invalid conversion from '" .. _get_type_name(value_t) .. "' to '" .. _get_type_name(type_info) .. "'")
	end
	
	if type_info.int_mask ~= nil
	then
		value_v = ImmediateValue:new(value_v:get() & type_info.int_mask)
	else
		_template_error(context, "Internal error: Unhandled cast from '" .. _get_type_name(value_t) .. "' to '" .. _get_type_name(type_info) .. "'")
	end
	
	return type_info, value_v
end

_eval_ternary = function(context, statement)
	local cond_expr     = statement[4]
	local if_true_expr  = statement[5]
	local if_false_expr = statement[6]
	
	local cond_t, cond_v = _eval_statement(context, cond_expr)
	if cond_t == nil or cond_t.base ~= "number"
	then
		_template_error(context, "Invalid condition operand to ternary operator - expected numeric, got '" .. _get_type_name(cond_t) .. "'")
	end
	
	if cond_v:get() ~= 0
	then
		-- Condition is true
		return _eval_statement(context, if_true_expr)
	else
		-- Condition is false
		return _eval_statement(context, if_false_expr)
	end
end

_eval_statement = function(context, statement)
	local filename = statement[1]
	local line_num = statement[2]
	
	context.interface.yield()
	
	local op = statement[3]
	
	if _ops[op] ~= nil
	then
		table.insert(context.st_stack, statement)
		local result = { _ops[op](context, statement) }
		table.remove(context.st_stack)
		
		return table.unpack(result);
	else
		error("Internal error: unexpected op '" .. op .. "' at " .. filename .. ":" .. line_num)
	end
	
end

_exec_statements = function(context, statements)
	for _, statement in ipairs(statements)
	do
		_eval_statement(context, statement)
	end
end

_ops = {
	num = _eval_number,
	str = _eval_string,
	ref = _eval_ref,
	
	["variable"]       = _eval_variable,
	["local-variable"] = _eval_local_variable,
	["assign"]         = _eval_assign,
	["call"]           = _eval_call,
	["return"]         = _eval_return,
	["function"]       = _eval_func_defn,
	["struct"]         = _eval_struct_defn,
	["typedef"]        = _eval_typedef,
	["enum"]           = _eval_enum,
	["if"]             = _eval_if,
	["for"]            = _eval_for,
	["switch"]         = _eval_switch,
	["block"]          = _eval_block,
	["break"]          = _eval_break,
	["continue"]       = _eval_continue,
	["cast"]           = _eval_cast,
	["ternary"]        = _eval_ternary,
	
	add      = _eval_add,
	subtract = _numeric_op_func(function(v1, v2) return v1 - v2 end, "-"),
	multiply = _numeric_op_func(function(v1, v2) return v1 * v2 end, "*"),
	divide   = _numeric_op_func(function(v1, v2) return v1 / v2 end, "/"),
	mod      = _numeric_op_func(function(v1, v2) return v1 % v2 end, "%"),
	
	["left-shift"]  = _numeric_op_func(function(v1, v2) return v1 << v2 end, "<<"),
	["right-shift"] = _numeric_op_func(function(v1, v2) return v1 >> v2 end, ">>"),
	
	["bitwise-not"] = _eval_bitwise_not,
	["bitwise-and"] = _numeric_op_func(function(v1, v2) return v1 & v2 end, "&"),
	["bitwise-xor"] = _numeric_op_func(function(v1, v2) return v1 ^ v2 end, "^"),
	["bitwise-or"]  = _numeric_op_func(function(v1, v2) return v1 | v2 end, "|"),
	
	["less-than"]             = _numeric_op_func(function(v1, v2) return v1 <  v2 and 1 or 0 end, "<"),
	["less-than-or-equal"]    = _numeric_op_func(function(v1, v2) return v1 <= v2 and 1 or 0 end, "<="),
	["greater-than"]          = _numeric_op_func(function(v1, v2) return v1 >  v2 and 1 or 0 end, ">"),
	["greater-than-or-equal"] = _numeric_op_func(function(v1, v2) return v1 >= v2 and 1 or 0 end, ">="),
	
	["equal"]     = _eval_equal,
	["not-equal"] = _eval_not_equal,
	
	["logical-not"] = _eval_logical_not,
	["logical-and"] = _eval_logical_and,
	["logical-or"]  = _eval_logical_or,
	
	["postfix-increment"] = _eval_postfix_increment,
	["postfix-decrement"] = _eval_postfix_decrement,
	
	["plus"]  = _eval_unary_plus,
	["minus"] = _eval_unary_minus,
}

local function _resolve_types(statements)
	local block_stack = { _builtin_types, {} }
	
	local find_type = function(type_name)
		for i = #block_stack, 1, -1
		do
			if block_stack[i][type_name] ~= nil
			then
				return block_stack[i][type_name]
			end
		end
	end
	
	local process_statement
	local process_optional_statement
	local process_statements
	local process_block
	
	process_statement = function(statement)
		local op = statement[3]
		
		if op == "function"
		then
			local func_statements = statement[7]
			process_block(func_statements)
			
		elseif op == "struct"
		then
			local struct_statements = statement[6]
			local var_decl          = statement[8]
			
			-- TODO: Define struct type
			
			process_block(struct_statements)
			
			if var_decl ~= nil
			then
				local var_args   = var_decl[2]
				local array_size = var_decl[3]
				
				process_statements(var_args)
				process_statement(array_size)
			end
			
		elseif op == "typedef"
		then
			local array_size = statement[6]
			walk_optional(array_size)
			
		elseif op == "enum"
		then
			local members  = statement[6]
			local var_decl = statement[8]
			
			for _, member_pair in pairs(members)
			do
				local member_name, member_expr = table.unpack(member_pair)
				walk_optional(member_expr)
			end
			
			if var_decl ~= nil
			then
				local var_args   = var_decl[2]
				local array_size = var_decl[3]
				
				walk_array(var_args)
				_walk_statement(array_size, func)
			end
			
		elseif op == "if"
		then
			for i = 4, #statement
			do
				local cond = statement[i][2] and statement[i][1] or nil
				local code = statement[i][2] or statement[i][1]
				
				if cond ~= nil
				then
					process_statement(cond)
				end
				
				process_block(code)
			end
			
		elseif op == "for"
		then
			local init_expr = statement[4]
			local cond_expr = statement[5]
			local iter_expr = statement[6]
			local body      = statement[7]
			
			process_optional_statement(init_expr)
			process_optional_statement(cond_expr)
			process_optional_statement(iter_expr)
			
			process_block(body)
			
		elseif op == "switch"
		then
			
		elseif op == "block"
		then
			process_block(statement[4])
			
		else
			_visit_statement_children(statement, process_statement)
		end
	end
	
	process_optional_statement = function(statement)
		if statement ~= nil
		then
			process_statement(statement)
		end
	end
	
	process_statements = function(statements)
		for _, statement in ipairs(statements)
		do
			process_statement(statement)
		end
	end
	
	process_block = function(statements)
		table.insert(block_stack, {})
		process_statements(statements)
		table.remove(block_stack)
	end
	
	process_statements(statements)
end

--- External entry point into the interpreter
-- @function execute
--
-- @param interface Table of interface functions to be used by the interpreter.
-- @param statements AST table as returned by the parser.
--
-- The interface table must have the following functions:
--
-- interface.set_data_type(offset, length, data_type)
-- interface.set_comment(offset, length, comment_text)
--
-- Thin wrappers around the REHex APIs, to allow for testing.
--
-- interface.yield()
--
-- Periodically called by the executor to allow processing UI events.
-- An error() may be raised within to abort the interpreter.

local function execute(interface, statements)
	statements = util.deep_copy_table(statements)
	
	local context = {
		interface = interface,
		
		functions = {},
		stack = {},
		
		-- This table holds the top-level "global" (i.e. not "local") variables by name.
		-- Each element points to a tuple of { type, value } like other rvalues.
		global_vars = {},
		
		var_stack = {},
		func_var_base = nil,
		
		next_variable = 0,
		
		-- Are we currently accessing variables from the file as big endian? Toggled by
		-- the built-in BigEndian() and LittleEndian() functions.
		big_endian = false,
		
		declaring_local_var = false,
		
		-- Stack of statements currently being executed, used for error reporting.
		st_stack = {},
		
		template_error = _template_error,
		
		valid_charsets = interface.get_valid_charsets(),
	}
	
	for k, v in pairs(_builtin_functions)
	do
		context.functions[k] = v
	end
	
	VarAllocator._allocate_variables(context, statements, _builtin_variables, _initialised_variable_placeholder)
	TypeMapper._resolve_types(context, statements, _builtin_types)
	
	table.insert(context.stack, {
		frame_type = FRAME_TYPE_BASE,
	})
	
	_exec_statements(context, statements)
	
	local set_comments = function(set_comments, name, type_info, value)
		local do_struct = function(v)
			for k,m in _sorted_pairs(v)
			do
				set_comments(set_comments, k, m[1], m[2])
			end
		end
		
		if type_info.is_array and type_info.base == "struct"
		then
			local elem_type = util.make_nonarray_type(type_info)
			
			for i = 1, #value
			do
				do_struct(value[i])
				
				local data_start, data_end = value[i]:data_range()
				if data_start ~= nil
				then
					context.interface.set_comment(data_start, (data_end - data_start), name .. "[" .. (i - 1) .. "]")
				end
			end
		else
			if type_info.base == "struct"
			then
				do_struct(value)
			end
			
			local data_start, data_end = value:data_range()
			if data_start ~= nil
			then
				context.interface.set_comment(data_start, (data_end - data_start), name)
			end
		end
	end
	
	local set_types = function(set_types, name, type_info, value)
		local do_struct = function(v)
			for k,m in _sorted_pairs(v)
			do
				set_types(set_types, k, m[1], m[2])
			end
		end
		
		if type_info.is_array and type_info.base == "struct"
		then
			local elem_type = util.make_nonarray_type(type_info)
			
			for i = 1, #value
			do
				do_struct(value[i])
			end
		elseif type_info.base == "struct"
		then
			do_struct(value)
		elseif type_info.rehex_type ~= nil
		then
			-- If this is a char array we assume it is a string and don't set the s8 data type
			-- for the range, else it would be displayed as a list of integers rather than a
			-- contiguous byte sequence.
			
			if value.charset ~= nil
			then
				local data_start, data_end = value:data_range()
				if data_start ~= nil
				then
					context.interface.set_data_type(data_start, (data_end - data_start), "text:" .. value.charset)
				end
			elseif not (type_info.is_array and (type_info.type_key == _builtin_types.char.type_key or type_info.type_key == _builtin_types.uint8_t.type_key))
			then
				local data_start, data_end = value:data_range()
				if data_start ~= nil
				then
					context.interface.set_data_type(data_start, (data_end - data_start), type_info.rehex_type)
				end
			end
		end
	end
	
	local set_highlights = function(set_highlights, name, type_info, value)
		local do_struct = function(v)
			for k,m in _sorted_pairs(v)
			do
				set_highlights(set_highlights, k, m[1], m[2])
			end
		end
		
		if value.__INTERNAL_highlight_idx ~= nil
		then
			local data_start, data_end = value:data_range()
			if data_start ~= nil
			then
				context.interface.set_highlight(data_start, (data_end - data_start), value.__INTERNAL_highlight_idx)
			end
		end
		
		if type_info.is_array and type_info.base == "struct"
		then
			for i = 1, #value
			do
				do_struct(value[i])
			end
		elseif type_info.base == "struct"
		then
			do_struct(value)
		end
	end
	
	for k,v in _sorted_pairs(context.global_vars)
	do
		set_comments(set_comments, k, v[1], v[2])
		set_types(set_types, k, v[1], v[2])
		set_highlights(set_highlights, k, v[1], v[2])
	end
end

M.execute = execute

return M
