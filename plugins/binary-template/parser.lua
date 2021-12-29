-- Binary Template plugin for REHex
-- Copyright (C) 2021 Daniel Collins <solemnwarning@solemnwarning.net>
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

local M = {}

--local lpeg = require 'lpeg'
local lpeg = require 'lulpeg.lulpeg'
setmetatable(_ENV, { __index=lpeg })

local function comment(openp,endp)
    openp = P(openp)
    endp = P(endp)
    local upto_endp = (1 - endp) ^ 1
    return openp * upto_endp * endp
end

local function input_pos_to_file_and_line_num(text, pos)
	local filename = "UNKNOWN FILE";
	local line_num = 1;
	
	local i = 1;
	while i <= pos
	do
		local m_filename, m_line_num = text:sub(i, pos):match("#file%s+([^\n]+)%s+(%d+)\n")
		
		if m_filename ~= nil
		then
			filename = m_filename
			line_num = math.floor(m_line_num)
			
			i = text:find("\n", i)
		elseif text:sub(i, i) == "\n"
		then
			line_num = line_num + 1
		end
		
		i = i + 1
	end
	
	return filename, line_num;
end

local function _parser_fallback(text, pos)
	-- Getting here means we're trying to parse something and none of the real captures have
	-- matched, so any actual text is a parse error.
	
	pos = pos - 1
	
	if pos < text:len()
	then
		local pos_filename, pos_line_num = input_pos_to_file_and_line_num(text, pos)
		error("Parse error at " .. pos_filename .. ":" .. pos_line_num .. " (at '" .. text:sub(pos, pos + 10) .. "')")
	end
	
	return nil
end

local function _consume_directive(text, pos)
	-- Directives from the preprocessor begin at column zero, anything else is from the
	-- template source.
	
	if (pos == 2 or text:sub(pos - 2, pos - 2) == "\n") and text:sub(pos - 1, pos - 1) == "#"
	then
		local directive_end = text:find("\n", pos);
		return directive_end + 1;
	end
	
	return nil
end

local function _capture_position(text, pos)
	local filename, line_num = input_pos_to_file_and_line_num(text, pos)
	return pos, filename, line_num
end

local function _capture_string(text, pos)
	local s = ""
	
	for i = pos, text:len()
	do
		local c = text:sub(i, i)
		
		if c == "\\"
		then
			-- TODO
		elseif c == '"'
		then
			return i + 1, s
		else
			s = s .. c
		end
	end
	
	local filename, line_num = input_pos_to_file_and_line_num(text, pos - 1)
	error("Unmatched \" at " .. filename .. ":" .. line_num)
end

local function _capture_type(text, pos)
	local _, match_end, struct_name = text:find("^struct%s+([%a_][%d%a_]*)%s*", pos)
	
	if struct_name ~= nil
	then
		return match_end + 1, "struct " .. struct_name
	else
		_, match_end, type_name = text:find("^([%a_][%d%a_]*)%s*", pos)
		
		if type_name ~= nil
		then
			return match_end + 1, type_name
		else
			return pos
		end
	end
end

local spc = S(" \t\r\n")^0
local digit = R('09')
local number = C( P('-')^-1 * digit^1 * ( P('.') * digit^1 )^-1 ) / tonumber * spc
local letter = R('AZ','az')
local name = C( letter * (digit+letter+"_")^0 ) * spc
local name_nospc = C( letter * (digit+letter+"_")^0 )
local comma  = P(",") * spc

local _parser = spc * P{
	"TEMPLATE";
	TEMPLATE =
		Ct( (V("STMT") + P(1) * P(_parser_fallback)) ^ 0),
	
	VALUE_NUM = Cc("num") * number,
	VALUE_STR = Cc("str") * P('"') * P(_capture_string) * spc,
	
	VALUE_REF = Cc("ref") * Ct(
		name_nospc * (P("[") * V("EXPR") * P("]"))^-1 *
		(P(".") * name_nospc * (P("[") * V("EXPR") * P("]"))^-1)^0
		) * spc,
	
	VALUE = P(_capture_position) * (V("VALUE_NUM") + V("VALUE_STR") + V("VALUE_REF")),
	
	STMT =
		P(1) * P(_consume_directive) +
		V("BLOCK") +
		V("COMMENT") +
		V("IF") +
		V("WHILE") +
		V("STRUCT_DEFN") +
		V("FUNC_DEFN") +
		V("LOCAL_VAR_DEFN") +
		V("VAR_DEFN") +
		V("RETURN") +
		V("EXPR") * P(";") * spc,
	
	BLOCK = P("{") * spc * ( V("STMT") ^ 0 ) * spc * P("}"),
	
	COMMENT = spc * comment("//", "\n") * spc
		+ spc * comment("/*", "*/") * spc,
	
	EXPR =
		Ct( P(_capture_position) * Cc("_expr") * Ct( V("EXPR2") ^ 1 ) ),
	
	EXPR2 =
		P("(") * V("EXPR") * P(")") * spc +
		Ct( P(_capture_position) * Cc("call") * name * Ct( S("(") * (V("EXPR") * (comma * V("EXPR")) ^ 0) ^ -1 * S(")") ) * spc ) +
		Ct( V("VALUE") ) +
		Ct( P(_capture_position) * Cc("_token") *
			C( P("<<") + P(">>") + P("<=") + P(">=") + P("==") + P("!=") + P("&&") + P("||") + S("!~*/%+-<>&^|=") ) * spc),
	
	VAR_DEFN = Ct( P(_capture_position) * Cc("variable") * P(_capture_type) * name * Ct( (P("[") * V("EXPR") * P("]")) ^ -1 ) * P(";") * spc ),
	LOCAL_VAR_DEFN = Ct( P(_capture_position) * Cc("local-variable") * P("local") * spc * name * name * Ct( (P("[") * V("EXPR") * P("]")) ^ -1 ) * spc * Ct( (P("=") * spc * V("EXPR") * spc) ^ -1 ) * P(";") * spc ),
	
	RETURN = Ct( P(_capture_position) * Cc("return") * P("return") * spc * V("EXPR") * P(";") * spc),
	
	ARG = Ct( P(_capture_type) * name ),
	
	--  {
	--      "struct",
	--      "name",
	--      { <arguments> },
	--      { <statements> },
	--  }
	STRUCT_ARG_LIST = Ct( (S("(") * (V("ARG") * (comma * V("ARG")) ^ 0) ^ -1 * S(")")) ^ -1 ),
	STRUCT_DEFN = Ct( P(_capture_position) * Cc("struct") * P("struct") * spc * name * V("STRUCT_ARG_LIST") * spc * P("{") * spc * Ct( V("STMT") ^ 0 ) * P("}") * spc * P(";") * spc ),
	
	--  {
	--      "function",
	--      "return type",
	--      "name",
	--      { <arguments> },
	--      { <statements> },
	--  }
	FUNC_ARG_LIST = Ct( S("(") * (V("ARG") * (comma * V("ARG")) ^ 0) ^ -1 * S(")") ) * spc,
	FUNC_DEFN = Ct( P(_capture_position) * Cc("function") * name * name * V("FUNC_ARG_LIST") * P("{") * spc * Ct( (V("STMT") * spc) ^ 0 ) * P("}") * spc ),
	
	--  {
	--      "if",
	--      { <condition>, { <statements> } },  <-- if
	--      { <condition>, { <statements> } },  <-- else if
	--      { <condition>, { <statements> } },  <-- else if
	--      {              { <statements> } },  <-- else
	--  }
	IF = Ct( P(_capture_position) * Cc("if") *
		Ct( P("if")      * spc * P("(") * V("EXPR") * P(")") * spc * Ct( V("STMT") ) )     * spc *
		Ct( P("else if") * spc * P("(") * V("EXPR") * P(")") * spc * Ct( V("STMT") ) ) ^ 0 * spc *
		Ct( P("else")                                        * spc * Ct( V("STMT") ) ) ^ -1
	),
	
	--  {
	--      "while", <condition>, { <statements> }
	--  }
	WHILE = Ct( P(_capture_position) * Cc("while") *
		P("while") * spc * P("(") * V("EXPR") * P(")") * spc * Ct( V("STMT") ) * spc
	),
}

local function _compile_expr(expr)
	local expr_parts = expr[4]
	
	if expr[3] ~= "_expr"
	then
		error("Internal error - _compile_expr() called with an '" .. expr[3] .. "' node")
	end
	
	local left_to_right = { start = function() return 1 end, step = 1 }
	local right_to_left = { start = function() return #expr_parts - 2 end, step = -1 }
	
	local expand_binops = function(dir, ops)
		local idx = dir.start()
		
		while idx >= 1 and (idx + 2) <= #expr_parts
		do
			local matched = false
			
			for op, ast_op in pairs(ops)
			do
				if
					expr_parts[idx + 1][3] == "_token" and expr_parts[idx + 1][4] == op and
					expr_parts[idx][3]:sub(1, 1) ~= "_" and
					expr_parts[idx + 2][3]:sub(1, 1) ~= "_"
				then
					expr_parts[idx] = { expr_parts[idx + 1][1], expr_parts[idx + 1][2], ast_op, expr_parts[idx], expr_parts[idx + 2] }
					table.remove(expr_parts, idx + 1)
					table.remove(expr_parts, idx + 1)
					
					matched = true
					break
				end
			end
			
			if not matched
			then
				idx = idx + dir.step
			elseif idx == #expr_parts
			then
				idx = idx + 2 * dir.step
			end
		end
	end
	
	for i = 1, #expr_parts
	do
		if expr_parts[i][3] == "_expr"
		then
			_compile_expr(expr_parts[i])
		end
		
		if expr_parts[i][3] == "ref"
		then
			local path = expr_parts[i][4]
			
			for i = 1, #path
			do
				if type(path[i]) == "table"
				then
					_compile_expr(path[i])
				end
			end
		elseif expr_parts[i][3] == "call"
		then
			local args = expr_parts[i][5]
			
			for i = 1, #args
			do
				_compile_expr(args[i])
			end
		end
	end
	
	expand_binops(left_to_right, {
		["*"] = "multiply",
		["/"] = "divide",
		["%"] = "mod",
	})
	
	expand_binops(left_to_right, {
		["+"] = "add",
		["-"] = "subtract",
	})
	
	expand_binops(left_to_right, {
		["<<"] = "left-shift",
		[">>"] = "right-shift",
	})
	
	expand_binops(left_to_right, {
		["<"]  = "less-than",
		["<="] = "less-than-or-equal",
		[">"]  = "greater-than",
		[">="] = "greater-than-or-equal",
	})
	
	expand_binops(left_to_right, {
		["=="] = "equal",
		["!="] = "not-equal",
	})
	
	expand_binops(left_to_right, { ["&"] = "bitwise-and" })
	expand_binops(left_to_right, { ["^"] = "bitwise-xor" })
	expand_binops(left_to_right, { ["|"] = "bitwise-or" })
	
	expand_binops(left_to_right, { ["&&"] = "logical-and" })
	expand_binops(left_to_right, { ["||"] = "logical-or" })
	
	expand_binops(right_to_left, { ["="] = "assign" })
	
	if #expr_parts ~= 1
	then
		error("Unable to compile expression starting at " .. expr[1] .. ":" .. expr[2])
	end
	
	-- Replace expr's content with the compiled expression in expr_parts[1]
	
	while #expr > 0
	do
		table.remove(expr, #expr)
	end
	
	for _,v in ipairs(expr_parts[1])
	do
		table.insert(expr, v)
	end
end

local function _compile_statement(s)
	local op = s[3]
	
	if op == "_expr"
	then
		_compile_expr(s)
	elseif op == "function"
	then
		local body = s[7]
		
		for i = 1, #body
		do
			_compile_statement(body[i])
		end
	elseif op == "local-variable"
	then
		local array_size = s[6][1]
		local init_val = s[7][1]
		
		if array_size then _compile_expr(array_size) end
		if init_val   then _compile_expr(init_val)   end
	elseif op == "variable"
	then
		local array_size = s[6][1]
		
		if array_size then _compile_expr(array_size) end
	end
end

local function parse_text(text)
	local ast = _parser:match(text)
	
	for i,v in ipairs(ast)
	do
		_compile_statement(v)
	end
	
	return ast
end

M.parse_text = parse_text;

-- local inspect = require 'inspect'
-- print(inspect(M.parser:match(io.input():read("*all"))));

return M
