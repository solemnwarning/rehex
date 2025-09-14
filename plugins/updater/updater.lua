-- Application Updater plugin for REHex
-- Copyright (C) 2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

local Updater = {}

local json = require "json"

local function ormatch(s, patterns, init)
	for _, pattern in ipairs(patterns)
	do
		local tok = string.match(s, pattern, init)
		if tok ~= nil
		then
			return tok
		end
	end

	return nil
end

Updater.versioncmp = function(a, b)
	local ai = 1
	local bi = 1

	while ai <= a:len() and bi <= b:len()
	do
		local atok = ormatch(a, { "^%.", "^[^%.]+" }, ai)
		local btok = ormatch(b, { "^%.", "^[^%.]+" }, bi)

		ai = ai + atok:len()
		bi = bi + btok:len()

		if atok ~= btok
		then
			if atok == "."
			then
				return -1
			elseif btok == "."
			then
				return 1
			elseif string.match(atok, "[^%d]") == nil and string.match(btok, "[^%d]") == nil
			then
				-- Both tokens are integers

				local anum = tonumber(atok)
				local bnum = tonumber(btok)

				if anum < bnum
				then
					return -1
				elseif anum > bnum
				then
					return 1
				end
			else
				if atok < btok
				then
					return -1
				elseif atok > btok
				then
					return 1
				end
			end
		end
	end

	if ai <= a:len()
	then
		return 1
	elseif bi <= b:len()
	then
		return -1
	else
		return 0
	end
end

local function isobj(x)
	if type(x) == "table"
	then
		for _, v in ipairs(x)
		do
			-- Table has an array portion - must be from an array in the JSON.
			return false
		end

		return true
	else
		-- Not a table
		return false
	end
end

local function isarr(x)
	if type(x) == "table"
	then
		local pnum = 0
		for _, v in ipairs(x)
		do
			pnum = pnum + 1
		end

		if pnum ~= #x
		then
			-- Table has some non-array keys, must've been an object.
			return false
		end

		-- Table has only numeric elements (or is empty)... assume array.
		return true
	else
		return false
	end
end

local function find_line(str, line_num)
	local this_line = 1
	
	local line_begin = 1
	local line_end = str:find("\n")
	
	while this_line < line_num
	do
		if line_end == nil
		then
			return nil, nil
		end
		
		line_begin = line_end + 1
		line_end = str:find("\n", line_begin)
		
		this_line = this_line + 1
	end
	
	if line_end == nil
	then
		line_end = str:len()
	end
	
	return line_begin, line_end
end

Updater.parse_feed = function(feed, verify_func)
	-- The update feed is a JSON feed with an embedded Ed25519 signature. The signature is injected
	-- as the third line of the feed so that we can trivially strip it to get the pre-signed feed
	-- and correctly validate the signature while ordinary JSON feed consumers can ignore it.
	
	local sig_line_begin, sig_line_end = find_line(feed, 3)
	if sig_line_begin == nil
	then
		error("Malformed update feed (no signature)")
	end
	
	local sig_line = feed:sub(sig_line_begin, sig_line_end)
	local original_feed = feed:sub(1, (sig_line_begin - 1)) .. feed:sub((sig_line_end + 1), feed:len())
	
	local signature_hex = sig_line:match("^[ \t]*\"_signature\"[ \t]*:[ \t]*\"(%x*)\",\n")
	if signature_hex == nil
	then
		error("Malformed update feed (no signature)")
	end
	
	-- https://stackoverflow.com/a/9140231
	local signature_bin = signature_hex:gsub('..', function (cc)
		return string.char(tonumber(cc, 16))
	end)
	
	if not verify_func(original_feed, signature_bin)
	then
		error("Signature verification failed")
	end
	
	-- ...then parse the JSON after the signature is verified.
	
	local ok, result = pcall(function() return json.decode(original_feed) end)
	if not ok
	then
		error("Malformed update feed (" .. result .. ")")
	end

	-- ... and finally, validate the structure of the JSON.

	if not isobj(result)
	then
		error("Malformed update feed (not a JSON object)")
	end

	if not isarr(result.items)
	then
		error("Malformed update feed (no items array)")
	end

	local versions = {}

	for _, item in ipairs(result.items)
	do
		if not isobj(item)
		then
			error("Malformed update feed (non-object in items array)")
		end

		if type(item.url) ~= "string"
		then
			error("Malformed update feed (missing 'url' string in item)")
		end

		if type(item.content_text) ~= "string"
		then
			error("Malformed update feed (missing 'content_text' string in item)")
		end

		if type(item._version) ~= "string"
		then
			error("Malformed update feed (missing '_version' string in item)")
		end

		if type(item._sha256sum) ~= "string"
		then
			error("Malformed update feed (missing '_sha256sum' string in item)")
		end

		table.insert(versions, {
			["url"] = item.url,
			["version"] = item._version,
			["sha256sum"] = item._sha256sum,
			["notes"] = item.content_text,
		})
	end

	return versions
end

return Updater
