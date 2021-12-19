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

local preprocessor = require 'preprocessor';
local parser = require 'parser';
local executor = require 'executor';

rehex.AddToToolsMenu("Binary Template test", function(window)
	local doc = window:active_document()
	
	local interface = {
		set_data_type = function(offset, length, data_type)
			doc:set_data_type(offset, length, data_type)
		end,
		
		set_comment = function(offset, length, text)
			doc:set_comment(offset, length, rehex.Comment.new(text))
		end,
		
		print = function(s) print(s) end
	}
	
	executor.execute(interface, parser.parse_text(preprocessor.preprocess_file("test.bt")))
end);
