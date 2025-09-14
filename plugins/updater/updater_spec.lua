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

local Updater = require 'updater'

describe("Updater.versioncmp()", function()
	it("compares numeric versions", function()
		assert.are.same( 0, Updater.versioncmp("1.2.3.4", "1.2.3.4"))

		assert.are.same(-1, Updater.versioncmp("1.2.3.4", "1.2.3.5"))
		assert.are.same( 1, Updater.versioncmp("1.2.3.5", "1.2.3.4"))

		assert.are.same( 1, Updater.versioncmp("1.3.3.4", "1.2.3.4"))
		assert.are.same(-1, Updater.versioncmp("1.2.3.4", "1.3.3.4"))

		assert.are.same(-1, Updater.versioncmp("1.2.3.4", "1.10.3.4"))
		assert.are.same( 1, Updater.versioncmp("1.10.3.4", "1.2.3.4"))
	end)

	it("compares non-numeric version tokens", function()
		assert.are.same(0, Updater.versioncmp("1.2.3a", "1.2.3a"))

		assert.are.same(-1, Updater.versioncmp("1.2.3a", "1.2.3b"))
		assert.are.same( 1, Updater.versioncmp("1.2.3b", "1.2.3a"))

		assert.are.same(-1, Updater.versioncmp("1.2.3a", "1.2.4a"))
		assert.are.same( 1, Updater.versioncmp("1.2.4a", "1.2.3a"))
	end)

	it("compares versions with different numbers of tokens", function()
		assert.are.same(-1, Updater.versioncmp("1.0", "1.0.0"))
		assert.are.same( 1, Updater.versioncmp("1.0.0", "1.0"))

		assert.are.same(-1, Updater.versioncmp("1.0", "1.0.1"))
		assert.are.same( 1, Updater.versioncmp("1.0.1", "1.0"))
	end)
end)

describe("Updater.parse_feed", function()
	local SIG = "\0\1\2\3\4\5\6\7\8\9\10\11\12\13\14\15\16\17\18\19\20\21\22\23\24\25\26\27\28\29\30\31\32\33\34\35\36\37\38\39\40\41\42\43\44\45\46\47\48\49\50\51\52\53\54\55\56\57\58\59\60\61\62\63"
	local EMPTY_FEED = "{ \"items\": [] }"

	it("rejects empty feed", function()
		assert.has_error(function()
			Updater.parse_feed("hello this is dog", function() error("Validator function called for empty feed") end) 
			end, "Malformed update feed (no signature)")
	end)

	it("rejects feed without signature", function()
		assert.has_error(function()
			Updater.parse_feed("hello this is dog", function() error("Validator function called for feed with no signature") end) 
			end, "Malformed update feed (no signature)")
	end)

	it("rejects feed with an invalid signature", function()
		assert.has_error(function()
			Updater.parse_feed(SIG .. EMPTY_FEED,
				function(msg, sig)
					assert.are.same(EMPTY_FEED, msg)
					assert.are.same(SIG, sig)
					return false
				end)
			end, "Signature verification failed")
	end)

	it("accepts valid feed", function()
		local FEED = "{ \"items\": [" ..
			"{ \"url\": \"http://example.com/rehex-1.0.zip\", \"_version\": \"1.0\", \"_sha256sum\": \"checksum1\" }," ..
			"{ \"url\": \"http://example.com/rehex-1.1.zip\", \"_version\": \"1.1\", \"_sha256sum\": \"checksum2\" }," ..
			"{ \"url\": \"http://example.com/rehex-1.2.zip\", \"_version\": \"1.2\", \"_sha256sum\": \"checksum3\" }" ..
		"] }"

		assert.are.same(
			{
				{ ["url"] = "http://example.com/rehex-1.0.zip", ["version"] = "1.0", ["sha256sum"] = "checksum1" },
				{ ["url"] = "http://example.com/rehex-1.1.zip", ["version"] = "1.1", ["sha256sum"] = "checksum2" },
				{ ["url"] = "http://example.com/rehex-1.2.zip", ["version"] = "1.2", ["sha256sum"] = "checksum3" },
			},

			Updater.parse_feed(SIG .. FEED,
				function(msg, sig)
					assert.are.same(FEED, msg)
					assert.are.same(SIG, sig)
					return true
				end))
	end)

	it("rejects feed with malformed JSON", function()
		assert.has_error(function()
			Updater.parse_feed(SIG .. "potato",
				function(msg, sig)
					return true
				end)
			end, "Malformed update feed (./json.lua:185: unexpected character 'p' at line 1 col 1)")
	end)

	it("rejects feed with invalid structure", function()
		assert.has_error(function()
			Updater.parse_feed(SIG .. "[ \"hello\" ]",
				function(msg, sig)
					return true
				end)
			end, "Malformed update feed (not a JSON object)")
		
		assert.has_error(function()
			Updater.parse_feed(SIG .. "{}",
				function(msg, sig)
					return true
				end)
			end, "Malformed update feed (no items array)")
		
		assert.has_error(function()
			Updater.parse_feed(SIG .. "{ \"items\": \"hello\" }",
				function(msg, sig)
					return true
				end)
			end, "Malformed update feed (no items array)")
		
		assert.has_error(function()
			Updater.parse_feed(SIG .. "{ \"items\": [ { \"url\": \"xxx\", \"_sha256sum\": \"abcd\" } ] }",
				function(msg, sig)
					return true
				end)
			end, "Malformed update feed (missing '_version' string in item)")
		
		assert.has_error(function()
			Updater.parse_feed(SIG .. "{ \"items\": [ { \"_version\": \"xxx\", \"_sha256sum\": \"abcd\" } ] }",
				function(msg, sig)
					return true
				end)
			end, "Malformed update feed (missing 'url' string in item)")
		
		assert.has_error(function()
			Updater.parse_feed(SIG .. "{ \"items\": [ { \"_version\": \"xxx\", \"url\": \"abcd\" } ] }",
				function(msg, sig)
					return true
				end)
			end, "Malformed update feed (missing '_sha256sum' string in item)")
	end)
end)
