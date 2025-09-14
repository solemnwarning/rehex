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
	local SIG_HEX = "010203040506070809000A0B0C0D0E0F"
	local SIG_BIN = "\1\2\3\4\5\6\7\8\9\0\10\11\12\13\14\15"

	it("rejects empty feed", function()
		assert.has_error(function()
			Updater.parse_feed("", function() error("Validator function called for empty feed") end) 
			end, "Malformed update feed (no signature)")
	end)

	it("rejects feed without signature", function()
		local FEED = "{\n" ..
			"  \"version\": \"https://jsonfeed.org/version/1.1\",\n" ..
			"  \"items\": [\n" ..
			"    { \"url\": \"http://example.com/rehex-1.0.zip\", \"_version\": \"1.0\", \"_sha256sum\": \"checksum1\" },\n" ..
			"    { \"url\": \"http://example.com/rehex-1.1.zip\", \"_version\": \"1.1\", \"_sha256sum\": \"checksum2\" },\n" ..
			"    { \"url\": \"http://example.com/rehex-1.2.zip\", \"_version\": \"1.2\", \"_sha256sum\": \"checksum3\" }\n" ..
			"  ]\n" ..
		"}"
		
		assert.has_error(function()
			Updater.parse_feed(FEED, function() error("Validator function called for feed with no signature") end) 
			end, "Malformed update feed (no signature)")
	end)

	it("rejects feed with an incorrect signature", function()
		assert.has_error(function()
			local FEED = "{\n" ..
				"  \"version\": \"https://jsonfeed.org/version/1.1\",\n" ..
				"  \"items\" : [\n" ..
				"    { \"url\" : \"http://example.com/rehex-1.0.zip\", \"_version\": \"1.0\", \"_sha256sum\": \"checksum1\" }," ..
				"    { \"url\" : \"http://example.com/rehex-1.1.zip\", \"_version\": \"1.1\", \"_sha256sum\": \"checksum2\" }," ..
				"    { \"url\" : \"http://example.com/rehex-1.2.zip\", \"_version\": \"1.2\", \"_sha256sum\": \"checksum3\" }" ..
				"  ]\n" ..
			"}"
			
			local FEED_WITH_SIG = "{\n" ..
				"  \"version\": \"https://jsonfeed.org/version/1.1\",\n" ..
				"  \"_signature\" : \"" .. SIG_HEX .. "\",\n" ..
				"  \"items\" : [\n" ..
				"    { \"url\" : \"http://example.com/rehex-1.0.zip\", \"_version\": \"1.0\", \"_sha256sum\": \"checksum1\" }," ..
				"    { \"url\" : \"http://example.com/rehex-1.1.zip\", \"_version\": \"1.1\", \"_sha256sum\": \"checksum2\" }," ..
				"    { \"url\" : \"http://example.com/rehex-1.2.zip\", \"_version\": \"1.2\", \"_sha256sum\": \"checksum3\" }" ..
				"  ]\n" ..
			"}"
			
			Updater.parse_feed(FEED_WITH_SIG,
				function(msg, sig)
					assert.are.same(FEED, msg)
					assert.are.same(SIG_BIN, sig)
					return false
				end)
			end, "Signature verification failed")
	end)

	it("accepts valid feed", function()
		local FEED = "{\n" ..
			"  \"version\": \"https://jsonfeed.org/version/1.1\",\n" ..
			"  \"items\" : [\n" ..
			"    { \"url\" : \"http://example.com/rehex-1.0.zip\", \"_version\": \"1.0\", \"_sha256sum\": \"checksum1\", \"content_text\": \"This is update 1\\nIt does things.\\n\" }," ..
			"    { \"url\" : \"http://example.com/rehex-1.1.zip\", \"_version\": \"1.1\", \"_sha256sum\": \"checksum2\", \"content_text\": \"This is update 2\\nIt does things.\\n\" }," ..
			"    { \"url\" : \"http://example.com/rehex-1.2.zip\", \"_version\": \"1.2\", \"_sha256sum\": \"checksum3\", \"content_text\": \"This is update 3\\nIt does things.\\n\" }" ..
			"  ]\n" ..
		"}"
		
		local FEED_WITH_SIG = "{\n" ..
			"  \"version\": \"https://jsonfeed.org/version/1.1\",\n" ..
			"  \"_signature\" : \"" .. SIG_HEX .. "\",\n" ..
			"  \"items\" : [\n" ..
			"    { \"url\" : \"http://example.com/rehex-1.0.zip\", \"_version\": \"1.0\", \"_sha256sum\": \"checksum1\", \"content_text\": \"This is update 1\\nIt does things.\\n\" }," ..
			"    { \"url\" : \"http://example.com/rehex-1.1.zip\", \"_version\": \"1.1\", \"_sha256sum\": \"checksum2\", \"content_text\": \"This is update 2\\nIt does things.\\n\" }," ..
			"    { \"url\" : \"http://example.com/rehex-1.2.zip\", \"_version\": \"1.2\", \"_sha256sum\": \"checksum3\", \"content_text\": \"This is update 3\\nIt does things.\\n\" }" ..
			"  ]\n" ..
		"}"

		assert.are.same(
			{
				{ ["url"] = "http://example.com/rehex-1.0.zip", ["version"] = "1.0", ["sha256sum"] = "checksum1", ["notes"] = "This is update 1\nIt does things.\n" },
				{ ["url"] = "http://example.com/rehex-1.1.zip", ["version"] = "1.1", ["sha256sum"] = "checksum2", ["notes"] = "This is update 2\nIt does things.\n" },
				{ ["url"] = "http://example.com/rehex-1.2.zip", ["version"] = "1.2", ["sha256sum"] = "checksum3", ["notes"] = "This is update 3\nIt does things.\n" },
			},

			Updater.parse_feed(FEED_WITH_SIG,
				function(msg, sig)
					assert.are.same(FEED, msg)
					assert.are.same(SIG_BIN, sig)
					return true
				end))
	end)

	it("rejects feed with malformed JSON", function()
		local env_os = os.getenv("OS")
		local pathsep = env_os == "Windows_NT" and "\\" or "/"

		assert.has_error(function()
			local FEED_WITH_SIG = "{\n" ..
				"  \"version\": \"https://jsonfeed.org/version/1.1\",\n" ..
				"  \"_signature\" : \"" .. SIG_HEX .. "\",\n" ..
				"  \"potato\""
			
			Updater.parse_feed(FEED_WITH_SIG,
				function(msg, sig)
					return true
				end)
			end, "Malformed update feed (." .. pathsep .. "json.lua:185: expected ':' after key at line 3 col 11)")
	end)

	it("rejects feed with invalid structure", function()
		assert.has_error(function()
			local FEED_WITH_SIG = "{\n" ..
				"  \"version\": \"https://jsonfeed.org/version/1.1\",\n" ..
				"  \"_signature\" : \"" .. SIG_HEX .. "\",\n" ..
				"}"
			
			Updater.parse_feed(FEED_WITH_SIG,
				function(msg, sig)
					return true
				end)
			end, "Malformed update feed (no items array)")
		
		assert.has_error(function()
			local FEED_WITH_SIG = "{\n" ..
				"  \"version\": \"https://jsonfeed.org/version/1.1\",\n" ..
				"  \"_signature\" : \"" .. SIG_HEX .. "\",\n" ..
				"  \"items\": \"hello\"" ..
				"}"
			
			Updater.parse_feed(FEED_WITH_SIG,
				function(msg, sig)
					return true
				end)
			end, "Malformed update feed (no items array)")
		
		assert.has_error(function()
			local FEED_WITH_SIG = "{\n" ..
				"  \"version\": \"https://jsonfeed.org/version/1.1\",\n" ..
				"  \"_signature\" : \"" .. SIG_HEX .. "\",\n" ..
				"  \"items\": [ { \"url\": \"xxx\", \"_sha256sum\": \"abcd\", \"content_text\": \"xxx\" } ]" ..
				"}"
			
			Updater.parse_feed(FEED_WITH_SIG,
				function(msg, sig)
					return true
				end)
			end, "Malformed update feed (missing '_version' string in item)")
		
		assert.has_error(function()
			local FEED_WITH_SIG = "{\n" ..
				"  \"version\": \"https://jsonfeed.org/version/1.1\",\n" ..
				"  \"_signature\" : \"" .. SIG_HEX .. "\",\n" ..
				"  \"items\": [ { \"_version\": \"xxx\", \"_sha256sum\": \"abcd\" } ]" ..
				"}"
			
			Updater.parse_feed(FEED_WITH_SIG,
				function(msg, sig)
					return true
				end)
			end, "Malformed update feed (missing 'url' string in item)")
		
		assert.has_error(function()
			local FEED_WITH_SIG = "{\n" ..
				"  \"version\": \"https://jsonfeed.org/version/1.1\",\n" ..
				"  \"_signature\" : \"" .. SIG_HEX .. "\",\n" ..
				"  \"items\": [ { \"_version\": \"xxx\", \"url\": \"abcd\", \"content_text\": \"xxx\" } ]" ..
				"}"
			
			Updater.parse_feed(FEED_WITH_SIG,
				function(msg, sig)
					return true
				end)
			end, "Malformed update feed (missing '_sha256sum' string in item)")

		assert.has_error(function()
			local FEED_WITH_SIG = "{\n" ..
				"  \"version\": \"https://jsonfeed.org/version/1.1\",\n" ..
				"  \"_signature\" : \"" .. SIG_HEX .. "\",\n" ..
				"  \"items\": [ { \"_version\": \"xxx\", \"url\": \"abcd\", \"_sha256sum\": \"xxx\" } ]" ..
				"}"
			
			Updater.parse_feed(FEED_WITH_SIG,
				function(msg, sig)
					return true
				end)
			end, "Malformed update feed (missing 'content_text' string in item)")
	end)
end)
