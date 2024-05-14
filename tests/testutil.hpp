/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022-2024 Daniel Collins <solemnwarning@solemnwarning.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef REHEX_TESTUTIL_HPP
#define REHEX_TESTUTIL_HPP

#include <functional>
#include <jansson.h>
#include <string>
#include <vector>

#ifdef _WIN32
#define CONFIG_EOL "\r\n"
#else
#define CONFIG_EOL "\n"
#endif

void run_wx_for(unsigned int ms);
bool run_wx_until(const std::function<bool()> &predicate, unsigned int timeout_ms = 10000, unsigned int check_interval_ms = 100);

void write_file(const std::string &filename, const std::vector<unsigned char>& data);
std::vector<unsigned char> read_file(const std::string &filename);

class TempFilename
{
	public:
		char tmpfile[L_tmpnam];
		
		TempFilename();
		~TempFilename();
};

class AutoJSON
{
	public:
		json_t *json;
		
		AutoJSON();
		AutoJSON(json_t *json_obj);
		AutoJSON(const char *json_text);
		~AutoJSON();
		
		std::string serialise() const;
		
		bool operator==(const AutoJSON &rhs) const;
};

/* Used by Google Test to print out JSON data. */
std::ostream& operator<<(std::ostream& os, const AutoJSON &json);

#endif /* !REHEX_TESTUTIL_HPP */
