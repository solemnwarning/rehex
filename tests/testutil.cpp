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

#include "../src/platform.hpp"

#include <ostream>
#include <stdexcept>
#include <stdio.h>
#include <vector>
#include <wx/app.h>
#include <wx/frame.h>
#include <wx/timer.h>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include "testutil.hpp"

void run_wx_for(unsigned int ms)
{
	wxFrame frame(NULL, wxID_ANY, "REHex Tests");
	wxTimer timer(&frame);
	
	frame.Bind(wxEVT_TIMER, [](wxTimerEvent &event)
	{
		wxTheApp->ExitMainLoop();
	}, timer.GetId(), timer.GetId());
	
	timer.Start(ms, wxTIMER_ONE_SHOT);
	wxTheApp->OnRun();
}

bool run_wx_until(const std::function<bool()> &predicate, unsigned int timeout_ms, unsigned int check_interval_ms)
{
	wxFrame frame(NULL, wxID_ANY, "REHex Tests");
	
	wxTimer timeout_timer(&frame);
	frame.Bind(wxEVT_TIMER, [](wxTimerEvent &event)
	{
		wxTheApp->ExitMainLoop();
	}, timeout_timer.GetId(), timeout_timer.GetId());
	
	bool predicate_returned_true = false;
	
	wxTimer check_timer(&frame);
	frame.Bind(wxEVT_TIMER, [&](wxTimerEvent &event)
	{
		predicate_returned_true = predicate();
		
		if(predicate_returned_true)
		{
			wxTheApp->ExitMainLoop();
		}
	}, check_timer.GetId(), check_timer.GetId());
	
	timeout_timer.Start(timeout_ms, wxTIMER_ONE_SHOT);
	check_timer.Start(check_interval_ms, wxTIMER_CONTINUOUS);
	wxTheApp->OnRun();
	
	return predicate_returned_true;
}

void write_file(const std::string &filename, const std::vector<unsigned char>& data)
{
	FILE *fh = fopen(filename.c_str(), "wb");
	if(!fh)
	{
		throw std::runtime_error(std::string("Unable to open file ") + filename);
	}
	
	if(data.size() > 0)
	{
		if(fwrite(data.data(), data.size(), 1, fh) != 1)
		{
			fclose(fh);
			throw std::runtime_error(std::string("Unable to write to file ") + filename);
		}
	}
	
	fclose(fh);
}

std::vector<unsigned char> read_file(const std::string &filename)
{
	FILE *fh = fopen(filename.c_str(), "rb");
	if(!fh)
	{
		throw std::runtime_error("Unable to open file " + filename);
	}
	
	std::vector<unsigned char> data;
	
	unsigned char buf[1024];
	size_t len;
	while((len = fread(buf, 1, sizeof(buf), fh)) > 0)
	{
		data.insert(data.end(), buf, buf + len);
	}
	
	if(ferror(fh))
	{
		fclose(fh);
		throw std::runtime_error("Unable to read file " + filename);
	}
	
	fclose(fh);
	
	return data;
}

TempFilename::TempFilename()
{
	if(tmpnam(tmpfile) == NULL)
	{
		throw std::runtime_error("Cannot generate temporary file name");
	}
	
#ifdef _WIN32
	/* > Note than when a file name is pre-pended with a backslash and no path
	 * > information, such as \fname21, this indicates that the name is valid
	 * > for the current working directory.
	 * - MSDN
	 *
	 * Sure, that makes total sense.
	*/
	if(tmpfile[0] == '\\' && strchr((tmpfile + 1), '\\') == NULL)
	{
		/* Remove the leading slash. */
		memmove(tmpfile, tmpfile + 1, strlen(tmpfile) - 1);
	}
#endif
}

TempFilename::~TempFilename()
{
	unlink(tmpfile);
}

AutoJSON::AutoJSON():
	json(NULL) {}

AutoJSON::AutoJSON(json_t *json_obj):
	json(json_obj) {}

AutoJSON::AutoJSON(const char *json_text)
{
	json_error_t err;
	json = json_loads(json_text, 0, &err);
	
	if(json == NULL)
	{
		throw std::runtime_error(err.text);
	}
}

AutoJSON::~AutoJSON()
{
	json_decref(json);
}

std::string AutoJSON::serialise() const
{
	std::vector<char> buf(json_dumpb(json, NULL, 0, JSON_INDENT(4) | JSON_SORT_KEYS));
	json_dumpb(json, buf.data(), buf.size(), JSON_INDENT(4) | JSON_SORT_KEYS);
	
	return std::string(buf.data(), buf.size());
}

bool AutoJSON::operator==(const AutoJSON &rhs) const
{
	return (json == NULL && rhs.json == NULL)
		|| json_equal(json, rhs.json);
}

std::ostream& operator<<(std::ostream& os, const AutoJSON &json)
{
	return os << json.serialise();
}
