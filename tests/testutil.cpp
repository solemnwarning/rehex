/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <wx/app.h>
#include <wx/frame.h>
#include <wx/timer.h>

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
