/* Reverse Engineer's Hex Editor
 * Copyright (C) 2021-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#import <Foundation/Foundation.h>
#include <wx/version.h>

#ifdef INTEL
#undef INTEL /* Sure thing Apple, go ahead and define that macro. */
#endif

#ifdef isset
#undef isset /* I guess they took the comment above to heart. */
#endif

#include "App.hpp"

#if !wxCHECK_VERSION(3,1,3)
static const int FALLBACK_CARET_BLINK = 500;

static int wxOSXGetUserDefault(NSString* key, int defaultValue)
{
    NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];
    if (!defaults)
    {
        return defaultValue;
    }

    id setting = [defaults objectForKey: key];
    if (!setting)
    {
        return defaultValue;
    }

    return [setting intValue];
}

int REHex::App::get_caret_on_time_ms()
{
	int value = wxOSXGetUserDefault(@"NSTextInsertionPointBlinkPeriodOn", -1);
	if (value > 0)
		return value;
	
	value = wxOSXGetUserDefault(@"NSTextInsertionPointBlinkPeriod", -1);
	if (value > 0)
		return value / 2;
	
	return FALLBACK_CARET_BLINK;
}

int REHex::App::get_caret_off_time_ms()
{
	int value = wxOSXGetUserDefault(@"NSTextInsertionPointBlinkPeriodOff", -1);
	if (value > 0)
		return value;
	
	value = wxOSXGetUserDefault(@"NSTextInsertionPointBlinkPeriod", -1);
	if (value > 0)
		return value / 2;
	
	return FALLBACK_CARET_BLINK;
}
#endif

std::string REHex::App::get_home_directory()
{
	NSString *home_directory = NSHomeDirectory();
	return [home_directory cStringUsingEncoding:[NSString defaultCStringEncoding]];
}
