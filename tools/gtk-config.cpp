/* Reverse Engineer's Hex Editor
 * Copyright (C) 2021 Daniel Collins <solemnwarning@solemnwarning.net>
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

/* We need to link directly against GTK so we can... read the cursor blink speed.
 *
 * Hopefully (relatively) short lived... we can actually get the setting from wxWidgets itself
 * from version 3.1.3 onwards, but until then we have to have to do it with platform-specific code
 * that I totally didn't just copy-paste from the wxWidgets source tree.
 *
 * This program is invoked by the Makefile on all platforms to get the GTK CFLAGS and LDLIBS which
 * are used for compiling the application. On wxGTK it will defer to pkg-config with a package name
 * derived from the GTK version provided by wxWidgets, on non-GTK it will no-op.
*/

#include <wx/defs.h>
#include <wx/version.h>

#if defined(__WXGTK__) && !wxCHECK_VERSION(3,1,3)

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <unistd.h>
#include <vector>

int main(int argc, const char **argv)
{
	std::vector<const char*> exec_argv = { "pkg-config" };
	
	#if defined(__WXGTK3__)
	exec_argv.push_back("gtk+-3.0");
	#elif defined(__WXGTK20__)
	exec_argv.push_back("gtk+-2.0");
	#else
	#error Unknown GTK version
	#endif
	
	exec_argv.insert(exec_argv.end(), (argv + 1), (argv + argc));
	exec_argv.push_back(NULL);
	
	execvp("pkg-config", (char**)(exec_argv.data()));
	
	perror("pkg-config");
	
	return EX_OSERR;
}

#else

int main()
{
	return 0;
}

#endif
