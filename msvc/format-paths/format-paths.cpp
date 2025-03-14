/* Reverse Engineer's Hex Editor
 * Copyright (C) 2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

/* This program converts a list of delimited paths to their short form but with
 * forward slashes as separators, so that they can be used in contexts where
 * spaces and/or backslashes would not be preserved, optionally changing the
 * delimiter or adding a prefix/argument to each path.
*/

#include <Windows.h>

#include <stdio.h>
#include <string>
#include <string.h>
#include <vector>

static void print_error_for_path(const std::string &path, DWORD error);

int main(int argc, char **argv)
{
	if(argc < 3 || argc > 5)
	{
		fprintf(stderr, "Usage %s <delimiter> <path(s)> [<output delimiter>] [<path prefix>]\n", argv[0]);
		return 1;
	}

	std::string delim = argv[1];
	std::string paths = argv[2];

	std::string output_delim = argc >= 4 ? argv[3] : delim;
	std::string prefix = argc >= 5 ? argv[4] : "";

	std::string short_paths = "";

	for(size_t i = 0; i < paths.length();)
	{
		size_t next_delim = paths.find(delim, i);
		size_t len = next_delim == std::string::npos ? (paths.length() - i) : (next_delim - i);

		if(len > 0)
		{
			/* Extract the next path from paths and convert it to a wide string... */

			std::string path = paths.substr(i, len);

			int wide_path_size = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, NULL, 0);
			if(wide_path_size <= 0)
			{
				DWORD error = GetLastError();
				print_error_for_path(path.c_str(), error);

				return 1;
			}

			std::vector<wchar_t> wide_path(wide_path_size);

			wide_path_size = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, wide_path.data(), wide_path_size);
			if(wide_path_size <= 0)
			{
				DWORD error = GetLastError();
				print_error_for_path(path.c_str(), error);

				return 1;
			}

			/* ...convert the wide path to its short form... */

			int wide_short_path_size = GetShortPathName(wide_path.data(), NULL, 0);
			if(wide_short_path_size == 0)
			{
				DWORD error = GetLastError();

				if(error == ERROR_PATH_NOT_FOUND)
				{
					/* Skip non-existant paths. */
					goto NEXT;
				}

				print_error_for_path(path.c_str(), error);
				return 1;
			}

			std::vector<wchar_t> wide_short_path(wide_short_path_size);

			wide_short_path_size = GetShortPathName(wide_path.data(), wide_short_path.data(), wide_short_path_size);
			if(wide_short_path_size == 0)
			{
				DWORD error = GetLastError();
				print_error_for_path(path.c_str(), error);

				return 1;
			}

			/* ...convert the short path to multibyte characters... */

			int short_path_size = WideCharToMultiByte(CP_ACP, 0, wide_short_path.data(), -1, NULL, 0, "?", NULL);
			if(short_path_size == 0)
			{
				DWORD error = GetLastError();
				print_error_for_path(path.c_str(), error);

				return 1;
			}

			std::vector<char> short_path(short_path_size);

			short_path_size = WideCharToMultiByte(CP_ACP, 0, wide_short_path.data(), -1, short_path.data(), short_path_size, "?", NULL);
			if(short_path_size == 0)
			{
				DWORD error = GetLastError();
				print_error_for_path(path.c_str(), error);

				return 1;
			}

			/* ...replace any backslashes with forward slashes... */

			for(auto it = short_path.begin(); it != short_path.end(); ++it)
			{
				if(*it == '\\')
				{
					*it = '/';
				}
			}

			/* ...and finally add it to the output... */

			if(i > 0)
			{
				short_paths += output_delim;
			}

			short_paths += prefix + short_path.data();
		}

	NEXT:
		i += len + 1;
	}

	printf("%s\n", short_paths.c_str());

	return 0;
}

static void print_error_for_path(const std::string &path, DWORD error)
{
	char error_s[1024];

	if(!FormatMessageA(
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		error_s,
		sizeof(error_s),
		NULL))
	{
		strcpy(error_s, "Unknown error");
	}

	/* Microsoft like to end some of their errors with newlines... */

	char *nl = strrchr(error_s, '\n');
	char *cr = strrchr(error_s, '\r');

	if(nl != NULL && nl[1] == '\0') { *nl = '\0'; }
	if(cr != NULL && cr[1] == '\0') { *cr = '\0'; }

	fprintf(stderr, "%s: %s\n", path.c_str(), error_s);
}
