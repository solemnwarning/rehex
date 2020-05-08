/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_EDITCOMMENTDIALOG_HPP
#define REHEX_EDITCOMMENTDIALOG_HPP

#include <sys/types.h>
#include <wx/window.h>

namespace REHex
{
	class EditCommentDialog
	{
		public:
			static void run_modal(wxWindow *parent, Document *doc, off_t offset, off_t length);
	};
}

#endif /* !REHEX_EDITCOMMENTDIALOG_HPP */
