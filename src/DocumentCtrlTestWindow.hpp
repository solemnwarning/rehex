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

#ifndef REHEX_DOCUMENTCTRLTESTWINDOW_HPP
#define REHEX_DOCUMENTCTRLTESTWINDOW_HPP

#include <wx/frame.h>

#include "document.hpp"
#include "DocumentCtrl.hpp"
#include "Events.hpp"

namespace REHex {
	class DocumentCtrlTestWindow: public wxFrame
	{
		public:
			DocumentCtrlTestWindow(Document *doc);
			virtual ~DocumentCtrlTestWindow();
			
		private:
			Document *doc;
			DocumentCtrl *doc_ctrl;
			
			void reinit_regions();
			
			void OnCommentLeftClick(OffsetLengthEvent &event);
			void OnCommentRightClick(OffsetLengthEvent &event);
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_DOCUMENTCTRLTESTWINDOW_HPP */
