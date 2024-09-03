/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_DATAMAPSCROLLBAR_HPP
#define REHEX_DATAMAPSCROLLBAR_HPP

#include <memory>
#include <wx/control.h>

#include "DataMapSource.hpp"
#include "Events.hpp"
#include "SharedDocumentPointer.hpp"

namespace REHex {
	class DataMapScrollbar: public wxControl {
		public:
			DataMapScrollbar(wxWindow *parent, wxWindowID id, const SharedDocumentPointer &document);
			~DataMapScrollbar();
			
		private:
			SharedDocumentPointer document;
			
			int client_height;
			wxTimer redraw_timer;
			
			std::unique_ptr<EntropyDataMapSource> source;
			
			void OnPaint(wxPaintEvent &event);
			void OnErase(wxEraseEvent &event);
			void OnSize(wxSizeEvent &event);
			
			/* Stays at the bottom because it changes the protection... */
			DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_DATAMAPSCROLLBAR_HPP */
