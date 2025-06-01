/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include "DocumentCtrl.hpp"
#include "Events.hpp"
#include "PopupTipWindow.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"

namespace REHex {
	class DataMapScrollbar: public wxControl {
		public:
			DataMapScrollbar(wxWindow *parent, wxWindowID id, const SharedEvtHandler<DataView> &view, std::unique_ptr<EntropyDataMapSource> &&source, DocumentCtrl *document_ctrl);
			~DataMapScrollbar();
			
		private:
			SharedEvtHandler<DataView> view;
			SafeWindowPointer<DocumentCtrl> document_ctrl;
			
			int client_height;
			
			std::unique_ptr<EntropyDataMapSource> m_source;
			
			BitRangeMap<DataMapSource::MapValue> m_data;
			wxTimer m_data_update_timer;
			
			bool mouse_dragging;
			bool mouse_in_window;
			
			SafeWindowPointer<PopupTipWindow> tip_window;
			
			void OnPaint(wxPaintEvent &event);
			void OnErase(wxEraseEvent &event);
			void OnSize(wxSizeEvent &event);
			void OnMotion(wxMouseEvent &event);
			void OnMouseEnter(wxMouseEvent &event);
			void OnMouseLeave(wxMouseEvent &event);
			void OnLeftDown(wxMouseEvent &event);
			void OnLeftUp(wxMouseEvent &event);
			void OnMouseCaptureLost(wxMouseCaptureLostEvent &event);
			void OnDocumentCtrlScroll(ScrollUpdateEvent &event);
			void OnSourceProcessing(wxCommandEvent &event);
			
			/* Stays at the bottom because it changes the protection... */
			DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_DATAMAPSCROLLBAR_HPP */
