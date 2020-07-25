/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_VALUEPANEL_HPP
#define REHEX_VALUEPANEL_HPP

#include <vector>
#include <wx/choice.h>
#include <wx/panel.h>
#include <wx/propgrid/propgrid.h>
#include <wx/propgrid/props.h>
#include <wx/wx.h>

#include "document.hpp"
#include "Events.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"
#include "ToolPanel.hpp"

namespace REHex {
	class DecodePanel: public ToolPanel
	{
		public:
			DecodePanel(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			
			virtual std::string name() const override;
// 			virtual std::string label() const override;
// 			virtual Shape shape() const override;
			
			virtual void save_state(wxConfig *config) const override;
			virtual void load_state(wxConfig *config) override;
			virtual void update() override;
			
			virtual wxSize DoGetBestClientSize() const override;
			
		private:
			SharedDocumentPointer document;
			SafeWindowPointer<DocumentCtrl> document_ctrl;
			
			wxChoice *endian;
			wxPropertyGrid *pgrid;
			int pgrid_best_width;
			
			wxPropertyCategory *c8;
			wxStringProperty *s8, *u8, *h8, *o8;
			
			wxPropertyCategory *c16;
			wxStringProperty *s16, *u16, *h16, *o16;
			
			wxPropertyCategory *c32;
			wxStringProperty *s32, *u32, *h32, *o32;
			
			wxPropertyCategory *c64;
			wxStringProperty *s64, *u64, *h64, *o64;
			
			wxPropertyCategory *c32f;
			wxStringProperty *f32;
			
			wxPropertyCategory *c64f;
			wxStringProperty *f64;
			
			std::vector<unsigned char> last_data;
			
			void OnCursorUpdate(CursorUpdateEvent &event);
			void OnDataModified(OffsetLengthEvent &event);
			void OnPropertyGridChanged(wxPropertyGridEvent& event);
			void OnPropertyGridSelected(wxPropertyGridEvent &event);
			void OnEndian(wxCommandEvent &event);
			void OnSize(wxSizeEvent &event);
			
			template<typename T, int base, T (*htoX)(T)> void OnSignedValue(wxStringProperty *property);
			template<typename T, int base, T (*htoX)(T)> void OnUnsignedValue(wxStringProperty *property);
			template<float (*htoX)(float)> void OnFloatValue(wxStringProperty *property);
			template<double (*htoX)(double)> void OnDoubleValue(wxStringProperty *property);
			
			/* Stays at the bottom because it changes the protection... */
			DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_VALUEPANEL_HPP */
