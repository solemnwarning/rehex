/* Reverse Engineer's Hex Editor
 * Copyright (C) 2023-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_BITEDITOR_HPP
#define REHEX_BITEDITOR_HPP

#include <functional>
#include <wx/button.h>
#include <wx/checkbox.h>
#include <wx/choice.h>
#include <wx/spinctrl.h>
#include <wx/statbmp.h>
#include <wx/stattext.h>

#include "document.hpp"
#include "Events.hpp"
#include "NumericTextCtrl.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"
#include "ToolPanel.hpp"

namespace REHex {
	class BitEditor: public ToolPanel
	{
		public:
			BitEditor(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			
			virtual std::string name() const override;
			virtual std::string label() const override;
			virtual Shape shape() const override;
			
			virtual void save_state(wxConfig *config) const override;
			virtual void load_state(wxConfig *config) override;
			virtual void update() override;
			
		private:
			static const int NUM_BITS = 8;
			static const int MAX_BYTES = 8;
			
			SharedDocumentPointer document;
			SafeWindowPointer<DocumentCtrl> document_ctrl;
			
			wxChoice *endian;
			wxSpinCtrl *size_bytes;
			
			NumericTextCtrl *num_value;
			wxChoice *num_base;
			wxStaticBitmap *num_value_bad;
			
			wxStaticText *byte_labels[MAX_BYTES];
			wxCheckBox *bits[MAX_BYTES][NUM_BITS];
			
			wxButton *not_btn, *and_btn, *or_btn;
			wxButton *xor_btn, *lsh_btn, *rsh_btn;
			
			BitOffset value_offset;
			uint64_t max_value;
			
			int get_num_base();
			
			uint64_t read_value();
			void write_value(uint64_t value);
			bool modify_value(const std::function<uint64_t(uint64_t)> &func);
			
			void disable_edit_controls();
			
			void OnCursorUpdate(CursorUpdateEvent &event);
			void OnDataModified(OffsetLengthEvent &event);
			void OnEndian(wxCommandEvent &event);
			void OnNumBytes(wxSpinEvent &event);
			void OnValueChange(wxCommandEvent &event);
			void OnBaseChange(wxCommandEvent &event);
			void OnBitToggle(wxCommandEvent &event);
			void OnNot(wxCommandEvent &event);
			void OnAnd(wxCommandEvent &event);
			void OnOr(wxCommandEvent &event);
			void OnXor(wxCommandEvent &event);
			void OnLeftShift(wxCommandEvent &event);
			void OnRightShift(wxCommandEvent &event);
			
			/* Stays at the bottom because it changes the protection... */
			DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_BITEDITOR_HPP */
