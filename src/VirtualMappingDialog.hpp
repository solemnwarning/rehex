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

#ifndef REHEX_VIRTUALMAPPINGDIALOG_HPP
#define REHEX_VIRTUALMAPPINGDIALOG_HPP

#include <wx/dialog.h>
#include <wx/statbmp.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>

#include "DocumentCtrl.hpp"
#include "NumericTextCtrl.hpp"
#include "SharedDocumentPointer.hpp"

namespace REHex {
	class VirtualMappingDialog: public wxDialog
	{
		public:
			VirtualMappingDialog(wxWindow *parent, SharedDocumentPointer &document, off_t real_base, off_t segment_length);
			virtual ~VirtualMappingDialog();
			
		private:
			bool initialised;
			
			off_t initial_real_base;
			off_t initial_virt_base;
			off_t initial_segment_length;
			
			SharedDocumentPointer document;
			
			NumericTextCtrl *real_base_input;
			wxStaticBitmap *real_base_bad;
			
			off_t get_real_base();
			
			NumericTextCtrl *virt_base_input;
			wxStaticBitmap *virt_base_bad;
			
			off_t get_virt_base();
			
			NumericTextCtrl *segment_length_input;
			wxStaticBitmap *segment_length_bad;
			
			off_t get_segment_length(off_t real_base);
			
			wxStaticText *conflict_warning;
			
			void update_warning();
			
			void OnOK(wxCommandEvent &event);
			void OnText(wxCommandEvent &event);
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_VIRTUALMAPPINGDIALOG_HPP */
