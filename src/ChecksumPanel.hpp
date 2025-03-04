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

#ifndef REHEX_CHECKSUMPANEL_HPP
#define REHEX_CHECKSUMPANEL_HPP

#include <memory>
#include <wx/button.h>
#include <wx/choice.h>
#include <wx/textctrl.h>

#include "BitOffset.hpp"
#include "Checksum.hpp"
#include "RangeChoiceLinear.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"
#include "ThreadPool.hpp"
#include "ToolPanel.hpp"

namespace REHex
{
	class ChecksumPanel: public ToolPanel
	{
		public:
			ChecksumPanel(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			~ChecksumPanel();
			
			virtual std::string name() const override;
			virtual std::string label() const override;
			virtual Shape shape() const override;
			
			virtual void save_state(wxConfig *config) const override;
			virtual void load_state(wxConfig *config) override;
			virtual void update() override;
			
			virtual wxSize DoGetBestClientSize() const override;
			
		private:
			SharedDocumentPointer document;
			SafeWindowPointer<DocumentCtrl> document_ctrl;
			
			std::vector<const ChecksumAlgorithm*> cs_algos;
			std::unique_ptr<ChecksumGenerator> cs_gen;
			
			BitOffset range_offset;
			off_t range_length;
			
			std::unique_ptr<ThreadPool::TaskHandle> work_task;
			BitOffset work_offset;
			
			RangeChoiceLinear *range_choice;
			wxChoice *algo_choice;
			wxTextCtrl *output;
			wxButton *copy_btn;
			
			void restart();
			bool process();
			
			void OnRangeChanged(wxCommandEvent &event);
			void OnAlgoChanged(wxCommandEvent &event);
			void OnCopyChecksum(wxCommandEvent &event);
			
			void OnDataErase(OffsetLengthEvent &event);
			void OnDataInsert(OffsetLengthEvent &event);
			void OnDataOverwrite(OffsetLengthEvent &event);
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_CHECKSUMPANEL_HPP */
