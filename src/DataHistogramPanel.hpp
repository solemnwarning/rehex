/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_DATAHISTOGRAMPANEL_HPP
#define REHEX_DATAHISTOGRAMPANEL_HPP

#include <wx/chartpanel.h>
#include <wx/choice.h>
#include <wx/timer.h>

#include "DataHistogramAccumulator.hpp"
#include "document.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"
#include "ToolPanel.hpp"

namespace REHex {
	class DataHistogramPanel: public ToolPanel
	{
		public:
			DataHistogramPanel(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			~DataHistogramPanel();
			
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
			
			wxChoice *word_size_choice;
			wxChoice *bucket_count_choice;
			
			wxChartPanel* chart_panel;
			wxTimer update_timer;
			
			DataHistogramAccumulatorInterface *accumulator;
			Dataset *dataset;
			
			void reset_chart();
			
			void OnWordSizeChanged(wxCommandEvent &event);
			void OnBucketCountChanged(wxCommandEvent &event);
			
// 			void OnDataModifying(OffsetLengthEvent &event);
// 			void OnDataModifyAborted(OffsetLengthEvent &event);
// 			void OnDataErase(OffsetLengthEvent &event);
// 			void OnDataInsert(OffsetLengthEvent &event);
// 			void OnDataOverwrite(OffsetLengthEvent &event);
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_DATAHISTOGRAMPANEL_HPP */
