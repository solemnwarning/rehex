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

#ifndef REHEX_DATAMAPTOOL_HPP
#define REHEX_DATAMAPTOOL_HPP

#include <memory>
#include <wx/choice.h>
//#include <wx/statbmp.h>
#include <wx/generic/statbmpg.h>
#include <wx/timer.h>

#include "BitOffset.hpp"
#include "DataMapSource.hpp"
#include "document.hpp"
#include "RangeChoiceLinear.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"
#include "ToolPanel.hpp"

namespace REHex {
	class DataMapTool: public ToolPanel
	{
		public:
			enum class Mode {
				ENTROPY_AVERAGE,
			};
			
			DataMapTool(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			virtual ~DataMapTool();
			
			virtual std::string name() const override;
			virtual std::string label() const override;
			virtual Shape shape() const override;
			
			virtual void save_state(wxConfig *config) const override;
			virtual void load_state(wxConfig *config) override;
			
			virtual wxSize DoGetBestClientSize() const override;
			
			bool is_processing();
			wxBitmap get_bitmap();
			
		private:
			SharedDocumentPointer document;
			SafeWindowPointer<DocumentCtrl> document_ctrl;
			
			std::shared_ptr<DataView> m_view;
			std::unique_ptr<DataMapSource> source;
			bool m_source_reset_pending;
			
			wxChoice *mode_choice;
			RangeChoiceLinear *range_choice;
			
			wxGenericStaticBitmap *s_bitmap;
			
			wxTimer update_timer;
			
			enum class UpdateStage
			{
				IDLE,
				GETTING_DATA,
				REDRAW,
			};
			
			std::atomic<UpdateStage> update_stage;
			BitRangeMap<DataMapSource::MapValue> update_data;
			ThreadPool::TaskHandle update_get_data_task;
			
			wxBitmap m_base_bitmap;
			
			int m_data_width;  /**< Width of bitmap (in points, not pixels). */
			int m_data_height; /**< Height of bitmap (in points, not pixels). */
			
			off_t m_bytes_per_row;
			off_t m_bytes_per_point;
			
			bool m_dragging;
			
			void reset_view();
			
			virtual void update() override;
			void update_output_bitmap();
			
			void OnModeChanged(wxCommandEvent &event);
			void OnRangeChanged(wxCommandEvent &event);
			void OnUpdateTimer(wxTimerEvent &event);
			void OnSize(wxSizeEvent &event);
			void OnBitmapSize(wxSizeEvent &event);
			void OnBitmapLeftDown(wxMouseEvent &event);
			void OnMotion(wxMouseEvent &event);
			void OnLeftUp(wxMouseEvent &event);
			void OnMouseCaptureLost(wxMouseCaptureLostEvent &event);
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_DATAMAPTOOL_HPP */
