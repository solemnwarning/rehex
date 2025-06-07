/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <list>
#include <memory>
#include <wx/animate.h>
#include <wx/bmpbuttn.h>
#include <wx/chartpanel.h>
#include <wx/choice.h>
#include <wx/spinctrl.h>
#include <wx/timer.h>
#include <wx/toolbar.h>

#include "DataHistogramAccumulator.hpp"
#include "document.hpp"
#include "RangeChoiceLinear.hpp"
#include "SafeWindowPointer.hpp"
#include "SharedDocumentPointer.hpp"
#include "ToolPanel.hpp"

namespace REHex {
	class DataHistogramRenderer;
	
	class DataHistogramPanel: public ToolPanel
	{
		public:
			DataHistogramPanel(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			~DataHistogramPanel();
			
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
			
			RangeChoiceLinear *range_choice;
			
			wxToolBar *toolbar;
			wxAnimationCtrl *spinner;
			
			std::unique_ptr<DataHistogramAccumulatorInterface> accumulator;
			Dataset *dataset;
			wxChartPanel* chart_panel;
			DataHistogramRenderer *renderer;
			NumberAxis *x_axis;
			wxTimer refresh_timer;
			
			int wheel_accumulator;
			wxPoint mouse_down_point;
			bool chart_panning;
			wxPoint mouse_last_point;
			
			void reset_accumulator();
			void reset_chart();
			void reset_chart_margins();
			
			/**
			 * Get the bounding box of the *chart* (excluding legends/axes/etc) within
			 * the chart_panel client area.
			*/
			wxRect get_chart_panel_rect();
			
			/**
			 * Get the bounding box of the *chart* (excluding legends/axes/etc) within
			 * the screen space.
			*/
			wxRect get_chart_screen_rect();
			
			void zoom_adj(int steps);
			
			void OnRangeChanged(wxCommandEvent &event);
			void OnRefreshTimer(wxTimerEvent &event);
			void OnBucketSelected(wxCommandEvent &event);
			void OnZoomIn(wxCommandEvent &event);
			void OnZoomOut(wxCommandEvent &event);
			
			void OnChartWheel(wxMouseEvent &event);
			void OnChartLeftDown(wxMouseEvent &event);
			void OnChartLeftUp(wxMouseEvent &event);
			void OnChartMotion(wxMouseEvent &event);
			
			void OnDataErase(OffsetLengthEvent &event);
			void OnDataInsert(OffsetLengthEvent &event);
			void OnDataOverwrite(OffsetLengthEvent &event);
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_DATAHISTOGRAMPANEL_HPP */
