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

#include "platform.hpp"

#include <assert.h>
#include <wx/axis/numberaxis.h>
#include <wx/xy/xyhistorenderer.h>
#include <wx/xy/xyplot.h>
#include <wx/xy/xysimpledataset.h>

#include "DataHistogramPanel.hpp"

static REHex::ToolPanel *DataHistogramPanel_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new REHex::DataHistogramPanel(parent, document, document_ctrl);
}

static REHex::ToolPanelRegistration tpr("DataHistogramPanel", "Histogram", REHex::ToolPanel::TPS_TALL, &DataHistogramPanel_factory);

BEGIN_EVENT_TABLE(REHex::DataHistogramPanel, wxPanel)
END_EVENT_TABLE()

REHex::DataHistogramPanel::DataHistogramPanel(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl):
	ToolPanel(parent),
	document(document),
	document_ctrl(document_ctrl),
	chart_panel(NULL)
{
	update_timer.Bind(wxEVT_TIMER, [this](wxTimerEvent &event)
	{
		update();
	});
	
	update_timer.Start(5000);
	
	acc = new DataHistogramAccumulator<uint8_t>(document, 0, 1, document->buffer_length(), 16);
}

REHex::DataHistogramPanel::~DataHistogramPanel() {}

std::string REHex::DataHistogramPanel::name() const
{
	return "DataHistogramPanel";
}

void REHex::DataHistogramPanel::save_state(wxConfig *config) const
{
	/* TODO */
}

void REHex::DataHistogramPanel::load_state(wxConfig *config)
{
	/* TODO */
}

wxSize REHex::DataHistogramPanel::DoGetBestClientSize() const
{
	/* TODO */
	return wxSize(100, -1);
}

void REHex::DataHistogramPanel::update()
{
	if (!is_visible)
	{
		/* There is no sense in updating this if we are not visible */
		return;
	}
	
	#if 0
	if(update_needed && document_ctrl)
	{
		size_t strings_count;
		
		{
			std::lock_guard<std::mutex> sl(strings_lock);
			
			strings_count = strings.size();
			update_needed = false;
		}
		
		list_ctrl->SetItemCount(strings_count);
		
		bool searching = spawned_threads > 0;
		std::string status_text = "";
		
		if(searching)
		{
			status_text += "Searching from " + format_offset(search_base, document_ctrl->get_offset_display_base(), document->buffer_length());
			continue_button->Disable();
		}
		else{
			status_text += "Searched from " + format_offset(search_base, document_ctrl->get_offset_display_base(), document->buffer_length());
			
			auto next_pending = pending.find_first_in(search_base, std::numeric_limits<off_t>::max());
			continue_button->Enable(next_pending != pending.end());
		}
		
		status_text += "\n";
		
		if(strings_count > 0)
		{
			status_text += "Found "
				+ wxNumberFormatter::ToString((long)(strings_count))
				+ " strings";
		}
		else if(!searching)
		{
			status_text += "No strings found";
		}
		
		this->status_text->SetLabelText(status_text);
	}
	#endif
	
	wxVector<wxRealPoint> data;
	
	auto buckets = acc->get_buckets();
	for(auto b = buckets.begin(); b != buckets.end(); ++b)
	{
		data.push_back(wxRealPoint(b->min_value, b->count));
	}
	
	// First step: create the plot.
	XYPlot *plot = new XYPlot();
	
	// Second step: create the dataset.
	XYSimpleDataset *dataset = new XYSimpleDataset();
	
	// Third step: add the series to it.
	dataset->AddSerie(new XYSerie(data));
	
	// create histogram renderer with bar width = 10 and vertical bars
	XYHistoRenderer *histoRenderer = new XYHistoRenderer(-1, true);
	
	// set bar areas to renderer
	// in this case, we set green bar with black outline for serie 0
	histoRenderer->SetBarArea(0, new FillAreaDraw(*wxBLACK_PEN, *wxGREEN_BRUSH));
	
	// set renderer to dataset
	dataset->SetRenderer(histoRenderer);
	
	// add our dataset to plot
	plot->AddDataset(dataset);
	
	// add left and bottom number axes
	NumberAxis *leftAxis = new NumberAxis(AXIS_LEFT);
	NumberAxis *bottomAxis = new NumberAxis(AXIS_BOTTOM);
	bottomAxis->SetFixedBounds(0, 255);
	
	// set bottom axis margins
	bottomAxis->SetMargins(15, 15);
	
	// add axes to plot
	plot->AddAxis(leftAxis);
	plot->AddAxis(bottomAxis);
	
	// link axes and dataset
	plot->LinkDataVerticalAxis(0, 0);
	plot->LinkDataHorizontalAxis(0, 0);
	
	// and finally create chart
	Chart *chart = new Chart(plot, GetName());
	
	if(chart_panel != NULL)
	{
		chart_panel->Destroy();
	}
	
	// Create a chart panel to display the chart.
	chart_panel = new wxChartPanel(this, wxID_ANY, chart, wxDefaultPosition, GetClientSize());
}

// void REHex::DataHistogramPanel::OnDataModifying(OffsetLengthEvent &event)
// {
// 	pause_threads();
// 	
// 	/* Continue propogation. */
// 	event.Skip();
// }
// 
// void REHex::DataHistogramPanel::OnDataModifyAborted(OffsetLengthEvent &event)
// {
// 	start_threads();
// 	
// 	/* Continue propogation. */
// 	event.Skip();
// }
// 
// void REHex::DataHistogramPanel::OnDataErase(OffsetLengthEvent &event)
// {
// 	{
// 		std::lock_guard<std::mutex> sl(strings_lock);
// 		strings.data_erased(event.offset, event.length);
// 	}
// 	
// 	{
// 		std::lock_guard<std::mutex> pl(pause_lock);
// 		
// 		dirty.data_erased(event.offset, event.length);
// 		pending.data_erased(event.offset, event.length);
// 		assert(working.empty());
// 		
// 		mark_dirty_pad(event.offset, 0);
// 	}
// 	
// 	start_threads();
// 	
// 	/* Continue propogation. */
// 	event.Skip();
// }
// 
// void REHex::DataHistogramPanel::OnDataInsert(OffsetLengthEvent &event)
// {
// 	{
// 		std::lock_guard<std::mutex> sl(strings_lock);
// 		strings.data_inserted(event.offset, event.length);
// 	}
// 	
// 	{
// 		std::lock_guard<std::mutex> pl(pause_lock);
// 		
// 		dirty.data_inserted(event.offset, event.length);
// 		pending.data_inserted(event.offset, event.length);
// 		assert(working.empty());
// 		
// 		mark_dirty_pad(event.offset, event.length);
// 	}
// 	
// 	start_threads();
// 	
// 	/* Continue propogation. */
// 	event.Skip();
// }
// 
// void REHex::DataHistogramPanel::OnDataOverwrite(OffsetLengthEvent &event)
// {
// 	{
// 		std::lock_guard<std::mutex> pl(pause_lock);
// 		mark_dirty_pad(event.offset, event.length);
// 	}
// 	
// 	start_threads();
// 	
// 	/* Continue propogation. */
// 	event.Skip();
// }

