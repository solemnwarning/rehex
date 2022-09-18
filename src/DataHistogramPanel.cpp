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

namespace REHex
{
	class DataHistogramDatasetAdapter : public XYDataset
	{
		public:
			DataHistogramDatasetAdapter(DataHistogramAccumulatorInterface *accumulator);
			virtual ~DataHistogramDatasetAdapter();
			
			virtual double GetX(size_t index, size_t serie) override;
			virtual double GetY(size_t index, size_t serie) override;
			virtual size_t GetSerieCount() override;
			virtual size_t GetCount(size_t serie) override;
			virtual wxString GetSerieName(size_t serie) override;
		
		private:
			DataHistogramAccumulatorInterface *accumulator;
	};
	
	class DataHistogramRenderer: public XYRenderer, public DrawObserver
	{
		public:
			DataHistogramRenderer(DataHistogramAccumulatorInterface *accumulator);
			virtual ~DataHistogramRenderer();
			
			virtual void Draw(wxDC &dc, wxRect rc, Axis *horizAxis, Axis *vertAxis, XYDataset *dataset) override;
			virtual void NeedRedraw(DrawObject *obj) override;
			
			DataHistogramAccumulatorInterface *accumulator;
			wxChartPanel *panel;
	};
};

REHex::DataHistogramDatasetAdapter::DataHistogramDatasetAdapter(DataHistogramAccumulatorInterface *accumulator):
	accumulator(accumulator) {}

REHex::DataHistogramDatasetAdapter::~DataHistogramDatasetAdapter() {}

double REHex::DataHistogramDatasetAdapter::GetX(size_t index, size_t serie)
{
	wxCHECK(serie < 1, 0);
	wxCHECK(index < accumulator->get_num_buckets(), 0);
	
	return accumulator->get_bucket_min_value_as_double(index);
}

double REHex::DataHistogramDatasetAdapter::GetY(size_t index, size_t serie)
{
	wxCHECK(serie < 1, 0);
	wxCHECK(index < accumulator->get_num_buckets(), 0);
	
	return accumulator->get_bucket_count(index) + 1;
}

size_t REHex::DataHistogramDatasetAdapter::GetSerieCount()
{
	return 1;
}

size_t REHex::DataHistogramDatasetAdapter::GetCount(size_t serie)
{
	return accumulator->get_num_buckets();
}

wxString REHex::DataHistogramDatasetAdapter::GetSerieName(size_t serie)
{
	wxCHECK(serie < 1, wxEmptyString);
	return "hello";
}

REHex::DataHistogramRenderer::DataHistogramRenderer(DataHistogramAccumulatorInterface *accumulator):
	accumulator(accumulator),
	panel(NULL) {}

REHex::DataHistogramRenderer::~DataHistogramRenderer() {}

void REHex::DataHistogramRenderer::Draw(wxDC &dc, wxRect rc, Axis *horizAxis, Axis *vertAxis, XYDataset *dataset)
{
	assert(dataset->GetSerieCount() == 1);
	
	wxPoint screen_mouse_pos = wxGetMousePosition();
	wxPoint panel_mouse_pos = wxDefaultPosition;
	
	if(panel != NULL)
	{
		wxRect panel_screen_rect = panel->GetScreenRect();
		if(panel_screen_rect.Contains(screen_mouse_pos))
		{
			panel_mouse_pos = panel->ScreenToClient(screen_mouse_pos);
		}
	}
	
	FOREACH_DATAITEM(n, 0, dataset)
	{
		double xVal = dataset->GetX(n, 0);
		double yVal = dataset->GetY(n, 0);
		
		if (!horizAxis->IsVisible(xVal) || !vertAxis->IsVisible(yVal))
		{
			continue;
		}
		
		wxCoord x = horizAxis->ToGraphics(dc, rc.x, rc.width, xVal);
		wxCoord y = vertAxis->ToGraphics(dc, rc.y, rc.height, yVal);
		
		wxRect rcBar = {
			x,
			y,
			rc.width / (int)(dataset->GetCount(0)),
			rc.height - y + rc.y,
		};
		
		dc.SetPen(*wxBLACK_PEN);
		
		if(rcBar.Contains(panel_mouse_pos))
		{
			dc.SetBrush(*wxRED_BRUSH);
			
			std::string min_value_s = accumulator->get_bucket_min_value_as_string(n);
			std::string max_value_s = accumulator->get_bucket_max_value_as_string(n);
			std::string value_range_s = min_value_s != max_value_s
				? min_value_s + " - " + max_value_s
				: min_value_s;
			
			off_t count = accumulator->get_bucket_count(n);
			
			std::string s =
				"Value: " + value_range_s + "\n" +
				"Count: " + std::to_string(count);
			
			dc.DrawText(s, rc.x, rc.y);
		}
		else{
			dc.SetBrush(*wxGREEN_BRUSH);
		}
		
		dc.DrawRectangle(rcBar);
	}
}

void REHex::DataHistogramRenderer::NeedRedraw(DrawObject *obj)
{
    FireNeedRedraw();
}

static REHex::ToolPanel *DataHistogramPanel_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new REHex::DataHistogramPanel(parent, document, document_ctrl);
}

static REHex::ToolPanelRegistration tpr("DataHistogramPanel", "Histogram", REHex::ToolPanel::TPS_TALL, &DataHistogramPanel_factory);

enum {
	ID_WORD_SIZE_CHOICE = 1,
	ID_BUCKET_COUNT_CHOICE,
	
	WORD_SIZE_CHOICE_8BIT = 0,
	WORD_SIZE_CHOICE_16BIT,
	WORD_SIZE_CHOICE_32BIT,
	WORD_SIZE_CHOICE_64BIT,
	
	BUCKET_COUNT_CHOICE_16 = 0,
	BUCKET_COUNT_CHOICE_256,
};

BEGIN_EVENT_TABLE(REHex::DataHistogramPanel, wxPanel)
	EVT_CHOICE(ID_WORD_SIZE_CHOICE, REHex::DataHistogramPanel::OnWordSizeChanged)
	EVT_CHOICE(ID_BUCKET_COUNT_CHOICE, REHex::DataHistogramPanel::OnBucketCountChanged)
END_EVENT_TABLE()

REHex::DataHistogramPanel::DataHistogramPanel(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl):
	ToolPanel(parent),
	document(document),
	document_ctrl(document_ctrl),
	chart_panel(NULL),
	dataset(NULL)
{
	static const int MARGIN = 5;
	
	word_size_choice = new wxChoice(this, ID_WORD_SIZE_CHOICE);
	word_size_choice->Append("8-bit");
	word_size_choice->Append("16-bit");
	word_size_choice->Append("32-bit");
	word_size_choice->Append("64-bit");
	word_size_choice->SetSelection(WORD_SIZE_CHOICE_8BIT);
	
	bucket_count_choice = new wxChoice(this, ID_BUCKET_COUNT_CHOICE);
	bucket_count_choice->Append("16");
	bucket_count_choice->Append("256");
	bucket_count_choice->SetSelection(BUCKET_COUNT_CHOICE_16);
	
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	sizer->Add(word_size_choice, 0, (wxLEFT | wxRIGHT | wxTOP), MARGIN);
	sizer->Add(bucket_count_choice, 0, (wxLEFT | wxRIGHT | wxTOP), MARGIN);
	SetSizerAndFit(sizer);
	
	reset_chart();
	
	update_timer.Bind(wxEVT_TIMER, [this](wxTimerEvent &event)
	{
		if(dataset != NULL)
		{
			dataset->DatasetChanged();
		}
	});
	
	update_timer.Start(500);
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
	
	reset_chart();
}

void REHex::DataHistogramPanel::reset_chart()
{
	int bucket_count;
	switch(bucket_count_choice->GetSelection())
	{
		case BUCKET_COUNT_CHOICE_16:
			bucket_count = 16;
			break;
			
		case BUCKET_COUNT_CHOICE_256:
			bucket_count = 256;
			break;
			
		default:
			/* Unreachable. */
			return;
	}
	
	switch(word_size_choice->GetSelection())
	{
		case WORD_SIZE_CHOICE_8BIT:
			accumulator = new DataHistogramAccumulator<uint8_t>(document, 0, sizeof(uint8_t), document->buffer_length(), bucket_count);
			break;
		
		case WORD_SIZE_CHOICE_16BIT:
			accumulator = new DataHistogramAccumulator<uint16_t>(document, 0, sizeof(uint16_t), document->buffer_length(), bucket_count);
			break;
		
		case WORD_SIZE_CHOICE_32BIT:
			accumulator = new DataHistogramAccumulator<uint32_t>(document, 0, sizeof(uint32_t), document->buffer_length(), bucket_count);
			break;
		
		case WORD_SIZE_CHOICE_64BIT:
			accumulator = new DataHistogramAccumulator<uint64_t>(document, 0, sizeof(uint64_t), document->buffer_length(), bucket_count);
			break;
		
		default:
			/* Unreachable. */
			return;
	}
	
	// First step: create the plot.
	XYPlot *plot = new XYPlot();
	
	// Second step: create the dataset.
	DataHistogramDatasetAdapter *dataset = new DataHistogramDatasetAdapter(accumulator);
	this->dataset = dataset;
	
	DataHistogramRenderer *renderer = new DataHistogramRenderer(accumulator);
	dataset->SetRenderer(renderer);
	
	// add our dataset to plot
	plot->AddDataset(dataset);
	
	// add left and bottom number axes
	NumberAxis *leftAxis = new NumberAxis(AXIS_LEFT);
	leftAxis->IntegerValues(true);
	
	NumberAxis *bottomAxis = new NumberAxis(AXIS_BOTTOM);
	bottomAxis->SetFixedBounds(accumulator->get_type_min_value_as_double(), accumulator->get_type_max_value_as_double());
	
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
		GetSizer()->Detach(chart_panel);
		chart_panel->Destroy();
	}
	
	// Create a chart panel to display the chart.
	chart_panel = new wxChartPanel(this, wxID_ANY, chart);
	GetSizer()->Add(chart_panel, 1, (wxLEFT | wxRIGHT | wxTOP | wxEXPAND), 5);
	GetSizer()->Layout();
	
	renderer->panel = chart_panel;
}

void REHex::DataHistogramPanel::OnWordSizeChanged(wxCommandEvent &event)
{
	reset_chart();
}

void REHex::DataHistogramPanel::OnBucketCountChanged(wxCommandEvent &event)
{
	reset_chart();
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

