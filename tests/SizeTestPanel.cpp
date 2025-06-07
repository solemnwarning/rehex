/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "../src/platform.hpp"

#include "SizeTestPanel.hpp"

BEGIN_EVENT_TABLE(SizeTestPanel, REHex::ToolPanel)
	EVT_PAINT(SizeTestPanel::OnPaint)
END_EVENT_TABLE()

SizeTestPanel::SizeTestPanel(wxWindow *parent, int min_width, int min_height, int best_width, int best_height, int max_width, int max_height, const std::string &name_s, const std::string &label_s, Shape shape):
	ToolPanel(parent),
	name_s(name_s),
	label_s(label_s),
	shape_(shape),
	min_width(min_width), min_height(min_height),
	best_width(best_width), best_height(best_height),
	max_width(max_width), max_height(max_height)
{
	SetMinClientSize(wxSize(min_width, min_height));
	SetMaxClientSize(wxSize(max_width, max_height));
}

wxSize SizeTestPanel::DoGetBestClientSize() const
{
	return wxSize(best_width, best_height);
}

void SizeTestPanel::OnPaint(wxPaintEvent &event)
{
	wxPaintDC dc(this);
	
	dc.SetBackground(*wxWHITE_BRUSH);
	dc.Clear();
	
	wxSize size = GetSize();
	
	{
		int xe = (min_width > 0 ? (min_width - 1) : (size.GetWidth() - 1));
		int ye = (min_height > 0 ? (min_height - 1) : (size.GetHeight() - 1));
		
		dc.SetPen(*wxRED);
		dc.DrawLine(0, 0, xe, 0);
		dc.DrawLine(0, 0, 0, ye);
		dc.DrawLine(xe, 0, xe, ye);
		dc.DrawLine(0, ye, xe, ye);
	}
	
	{
		int xe = (best_width > 0 ? (best_width - 1) : (size.GetWidth() - 1));
		int ye = (best_height > 0 ? (best_height - 1) : (size.GetHeight() - 1));
		
		dc.SetPen(*wxBLUE);
		dc.DrawLine(0, 0, xe, 0);
		dc.DrawLine(0, 0, 0, ye);
		dc.DrawLine(xe, 0, xe, ye);
		dc.DrawLine(0, ye, xe, ye);
	}
	
	{
		int xe = (max_width > 0 ? (max_width - 1) : (size.GetWidth() - 1));
		int ye = (max_height > 0 ? (max_height - 1) : (size.GetHeight() - 1));
		
		dc.SetPen(*wxBLACK);
		dc.DrawLine(0, 0, xe, 0);
		dc.DrawLine(0, 0, 0, ye);
		dc.DrawLine(xe, 0, xe, ye);
		dc.DrawLine(0, ye, xe, ye);
	}
}

static REHex::ToolPanel *short_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new SizeTestPanel(parent, 0, 20, 0, 40, 10000, 300, "short_tp", "Short panel", REHex::ToolPanel::TPS_WIDE);
}

static REHex::ToolPanel *tall_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new SizeTestPanel(parent, 0, 200, 0, 250, 10000, 400, "tall_tp", "Tall panel", REHex::ToolPanel::TPS_WIDE);
}

static REHex::ToolPanel *narrow_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new SizeTestPanel(parent, 20, 0, 40, 0, 250, 10000, "narrow_tp", "Narrow panel", REHex::ToolPanel::TPS_TALL);
}

static REHex::ToolPanel *wide_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new SizeTestPanel(parent, 200, 0, 250, 0, 400, 10000, "wide_tp", "Wide panel", REHex::ToolPanel::TPS_TALL);
}

static REHex::ToolPanelRegistration short_tpr("short_tp", "Short panel", REHex::ToolPanel::TPS_WIDE, &short_factory);
static REHex::ToolPanelRegistration tall_tpr("tall_tp", "Tall panel", REHex::ToolPanel::TPS_WIDE, &tall_factory);
static REHex::ToolPanelRegistration narrow_tpr("narrow_tp", "Narrow panel", REHex::ToolPanel::TPS_TALL, &narrow_factory);
static REHex::ToolPanelRegistration wide_tpr("wide_tp", "Wide panel", REHex::ToolPanel::TPS_TALL, &wide_factory);
