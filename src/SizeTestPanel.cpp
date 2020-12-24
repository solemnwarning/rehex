#include "ToolPanel.hpp"

class SizeTestPanel: public REHex::ToolPanel
{
	public:
		SizeTestPanel(wxWindow *parent, int min_width, int min_height, int best_width, int best_height, int max_width, int max_height);
		virtual wxSize DoGetBestClientSize() const override;
		
		virtual std::string name() const override { return "???"; }
		
		virtual void save_state(wxConfig *config) const override {}
		virtual void load_state(wxConfig *config) override {}
		virtual void update() override {}
		
	private:
		int min_width, min_height;
		int best_width, best_height;
		int max_width, max_height;
		
		void OnPaint(wxPaintEvent &event);
		DECLARE_EVENT_TABLE()
};

BEGIN_EVENT_TABLE(SizeTestPanel, wxControl)
	EVT_PAINT(SizeTestPanel::OnPaint)
END_EVENT_TABLE()

SizeTestPanel::SizeTestPanel(wxWindow *parent, int min_width, int min_height, int best_width, int best_height, int max_width, int max_height):
	ToolPanel(parent),
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
	return new SizeTestPanel(parent, 0, 20, 0, 40, 10000, 80);
}

static REHex::ToolPanel *tall_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new SizeTestPanel(parent, 0, 200, 0, 250, 10000, 300);
}

static REHex::ToolPanel *narrow_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new SizeTestPanel(parent, 20, 0, 40, 0, 80, 10000);
}

static REHex::ToolPanel *wide_factory(wxWindow *parent, REHex::SharedDocumentPointer &document, REHex::DocumentCtrl *document_ctrl)
{
	return new SizeTestPanel(parent, 200, 0, 250, 0, 300, 10000);
}

static REHex::ToolPanelRegistration short_tpr("short_tp", "Short panel", REHex::ToolPanel::TPS_WIDE, &short_factory);
static REHex::ToolPanelRegistration tall_tpr("tall_tp", "Tall panel", REHex::ToolPanel::TPS_WIDE, &tall_factory);
static REHex::ToolPanelRegistration narrow_tpr("narrow_tp", "Narrow panel", REHex::ToolPanel::TPS_TALL, &narrow_factory);
static REHex::ToolPanelRegistration wide_tpr("wide_tp", "Wide panel", REHex::ToolPanel::TPS_TALL, &wide_factory);
