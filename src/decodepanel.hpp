/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_VALUEPANEL_HPP
#define REHEX_VALUEPANEL_HPP

#include <vector>
#include <wx/choice.h>
#include <wx/panel.h>
#include <wx/propgrid/propgrid.h>
#include <wx/propgrid/props.h>
#include <wx/wx.h>

namespace REHex {
	class ValueChange;
	wxDECLARE_EVENT(EV_VALUE_CHANGE, REHex::ValueChange);
	
	class ValueChange: public wxCommandEvent
	{
		public:
			template<typename T> ValueChange(const T &data, wxPGProperty *source):
				wxCommandEvent(EV_VALUE_CHANGE), source(source)
			{
				this->data.insert(this->data.end(),
					(const unsigned char*)(&data),
					(const unsigned char*)(&data) + sizeof(data));
			}
			
			ValueChange(const ValueChange &event):
				wxCommandEvent(EV_VALUE_CHANGE), data(event.data), source(event.source) {}
		
			wxEvent* Clone() const
			{
				return new ValueChange(*this);
			}
			
			std::vector<unsigned char> get_data() const
			{
				return data;
			}
			
			wxPGProperty *get_source() const
			{
				return source;
			}
			
		private:
			std::vector<unsigned char> data;
			wxPGProperty *source;
	};
	
	class ValueFocus;
	wxDECLARE_EVENT(EV_VALUE_FOCUS, REHex::ValueFocus);
	
	class ValueFocus: public wxCommandEvent
	{
		public:
			ValueFocus(size_t size):
				wxCommandEvent(EV_VALUE_FOCUS), size(size) {}
			
			ValueFocus(const ValueFocus &event):
				wxCommandEvent(EV_VALUE_FOCUS), size(event.size) {}
		
			wxEvent* Clone() const
			{
				return new ValueFocus(*this);
			}
			
			size_t get_size() const
			{
				return size;
			}
			
		private:
			size_t size;
	};
	
	class DecodePanel: public wxPanel
	{
		public:
			DecodePanel(wxWindow *parent, wxWindowID id = wxID_ANY);
			
			virtual wxSize DoGetBestClientSize() const override;
			
			void update(const unsigned char *data, size_t size, wxPGProperty *skip_control = NULL);
			
		private:
			wxChoice *endian;
			wxPropertyGrid *pgrid;
			int pgrid_best_width;
			
			wxPropertyCategory *c8;
			wxStringProperty *s8, *u8, *h8, *o8;
			
			wxPropertyCategory *c16;
			wxStringProperty *s16, *u16, *h16, *o16;
			
			wxPropertyCategory *c32;
			wxStringProperty *s32, *u32, *h32, *o32;
			
			wxPropertyCategory *c64;
			wxStringProperty *s64, *u64, *h64, *o64;
			
			wxPropertyCategory *c32f;
			wxStringProperty *f32;
			
			wxPropertyCategory *c64f;
			wxStringProperty *f64;
			
			std::vector<unsigned char> last_data;
			
			void OnPropertyGridChanged(wxPropertyGridEvent& event);
			void OnPropertyGridSelected(wxPropertyGridEvent &event);
			void OnEndian(wxCommandEvent &event);
			void OnSize(wxSizeEvent &event);
			
			template<typename T, int base, T (*htoX)(T)> void OnSignedValue(wxStringProperty *property);
			template<typename T, int base, T (*htoX)(T)> void OnUnsignedValue(wxStringProperty *property);
			template<float (*htoX)(float)> void OnFloatValue(wxStringProperty *property);
			template<double (*htoX)(double)> void OnDoubleValue(wxStringProperty *property);
			
			/* Stays at the bottom because it changes the protection... */
			DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_VALUEPANEL_HPP */
