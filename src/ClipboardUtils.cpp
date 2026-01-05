/* Reverse Engineer's Hex Editor
 * Copyright (C) 2026 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <wx/clipbrd.h>

#include "ClipboardUtils.hpp"
#include "DataType.hpp"

REHex::ClipboardGuard::ClipboardGuard(bool primary)
{
	wxTheClipboard->UsePrimarySelection(primary);
	open = wxTheClipboard->Open();
}

REHex::ClipboardGuard::~ClipboardGuard()
{
	if(open)
	{
		wxTheClipboard->Close();
	}
}

void REHex::ClipboardGuard::close()
{
	if(open)
	{
		wxTheClipboard->Close();
		open = false;
	}
}

std::unique_ptr<wxDataObject> REHex::clipboard_data_from_doc(Document *doc, DocumentCtrl *doc_ctrl, const OrderedBitRangeSet &selection, const std::function<bool(size_t)> &size_pred)
{
	Document::CursorState cursor_state = doc_ctrl->get_cursor_state();
	
	std::unique_ptr<wxDataObject> copy_data = NULL;
	
	/* If the selection is contained within a single Region, give it the chance to do something
	 * special rather than just copying out the hex/ASCII for the selection.
	 *
	 * TODO: Check how much space will be needed and warn the user like below...
	*/
	
	if(selection.size() == 1)
	{
		REHex::DocumentCtrl::GenericDataRegion *selection_region = doc_ctrl->data_region_by_offset(selection[0].offset);
		assert(selection_region != NULL);
		
		assert(selection_region->d_offset <= selection[0].offset);
		
		if((selection_region->d_offset + selection_region->d_length) >= (selection[0].offset + selection[0].length))
		{
			copy_data.reset(selection_region->OnCopy(*doc_ctrl));
		}
		
		if(copy_data != NULL && copy_data->IsSupported(wxDF_TEXT) && !(size_pred(copy_data->GetDataSize(wxDF_TEXT))))
		{
			return NULL;
		}
	}
	
	if(copy_data == NULL)
	{
		size_t upper_limit = cursor_state == Document::CSTATE_ASCII
			? selection.total_bytes().byte()
			: (selection.total_bytes().byte() * 2);
		
		if(!size_pred(upper_limit))
		{
			return NULL;
		}
		
		try {
			wxString data_string;
			data_string.reserve(upper_limit);
			
			const BitRangeMap<Document::TypeInfo> &types = doc->get_data_types();
			
			for(auto sr = selection.begin(); sr != selection.end(); ++sr)
			{
				if(!sr->length.byte_aligned())
				{
					throw InvalidCopyRange("selection not a whole number of bytes");
				}
				
				std::vector<unsigned char> selection_data = doc->read_data(sr->offset, sr->length.byte());
				assert((off_t)(selection_data.size()) == sr->length.byte());
				
				if(cursor_state == Document::CSTATE_ASCII)
				{
					for(size_t sd_off = 0; sd_off < selection_data.size();)
					{
						auto type_at_off = types.get_range(sr->offset + (off_t)(sd_off));
						assert(type_at_off != types.end());
						
						static REHex::CharacterEncoderASCII ascii_encoder;
						const CharacterEncoder *encoder = &ascii_encoder;
						if(type_at_off->second.name != "")
						{
							std::shared_ptr<const DataType> dt_reg = DataTypeRegistry::get_type(type_at_off->second.name, type_at_off->second.options);
							assert(dt_reg != NULL);
							
							if(dt_reg->encoder != NULL)
							{
								encoder = dt_reg->encoder;
							}
						}
						
						/* TODO: Should we restrict to printable characters here? */
						EncodedCharacter ec = encoder->decode((selection_data.data() + sd_off), (selection_data.size() - sd_off));
						
						if(ec.valid)
						{
							data_string.append(wxString::FromUTF8(ec.utf8_char().c_str()));
							sd_off += ec.encoded_char().size();
						}
						else{
							/* Ignore invalid characters. */
							++sd_off;
						}
					}
				}
				else{
					for(auto c = selection_data.begin(); c != selection_data.end(); ++c)
					{
						const char *nibble_to_hex = "0123456789ABCDEF";
						
						unsigned char high_nibble = (*c & 0xF0) >> 4;
						unsigned char low_nibble  = (*c & 0x0F);
						
						data_string.append(&(nibble_to_hex[high_nibble]), 1);
						data_string.append(&(nibble_to_hex[low_nibble]), 1);
					}
				}
			}
			
			if(!data_string.empty())
			{
				copy_data.reset(new wxTextDataObject(data_string));
			}
		}
		catch(const std::bad_alloc &)
		{
			throw std::runtime_error("Memory allocation failed while preparing clipboard buffer.");
		}
	}
	
	return copy_data;
}

void REHex::copy_from_doc(REHex::Document *doc, REHex::DocumentCtrl *doc_ctrl, wxWindow *dialog_parent, bool cut)
{
	OrderedBitRangeSet selection = doc_ctrl->get_selection_ranges();
	
	if(selection.empty())
	{
		/* Nothing selected - nothing to copy. */
		wxBell();
		return;
	}
	
	if(cut)
	{
		for(auto s = selection.begin(); s != selection.end(); ++s)
		{
			if(!s->offset.byte_aligned() || !s->length.byte_aligned())
			{
				/* Selection isn't byte-aligned - can't cut */
				wxBell();
				return;
			}
		}
	}
	
	std::unique_ptr<wxDataObject> copy_data;
	try {
		copy_data = clipboard_data_from_doc(doc, doc_ctrl, selection, [&](size_t size)
		{
			/* Warn the user this might be a bad idea before dumping silly amounts
			 * of data (>16MiB) into the clipboard.
			*/
			
			static size_t COPY_MAX_SOFT = 16777216;
			
			if(size > COPY_MAX_SOFT)
			{
				char msg[128];
				snprintf(msg, sizeof(msg),
					"You are about to copy %uMB into the clipboard.\n"
					"This may take a long time and/or crash some applications.",
					(unsigned)(size / 1000000));
				
				int result = wxMessageBox(msg, "Warning", (wxOK | wxCANCEL | wxICON_EXCLAMATION), dialog_parent);
				return result == wxOK;
			}
			
			return true;
		});
	}
	catch(const InvalidCopyRange &e)
	{
		wxBell();
		return;
	}
	catch(const std::exception &e)
	{
		wxMessageBox(e.what(), "Error", (wxOK | wxICON_ERROR), dialog_parent);
		return;
	}
	
	if(copy_data != NULL)
	{
		ClipboardGuard cg;
		if(cg)
		{
			wxTheClipboard->SetData(copy_data.release());
			
			if(cut)
			{
				ScopedTransaction t(doc, "cut selection");
				
				for(auto sr = selection.begin(); sr != selection.end(); ++sr)
				{
					doc->erase_data(sr->offset.byte(), sr->length.byte());
				}
				
				t.commit();
			}
		}
	}
}
