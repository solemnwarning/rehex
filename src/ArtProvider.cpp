/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include "ArtProvider.hpp"

#include "res/ascii16.h"
#include "res/ascii24.h"
#include "res/ascii32.h"
#include "res/ascii48.h"

#include "res/offsets16.h"
#include "res/offsets24.h"
#include "res/offsets32.h"
#include "res/offsets48.h"

const wxArtID REHex::ART_ASCII_ICON  ("rehex-ascii");
const wxArtID REHex::ART_OFFSETS_ICON("rehex-offsets");

void REHex::ArtProvider::init()
{
	wxArtProvider::PushBack(new ArtProvider());
}

wxBitmap REHex::ArtProvider::CreateBitmap(const wxArtID &id, const wxArtClient &client, const wxSize &sizeHint)
{
	wxSize size = sizeHint == wxDefaultSize
		? GetNativeSizeHint(client)
		: sizeHint;
	
	wxImage image;
	
	if(id == ART_ASCII_ICON)
	{
		if(size.x <= 16 && size.y <= 16)
		{
			image = wxBITMAP_PNG_FROM_DATA(ascii16).ConvertToImage();
		}
		else if(size.x <= 24 && size.y <= 24)
		{
			image = wxBITMAP_PNG_FROM_DATA(ascii24).ConvertToImage();
		}
		else if(size.x <= 32 && size.y <= 32)
		{
			image = wxBITMAP_PNG_FROM_DATA(ascii32).ConvertToImage();
		}
		else{
			image = wxBITMAP_PNG_FROM_DATA(ascii48).ConvertToImage();
		}
	}
	else if(id == ART_OFFSETS_ICON)
	{
		if(size.x <= 16 && size.y <= 16)
		{
			image = wxBITMAP_PNG_FROM_DATA(offsets16).ConvertToImage();
		}
		else if(size.x <= 24 && size.y <= 24)
		{
			image = wxBITMAP_PNG_FROM_DATA(offsets24).ConvertToImage();
		}
		else if(size.x <= 32 && size.y <= 32)
		{
			image = wxBITMAP_PNG_FROM_DATA(offsets32).ConvertToImage();
		}
		else{
			image = wxBITMAP_PNG_FROM_DATA(offsets48).ConvertToImage();
		}
	}
	else{
		return wxNullBitmap;
	}
	
	image.Rescale(size.x, size.y);
	
	return image;
}
