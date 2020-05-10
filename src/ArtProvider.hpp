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

#ifndef REHEX_ARTPROVIDER_HPP
#define REHEX_ARTPROVIDER_HPP

#include <wx/artprov.h>
#include <wx/wx.h>

namespace REHex
{
	extern const wxArtID ART_ASCII_ICON;
	extern const wxArtID ART_OFFSETS_ICON;
	
	class ArtProvider: public wxArtProvider
	{
		public:
			static void init();
			
		protected:
			virtual wxBitmap CreateBitmap(const wxArtID &id, const wxArtClient &client, const wxSize &size) override;
	};
}

#endif /* !REHEX_ARTPROVIDER_HPP */
