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

#ifndef REHEX_CLIPBOARDUTILS_HPP
#define REHEX_CLIPBOARDUTILS_HPP

#include <memory>
#include <functional>
#include <stdexcept>
#include <wx/window.h>

#include "ByteRangeSet.hpp"
#include "document.hpp"
#include "DocumentCtrl.hpp"

namespace REHex
{
	/**
	 * @brief RAII-style access to the clipboard.
	 *
	 * This class provides an RAII-style wrapper around the Open() and Close() methods of the
	 * wxTheClipboard object.
	*/
	class ClipboardGuard
	{
		private:
			bool open;
			
		public:
			/**
			 * @brief Attempts to open the clipboard. Does not throw an exception on failure.
			*/
			ClipboardGuard(bool primary = false);
			
			/**
			 * @brief Closes the clipboard, if open.
			*/
			~ClipboardGuard();
			
			/**
			 * @brief Close the clipboard early.
			*/
			void close();
			
			/**
			 * @brief Check if the clipboard is open.
			*/
			operator bool() const
			{
				return open;
			}
	};
	
	class InvalidCopyRange: public std::runtime_error
	{
		public:
			InvalidCopyRange(const char *what_arg):
				runtime_error(what_arg) {}
	};
	
	/**
	 * @brief Copy the current selection to the clipboard.
	*/
	void copy_from_doc(Document *doc, DocumentCtrl *doc_ctrl, wxWindow *dialog_parent, bool cut);
	
	/**
	 * @brief Prepare a wxDataObject of a selection for copying to the clipboard.
	*/
	std::unique_ptr<wxDataObject> clipboard_data_from_doc(Document *doc, DocumentCtrl *doc_ctrl, const OrderedBitRangeSet &selection, const std::function<bool(size_t)> &size_pred);
}

#endif /* !REHEX_CLIPBOARDUTILS_HPP */
