/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2026 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <gtest/gtest.h>
#include <memory>

#include "../src/DisassemblyRegion.hpp"
#include "../src/document.hpp"
#include "../src/DocumentCtrl.hpp"
#include "../src/SharedDocumentPointer.hpp"
#include "testutil.hpp"

using namespace REHex;

static TextColour NULL_HIGHLIGHT_FUNC(BitOffset offset, BitOffset length)
{
	return TextColour::INVALID();
}

TEST(DisassemblyRegion, CopyWholeInstructions)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make(wxFileName("tests/ls.x86_64")));
	doc->set_data_type(0x46F0, 0x125BE, "code:x86_64");
	
	/* Create region covering the entire .text section */
	DisassemblyRegion* region = new DisassemblyRegion(doc, 0x46F0, 0x125BE, 0x46F0, NULL_HIGHLIGHT_FUNC);
	
	/* Wait for analysis to finish. */
	while((region->check() & DocumentCtrl::Region::PROCESSING) != 0)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	
	AutoFrame frame(NULL, wxID_ANY, "REHex Tests");
	DocumentCtrl *doc_ctrl = new DocumentCtrl(frame, doc);
	
	std::vector<DocumentCtrl::Region*> regions(&region, &region + 1);
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_cursor_position(0x7150, Document::CSTATE_SPECIAL);
	doc_ctrl->set_selection_raw(BitOffset(0x7150, 0), BitOffset((0x7150 + 22 - 1), 7));
	
	wxDataObject *data_obj = region->OnCopy(*doc_ctrl);
	
	ASSERT_NE(data_obj, (wxDataObject*)(NULL));
	
	wxTextDataObject *tdo = dynamic_cast<wxTextDataObject*>(data_obj);
	ASSERT_NE(tdo, (wxTextDataObject*)(NULL));
	
	EXPECT_STREQ(tdo->GetText(),
		"push    r12\n"
		"push    rbp\n"
		"mov     rbp, rsi\n"
		"mov     rsi, rdx\n"
		"push    rbx\n"
		"mov     ebx, edi\n"
		"mov     edi, 4\n"
		"call    0x14630");
	
	delete data_obj;
}

TEST(DisassemblyRegion, CopyInHexView)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make(wxFileName("tests/ls.x86_64")));
	doc->set_data_type(0x46F0, 0x125BE, "code:x86_64");
	
	/* Create region covering the entire .text section */
	DisassemblyRegion* region = new DisassemblyRegion(doc, 0x46F0, 0x125BE, 0x46F0, NULL_HIGHLIGHT_FUNC);
	
	/* Wait for analysis to finish. */
	while((region->check() & DocumentCtrl::Region::PROCESSING) != 0)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	
	AutoFrame frame(NULL, wxID_ANY, "REHex Tests");
	DocumentCtrl *doc_ctrl = new DocumentCtrl(frame, doc);
	
	std::vector<DocumentCtrl::Region*> regions(&region, &region + 1);
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_cursor_position(0x7150, Document::CSTATE_HEX);
	doc_ctrl->set_selection_raw(BitOffset(0x7150, 0), BitOffset((0x7150 + 22 - 1), 7));
	
	wxDataObject *data_obj = region->OnCopy(*doc_ctrl);
	
	EXPECT_EQ(data_obj, (wxDataObject*)(NULL));
}

TEST(DisassemblyRegion, CopyPartialInstructions)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make(wxFileName("tests/ls.x86_64")));
	doc->set_data_type(0x46F0, 0x125BE, "code:x86_64");
	
	/* Create region covering the entire .text section */
	DisassemblyRegion* region = new DisassemblyRegion(doc, 0x46F0, 0x125BE, 0x46F0, NULL_HIGHLIGHT_FUNC);
	
	/* Wait for analysis to finish. */
	while((region->check() & DocumentCtrl::Region::PROCESSING) != 0)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	
	AutoFrame frame(NULL, wxID_ANY, "REHex Tests");
	DocumentCtrl *doc_ctrl = new DocumentCtrl(frame, doc);
	
	std::vector<DocumentCtrl::Region*> regions(&region, &region + 1);
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_cursor_position(0x7150, Document::CSTATE_SPECIAL);
	doc_ctrl->set_selection_raw(BitOffset(0x7151, 0), BitOffset((0x7151 + 20 - 1), 7));
	
	wxDataObject *data_obj = region->OnCopy(*doc_ctrl);
	
	ASSERT_NE(data_obj, (wxDataObject*)(NULL));
	
	wxTextDataObject *tdo = dynamic_cast<wxTextDataObject*>(data_obj);
	ASSERT_NE(tdo, (wxTextDataObject*)(NULL));
	
	EXPECT_STREQ(tdo->GetText(),
		"push    rbp\n"
		"mov     rbp, rsi\n"
		"mov     rsi, rdx\n"
		"push    rbx\n"
		"mov     ebx, edi\n"
		"mov     edi, 4");
	
	delete data_obj;
}

TEST(DisassemblyRegion, CopyPartialInstruction)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make(wxFileName("tests/ls.x86_64")));
	doc->set_data_type(0x46F0, 0x125BE, "code:x86_64");
	
	/* Create region covering the entire .text section */
	DisassemblyRegion* region = new DisassemblyRegion(doc, 0x46F0, 0x125BE, 0x46F0, NULL_HIGHLIGHT_FUNC);
	
	/* Wait for analysis to finish. */
	while((region->check() & DocumentCtrl::Region::PROCESSING) != 0)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	
	AutoFrame frame(NULL, wxID_ANY, "REHex Tests");
	DocumentCtrl *doc_ctrl = new DocumentCtrl(frame, doc);
	
	std::vector<DocumentCtrl::Region*> regions(&region, &region + 1);
	doc_ctrl->replace_all_regions(regions);
	
	doc_ctrl->set_cursor_position(0x7150, Document::CSTATE_SPECIAL);
	doc_ctrl->set_selection_raw(BitOffset(0x7153, 0), BitOffset((0x7153 + 2 - 1), 7));
	
	wxDataObject *data_obj = region->OnCopy(*doc_ctrl);
	
	EXPECT_EQ(data_obj, (wxDataObject*)(NULL));
}
