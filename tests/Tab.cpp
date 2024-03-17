/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <stdexcept>
#include <vector>
#include <wx/frame.h>
#include <wx/timer.h>

#include "../src/BasicDataTypes.hpp"
#include "../src/document.hpp"
#include "../src/SharedDocumentPointer.hpp"
#include "../src/Tab.hpp"

#define FRAME_WIDTH 800
#define FRAME_HEIGHT 600

using namespace REHex;

static std::vector<std::string> stringify_regions(const std::vector<DocumentCtrl::Region*> &regions)
{
	std::vector<std::string> s_regions;
	
	for(auto r = regions.begin(); r != regions.end(); ++r)
	{
		char buf[256];
		
		DocumentCtrl::CommentRegion          *cr   = dynamic_cast<DocumentCtrl::CommentRegion*>(*r);
		DocumentCtrl::DataRegionDocHighlight *drdh = dynamic_cast<DocumentCtrl::DataRegionDocHighlight*>(*r);
		
		S16LEDataRegion *s16le = dynamic_cast<S16LEDataRegion*>(*r);
		S64LEDataRegion *s64le = dynamic_cast<S64LEDataRegion*>(*r);
		
		if(cr != NULL)
		{
			snprintf(buf, sizeof(buf),
				"CommentRegion(c_offset = %ld.%d, c_length = %ld.%d, indent_offset = %ld+%db, indent_length = %ld+%db, c_text = '%s', truncate = %d)",
				(long)(cr->c_offset.byte()), cr->c_offset.bit(), (long)(cr->c_length.byte()), cr->c_length.bit(), (long)(cr->indent_offset.byte()), cr->indent_offset.bit(), (long)(cr->indent_length.byte()), cr->indent_length.bit(), cr->c_text.ToStdString().c_str(), (int)(cr->truncate));
		}
		else if(drdh != NULL)
		{
			snprintf(buf, sizeof(buf),
				"DataRegionDocHighlight(d_offset = %ld+%db, d_length = %ld+%db, indent_offset = %ld+%db, indent_length = %ld+%db)",
				(long)(drdh->d_offset.byte()), drdh->d_offset.bit(), (long)(drdh->d_length.byte()), drdh->d_length.bit(), (long)(drdh->indent_offset.byte()), drdh->indent_offset.bit(), (long)(drdh->indent_length.byte()), drdh->indent_length.bit());
		}
		else if(s16le != NULL)
		{
			snprintf(buf, sizeof(buf),
				"S16LEDataRegion(d_offset = %ld+%db, d_length = %ld+%db, indent_offset = %ld+%db, indent_length = %ld+%db)",
				(long)(s16le->d_offset.byte()), s16le->d_offset.bit(), (long)(s16le->d_length.byte()), s16le->d_length.bit(), (long)(s16le->indent_offset.byte()), s16le->indent_offset.bit(), (long)(s16le->indent_length.byte()), s16le->indent_length.bit());
		}
		else if(s64le != NULL)
		{
			snprintf(buf, sizeof(buf),
				"S64LEDataRegion(d_offset = %ld+%db, d_length = %ld+%db, indent_offset = %ld+%db, indent_length = %ld+%db)",
				(long)(s64le->d_offset.byte()), s64le->d_offset.bit(), (long)(s64le->d_length.byte()), s64le->d_length.bit(), (long)(s64le->indent_offset.byte()), s64le->indent_offset.bit(), (long)(s64le->indent_length.byte()), s64le->indent_length.bit());
		}
		else{
			throw std::runtime_error("Unknown Region subclass encountered");
		}
		
		s_regions.push_back(buf);
	}
	
	return s_regions;
}

static void free_regions(std::vector<DocumentCtrl::Region*> &regions)
{
	for(auto r = regions.begin(); r != regions.end(); ++r)
	{
		delete (*r);
	}
	
	regions.clear();
}

#if 0
/* Logic moved into Tab::repopulate_regions() */
TEST(Tab, ComputeRegionsEmptyFile)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	std::vector<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, 0, 0, doc->buffer_length(), ICM_FULL);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0+0b, d_length = 0+0b, indent_offset = 0+0b, indent_length = 0+0b)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}
#endif

TEST(Tab, ComputeRegionsNoComments)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	std::vector<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, 0, 0, doc->buffer_length(), ICM_FULL);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0+0b, d_length = 4096+0b, indent_offset = 0+0b, indent_length = 0+0b)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsFlatComments)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_comment(1024, 128, REHex::Document::Comment("unite"));
	doc->set_comment(1024,   0, REHex::Document::Comment("robin"));
	doc->set_comment(1024,  64, REHex::Document::Comment("release"));
	doc->set_comment(1088,  64, REHex::Document::Comment("uncle"));
	doc->set_comment(1152,  64, REHex::Document::Comment("scarecrow"));
	doc->set_comment(2048,  64, REHex::Document::Comment("crowded"));
	
	std::vector<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, 0, 0, doc->buffer_length(), ICM_FULL);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0+0b, d_length = 1024+0b, indent_offset = 0+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 1024.0, c_length = 128.0, indent_offset = 1024+0b, indent_length = 0+0b, c_text = 'unite', truncate = 0)",
		"CommentRegion(c_offset = 1024.0, c_length = 64.0, indent_offset = 1024+0b, indent_length = 0+0b, c_text = 'release', truncate = 0)",
		"CommentRegion(c_offset = 1024.0, c_length = 0.0, indent_offset = 1024+0b, indent_length = 0+0b, c_text = 'robin', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1024+0b, d_length = 64+0b, indent_offset = 1024+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 1088.0, c_length = 64.0, indent_offset = 1088+0b, indent_length = 0+0b, c_text = 'uncle', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1088+0b, d_length = 64+0b, indent_offset = 1088+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 1152.0, c_length = 64.0, indent_offset = 1152+0b, indent_length = 0+0b, c_text = 'scarecrow', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1152+0b, d_length = 896+0b, indent_offset = 1152+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 2048.0, c_length = 64.0, indent_offset = 2048+0b, indent_length = 0+0b, c_text = 'crowded', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 2048+0b, d_length = 2048+0b, indent_offset = 2048+0b, indent_length = 0+0b)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsShortComments)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_comment(   0, 128, REHex::Document::Comment("unite"));
	doc->set_comment(   0,   0, REHex::Document::Comment("robin"));
	doc->set_comment(   0,  64, REHex::Document::Comment("release"));
	doc->set_comment(  64,  64, REHex::Document::Comment("uncle"));
	doc->set_comment( 128,  64, REHex::Document::Comment("scarecrow"));
	doc->set_comment(2048,  64, REHex::Document::Comment("crowded"));
	
	std::vector<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, 0, 0, doc->buffer_length(), ICM_SHORT);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"CommentRegion(c_offset = 0.0, c_length = 128.0, indent_offset = 0+0b, indent_length = 0+0b, c_text = 'unite', truncate = 1)",
		"CommentRegion(c_offset = 0.0, c_length = 64.0, indent_offset = 0+0b, indent_length = 0+0b, c_text = 'release', truncate = 1)",
		"CommentRegion(c_offset = 0.0, c_length = 0.0, indent_offset = 0+0b, indent_length = 0+0b, c_text = 'robin', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 0+0b, d_length = 64+0b, indent_offset = 0+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 64.0, c_length = 64.0, indent_offset = 64+0b, indent_length = 0+0b, c_text = 'uncle', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 64+0b, d_length = 64+0b, indent_offset = 64+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 128.0, c_length = 64.0, indent_offset = 128+0b, indent_length = 0+0b, c_text = 'scarecrow', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 128+0b, d_length = 1920+0b, indent_offset = 128+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 2048.0, c_length = 64.0, indent_offset = 2048+0b, indent_length = 0+0b, c_text = 'crowded', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 2048+0b, d_length = 2048+0b, indent_offset = 2048+0b, indent_length = 0+0b)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsHiddenComments)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_comment(1024, 128, REHex::Document::Comment("unite"));
	
	std::vector<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, 0, 0, doc->buffer_length(), ICM_HIDDEN);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0+0b, d_length = 4096+0b, indent_offset = 0+0b, indent_length = 0+0b)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsNestedComments)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_comment(1024,   128, REHex::Document::Comment("unite"));
	doc->set_comment(1024,     0, REHex::Document::Comment("robin"));
	doc->set_comment(1024,    64, REHex::Document::Comment("release"));
	doc->set_comment(1088,    64, REHex::Document::Comment("uncle"));
	doc->set_comment(1152,    64, REHex::Document::Comment("scarecrow"));
	doc->set_comment(2048,  2048, REHex::Document::Comment("crowded"));
	
	std::vector<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, 0, 0, doc->buffer_length(), ICM_FULL_INDENT);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0+0b, d_length = 1024+0b, indent_offset = 0+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 1024.0, c_length = 128.0, indent_offset = 1024+0b, indent_length = 128+0b, c_text = 'unite', truncate = 0)",
		"CommentRegion(c_offset = 1024.0, c_length = 64.0, indent_offset = 1024+0b, indent_length = 64+0b, c_text = 'release', truncate = 0)",
		"CommentRegion(c_offset = 1024.0, c_length = 0.0, indent_offset = 1024+0b, indent_length = 0+0b, c_text = 'robin', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1024+0b, d_length = 64+0b, indent_offset = 1024+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 1088.0, c_length = 64.0, indent_offset = 1088+0b, indent_length = 64+0b, c_text = 'uncle', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1088+0b, d_length = 64+0b, indent_offset = 1088+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 1152.0, c_length = 64.0, indent_offset = 1152+0b, indent_length = 64+0b, c_text = 'scarecrow', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1152+0b, d_length = 64+0b, indent_offset = 1152+0b, indent_length = 0+0b)",
		"DataRegionDocHighlight(d_offset = 1216+0b, d_length = 832+0b, indent_offset = 1216+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 2048.0, c_length = 2048.0, indent_offset = 2048+0b, indent_length = 2048+0b, c_text = 'crowded', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 2048+0b, d_length = 2048+0b, indent_offset = 2048+0b, indent_length = 0+0b)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsNestedShortComments)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_comment(1024, 128, REHex::Document::Comment("unite"));
	doc->set_comment(1024,   0, REHex::Document::Comment("robin"));
	doc->set_comment(1024,  64, REHex::Document::Comment("release"));
	doc->set_comment(1088,  64, REHex::Document::Comment("uncle"));
	doc->set_comment(1152,  64, REHex::Document::Comment("scarecrow"));
	doc->set_comment(2048,  64, REHex::Document::Comment("crowded"));
	
	std::vector<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, 0, 0, doc->buffer_length(), ICM_SHORT_INDENT);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0+0b, d_length = 1024+0b, indent_offset = 0+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 1024.0, c_length = 128.0, indent_offset = 1024+0b, indent_length = 128+0b, c_text = 'unite', truncate = 1)",
		"CommentRegion(c_offset = 1024.0, c_length = 64.0, indent_offset = 1024+0b, indent_length = 64+0b, c_text = 'release', truncate = 1)",
		"CommentRegion(c_offset = 1024.0, c_length = 0.0, indent_offset = 1024+0b, indent_length = 0+0b, c_text = 'robin', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 1024+0b, d_length = 64+0b, indent_offset = 1024+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 1088.0, c_length = 64.0, indent_offset = 1088+0b, indent_length = 64+0b, c_text = 'uncle', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 1088+0b, d_length = 64+0b, indent_offset = 1088+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 1152.0, c_length = 64.0, indent_offset = 1152+0b, indent_length = 64+0b, c_text = 'scarecrow', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 1152+0b, d_length = 64+0b, indent_offset = 1152+0b, indent_length = 0+0b)",
		"DataRegionDocHighlight(d_offset = 1216+0b, d_length = 832+0b, indent_offset = 1216+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 2048.0, c_length = 64.0, indent_offset = 2048+0b, indent_length = 64+0b, c_text = 'crowded', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 2048+0b, d_length = 64+0b, indent_offset = 2048+0b, indent_length = 0+0b)",
		"DataRegionDocHighlight(d_offset = 2112+0b, d_length = 1984+0b, indent_offset = 2112+0b, indent_length = 0+0b)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsClampStart)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_comment(1024,   128, REHex::Document::Comment("unite"));
	doc->set_comment(1024,     0, REHex::Document::Comment("robin"));
	doc->set_comment(1024,    64, REHex::Document::Comment("release"));
	doc->set_comment(1088,    64, REHex::Document::Comment("uncle"));
	doc->set_comment(1152,    64, REHex::Document::Comment("scarecrow"));
	doc->set_comment(2048,  2048, REHex::Document::Comment("crowded"));
	
	std::vector<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, 1050, 1050, (doc->buffer_length() - 1050), ICM_FULL_INDENT);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 1050+0b, d_length = 38+0b, indent_offset = 1050+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 1088.0, c_length = 64.0, indent_offset = 1088+0b, indent_length = 64+0b, c_text = 'uncle', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1088+0b, d_length = 64+0b, indent_offset = 1088+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 1152.0, c_length = 64.0, indent_offset = 1152+0b, indent_length = 64+0b, c_text = 'scarecrow', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1152+0b, d_length = 64+0b, indent_offset = 1152+0b, indent_length = 0+0b)",
		"DataRegionDocHighlight(d_offset = 1216+0b, d_length = 832+0b, indent_offset = 1216+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 2048.0, c_length = 2048.0, indent_offset = 2048+0b, indent_length = 2048+0b, c_text = 'crowded', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 2048+0b, d_length = 2048+0b, indent_offset = 2048+0b, indent_length = 0+0b)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsClampEnd)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_comment(1024,   128, REHex::Document::Comment("unite"));
	doc->set_comment(1024,     0, REHex::Document::Comment("robin"));
	doc->set_comment(1024,    64, REHex::Document::Comment("release"));
	doc->set_comment(1088,    64, REHex::Document::Comment("uncle"));
	doc->set_comment(1152,    64, REHex::Document::Comment("scarecrow"));
	doc->set_comment(2048,  2048, REHex::Document::Comment("crowded"));
	
	std::vector<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, 0, 0, 1200, ICM_FULL_INDENT);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0+0b, d_length = 1024+0b, indent_offset = 0+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 1024.0, c_length = 128.0, indent_offset = 1024+0b, indent_length = 128+0b, c_text = 'unite', truncate = 0)",
		"CommentRegion(c_offset = 1024.0, c_length = 64.0, indent_offset = 1024+0b, indent_length = 64+0b, c_text = 'release', truncate = 0)",
		"CommentRegion(c_offset = 1024.0, c_length = 0.0, indent_offset = 1024+0b, indent_length = 0+0b, c_text = 'robin', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1024+0b, d_length = 64+0b, indent_offset = 1024+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 1088.0, c_length = 64.0, indent_offset = 1088+0b, indent_length = 64+0b, c_text = 'uncle', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1088+0b, d_length = 64+0b, indent_offset = 1088+0b, indent_length = 0+0b)",
		"CommentRegion(c_offset = 1152.0, c_length = 64.0, indent_offset = 1152+0b, indent_length = 48+0b, c_text = 'scarecrow', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1152+0b, d_length = 48+0b, indent_offset = 1152+0b, indent_length = 0+0b)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsDataTypes)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_data_type(128, 2, "s16le");
	doc->set_data_type(132, 8, "s64le");
	
	std::vector<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, 0, 0, doc->buffer_length(), ICM_FULL_INDENT);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0+0b, d_length = 128+0b, indent_offset = 0+0b, indent_length = 0+0b)",
		"S16LEDataRegion(d_offset = 128+0b, d_length = 2+0b, indent_offset = 128+0b, indent_length = 0+0b)",
		"DataRegionDocHighlight(d_offset = 130+0b, d_length = 2+0b, indent_offset = 130+0b, indent_length = 0+0b)",
		"S64LEDataRegion(d_offset = 132+0b, d_length = 8+0b, indent_offset = 132+0b, indent_length = 0+0b)",
		"DataRegionDocHighlight(d_offset = 140+0b, d_length = 3956+0b, indent_offset = 140+0b, indent_length = 0+0b)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsDataTypesRepeated)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_data_type(128, 8, "s16le");
	
	std::vector<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, 0, 0, doc->buffer_length(), ICM_FULL_INDENT);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0+0b, d_length = 128+0b, indent_offset = 0+0b, indent_length = 0+0b)",
		"S16LEDataRegion(d_offset = 128+0b, d_length = 2+0b, indent_offset = 128+0b, indent_length = 0+0b)",
		"S16LEDataRegion(d_offset = 130+0b, d_length = 2+0b, indent_offset = 130+0b, indent_length = 0+0b)",
		"S16LEDataRegion(d_offset = 132+0b, d_length = 2+0b, indent_offset = 132+0b, indent_length = 0+0b)",
		"S16LEDataRegion(d_offset = 134+0b, d_length = 2+0b, indent_offset = 134+0b, indent_length = 0+0b)",
		"DataRegionDocHighlight(d_offset = 136+0b, d_length = 3960+0b, indent_offset = 136+0b, indent_length = 0+0b)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsDataTypesNestedInComment)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_comment(126, 8, REHex::Document::Comment("special"));
	doc->set_data_type(128, 2, "s16le");
	
	std::vector<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, 0, 0, doc->buffer_length(), ICM_FULL_INDENT);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0+0b, d_length = 126+0b, indent_offset = 0+0b, indent_length = 0+0b)",
		
		"CommentRegion(c_offset = 126.0, c_length = 8.0, indent_offset = 126+0b, indent_length = 8+0b, c_text = 'special', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 126+0b, d_length = 2+0b, indent_offset = 126+0b, indent_length = 0+0b)",
		"S16LEDataRegion(d_offset = 128+0b, d_length = 2+0b, indent_offset = 128+0b, indent_length = 0+0b)",
		"DataRegionDocHighlight(d_offset = 130+0b, d_length = 4+0b, indent_offset = 130+0b, indent_length = 0+0b)",
		
		"DataRegionDocHighlight(d_offset = 134+0b, d_length = 3962+0b, indent_offset = 134+0b, indent_length = 0+0b)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsDataTypesNestedAtStartOfComment)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_comment(140, 10, REHex::Document::Comment("gusty"));
	doc->set_data_type(140, 4, "s16le");
	
	std::vector<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, 0, 0, doc->buffer_length(), ICM_FULL_INDENT);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0+0b, d_length = 140+0b, indent_offset = 0+0b, indent_length = 0+0b)",
		
		"CommentRegion(c_offset = 140.0, c_length = 10.0, indent_offset = 140+0b, indent_length = 10+0b, c_text = 'gusty', truncate = 0)",
		"S16LEDataRegion(d_offset = 140+0b, d_length = 2+0b, indent_offset = 140+0b, indent_length = 0+0b)",
		"S16LEDataRegion(d_offset = 142+0b, d_length = 2+0b, indent_offset = 142+0b, indent_length = 0+0b)",
		"DataRegionDocHighlight(d_offset = 144+0b, d_length = 6+0b, indent_offset = 144+0b, indent_length = 0+0b)",
		
		"DataRegionDocHighlight(d_offset = 150+0b, d_length = 3946+0b, indent_offset = 150+0b, indent_length = 0+0b)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsDataTypesNestedAtEndOfComment)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_comment(160, 10, REHex::Document::Comment("call"));
	doc->set_data_type(168, 2, "s16le");
	
	std::vector<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, 0, 0, doc->buffer_length(), ICM_FULL_INDENT);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0+0b, d_length = 160+0b, indent_offset = 0+0b, indent_length = 0+0b)",
		
		"CommentRegion(c_offset = 160.0, c_length = 10.0, indent_offset = 160+0b, indent_length = 10+0b, c_text = 'call', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 160+0b, d_length = 8+0b, indent_offset = 160+0b, indent_length = 0+0b)",
		"S16LEDataRegion(d_offset = 168+0b, d_length = 2+0b, indent_offset = 168+0b, indent_length = 0+0b)",
		
		"DataRegionDocHighlight(d_offset = 170+0b, d_length = 3926+0b, indent_offset = 170+0b, indent_length = 0+0b)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsDataTypesNestedOccupyingWholeComment)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_comment(180, 2, REHex::Document::Comment("wind"));
	doc->set_data_type(180, 2, "s16le");
	
	std::vector<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, 0, 0, doc->buffer_length(), ICM_FULL_INDENT);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0+0b, d_length = 180+0b, indent_offset = 0+0b, indent_length = 0+0b)",
		
		"CommentRegion(c_offset = 180.0, c_length = 2.0, indent_offset = 180+0b, indent_length = 2+0b, c_text = 'wind', truncate = 0)",
		"S16LEDataRegion(d_offset = 180+0b, d_length = 2+0b, indent_offset = 180+0b, indent_length = 0+0b)",
		
		"DataRegionDocHighlight(d_offset = 182+0b, d_length = 3914+0b, indent_offset = 182+0b, indent_length = 0+0b)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsDataTypesNestedMultipleInComment)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_comment(256, 64, REHex::Document::Comment("sister"));
	doc->set_data_type(260, 2, "s16le");
	doc->set_data_type(270, 8, "s16le");
	
	std::vector<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, 0, 0, doc->buffer_length(), ICM_FULL_INDENT);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0+0b, d_length = 256+0b, indent_offset = 0+0b, indent_length = 0+0b)",
		
		"CommentRegion(c_offset = 256.0, c_length = 64.0, indent_offset = 256+0b, indent_length = 64+0b, c_text = 'sister', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 256+0b, d_length = 4+0b, indent_offset = 256+0b, indent_length = 0+0b)",
		"S16LEDataRegion(d_offset = 260+0b, d_length = 2+0b, indent_offset = 260+0b, indent_length = 0+0b)",
		"DataRegionDocHighlight(d_offset = 262+0b, d_length = 8+0b, indent_offset = 262+0b, indent_length = 0+0b)",
		"S16LEDataRegion(d_offset = 270+0b, d_length = 2+0b, indent_offset = 270+0b, indent_length = 0+0b)",
		"S16LEDataRegion(d_offset = 272+0b, d_length = 2+0b, indent_offset = 272+0b, indent_length = 0+0b)",
		"S16LEDataRegion(d_offset = 274+0b, d_length = 2+0b, indent_offset = 274+0b, indent_length = 0+0b)",
		"S16LEDataRegion(d_offset = 276+0b, d_length = 2+0b, indent_offset = 276+0b, indent_length = 0+0b)",
		"DataRegionDocHighlight(d_offset = 278+0b, d_length = 42+0b, indent_offset = 278+0b, indent_length = 0+0b)",
		
		"DataRegionDocHighlight(d_offset = 320+0b, d_length = 3776+0b, indent_offset = 320+0b, indent_length = 0+0b)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsDataTypesNotFixedSizeMultiple)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_data_type(128,  1, "s16le");
	doc->set_data_type(132,  3, "s16le");
	doc->set_data_type(140, 23, "s64le");
	
	std::vector<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, 0, 0, doc->buffer_length(), ICM_FULL_INDENT);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		/* Having all these fragmented data regions isn't ideal, but probably not worth the
		 * extra complexity of merging them to handle what should only ever happen if the
		 * metadata has been corrupted anyway.
		*/
		
		"DataRegionDocHighlight(d_offset = 0+0b, d_length = 128+0b, indent_offset = 0+0b, indent_length = 0+0b)",
		"DataRegionDocHighlight(d_offset = 128+0b, d_length = 1+0b, indent_offset = 128+0b, indent_length = 0+0b)",
		"DataRegionDocHighlight(d_offset = 129+0b, d_length = 3+0b, indent_offset = 129+0b, indent_length = 0+0b)",
		"S16LEDataRegion(d_offset = 132+0b, d_length = 2+0b, indent_offset = 132+0b, indent_length = 0+0b)",
		"DataRegionDocHighlight(d_offset = 134+0b, d_length = 1+0b, indent_offset = 134+0b, indent_length = 0+0b)",
		"DataRegionDocHighlight(d_offset = 135+0b, d_length = 5+0b, indent_offset = 135+0b, indent_length = 0+0b)",
		"S64LEDataRegion(d_offset = 140+0b, d_length = 8+0b, indent_offset = 140+0b, indent_length = 0+0b)",
		"S64LEDataRegion(d_offset = 148+0b, d_length = 8+0b, indent_offset = 148+0b, indent_length = 0+0b)",
		"DataRegionDocHighlight(d_offset = 156+0b, d_length = 7+0b, indent_offset = 156+0b, indent_length = 0+0b)",
		"DataRegionDocHighlight(d_offset = 163+0b, d_length = 3933+0b, indent_offset = 163+0b, indent_length = 0+0b)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

#if 0
static void run_wx(int run_for_ms)
{
	wxFrame frame(NULL, wxID_ANY, "Unit tests");
	
	wxTimer *timer = new wxTimer(&frame, wxID_ANY);
	
	frame.Bind(wxEVT_TIMER, [](wxTimerEvent &event)
	{
		wxTheApp->ExitMainLoop();
	}, timer->GetId(), timer->GetId());
	
	timer->Start(run_for_ms, wxTIMER_ONE_SHOT);
	
	wxTheApp->OnRun();
	
	timer->Stop();
}

TEST(Tab, CreateVerticalToolPanel)
{
	wxFrame frame(NULL, wxID_ANY, "Unit tests", wxDefaultPosition, wxSize(FRAME_WIDTH, FRAME_HEIGHT));
	
	Tab *tab = new Tab(&frame);
	
	frame.PostSizeEvent();
	frame.Show();
	
	run_wx(100);
	
	tab->tool_create("wide_tp", false);
	ToolPanel *tp = tab->tool_get("wide_tp");
	
	run_wx(100);
	
	ASSERT_NE(tp, (ToolPanel*)(NULL)) << "ToolPanel was created";
	
	EXPECT_EQ(tp->GetSize().GetWidth(), tp->GetBestSize().GetWidth()) << "Sizer position set for ToolPanel's best size";
}
#endif
