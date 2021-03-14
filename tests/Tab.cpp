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
		char buf[128];
		
		DocumentCtrl::CommentRegion          *cr   = dynamic_cast<DocumentCtrl::CommentRegion*>(*r);
		DocumentCtrl::DataRegionDocHighlight *drdh = dynamic_cast<DocumentCtrl::DataRegionDocHighlight*>(*r);
		
		S16LEDataRegion *s16le = dynamic_cast<S16LEDataRegion*>(*r);
		S64LEDataRegion *s64le = dynamic_cast<S64LEDataRegion*>(*r);
		
		if(cr != NULL)
		{
			snprintf(buf, sizeof(buf),
				"CommentRegion(c_offset = %ld, c_length = %ld, indent_offset = %ld, indent_length = %ld, c_text = '%s', truncate = %d)",
				(long)(cr->c_offset), (long)(cr->c_length), (long)(cr->indent_offset), (long)(cr->indent_length), cr->c_text.ToStdString().c_str(), (int)(cr->truncate));
		}
		else if(drdh != NULL)
		{
			snprintf(buf, sizeof(buf),
				"DataRegionDocHighlight(d_offset = %ld, d_length = %ld, indent_offset = %ld, indent_length = %ld)",
				(long)(drdh->d_offset), (long)(drdh->d_length), (long)(drdh->indent_offset), (long)(drdh->indent_length));
		}
		else if(s16le != NULL)
		{
			snprintf(buf, sizeof(buf),
				"S16LEDataRegion(d_offset = %ld, d_length = %ld, indent_offset = %ld, indent_length = %ld)",
				(long)(s16le->d_offset), (long)(s16le->d_length), (long)(s16le->indent_offset), (long)(s16le->indent_length));
		}
		else if(s64le != NULL)
		{
			snprintf(buf, sizeof(buf),
				"S64LEDataRegion(d_offset = %ld, d_length = %ld, indent_offset = %ld, indent_length = %ld)",
				(long)(s64le->d_offset), (long)(s64le->d_length), (long)(s64le->indent_offset), (long)(s64le->indent_length));
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
		"DataRegionDocHighlight(d_offset = 0, d_length = 0, indent_offset = 0, indent_length = 0)",
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
		"DataRegionDocHighlight(d_offset = 0, d_length = 4096, indent_offset = 0, indent_length = 0)",
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
		"DataRegionDocHighlight(d_offset = 0, d_length = 1024, indent_offset = 0, indent_length = 0)",
		"CommentRegion(c_offset = 1024, c_length = 128, indent_offset = 1024, indent_length = 0, c_text = 'unite', truncate = 0)",
		"CommentRegion(c_offset = 1024, c_length = 64, indent_offset = 1024, indent_length = 0, c_text = 'release', truncate = 0)",
		"CommentRegion(c_offset = 1024, c_length = 0, indent_offset = 1024, indent_length = 0, c_text = 'robin', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1024, d_length = 64, indent_offset = 1024, indent_length = 0)",
		"CommentRegion(c_offset = 1088, c_length = 64, indent_offset = 1088, indent_length = 0, c_text = 'uncle', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1088, d_length = 64, indent_offset = 1088, indent_length = 0)",
		"CommentRegion(c_offset = 1152, c_length = 64, indent_offset = 1152, indent_length = 0, c_text = 'scarecrow', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1152, d_length = 896, indent_offset = 1152, indent_length = 0)",
		"CommentRegion(c_offset = 2048, c_length = 64, indent_offset = 2048, indent_length = 0, c_text = 'crowded', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 2048, d_length = 2048, indent_offset = 2048, indent_length = 0)",
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
		"CommentRegion(c_offset = 0, c_length = 128, indent_offset = 0, indent_length = 0, c_text = 'unite', truncate = 1)",
		"CommentRegion(c_offset = 0, c_length = 64, indent_offset = 0, indent_length = 0, c_text = 'release', truncate = 1)",
		"CommentRegion(c_offset = 0, c_length = 0, indent_offset = 0, indent_length = 0, c_text = 'robin', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 0, d_length = 64, indent_offset = 0, indent_length = 0)",
		"CommentRegion(c_offset = 64, c_length = 64, indent_offset = 64, indent_length = 0, c_text = 'uncle', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 64, d_length = 64, indent_offset = 64, indent_length = 0)",
		"CommentRegion(c_offset = 128, c_length = 64, indent_offset = 128, indent_length = 0, c_text = 'scarecrow', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 128, d_length = 1920, indent_offset = 128, indent_length = 0)",
		"CommentRegion(c_offset = 2048, c_length = 64, indent_offset = 2048, indent_length = 0, c_text = 'crowded', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 2048, d_length = 2048, indent_offset = 2048, indent_length = 0)",
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
		"DataRegionDocHighlight(d_offset = 0, d_length = 4096, indent_offset = 0, indent_length = 0)",
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
		"DataRegionDocHighlight(d_offset = 0, d_length = 1024, indent_offset = 0, indent_length = 0)",
		"CommentRegion(c_offset = 1024, c_length = 128, indent_offset = 1024, indent_length = 128, c_text = 'unite', truncate = 0)",
		"CommentRegion(c_offset = 1024, c_length = 64, indent_offset = 1024, indent_length = 64, c_text = 'release', truncate = 0)",
		"CommentRegion(c_offset = 1024, c_length = 0, indent_offset = 1024, indent_length = 0, c_text = 'robin', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1024, d_length = 64, indent_offset = 1024, indent_length = 0)",
		"CommentRegion(c_offset = 1088, c_length = 64, indent_offset = 1088, indent_length = 64, c_text = 'uncle', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1088, d_length = 64, indent_offset = 1088, indent_length = 0)",
		"CommentRegion(c_offset = 1152, c_length = 64, indent_offset = 1152, indent_length = 64, c_text = 'scarecrow', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1152, d_length = 64, indent_offset = 1152, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 1216, d_length = 832, indent_offset = 1216, indent_length = 0)",
		"CommentRegion(c_offset = 2048, c_length = 2048, indent_offset = 2048, indent_length = 2048, c_text = 'crowded', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 2048, d_length = 2048, indent_offset = 2048, indent_length = 0)",
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
		"DataRegionDocHighlight(d_offset = 0, d_length = 1024, indent_offset = 0, indent_length = 0)",
		"CommentRegion(c_offset = 1024, c_length = 128, indent_offset = 1024, indent_length = 128, c_text = 'unite', truncate = 1)",
		"CommentRegion(c_offset = 1024, c_length = 64, indent_offset = 1024, indent_length = 64, c_text = 'release', truncate = 1)",
		"CommentRegion(c_offset = 1024, c_length = 0, indent_offset = 1024, indent_length = 0, c_text = 'robin', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 1024, d_length = 64, indent_offset = 1024, indent_length = 0)",
		"CommentRegion(c_offset = 1088, c_length = 64, indent_offset = 1088, indent_length = 64, c_text = 'uncle', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 1088, d_length = 64, indent_offset = 1088, indent_length = 0)",
		"CommentRegion(c_offset = 1152, c_length = 64, indent_offset = 1152, indent_length = 64, c_text = 'scarecrow', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 1152, d_length = 64, indent_offset = 1152, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 1216, d_length = 832, indent_offset = 1216, indent_length = 0)",
		"CommentRegion(c_offset = 2048, c_length = 64, indent_offset = 2048, indent_length = 64, c_text = 'crowded', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 2048, d_length = 64, indent_offset = 2048, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 2112, d_length = 1984, indent_offset = 2112, indent_length = 0)",
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
		"DataRegionDocHighlight(d_offset = 1050, d_length = 38, indent_offset = 1050, indent_length = 0)",
		"CommentRegion(c_offset = 1088, c_length = 64, indent_offset = 1088, indent_length = 64, c_text = 'uncle', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1088, d_length = 64, indent_offset = 1088, indent_length = 0)",
		"CommentRegion(c_offset = 1152, c_length = 64, indent_offset = 1152, indent_length = 64, c_text = 'scarecrow', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1152, d_length = 64, indent_offset = 1152, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 1216, d_length = 832, indent_offset = 1216, indent_length = 0)",
		"CommentRegion(c_offset = 2048, c_length = 2048, indent_offset = 2048, indent_length = 2048, c_text = 'crowded', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 2048, d_length = 2048, indent_offset = 2048, indent_length = 0)",
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
		"DataRegionDocHighlight(d_offset = 0, d_length = 1024, indent_offset = 0, indent_length = 0)",
		"CommentRegion(c_offset = 1024, c_length = 128, indent_offset = 1024, indent_length = 128, c_text = 'unite', truncate = 0)",
		"CommentRegion(c_offset = 1024, c_length = 64, indent_offset = 1024, indent_length = 64, c_text = 'release', truncate = 0)",
		"CommentRegion(c_offset = 1024, c_length = 0, indent_offset = 1024, indent_length = 0, c_text = 'robin', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1024, d_length = 64, indent_offset = 1024, indent_length = 0)",
		"CommentRegion(c_offset = 1088, c_length = 64, indent_offset = 1088, indent_length = 64, c_text = 'uncle', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1088, d_length = 64, indent_offset = 1088, indent_length = 0)",
		"CommentRegion(c_offset = 1152, c_length = 64, indent_offset = 1152, indent_length = 48, c_text = 'scarecrow', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1152, d_length = 48, indent_offset = 1152, indent_length = 0)",
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
		"DataRegionDocHighlight(d_offset = 0, d_length = 128, indent_offset = 0, indent_length = 0)",
		"S16LEDataRegion(d_offset = 128, d_length = 2, indent_offset = 128, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 130, d_length = 2, indent_offset = 130, indent_length = 0)",
		"S64LEDataRegion(d_offset = 132, d_length = 8, indent_offset = 132, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 140, d_length = 3956, indent_offset = 140, indent_length = 0)",
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
		"DataRegionDocHighlight(d_offset = 0, d_length = 128, indent_offset = 0, indent_length = 0)",
		"S16LEDataRegion(d_offset = 128, d_length = 2, indent_offset = 128, indent_length = 0)",
		"S16LEDataRegion(d_offset = 130, d_length = 2, indent_offset = 130, indent_length = 0)",
		"S16LEDataRegion(d_offset = 132, d_length = 2, indent_offset = 132, indent_length = 0)",
		"S16LEDataRegion(d_offset = 134, d_length = 2, indent_offset = 134, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 136, d_length = 3960, indent_offset = 136, indent_length = 0)",
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
		"DataRegionDocHighlight(d_offset = 0, d_length = 126, indent_offset = 0, indent_length = 0)",
		
		"CommentRegion(c_offset = 126, c_length = 8, indent_offset = 126, indent_length = 8, c_text = 'special', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 126, d_length = 2, indent_offset = 126, indent_length = 0)",
		"S16LEDataRegion(d_offset = 128, d_length = 2, indent_offset = 128, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 130, d_length = 4, indent_offset = 130, indent_length = 0)",
		
		"DataRegionDocHighlight(d_offset = 134, d_length = 3962, indent_offset = 134, indent_length = 0)",
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
		"DataRegionDocHighlight(d_offset = 0, d_length = 140, indent_offset = 0, indent_length = 0)",
		
		"CommentRegion(c_offset = 140, c_length = 10, indent_offset = 140, indent_length = 10, c_text = 'gusty', truncate = 0)",
		"S16LEDataRegion(d_offset = 140, d_length = 2, indent_offset = 140, indent_length = 0)",
		"S16LEDataRegion(d_offset = 142, d_length = 2, indent_offset = 142, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 144, d_length = 6, indent_offset = 144, indent_length = 0)",
		
		"DataRegionDocHighlight(d_offset = 150, d_length = 3946, indent_offset = 150, indent_length = 0)",
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
		"DataRegionDocHighlight(d_offset = 0, d_length = 160, indent_offset = 0, indent_length = 0)",
		
		"CommentRegion(c_offset = 160, c_length = 10, indent_offset = 160, indent_length = 10, c_text = 'call', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 160, d_length = 8, indent_offset = 160, indent_length = 0)",
		"S16LEDataRegion(d_offset = 168, d_length = 2, indent_offset = 168, indent_length = 0)",
		
		"DataRegionDocHighlight(d_offset = 170, d_length = 3926, indent_offset = 170, indent_length = 0)",
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
		"DataRegionDocHighlight(d_offset = 0, d_length = 180, indent_offset = 0, indent_length = 0)",
		
		"CommentRegion(c_offset = 180, c_length = 2, indent_offset = 180, indent_length = 2, c_text = 'wind', truncate = 0)",
		"S16LEDataRegion(d_offset = 180, d_length = 2, indent_offset = 180, indent_length = 0)",
		
		"DataRegionDocHighlight(d_offset = 182, d_length = 3914, indent_offset = 182, indent_length = 0)",
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
		"DataRegionDocHighlight(d_offset = 0, d_length = 256, indent_offset = 0, indent_length = 0)",
		
		"CommentRegion(c_offset = 256, c_length = 64, indent_offset = 256, indent_length = 64, c_text = 'sister', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 256, d_length = 4, indent_offset = 256, indent_length = 0)",
		"S16LEDataRegion(d_offset = 260, d_length = 2, indent_offset = 260, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 262, d_length = 8, indent_offset = 262, indent_length = 0)",
		"S16LEDataRegion(d_offset = 270, d_length = 2, indent_offset = 270, indent_length = 0)",
		"S16LEDataRegion(d_offset = 272, d_length = 2, indent_offset = 272, indent_length = 0)",
		"S16LEDataRegion(d_offset = 274, d_length = 2, indent_offset = 274, indent_length = 0)",
		"S16LEDataRegion(d_offset = 276, d_length = 2, indent_offset = 276, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 278, d_length = 42, indent_offset = 278, indent_length = 0)",
		
		"DataRegionDocHighlight(d_offset = 320, d_length = 3776, indent_offset = 320, indent_length = 0)",
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
		
		"DataRegionDocHighlight(d_offset = 0, d_length = 128, indent_offset = 0, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 128, d_length = 1, indent_offset = 128, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 129, d_length = 3, indent_offset = 129, indent_length = 0)",
		"S16LEDataRegion(d_offset = 132, d_length = 2, indent_offset = 132, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 134, d_length = 1, indent_offset = 134, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 135, d_length = 5, indent_offset = 135, indent_length = 0)",
		"S64LEDataRegion(d_offset = 140, d_length = 8, indent_offset = 140, indent_length = 0)",
		"S64LEDataRegion(d_offset = 148, d_length = 8, indent_offset = 148, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 156, d_length = 7, indent_offset = 156, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 163, d_length = 3933, indent_offset = 163, indent_length = 0)",
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
