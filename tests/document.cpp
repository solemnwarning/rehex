/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2018 Daniel Collins <solemnwarning@solemnwarning.net>
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

#undef NDEBUG
#include <assert.h>

#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wx/init.h>
#include <wx/wx.h>

#include "tests/tap/basic.h"

#define UNIT_TEST
#include "../src/app.hpp"
#include "../src/document.hpp"

bool REHex::App::OnInit()
{
	return true;
}

int REHex::App::OnExit()
{
	return 0;
}

REHex::App &wxGetApp()
{
	static REHex::App instance;
	return instance;
}

#define TEST_REGION_INT(region_i, type, field, expect) { \
	auto r = dynamic_cast<type*>(*(std::next(doc->regions.begin(), region_i))); \
	assert(r != NULL); \
	is_int(expect, r->field, "Document::regions[" #region_i "]." #field); \
}

#define TEST_REGION_STR(region_i, type, field, expect) { \
	auto r = dynamic_cast<type*>(*(std::next(doc->regions.begin(), region_i))); \
	assert(r != NULL); \
	is_string(expect, r->field.c_str(), "Document::regions[" #region_i "]." #field); \
}

static void insert_tests()
{
	{
		diag("Inserting into an empty file...");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char z4[] = {0x00,0x00,0x00,0x00};
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Data(0,0));
		doc->data_regions_count = 1;
		
		doc->insert_data(0, z4, 4);
		
		is_int(4, doc->buffer->length(), "Document::insert_data() expands Buffer")
			&& is_blob(z4, doc->buffer->read_data(0, 1024).data(), 4, "Document::insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 1);
		
		{
			auto dr = dynamic_cast<REHex::Document::Region::Data*>(*(doc->regions.begin()));
			assert(dr != NULL);
			
			is_int(0, dr->d_offset, "Document::regions[0].d_offset");
			is_int(4, dr->d_length, "Document::regions[0].d_length");
		}
	}
	
	{
		diag("Prepending to a file with a single data region");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char z4[]   = {0x00,0x00,0x00,0x00};
		unsigned char f2[]   = {0xFF,0xFF};
		unsigned char f2z4[] = {0xFF,0xFF,0x00,0x00,0x00,0x00};
		
		doc->buffer->insert_data(0, z4, 4);
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Data(0,4));
		doc->data_regions_count = 1;
		
		doc->insert_data(0, f2, 2);
		
		is_int(6, doc->buffer->length(), "Document::insert_data() expands Buffer")
			&& is_blob(f2z4, doc->buffer->read_data(0, 1024).data(), 6, "Document::insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 1);
		
		{
			auto dr = dynamic_cast<REHex::Document::Region::Data*>(*(doc->regions.begin()));
			assert(dr != NULL);
			
			is_int(0, dr->d_offset, "Document::regions[0].d_offset");
			is_int(6, dr->d_length, "Document::regions[0].d_length");
		}
	}
	
	{
		diag("Inserting into a file with a single data region");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char z4[]     = {0x00,0x00,0x00,0x00};
		unsigned char f2[]     = {0xFF,0xFF};
		unsigned char z2f2z2[] = {0x00,0x00,0xFF,0xFF,0x00,0x00};
		
		doc->buffer->insert_data(0, z4, 4);
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Data(0,4));
		doc->data_regions_count = 1;
		
		doc->insert_data(2, f2, 2);
		
		is_int(6, doc->buffer->length(), "Document::insert_data() expands Buffer")
			&& is_blob(z2f2z2, doc->buffer->read_data(0, 1024).data(), 6, "Document::insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 1);
		
		{
			auto dr = dynamic_cast<REHex::Document::Region::Data*>(*(doc->regions.begin()));
			assert(dr != NULL);
			
			is_int(0, dr->d_offset, "Document::regions[0].d_offset");
			is_int(6, dr->d_length, "Document::regions[0].d_length");
		}
	}
	
	{
		diag("Appending to a file with a single data region");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char z4[]   = {0x00,0x00,0x00,0x00};
		unsigned char f2[]   = {0xFF,0xFF};
		unsigned char z4f2[] = {0x00,0x00,0x00,0x00,0xFF,0xFF};
		
		doc->buffer->insert_data(0, z4, 4);
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Data(0,4));
		doc->data_regions_count = 1;
		
		doc->insert_data(4, f2, 2);
		
		is_int(6, doc->buffer->length(), "Document::insert_data() expands Buffer")
			&& is_blob(z4f2, doc->buffer->read_data(0, 1024).data(), 6, "Document::insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 1);
		
		{
			auto dr = dynamic_cast<REHex::Document::Region::Data*>(*(doc->regions.begin()));
			assert(dr != NULL);
			
			is_int(0, dr->d_offset, "Document::regions[0].d_offset");
			is_int(6, dr->d_length, "Document::regions[0].d_length");
		}
	}
	
	{
		diag("Prepending to data region 1/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0x02};
		unsigned char to_insert[]      = {0xFF,0xFF};
		unsigned char buffer_final[]   = {0xFF,0xFF,0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0x02};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,3));
		doc->regions.push_back(new REHex::Document::Region::Comment(3,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(3,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(7,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(7,2));
		doc->data_regions_count = 3;
		
		doc->insert_data(0, to_insert, sizeof(to_insert));
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::insert_data() expands Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 6);
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, c_offset, 9);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 9);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 2);
	}
	
	{
		diag("Inserting into data region 1/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0x02};
		unsigned char to_insert[]      = {0xFF,0xFF};
		unsigned char buffer_final[]   = {0x00,0x00,0xFF,0xFF,0x00,0x01,0x01,0x01,0x01,0x02,0x02};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,3));
		doc->regions.push_back(new REHex::Document::Region::Comment(3,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(3,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(7,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(7,2));
		doc->data_regions_count = 3;
		
		doc->insert_data(2, to_insert, sizeof(to_insert));
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::insert_data() expands Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 6);
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, c_offset, 9);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 9);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 2);
	}
	
	{
		diag("Prepending to data region 2/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0x02};
		unsigned char to_insert[]      = {0xFF,0xFF};
		unsigned char buffer_final[]   = {0x00,0x00,0x00,0xFF,0xFF,0x01,0x01,0x01,0x01,0x02,0x02};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,3));
		doc->regions.push_back(new REHex::Document::Region::Comment(3,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(3,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(7,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(7,2));
		doc->data_regions_count = 3;
		
		doc->insert_data(3, to_insert, sizeof(to_insert));
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::insert_data() expands Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 6);
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 3);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 3);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 6);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, c_offset, 9);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 9);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 2);
	}
	
	{
		diag("Inserting into data region 2/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0x02};
		unsigned char to_insert[]      = {0xFF,0xFF};
		unsigned char buffer_final[]   = {0x00,0x00,0x00,0x01,0x01,0x01,0xFF,0xFF,0x01,0x02,0x02};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,3));
		doc->regions.push_back(new REHex::Document::Region::Comment(3,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(3,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(7,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(7,2));
		doc->data_regions_count = 3;
		
		doc->insert_data(6, to_insert, sizeof(to_insert));
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::insert_data() expands Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 6);
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 3);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 3);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 6);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, c_offset, 9);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 9);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 2);
	}
	
	{
		diag("Prepending to data region 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0x02};
		unsigned char to_insert[]      = {0xFF,0xFF};
		unsigned char buffer_final[]   = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0xFF,0xFF,0x02,0x02};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,3));
		doc->regions.push_back(new REHex::Document::Region::Comment(3,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(3,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(7,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(7,2));
		doc->data_regions_count = 3;
		
		doc->insert_data(7, to_insert, sizeof(to_insert));
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::insert_data() expands Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 6);
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 3);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 3);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, c_offset, 7);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 7);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Inserting into data region 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0x02,0x02,0x02};
		unsigned char to_insert[]      = {0xFF,0xFF};
		unsigned char buffer_final[]   = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0xFF,0xFF,0x02,0x02,0x02};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,3));
		doc->regions.push_back(new REHex::Document::Region::Comment(3,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(3,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(7,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(7,4));
		doc->data_regions_count = 3;
		
		doc->insert_data(8, to_insert, sizeof(to_insert));
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::insert_data() expands Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 6);
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 3);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 3);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, c_offset, 7);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 7);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 6);
	}
	
	{
		diag("Appending to data region 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0x02};
		unsigned char to_insert[]      = {0xFF,0xFF};
		unsigned char buffer_final[]   = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0x02,0xFF,0xFF};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,3));
		doc->regions.push_back(new REHex::Document::Region::Comment(3,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(3,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(7,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(7,2));
		doc->data_regions_count = 3;
		
		doc->insert_data(9, to_insert, sizeof(to_insert));
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::insert_data() expands Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 6);
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 3);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 3);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, c_offset, 7);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 7);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 4);
	}
	
	/* TODO: Check y_* values */
}

static void erase_tests()
{
	{
		diag("Erasing the start of a Document with a single data region");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
		unsigned char buffer_final[]   = {0x03,0x04,0x05,0x06,0x07};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Data(0,8));
		doc->data_regions_count = 1;
		
		doc->erase_data(0, 3);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 1);
		is_int(1, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_offset, 0);
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_length, 5);
	}
	
	{
		diag("Erasing the middle of a Document with a single data region");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
		unsigned char buffer_final[]   = {0x00,0x01,0x03,0x04,0x05,0x06,0x07};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Data(0,8));
		doc->data_regions_count = 1;
		
		doc->erase_data(2, 1);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 1);
		is_int(1, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_offset, 0);
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_length, 7);
	}
	
	{
		diag("Erasing the end of a Document with a single data region");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x05};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Data(0,8));
		doc->data_regions_count = 1;
		
		doc->erase_data(6, 2);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 1);
		is_int(1, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_offset, 0);
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_length, 6);
	}
	
	{
		diag("Erasing all of a Document with a single data region");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
		unsigned char buffer_final[]   = {};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Data(0,8));
		doc->data_regions_count = 1;
		
		doc->erase_data(0, 8);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 1);
		is_int(1, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_offset, 0);
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_length, 0);
	}
	
	{
		diag("Erasing the start of data region 1/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(0, 2);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 3);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 3);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, c_offset, 7);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 7);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing the middle of data region 1/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(1, 3);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 2);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 2);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 2);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, c_offset, 6);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 6);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing the end of data region 1/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(1, 4);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 1);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 1);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 1);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, c_offset, 5);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing all of data region 1/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(0, 5);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 4);
		is_int(2, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 4);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 4);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing the start of data region 2/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(5, 1);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, c_offset, 8);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 8);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing the middle of data region 2/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(6, 1);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, c_offset, 8);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 8);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing the end of data region 2/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(8, 1);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, c_offset, 8);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 8);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing all of data region 2/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(5, 4);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 4);
		is_int(2, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing the start of data region 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(9, 3);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, c_offset, 9);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 9);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 1);
	}
	
	{
		diag("Erasing the middle of data region 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(11, 1);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, c_offset, 9);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 9);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 3);
	}
	
	{
		diag("Erasing the end of data region 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(10, 3);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, c_offset, 9);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 9);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 1);
	}
	
	{
		diag("Erasing all of data region 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(9, 4);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 4);
		is_int(2, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing some of data region 1/3 and 2/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(3, 4);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 3);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 3);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 2);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, c_offset, 5);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing some of data region 1/3 and all of 2/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(3, 6);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 4);
		is_int(2, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 3);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 3);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing all of data region 1/3 and some of 2/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(0, 6);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 4);
		is_int(2, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 3);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 3);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing some of data region 1/3, all of 2/3 and some of 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(4, 7);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 4);
		is_int(2, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 4);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 4);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 2);
	}
	
	{
		diag("Erasing some of data region 2/3, and some of 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(8, 2);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, c_offset, 8);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, c_text,   "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 8);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 3);
	}
	
	{
		diag("Erasing some of data region 2/3, and all of 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(8, 5);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 4);
		is_int(2, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, c_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, c_text,   "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, c_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, c_text,   "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 3);
	}
	
	{
		diag("Erasing all data from a Document with 3 data regions");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		doc->erase_data(0, 13);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 1);
		is_int(1, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_offset, 0);
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_length, 0);
	}
	
	/* TODO: Check y_* values */
}

static void paste_ovr_nosel_hex_tests()
{
	{
		const char *TEST = "Pasting a hex string at offset 0 in OVERWRITE mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98 97");
		
		const unsigned char MUNGED_DATA[] = { 0x99, 0x98, 0x97, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites existing data", TEST);
		
		is_int(3, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string which runs to EOF at offset 0 in OVERWRITE mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98 97 96 95 94 93 92");
		
		const unsigned char MUNGED_DATA[] = { 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites existing data", TEST);
		
		is_int(7, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string which runs past EOF at offset 0 in OVERWRITE mode and CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98 97 96 95 94 93 92 91 90");
		
		const unsigned char MUNGED_DATA[] = { 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites up to EOF", TEST);
		
		is_int(7, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string at offset 4 in OVERWRITE mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 4;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x99, 0x98, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites existing data", TEST);
		
		is_int(6, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string which runs to EOF at offset 4 in OVERWRITE mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 4;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98 97 96");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x99, 0x98, 0x97, 0x96 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites existing data", TEST);
		
		is_int(7, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string which runs past EOF at offset 4 in OVERWRITE mode and CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 4;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98 97 96 95 94 93 92 91 90");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x99, 0x98, 0x97, 0x96 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites up to EOF", TEST);
		
		is_int(7, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		/* Make sure strings which aren't valid hex strings are ignored. */
		const char *TEST = "Pasting an invalid hex string at offset 0 in OVERWRITE mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98!");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s doesn't change existing data", TEST);
		
		is_int(0, doc->cpos_off, "%s doesn't advance the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting an empty string at offset 0 in OVERWRITE mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s doesn't change existing data", TEST);
		
		is_int(0, doc->cpos_off, "%s doesn't advance the cursor", TEST);
	}
}

void paste_ovr_nosel_hex_mid_tests()
{
	{
		const char *TEST = "Pasting a hex string at offset 0 in OVERWRITE mode with CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		doc->handle_paste("99 98 97");
		
		const unsigned char MUNGED_DATA[] = { 0x99, 0x98, 0x97, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites existing data", TEST);
		
		is_int(3, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string which runs to EOF at offset 0 in OVERWRITE mode with CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		doc->handle_paste("99 98 97 96 95 94 93 92");
		
		const unsigned char MUNGED_DATA[] = { 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites existing data", TEST);
		
		is_int(7, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string which runs past EOF at offset 0 in OVERWRITE mode and CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		doc->handle_paste("99 98 97 96 95 94 93 92 91 90");
		
		const unsigned char MUNGED_DATA[] = { 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites up to EOF", TEST);
		
		is_int(7, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string at offset 4 in OVERWRITE mode with CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 4;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		doc->handle_paste("99 98");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x99, 0x98, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites existing data", TEST);
		
		is_int(6, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string which runs to EOF at offset 4 in OVERWRITE mode with CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 4;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		doc->handle_paste("99 98 97 96");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x99, 0x98, 0x97, 0x96 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites existing data", TEST);
		
		is_int(7, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string which runs past EOF at offset 4 in OVERWRITE mode and CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 4;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		doc->handle_paste("99 98 97 96 95 94 93 92 91 90");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x99, 0x98, 0x97, 0x96 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites up to EOF", TEST);
		
		is_int(7, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		/* Make sure strings which aren't valid hex strings are ignored. */
		const char *TEST = "Pasting an invalid hex string at offset 0 in OVERWRITE mode with CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		doc->handle_paste("99 98!");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s doesn't change existing data", TEST);
		
		is_int(0, doc->cpos_off, "%s doesn't advance the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting an empty string at offset 0 in OVERWRITE mode with CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		doc->handle_paste("");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s doesn't change existing data", TEST);
		
		is_int(0, doc->cpos_off, "%s doesn't advance the cursor", TEST);
	}
}

void paste_ovr_nosel_ascii_tests()
{
	{
		const char *TEST = "Pasting a text string at offset 0 in OVERWRITE mode with CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		doc->handle_paste("foo");
		
		const unsigned char MUNGED_DATA[] = { 'f', 'o', 'o', 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites existing text", TEST);
		
		is_int(3, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a text string which runs to EOF at offset 0 in OVERWRITE mode with CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		doc->handle_paste("foobarba");
		
		const unsigned char MUNGED_DATA[] = { 'f', 'o', 'o', 'b', 'a', 'r', 'b', 'a' };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites existing text", TEST);
		
		is_int(7, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a text string which runs past EOF at offset 0 in OVERWRITE mode and CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		doc->handle_paste("foobarbazquxquuxfoobarbazquxquux");
		
		const unsigned char MUNGED_DATA[] = { 'f', 'o', 'o', 'b', 'a', 'r', 'b', 'a' };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites up to EOF", TEST);
		
		is_int(7, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a text string at offset 4 in OVERWRITE mode with CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 4;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		doc->handle_paste("fo");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 'f', 'o', 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites existing text", TEST);
		
		is_int(6, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a text string which runs to EOF at offset 4 in OVERWRITE mode with CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 4;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		doc->handle_paste("foob");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 'f', 'o', 'o', 'b' };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites existing text", TEST);
		
		is_int(7, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a text string which runs past EOF at offset 4 in OVERWRITE mode and CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 4;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		doc->handle_paste("foobarbazquxquuxfoobarbazquxquux");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 'f', 'o', 'o', 'b' };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites up to EOF", TEST);
		
		is_int(7, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		/* Make sure strings which are valid hex get treated as text. */
		const char *TEST = "Pasting a hex string at offset 0 in OVERWRITE mode with CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		doc->handle_paste("999897");
		
		const unsigned char MUNGED_DATA[] = { '9', '9', '9', '8', '9', '7', 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites existing text", TEST);
		
		is_int(6, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting an empty string at offset 0 in OVERWRITE mode with CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = false;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		doc->handle_paste("");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s doesn't change existing data", TEST);
		
		is_int(0, doc->cpos_off, "%s doesn't advance the cursor", TEST);
	}
}

void paste_ins_nosel_hex_tests()
{
	{
		const char *TEST = "Pasting a hex string at offset 0 in INSERT mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98 97");
		
		const unsigned char MUNGED_DATA[] = { 0x99, 0x98, 0x97, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(11, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts data", TEST);
		
		is_int(3, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string which runs to EOF at offset 0 in INSERT mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98 97 96 95 94 93 92");
		
		const unsigned char MUNGED_DATA[] = { 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(16, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts data", TEST);
		
		is_int(8, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string which runs past EOF at offset 0 in INSERT mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98 97 96 95 94 93 92 91 90");
		
		const unsigned char MUNGED_DATA[] = { 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(18, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts data", TEST);
		
		is_int(10, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string at offset 4 in INSERT mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 4;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x99, 0x98, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(10, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts data", TEST);
		
		is_int(6, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string which runs to EOF at offset 4 in INSERT mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 4;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98 97 96");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x99, 0x98, 0x97, 0x96, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(12, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts data", TEST);
		
		is_int(8, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string which runs past EOF at offset 4 in INSERT mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 4;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98 97 96 95 94 93 92 91 90");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(18, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts data", TEST);
		
		is_int(14, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		/* Make sure strings which aren't valid hex strings are ignored. */
		const char *TEST = "Pasting an invalid hex string at offset 0 in INSERT mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98!");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s doesn't change existing data", TEST);
		
		is_int(0, doc->cpos_off, "%s doesn't advance the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting an empty string at offset 0 in INSERT mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s doesn't change existing data", TEST);
		
		is_int(0, doc->cpos_off, "%s doesn't advance the cursor", TEST);
	}
}

void paste_ins_nosel_hex_mid_tests()
{
	{
		const char *TEST = "Pasting a hex string at offset 0 in INSERT mode with CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		doc->handle_paste("99 98 97");
		
		const unsigned char MUNGED_DATA[] = { 0x99, 0x98, 0x97, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(11, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts data", TEST);
		
		is_int(3, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string which runs to EOF at offset 0 in INSERT mode with CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		doc->handle_paste("99 98 97 96 95 94 93 92");
		
		const unsigned char MUNGED_DATA[] = { 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(16, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts data", TEST);
		
		is_int(8, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string which runs past EOF at offset 0 in INSERT mode with CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		doc->handle_paste("99 98 97 96 95 94 93 92 91 90");
		
		const unsigned char MUNGED_DATA[] = { 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(18, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts data", TEST);
		
		is_int(10, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string at offset 4 in INSERT mode with CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 4;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		doc->handle_paste("99 98");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x99, 0x98, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(10, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts data", TEST);
		
		is_int(6, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string which runs to EOF at offset 4 in INSERT mode with CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 4;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		doc->handle_paste("99 98 97 96");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x99, 0x98, 0x97, 0x96, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(12, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts data", TEST);
		
		is_int(8, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string which runs past EOF at offset 4 in INSERT mode with CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 4;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		doc->handle_paste("99 98 97 96 95 94 93 92 91 90");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(18, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts data", TEST);
		
		is_int(14, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		/* Make sure strings which aren't valid hex strings are ignored. */
		const char *TEST = "Pasting an invalid hex string at offset 0 in INSERT mode with CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		doc->handle_paste("99 98!");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s doesn't change existing data", TEST);
		
		is_int(0, doc->cpos_off, "%s doesn't advance the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting an empty string at offset 0 in INSERT mode with CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		doc->handle_paste("");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s doesn't change existing data", TEST);
		
		is_int(0, doc->cpos_off, "%s doesn't advance the cursor", TEST);
	}
}

void paste_ins_nosel_ascii_tests()
{
	{
		const char *TEST = "Pasting a text string at offset 0 in INSERT mode with CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		doc->handle_paste("foo");
		
		const unsigned char MUNGED_DATA[] = { 'f', 'o', 'o', 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(11, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts text", TEST);
		
		is_int(3, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a text string which runs to EOF at offset 0 in INSERT mode with CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		doc->handle_paste("foobarba");
		
		const unsigned char MUNGED_DATA[] = { 'f', 'o', 'o', 'b', 'a', 'r', 'b', 'a', 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(16, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts text", TEST);
		
		is_int(8, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a text string which runs past EOF at offset 0 in INSERT mode and CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		doc->handle_paste("foobarbazqux");
		
		const unsigned char MUNGED_DATA[] = { 'f', 'o', 'o', 'b', 'a', 'r', 'b', 'a', 'z', 'q', 'u', 'x', 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(20, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts text", TEST);
		
		is_int(12, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a text string at offset 4 in INSERT mode with CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 4;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		doc->handle_paste("fo");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 'f', 'o', 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(10, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts text", TEST);
		
		is_int(6, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a text string which runs to EOF at offset 4 in INSERT mode with CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 4;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		doc->handle_paste("foob");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 'f', 'o', 'o', 'b', 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(12, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts text", TEST);
		
		is_int(8, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting a text string which runs past EOF at offset 4 in INSERT mode and CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 4;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		doc->handle_paste("foobar");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 'f', 'o', 'o', 'b', 'a', 'r', 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(14, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts text", TEST);
		
		is_int(10, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		/* Make sure strings which are valid hex get treated as text. */
		const char *TEST = "Pasting a hex string at offset 0 in INSERT mode with CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		doc->handle_paste("999897");
		
		const unsigned char MUNGED_DATA[] = { '9', '9', '9', '8', '9', '7', 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(14, doc->buffer->length(), "%s increases the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s inserts text", TEST);
		
		is_int(6, doc->cpos_off, "%s advances the cursor", TEST);
	}
	
	{
		const char *TEST = "Pasting an empty string at offset 0 in INSERT mode with CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = true;
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		doc->handle_paste("");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(8, doc->buffer->length(), "%s doesn't change the buffer size", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s doesn't change existing data", TEST);
		
		is_int(0, doc->cpos_off, "%s doesn't advance the cursor", TEST);
	}
}

static void paste_ovr_sel_hex_tests()
{
	{
		const char *TEST = "Pasting a hex string with the start of the document selected in OVERWRITE mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = false;
		doc->set_selection(0, 4);
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98 97");
		
		const unsigned char MUNGED_DATA[] = { 0x99, 0x98, 0x97, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(7, doc->buffer->length(), "%s resizes the buffer", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites the selected data", TEST);
		
		is_int(3, doc->cpos_off,         "%s moves the cursor", TEST);
		is_int(0, doc->selection_length, "%s clears the selection", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string with the middle of the document selected in OVERWRITE mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = false;
		doc->set_selection(3, 2);
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98 97 96");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x99, 0x98, 0x97, 0x96, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(10, doc->buffer->length(), "%s resizes the buffer", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites the selected data", TEST);
		
		is_int(7, doc->cpos_off,         "%s moves the cursor", TEST);
		is_int(0, doc->selection_length, "%s clears the selection", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string with the end of the document selected in OVERWRITE mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = false;
		doc->set_selection(5, 3);
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98 97 96 95 94 93 92");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(13, doc->buffer->length(), "%s resizes the buffer", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites the selected data", TEST);
		
		is_int(12, doc->cpos_off,         "%s moves the cursor", TEST);
		is_int(0,  doc->selection_length, "%s clears the selection", TEST);
	}
}

static void paste_ins_sel_hex_tests()
{
	{
		const char *TEST = "Pasting a hex string with the start of the document selected in INSERT mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = true;
		doc->set_selection(0, 4);
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98 97");
		
		const unsigned char MUNGED_DATA[] = { 0x99, 0x98, 0x97, 0x04, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(7, doc->buffer->length(), "%s resizes the buffer", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites the selected data", TEST);
		
		is_int(3, doc->cpos_off,         "%s moves the cursor", TEST);
		is_int(0, doc->selection_length, "%s clears the selection", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string with the middle of the document selected in INSERT mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = true;
		doc->set_selection(3, 2);
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98 97 96");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x99, 0x98, 0x97, 0x96, 0x05, 0x06, 0x07 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(10, doc->buffer->length(), "%s resizes the buffer", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites the selected data", TEST);
		
		is_int(7, doc->cpos_off,         "%s moves the cursor", TEST);
		is_int(0, doc->selection_length, "%s clears the selection", TEST);
	}
	
	{
		const char *TEST = "Pasting a hex string with the end of the document selected in INSERT mode with CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->cpos_off = 0;
		doc->insert_mode = true;
		doc->set_selection(5, 3);
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		doc->handle_paste("99 98 97 96 95 94 93 92");
		
		const unsigned char MUNGED_DATA[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92 };
		auto got_data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(13, doc->buffer->length(), "%s resizes the buffer", TEST)
			&& is_blob(MUNGED_DATA, got_data.data(), got_data.size(), "%s overwrites the selected data", TEST);
		
		is_int(13, doc->cpos_off,         "%s moves the cursor", TEST);
		is_int(0,  doc->selection_length, "%s clears the selection", TEST);
	}
}

static void copy_tests()
{
	{
		const char *TEST = "REHex::Document::handle_copy(false) when nothing is selected in CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 'a', 'B', 0x02, '\n', '\0', '3', '~', 0x03, 0x04 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		std::string copy_text = doc->handle_copy(false);
		
		auto data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(0, copy_text.length(), "%s returns empty string", TEST)
			&& is_string("", copy_text.c_str(), "%s returns empty string", TEST);
		
		is_int(11, data.size(), "%s doesn't modify buffer", TEST)
			&& is_blob(INITIAL_DATA, data.data(), data.size(), "%s doesn't modify buffer", TEST);
		
		is_int(0, doc->selection_length, "%s doesn't set selection", TEST);
	}
	
	{
		const char *TEST = "REHex::Document::handle_copy(false) when something is selected in CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 'a', 'B', 0x02, '\n', '\0', '3', '~', 0x03, 0x04 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->set_selection(1, 5);
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		std::string copy_text = doc->handle_copy(false);
		
		auto data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(10, copy_text.length(), "%s returns the data as a hex string", TEST)
			&& is_string("016142020A", copy_text.c_str(), "%s returns the data as a hex string", TEST);
		
		is_int(11, data.size(), "%s doesn't modify buffer", TEST)
			&& is_blob(INITIAL_DATA, data.data(), data.size(), "%s doesn't modify buffer", TEST);
		
		is_int(1, doc->selection_off,    "%s doesn't modify selection", TEST);
		is_int(5, doc->selection_length, "%s doesn't modify selection", TEST);
	}
	
	{
		const char *TEST = "REHex::Document::handle_copy(false) when nothing is selected in CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 'a', 'B', 0x02, '\n', '\0', '3', '~', 0x03, 0x04 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		std::string copy_text = doc->handle_copy(false);
		
		auto data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(0, copy_text.length(), "%s returns empty string", TEST)
			&& is_string("", copy_text.c_str(), "%s returns empty string", TEST);
		
		is_int(11, data.size(), "%s doesn't modify buffer", TEST)
			&& is_blob(INITIAL_DATA, data.data(), data.size(), "%s doesn't modify buffer", TEST);
		
		is_int(0, doc->selection_length, "%s doesn't set selection", TEST);
	}
	
	{
		const char *TEST = "REHex::Document::handle_copy(false) when something is selected in CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 'a', 'B', 0x02, '\n', '\0', '3', '~', 0x03, 0x04 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->set_selection(1, 5);
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		std::string copy_text = doc->handle_copy(false);
		
		auto data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(10, copy_text.length(), "%s returns the data as a hex string", TEST)
			&& is_string("016142020A", copy_text.c_str(), "%s returns the data as a hex string", TEST);
		
		is_int(11, data.size(), "%s doesn't modify buffer", TEST)
			&& is_blob(INITIAL_DATA, data.data(), data.size(), "%s doesn't modify buffer", TEST);
		
		is_int(1, doc->selection_off,    "%s doesn't modify selection", TEST);
		is_int(5, doc->selection_length, "%s doesn't modify selection", TEST);
	}
	
	{
		const char *TEST = "REHex::Document::handle_copy(false) when nothing is selected in CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 'a', 'B', 0x02, '\n', '\0', '3', '~', 0x03, 0x04 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		std::string copy_text = doc->handle_copy(false);
		
		auto data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(0, copy_text.length(), "%s returns empty string", TEST)
			&& is_string("", copy_text.c_str(), "%s returns empty string", TEST);
		
		is_int(11, data.size(), "%s doesn't modify buffer", TEST)
			&& is_blob(INITIAL_DATA, data.data(), data.size(), "%s doesn't modify buffer", TEST);
		
		is_int(0, doc->selection_length, "%s doesn't set selection", TEST);
	}
	
	{
		const char *TEST = "REHex::Document::handle_copy(false) when something is selected in CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 'a', 'B', 0x02, '\n', '\0', '3', '~', 0x03, 0x04 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->set_selection(1, 10);
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		std::string copy_text = doc->handle_copy(false);
		
		auto data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(5, copy_text.length(), "%s returns the safe characters as a string", TEST)
			&& is_string("aB\n3~", copy_text.c_str(), "%s returns the safe characters as a string", TEST);
		
		is_int(11, data.size(), "%s doesn't modify buffer", TEST)
			&& is_blob(INITIAL_DATA, data.data(), data.size(), "%s doesn't modify buffer", TEST);
		
		is_int(1,  doc->selection_off,    "%s doesn't modify selection", TEST);
		is_int(10, doc->selection_length, "%s doesn't modify selection", TEST);
	}
}

static void cut_tests()
{
	{
		const char *TEST = "REHex::Document::handle_copy(true) when nothing is selected in CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 'a', 'B', 0x02, '\n', '\0', '3', '~', 0x03, 0x04 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		std::string copy_text = doc->handle_copy(true);
		
		auto data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(0, copy_text.length(), "%s returns empty string", TEST)
			&& is_string("", copy_text.c_str(), "%s returns empty string", TEST);
		
		is_int(11, data.size(), "%s doesn't modify buffer", TEST)
			&& is_blob(INITIAL_DATA, data.data(), data.size(), "%s doesn't modify buffer", TEST);
		
		is_int(0, doc->selection_length, "%s doesn't set selection", TEST);
	}
	
	{
		const char *TEST = "REHex::Document::handle_copy(true) when something is selected in CSTATE_HEX";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 'a', 'B', 0x02, '\n', '\0', '3', '~', 0x03, 0x04 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->set_selection(1, 5);
		doc->cursor_state = REHex::Document::CSTATE_HEX;
		
		std::string copy_text = doc->handle_copy(true);
		
		auto data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(10, copy_text.length(), "%s returns the data as a hex string", TEST)
			&& is_string("016142020A", copy_text.c_str(), "%s returns the data as a hex string", TEST);
		
		const unsigned char MUNGED_DATA[] = { 0x00, '\0', '3', '~', 0x03, 0x04 };
		
		is_int(6, data.size(), "%s erases the selection", TEST)
			&& is_blob(MUNGED_DATA, data.data(), data.size(), "%s erases the selection", TEST);
		
		is_int(0, doc->selection_length, "%s clears the selection", TEST);
	}
	
	{
		const char *TEST = "REHex::Document::handle_copy(true) when nothing is selected in CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 'a', 'B', 0x02, '\n', '\0', '3', '~', 0x03, 0x04 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		std::string copy_text = doc->handle_copy(true);
		
		auto data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(0, copy_text.length(), "%s returns empty string", TEST)
			&& is_string("", copy_text.c_str(), "%s returns empty string", TEST);
		
		is_int(11, data.size(), "%s doesn't modify buffer", TEST)
			&& is_blob(INITIAL_DATA, data.data(), data.size(), "%s doesn't modify buffer", TEST);
		
		is_int(0, doc->selection_length, "%s doesn't set selection", TEST);
	}
	
	{
		const char *TEST = "REHex::Document::handle_copy(true) when something is selected in CSTATE_HEX_MID";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 'a', 'B', 0x02, '\n', '\0', '3', '~', 0x03, 0x04 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->set_selection(1, 5);
		doc->cursor_state = REHex::Document::CSTATE_HEX_MID;
		
		std::string copy_text = doc->handle_copy(true);
		
		auto data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(10, copy_text.length(), "%s returns the data as a hex string", TEST)
			&& is_string("016142020A", copy_text.c_str(), "%s returns the data as a hex string", TEST);
		
		const unsigned char MUNGED_DATA[] = { 0x00, '\0', '3', '~', 0x03, 0x04 };
		
		is_int(6, data.size(), "%s erases the selection", TEST)
			&& is_blob(MUNGED_DATA, data.data(), data.size(), "%s erases the selection", TEST);
		
		is_int(0, doc->selection_length, "%s clears the selection", TEST);
	}
	
	{
		const char *TEST = "REHex::Document::handle_copy(true) when nothing is selected in CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 'a', 'B', 0x02, '\n', '\0', '3', '~', 0x03, 0x04 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->clear_selection();
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		std::string copy_text = doc->handle_copy(true);
		
		auto data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(0, copy_text.length(), "%s returns empty string", TEST)
			&& is_string("", copy_text.c_str(), "%s returns empty string", TEST);
		
		is_int(11, data.size(), "%s doesn't modify buffer", TEST)
			&& is_blob(INITIAL_DATA, data.data(), data.size(), "%s doesn't modify buffer", TEST);
		
		is_int(0, doc->selection_length, "%s doesn't set selection", TEST);
	}
	
	{
		const char *TEST = "REHex::Document::handle_copy(true) when something is selected in CSTATE_ASCII";
		
		const unsigned char INITIAL_DATA[] = { 0x00, 0x01, 'a', 'B', 0x02, '\n', '\0', '3', '~', 0x03, 0x04 };
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame);
		doc->SetSize(0,0, 640,480);
		
		doc->insert_data(0, INITIAL_DATA, sizeof(INITIAL_DATA));
		
		doc->set_selection(1, 10);
		doc->cursor_state = REHex::Document::CSTATE_ASCII;
		
		std::string copy_text = doc->handle_copy(true);
		
		auto data = doc->buffer->read_data(0, 0xFFFF);
		
		is_int(5, copy_text.length(), "%s returns the safe characters as a string", TEST)
			&& is_string("aB\n3~", copy_text.c_str(), "%s returns the safe characters as a string", TEST);
		
		const unsigned char MUNGED_DATA[] = { 0x00 };
		
		is_int(1, data.size(), "%s erases the selection", TEST)
			&& is_blob(MUNGED_DATA, data.data(), data.size(), "%s erases the selection", TEST);
		
		is_int(0, doc->selection_length, "%s clears the selection", TEST);
	}
}

int main(int argc, char **argv)
{
	wxApp::SetInstance(new wxApp());
	wxEntryStart(argc, argv);
	wxTheApp->OnInit();
	
	plan_lazy();
	
	insert_tests();
	erase_tests();
	
	paste_ovr_nosel_hex_tests();
	paste_ovr_nosel_hex_mid_tests();
	paste_ovr_nosel_ascii_tests();
	paste_ins_nosel_hex_tests();
	paste_ins_nosel_hex_mid_tests();
	paste_ins_nosel_ascii_tests();
	paste_ovr_sel_hex_tests();
	paste_ins_sel_hex_tests();
	
	copy_tests();
	cut_tests();
	
	wxTheApp->OnExit();
	wxEntryCleanup();
	
	return 0;
}
