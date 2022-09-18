/////////////////////////////////////////////////////////////////////////////
// Name:    title.cpp
// Purpose: title implementation
// Author:    Andreas Kuechler
// Created:    2010/03/23
// Copyright:    (c) 2010 Andreas Kuechler
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include <wx/title.h>
#include <wx/drawutils.h>
#include <wx/tokenzr.h>
#include <iostream>
#include <wx/arrimpl.cpp>


WX_DEFINE_EXPORTED_OBJARRAY(Elements)

TextElement::TextElement(const wxString& text, int hAlign, wxFont font)
    : m_text(text)
    , m_hAlign(hAlign)
    , m_font(font)
    , m_textColour(DEFAULT_TITLE_COLOUR)
{
}

TextElement::TextElement(const TextElement& orig)
    : m_text(orig.m_text)
    , m_hAlign(orig.m_hAlign)
    , m_font(orig.m_font)
    , m_textColour(orig.m_textColour)
{
}

TextElement& TextElement::operator=(const TextElement& orig)
{
    if (this == &orig)
        return *this;

    m_text = orig.m_text;
    m_font = orig.m_font;
    m_hAlign = orig.m_hAlign;
    m_textColour = orig.m_textColour;

    return *this;
}

TextElement::~TextElement()
{
}

void TextElement::Draw(wxDC& dc, wxRect rc)
{
    wxColour fgColour = dc.GetTextForeground();
    dc.SetFont(m_font);
    dc.SetBrush(*wxTRANSPARENT_BRUSH);
    dc.SetTextForeground(m_textColour);
    dc.DrawLabel(m_text, rc, m_hAlign);
    dc.SetTextForeground(fgColour);
}

wxSize TextElement::CalculateExtent(wxDC& dc)
{
    dc.SetFont(m_font);
    return dc.GetMultiLineTextExtent(m_text);
}




TextElementContainer::TextElementContainer()
: m_extent()
, m_margin(40)
{
}

TextElementContainer::TextElementContainer(const TextElement& element)
: m_extent()
, m_margin(40)
{
    m_elements.push_back(element);
}

TextElementContainer::TextElementContainer(const wxString& contents)
: m_extent()
, m_margin(40)
{
    m_elements.push_back(TextElement(contents, wxALIGN_CENTER_HORIZONTAL));
}

TextElementContainer::~TextElementContainer()
{
}

void TextElementContainer::AddElement(TextElement element)
{
    m_elements.push_back(element);
}

bool TextElementContainer::IsEmpty() const
{
    return m_elements.empty();
}


void TextElementContainer::Draw(wxDC& dc, wxRect rc)
{
    for(size_t i = 0; i < m_elements.size(); ++i) {
        TextElement& element = m_elements[i];
        element.Draw(dc, rc);
    }
}

wxSize TextElementContainer::CalculateExtent(wxDC& dc)
{
    wxSize extent(0, 0);
    for(size_t i = 0; i < m_elements.size(); ++i) {
        TextElement& element = m_elements[i];
        wxSize boxSize = element.CalculateExtent(dc);
        extent.y = wxMax(extent.y, boxSize.y);
    }

    return extent;
}

