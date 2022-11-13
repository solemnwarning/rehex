/////////////////////////////////////////////////////////////////////////////
// Name:    chart.h
// Purpose: title text element declarations
// Author:    Andreas Kuechler
// Created:    2010/03/23
// Copyright:    (c) 2010 Andreas Kulcher
// Licence:    wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#ifndef TITLE_H_
#define TITLE_H_

#include <wx/wxfreechartdefs.h>
#include <wx/arrstr.h>
#include <wx/hashmap.h>
#include <wx/defs.h>

/**
 * Represents a TitleElement, ie a box containing text which is displayed in the title area.
 */
class WXDLLIMPEXP_FREECHART TextElement
{
public:
    // Constructors
    TextElement(const wxString& text, int hAlign = wxALIGN_CENTER_HORIZONTAL, wxFont font = *wxNORMAL_FONT);
    TextElement(const TextElement& orig);

    TextElement& operator = (const TextElement& orig);

    virtual ~TextElement();

    /**
     * Calculates the extent of the TextElement
     * @return The size of the TextElement
     */
    wxSize CalculateExtent(wxDC& dc);

    /**
     * Draws the TextElement with the given DC in a specified box.
     * @param dc    The device context to draw on.
     * @param rc    The rect into which the text will be drawn.
     */
    void Draw(wxDC& dc, wxRect rc);

    /**
     * Sets the horizontal alignment of the text inside its box.
     * @param hAlign  One of the horizontal alignment flags specified by wxWidgets.
     */
    void SetHorzAlign(int hAlign)
    {
        m_hAlign = hAlign;
    }

    /**
     * Sets the text colour.
     * @param colour The colour to set.
     */
    void SetColour(wxColour colour)
    {
        m_textColour = colour;
    }

private:
    wxString m_text;
    int m_hAlign;
    wxFont m_font;
    wxColour m_textColour;
};

WX_DECLARE_USER_EXPORTED_OBJARRAY(TextElement, Elements, WXDLLIMPEXP_FREECHART);

/**
 * Represents a chart title.
 * Divides the title line into three boxes which could be independently filled with content.
 * When drawing the title, the text in the boxes is wrapped at word boundary.
 */
class WXDLLIMPEXP_FREECHART TextElementContainer
{
public:
    TextElementContainer();
    wxDEPRECATED_MSG("Use TextElementContainer(const TextElement&) instead)")
    TextElementContainer(const wxString& title);
    TextElementContainer(const TextElement& element);
    TextElementContainer(const TextElementContainer& orig);
    TextElementContainer& operator=(const TextElementContainer& title);
    virtual ~TextElementContainer();

    /**
     * Adds a TextElement to the TextElementContainer.
     * Title takes ownership of the TextElement object.
     * @param element  A new TextElement object which is added to the list of elements.
     */
    void AddElement(TextElement element);

    /**
     * Checks whether the TextElementContainer is empty.
     * @returns true if the title is empty, false otherwise.
     */
    bool IsEmpty() const;

    /**
     * Draws the TextElementContainer.
     * @param dc  The wxDC drawing context used to draw the text.
     * @param rc  The rectangle of the drawing area.
     */
    void Draw(wxDC& dc, wxRect rc);

    /**
     * Calculates the extent of the TextElementContainer.
     * @param dc  A wxDC drawing context.
     * @param rc  The rectangle of the drawing area
     * @return The dimension of the TextElementContainer.
     */
    wxSize CalculateExtent(wxDC& dc);

private:
    Elements m_elements;
    wxSize m_extent;
    size_t m_margin;
};


typedef TextElementContainer Header;
typedef TextElementContainer Footer;

#endif // TITLE_H_
