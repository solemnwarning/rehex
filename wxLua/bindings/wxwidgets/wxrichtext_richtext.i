// ===========================================================================
// Purpose:     wxRichText library
// Author:      John Labenski
// Created:     07/03/2007
// Copyright:   (c) 2007 John Labenski. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

// NOTE: This file is mostly copied from wxWidget's include/richtext/*.h headers
// to make updating it easier.

#if wxLUA_USE_wxRichText && %wxchkver_3_0 && wxUSE_RICHTEXT

#include "wx/richtext/richtextbuffer.h"

#define wxRICHTEXT_USE_OWN_CARET // 1 (GTK, MAC) or 0 (others)

/**
    File types in wxRichText context.
 */
enum wxRichTextFileType
{
    wxRICHTEXT_TYPE_ANY = 0,
    wxRICHTEXT_TYPE_TEXT,
    wxRICHTEXT_TYPE_XML,
    wxRICHTEXT_TYPE_HTML,
    wxRICHTEXT_TYPE_RTF,
    wxRICHTEXT_TYPE_PDF
};

/*
 * Forward declarations
 */
/*
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextCtrl;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextObject;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextImage;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextPlainText;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextCacheObject;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextObjectList;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextLine;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextParagraph;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextFileHandler;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextDrawingHandler;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextField;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextFieldType;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextStyleSheet;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextListStyleDefinition;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextEvent;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextRenderer;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextBuffer;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextXMLHandler;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextParagraphLayoutBox;
class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextImageBlock;
class /*WXDLLIMPEXP_FWD_XML*/      wxXmlNode;
class /*WXDLLIMPEXP_FWD_BASE*/ wxDataInputStream;
class /*WXDLLIMPEXP_FWD_BASE*/ wxDataOutputStream;
*/
/**
    Flags determining the available space, passed to Layout.
 */

#define wxRICHTEXT_FIXED_WIDTH      0x01
#define wxRICHTEXT_FIXED_HEIGHT     0x02
#define wxRICHTEXT_VARIABLE_WIDTH   0x04
#define wxRICHTEXT_VARIABLE_HEIGHT  0x08

// Only lay out the part of the buffer that lies within
// the rect passed to Layout.
#define wxRICHTEXT_LAYOUT_SPECIFIED_RECT 0x10

/**
    Flags to pass to Draw
 */

// Ignore paragraph cache optimization, e.g. for printing purposes
// where one line may be drawn higher (on the next page) compared
// with the previous line
#define wxRICHTEXT_DRAW_IGNORE_CACHE    0x01
#define wxRICHTEXT_DRAW_SELECTED        0x02
#define wxRICHTEXT_DRAW_PRINT           0x04
#define wxRICHTEXT_DRAW_GUIDELINES      0x08

/**
    Flags returned from hit-testing, or passed to hit-test function.
 */
enum wxRichTextHitTestFlags
{
    // The point was not on this object
    wxRICHTEXT_HITTEST_NONE =    0x01,

    // The point was before the position returned from HitTest
    wxRICHTEXT_HITTEST_BEFORE =  0x02,

    // The point was after the position returned from HitTest
    wxRICHTEXT_HITTEST_AFTER =   0x04,

    // The point was on the position returned from HitTest
    wxRICHTEXT_HITTEST_ON =      0x08,

    // The point was on space outside content
    wxRICHTEXT_HITTEST_OUTSIDE = 0x10,

    // Only do hit-testing at the current level (don't traverse into top-level objects)
    wxRICHTEXT_HITTEST_NO_NESTED_OBJECTS = 0x20,

    // Ignore floating objects
    wxRICHTEXT_HITTEST_NO_FLOATING_OBJECTS = 0x40,

    // Don't recurse into objects marked as atomic
    wxRICHTEXT_HITTEST_HONOUR_ATOMIC = 0x80
};

/**
    Flags for GetRangeSize.
 */

#define wxRICHTEXT_FORMATTED        0x01
#define wxRICHTEXT_UNFORMATTED      0x02
#define wxRICHTEXT_CACHE_SIZE       0x04
#define wxRICHTEXT_HEIGHT_ONLY      0x08

/**
    Flags for SetStyle/SetListStyle.
 */

#define wxRICHTEXT_SETSTYLE_NONE            0x00

// Specifies that this operation should be undoable
#define wxRICHTEXT_SETSTYLE_WITH_UNDO       0x01

// Specifies that the style should not be applied if the
// combined style at this point is already the style in question.
#define wxRICHTEXT_SETSTYLE_OPTIMIZE        0x02

// Specifies that the style should only be applied to paragraphs,
// and not the content. This allows content styling to be
// preserved independently from that of e.g. a named paragraph style.
#define wxRICHTEXT_SETSTYLE_PARAGRAPHS_ONLY 0x04

// Specifies that the style should only be applied to characters,
// and not the paragraph. This allows content styling to be
// preserved independently from that of e.g. a named paragraph style.
#define wxRICHTEXT_SETSTYLE_CHARACTERS_ONLY 0x08

// For SetListStyle only: specifies starting from the given number, otherwise
// deduces number from existing attributes
#define wxRICHTEXT_SETSTYLE_RENUMBER        0x10

// For SetListStyle only: specifies the list level for all paragraphs, otherwise
// the current indentation will be used
#define wxRICHTEXT_SETSTYLE_SPECIFY_LEVEL   0x20

// Resets the existing style before applying the new style
#define wxRICHTEXT_SETSTYLE_RESET           0x40

// Removes the given style instead of applying it
#define wxRICHTEXT_SETSTYLE_REMOVE          0x80

/**
    Flags for SetProperties.
 */

#define wxRICHTEXT_SETPROPERTIES_NONE            0x00

// Specifies that this operation should be undoable
#define wxRICHTEXT_SETPROPERTIES_WITH_UNDO       0x01

// Specifies that the properties should only be applied to paragraphs,
// and not the content.
#define wxRICHTEXT_SETPROPERTIES_PARAGRAPHS_ONLY 0x02

// Specifies that the properties should only be applied to characters,
// and not the paragraph.
#define wxRICHTEXT_SETPROPERTIES_CHARACTERS_ONLY 0x04

// Resets the existing properties before applying the new properties.
#define wxRICHTEXT_SETPROPERTIES_RESET           0x08

// Removes the given properties instead of applying them.
#define wxRICHTEXT_SETPROPERTIES_REMOVE          0x10

/**
    Flags for object insertion.
 */

#define wxRICHTEXT_INSERT_NONE                              0x00
#define wxRICHTEXT_INSERT_WITH_PREVIOUS_PARAGRAPH_STYLE     0x01
#define wxRICHTEXT_INSERT_INTERACTIVE                       0x02

// A special flag telling the buffer to keep the first paragraph style
// as-is, when deleting a paragraph marker. In future we might pass a
// flag to InsertFragment and DeleteRange to indicate the appropriate mode.
#define wxTEXT_ATTR_KEEP_FIRST_PARA_STYLE   0x20000000

/**
    Default superscript/subscript font multiplication factor.
 */

#define wxSCRIPT_MUL_FACTOR             1.5

/**
    The type for wxTextAttrDimension flags.
 */
typedef unsigned short wxTextAttrDimensionFlags;


/**
    Miscellaneous text box flags
 */
enum wxTextBoxAttrFlags
{
    wxTEXT_BOX_ATTR_FLOAT                   = 0x00000001,
    wxTEXT_BOX_ATTR_CLEAR                   = 0x00000002,
    wxTEXT_BOX_ATTR_COLLAPSE_BORDERS        = 0x00000004,
    wxTEXT_BOX_ATTR_VERTICAL_ALIGNMENT      = 0x00000008,
    wxTEXT_BOX_ATTR_BOX_STYLE_NAME          = 0x00000010
};

/**
    Whether a value is present, used in dimension flags.
 */
enum wxTextAttrValueFlags
{
    wxTEXT_ATTR_VALUE_VALID               = 0x1000,
    wxTEXT_ATTR_VALUE_VALID_MASK          = 0x1000
};

/**
    Units, included in the dimension value.
 */
enum wxTextAttrUnits
{
    wxTEXT_ATTR_UNITS_TENTHS_MM             = 0x0001,
    wxTEXT_ATTR_UNITS_PIXELS                = 0x0002,
    wxTEXT_ATTR_UNITS_PERCENTAGE            = 0x0004,
    wxTEXT_ATTR_UNITS_POINTS                = 0x0008,
    wxTEXT_ATTR_UNITS_HUNDREDTHS_POINT      = 0x0100,

    wxTEXT_ATTR_UNITS_MASK                  = 0x010F
};

/**
    Position alternatives, included in the dimension flags.
 */
enum wxTextBoxAttrPosition
{
    wxTEXT_BOX_ATTR_POSITION_STATIC         = 0x0000, // Default is static, i.e. as per normal layout
    wxTEXT_BOX_ATTR_POSITION_RELATIVE       = 0x0010, // Relative to the relevant edge
    wxTEXT_BOX_ATTR_POSITION_ABSOLUTE       = 0x0020, // Relative to the parent
    wxTEXT_BOX_ATTR_POSITION_FIXED          = 0x0040, // Relative to the top-level window

    wxTEXT_BOX_ATTR_POSITION_MASK           = 0x00F0
};

/**
    @class wxTextAttrDimension

    A class representing a rich text dimension, including units and position.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextAttr, wxRichTextCtrl,  wxTextAttrDimensions
*/

class %delete wxTextAttrDimension
{
public:
    /**
        Default constructor.
    */
    wxTextAttrDimension();
    /**
        Constructor taking value and units flag.
    */
    wxTextAttrDimension(int value, wxTextAttrUnits units = wxTEXT_ATTR_UNITS_TENTHS_MM);

    /**
        Resets the dimension value and flags.
    */
    void Reset();

    /**
        Partial equality test. If @a weakTest is @true, attributes of this object do not
        have to be present if those attributes of @a dim are present. If @a weakTest is
        @false, the function will fail if an attribute is present in @a dim but not
        in this object.
    */
    bool EqPartial(const wxTextAttrDimension& dim, bool weakTest = true) const;

    /** Apply the dimension, but not those identical to @a compareWith if present.
    */
    bool Apply(const wxTextAttrDimension& dim, const wxTextAttrDimension* compareWith = NULL);

    /** Collects the attributes that are common to a range of content, building up a note of
        which attributes are absent in some objects and which clash in some objects.
    */
    void CollectCommonAttributes(const wxTextAttrDimension& attr, wxTextAttrDimension& clashingAttr, wxTextAttrDimension& absentAttr);

    /**
        Equality operator.
    */
    bool operator==(const wxTextAttrDimension& dim) const;

    /**
        Returns the integer value of the dimension.
    */
    int GetValue() const;

    /**
        Returns the floating-pointing value of the dimension in mm.

    */
    float GetValueMM() const;

    /**
        Sets the value of the dimension in mm.
    */
    void SetValueMM(float value);

    /**
        Sets the integer value of the dimension.
    */
    void SetValue(int value);

    /**
        Sets the integer value of the dimension, passing dimension flags.
    */
    void SetValue(int value, wxTextAttrDimensionFlags flags);

    /**
        Sets the integer value and units.
    */
    void SetValue(int value, wxTextAttrUnits units);

    /**
        Sets the dimension.
    */
    void SetValue(const wxTextAttrDimension& dim);

    /**
        Gets the units of the dimension.
    */
    wxTextAttrUnits GetUnits() const;

    /**
        Sets the units of the dimension.
    */
    void SetUnits(wxTextAttrUnits units);

    /**
        Gets the position flags.
    */
    wxTextBoxAttrPosition GetPosition() const;

    /**
        Sets the position flags.
    */
    void SetPosition(wxTextBoxAttrPosition pos);

    /**
        Returns @true if the dimension is valid.
    */
    bool IsValid() const;

    /**
        Sets the valid flag.
    */
    void SetValid(bool b);

    /**
        Gets the dimension flags.
    */
    wxTextAttrDimensionFlags GetFlags() const;

    /**
        Sets the dimension flags.
    */
    void SetFlags(wxTextAttrDimensionFlags flags);

    int                         m_value;
    wxTextAttrDimensionFlags    m_flags;
};

/**
    @class wxTextAttrDimensions
    A class for left, right, top and bottom dimensions.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextAttr, wxRichTextCtrl, wxTextAttrDimension
*/

class %delete wxTextAttrDimensions
{
public:
    /**
        Default constructor.
    */
    wxTextAttrDimensions();

    /**
        Resets the value and flags for all dimensions.
    */
    void Reset();

    /**
        Equality operator.
    */
    bool operator==(const wxTextAttrDimensions& dims) const;

    /**
        Partial equality test. If @a weakTest is @true, attributes of this object do not
        have to be present if those attributes of @a dim sare present. If @a weakTest is
        @false, the function will fail if an attribute is present in @a dims but not
        in this object.

    */
    bool EqPartial(const wxTextAttrDimensions& dims, bool weakTest = true) const;

    /**
        Apply to 'this', but not if the same as @a compareWith.

    */
    bool Apply(const wxTextAttrDimensions& dims, const wxTextAttrDimensions* compareWith = NULL);

    /**
        Collects the attributes that are common to a range of content, building up a note of
        which attributes are absent in some objects and which clash in some objects.

    */
    void CollectCommonAttributes(const wxTextAttrDimensions& attr, wxTextAttrDimensions& clashingAttr, wxTextAttrDimensions& absentAttr);

    /**
        Remove specified attributes from this object.
    */
    bool RemoveStyle(const wxTextAttrDimensions& attr);

    /**
        Gets the left dimension.
    */
    const wxTextAttrDimension& GetLeft() const;
    wxTextAttrDimension& GetLeft();

    /**
        Gets the right dimension.

    */
    const wxTextAttrDimension& GetRight() const;
    wxTextAttrDimension& GetRight();

    /**
        Gets the top dimension.

    */
    const wxTextAttrDimension& GetTop() const;
    wxTextAttrDimension& GetTop();

    /**
        Gets the bottom dimension.

    */
    const wxTextAttrDimension& GetBottom() const;
    wxTextAttrDimension& GetBottom();

    /**
        Are all dimensions valid?

    */
    bool IsValid() const;

    wxTextAttrDimension         m_left;
    wxTextAttrDimension         m_top;
    wxTextAttrDimension         m_right;
    wxTextAttrDimension         m_bottom;
};

/**
    @class wxTextAttrSize
    A class for representing width and height.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextAttr, wxRichTextCtrl, wxTextAttrDimension
*/

class %delete wxTextAttrSize
{
public:
    /**
        Default constructor.
    */
    wxTextAttrSize();

    /**
        Resets the width and height dimensions.
    */
    void Reset();

    /**
        Equality operator.
    */
    bool operator==(const wxTextAttrSize& size) const;

    /**
        Partial equality test. If @a weakTest is @true, attributes of this object do not
        have to be present if those attributes of @a size are present. If @a weakTest is
        @false, the function will fail if an attribute is present in @a size but not
        in this object.
    */
    bool EqPartial(const wxTextAttrSize& size, bool weakTest = true) const;

    /**
        Apply to this object, but not if the same as @a compareWith.
    */
    bool Apply(const wxTextAttrSize& dims, const wxTextAttrSize* compareWith = NULL);

    /**
        Collects the attributes that are common to a range of content, building up a note of
        which attributes are absent in some objects and which clash in some objects.
    */
    void CollectCommonAttributes(const wxTextAttrSize& attr, wxTextAttrSize& clashingAttr, wxTextAttrSize& absentAttr);

    /**
        Removes the specified attributes from this object.
    */
    bool RemoveStyle(const wxTextAttrSize& attr);

    /**
        Returns the width.
    */
    wxTextAttrDimension& GetWidth();
    const wxTextAttrDimension& GetWidth() const;

    /**
        Sets the width.
    */
    void SetWidth(int value, wxTextAttrDimensionFlags flags);

    /**
        Sets the width.
    */
    void SetWidth(int value, wxTextAttrUnits units);

    /**
        Sets the width.
    */
    void SetWidth(const wxTextAttrDimension& dim);

    /**
        Gets the height.
    */
    wxTextAttrDimension& GetHeight();
    const wxTextAttrDimension& GetHeight() const;

    /**
        Sets the height.
    */
    void SetHeight(int value, wxTextAttrDimensionFlags flags);

    /**
        Sets the height.
    */
    void SetHeight(int value, wxTextAttrUnits units);

    /**
        Sets the height.
    */
    void SetHeight(const wxTextAttrDimension& dim);

    /**
        Is the size valid?
    */
    bool IsValid() const;

    wxTextAttrDimension         m_width;
    wxTextAttrDimension         m_height;
};

/**
    @class wxTextAttrDimensionConverter
    A class to make it easier to convert dimensions.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextAttr, wxRichTextCtrl, wxTextAttrDimension
*/

class %delete wxTextAttrDimensionConverter
{
public:
    /**
        Constructor.
    */
    wxTextAttrDimensionConverter(wxDC& dc, double scale = 1.0, const wxSize& parentSize = wxDefaultSize);
    /**
        Constructor.
    */
    wxTextAttrDimensionConverter(int ppi, double scale = 1.0, const wxSize& parentSize = wxDefaultSize);

    /**
        Gets the pixel size for the given dimension.
    */
    int GetPixels(const wxTextAttrDimension& dim, int direction = wxHORIZONTAL) const;
    /**
        Gets the mm size for the given dimension.
    */
    int GetTenthsMM(const wxTextAttrDimension& dim) const;

    /**
        Converts tenths of a mm to pixels.
    */
    int ConvertTenthsMMToPixels(int units) const;
    /**
        Converts pixels to tenths of a mm.
    */
    int ConvertPixelsToTenthsMM(int pixels) const;

    /**
        Sets the scale factor.
    */
    void SetScale(double scale);
    /**
        Returns the scale factor.
    */
    double GetScale() const;

    /**
        Sets the ppi.
    */
    void SetPPI(int ppi);
    /**
        Returns the ppi.
    */
    int GetPPI() const;

    /**
        Sets the parent size.
    */
    void SetParentSize(const wxSize& parentSize);
    /**
        Returns the parent size.
    */
    const wxSize& GetParentSize() const;

    int     m_ppi;
    double  m_scale;
    wxSize  m_parentSize;
};

/**
    Border styles, used with wxTextAttrBorder.
 */
enum wxTextAttrBorderStyle
{
    wxTEXT_BOX_ATTR_BORDER_NONE             = 0,
    wxTEXT_BOX_ATTR_BORDER_SOLID            = 1,
    wxTEXT_BOX_ATTR_BORDER_DOTTED           = 2,
    wxTEXT_BOX_ATTR_BORDER_DASHED           = 3,
    wxTEXT_BOX_ATTR_BORDER_DOUBLE           = 4,
    wxTEXT_BOX_ATTR_BORDER_GROOVE           = 5,
    wxTEXT_BOX_ATTR_BORDER_RIDGE            = 6,
    wxTEXT_BOX_ATTR_BORDER_INSET            = 7,
    wxTEXT_BOX_ATTR_BORDER_OUTSET           = 8
};

/**
    Border style presence flags, used with wxTextAttrBorder.
 */
enum wxTextAttrBorderFlags
{
    wxTEXT_BOX_ATTR_BORDER_STYLE            = 0x0001,
    wxTEXT_BOX_ATTR_BORDER_COLOUR           = 0x0002
};

/**
    Border width symbols for qualitative widths, used with wxTextAttrBorder.
 */
enum wxTextAttrBorderWidth
{
    wxTEXT_BOX_ATTR_BORDER_THIN             = -1,
    wxTEXT_BOX_ATTR_BORDER_MEDIUM           = -2,
    wxTEXT_BOX_ATTR_BORDER_THICK            = -3
};

/**
    Float styles.
 */
enum wxTextBoxAttrFloatStyle
{
    wxTEXT_BOX_ATTR_FLOAT_NONE              = 0,
    wxTEXT_BOX_ATTR_FLOAT_LEFT              = 1,
    wxTEXT_BOX_ATTR_FLOAT_RIGHT             = 2
};

/**
    Clear styles.
 */
enum wxTextBoxAttrClearStyle
{
    wxTEXT_BOX_ATTR_CLEAR_NONE              = 0,
    wxTEXT_BOX_ATTR_CLEAR_LEFT              = 1,
    wxTEXT_BOX_ATTR_CLEAR_RIGHT             = 2,
    wxTEXT_BOX_ATTR_CLEAR_BOTH              = 3
};

/**
    Collapse mode styles. TODO: can they be switched on per side?
 */
enum wxTextBoxAttrCollapseMode
{
    wxTEXT_BOX_ATTR_COLLAPSE_NONE           = 0,
    wxTEXT_BOX_ATTR_COLLAPSE_FULL           = 1
};

/**
    Vertical alignment values.
 */
enum wxTextBoxAttrVerticalAlignment
{
    wxTEXT_BOX_ATTR_VERTICAL_ALIGNMENT_NONE =       0,
    wxTEXT_BOX_ATTR_VERTICAL_ALIGNMENT_TOP  =       1,
    wxTEXT_BOX_ATTR_VERTICAL_ALIGNMENT_CENTRE =     2,
    wxTEXT_BOX_ATTR_VERTICAL_ALIGNMENT_BOTTOM  =    3
};

/**
    @class wxTextAttrBorder
    A class representing a rich text object border.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextAttr, wxRichTextCtrl, wxRichTextAttrBorders
*/

class %delete wxTextAttrBorder
{
public:
    /**
        Default constructor.
    */
    wxTextAttrBorder();

    /**
        Equality operator.
    */
    bool operator==(const wxTextAttrBorder& border) const;

    /**
        Resets the border style, colour, width and flags.
    */
    void Reset();

    /**
        Partial equality test. If @a weakTest is @true, attributes of this object do not
        have to be present if those attributes of @a border are present. If @a weakTest is
        @false, the function will fail if an attribute is present in @a border but not
        in this object.
    */
    bool EqPartial(const wxTextAttrBorder& border, bool weakTest = true) const;

    /**
        Applies the border to this object, but not if the same as @a compareWith.

    */
    bool Apply(const wxTextAttrBorder& border, const wxTextAttrBorder* compareWith = NULL);

    /**
        Removes the specified attributes from this object.
    */
    bool RemoveStyle(const wxTextAttrBorder& attr);

    /**
        Collects the attributes that are common to a range of content, building up a note of
        which attributes are absent in some objects and which clash in some objects.
    */
    void CollectCommonAttributes(const wxTextAttrBorder& attr, wxTextAttrBorder& clashingAttr, wxTextAttrBorder& absentAttr);

    /**
        Sets the border style.
    */
    void SetStyle(int style);

    /**
        Gets the border style.

    */
    int GetStyle() const;

    /**
        Sets the border colour.
    */
    void SetColour(unsigned long colour);

    /**
        Sets the border colour.
    */
    void SetColour(const wxColour& colour);

    /**
        Gets the colour as a long.
    */
    unsigned long GetColourLong() const;

    /**
        Gets the colour.
    */
    wxColour GetColour() const;

    /**
        Gets the border width.
    */
    wxTextAttrDimension& GetWidth();
    const wxTextAttrDimension& GetWidth() const;

    /**
        Sets the border width.
    */
    void SetWidth(const wxTextAttrDimension& width);
    /**
        Sets the border width.
    */
    void SetWidth(int value, wxTextAttrUnits units = wxTEXT_ATTR_UNITS_TENTHS_MM);

    /**
        True if the border has a valid style.
    */
    bool HasStyle() const;

    /**
        True if the border has a valid colour.
    */
    bool HasColour() const;

    /**
        True if the border has a valid width.
    */
    bool HasWidth() const;

    /**
        True if the border is valid.
    */
    bool IsValid() const;

    /**
        Set the valid flag for this border.
    */
    void MakeValid();

    /**
        True if the border has no attributes set.
    */
    bool IsDefault() const;

    /**
        Returns the border flags.
    */
    int GetFlags() const;

    /**
        Sets the border flags.
    */
    void SetFlags(int flags);

    /**
        Adds a border flag.
    */
    void AddFlag(int flag);

    /**
        Removes a border flag.
    */
    void RemoveFlag(int flag);

    int                         m_borderStyle;
    unsigned long               m_borderColour;
    wxTextAttrDimension         m_borderWidth;
    int                         m_flags;
};

class %delete wxTextAttrBorders
{
public:
    /**
        Default constructor.
    */
    wxTextAttrBorders();

    /**
        Equality operator.
    */
    bool operator==(const wxTextAttrBorders& borders) const;

    /**
        Sets the style of all borders.
    */
    void SetStyle(int style);

    /**
        Sets colour of all borders.
    */
    void SetColour(unsigned long colour);

    /**
        Sets the colour for all borders.
    */
    void SetColour(const wxColour& colour);

    /**
        Sets the width of all borders.
    */
    void SetWidth(const wxTextAttrDimension& width);

    /**
        Sets the width of all borders.
    */
    void SetWidth(int value, wxTextAttrUnits units = wxTEXT_ATTR_UNITS_TENTHS_MM);
    /**
        Resets all borders.
    */
    void Reset();

    /**
        Partial equality test. If @a weakTest is @true, attributes of this object do not
        have to be present if those attributes of @a borders are present. If @a weakTest is
        @false, the function will fail if an attribute is present in @a borders but not
        in this object.
    */
    bool EqPartial(const wxTextAttrBorders& borders, bool weakTest = true) const;

    /**
        Applies border to this object, but not if the same as @a compareWith.
    */
    bool Apply(const wxTextAttrBorders& borders, const wxTextAttrBorders* compareWith = NULL);

    /**
        Removes the specified attributes from this object.
    */
    bool RemoveStyle(const wxTextAttrBorders& attr);

    /**
        Collects the attributes that are common to a range of content, building up a note of
        which attributes are absent in some objects and which clash in some objects.
    */
    void CollectCommonAttributes(const wxTextAttrBorders& attr, wxTextAttrBorders& clashingAttr, wxTextAttrBorders& absentAttr);

    /**
        Returns @true if at least one border is valid.
    */
    bool IsValid() const;

    /**
        Returns @true if no border attributes were set.
    */
    bool IsDefault() const;

    /**
        Returns the left border.
    */
    const wxTextAttrBorder& GetLeft() const;
    wxTextAttrBorder& GetLeft();

    /**
        Returns the right border.
    */
    const wxTextAttrBorder& GetRight() const;
    wxTextAttrBorder& GetRight();

    /**
        Returns the top border.
    */
    const wxTextAttrBorder& GetTop() const;
    wxTextAttrBorder& GetTop();

    /**
        Returns the bottom border.
    */
    const wxTextAttrBorder& GetBottom() const;
    wxTextAttrBorder& GetBottom();

    // wxTextAttrBorder m_left, m_right, m_top, m_bottom;

};

/**
    @class wxTextBoxAttr
    A class representing the box attributes of a rich text object.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextAttr, wxRichTextCtrl
*/

class %delete wxTextBoxAttr
{
public:
    /**
        Default constructor.
    */
    wxTextBoxAttr();

    /**
        Copy constructor.
    */
    wxTextBoxAttr(const wxTextBoxAttr& attr);

    /**
        Initialises this object.
    */
    void Init();

    /**
        Resets this object.
    */
    void Reset();

    // Copy. Unnecessary since we let it do a binary copy
    //void Copy(const wxTextBoxAttr& attr);

    // Assignment
    //void operator= (const wxTextBoxAttr& attr);

    /**
        Equality test.
    */
    bool operator== (const wxTextBoxAttr& attr) const;

    /**
        Partial equality test, ignoring unset attributes. If @a weakTest is @true, attributes of this object do not
        have to be present if those attributes of @a attr are present. If @a weakTest is
        @false, the function will fail if an attribute is present in @a attr but not
        in this object.

    */
    bool EqPartial(const wxTextBoxAttr& attr, bool weakTest = true) const;

    /**
        Merges the given attributes. If @a compareWith is non-NULL, then it will be used
        to mask out those attributes that are the same in style and @a compareWith, for
        situations where we don't want to explicitly set inherited attributes.
    */
    bool Apply(const wxTextBoxAttr& style, const wxTextBoxAttr* compareWith = NULL);

    /**
        Collects the attributes that are common to a range of content, building up a note of
        which attributes are absent in some objects and which clash in some objects.
    */
    void CollectCommonAttributes(const wxTextBoxAttr& attr, wxTextBoxAttr& clashingAttr, wxTextBoxAttr& absentAttr);

    /**
        Removes the specified attributes from this object.
    */
    bool RemoveStyle(const wxTextBoxAttr& attr);

    /**
        Sets the flags.
    */
    void SetFlags(int flags);

    /**
        Returns the flags.
    */
    int GetFlags() const;

    /**
        Is this flag present?
    */
    bool HasFlag(wxTextBoxAttrFlags flag) const;

    /**
        Removes this flag.
    */
    void RemoveFlag(wxTextBoxAttrFlags flag);

    /**
        Adds this flag.
    */
    void AddFlag(wxTextBoxAttrFlags flag);

    /**
        Returns @true if no attributes are set.
    */
    bool IsDefault() const;

    /**
        Returns the float mode.
    */
    wxTextBoxAttrFloatStyle GetFloatMode() const;

    /**
        Sets the float mode.
    */
    void SetFloatMode(wxTextBoxAttrFloatStyle mode);

    /**
        Returns @true if float mode is active.
    */
    bool HasFloatMode() const;

    /**
        Returns @true if this object is floating.
    */
    bool IsFloating() const;

    /**
        Returns the clear mode - whether to wrap text after object. Currently unimplemented.
    */
    wxTextBoxAttrClearStyle GetClearMode() const;

    /**
        Set the clear mode. Currently unimplemented.
    */
    void SetClearMode(wxTextBoxAttrClearStyle mode);

    /**
        Returns @true if we have a clear flag.
    */
    bool HasClearMode() const;

    /**
        Returns the collapse mode - whether to collapse borders.
    */
    wxTextBoxAttrCollapseMode GetCollapseBorders() const;

    /**
        Sets the collapse mode - whether to collapse borders.
    */
    void SetCollapseBorders(wxTextBoxAttrCollapseMode collapse);

    /**
        Returns @true if the collapse borders flag is present.
    */
    bool HasCollapseBorders() const;

    /**
        Returns the vertical alignment.
    */
    wxTextBoxAttrVerticalAlignment GetVerticalAlignment() const;

    /**
        Sets the vertical alignment.
    */
    void SetVerticalAlignment(wxTextBoxAttrVerticalAlignment verticalAlignment);

    /**
        Returns @true if a vertical alignment flag is present.
    */
    bool HasVerticalAlignment() const;
    
    /**
        Returns the margin values.
    */
    wxTextAttrDimensions& GetMargins();
    const wxTextAttrDimensions& GetMargins() const;

    /**
        Returns the left margin.
    */
    wxTextAttrDimension& GetLeftMargin();
    const wxTextAttrDimension& GetLeftMargin() const;

    /**
        Returns the right margin.
    */
    wxTextAttrDimension& GetRightMargin();
    const wxTextAttrDimension& GetRightMargin() const;

    /**
        Returns the top margin.
    */
    wxTextAttrDimension& GetTopMargin();
    const wxTextAttrDimension& GetTopMargin() const;

    /**
        Returns the bottom margin.
    */
    wxTextAttrDimension& GetBottomMargin();
    const wxTextAttrDimension& GetBottomMargin() const;

    /**
        Returns the position.
    */
    wxTextAttrDimensions& GetPosition();
    const wxTextAttrDimensions& GetPosition() const;

    /**
        Returns the left position.
    */
    wxTextAttrDimension& GetLeft();
    const wxTextAttrDimension& GetLeft() const;

    /**
        Returns the right position.
    */
    wxTextAttrDimension& GetRight();
    const wxTextAttrDimension& GetRight() const;

    /**
        Returns the top position.
    */
    wxTextAttrDimension& GetTop();
    const wxTextAttrDimension& GetTop() const;

    /**
        Returns the bottom position.
    */
    wxTextAttrDimension& GetBottom();
    const wxTextAttrDimension& GetBottom() const;

    /**
        Returns the padding values.
    */
    wxTextAttrDimensions& GetPadding();
    const wxTextAttrDimensions& GetPadding() const;

    /**
        Returns the left padding value.
    */
    wxTextAttrDimension& GetLeftPadding();
    const wxTextAttrDimension& GetLeftPadding() const;

    /**
        Returns the right padding value.
    */
    wxTextAttrDimension& GetRightPadding();
    const wxTextAttrDimension& GetRightPadding() const;

    /**
        Returns the top padding value.
    */
    wxTextAttrDimension& GetTopPadding();
    const wxTextAttrDimension& GetTopPadding() const;

    /**
        Returns the bottom padding value.
    */
    wxTextAttrDimension& GetBottomPadding();
    const wxTextAttrDimension& GetBottomPadding() const;

    /**
        Returns the borders.
    */
    wxTextAttrBorders& GetBorder();
    const wxTextAttrBorders& GetBorder() const;

    /**
        Returns the left border.
    */
    wxTextAttrBorder& GetLeftBorder();
    const wxTextAttrBorder& GetLeftBorder() const;

    /**
        Returns the top border.
    */
    wxTextAttrBorder& GetTopBorder();
    const wxTextAttrBorder& GetTopBorder() const;

    /**
        Returns the right border.
    */
    wxTextAttrBorder& GetRightBorder();
    const wxTextAttrBorder& GetRightBorder() const;

    /**
        Returns the bottom border.
    */
    wxTextAttrBorder& GetBottomBorder();
    const wxTextAttrBorder& GetBottomBorder() const;

    /**
        Returns the outline.
    */
    wxTextAttrBorders& GetOutline();
    const wxTextAttrBorders& GetOutline() const;

    /**
        Returns the left outline.
    */
    wxTextAttrBorder& GetLeftOutline();
    const wxTextAttrBorder& GetLeftOutline() const;

    /**
        Returns the top outline.
    */
    wxTextAttrBorder& GetTopOutline();
    const wxTextAttrBorder& GetTopOutline() const;

    /**
        Returns the right outline.
    */
    wxTextAttrBorder& GetRightOutline();
    const wxTextAttrBorder& GetRightOutline() const;

    /**
        Returns the bottom outline.
    */
    wxTextAttrBorder& GetBottomOutline();
    const wxTextAttrBorder& GetBottomOutline() const;

    /**
        Returns the object size.
    */
    wxTextAttrSize& GetSize();
    const wxTextAttrSize& GetSize() const;

    /**
        Returns the object minimum size.
    */

    wxTextAttrSize& GetMinSize();
    const wxTextAttrSize& GetMinSize() const;

    /**
        Returns the object maximum size.
    */

    wxTextAttrSize& GetMaxSize();
    const wxTextAttrSize& GetMaxSize() const;

    /**
        Sets the object size.
    */
    void SetSize(const wxTextAttrSize& sz);

    /**
        Sets the object minimum size.
    */
    void SetMinSize(const wxTextAttrSize& sz);

    /**
        Sets the object maximum size.
    */
    void SetMaxSize(const wxTextAttrSize& sz);

    /**
        Returns the object width.
    */
    wxTextAttrDimension& GetWidth();
    const wxTextAttrDimension& GetWidth() const;

    /**
        Returns the object height.
    */
    wxTextAttrDimension& GetHeight();
    const wxTextAttrDimension& GetHeight() const;

    /**
        Returns the box style name.
    */
    const wxString& GetBoxStyleName() const;

    /**
        Sets the box style name.
    */
    void SetBoxStyleName(const wxString& name);

    /**
        Returns @true if the box style name is present.
    */
    bool HasBoxStyleName() const;

public:

    int                             m_flags;

    wxTextAttrDimensions            m_margins;
    wxTextAttrDimensions            m_padding;
    wxTextAttrDimensions            m_position;

    wxTextAttrSize                  m_size;
    wxTextAttrSize                  m_minSize;
    wxTextAttrSize                  m_maxSize;

    wxTextAttrBorders               m_border;
    wxTextAttrBorders               m_outline;

    wxTextBoxAttrFloatStyle         m_floatMode;
    wxTextBoxAttrClearStyle         m_clearMode;
    wxTextBoxAttrCollapseMode       m_collapseMode;
    wxTextBoxAttrVerticalAlignment  m_verticalAlignment;
    wxString                        m_boxStyleName;
};

/**
    @class wxRichTextAttr
    A class representing enhanced attributes for rich text objects.
    This adds a wxTextBoxAttr member to the basic wxTextAttr class.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextAttr, wxTextBoxAttr, wxRichTextCtrl
*/

class %delete wxRichTextAttr: public wxTextAttr
{
public:
    /**
        Constructor taking a wxTextAttr.
    */
    wxRichTextAttr(const wxTextAttr& attr);

    /**
        Copy constructor.
    */
    wxRichTextAttr(const wxRichTextAttr& attr);

    /**
        Default constructor.
    */
    wxRichTextAttr();

    /**
        Copy function.
    */
    void Copy(const wxRichTextAttr& attr);

    /**
        Assignment operator.
    */
    void operator=(const wxRichTextAttr& attr);

    /**
        Assignment operator.
    */
    void operator=(const wxTextAttr& attr);

    /**
        Equality test.
    */
    bool operator==(const wxRichTextAttr& attr) const;

    /**
        Partial equality test. If @a weakTest is @true, attributes of this object do not
        have to be present if those attributes of @a attr are present. If @a weakTest is
        @false, the function will fail if an attribute is present in @a attr but not
        in this object.
    */
    bool EqPartial(const wxRichTextAttr& attr, bool weakTest = true) const;

    /**
        Merges the given attributes. If @a compareWith
        is non-NULL, then it will be used to mask out those attributes that are the same in style
        and @a compareWith, for situations where we don't want to explicitly set inherited attributes.
    */
    bool Apply(const wxRichTextAttr& style, const wxRichTextAttr* compareWith = NULL);

    /**
        Collects the attributes that are common to a range of content, building up a note of
        which attributes are absent in some objects and which clash in some objects.
    */
    void CollectCommonAttributes(const wxRichTextAttr& attr, wxRichTextAttr& clashingAttr, wxRichTextAttr& absentAttr);

    /**
        Removes the specified attributes from this object.
    */
    bool RemoveStyle(const wxRichTextAttr& attr);

    /**
        Returns the text box attributes.
    */
    wxTextBoxAttr& GetTextBoxAttr();
    const wxTextBoxAttr& GetTextBoxAttr() const;

    /**
        Set the text box attributes.
    */
    void SetTextBoxAttr(const wxTextBoxAttr& attr);

    /**
        Returns @true if no attributes are set.
    */
    bool IsDefault() const;

    wxTextBoxAttr    m_textBoxAttr;
};

// WX_DECLARE_USER_EXPORTED_OBJARRAY(wxRichTextAttr, wxRichTextAttrArray, WXDLLIMPEXP_RICHTEXT);
class %delete wxRichTextAttrArray
{
    wxRichTextAttrArray();
    wxRichTextAttrArray(const wxRichTextAttrArray& array);

    void Add(const wxRichTextAttr& item);
    void Clear();
    int  GetCount() const;
    void Insert(const wxRichTextAttr& item, int nIndex);
    bool IsEmpty();
    wxRichTextAttr Item(size_t nIndex) const;
    void RemoveAt(size_t nIndex);
};

// WX_DECLARE_USER_EXPORTED_OBJARRAY(wxVariant, wxRichTextVariantArray, WXDLLIMPEXP_RICHTEXT);
class %delete wxRichTextVariantArray
{
    wxRichTextVariantArray();
    wxRichTextVariantArray(const wxRichTextVariantArray& array);

    void Add(const wxVariant& item);
    void Clear();
    int  GetCount() const;
    void Insert(const wxVariant& item, int nIndex);
    bool IsEmpty();
    wxVariant Item(size_t nIndex) const;
    void RemoveAt(size_t nIndex);
};

// WX_DECLARE_USER_EXPORTED_OBJARRAY(wxRect, wxRichTextRectArray, WXDLLIMPEXP_RICHTEXT);
class %delete wxRichTextRectArray
{
    wxRichTextRectArray();
    wxRichTextRectArray(const wxRichTextRectArray& array);

    void Add(const wxRect& item);
    void Clear();
    int  GetCount() const;
    void Insert(const wxRect& item, int nIndex);
    bool IsEmpty();
    wxRect Item(size_t nIndex) const;
    void RemoveAt(size_t nIndex);
};

/**
    @class wxRichTextProperties
    A simple property class using wxVariants. This is used to give each rich text object the
    ability to store custom properties that can be used by the application.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextBuffer, wxRichTextObject, wxRichTextCtrl
*/

class %delete wxRichTextProperties: public wxObject
{
//DECLARE_DYNAMIC_CLASS(wxRichTextProperties)
public:

    /**
        Default constructor.
    */
    wxRichTextProperties();

    /**
        Copy constructor.
    */
    wxRichTextProperties(const wxRichTextProperties& props);

    /**
        Assignment operator.
    */
    void operator=(const wxRichTextProperties& props);

    /**
        Equality operator.
    */
    bool operator==(const wxRichTextProperties& props) const;

    /**
        Copies from @a props.
    */
    void Copy(const wxRichTextProperties& props);

    /**
        Returns the variant at the given index.
    */
    const wxVariant& operator[](size_t idx) const;

    /**
        Returns the variant at the given index.
    */
    wxVariant& operator[](size_t idx);

    /**
        Clears the properties.
    */
    void Clear();

    /**
        Returns the array of variants implementing the properties.
    */
    // wxLua: we do not need the const version
    //const wxRichTextVariantArray& GetProperties() const;

    /**
        Returns the array of variants implementing the properties.
    */
    wxRichTextVariantArray& GetProperties();

    /**
        Sets the array of variants.
    */
    void SetProperties(const wxRichTextVariantArray& props);

    /**
        Returns all the property names.
    */
    wxArrayString GetPropertyNames() const;

    /**
        Returns a count of the properties.
    */
    size_t GetCount() const;

    /**
        Returns @true if the given property is found.
    */
    bool HasProperty(const wxString& name) const;

    /**
        Finds the given property.
    */
    int Find(const wxString& name) const;

    /**
        Removes the given property.
    */
    bool Remove(const wxString& name);

    /**
        Gets the property variant by name.
    */
    const wxVariant& GetProperty(const wxString& name) const;

    /**
        Finds or creates a property with the given name, returning a pointer to the variant.
    */
    wxVariant* FindOrCreateProperty(const wxString& name);

    /**
        Gets the value of the named property as a string.
    */
    wxString GetPropertyString(const wxString& name) const;

    /**
        Gets the value of the named property as a long integer.
    */
    long GetPropertyLong(const wxString& name) const;

    /**
        Gets the value of the named property as a boolean.
    */
    bool GetPropertyBool(const wxString& name) const;

    /**
        Gets the value of the named property as a double.
    */
    double GetPropertyDouble(const wxString& name) const;

    /**
        Sets the property by passing a variant which contains a name and value.
    */
    void SetProperty(const wxVariant& variant);

    /**
        Sets a property by name and variant.
    */
    void SetProperty(const wxString& name, const wxVariant& variant);

    /**
        Sets a property by name and string value.
    */
    void SetProperty(const wxString& name, const wxString& value);

    /**
        Sets a property by name and wxChar* value.
    */
    //void SetProperty(const wxString& name, const wxChar* value);

    /**
        Sets  property by name and long integer value.
    */
    void SetProperty(const wxString& name, long value);

    /**
        Sets  property by name and double value.
    */
    void SetProperty(const wxString& name, double value);

    /**
        Sets  property by name and boolean value.
    */
    void SetProperty(const wxString& name, bool value);

    /**
        Removes the given properties from these properties.
    */
    void RemoveProperties(const wxRichTextProperties& properties);

    /**
        Merges the given properties with these properties.
    */
    void MergeProperties(const wxRichTextProperties& properties);

protected:
    wxRichTextVariantArray  m_properties;
};

/**
    @class wxRichTextFontTable
    Manages quick access to a pool of fonts for rendering rich text.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextFontTable: public wxObject
{
public:
    /**
        Default constructor.
    */
    wxRichTextFontTable();

    /**
        Copy constructor.
    */
    wxRichTextFontTable(const wxRichTextFontTable& table);
    virtual ~wxRichTextFontTable();

    /**
        Returns @true if the font table is valid.
    */
    bool IsOk() const;

    /**
        Finds a font for the given attribute object.
    */
    wxFont FindFont(const wxRichTextAttr& fontSpec);

    /**
        Clears the font table.
    */
    void Clear();

    /**
        Assignment operator.
    */
    void operator= (const wxRichTextFontTable& table);

    /**
        Equality operator.
    */
    bool operator == (const wxRichTextFontTable& table) const;

    /**
        Inequality operator.
    */
    bool operator != (const wxRichTextFontTable& table) const;

    /**
        Set the font scale factor.
    */
    void SetFontScale(double fontScale);

protected:

    double m_fontScale;

    //DECLARE_DYNAMIC_CLASS(wxRichTextFontTable)
};

//WX_DECLARE_USER_EXPORTED_OBJARRAY(wxRichTextRange, wxRichTextRangeArray, WXDLLIMPEXP_RICHTEXT);
class %delete wxRichTextRangeArray
{
    wxRichTextRangeArray();
    wxRichTextRangeArray(const wxRichTextRangeArray& array);

    void Add(const wxRichTextRange& item);
    void Clear();
    int  GetCount() const;
    void Insert(const wxRichTextRange& item, int nIndex);
    bool IsEmpty();
    wxRichTextRange Item(size_t nIndex) const;
    void RemoveAt(size_t nIndex);
};

//#define wxRICHTEXT_ALL  wxRichTextRange(-2, -2)
//#define wxRICHTEXT_NONE  wxRichTextRange(-1, -1)
//#define wxRICHTEXT_NO_SELECTION wxRichTextRange(-2, -2)

/**
    @class wxRichTextRange

    This stores beginning and end positions for a range of data.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextRange
{
#define_object wxRICHTEXT_ALL
#define_object wxRICHTEXT_NONE
#define_object wxRICHTEXT_NO_SELECTION

public:
// Constructors

    /**
        Default constructor.
    */
    wxRichTextRange();

    /**
        Constructor taking start and end positions.
    */
    wxRichTextRange(long start, long end);

    /**
        Copy constructor.
    */
    wxRichTextRange(const wxRichTextRange& range);
    //~wxRichTextRange();

    /**
        Assigns @a range to this range.
    */
    void operator =(const wxRichTextRange& range);

    /**
        Equality operator. Returns @true if @a range is the same as this range.
    */
    bool operator ==(const wxRichTextRange& range) const;

    /**
        Inequality operator.
    */
    bool operator !=(const wxRichTextRange& range) const;

    /**
        Subtracts a range from this range.
    */
    wxRichTextRange operator -(const wxRichTextRange& range) const;

    /**
        Adds a range to this range.
    */
    wxRichTextRange operator +(const wxRichTextRange& range) const;

    /**
        Sets the range start and end positions.
    */
    void SetRange(long start, long end);

    /**
        Sets the start position.
    */
    void SetStart(long start);

    /**
        Returns the start position.
    */
    long GetStart() const;

    /**
        Sets the end position.
    */
    void SetEnd(long end);

    /**
        Gets the end position.
    */
    long GetEnd() const;

    /**
        Returns true if this range is completely outside @a range.
    */
    bool IsOutside(const wxRichTextRange& range) const;

    /**
        Returns true if this range is completely within @a range.
    */
    bool IsWithin(const wxRichTextRange& range) const;

    /**
        Returns true if @a pos was within the range. Does not match if the range is empty.
    */
    bool Contains(long pos) const;

    /**
        Limit this range to be within @a range.
    */
    bool LimitTo(const wxRichTextRange& range) ;

    /**
        Gets the length of the range.
    */
    long GetLength() const;

    /**
        Swaps the start and end.
    */
    void Swap();

    /**
        Converts the API-standard range, whose end is one past the last character in
        the range, to the internal form, which uses the first and last character
        positions of the range. In other words, one is subtracted from the end position.
        (n, n) is the range of a single character.
    */
    wxRichTextRange ToInternal() const;

    /**
        Converts the internal range, which uses the first and last character positions
        of the range, to the API-standard range, whose end is one past the last
        character in the range. In other words, one is added to the end position.
        (n, n+1) is the range of a single character.
    */
    wxRichTextRange FromInternal() const;

protected:
    long m_start;
    long m_end;
};

/**
    @class wxRichTextSelection

    Stores selection information. The selection does not have to be contiguous, though currently non-contiguous
    selections are only supported for a range of table cells (a geometric block of cells can consist
    of a set of non-contiguous positions).

    The selection consists of an array of ranges, and the container that is the context for the selection. It
    follows that a single selection object can only represent ranges with the same parent container.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextSelection
{
public:
    /**
        Copy constructor.
    */
    wxRichTextSelection(const wxRichTextSelection& sel);

    /**
        Creates a selection from a range and a container.
    */
    wxRichTextSelection(const wxRichTextRange& range, wxRichTextParagraphLayoutBox* container);

    /**
        Default constructor.
    */
    wxRichTextSelection();

    /**
        Resets the selection.
    */
    void Reset();

    /**
        Sets the selection.
    */

    void Set(const wxRichTextRange& range, wxRichTextParagraphLayoutBox* container);

    /**
        Adds a range to the selection.
    */
    void Add(const wxRichTextRange& range);

    /**
        Sets the selections from an array of ranges and a container object.
    */
    void Set(const wxRichTextRangeArray& ranges, wxRichTextParagraphLayoutBox* container);

    /**
        Copies from @a sel.
    */
    void Copy(const wxRichTextSelection& sel);

    /**
        Assignment operator.
    */
    void operator=(const wxRichTextSelection& sel);

    /**
        Equality operator.
    */
    bool operator==(const wxRichTextSelection& sel) const;

    /**
        Index operator.
    */
    wxRichTextRange operator[](size_t i) const;

    /**
        Returns the selection ranges.
    */
    wxRichTextRangeArray& GetRanges();

    /**
        Returns the selection ranges.
    */
    // wxLua: we do not need the const version
    //const wxRichTextRangeArray& GetRanges() const;

    /**
        Sets the selection ranges.
    */
    void SetRanges(const wxRichTextRangeArray& ranges);

    /**
        Returns the number of ranges in the selection.
    */
    size_t GetCount() const;

    /**
        Returns the range at the given index.

    */
    wxRichTextRange GetRange(size_t i) const;

    /**
        Returns the first range if there is one, otherwise wxRICHTEXT_NO_SELECTION.
    */
    wxRichTextRange GetRange() const;

    /**
        Sets a single range.
    */
    void SetRange(const wxRichTextRange& range);

    /**
        Returns the container for which the selection is valid.
    */
    wxRichTextParagraphLayoutBox* GetContainer() const;

    /**
        Sets the container for which the selection is valid.
    */
    void SetContainer(wxRichTextParagraphLayoutBox* container);

    /**
        Returns @true if the selection is valid.
    */
    bool IsValid() const;

    /**
        Returns the selection appropriate to the specified object, if any; returns an empty array if none
        at the level of the object's container.
    */
    wxRichTextRangeArray GetSelectionForObject(wxRichTextObject* obj) const;

    /**
        Returns @true if the given position is within the selection.
    */
    bool WithinSelection(long pos, wxRichTextObject* obj) const;

    /**
        Returns @true if the given position is within the selection.

    */
    bool WithinSelection(long pos) const;

    /**
        Returns @true if the given position is within the selection range.
    */
    static bool WithinSelection(long pos, const wxRichTextRangeArray& ranges);

    /**
        Returns @true if the given range is within the selection range.
    */
    static bool WithinSelection(const wxRichTextRange& range, const wxRichTextRangeArray& ranges);

    wxRichTextRangeArray            m_ranges;
    wxRichTextParagraphLayoutBox*   m_container;
};

/**
    @class wxRichTextDrawingContext

    A class for passing information to drawing and measuring functions.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextDrawingContext: public wxObject
{
    //DECLARE_CLASS(wxRichTextDrawingContext)
public:

    /**
        Pass the buffer to the context so the context can retrieve information
        such as virtual attributes.
    */
    wxRichTextDrawingContext(wxRichTextBuffer* buffer);

    void Init();

    /**
        Does this object have virtual attributes?
        Virtual attributes can be provided for visual cues without
        affecting the actual styling.
    */
    bool HasVirtualAttributes(wxRichTextObject* obj) const;

    /**
        Returns the virtual attributes for this object.
        Virtual attributes can be provided for visual cues without
        affecting the actual styling.
    */
    wxRichTextAttr GetVirtualAttributes(wxRichTextObject* obj) const;

    /**
        Applies any virtual attributes relevant to this object.
    */
    bool ApplyVirtualAttributes(wxRichTextAttr& attr, wxRichTextObject* obj) const;

    /**
        Gets the count for mixed virtual attributes for individual positions within the object.
        For example, individual characters within a text object may require special highlighting.
    */
    int GetVirtualSubobjectAttributesCount(wxRichTextObject* obj) const;

    /**
        Gets the mixed virtual attributes for individual positions within the object.
        For example, individual characters within a text object may require special highlighting.
        The function is passed the count returned by GetVirtualSubobjectAttributesCount.
    */
    int GetVirtualSubobjectAttributes(wxRichTextObject* obj, wxArrayInt& positions, wxRichTextAttrArray& attributes) const;

    /**
        Do we have virtual text for this object? Virtual text allows an application
        to replace characters in an object for editing and display purposes, for example
        for highlighting special characters.
    */
    bool HasVirtualText(const wxRichTextPlainText* obj) const;

    /**
        Gets the virtual text for this object.
    */
    bool GetVirtualText(const wxRichTextPlainText* obj, wxString& text) const;

    /**
        Enables virtual attribute processing.
    */

    void EnableVirtualAttributes(bool b);

    /**
        Returns @true if virtual attribute processing is enabled.
    */

    bool GetVirtualAttributesEnabled() const;

    wxRichTextBuffer*   m_buffer;
    bool                m_enableVirtualAttributes;
};

/**
    @class wxRichTextObject

    This is the base for drawable rich text objects.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextObject: public wxObject
{
    //DECLARE_CLASS(wxRichTextObject)
public:
    /**
        Constructor, taking an optional parent pointer.
    */
    //wxRichTextObject(wxRichTextObject* parent = NULL);

    //virtual ~wxRichTextObject();

// Overridables

    /**
        Draw the item, within the given range. Some objects may ignore the range (for
        example paragraphs) while others must obey it (lines, to implement wrapping)
    */
    virtual bool Draw(wxDC& dc, wxRichTextDrawingContext& context, const wxRichTextRange& range, const wxRichTextSelection& selection, const wxRect& rect, int descent, int style);

    /**
        Lay the item out at the specified position with the given size constraint.
        Layout must set the cached size. @rect is the available space for the object,
        and @a parentRect is the container that is used to determine a relative size
        or position (for example if a text box must be 50% of the parent text box).
    */
    virtual bool Layout(wxDC& dc, wxRichTextDrawingContext& context, const wxRect& rect, const wxRect& parentRect, int style);

    /**
        Hit-testing: returns a flag indicating hit test details, plus
        information about position. @a contextObj is returned to specify what object
        position is relevant to, since otherwise there's an ambiguity.
        @ obj might not be a child of @a contextObj, since we may be referring to the container itself
        if we have no hit on a child - for example if we click outside an object.

        The function puts the position in @a textPosition if one is found.
        @a pt is in logical units (a zero y position is at the beginning of the buffer).

        Pass wxRICHTEXT_HITTEST_NO_NESTED_OBJECTS if you only want to consider objects
        directly under the object you are calling HitTest on. Otherwise, it will recurse
        and potentially find a nested object.

        @return One of the ::wxRichTextHitTestFlags values.
    */

    virtual int HitTest(wxDC& dc, wxRichTextDrawingContext& context, const wxPoint& pt, long& textPosition, wxRichTextObject** obj, wxRichTextObject** contextObj, int flags = 0);

    /**
        Finds the absolute position and row height for the given character position.
    */
    virtual bool FindPosition(wxDC& dc, wxRichTextDrawingContext& context, long index, wxPoint& pt, int* height, bool forceLineStart);

    /**
        Returns the best size, i.e. the ideal starting size for this object irrespective
        of available space. For a short text string, it will be the size that exactly encloses
        the text. For a longer string, it might use the parent width for example.
    */
    virtual wxSize GetBestSize() const;

    /**
        Returns the object size for the given range. Returns @false if the range
        is invalid for this object.
    */

    virtual bool GetRangeSize(const wxRichTextRange& range, wxSize& size, int& descent, wxDC& dc, wxRichTextDrawingContext& context, int flags, const wxPoint& position = wxNULLPOINT, const wxSize& parentSize = wxDefaultSize, wxArrayInt* partialExtents = NULL) const;

    /**
        Do a split from @a pos, returning an object containing the second part, and setting
        the first part in 'this'.
    */
    virtual wxRichTextObject* DoSplit(long pos);

    /**
        Calculates the range of the object. By default, guess that the object is 1 unit long.
    */
    virtual void CalculateRange(long start, long& end);

    /**
        Deletes the given range.
    */
    virtual bool DeleteRange(const wxRichTextRange& range);

    /**
        Returns @true if the object is empty.
    */
    virtual bool IsEmpty() const;

    /**
        Returns @true if this class of object is floatable.
    */
    virtual bool IsFloatable() const;

    /**
        Returns @true if this object is currently floating.
    */
    virtual bool IsFloating() const;

    /**
        Returns the floating direction.
    */
    virtual int GetFloatDirection() const;

    /**
        Returns any text in this object for the given range.
    */
    virtual wxString GetTextForRange(const wxRichTextRange& range) const;

    /**
        Returns @true if this object can merge itself with the given one.
    */
    virtual bool CanMerge(wxRichTextObject* object, wxRichTextDrawingContext& context) const;

    /**
        Returns @true if this object merged itself with the given one.
        The calling code will then delete the given object.
    */
    virtual bool Merge(wxRichTextObject* object, wxRichTextDrawingContext& context);

    /**
        JACS
        Returns @true if this object can potentially be split, by virtue of having
        different virtual attributes for individual sub-objects.
    */
    virtual bool CanSplit(wxRichTextDrawingContext& context) const;

    /**
        Returns the final object in the split objects if this object was split due to differences between sub-object virtual attributes.
        Returns itself if it was not split.
    */
    virtual wxRichTextObject* Split(wxRichTextDrawingContext& context);

    /**
        Dump object data to the given output stream for debugging.
    */
    virtual void Dump(wxTextOutputStream& stream);

    /**
        Returns @true if we can edit the object's properties via a GUI.
    */
    virtual bool CanEditProperties() const;

    /**
        Edits the object's properties via a GUI.
    */
    virtual bool EditProperties(wxWindow* parent, wxRichTextBuffer* buffer);

    /**
        Returns the label to be used for the properties context menu item.
    */
    virtual wxString GetPropertiesMenuLabel() const;

    /**
        Returns @true if objects of this class can accept the focus, i.e. a call to SetFocusObject
        is possible. For example, containers supporting text, such as a text box object, can accept the focus,
        but a table can't (set the focus to individual cells instead).
    */
    virtual bool AcceptsFocus() const;

#if wxUSE_XML
    /**
        Imports this object from XML.
    */
    virtual bool ImportFromXML(wxRichTextBuffer* buffer, wxXmlNode* node, wxRichTextXMLHandler* handler, bool* recurse);
#endif

#if wxRICHTEXT_HAVE_DIRECT_OUTPUT
    /**
        Exports this object directly to the given stream, bypassing the creation of a wxXmlNode hierarchy.
        This method is considerably faster than creating a tree first. However, both versions of ExportXML must be
        implemented so that if the tree method is made efficient in the future, we can deprecate the
        more verbose direct output method. Compiled only if wxRICHTEXT_HAVE_DIRECT_OUTPUT is defined (on by default).
    */
    virtual bool ExportXML(wxOutputStream& stream, int indent, wxRichTextXMLHandler* handler);
#endif

#if wxRICHTEXT_HAVE_XMLDOCUMENT_OUTPUT
    /**
        Exports this object to the given parent node, usually creating at least one child node.
        This method is less efficient than the direct-to-stream method but is retained to allow for
        switching to this method if we make it more efficient. Compiled only if wxRICHTEXT_HAVE_XMLDOCUMENT_OUTPUT is defined
        (on by default).
    */
    virtual bool ExportXML(wxXmlNode* parent, wxRichTextXMLHandler* handler);
#endif

    /**
        Returns @true if this object takes note of paragraph attributes (text and image objects don't).
    */
    virtual bool UsesParagraphAttributes() const;

    /**
        Returns the XML node name of this object. This must be overridden for wxXmlNode-base XML export to work.
    */
    virtual wxString GetXMLNodeName() const;

    /**
        Invalidates the object at the given range. With no argument, invalidates the whole object.
    */
    virtual void Invalidate(const wxRichTextRange& invalidRange = wxRICHTEXT_ALL);

    /**
        Returns @true if this object can handle the selections of its children, fOr example a table.
        Required for composite selection handling to work.
    */
    virtual bool HandlesChildSelections() const;

    /**
        Returns a selection object specifying the selections between start and end character positions.
        For example, a table would deduce what cells (of range length 1) are selected when dragging across the table.
    */
    virtual wxRichTextSelection GetSelection(long start, long end) const;

// Accessors

    /**
        Gets the cached object size as calculated by Layout.
    */
    virtual wxSize GetCachedSize() const;

    /**
        Sets the cached object size as calculated by Layout.
    */
    virtual void SetCachedSize(const wxSize& sz);

    /**
        Gets the maximum object size as calculated by Layout. This allows
        us to fit an object to its contents or allocate extra space if required.
    */
    virtual wxSize GetMaxSize() const;

    /**
        Sets the maximum object size as calculated by Layout. This allows
        us to fit an object to its contents or allocate extra space if required.
    */
    virtual void SetMaxSize(const wxSize& sz);

    /**
        Gets the minimum object size as calculated by Layout. This allows
        us to constrain an object to its absolute minimum size if necessary.
    */
    virtual wxSize GetMinSize() const;

    /**
        Sets the minimum object size as calculated by Layout. This allows
        us to constrain an object to its absolute minimum size if necessary.
    */
    virtual void SetMinSize(const wxSize& sz);

    /**
        Gets the 'natural' size for an object. For an image, it would be the
        image size.
    */
    virtual wxTextAttrSize GetNaturalSize() const;

    /**
        Returns the object position in pixels.
    */
    virtual wxPoint GetPosition() const;

    /**
        Sets the object position in pixels.
    */
    virtual void SetPosition(const wxPoint& pos);

    /**
        Returns the absolute object position, by traversing up the child/parent hierarchy.
        TODO: may not be needed, if all object positions are in fact relative to the
        top of the coordinate space.
    */
    virtual wxPoint GetAbsolutePosition() const;

    /**
        Returns the rectangle enclosing the object.
    */
    virtual wxRect GetRect() const;

    /**
        Sets the object's range within its container.
    */
    void SetRange(const wxRichTextRange& range);

    /**
        Returns the object's range.
    */
    const wxRichTextRange& GetRange() const;

    /**
        Returns the object's range.
    */
    wxRichTextRange& GetRange();

    /**
        Set the object's own range, for a top-level object with its own position space.
    */
    void SetOwnRange(const wxRichTextRange& range);

    /**
        Returns the object's own range (valid if top-level).
    */
    const wxRichTextRange& GetOwnRange() const;

    /**
        Returns the object's own range (valid if top-level).
    */
    wxRichTextRange& GetOwnRange();

    /**
        Returns the object's own range only if a top-level object.
    */
    wxRichTextRange GetOwnRangeIfTopLevel() const;

    /**
        Returns @true if this object is composite.
    */
    virtual bool IsComposite() const;

    /**
        Returns @true if no user editing can be done inside the object. This returns @true for simple objects,
        @false for most composite objects, but @true for fields, which if composite, should not be user-edited.
    */
    virtual bool IsAtomic() const;

    /**
        Returns a pointer to the parent object.
    */
    virtual wxRichTextObject* GetParent() const;

    /**
        Sets the pointer to the parent object.
    */
    virtual void SetParent(wxRichTextObject* parent);

    /**
        Returns the top-level container of this object.
        May return itself if it's a container; use GetParentContainer to return
        a different container.
    */
    virtual wxRichTextParagraphLayoutBox* GetContainer() const;

    /**
        Returns the top-level container of this object.
        Returns a different container than itself, unless there's no parent, in which case it will return NULL.
    */
    virtual wxRichTextParagraphLayoutBox* GetParentContainer() const;

    /**
        Set the margin around the object, in pixels.
    */
    virtual void SetMargins(int margin);

    /**
        Set the margin around the object, in pixels.
    */
    virtual void SetMargins(int leftMargin, int rightMargin, int topMargin, int bottomMargin);

    /**
        Returns the left margin of the object, in pixels.
    */
    virtual int GetLeftMargin() const;

    /**
        Returns the right margin of the object, in pixels.
    */
    virtual int GetRightMargin() const;

    /**
        Returns the top margin of the object, in pixels.
    */
    virtual int GetTopMargin() const;

    /**
        Returns the bottom margin of the object, in pixels.
    */
    virtual int GetBottomMargin() const;

    /**
        Calculates the available content space in the given rectangle, given the
        margins, border and padding specified in the object's attributes.
    */
    virtual wxRect GetAvailableContentArea(wxDC& dc, wxRichTextDrawingContext& context, const wxRect& outerRect) const;

    /**
        Lays out the object first with a given amount of space, and then if no width was specified in attr,
        lays out the object again using the minimum size. @a availableParentSpace is the maximum space
        for the object, whereas @a availableContainerSpace is the container with which relative positions and
        sizes should be computed. For example, a text box whose space has already been constrained
        in a previous layout pass to @a availableParentSpace, but should have a width of 50% of @a availableContainerSpace.
        (If these two rects were the same, a 2nd pass could see the object getting too small.)
    */
    virtual bool LayoutToBestSize(wxDC& dc, wxRichTextDrawingContext& context, wxRichTextBuffer* buffer,
                    const wxRichTextAttr& parentAttr, const wxRichTextAttr& attr,
                    const wxRect& availableParentSpace, const wxRect& availableContainerSpace, int style);

    /**
        Adjusts the attributes for virtual attribute provision, collapsed borders, etc.
    */
    virtual bool AdjustAttributes(wxRichTextAttr& attr, wxRichTextDrawingContext& context);

    /**
        Sets the object's attributes.
    */
    void SetAttributes(const wxRichTextAttr& attr);

    /**
        Returns the object's attributes.
    */
    const wxRichTextAttr& GetAttributes() const;

    /**
        Returns the object's attributes.
    */
    wxRichTextAttr& GetAttributes();

    /**
        Returns the object's properties.
    */
    wxRichTextProperties& GetProperties();

    /**
        Returns the object's properties.
    */
    const wxRichTextProperties& GetProperties() const;

    /**
        Sets the object's properties.
    */
    void SetProperties(const wxRichTextProperties& props);

    /**
        Sets the stored descent value.
    */
    void SetDescent(int descent);

    /**
        Returns the stored descent value.
    */
    int GetDescent() const;

    /**
        Returns the containing buffer.
    */
    wxRichTextBuffer* GetBuffer() const;

    /**
        Sets the identifying name for this object as a property using the "name" key.
    */
    void SetName(const wxString& name);

    /**
        Returns the identifying name for this object from the properties, using the "name" key.
    */
    wxString GetName() const;

    /**
        Returns @true if this object is top-level, i.e. contains its own paragraphs, such as a text box.
    */
    virtual bool IsTopLevel() const;

    /**
        Returns @true if the object will be shown, @false otherwise.
    */
    bool IsShown() const;

// Operations

    /**
        Call to show or hide this object. This function does not cause the content to be
        laid out or redrawn.
    */
    virtual void Show(bool show);

    /**
        Clones the object.
    */
    virtual wxRichTextObject* Clone() const;

    /**
        Copies the object.
    */
    void Copy(const wxRichTextObject& obj);

    /**
        Reference-counting allows us to use the same object in multiple
        lists (not yet used).
    */

    void Reference();

    /**
        Reference-counting allows us to use the same object in multiple
        lists (not yet used).
    */
    void Dereference();

    /**
        Moves the object recursively, by adding the offset from old to new.
    */
    virtual void Move(const wxPoint& pt);

    /**
        Converts units in tenths of a millimetre to device units.
    */
    int ConvertTenthsMMToPixels(wxDC& dc, int units) const;

    /**
        Converts units in tenths of a millimetre to device units.
    */
    static int ConvertTenthsMMToPixels(int ppi, int units, double scale = 1.0);

    /**
        Convert units in pixels to tenths of a millimetre.
    */
    int ConvertPixelsToTenthsMM(wxDC& dc, int pixels) const;

    /**
        Convert units in pixels to tenths of a millimetre.
    */
    static int ConvertPixelsToTenthsMM(int ppi, int pixels, double scale = 1.0);

    /**
        Draws the borders and background for the given rectangle and attributes.
        @a boxRect is taken to be the outer margin box, not the box around the content.
    */
    static bool DrawBoxAttributes(wxDC& dc, wxRichTextBuffer* buffer, const wxRichTextAttr& attr, const wxRect& boxRect, int flags = 0, wxRichTextObject* obj = NULL);

    /**
        Draws a border.
    */
    !%wxchkver_3_1_0 static bool DrawBorder(wxDC& dc, wxRichTextBuffer* buffer, const wxTextAttrBorders& attr, const wxRect& rect, int flags = 0);
    %wxchkver_3_1_0  static bool DrawBorder(wxDC& dc, wxRichTextBuffer* buffer, const wxRichTextAttr& attr, const wxTextAttrBorders& borders, const wxRect& rect, int flags = 0);

    /**
        Returns the various rectangles of the box model in pixels. You can either specify @a contentRect (inner)
        or @a marginRect (outer), and the other must be the default rectangle (no width or height).
        Note that the outline doesn't affect the position of the rectangle, it's drawn in whatever space
        is available.
    */
    static bool GetBoxRects(wxDC& dc, wxRichTextBuffer* buffer, const wxRichTextAttr& attr, wxRect& marginRect, wxRect& borderRect, wxRect& contentRect, wxRect& paddingRect, wxRect& outlineRect);

    /**
        Returns the total margin for the object in pixels, taking into account margin, padding and border size.
    */
    static bool GetTotalMargin(wxDC& dc, wxRichTextBuffer* buffer, const wxRichTextAttr& attr, int& leftMargin, int& rightMargin,
        int& topMargin, int& bottomMargin);

    /**
        Returns the rectangle which the child has available to it given restrictions specified in the
        child attribute, e.g. 50% width of the parent, 400 pixels, x position 20% of the parent, etc.
        availableContainerSpace might be a parent that the cell has to compute its width relative to.
        E.g. a cell that's 50% of its parent.
    */
    static wxRect AdjustAvailableSpace(wxDC& dc, wxRichTextBuffer* buffer, const wxRichTextAttr& parentAttr, const wxRichTextAttr& childAttr,
        const wxRect& availableParentSpace, const wxRect& availableContainerSpace);

protected:
    wxSize                  m_size;
    wxSize                  m_maxSize;
    wxSize                  m_minSize;
    wxPoint                 m_pos;
    int                     m_descent; // Descent for this object (if any)
    int                     m_refCount;
    bool                    m_show;
    wxRichTextObject*       m_parent;

    // The range of this object (start position to end position)
    wxRichTextRange         m_range;

    // The internal range of this object, if it's a top-level object with its own range space
    wxRichTextRange         m_ownRange;

    // Attributes
    wxRichTextAttr          m_attributes;

    // Properties
    wxRichTextProperties    m_properties;
};

class wxRichTextObjectList : public wxList
{
    // Use the wxList methods, see also wxNode
};

/**
    @class wxRichTextCompositeObject

    Objects of this class can contain other objects.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextObject, wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextCompositeObject: public wxRichTextObject
{
    //DECLARE_CLASS(wxRichTextCompositeObject)
public:
// Constructors

    //wxRichTextCompositeObject(wxRichTextObject* parent = NULL);
    //virtual ~wxRichTextCompositeObject();

// Overridables

    virtual int HitTest(wxDC& dc, wxRichTextDrawingContext& context, const wxPoint& pt, long& textPosition, wxRichTextObject** obj, wxRichTextObject** contextObj, int flags = 0);

    virtual bool FindPosition(wxDC& dc, wxRichTextDrawingContext& context, long index, wxPoint& pt, int* height, bool forceLineStart);

    virtual void CalculateRange(long start, long& end);

    virtual bool DeleteRange(const wxRichTextRange& range);

    virtual wxString GetTextForRange(const wxRichTextRange& range) const;

    virtual bool GetRangeSize(const wxRichTextRange& range, wxSize& size, int& descent, wxDC& dc, wxRichTextDrawingContext& context, int flags, const wxPoint& position = wxNULLPOINT, const wxSize& parentSize = wxDefaultSize, wxArrayInt* partialExtents = NULL) const;

    virtual void Dump(wxTextOutputStream& stream);

    virtual void Invalidate(const wxRichTextRange& invalidRange = wxRICHTEXT_ALL);

// Accessors

    /**
        Returns the children.
    */
    wxRichTextObjectList& GetChildren();
    /**
        Returns the children.
    */
    // wxLua: we do not need const version
    //const wxRichTextObjectList& GetChildren() const;

    /**
        Returns the number of children.
    */
    size_t GetChildCount() const ;

    /**
        Returns the nth child.
    */
    wxRichTextObject* GetChild(size_t n) const ;

    /**
        Returns @true if this object is composite.
    */
    virtual bool IsComposite() const;

    /**
        Returns @true if no user editing can be done inside the object. This returns @true for simple objects,
        @false for most composite objects, but @true for fields, which if composite, should not be user-edited.
    */
    virtual bool IsAtomic() const;

    /**
        Returns true if the buffer is empty.
    */
    virtual bool IsEmpty() const;

    /**
        Returns the child object at the given character position.
    */
    virtual wxRichTextObject* GetChildAtPosition(long pos) const;

// Operations

    void Copy(const wxRichTextCompositeObject& obj);

    void operator= (const wxRichTextCompositeObject& obj);

    /**
        Appends a child, returning the position.
    */
    size_t AppendChild(wxRichTextObject* child) ;

    /**
        Inserts the child in front of the given object, or at the beginning.
    */
    bool InsertChild(wxRichTextObject* child, wxRichTextObject* inFrontOf) ;

    /**
        Removes and optionally deletes the specified child.
    */
    bool RemoveChild(wxRichTextObject* child, bool deleteChild = false) ;

    /**
        Deletes all the children.
    */
    bool DeleteChildren() ;

    /**
        Recursively merges all pieces that can be merged.
    */
    bool Defragment(wxRichTextDrawingContext& context, const wxRichTextRange& range = wxRICHTEXT_ALL);

    /**
        Moves the object recursively, by adding the offset from old to new.
    */
    virtual void Move(const wxPoint& pt);

protected:
    wxRichTextObjectList    m_children;
};

/**
    @class wxRichTextParagraphLayoutBox

    This class knows how to lay out paragraphs.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextCompositeObject, wxRichTextObject, wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextParagraphLayoutBox: public wxRichTextCompositeObject
{
    //DECLARE_DYNAMIC_CLASS(wxRichTextParagraphLayoutBox)
public:
// Constructors

    wxRichTextParagraphLayoutBox(wxRichTextObject* parent = NULL);
    wxRichTextParagraphLayoutBox(const wxRichTextParagraphLayoutBox& obj);
    //~wxRichTextParagraphLayoutBox();

// Overridables

    virtual int HitTest(wxDC& dc, wxRichTextDrawingContext& context, const wxPoint& pt, long& textPosition, wxRichTextObject** obj, wxRichTextObject** contextObj, int flags = 0);

    virtual bool Draw(wxDC& dc, wxRichTextDrawingContext& context, const wxRichTextRange& range, const wxRichTextSelection& selection, const wxRect& rect, int descent, int style);

    virtual bool Layout(wxDC& dc, wxRichTextDrawingContext& context, const wxRect& rect, const wxRect& parentRect, int style);

    virtual bool GetRangeSize(const wxRichTextRange& range, wxSize& size, int& descent, wxDC& dc, wxRichTextDrawingContext& context, int flags, const wxPoint& position = wxNULLPOINT, const wxSize& parentSize = wxDefaultSize, wxArrayInt* partialExtents = NULL) const;

    virtual bool DeleteRange(const wxRichTextRange& range);

    virtual wxString GetTextForRange(const wxRichTextRange& range) const;

#if wxUSE_XML
    virtual bool ImportFromXML(wxRichTextBuffer* buffer, wxXmlNode* node, wxRichTextXMLHandler* handler, bool* recurse);
#endif

#if wxRICHTEXT_HAVE_DIRECT_OUTPUT
    virtual bool ExportXML(wxOutputStream& stream, int indent, wxRichTextXMLHandler* handler);
#endif

#if wxRICHTEXT_HAVE_XMLDOCUMENT_OUTPUT
    virtual bool ExportXML(wxXmlNode* parent, wxRichTextXMLHandler* handler);
#endif

    virtual wxString GetXMLNodeName() const;

    virtual bool AcceptsFocus() const;

// Accessors

    /**
        Associates a control with the buffer, for operations that for example require refreshing the window.
    */
    void SetRichTextCtrl(wxRichTextCtrl* ctrl);

    /**
        Returns the associated control.
    */
    wxRichTextCtrl* GetRichTextCtrl() const;

    /**
        Sets a flag indicating whether the last paragraph is partial or complete.
    */
    void SetPartialParagraph(bool partialPara);

    /**
        Returns a flag indicating whether the last paragraph is partial or complete.
    */
    bool GetPartialParagraph() const;

    /**
        Returns the style sheet associated with the overall buffer.
    */
    virtual wxRichTextStyleSheet* GetStyleSheet() const;

    virtual bool IsTopLevel() const;

// Operations

    /**
        Submits a command to insert paragraphs.
    */
    bool InsertParagraphsWithUndo(wxRichTextBuffer* buffer, long pos, const wxRichTextParagraphLayoutBox& paragraphs, wxRichTextCtrl* ctrl, int flags = 0);

    /**
        Submits a command to insert the given text.
    */
    bool InsertTextWithUndo(wxRichTextBuffer* buffer, long pos, const wxString& text, wxRichTextCtrl* ctrl, int flags = 0);

    /**
        Submits a command to insert the given text.
    */
    bool InsertNewlineWithUndo(wxRichTextBuffer* buffer, long pos, wxRichTextCtrl* ctrl, int flags = 0);

    /**
        Submits a command to insert the given image.
    */
    bool InsertImageWithUndo(wxRichTextBuffer* buffer, long pos, const wxRichTextImageBlock& imageBlock,
                                                        wxRichTextCtrl* ctrl, int flags, const wxRichTextAttr& textAttr);

    /**
        Submits a command to insert the given field. Field data can be included in properties.

        @see wxRichTextField, wxRichTextFieldType, wxRichTextFieldTypeStandard
    */
    wxRichTextField* InsertFieldWithUndo(wxRichTextBuffer* buffer, long pos, const wxString& fieldType,
                                                        const wxRichTextProperties& properties,
                                                        wxRichTextCtrl* ctrl, int flags,
                                                        const wxRichTextAttr& textAttr);

    /**
        Returns the style that is appropriate for a new paragraph at this position.
        If the previous paragraph has a paragraph style name, looks up the next-paragraph
        style.
    */
    wxRichTextAttr GetStyleForNewParagraph(wxRichTextBuffer* buffer, long pos, bool caretPosition = false, bool lookUpNewParaStyle=false) const;

    /**
        Inserts an object.
    */
    wxRichTextObject* InsertObjectWithUndo(wxRichTextBuffer* buffer, long pos, wxRichTextObject *object, wxRichTextCtrl* ctrl, int flags = 0);

    /**
        Submits a command to delete this range.
    */
    bool DeleteRangeWithUndo(const wxRichTextRange& range, wxRichTextCtrl* ctrl, wxRichTextBuffer* buffer);

    /**
        Draws the floating objects in this buffer.
    */
    void DrawFloats(wxDC& dc, wxRichTextDrawingContext& context, const wxRichTextRange& range, const wxRichTextSelection& selection, const wxRect& rect, int descent, int style);

    /**
        Moves an anchored object to another paragraph.
    */
    void MoveAnchoredObjectToParagraph(wxRichTextParagraph* from, wxRichTextParagraph* to, wxRichTextObject* obj);

    /**
        Initializes the object.
    */
    void Init();

    /**
        Clears all the children.
    */
    virtual void Clear();

    /**
        Clears and initializes with one blank paragraph.
    */
    virtual void Reset();

    /**
        Convenience function to add a paragraph of text.
    */
    virtual wxRichTextRange AddParagraph(const wxString& text, wxRichTextAttr* paraStyle = NULL);

    /**
        Convenience function to add an image.
    */
    virtual wxRichTextRange AddImage(const wxImage& image, wxRichTextAttr* paraStyle = NULL);

    /**
        Adds multiple paragraphs, based on newlines.
    */
    virtual wxRichTextRange AddParagraphs(const wxString& text, wxRichTextAttr* paraStyle = NULL);

    /**
        Returns the line at the given position. If @a caretPosition is true, the position is
        a caret position, which is normally a smaller number.
    */
    virtual wxRichTextLine* GetLineAtPosition(long pos, bool caretPosition = false) const;

    /**
        Returns the line at the given y pixel position, or the last line.
    */
    virtual wxRichTextLine* GetLineAtYPosition(int y) const;

    /**
        Returns the paragraph at the given character or caret position.
    */
    virtual wxRichTextParagraph* GetParagraphAtPosition(long pos, bool caretPosition = false) const;

    /**
        Returns the line size at the given position.
    */
    virtual wxSize GetLineSizeAtPosition(long pos, bool caretPosition = false) const;

    /**
        Given a position, returns the number of the visible line (potentially many to a paragraph),
        starting from zero at the start of the buffer. We also have to pass a bool (@a startOfLine)
        that indicates whether the caret is being shown at the end of the previous line or at the start
        of the next, since the caret can be shown at two visible positions for the same underlying
        position.
    */
    virtual long GetVisibleLineNumber(long pos, bool caretPosition = false, bool startOfLine = false) const;

    /**
        Given a line number, returns the corresponding wxRichTextLine object.
    */
    virtual wxRichTextLine* GetLineForVisibleLineNumber(long lineNumber) const;

    /**
        Returns the leaf object in a paragraph at this position.
    */
    virtual wxRichTextObject* GetLeafObjectAtPosition(long position) const;

    /**
        Returns the paragraph by number.
    */
    virtual wxRichTextParagraph* GetParagraphAtLine(long paragraphNumber) const;

    /**
        Returns the paragraph for a given line.
    */
    virtual wxRichTextParagraph* GetParagraphForLine(wxRichTextLine* line) const;

    /**
        Returns the length of the paragraph.
    */
    virtual int GetParagraphLength(long paragraphNumber) const;

    /**
        Returns the number of paragraphs.
    */
    virtual int GetParagraphCount() const;

    /**
        Returns the number of visible lines.
    */
    virtual int GetLineCount() const;

    /**
        Returns the text of the paragraph.
    */
    virtual wxString GetParagraphText(long paragraphNumber) const;

    /**
        Converts zero-based line column and paragraph number to a position.
    */
    virtual long XYToPosition(long x, long y) const;

    /**
        Converts a zero-based position to line column and paragraph number.
    */
    virtual bool PositionToXY(long pos, long* x, long* y) const;

    /**
        Sets the attributes for the given range. Pass flags to determine how the
        attributes are set.

        The end point of range is specified as the last character position of the span
        of text. So, for example, to set the style for a character at position 5,
        use the range (5,5).
        This differs from the wxRichTextCtrl API, where you would specify (5,6).

        @a flags may contain a bit list of the following values:
        - wxRICHTEXT_SETSTYLE_NONE: no style flag.
        - wxRICHTEXT_SETSTYLE_WITH_UNDO: specifies that this operation should be
          undoable.
        - wxRICHTEXT_SETSTYLE_OPTIMIZE: specifies that the style should not be applied
          if the combined style at this point is already the style in question.
        - wxRICHTEXT_SETSTYLE_PARAGRAPHS_ONLY: specifies that the style should only be
          applied to paragraphs, and not the content.
          This allows content styling to be preserved independently from that
          of e.g. a named paragraph style.
        - wxRICHTEXT_SETSTYLE_CHARACTERS_ONLY: specifies that the style should only be
          applied to characters, and not the paragraph.
          This allows content styling to be preserved independently from that
          of e.g. a named paragraph style.
        - wxRICHTEXT_SETSTYLE_RESET: resets (clears) the existing style before applying
          the new style.
        - wxRICHTEXT_SETSTYLE_REMOVE: removes the specified style.
          Only the style flags are used in this operation.
    */
    virtual bool SetStyle(const wxRichTextRange& range, const wxRichTextAttr& style, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO);

    /**
        Sets the attributes for the given object only, for example the box attributes for a text box.
    */
    virtual void SetStyle(wxRichTextObject *obj, const wxRichTextAttr& textAttr, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO);

    /**
        Returns the combined text attributes for this position.

        This function gets the @e uncombined style - that is, the attributes associated
        with the paragraph or character content, and not necessarily the combined
        attributes you see on the screen. To get the combined attributes, use GetStyle().
        If you specify (any) paragraph attribute in @e style's flags, this function
        will fetch the paragraph attributes.
        Otherwise, it will return the character attributes.
    */
    //  Lua: %override [bool, wxRichTextAttr] GetStyle(long position)
    //virtual bool GetStyle(long position, wxRichTextAttr& style);
    virtual bool GetStyle(long position);

    /**
        Returns the content (uncombined) attributes for this position.
    */
    //  Lua: %override [bool, wxRichTextAttr] GetUncombinedStyle(long position);
    //virtual bool GetUncombinedStyle(long position, wxRichTextAttr& style);
    virtual bool GetUncombinedStyle(long position);

    /**
        Implementation helper for GetStyle. If combineStyles is true, combine base, paragraph and
        context attributes.
    */
    virtual bool DoGetStyle(long position, wxRichTextAttr& style, bool combineStyles = true);

    /**
        This function gets a style representing the common, combined attributes in the
        given range.
        Attributes which have different values within the specified range will not be
        included the style flags.

        The function is used to get the attributes to display in the formatting dialog:
        the user can edit the attributes common to the selection, and optionally specify the
        values of further attributes to be applied uniformly.

        To apply the edited attributes, you can use SetStyle() specifying
        the wxRICHTEXT_SETSTYLE_OPTIMIZE flag, which will only apply attributes that
        are different from the @e combined attributes within the range.
        So, the user edits the effective, displayed attributes for the range,
        but his choice won't be applied unnecessarily to content. As an example,
        say the style for a paragraph specifies bold, but the paragraph text doesn't
        specify a weight.
        The combined style is bold, and this is what the user will see on-screen and
        in the formatting dialog. The user now specifies red text, in addition to bold.
        When applying with SetStyle(), the content font weight attributes won't be
        changed to bold because this is already specified by the paragraph.
        However the text colour attributes @e will be changed to show red.
    */
    //  Lua: %override [bool, wxRichTextAttr] GetStyleForRange(const wxRichTextRange& range);
    //virtual bool GetStyleForRange(const wxRichTextRange& range, wxRichTextAttr& style);
    virtual bool GetStyleForRange(const wxRichTextRange& range);

    /**
        Combines @a style with @a currentStyle for the purpose of summarising the attributes of a range of
        content.
    */
    bool CollectStyle(wxRichTextAttr& currentStyle, const wxRichTextAttr& style, wxRichTextAttr& clashingAttr, wxRichTextAttr& absentAttr);

    //@{
    /**
        Sets the list attributes for the given range, passing flags to determine how
        the attributes are set.
        Either the style definition or the name of the style definition (in the current
        sheet) can be passed.

        @a flags is a bit list of the following:
        - wxRICHTEXT_SETSTYLE_WITH_UNDO: specifies that this command will be undoable.
        - wxRICHTEXT_SETSTYLE_RENUMBER: specifies that numbering should start from
          @a startFrom, otherwise existing attributes are used.
        - wxRICHTEXT_SETSTYLE_SPECIFY_LEVEL: specifies that @a listLevel should be used
          as the level for all paragraphs, otherwise the current indentation will be used.

        @see NumberList(), PromoteList(), ClearListStyle().
    */
    virtual bool SetListStyle(const wxRichTextRange& range, wxRichTextListStyleDefinition* def, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO, int startFrom = 1, int specifiedLevel = -1);
    virtual bool SetListStyle(const wxRichTextRange& range, const wxString& defName, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO, int startFrom = 1, int specifiedLevel = -1);
    //@}

    /**
        Clears the list style from the given range, clearing list-related attributes
        and applying any named paragraph style associated with each paragraph.

        @a flags is a bit list of the following:
        - wxRICHTEXT_SETSTYLE_WITH_UNDO: specifies that this command will be undoable.

        @see SetListStyle(), PromoteList(), NumberList()
    */
    virtual bool ClearListStyle(const wxRichTextRange& range, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO);

    //@{
    /**
        Numbers the paragraphs in the given range.

        Pass flags to determine how the attributes are set.
        Either the style definition or the name of the style definition (in the current
        sheet) can be passed.

        @a flags is a bit list of the following:
        - wxRICHTEXT_SETSTYLE_WITH_UNDO: specifies that this command will be undoable.
        - wxRICHTEXT_SETSTYLE_RENUMBER: specifies that numbering should start from
          @a startFrom, otherwise existing attributes are used.
        - wxRICHTEXT_SETSTYLE_SPECIFY_LEVEL: specifies that @a listLevel should be used
          as the level for all paragraphs, otherwise the current indentation will be used.

        @a def can be NULL to indicate that the existing list style should be used.

        @see SetListStyle(), PromoteList(), ClearListStyle()
    */
    virtual bool NumberList(const wxRichTextRange& range, wxRichTextListStyleDefinition* def = NULL, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO, int startFrom = 1, int specifiedLevel = -1);
    virtual bool NumberList(const wxRichTextRange& range, const wxString& defName, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO, int startFrom = 1, int specifiedLevel = -1);
    //@}

    //@{
    /**
        Promotes the list items within the given range.
        A positive @a promoteBy produces a smaller indent, and a negative number
        produces a larger indent. Pass flags to determine how the attributes are set.
        Either the style definition or the name of the style definition (in the current
        sheet) can be passed.

        @a flags is a bit list of the following:
        - wxRICHTEXT_SETSTYLE_WITH_UNDO: specifies that this command will be undoable.
        - wxRICHTEXT_SETSTYLE_RENUMBER: specifies that numbering should start from
          @a startFrom, otherwise existing attributes are used.
        - wxRICHTEXT_SETSTYLE_SPECIFY_LEVEL: specifies that @a listLevel should be used
          as the level for all paragraphs, otherwise the current indentation will be used.

        @see SetListStyle(), SetListStyle(), ClearListStyle()
    */
    virtual bool PromoteList(int promoteBy, const wxRichTextRange& range, wxRichTextListStyleDefinition* def = NULL, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO, int specifiedLevel = -1);
    virtual bool PromoteList(int promoteBy, const wxRichTextRange& range, const wxString& defName, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO, int specifiedLevel = -1);
    //@}

    /**
        Helper for NumberList and PromoteList, that does renumbering and promotion simultaneously
        @a def can be NULL/empty to indicate that the existing list style should be used.
    */
    virtual bool DoNumberList(const wxRichTextRange& range, const wxRichTextRange& promotionRange, int promoteBy, wxRichTextListStyleDefinition* def, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO, int startFrom = 1, int specifiedLevel = -1);

    /**
        Fills in the attributes for numbering a paragraph after previousParagraph.
    */
    virtual bool FindNextParagraphNumber(wxRichTextParagraph* previousParagraph, wxRichTextAttr& attr) const;

    /**
        Sets the properties for the given range, passing flags to determine how the
        attributes are set. You can merge properties or replace them.

        The end point of range is specified as the last character position of the span
        of text, plus one. So, for example, to set the properties for a character at
        position 5, use the range (5,6).

        @a flags may contain a bit list of the following values:
        - wxRICHTEXT_SETPROPERTIES_NONE: no flag.
        - wxRICHTEXT_SETPROPERTIES_WITH_UNDO: specifies that this operation should be
          undoable.
        - wxRICHTEXT_SETPROPERTIES_PARAGRAPHS_ONLY: specifies that the properties should only be
          applied to paragraphs, and not the content.
        - wxRICHTEXT_SETPROPERTIES_CHARACTERS_ONLY: specifies that the properties should only be
          applied to characters, and not the paragraph.
        - wxRICHTEXT_SETPROPERTIES_RESET: resets (clears) the existing properties before applying
          the new properties.
        - wxRICHTEXT_SETPROPERTIES_REMOVE: removes the specified properties.
    */
    virtual bool SetProperties(const wxRichTextRange& range, const wxRichTextProperties& properties, int flags = wxRICHTEXT_SETPROPERTIES_WITH_UNDO);

    /**
        Sets with undo the properties for the given object.
    */
    virtual bool SetObjectPropertiesWithUndo(wxRichTextObject& obj, const wxRichTextProperties& properties, wxRichTextObject* objToSet = NULL);

    /**
        Test if this whole range has character attributes of the specified kind. If any
        of the attributes are different within the range, the test fails. You
        can use this to implement, for example, bold button updating. style must have
        flags indicating which attributes are of interest.
    */
    virtual bool HasCharacterAttributes(const wxRichTextRange& range, const wxRichTextAttr& style) const;

    /**
        Test if this whole range has paragraph attributes of the specified kind. If any
        of the attributes are different within the range, the test fails. You
        can use this to implement, for example, centering button updating. style must have
        flags indicating which attributes are of interest.
    */
    virtual bool HasParagraphAttributes(const wxRichTextRange& range, const wxRichTextAttr& style) const;

    virtual wxRichTextObject* Clone() const;

    /**
        Prepares the content just before insertion (or after buffer reset).
        Currently is only called if undo mode is on.
    */
    virtual void PrepareContent(wxRichTextParagraphLayoutBox& container);

    /**
        Insert fragment into this box at the given position. If partialParagraph is true,
        it is assumed that the last (or only) paragraph is just a piece of data with no paragraph
        marker.
    */
    virtual bool InsertFragment(long position, wxRichTextParagraphLayoutBox& fragment);

    /**
        Make a copy of the fragment corresponding to the given range, putting it in @a fragment.
    */
    virtual bool CopyFragment(const wxRichTextRange& range, wxRichTextParagraphLayoutBox& fragment);

    /**
        Apply the style sheet to the buffer, for example if the styles have changed.
    */
    virtual bool ApplyStyleSheet(wxRichTextStyleSheet* styleSheet);

    void Copy(const wxRichTextParagraphLayoutBox& obj);

    void operator= (const wxRichTextParagraphLayoutBox& obj);

    /**
        Calculate ranges.
    */
    virtual void UpdateRanges();

    /**
        Get all the text.
    */
    virtual wxString GetText() const;

    /**
        Sets the default style, affecting the style currently being applied
        (for example, setting the default style to bold will cause subsequently
        inserted text to be bold).

        This is not cumulative - setting the default style will replace the previous
        default style.

        Setting it to a default attribute object makes new content take on the 'basic' style.
    */
    virtual bool SetDefaultStyle(const wxRichTextAttr& style);

    /**
        Returns the current default style, affecting the style currently being applied
        (for example, setting the default style to bold will cause subsequently
        inserted text to be bold).
    */
    virtual const wxRichTextAttr& GetDefaultStyle() const;

    /**
        Sets the basic (overall) style. This is the style of the whole
        buffer before further styles are applied, unlike the default style, which
        only affects the style currently being applied (for example, setting the default
        style to bold will cause subsequently inserted text to be bold).
    */
    virtual void SetBasicStyle(const wxRichTextAttr& style);

    /**
        Returns the basic (overall) style.

        This is the style of the whole buffer before further styles are applied,
        unlike the default style, which only affects the style currently being
        applied (for example, setting the default style to bold will cause
        subsequently inserted text to be bold).
    */
    virtual const wxRichTextAttr& GetBasicStyle() const;

    /**
        Invalidates the buffer. With no argument, invalidates whole buffer.
    */
    virtual void Invalidate(const wxRichTextRange& invalidRange = wxRICHTEXT_ALL);

    /**
        Do the (in)validation for this object only.
    */
    virtual void DoInvalidate(const wxRichTextRange& invalidRange);

    /**
        Do the (in)validation both up and down the hierarchy.
    */
    virtual void InvalidateHierarchy(const wxRichTextRange& invalidRange = wxRICHTEXT_ALL);

    /**
        Gather information about floating objects. If untilObj is non-NULL,
        will stop getting information if the current object is this, since we
        will collect the rest later.
    */
    virtual bool UpdateFloatingObjects(const wxRect& availableRect, wxRichTextObject* untilObj = NULL);

    /**
        Get invalid range, rounding to entire paragraphs if argument is true.
    */
    wxRichTextRange GetInvalidRange(bool wholeParagraphs = false) const;

    /**
        Returns @true if this object needs layout.
    */
    bool IsDirty() const;

    /**
        Returns the number of floating objects at this level.
    */
    int GetFloatingObjectCount() const;

    /**
        Returns a list of floating objects.
    */
    // C++: bool GetFloatingObjects(wxRichTextObjectList& objects) const;
    // Lua: %override [bool, wxRichTextObjectList]GetFloatingObjects();
    bool GetFloatingObjects(wxRichTextObjectList& objects) const;
};

/**
    @class wxRichTextBox

    This class implements a floating or inline text box, containing paragraphs.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextParagraphLayoutBox, wxRichTextObject, wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextBox: public wxRichTextParagraphLayoutBox
{
    //DECLARE_DYNAMIC_CLASS(wxRichTextBox)
public:
// Constructors

    /**
        Default constructor; optionally pass the parent object.
    */

    wxRichTextBox(wxRichTextObject* parent = NULL);

    /**
        Copy constructor.
    */

    wxRichTextBox(const wxRichTextBox& obj);

// Overridables

    virtual bool Draw(wxDC& dc, wxRichTextDrawingContext& context, const wxRichTextRange& range, const wxRichTextSelection& selection, const wxRect& rect, int descent, int style);

    virtual wxString GetXMLNodeName() const;

    virtual bool CanEditProperties() const;

    virtual bool EditProperties(wxWindow* parent, wxRichTextBuffer* buffer);

    virtual wxString GetPropertiesMenuLabel() const;

// Accessors

// Operations

    virtual wxRichTextObject* Clone() const;

    void Copy(const wxRichTextBox& obj);

protected:
};

/**
    @class wxRichTextField

    This class implements the general concept of a field, an object that represents
    additional functionality such as a footnote, a bookmark, a page number, a table
    of contents, and so on. Extra information (such as a bookmark name) can be stored
    in the object properties.

    Drawing, layout, and property editing is delegated to classes derived
    from wxRichTextFieldType, such as instances of wxRichTextFieldTypeStandard; this makes
    the use of fields an efficient method of introducing extra functionality, since
    most of the information required to draw a field (such as a bitmap) is kept centrally
    in a single field type definition.

    The FieldType property, accessed by SetFieldType/GetFieldType, is used to retrieve
    the field type definition. So be careful not to overwrite this property.

    wxRichTextField is derived from wxRichTextParagraphLayoutBox, which means that it
    can contain its own read-only content, refreshed when the application calls the UpdateField
    function. Whether a field is treated as a composite or a single graphic is determined
    by the field type definition. If using wxRichTextFieldTypeStandard, passing the display
    type wxRICHTEXT_FIELD_STYLE_COMPOSITE to the field type definition causes the field
    to behave like a composite; the other display styles display a simple graphic.
    When implementing a composite field, you will still need to derive from wxRichTextFieldTypeStandard
    or wxRichTextFieldType, if only to implement UpdateField to refresh the field content
    appropriately. wxRichTextFieldTypeStandard is only one possible implementation, but
    covers common needs especially for simple, static fields using text or a bitmap.

    Register field types on application initialisation with the static function
    wxRichTextBuffer::AddFieldType. They will be deleted automatically on 
    application exit.

    An application can write a field to a control with wxRichTextCtrl::WriteField,
    taking a field type, the properties for the field, and optional attributes.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextFieldTypeStandard, wxRichTextFieldType, wxRichTextParagraphLayoutBox, wxRichTextProperties, wxRichTextCtrl
*/

class %delete wxRichTextField: public wxRichTextParagraphLayoutBox
{
    //DECLARE_DYNAMIC_CLASS(wxRichTextField)
public:
// Constructors

    /**
        Default constructor; optionally pass the parent object.
    */

    wxRichTextField(const wxString& fieldType = wxEmptyString, wxRichTextObject* parent = NULL);

    /**
        Copy constructor.
    */

    wxRichTextField(const wxRichTextField& obj);

// Overridables

    virtual bool Draw(wxDC& dc, wxRichTextDrawingContext& context, const wxRichTextRange& range, const wxRichTextSelection& selection, const wxRect& rect, int descent, int style);

    virtual bool Layout(wxDC& dc, wxRichTextDrawingContext& context, const wxRect& rect, const wxRect& parentRect, int style);

    virtual bool GetRangeSize(const wxRichTextRange& range, wxSize& size, int& descent, wxDC& dc, wxRichTextDrawingContext& context, int flags, const wxPoint& position = wxNULLPOINT, const wxSize& parentSize = wxDefaultSize, wxArrayInt* partialExtents = NULL) const;

    virtual wxString GetXMLNodeName() const;

    virtual bool CanEditProperties() const;

    virtual bool EditProperties(wxWindow* parent, wxRichTextBuffer* buffer);

    virtual wxString GetPropertiesMenuLabel() const;

    virtual bool AcceptsFocus() const;

    virtual void CalculateRange(long start, long& end);

    /**
        If a field has children, we don't want the user to be able to edit it.
    */
    virtual bool IsAtomic() const;

    virtual bool IsEmpty() const;

    virtual bool IsTopLevel() const;

// Accessors

    void SetFieldType(const wxString& fieldType);
    wxString GetFieldType() const;

// Operations

    /**
        Update the field; delegated to the associated field type. This would typically expand the field to its value,
        if this is a dynamically changing and/or composite field.
     */
    virtual bool UpdateField(wxRichTextBuffer* buffer);

    virtual wxRichTextObject* Clone() const;

    void Copy(const wxRichTextField& obj);

protected:
};

/**
    @class wxRichTextFieldType

    The base class for custom field types. Each type definition handles one
    field type. Override functions to provide drawing, layout, updating and
    property editing functionality for a field.

    Register field types on application initialisation with the static function
    wxRichTextBuffer::AddFieldType. They will be deleted automatically on
    application exit.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextFieldTypeStandard, wxRichTextField, wxRichTextCtrl
*/

class %delete wxRichTextFieldType: public wxObject
{
    //DECLARE_CLASS(wxRichTextFieldType)
public:
    /**
        Creates a field type definition.
    */
    //wxRichTextFieldType(const wxString& name = wxEmptyString);

    /**
        Copy constructor.
    */
    //wxRichTextFieldType(const wxRichTextFieldType& fieldType);

    void Copy(const wxRichTextFieldType& fieldType);

    /**
        Draw the item, within the given range. Some objects may ignore the range (for
        example paragraphs) while others must obey it (lines, to implement wrapping)
    */
    virtual bool Draw(wxRichTextField* obj, wxDC& dc, wxRichTextDrawingContext& context, const wxRichTextRange& range, const wxRichTextSelection& selection, const wxRect& rect, int descent, int style);

    /**
        Lay the item out at the specified position with the given size constraint.
        Layout must set the cached size. @rect is the available space for the object,
        and @a parentRect is the container that is used to determine a relative size
        or position (for example if a text box must be 50% of the parent text box).
    */
    virtual bool Layout(wxRichTextField* obj, wxDC& dc, wxRichTextDrawingContext& context, const wxRect& rect, const wxRect& parentRect, int style);

    /**
        Returns the object size for the given range. Returns @false if the range
        is invalid for this object.
    */
    virtual bool GetRangeSize(wxRichTextField* obj, const wxRichTextRange& range, wxSize& size, int& descent, wxDC& dc, wxRichTextDrawingContext& context, int flags, const wxPoint& position = wxNULLPOINT, const wxSize& parentSize = wxDefaultSize, wxArrayInt* partialExtents = NULL) const;

    /**
        Returns @true if we can edit the object's properties via a GUI.
    */
    virtual bool CanEditProperties(wxRichTextField* obj) const;

    /**
        Edits the object's properties via a GUI.
    */
    virtual bool EditProperties(wxRichTextField* obj, wxWindow* parent, wxRichTextBuffer* buffer);

    /**
        Returns the label to be used for the properties context menu item.
    */
    virtual wxString GetPropertiesMenuLabel(wxRichTextField* obj) const;

    /**
        Update the field. This would typically expand the field to its value,
        if this is a dynamically changing and/or composite field.
     */
    virtual bool UpdateField(wxRichTextBuffer* buffer, wxRichTextField* obj);

    /**
        Returns @true if this object is top-level, i.e. contains its own paragraphs, such as a text box.
    */
    virtual bool IsTopLevel(wxRichTextField* obj) const;

    /**
        Sets the field type name. There should be a unique name per field type object.
    */
    void SetName(const wxString& name);

    /**
        Returns the field type name. There should be a unique name per field type object.
    */
    wxString GetName() const;

protected:

    wxString  m_name;
};

//WX_DECLARE_STRING_HASH_MAP(wxRichTextFieldType*, wxRichTextFieldTypeHashMap);

class %delete wxRichTextFieldTypeHashMap::iterator
{
    wxString first;
    wxRichTextFieldType *second;

    // operator used to compare with wxRichTextFieldTypeHashMap::end() iterator
    bool operator==(const wxRichTextFieldTypeHashMap::iterator& other) const;

    //wxRichTextFieldTypeHashMap::iterator& operator++(); // it just returns *this
    void operator++(); // it's best if we don't return the iterator
};

class %delete wxRichTextFieldTypeHashMap
{
    // Selected functions from the base wxHashMap class
    // The method names are capitalized to avoid conflict with the reserved word 'end'.
    %rename Begin wxRichTextFieldTypeHashMap::iterator begin() const; // not const iterator
    %rename Clear void clear();
    %rename Count size_t count(wxString &key) const;
    %rename Empty bool empty() const;
    %rename End wxRichTextFieldTypeHashMap::iterator end() const; // not const iterator
    %rename Erase size_t erase(wxString &key);
    %rename Find wxRichTextFieldTypeHashMap::iterator find(wxString &key);
    //%rename Insert Insert_Result insert(wxRichTextFieldType *v);
    %rename Size size_t size() const;
};

/**
    @class wxRichTextFieldTypeStandard

    A field type that can handle fields with text or bitmap labels, with a small range
    of styles for implementing rectangular fields and fields that can be used for start
    and end tags.

    The border, text and background colours can be customised; the default is
    white text on a black background.

    The following display styles can be used.

    @beginStyleTable
    @style{wxRICHTEXT_FIELD_STYLE_COMPOSITE}
           Creates a composite field; you will probably need to derive a new class to implement UpdateField.
    @style{wxRICHTEXT_FIELD_STYLE_RECTANGLE}
           Shows a rounded rectangle background.
    @style{wxRICHTEXT_FIELD_STYLE_NO_BORDER}
           Suppresses the background and border; mostly used with a bitmap label.
    @style{wxRICHTEXT_FIELD_STYLE_START_TAG}
           Shows a start tag background, with the pointy end facing right.
    @style{wxRICHTEXT_FIELD_STYLE_END_TAG}
           Shows an end tag background, with the pointy end facing left.
    @endStyleTable

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextFieldType, wxRichTextField, wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextFieldTypeStandard: public wxRichTextFieldType
{
    //DECLARE_CLASS(wxRichTextFieldTypeStandard)
public:

    enum { wxRICHTEXT_FIELD_STYLE_COMPOSITE = 0x01,
           wxRICHTEXT_FIELD_STYLE_RECTANGLE = 0x02,
           wxRICHTEXT_FIELD_STYLE_NO_BORDER = 0x04,
           wxRICHTEXT_FIELD_STYLE_START_TAG = 0x08,
           wxRICHTEXT_FIELD_STYLE_END_TAG = 0x10
         };

    /**
        Constructor, creating a field type definition with a text label.

        @param parent
            The name of the type definition. This must be unique, and is the type
            name used when adding a field to a control.
        @param label
            The text label to be shown on the field.
        @param displayStyle
            The display style: one of wxRICHTEXT_FIELD_STYLE_RECTANGLE,
            wxRICHTEXT_FIELD_STYLE_NO_BORDER, wxRICHTEXT_FIELD_STYLE_START_TAG,
            wxRICHTEXT_FIELD_STYLE_END_TAG.

    */
    wxRichTextFieldTypeStandard(const wxString& name, const wxString& label, int displayStyle = wxRichTextFieldTypeStandard::wxRICHTEXT_FIELD_STYLE_RECTANGLE);

    /**
        Constructor, creating a field type definition with a bitmap label.

        @param parent
            The name of the type definition. This must be unique, and is the type
            name used when adding a field to a control.
        @param label
            The bitmap label to be shown on the field.
        @param displayStyle
            The display style: one of wxRICHTEXT_FIELD_STYLE_RECTANGLE,
            wxRICHTEXT_FIELD_STYLE_NO_BORDER, wxRICHTEXT_FIELD_STYLE_START_TAG,
            wxRICHTEXT_FIELD_STYLE_END_TAG.

    */
    wxRichTextFieldTypeStandard(const wxString& name, const wxBitmap& bitmap, int displayStyle = wxRichTextFieldTypeStandard::wxRICHTEXT_FIELD_STYLE_NO_BORDER);

    /**
        The default constructor.

    */
    wxRichTextFieldTypeStandard();

    /**
        The copy constructor.

    */
    wxRichTextFieldTypeStandard(const wxRichTextFieldTypeStandard& field);

    /**
        Initialises the object.
    */
    void Init();

    /**
        Copies the object.
    */
    void Copy(const wxRichTextFieldTypeStandard& field);

    /**
        The assignment operator.
    */
    void operator=(const wxRichTextFieldTypeStandard& field);

    /**
        Draw the item, within the given range. Some objects may ignore the range (for
        example paragraphs) while others must obey it (lines, to implement wrapping)
    */
    virtual bool Draw(wxRichTextField* obj, wxDC& dc, wxRichTextDrawingContext& context, const wxRichTextRange& range, const wxRichTextSelection& selection, const wxRect& rect, int descent, int style);

    /**
        Lay the item out at the specified position with the given size constraint.
        Layout must set the cached size. @rect is the available space for the object,
        and @a parentRect is the container that is used to determine a relative size
        or position (for example if a text box must be 50% of the parent text box).
    */
    virtual bool Layout(wxRichTextField* obj, wxDC& dc, wxRichTextDrawingContext& context, const wxRect& rect, const wxRect& parentRect, int style);

    /**
        Returns the object size for the given range. Returns @false if the range
        is invalid for this object.
    */
    virtual bool GetRangeSize(wxRichTextField* obj, const wxRichTextRange& range, wxSize& size, int& descent, wxDC& dc, wxRichTextDrawingContext& context, int flags, const wxPoint& position = wxNULLPOINT, const wxSize& parentSize = wxDefaultSize, wxArrayInt* partialExtents = NULL) const;

    /**
        Get the size of the field, given the label, font size, and so on.
    */
    wxSize GetSize(wxRichTextField* obj, wxDC& dc, wxRichTextDrawingContext& context, int style) const;

    /**
        Returns @true if the display type is wxRICHTEXT_FIELD_STYLE_COMPOSITE, @false otherwise.
    */
    virtual bool IsTopLevel(wxRichTextField* obj) const;

    /**
        Sets the text label for fields of this type.
    */
    void SetLabel(const wxString& label);

    /**
        Returns the text label for fields of this type.
    */
    const wxString& GetLabel() const;

    /**
        Sets the bitmap label for fields of this type.
    */
    void SetBitmap(const wxBitmap& bitmap);

    /**
        Gets the bitmap label for fields of this type.
    */
    const wxBitmap& GetBitmap() const;

    /**
        Gets the display style for fields of this type.
    */
    int GetDisplayStyle() const;

    /**
        Sets the display style for fields of this type.
    */
    void SetDisplayStyle(int displayStyle);

    /**
        Gets the font used for drawing the text label.
    */
    const wxFont& GetFont() const;

    /**
        Sets the font used for drawing the text label.
    */
    void SetFont(const wxFont& font);

    /**
        Gets the colour used for drawing the text label.
    */
    const wxColour& GetTextColour() const;

    /**
        Sets the colour used for drawing the text label.
    */
    void SetTextColour(const wxColour& colour);

    /**
        Gets the colour used for drawing the field border.
    */
    const wxColour& GetBorderColour() const;

    /**
        Sets the colour used for drawing the field border.
    */
    void SetBorderColour(const wxColour& colour);

    /**
        Gets the colour used for drawing the field background.
    */
    const wxColour& GetBackgroundColour() const;

    /**
        Sets the colour used for drawing the field background.
    */
    void SetBackgroundColour(const wxColour& colour);

    /**
        Sets the vertical padding (the distance between the border and the text).
    */
    void SetVerticalPadding(int padding);

    /**
        Gets the vertical padding (the distance between the border and the text).
    */
    int GetVerticalPadding() const;

    /**
        Sets the horizontal padding (the distance between the border and the text).
    */
    void SetHorizontalPadding(int padding);

    /**
        Sets the horizontal padding (the distance between the border and the text).
    */
    int GetHorizontalPadding() const;

    /**
        Sets the horizontal margin surrounding the field object.
    */
    void SetHorizontalMargin(int margin);

    /**
        Gets the horizontal margin surrounding the field object.
    */
    int GetHorizontalMargin() const;

    /**
        Sets the vertical margin surrounding the field object.
    */
    void SetVerticalMargin(int margin);

    /**
        Gets the vertical margin surrounding the field object.
    */
    int GetVerticalMargin() const;

protected:

    wxString    m_label;
    int         m_displayStyle;
    wxFont      m_font;
    wxColour    m_textColour;
    wxColour    m_borderColour;
    wxColour    m_backgroundColour;
    int         m_verticalPadding;
    int         m_horizontalPadding;
    int         m_horizontalMargin;
    int         m_verticalMargin;
    wxBitmap    m_bitmap;
};

/**
    @class wxRichTextLine

    This object represents a line in a paragraph, and stores
    offsets from the start of the paragraph representing the
    start and end positions of the line.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextLine
{
public:
// Constructors

    wxRichTextLine(wxRichTextParagraph* parent);
    wxRichTextLine(const wxRichTextLine& obj);
    //virtual ~wxRichTextLine() {}

// Overridables

// Accessors

    /**
        Sets the range associated with this line.
    */
    void SetRange(const wxRichTextRange& range);
    /**
        Sets the range associated with this line.
    */
    void SetRange(long from, long to);

    /**
        Returns the parent paragraph.
    */
    wxRichTextParagraph* GetParent();

    /**
        Returns the range.
    */
    const wxRichTextRange& GetRange() const;
    /**
        Returns the range.
    */
    wxRichTextRange& GetRange();

    /**
        Returns the absolute range.
    */
    wxRichTextRange GetAbsoluteRange() const;

    /**
        Returns the line size as calculated by Layout.
    */
    virtual wxSize GetSize() const;

    /**
        Sets the line size as calculated by Layout.
    */
    virtual void SetSize(const wxSize& sz);

    /**
        Returns the object position relative to the parent.
    */
    virtual wxPoint GetPosition() const;

    /**
        Sets the object position relative to the parent.
    */
    virtual void SetPosition(const wxPoint& pos);

    /**
        Returns the absolute object position.
    */
    virtual wxPoint GetAbsolutePosition() const;

    /**
        Returns the rectangle enclosing the line.
    */
    virtual wxRect GetRect() const;

    /**
        Sets the stored descent.
    */
    void SetDescent(int descent);

    /**
        Returns the stored descent.
    */
    int GetDescent() const;

#if wxRICHTEXT_USE_OPTIMIZED_LINE_DRAWING
    wxArrayInt& GetObjectSizes();
    const wxArrayInt& GetObjectSizes() const;
#endif

// Operations

    /**
        Initialises the object.
    */
    void Init(wxRichTextParagraph* parent);

    /**
        Copies from @a obj.
    */
    void Copy(const wxRichTextLine& obj);

    virtual wxRichTextLine* Clone() const;

protected:

    // The range of the line (start position to end position)
    // This is relative to the parent paragraph.
    wxRichTextRange     m_range;

    // Size and position measured relative to top of paragraph
    wxPoint             m_pos;
    wxSize              m_size;

    // Maximum descent for this line (location of text baseline)
    int                 m_descent;

    // The parent object
    wxRichTextParagraph* m_parent;

#if wxRICHTEXT_USE_OPTIMIZED_LINE_DRAWING
    wxArrayInt          m_objectSizes;
#endif
};

#if wxRICHTEXT_USE_PARTIAL_TEXT_EXTENTS && wxRICHTEXT_USE_OPTIMIZED_LINE_DRAWING
class wxRichTextLineList : public wxList
{
    // Use the wxList methods, see also wxNode
};
#endif // wxRICHTEXT_USE_PARTIAL_TEXT_EXTENTS && wxRICHTEXT_USE_OPTIMIZED_LINE_DRAWING

/**
    @class wxRichTextParagraph

    This object represents a single paragraph containing various objects such as text content, images, and further paragraph layout objects.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextParagraph: public wxRichTextCompositeObject
{
    //DECLARE_DYNAMIC_CLASS(wxRichTextParagraph)
public:
// Constructors

    /**
        Constructor taking a parent and style.
    */
    wxRichTextParagraph(wxRichTextObject* parent = NULL, wxRichTextAttr* style = NULL);
    /**
        Constructor taking a text string, a parent and paragraph and character attributes.
    */
    wxRichTextParagraph(const wxString& text, wxRichTextObject* parent = NULL, wxRichTextAttr* paraStyle = NULL, wxRichTextAttr* charStyle = NULL);
    virtual ~wxRichTextParagraph();
    wxRichTextParagraph(const wxRichTextParagraph& obj);

// Overridables

    virtual bool Draw(wxDC& dc, wxRichTextDrawingContext& context, const wxRichTextRange& range, const wxRichTextSelection& selection, const wxRect& rect, int descent, int style);

    virtual bool Layout(wxDC& dc, wxRichTextDrawingContext& context, const wxRect& rect, const wxRect& parentRect, int style);

    virtual bool GetRangeSize(const wxRichTextRange& range, wxSize& size, int& descent, wxDC& dc, wxRichTextDrawingContext& context, int flags, const wxPoint& position = wxNULLPOINT, const wxSize& parentSize = wxDefaultSize, wxArrayInt* partialExtents = NULL) const;

    virtual bool FindPosition(wxDC& dc, wxRichTextDrawingContext& context, long index, wxPoint& pt, int* height, bool forceLineStart);

    virtual int HitTest(wxDC& dc, wxRichTextDrawingContext& context, const wxPoint& pt, long& textPosition, wxRichTextObject** obj, wxRichTextObject** contextObj, int flags = 0);

    virtual void CalculateRange(long start, long& end);

    virtual wxString GetXMLNodeName() const;

// Accessors

    /**
        Returns the cached lines.
    */
#if wxRICHTEXT_USE_PARTIAL_TEXT_EXTENTS && wxRICHTEXT_USE_OPTIMIZED_LINE_DRAWING
    wxRichTextLineList& GetLines();
#endif // wxRICHTEXT_USE_PARTIAL_TEXT_EXTENTS && wxRICHTEXT_USE_OPTIMIZED_LINE_DRAWING

// Operations

    /**
        Copies the object.
    */
    void Copy(const wxRichTextParagraph& obj);

    virtual wxRichTextObject* Clone() const;

    /**
        Clears the cached lines.
    */
    void ClearLines();

// Implementation

    /**
        Applies paragraph styles such as centering to the wrapped lines.
    */
    virtual void ApplyParagraphStyle(wxRichTextLine* line, const wxRichTextAttr& attr, const wxRect& rect, wxDC& dc);

    /**
        Inserts text at the given position.
    */
    virtual bool InsertText(long pos, const wxString& text);

    /**
        Splits an object at this position if necessary, and returns
        the previous object, or NULL if inserting at the beginning.
    */
    virtual wxRichTextObject* SplitAt(long pos, wxRichTextObject** previousObject = NULL);

    /**
        Moves content to a list from this point.
    */
    virtual void MoveToList(wxRichTextObject* obj, wxList& list);

    /**
        Adds content back from a list.
    */
    virtual void MoveFromList(wxList& list);

    /**
        Returns the plain text searching from the start or end of the range.
        The resulting string may be shorter than the range given.
    */
    bool GetContiguousPlainText(wxString& text, const wxRichTextRange& range, bool fromStart = true);

    /**
        Finds a suitable wrap position. @a wrapPosition is the last position in the line to the left
        of the split.
    */
    bool FindWrapPosition(const wxRichTextRange& range, wxDC& dc, wxRichTextDrawingContext& context, int availableSpace, long& wrapPosition, wxArrayInt* partialExtents);

    /**
        Finds the object at the given position.
    */
    wxRichTextObject* FindObjectAtPosition(long position);

    /**
        Returns the bullet text for this paragraph.
    */
    wxString GetBulletText();

    /**
        Allocates or reuses a line object.
    */
    wxRichTextLine* AllocateLine(int pos);

    /**
        Clears remaining unused line objects, if any.
    */
    bool ClearUnusedLines(int lineCount);

    /**
        Returns combined attributes of the base style, paragraph style and character style. We use this to dynamically
        retrieve the actual style.
    */
    wxRichTextAttr GetCombinedAttributes(const wxRichTextAttr& contentStyle, bool includingBoxAttr = false) const;

    /**
        Returns the combined attributes of the base style and paragraph style.
    */
    wxRichTextAttr GetCombinedAttributes(bool includingBoxAttr = false) const;

    /**
        Returns the first position from pos that has a line break character.
    */
    long GetFirstLineBreakPosition(long pos);

    /**
        Creates a default tabstop array.
    */
    static void InitDefaultTabs();

    /**
        Clears the default tabstop array.
    */
    static void ClearDefaultTabs();

    /**
        Returns the default tabstop array.
    */
    static const wxArrayInt& GetDefaultTabs();
};

/**
    @class wxRichTextPlainText

    This object represents a single piece of text.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextPlainText: public wxRichTextObject
{
    //DECLARE_DYNAMIC_CLASS(wxRichTextPlainText)
public:
// Constructors

    /**
        Constructor.
    */
    wxRichTextPlainText(const wxString& text = wxEmptyString, wxRichTextObject* parent = NULL, wxRichTextAttr* style = NULL);

    /**
        Copy constructor.
    */
    wxRichTextPlainText(const wxRichTextPlainText& obj);

// Overridables

    virtual bool Draw(wxDC& dc, wxRichTextDrawingContext& context, const wxRichTextRange& range, const wxRichTextSelection& selection, const wxRect& rect, int descent, int style);

    virtual bool Layout(wxDC& dc, wxRichTextDrawingContext& context, const wxRect& rect, const wxRect& parentRect, int style);

    virtual bool AdjustAttributes(wxRichTextAttr& attr, wxRichTextDrawingContext& context);

    virtual bool GetRangeSize(const wxRichTextRange& range, wxSize& size, int& descent, wxDC& dc, wxRichTextDrawingContext& context, int flags, const wxPoint& position = wxNULLPOINT, const wxSize& parentSize = wxDefaultSize, wxArrayInt* partialExtents = NULL) const;

    virtual wxString GetTextForRange(const wxRichTextRange& range) const;

    virtual wxRichTextObject* DoSplit(long pos);

    virtual void CalculateRange(long start, long& end);

    virtual bool DeleteRange(const wxRichTextRange& range);

    virtual bool IsEmpty() const;

    virtual bool CanMerge(wxRichTextObject* object, wxRichTextDrawingContext& context) const;

    virtual bool Merge(wxRichTextObject* object, wxRichTextDrawingContext& context);

    virtual void Dump(wxTextOutputStream& stream);

    virtual bool CanSplit(wxRichTextDrawingContext& context) const;

    virtual wxRichTextObject* Split(wxRichTextDrawingContext& context);

    /**
        Get the first position from pos that has a line break character.
    */
    long GetFirstLineBreakPosition(long pos);

    /// Does this object take note of paragraph attributes? Text and image objects don't.
    virtual bool UsesParagraphAttributes() const;

#if wxUSE_XML
    virtual bool ImportFromXML(wxRichTextBuffer* buffer, wxXmlNode* node, wxRichTextXMLHandler* handler, bool* recurse);
#endif

#if wxRICHTEXT_HAVE_DIRECT_OUTPUT
    virtual bool ExportXML(wxOutputStream& stream, int indent, wxRichTextXMLHandler* handler);
#endif

#if wxRICHTEXT_HAVE_XMLDOCUMENT_OUTPUT
    virtual bool ExportXML(wxXmlNode* parent, wxRichTextXMLHandler* handler);
#endif

    virtual wxString GetXMLNodeName() const;

// Accessors

    /**
        Returns the text.
    */
    const wxString& GetText() const;

    /**
        Sets the text.
    */
    void SetText(const wxString& text);

// Operations

    // Copies the text object,
    void Copy(const wxRichTextPlainText& obj);

    // Clones the text object.
    virtual wxRichTextObject* Clone() const;

private:
    bool DrawTabbedString(wxDC& dc, const wxRichTextAttr& attr, const wxRect& rect, wxString& str, wxCoord& x, wxCoord& y, bool selected);

protected:
    wxString    m_text;
};

/**
    @class wxRichTextImageBlock

    This class stores information about an image, in binary in-memory form.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextImageBlock: public wxObject
{
public:
    /**
        Constructor.
    */
    wxRichTextImageBlock();

    /**
        Copy constructor.
    */
    wxRichTextImageBlock(const wxRichTextImageBlock& block);
    virtual ~wxRichTextImageBlock();

    /**
        Initialises the block.
    */
    void Init();

    /**
        Clears the block.
    */

    void Clear();

    /**
        Load the original image into a memory block.
        If the image is not a JPEG, we must convert it into a JPEG
        to conserve space.
        If it's not a JPEG we can make use of @a image, already scaled, so we don't have to
        load the image a second time.
    */
    virtual bool MakeImageBlock(const wxString& filename, wxBitmapType imageType,
                                wxImage& image, bool convertToJPEG = true);

    /**
        Make an image block from the wxImage in the given
        format.
    */
    virtual bool MakeImageBlock(wxImage& image, wxBitmapType imageType, int quality = 80);

    /**
        Uses a const wxImage for efficiency, but can't set quality (only relevant for JPEG)
    */
    virtual bool MakeImageBlockDefaultQuality(const wxImage& image, wxBitmapType imageType);

    /**
        Makes the image block.
    */
    virtual bool DoMakeImageBlock(const wxImage& image, wxBitmapType imageType);

    /**
        Writes the block to a file.
    */
    bool Write(const wxString& filename);

    /**
        Writes the data in hex to a stream.
    */
    bool WriteHex(wxOutputStream& stream);

    /**
        Reads the data in hex from a stream.
    */
    bool ReadHex(wxInputStream& stream, int length, wxBitmapType imageType);

    /**
        Copy from @a block.
    */
    void Copy(const wxRichTextImageBlock& block);

    // Load a wxImage from the block
    /**
    */
    bool Load(wxImage& image);

// Operators

    /**
        Assignment operation.
    */
    void operator=(const wxRichTextImageBlock& block);

// Accessors

    /**
        Returns the raw data.
    */
    unsigned char* GetData() const;

    /**
        Returns the data size in bytes.
    */
    size_t GetDataSize() const;

    /**
        Returns the image type.
    */
    wxBitmapType GetImageType() const;

    /**
    */
    void SetData(unsigned char* image);

    /**
        Sets the data size.
    */
    void SetDataSize(size_t size);

    /**
        Sets the image type.
    */
    void SetImageType(wxBitmapType imageType);

    /**
        Returns @true if the data is non-NULL.
    */
    bool IsOk() const;
    bool Ok() const;

    /**
        Gets the extension for the block's type.
    */
    wxString GetExtension() const;

/// Implementation

    /**
        Allocates and reads from a stream as a block of memory.
    */
    static unsigned char* ReadBlock(wxInputStream& stream, size_t size);

    /**
        Allocates and reads from a file as a block of memory.
    */
    static unsigned char* ReadBlock(const wxString& filename, size_t size);

    /**
        Writes a memory block to stream.
    */
    static bool WriteBlock(wxOutputStream& stream, unsigned char* block, size_t size);

    /**
        Writes a memory block to a file.
    */
    static bool WriteBlock(const wxString& filename, unsigned char* block, size_t size);

protected:
    // Size in bytes of the image stored.
    // This is in the raw, original form such as a JPEG file.
    unsigned char*      m_data;
    size_t              m_dataSize;
    wxBitmapType        m_imageType;
};

/**
    @class wxRichTextImage

    This class implements a graphic object.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextBuffer, wxRichTextCtrl, wxRichTextImageBlock
*/

class %delete wxRichTextImage: public wxRichTextObject
{
    //DECLARE_DYNAMIC_CLASS(wxRichTextImage)
public:
// Constructors

    /**
        Default constructor.
    */
    wxRichTextImage(wxRichTextObject* parent = NULL);

    /**
        Creates a wxRichTextImage from a wxImage.
    */
    wxRichTextImage(const wxImage& image, wxRichTextObject* parent = NULL, wxRichTextAttr* charStyle = NULL);

    /**
        Creates a wxRichTextImage from an image block.
    */
    wxRichTextImage(const wxRichTextImageBlock& imageBlock, wxRichTextObject* parent = NULL, wxRichTextAttr* charStyle = NULL);

    /**
        Copy constructor.
    */
    wxRichTextImage(const wxRichTextImage& obj);

    /**
        Destructor.
    */
    //~wxRichTextImage();

    /**
        Initialisation.
    */
    void Init();

// Overridables

    virtual bool Draw(wxDC& dc, wxRichTextDrawingContext& context, const wxRichTextRange& range, const wxRichTextSelection& selection, const wxRect& rect, int descent, int style);

    virtual bool Layout(wxDC& dc, wxRichTextDrawingContext& context, const wxRect& rect, const wxRect& parentRect, int style);

    virtual bool GetRangeSize(const wxRichTextRange& range, wxSize& size, int& descent, wxDC& dc, wxRichTextDrawingContext& context, int flags, const wxPoint& position = wxNULLPOINT, const wxSize& parentSize = wxDefaultSize, wxArrayInt* partialExtents = NULL) const;

    /**
        Returns the 'natural' size for this object - the image size.
    */
    virtual wxTextAttrSize GetNaturalSize() const;

    virtual bool IsEmpty() const;

    virtual bool CanEditProperties() const;

    virtual bool EditProperties(wxWindow* parent, wxRichTextBuffer* buffer);

    virtual wxString GetPropertiesMenuLabel() const;

    virtual bool UsesParagraphAttributes() const;

#if wxUSE_XML
    virtual bool ImportFromXML(wxRichTextBuffer* buffer, wxXmlNode* node, wxRichTextXMLHandler* handler, bool* recurse);
#endif

#if wxRICHTEXT_HAVE_DIRECT_OUTPUT
    virtual bool ExportXML(wxOutputStream& stream, int indent, wxRichTextXMLHandler* handler);
#endif

#if wxRICHTEXT_HAVE_XMLDOCUMENT_OUTPUT
    virtual bool ExportXML(wxXmlNode* parent, wxRichTextXMLHandler* handler);
#endif

    // Images can be floatable (optionally).
    virtual bool IsFloatable() const;

    virtual wxString GetXMLNodeName() const;

// Accessors

    /**
        Returns the image cache (a scaled bitmap).
    */
    const wxBitmap& GetImageCache() const;

    /**
        Sets the image cache.
    */
    void SetImageCache(const wxBitmap& bitmap);

    /**
        Resets the image cache.
    */
    void ResetImageCache();

    /**
        Returns the image block containing the raw data.
    */
    wxRichTextImageBlock& GetImageBlock();

// Operations

    /**
        Copies the image object.
    */
    void Copy(const wxRichTextImage& obj);

    /**
        Clones the image object.
    */
    virtual wxRichTextObject* Clone() const;

    /**
        Creates a cached image at the required size.
    */
    !%wxchkver_3_1_0 virtual bool LoadImageCache(wxDC& dc, bool resetCache = false, const wxSize& parentSize = wxDefaultSize);
    %wxchkver_3_1_0 virtual bool LoadImageCache(wxDC& dc, wxRichTextDrawingContext& context, wxSize& retImageSize, bool resetCache = false, const wxSize& parentSize = wxDefaultSize);

    /**
        Gets the original image size.
    */
    wxSize GetOriginalImageSize() const;

    /**
        Sets the original image size.
    */
    void SetOriginalImageSize(const wxSize& sz);

protected:
    wxRichTextImageBlock    m_imageBlock;
    wxBitmap                m_imageCache;
    wxSize                  m_originalImageSize;
};

//class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextCommand;
//class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextAction;


/**
    @class wxRichTextBuffer

    This is a kind of paragraph layout box, used to represent the whole buffer.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextParagraphLayoutBox, wxRichTextCtrl
*/

class %delete wxRichTextBuffer: public wxRichTextParagraphLayoutBox
{
    //DECLARE_DYNAMIC_CLASS(wxRichTextBuffer)
public:
// Constructors

    /**
        Default constructor.
    */
    wxRichTextBuffer();

    /**
        Copy constructor.
    */
    wxRichTextBuffer(const wxRichTextBuffer& obj);

    //virtual ~wxRichTextBuffer() ;

// Accessors

    /**
        Returns the command processor.
        A text buffer always creates its own command processor when it is initialized.
    */
    wxCommandProcessor* GetCommandProcessor() const;

    /**
        Sets style sheet, if any. This will allow the application to use named character and paragraph
        styles found in the style sheet.

        Neither the buffer nor the control owns the style sheet so must be deleted by the application.
    */
    void SetStyleSheet(wxRichTextStyleSheet* styleSheet);

    /**
        Returns the style sheet.
    */
    virtual wxRichTextStyleSheet* GetStyleSheet() const;

    /**
        Sets the style sheet and sends a notification of the change.
    */
    bool SetStyleSheetAndNotify(wxRichTextStyleSheet* sheet);

    /**
        Pushes the style sheet to the top of the style sheet stack.
    */
    bool PushStyleSheet(wxRichTextStyleSheet* styleSheet);

    /**
        Pops the style sheet from the top of the style sheet stack.
    */
    wxRichTextStyleSheet* PopStyleSheet();

    /**
        Returns the table storing fonts, for quick access and font reuse.
    */
    wxRichTextFontTable& GetFontTable();

    /**
        Returns the table storing fonts, for quick access and font reuse.
    */
    const wxRichTextFontTable& GetFontTable() const;

    /**
        Sets table storing fonts, for quick access and font reuse.
    */
    void SetFontTable(const wxRichTextFontTable& table);

    /**
        Sets the scale factor for displaying fonts, for example for more comfortable
        editing.
    */
    void SetFontScale(double fontScale);

    /**
        Returns the scale factor for displaying fonts, for example for more comfortable
        editing.
    */
    double GetFontScale() const;

    /**
        Sets the scale factor for displaying certain dimensions such as indentation and
        inter-paragraph spacing. This can be useful when editing in a small control
        where you still want legible text, but a minimum of wasted white space.
    */
    void SetDimensionScale(double dimScale);

    /**
        Returns the scale factor for displaying certain dimensions such as indentation
        and inter-paragraph spacing.
    */
    double GetDimensionScale() const;

// Operations

    /**
        Initialisation.
    */
    void Init();

    /**
        Clears the buffer, adds an empty paragraph, and clears the command processor.
    */
    virtual void ResetAndClearCommands();

#if wxUSE_FFILE && wxUSE_STREAMS
    //@{
    /**
        Loads content from a file.
        Not all handlers will implement file loading.
    */
    virtual bool LoadFile(const wxString& filename, wxRichTextFileType type = wxRICHTEXT_TYPE_ANY);
    //@}

    //@{
    /**
        Saves content to a file.
        Not all handlers will implement file saving.
    */
    virtual bool SaveFile(const wxString& filename, wxRichTextFileType type = wxRICHTEXT_TYPE_ANY);
    //@}
#endif // wxUSE_FFILE

#if wxUSE_STREAMS
    //@{
    /**
        Loads content from a stream.
        Not all handlers will implement loading from a stream.
    */
    virtual bool LoadFile(wxInputStream& stream, wxRichTextFileType type = wxRICHTEXT_TYPE_ANY);
    //@}

    //@{
    /**
        Saves content to a stream.
        Not all handlers will implement saving to a stream.
    */
    virtual bool SaveFile(wxOutputStream& stream, wxRichTextFileType type = wxRICHTEXT_TYPE_ANY);
    //@}
#endif // wxUSE_STREAMS

    /**
        Sets the handler flags, controlling loading and saving.
    */
    void SetHandlerFlags(int flags);

    /**
        Gets the handler flags, controlling loading and saving.
    */
    int GetHandlerFlags() const;

    /**
        Convenience function to add a paragraph of text.
    */
    virtual wxRichTextRange AddParagraph(const wxString& text, wxRichTextAttr* paraStyle = NULL);

    /**
        Begin collapsing undo/redo commands. Note that this may not work properly
        if combining commands that delete or insert content, changing ranges for
        subsequent actions.

        @a cmdName should be the name of the combined command that will appear
        next to Undo and Redo in the edit menu.
    */
    virtual bool BeginBatchUndo(const wxString& cmdName);

    /**
        End collapsing undo/redo commands.
    */
    virtual bool EndBatchUndo();

    /**
        Returns @true if we are collapsing commands.
    */
    virtual bool BatchingUndo() const;

    /**
        Submit the action immediately, or delay according to whether collapsing is on.
    */
    virtual bool SubmitAction(wxRichTextAction* action);

    /**
        Returns the collapsed command.
    */
    virtual wxRichTextCommand* GetBatchedCommand() const;

    /**
        Begin suppressing undo/redo commands. The way undo is suppressed may be implemented
        differently by each command. If not dealt with by a command implementation, then
        it will be implemented automatically by not storing the command in the undo history
        when the action is submitted to the command processor.
    */
    virtual bool BeginSuppressUndo();

    /**
        End suppressing undo/redo commands.
    */
    virtual bool EndSuppressUndo();

    /**
        Are we suppressing undo??
    */
    virtual bool SuppressingUndo() const;

    /**
        Copy the range to the clipboard.
    */
    virtual bool CopyToClipboard(const wxRichTextRange& range);

    /**
        Paste the clipboard content to the buffer.
    */
    virtual bool PasteFromClipboard(long position);

    /**
        Returns @true if we can paste from the clipboard.
    */
    virtual bool CanPasteFromClipboard() const;

    /**
        Begin using a style.
    */
    virtual bool BeginStyle(const wxRichTextAttr& style);

    /**
        End the style.
    */
    virtual bool EndStyle();

    /**
        End all styles.
    */
    virtual bool EndAllStyles();

    /**
        Clears the style stack.
    */
    virtual void ClearStyleStack();

    /**
        Returns the size of the style stack, for example to check correct nesting.
    */
    virtual size_t GetStyleStackSize() const;

    /**
        Begins using bold.
    */
    bool BeginBold();

    /**
        Ends using bold.
    */
    bool EndBold();

    /**
        Begins using italic.
    */
    bool BeginItalic();

    /**
        Ends using italic.
    */
    bool EndItalic();

    /**
        Begins using underline.
    */
    bool BeginUnderline();

    /**
        Ends using underline.
    */
    bool EndUnderline();

    /**
        Begins using point size.
    */
    bool BeginFontSize(int pointSize);

    /**
        Ends using point size.
    */
    bool EndFontSize();

    /**
        Begins using this font.
    */
    bool BeginFont(const wxFont& font);

    /**
        Ends using a font.
    */
    bool EndFont();

    /**
        Begins using this colour.
    */
    bool BeginTextColour(const wxColour& colour);

    /**
        Ends using a colour.
    */
    bool EndTextColour();

    /**
        Begins using alignment.
    */
    bool BeginAlignment(wxTextAttrAlignment alignment);

    /**
        Ends alignment.
    */
    bool EndAlignment();

    /**
        Begins using @a leftIndent for the left indent, and optionally @a leftSubIndent for
        the sub-indent. Both are expressed in tenths of a millimetre.

        The sub-indent is an offset from the left of the paragraph, and is used for all
        but the first line in a paragraph. A positive value will cause the first line to appear
        to the left of the subsequent lines, and a negative value will cause the first line to be
        indented relative to the subsequent lines.
    */
    bool BeginLeftIndent(int leftIndent, int leftSubIndent = 0);

    /**
        Ends left indent.
    */
    bool EndLeftIndent();

    /**
        Begins a right indent, specified in tenths of a millimetre.
    */
    bool BeginRightIndent(int rightIndent);

    /**
        Ends right indent.
    */
    bool EndRightIndent();

    /**
        Begins paragraph spacing; pass the before-paragraph and after-paragraph spacing
        in tenths of a millimetre.
    */
    bool BeginParagraphSpacing(int before, int after);

    /**
        Ends paragraph spacing.
    */
    bool EndParagraphSpacing();

    /**
        Begins line spacing using the specified value. @e spacing is a multiple, where
        10 means single-spacing, 15 means 1.5 spacing, and 20 means double spacing.

        The ::wxTextAttrLineSpacing enumeration values are defined for convenience.
    */
    bool BeginLineSpacing(int lineSpacing);

    /**
        Ends line spacing.
    */
    bool EndLineSpacing();

    /**
        Begins numbered bullet.

        This call will be needed for each item in the list, and the
        application should take care of incrementing the numbering.

        @a bulletNumber is a number, usually starting with 1.
        @a leftIndent and @a leftSubIndent are values in tenths of a millimetre.
        @a bulletStyle is a bitlist of the following values:

        wxRichTextBuffer uses indentation to render a bulleted item.
        The left indent is the distance between the margin and the bullet.
        The content of the paragraph, including the first line, starts
        at leftMargin + leftSubIndent.
        So the distance between the left edge of the bullet and the
        left of the actual paragraph is leftSubIndent.
    */
    bool BeginNumberedBullet(int bulletNumber, int leftIndent, int leftSubIndent, int bulletStyle = wxTEXT_ATTR_BULLET_STYLE_ARABIC|wxTEXT_ATTR_BULLET_STYLE_PERIOD);

    /**
        Ends numbered bullet.
    */
    bool EndNumberedBullet();

    /**
        Begins applying a symbol bullet, using a character from the current font.

        See BeginNumberedBullet() for an explanation of how indentation is used
        to render the bulleted paragraph.
    */
    bool BeginSymbolBullet(const wxString& symbol, int leftIndent, int leftSubIndent, int bulletStyle = wxTEXT_ATTR_BULLET_STYLE_SYMBOL);

    /**
        Ends symbol bullet.
    */
    bool EndSymbolBullet();

    /**
        Begins applying a standard bullet, using one of the standard bullet names
        (currently @c standard/circle or @c standard/square.

        See BeginNumberedBullet() for an explanation of how indentation is used to
        render the bulleted paragraph.
    */
    bool BeginStandardBullet(const wxString& bulletName, int leftIndent, int leftSubIndent, int bulletStyle = wxTEXT_ATTR_BULLET_STYLE_STANDARD);

    /**
        Ends standard bullet.
    */
    bool EndStandardBullet();

    /**
        Begins named character style.
    */
    bool BeginCharacterStyle(const wxString& characterStyle);

    /**
        Ends named character style.
    */
    bool EndCharacterStyle();

    /**
        Begins named paragraph style.
    */
    bool BeginParagraphStyle(const wxString& paragraphStyle);

    /**
        Ends named character style.
    */
    bool EndParagraphStyle();

    /**
        Begins named list style.

        Optionally, you can also pass a level and a number.
    */
    bool BeginListStyle(const wxString& listStyle, int level = 1, int number = 1);

    /**
        Ends named character style.
    */
    bool EndListStyle();

    /**
        Begins applying wxTEXT_ATTR_URL to the content.

        Pass a URL and optionally, a character style to apply, since it is common
        to mark a URL with a familiar style such as blue text with underlining.
    */
    bool BeginURL(const wxString& url, const wxString& characterStyle = wxEmptyString);

    /**
        Ends URL.
    */
    bool EndURL();

// Event handling

    /**
        Adds an event handler.

        A buffer associated with a control has the control as the only event handler,
        but the application is free to add more if further notification is required.
        All handlers are notified of an event originating from the buffer, such as
        the replacement of a style sheet during loading.

        The buffer never deletes any of the event handlers, unless RemoveEventHandler()
        is called with @true as the second argument.
    */
    bool AddEventHandler(wxEvtHandler* handler);

    /**
        Removes an event handler from the buffer's list of handlers, deleting the
        object if @a deleteHandler is @true.
    */
    bool RemoveEventHandler(wxEvtHandler* handler, bool deleteHandler = false);

    /**
        Clear event handlers.
    */
    void ClearEventHandlers();

    /**
        Send event to event handlers. If sendToAll is true, will send to all event handlers,
        otherwise will stop at the first successful one.
    */
    bool SendEvent(wxEvent& event, bool sendToAll = true);

// Implementation

    virtual int HitTest(wxDC& dc, wxRichTextDrawingContext& context, const wxPoint& pt, long& textPosition, wxRichTextObject** obj, wxRichTextObject** contextObj, int flags = 0);

    /**
        Copies the buffer.
    */
    void Copy(const wxRichTextBuffer& obj);

    /**
        Assignment operator.
    */
    void operator= (const wxRichTextBuffer& obj);

    /**
        Clones the buffer.
    */
    virtual wxRichTextObject* Clone() const;

    /**
        Submits a command to insert paragraphs.
    */
    bool InsertParagraphsWithUndo(long pos, const wxRichTextParagraphLayoutBox& paragraphs, wxRichTextCtrl* ctrl, int flags = 0);

    /**
        Submits a command to insert the given text.
    */
    bool InsertTextWithUndo(long pos, const wxString& text, wxRichTextCtrl* ctrl, int flags = 0);

    /**
        Submits a command to insert a newline.
    */
    bool InsertNewlineWithUndo(long pos, wxRichTextCtrl* ctrl, int flags = 0);

    /**
        Submits a command to insert the given image.
    */
    bool InsertImageWithUndo(long pos, const wxRichTextImageBlock& imageBlock, wxRichTextCtrl* ctrl, int flags, const wxRichTextAttr& textAttr = wxDEFAULT_RICHTEXTATTR);

    /**
        Submits a command to insert an object.
    */
    wxRichTextObject* InsertObjectWithUndo(long pos, wxRichTextObject *object, wxRichTextCtrl* ctrl, int flags);

    /**
        Submits a command to delete this range.
    */
    bool DeleteRangeWithUndo(const wxRichTextRange& range, wxRichTextCtrl* ctrl);

    /**
        Mark modified.
    */
    void Modify(bool modify = true);

    /**
        Returns @true if the buffer was modified.
    */
    bool IsModified() const;

    //@{
    /**
        Dumps contents of buffer for debugging purposes.
    */
    virtual void Dump();
    virtual void Dump(wxTextOutputStream& stream);
    //@}

    /**
        Returns the file handlers.
    */
    static wxList& GetHandlers();

    /**
        Adds a file handler to the end.
    */
    static void AddHandler(wxRichTextFileHandler *handler);

    /**
        Inserts a file handler at the front.
    */
    static void InsertHandler(wxRichTextFileHandler *handler);

    /**
        Removes a file handler.
    */
    static bool RemoveHandler(const wxString& name);

    /**
        Finds a file handler by name.
    */
    static wxRichTextFileHandler *FindHandler(const wxString& name);

    /**
        Finds a file handler by extension and type.
    */
    static wxRichTextFileHandler *FindHandler(const wxString& extension, wxRichTextFileType imageType);

    /**
        Finds a handler by filename or, if supplied, type.
    */
    static wxRichTextFileHandler *FindHandlerFilenameOrType(const wxString& filename,
                                                            wxRichTextFileType imageType);

    /**
        Finds a handler by type.
    */
    static wxRichTextFileHandler *FindHandler(wxRichTextFileType imageType);

    /**
        Gets a wildcard incorporating all visible handlers. If @a types is present,
        it will be filled with the file type corresponding to each filter. This can be
        used to determine the type to pass to LoadFile given a selected filter.
    */
    static wxString GetExtWildcard(bool combine = false, bool save = false, wxArrayInt* types = NULL);

    /**
        Clean up file handlers.
    */
    static void CleanUpHandlers();

    /**
        Initialise the standard file handlers.
        Currently, only the plain text loading/saving handler is initialised by default.
    */
    static void InitStandardHandlers();

    /**
        Returns the drawing handlers.
    */
    static wxList& GetDrawingHandlers();

    /**
        Adds a drawing handler to the end.
    */
    static void AddDrawingHandler(wxRichTextDrawingHandler *handler);

    /**
        Inserts a drawing handler at the front.
    */
    static void InsertDrawingHandler(wxRichTextDrawingHandler *handler);

    /**
        Removes a drawing handler.
    */
    static bool RemoveDrawingHandler(const wxString& name);

    /**
        Finds a drawing handler by name.
    */
    static wxRichTextDrawingHandler *FindDrawingHandler(const wxString& name);

    /**
        Clean up drawing handlers.
    */
    static void CleanUpDrawingHandlers();

    /**
        Returns the field types.
    */
    static wxRichTextFieldTypeHashMap& GetFieldTypes();

    /**
        Adds a field type.

        @see RemoveFieldType(), FindFieldType(), wxRichTextField, wxRichTextFieldType, wxRichTextFieldTypeStandard

    */
    static void AddFieldType(wxRichTextFieldType *fieldType);

    /**
        Removes a field type by name.

        @see AddFieldType(), FindFieldType(), wxRichTextField, wxRichTextFieldType, wxRichTextFieldTypeStandard
    */
    static bool RemoveFieldType(const wxString& name);

    /**
        Finds a field type by name.

        @see RemoveFieldType(), AddFieldType(), wxRichTextField, wxRichTextFieldType, wxRichTextFieldTypeStandard
    */
    static wxRichTextFieldType *FindFieldType(const wxString& name);

    /**
        Cleans up field types.
    */
    static void CleanUpFieldTypes();

    /**
        Returns the renderer object.
    */
    static wxRichTextRenderer* GetRenderer();

    /**
        Sets @a renderer as the object to be used to render certain aspects of the
        content, such as bullets.

        You can override default rendering by deriving a new class from
        wxRichTextRenderer or wxRichTextStdRenderer, overriding one or more
        virtual functions, and setting an instance of the class using this function.
    */
    static void SetRenderer(wxRichTextRenderer* renderer);

    /**
        Returns the minimum margin between bullet and paragraph in 10ths of a mm.
    */
    static int GetBulletRightMargin();

    /**
        Sets the minimum margin between bullet and paragraph in 10ths of a mm.
    */
    static void SetBulletRightMargin(int margin);

    /**
        Returns the factor to multiply by character height to get a reasonable bullet size.
    */
    static float GetBulletProportion();

    /**
        Sets the factor to multiply by character height to get a reasonable bullet size.
    */
    static void SetBulletProportion(float prop);

    /**
        Returns the scale factor for calculating dimensions.
    */
    double GetScale() const;

    /**
        Sets the scale factor for calculating dimensions.
    */
    void SetScale(double scale);

    /**
        Sets the floating layout mode. Pass @false to speed up editing by not performing
        floating layout. This setting affects all buffers.

    */
    static void SetFloatingLayoutMode(bool mode);

    /**
        Returns the floating layout mode. The default is @true, where objects
        are laid out according to their floating status.
    */
    static bool GetFloatingLayoutMode();

protected:

    /// Command processor
    wxCommandProcessor*     m_commandProcessor;

    /// Table storing fonts
    wxRichTextFontTable     m_fontTable;

    /// Has been modified?
    bool                    m_modified;

    /// Collapsed command stack
    int                     m_batchedCommandDepth;

    /// Name for collapsed command
    wxString                m_batchedCommandsName;

    /// Current collapsed command accumulating actions
    wxRichTextCommand*      m_batchedCommand;

    /// Whether to suppress undo
    int                     m_suppressUndo;

    /// Style sheet, if any
    wxRichTextStyleSheet*   m_styleSheet;

    /// List of event handlers that will be notified of events
    wxList                  m_eventHandlers;

    /// Stack of attributes for convenience functions
    wxList                  m_attributeStack;

    /// Flags to be passed to handlers
    int                     m_handlerFlags;

    /// File handlers
    static wxList           sm_handlers;

    /// Drawing handlers
    static wxList           sm_drawingHandlers;

    /// Field types
    static wxRichTextFieldTypeHashMap sm_fieldTypes;

    /// Renderer
    static wxRichTextRenderer* sm_renderer;

    /// Minimum margin between bullet and paragraph in 10ths of a mm
    static int              sm_bulletRightMargin;

    /// Factor to multiply by character height to get a reasonable bullet size
    static float            sm_bulletProportion;

    /// Floating layout mode, @true by default
    static bool             sm_floatingLayoutMode;

    /// Scaling factor in use: needed to calculate correct dimensions when printing
    double                  m_scale;

    /// Font scale for adjusting the text size when editing
    double                  m_fontScale;

    /// Dimension scale for reducing redundant whitespace when editing
    double                  m_dimensionScale;
};

/**
    @class wxRichTextCell

    wxRichTextCell is the cell in a table.
 */

class %delete wxRichTextCell: public wxRichTextBox
{
    //DECLARE_DYNAMIC_CLASS(wxRichTextCell)
public:
// Constructors

    /**
        Default constructor; optionally pass the parent object.
    */

    wxRichTextCell(wxRichTextObject* parent = NULL);

    /**
        Copy constructor.
    */

    wxRichTextCell(const wxRichTextCell& obj);

// Overridables

    virtual bool Draw(wxDC& dc, wxRichTextDrawingContext& context, const wxRichTextRange& range, const wxRichTextSelection& selection, const wxRect& rect, int descent, int style);

    virtual int HitTest(wxDC& dc, wxRichTextDrawingContext& context, const wxPoint& pt, long& textPosition, wxRichTextObject** obj, wxRichTextObject** contextObj, int flags = 0);

    virtual bool AdjustAttributes(wxRichTextAttr& attr, wxRichTextDrawingContext& context);

    virtual wxString GetXMLNodeName() const;

    virtual bool CanEditProperties() const;

    virtual bool EditProperties(wxWindow* parent, wxRichTextBuffer* buffer);

    virtual wxString GetPropertiesMenuLabel() const;

// Accessors

    int GetColSpan() const;

    void SetColSpan(long span);

    int GetRowSpan() const;

    void SetRowSpan(long span);

// Operations

    virtual wxRichTextObject* Clone() const;

    void Copy(const wxRichTextCell& obj);

protected:
};

//class wxPosition;

/**
    @class wxRichTextTable

    wxRichTextTable represents a table with arbitrary columns and rows.
 */

//WX_DEFINE_ARRAY_PTR(wxRichTextObject*, wxRichTextObjectPtrArray);
class %delete wxRichTextObjectPtrArray
{
    wxRichTextObjectPtrArray();
    wxRichTextObjectPtrArray(const wxRichTextObjectPtrArray& array);

    void Add(wxRichTextObject* item);
    void Clear();
    int  GetCount() const;
    void Insert(wxRichTextObject* item, int nIndex);
    bool IsEmpty();
    wxRichTextObject* Item(size_t nIndex) const;
    void RemoveAt(size_t nIndex);
};

//WX_DECLARE_USER_EXPORTED_OBJARRAY(wxRichTextObjectPtrArray, wxRichTextObjectPtrArrayArray, WXDLLIMPEXP_RICHTEXT);
class %delete wxRichTextObjectPtrArrayArray
{
    wxRichTextObjectPtrArrayArray();
    wxRichTextObjectPtrArrayArray(const wxRichTextObjectPtrArrayArray& array);

    void Add(const wxRichTextObjectPtrArray& item);
    void Clear();
    int  GetCount() const;
    void Insert(const wxRichTextObjectPtrArray& item, int nIndex);
    bool IsEmpty();
    wxRichTextObjectPtrArray Item(size_t nIndex) const;
    void RemoveAt(size_t nIndex);
};


class %delete wxRichTextTable: public wxRichTextBox
{
    //DECLARE_DYNAMIC_CLASS(wxRichTextTable)
public:

// Constructors

    /**
        Default constructor; optionally pass the parent object.
    */

    wxRichTextTable(wxRichTextObject* parent = NULL);

    /**
        Copy constructor.
    */

    wxRichTextTable(const wxRichTextTable& obj);

// Overridables

    virtual bool Draw(wxDC& dc, wxRichTextDrawingContext& context, const wxRichTextRange& range, const wxRichTextSelection& selection, const wxRect& rect, int descent, int style);

    virtual int HitTest(wxDC& dc, wxRichTextDrawingContext& context, const wxPoint& pt, long& textPosition, wxRichTextObject** obj, wxRichTextObject** contextObj, int flags = 0);

    virtual bool AdjustAttributes(wxRichTextAttr& attr, wxRichTextDrawingContext& context);

    virtual wxString GetXMLNodeName() const;

    virtual bool Layout(wxDC& dc, wxRichTextDrawingContext& context, const wxRect& rect, const wxRect& parentRect, int style);

    virtual bool GetRangeSize(const wxRichTextRange& range, wxSize& size, int& descent, wxDC& dc, wxRichTextDrawingContext& context, int flags, const wxPoint& position = wxNULLPOINT, const wxSize& parentSize = wxDefaultSize, wxArrayInt* partialExtents = NULL) const;

    virtual bool DeleteRange(const wxRichTextRange& range);

    virtual wxString GetTextForRange(const wxRichTextRange& range) const;

#if wxUSE_XML
    virtual bool ImportFromXML(wxRichTextBuffer* buffer, wxXmlNode* node, wxRichTextXMLHandler* handler, bool* recurse);
#endif

#if wxRICHTEXT_HAVE_DIRECT_OUTPUT
    virtual bool ExportXML(wxOutputStream& stream, int indent, wxRichTextXMLHandler* handler);
#endif

#if wxRICHTEXT_HAVE_XMLDOCUMENT_OUTPUT
    virtual bool ExportXML(wxXmlNode* parent, wxRichTextXMLHandler* handler);
#endif

    virtual bool FindPosition(wxDC& dc, wxRichTextDrawingContext& context, long index, wxPoint& pt, int* height, bool forceLineStart);

    virtual void CalculateRange(long start, long& end);

    // Can this object handle the selections of its children? FOr example, a table.
    virtual bool HandlesChildSelections() const;

    /// Returns a selection object specifying the selections between start and end character positions.
    /// For example, a table would deduce what cells (of range length 1) are selected when dragging across the table.
    virtual wxRichTextSelection GetSelection(long start, long end) const;

    virtual bool CanEditProperties() const;

    virtual bool EditProperties(wxWindow* parent, wxRichTextBuffer* buffer);

    virtual wxString GetPropertiesMenuLabel() const;

    // Returns true if objects of this class can accept the focus, i.e. a call to SetFocusObject
    // is possible. For example, containers supporting text, such as a text box object, can accept the focus,
    // but a table can't (set the focus to individual cells instead).
    virtual bool AcceptsFocus() const;

// Accessors

    /**
        Returns the cells array.
    */
    // wxLua: we do not need the const version
    //const wxRichTextObjectPtrArrayArray& GetCells() const;

    /**
        Returns the cells array.
    */
    wxRichTextObjectPtrArrayArray& GetCells();

    /**
        Returns the row count.
    */
    int GetRowCount() const;

    /**
        Sets the row count.
    */
    void SetRowCount(int count);

    /**
        Returns the column count.
    */
    int GetColumnCount() const;

    /**
        Sets the column count.
    */
    void SetColumnCount(int count);

    /**
        Returns the cell at the given row/column position.
    */
    virtual wxRichTextCell* GetCell(int row, int col) const;

    /**
        Returns the cell at the given character position (in the range of the table).
    */
    virtual wxRichTextCell* GetCell(long pos) const;

    /**
        Returns the row/column for a given character position.
    */
    virtual bool GetCellRowColumnPosition(long pos, int& row, int& col) const;

    /**
        Returns the coordinates of the cell with keyboard focus, or (-1,-1) if none.
    */    
    virtual wxPosition GetFocusedCell() const;

// Operations

    /**
        Clears the table.
    */

    virtual void ClearTable();

    /**
        Creates a table of the given dimensions.
    */

    virtual bool CreateTable(int rows, int cols);

    /**
        Sets the attributes for the cells specified by the selection.
    */

    virtual bool SetCellStyle(const wxRichTextSelection& selection, const wxRichTextAttr& style, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO);

    /**
        Deletes rows from the given row position.
    */

    virtual bool DeleteRows(int startRow, int noRows = 1);

    /**
        Deletes columns from the given column position.
    */

    virtual bool DeleteColumns(int startCol, int noCols = 1);

    /**
        Adds rows from the given row position.
    */

    virtual bool AddRows(int startRow, int noRows, const wxRichTextAttr& attr = wxDEFAULT_RICHTEXTATTR);

    /**
        Adds columns from the given column position.
    */

    virtual bool AddColumns(int startCol, int noCols, const wxRichTextAttr& attr = wxDEFAULT_RICHTEXTATTR);

    // Makes a clone of this object.
    virtual wxRichTextObject* Clone() const;

    // Copies this object.
    void Copy(const wxRichTextTable& obj);

protected:

    int m_rowCount;
    int m_colCount;

    // An array of rows, each of which is a wxRichTextObjectPtrArray containing
    // the cell objects. The cell objects are also children of this object.
    // Problem: if boxes are immediate children of a box, this will cause problems
    // with wxRichTextParagraphLayoutBox functions (and functions elsewhere) that
    // expect to find just paragraphs. May have to adjust the way we handle the
    // hierarchy to accept non-paragraph objects in a paragraph layout box.
    // We'll be overriding much wxRichTextParagraphLayoutBox functionality so this
    // may not be such a problem. Perhaps the table should derive from a different
    // class?
    wxRichTextObjectPtrArrayArray   m_cells;
};

/** @class wxRichTextTableBlock

    Stores the coordinates for a block of cells.
 */

class %delete wxRichTextTableBlock
{
public:
    wxRichTextTableBlock();
    wxRichTextTableBlock(int colStart, int colEnd, int rowStart, int rowEnd);
    wxRichTextTableBlock(const wxRichTextTableBlock& block);

    void Init();
    
    void Copy(const wxRichTextTableBlock& block);
    void operator=(const wxRichTextTableBlock& block);
    bool operator==(const wxRichTextTableBlock& block);

    /// Computes the block given a table (perhaps about to be edited) and a rich text control
    /// that may have a selection. If no selection, the whole table is used. If just the whole content
    /// of one cell is selected, this cell only is used. If the cell contents is not selected and
    /// requireCellSelection is @false, the focused cell will count as a selected cell.
    bool ComputeBlockForSelection(wxRichTextTable* table, wxRichTextCtrl* ctrl, bool requireCellSelection = true);

    /// Does this block represent the whole table?
    bool IsWholeTable(wxRichTextTable* table) const;

    /// Returns the cell focused in the table, if any
    static wxRichTextCell* GetFocusedCell(wxRichTextCtrl* ctrl);

    int& ColStart();
    int ColStart() const;

    int& ColEnd();
    int ColEnd() const;

    int& RowStart();
    int RowStart() const;

    int& RowEnd();
    int RowEnd() const;

    //int m_colStart, m_colEnd, m_rowStart, m_rowEnd;
};

/**
    The command identifiers for Do/Undo.
*/

enum wxRichTextCommandId
{
    wxRICHTEXT_INSERT,
    wxRICHTEXT_DELETE,
    wxRICHTEXT_CHANGE_ATTRIBUTES,
    wxRICHTEXT_CHANGE_STYLE,
    wxRICHTEXT_CHANGE_PROPERTIES,
    wxRICHTEXT_CHANGE_OBJECT
};

/**
    @class wxRichTextObjectAddress

    A class for specifying an object anywhere in an object hierarchy,
    without using a pointer, necessary since wxRTC commands may delete
    and recreate sub-objects so physical object addresses change. An array
    of positions (one per hierarchy level) is used.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextCommand
*/

class %delete wxRichTextObjectAddress
{
public:
    /**
        Creates the address given a container and an object.
    */
    wxRichTextObjectAddress(wxRichTextParagraphLayoutBox* topLevelContainer, wxRichTextObject* obj); 
    /**
    */
    wxRichTextObjectAddress();
    /**
    */
    wxRichTextObjectAddress(const wxRichTextObjectAddress& address);

    void Init();

    /**
        Copies the address.
    */
    void Copy(const wxRichTextObjectAddress& address);

    /**
        Assignment operator.
    */
    void operator=(const wxRichTextObjectAddress& address);

    /**
        Returns the object specified by the address, given a top level container.
    */
    wxRichTextObject* GetObject(wxRichTextParagraphLayoutBox* topLevelContainer) const;

    /**
        Creates the address given a container and an object.
    */
    bool Create(wxRichTextParagraphLayoutBox* topLevelContainer, wxRichTextObject* obj);

    /**
        Returns the array of integers representing the object address.
    */
    wxArrayInt& GetAddress();

    /**
        Returns the array of integers representing the object address.
    */
    const wxArrayInt& GetAddress() const;

    /**
        Sets the address from an array of integers.
    */
    void SetAddress(const wxArrayInt& address);

protected:

    wxArrayInt  m_address;
};

//class /*WXDLLIMPEXP_FWD_RICHTEXT*/ wxRichTextAction;

/**
    @class wxRichTextCommand

    Implements a command on the undo/redo stack. A wxRichTextCommand object contains one or more wxRichTextAction
    objects, allowing aggregation of a number of operations into one command.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextAction
*/

class %delete wxRichTextCommand: public wxCommand
{
public:
    /**
        Constructor for one action.
    */
    wxRichTextCommand(const wxString& name, wxRichTextCommandId id, wxRichTextBuffer* buffer,
        wxRichTextParagraphLayoutBox* container, wxRichTextCtrl* ctrl, bool ignoreFirstTime = false);

    /**
        Constructor for multiple actions.
    */
    wxRichTextCommand(const wxString& name);

    //virtual ~wxRichTextCommand();

    /**
        Performs the command.
    */
    bool Do();

    /**
        Undoes the command.
    */
    bool Undo();

    /**
        Adds an action to the action list.
    */
    void AddAction(wxRichTextAction* action);

    /**
        Clears the action list.
    */
    void ClearActions();

    /**
        Returns the action list.
    */
    wxList& GetActions();

protected:

    wxList  m_actions;
};

/**
    @class wxRichTextAction

    Implements a part of a command.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextCommand
*/

class %delete wxRichTextAction: public wxObject
{
public:
    /**
        Constructor. @a buffer is the top-level buffer, while @a container is the object within
        which the action is taking place. In the simplest case, they are the same.
    */
    wxRichTextAction(wxRichTextCommand* cmd, const wxString& name, wxRichTextCommandId id,
        wxRichTextBuffer* buffer, wxRichTextParagraphLayoutBox* container,
        wxRichTextCtrl* ctrl, bool ignoreFirstTime = false);

    virtual ~wxRichTextAction();

    /**
        Performs the action.
    */
    bool Do();

    /**
        Undoes the action.
    */
    bool Undo();

    /**
        Updates the control appearance, optimizing if possible given information from the call to Layout.
    */
    !%wxchkver_3_1_0 void UpdateAppearance(long caretPosition, bool sendUpdateEvent = false, wxArrayInt* optimizationLineCharPositions = NULL, wxArrayInt* optimizationLineYPositions = NULL, bool isDoCmd = true);
    %wxchkver_3_1_0 void UpdateAppearance(long caretPosition, bool sendUpdateEvent = false, const wxRect& oldFloatRect = wxNULLRECT, wxArrayInt* optimizationLineCharPositions = NULL, wxArrayInt* optimizationLineYPositions = NULL, bool isDoCmd = true);

    /**
        Replaces the buffer paragraphs with the given fragment.
    */
    void ApplyParagraphs(const wxRichTextParagraphLayoutBox& fragment);

    /**
        Returns the new fragments.
    */
    wxRichTextParagraphLayoutBox& GetNewParagraphs();

    /**
        Returns the old fragments.
    */
    wxRichTextParagraphLayoutBox& GetOldParagraphs();

    /**
        Returns the attributes, for single-object commands.
    */
    wxRichTextAttr& GetAttributes();

    /**
        Returns the object to replace the one at the position defined by the container address
        and the action's range start position.
    */
    wxRichTextObject* GetObject() const;

    /**
        Stores the object to replace the one at the position defined by the container address
        without making an address for it (cf SetObject() and MakeObject()).
    */
    void StoreObject(wxRichTextObject* obj);

    /**
        Sets the object to replace the one at the position defined by the container address
        and the action's range start position.
    */
    void SetObject(wxRichTextObject* obj);

    /**
        Makes an address from the given object.
    */
    void MakeObject(wxRichTextObject* obj);

    /**
        Sets the existing and new objects, for use with wxRICHTEXT_CHANGE_OBJECT.
    */
    void SetOldAndNewObjects(wxRichTextObject* oldObj, wxRichTextObject* newObj);

    /**
        Calculate arrays for refresh optimization.
    */
    !%wxchkver_3_1_0 void CalculateRefreshOptimizations(wxArrayInt& optimizationLineCharPositions, wxArrayInt& optimizationLineYPositions);
    %wxchkver_3_1_0 void CalculateRefreshOptimizations(wxArrayInt& optimizationLineCharPositions, wxArrayInt& optimizationLineYPositions, wxRect& oldFloatRect);

    /**
        Sets the position used for e.g. insertion.
    */
    void SetPosition(long pos);

    /**
        Returns the position used for e.g. insertion.
    */
    long GetPosition() const;

    /**
        Sets the range for e.g. deletion.
    */
    void SetRange(const wxRichTextRange& range);

    /**
        Returns the range for e.g. deletion.
    */
    const wxRichTextRange& GetRange() const;

    /**
        Returns the address (nested position) of the container within the buffer being manipulated.
    */
    wxRichTextObjectAddress& GetContainerAddress();

    /**
        Returns the address (nested position) of the container within the buffer being manipulated.
    */
    const wxRichTextObjectAddress& GetContainerAddress() const;

    /**
        Sets the address (nested position) of the container within the buffer being manipulated.
    */
    void SetContainerAddress(const wxRichTextObjectAddress& address);

    /**
        Sets the address (nested position) of the container within the buffer being manipulated.
    */
    void SetContainerAddress(wxRichTextParagraphLayoutBox* container, wxRichTextObject* obj);

    /**
        Returns the container that this action refers to, using the container address and top-level buffer.
    */
    wxRichTextParagraphLayoutBox* GetContainer() const;

    /**
        Returns the action name.
    */
    const wxString& GetName() const;

    /**
        Instructs the first Do() command should be skipped as it's already been applied.
    */
    void SetIgnoreFirstTime(bool b);

    /**
        Returns true if the first Do() command should be skipped as it's already been applied.
    */
    bool GetIgnoreFirstTime() const;

protected:
    // Action name
    wxString                        m_name;

    // Buffer
    wxRichTextBuffer*               m_buffer;

    // The address (nested position) of the container being manipulated.
    // This is necessary because objects are deleted, and we can't
    // therefore store actual pointers.
    wxRichTextObjectAddress         m_containerAddress;

    // Control
    wxRichTextCtrl*                 m_ctrl;

    // Stores the new paragraphs
    wxRichTextParagraphLayoutBox    m_newParagraphs;

    // Stores the old paragraphs
    wxRichTextParagraphLayoutBox    m_oldParagraphs;

    // Stores an object to replace the one at the position
    // defined by the container address and the action's range start position.
    wxRichTextObject*               m_object;

    // Stores the attributes
    wxRichTextAttr                  m_attributes;

    // The address of the object being manipulated (used for changing an individual object or its attributes)
    wxRichTextObjectAddress         m_objectAddress;

    // Stores the old attributes
    // wxRichTextAttr                  m_oldAttributes;

    // The affected range
    wxRichTextRange                 m_range;

    // The insertion point for this command
    long                            m_position;

    // Ignore 1st 'Do' operation because we already did it
    bool                            m_ignoreThis;

    // The command identifier
    wxRichTextCommandId             m_cmdId;
};

/*!
 * Handler flags
 */

// Include style sheet when loading and saving
#define wxRICHTEXT_HANDLER_INCLUDE_STYLESHEET       0x0001

// Save images to memory file system in HTML handler
#define wxRICHTEXT_HANDLER_SAVE_IMAGES_TO_MEMORY    0x0010

// Save images to files in HTML handler
#define wxRICHTEXT_HANDLER_SAVE_IMAGES_TO_FILES     0x0020

// Save images as inline base64 data in HTML handler
#define wxRICHTEXT_HANDLER_SAVE_IMAGES_TO_BASE64    0x0040

// Don't write header and footer (or BODY), so we can include the fragment
// in a larger document
#define wxRICHTEXT_HANDLER_NO_HEADER_FOOTER         0x0080

// Convert the more common face names to names that will work on the current platform
// in a larger document
#define wxRICHTEXT_HANDLER_CONVERT_FACENAMES        0x0100

/**
    @class wxRichTextFileHandler

    The base class for file handlers.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextFileHandler: public wxObject
{
    //DECLARE_CLASS(wxRichTextFileHandler)
public:
    /**
        Creates a file handler object.
    */
    //wxRichTextFileHandler(const wxString& name = wxEmptyString, const wxString& ext = wxEmptyString, int type = 0);

#if wxUSE_STREAMS
    /**
        Loads the buffer from a stream.
        Not all handlers will implement file loading.
    */
    bool LoadFile(wxRichTextBuffer *buffer, wxInputStream& stream);

    /**
        Saves the buffer to a stream.
        Not all handlers will implement file saving.
    */
    bool SaveFile(wxRichTextBuffer *buffer, wxOutputStream& stream);
#endif

#if wxUSE_FFILE && wxUSE_STREAMS
    /**
        Loads the buffer from a file.
    */
    virtual bool LoadFile(wxRichTextBuffer *buffer, const wxString& filename);

    /**
        Saves the buffer to a file.
    */
    virtual bool SaveFile(wxRichTextBuffer *buffer, const wxString& filename);
#endif // wxUSE_STREAMS && wxUSE_STREAMS

    /**
        Returns @true if we handle this filename (if using files). By default, checks the extension.
    */
    virtual bool CanHandle(const wxString& filename) const;

    /**
        Returns @true if we can save using this handler.
    */
    virtual bool CanSave() const;

    /**
        Returns @true if we can load using this handler.
    */
    virtual bool CanLoad() const;

    /**
        Returns @true if this handler should be visible to the user.
    */
    virtual bool IsVisible() const;

    /**
        Sets whether the handler should be visible to the user (via the application's
        load and save dialogs).
    */
    virtual void SetVisible(bool visible);

    /**
        Sets the name of the handler.
    */
    void SetName(const wxString& name);

    /**
        Returns the name of the handler.
    */
    wxString GetName() const;

    /**
        Sets the default extension to recognise.
    */
    void SetExtension(const wxString& ext);

    /**
        Returns the default extension to recognise.
    */
    wxString GetExtension() const;

    /**
        Sets the handler type.
    */
    void SetType(int type);

    /**
        Returns the handler type.
    */
    int GetType() const;

    /**
        Sets flags that change the behaviour of loading or saving.
        See the documentation for each handler class to see what flags are relevant
        for each handler.

        You call this function directly if you are using a file handler explicitly
        (without going through the text control or buffer LoadFile/SaveFile API).
        Or, you can call the control or buffer's SetHandlerFlags function to set
        the flags that will be used for subsequent load and save operations.
    */
    void SetFlags(int flags);

    /**
        Returns flags controlling how loading and saving is done.
    */
    int GetFlags() const;

    /**
        Sets the encoding to use when saving a file. If empty, a suitable encoding is chosen.
    */
    void SetEncoding(const wxString& encoding);

    /**
        Returns the encoding to use when saving a file. If empty, a suitable encoding is chosen.
    */
    const wxString& GetEncoding() const;

protected:

#if wxUSE_STREAMS
    /**
        Override to load content from @a stream into @a buffer.
    */
    virtual bool DoLoadFile(wxRichTextBuffer *buffer, wxInputStream& stream);

    /**
        Override to save content to @a stream from @a buffer.
    */
    virtual bool DoSaveFile(wxRichTextBuffer *buffer, wxOutputStream& stream);
#endif

    wxString  m_name;
    wxString  m_encoding;
    wxString  m_extension;
    int       m_type;
    int       m_flags;
    bool      m_visible;
};

/**
    @class wxRichTextPlainTextHandler

    Implements saving a buffer to plain text.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextFileHandler, wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextPlainTextHandler: public wxRichTextFileHandler
{
    //DECLARE_CLASS(wxRichTextPlainTextHandler)
public:
    wxRichTextPlainTextHandler(const wxString& name = "Text",
                               const wxString& ext = "txt",
                               wxRichTextFileType type = wxRICHTEXT_TYPE_TEXT);

    // Can we save using this handler?
    virtual bool CanSave() const;

    // Can we load using this handler?
    virtual bool CanLoad() const;

protected:

#if wxUSE_STREAMS
    virtual bool DoLoadFile(wxRichTextBuffer *buffer, wxInputStream& stream);
    virtual bool DoSaveFile(wxRichTextBuffer *buffer, wxOutputStream& stream);
#endif

};

/**
    @class wxRichTextDrawingHandler

    The base class for custom drawing handlers.
    Currently, drawing handlers can provide virtual attributes.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextDrawingHandler: public wxObject
{
    //DECLARE_CLASS(wxRichTextDrawingHandler)
public:
    /**
        Creates a drawing handler object.
    */
    //wxRichTextDrawingHandler(const wxString& name = wxEmptyString);

    /**
        Returns @true if this object has virtual attributes that we can provide.
    */
    virtual bool HasVirtualAttributes(wxRichTextObject* obj) const;

    /**
        Provides virtual attributes that we can provide.
    */
    virtual bool GetVirtualAttributes(wxRichTextAttr& attr, wxRichTextObject* obj) const;

    /**
        Gets the count for mixed virtual attributes for individual positions within the object.
        For example, individual characters within a text object may require special highlighting.
    */
    virtual int GetVirtualSubobjectAttributesCount(wxRichTextObject* obj) const;

    /**
        Gets the mixed virtual attributes for individual positions within the object.
        For example, individual characters within a text object may require special highlighting.
        Returns the number of virtual attributes found.
    */
    virtual int GetVirtualSubobjectAttributes(wxRichTextObject* obj, wxArrayInt& positions, wxRichTextAttrArray& attributes) const;

    /**
        Do we have virtual text for this object? Virtual text allows an application
        to replace characters in an object for editing and display purposes, for example
        for highlighting special characters.
    */
    virtual bool HasVirtualText(const wxRichTextPlainText* obj) const;

    /**
        Gets the virtual text for this object.
    */
    virtual bool GetVirtualText(const wxRichTextPlainText* obj, wxString& text) const;

    /**
        Sets the name of the handler.
    */
    void SetName(const wxString& name);

    /**
        Returns the name of the handler.
    */
    wxString GetName() const;

protected:

    wxString  m_name;
};

#if wxUSE_DATAOBJ

/**
    @class wxRichTextBufferDataObject

    Implements a rich text data object for clipboard transfer.

    @library{wxrichtext}
    @category{richtext}

    @see wxDataObjectSimple, wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextBufferDataObject: public wxDataObjectSimple
{
public:
    /**
        The constructor doesn't copy the pointer, so it shouldn't go away while this object
        is alive.
    */
    wxRichTextBufferDataObject(wxRichTextBuffer* richTextBuffer = NULL);
    //virtual ~wxRichTextBufferDataObject();

    /**
        After a call to this function, the buffer is owned by the caller and it
        is responsible for deleting it.
    */
    wxRichTextBuffer* GetRichTextBuffer();

    /**
        Returns the id for the new data format.
    */
    static const wxChar* GetRichTextBufferFormatId();

    // base class pure virtuals

    virtual wxDataFormat GetPreferredFormat(wxDataObject::Direction dir) const;
    virtual size_t GetDataSize() const;
    virtual bool GetDataHere(void *pBuf) const;
    virtual bool SetData(size_t len, const void *buf);

    // prevent warnings

    virtual size_t GetDataSize(const wxDataFormat&) const;
    virtual bool GetDataHere(const wxDataFormat&, void *buf) const;
    virtual bool SetData(const wxDataFormat&, size_t len, const void *buf);

private:
    wxDataFormat            m_formatRichTextBuffer;     // our custom format
    wxRichTextBuffer*       m_richTextBuffer;           // our data
    static const wxChar*    ms_richTextBufferFormatId;  // our format id
};

#endif

/**
    @class wxRichTextRenderer

    This class isolates some common drawing functionality.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextRenderer: public wxObject
{
public:
    /**
        Constructor.
    */
    //wxRichTextRenderer();
    //virtual ~wxRichTextRenderer();

    /**
        Draws a standard bullet, as specified by the value of GetBulletName. This function should be overridden.
    */
    virtual bool DrawStandardBullet(wxRichTextParagraph* paragraph, wxDC& dc, const wxRichTextAttr& attr, const wxRect& rect);

    /**
        Draws a bullet that can be described by text, such as numbered or symbol bullets. This function should be overridden.
    */
    virtual bool DrawTextBullet(wxRichTextParagraph* paragraph, wxDC& dc, const wxRichTextAttr& attr, const wxRect& rect, const wxString& text);

    /**
        Draws a bitmap bullet, where the bullet bitmap is specified by the value of GetBulletName. This function should be overridden.
    */
    virtual bool DrawBitmapBullet(wxRichTextParagraph* paragraph, wxDC& dc, const wxRichTextAttr& attr, const wxRect& rect);

    /**
        Enumerate the standard bullet names currently supported. This function should be overridden.
    */
    virtual bool EnumerateStandardBulletNames(wxArrayString& bulletNames);
};

/**
    @class wxRichTextStdRenderer

    The standard renderer for drawing bullets.

    @library{wxrichtext}
    @category{richtext}

    @see wxRichTextRenderer, wxRichTextBuffer, wxRichTextCtrl
*/

class %delete wxRichTextStdRenderer: public wxRichTextRenderer
{
public:
    /**
        Constructor.
    */
    wxRichTextStdRenderer();

    // Draw a standard bullet, as specified by the value of GetBulletName
    virtual bool DrawStandardBullet(wxRichTextParagraph* paragraph, wxDC& dc, const wxRichTextAttr& attr, const wxRect& rect);

    // Draw a bullet that can be described by text, such as numbered or symbol bullets
    virtual bool DrawTextBullet(wxRichTextParagraph* paragraph, wxDC& dc, const wxRichTextAttr& attr, const wxRect& rect, const wxString& text);

    // Draw a bitmap bullet, where the bullet bitmap is specified by the value of GetBulletName
    virtual bool DrawBitmapBullet(wxRichTextParagraph* paragraph, wxDC& dc, const wxRichTextAttr& attr, const wxRect& rect);

    // Enumerate the standard bullet names currently supported
    virtual bool EnumerateStandardBulletNames(wxArrayString& bulletNames);
};

/*!
 * Utilities
 *
 */

/*inline*/ bool wxRichTextHasStyle(int flags, int style);

/// Compare two attribute objects
/*WXDLLIMPEXP_RICHTEXT*/ bool wxTextAttrEq(const wxRichTextAttr& attr1, const wxRichTextAttr& attr2);
/*WXDLLIMPEXP_RICHTEXT*/ bool wxTextAttrEq(const wxRichTextAttr& attr1, const wxRichTextAttr& attr2);

/// Apply one style to another
/*WXDLLIMPEXP_RICHTEXT*/ bool wxRichTextApplyStyle(wxRichTextAttr& destStyle, const wxRichTextAttr& style, wxRichTextAttr* compareWith = NULL);

// Remove attributes
/*WXDLLIMPEXP_RICHTEXT*/ bool wxRichTextRemoveStyle(wxRichTextAttr& destStyle, const wxRichTextAttr& style);

/// Combine two bitlists
/*WXDLLIMPEXP_RICHTEXT*/ bool wxRichTextCombineBitlists(int& valueA, int valueB, int& flagsA, int flagsB);

/// Compare two bitlists
/*WXDLLIMPEXP_RICHTEXT*/ bool wxRichTextBitlistsEqPartial(int valueA, int valueB, int flags);

/// Split into paragraph and character styles
/*WXDLLIMPEXP_RICHTEXT*/ bool wxRichTextSplitParaCharStyles(const wxRichTextAttr& style, wxRichTextAttr& parStyle, wxRichTextAttr& charStyle);

/// Compare tabs
/*WXDLLIMPEXP_RICHTEXT*/ bool wxRichTextTabsEq(const wxArrayInt& tabs1, const wxArrayInt& tabs2);

/// Convert a decimal to Roman numerals
/*WXDLLIMPEXP_RICHTEXT*/ wxString wxRichTextDecimalToRoman(long n);

// Collects the attributes that are common to a range of content, building up a note of
// which attributes are absent in some objects and which clash in some objects.
/*WXDLLIMPEXP_RICHTEXT*/ void wxTextAttrCollectCommonAttributes(wxTextAttr& currentStyle, const wxTextAttr& attr, wxTextAttr& clashingAttr, wxTextAttr& absentAttr);

/*WXDLLIMPEXP_RICHTEXT*/ void wxRichTextModuleInit();

//  End richtextbuffer.h
#endif // wxLUA_USE_wxRichText && %wxchkver_3_0 && wxUSE_RICHTEXT

#if wxLUA_USE_wxRichText && %wxchkver_3_0 && wxUSE_RICHTEXT

#include "wx/richtext/richtextctrl.h"

/*
 * Styles and flags
 */

/**
    Styles
*/

#define wxRE_READONLY          0x0010
#define wxRE_MULTILINE         0x0020
#define wxRE_CENTRE_CARET      0x8000
#define wxRE_CENTER_CARET      wxRE_CENTRE_CARET

/**
    Flags
*/

#define wxRICHTEXT_SHIFT_DOWN  0x01
#define wxRICHTEXT_CTRL_DOWN   0x02
#define wxRICHTEXT_ALT_DOWN    0x04

/**
    Extra flags
*/

// Don't draw guide lines around boxes and tables
#define wxRICHTEXT_EX_NO_GUIDELINES 0x00000100


/*
    Defaults
*/

//#define wxRICHTEXT_DEFAULT_OVERALL_SIZE wxSize(-1, -1)
//#define wxRICHTEXT_DEFAULT_IMAGE_SIZE wxSize(80, 80)
#define wxRICHTEXT_DEFAULT_SPACING 3
#define wxRICHTEXT_DEFAULT_MARGIN 3
//#define wxRICHTEXT_DEFAULT_UNFOCUSSED_BACKGROUND wxColour(175, 175, 175)
//#define wxRICHTEXT_DEFAULT_FOCUSSED_BACKGROUND wxColour(140, 140, 140)
//#define wxRICHTEXT_DEFAULT_UNSELECTED_BACKGROUND wxSystemSettings::GetColour(wxSYS_COLOUR_3DFACE)
//#define wxRICHTEXT_DEFAULT_TYPE_COLOUR wxColour(0, 0, 200)
//#define wxRICHTEXT_DEFAULT_FOCUS_RECT_COLOUR wxColour(100, 80, 80)
#define wxRICHTEXT_DEFAULT_CARET_WIDTH 2
// Minimum buffer size before delayed layout kicks in
#define wxRICHTEXT_DEFAULT_DELAYED_LAYOUT_THRESHOLD 20000
// Milliseconds before layout occurs after resize
#define wxRICHTEXT_DEFAULT_LAYOUT_INTERVAL 50

/* Identifiers
 */
#define wxID_RICHTEXT_PROPERTIES1   (wxID_HIGHEST + 1)
#define wxID_RICHTEXT_PROPERTIES2   (wxID_HIGHEST + 2)
#define wxID_RICHTEXT_PROPERTIES3   (wxID_HIGHEST + 3)

/*
    Normal selection occurs initially and as user drags within one container.
    Common ancestor selection occurs when the user starts dragging across containers
    that have a common ancestor, for example the cells in a table.
 */

enum wxRichTextCtrlSelectionState
{
    wxRichTextCtrlSelectionState_Normal,
    wxRichTextCtrlSelectionState_CommonAncestor
};

/**
    @class wxRichTextContextMenuPropertiesInfo

    wxRichTextContextMenuPropertiesInfo keeps track of objects that appear in the context menu,
    whose properties are available to be edited.
 */

class %delete wxRichTextContextMenuPropertiesInfo
{
public:
    /**
        Constructor.
    */
    wxRichTextContextMenuPropertiesInfo();

// Operations

    /**
        Initialisation.
    */
    void Init();

    /**
        Adds an item.
    */
    bool AddItem(const wxString& label, wxRichTextObject* obj);

    /**
        Returns the number of menu items that were added.
    */
    int AddMenuItems(wxMenu* menu, int startCmd = wxID_RICHTEXT_PROPERTIES1) const;

    /**
        Adds appropriate menu items for the current container and clicked on object
        (and container's parent, if appropriate).
    */
    int AddItems(wxRichTextCtrl* ctrl, wxRichTextObject* container, wxRichTextObject* obj);

    /**
        Clears the items.
    */
    void Clear();

// Accessors

    /**
        Returns the nth label.
    */
    wxString GetLabel(int n) const;

    /**
        Returns the nth object.
    */
    wxRichTextObject* GetObject(int n) const;

    /**
        Returns the array of objects.
    */
    wxRichTextObjectPtrArray& GetObjects();

    /**
        Returns the array of objects.
    */
    // wxLua: we do not need the const version
    //const wxRichTextObjectPtrArray& GetObjects() const;

    /**
        Returns the array of labels.
    */
    wxArrayString& GetLabels();

    /**
        Returns the array of labels.
    */
    const wxArrayString& GetLabels() const;

    /**
        Returns the number of items.
    */
    int GetCount() const;

    wxRichTextObjectPtrArray    m_objects;
    wxArrayString               m_labels;
};

/**
    @class wxRichTextCtrl

    wxRichTextCtrl provides a generic, ground-up implementation of a text control
    capable of showing multiple styles and images.

    wxRichTextCtrl sends notification events: see wxRichTextEvent.

    It also sends the standard wxTextCtrl events @c wxEVT_TEXT_ENTER and
    @c wxEVT_TEXT, and wxTextUrlEvent when URL content is clicked.

    For more information, see the @ref overview_richtextctrl.

    @beginStyleTable
    @style{wxRE_CENTRE_CARET}
           The control will try to keep the caret line centred vertically while editing.
           wxRE_CENTER_CARET is a synonym for this style.
    @style{wxRE_MULTILINE}
           The control will be multiline (mandatory).
    @style{wxRE_READONLY}
           The control will not be editable.
    @endStyleTable

    @library{wxrichtext}
    @category{richtext}
    @appearance{richtextctrl.png}

 */

class wxRichTextCtrl : public wxControl, public wxTextCtrlIface, public wxScrollHelper
{
    //DECLARE_DYNAMIC_CLASS( wxRichTextCtrl )
    //DECLARE_EVENT_TABLE()

public:
// Constructors

    /**
        Default constructor.
    */
    wxRichTextCtrl( );

    /**
        Constructor, creating and showing a rich text control.

        @param parent
            Parent window. Must not be @NULL.
        @param id
            Window identifier. The value @c wxID_ANY indicates a default value.
        @param value
            Default string.
        @param pos
            Window position.
        @param size
            Window size.
        @param style
            Window style.
        @param validator
            Window validator.
        @param name
            Window name.

        @see Create(), wxValidator
    */
    wxRichTextCtrl( wxWindow* parent, wxWindowID id = -1, const wxString& value = wxEmptyString, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize,
        long style = wxRE_MULTILINE, const wxValidator& validator = wxDefaultValidator, const wxString& name = wxTextCtrlNameStr);

    /**
        Destructor.
    */
    //virtual ~wxRichTextCtrl( );

// Operations

    /**
        Creates the underlying window.
    */
    bool Create( wxWindow* parent, wxWindowID id = -1, const wxString& value = wxEmptyString, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize,
        long style = wxRE_MULTILINE, const wxValidator& validator = wxDefaultValidator, const wxString& name = wxTextCtrlNameStr );

    /**
        Initialises the members of the control.
    */
    void Init();

// Accessors

    /**
        Gets the text for the given range.
        The end point of range is specified as the last character position of
        the span of text, plus one.
    */
    virtual wxString GetRange(long from, long to) const;

    /**
        Returns the length of the specified line in characters.
    */
    virtual int GetLineLength(long lineNo) const ;

    /**
        Returns the text for the given line.
    */
    virtual wxString GetLineText(long lineNo) const ;

    /**
        Returns the number of lines in the buffer.
    */
    virtual int GetNumberOfLines() const ;

    /**
        Returns @true if the buffer has been modified.
    */
    virtual bool IsModified() const ;

    /**
        Returns @true if the control is editable.
    */
    virtual bool IsEditable() const ;

    /**
        Returns @true if the control is single-line.
        Currently wxRichTextCtrl does not support single-line editing.
    */
    bool IsSingleLine() const;

    /**
        Returns @true if the control is multiline.
    */
    bool IsMultiLine() const;

    //@{
    /**
        Returns the range of the current selection.
        The end point of range is specified as the last character position of the span
        of text, plus one.
        If the return values @a from and @a to are the same, there is no selection.
    */
    virtual void GetSelection(long* from, long* to) const;
    const wxRichTextSelection& GetSelection() const;
    wxRichTextSelection& GetSelection();
    //@}

    /**
        Returns the text within the current selection range, if any.
    */
    virtual wxString GetStringSelection() const;

    /**
        Gets the current filename associated with the control.
    */
    wxString GetFilename() const;

    /**
        Sets the current filename.
    */
    void SetFilename(const wxString& filename);

    /**
        Sets the size of the buffer beyond which layout is delayed during resizing.
        This optimizes sizing for large buffers. The default is 20000.
    */
    void SetDelayedLayoutThreshold(long threshold);

    /**
        Gets the size of the buffer beyond which layout is delayed during resizing.
        This optimizes sizing for large buffers. The default is 20000.
    */
    long GetDelayedLayoutThreshold() const;

    /**
        Gets the flag indicating that full layout is required.
    */
    bool GetFullLayoutRequired() const;

    /**
        Sets the flag indicating that full layout is required.
    */
    void SetFullLayoutRequired(bool b);

    /**
        Returns the last time full layout was performed.
    */
    wxLongLong GetFullLayoutTime() const;

    /**
        Sets the last time full layout was performed.
    */
    void SetFullLayoutTime(wxLongLong t);

    /**
        Returns the position that should be shown when full (delayed) layout is performed.
    */
    long GetFullLayoutSavedPosition() const;

    /**
        Sets the position that should be shown when full (delayed) layout is performed.
    */
    void SetFullLayoutSavedPosition(long p);

    /**
        Forces any pending layout due to delayed, partial layout when the control
        was resized.
    */
    void ForceDelayedLayout();

    /**
        Sets the text (normal) cursor.
    */
    void SetTextCursor(const wxCursor& cursor );

    /**
        Returns the text (normal) cursor.
    */
    wxCursor GetTextCursor() const;

    /**
        Sets the cursor to be used over URLs.
    */
    void SetURLCursor(const wxCursor& cursor );

    /**
        Returns the cursor to be used over URLs.
    */
    wxCursor GetURLCursor() const;

    /**
        Returns @true if we are showing the caret position at the start of a line
        instead of at the end of the previous one.
    */
    bool GetCaretAtLineStart() const;

    /**
        Sets a flag to remember that we are showing the caret position at the start of a line
        instead of at the end of the previous one.
    */
    void SetCaretAtLineStart(bool atStart);

    /**
        Returns @true if we are dragging a selection.
    */
    bool GetDragging() const;

    /**
        Sets a flag to remember if we are dragging a selection.
    */
    void SetDragging(bool dragging);

#if wxUSE_DRAG_AND_DROP
    /**
        Are we trying to start Drag'n'Drop?
    */
    bool GetPreDrag() const;

    /**
        Set if we're trying to start Drag'n'Drop
    */
    void SetPreDrag(bool pd);

    /**
        Get the possible Drag'n'Drop start point
    */
    wxPoint GetDragStartPoint() const;

    /**
        Set the possible Drag'n'Drop start point
    */
    void SetDragStartPoint(wxPoint sp);

#if wxUSE_DATETIME
    /**
        Get the possible Drag'n'Drop start time
    */
    wxDateTime GetDragStartTime() const;

    /**
        Set the possible Drag'n'Drop start time
    */
    void SetDragStartTime(wxDateTime st);
#endif // wxUSE_DATETIME

#endif // wxUSE_DRAG_AND_DROP

#if wxRICHTEXT_BUFFERED_PAINTING
    //@{
    /**
        Returns the buffer bitmap if using buffered painting.
    */
    const wxBitmap& GetBufferBitmap() const;
    wxBitmap& GetBufferBitmap();
    //@}
#endif

    /**
        Returns the current context menu.
    */
    wxMenu* GetContextMenu() const;

    /**
        Sets the current context menu.
    */
    void SetContextMenu(wxMenu* menu);

    /**
        Returns an anchor so we know how to extend the selection.
        It's a caret position since it's between two characters.
    */
    long GetSelectionAnchor() const;

    /**
        Sets an anchor so we know how to extend the selection.
        It's a caret position since it's between two characters.
    */
    void SetSelectionAnchor(long anchor);

    /**
        Returns the anchor object if selecting multiple containers.
    */
    wxRichTextObject* GetSelectionAnchorObject() const;

    /**
        Sets the anchor object if selecting multiple containers.
    */
    void SetSelectionAnchorObject(wxRichTextObject* anchor);

    //@{
    /**
        Returns an object that stores information about context menu property item(s),
        in order to communicate between the context menu event handler and the code
        that responds to it. The wxRichTextContextMenuPropertiesInfo stores one
        item for each object that could respond to a property-editing event. If
        objects are nested, several might be editable.
    */
    wxRichTextContextMenuPropertiesInfo& GetContextMenuPropertiesInfo();
    const wxRichTextContextMenuPropertiesInfo& GetContextMenuPropertiesInfo() const;
    //@}

    /**
        Returns the wxRichTextObject object that currently has the editing focus.
        If there are no composite objects, this will be the top-level buffer.
    */
    wxRichTextParagraphLayoutBox* GetFocusObject() const;

    /**
        Sets m_focusObject without making any alterations.
    */
    void StoreFocusObject(wxRichTextParagraphLayoutBox* obj);

    /**
        Sets the wxRichTextObject object that currently has the editing focus.
    */
    bool SetFocusObject(wxRichTextParagraphLayoutBox* obj, bool setCaretPosition = true);

// Operations

    /**
        Invalidates the whole buffer to trigger painting later.
    */
    void Invalidate();

    /**
        Clears the buffer content, leaving a single empty paragraph. Cannot be undone.
    */
    virtual void Clear();

    /**
        Replaces the content in the specified range with the string specified by
        @a value.
    */
    virtual void Replace(long from, long to, const wxString& value);

    /**
        Removes the content in the specified range.
    */
    virtual void Remove(long from, long to);

//#ifdef DOXYGEN
    /**
        Loads content into the control's buffer using the given type.

        If the specified type is wxRICHTEXT_TYPE_ANY, the type is deduced from
        the filename extension.

        This function looks for a suitable wxRichTextFileHandler object.
    */
    //bool LoadFile(const wxString& file,
    //              int type = wxRICHTEXT_TYPE_ANY);
//#endif

#if wxUSE_FFILE && wxUSE_STREAMS
    /**
        Helper function for LoadFile(). Loads content into the control's buffer using the given type.

        If the specified type is wxRICHTEXT_TYPE_ANY, the type is deduced from
        the filename extension.

        This function looks for a suitable wxRichTextFileHandler object.
    */
    virtual bool DoLoadFile(const wxString& file, int fileType);
#endif // wxUSE_FFILE && wxUSE_STREAMS

//#ifdef DOXYGEN
    /**
        Saves the buffer content using the given type.

        If the specified type is wxRICHTEXT_TYPE_ANY, the type is deduced from
        the filename extension.

        This function looks for a suitable wxRichTextFileHandler object.
    */
    //bool SaveFile(const wxString& file = wxEmptyString,
    //             int type = wxRICHTEXT_TYPE_ANY);
//#endif

#if wxUSE_FFILE && wxUSE_STREAMS
    /**
        Helper function for SaveFile(). Saves the buffer content using the given type.

        If the specified type is wxRICHTEXT_TYPE_ANY, the type is deduced from
        the filename extension.

        This function looks for a suitable wxRichTextFileHandler object.
    */
    virtual bool DoSaveFile(const wxString& file = wxEmptyString,
                            int fileType = wxRICHTEXT_TYPE_ANY);
#endif // wxUSE_FFILE && wxUSE_STREAMS

    /**
        Sets flags that change the behaviour of loading or saving.

        See the documentation for each handler class to see what flags are
        relevant for each handler.
    */
    void SetHandlerFlags(int flags);

    /**
        Returns flags that change the behaviour of loading or saving.
        See the documentation for each handler class to see what flags are
        relevant for each handler.
    */
    int GetHandlerFlags() const;

    /**
        Marks the buffer as modified.
    */
    virtual void MarkDirty();

    /**
        Sets the buffer's modified status to @false, and clears the buffer's command
        history.
    */
    virtual void DiscardEdits();

    /**
        Sets the maximum number of characters that may be entered in a single line
        text control. For compatibility only; currently does nothing.
    */
    virtual void SetMaxLength(unsigned long len);

    /**
        Writes text at the current position.
    */
    virtual void WriteText(const wxString& text);

    /**
        Sets the insertion point to the end of the buffer and writes the text.
    */
    virtual void AppendText(const wxString& text);

    //@{
    /**
        Gets the attributes at the given position.
        This function gets the combined style - that is, the style you see on the
        screen as a result of combining base style, paragraph style and character
        style attributes.

        To get the character or paragraph style alone, use GetUncombinedStyle().

        @beginWxPerlOnly
        In wxPerl this method is implemented as GetStyle(@a position)
        returning a 2-element list (ok, attr).
        @endWxPerlOnly
    */
    //  Lua: %override [bool, wxRichTextAttr] GetStyle(long position)
    //       %override [bool, wxRichTextAttr] GetStyle(long position, wxRichTextParagraphLayoutBox *container);
    
    //virtual bool GetStyle(long position, wxTextAttr& style);
    //virtual bool GetStyle(long position, wxRichTextAttr& style);
    //virtual bool GetStyle(long position, wxRichTextAttr& style, wxRichTextParagraphLayoutBox* container);
    virtual bool GetStyle(long position);
    virtual bool GetStyle(long position, wxRichTextParagraphLayoutBox* container);
    //@}

    //@{
    /**
        Sets the attributes for the given range.
        The end point of range is specified as the last character position of the span
        of text, plus one.

        So, for example, to set the style for a character at position 5, use the range
        (5,6).
    */
    virtual bool SetStyle(long start, long end, const wxTextAttr& style);
    virtual bool SetStyle(long start, long end, const wxRichTextAttr& style);
    virtual bool SetStyle(const wxRichTextRange& range, const wxTextAttr& style);
    virtual bool SetStyle(const wxRichTextRange& range, const wxRichTextAttr& style);
    //@}

    /**
        Sets the attributes for a single object
    */
    virtual void SetStyle(wxRichTextObject *obj, const wxRichTextAttr& textAttr, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO);

    //@{
    /**
        Gets the attributes common to the specified range.
        Attributes that differ in value within the range will not be included
        in @a style flags.

        @beginWxPerlOnly
        In wxPerl this method is implemented as GetStyleForRange(@a position)
        returning a 2-element list (ok, attr).
        @endWxPerlOnly
    */
    //  Lua: %override [bool, wxRichTextAttr] GetStyleForRange(const wxRichTextRange& range);
    //       %override [bool, wxRichTextAttr] GetStyleForRange(const wxRichTextRange& range, wxRichTextParagraphLayoutBox* container);
    //virtual bool GetStyleForRange(const wxRichTextRange& range, wxTextAttr& style);
    //virtual bool GetStyleForRange(const wxRichTextRange& range, wxRichTextAttr& style);
    //virtual bool GetStyleForRange(const wxRichTextRange& range, wxRichTextAttr& style, wxRichTextParagraphLayoutBox* container);
    virtual bool GetStyleForRange(const wxRichTextRange& range);
    virtual bool GetStyleForRange(const wxRichTextRange& range, wxRichTextParagraphLayoutBox* container);
    //@}

    /**
        Sets the attributes for the given range, passing flags to determine how the
        attributes are set.

        The end point of range is specified as the last character position of the span
        of text, plus one. So, for example, to set the style for a character at
        position 5, use the range (5,6).

        @a flags may contain a bit list of the following values:
        - wxRICHTEXT_SETSTYLE_NONE: no style flag.
        - wxRICHTEXT_SETSTYLE_WITH_UNDO: specifies that this operation should be
          undoable.
        - wxRICHTEXT_SETSTYLE_OPTIMIZE: specifies that the style should not be applied
          if the combined style at this point is already the style in question.
        - wxRICHTEXT_SETSTYLE_PARAGRAPHS_ONLY: specifies that the style should only be
          applied to paragraphs, and not the content.
          This allows content styling to be preserved independently from that
          of e.g. a named paragraph style.
        - wxRICHTEXT_SETSTYLE_CHARACTERS_ONLY: specifies that the style should only be
          applied to characters, and not the paragraph.
          This allows content styling to be preserved independently from that
          of e.g. a named paragraph style.
        - wxRICHTEXT_SETSTYLE_RESET: resets (clears) the existing style before applying
          the new style.
        - wxRICHTEXT_SETSTYLE_REMOVE: removes the specified style. Only the style flags
          are used in this operation.
    */
    virtual bool SetStyleEx(const wxRichTextRange& range, const wxRichTextAttr& style, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO);

    //@{
    /**
        Gets the attributes at the given position.
        This function gets the @e uncombined style - that is, the attributes associated
        with the paragraph or character content, and not necessarily the combined
        attributes you see on the screen.
        To get the combined attributes, use GetStyle().

        If you specify (any) paragraph attribute in @e style's flags, this function
        will fetch the paragraph attributes.
        Otherwise, it will return the character attributes.

        @beginWxPerlOnly
        In wxPerl this method is implemented as GetUncombinedStyle(@a position)
        returning a 2-element list (ok, attr).
        @endWxPerlOnly
    */
    //  Lua: %override [bool, wxRichTextAttr] GetUncombinedStyle(long position);
    //       %override [bool, wxRichTextAttr] GetUncombinedStyle(long position, wxRichTextParagraphLayoutBox* container);
    //virtual bool GetUncombinedStyle(long position, wxRichTextAttr& style);
    //virtual bool GetUncombinedStyle(long position, wxRichTextAttr& style, wxRichTextParagraphLayoutBox* container);
    virtual bool GetUncombinedStyle(long position);
    virtual bool GetUncombinedStyle(long position, wxRichTextParagraphLayoutBox* container);
    //@}

    //@{
    /**
        Sets the current default style, which can be used to change how subsequently
        inserted text is displayed.
    */
    virtual bool SetDefaultStyle(const wxTextAttr& style);
    virtual bool SetDefaultStyle(const wxRichTextAttr& style);
    //@}

    /**
        Returns the current default style, which can be used to change how subsequently
        inserted text is displayed.
    */
    virtual const wxRichTextAttr& GetDefaultStyleEx() const;

    //virtual const wxTextAttr& GetDefaultStyle() const;

    //@{
    /**
        Sets the list attributes for the given range, passing flags to determine how
        the attributes are set.

        Either the style definition or the name of the style definition (in the current
        sheet) can be passed.
        @a flags is a bit list of the following:
        - wxRICHTEXT_SETSTYLE_WITH_UNDO: specifies that this command will be undoable.
        - wxRICHTEXT_SETSTYLE_RENUMBER: specifies that numbering should start from
          @a startFrom, otherwise existing attributes are used.
        - wxRICHTEXT_SETSTYLE_SPECIFY_LEVEL: specifies that @a listLevel should be used
          as the level for all paragraphs, otherwise the current indentation will be used.

        @see NumberList(), PromoteList(), ClearListStyle().
    */
    virtual bool SetListStyle(const wxRichTextRange& range, wxRichTextListStyleDefinition* def, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO, int startFrom = 1, int specifiedLevel = -1);
    virtual bool SetListStyle(const wxRichTextRange& range, const wxString& defName, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO, int startFrom = 1, int specifiedLevel = -1);
    //@}

    /**
        Clears the list style from the given range, clearing list-related attributes
        and applying any named paragraph style associated with each paragraph.

        @a flags is a bit list of the following:
        - wxRICHTEXT_SETSTYLE_WITH_UNDO: specifies that this command will be undoable.

        @see SetListStyle(), PromoteList(), NumberList().
    */
    virtual bool ClearListStyle(const wxRichTextRange& range, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO);

    //@{
    /**
        Numbers the paragraphs in the given range.
        Pass flags to determine how the attributes are set.

        Either the style definition or the name of the style definition (in the current
        sheet) can be passed.

        @a flags is a bit list of the following:
        - wxRICHTEXT_SETSTYLE_WITH_UNDO: specifies that this command will be undoable.
        - wxRICHTEXT_SETSTYLE_RENUMBER: specifies that numbering should start from
          @a startFrom, otherwise existing attributes are used.
        - wxRICHTEXT_SETSTYLE_SPECIFY_LEVEL: specifies that @a listLevel should be used
          as the level for all paragraphs, otherwise the current indentation will be used.

        @see SetListStyle(), PromoteList(), ClearListStyle().
    */
    virtual bool NumberList(const wxRichTextRange& range, wxRichTextListStyleDefinition* def = NULL, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO, int startFrom = 1, int specifiedLevel = -1);
    virtual bool NumberList(const wxRichTextRange& range, const wxString& defName, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO, int startFrom = 1, int specifiedLevel = -1);
    //@}

    //@{
    /**
        Promotes or demotes the paragraphs in the given range.
        A positive @a promoteBy produces a smaller indent, and a negative number
        produces a larger indent. Pass flags to determine how the attributes are set.
        Either the style definition or the name of the style definition (in the current
        sheet) can be passed.

        @a flags is a bit list of the following:
        - wxRICHTEXT_SETSTYLE_WITH_UNDO: specifies that this command will be undoable.
        - wxRICHTEXT_SETSTYLE_RENUMBER: specifies that numbering should start from
          @a startFrom, otherwise existing attributes are used.
        - wxRICHTEXT_SETSTYLE_SPECIFY_LEVEL: specifies that @a listLevel should be used
        as the level for all paragraphs, otherwise the current indentation will be used.

        @see SetListStyle(), @see SetListStyle(), ClearListStyle().
    */
    virtual bool PromoteList(int promoteBy, const wxRichTextRange& range, wxRichTextListStyleDefinition* def = NULL, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO, int specifiedLevel = -1);
    virtual bool PromoteList(int promoteBy, const wxRichTextRange& range, const wxString& defName, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO, int specifiedLevel = -1);
    //@}

    /**
        Sets the properties for the given range, passing flags to determine how the
        attributes are set. You can merge properties or replace them.

        The end point of range is specified as the last character position of the span
        of text, plus one. So, for example, to set the properties for a character at
        position 5, use the range (5,6).

        @a flags may contain a bit list of the following values:
        - wxRICHTEXT_SETSPROPERTIES_NONE: no flag.
        - wxRICHTEXT_SETPROPERTIES_WITH_UNDO: specifies that this operation should be
          undoable.
        - wxRICHTEXT_SETPROPERTIES_PARAGRAPHS_ONLY: specifies that the properties should only be
          applied to paragraphs, and not the content.
        - wxRICHTEXT_SETPROPERTIES_CHARACTERS_ONLY: specifies that the properties should only be
          applied to characters, and not the paragraph.
        - wxRICHTEXT_SETPROPERTIES_RESET: resets (clears) the existing properties before applying
          the new properties.
        - wxRICHTEXT_SETPROPERTIES_REMOVE: removes the specified properties.
    */
    virtual bool SetProperties(const wxRichTextRange& range, const wxRichTextProperties& properties, int flags = wxRICHTEXT_SETPROPERTIES_WITH_UNDO);

    /**
        Deletes the content within the given range.
    */
    virtual bool Delete(const wxRichTextRange& range);

    /**
        Translates from column and line number to position.
    */
    virtual long XYToPosition(long x, long y) const;

    /**
        Converts a text position to zero-based column and line numbers.
    */
    virtual bool PositionToXY(long pos, long *x, long *y) const;

    /**
        Scrolls the buffer so that the given position is in view.
    */
    virtual void ShowPosition(long pos);

    //@{
    /**
        Finds the character at the given position in pixels.
        @a pt is in device coords (not adjusted for the client area origin nor for
        scrolling).
    */
    virtual wxTextCtrlHitTestResult HitTest(const wxPoint& pt, long *pos) const;
    virtual wxTextCtrlHitTestResult HitTest(const wxPoint& pt,
                                            wxTextCoord *col,
                                            wxTextCoord *row) const;

    /**
        Finds the container at the given point, which is in screen coordinates.
    */
    wxRichTextParagraphLayoutBox* FindContainerAtPoint(const wxPoint pt, long& position, int& hit, wxRichTextObject* hitObj, int flags = 0);
    //@}

#if wxUSE_DRAG_AND_DROP
    /**
        Does the 'drop' of Drag'n'Drop.
    */
    void OnDrop(wxCoord x, wxCoord y, wxDragResult def, wxDataObject* DataObj);
#endif

// Clipboard operations

    /**
        Copies the selected content (if any) to the clipboard.
    */
    virtual void Copy();

    /**
        Copies the selected content (if any) to the clipboard and deletes the selection.
        This is undoable.
    */
    virtual void Cut();

    /**
        Pastes content from the clipboard to the buffer.
    */
    virtual void Paste();

    /**
        Deletes the content in the selection, if any. This is undoable.
    */
    virtual void DeleteSelection();

    /**
        Returns @true if selected content can be copied to the clipboard.
    */
    virtual bool CanCopy() const;

    /**
        Returns @true if selected content can be copied to the clipboard and deleted.
    */
    virtual bool CanCut() const;

    /**
        Returns @true if the clipboard content can be pasted to the buffer.
    */
    virtual bool CanPaste() const;

    /**
        Returns @true if selected content can be deleted.
    */
    virtual bool CanDeleteSelection() const;

    /**
        Undoes the command at the top of the command history, if there is one.
    */
    virtual void Undo();

    /**
        Redoes the current command.
    */
    virtual void Redo();

    /**
        Returns @true if there is a command in the command history that can be undone.
    */
    virtual bool CanUndo() const;

    /**
        Returns @true if there is a command in the command history that can be redone.
    */
    virtual bool CanRedo() const;

    /**
        Sets the insertion point and causes the current editing style to be taken from
        the new position (unlike wxRichTextCtrl::SetCaretPosition).
    */
    virtual void SetInsertionPoint(long pos);

    /**
        Sets the insertion point to the end of the text control.
    */
    virtual void SetInsertionPointEnd();

    /**
        Returns the current insertion point.
    */
    virtual long GetInsertionPoint() const;

    /**
        Returns the last position in the buffer.
    */
    virtual wxTextPos GetLastPosition() const;

    //@{
    /**
        Sets the selection to the given range.
        The end point of range is specified as the last character position of the span
        of text, plus one.

        So, for example, to set the selection for a character at position 5, use the
        range (5,6).
    */
    virtual void SetSelection(long from, long to);
    void SetSelection(const wxRichTextSelection& sel);
    //@}

    /**
        Makes the control editable, or not.
    */
    virtual void SetEditable(bool editable);

    /**
        Returns @true if there is a selection and the object containing the selection
        was the same as the current focus object.
    */
    virtual bool HasSelection() const;

    /**
        Returns @true if there was a selection, whether or not the current focus object
        is the same as the selection's container object.
    */
    virtual bool HasUnfocusedSelection() const;

    //@{
    /**
        Write a bitmap or image at the current insertion point.
        Supply an optional type to use for internal and file storage of the raw data.
    */
    virtual bool WriteImage(const wxImage& image, wxBitmapType bitmapType = wxBITMAP_TYPE_PNG,
                            const wxRichTextAttr& textAttr = wxDEFAULT_RICHTEXTATTR);

    virtual bool WriteImage(const wxBitmap& bitmap, wxBitmapType bitmapType = wxBITMAP_TYPE_PNG,
                            const wxRichTextAttr& textAttr = wxDEFAULT_RICHTEXTATTR);
    //@}

    /**
        Loads an image from a file and writes it at the current insertion point.
    */
    virtual bool WriteImage(const wxString& filename, wxBitmapType bitmapType = wxBITMAP_TYPE_PNG,
                            const wxRichTextAttr& textAttr = wxDEFAULT_RICHTEXTATTR);

    /**
        Writes an image block at the current insertion point.
    */
    virtual bool WriteImage(const wxRichTextImageBlock& imageBlock,
                            const wxRichTextAttr& textAttr = wxDEFAULT_RICHTEXTATTR);

    /**
        Write a text box at the current insertion point, returning the text box.
        You can then call SetFocusObject() to set the focus to the new object.
    */
    virtual wxRichTextBox* WriteTextBox(const wxRichTextAttr& textAttr = wxDEFAULT_RICHTEXTATTR);

    /**
        Writes a field at the current insertion point.

        @param fieldType
            The field type, matching an existing field type definition.
        @param properties
            Extra data for the field.
        @param textAttr
            Optional attributes.

        @see wxRichTextField, wxRichTextFieldType, wxRichTextFieldTypeStandard
    */
    virtual wxRichTextField* WriteField(const wxString& fieldType, const wxRichTextProperties& properties,
                            const wxRichTextAttr& textAttr = wxDEFAULT_RICHTEXTATTR);

    /**
        Write a table at the current insertion point, returning the table.
        You can then call SetFocusObject() to set the focus to the new object.
    */
    virtual wxRichTextTable* WriteTable(int rows, int cols, const wxRichTextAttr& tableAttr = wxDEFAULT_RICHTEXTATTR, const wxRichTextAttr& cellAttr = wxDEFAULT_RICHTEXTATTR);

    /**
        Inserts a new paragraph at the current insertion point. @see LineBreak().
    */
    virtual bool Newline();

    /**
        Inserts a line break at the current insertion point.

        A line break forces wrapping within a paragraph, and can be introduced by
        using this function, by appending the wxChar value @b  wxRichTextLineBreakChar
        to text content, or by typing Shift-Return.
    */
    virtual bool LineBreak();

    /**
        Sets the basic (overall) style.

        This is the style of the whole buffer before further styles are applied,
        unlike the default style, which only affects the style currently being
        applied (for example, setting the default style to bold will cause
        subsequently inserted text to be bold).
    */
    virtual void SetBasicStyle(const wxRichTextAttr& style);

    /**
        Gets the basic (overall) style.

        This is the style of the whole buffer before further styles are applied,
        unlike the default style, which only affects the style currently being
        applied (for example, setting the default style to bold will cause
        subsequently inserted text to be bold).
    */
    virtual const wxRichTextAttr& GetBasicStyle() const;

    /**
        Begins applying a style.
    */
    virtual bool BeginStyle(const wxRichTextAttr& style);

    /**
        Ends the current style.
    */
    virtual bool EndStyle();

    /**
        Ends application of all styles in the current style stack.
    */
    virtual bool EndAllStyles();

    /**
        Begins using bold.
    */
    bool BeginBold();

    /**
        Ends using bold.
    */
    bool EndBold();

    /**
        Begins using italic.
    */
    bool BeginItalic();

    /**
        Ends using italic.
    */
    bool EndItalic();

    /**
        Begins using underlining.
    */
    bool BeginUnderline();

    /**
        End applying underlining.
    */
    bool EndUnderline();

    /**
        Begins using the given point size.
    */
    bool BeginFontSize(int pointSize);

    /**
        Ends using a point size.
    */
    bool EndFontSize();

    /**
        Begins using this font.
    */
    bool BeginFont(const wxFont& font);

    /**
        Ends using a font.
    */
    bool EndFont();

    /**
        Begins using this colour.
    */
    bool BeginTextColour(const wxColour& colour);

    /**
        Ends applying a text colour.
    */
    bool EndTextColour();

    /**
        Begins using alignment.
        For alignment values, see wxTextAttr.
    */
    bool BeginAlignment(wxTextAttrAlignment alignment);

    /**
        Ends alignment.
    */
    bool EndAlignment();

    /**
        Begins applying a left indent and subindent in tenths of a millimetre.
        The subindent is an offset from the left edge of the paragraph, and is
        used for all but the first line in a paragraph. A positive value will
        cause the first line to appear to the left of the subsequent lines, and
        a negative value will cause the first line to be indented to the right
        of the subsequent lines.

        wxRichTextBuffer uses indentation to render a bulleted item. The
        content of the paragraph, including the first line, starts at the
        @a leftIndent plus the @a leftSubIndent.

        @param leftIndent
            The distance between the margin and the bullet.
        @param leftSubIndent
             The distance between the left edge of the bullet and the left edge
             of the actual paragraph.
    */
    bool BeginLeftIndent(int leftIndent, int leftSubIndent = 0);

    /**
        Ends left indent.
    */
    bool EndLeftIndent();

    /**
        Begins a right indent, specified in tenths of a millimetre.
    */
    bool BeginRightIndent(int rightIndent);

    /**
        Ends right indent.
    */
    bool EndRightIndent();

    /**
        Begins paragraph spacing; pass the before-paragraph and after-paragraph spacing
        in tenths of a millimetre.
    */
    bool BeginParagraphSpacing(int before, int after);

    /**
        Ends paragraph spacing.
    */
    bool EndParagraphSpacing();

    /**
        Begins appling line spacing. @e spacing is a multiple, where 10 means
        single-spacing, 15 means 1.5 spacing, and 20 means double spacing.

        The ::wxTextAttrLineSpacing constants are defined for convenience.
    */
    bool BeginLineSpacing(int lineSpacing);

    /**
        Ends line spacing.
    */
    bool EndLineSpacing();

    /**
        Begins a numbered bullet.

        This call will be needed for each item in the list, and the
        application should take care of incrementing the numbering.

        @a bulletNumber is a number, usually starting with 1.
        @a leftIndent and @a leftSubIndent are values in tenths of a millimetre.
        @a bulletStyle is a bitlist of the  ::wxTextAttrBulletStyle values.

        wxRichTextBuffer uses indentation to render a bulleted item.
        The left indent is the distance between the margin and the bullet.
        The content of the paragraph, including the first line, starts
        at leftMargin + leftSubIndent.
        So the distance between the left edge of the bullet and the
        left of the actual paragraph is leftSubIndent.
    */
    bool BeginNumberedBullet(int bulletNumber, int leftIndent, int leftSubIndent, int bulletStyle = wxTEXT_ATTR_BULLET_STYLE_ARABIC|wxTEXT_ATTR_BULLET_STYLE_PERIOD);

    /**
        Ends application of a numbered bullet.
    */
    bool EndNumberedBullet();

    /**
        Begins applying a symbol bullet, using a character from the current font.
        See BeginNumberedBullet() for an explanation of how indentation is used
        to render the bulleted paragraph.
    */
    bool BeginSymbolBullet(const wxString& symbol, int leftIndent, int leftSubIndent, int bulletStyle = wxTEXT_ATTR_BULLET_STYLE_SYMBOL);

    /**
        Ends applying a symbol bullet.
    */
    bool EndSymbolBullet();

    /**
        Begins applying a symbol bullet.
    */
    bool BeginStandardBullet(const wxString& bulletName, int leftIndent, int leftSubIndent, int bulletStyle = wxTEXT_ATTR_BULLET_STYLE_STANDARD);

    /**
        Begins applying a standard bullet.
    */
    bool EndStandardBullet();

    /**
        Begins using the named character style.
    */
    bool BeginCharacterStyle(const wxString& characterStyle);

    /**
        Ends application of a named character style.
    */
    bool EndCharacterStyle();

    /**
        Begins applying the named paragraph style.
    */
    bool BeginParagraphStyle(const wxString& paragraphStyle);

    /**
        Ends application of a named paragraph style.
    */
    bool EndParagraphStyle();

    /**
        Begins using a specified list style.
        Optionally, you can also pass a level and a number.
    */
    bool BeginListStyle(const wxString& listStyle, int level = 1, int number = 1);

    /**
        Ends using a specified list style.
    */
    bool EndListStyle();

    /**
        Begins applying wxTEXT_ATTR_URL to the content.

        Pass a URL and optionally, a character style to apply, since it is common
        to mark a URL with a familiar style such as blue text with underlining.
    */
    bool BeginURL(const wxString& url, const wxString& characterStyle = wxEmptyString);

    /**
        Ends applying a URL.
    */
    bool EndURL();

    /**
        Sets the default style to the style under the cursor.
    */
    bool SetDefaultStyleToCursorStyle();

    /**
        Cancels any selection.
    */
    virtual void SelectNone();

    /**
        Selects the word at the given character position.
    */
    virtual bool SelectWord(long position);

    /**
        Returns the selection range in character positions. -1, -1 means no selection.

        The range is in API convention, i.e. a single character selection is denoted
        by (n, n+1)
    */
    wxRichTextRange GetSelectionRange() const;

    /**
        Sets the selection to the given range.
        The end point of range is specified as the last character position of the span
        of text, plus one.

        So, for example, to set the selection for a character at position 5, use the
        range (5,6).
    */
    void SetSelectionRange(const wxRichTextRange& range);

    /**
        Returns the selection range in character positions. -2, -2 means no selection
        -1, -1 means select everything.
        The range is in internal format, i.e. a single character selection is denoted
        by (n, n)
    */
    wxRichTextRange GetInternalSelectionRange() const;

    /**
        Sets the selection range in character positions. -2, -2 means no selection
        -1, -1 means select everything.
        The range is in internal format, i.e. a single character selection is denoted
        by (n, n)
    */
    void SetInternalSelectionRange(const wxRichTextRange& range);

    /**
        Adds a new paragraph of text to the end of the buffer.
    */
    virtual wxRichTextRange AddParagraph(const wxString& text);

    /**
        Adds an image to the control's buffer.
    */
    virtual wxRichTextRange AddImage(const wxImage& image);

    /**
        Lays out the buffer, which must be done before certain operations, such as
        setting the caret position.
        This function should not normally be required by the application.
    */
    virtual bool LayoutContent(bool onlyVisibleRect = false);

    /**
        Move the caret to the given character position.

        Please note that this does not update the current editing style
        from the new position; to do that, call wxRichTextCtrl::SetInsertionPoint instead.
    */
    virtual bool MoveCaret(long pos, bool showAtLineStart = false, wxRichTextParagraphLayoutBox* container = NULL);

    /**
        Moves right.
    */
    virtual bool MoveRight(int noPositions = 1, int flags = 0);

    /**
        Moves left.
    */
    virtual bool MoveLeft(int noPositions = 1, int flags = 0);

    /**
        Moves to the start of the paragraph.
    */
    virtual bool MoveUp(int noLines = 1, int flags = 0);

    /**
        Moves the caret down.
    */
    virtual bool MoveDown(int noLines = 1, int flags = 0);

    /**
        Moves to the end of the line.
    */
    virtual bool MoveToLineEnd(int flags = 0);

    /**
        Moves to the start of the line.
    */
    virtual bool MoveToLineStart(int flags = 0);

    /**
        Moves to the end of the paragraph.
    */
    virtual bool MoveToParagraphEnd(int flags = 0);

    /**
        Moves to the start of the paragraph.
    */
    virtual bool MoveToParagraphStart(int flags = 0);

    /**
        Moves to the start of the buffer.
    */
    virtual bool MoveHome(int flags = 0);

    /**
        Moves to the end of the buffer.
    */
    virtual bool MoveEnd(int flags = 0);

    /**
        Moves one or more pages up.
    */
    virtual bool PageUp(int noPages = 1, int flags = 0);

    /**
        Moves one or more pages down.
    */
    virtual bool PageDown(int noPages = 1, int flags = 0);

    /**
        Moves a number of words to the left.
    */
    virtual bool WordLeft(int noPages = 1, int flags = 0);

    /**
        Move a nuber of words to the right.
    */
    virtual bool WordRight(int noPages = 1, int flags = 0);

    //@{
    /**
        Returns the buffer associated with the control.
    */
    wxRichTextBuffer& GetBuffer();
    const wxRichTextBuffer& GetBuffer() const;
    //@}

    /**
        Starts batching undo history for commands.
    */
    virtual bool BeginBatchUndo(const wxString& cmdName);

    /**
        Ends batching undo command history.
    */
    virtual bool EndBatchUndo();

    /**
        Returns @true if undo commands are being batched.
    */
    virtual bool BatchingUndo() const;

    /**
        Starts suppressing undo history for commands.
    */
    virtual bool BeginSuppressUndo();

    /**
        Ends suppressing undo command history.
    */
    virtual bool EndSuppressUndo();

    /**
        Returns @true if undo history suppression is on.
    */
    virtual bool SuppressingUndo() const;

    /**
        Test if this whole range has character attributes of the specified kind.
        If any of the attributes are different within the range, the test fails.

        You can use this to implement, for example, bold button updating.
        @a style must have flags indicating which attributes are of interest.
    */
    virtual bool HasCharacterAttributes(const wxRichTextRange& range, const wxRichTextAttr& style) const;

    /**
        Test if this whole range has paragraph attributes of the specified kind.
        If any of the attributes are different within the range, the test fails.
        You can use this to implement, for example, centering button updating.
        @a style must have flags indicating which attributes are of interest.
    */
    virtual bool HasParagraphAttributes(const wxRichTextRange& range, const wxRichTextAttr& style) const;

    /**
        Returns @true if all of the selection, or the content at the caret position, is bold.
    */
    virtual bool IsSelectionBold();

    /**
        Returns @true if all of the selection, or the content at the caret position, is italic.
    */
    virtual bool IsSelectionItalics();

    /**
        Returns @true if all of the selection, or the content at the caret position, is underlined.
    */
    virtual bool IsSelectionUnderlined();

    /**
        Returns @true if all of the selection, or the content at the current caret position, has the supplied wxTextAttrEffects flag(s).
    */
    virtual bool DoesSelectionHaveTextEffectFlag(int flag);

    /**
        Returns @true if all of the selection, or the content at the caret position, is aligned according to the specified flag.
    */
    virtual bool IsSelectionAligned(wxTextAttrAlignment alignment);

    /**
        Apples bold to the selection or default style (undoable).
    */
    virtual bool ApplyBoldToSelection();

    /**
        Applies italic to the selection or default style (undoable).
    */
    virtual bool ApplyItalicToSelection();

    /**
        Applies underline to the selection or default style (undoable).
    */
    virtual bool ApplyUnderlineToSelection();

    /**
        Applies one or more wxTextAttrEffects flags to the selection (undoable).
        If there is no selection, it is applied to the default style.
    */
    virtual bool ApplyTextEffectToSelection(int flags);

    /**
        Applies the given alignment to the selection or the default style (undoable).
        For alignment values, see wxTextAttr.
    */
    virtual bool ApplyAlignmentToSelection(wxTextAttrAlignment alignment);

    /**
        Applies the style sheet to the buffer, matching paragraph styles in the sheet
        against named styles in the buffer.

        This might be useful if the styles have changed.
        If @a sheet is @NULL, the sheet set with SetStyleSheet() is used.
        Currently this applies paragraph styles only.
    */
    virtual bool ApplyStyle(wxRichTextStyleDefinition* def);

    /**
        Sets the style sheet associated with the control.
        A style sheet allows named character and paragraph styles to be applied.
    */
    void SetStyleSheet(wxRichTextStyleSheet* styleSheet);

    /**
        Returns the style sheet associated with the control, if any.
        A style sheet allows named character and paragraph styles to be applied.
    */
    wxRichTextStyleSheet* GetStyleSheet() const;

    /**
        Push the style sheet to top of stack.
    */
    bool PushStyleSheet(wxRichTextStyleSheet* styleSheet);

    /**
        Pops the style sheet from top of stack.
    */
    wxRichTextStyleSheet* PopStyleSheet();

    /**
        Applies the style sheet to the buffer, for example if the styles have changed.
    */
    bool ApplyStyleSheet(wxRichTextStyleSheet* styleSheet = NULL);

    /**
        Shows the given context menu, optionally adding appropriate property-editing commands for the current position in the object hierarchy.
    */
    virtual bool ShowContextMenu(wxMenu* menu, const wxPoint& pt, bool addPropertyCommands = true);

    /**
        Prepares the context menu, optionally adding appropriate property-editing commands.
        Returns the number of property commands added.
    */
    virtual int PrepareContextMenu(wxMenu* menu, const wxPoint& pt, bool addPropertyCommands = true);

    /**
        Returns @true if we can edit the object's properties via a GUI.
    */
    virtual bool CanEditProperties(wxRichTextObject* obj) const;

    /**
        Edits the object's properties via a GUI.
    */
    virtual bool EditProperties(wxRichTextObject* obj, wxWindow* parent);

    /**
        Gets the object's properties menu label.
    */
    virtual wxString GetPropertiesMenuLabel(wxRichTextObject* obj);

    /**
        Prepares the content just before insertion (or after buffer reset). Called by the same function in wxRichTextBuffer.
        Currently is only called if undo mode is on.
    */
    virtual void PrepareContent(wxRichTextParagraphLayoutBox& container);

    /**
        Can we delete this range?
        Sends an event to the control.
    */
    virtual bool CanDeleteRange(wxRichTextParagraphLayoutBox& container, const wxRichTextRange& range) const;

    /**
        Can we insert content at this position?
        Sends an event to the control.
    */
    virtual bool CanInsertContent(wxRichTextParagraphLayoutBox& container, long pos) const;

    /**
        Enable or disable the vertical scrollbar.
    */
    virtual void EnableVerticalScrollbar(bool enable);

    /**
        Returns @true if the vertical scrollbar is enabled.
    */
    virtual bool GetVerticalScrollbarEnabled() const;

    /**
        Sets the scale factor for displaying fonts, for example for more comfortable
        editing.
    */
    void SetFontScale(double fontScale, bool refresh = false);

    /**
        Returns the scale factor for displaying fonts, for example for more comfortable
        editing.
    */
    double GetFontScale() const;

    /**
        Sets the scale factor for displaying certain dimensions such as indentation and
        inter-paragraph spacing. This can be useful when editing in a small control
        where you still want legible text, but a minimum of wasted white space.
    */
    void SetDimensionScale(double dimScale, bool refresh = false);

    /**
        Returns the scale factor for displaying certain dimensions such as indentation
        and inter-paragraph spacing.
    */
    double GetDimensionScale() const;

    /**
        Sets an overall scale factor for displaying and editing the content.
    */
    void SetScale(double scale, bool refresh = false);

    /**
        Returns an overall scale factor for displaying and editing the content.
    */
    double GetScale() const;

    /**
        Returns an unscaled point.
    */
    wxPoint GetUnscaledPoint(const wxPoint& pt) const;

    /**
        Returns a scaled point.
    */
    wxPoint GetScaledPoint(const wxPoint& pt) const;

    /**
        Returns an unscaled size.
    */
    wxSize GetUnscaledSize(const wxSize& sz) const;

    /**
        Returns a scaled size.
    */
    wxSize GetScaledSize(const wxSize& sz) const;

    /**
        Returns an unscaled rectangle.
    */
    wxRect GetUnscaledRect(const wxRect& rect) const;

    /**
        Returns a scaled rectangle.
    */
    wxRect GetScaledRect(const wxRect& rect) const;

    /**
        Returns @true if this control can use virtual attributes and virtual text.
        The default is @false.
    */
    bool GetVirtualAttributesEnabled() const;

    /**
        Pass @true to let the control use virtual attributes.
        The default is @false.
    */
    void EnableVirtualAttributes(bool b);

// Command handlers

    /**
        Sends the event to the control.
    */
    void Command(wxCommandEvent& event);

    /**
        Loads the first dropped file.
    */
    void OnDropFiles(wxDropFilesEvent& event);

    void OnCaptureLost(wxMouseCaptureLostEvent& event);
    void OnSysColourChanged(wxSysColourChangedEvent& event);

    /**
        Standard handler for the wxID_CUT command.
    */
    void OnCut(wxCommandEvent& event);

    /**
        Standard handler for the wxID_COPY command.
    */
    void OnCopy(wxCommandEvent& event);

    /**
        Standard handler for the wxID_PASTE command.
    */
    void OnPaste(wxCommandEvent& event);

    /**
        Standard handler for the wxID_UNDO command.
    */
    void OnUndo(wxCommandEvent& event);

    /**
        Standard handler for the wxID_REDO command.
    */
    void OnRedo(wxCommandEvent& event);

    /**
        Standard handler for the wxID_SELECTALL command.
    */
    void OnSelectAll(wxCommandEvent& event);

    /**
        Standard handler for property commands.
    */
    void OnProperties(wxCommandEvent& event);

    /**
        Standard handler for the wxID_CLEAR command.
    */
    void OnClear(wxCommandEvent& event);

    /**
        Standard update handler for the wxID_CUT command.
    */
    void OnUpdateCut(wxUpdateUIEvent& event);

    /**
        Standard update handler for the wxID_COPY command.
    */
    void OnUpdateCopy(wxUpdateUIEvent& event);

    /**
        Standard update handler for the wxID_PASTE command.
    */
    void OnUpdatePaste(wxUpdateUIEvent& event);

    /**
        Standard update handler for the wxID_UNDO command.
    */
    void OnUpdateUndo(wxUpdateUIEvent& event);

    /**
        Standard update handler for the wxID_REDO command.
    */
    void OnUpdateRedo(wxUpdateUIEvent& event);

    /**
        Standard update handler for the wxID_SELECTALL command.
    */
    void OnUpdateSelectAll(wxUpdateUIEvent& event);

    /**
        Standard update handler for property commands.
    */

    void OnUpdateProperties(wxUpdateUIEvent& event);

    /**
        Standard update handler for the wxID_CLEAR command.
    */
    void OnUpdateClear(wxUpdateUIEvent& event);

    /**
        Shows a standard context menu with undo, redo, cut, copy, paste, clear, and
        select all commands.
    */
    void OnContextMenu(wxContextMenuEvent& event);

// Event handlers

    // Painting
    void OnPaint(wxPaintEvent& event);
    void OnEraseBackground(wxEraseEvent& event);

    // Left-click
    void OnLeftClick(wxMouseEvent& event);

    // Left-up
    void OnLeftUp(wxMouseEvent& event);

    // Motion
    void OnMoveMouse(wxMouseEvent& event);

    // Left-double-click
    void OnLeftDClick(wxMouseEvent& event);

    // Middle-click
    void OnMiddleClick(wxMouseEvent& event);

    // Right-click
    void OnRightClick(wxMouseEvent& event);

    // Key press
    void OnChar(wxKeyEvent& event);

    // Sizing
    void OnSize(wxSizeEvent& event);

    // Setting/losing focus
    void OnSetFocus(wxFocusEvent& event);
    void OnKillFocus(wxFocusEvent& event);

    // Idle-time processing
    void OnIdle(wxIdleEvent& event);

    // Scrolling
    void OnScroll(wxScrollWinEvent& event);

    /**
        Sets the font, and also the basic and default attributes
        (see wxRichTextCtrl::SetDefaultStyle).
    */
    virtual bool SetFont(const wxFont& font);

    /**
        A helper function setting up scrollbars, for example after a resize.
    */
    virtual void SetupScrollbars(bool atTop = false);

    /**
        Helper function implementing keyboard navigation.
    */
    virtual bool KeyboardNavigate(int keyCode, int flags);

    /**
        Paints the background.
    */
    virtual void PaintBackground(wxDC& dc);

    /**
        Other user defined painting after everything else (i.e. all text) is painted.

        @since 2.9.1
    */
    virtual void PaintAboveContent(wxDC& dc);

#if wxRICHTEXT_BUFFERED_PAINTING
    /**
        Recreates the buffer bitmap if necessary.
    */
    virtual bool RecreateBuffer(const wxSize& size = wxDefaultSize);
#endif

    // Write text
    virtual void DoWriteText(const wxString& value, int flags = 0);

    // Should we inherit colours?
    virtual bool ShouldInheritColours() const;

    /**
        Internal function to position the visible caret according to the current caret
        position.
    */
    virtual void PositionCaret(wxRichTextParagraphLayoutBox* container = NULL);

    /**
        Helper function for extending the selection, returning @true if the selection
        was changed. Selections are in caret positions.
    */
    virtual bool ExtendSelection(long oldPosition, long newPosition, int flags);

    /**
        Scrolls @a position into view. This function takes a caret position.
    */
    virtual bool ScrollIntoView(long position, int keyCode);

    /**
        Refreshes the area affected by a selection change.
    */
    bool RefreshForSelectionChange(const wxRichTextSelection& oldSelection, const wxRichTextSelection& newSelection);

    /**
        Sets the caret position.

        The caret position is the character position just before the caret.
        A value of -1 means the caret is at the start of the buffer.
        Please note that this does not update the current editing style
        from the new position or cause the actual caret to be refreshed; to do that,
        call wxRichTextCtrl::SetInsertionPoint instead.
    */
    void SetCaretPosition(long position, bool showAtLineStart = false) ;

    /**
        Returns the current caret position.
    */
    long GetCaretPosition() const;

    /**
        The adjusted caret position is the character position adjusted to take
        into account whether we're at the start of a paragraph, in which case
        style information should be taken from the next position, not current one.
    */
    long GetAdjustedCaretPosition(long caretPos) const;

    /**
        Move the caret one visual step forward: this may mean setting a flag
        and keeping the same position if we're going from the end of one line
        to the start of the next, which may be the exact same caret position.
    */
    void MoveCaretForward(long oldPosition) ;

    /**
        Move the caret one visual step forward: this may mean setting a flag
        and keeping the same position if we're going from the end of one line
        to the start of the next, which may be the exact same caret position.
    */
    void MoveCaretBack(long oldPosition) ;

    /**
        Returns the caret height and position for the given character position.
        If container is null, the current focus object will be used.

        @beginWxPerlOnly
        In wxPerl this method is implemented as
        GetCaretPositionForIndex(@a position) returning a
        2-element list (ok, rect).
        @endWxPerlOnly
    */
    //  Lua: %override [bool, wxRect] GetCaretPositionForIndex(long position, wxRect& rect, wxRichTextParagraphLayoutBox* container = NULL);
    //bool GetCaretPositionForIndex(long position, wxRect& rect, wxRichTextParagraphLayoutBox* container = NULL);
    bool GetCaretPositionForIndex(long position, wxRichTextParagraphLayoutBox* container = NULL);

    /**
        Internal helper function returning the line for the visible caret position.
        If the caret is shown at the very end of the line, it means the next character
        is actually on the following line.
        So this function gets the line we're expecting to find if this is the case.
    */
    wxRichTextLine* GetVisibleLineForCaretPosition(long caretPosition) const;

    /**
        Gets the command processor associated with the control's buffer.
    */
    wxCommandProcessor* GetCommandProcessor() const;

    /**
        Deletes content if there is a selection, e.g. when pressing a key.
        Returns the new caret position in @e newPos, or leaves it if there
        was no action. This is undoable.

        @beginWxPerlOnly
        In wxPerl this method takes no arguments and returns a 2-element
        list (ok, newPos).
        @endWxPerlOnly
    */
    //  Lua: %override [bool, long] DeleteSelectedContent();
    bool DeleteSelectedContent(long* newPos= NULL);

    /**
        Transforms logical (unscrolled) position to physical window position.
    */
    wxPoint GetPhysicalPoint(const wxPoint& ptLogical) const;

    /**
        Transforms physical window position to logical (unscrolled) position.
    */
    wxPoint GetLogicalPoint(const wxPoint& ptPhysical) const;

    /**
        Helper function for finding the caret position for the next word.
        Direction is 1 (forward) or -1 (backwards).
    */
    virtual long FindNextWordPosition(int direction = 1) const;

    /**
        Returns @true if the given position is visible on the screen.
    */
    bool IsPositionVisible(long pos) const;

    /**
        Returns the first visible position in the current view.
    */
    long GetFirstVisiblePosition() const;

    /**
        Returns the caret position since the default formatting was changed. As
        soon as this position changes, we no longer reflect the default style
        in the UI. A value of -2 means that we should only reflect the style of the
        content under the caret.
    */
    long GetCaretPositionForDefaultStyle() const;

    /**
        Set the caret position for the default style that the user is selecting.
    */
    void SetCaretPositionForDefaultStyle(long pos);

    /**
        Returns @true if the user has recently set the default style without moving
        the caret, and therefore the UI needs to reflect the default style and not
        the style at the caret.

        Below is an example of code that uses this function to determine whether the UI
        should show that the current style is bold.

        @see SetAndShowDefaultStyle().
    */
    bool IsDefaultStyleShowing() const;

    /**
        Sets @a attr as the default style and tells the control that the UI should
        reflect this attribute until the user moves the caret.

        @see IsDefaultStyleShowing().
    */
    void SetAndShowDefaultStyle(const wxRichTextAttr& attr);

    /**
        Returns the first visible point in the window.
    */
    wxPoint GetFirstVisiblePoint() const;

//#ifdef DOXYGEN
    /**
        Returns the content of the entire control as a string.
    */
    //virtual wxString GetValue() const;

    /**
        Replaces existing content with the given text.
    */
    //virtual void SetValue(const wxString& value);

    /**
        Call this function to prevent refresh and allow fast updates, and then Thaw() to
        refresh the control.
    */
    //void Freeze();

    /**
        Call this function to end a Freeze and refresh the display.
    */
    //void Thaw();

    /**
        Returns @true if Freeze has been called without a Thaw.
    */
    //bool IsFrozen() const;

//#endif

// Implementation

    /**
        Processes the back key.
    */
    virtual bool ProcessBackKey(wxKeyEvent& event, int flags);

    /**
        Given a character position at which there is a list style, find the range
        encompassing the same list style by looking backwards and forwards.
    */
    virtual wxRichTextRange FindRangeForList(long pos, bool& isNumberedList);

    /**
        Sets up the caret for the given position and container, after a mouse click.
    */
    bool SetCaretPositionAfterClick(wxRichTextParagraphLayoutBox* container, long position, int hitTestFlags, bool extendSelection = false);

    /**
        Find the caret position for the combination of hit-test flags and character position.
        Returns the caret position and also an indication of where to place the caret (caretLineStart)
        since this is ambiguous (same position used for end of line and start of next).
    */
    long FindCaretPositionForCharacterPosition(long position, int hitTestFlags, wxRichTextParagraphLayoutBox* container,
                                                   bool& caretLineStart);

    /**
        Processes mouse movement in order to change the cursor
    */
    virtual bool ProcessMouseMovement(wxRichTextParagraphLayoutBox* container, wxRichTextObject* obj, long position, const wxPoint& pos);

    /**
        Font names take a long time to retrieve, so cache them (on demand).
    */
    static const wxArrayString& GetAvailableFontNames();

    /**
        Clears the cache of available font names.
    */
    static void ClearAvailableFontNames();

    //WX_FORWARD_TO_SCROLL_HELPER()

    // implement wxTextEntry methods
    virtual wxString DoGetValue() const;

protected:
    // implement the wxTextEntry pure virtual method
    virtual wxWindow *GetEditableWindow();

    // margins functions
    virtual bool DoSetMargins(const wxPoint& pt);
    virtual wxPoint DoGetMargins() const;

/*
     // FIXME: this does not work, it allows this code to compile but will fail
     //        during run-time
#ifndef __WXUNIVERSAL__
#ifdef __WXMSW__
    virtual WXHWND GetEditHWND() const;
#endif
#ifdef __WXMOTIF__
    virtual WXWidget GetTextWidget() const;
#endif
#ifdef __WXGTK20__
    virtual GtkEditable *GetEditable() const;
    virtual GtkEntry *GetEntry() const;
#endif
#endif // !__WXUNIVERSAL__
*/

// Overrides
protected:

    /**
        Currently this simply returns @c wxSize(10, 10).
    */
    virtual wxSize DoGetBestSize() const ;

    virtual void DoSetValue(const wxString& value, int flags = 0);

    virtual void DoThaw();


// Data members
protected:
#if wxRICHTEXT_BUFFERED_PAINTING
    /// Buffer bitmap
    wxBitmap                m_bufferBitmap;
#endif

    /// Text buffer
    wxRichTextBuffer        m_buffer;

    wxMenu*                 m_contextMenu;

    /// Caret position (1 less than the character position, so -1 is the
    /// first caret position).
    long                    m_caretPosition;

    /// Caret position when the default formatting has been changed. As
    /// soon as this position changes, we no longer reflect the default style
    /// in the UI.
    long                    m_caretPositionForDefaultStyle;

    /// Selection range in character positions. -2, -2 means no selection.
    wxRichTextSelection     m_selection;

    wxRichTextCtrlSelectionState m_selectionState;

    /// Anchor so we know how to extend the selection
    /// It's a caret position since it's between two characters.
    long                    m_selectionAnchor;

    /// Anchor object if selecting multiple container objects, such as grid cells.
    wxRichTextObject*       m_selectionAnchorObject;

    /// Are we editable?
    bool                    m_editable;

    /// Can we use virtual attributes and virtual text?
    bool                    m_useVirtualAttributes;

    /// Is the vertical scrollbar enabled?
    bool                    m_verticalScrollbarEnabled;

    /// Are we showing the caret position at the start of a line
    /// instead of at the end of the previous one?
    bool                    m_caretAtLineStart;

    /// Are we dragging (i.e. extending) a selection?
    bool                    m_dragging;

#if wxUSE_DRAG_AND_DROP
    /// Are we trying to start Drag'n'Drop?
    bool m_preDrag;

    /// Initial position when starting Drag'n'Drop
    wxPoint m_dragStartPoint;

#if wxUSE_DATETIME
    /// Initial time when starting Drag'n'Drop
  wxDateTime m_dragStartTime;
#endif // wxUSE_DATETIME
#endif // wxUSE_DRAG_AND_DROP

    /// Do we need full layout in idle?
    bool                    m_fullLayoutRequired;
    wxLongLong              m_fullLayoutTime;
    long                    m_fullLayoutSavedPosition;

    /// Threshold for doing delayed layout
    long                    m_delayedLayoutThreshold;

    /// Cursors
    wxCursor                m_textCursor;
    wxCursor                m_urlCursor;

    static wxArrayString    sm_availableFontNames;

    wxRichTextContextMenuPropertiesInfo m_contextMenuPropertiesInfo;

    /// The object that currently has the editing focus
    wxRichTextParagraphLayoutBox* m_focusObject;

    /// An overall scale factor
    double                  m_scale;
};

#if wxUSE_DRAG_AND_DROP
class %delete wxRichTextDropSource : public wxDropSource
{
public:
    wxRichTextDropSource(wxDataObject& data, wxRichTextCtrl* tc);

protected:
    bool GiveFeedback(wxDragResult effect);

    wxRichTextCtrl* m_rtc;
};

class %delete wxRichTextDropTarget : public wxDropTarget
{
public:
  wxRichTextDropTarget(wxRichTextCtrl* tc);

    virtual wxDragResult OnData(wxCoord x, wxCoord y, wxDragResult def);

protected:
    wxRichTextCtrl* m_rtc;
};

class %delete wxRichTextEvent : public wxNotifyEvent
{
public:
    %wxEventType wxEVT_RICHTEXT_LEFT_CLICK
    %wxEventType wxEVT_RICHTEXT_RIGHT_CLICK
    %wxEventType wxEVT_RICHTEXT_MIDDLE_CLICK
    %wxEventType wxEVT_RICHTEXT_LEFT_DCLICK
    %wxEventType wxEVT_RICHTEXT_RETURN
    %wxEventType wxEVT_RICHTEXT_CHARACTER
    %wxEventType wxEVT_RICHTEXT_CONSUMING_CHARACTER
    %wxEventType wxEVT_RICHTEXT_DELETE
    
    %wxEventType wxEVT_RICHTEXT_STYLESHEET_CHANGING
    %wxEventType wxEVT_RICHTEXT_STYLESHEET_CHANGED
    %wxEventType wxEVT_RICHTEXT_STYLESHEET_REPLACING
    %wxEventType wxEVT_RICHTEXT_STYLESHEET_REPLACED
    
    %wxEventType wxEVT_RICHTEXT_CONTENT_INSERTED
    %wxEventType wxEVT_RICHTEXT_CONTENT_DELETED
    %wxEventType wxEVT_RICHTEXT_STYLE_CHANGED
    %wxEventType wxEVT_RICHTEXT_PROPERTIES_CHANGED
    %wxEventType wxEVT_RICHTEXT_SELECTION_CHANGED
    %wxEventType wxEVT_RICHTEXT_BUFFER_RESET
    %wxEventType wxEVT_RICHTEXT_FOCUS_OBJECT_CHANGED

    /**
        Constructor.

        @param commandType
            The type of the event.
        @param id
            Window identifier. The value @c wxID_ANY indicates a default value.
    */
    wxRichTextEvent(wxEventType commandType = wxEVT_NULL, int winid = 0);

    /**
        Copy constructor.
    */
    wxRichTextEvent(const wxRichTextEvent& event);

    /**
        Returns the buffer position at which the event occured.
    */
    long GetPosition() const;

    /**
        Sets the buffer position variable.
    */
    void SetPosition(long pos);

    /**
        Returns flags indicating modifier keys pressed.

        Possible values are @c wxRICHTEXT_CTRL_DOWN, @c wxRICHTEXT_SHIFT_DOWN, and @c wxRICHTEXT_ALT_DOWN.
    */
    int GetFlags() const;

    /**
        Sets flags indicating modifier keys pressed.

        Possible values are @c wxRICHTEXT_CTRL_DOWN, @c wxRICHTEXT_SHIFT_DOWN, and @c wxRICHTEXT_ALT_DOWN.
    */
    void SetFlags(int flags);

    /**
        Returns the old style sheet.

        Can be used in a @c wxEVT_RICHTEXT_STYLESHEET_CHANGING or
        @c wxEVT_RICHTEXT_STYLESHEET_CHANGED event handler.
    */
    wxRichTextStyleSheet* GetOldStyleSheet() const;

    /**
        Sets the old style sheet variable.
    */
    void SetOldStyleSheet(wxRichTextStyleSheet* sheet);

    /**
        Returns the new style sheet.

        Can be used in a @c wxEVT_RICHTEXT_STYLESHEET_CHANGING or
        @c wxEVT_RICHTEXT_STYLESHEET_CHANGED event handler.
    */
    wxRichTextStyleSheet* GetNewStyleSheet() const;

    /**
        Sets the new style sheet variable.
    */
    void SetNewStyleSheet(wxRichTextStyleSheet* sheet);

    /**
        Gets the range for the current operation.
    */
    const wxRichTextRange& GetRange() const;

    /**
        Sets the range variable.
    */
    void SetRange(const wxRichTextRange& range);

    /**
        Returns the character pressed, within a @c wxEVT_RICHTEXT_CHARACTER event.
    */
    wxChar GetCharacter() const;

    /**
        Sets the character variable.
    */
    void SetCharacter(wxChar ch);

    /**
        Returns the container for which the event is relevant.
    */
    wxRichTextParagraphLayoutBox* GetContainer() const;

    /**
        Sets the container for which the event is relevant.
    */
    void SetContainer(wxRichTextParagraphLayoutBox* container);

    /**
        Returns the old container, for a focus change event.
    */
    wxRichTextParagraphLayoutBox* GetOldContainer() const;

    /**
        Sets the old container, for a focus change event.
    */
    void SetOldContainer(wxRichTextParagraphLayoutBox* container);

    virtual wxEvent *Clone() const;

protected:
    int                             m_flags;
    long                            m_position;
    wxRichTextStyleSheet*           m_oldStyleSheet;
    wxRichTextStyleSheet*           m_newStyleSheet;
    wxRichTextRange                 m_range;
    wxChar                          m_char;
    wxRichTextParagraphLayoutBox*   m_container;
    wxRichTextParagraphLayoutBox*   m_oldContainer;

private:
    //DECLARE_DYNAMIC_CLASS_NO_ASSIGN(wxRichTextEvent)
};

//  End richtextctrl.h
#endif // wxLUA_USE_wxRichText && %wxchkver_3_0 && wxUSE_RICHTEXT

#if wxLUA_USE_wxRichText && %wxchkver_3_0 && wxUSE_RICHTEXT

#include "wx/richtext/richtextformatdlg.h"

/*!
 * Flags determining the pages and buttons to be created in the dialog
 */

#define wxRICHTEXT_FORMAT_STYLE_EDITOR      0x0001
#define wxRICHTEXT_FORMAT_FONT              0x0002
#define wxRICHTEXT_FORMAT_TABS              0x0004
#define wxRICHTEXT_FORMAT_BULLETS           0x0008
#define wxRICHTEXT_FORMAT_INDENTS_SPACING   0x0010
#define wxRICHTEXT_FORMAT_LIST_STYLE        0x0020
#define wxRICHTEXT_FORMAT_MARGINS           0x0040
#define wxRICHTEXT_FORMAT_SIZE              0x0080
#define wxRICHTEXT_FORMAT_BORDERS           0x0100
#define wxRICHTEXT_FORMAT_BACKGROUND        0x0200

#define wxRICHTEXT_FORMAT_HELP_BUTTON       0x1000

/*!
 * Indices for bullet styles in list control
 */

enum {
    wxRICHTEXT_BULLETINDEX_NONE = 0,
    wxRICHTEXT_BULLETINDEX_ARABIC,
    wxRICHTEXT_BULLETINDEX_UPPER_CASE,
    wxRICHTEXT_BULLETINDEX_LOWER_CASE,
    wxRICHTEXT_BULLETINDEX_UPPER_CASE_ROMAN,
    wxRICHTEXT_BULLETINDEX_LOWER_CASE_ROMAN,
    wxRICHTEXT_BULLETINDEX_OUTLINE,
    wxRICHTEXT_BULLETINDEX_SYMBOL,
    wxRICHTEXT_BULLETINDEX_BITMAP,
    wxRICHTEXT_BULLETINDEX_STANDARD
};

/*!
 * Shorthand for common combinations of pages
 */

#define wxRICHTEXT_FORMAT_PARAGRAPH         (wxRICHTEXT_FORMAT_INDENTS_SPACING | wxRICHTEXT_FORMAT_BULLETS | wxRICHTEXT_FORMAT_TABS | wxRICHTEXT_FORMAT_FONT)
#define wxRICHTEXT_FORMAT_CHARACTER         (wxRICHTEXT_FORMAT_FONT)
#define wxRICHTEXT_FORMAT_STYLE             (wxRICHTEXT_FORMAT_PARAGRAPH | wxRICHTEXT_FORMAT_STYLE_EDITOR)

/*!
 * Factory for formatting dialog
 */

class %delete wxRichTextFormattingDialogFactory: public wxObject
{
public:
    wxRichTextFormattingDialogFactory();
    //virtual ~wxRichTextFormattingDialogFactory();

// Overridables

    /// Create all pages, under the dialog's book control, also calling AddPage
    virtual bool CreatePages(long pages, wxRichTextFormattingDialog* dialog);

    /// Create a page, given a page identifier
    virtual wxPanel* CreatePage(int page, wxString& title, wxRichTextFormattingDialog* dialog);

    /// Enumerate all available page identifiers
    virtual int GetPageId(int i) const;

    /// Get the number of available page identifiers
    virtual int GetPageIdCount() const;

    /// Get the image index for the given page identifier
    virtual int GetPageImage(int id) const;

    /// Invoke help for the dialog
    virtual bool ShowHelp(int page, wxRichTextFormattingDialog* dialog);

    /// Set the sheet style, called at the start of wxRichTextFormattingDialog::Create
    virtual bool SetSheetStyle(wxRichTextFormattingDialog* dialog);

    /// Create the main dialog buttons
    virtual bool CreateButtons(wxRichTextFormattingDialog* dialog);
};

/*!
 * Formatting dialog for a wxRichTextCtrl
 */

class %delete wxRichTextFormattingDialog /*: public wxPropertySheetDialog,
                                                       public wxWithImages */
{
//DECLARE_CLASS(wxRichTextFormattingDialog)
//DECLARE_HELP_PROVISION()

public:
    enum { Option_AllowPixelFontSize = 0x0001 };

    wxRichTextFormattingDialog();

    wxRichTextFormattingDialog(long flags, wxWindow* parent, const wxString& title, wxWindowID id = wxID_ANY,
        const wxPoint& pos = wxDefaultPosition, const wxSize& sz = wxDefaultSize,
        long style = wxDEFAULT_DIALOG_STYLE);

    //~wxRichTextFormattingDialog();

    void Init();

    bool Create(long flags, wxWindow* parent, const wxString& title, wxWindowID id = wxID_ANY,
        const wxPoint& pos = wxDefaultPosition, const wxSize& sz = wxDefaultSize,
        long style = wxDEFAULT_DIALOG_STYLE);

    /// Get attributes from the given range
    virtual bool GetStyle(wxRichTextCtrl* ctrl, const wxRichTextRange& range);

    /// Set the attributes and optionally update the display
    virtual bool SetStyle(const wxRichTextAttr& style, bool update = true);

    /// Set the style definition and optionally update the display
    virtual bool SetStyleDefinition(const wxRichTextStyleDefinition& styleDef, wxRichTextStyleSheet* sheet, bool update = true);

    /// Get the style definition, if any
    virtual wxRichTextStyleDefinition* GetStyleDefinition() const;

    /// Get the style sheet, if any
    virtual wxRichTextStyleSheet* GetStyleSheet() const;

    /// Update the display
    virtual bool UpdateDisplay();

    /// Apply attributes to the given range
    virtual bool ApplyStyle(wxRichTextCtrl* ctrl, const wxRichTextRange& range, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO|wxRICHTEXT_SETSTYLE_OPTIMIZE);

    /// Apply attributes to the object being edited, if any
    virtual bool ApplyStyle(wxRichTextCtrl* ctrl, int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO);

    /// Gets and sets the attributes
    const wxRichTextAttr& GetAttributes() const;
    wxRichTextAttr& GetAttributes();
    void SetAttributes(const wxRichTextAttr& attr);

    /// Sets the dialog options, determining what the interface presents to the user.
    /// Currently the only option is Option_AllowPixelFontSize.
    void SetOptions(int options);

    /// Gets the dialog options, determining what the interface presents to the user.
    /// Currently the only option is Option_AllowPixelFontSize.
    int GetOptions() const;

    /// Returns @true if the given option is present.
    bool HasOption(int option) const;

    /// If editing the attributes for a particular object, such as an image,
    /// set the object so the code can initialize attributes such as size correctly.
    wxRichTextObject* GetObject() const;
    void SetObject(wxRichTextObject* obj);

    /// Transfers the data and from to the window
    virtual bool TransferDataToWindow();
    virtual bool TransferDataFromWindow();

    /// Apply the styles when a different tab is selected, so the previews are
    /// up to date
    //void OnTabChanged(wxBookCtrlEvent& event);

    /// Respond to help command
    void OnHelp(wxCommandEvent& event);
    void OnUpdateHelp(wxUpdateUIEvent& event);

    /// Get/set formatting factory object
    static void SetFormattingDialogFactory(wxRichTextFormattingDialogFactory* factory);
    static wxRichTextFormattingDialogFactory* GetFormattingDialogFactory();

    /// Helper for pages to get the top-level dialog
    static wxRichTextFormattingDialog* GetDialog(wxWindow* win);

    /// Helper for pages to get the attributes
    static wxRichTextAttr* GetDialogAttributes(wxWindow* win);

    /// Helper for pages to get the reset attributes 
    //static wxRichTextAttr* GetDialogResetAttributes(wxWindow* win); // not implemented

    /// Helper for pages to get the style
    static wxRichTextStyleDefinition* GetDialogStyleDefinition(wxWindow* win);

    /// Should we show tooltips?
    static bool ShowToolTips();

    /// Determines whether tooltips will be shown
    static void SetShowToolTips(bool show);

    /// Set the dimension into the value and units controls. Optionally pass units to
    /// specify the ordering of units in the combobox.
    static void SetDimensionValue(wxTextAttrDimension& dim, wxTextCtrl* valueCtrl, wxComboBox* unitsCtrl, wxCheckBox* checkBox, wxArrayInt* units = NULL);

    /// Get the dimension from the value and units controls Optionally pass units to
    /// specify the ordering of units in the combobox.
    static void GetDimensionValue(wxTextAttrDimension& dim, wxTextCtrl* valueCtrl, wxComboBox* unitsCtrl, wxCheckBox* checkBox, wxArrayInt* units = NULL);

    /// Convert from a string to a dimension integer.
    static bool ConvertFromString(const wxString& str, int& ret, int unit);

    /// Map book control page index to our page id
    void AddPageId(int id);

    /// Find a page by class
    wxWindow* FindPage(wxClassInfo* info) const;

protected:

    wxRichTextAttr                              m_attributes;
    wxRichTextStyleDefinition*                  m_styleDefinition;
    wxRichTextStyleSheet*                       m_styleSheet;
    wxRichTextObject*                           m_object;
    wxArrayInt                                  m_pageIds; // mapping of book control indexes to page ids
    int                                         m_options; // UI options

    static wxRichTextFormattingDialogFactory*   ms_FormattingDialogFactory;
    static bool                                 sm_showToolTips;

//DECLARE_EVENT_TABLE()
};

//  End richtextformatdlg.h
#endif // wxLUA_USE_wxRichText && %wxchkver_3_0 && wxUSE_RICHTEXT

#if wxLUA_USE_wxRichText && %wxchkver_3_0 && wxUSE_RICHTEXT

#include "wx/richtext/richtexthtml.h"

// Use CSS styles where applicable, otherwise use non-CSS workarounds
#define wxRICHTEXT_HANDLER_USE_CSS 0x1000

/*!
 * wxRichTextHTMLHandler
 */

class %delete wxRichTextHTMLHandler: public wxRichTextFileHandler
{
    //DECLARE_DYNAMIC_CLASS(wxRichTextHTMLHandler)
public:
    wxRichTextHTMLHandler(const wxString& name, const wxString& ext, int type = wxRICHTEXT_TYPE_HTML);

    /// Can we save using this handler?
    virtual bool CanSave() const;

    /// Can we load using this handler?
    virtual bool CanLoad() const;

    /// Can we handle this filename (if using files)? By default, checks the extension.
    virtual bool CanHandle(const wxString& filename) const;

// Accessors and operations unique to this handler

    /// Set and get the list of image locations generated by the last operation
    void SetTemporaryImageLocations(const wxArrayString& locations);
    const wxArrayString& GetTemporaryImageLocations() const;

    /// Clear the image locations generated by the last operation
    void ClearTemporaryImageLocations();

    /// Delete the in-memory or temporary files generated by the last operation
    bool DeleteTemporaryImages();

    /// Delete the in-memory or temporary files generated by the last operation. This is a static
    /// function that can be used to delete the saved locations from an earlier operation,
    /// for example after the user has viewed the HTML file.
    static bool DeleteTemporaryImages(int flags, const wxArrayString& imageLocations);

    /// Reset the file counter, in case, for example, the same names are required each time
    static void SetFileCounter(int counter);

    /// Set and get the directory for storing temporary files. If empty, the system
    /// temporary directory will be used.
    void SetTempDir(const wxString& tempDir);
    const wxString& GetTempDir() const;

    /// Set and get mapping from point size to HTML font size. There should be 7 elements,
    /// one for each HTML font size, each element specifying the maximum point size for that
    /// HTML font size. E.g. 8, 10, 13, 17, 22, 29, 100
    void SetFontSizeMapping(const wxArrayInt& fontSizeMapping);
    wxArrayInt GetFontSizeMapping() const;

protected:

// Implementation

#if wxUSE_STREAMS
    virtual bool DoLoadFile(wxRichTextBuffer *buffer, wxInputStream& stream);
    virtual bool DoSaveFile(wxRichTextBuffer *buffer, wxOutputStream& stream);

    /// Output character formatting
    void BeginCharacterFormatting(const wxRichTextAttr& currentStyle, const wxRichTextAttr& thisStyle, const wxRichTextAttr& paraStyle, wxTextOutputStream& stream );
    void EndCharacterFormatting(const wxRichTextAttr& currentStyle, const wxRichTextAttr& thisStyle, const wxRichTextAttr& paraStyle, wxTextOutputStream& stream );

    /// Output paragraph formatting
    void BeginParagraphFormatting(const wxRichTextAttr& currentStyle, const wxRichTextAttr& thisStyle, wxTextOutputStream& stream);
    void EndParagraphFormatting(const wxRichTextAttr& currentStyle, const wxRichTextAttr& thisStyle, wxTextOutputStream& stream);

    /// Output font tag
    void OutputFont(const wxRichTextAttr& style, wxTextOutputStream& stream);

    /// Closes lists to level (-1 means close all)
    void CloseLists(int level, wxTextOutputStream& str);

    /// Writes an image to its base64 equivalent, or to the memory filesystem, or to a file
    void WriteImage(wxRichTextImage* image, wxOutputStream& stream);

    /// Converts from pt to size property compatible height
    long PtToSize(long size);

    /// Typical base64 encoder
    wxChar* b64enc(unsigned char* input, size_t in_len);

    /// Gets the mime type of the given wxBITMAP_TYPE
    const wxChar* GetMimeType(int imageType);

    /// Gets the html equivalent of the specified value
    wxString GetAlignment(const wxRichTextAttr& thisStyle);

    /// Generates &nbsp; array for indentations
    wxString SymbolicIndent(long indent);

    /// Finds the html equivalent of the specified bullet
    int TypeOfList(const wxRichTextAttr& thisStyle, wxString& tag);
#endif

// Data members

    wxRichTextBuffer* m_buffer;

    /// Indentation values of the table tags
    wxArrayInt      m_indents;

    /// Stack of list types: 0 = ol, 1 = ul
    wxArrayInt      m_listTypes;

    /// Is there any opened font tag?
    bool            m_font;

    /// Are we in a table?
    bool            m_inTable;

    /// A list of the image files or in-memory images created by the last operation.
    wxArrayString   m_imageLocations;

    /// A location for the temporary files
    wxString        m_tempDir;

    /// A mapping from point size to HTML font size
    wxArrayInt      m_fontSizeMapping;

    /// A counter for generating filenames
    static int      sm_fileCounter;
};

//  End richtexthtml.h
#endif // wxLUA_USE_wxRichText && %wxchkver_3_0 && wxUSE_RICHTEXT

#if wxLUA_USE_wxRichText && %wxchkver_3_0 && wxUSE_RICHTEXT

#include "wx/richtext/richtextimagedlg.h"

#define SYMBOL_WXRICHTEXTOBJECTPROPERTIESDIALOG_STYLE wxDEFAULT_DIALOG_STYLE|wxTAB_TRAVERSAL
//#define SYMBOL_WXRICHTEXTOBJECTPROPERTIESDIALOG_TITLE "Object Properties" // wxGetTranslation("Object Properties")
//#define SYMBOL_WXRICHTEXTOBJECTPROPERTIESDIALOG_IDNAME wxRichTextObjectPropertiesDialog::ID_RICHTEXTOBJECTPROPERTIESDIALOG
//#define SYMBOL_WXRICHTEXTOBJECTPROPERTIESDIALOG_SIZE wxDefaultSize  //wxSize(400, 300)
//#define SYMBOL_WXRICHTEXTOBJECTPROPERTIESDIALOG_POSITION wxDefaultPosition

/*!
 * wxRichTextObjectPropertiesDialog class declaration
 */

class %delete wxRichTextObjectPropertiesDialog: public wxRichTextFormattingDialog
{    
    //DECLARE_DYNAMIC_CLASS( wxRichTextObjectPropertiesDialog )
    //DECLARE_EVENT_TABLE()

public:
    /// Constructors
    wxRichTextObjectPropertiesDialog();
    wxRichTextObjectPropertiesDialog( wxRichTextObject* obj, wxWindow* parent, wxWindowID id = wxRichTextObjectPropertiesDialog::ID_RICHTEXTOBJECTPROPERTIESDIALOG, const wxString& caption = "Object Properties", const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = SYMBOL_WXRICHTEXTOBJECTPROPERTIESDIALOG_STYLE );

    /// Creation
    bool Create( wxRichTextObject* obj, wxWindow* parent, wxWindowID id = wxRichTextObjectPropertiesDialog::ID_RICHTEXTOBJECTPROPERTIESDIALOG, const wxString& caption = "Object Properties", const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = SYMBOL_WXRICHTEXTOBJECTPROPERTIESDIALOG_STYLE );

    /// Destructor
    //~wxRichTextObjectPropertiesDialog();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin wxRichTextObjectPropertiesDialog event handler declarations

////@end wxRichTextObjectPropertiesDialog event handler declarations

////@begin wxRichTextObjectPropertiesDialog member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end wxRichTextObjectPropertiesDialog member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin wxRichTextObjectPropertiesDialog member variables
    /// Control identifiers
    enum {
        ID_RICHTEXTOBJECTPROPERTIESDIALOG = 10650
    };
////@end wxRichTextObjectPropertiesDialog member variables
};

//  End richtextimagedlg.h
#endif // wxLUA_USE_wxRichText && %wxchkver_3_0 && wxUSE_RICHTEXT
