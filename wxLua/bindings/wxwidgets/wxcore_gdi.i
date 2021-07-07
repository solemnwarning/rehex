// ===========================================================================
// Purpose:     GDI classes, Colour, Pen, Brush, Font, DC, Bitmap...
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

// ---------------------------------------------------------------------------
// wxPoint

#if wxLUA_USE_wxPointSizeRect

#include "wx/gdicmn.h"

#define wxDefaultCoord

#define_object wxPoint wxDefaultPosition

class %delete wxPoint
{
    //#define_object wxDefaultPosition

    wxPoint(int x = 0, int y = 0);
    wxPoint(const wxPoint& pt);

    // %override [int x, int y] wxPoint::GetXY();
    // wxLua added function
    int GetXY() const;

    // %override void wxPoint::Set(int x, int y);
    // wxLua added function
    void Set(int x, int y);

    %rename X %member_func int x; // GetX() and SetX(int x);
    %rename Y %member_func int y; // GetY() and SetY(int y);

    wxPoint& operator=(const wxPoint& p) const;

    bool operator==(const wxPoint& p) const; //{ return x == p.x && y == p.y; }
    bool operator!=(const wxPoint& p) const; //{ return !(*this == p); }

    // arithmetic operations (component wise);
    wxPoint operator+(const wxPoint& p) const; //{ return wxPoint(x + p.x, y + p.y); }
    wxPoint operator-(const wxPoint& p) const; //{ return wxPoint(x - p.x, y - p.y); }

    wxPoint& operator+=(const wxPoint& p); //{ x += p.x; y += p.y; return *this; }
    wxPoint& operator-=(const wxPoint& p); //{ x -= p.x; y -= p.y; return *this; }

    wxPoint& operator+=(const wxSize& s); //{ x += s.GetWidth(); y += s.GetHeight(); return *this; }
    wxPoint& operator-=(const wxSize& s); //{ x -= s.GetWidth(); y -= s.GetHeight(); return *this; }

    wxPoint operator+(const wxSize& s) const; //{ return wxPoint(x + s.GetWidth(), y + s.GetHeight()); }
    wxPoint operator-(const wxSize& s) const; //{ return wxPoint(x - s.GetWidth(), y - s.GetHeight()); }

    wxPoint operator-() const; //{ return wxPoint(-x, -y); }
};

// ---------------------------------------------------------------------------
// wxPointList

//#if %wxchkver_2_9

//class %delete wxPointList : public wxList
//{
//    wxPointList();
//};

//#endif

// ---------------------------------------------------------------------------
// wxRealPoint - Used nowhere in wxWidgets

class %delete wxRealPoint
{
    wxRealPoint(double xx = 0, double yy = 0);

    %rename X double x; // GetX() and SetX(int x);
    %rename Y double y; // GetY() and SetY(int y);
};

// ---------------------------------------------------------------------------
// wxSize

class %delete wxSize
{
    #define_object wxDefaultSize

    wxSize(int width = 0, int height = 0);
    wxSize(const wxSize& size);

    %wxchkver_2_8 void DecBy(int dx, int dy);
    //%wxchkver_2_8 void DecBy(const wxSize& sz);
    //%wxchkver_2_8 void DecBy(int d);
    void DecTo(const wxSize& sz);
    bool IsFullySpecified() const;
    int GetHeight() const;
    int GetWidth() const;
    %wxchkver_2_8 void IncBy(int dx, int dy);
    //%wxchkver_2_8 void IncBy(const wxSize& sz);
    //%wxchkver_2_8 void IncBy(int d);
    void IncTo(const wxSize& sz);
    %wxchkver_2_8 wxSize& Scale(float xscale, float yscale);
    void Set(int width, int height);
    void SetDefaults(const wxSize& size);
    void SetHeight(int height);
    void SetWidth(int width);

    wxSize& operator=(const wxSize& s) const;

    bool operator==(const wxSize& sz) const; //{ return x == sz.x && y == sz.y; }
    bool operator!=(const wxSize& sz) const; //{ return x != sz.x || y != sz.y; }

    wxSize operator+(const wxSize& sz) const; //{ return wxSize(x + sz.x, y + sz.y); }
    wxSize operator-(const wxSize& sz) const; //{ return wxSize(x - sz.x, y - sz.y); }
    wxSize operator/(int i) const; //{ return wxSize(x / i, y / i); }
    wxSize operator*(int i) const; //{ return wxSize(x * i, y * i); }

    wxSize& operator+=(const wxSize& sz); //{ x += sz.x; y += sz.y; return *this; }
    wxSize& operator-=(const wxSize& sz); //{ x -= sz.x; y -= sz.y; return *this; }
    wxSize& operator/=(const int i);      //{ x /= i; y /= i; return *this; }
    wxSize& operator*=(const int i);      //{ x *= i; y *= i; return *this; }
};

// ---------------------------------------------------------------------------
// wxRect

class %delete wxRect
{
    wxRect(int x = 0, int y = 0, int w = 0, int h = 0);
    wxRect(const wxRect& rect);
    wxRect(const wxPoint& topLeft, const wxPoint& bottomRight);
    wxRect(const wxPoint& pos, const wxSize& size);
    wxRect(const wxSize& size);

    #if %wxchkver_2_8
        wxRect CentreIn(const wxRect& r, int dir = wxBOTH) const; // CenterIn
        bool Contains(wxCoord dx, wxCoord dy) const;
        bool Contains(const wxPoint& pt) const;
        bool Contains(const wxRect& rect) const;
    #endif // %wxchkver_2_8

    wxRect  Deflate(wxCoord dx, wxCoord dy) const; //wxRect& Deflate(wxCoord dx, wxCoord dy);
    int     GetBottom();
    int     GetHeight();
    int     GetLeft();
    wxPoint GetPosition();
    wxPoint GetTopLeft() const;                  // GetLeftTop
    %wxchkver_2_8 wxPoint GetTopRight() const;   // GetRightTop
    wxPoint GetBottomRight() const;              // GetRightBottom
    %wxchkver_2_8 wxPoint GetBottomLeft() const; // GetLeftBottom
    int     GetRight();
    wxSize  GetSize();
    int     GetTop();
    int     GetWidth();
    int     GetX();
    int     GetY();
    wxRect  Inflate(wxCoord dx, wxCoord dy) const; //wxRect& Inflate(wxCoord dx, wxCoord dy);
    %wxcompat_2_6 bool    Inside(wxCoord cx, wxCoord cy);
    bool    Intersects(const wxRect& rect) const;
    bool    IsEmpty() const;
    void    Offset(wxCoord dx, wxCoord dy);  //void Offset(const wxPoint& pt);
    void    SetBottom(int bottom);
    void    SetHeight(int height);
    void    SetLeft(int left);
    void    SetPosition(const wxPoint &p);
    %wxchkver_2_8 void    SetBottomLeft(const wxPoint &p);   // SetLeftBottom
    void    SetBottomRight(const wxPoint &p);                // SetRightBottom
    void    SetRight(int right);
    void    SetSize(const wxSize &s);
    void    SetTop(int top);
    %wxchkver_2_8 void    SetTopRight(const wxPoint &p);     // SetRightTop
    void    SetWidth(int width);
    void    SetX(int X);
    void    SetY(int Y);
    wxRect  Union(const wxRect& rect) const; //wxRect& Union(const wxRect& rect);

    wxRect& operator=(const wxRect& r) const;

    bool operator==(const wxRect& rect) const;
    wxRect operator+(const wxRect& rect) const;
    wxRect& operator+=(const wxRect& rect);

    int height;
    int width;
    int x;
    int y;
};

#endif //wxLUA_USE_wxPointSizeRect

// ---------------------------------------------------------------------------
// wxGDIObject

class %delete wxGDIObject : public wxObject
{
    bool IsNull();
};

// ---------------------------------------------------------------------------
// wxRegion

#if wxLUA_USE_wxRegion

#include "wx/region.h"

enum wxRegionContain
{
    wxOutRegion,
    wxPartRegion,
    wxInRegion
};

#if defined(wxHAS_REGION_COMBINE); // MSW and MAC
    enum wxRegionOp
    {
        wxRGN_AND,   // Creates the intersection of the two combined regions.
        wxRGN_COPY,  // Creates a copy of the region
        wxRGN_DIFF,  // Combines the parts of first region that are not in the second one
        wxRGN_OR,    // Creates the union of two combined regions.
        wxRGN_XOR    // Creates the union of two regions except for any overlapping areas.
    };

#define wxHAS_REGION_COMBINE 1
#endif // defined(wxHAS_REGION_COMBINE);

class %delete wxRegion : public wxGDIObject
{
    wxRegion(long x = 0, long y = 0, long width = 0, long height = 0);
    wxRegion(const wxPoint& topLeft, const wxPoint& bottomRight);
    // wxRegion(const wxPoint& pos, const wxSize& size);
    wxRegion(const wxRect& rect);
    wxRegion(const wxRegion& region);

    void Clear();

#if defined(wxHAS_REGION_COMBINE); // MSW and MAC
    bool Combine(wxCoord x, wxCoord y, wxCoord w, wxCoord h, wxRegionOp op);
    bool Combine(const wxRect& rect, wxRegionOp op);
    bool Combine(const wxRegion& region, wxRegionOp op);
#endif // defined(wxHAS_REGION_COMBINE);

    wxRegionContain Contains(long x, long y);
    wxRegionContain Contains(const wxPoint& pt);
    wxRegionContain Contains(const wxRect& rect);
    wxRegionContain Contains(long x, long y, long w, long h);
    wxBitmap ConvertToBitmap() const;
    wxRect GetBox() const;

    // %override [int x, int y, int width, int height] wxRegion::GetBoxXYWH();
    // C++ Func: void GetBox(int &x, int &y, int &width, int &height);
    %rename GetBoxXYWH void GetBox();

    bool Intersect(long x, long y, long width, long height);
    bool Intersect(const wxRect& rect);
    bool Intersect(const wxRegion& region);
    bool IsEmpty() const;
    %wxchkver_2_8 bool IsEqual(const wxRegion& region) const;
    %wxchkver_2_8 bool Ok() const;
    bool Subtract(long x, long y, long width, long height);
    bool Subtract(const wxRect& rect);
    bool Subtract(const wxRegion& region);
    bool Offset(wxCoord x, wxCoord y);
    bool Union(long x, long y, long width, long height);
    bool Union(const wxRect& rect);
    bool Union(const wxRegion& region);
    bool Union(const wxBitmap& bmp);
    bool Union(const wxBitmap& bmp, const wxColour& transColour, int tolerance = 0);
    bool Xor(long x, long y, long width, long height);
    bool Xor(const wxRect& rect);
    bool Xor(const wxRegion& region);

    wxRegion& operator=(const wxRegion& r) const;
    // operator == just calls IsEqual();
};

// ---------------------------------------------------------------------------
// wxRegionIterator

class %delete wxRegionIterator : public wxObject
{
    wxRegionIterator(const wxRegion& region);

    long GetX();
    long GetY();
    long GetWidth();     // long GetW();
    long GetHeight();    // long GetH();
    wxRect GetRect();
    bool HaveRects();
    void Reset();

    // %override wxRegionIterator::Next() is ++ operator
    // This is a wxLua added function.
    void Next();         // operator++
};

#endif //wxLUA_USE_wxRegion

// ---------------------------------------------------------------------------
// wxFont

#if wxLUA_USE_wxFont

#include "wx/font.h"

enum
{
    wxDEFAULT,      // these are deprecated use wxFONTFAMILY_XXX
    wxDECORATIVE,
    wxROMAN,
    wxSCRIPT,
    wxSWISS,
    wxMODERN,
    wxTELETYPE,

    wxVARIABLE,      // unused ?
    wxFIXED,         // unused ?

    wxNORMAL,
    wxLIGHT,
    wxBOLD,
    wxITALIC,
    wxSLANT
};

enum wxFontFamily
{
    wxFONTFAMILY_DEFAULT,
    wxFONTFAMILY_DECORATIVE,
    wxFONTFAMILY_ROMAN,
    wxFONTFAMILY_SCRIPT,
    wxFONTFAMILY_SWISS,
    wxFONTFAMILY_MODERN,
    wxFONTFAMILY_TELETYPE,
    wxFONTFAMILY_MAX,
    wxFONTFAMILY_UNKNOWN
};

enum wxFontStyle
{
    wxFONTSTYLE_NORMAL,
    wxFONTSTYLE_ITALIC,
    wxFONTSTYLE_SLANT,
    wxFONTSTYLE_MAX
};

enum wxFontWeight
{
#if %wxchkver_3_1_2
    wxFONTWEIGHT_INVALID,
    wxFONTWEIGHT_THIN,
    wxFONTWEIGHT_EXTRALIGHT,
    wxFONTWEIGHT_MEDIUM,
    wxFONTWEIGHT_SEMIBOLD,
    wxFONTWEIGHT_EXTRABOLD,
    wxFONTWEIGHT_HEAVY,
    wxFONTWEIGHT_EXTRAHEAVY,
#endif //%wxchkver_3_1_2
    wxFONTWEIGHT_NORMAL,
    wxFONTWEIGHT_LIGHT,
    wxFONTWEIGHT_BOLD,
    wxFONTWEIGHT_MAX
};

enum
{
    wxFONTFLAG_DEFAULT,
    wxFONTFLAG_ITALIC,
    wxFONTFLAG_SLANT,
    wxFONTFLAG_LIGHT,
    wxFONTFLAG_BOLD,
    wxFONTFLAG_ANTIALIASED,
    wxFONTFLAG_NOT_ANTIALIASED,
    wxFONTFLAG_UNDERLINED,
    wxFONTFLAG_STRIKETHROUGH,
    wxFONTFLAG_MASK
};

#if %wxchkver_2_9_2
enum wxFontSymbolicSize
{
    wxFONTSIZE_XX_SMALL = -3,   //!< Extra small.
    wxFONTSIZE_X_SMALL,         //!< Very small.
    wxFONTSIZE_SMALL,           //!< Small.
    wxFONTSIZE_MEDIUM,          //!< Normal.
    wxFONTSIZE_LARGE,           //!< Large.
    wxFONTSIZE_X_LARGE,         //!< Very large.
    wxFONTSIZE_XX_LARGE         //!< Extra large.
};
#endif // %wxchkver_2_9_2

class wxFontInfo
{
    %wxchkver_3_0_0 wxFontInfo();
    // wxFontInfo(T pointSize); // unroll the template T into explicit float/int
    %wxchkver_3_0_0 wxFontInfo(const wxSize& pixelSize);
    %wxchkver_3_0_0 wxFontInfo& Family(wxFontFamily family);
    %wxchkver_3_0_0 wxFontInfo& FaceName(const wxString& faceName);
    %wxchkver_3_1_2 wxFontInfo& Weight(int weight);
    %wxchkver_3_0_0 wxFontInfo& Bold(bool bold = true);
    %wxchkver_3_0_0 wxFontInfo& Light(bool light = true);
    %wxchkver_3_0_0 wxFontInfo& Italic(bool italic = true);
    %wxchkver_3_0_0 wxFontInfo& Slant(bool slant = true);
    %wxchkver_3_1_2 wxFontInfo& Style(wxFontStyle style);
    %wxchkver_3_0_0 wxFontInfo& AntiAliased(bool antiAliased = true);
    %wxchkver_3_0_0 wxFontInfo& Underlined(bool underlined = true);
    %wxchkver_3_0_0 wxFontInfo& Strikethrough(bool strikethrough = true);
    %wxchkver_3_0_0 wxFontInfo& Encoding(wxFontEncoding encoding);
    %wxchkver_3_0_0 wxFontInfo& AllFlags(int flags);
    %wxchkver_3_1_2 static wxFontWeight GetWeightClosestToNumericValue(int numWeight);
    %wxchkver_3_0_0 wxFontInfo(int pointSize); // %override added explicitly
    %wxchkver_3_1_2 wxFontInfo(float pointSize);
};

class %delete wxFont : public wxGDIObject
{
    #define_object wxNullFont
    %rename wxNORMAL_FONT #define_pointer wxLua_wxNORMAL_FONT // hack for wxWidgets >2.7
    %rename wxSMALL_FONT  #define_pointer wxLua_wxSMALL_FONT
    %rename wxITALIC_FONT #define_pointer wxLua_wxITALIC_FONT
    %rename wxSWISS_FONT  #define_pointer wxLua_wxSWISS_FONT
    %wxchkver_3_0_0 wxFont();
    wxFont(const wxFont& font);
    %wxchkver_3_0_0 wxFont(const wxFontInfo& font);
    %wxchkver_3_0_0 wxFont(int pointSize, wxFontFamily family, wxFontStyle style, wxFontWeight weight, bool underline = false, const wxString& faceName = wxEmptyString, wxFontEncoding encoding = wxFONTENCODING_DEFAULT);
    %wxchkver_3_0_0 wxFont(const wxSize& pixelSize, wxFontFamily family, wxFontStyle style, wxFontWeight weight, bool underline = false, const wxString& faceName = wxEmptyString, wxFontEncoding encoding = wxFONTENCODING_DEFAULT);
    %wxchkver_3_0_0 wxFont(const wxString& nativeInfoString);
    %wxchkver_3_0_0 wxFont(const wxNativeFontInfo& nativeInfo);
    %wxchkver_3_1_0 wxFont GetBaseFont() const;
    %wxchkver_3_0_0 wxFontEncoding GetEncoding() const;
    wxString GetFaceName() const;
    int      GetFamily() const;
    wxString GetNativeFontInfoDesc() const;
    %wxchkver_3_0_0 wxString GetNativeFontInfoUserDesc() const;
    %wxchkver_3_0_0 const wxNativeFontInfo *GetNativeFontInfo() const;
    wxUSE_PRIVATE_FONTS && %wxchkver_3_1_2 static bool AddPrivateFont(const wxString& filename);
    int      GetPointSize() const;
    %wxchkver_3_1_2 float  GetFractionalPointSize() const;
    %wxchkver_3_0_0 wxSize GetPixelSize() const;
    int      GetStyle() const;
    bool     GetUnderlined() const;
    %wxchkver_3_0_0 bool GetStrikethrough() const;
    int      GetWeight() const;
    %wxchkver_3_1_2 int GetNumericWeight() const;
    bool IsFixedWidth() const;
    %wxchkver_3_0_0 bool IsOk() const;
    %wxchkver_3_0_0 wxFont Bold() const;
    %wxchkver_3_0_0 wxFont Italic() const;
    %wxchkver_3_0_0 wxFont Larger() const;
    %wxchkver_3_0_0 wxFont Smaller() const;
    %wxchkver_3_0_0 wxFont Underlined() const;
    %wxchkver_3_0_0 wxFont Strikethrough() const;
    %wxchkver_3_0_0 wxFont& MakeBold();
    %wxchkver_3_0_0 wxFont& MakeItalic();
    %wxchkver_3_0_0 wxFont& MakeLarger();
    %wxchkver_3_0_0 wxFont& MakeSmaller();
    %wxchkver_3_0_0 wxFont& MakeUnderlined();
    %wxchkver_3_0_0 wxFont& MakeStrikethrough();
    %wxchkver_3_0_0 wxFont& Scale(float x);
    %wxchkver_3_0_0 wxFont Scaled(float x) const;
    %wxchkver_3_0_0 void SetEncoding(wxFontEncoding encoding);
    %not_overload %wxchkver_2_8 bool SetFaceName(const wxString& faceName);
    %wxchkver_3_0_0 void SetFamily(wxFontFamily family);
    %not_overload %wxchkver_2_8 bool SetNativeFontInfo(const wxString& info);
    %wxchkver_2_8 bool SetNativeFontInfoUserDesc(const wxString& info);
    void     SetPointSize(int pointSize);
    %wxchkver_3_1_2 void SetFractionalPointSize(float pointSize);
    %wxchkver_3_0_0 void SetPixelSize(const wxSize& pixelSize);
    %wxchkver_3_0_0 void SetStyle(wxFontStyle style);
    %wxchkver_3_0_0 void SetSymbolicSize(wxFontSymbolicSize size);
    %wxchkver_3_0_0 void SetSymbolicSizeRelativeTo(wxFontSymbolicSize size, int base);
    %wxchkver_3_0_0 void SetUnderlined(bool underlined);
    %wxchkver_3_0_0 void SetStrikethrough(bool strikethrough);
    %wxchkver_3_0_0 void SetWeight(wxFontWeight weight);
    %wxchkver_3_1_2 void SetNumericWeight(int weight);
    %wxchkver_3_0_0 bool operator!=(const wxFont& font) const;
    %wxchkver_3_0_0 bool operator==(const wxFont& font) const;
    wxFont& operator =(const wxFont& font);
    static wxFontEncoding GetDefaultEncoding();
    static void SetDefaultEncoding(wxFontEncoding encoding);
    %wxchkver_3_1_2 static int GetNumericWeightOf(wxFontWeight weight);
    static %gc wxFont* New(int pointSize, wxFontFamily family, int flags = wxFONTFLAG_DEFAULT, const wxString& faceName = "", wxFontEncoding encoding = wxFONTENCODING_DEFAULT);
    static %gc wxFont* New(const wxSize& pixelSize, wxFontFamily family, int flags = wxFONTFLAG_DEFAULT, const wxString& faceName = "", wxFontEncoding encoding = wxFONTENCODING_DEFAULT);
    !%wxchkver_3_0_0 void     SetFamily(int family);
    !%wxchkver_3_0_0 void     SetStyle(int style);
    !%wxchkver_3_0_0 void     SetUnderlined(const bool underlined);
    !%wxchkver_3_0_0 void     SetWeight(int weight);
    !%wxchkver_3_0_0 wxFont& operator=(const wxFont& f) const;
    !%wxchkver_3_0_0 wxFont(int pointSize, int family, int style, int weight, const bool underline = false, const wxString& faceName = "", wxFontEncoding encoding = wxFONTENCODING_DEFAULT);
    !%wxchkver_3_0_0 wxFont(int pointSize, wxFontFamily family, int style, wxFontWeight weight, const bool underline = false, const wxString& faceName = "", wxFontEncoding encoding = wxFONTENCODING_DEFAULT);
    bool Ok(); // %add for compatibility with earlier versions of wxlua
    static %gc wxFont* New(const wxSize& pixelSize, wxFontFamily family, int style, wxFontWeight weight, const bool underline = false, const wxString& faceName = "", wxFontEncoding encoding = wxFONTENCODING_DEFAULT);
    static %gc wxFont* New(int pointSize, wxFontFamily family, int style, wxFontWeight weight, const bool underline = false, const wxString& faceName = "", wxFontEncoding encoding = wxFONTENCODING_DEFAULT);
};

// ---------------------------------------------------------------------------
// wxNativeFontInfo

#include "wx/fontutil.h"

class %delete wxNativeFontInfo
{
    wxNativeFontInfo();
    wxNativeFontInfo(const wxNativeFontInfo& info);

    // accessors and modifiers for the font elements
    int GetPointSize() const;
    %msw wxSize GetPixelSize() const; // FIXME wxWidgets has undefined symbol in gtk/mac
    wxFontStyle GetStyle() const;
    wxFontWeight GetWeight() const;
    bool GetUnderlined() const;
    wxString GetFaceName() const;
    wxFontFamily GetFamily() const;
    wxFontEncoding GetEncoding() const;

    void SetPointSize(int pointsize);
    %msw void SetPixelSize(const wxSize& pixelSize);
    void SetStyle(wxFontStyle style);
    void SetWeight(wxFontWeight weight);
    void SetUnderlined(bool underlined);
    %wxchkver_2_8 bool SetFaceName(const wxString& facename);
    !%wxchkver_2_8 void SetFaceName(const wxString& facename);
    void SetFamily(wxFontFamily family);
    void SetEncoding(wxFontEncoding encoding);

    // sets the first facename in the given array which is found
    // to be valid. If no valid facename is given, sets the
    // first valid facename returned by wxFontEnumerator::GetFacenames().
    // Does not return a bool since it cannot fail.
    %wxchkver_2_8 void SetFaceName(const wxArrayString& facenames);

    // it is important to be able to serialize wxNativeFontInfo objects to be
    // able to store them (in config file, for example);
    bool FromString(const wxString& s);
    wxString ToString() const;

    // we also want to present the native font descriptions to the user in some
    // human-readable form (it is not platform independent neither, but can
    // hopefully be understood by the user);
    bool FromUserString(const wxString& s);
    wxString ToUserString() const;
};

#endif //wxLUA_USE_wxFont

// ---------------------------------------------------------------------------
// wxFontEnumerator

#if wxLUA_USE_wxFontEnumerator

#include "wx/fontenum.h"

class %delete wxFontEnumerator
{
    wxFontEnumerator();

    virtual bool EnumerateFacenames(wxFontEncoding encoding = wxFONTENCODING_SYSTEM, bool fixedWidthOnly = false);
    virtual bool EnumerateEncodings(const wxString &font = "");

    %wxchkver_2_8 static wxArrayString GetEncodings(const wxString& facename = "");
    %wxchkver_2_8 static wxArrayString GetFacenames(wxFontEncoding encoding = wxFONTENCODING_SYSTEM, bool fixedWidthOnly = false);
    !%wxchkver_2_8 wxArrayString* GetEncodings();
    !%wxchkver_2_8 wxArrayString* GetFacenames();

    // Use GetEncodings/Facenames after calling EnumerateXXX
    //virtual bool OnFacename(const wxString& facename);
    //virtual bool OnFontEncoding(const wxString& facename, const wxString& encoding);
};

#endif //wxLUA_USE_wxFontEnumerator

// ---------------------------------------------------------------------------
// wxFontList

#if wxLUA_USE_wxFontList

class wxFontList
{
    #define_pointer wxTheFontList

    // No constructor, use wxTheFontList

    // Note: we don't gc the returned font as the list will delete it
    !%wxchkver_3_0 wxFont* FindOrCreateFont(int pointSize, int family, int style, int weight, bool underline = false, const wxString &faceName = "", wxFontEncoding encoding = wxFONTENCODING_DEFAULT);
    %wxchkver_3_0 wxFont *FindOrCreateFont(int pointSize, wxFontFamily family, wxFontStyle style, wxFontWeight weight, bool underline = false, const wxString& face = wxEmptyString, wxFontEncoding encoding = wxFONTENCODING_DEFAULT);
    %wxchkver_3_1_1 wxFont *FindOrCreateFont(const wxFontInfo& fontInfo);
};

#endif //wxLUA_USE_wxFontList

// ---------------------------------------------------------------------------
// wxFontMapper

#if wxLUA_USE_wxFontMapper

#include "wx/fontmap.h"

class wxFontMapper
{
    // No constructor, use static Get() function

    wxFontEncoding CharsetToEncoding(const wxString &charset, bool interactive = true);
    static wxFontMapper *Get();

    // %override [bool, wxFontEncoding *altEncoding] wxFontMapper::GetAltForEncoding(wxFontEncoding encoding, const wxString &faceName = "", bool interactive = true);
    // C++ Func: bool GetAltForEncoding(wxFontEncoding encoding, wxFontEncoding *altEncoding, const wxString &faceName = "", bool interactive = true);
    bool GetAltForEncoding(wxFontEncoding encoding, const wxString &faceName = "", bool interactive = true);

    // This function is really for wxWidgets internal use
    // %rename GetAltForEncodingInternal bool GetAltForEncoding(wxFontEncoding encoding, wxNativeEncodingInfo *info, const wxString &faceName = "", bool interactive = true);

    static wxString GetDefaultConfigPath();
    static wxFontEncoding GetEncoding(size_t n);
    static wxString GetEncodingDescription(wxFontEncoding encoding);
    static wxFontEncoding GetEncodingFromName(const wxString& encoding);
    static wxString GetEncodingName(wxFontEncoding encoding);
    static size_t GetSupportedEncodingsCount();
    bool IsEncodingAvailable(wxFontEncoding encoding, const wxString &facename = "");
    %wxchkver_2_8 static void Reset();
    void SetDialogParent(wxWindow *parent);
    void SetDialogTitle(const wxString &title);
    //static wxFontMapper *Set(wxFontMapper *mapper); // wxLua probably doesn't need this
    !%wxchkver_2_8 void SetConfig(wxConfigBase *config = NULL);
    void SetConfigPath(const wxString &prefix);
};

#endif //wxLUA_USE_wxFontMapper

// ---------------------------------------------------------------------------
// wxColour

#if wxLUA_USE_wxColourPenBrush

#include "wx/colour.h"
#include "wx/gdicmn.h"

#if %wxchkver_2_8
    #define wxC2S_NAME          // return colour name, when possible
    #define wxC2S_CSS_SYNTAX    // return colour in rgb(r,g,b) syntax
    #define wxC2S_HTML_SYNTAX   // return colour in #rrggbb syntax

    #define wxALPHA_TRANSPARENT
    #define wxALPHA_OPAQUE
#endif // %wxchkver_2_8

class %delete wxColour : public wxGDIObject
{
    #define_object  wxNullColour
    %rename wxBLACK      #define_pointer wxLua_wxBLACK  // hack for wxWidgets >2.7 wxStockGDI::GetColour
    %rename wxWHITE      #define_pointer wxLua_wxWHITE
    %rename wxRED        #define_pointer wxLua_wxRED
    %rename wxBLUE       #define_pointer wxLua_wxBLUE
    %rename wxGREEN      #define_pointer wxLua_wxGREEN
    %rename wxCYAN       #define_pointer wxLua_wxCYAN
    %rename wxLIGHT_GREY #define_pointer wxLua_wxLIGHT_GREY
    %rename wxYELLOW     #define_pointer wxLua_wxYELLOW
    %wxchkver_3_0_0 wxColour();
    %wxchkver_2_8 wxColour(unsigned char red, unsigned char green, unsigned char blue, unsigned char alpha = wxALPHA_OPAQUE);
    wxColour(const wxString& colourName);
    %wxchkver_3_0_0 wxColour(unsigned long colRGB);
    wxColour(const wxColour& colour);
    %wxchkver_2_8 unsigned char Alpha() const;
    unsigned char Blue() const;
    %wxchkver_2_8 virtual wxString GetAsString(long flags = wxC2S_NAME | wxC2S_CSS_SYNTAX) const;
    %wxchkver_3_0_0 void SetRGB(wxUint32 colRGB);
    %wxchkver_3_0_0 void SetRGBA(wxUint32 colRGBA);
    %wxchkver_3_0_0 wxUint32 GetRGB() const;
    %wxchkver_3_0_0 wxUint32 GetRGBA() const;
    %wxchkver_3_1_3 double GetLuminance() const;
    // long GetPixel(); // not well supported and the return type is different to map
    unsigned char Green() const;
    %wxchkver_3_0_0 bool IsOk() const;
    unsigned char Red() const;
    %wxchkver_3_1_2 bool IsSolid() const;
    %wxchkver_2_8 void Set(unsigned char red, unsigned char green, unsigned char blue, unsigned char alpha = wxALPHA_OPAQUE);
    %wxchkver_2_8 void Set(unsigned long colRGB);
    %wxchkver_2_8 bool Set(const wxString &str);
    bool operator !=(const wxColour& colour) const;
    wxColour& operator=(const wxColour& c) const;
    bool operator ==(const wxColour& colour) const;
    // static void MakeMono(unsigned char* r, unsigned char* g, unsigned char* b, bool on); // requires override, but easy to do in Lua
    // static void MakeDisabled(unsigned char* r, unsigned char* g, unsigned char* b, unsigned char brightness = 255); // requires override, but has an alternative version
    %wxchkver_3_0_0 wxColour& MakeDisabled(unsigned char brightness = 255);
    // static void MakeGrey(unsigned char* r, unsigned char* g, unsigned char* b); // requires override, but easy to do in Lua
    // static void MakeGrey(unsigned char* r, unsigned char* g, unsigned char* b, double weight_r, double weight_g, double weight_b); // requires override, but easy to do in Lua
    %wxchkver_3_0_0 static unsigned char AlphaBlend(unsigned char fg, unsigned char bg, double alpha);
    // static void ChangeLightness(unsigned char* r, unsigned char* g, unsigned char* b, int ialpha); // requires override, but has an alternative version
    %wxchkver_3_0_0 wxColour ChangeLightness(int ialpha) const;
    !%wxchkver_2_8 void Set(unsigned char red, unsigned char green, unsigned char blue);
    !%wxchkver_2_8 wxColour(unsigned char red, unsigned char green, unsigned char blue);
    bool Ok(); // %add for compatibility with earlier versions of wxlua
};

// ---------------------------------------------------------------------------
// wxColourDatabase

class %delete wxColourDatabase
{
    wxColourDatabase();

    #define_pointer wxTheColourDatabase

    wxColour Find(const wxString& name) const;
    wxString FindName(const wxColour& colour) const;
    void AddColour(const wxString& name, const wxColour& colour);
};

// ---------------------------------------------------------------------------
// wxPen

#include "wx/pen.h"

enum wxPenCap
{
    %wxchkver_3_0 wxCAP_INVALID,
    wxCAP_BUTT,
    wxCAP_PROJECTING,
    wxCAP_ROUND
};

enum wxPenStyle
{
    %wxchkver_3_0 wxPENSTYLE_INVALID,
    %wxchkver_3_0 wxPENSTYLE_SOLID, /**< Solid style. */
    %wxchkver_3_0 wxPENSTYLE_DOT, /**< Dotted style. */
    %wxchkver_3_0 wxPENSTYLE_LONG_DASH, /**< Long dashed style. */
    %wxchkver_3_0 wxPENSTYLE_SHORT_DASH, /**< Short dashed style. */
    %wxchkver_3_0 wxPENSTYLE_DOT_DASH, /**< Dot and dash style. */
    %wxchkver_3_0 wxPENSTYLE_USER_DASH, /**< Use the user dashes: see wxPen::SetDashes. */
    %wxchkver_3_0 wxPENSTYLE_TRANSPARENT, /**< No pen is used. */
    %wxchkver_3_0 wxPENSTYLE_STIPPLE_MASK_OPAQUE, /**< @todo WHAT's this? */
    %wxchkver_3_0 wxPENSTYLE_STIPPLE_MASK, /**< @todo WHAT's this? */
    %wxchkver_3_0 wxPENSTYLE_STIPPLE, /**< Use the stipple bitmap. */
    %wxchkver_3_0 wxPENSTYLE_BDIAGONAL_HATCH, /**< Backward diagonal hatch. */
    %wxchkver_3_0 wxPENSTYLE_CROSSDIAG_HATCH, /**< Cross-diagonal hatch. */
    %wxchkver_3_0 wxPENSTYLE_FDIAGONAL_HATCH, /**< Forward diagonal hatch. */
    %wxchkver_3_0 wxPENSTYLE_CROSS_HATCH, /**< Cross hatch. */
    %wxchkver_3_0 wxPENSTYLE_HORIZONTAL_HATCH, /**< Horizontal hatch. */
    %wxchkver_3_0 wxPENSTYLE_VERTICAL_HATCH, /**< Vertical hatch. */
    %wxchkver_3_0 wxPENSTYLE_FIRST_HATCH, /**< First of the hatch styles (inclusive). */
    %wxchkver_3_0 wxPENSTYLE_LAST_HATCH, /**< Last of the hatch styles (inclusive). */
    wxDOT,
    wxDOT_DASH,
    wxSOLID,
    wxLONG_DASH,
    wxSHORT_DASH,
    wxUSER_DASH
};

enum wxPenJoin
{
    %wxchkver_3_0 wxJOIN_INVALID,
    wxJOIN_BEVEL,
    wxJOIN_MITER,
    wxJOIN_ROUND
};

enum
{
    wxTRANSPARENT,

    wxSTIPPLE_MASK_OPAQUE,
    wxSTIPPLE_MASK,
    wxSTIPPLE,
    wxBDIAGONAL_HATCH,
    wxCROSSDIAG_HATCH,
    wxFDIAGONAL_HATCH,
    wxCROSS_HATCH,
    wxHORIZONTAL_HATCH,
    wxVERTICAL_HATCH
};


#if %wxchkver_3_1_1
class wxPenInfo
{
    wxPenInfo(const wxColour& colour, int width = 1, wxPenStyle style = wxPENSTYLE_SOLID);
    wxPenInfo& Colour(const wxColour& col);
    wxPenInfo& Width(int width);
    wxPenInfo& Style(wxPenStyle style);
    wxPenInfo& Stipple(const wxBitmap& stipple);
    // wxPenInfo& Dashes(int nb_dashes, const wxDash *dash);
    wxPenInfo& Join(wxPenJoin join);
    wxPenInfo& Cap(wxPenCap cap);
};
#endif // %wxchkver_3_1_1

class %delete wxPen : public wxGDIObject
{
    #define_object  wxNullPen
    %rename wxRED_PEN          #define_pointer wxLua_wxRED_PEN  // hack for wxWidgets >2.7 wxStockGDI::GetPen
    %rename wxCYAN_PEN         #define_pointer wxLua_wxCYAN_PEN
    %rename wxGREEN_PEN        #define_pointer wxLua_wxGREEN_PEN
    %rename wxBLACK_PEN        #define_pointer wxLua_wxBLACK_PEN
    %rename wxWHITE_PEN        #define_pointer wxLua_wxWHITE_PEN
    %rename wxTRANSPARENT_PEN  #define_pointer wxLua_wxTRANSPARENT_PEN
    %rename wxBLACK_DASHED_PEN #define_pointer wxLua_wxBLACK_DASHED_PEN
    %rename wxGREY_PEN         #define_pointer wxLua_wxGREY_PEN
    %rename wxMEDIUM_GREY_PEN  #define_pointer wxLua_wxMEDIUM_GREY_PEN
    %rename wxLIGHT_GREY_PEN   #define_pointer wxLua_wxLIGHT_GREY_PEN
    %rename wxBLUE_PEN         #define_pointer wxLua_wxBLUE_PEN
    %rename wxYELLOW_PEN       #define_pointer wxLua_wxYELLOW_PEN
    wxPen();
    %wxchkver_3_1_1 wxPen(const wxPenInfo& info);
    wxPen(const wxColour& colour, int width, wxPenStyle style);
    %win wxPen(const wxBitmap& stipple, int width);
    wxPen(const wxPen& pen);
    wxPenCap GetCap() const;
    wxColour GetColour() const; // not wxColur& so we allocate a new one
    // %override [table-of-integers] wxPen::GetDashes();
    // C++ Func: int GetDashes(wxDash** dashes) const;
    void GetDashes() const;
    wxPenJoin GetJoin() const;
    %win wxBitmap* GetStipple() const;
    wxPenStyle GetStyle() const;
    int GetWidth() const;
    %wxchkver_3_0_0 bool IsOk() const;
    %wxchkver_3_0_0 bool IsNonTransparent() const;
    %wxchkver_3_0_0 bool IsTransparent() const;
    void SetCap(wxPenCap capStyle);
    void SetColour(wxColour& colour);
    void SetColour(unsigned char red, unsigned char green, unsigned char blue);
    // %override void SetDashes(Lua-table-of-integers);
    // C++ Func: void wxPen::SetDashes(int nb_dashes, const wxDash *dash);
    void SetDashes();
    void SetJoin(wxPenJoin join_style);
    %win void SetStipple(const wxBitmap& stipple);
    void SetStyle(wxPenStyle style);
    void SetWidth(int width);
    %wxchkver_3_0_0 bool operator!=(const wxPen& pen) const;
    wxPen& operator=(const wxPen& p) const;
    %wxchkver_3_0_0 bool operator==(const wxPen& pen) const;
    !%wxchkver_3_0_0 void SetColour(const wxString& colourName);
    !%wxchkver_3_0_0 wxPen(const wxString& colourName, int width, wxPenStyle style);
    bool Ok() const; // %add for compatibility with earlier versions of wxlua
};

// ---------------------------------------------------------------------------
// wxPenList

#if wxLUA_USE_wxPenList

class wxPenList //: public wxList - it's not really derived from a wxList
{
    #define_pointer wxThePenList

    // No constructor, use wxThePenList

    // Note: we don't gc the returned pen as the list will delete it
    !%wxchkver_3_0 wxPen* FindOrCreatePen(const wxColour& colour, int width, int style);
    %wxchkver_3_0 wxPen *FindOrCreatePen(const wxColour& colour, int width = 1, wxPenStyle style = wxPENSTYLE_SOLID);
};

#endif //wxLUA_USE_wxPenList

// ---------------------------------------------------------------------------
// wxBrush

#include "wx/brush.h"

#if %wxchkver_3_0_0

enum wxBrushStyle
{
    wxBRUSHSTYLE_INVALID,
    wxBRUSHSTYLE_SOLID, /**< Solid. */
    wxBRUSHSTYLE_TRANSPARENT, /**< Transparent (no fill). */
    wxBRUSHSTYLE_STIPPLE_MASK_OPAQUE, /**< Uses a bitmap as a stipple; the mask is used for blitting monochrome using text foreground and background colors. */
    wxBRUSHSTYLE_STIPPLE_MASK, /**< Uses a bitmap as a stipple; mask is used for masking areas in the stipple bitmap. */
    wxBRUSHSTYLE_STIPPLE, /**< Uses a bitmap as a stipple. */
    wxBRUSHSTYLE_BDIAGONAL_HATCH, /**< Backward diagonal hatch. */
    wxBRUSHSTYLE_CROSSDIAG_HATCH, /**< Cross-diagonal hatch. */
    wxBRUSHSTYLE_FDIAGONAL_HATCH, /**< Forward diagonal hatch. */
    wxBRUSHSTYLE_CROSS_HATCH, /**< Cross hatch. */
    wxBRUSHSTYLE_HORIZONTAL_HATCH, /**< Horizontal hatch. */
    wxBRUSHSTYLE_VERTICAL_HATCH, /**< Vertical hatch. */
    wxBRUSHSTYLE_FIRST_HATCH, /**< First of the hatch styles (inclusive). */
    wxBRUSHSTYLE_LAST_HATCH /**< Last of the hatch styles (inclusive). */
};

#endif // %wxchkver_3_0_0

class %delete wxBrush : public wxGDIObject
{
    #define_object  wxNullBrush
    %rename wxBLUE_BRUSH        #define_pointer wxLua_wxBLUE_BRUSH // hack for wxWidgets >2.7 wxStockGDI::GetBrush
    %rename wxGREEN_BRUSH       #define_pointer wxLua_wxGREEN_BRUSH
    %rename wxWHITE_BRUSH       #define_pointer wxLua_wxWHITE_BRUSH
    %rename wxBLACK_BRUSH       #define_pointer wxLua_wxBLACK_BRUSH
    %rename wxGREY_BRUSH        #define_pointer wxLua_wxGREY_BRUSH
    %rename wxMEDIUM_GREY_BRUSH #define_pointer wxLua_wxMEDIUM_GREY_BRUSH
    %rename wxLIGHT_GREY_BRUSH  #define_pointer wxLua_wxLIGHT_GREY_BRUSH
    %rename wxTRANSPARENT_BRUSH #define_pointer wxLua_wxTRANSPARENT_BRUSH
    %rename wxCYAN_BRUSH        #define_pointer wxLua_wxCYAN_BRUSH
    %rename wxRED_BRUSH         #define_pointer wxLua_wxRED_BRUSH
    %rename wxYELLOW_BRUSH      #define_pointer wxLua_wxYELLOW_BRUSH
    wxBrush();
    %wxchkver_3_0_0 wxBrush(const wxColour& colour, wxBrushStyle style = wxBRUSHSTYLE_SOLID);
    wxBrush(const wxBitmap& stippleBitmap);
    wxBrush(const wxBrush& brush);
    wxColour GetColour() const;
    wxBitmap* GetStipple() const;
    int GetStyle() const;
    bool IsHatch() const;
    %wxchkver_3_0_0 bool IsOk() const;
    %wxchkver_3_0_0 bool IsNonTransparent() const;
    %wxchkver_3_0_0 bool IsTransparent() const;
    %wxchkver_3_0_0 void SetColour(const wxColour& colour);
    %wxchkver_3_0_0 void SetColour(unsigned char red, unsigned char green, unsigned char blue);
    void SetStipple(const wxBitmap& bitmap);
    %wxchkver_3_0_0 void SetStyle(wxBrushStyle style);
    bool operator !=(const wxBrush& brush) const;
    bool operator ==(const wxBrush& brush) const;
    !%wxchkver_3_0_0 void SetColour(const unsigned char red, const unsigned char green, const unsigned char blue);
    !%wxchkver_3_0_0 void SetColour(const wxString& colourName);
    !%wxchkver_3_0_0 void SetColour(wxColour& colour);
    !%wxchkver_3_0_0 void SetStyle(int style);
    !%wxchkver_3_0_0 wxBrush& operator=(const wxBrush& b) const;
    !%wxchkver_3_0_0 wxBrush(const wxColour& colour, int style);
    !%wxchkver_3_0_0 wxBrush(const wxString& colourName, int style);
    bool Ok() const; // %add for compatibility with earlier versions of wxlua
};

// ---------------------------------------------------------------------------
// wxBrushList

#if wxLUA_USE_wxBrushList

class wxBrushList // : public wxList - it's not really derived from it
{
    #define_pointer wxTheBrushList

    // No constructor, use wxTheBrushList

    // Note: we don't gc the returned brush as the list will delete it
    !%wxchkver_3_0_0 wxBrush* FindOrCreateBrush(const wxColour& colour, int style);
    %wxchkver_3_0_0 wxBrush *FindOrCreateBrush(const wxColour& colour, wxBrushStyle style = wxBRUSHSTYLE_SOLID);
};

#endif //wxLUA_USE_wxBrushList


// ---------------------------------------------------------------------------
// wxStockGDI

#include "wx/gdicmn.h"

#if %wxchkver_2_8

enum wxStockGDI::Item
{
        BRUSH_BLACK,
        BRUSH_BLUE,
        BRUSH_CYAN,
        BRUSH_GREEN,
        BRUSH_GREY,
        BRUSH_LIGHTGREY,
        BRUSH_MEDIUMGREY,
        BRUSH_RED,
        BRUSH_TRANSPARENT,
        BRUSH_WHITE,
        COLOUR_BLACK,
        COLOUR_BLUE,
        COLOUR_CYAN,
        COLOUR_GREEN,
        COLOUR_LIGHTGREY,
        COLOUR_RED,
        COLOUR_WHITE,
        CURSOR_CROSS,
        CURSOR_HOURGLASS,
        CURSOR_STANDARD,
        FONT_ITALIC,
        FONT_NORMAL,
        FONT_SMALL,
        FONT_SWISS,
        PEN_BLACK,
        PEN_BLACKDASHED,
        PEN_CYAN,
        PEN_GREEN,
        PEN_GREY,
        PEN_LIGHTGREY,
        PEN_MEDIUMGREY,
        PEN_RED,
        PEN_TRANSPARENT,
        PEN_WHITE,
        ITEMCOUNT
};

class wxStockGDI
{
    //wxStockGDI() use instance to get the implemented wxStockGDI

    //static void DeleteAll();
    static wxStockGDI& instance();

    static const wxBrush* GetBrush(wxStockGDI::Item item);
    static const wxColour* GetColour(wxStockGDI::Item item);
    static const wxCursor* GetCursor(wxStockGDI::Item item);
    // Can be overridden by platform-specific derived classes
    virtual const wxFont* GetFont(wxStockGDI::Item item);
    static const wxPen* GetPen(wxStockGDI::Item item);
};

#endif // %wxchkver_2_8
#endif //wxLUA_USE_wxColourPenBrush

// ---------------------------------------------------------------------------
// wxPalette

#if wxLUA_USE_wxPalette && wxUSE_PALETTE

#include "wx/palette.h"

class %delete wxPalette : public wxGDIObject
{
    #define_object wxNullPalette
    wxPalette();
    wxPalette(const wxPalette& palette);
    %wxchkver_3_0_0 wxPalette(int n, const unsigned char* red, const unsigned char* green, const unsigned char* blue);
    bool Create(int n, const unsigned char* red, const unsigned char* green, const unsigned char* blue); // %override bool wxPalette::Create(int n, Lua string red, Lua string green, Lua string blue);
    int GetColoursCount() const;
    int GetPixel(unsigned char red, unsigned char green, unsigned char blue) const;
    %wxchkver_3_0_0 bool IsOk() const;
    wxPalette& operator =(const wxPalette& palette);
    bool GetRGB(int pixel) const; // %override [bool, char red, char green, char blue] wxPalette::GetRGB(int pixel) const;
    bool Ok() const; // %add for compatibility with earlier versions of wxlua
};

#endif //wxLUA_USE_wxPalette && wxUSE_PALETTE

// ---------------------------------------------------------------------------
// wxIcon

#if wxLUA_USE_wxIcon
typedef void* WXHANDLE

class %delete wxIcon : public wxGDIObject
{
    #define_object wxNullIcon
    wxIcon();
    %wxchkver_2_9_5 wxIcon(const wxIcon& icon);
    // wxIcon(const char bits[], int width, int height); // doesn't compile on Linux using gcc 4.6-4.8.1
    // wxIcon(const char* const* bits); // wxlua doesn't handle `const char* const*`
    wxIcon(const wxString& name, wxBitmapType type = wxICON_DEFAULT_TYPE, int desiredWidth = -1, int desiredHeight = -1);
    %wxchkver_2_9_5 wxIcon(const wxIconLocation& loc);
    // bool CreateFromHICON(WXHICON icon); // skip this one as it's windows specific
    // wxIcon ConvertToDisabled(unsigned char brightness = 255) const; // skip as it's win-only; can use one from wxBitmap
    %wxchkver_2_9_5 void CopyFromBitmap(const wxBitmap& bmp);
    int     GetDepth();
    int     GetHeight();
    int     GetWidth();
    %wxchkver_2_9_5 bool IsOk() const;
    %wxchkver_2_9_5 bool LoadFile(const wxString& name, wxBitmapType type = wxICON_DEFAULT_TYPE, int desiredWidth = -1, int desiredHeight = -1);
    void    SetDepth(int d);
    void    SetHeight(int h);
    void    SetWidth(int w);
    wxIcon& operator=(const wxIcon& i) const;
    !%wxchkver_2_9_5 bool LoadFile(const wxString& name, wxBitmapType flag);
    bool    Ok(); // %add for compatibility with earlier versions of wxlua
};

// ---------------------------------------------------------------------------
// wxIconBundle

#include "wx/iconbndl.h"

class %delete wxIconBundle : public wxGDIObject
{
    wxIconBundle();
    !%wxchkver_2_9 || %wxcompat_2_8 wxIconBundle(const wxString& file, long type);
    wxIconBundle(const wxIcon& icon);
    wxIconBundle(const wxIconBundle& ic);

#if wxUSE_STREAMS && wxUSE_IMAGE
#if wxUSE_FFILE || wxUSE_FILE
    wxIconBundle(const wxString& file, wxBitmapType type = wxBITMAP_TYPE_ANY);
#endif // wxUSE_FFILE || wxUSE_FILE
    wxIconBundle(wxInputStream& stream, wxBitmapType type = wxBITMAP_TYPE_ANY);
#endif // wxUSE_STREAMS && wxUSE_IMAGE

    !%wxchkver_2_9 || %wxcompat_2_8 void AddIcon(const wxString& file, long type);
    void AddIcon(const wxIcon& icon);

#if wxUSE_STREAMS && wxUSE_IMAGE
#if wxUSE_FFILE || wxUSE_FILE
    void AddIcon(const wxString& file, wxBitmapType type = wxBITMAP_TYPE_ANY);
#endif // wxUSE_FFILE || wxUSE_FILE
    void AddIcon(wxInputStream& stream, wxBitmapType type = wxBITMAP_TYPE_ANY);
#endif // wxUSE_STREAMS && wxUSE_IMAGE

    wxIcon GetIcon(const wxSize& size) const;
    // equivalent to GetIcon(wxSize(size, size));
    wxIcon GetIcon(int size = wxDefaultCoord) const;
};

#endif //wxLUA_USE_wxIcon

// ---------------------------------------------------------------------------
// wxBitmap

#if wxLUA_USE_wxBitmap

#include "wx/bitmap.h"

class %delete wxBitmap : public wxGDIObject
{
    #define_object wxNullBitmap
    wxBitmap();
    wxBitmap(const wxBitmap& bitmap);
    %wxchkver_3_0_0 wxBitmap(const char bits[], int width, int height, int depth = 1);
    wxBitmap(int width, int height, int depth = wxBITMAP_SCREEN_DEPTH);
    %wxchkver_3_0_0 wxBitmap(const wxSize& sz, int depth = wxBITMAP_SCREEN_DEPTH);
    // wxBitmap(const char* const* bits); // wxlua doesn't handle `const char* const*`
    wxBitmap(const wxString& name, wxBitmapType type = wxBITMAP_TYPE_ANY);
    %wxchkver_3_1_2 wxBitmap(const wxImage &image, int depth = wxBITMAP_SCREEN_DEPTH, double scale = 1.0);
    %wxchkver_3_1_0 & %win wxBitmap(const wxCursor& cursor); // %override windows only
    // %win static void AddHandler(wxBitmapHandler* handler); // no support for wxBitmapHandler
    // %win static void CleanUpHandlers(); // no support for wxBitmapHandler
    wxImage ConvertToImage();
    bool CopyFromIcon(const wxIcon& icon);
    virtual bool Create(int width, int height, int depth = wxBITMAP_SCREEN_DEPTH);
    %wxchkver_3_0_0 bool Create(const wxSize& sz, int depth = wxBITMAP_SCREEN_DEPTH);
    %wxchkver_3_0_0 bool Create(int width, int height, const wxDC& dc);
    %wxchkver_3_0_0 bool CreateScaled(int logwidth, int logheight, int depth, double logicalScale);
    // static wxBitmapHandler* FindHandler(const wxString& name); // no support for wxBitmapHandler
    // static wxBitmapHandler* FindHandler(const wxString& extension, wxBitmapType bitmapType); // no support for wxBitmapHandler
    // static wxBitmapHandler* FindHandler(wxBitmapType bitmapType); // no support for wxBitmapHandler
    int GetDepth() const;
    // %wxchkver_2_6&%win static wxGDIImageHandlerList& GetHandlers(); // no support for wxBitmapHandler
    int GetHeight() const;
    wxMask* GetMask() const;
    wxPalette* GetPalette() const;
    wxBitmap GetSubBitmap(const wxRect&rect) const;
    %wxchkver_3_0_0 wxSize GetSize() const;
    %wxchkver_3_0_0 wxBitmap ConvertToDisabled(unsigned char brightness = 255) const;
    int GetWidth() const;

    // support for scaled bitmaps
    %wxchkver_2_9_5 double GetScaleFactor() const;
    %wxchkver_2_9_5 double GetScaledWidth() const;
    %wxchkver_2_9_5 double GetScaledHeight() const;
    %wxchkver_2_9_5 wxSize GetScaledSize() const;

    // %win static void InitStandardHandlers(); // no support for wxBitmapHandler
    // %win static void InsertHandler(wxBitmapHandler* handler); // no support for wxBitmapHandler
    %wxchkver_3_0_0 bool IsOk() const;
    bool LoadFile(const wxString& name, wxBitmapType type);
    %wxchkver_3_0_0 static wxBitmap NewFromPNGData(const void* data, size_t size);
    // %win static bool RemoveHandler(const wxString& name); // no support for wxBitmapHandler
    %wxchkver_3_0_0 bool SaveFile(const wxString& name, wxBitmapType type, const wxPalette* palette = NULL) const;
    void SetDepth(int depth);
    void SetHeight(int height);
    void SetMask(%ungc wxMask* mask);
    %win void SetPalette(const wxPalette& palette);
    void SetWidth(int width);
    !%wxchkver_3_0_0 bool SaveFile(const wxString& name, wxBitmapType type, wxPalette* palette = NULL);
    !%wxchkver_3_0_0 wxBitmap& operator=(const wxBitmap& b) const;
    !%wxchkver_3_1_2 wxBitmap(const wxImage &image, int depth = wxBITMAP_SCREEN_DEPTH);
    %override_name wxLua_wxBitmapFromBitTable_constructor wxBitmap(LuaTable charTable, int width, int height, int depth /* = 1 */); // %override wxBitmap(LuaTable charTable, int width, int height, int depth);
    %override_name wxLua_wxBitmapFromBits_constructor wxBitmap(const char* mono_bits, int width, int height, int depth /* = 1 */); // %override wxBitmap(lua string, int width, int height, int depth);
    %override_name wxLua_wxBitmapFromData_constructor %win wxBitmap(const wxString& data, int type, int width, int height, int depth /* = -1 */); // %override wxBitmap(Lua string of data, int type, int width, int height, int depth = -1);
    %override_name wxLua_wxBitmapFromXPMData_constructor wxBitmap(LuaTable charTable); // %override wxBitmap(LuaTable stringTable where each index is a row in the image);
    // !%msw&%wxchkver_2_8 virtual wxColour QuantizeColour(const wxColour& colour) const; // generic implementation only; not present in interface files
    bool Ok() const; // %add for compatibility with earlier versions of wxlua
};

#endif //wxLUA_USE_wxBitmap

// ---------------------------------------------------------------------------
// wxCursor

#if wxLUA_USE_wxCursor

//typedef void* WXHANDLE

#include "wx/cursor.h"

enum wxStockCursor
{
    wxCURSOR_NONE,
    wxCURSOR_ARROW,
    wxCURSOR_RIGHT_ARROW,
    wxCURSOR_BULLSEYE,
    wxCURSOR_CHAR,
    wxCURSOR_CROSS,
    wxCURSOR_HAND,
    wxCURSOR_IBEAM,
    wxCURSOR_LEFT_BUTTON,
    wxCURSOR_MAGNIFIER,
    wxCURSOR_MIDDLE_BUTTON,
    wxCURSOR_NO_ENTRY,
    wxCURSOR_PAINT_BRUSH,
    wxCURSOR_PENCIL,
    wxCURSOR_POINT_LEFT,
    wxCURSOR_POINT_RIGHT,
    wxCURSOR_QUESTION_ARROW,
    wxCURSOR_RIGHT_BUTTON,
    wxCURSOR_SIZENESW,
    wxCURSOR_SIZENS,
    wxCURSOR_SIZENWSE,
    wxCURSOR_SIZEWE,
    wxCURSOR_SIZING,
    wxCURSOR_SPRAYCAN,
    wxCURSOR_WAIT,
    wxCURSOR_WATCH,
    wxCURSOR_BLANK,
    wxCURSOR_DEFAULT,
    %mac wxCURSOR_COPY_ARROW,

    #if defined(__X__);
        // Not yet implemented for Windows
        wxCURSOR_CROSS_REVERSE,
        wxCURSOR_DOUBLE_ARROW,
        wxCURSOR_BASED_ARROW_UP,
        wxCURSOR_BASED_ARROW_DOWN,
    #endif // X11

    wxCURSOR_ARROWWAIT,
    wxCURSOR_MAX
};

class %delete wxCursor : public wxGDIObject
{
    #define_object  wxNullCursor
    %rename wxSTANDARD_CURSOR  #define_pointer wxLua_wxSTANDARD_CURSOR  // hack for wxWidgets >2.7
    %rename wxHOURGLASS_CURSOR #define_pointer wxLua_wxHOURGLASS_CURSOR
    %rename wxCROSS_CURSOR     #define_pointer wxLua_wxCROSS_CURSOR
    wxCursor();
    // wxCursor(const char bits[], int width, int height, int hotSpotX = -1, int hotSpotY = -1, const char maskBits[] = NULL); // doesn't compile in wxlua, so skip it
    %wxchkver_2_9_0 wxCursor(const wxString& cursorName, wxBitmapType type, int hotSpotX = 0, int hotSpotY = 0);
    %wxchkver_3_0_0 wxCursor(wxStockCursor cursorId);
    wxCursor(const wxImage& image);
    %wxchkver_3_0_0 wxCursor(const wxCursor& cursor);
    %wxchkver_3_0_0 bool IsOk() const;
    %wxchkver_3_1_0 wxPoint GetHotSpot() const;
    wxCursor& operator =(const wxCursor& cursor);
    !%wxchkver_3_0_0 wxCursor& operator=(const wxCursor& c) const;
    !%wxchkver_3_0_0 wxCursor(int id);
    %win int GetDepth(); // %add only for windows
    %win int GetHeight(); // %add only for windows
    %win int GetWidth(); // %add only for windows
    bool Ok(); // %add for compatibility with earlier versions of wxlua
};

#endif //wxLUA_USE_wxCursor

// ---------------------------------------------------------------------------
// wxMask

#if wxLUA_USE_wxMask

#include "wx/bitmap.h"

class %delete wxMask : public wxObject
{
    wxMask();
    %win wxMask(const wxBitmap& bitmap, int index);
    wxMask(const wxBitmap& bitmap);
    wxMask(const wxBitmap& bitmap, const wxColour& colour);
    %win bool Create(const wxBitmap& bitmap, int index);
    bool Create(const wxBitmap& bitmap);
    bool Create(const wxBitmap& bitmap, const wxColour& colour);
    %wxchkver_3_0_0 wxBitmap GetBitmap() const;
    !%wxchkver_3_0_0 wxMask& operator=(const wxMask& m) const;
};

#endif //wxLUA_USE_wxMask

// ---------------------------------------------------------------------------
// wxImageList

#if wxLUA_USE_wxImageList

#include "wx/imaglist.h"

#define wxIMAGELIST_DRAW_NORMAL
#define wxIMAGELIST_DRAW_TRANSPARENT
#define wxIMAGELIST_DRAW_SELECTED
#define wxIMAGELIST_DRAW_FOCUSED

#define wxIMAGE_LIST_NORMAL
#define wxIMAGE_LIST_SMALL
#define wxIMAGE_LIST_STATE

class %delete wxImageList : public wxObject
{
    wxImageList(int width, int height, bool mask = true, int initialCount = 1);

    int Add(const wxBitmap& bitmap, const wxBitmap& mask = wxNullBitmap);
    int Add(const wxBitmap& bitmap, const wxColour& maskColour);
    int Add(const wxIcon& icon);
    bool    Draw(int index, wxDC& dc, int x, int y, int flags = wxIMAGELIST_DRAW_NORMAL, bool solidBackground = false);
    wxBitmap GetBitmap(int index) const;
    wxIcon  GetIcon(int index) const;
    int     GetImageCount();

    // %override [int width, int height] wxImageList::GetSize(int index);
    // C++ Func: void GetSize(int index, int& width, int& height);
    void    GetSize(int index);

    bool    Remove(int index);
    bool    RemoveAll();
    %win bool Replace(int index, const wxBitmap& bitmap, const wxBitmap& mask = wxNullBitmap);
    %gtk|%mac bool Replace(int index, const wxBitmap& bitmap);
    //bool ReplaceIcon(int index, const wxIcon& icon);
};

#endif //wxLUA_USE_wxImageList

// ---------------------------------------------------------------------------
// wxAffineMatrix2D

#if %wxchkver_2_9_2

#if wxUSE_GEOMETRY

#include "wx/affinematrix2d.h"

struct wxMatrix2D
{
    wxMatrix2D(wxDouble v11 = 1, wxDouble v12 = 0, wxDouble v21 = 0, wxDouble v22 = 1);
};

class %delete wxAffineMatrix2D
{
public:
    wxAffineMatrix2D();
    void Get(wxMatrix2D* mat2D, wxPoint2DDouble* tr) const;
    void Set(const wxMatrix2D& mat2D, const wxPoint2DDouble& tr);
    void Concat(const wxAffineMatrix2D& t);
    bool Invert();
    bool IsIdentity() const;
    void IsEqual(const wxAffineMatrix2D& t);
    void Translate(wxDouble dx, wxDouble dy);
    void Scale(wxDouble xScale, wxDouble yScale);
    void Mirror(int direction = wxHORIZONTAL);
    void Rotate(wxDouble cRadians);
    wxPoint2DDouble TransformPoint(const wxPoint2DDouble& p) const;
    void TransformPoint(wxDouble* x, wxDouble* y) const;
    wxPoint2DDouble TransformDistance(const wxPoint2DDouble& p) const;
    void TransformDistance(wxDouble* dx, wxDouble* dy) const;
};

#endif //wxUSE_GEOMETRY

#endif //%wxchkver_2_9_2

// ---------------------------------------------------------------------------
// wxDC

#if wxLUA_USE_wxDC

#include "wx/dc.h"

enum wxMappingMode
{
    wxMM_TEXT,
    wxMM_METRIC,
    wxMM_LOMETRIC,
    wxMM_TWIPS,
    wxMM_POINTS,

    !%wxchkver_2_9_2 wxMM_HIMETRIC,
    !%wxchkver_2_9_2 wxMM_LOENGLISH,
    !%wxchkver_2_9_2 wxMM_HIENGLISH,
    !%wxchkver_2_9_2 wxMM_ISOTROPIC,
    !%wxchkver_2_9_2 wxMM_ANISOTROPIC
};

enum wxRasterOperationMode
{
    wxCLEAR,
    wxXOR,
    wxINVERT,
    wxOR_REVERSE,
    wxAND_REVERSE,
    wxCOPY,
    wxAND,
    wxAND_INVERT,
    wxNO_OP,
    wxNOR,
    wxEQUIV,
    wxSRC_INVERT,
    wxOR_INVERT,
    wxNAND,
    wxOR,
    wxSET,

    !%wxchkver_2_9_0 || %wxcompat_2_8 wxROP_BLACK,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxROP_COPYPEN,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxROP_MASKNOTPEN,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxROP_MASKPEN,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxROP_MASKPENNOT,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxROP_MERGENOTPEN,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxROP_MERGEPEN,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxROP_MERGEPENNOT,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxROP_NOP,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxROP_NOT,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxROP_NOTCOPYPEN,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxROP_NOTMASKPEN,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxROP_NOTMERGEPEN,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxROP_NOTXORPEN,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxROP_WHITE,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxROP_XORPEN,

    !%wxchkver_2_9_0 || %wxcompat_2_8 wxBLIT_00220326,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxBLIT_007700E6,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxBLIT_00990066,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxBLIT_00AA0029,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxBLIT_00DD0228,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxBLIT_BLACKNESS,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxBLIT_DSTINVERT,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxBLIT_MERGEPAINT,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxBLIT_NOTSCRCOPY,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxBLIT_NOTSRCERASE,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxBLIT_SRCAND,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxBLIT_SRCCOPY,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxBLIT_SRCERASE,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxBLIT_SRCINVERT,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxBLIT_SRCPAINT,
    !%wxchkver_2_9_0 || %wxcompat_2_8 wxBLIT_WHITENESS
};

enum wxFloodFillStyle
{
    wxFLOOD_BORDER,
    wxFLOOD_SURFACE
};

enum wxPolygonFillMode
{
    wxODDEVEN_RULE,
    wxWINDING_RULE
};

class %delete wxDC : public wxObject
{
    // %win wxDC() wxDC is abstract use wxXXXDC

    //void BeginDrawing(); // these are deprecated in 2.8 and didn't do anything anyway
    bool Blit(wxCoord xdest, wxCoord ydest, wxCoord width, wxCoord height, wxDC* source, wxCoord xsrc, wxCoord ysrc, wxRasterOperationMode logicalFunc = wxCOPY, bool useMask = false);
    void CalcBoundingBox(wxCoord x, wxCoord y);
    void Clear();
    //void ComputeScaleAndOrigin()  used internally
    void CrossHair(wxCoord x, wxCoord y);
    void DestroyClippingRegion();
    wxCoord DeviceToLogicalX(wxCoord x);
    wxCoord DeviceToLogicalXRel(wxCoord x);
    wxCoord DeviceToLogicalY(wxCoord y);
    wxCoord DeviceToLogicalYRel(wxCoord y);
    void DrawArc(wxCoord x1, wxCoord y1, wxCoord x2, wxCoord y2, wxCoord xc, wxCoord yc);
    void DrawBitmap(const wxBitmap& bitmap, wxCoord x, wxCoord y, bool transparent);
    void DrawCheckMark(wxCoord x, wxCoord y, wxCoord width, wxCoord height);
    void DrawCheckMark(const wxRect &rect);
    void DrawCircle(wxCoord x, wxCoord y, wxCoord radius);
    //void DrawCircle(const wxPoint& pt, wxCoord radius);
    void DrawEllipse(wxCoord x, wxCoord y, wxCoord width, wxCoord height);
    //void DrawEllipse(const wxPoint& pt, const wxSize& size);
    //void DrawEllipse(const wxRect& rect);
    void DrawEllipticArc(wxCoord x, wxCoord y, wxCoord width, wxCoord height, double start, double end);
    void DrawIcon(const wxIcon& icon, wxCoord x, wxCoord y);
    void DrawLabel(const wxString& text, const wxBitmap& image, const wxRect& rect, int alignment = wxALIGN_LEFT | wxALIGN_TOP, int indexAccel = -1); //, wxRect *rectBounding = NULL);
    void DrawLabel(const wxString& text, const wxRect& rect, int alignment = wxALIGN_LEFT | wxALIGN_TOP, int indexAccel = -1);
    void DrawLine(wxCoord x1, wxCoord y1, wxCoord x2, wxCoord y2);

    //void DrawLines(int n, wxPoint points[], wxCoord xoffset = 0, wxCoord yoffset = 0);
    // Provide a Lua Table of {{1,2},{3,4},...}, {{x=1,y=2},{x=3,y=4},...}, or {wx.wxPoint(1,2),wx.wxPoint(3,4),...}
    void DrawLines(wxPointArray_FromLuaTable points, wxCoord xoffset = 0, wxCoord yoffset = 0);
    //%wxchkver_2_9  void DrawLines(const wxPointList *points, wxCoord xoffset = 0, wxCoord yoffset = 0);
    //!%wxchkver_2_9 void DrawLines(const wxList *points, wxCoord xoffset = 0, wxCoord yoffset = 0);

    //void DrawPolygon(int n, wxPoint points[], wxCoord xoffset = 0, wxCoord yoffset = 0, wxPolygonFillMode fill_style = wxODDEVEN_RULE);
    // Provide a Lua Table of {{1,2},{3,4},...}, {{x=1,y=2},{x=3,y=4},...}, or {wx.wxPoint(1,2),wx.wxPoint(3,4),...}
    void DrawPolygon(wxPointArray_FromLuaTable points, wxCoord xoffset = 0, wxCoord yoffset = 0, wxPolygonFillMode fill_style = wxODDEVEN_RULE);
    //%wxchkver_2_9 void DrawPolygon(const wxPointList *points, wxCoord xoffset = 0, wxCoord yoffset = 0, wxPolygonFillMode fill_style = wxODDEVEN_RULE);
    //!%wxchkver_2_9 void DrawPolygon(const wxList *points, wxCoord xoffset = 0, wxCoord yoffset = 0, wxPolygonFillMode fill_style = wxODDEVEN_RULE);

    //void DrawPolyPolygon(int n, int count[], wxPoint points[], wxCoord xoffset = 0, wxCoord yoffset = 0, wxPolygonFillMode fill_style = wxODDEVEN_RULE);

    void DrawPoint(wxCoord x, wxCoord y);
    void DrawRectangle(wxCoord x, wxCoord y, wxCoord width, wxCoord height);
    void DrawRotatedText(const wxString& text, wxCoord x, wxCoord y, double angle);
    void DrawRoundedRectangle(wxCoord x, wxCoord y, wxCoord width, wxCoord height, double radius = 20);
    #if wxUSE_SPLINES
        //void DrawSpline(int n, wxPoint points[]);
        // Provide a Lua Table of {{1,2},{3,4},...}, {{x=1,y=2},{x=3,y=4},...}, or {wx.wxPoint(1,2),wx.wxPoint(3,4),...}
        void DrawSpline(wxPointArray_FromLuaTable points);
        //void DrawSpline(wxList *points);
    #endif //wxUSE_SPLINES
    void DrawText(const wxString& text, wxCoord x, wxCoord y);
    void EndDoc();
    //void EndDrawing();  // these are deprecated in 2.8 and didn't do anything anyway
    void EndPage();
    void FloodFill(wxCoord x, wxCoord y, const wxColour& colour, wxFloodFillStyle style=wxFLOOD_SURFACE);

    %wxchkver_2_9_2 bool CanUseTransformMatrix() const;
    %wxchkver_2_9_2 bool SetTransformMatrix(const wxAffineMatrix2D& matrix);
    %wxchkver_2_9_2 wxAffineMatrix2D GetTransformMatrix() const;
    %wxchkver_2_9_2 void ResetTransformMatrix();

    #if %wxchkver_2_8
        //void GradientFillConcentric(const wxRect& rect, const wxColour& initialColour, const wxColour& destColour);
        void GradientFillConcentric(const wxRect& rect, const wxColour& initialColour, const wxColour& destColour, const wxPoint& circleCenter);
        void GradientFillLinear(const wxRect& rect, const wxColour& initialColour, const wxColour& destColour, wxDirection nDirection = wxEAST);
        wxBitmap GetAsBitmap(const wxRect *subrect = NULL) const;
    #endif //%wxchkver_2_8

    // alias
    const wxBrush& GetBackground();
    int GetBackgroundMode() const;
    const wxBrush& GetBrush();
    wxCoord GetCharHeight();
    wxCoord GetCharWidth();
    void GetClippingBox(wxCoord *x, wxCoord *y, wxCoord *width, wxCoord *height);
    const wxFont& GetFont();
    %wxchkver_2_8 wxLayoutDirection GetLayoutDirection() const;
    int GetLogicalFunction();
    int GetMapMode();
    bool GetPartialTextExtents(const wxString& text, wxArrayInt& widths) const;
    const wxPen& GetPen();
    bool GetPixel(wxCoord x, wxCoord y, wxColour *colour);
    wxSize GetPPI() const;
    void GetSize(wxCoord *width, wxCoord *height); // wxSize GetSize() const;
    //void GetSizeMM(wxCoord *width, wxCoord *height) const; // wxSize GetSizeMM() const;
    const wxColour& GetTextBackground() const;

    // %override [int x, int y, int descent, int externalLeading] int wxDC::GetTextExtent(const wxString& string, const wxFont* font = NULL);
    // C++ Func: void GetTextExtent(const wxString& string, wxCoord* x, wxCoord* y, wxCoord* descent = NULL, wxCoord* externalLeading = NULL, const wxFont* font = NULL);
    void GetTextExtent(const wxString& string, wxFont *font = NULL);

    %wxchkver_2_8 %rename GetTextExtentSize wxSize GetTextExtent(const wxString& string) const;

    // %override [int x, int y, int heightLine] int wxDC::GetMultiLineTextExtent(const wxString& string, const wxFont* font = NULL);
    // C++ Func: void GetMultiLineTextExtent(const wxString& string, wxCoord* x, wxCoord* y, wxCoord* heightLine = NULL, const wxFont* font = NULL);
    %wxchkver_2_8 void GetMultiLineTextExtent(const wxString& string, wxFont *font = NULL) const;

    %wxchkver_2_8 %rename GetMultiLineTextExtentSize wxSize GetMultiLineTextExtent(const wxString& string) const;

    const wxColour& GetTextForeground();

    // %override [int x, int y] wxDC::GetUserScale();
    // C++ Func: void GetUserScale(double *x, double *y);
    void GetUserScale();

    wxCoord LogicalToDeviceX(wxCoord x);
    wxCoord LogicalToDeviceXRel(wxCoord x);
    wxCoord LogicalToDeviceY(wxCoord y);
    wxCoord LogicalToDeviceYRel(wxCoord y);
    wxCoord MaxX();
    wxCoord MaxY();
    wxCoord MinX();
    wxCoord MinY();
    bool IsOk();
    void ResetBoundingBox();
    void SetAxisOrientation(bool xLeftRight, bool yBottomUp);
    %wxchkver_2_9_5 virtual double GetContentScaleFactor() const;
    void SetBackground(const wxBrush& brush);
    void SetBackgroundMode(int mode);
    void SetBrush(const wxBrush& brush);
    void SetClippingRegion(wxCoord x, wxCoord y, wxCoord width, wxCoord height);
    !%wxchkver_3_0 void SetClippingRegion(const wxRegion& region);
    void SetClippingRegion(const wxPoint& pt, const wxSize& sz);
    void SetClippingRegion(const wxRect& rect);
    void SetDeviceOrigin(wxCoord x, wxCoord y);
    void SetFont(const wxFont& font);
    %wxchkver_2_8 void SetLayoutDirection(wxLayoutDirection dir);
    void SetLogicalFunction(wxRasterOperationMode function);
    void SetMapMode(wxMappingMode unit);
    void SetPalette(const wxPalette& palette);
    void SetPen(const wxPen& pen);
    void SetTextBackground(const wxColour& colour);
    void SetTextForeground(const wxColour& colour);
    void SetUserScale(double xScale, double yScale);
    bool StartDoc(const wxString& message);
    void StartPage();
};

// ---------------------------------------------------------------------------
// wxMemoryDC

#include "wx/dcmemory.h"

class %delete wxMemoryDC : public wxDC
{
    wxMemoryDC();
    void SelectObject(wxBitmap& bitmap); // not const in >=2.8

    %wxchkver_2_8 virtual void SelectObjectAsSource(const wxBitmap& bmp);
};

// ---------------------------------------------------------------------------
// wxWindowDC

#include "wx/dcclient.h"

class %delete wxWindowDC : public wxDC
{
    wxWindowDC(wxWindow* window);
};

// ---------------------------------------------------------------------------
// wxClientDC

#include "wx/dcclient.h"

class %delete wxClientDC : public wxWindowDC
{
    wxClientDC(wxWindow* window);
};

// ---------------------------------------------------------------------------
// wxPaintDC

#include "wx/dcclient.h"

class %delete wxPaintDC : public wxWindowDC // base ok as wxWindowDC since only some platforms have wxClientDC as base
{
    wxPaintDC(wxWindow* window);
};

// ---------------------------------------------------------------------------
// wxScreenDC

#include "wx/dcscreen.h"

class %delete wxScreenDC : public wxDC
{
    wxScreenDC();

    static bool StartDrawingOnTop(wxWindow* window);
    static bool StartDrawingOnTop(wxRect* rect = NULL);
    static bool EndDrawingOnTop();
};

// ---------------------------------------------------------------------------
// wxBufferedDC

#include "wx/dcbuffer.h"

class %delete wxBufferedDC : public wxMemoryDC
{
    wxBufferedDC();
    wxBufferedDC(wxDC *dc, const wxSize& area, int style = wxBUFFER_CLIENT_AREA);
    wxBufferedDC(wxDC *dc, wxBitmap& buffer, int style = wxBUFFER_CLIENT_AREA); // not const bitmap >= 2.8

    void Init(wxDC *dc, const wxSize& area, int style = wxBUFFER_CLIENT_AREA);
    void Init(wxDC *dc, wxBitmap& buffer, int style = wxBUFFER_CLIENT_AREA); // not const bitmap in >= 2.8
};

// ---------------------------------------------------------------------------
// wxBufferedPaintDC

#include "wx/dcbuffer.h"

class %delete wxBufferedPaintDC : public wxBufferedDC
{
    wxBufferedPaintDC(wxWindow *window, int style = wxBUFFER_CLIENT_AREA);
    wxBufferedPaintDC(wxWindow *window, wxBitmap& buffer, int style = wxBUFFER_CLIENT_AREA); // not const bitmap in >= 2.8
};

// ---------------------------------------------------------------------------
// wxAutoBufferedPaintDC

#include "wx/dcbuffer.h"

#if %wxchkver_2_8

#define wxALWAYS_NATIVE_DOUBLE_BUFFER

// This class is derived from a wxPaintDC if wxALWAYS_NATIVE_DOUBLE_BUFFER else wxBufferedPaintDC
// In fact in release mode it's only a #define to either

class %delete wxAutoBufferedPaintDC : public wxDC // base ok as wxDC since no need for others
{
    wxAutoBufferedPaintDC(wxWindow *window);
};

#endif // %wxchkver_2_8

// ---------------------------------------------------------------------------
// wxMirrorDC

#include "wx/dcmirror.h"

class %delete wxMirrorDC : public wxDC
{
    wxMirrorDC(wxDC& dc, bool mirror);
};

// ---------------------------------------------------------------------------
// wxDCClipper

#include "wx/dc.h"

class %delete wxDCClipper
{
    wxDCClipper(wxDC& dc, const wxRect& r);
    //wxDCClipper(wxDC& dc, const wxRegion& r);
    wxDCClipper(wxDC& dc, wxCoord x, wxCoord y, wxCoord w, wxCoord h);
};

#endif //wxLUA_USE_wxDC

// ---------------------------------------------------------------------------
// wxCaret

#if wxLUA_USE_wxCaret && wxUSE_CARET

#include "wx/caret.h"

class %delete wxCaret
{
    wxCaret();
    wxCaret(wxWindow* window, int width, int height);
    wxCaret(wxWindow* window, const wxSize& size);
    bool Create(wxWindow* window, int width, int height);
    bool Create(wxWindow* window, const wxSize& size);
    static int GetBlinkTime();
    wxPoint GetPosition();
    wxSize GetSize();
    wxWindow *GetWindow();
    void Hide();
    bool IsOk();
    bool IsVisible();
    void Move(int x, int y);
    void Move(const wxPoint& pt);
    static void SetBlinkTime(int ms);
    void SetSize(int width, int height);
    void SetSize(const wxSize& size);
    void Show(bool show = true);
    %rename GetPositionXY void GetPosition(); // %override [int x, int y] wxCaret::GetPositionXY();
    %rename GetSizeWH void GetSize(); // %override [int x, int y] wxCaret::GetSizeWH();
};

// ---------------------------------------------------------------------------
// wxCaretSuspend

#include "wx/caret.h"

class %delete wxCaretSuspend
{
    // NOTE: ALWAYS delete() this when done since Lua's gc may not delete it soon enough
    wxCaretSuspend(wxWindow *win = NULL);
};

#endif //wxLUA_USE_wxCaret && wxUSE_CARET

// ---------------------------------------------------------------------------
// wxVideoMode

#if wxLUA_USE_wxDisplay && wxUSE_DISPLAY

#include "wx/display.h"

class %delete wxVideoMode
{
    #define_object wxDefaultVideoMode

    wxVideoMode(int width = 0, int height = 0, int depth = 0, int freq = 0);

    bool Matches(const wxVideoMode& other) const;
    int  GetWidth() const;
    int  GetHeight() const;
    int  GetDepth() const;
    bool IsOk() const;

    bool operator==(const wxVideoMode& v) const;
};

// ---------------------------------------------------------------------------
// wxArrayVideoModes

class %delete wxArrayVideoModes
{
    wxArrayVideoModes();
    wxArrayVideoModes(const wxArrayVideoModes& array);

    void Add(const wxVideoMode& vm, size_t copies = 1);
    void Alloc(size_t nCount);
    void Clear();
    void Empty();
    int  GetCount() const;
    void Insert(const wxVideoMode& vm, int nIndex, size_t copies = 1);
    bool IsEmpty();
    wxVideoMode Item(size_t nIndex) const;
    wxVideoMode Last();
    void RemoveAt(size_t nIndex, size_t count = 1);
    void Shrink();

    wxVideoMode& operator[](size_t nIndex);
};

// ---------------------------------------------------------------------------
// wxDisplay

class %delete wxDisplay
{
    %wxchkver_3_0_0 wxDisplay(unsigned int index = 0);
    %wxchkver_3_1_2 wxDisplay(const wxWindow* window);
    bool  ChangeMode(const wxVideoMode& mode = wxDefaultVideoMode);
    %wxchkver_2_8 wxRect GetClientArea() const;
    static size_t GetCount();
    wxVideoMode  GetCurrentMode() const;
    static int GetFromPoint(const wxPoint& pt);
    wxRect  GetGeometry() const;
    wxArrayVideoModes  GetModes(const wxVideoMode& mode = wxDefaultVideoMode) const;
    wxString  GetName() const;
    %wxchkver_3_1_2 wxSize GetPPI() const;
    %wxchkver_3_1_5 double GetScaleFactor() const;
    %wxchkver_3_1_5 static int GetStdPPIValue();
    %wxchkver_3_1_5 static wxSize GetStdPPI();
    bool  IsPrimary();
    !%wxchkver_3_0_0 bool  IsOk() const;
    !%wxchkver_3_0_0 wxDisplay(size_t index = 0);
    static int GetFromWindow(const wxWindow* win);
};

#endif //wxLUA_USE_wxDisplay && wxUSE_DISPLAY

// ---------------------------------------------------------------------------
// wxEffects

#if %wxcompat_2_8
#include "wx/effects.h"

class %delete wxEffects : public wxObject
{
    wxEffects(); // use system default colours
    wxEffects(const wxColour& highlightColour, const wxColour& lightShadow, const wxColour& faceColour, const wxColour& mediumShadow, const wxColour& darkShadow);

    wxColour GetHighlightColour() const;
    wxColour GetLightShadow() const;
    wxColour GetFaceColour() const;
    wxColour GetMediumShadow() const;
    wxColour GetDarkShadow() const;

    void SetHighlightColour(const wxColour& c);
    void SetLightShadow(const wxColour& c);
    void SetFaceColour(const wxColour& c);
    void SetMediumShadow(const wxColour& c);
    void SetDarkShadow(const wxColour& c);

    void Set(const wxColour& highlightColour, const wxColour& lightShadow, const wxColour& faceColour, const wxColour& mediumShadow, const wxColour& darkShadow);

    void DrawSunkenEdge(wxDC& dc, const wxRect& rect, int borderSize = 1);
    bool TileBitmap(const wxRect& rect, wxDC& dc, wxBitmap& bitmap);
};
#endif //%wxcompat_2_8

// ---------------------------------------------------------------------------
// wxRenderer

#if wxLUA_USE_wxRenderer

#include "wx/renderer.h"

%wxHAS_NATIVE_RENDERER #define wxHAS_NATIVE_RENDERER 1

enum
{
    wxCONTROL_DISABLED,   //= 0x00000001,  // control is disabled
    wxCONTROL_FOCUSED,    //= 0x00000002,  // currently has keyboard focus
    wxCONTROL_PRESSED,    //= 0x00000004,  // (button) is pressed
    wxCONTROL_SPECIAL,    //= 0x00000008,  // control-specific bit:
    wxCONTROL_ISDEFAULT,  //= wxCONTROL_SPECIAL, // only for the buttons
    wxCONTROL_ISSUBMENU,  //= wxCONTROL_SPECIAL, // only for the menu items
    wxCONTROL_EXPANDED,   //= wxCONTROL_SPECIAL, // only for the tree items
    wxCONTROL_SIZEGRIP,   //= wxCONTROL_SPECIAL, // only for the status bar panes
    wxCONTROL_CURRENT,    //= 0x00000010,  // mouse is currently over the control
    wxCONTROL_SELECTED,   //= 0x00000020,  // selected item in e.g. listbox
    wxCONTROL_CHECKED,    //= 0x00000040,  // (check/radio button) is checked
    wxCONTROL_CHECKABLE,  //= 0x00000080,  // (menu) item can be checked
    wxCONTROL_UNDETERMINED, //= wxCONTROL_CHECKABLE, // (check) undetermined state

    wxCONTROL_FLAGS_MASK, //= 0x000000ff,

    // this is a pseudo flag not used directly by wxRenderer but rather by some
    // controls internally
    wxCONTROL_DIRTY       //= 0x80000000
};

struct %delete wxSplitterRenderParams
{
    // the only way to initialize this struct is by using this ctor
    wxSplitterRenderParams(wxCoord widthSash_, wxCoord border_, bool isSens_);

    const wxCoord widthSash;     // the width of the splitter sash
    const wxCoord border;        // the width of the border of the splitter window
    const bool isHotSensitive;   // true if the splitter changes its appearance when the mouse is over it
};


// extra optional parameters for DrawHeaderButton
struct %delete wxHeaderButtonParams
{
    wxHeaderButtonParams();

    wxColour    m_arrowColour;
    wxColour    m_selectionColour;
    wxString    m_labelText;
    wxFont      m_labelFont;
    wxColour    m_labelColour;
    wxBitmap    m_labelBitmap;
    int         m_labelAlignment;
};

enum wxHeaderSortIconType
{
    wxHDR_SORT_ICON_NONE,        // Header button has no sort arrow
    wxHDR_SORT_ICON_UP,          // Header button an an up sort arrow icon
    wxHDR_SORT_ICON_DOWN         // Header button an a down sort arrow icon
};

// the current version and age of wxRendererNative interface: different
// versions are incompatible (in both ways) while the ages inside the same
// version are upwards compatible, i.e. the version of the renderer must
// match the version of the main program exactly while the age may be
// highergreater or equal to it
enum wxRendererVersion::dummy
{
    Current_Version, //= 1,
    Current_Age      //= 5
};

// wxRendererNative interface version
struct %delete wxRendererVersion
{
    wxRendererVersion(int version_, int age_);

    // check if the given version is compatible with the current one
    static bool IsCompatible(const wxRendererVersion& ver);

    const int version;
    const int age;
};


class %delete wxRendererNative
{
    // pseudo constructors
    // -------------------
    // return the currently used renderer
    static wxRendererNative& Get();
    // return the generic implementation of the renderer
    static wxRendererNative& GetGeneric();
    // return the default (native) implementation for this platform
    static wxRendererNative& GetDefault();


    // draw the header control button (used by wxListCtrl) Returns optimal
    // width for the label contents.
    virtual int  DrawHeaderButton(wxWindow *win, wxDC& dc, const wxRect& rect, int flags = 0, wxHeaderSortIconType sortArrow = wxHDR_SORT_ICON_NONE, wxHeaderButtonParams* params=NULL); //= 0;

    // Draw the contents of a header control button (label, sort arrows, etc.);
    // Normally only called by DrawHeaderButton.
    virtual int  DrawHeaderButtonContents(wxWindow *win, wxDC& dc, const wxRect& rect, int flags = 0, wxHeaderSortIconType sortArrow = wxHDR_SORT_ICON_NONE, wxHeaderButtonParams* params=NULL); //= 0;

    // Returns the default height of a header button, either a fixed platform
    // height if available, or a generic height based on the window's font.
    virtual int GetHeaderButtonHeight(wxWindow *win); //= 0;

    // draw the expanded/collapsed icon for a tree control item
    virtual void DrawTreeItemButton(wxWindow *win, wxDC& dc, const wxRect& rect, int flags = 0); //= 0;

    // draw the border for sash window: this border must be such that the sash
    // drawn by DrawSash() blends into it well
    virtual void DrawSplitterBorder(wxWindow *win, wxDC& dc, const wxRect& rect, int flags = 0); //= 0;

    // draw a (vertical) sash
    virtual void DrawSplitterSash(wxWindow *win, wxDC& dc, const wxSize& size, wxCoord position, wxOrientation orient, int flags = 0); //= 0;

    // draw a combobox dropdown button
    // flags may use wxCONTROL_PRESSED and wxCONTROL_CURRENT
    virtual void DrawComboBoxDropButton(wxWindow *win, wxDC& dc, const wxRect& rect, int flags = 0); //= 0;

    // draw a dropdown arrow
    // flags may use wxCONTROL_PRESSED and wxCONTROL_CURRENT
    virtual void DrawDropArrow(wxWindow *win, wxDC& dc, const wxRect& rect, int flags = 0); //= 0;

    // draw check button
    // flags may use wxCONTROL_CHECKED, wxCONTROL_UNDETERMINED and wxCONTROL_CURRENT
    virtual void DrawCheckBox(wxWindow *win, wxDC& dc, const wxRect& rect, int flags = 0); //= 0;

    // draw blank button
    // flags may use wxCONTROL_PRESSED, wxCONTROL_CURRENT and wxCONTROL_ISDEFAULT
    virtual void DrawPushButton(wxWindow *win, wxDC& dc, const wxRect& rect, int flags = 0); //= 0;

    // draw rectangle indicating that an item in e.g. a list control has been selected or focused
    // flags may use
    // wxCONTROL_SELECTED (item is selected, e.g. draw background);
    // wxCONTROL_CURRENT (item is the current item, e.g. dotted border);
    // wxCONTROL_FOCUSED (the whole control has focus, e.g. blue background vs. grey otherwise);
    virtual void DrawItemSelectionRect(wxWindow *win, wxDC& dc, const wxRect& rect, int flags = 0); //= 0;

    // geometry functions
    // ------------------

    // get the splitter parameters: the x field of the returned point is the
    // sash width and the y field is the border width
    virtual wxSplitterRenderParams GetSplitterParams(const wxWindow *win); //= 0;

    // changing the global renderer
    // ----------------------------

#if wxUSE_DYNLIB_CLASS
    // load the renderer from the specified DLL, the returned pointer must be
    // deleted by caller if not NULL when it is not used any more
    static %gc wxRendererNative *Load(const wxString& name);
#endif // wxUSE_DYNLIB_CLASS

    // set the renderer to use, passing NULL reverts to using the default
    // renderer
    //
    // return the previous renderer used with Set() or NULL if none
    static %gc wxRendererNative *Set(%ungc wxRendererNative *renderer);

    // this function is used for version checking: Load() refuses to load any
    // DLLs implementing an older or incompatible version; it should be
    // implemented simply by returning wxRendererVersion::Current_XXX values
    virtual wxRendererVersion GetVersion() const; //= 0;
};

#endif // wxLUA_USE_wxRenderer
