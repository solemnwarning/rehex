// ===========================================================================
// Purpose:     wxImage
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================


#define wxIMAGE_ALPHA_TRANSPARENT
#define wxIMAGE_ALPHA_THRESHOLD
#define wxIMAGE_ALPHA_OPAQUE

enum wxBitmapType
{
    wxBITMAP_TYPE_INVALID,
    wxBITMAP_TYPE_BMP,
    wxBITMAP_TYPE_BMP_RESOURCE,
    wxBITMAP_TYPE_RESOURCE,
    wxBITMAP_TYPE_ICO,
    wxBITMAP_TYPE_ICO_RESOURCE,
    wxBITMAP_TYPE_CUR,
    wxBITMAP_TYPE_CUR_RESOURCE,
    wxBITMAP_TYPE_XBM,
    wxBITMAP_TYPE_XBM_DATA,
    wxBITMAP_TYPE_XPM,
    wxBITMAP_TYPE_XPM_DATA,
    wxBITMAP_TYPE_TIF,
    wxBITMAP_TYPE_TIF_RESOURCE,
    wxBITMAP_TYPE_GIF,
    wxBITMAP_TYPE_GIF_RESOURCE,
    wxBITMAP_TYPE_PNG,
    wxBITMAP_TYPE_PNG_RESOURCE,
    wxBITMAP_TYPE_JPEG,
    wxBITMAP_TYPE_JPEG_RESOURCE,
    wxBITMAP_TYPE_PNM,
    wxBITMAP_TYPE_PNM_RESOURCE,
    wxBITMAP_TYPE_PCX,
    wxBITMAP_TYPE_PCX_RESOURCE,
    wxBITMAP_TYPE_PICT,
    wxBITMAP_TYPE_PICT_RESOURCE,
    wxBITMAP_TYPE_ICON,
    wxBITMAP_TYPE_ICON_RESOURCE,
    wxBITMAP_TYPE_ANI,
    wxBITMAP_TYPE_IFF,
    %wxchkver_2_8 wxBITMAP_TYPE_TGA,
    wxBITMAP_TYPE_MACCURSOR,
    wxBITMAP_TYPE_MACCURSOR_RESOURCE,
    wxBITMAP_TYPE_ANY
};

// ---------------------------------------------------------------------------
// wxImage

#if wxLUA_USE_wxImage && wxUSE_IMAGE

#include "wx/image.h"

%wxchkver_2_6 #define_wxstring wxIMAGE_OPTION_CUR_HOTSPOT_X
%wxchkver_2_6 #define_wxstring wxIMAGE_OPTION_CUR_HOTSPOT_Y

//#define_string wxIMAGE_OPTION_PNG_FORMAT     see wxPNGHandler
//#define_string wxIMAGE_OPTION_PNG_BITDEPTH   see wxPNGHandler
//#define_string wxIMAGE_OPTION_BMP_FORMAT     see wxBMPHandler

#define_wxstring wxIMAGE_OPTION_QUALITY        wxT("quality");
#define_wxstring wxIMAGE_OPTION_FILENAME       wxT("FileName");

#define_wxstring wxIMAGE_OPTION_RESOLUTION     wxT("Resolution");
#define_wxstring wxIMAGE_OPTION_RESOLUTIONX    wxT("ResolutionX");
#define_wxstring wxIMAGE_OPTION_RESOLUTIONY    wxT("ResolutionY");
#define_wxstring wxIMAGE_OPTION_RESOLUTIONUNIT wxT("ResolutionUnit");

enum
{
    // constants used with wxIMAGE_OPTION_RESOLUTIONUNIT
    wxIMAGE_RESOLUTION_INCHES,
    wxIMAGE_RESOLUTION_CM
};

// Constants for wxImage::Scale() for determining the level of quality
enum wxImageResizeQuality
{
    // different image resizing algorithms used by Scale() and Rescale();
    %wxchkver_2_9_2 wxIMAGE_QUALITY_NEAREST,
    %wxchkver_2_9_2 wxIMAGE_QUALITY_BILINEAR,
    %wxchkver_2_9_2 wxIMAGE_QUALITY_BICUBIC,
    %wxchkver_2_9_2 wxIMAGE_QUALITY_BOX_AVERAGE,

    // default quality is low (but fast);
    %wxchkver_2_8 wxIMAGE_QUALITY_NORMAL,

    // highest (but best) quality
    %wxchkver_2_8 wxIMAGE_QUALITY_HIGH
};



class %delete wxImage : public wxObject
{
    #define_object wxNullImage
    wxImage();
    wxImage(int width, int height, bool clear=true);
    %wxchkver_3_0_0 wxImage(const wxSize& sz, bool clear = true);
    %wxchkver_3_0_0 wxImage(const wxSize& sz, unsigned char* data, bool static_data = false);
    %wxchkver_3_0_0 wxImage(int width, int height, unsigned char* data, unsigned char* alpha, bool static_data = false);
    %wxchkver_3_0_0 wxImage(const wxSize& sz, unsigned char* data, unsigned char* alpha, bool static_data = false);
    // wxImage(const char* const* xpmData); // wxlua doesn't handle `const char* const*`
    %wxchkver_3_0_0 wxImage(const wxString& name, wxBitmapType type = wxBITMAP_TYPE_ANY, int index = -1);
    %wxchkver_3_0_0 wxImage(const wxString& name, const wxString& mimetype, int index = -1);
    %wxchkver_3_0_0 wxImage(wxInputStream& stream, wxBitmapType type = wxBITMAP_TYPE_ANY, int index = -1);
    %wxchkver_3_0_0 wxImage(wxInputStream& stream, const wxString& mimetype, int index = -1);
    wxImage Copy() const;
    void Create(int width, int height, bool clear=true);
    %wxchkver_3_0_0 bool Create(const wxSize& sz, bool clear = true);
    %wxchkver_3_0_0 bool Create(int width, int height, unsigned char* data, bool static_data = false);
    %wxchkver_3_0_0 bool Create(const wxSize& sz, unsigned char* data, bool static_data = false);
    %wxchkver_3_0_0 bool Create(int width, int height, unsigned char* data, unsigned char* alpha, bool static_data = false);
    %wxchkver_3_0_0 bool Create(const wxSize& sz, unsigned char* data, unsigned char* alpha, bool static_data = false);
    %wxchkver_3_0_0 void Clear(unsigned char value = 0);
    void Destroy();
    void InitAlpha();
    %wxchkver_2_8 wxImage Blur(int radius);
    %wxchkver_2_8 wxImage BlurHorizontal(int radius);
    %wxchkver_2_8 wxImage BlurVertical(int radius);
    wxImage Mirror(bool horizontally = true) const;
    %wxchkver_3_0_0 void Paste(const wxImage& image, int x, int y);
    void Replace(unsigned char r1, unsigned char g1, unsigned char b1, unsigned char r2, unsigned char g2, unsigned char b2);
    %wxchkver_2_8 wxImage& Rescale(int width, int height, wxImageResizeQuality quality = wxIMAGE_QUALITY_NORMAL);
    wxImage& Resize(const wxSize& size, const wxPoint& pos, int red = -1, int green = -1, int blue = -1);
    wxImage Rotate(double angle, const wxPoint& rotationCentre, bool interpolating = true, wxPoint* offsetAfterRotation = NULL);
    wxImage Rotate90(bool clockwise = true) const;
    %wxchkver_3_0_0 wxImage Rotate180() const;
    void RotateHue(double angle);
    %wxchkver_2_8 wxImage Scale(int width, int height, wxImageResizeQuality quality = wxIMAGE_QUALITY_NORMAL) const;
    wxImage Size(const wxSize& size, const wxPoint& pos, int red = -1, int green = -1, int blue = -1) const;
    %wxchkver_3_0_0 bool ConvertAlphaToMask(unsigned char threshold = wxIMAGE_ALPHA_THRESHOLD);
    %wxchkver_3_0_0 bool ConvertAlphaToMask(unsigned char mr, unsigned char mg, unsigned char mb, unsigned char threshold = wxIMAGE_ALPHA_THRESHOLD);
    wxImage ConvertToMono(unsigned char r, unsigned char g, unsigned char b) const;
    %wxchkver_3_0_0 wxImage ConvertToDisabled(unsigned char brightness = 255) const;
    unsigned long ComputeHistogram(wxImageHistogram& histogram) const;
    wxImage& operator=(const wxImage& image);
    unsigned char* GetData() const; // %override [Lua string] wxImage::GetData() const;
    unsigned char GetAlpha(int x, int y) const;
    unsigned char GetRed(int x, int y) const;
    unsigned char GetGreen(int x, int y) const;
    unsigned char GetBlue(int x, int y) const;
    unsigned char GetMaskRed() const;
    unsigned char GetMaskGreen() const;
    unsigned char GetMaskBlue() const;
    int GetWidth() const;
    int GetHeight() const;
    %wxchkver_3_0_0 wxSize GetSize() const;
    wxString GetOption(const wxString &name) const;
    int GetOptionInt(const wxString &name) const;
    wxPalette GetPalette() const;
    wxImage GetSubImage(const wxRect& rect) const;
    %wxchkver_3_0_0 wxBitmapType GetType() const;
    bool HasAlpha() const;
    bool HasMask() const;
    int HasOption(const wxString &name) const;
    %wxchkver_3_0_0 bool IsOk() const;
    bool IsTransparent(int x, int y, unsigned char threshold = 128) const;
    bool LoadFile(wxInputStream& stream, wxBitmapType type = wxBITMAP_TYPE_ANY, int index = -1);
    bool LoadFile(const wxString& name, wxBitmapType type = wxBITMAP_TYPE_ANY, int index = -1);
    bool LoadFile(const wxString& name, const wxString& mimetype, int index = -1);
    bool LoadFile(wxInputStream& stream, const wxString& mimetype, int index = -1);
    %wxchkver_3_0_0 bool SaveFile(wxOutputStream& stream, const wxString& mimetype) const;
    %wxchkver_3_0_0 bool SaveFile(const wxString& name, wxBitmapType type) const;
    bool SaveFile(const wxString& name, const wxString& mimetype);
    bool SaveFile(const wxString& name);
    %wxchkver_3_0_0 bool SaveFile(wxOutputStream& stream, wxBitmapType type) const;
    %wxchkver_3_0_0 void SetAlpha(unsigned char* alpha = NULL, bool static_data = false);
    void SetAlpha(int x, int y, unsigned char alpha);
    %wxchkver_3_0_0 void ClearAlpha();
    %wxchkver_3_1_0 static void SetDefaultLoadFlags(int flags);
    %wxchkver_3_1_0 void SetLoadFlags(int flags);
    void SetMask(bool hasMask = true);
    void SetMaskColour(unsigned char red, unsigned char blue, unsigned char green);
    bool SetMaskFromImage(const wxImage& mask, unsigned char mr, unsigned char mg, unsigned char mb);
    void SetOption(const wxString &name, const wxString &value);
    void SetOption(const wxString &name, int value);
    void SetPalette(const wxPalette& palette);
    void SetRGB(int x, int y, unsigned char r, unsigned char g, unsigned char b);
    %wxchkver_3_0_0 void SetRGB(const wxRect& rect, unsigned char red, unsigned char green, unsigned char blue);
    %wxchkver_3_0_0 void SetType(wxBitmapType type);
    static void AddHandler(%ungc wxImageHandler* handler);
    static void CleanUpHandlers();
    static wxImageHandler* FindHandler(const wxString& name);
    %wxchkver_3_0_0 static wxImageHandler* FindHandler(const wxString& extension, wxBitmapType imageType);
    %wxchkver_3_0_0 static wxImageHandler* FindHandler(wxBitmapType imageType);
    static wxImageHandler* FindHandlerMime(const wxString& mimetype);
    static wxList& GetHandlers();
    static void InitStandardHandlers();
    static void InsertHandler(%ungc wxImageHandler* handler);
    static bool RemoveHandler(const wxString& name);
    %wxchkver_3_0_0 static bool CanRead(const wxString& filename);
    %wxchkver_3_0_0 static bool CanRead(wxInputStream& stream);
    %wxchkver_3_1_0 static int GetDefaultLoadFlags();
    static int GetImageCount(const wxString& filename, wxBitmapType type = wxBITMAP_TYPE_ANY);
    static int GetImageCount(wxInputStream& stream, wxBitmapType type = wxBITMAP_TYPE_ANY);
    static wxString GetImageExtWildcard();
    %wxchkver_3_1_0 int GetLoadFlags() const;
    !%wxchkver_2_8 wxImage Scale(int width, int height) const;
    !%wxchkver_2_8 wxImage& Rescale(int width, int height);
    !%wxchkver_3_0_0 bool SaveFile(const wxString& name, int type);
    !%wxchkver_3_0_0 static wxImageHandler* FindHandler(const wxString& extension, long imageType);
    !%wxchkver_3_0_0 static wxImageHandler* FindHandler(long imageType);
    !%wxchkver_3_0_0 void SetRGB(wxRect& rect, unsigned char red, unsigned char green, unsigned char blue);
    !%wxchkver_3_0_0 wxImage(const wxImage& image);
    !%wxchkver_3_0_0 wxImage(const wxString& name, long type = wxBITMAP_TYPE_ANY);
    %override_name wxLua_wxImageFromBitmap_constructor wxImage(const wxBitmap& bitmap); // %override wxLua provides this constructor
    %override_name wxLua_wxImageFromData_constructor wxImage(int width, int height, unsigned char* data, bool static_data = false); // %override wxImage(int width, int height, unsigned char* data, bool static_data = false);
    %override_name wxLua_wxImage_GetAlphaData unsigned char* GetAlpha() const; // %override [Lua string] wxImage::GetAlpha() const;
    %override_name wxLua_wxImage_SetAlphaData void SetAlpha(const wxString& dataStr); // %override void wxImage::SetAlpha(Lua string) - copy contents of string to image
    %wxchkver_2_8 wxImage ConvertToGreyscale(double lr = 0.299, double lg = 0.587, double lb = 0.114) const; // %override parameter initialization
    %wxchkver_2_8 wxImage ResampleBicubic(int width, int height) const; // %add missing in interface description
    %wxchkver_2_8 wxImage ResampleBox(int width, int height) const; // %add missing in interface description
    %wxchkver_3_1 wxImage ResampleBilinear(int width, int height) const; // %add missing in interface description
    %wxchkver_3_1 wxImage ResampleNearest(int width, int height) const; // %add missing in interface description
    bool FindFirstUnusedColour(unsigned char startR = 1, unsigned char startG = 0, unsigned char startB = 0); // %override [bool, uchar r, uchar g, char b] wxImage::FindFirstUnusedColour(unsigned char startR = 1, unsigned char startG = 0, unsigned char startB = 0);
    bool GetOrFindMaskColour() const; // %override [bool, uchar r, uchar g, uchar b] wxImage::GetOrFindMaskColour() const;
    bool Ok() const; // %add for compatibility with earlier versions of wxlua
    static int HSVtoRGB(double h, double s, double v); // %override [r, g, b] wxImage::HSVtoRGB(double h, double s, double v);
    static int RGBtoHSV(unsigned char r, unsigned char g, unsigned char b); // %override [h, s, v] wxImage::RGBtoHSV(unsigned char r, unsigned char g, unsigned char b);
    void SetData(const wxString& data); // %override void wxImage::SetData(Lua string) - copy contents of string to image
};

// ---------------------------------------------------------------------------
// wxImageHistogram

class %delete wxImageHistogramEntry
{
    wxImageHistogramEntry();
    unsigned long index; // GetIndex() only, SetIndex(idx) is not allowed
    unsigned long value; // GetValue() and SetValue(val);
};

class %delete wxImageHistogram::iterator
{
    long first;
    wxImageHistogramEntry second;

    // operator used to compare with wxImageHistogram::end() iterator
    bool operator==(const wxImageHistogram::iterator& other) const;

    //wxImageHistogram::iterator& operator++(); // it just returns *this
    void operator++(); // it's best if we don't return the iterator
};

class %delete wxImageHistogram // wxImageHistogramBase actually a hash map
{
    wxImageHistogram();

    // get the key in the histogram for the given RGB values
    static unsigned long MakeKey(unsigned char r, unsigned char g, unsigned char b);

    // Use the function wxImage::FindFirstUnusedColour
    //bool FindFirstUnusedColour(unsigned char *r, unsigned char *g, unsigned char *b, unsigned char startR = 1, unsigned char startG = 0, unsigned char startB = 0) const;

    // Selected functions from the base wxHashMap class
    wxImageHistogram::iterator begin() const; // not const iterator since we create a new copy of it
    void clear();
    size_t count(long key) const;
    bool empty() const;
    wxImageHistogram::iterator end() const; // not const iterator since we create a new copy of it
    size_t erase(long key);
    wxImageHistogram::iterator find(long key);
    //Insert_Result insert(const value_type& v);
    size_t size() const;
    //mapped_type& operator[](const key_type& key);
};

// ---------------------------------------------------------------------------
// wxQuantize

#include "wx/quantize.h"

#define wxQUANTIZE_INCLUDE_WINDOWS_COLOURS
#define wxQUANTIZE_RETURN_8BIT_DATA
#define wxQUANTIZE_FILL_DESTINATION_IMAGE

class wxQuantize : public wxObject
{
    // No constructor - all methods static

    // %override bool wxQuantize::Quantize(const wxImage& src, wxImage& dest, int desiredNoColours = 236, int flags = wxQUANTIZE_INCLUDE_WINDOWS_COLOURS|wxQUANTIZE_FILL_DESTINATION_IMAGE|wxQUANTIZE_RETURN_8BIT_DATA);
    // C++ Func: static bool Quantize(const wxImage& src, wxImage& dest, wxPalette** pPalette, int desiredNoColours = 236, unsigned char** eightBitData = 0, int flags = wxQUANTIZE_INCLUDE_WINDOWS_COLOURS|wxQUANTIZE_FILL_DESTINATION_IMAGE|wxQUANTIZE_RETURN_8BIT_DATA);
    static bool Quantize(const wxImage& src, wxImage& dest, int desiredNoColours = 236, int flags = wxQUANTIZE_INCLUDE_WINDOWS_COLOURS|wxQUANTIZE_FILL_DESTINATION_IMAGE|wxQUANTIZE_RETURN_8BIT_DATA);

    //static bool Quantize(const wxImage& src, wxImage& dest, int desiredNoColours = 236, unsigned char** eightBitData = 0, int flags = wxQUANTIZE_INCLUDE_WINDOWS_COLOURS|wxQUANTIZE_FILL_DESTINATION_IMAGE|wxQUANTIZE_RETURN_8BIT_DATA);
    //static void DoQuantize(unsigned w, unsigned h, unsigned char **in_rows, unsigned char **out_rows, unsigned char *palette, int desiredNoColours);
};

// ---------------------------------------------------------------------------
// wxImageHandler and derived classes

class %delete wxImageHandler : public wxObject
{
    // no constructor - abstract class

    wxString GetName() const;
    wxString GetExtension() const;
    int GetImageCount(wxInputStream& stream);
    long GetType() const;
    wxString GetMimeType() const;
    bool LoadFile(wxImage* image, wxInputStream& stream, bool verbose=true, int index=0);
    bool SaveFile(wxImage* image, wxOutputStream& stream);
    void SetName(const wxString& name);
    void SetExtension(const wxString& extension);
    void SetMimeType(const wxString& mimetype);
    !%wxchkver_2_9 || %wxcompat_2_8 void SetType(long type);
    %wxchkver_2_8 void SetType(wxBitmapType type);
};

// ---------------------------------------------------------------------------
// wxBMPHandler and friends in imagbmp.h

#include "wx/imagbmp.h"

enum
{
    wxBMP_24BPP,
    //wxBMP_16BPP,  - remmed out in wxWidgets
    wxBMP_8BPP,
    wxBMP_8BPP_GREY,
    wxBMP_8BPP_GRAY,
    wxBMP_8BPP_RED,
    wxBMP_8BPP_PALETTE,
    wxBMP_4BPP,
    wxBMP_1BPP,
    wxBMP_1BPP_BW
};

#define_wxstring wxIMAGE_OPTION_BMP_FORMAT wxT("wxBMP_FORMAT"); // wxString(wxT("wxBMP_FORMAT"));

class %delete wxBMPHandler : public wxImageHandler
{
    wxBMPHandler();
};

#if wxUSE_ICO_CUR

class %delete wxICOHandler : public wxBMPHandler
{
    wxICOHandler();
};

class %delete wxCURHandler : public wxICOHandler
{
    wxCURHandler();
};

class %delete wxANIHandler : public wxCURHandler
{
    wxANIHandler();
};

#endif // wxUSE_ICO_CUR

// ---------------------------------------------------------------------------
// wxIFFHandler and friends in imagiff.h

#include "wx/imagiff.h"

#if wxUSE_IFF

class %delete wxIFFHandler : public wxImageHandler
{
    wxIFFHandler();
};

#endif //wxUSE_IFF

// ---------------------------------------------------------------------------
// wxGIFHandler and friends in imaggif.h

#include "wx/imaggif.h"

#if wxUSE_GIF

class %delete wxGIFHandler : public wxImageHandler
{
    wxGIFHandler();
};

#endif //wxUSE_GIF

// ---------------------------------------------------------------------------
// wxJPEGHandler and friends in imagjpeg.h

#include "wx/imagjpeg.h"

#if wxUSE_LIBJPEG

class %delete wxJPEGHandler : public wxImageHandler
{
    wxJPEGHandler();
};

#endif //wxUSE_LIBJPEG

// ---------------------------------------------------------------------------
// wxPCXHandler and friends in imagpcx.h

#include "wx/imagpcx.h"

#if wxUSE_PCX

class %delete wxPCXHandler : public wxImageHandler
{
    wxPCXHandler();
};

#endif //wxUSE_PCX

// ---------------------------------------------------------------------------
// wxPNGHandler and friends in imagpng.h

#include "wx/imagpng.h"

#if wxUSE_LIBPNG

#define_wxstring wxIMAGE_OPTION_PNG_FORMAT    // wxT("PngFormat");
#define_wxstring wxIMAGE_OPTION_PNG_BITDEPTH  // wxT("PngBitDepth");

enum
{
    wxPNG_TYPE_COLOUR,
    wxPNG_TYPE_GREY,
    wxPNG_TYPE_GREY_RED
};

class %delete wxPNGHandler : public wxImageHandler
{
    wxPNGHandler();
};

#endif //wxUSE_LIBPNG

// ---------------------------------------------------------------------------
// wxPNMHandler and friends in imagpnm.h

#include "wx/imagpnm.h"

#if wxUSE_PNM

class %delete wxPNMHandler : public wxImageHandler
{
    wxPNMHandler();
};

#endif //wxUSE_PNM

// ---------------------------------------------------------------------------
// wxTIFFHandler and friends in imagtiff.h

#include "wx/imagtiff.h"

#if wxUSE_LIBTIFF

#define_wxstring wxIMAGE_OPTION_BITSPERSAMPLE   wxT("BitsPerSample");
#define_wxstring wxIMAGE_OPTION_SAMPLESPERPIXEL wxT("SamplesPerPixel");
#define_wxstring wxIMAGE_OPTION_COMPRESSION     wxT("Compression");
#define_wxstring wxIMAGE_OPTION_IMAGEDESCRIPTOR wxT("ImageDescriptor");

class %delete wxTIFFHandler : public wxImageHandler
{
    wxTIFFHandler();
};

#endif //wxUSE_LIBTIFF

// ---------------------------------------------------------------------------
// wxTGAHandler and friends in imagtga.h

#if %wxchkver_2_8 && wxUSE_TGA

#include "wx/imagtga.h"

class %delete wxTGAHandler : public wxImageHandler
{
    wxTGAHandler();
};

#endif // %wxchkver_2_8 && wxUSE_TGA

// ---------------------------------------------------------------------------
// wxXPMHandler and friends in imagxpm.h

#include "wx/imagxpm.h"

class %delete wxXPMHandler : public wxImageHandler
{
    wxXPMHandler();
};


#endif //wxLUA_USE_wxImage && wxUSE_IMAGE

// ---------------------------------------------------------------------------
// wxArtProvider and friends

#if wxLUA_USE_wxArtProvider

#include "wx/artprov.h"

//typedef wxString wxArtClient   Just treat these as wxStrings
//typedef wxString wxArtID

// ----------------------------------------------------------------------------
// Art clients
// ----------------------------------------------------------------------------

#if %wxchkver_2_9_0
#define_string wxART_TOOLBAR
#define_string wxART_MENU
#define_string wxART_FRAME_ICON

#define_string wxART_CMN_DIALOG
#define_string wxART_HELP_BROWSER
#define_string wxART_MESSAGE_BOX
#define_string wxART_BUTTON

#define_string wxART_OTHER
#endif

#if !%wxchkver_2_9_0
#define_wxstring wxART_TOOLBAR
#define_wxstring wxART_MENU
#define_wxstring wxART_FRAME_ICON

#define_wxstring wxART_CMN_DIALOG
#define_wxstring wxART_HELP_BROWSER
#define_wxstring wxART_MESSAGE_BOX
#define_wxstring wxART_BUTTON

#define_wxstring wxART_OTHER
#endif

// ----------------------------------------------------------------------------
// Art IDs
// ----------------------------------------------------------------------------

#if %wxchkver_2_9_0
#define_string wxART_ADD_BOOKMARK
#define_string wxART_DEL_BOOKMARK
#define_string wxART_HELP_SIDE_PANEL
#define_string wxART_HELP_SETTINGS
#define_string wxART_HELP_BOOK
#define_string wxART_HELP_FOLDER
#define_string wxART_HELP_PAGE
#define_string wxART_GO_BACK
#define_string wxART_GO_FORWARD
#define_string wxART_GO_UP
#define_string wxART_GO_DOWN
#define_string wxART_GO_TO_PARENT
#define_string wxART_GO_HOME
#define_string wxART_FILE_OPEN
#define_string wxART_FILE_SAVE
#define_string wxART_FILE_SAVE_AS
#define_string wxART_PRINT
#define_string wxART_HELP
#define_string wxART_TIP
#define_string wxART_REPORT_VIEW
#define_string wxART_LIST_VIEW
#define_string wxART_NEW_DIR
#define_string wxART_HARDDISK
#define_string wxART_FLOPPY
#define_string wxART_CDROM
#define_string wxART_REMOVABLE
#define_string wxART_FOLDER
#define_string wxART_FOLDER_OPEN
#define_string wxART_GO_DIR_UP
#define_string wxART_EXECUTABLE_FILE
#define_string wxART_NORMAL_FILE
#define_string wxART_TICK_MARK
#define_string wxART_CROSS_MARK
#define_string wxART_ERROR
#define_string wxART_QUESTION
#define_string wxART_WARNING
#define_string wxART_INFORMATION
#define_string wxART_MISSING_IMAGE
#define_string wxART_COPY
#define_string wxART_CUT
#define_string wxART_PASTE
#define_string wxART_DELETE
#define_string wxART_NEW

#define_string wxART_UNDO
#define_string wxART_REDO

#define_string wxART_QUIT

#define_string wxART_FIND
#define_string wxART_FIND_AND_REPLACE
#endif

#if !%wxchkver_2_9_0
#define_wxstring wxART_ADD_BOOKMARK
#define_wxstring wxART_DEL_BOOKMARK
#define_wxstring wxART_HELP_SIDE_PANEL
#define_wxstring wxART_HELP_SETTINGS
#define_wxstring wxART_HELP_BOOK
#define_wxstring wxART_HELP_FOLDER
#define_wxstring wxART_HELP_PAGE
#define_wxstring wxART_GO_BACK
#define_wxstring wxART_GO_FORWARD
#define_wxstring wxART_GO_UP
#define_wxstring wxART_GO_DOWN
#define_wxstring wxART_GO_TO_PARENT
#define_wxstring wxART_GO_HOME
#define_wxstring wxART_FILE_OPEN
#define_wxstring wxART_FILE_SAVE
#define_wxstring wxART_FILE_SAVE_AS
#define_wxstring wxART_PRINT
#define_wxstring wxART_HELP
#define_wxstring wxART_TIP
#define_wxstring wxART_REPORT_VIEW
#define_wxstring wxART_LIST_VIEW
#define_wxstring wxART_NEW_DIR
#define_wxstring wxART_HARDDISK
#define_wxstring wxART_FLOPPY
#define_wxstring wxART_CDROM
#define_wxstring wxART_REMOVABLE
#define_wxstring wxART_FOLDER
#define_wxstring wxART_FOLDER_OPEN
#define_wxstring wxART_GO_DIR_UP
#define_wxstring wxART_EXECUTABLE_FILE
#define_wxstring wxART_NORMAL_FILE
#define_wxstring wxART_TICK_MARK
#define_wxstring wxART_CROSS_MARK
#define_wxstring wxART_ERROR
#define_wxstring wxART_QUESTION
#define_wxstring wxART_WARNING
#define_wxstring wxART_INFORMATION
#define_wxstring wxART_MISSING_IMAGE
#define_wxstring wxART_COPY
#define_wxstring wxART_CUT
#define_wxstring wxART_PASTE
#define_wxstring wxART_DELETE
#define_wxstring wxART_NEW

#define_wxstring wxART_UNDO
#define_wxstring wxART_REDO

#define_wxstring wxART_QUIT

#define_wxstring wxART_FIND
#define_wxstring wxART_FIND_AND_REPLACE
#endif

class wxArtProvider : public wxObject
{
    // wxArtProvider() - abstract class

    #if %wxchkver_2_8
        static void Push(%ungc wxArtProvider *provider);
        !%wxchkver_2_9 || %wxcompat_2_8 static void Insert(%ungc wxArtProvider *provider);
        static bool Pop();
        static bool Remove(%gc wxArtProvider *provider); // FIXME - mem leak if not found
        static bool Delete(%ungc wxArtProvider *provider);
    #endif // %wxchkver_2_8

    static wxBitmap GetBitmap(const wxString& id, const wxString& client = wxART_OTHER, const wxSize& size = wxDefaultSize);
    static wxIcon GetIcon(const wxString& id, const wxString& client = wxART_OTHER, const wxSize& size = wxDefaultSize);
    static wxSize GetSizeHint(const wxString& client, bool platform_dependent = false);
    %wxchkver_3_1 static void RescaleBitmap(wxBitmap& bmp, const wxSize& sizeNeeded);
};

class %delete wxLuaArtProvider : public wxArtProvider
{
    // %override - the C++ function takes the wxLuaState as the first param
    wxLuaArtProvider();

    // virtual function that you can override in Lua.
    virtual wxSize DoGetSizeHint(const wxString& client); // { return GetSizeHint(client, true); }

    // virtual function that you can override in Lua.

    // Derived classes must override this method to create requested
    // art resource. This method is called only once per instance's
    // lifetime for each requested wxArtID.
    virtual wxBitmap CreateBitmap(const wxString& id, const wxString& client, const wxSize& size);
};

#endif //wxLUA_USE_wxArtProvider
