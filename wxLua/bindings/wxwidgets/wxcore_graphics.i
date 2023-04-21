// ===========================================================================
// Purpose:     GDI Graphics classes...
// Author:      Konstantin. S Matveyev
// Created:     20/08/2018
// License:     wxWidgets licence
// ===========================================================================

#include "wx/dcgraph.h"
#include "wx/graphics.h"

#if wxUSE_GRAPHICS_CONTEXT

#include "wx/affinematrix2d.h"
#include "wx/geometry.h"
#include "wx/colour.h"
#include "wx/dynarray.h"
#include "wx/font.h"
#include "wx/image.h"
#include "wx/pen.h"
#include "wx/vector.h"

enum wxAntialiasMode
{
    wxANTIALIAS_NONE, // should be 0
    wxANTIALIAS_DEFAULT
};

enum wxInterpolationQuality
{
    // default interpolation
    wxINTERPOLATION_DEFAULT,
    // no interpolation
    wxINTERPOLATION_NONE,
    // fast interpolation, suited for interactivity
    wxINTERPOLATION_FAST,
    // better quality
    wxINTERPOLATION_GOOD,
    // best quality, not suited for interactivity
    wxINTERPOLATION_BEST
};

enum wxCompositionMode
{
    // R = Result, S = Source, D = Destination, premultiplied with alpha
    // Ra, Sa, Da their alpha components

    // classic Porter-Duff compositions
    // http://keithp.com/~keithp/porterduff/p253-porter.pdf

    wxCOMPOSITION_INVALID = -1, /* indicates invalid/unsupported mode */
    wxCOMPOSITION_CLEAR, /* R = 0 */
    wxCOMPOSITION_SOURCE, /* R = S */
    wxCOMPOSITION_OVER, /* R = S + D*(1 - Sa) */
    wxCOMPOSITION_IN, /* R = S*Da */
    wxCOMPOSITION_OUT, /* R = S*(1 - Da) */
    wxCOMPOSITION_ATOP, /* R = S*Da + D*(1 - Sa) */

    wxCOMPOSITION_DEST, /* R = D, essentially a noop */
    wxCOMPOSITION_DEST_OVER, /* R = S*(1 - Da) + D */
    wxCOMPOSITION_DEST_IN, /* R = D*Sa */
    wxCOMPOSITION_DEST_OUT, /* R = D*(1 - Sa) */
    wxCOMPOSITION_DEST_ATOP, /* R = S*(1 - Da) + D*Sa */
    wxCOMPOSITION_XOR, /* R = S*(1 - Da) + D*(1 - Sa) */

    // mathematical compositions
    wxCOMPOSITION_ADD /* R = S + D */
};

class %delete wxGraphicsObject : public wxObject
{
    wxGraphicsObject();
    wxGraphicsObject( wxGraphicsRenderer* renderer );

    bool IsNull() const;

    // returns the renderer that was used to create this instance, or NULL if it has not been initialized yet
    wxGraphicsRenderer* GetRenderer() const;
//    wxGraphicsObjectRefData* GetGraphicsData() const;
};


#if %wxchkver_3_1_1

enum wxGradientType
{
    wxGRADIENT_NONE,
    wxGRADIENT_LINEAR,
    wxGRADIENT_RADIAL
};

// ----------------------------------------------------------------------------
// wxGraphicsPenInfo describes a wxGraphicsPen
// ----------------------------------------------------------------------------

class %delete wxGraphicsPenInfo// : public wxPenInfoBase<wxGraphicsPenInfo>
{
    wxGraphicsPenInfo();
    wxGraphicsPenInfo(const wxColour& colour,// = wxColour(),
                      wxDouble width = 1.0,
                      wxPenStyle style = wxPENSTYLE_SOLID);

    // Setters

    wxGraphicsPenInfo& Width(wxDouble width);
    wxGraphicsPenInfo& Colour(const wxColour& colour);
    wxGraphicsPenInfo& Style(wxPenStyle style);
    wxGraphicsPenInfo& Stipple(const wxBitmap& stipple);
    // %override wxGraphicsPenInfo& Dashes(Lua-table-of-integers);
    // C++ Func: wxGraphicsPenInfo& Dashes(int nb_dashes, const wxDash *dash);
    wxGraphicsPenInfo& Dashes();

    wxGraphicsPenInfo& Join(wxPenJoin join);
    wxGraphicsPenInfo& Cap(wxPenCap cap);

    wxGraphicsPenInfo& LinearGradient(wxDouble x1, wxDouble y1, wxDouble x2, wxDouble y2,
                   const wxColour& c1, const wxColour& c2,
                   const wxGraphicsMatrix& matrix = wxNullGraphicsMatrix);
    wxGraphicsPenInfo& LinearGradient(wxDouble x1, wxDouble y1, wxDouble x2, wxDouble y2,
                   const wxGraphicsGradientStops& stops,
                   const wxGraphicsMatrix& matrix = wxNullGraphicsMatrix);
    wxGraphicsPenInfo& RadialGradient(wxDouble startX, wxDouble startY,
                   wxDouble endX, wxDouble endY, wxDouble radius,
                   const wxColour& oColor, const wxColour& cColor,
                   const wxGraphicsMatrix& matrix = wxNullGraphicsMatrix);
    wxGraphicsPenInfo& RadialGradient(wxDouble startX, wxDouble startY,
                   wxDouble endX, wxDouble endY,
                   wxDouble radius, const wxGraphicsGradientStops& stops,
                   const wxGraphicsMatrix& matrix = wxNullGraphicsMatrix);
                   


    // Accessors

    wxDouble GetWidth() const;
    wxColour GetColour() const;
    wxBitmap GetStipple() const;
    wxPenStyle GetStyle() const;
    wxPenJoin GetJoin() const;
    wxPenCap GetCap() const;
    // %override [table-of-integers] wxPen::GetDashes();
    // C++ Func: int GetDashes(wxDash** ptr) const;
    void GetDashes();
    int GetDashCount() const;
//    wxDash* GetDash() const;  //  Maybe we do not need this

    wxGradientType GetGradientType() const;
    wxDouble GetX1() const;
    wxDouble GetY1() const;
    wxDouble GetX2() const;
    wxDouble GetY2() const;
    wxDouble GetStartX() const;
    wxDouble GetStartY() const;
    wxDouble GetEndX() const;
    wxDouble GetEndY() const;
    wxDouble GetRadius() const;
    const wxGraphicsGradientStops& GetStops() const;
    const wxGraphicsMatrix& GetMatrix() const;
};

#endif // !%wxchkver_3_1_1

class %delete wxGraphicsPen : public wxGraphicsObject
{
    wxGraphicsPen();
};

// extern WXDLLIMPEXP_DATA_CORE(wxGraphicsPen) wxNullGraphicsPen;

class %delete wxGraphicsBrush : public wxGraphicsObject
{
    wxGraphicsBrush();
};

// extern WXDLLIMPEXP_DATA_CORE(wxGraphicsBrush) wxNullGraphicsBrush;

class %delete wxGraphicsFont : public wxGraphicsObject
{
    wxGraphicsFont();
};

// extern WXDLLIMPEXP_DATA_CORE(wxGraphicsFont) wxNullGraphicsFont;

class %delete wxGraphicsBitmap : public wxGraphicsObject
{
    wxGraphicsBitmap();

    // Convert bitmap to wxImage: this is more efficient than converting to
    // wxBitmap first and then to wxImage and also works without X server
    // connection under Unix that wxBitmap requires.
#if wxUSE_IMAGE
    wxImage ConvertToImage() const;
#endif // wxUSE_IMAGE

    void* GetNativeBitmap() const;

//    const wxGraphicsBitmapData* GetBitmapData() const;
//    wxGraphicsBitmapData* GetBitmapData();
};

// extern WXDLLIMPEXP_DATA_CORE(wxGraphicsBitmap) wxNullGraphicsBitmap;

class %delete wxGraphicsMatrix : public wxGraphicsObject
{
    wxGraphicsMatrix();

    // concatenates the matrix
    virtual void Concat( const wxGraphicsMatrix *t );
    void Concat( const wxGraphicsMatrix &t );

    // sets the matrix to the respective values
    virtual void Set(wxDouble a=1.0, wxDouble b=0.0, wxDouble c=0.0, wxDouble d=1.0,
        wxDouble tx=0.0, wxDouble ty=0.0);

    // gets the component valuess of the matrix
    virtual void Get(wxDouble* a=NULL, wxDouble* b=NULL,  wxDouble* c=NULL,
                     wxDouble* d=NULL, wxDouble* tx=NULL, wxDouble* ty=NULL) const;

    // makes this the inverse matrix
    virtual void Invert();

    // returns true if the elements of the transformation matrix are equal ?
    virtual bool IsEqual( const wxGraphicsMatrix* t) const;
    bool IsEqual( const wxGraphicsMatrix& t) const;

    // return true if this is the identity matrix
    virtual bool IsIdentity() const;

    //
    // transformation
    //

    // add the translation to this matrix
    virtual void Translate( wxDouble dx , wxDouble dy );

    // add the scale to this matrix
    virtual void Scale( wxDouble xScale , wxDouble yScale );

    // add the rotation to this matrix (radians)
    virtual void Rotate( wxDouble angle );

    //
    // apply the transforms
    //

    // applies that matrix to the point
    virtual void TransformPoint( wxDouble *x, wxDouble *y ) const;

    // applies the matrix except for translations
    virtual void TransformDistance( wxDouble *dx, wxDouble *dy ) const;

    // returns the native representation
    virtual void * GetNativeMatrix() const;

//    const wxGraphicsMatrixData* GetMatrixData() const;
//    wxGraphicsMatrixData* GetMatrixData();
};

// extern WXDLLIMPEXP_DATA_CORE(wxGraphicsMatrix) wxNullGraphicsMatrix;

class %delete wxGraphicsPath : public wxGraphicsObject
{
    wxGraphicsPath();

    //
    // These are the path primitives from which everything else can be constructed
    //

    // begins a new subpath at (x,y)
    virtual void MoveToPoint( wxDouble x, wxDouble y );
    void MoveToPoint( const wxPoint2DDouble& p);

    // adds a straight line from the current point to (x,y)
    virtual void AddLineToPoint( wxDouble x, wxDouble y );
    void AddLineToPoint( const wxPoint2DDouble& p);

    // adds a cubic Bezier curve from the current point, using two control points and an end point
    virtual void AddCurveToPoint( wxDouble cx1, wxDouble cy1, wxDouble cx2, wxDouble cy2, wxDouble x, wxDouble y );
    void AddCurveToPoint( const wxPoint2DDouble& c1, const wxPoint2DDouble& c2, const wxPoint2DDouble& e);

    // adds another path
    virtual void AddPath( const wxGraphicsPath& path );

    // closes the current sub-path
    virtual void CloseSubpath();

    // gets the last point of the current path, (0,0) if not yet set
    virtual void GetCurrentPoint( wxDouble* x, wxDouble* y) const;
    wxPoint2DDouble GetCurrentPoint() const;

    // adds an arc of a circle centering at (x,y) with radius (r) from startAngle to endAngle
    virtual void AddArc( wxDouble x, wxDouble y, wxDouble r, wxDouble startAngle, wxDouble endAngle, bool clockwise );
    void AddArc( const wxPoint2DDouble& c, wxDouble r, wxDouble startAngle, wxDouble endAngle, bool clockwise);

    //
    // These are convenience functions which - if not available natively will be assembled
    // using the primitives from above
    //

    // adds a quadratic Bezier curve from the current point, using a control point and an end point
    virtual void AddQuadCurveToPoint( wxDouble cx, wxDouble cy, wxDouble x, wxDouble y );

    // appends a rectangle as a new closed subpath
    virtual void AddRectangle( wxDouble x, wxDouble y, wxDouble w, wxDouble h );

    // appends an ellipsis as a new closed subpath fitting the passed rectangle
    virtual void AddCircle( wxDouble x, wxDouble y, wxDouble r );

    // appends a an arc to two tangents connecting (current) to (x1,y1) and (x1,y1) to (x2,y2), also a straight line from (current) to (x1,y1)
    virtual void AddArcToPoint( wxDouble x1, wxDouble y1 , wxDouble x2, wxDouble y2, wxDouble r );

    // appends an ellipse
    virtual void AddEllipse( wxDouble x, wxDouble y, wxDouble w, wxDouble h);

    // appends a rounded rectangle
    virtual void AddRoundedRectangle( wxDouble x, wxDouble y, wxDouble w, wxDouble h, wxDouble radius);

    // returns the native path
    virtual void * GetNativePath() const;

    // give the native path returned by GetNativePath() back (there might be some deallocations necessary)
    virtual void UnGetNativePath(void *p) const;

    // transforms each point of this path by the matrix
    virtual void Transform( const wxGraphicsMatrix& matrix );

    // gets the bounding box enclosing all points (possibly including control points)
    virtual void GetBox(wxDouble *x, wxDouble *y, wxDouble *w, wxDouble *h) const;
    wxRect2DDouble GetBox() const;

    virtual bool Contains( wxDouble x, wxDouble y, wxPolygonFillMode fillStyle = wxODDEVEN_RULE) const;
    bool Contains( const wxPoint2DDouble& c, wxPolygonFillMode fillStyle = wxODDEVEN_RULE) const;

//    const wxGraphicsPathData* GetPathData() const;
//    wxGraphicsPathData* GetPathData();
};

// extern WXDLLIMPEXP_DATA_CORE(wxGraphicsPath) wxNullGraphicsPath;


// Describes a single gradient stop.
class %delete wxGraphicsGradientStop
{
    wxGraphicsGradientStop(wxColour col = wxTransparentColour, float pos = 0.0);

    // default copy ctor, assignment operator and dtor are ok

    const wxColour& GetColour() const;
    void SetColour(const wxColour& col);

    float GetPosition() const;
    void SetPosition(float pos);
};

// A collection of gradient stops ordered by their positions (from lowest to
// highest). The first stop (index 0, position 0.0) is always the starting
// colour and the last one (index GetCount() - 1, position 1.0) is the end
// colour.
class %delete wxGraphicsGradientStops
{
    wxGraphicsGradientStops(wxColour startCol = wxTransparentColour,
                            wxColour endCol = wxTransparentColour);

    // default copy ctor, assignment operator and dtor are ok for this class


    // Add a stop in correct order.
    void Add(const wxGraphicsGradientStop& stop);
    void Add(wxColour col, float pos);

    // Get the number of stops.
    size_t GetCount() const;

    // Return the stop at the given index (which must be valid).
//    wxGraphicsGradientStop Item(unsigned n) const;

    // Get/set start and end colours.
    void SetStartColour(wxColour col);
    wxColour GetStartColour() const;
    void SetEndColour(wxColour col);
    wxColour GetEndColour() const;
};

class %delete wxGraphicsContext : public wxGraphicsObject
{
    static %gc wxGraphicsContext* Create( const wxWindowDC& dc);
    static %gc wxGraphicsContext* Create( const wxMemoryDC& dc);
#if wxUSE_PRINTING_ARCHITECTURE
    static %gc wxGraphicsContext* Create( const wxPrinterDC& dc);
#endif

    // Create a context from a DC of unknown type, if supported, returns NULL otherwise
    %wxchkver_3_1_1 static %gc wxGraphicsContext* CreateFromUnknownDC(const wxDC& dc);
    static %gc wxGraphicsContext* CreateFromNative( void * context );
    static %gc wxGraphicsContext* CreateFromNativeWindow( void * window );
    static %gc wxGraphicsContext* Create( wxWindow* window );

#if wxUSE_IMAGE
    // Create a context for drawing onto a wxImage. The image life time must be
    // greater than that of the context itself as when the context is destroyed
    // it will copy its contents to the specified image.
    static %gc wxGraphicsContext* Create(wxImage& image);
#endif // wxUSE_IMAGE

    // create a context that can be used for measuring texts only, no drawing allowed
    static %gc wxGraphicsContext* Create();

    // begin a new document (relevant only for printing / pdf etc) if there is a progress dialog, message will be shown
    virtual bool StartDoc( const wxString& message );

    // done with that document (relevant only for printing / pdf etc)
    virtual void EndDoc();

    // opens a new page  (relevant only for printing / pdf etc) with the given size in points
    // (if both are null the default page size will be used)
    virtual void StartPage( wxDouble width = 0, wxDouble height = 0 );

    // ends the current page  (relevant only for printing / pdf etc)
    virtual void EndPage();

    // make sure that the current content of this context is immediately visible
    virtual void Flush();

    wxGraphicsPath CreatePath() const;

    wxGraphicsPen CreatePen(const wxPen& pen) const;

    %wxchkver_3_1_1 wxGraphicsPen CreatePen(const wxGraphicsPenInfo& info) const;

    virtual wxGraphicsBrush CreateBrush(const wxBrush& brush ) const;

    // sets the brush to a linear gradient, starting at (x1,y1) and ending at
    // (x2,y2) with the given boundary colours or the specified stops
    wxGraphicsBrush CreateLinearGradientBrush(wxDouble x1, wxDouble y1,
                                              wxDouble x2, wxDouble y2,
                                              const wxColour& c1, const wxColour& c2) const;
    wxGraphicsBrush CreateLinearGradientBrush(wxDouble x1, wxDouble y1,
                                              wxDouble x2, wxDouble y2,
                                              const wxGraphicsGradientStops& stops) const;

    // sets the brush to a radial gradient originating at (xo,yc) and ending
    // on a circle around (xc,yc) with the given radius; the colours may be
    // specified by just the two extremes or the full array of gradient stops
    wxGraphicsBrush CreateRadialGradientBrush(wxDouble xo, wxDouble yo,
                                              wxDouble xc, wxDouble yc, wxDouble radius,
                                              const wxColour& oColor, const wxColour& cColor) const;

    wxGraphicsBrush CreateRadialGradientBrush(wxDouble xo, wxDouble yo,
                                              wxDouble xc, wxDouble yc, wxDouble radius,
                                              const wxGraphicsGradientStops& stops) const;

    // creates a font
    virtual wxGraphicsFont CreateFont( const wxFont &font) const;// , const wxColour &col = *wxBLACK ) const;
    virtual wxGraphicsFont CreateFont( const wxFont &font, const wxColour &col) const;
    virtual wxGraphicsFont CreateFont(double sizeInPixels,
                                      const wxString& facename,
                                      int flags = wxFONTFLAG_DEFAULT) const;
//                                      const wxColour& col = *wxBLACK) const;

    // create a native bitmap representation
    virtual wxGraphicsBitmap CreateBitmap( const wxBitmap &bitmap ) const;
#if wxUSE_IMAGE
    wxGraphicsBitmap CreateBitmapFromImage(const wxImage& image) const;
#endif // wxUSE_IMAGE

    // create a native bitmap representation
    virtual wxGraphicsBitmap CreateSubBitmap( const wxGraphicsBitmap &bitmap, wxDouble x, wxDouble y, wxDouble w, wxDouble h  ) const;

    // create a 'native' matrix corresponding to these values
    virtual wxGraphicsMatrix CreateMatrix( wxDouble a=1.0, wxDouble b=0.0,
                                           wxDouble c=0.0, wxDouble d=1.0,
                                           wxDouble tx=0.0, wxDouble ty=0.0) const;

//    wxGraphicsMatrix CreateMatrix( const wxAffineMatrix2DBase& mat ) const;

    // push the current state of the context, ie the transformation matrix on a stack
    virtual void PushState();// = 0;

    // pops a stored state from the stack
    virtual void PopState();// = 0;

    // clips drawings to the region intersected with the current clipping region
    virtual void Clip( const wxRegion &region );// = 0;

    // clips drawings to the rect intersected with the current clipping region
    virtual void Clip( wxDouble x, wxDouble y, wxDouble w, wxDouble h );// = 0;

    // resets the clipping to original extent
    virtual void ResetClip();// = 0;

    // returns bounding box of the clipping region
    %wxchkver_3_1_1 virtual void GetClipBox(wxDouble* x, wxDouble* y, wxDouble* w, wxDouble* h);// = 0;

    // returns the native context
    virtual void * GetNativeContext();// = 0;

    // returns the current shape antialiasing mode
    virtual wxAntialiasMode GetAntialiasMode() const;

    // sets the antialiasing mode, returns true if it supported
    virtual bool SetAntialiasMode(wxAntialiasMode antialias);// = 0;

    // returns the current interpolation quality
    virtual wxInterpolationQuality GetInterpolationQuality() const;

    // sets the interpolation quality, returns true if it supported
    virtual bool SetInterpolationQuality(wxInterpolationQuality interpolation);// = 0;

    // returns the current compositing operator
    virtual wxCompositionMode GetCompositionMode() const;

    // sets the compositing operator, returns true if it supported
    virtual bool SetCompositionMode(wxCompositionMode op);// = 0;

    // returns the size of the graphics context in device coordinates
    void GetSize(wxDouble* width, wxDouble* height) const;

    // returns the resolution of the graphics context in device points per inch
    virtual void GetDPI( wxDouble* dpiX, wxDouble* dpiY);

#if 0
    // sets the current alpha on this context
    virtual void SetAlpha( wxDouble alpha );

    // returns the alpha on this context
    virtual wxDouble GetAlpha() const;
#endif

    // all rendering is done into a fully transparent temporary context
    virtual void BeginLayer(wxDouble opacity);// = 0;

    // composites back the drawings into the context with the opacity given at
    // the BeginLayer call
    virtual void EndLayer();// = 0;

    //
    // transformation : changes the current transformation matrix CTM of the context
    //

    // translate
    virtual void Translate( wxDouble dx , wxDouble dy );// = 0;

    // scale
    virtual void Scale( wxDouble xScale , wxDouble yScale );// = 0;

    // rotate (radians)
    virtual void Rotate( wxDouble angle );// = 0;

    // concatenates this transform with the current transform of this context
    virtual void ConcatTransform( const wxGraphicsMatrix& matrix );// = 0;

    // sets the transform of this context
    virtual void SetTransform( const wxGraphicsMatrix& matrix );// = 0;

    // gets the matrix of this context
    virtual wxGraphicsMatrix GetTransform() const;// = 0;
    //
    // setting the paint
    //

    // sets the pen
    virtual void SetPen( const wxGraphicsPen& pen );

    void SetPen( const wxPen& pen );

    // sets the brush for filling
    virtual void SetBrush( const wxGraphicsBrush& brush );

    void SetBrush( const wxBrush& brush );

    // sets the font
    virtual void SetFont( const wxGraphicsFont& font );

    void SetFont( const wxFont& font, const wxColour& colour );


    // strokes along a path with the current pen
    virtual void StrokePath( const wxGraphicsPath& path );// = 0;

    // fills a path with the current brush
    virtual void FillPath( const wxGraphicsPath& path, wxPolygonFillMode fillStyle = wxODDEVEN_RULE );// = 0;

    // draws a path by first filling and then stroking
    virtual void DrawPath( const wxGraphicsPath& path, wxPolygonFillMode fillStyle = wxODDEVEN_RULE );

    // paints a transparent rectangle (only useful for bitmaps or windows)
    %wxchkver_3_1_1 virtual void ClearRectangle(wxDouble x, wxDouble y, wxDouble w, wxDouble h);

    //
    // text
    //

    void DrawText( const wxString &str, wxDouble x, wxDouble y );

    void DrawText( const wxString &str, wxDouble x, wxDouble y, wxDouble angle );

    void DrawText( const wxString &str, wxDouble x, wxDouble y,
                   const wxGraphicsBrush& backgroundBrush );

    void DrawText( const wxString &str, wxDouble x, wxDouble y,
                   wxDouble angle, const wxGraphicsBrush& backgroundBrush );

    // %override [wxDouble width, wxDouble height, wxDouble descent, wxDouble externalLeading] int GetTextExtent(const wxString& string;
    void GetTextExtent(const wxString& string);

    virtual void GetPartialTextExtents(const wxString& text, wxArrayDouble& widths) const;// = 0;

    //
    // image support
    //

    virtual void DrawBitmap( const wxGraphicsBitmap &bmp, wxDouble x, wxDouble y, wxDouble w, wxDouble h );// = 0;

    virtual void DrawBitmap( const wxBitmap &bmp, wxDouble x, wxDouble y, wxDouble w, wxDouble h );// = 0;

    virtual void DrawIcon( const wxIcon &icon, wxDouble x, wxDouble y, wxDouble w, wxDouble h );// = 0;

    //
    // convenience methods
    //

    // strokes a single line
    virtual void StrokeLine( wxDouble x1, wxDouble y1, wxDouble x2, wxDouble y2);

    // stroke lines connecting each of the points
    // virtual void StrokeLines( size_t n, const wxPoint2DDouble *points);
    // Provide a Lua Table of {{1,2},{3,4},...}, {{x=1,y=2},{x=3,y=4},...}, or {wx.wxPoint2DDouble(1,2),wx.wxPoint2DDouble(3,4),...}
    virtual void StrokeLines( wxPoint2DDoubleArray_FromLuaTable points );

    // stroke disconnected lines from begin to end points
    // virtual void StrokeLines( size_t n, const wxPoint2DDouble *beginPoints, const wxPoint2DDouble *endPoints);
    // Provide a Lua Table of {{1,2},{3,4},...}, {{x=1,y=2},{x=3,y=4},...}, or {wx.wxPoint2DDouble(1,2),wx.wxPoint2DDouble(3,4),...}
    // Note: We need an override here, because the C++ API accepts only one 'n',
    //  both for beginPoints and endPoints.
    virtual void StrokeLines( wxPoint2DDoubleArray_FromLuaTable beginPoints, wxPoint2DDoubleArray_FromLuaTable endPoints );

    // draws a polygon
    // virtual void DrawLines( size_t n, const wxPoint2DDouble *points, wxPolygonFillMode fillStyle = wxODDEVEN_RULE );
    // Provide a Lua Table of {{1,2},{3,4},...}, {{x=1,y=2},{x=3,y=4},...}, or {wx.wxPoint2DDouble(1,2),wx.wxPoint2DDouble(3,4),...}
    virtual void DrawLines(wxPoint2DDoubleArray_FromLuaTable points, wxPolygonFillMode fillStyle = wxODDEVEN_RULE );

    // draws a rectangle
    virtual void DrawRectangle( wxDouble x, wxDouble y, wxDouble w, wxDouble h);

    // draws an ellipse
    virtual void DrawEllipse( wxDouble x, wxDouble y, wxDouble w, wxDouble h);

    // draws a rounded rectangle
    virtual void DrawRoundedRectangle( wxDouble x, wxDouble y, wxDouble w, wxDouble h, wxDouble radius);

     // wrappers using wxPoint2DDouble TODO

    // helper to determine if a 0.5 offset should be applied for the drawing operation
    virtual bool ShouldOffset() const;

    // indicates whether the context should try to offset for pixel boundaries, this only makes sense on
    // bitmap devices like screen, by default this is turned off
    virtual void EnableOffset(bool enable = true);

    void DisableOffset();
    bool OffsetEnabled();
};

//
// The graphics renderer is the instance corresponding to the rendering engine used, eg there is ONE core graphics renderer
// instance on OSX. This instance is pointed back to by all objects created by it. Therefore you can create eg additional
// paths at any point from a given matrix etc.
//

class %delete wxGraphicsRenderer : public wxObject
{
//    wxGraphicsRenderer();

    static wxGraphicsRenderer* GetDefaultRenderer();

    static wxGraphicsRenderer* GetCairoRenderer();

//#ifdef __WXMSW__
//#if wxUSE_GRAPHICS_GDIPLUS
//    static wxGraphicsRenderer* GetGDIPlusRenderer();
//#endif
//
//#if wxUSE_GRAPHICS_DIRECT2D
//    static wxGraphicsRenderer* GetDirect2DRenderer();
//#endif
//#endif

    // Context

    virtual %gc wxGraphicsContext* CreateContext( const wxWindowDC& dc);// = 0;
    virtual %gc wxGraphicsContext* CreateContext( const wxMemoryDC& dc);// = 0;
#if wxUSE_PRINTING_ARCHITECTURE
    virtual %gc wxGraphicsContext* CreateContext( const wxPrinterDC& dc);// = 0;
#endif
//#ifdef __WXMSW__
//#if wxUSE_ENH_METAFILE
//    virtual wxGraphicsContext * CreateContext( const wxEnhMetaFileDC& dc);// = 0;
//#endif
//#endif
//
//    virtual wxGraphicsContext * CreateContextFromNativeContext( void * context );// = 0;
//
//    virtual wxGraphicsContext * CreateContextFromNativeWindow( void * window );// = 0;
//
//#ifdef __WXMSW__
//    virtual wxGraphicsContext * CreateContextFromNativeHDC(WXHDC dc);// = 0;
//#endif
//
//    virtual wxGraphicsContext * CreateContext( wxWindow* window );// = 0;
//
#if wxUSE_IMAGE
    virtual %gc wxGraphicsContext* CreateContextFromImage(wxImage& image);// = 0;
#endif // wxUSE_IMAGE

    // create a context that can be used for measuring texts only, no drawing allowed
    virtual %gc wxGraphicsContext* CreateMeasuringContext();// = 0;

    // Path

    virtual wxGraphicsPath CreatePath();// = 0;

    // Matrix

    virtual wxGraphicsMatrix CreateMatrix( wxDouble a=1.0, wxDouble b=0.0, wxDouble c=0.0, wxDouble d=1.0,
        wxDouble tx=0.0, wxDouble ty=0.0);// = 0;

    // Paints

    %wxchkver_3_1_1 virtual wxGraphicsPen CreatePen(const wxGraphicsPenInfo& info);// = 0;

    virtual wxGraphicsBrush CreateBrush(const wxBrush& brush );// = 0;

    // Gradient brush creation functions may not honour all the stops specified
    // stops and use just its boundary colours (this is currently the case
    // under OS X)
    virtual wxGraphicsBrush CreateLinearGradientBrush(wxDouble x1, wxDouble y1,
                                                      wxDouble x2, wxDouble y2,
                                                      const wxGraphicsGradientStops& stops);// = 0;

    virtual wxGraphicsBrush CreateRadialGradientBrush(wxDouble xo, wxDouble yo,
                                                      wxDouble xc, wxDouble yc,
                                                      wxDouble radius,
                                                      const wxGraphicsGradientStops& stops);// = 0;

    // sets the font
//    virtual wxGraphicsFont CreateFont( const wxFont &font , const wxColour &col = *wxBLACK );// = 0;
//    virtual wxGraphicsFont CreateFont(double sizeInPixels,
//                                      const wxString& facename,
//                                      int flags = wxFONTFLAG_DEFAULT,
//                                      const wxColour& col = *wxBLACK);// = 0;

    // create a native bitmap representation
    virtual wxGraphicsBitmap CreateBitmap( const wxBitmap &bitmap );// = 0;
#if wxUSE_IMAGE
    virtual wxGraphicsBitmap CreateBitmapFromImage(const wxImage& image);// = 0;
    virtual wxImage CreateImageFromBitmap(const wxGraphicsBitmap& bmp);// = 0;
#endif // wxUSE_IMAGE

    // create a graphics bitmap from a native bitmap
    virtual wxGraphicsBitmap CreateBitmapFromNativeBitmap( void* bitmap );// = 0;

    // create a subimage from a native image representation
    virtual wxGraphicsBitmap CreateSubBitmap( const wxGraphicsBitmap &bitmap, wxDouble x, wxDouble y, wxDouble w, wxDouble h  );// = 0;

    %wxchkver_3_1_0 virtual wxString GetName() const;// = 0;
    %wxchkver_3_1_0 virtual void GetVersion(int* major, int* minor = NULL, int* micro = NULL) const;// = 0;
};

class %delete wxGCDC: public wxDC
{
    wxGCDC( const wxWindowDC& dc );
    wxGCDC( const wxMemoryDC& dc );
#if wxUSE_PRINTING_ARCHITECTURE
    wxGCDC( const wxPrinterDC& dc );
#endif
//#if defined(__WXMSW__) && wxUSE_ENH_METAFILE
//    wxGCDC( const wxEnhMetaFileDC& dc );
//#endif
    wxGCDC(wxGraphicsContext* context);
    wxGCDC();

//#ifdef __WXMSW__
//    // override wxDC virtual functions to provide access to HDC associated with
//    // this Graphics object (implemented in src/msw/graphics.cpp)
//    virtual WXHDC AcquireHDC() wxOVERRIDE;
//    virtual void ReleaseHDC(WXHDC hdc) wxOVERRIDE;
//#endif // __WXMSW__
};

#endif // wxUSE_GRAPHICS_CONTEXT
