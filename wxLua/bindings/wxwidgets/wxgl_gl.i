// ===========================================================================
// Purpose:     wxGL library
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

//#if wxUSE_OPENGL // FIXME ? Is it probably enough to test for wxUSE_GLCANVAS

// ---------------------------------------------------------------------------
// wxGLCanvas

#if wxLUA_USE_wxGLCanvas && wxUSE_GLCANVAS

// FIXME : Need to wrap wxGLApp?

#include "wx/glcanvas.h"

enum
{
    WX_GL_RGBA,
    WX_GL_BUFFER_SIZE,
    WX_GL_LEVEL,
    WX_GL_DOUBLEBUFFER,
    WX_GL_STEREO,
    WX_GL_AUX_BUFFERS,
    WX_GL_MIN_RED,
    WX_GL_MIN_GREEN,
    WX_GL_MIN_BLUE,
    WX_GL_MIN_ALPHA,
    WX_GL_DEPTH_SIZE,
    WX_GL_STENCIL_SIZE,
    WX_GL_MIN_ACCUM_RED,
    WX_GL_MIN_ACCUM_GREEN,
    WX_GL_MIN_ACCUM_BLUE,
    WX_GL_MIN_ACCUM_ALPHA
};

class wxGLCanvas : public wxWindow
{
#if !%wxchkver_3_0
    wxGLCanvas(wxWindow* parent, wxWindowID id = wxID_ANY, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style=0, const wxString& name="GLCanvas", int attribList[] = 0, const wxPalette& palette = wxNullPalette);
    wxGLCanvas(wxWindow* parent, wxGLContext* sharedContext, wxWindowID id = -1, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style=0, const wxString& name="GLCanvas", int attribList[] = 0, const wxPalette& palette = wxNullPalette);
    wxGLCanvas(wxWindow* parent, wxGLCanvas* sharedCanvas, wxWindowID id = -1, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style=0, const wxString& name="GLCanvas", int attribList[] = 0, const wxPalette& palette = wxNullPalette);
    !%mac wxGLCanvas(wxWindow* parent, wxWindowID id = wxID_ANY, int attribList[] = 0, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style=0, const wxString& name="GLCanvas", const wxPalette& palette = wxNullPalette);
#endif

#if %wxchkver_3_0
    !%mac wxGLCanvas(wxWindow* parent, wxWindowID id = wxID_ANY, int attribList[] = 0, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style=0, const wxString& name="GLCanvas", const wxPalette& palette = wxNullPalette);
#endif

#if %wxchkver_3_1
    static bool IsDisplaySupported(const wxGLAttributes& dispAttrs);
    static bool IsDisplaySupported(const int* attribList);
    static bool IsExtensionSupported(const char *extension);
#endif

    !%wxchkver_3_1_1 && %mac void SetCurrent();
    %wxchkver_2_8 && !%wxchkver_3_1_1 && !%mac void SetCurrent(const wxGLContext& RC) const;

    %wxchkver_3_1_1 bool SetCurrent(const wxGLContext& context) const;

    void SetColour(const wxString& colour);
    void SwapBuffers();
};

#if %wxchkver_3_1
class wxGLAttribsBase
{
public:
    wxGLAttribsBase();

    void AddAttribute(int attribute);
    void AddAttribBits(int searchVal, int combineVal);
    void SetNeedsARB(bool needsARB = true);
    void Reset();

    const int* GetGLAttrs() const;
    int GetSize();
    bool NeedsARB() const;
};

class wxGLAttributes : public wxGLAttribsBase
{
public:
    wxGLAttributes();

    wxGLAttributes& RGBA();
    wxGLAttributes& BufferSize(int val);
    wxGLAttributes& Level(int val);
    wxGLAttributes& DoubleBuffer();
    wxGLAttributes& Stereo();
    wxGLAttributes& AuxBuffers(int val);
    wxGLAttributes& MinRGBA(int mRed, int mGreen, int mBlue, int mAlpha);
    wxGLAttributes& Depth(int val);
    wxGLAttributes& Stencil(int val);
    wxGLAttributes& MinAcumRGBA(int mRed, int mGreen, int mBlue, int mAlpha);
    wxGLAttributes& SampleBuffers(int val);
    wxGLAttributes& Samplers(int val);
    wxGLAttributes& FrameBuffersRGB();
    wxGLAttributes& PlatformDefaults();
    wxGLAttributes& Defaults();
    void EndList();
};

class wxGLContextAttrs : public wxGLAttribsBase
{
public:
    wxGLContextAttrs();

    wxGLContextAttrs& CoreProfile();
    wxGLContextAttrs& MajorVersion(int val);
    wxGLContextAttrs& MinorVersion(int val);
    wxGLContextAttrs& OGLVersion(int vmayor, int vminor);
    wxGLContextAttrs& CompatibilityProfile();
    wxGLContextAttrs& ForwardCompatible();
    wxGLContextAttrs& ES2();
    wxGLContextAttrs& DebugCtx();
    wxGLContextAttrs& Robust();
    wxGLContextAttrs& NoResetNotify();
    wxGLContextAttrs& LoseOnReset();
    wxGLContextAttrs& ResetIsolation();
    wxGLContextAttrs& ReleaseFlush(int val = 1);
    wxGLContextAttrs& PlatformDefaults();
    void EndList();
};
#endif

// ---------------------------------------------------------------------------
// wxGLContext

class wxGLContext : public wxObject
{
    #if %wxchkver_2_8
        !%mac wxGLContext(wxGLCanvas *win, const wxGLContext* other = NULL); // FIXME

        !%mac | %wxchkver_2_9 void SetCurrent(const wxGLCanvas& win) const;
        %mac & !%wxchkver_2_9 void SetCurrent() const;
    #endif // %wxchkver_2_8

    #if !%wxchkver_2_8
        wxGLContext(bool isRGB, wxGLCanvas* win, const wxPalette& palette = wxNullPalette);
        wxGLContext(bool isRGB, wxGLCanvas* win, const wxPalette& palette = wxNullPalette, const wxGLContext* other = NULL);

        const wxWindow*  GetWindow();
        void SetCurrent();
        void SetColour(const wxString& colour);
        void SwapBuffers();
    #endif // !%wxchkver_2_8
};

#endif //wxLUA_USE_wxGLCanvas && wxUSE_GLCANVAS

//#endif wxUSE_OPENGL
