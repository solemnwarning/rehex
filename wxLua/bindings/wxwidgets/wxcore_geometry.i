// ===========================================================================
// Purpose:     wxPoint2DInt, wxRect2DInt and other classes from wx/geometry.h
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

#if wxLUA_USE_Geometry && wxUSE_GEOMETRY

typedef int wxInt32
typedef double wxDouble

enum wxOutCode
{
    wxInside,
    wxOutLeft,
    wxOutRight,
    wxOutTop,
    wxOutBottom
};

// ---------------------------------------------------------------------------
// wxPoint2DInt

#include "wx/geometry.h"
class %delete wxPoint2DInt
{
    //wxPoint2DInt();
    wxPoint2DInt(wxInt32 x=0, wxInt32 y=0);
    wxPoint2DInt(const wxPoint2DInt &pt);
    wxPoint2DInt(const wxPoint &pt);

    //void GetFloor(wxInt32 *x , wxInt32 *y) const;
    //void GetRounded(wxInt32 *x , wxInt32 *y) const;
    wxDouble GetVectorLength() const;
    wxDouble GetVectorAngle() const;
    void SetVectorLength(wxDouble length);
    void SetVectorAngle(wxDouble degrees);
    //void SetPolarCoordinates(wxInt32 angle, wxInt32 length) - no function body in wxWidgets
    void Normalize();
    wxDouble GetDistance(const wxPoint2DInt &pt) const;
    wxDouble GetDistanceSquare(const wxPoint2DInt &pt) const;
    wxInt32 GetDotProduct(const wxPoint2DInt &vec) const;
    wxInt32 GetCrossProduct(const wxPoint2DInt &vec) const;

    //void WriteTo(wxDataOutputStream &stream) const;
    //void ReadFrom(wxDataInputStream &stream);

    %rename X %member_func wxInt32 m_x;
    %rename Y %member_func wxInt32 m_y;

    wxPoint2DInt operator-();
    wxPoint2DInt& operator=(const wxPoint2DInt& pt);
    wxPoint2DInt& operator+=(const wxPoint2DInt& pt);
    wxPoint2DInt& operator-=(const wxPoint2DInt& pt);
    wxPoint2DInt& operator*=(const wxPoint2DInt& pt);
    //wxPoint2DInt& operator*=(wxDouble n) - no function body in wxWidgets
    //wxPoint2DInt& operator*=(wxInt32 n) - no function body in wxWidgets
    wxPoint2DInt& operator/=(const wxPoint2DInt& pt);
    //wxPoint2DInt& operator/=(wxDouble n) - no function body in wxWidgets
    //wxPoint2DInt& operator/=(wxInt32 n) - no function body in wxWidgets
    //operator wxPoint() const;
    bool operator==(const wxPoint2DInt& pt) const;
    //bool operator!=(const wxPoint2DInt& pt) const;

    wxPoint2DInt operator*(wxInt32 n);
};

// ---------------------------------------------------------------------------
// wxPoint2DDouble

#include "wx/geometry.h"
class %delete wxPoint2DDouble
{
    //wxPoint2DDouble();
    wxPoint2DDouble(wxDouble x=0, wxDouble y=0);
    wxPoint2DDouble(const wxPoint2DDouble &pt);
    wxPoint2DDouble(const wxPoint2DInt &pt);
    wxPoint2DDouble(const wxPoint &pt);

    //void GetFloor(wxInt32 *x , wxInt32 *y) const;
    //void GetRounded(wxInt32 *x , wxInt32 *y) const;
    wxDouble GetVectorLength() const;
    wxDouble GetVectorAngle() const;
    void SetVectorLength(wxDouble length);
    void SetVectorAngle(wxDouble degrees);
    //void SetPolarCoordinates(wxDouble angle, wxDouble length) - no function body in wxWidgets
    //void Normalize() - no function body in wxWidgets
    wxDouble GetDistance(const wxPoint2DDouble &pt) const;
    wxDouble GetDistanceSquare(const wxPoint2DDouble &pt) const;
    wxDouble GetDotProduct(const wxPoint2DDouble &vec) const;
    wxDouble GetCrossProduct(const wxPoint2DDouble &vec) const;

    %rename X %member_func wxDouble m_x;
    %rename Y %member_func wxDouble m_y;

    wxPoint2DDouble operator-();
    wxPoint2DDouble& operator=(const wxPoint2DDouble& pt);
    wxPoint2DDouble& operator+=(const wxPoint2DDouble& pt);
    wxPoint2DDouble& operator-=(const wxPoint2DDouble& pt);
    wxPoint2DDouble& operator*=(const wxPoint2DDouble& pt);
    //wxPoint2DDouble& operator*=(wxDouble n);
    //wxPoint2DDouble& operator*=(wxInt32 n);
    wxPoint2DDouble& operator/=(const wxPoint2DDouble& pt);
    //wxPoint2DDouble& operator/=(wxDouble n);
    //wxPoint2DDouble& operator/=(wxInt32 n);
    bool operator==(const wxPoint2DDouble& pt) const;
    //bool operator!=(const wxPoint2DDouble& pt) const;
};

// ---------------------------------------------------------------------------
// wxRect2DDouble

#include "wx/geometry.h"
class %delete wxRect2DDouble
{
    //wxRect2DDouble();
    wxRect2DDouble(wxDouble x=0, wxDouble y=0, wxDouble w=0, wxDouble h=0);
    wxRect2DDouble(const wxRect2DDouble& rect);

    wxPoint2DDouble GetPosition();
    wxSize GetSize();
    wxDouble GetLeft() const;
    void SetLeft(wxDouble n);
    void MoveLeftTo(wxDouble n);
    wxDouble GetTop() const;
    void SetTop(wxDouble n);
    void MoveTopTo(wxDouble n);
    wxDouble GetBottom() const;
    void SetBottom(wxDouble n);
    void MoveBottomTo(wxDouble n);
    wxDouble GetRight() const;
    void SetRight(wxDouble n);
    void MoveRightTo(wxDouble n);
    wxPoint2DDouble GetLeftTop() const;
    void SetLeftTop(const wxPoint2DDouble &pt);
    void MoveLeftTopTo(const wxPoint2DDouble &pt);
    wxPoint2DDouble GetLeftBottom() const;
    void SetLeftBottom(const wxPoint2DDouble &pt);
    void MoveLeftBottomTo(const wxPoint2DDouble &pt);
    wxPoint2DDouble GetRightTop() const;
    void SetRightTop(const wxPoint2DDouble &pt);
    void MoveRightTopTo(const wxPoint2DDouble &pt);
    wxPoint2DDouble GetRightBottom() const;
    void SetRightBottom(const wxPoint2DDouble &pt);
    void MoveRightBottomTo(const wxPoint2DDouble &pt);
    wxPoint2DDouble GetCentre() const;
    void SetCentre(const wxPoint2DDouble &pt);
    void MoveCentreTo(const wxPoint2DDouble &pt);
    wxOutCode GetOutCode(const wxPoint2DDouble &pt) const;
    bool Contains(const wxPoint2DDouble &pt) const;
    bool Contains(const wxRect2DDouble &rect) const;
    bool IsEmpty() const;
    bool HaveEqualSize(const wxRect2DDouble &rect) const;
    //void Inset(wxDouble x, wxDouble y);
    void Inset(wxDouble left, wxDouble top, wxDouble right, wxDouble bottom );
    void Offset(const wxPoint2DDouble &pt);
    void ConstrainTo(const wxRect2DDouble &rect);
    wxPoint2DDouble Interpolate(wxInt32 widthfactor , wxInt32 heightfactor);
    //static void Intersect(const wxRect2DDouble &src1 , const wxRect2DDouble &src2 , wxRect2DDouble *dest);
    void Intersect(const wxRect2DDouble &otherRect);
    wxRect2DDouble CreateIntersection(const wxRect2DDouble &otherRect) const;
    bool Intersects(const wxRect2DDouble &rect) const;
    //static void Union(const wxRect2DDouble &src1 , const wxRect2DDouble &src2 , wxRect2DDouble *dest);
    void Union(const wxRect2DDouble &otherRect);
    void Union(const wxPoint2DDouble &pt);
    wxRect2DDouble CreateUnion(const wxRect2DDouble &otherRect) const;
    void Scale(wxDouble f);
    //void Scale(wxInt32 num , wxInt32 denum);

    %rename X %member_func wxDouble m_x;
    %rename Y %member_func wxDouble m_y;
    %rename Width %member_func wxDouble m_width;
    %rename Height %member_func wxDouble m_height;

    //wxRect2DDouble& operator = (const wxRect2DDouble& rect) - use copy constructor
    bool operator==(const wxRect2DDouble& rect);
    //bool operator != (const wxRect2DDouble& rect) const;
};

// ---------------------------------------------------------------------------
// wxRect2DInt

#include "wx/geometry.h"
class %delete wxRect2DInt
{
    //wxRect2DInt();
    wxRect2DInt(wxInt32 x=0, wxInt32 y=0, wxInt32 w=0, wxInt32 h=0);
    wxRect2DInt(const wxRect2DInt& rect);
    wxRect2DInt(const wxRect& r);
    wxRect2DInt(const wxPoint2DInt& topLeft, const wxPoint2DInt& bottomRight);
    wxRect2DInt(const wxPoint2DInt& pos, const wxSize& size);

    wxPoint2DInt GetPosition();
    wxSize GetSize();
    wxInt32 GetLeft() const;
    void SetLeft(wxInt32 n);
    void MoveLeftTo(wxInt32 n);
    wxInt32 GetTop() const;
    void SetTop(wxInt32 n);
    void MoveTopTo(wxInt32 n);
    wxInt32 GetBottom() const;
    void SetBottom(wxInt32 n);
    void MoveBottomTo(wxInt32 n);
    wxInt32 GetRight() const;
    void SetRight(wxInt32 n);
    void MoveRightTo(wxInt32 n);
    wxPoint2DInt GetLeftTop() const;
    void SetLeftTop(const wxPoint2DInt &pt);
    void MoveLeftTopTo(const wxPoint2DInt &pt);
    wxPoint2DInt GetLeftBottom() const;
    void SetLeftBottom(const wxPoint2DInt &pt);
    void MoveLeftBottomTo(const wxPoint2DInt &pt);
    wxPoint2DInt GetRightTop() const;
    void SetRightTop(const wxPoint2DInt &pt);
    void MoveRightTopTo(const wxPoint2DInt &pt);
    wxPoint2DInt GetRightBottom() const;
    void SetRightBottom(const wxPoint2DInt &pt);
    void MoveRightBottomTo(const wxPoint2DInt &pt);
    wxPoint2DInt GetCentre() const;
    void SetCentre(const wxPoint2DInt &pt);
    void MoveCentreTo(const wxPoint2DInt &pt);
    wxOutCode GetOutCode(const wxPoint2DInt &pt) const;
    bool Contains(const wxPoint2DInt &pt) const;
    bool Contains(const wxRect2DInt &rect) const;
    bool IsEmpty() const;
    bool HaveEqualSize(const wxRect2DInt &rect) const;
    //void Inset(wxInt32 x , wxInt32 y);
    void Inset(wxInt32 left, wxInt32 top, wxInt32 right, wxInt32 bottom );
    void Offset(const wxPoint2DInt &pt);
    void ConstrainTo(const wxRect2DInt &rect);
    wxPoint2DInt Interpolate(wxInt32 widthfactor , wxInt32 heightfactor);
    //static void Intersect(const wxRect2DInt &src1 , const wxRect2DInt &src2 , wxRect2DInt *dest);
    void Intersect(const wxRect2DInt &otherRect);
    wxRect2DInt CreateIntersection(const wxRect2DInt &otherRect) const;
    bool Intersects(const wxRect2DInt &rect) const;
    //static void Union(const wxRect2DInt &src1 , const wxRect2DInt &src2 , wxRect2DInt *dest);
    void Union(const wxRect2DInt &otherRect);
    void Union(const wxPoint2DInt &pt);
    wxRect2DInt CreateUnion(const wxRect2DInt &otherRect) const;
    void Scale(wxInt32 f);
    //void Scale(wxInt32 num , wxInt32 denum);

    //void WriteTo(wxDataOutputStream &stream) const;
    //void ReadFrom(wxDataInputStream &stream);

    %rename X %member_func wxInt32 m_x;
    %rename Y %member_func wxInt32 m_y;
    %rename Width %member_func wxInt32 m_width;
    %rename Height %member_func wxInt32 m_height;

    //wxRect2DInt& operator = (const wxRect2DInt& rect) - use copy constructor
    bool operator == (const wxRect2DInt& rect) const;
    //bool operator != (const wxRect2DInt& rect) const;
};

// ---------------------------------------------------------------------------
// wxTransform2D - an abstract class

//#include "wx/geometry.h"
//
//class %delete wxTransform2D
//{
//    virtual void                    Transform(wxPoint2DInt* pt)const; //  = 0
//    virtual void                    Transform(wxRect2DInt* r) const;
//    virtual wxPoint2DInt    Transform(const wxPoint2DInt &pt) const;
//    virtual wxRect2DInt        Transform(const wxRect2DInt &r) const;
//    virtual void                    InverseTransform(wxPoint2DInt* pt) const; //  = 0
//    virtual void                    InverseTransform(wxRect2DInt* r) const;
//    virtual wxPoint2DInt    InverseTransform(const wxPoint2DInt &pt) const;
//    virtual wxRect2DInt        InverseTransform(const wxRect2DInt &r) const;
//    void    wxTransform2D::Transform(wxRect2DInt* r) const;
//    wxPoint2DInt    wxTransform2D::Transform(const wxPoint2DInt &pt) const;
//    wxRect2DInt     wxTransform2D::Transform(const wxRect2DInt &r) const;
//    void    wxTransform2D::InverseTransform(wxRect2DInt* r) const;
//    wxPoint2DInt    wxTransform2D::InverseTransform(const wxPoint2DInt &pt) const;
//    wxRect2DInt     wxTransform2D::InverseTransform(const wxRect2DInt &r) const;
//};

// ---------------------------------------------------------------------------
// wxPosition

#include "wx/position.h"
class %delete wxPosition
{
public:
    wxPosition();
    wxPosition(int row, int col);

    // default copy ctor and assignment operator are okay.

    int GetRow() const;
    int GetColumn() const;
    int GetCol() const;
    void SetRow(int row);
    void SetColumn(int column);
    void SetCol(int column);

    bool operator==(const wxPosition& p) const;
    bool operator!=(const wxPosition& p) const;

    wxPosition& operator+=(const wxPosition& p);
    wxPosition& operator-=(const wxPosition& p);
    wxPosition& operator+=(const wxSize& s);
    wxPosition& operator-=(const wxSize& s);

    wxPosition operator+(const wxPosition& p) const;
    wxPosition operator-(const wxPosition& p) const;
    wxPosition operator+(const wxSize& s) const;
    wxPosition operator-(const wxSize& s) const;

private:
    int m_row;
    int m_column;
};

#endif //wxLUA_USE_Geometry && wxUSE_GEOMETRY
