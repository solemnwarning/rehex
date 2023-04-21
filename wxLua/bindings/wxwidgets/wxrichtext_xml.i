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
#if wxUSE_XML

#include "wx/richtext/richtextxml.h"

class %delete wxRichTextXMLHelper: public wxObject
{
public:
    wxRichTextXMLHelper();
    wxRichTextXMLHelper(const wxString& enc);
    //~wxRichTextXMLHelper();

    void Init();

    void SetupForSaving(const wxString& enc);

    void Clear();

    void SetFileEncoding(const wxString& encoding);
    const wxString& GetFileEncoding() const;

    // Convert a colour to a 6-digit hex string
    static wxString ColourToHexString(const wxColour& col);

    // Convert 6-digit hex string to a colour
    static wxColour HexStringToColour(const wxString& hex);

    static wxString MakeString(const int& v);
    static wxString MakeString(const long& v);
    static wxString MakeString(const double& v);
    static wxString MakeString(const wxString& s);
    static wxString MakeString(const wxColour& col);

    static bool HasParam(wxXmlNode* node, const wxString& param);
    static wxXmlNode *GetParamNode(wxXmlNode* node, const wxString& param);
    static wxString GetNodeContent(wxXmlNode *node);
    static wxString GetParamValue(wxXmlNode *node, const wxString& param);
    static wxString GetText(wxXmlNode *node, const wxString& param = wxEmptyString);
    static wxXmlNode* FindNode(wxXmlNode* node, const wxString& name);

    static wxString AttributeToXML(const wxString& str);

    static bool RichTextFixFaceName(wxString& facename);
    static long ColourStringToLong(const wxString& colStr);
    static wxTextAttrDimension ParseDimension(const wxString& dimStr);

    // Make a string from the given property. This can be overridden for custom variants.
    virtual wxString MakeStringFromProperty(const wxVariant& var);

    // Create a proprty from the string read from the XML file.
    virtual wxVariant MakePropertyFromString(const wxString& name, const wxString& value, const wxString& type);

    // Import properties
    virtual bool ImportProperties(wxRichTextProperties& properties, wxXmlNode* node);

    virtual bool ImportStyle(wxRichTextAttr& attr, wxXmlNode* node, bool isPara = false);
    virtual bool ImportStyleDefinition(wxRichTextStyleSheet* sheet, wxXmlNode* node);

    // Get flags, as per handler flags
    int GetFlags() const;
    void SetFlags(int flags);

#if wxRICHTEXT_HAVE_DIRECT_OUTPUT
    // write string to output
    static void OutputString(wxOutputStream& stream, const wxString& str); // , wxMBConv *convMem, wxMBConv *convFile);

    static void OutputIndentation(wxOutputStream& stream, int indent);

    // Same as above, but create entities first.
    // Translates '<' to "&lt;", '>' to "&gt;" and '&' to "&amp;"
    static void OutputStringEnt(wxOutputStream& stream, const wxString& str); // , wxMBConv *convMem, wxMBConv *convFile);

    void OutputString(wxOutputStream& stream, const wxString& str);
    void OutputStringEnt(wxOutputStream& stream, const wxString& str);
    
    static void AddString(wxString& str, const int& v);
    static void AddString(wxString& str, const long& v);
    static void AddString(wxString& str, const double& v);
    //static void AddString(wxString& str, const wxChar* s);
    static void AddString(wxString& str, const wxString& s);
    static void AddString(wxString& str, const wxColour& col);

    static void AddAttribute(wxString& str, const wxString& name, const int& v);
    static void AddAttribute(wxString& str, const wxString& name, const long& v);
    static void AddAttribute(wxString& str, const wxString& name, const double& v);
    //static void AddAttribute(wxString& str, const wxString& name, const wxChar* s);
    static void AddAttribute(wxString& str, const wxString& name, const wxString& s);
    static void AddAttribute(wxString& str, const wxString& name, const wxColour& col);
    static void AddAttribute(wxString& str, const wxString& name, const wxTextAttrDimension& dim);
    static void AddAttribute(wxString& str, const wxString& rootName, const wxTextAttrDimensions& dims);
    static void AddAttribute(wxString& str, const wxString& rootName, const wxTextAttrBorder& border);
    static void AddAttribute(wxString& str, const wxString& rootName, const wxTextAttrBorders& borders);

    /// Create a string containing style attributes
    static wxString AddAttributes(const wxRichTextAttr& attr, bool isPara = false);
    virtual bool ExportStyleDefinition(wxOutputStream& stream, wxRichTextStyleDefinition* def, int level);

    virtual bool WriteProperties(wxOutputStream& stream, const wxRichTextProperties& properties, int level);
#endif

#if wxRICHTEXT_HAVE_XMLDOCUMENT_OUTPUT
    static void AddAttribute(wxXmlNode* node, const wxString& name, const int& v);
    static void AddAttribute(wxXmlNode* node, const wxString& name, const long& v);
    static void AddAttribute(wxXmlNode* node, const wxString& name, const double& v);
    static void AddAttribute(wxXmlNode* node, const wxString& name, const wxString& s);
    static void AddAttribute(wxXmlNode* node, const wxString& name, const wxColour& col);
    static void AddAttribute(wxXmlNode* node, const wxString& name, const wxTextAttrDimension& dim);
    static void AddAttribute(wxXmlNode* node, const wxString& rootName, const wxTextAttrDimensions& dims);
    static void AddAttribute(wxXmlNode* node, const wxString& rootName, const wxTextAttrBorder& border);
    static void AddAttribute(wxXmlNode* node, const wxString& rootName, const wxTextAttrBorders& borders);

    static bool AddAttributes(wxXmlNode* node, wxRichTextAttr& attr, bool isPara = false);

    virtual bool ExportStyleDefinition(wxXmlNode* parent, wxRichTextStyleDefinition* def);

    // Write the properties
    virtual bool WriteProperties(wxXmlNode* node, const wxRichTextProperties& properties);
#endif

public:

#if wxRICHTEXT_HAVE_DIRECT_OUTPUT
    // Used during saving
    //wxMBConv*   m_convMem;
    //wxMBConv*   m_convFile;
    bool        m_deleteConvFile;
#endif

    wxString    m_fileEncoding;
    int         m_flags;
};

/*!
    @class wxRichTextXMLHandler

    Implements XML loading and saving. Two methods of saving are included:
    writing directly to a text stream, and populating an wxXmlDocument
    before writing it. The former method is considerably faster, so we favour
    that one, even though the code is a little less elegant.
 */

//class WXDLLIMPEXP_FWD_XML wxXmlNode;
//class WXDLLIMPEXP_FWD_XML wxXmlDocument;

class %delete wxRichTextXMLHandler: public wxRichTextFileHandler
{
    //DECLARE_DYNAMIC_CLASS(wxRichTextXMLHandler)
public:
    wxRichTextXMLHandler(const wxString& name, const wxString& ext, int type = wxRICHTEXT_TYPE_XML);

    void Init();

#if wxUSE_STREAMS

#if wxRICHTEXT_HAVE_DIRECT_OUTPUT
    /// Recursively export an object
    bool ExportXML(wxOutputStream& stream, wxRichTextObject& obj, int level);
#endif

#if wxRICHTEXT_HAVE_XMLDOCUMENT_OUTPUT
    bool ExportXML(wxXmlNode* parent, wxRichTextObject& obj);
#endif

    /// Recursively import an object
    bool ImportXML(wxRichTextBuffer* buffer, wxRichTextObject* obj, wxXmlNode* node);
#endif

    /// Creates an object given an XML element name
    virtual wxRichTextObject* CreateObjectForXMLName(wxRichTextObject* parent, const wxString& name) const;

    /// Can we save using this handler?
    virtual bool CanSave() const;

    /// Can we load using this handler?
    virtual bool CanLoad() const;

    /// Returns the XML helper object, implementing functionality
    /// that can be reused elsewhere.
    wxRichTextXMLHelper& GetHelper();

// Implementation

    /**
        Call with XML node name, C++ class name so that wxRTC can read in the node.
        If you add a custom object, call this.
    */
    static void RegisterNodeName(const wxString& nodeName, const wxString& className);

    /**
        Cleans up the mapping between node name and C++ class.
    */
    static void ClearNodeToClassMap();

protected:
#if wxUSE_STREAMS
    virtual bool DoLoadFile(wxRichTextBuffer *buffer, wxInputStream& stream);
    virtual bool DoSaveFile(wxRichTextBuffer *buffer, wxOutputStream& stream);
#endif

    wxRichTextXMLHelper m_helper;

    static wxStringToStringHashMap sm_nodeNameToClassMap;
};

#endif // wxUSE_XML

//  End richtextxml.h
#endif // wxLUA_USE_wxRichText && %wxchkver_3_0 && wxUSE_RICHTEXT
