local math_floor   = math.floor
local string_find  = string.find
local string_sub   = string.sub
local string_gsub  = string.gsub
local table_insert = table.insert


p = 'C:/jlabenski/development/wx/wx/wxWidgets/wxWidgets-trunk/docs/doxygen/out/xml/'
--p = "/home/jlabenski/wx/wx-svn/wx/wxWidgets/wxWidgets-trunk/docs/doxygen/out/xml/"

f_html = {
'index.xml',

'defs_8h.xml',

'brush_8h.xml',
'classwx_brush.xml',
'artprov_8h.xml',
'classwx_art_provider.xml',

'classwx_html_cell.xml',
'classwx_html_cell_event.xml',
'classwx_html_colour_cell.xml',
'classwx_html_container_cell.xml',
'classwx_html_d_c_renderer.xml',
'classwx_html_easy_printing.xml',
'classwx_html_filter.xml',
'classwx_html_help_controller.xml',
'classwx_html_help_data.xml',
'classwx_html_help_dialog.xml',
'classwx_html_help_frame.xml',
'classwx_html_help_window.xml',
'classwx_html_link_event.xml',
'classwx_html_link_info.xml',
'classwx_html_list_box.xml',
'classwx_html_modal_help.xml',
'classwx_html_parser.xml',
'classwx_html_printout.xml',
'classwx_html_rendering_info.xml',
'classwx_html_rendering_style.xml',
'classwx_html_tag.xml',
'classwx_html_tag_handler.xml',
'classwx_html_tags_module.xml',
'classwx_html_widget_cell.xml',
'classwx_html_win_parser.xml',
'classwx_html_win_tag_handler.xml',
'classwx_html_window.xml',

'classwx_date_time.xml',
'classwx_date_span.xml'
}

--f_html = {p.."compound.xsd"}
    --for line in io.lines(p.."/0dir.txt") do
    --    f_html[#f_html+1] = line
    --end


function parse()

    local t1 = os.time()

    --for i = 2,5 do --#f_html do
    for i = 2,#f_html do
        print(i, f_html[i])

        local filename = p..f_html[i]

        local T_file, T_xml = ParseXMLFile(filename)

        DoxyXMLTable[filename] = T_xml

        ParseDoxyXMLTable(T_xml)
    end

    local t2 = os.time()
    print("Completed in : "..t2-t1.." secs")

end

DoxyXMLTable   =
{
    -- ["filename.xml"] = ParseXmlFile("filename.xml")
}
DoxyClassTable =
{
    -- ["wxDateTime"] = {
    --      baseclassnames[1]   = { name="BaseClassName", prot="public/protected/private", virt="virtual/non-virtual" }
    --      classname           = "wxDateTime"
    --      includes[1]         = { local="yes/no", name="wx/datetime.h" }
    --      innerclass          = { "wxDateTime::TimeZone", "wxDateTime::Tm" }  // member classes, if any.
    --      kind                = "class"
    --      memberdef_enums[1]  = {
    --          kind    = "enum",
    --          name    = "TZ",
    --          prot    = "public",
    --          static  = "no",
    --          { {name = "Local"} {name = "EEST", initializer = "GMT3"} }
    --      }
    --      memberdef_functions = {
    --          "Add"[1]  = {                                           // an array since there may be overloads
    --              argstring   = "(const wxDateSpan& diff) const",     // everything after the function name
    --              const       = "yes/no",
    --              definition  = "virtual wxDateTime wxDateTime::Add"  // everything before the '('
    --              explicit    = "yes/no"
    --              inline      = "yes/no"
    --              kind        = "function"
    --              name        = "Add"
    --              params[1]   = { declname = "diff", kind = "param", type = "const wxDateSpan&", types = { "const", "wxDateSpan", "&" } }
    --              prot        = "public"
    --              static      = "yes/no"
    --              type        = "wxDateTime"      // the return value
    --              types       = { "wxDateTime" }  // the return value unrolled, like types in params above
    --              virt        = "virtual/non-virtual"
    --          }
    --      }
    --      memberdef_typedefs  = {
    --          definition      = "typedef unsigned short wxDateTime::wxDateTime_t"
    --          kind            = "typedef"
    --          name            = "wxDateTime_t"
    --          prot            = "public"
    --          static          = "no"
    --          type            = "unsigned short"
    --          types           = { "unsigned short" }
    --      }
    --      memberdef_variables = {}
    --      prot                = "public/protected/private"
    --      xml_filename        = "/path/to/filename.xml"
    --  }

}
DoxyFileTable  = {
--  classes = { "wxBrush", "wxBrushList" }
--  defines = {}
--  enums[1] = {
--      { initializer = "-1", name = "wxBRUSHSTYLE_INVALID" },
--      kind = "enum",
--      name = "wxBrushStyle",
--      prot = "public",
--      static = "no"
--  }
--  filename = "brush.h"
--  functions = {}
--  kind = "file"
--  typedefs = {}
--  variables = {
--      { definition = "wxBrush wxNullBrush", kind = "variable", mutable = "no",
--        name = "wxNullBrush", prot = "public", static = "no", type = "wxBrush" }
--  }
--  xml_filename = "file.xml"
}
DoxyIndexTable = {}

-- --------------------------------------------------------------------------
-- Parse the Lua table returned by ParseXMLString from a Doxygen XML file
-- --------------------------------------------------------------------------
function ParseDoxyXMLTable(T_xml)

    for k, v in ipairs(T_xml) do

        if type(v) == "table" then

            if (v.label == "xsd:schema") and (v.xarg["xmlns:xsd"] ~= nil) then
                -- compound.xsd : <xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema">
                local T = {}
                local T_file = ParseDoxyXSD_schema(v, T, T)
                AddToTable(T_file, "xml_filename", T_xml.xml_filename)
                AddToTable(DoxyFileTable, T_file.filename, T_file, v)

            elseif (v.label == "compounddef") and (v.xarg.kind == "file") then
                -- brush_8h.xml : <compounddef id="brush_8h" kind="file">
                local T_file = ParseDoxyXML_compounddef_file(v, {})
                AddToTable(T_file, "xml_filename", T_xml.xml_filename)
                AddToTable(DoxyFileTable, T_file.filename, T_file, v)

            elseif (v.label == "compounddef") and (v.xarg.kind == "class") then
                -- classwx_brush.xml : <compounddef id="classwx_brush" kind="class" prot="public">
                local T_class = ParseDoxyXML_compounddef_class(v, {})
                AddToTable(T_class, "xml_filename", T_xml.xml_filename)
                AddToTable(DoxyClassTable, T_class.classname, T_class)

            elseif (v.label == "doxygen") then
                -- this tag encloses the XML data in most of the files
                -- <doxygen xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="compound.xsd" version="1.5.5">
                AddToTable(v, "xml_filename", T_xml.xml_filename)
                ParseDoxyXMLTable(v)

            elseif (v.label == "doxygenindex") then
                -- this tag encloses the XML data in the file index.xml
                -- <doxygenindex xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="index.xsd" version="1.5.5">
                T_index = ParseDoxyXML_doxygenindex(v, {})
                AddToTable(T_index, "xml_filename", T_xml.xml_filename)
                DoxyIndexTable[#DoxyIndexTable+1] = T_index

            else
                print("Unknown value in ParseDoxyXMLTable:", k, v, " on line ", v.line, "in file", T_xml.xml_filename)
            end

        elseif (type(v) == "string") and string.find(v, "<?xml version") then
            -- ignore
        else
            printf("Unknown XML tag in ParseDoxyXMLTable '%s'='%s' on line %d in file '%s'.", tostring(k), tostring(v), v.line or 0, T_xml.xml_filename)
        end
    end
end

-- --------------------------------------------------------------------------
-- Parse Doxygen XML Lua table for label="xsd:schema"
-- --------------------------------------------------------------------------
function ParseDoxyXSD_schema(T_xml, T_doxidx, T_root)
    local func_name = "ParseDoxyXSD_schema"

    if not T_root.xsd_types then
        T_root["xsd_types"] = {}
    end

    for k, v in ipairs(T_xml) do

        v = RemoveDoxyXML_ref(v)

        if (v.label == "xsd:element") then

            if not v.xarg.type then
                T_doxidx[v.xarg.name] = 0
            else
                -- create linked tables to access them both ways
                if T_root["xsd_types"][v.xarg.type] then
                    T_doxidx[v.xarg.name] = T_root["xsd_types"][v.xarg.type]
                else
                    T_root["xsd_types"][v.xarg.type] = {}
                end

                AddToTable(T_doxidx, v.xarg.name, T_root["xsd_types"][v.xarg.type])
                AddToTable(T_doxidx[v.xarg.name], "xsd_type", v.xarg.type)
            end

            local minOccurs = v.xarg.minOccurs or 1
            local maxOccurs = v.xarg.maxOccurs or 1

            CheckDoxyXML_nvalues(v, #v == 0, func_name)
            CheckDoxyXML_xarg(v, {"name", "~type", "~minOccurs", "~maxOccurs"}, func_name)

        elseif (v.label == "xsd:attribute") then

            if not T_doxidx["attributes"] then
                T_doxidx["attributes"] = {}
            end

            if not v.xarg.type then
                T_doxidx["attributes"][v.xarg.name] = 0
            else
                -- create linked tables to access them both ways
                if T_root["xsd_types"][v.xarg.type] then
                    T_doxidx["attributes"][v.xarg.name] = T_root["xsd_types"][v.xarg.type]
                else
                    T_root["xsd_types"][v.xarg.type] = {}
                end

                AddToTable(T_doxidx["attributes"], v.xarg.name, T_root["xsd_types"][v.xarg.type])
                AddToTable(T_doxidx["attributes"][v.xarg.name], "xsd_type", v.xarg.type)
            end

            CheckDoxyXML_nvalues(v, #v == 0, func_name)
            CheckDoxyXML_xarg(v, {"name", "type", "~use"}, func_name)

        elseif (v.label == "xsd:complexType") then

            if not T_root["xsd_types"][v.xarg.name] then
                T_root["xsd_types"][v.xarg.name] = {}
            end

            ParseDoxyXSD_schema(v, T_root["xsd_types"][v.xarg.name], T_root)

            CheckDoxyXML_nvalues(v, #v >= 0, func_name)  -- can be 0 for docEmptyType
            CheckDoxyXML_xarg(v, {"name", "~mixed"}, func_name)

        elseif (v.label == "xsd:simpleType") then

            if not T_root["xsd_types"][v.xarg.name] then
                T_root["xsd_types"][v.xarg.name] = {}
            end

            ParseDoxyXSD_schema(v, T_root["xsd_types"][v.xarg.name], T_root)

            CheckDoxyXML_nvalues(v, #v > 0, func_name)
            CheckDoxyXML_xarg(v, {"name"}, func_name)

        elseif (v.label == "xsd:simpleContent") then

            ParseDoxyXSD_schema(v, T_doxidx, T_root)

            CheckDoxyXML_nvalues(v, #v > 0, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "xsd:sequence") then

            ParseDoxyXSD_schema(v, T_doxidx, T_root)

            CheckDoxyXML_nvalues(v, #v > 0, func_name)
            CheckDoxyXML_xarg(v, {"~minOccurs", "~maxOccurs"}, func_name)

        elseif (v.label == "xsd:restriction") then

            ParseDoxyXSD_schema(v, T_doxidx, T_root)

            CheckDoxyXML_nvalues(v, #v > 0, func_name)
            CheckDoxyXML_xarg(v, {"base"}, func_name)

        elseif (v.label == "xsd:extension") and v.xarg and (v.xarg.base == "xsd:string") then

            ParseDoxyXSD_schema(v, T_doxidx, T_root)

            CheckDoxyXML_nvalues(v, #v > 0, func_name)
            CheckDoxyXML_xarg(v, {"base"}, func_name)

        elseif (v.label == "xsd:enumeration") then

            AddToTable(T_doxidx, v.xarg.value, 1)
            T_doxidx["xsd:enumeration"] = (T_doxidx["xsd:enumeration"] or "")..v.xarg.value..";"

            CheckDoxyXML_nvalues(v, #v == 0, func_name)
            CheckDoxyXML_xarg(v, {"value"}, func_name)

        elseif (v.label == "xsd:choice") then

            ParseDoxyXSD_schema(v, T_doxidx, T_root)

            CheckDoxyXML_nvalues(v, #v > 0, func_name)
            CheckDoxyXML_xarg(v, {"~minOccurs", "~maxOccurs"}, func_name)

        elseif (v.label == "xsd:group") and v.xarg and (v.xarg.name) then

            if not T_root["xsd_types"][v.xarg.name] then
                T_root["xsd_types"][v.xarg.name] = {}
            end

            ParseDoxyXSD_schema(v, T_root["xsd_types"][v.xarg.name], T_root)

            CheckDoxyXML_nvalues(v, #v > 0, func_name)
            CheckDoxyXML_xarg(v, {"name"}, func_name)

        elseif (v.label == "xsd:group") and v.xarg and (v.xarg.ref) then

            -- create linked tables to access them both ways
            if not T_root["xsd_types"][v.xarg.ref] then
                T_root["xsd_types"][v.xarg.ref] = {}
            end

            AddToTable(T_doxidx, "xsd:ref", T_root["xsd_types"][v.xarg.ref])
            T_doxidx["xsd:ref"]["xsd_type"] = v.xarg.ref

            local minOccurs = v.xarg.minOccurs or 1
            local maxOccurs = v.xarg.maxOccurs or 1

            CheckDoxyXML_nvalues(v, #v >= 0, func_name)
            CheckDoxyXML_xarg(v, {"ref", "~minOccurs", "~maxOccurs"}, func_name)

        else
            print("Unknown value in ParseDoxyXSD_schema:", k, v, " on line ", v.line)
        end
    end

    return T_doxidx
end

-- --------------------------------------------------------------------------
-- Parse Doxygen XML Lua table for label="compounddef" xarg.kind="file"
-- --------------------------------------------------------------------------
function ParseDoxyXML_doxygenindex(T_xml, T_doxidx)
    local func_name = "ParseDoxyXML_doxygenindex"

    CheckDoxyXML_xarg(T_xml, {"kind"}, func_name)

    -- parse "compound" XML tagged items and add them to the T_out table
    local function ParseCompoundMember(v, T_out)
        if (v.label == "name") then

            T_out.name = v[1] -- should just be a single item

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "member")  then

            local name = v[1][1] -- should be a single "name" tag enclosed

            if (v.xarg.kind == "function") then

                if T_out.functions == nil then T_out.functions = {} end
                T_out.functions[#T_out.functions+1] = name

            elseif (v.xarg.kind == "variable") then

                if T_out.variables == nil then T_out.variables = {} end
                AddToTable(T_out.variables, name, name)

            elseif (v.xarg.kind == "typedef") then

                if T_out.typedefs == nil then T_out.typedefs = {} end
                AddToTable(T_out.typedefs, name, name)

            elseif (v.xarg.kind == "enum") then

                if T_out.enums == nil then T_out.enums = {} end
                AddToTable(T_out.enums, name, name)

            elseif (v.xarg.kind == "enumvalue") then

                if T_out.enumvalues == nil then T_out.enumvalues = {} end
                AddToTable(T_out.enumvalues, name, name)

            elseif (v.xarg.kind == "friend") then

                if T_out.friends == nil then T_out.friends = {} end
                AddToTable(T_out.friends, name, name)

            elseif (v.xarg.kind == "define") then

                if T_out.defines == nil then T_out.defines = {} end
                AddToTable(T_out.defines, name, name)

            else
                print("Unknown value in ParseDoxyXML_doxygenindex for compound member:", k, v, " on line ", v.line)
            end

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {"refid", "kind"}, func_name)

            if v[1].label ~= "name" then
                printf("Unknown label in ParseDoxyXML_doxygenindex for compound member:", k, v, " on line ", v.line)
            end

            CheckDoxyXML_nvalues(v[1], #v[1] == 1, func_name)
            CheckDoxyXML_xarg(v[1], {}, func_name)

        else
            print("Unknown value in ParseDoxyXML_doxygenindex for compound:", k, v, " on line ", v.line)
        end
    end

    if not T_doxidx.kind then
        T_doxidx.kind      = "doxygenindex"
        T_doxidx.classes   = {}
        T_doxidx.structs   = {}
        T_doxidx.enums     = {}
        T_doxidx.variables = {}
        T_doxidx.unions    = {}
        T_doxidx.files     = {}
        T_doxidx.groups    = {}
        T_doxidx.pages     = {}
        T_doxidx.dirs      = {}
    end

    for k, v in ipairs(T_xml) do

        v = RemoveDoxyXML_ref(v)

        if (v.label == "compound") and (v.xarg.kind == "class") then

            local T_class    = {}
            T_class.kind     = v.xarg.kind
            T_class.filename = v.xarg.refid

            for k2, v2 in ipairs(v) do
                ParseCompoundMember(v2, T_class)
            end

            AddToTable(T_doxidx.classes, T_class.name, T_class)

            CheckDoxyXML_nvalues(v, #v >= 1, func_name)
            CheckDoxyXML_xarg(v, {"refid", "kind"}, func_name)

        elseif (v.label == "compound") and (v.xarg.kind == "struct") then

            local T_struct    = {}
            T_struct.kind     = v.xarg.kind
            T_struct.filename = v.xarg.refid

            for k2, v2 in ipairs(v) do
                ParseCompoundMember(v2, T_struct)
            end

            AddToTable(T_doxidx.structs, T_struct.name, T_struct)

            CheckDoxyXML_nvalues(v, #v >= 1, func_name)
            CheckDoxyXML_xarg(v, {"refid", "kind"}, func_name)

        elseif (v.label == "compound") and (v.xarg.kind == "union") then

            local T_union    = {}
            T_union.kind     = v.xarg.kind
            T_union.filename = v.xarg.refid

            for k2, v2 in ipairs(v) do
                ParseCompoundMember(v2, T_union)
            end

            AddToTable(T_doxidx.unions, T_union.name, T_union)

            CheckDoxyXML_nvalues(v, #v >= 1, func_name)
            CheckDoxyXML_xarg(v, {"refid", "kind"}, func_name)

        elseif (v.label == "compound") and (v.xarg.kind == "file") then

            local T_file    = {}
            T_file.kind     = v.xarg.kind
            T_file.filename = v.xarg.refid

            for k2, v2 in ipairs(v) do
                ParseCompoundMember(v2, T_file)
                ParseCompoundMember(v2, T_doxidx) -- add to globals too
            end

            AddToTable(T_doxidx.files, T_file.filename, T_file)

            CheckDoxyXML_nvalues(v, #v >= 1, func_name)
            CheckDoxyXML_xarg(v, {"refid", "kind"}, func_name)

        elseif (v.label == "compound") and (v.xarg.kind == "group") then

            local T_group    = {}
            T_group.kind     = v.xarg.kind
            T_group.filename = v.xarg.refid

            for k2, v2 in ipairs(v) do
                ParseCompoundMember(v2, T_group)
            end

            AddToTable(T_doxidx.groups, T_group.name, T_group)

            CheckDoxyXML_nvalues(v, #v >= 1, func_name)
            CheckDoxyXML_xarg(v, {"refid", "kind"}, func_name)

        elseif (v.label == "compound") and (v.xarg.kind == "page") then

            AddToTable(T_doxidx.pages, v[1][1], v[1][1])

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {"refid", "kind"}, func_name)

            CheckDoxyXML_nvalues(v[1], #v[1] == 1, func_name)
            CheckDoxyXML_xarg(v[1], {}, func_name)

        elseif (v.label == "compound") and (v.xarg.kind == "dir") then

            AddToTable(T_doxidx.dirs, v[1][1], v[1][1])

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {"refid", "kind"}, func_name)

            CheckDoxyXML_nvalues(v[1], #v[1] == 1, func_name)
            CheckDoxyXML_xarg(v[1], {}, func_name)

        else
            print("Unknown value in ParseDoxyXML_doxygenindex:", k, v, " on line ", v.line)
        end
    end

    return T_doxidx
end


-- --------------------------------------------------------------------------
-- Parse Doxygen XML Lua table for label="compounddef" xarg.kind="file"
-- --------------------------------------------------------------------------
function ParseDoxyXML_compounddef_file(T_xml, T_file)
    local func_name = "ParseDoxyXML_compounddef_file"

    CheckDoxyXML_xarg(T_xml, {"kind", "~id"}, func_name)

    if not T_file.kind then
        T_file.kind      = "file"
        T_file.classes   = {}
        T_file.enums     = {}
        T_file.variables = {}
        T_file.defines   = {}
        T_file.typedefs  = {}
        T_file.functions = {}
    end

    for k, v in ipairs(T_xml) do

        v = RemoveDoxyXML_ref(v)

        if (v.label == "compoundname") then

            AddToTable(T_file, "filename", v[1])

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "sectiondef") then

            ParseDoxyXML_compounddef_file(v, T_file)

            CheckDoxyXML_xarg(v, {"kind"}, func_name)

        elseif (v.label == "innerclass") then

            --if v.xarg.prot == "public" then
                AddToTable(T_file.classes, #T_file.classes+1, v[1])
            --end

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {"refid", "prot"}, func_name)

        elseif (v.label == "memberdef") and (v.xarg.kind == "enum") then

            local T_enum = ParseDoxyXML_compounddef_memberdef_enum(v)
            T_file.enums[#T_file.enums+1] = T_enum

            CheckDoxyXML_xarg(v, {"kind", "id", "prot", "static"}, func_name)

        elseif (v.label == "memberdef") and (v.xarg.kind == "variable") then

            local T_variable = ParseDoxyXML_compounddef_memberdef_variable(v)
            T_file.variables[#T_file.variables+1] = T_variable

            CheckDoxyXML_xarg(v, {"kind", "id", "prot", "static", "mutable"}, func_name)

        elseif (v.label == "memberdef") and (v.xarg.kind == "define") then

            local T_define = ParseDoxyXML_compounddef_memberdef_define(v)
            T_file.defines[#T_file.defines+1] = T_define

            CheckDoxyXML_xarg(v, {"kind", "id", "prot", "static"}, func_name)

        elseif (v.label == "memberdef") and (v.xarg.kind == "typedef") then

            local T_typedef = ParseDoxyXML_compounddef_memberdef_typedef(v)
            T_file.typedefs[#T_file.typedefs+1] = T_typedef

            CheckDoxyXML_xarg(v, {"kind", "id", "prot", "static"}, func_name)

        elseif (v.label == "memberdef") and (v.xarg.kind == "function") then

            local T_function = ParseDoxyXML_compounddef_class_memberdef_function(v, nil)

            if T_file.functions[T_function.name] == nil then
                T_file.functions[T_function.name] = {}
            end

            T_file.functions[T_function.name][#T_file.functions[T_function.name]+1] = T_function

            CheckDoxyXML_xarg(v, {"kind", "id", "prot", "static", "const", "explicit", "inline", "virt"}, func_name)

        elseif (v.label == "briefdescription") or
               (v.label == "detaileddescription") or
               (v.label == "description") or
               (v.label == "header") or
               (v.label == "location") then

            -- ignore
        else
            print("Unknown value in ParseDoxyXML_compounddef_file:", k, v.label, " on line ", v.line)
        end
    end

    return T_file
end

-- --------------------------------------------------------------------------
-- Parse the children of <sectiondef kind="enum/"> or
-- classwx_brush.xml : <compounddef id="classwx_brush" kind="class" prot="public">

function ParseDoxyXML_compounddef_class(T_xml, T_class)
    local func_name = "ParseDoxyXML_compounddef_class"

    CheckDoxyXML_xarg(T_xml, {"kind", "~id", "~prot", "~abstract"}, func_name)

    if not T_class.kind then
        T_class.kind = "class"
        T_class.memberdef_functions = {}
        T_class.memberdef_enums     = {}
        T_class.memberdef_variables = {}
        T_class.memberdef_typedefs  = {}
        T_class.innerclass          = {}
    end

    if T_xml.xarg.prot then
        AddToTable(T_class, "prot", T_xml.xarg.prot)
    end
    if T_xml.xarg.abstract then
        AddToTable(T_class, "abstract", T_xml.xarg.abstract)
    end

    for k, v in ipairs(T_xml) do

        v = RemoveDoxyXML_ref(v)

        if (v.label == "compoundname") then

            AddToTable(T_class, "classname", v[1])

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "basecompoundref") then

            if not T_class["baseclassnames"] then T_class["baseclassnames"] = {} end

            local T_baseclass = {}
            T_baseclass.name = v[1]
            T_baseclass.prot = v.xarg.prot
            T_baseclass.virt = v.xarg.virt
            T_class["baseclassnames"][#T_class["baseclassnames"]+1] = T_baseclass

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {"refid", "prot", "virt"}, func_name)

        elseif (v.label == "includes") then

            if not T_class["includes"] then T_class["includes"] = {} end

            local T_include = {}
            T_include.name  = v[1]
            T_include["local"] = v.xarg["local"]
            T_class["includes"][#T_class["includes"]+1] = T_include

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {"local"}, func_name)

        elseif (v.label == "memberdef") and (v.xarg.kind == "function") then

            local T_function = ParseDoxyXML_compounddef_class_memberdef_function(v, T_class.classname)

            if T_class.memberdef_functions[T_function.name] == nil then
                T_class.memberdef_functions[T_function.name] = {}
            end

            T_class.memberdef_functions[T_function.name][#T_class.memberdef_functions[T_function.name]+1] = T_function

            CheckDoxyXML_xarg(v, {"kind", "id", "prot", "static", "const", "explicit", "inline", "virt"}, func_name)

        elseif (v.label == "memberdef") and (v.xarg.kind == "enum") then

            local T_enum = ParseDoxyXML_compounddef_memberdef_enum(v)
            T_class.memberdef_enums[#T_class.memberdef_enums+1] = T_enum

            CheckDoxyXML_xarg(v, {"kind", "id", "prot", "static"}, func_name)

        elseif (v.label == "memberdef") and (v.xarg.kind == "variable") then

            local T_variable = ParseDoxyXML_compounddef_memberdef_variable(v)

            AddToTable(T_class.memberdef_variables, T_variable.name, T_variable)

            CheckDoxyXML_xarg(v, {"kind", "id", "prot", "static", "mutable"}, func_name)

        elseif (v.label == "memberdef") and (v.xarg.kind == "typedef") then

            local T_typedef = ParseDoxyXML_compounddef_memberdef_typedef(v)
            T_class.memberdef_typedefs[#T_class.memberdef_typedefs+1] = T_typedef

            CheckDoxyXML_xarg(v, {"kind", "id", "prot", "static"}, func_name)

        elseif (v.label == "innerclass") then

            AddToTable(T_class.innerclass, v[1], v[1])

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {"refid", "prot"}, func_name)

        elseif (v.label == "sectiondef") then

            ParseDoxyXML_compounddef_class(v, T_class)

            CheckDoxyXML_xarg(v, {"kind"}, func_name)

        elseif (v.label == "description") or
               (v.label == "briefdescription") or
               (v.label == "detaileddescription") or
               (v.label == "derivedcompoundref") or
               (v.label == "inheritancegraph") or
               (v.label == "collaborationgraph") or
               (v.label == "location") or
               (v.label == "listofallmembers") or
               (v.label == "header") or             -- desciption of section
               (v.label == "memberdef" and (v.xarg.kind == "friend")) or
               (v.label == "reimplementedby") then

            -- ignore

        else
            print("Unknown label in ParseDoxyXML_compounddef_class:", v.label, " on line ", v.line)

        end
    end

    return T_class
end

-- --------------------------------------------------------------------------
--
-- <memberdef kind="function" id="group__group__funcmacro__log_1gaf57b7e28ab76bacf10b3be044e8bd634"
--  prot="public" static="no" const="no" explicit="no" inline="no" virt="non-virtual">

function ParseDoxyXML_compounddef_class_memberdef_function(T_xml, classname)
    local func_name = "ParseDoxyXML_compounddef_class_memberdef_function"

    CheckDoxyXML_xarg(T_xml, {"kind", "id", "prot", "static", "const", "explicit", "inline", "virt"}, func_name)

    local T_function    = {}
    T_function.kind     = "function"
    T_function.prot     = T_xml.xarg.prot
    T_function.static   = T_xml.xarg.static
    T_function.const    = T_xml.xarg.const
    T_function.explicit = T_xml.xarg.explicit
    T_function.inline   = T_xml.xarg.inline
    T_function.virt     = T_xml.xarg.virt

    --T_function.params = {}  only created if used
    --T_function.type   =     only created if used, types concatenated together
    --T_function.types  = {}  only created if used
    --T_function.constructor = nil
    --T_function.operator    = nil or "=="

    for k, v in ipairs(T_xml) do

        v = RemoveDoxyXML_ref(v)

        if (v.label == "type") then

            local T_types = {}

            for kt, vt in ipairs(v) do
                vt = RemoveDoxyXML_ref(vt)
                T_types[#T_types+1] = vt
            end

            if #T_types > 0 then
                AddToTable(T_function, "types", T_types)
                AddToTable(T_function, "type", table.concat(T_types, " "))
            end

            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "definition") then

            AddToTable(T_function, "definition", v[1])

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "argsstring") then

            AddToTable(T_function, "argstring", v[1])

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "name") then

            local name = v[1]

            AddToTable(T_function, "name", name)

            if name == classname then
                T_function.constructor = true
            elseif string.find(name, "operator", 1, 1) == 1 then
                T_function.operator = string.sub(name, 9)
            end

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)
        elseif (v.label == "param") then

            local T_param = ParseDoxyXML_param(v, T_function)

            if not T_function.params then T_function.params = {} end
            T_function.params[#T_function.params+1] = T_param
            CheckDoxyXML_xarg(v, {}, func_name)
        elseif (v.label == "templateparamlist") then

            local T_param = ParseDoxyXML_param(v[1], T_function)

            if not T_function.templateparamlist then T_function.templateparamlist = {} end
            T_function.templateparamlist[#T_function.templateparamlist+1] = T_param
            CheckDoxyXML_nvalues(v, v[1].label == "param", func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "briefdescription") or
               (v.label == "detaileddescription") or
               (v.label == "inbodydescription") or
               (v.label == "location") or
               (v.label == "reimplementedby") or
               (v.label == "reimplements") then

            -- ignore

        else
            print("Unknown label in ParseDoxyXML_compounddef_class_memberdef_function:", v.label, " on line ", v.line)

        end
    end

    return T_function
end

-- --------------------------------------------------------------------------
-- Parse a <param> or <templateparamlist>

function ParseDoxyXML_param(T_xml, T_class)
    local func_name = "ParseDoxyXML_param"

    CheckDoxyXML_xarg(T_xml, {}, func_name)

    local T_param = {}

    T_param.kind  = "param"
    --T_param.types = {} only created if used

    for k, v in ipairs(T_xml) do

        v = RemoveDoxyXML_ref(v)

        if (v.label == "type") then

            local T_types = {}

            for kt, vt in ipairs(v) do
                vt = RemoveDoxyXML_ref(vt)

                T_types[#T_types+1] = vt
            end

            if #T_types > 0 then
                T_param.types = T_types
                AddToTable(T_param, "type", table.concat(T_types, " "))
            end
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "declname") then

            AddToTable(T_param, "declname", v[1])

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "defname") then

            AddToTable(T_param, "defname", v[1])

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "array") then

            AddToTable(T_param, "array", v[1])

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "defval") then

            local defval = ""
            for i = 1,#v do
                defval = defval..RemoveDoxyXML_ref(v[i])
            end

            AddToTable(T_param, "defval", defval)

            CheckDoxyXML_xarg(v, {}, func_name)
        else
            print("Unknown label in ParseDoxyXML_param:", v.label)
        end
    end

    return T_param
end

-- --------------------------------------------------------------------------
-- Parse a <compounddef> <memberdef kind="variable" ...>
-- <memberdef kind="enum" id="toplevel_8h_1adb49720dc49f7d4e4cf9adbf2948e409" prot="public" static="no">

function ParseDoxyXML_compounddef_memberdef_enum(T_xml)
    local func_name = "ParseDoxyXML_compounddef_memberdef_enum"

    CheckDoxyXML_xarg(T_xml, {"kind", "id", "prot", "static"}, func_name)

    local T_enum = {};
    T_enum.kind  = "enum"
    T_enum.prot    = T_xml.xarg.prot
    T_enum.static  = T_xml.xarg.static

    for k, v in ipairs(T_xml) do
        v = RemoveDoxyXML_ref(v)

        if (v.label == "name") then

            AddToTable(T_enum, "name", v[1])

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "enumvalue") then

            local T_enumvalue = {}

            for ke, ve in ipairs(v) do
                ve = RemoveDoxyXML_ref(ve)

                if (ve.label == "name") then
                    T_enumvalue.name = ve[1]

                    CheckDoxyXML_nvalues(ve, #ve == 1, func_name)
                    CheckDoxyXML_xarg(ve, {}, func_name)

                elseif (ve.label == "initializer") then
                    T_enumvalue.initializer = ve[1]

                    CheckDoxyXML_xarg(ve, {}, func_name)

                elseif (ve.label == "briefdescription") or
                       (ve.label == "detaileddescription") then

                       -- ignore
                else
                    print("Unknown label in ParseDoxyXML_compounddef_memberdef_enum:", ve.label, " on line ", ve.line)
                end
            end

            T_enum[#T_enum+1] = T_enumvalue

            CheckDoxyXML_xarg(v, {"id", "prot"}, func_name)

        elseif (v.label == "briefdescription") or
               (v.label == "detaileddescription") or
               (v.label == "inbodydescription") or
               (v.label == "location") then

            -- ignore
        else
            print("Unknown label in ParseDoxyXML_compounddef_memberdef_enum:", v.label, " on line ", v.line)
        end
    end

    return T_enum
end

-- --------------------------------------------------------------------------
-- Parse a <compounddef> <memberdef kind="variable" ...>
-- <memberdef kind="variable" id="pen_8h_1a4dbfd18a818b95630453f3d755a1c95d" prot="public" static="no" mutable="no">

function ParseDoxyXML_compounddef_memberdef_variable(T_xml)
    local func_name = "ParseDoxyXML_compounddef_memberdef_variable"

    CheckDoxyXML_xarg(T_xml, {"kind", "id", "prot", "static", "mutable"}, func_name)

    local T_variable   = {};
    T_variable.kind    = "variable"
    T_variable.types   = {}
    T_variable.prot    = T_xml.xarg.prot
    T_variable.static  = T_xml.xarg.static
    T_variable.mutable = T_xml.xarg.mutable

    for k, v in ipairs(T_xml) do
        v = RemoveDoxyXML_ref(v)

        if (v.label == "type") then

            for kt, vt in ipairs(v) do
                vt = RemoveDoxyXML_ref(vt)

                T_variable.types[#T_variable.types+1] = vt
            end

            AddToTable(T_variable, "type", table.concat(T_variable.types, " "))

            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "definition") then

            AddToTable(T_variable, "definition", v[1])

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "argsstring") then

            AddToTable(T_variable, "argsstring", v[1])

            CheckDoxyXML_nvalues(v, #v < 2, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "name") then

            AddToTable(T_variable, "name", v[1])

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "initializer") then

            AddToTable(T_variable, "initializer", v[1])

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "briefdescription") or
               (v.label == "detaileddescription") or
               (v.label == "inbodydescription") or
               (v.label == "location") then

            -- ignore
        else
            print("Unknown label in ParseDoxyXML_compounddef_memberdef_variable:", v.label, " on line ", v.line)
        end

    end

    return T_variable
end

-- --------------------------------------------------------------------------
-- Parse a <compounddef> <memberdef kind="define" ...>
-- <memberdef kind="define" id="defs_8h_1a5ca7bb9c778fe2d44b4a1af3ceed8355" prot="public" static="no">

function ParseDoxyXML_compounddef_memberdef_define(T_xml)
    local func_name = "ParseDoxyXML_compounddef_memberdef_define"

    CheckDoxyXML_xarg(T_xml, {"kind", "id", "prot", "static"}, func_name)

    local T_define  = {};
    T_define.kind   = "define"
    T_define.prot   = T_xml.xarg.prot
    T_define.static = T_xml.xarg.static

    for k, v in ipairs(T_xml) do
        v = RemoveDoxyXML_ref(v)

        if (v.label == "initializer") then

            s = ""
            for i = 1,#v do
                s = s..RemoveDoxyXML_ref(v[i])
            end

            AddToTable(T_define, "initializer", s)

            --CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "param") then
            -- Check if there is a table of params since it may be empty, e.g. DEFINE()
            if v[1] then
                if not T_define.param then T_define.param = {} end
                T_define.param[#T_define.param+1] = v[1][1]

                CheckDoxyXML_nvalues(v, v[1].label == "defname", func_name)
                CheckDoxyXML_nvalues(v, #v[1] == 1, func_name)
                CheckDoxyXML_nvalues(v, #v == 1, func_name)
                CheckDoxyXML_xarg(v, {}, func_name)
            end
        elseif (v.label == "name") then

            AddToTable(T_define, "name", v[1])

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "briefdescription") or
               (v.label == "detaileddescription") or
               (v.label == "inbodydescription") or
               (v.label == "location") then

            -- ignore
        else
            print("Unknown label in ParseDoxyXML_compounddef_memberdef_define:", v.label, " on line ", v.line)
        end

    end

    return T_define
end

-- --------------------------------------------------------------------------
-- Parse a <compounddef> <memberdef kind="typedef" ...>
-- <memberdef kind="typedef" id="artprov_8h_1ad9c24b799a686f312c2bb64f47b6ef95" prot="public" static="no">

function ParseDoxyXML_compounddef_memberdef_typedef(T_xml)
    local func_name = "ParseDoxyXML_compounddef_memberdef_typedef"

    CheckDoxyXML_xarg(T_xml, {"kind", "id", "prot", "static"}, func_name)

    local T_typedef  = {};
    T_typedef.kind   = "typedef"
    T_typedef.types  = {}
    T_typedef.prot   = T_xml.xarg.prot
    T_typedef.static = T_xml.xarg.static

    for k, v in ipairs(T_xml) do
        v = RemoveDoxyXML_ref(v)

        if (v.label == "type") then

            for kt, vt in ipairs(v) do
                vt = RemoveDoxyXML_ref(vt)

                T_typedef.types[#T_typedef.types+1] = vt
            end

            AddToTable(T_typedef, "type", table.concat(T_typedef.types, " "))

            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "definition") then

            AddToTable(T_typedef, "definition", v[1])

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "argsstring") then

            AddToTable(T_typedef, "argsstring", v[1]) -- should be nil, but XML has these tags anyway

            CheckDoxyXML_nvalues(v, #v == 0 or #v == 1, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "name") then

            AddToTable(T_typedef, "name", v[1])

            CheckDoxyXML_nvalues(v, #v == 1, func_name)
            CheckDoxyXML_xarg(v, {}, func_name)

        elseif (v.label == "briefdescription") or
               (v.label == "detaileddescription") or
               (v.label == "inbodydescription") or
               (v.label == "location") then

            -- ignore
        else
            print("Unknown label in ParseDoxyXML_compounddef_memberdef_typedef:", v.label, " on line ", v.line)
        end

    end

    return T_typedef
end


-- --------------------------------------------------------------------------
-- Remove the <ref refid="other_xml_file"...> </ref> tag returning the inner tags
-- Ex. aboutdlg_8h.xml:  <type><ref refid="classwx_window" kindref="compound">wxWindow</ref> *</type>
--     returns this part <type>wxWindow *</type>

function RemoveDoxyXML_ref(v)
    if (type(v) == "table") and (v.label == "ref") then

        CheckDoxyXML_xarg(v, {"refid", "kindref"}, "RemoveDoxyXML_ref")
        CheckDoxyXML_nvalues(v, #v == 1, "RemoveDoxyXML_ref")

        v = v[1]
    end

    return v
end

-- --------------------------------------------------------------------------
-- Compares T.xarg with a table of expected xargs to warn of unexpected xargs
-- T_known_xarg = { 'required_arg1', '~optional_arg2', ...}
-- --------------------------------------------------------------------------

function CheckDoxyXML_xarg(T, T_known_xarg, func_name)
    local T_xarg = T.xarg
    if not T_xarg then T_xarg = {} end

    if ((T_xarg       == nil) or (CountTable(T_xarg       or {}) == 0)) and
       ((T_known_xarg == nil) or (CountTable(T_known_xarg or {}) == 0))then
        return
    end

    local n_T_xarg       = CountTable(T_xarg)
    local n_T_known_xarg = CountTable(T_known_xarg)
    local T_known_xarg_v = {}

    for k, v in ipairs(T_known_xarg) do
        if (string.sub(v,1,1) == "~") then
            T_known_xarg_v[string.sub(v,2)] = 1
        else
            T_known_xarg_v[v] = 1
            if (T_xarg[v] == nil) then
                local linenumber = debug.getinfo(2).currentline -- get source line #
                printf("WARNING: Missing xarg '%s' on line %d in func '%s' line %d.", v, T.line, func_name, linenumber)
            end
        end
    end
    for k, v in pairs(T_xarg) do
        if T_known_xarg_v[k] == nil then
            local linenumber = debug.getinfo(2).currentline -- get source line #
            printf("WARNING: Extra xarg '%s' on line %d in func '%s' line %d.", k, T.line, func_name, linenumber)
        end
    end

    if n_T_xarg ~= n_T_known_xarg then
        --local linenumber = debug.getinfo(2).currentline -- get source line #
        --printf("WARNING: Different number of xargs on line %d in func '%s' line %d.", T.line, func_name, linenumber)
    end

end

-- --------------------------------------------------------------------------
-- The table element from ParseXMLFile() has the proper number of expected values if 'ok' = true

function CheckDoxyXML_nvalues(T, ok, func_name)
    if not ok then
        local linenumber = debug.getinfo(2).currentline -- get source line #
        printf("WARNING: '%s' has %d values on line %s in func '%s' on line %d.", T.label, #T, tostring(T.line), func_name, linenumber)
    end
end

-- --------------------------------------------------------------------------
-- Generic helper functions not related to XML
-- --------------------------------------------------------------------------

-- --------------------------------------------------------------------------
-- Add to the table T[key] = value, prints a warning if the key already exits
function AddToTable(T, key, value, v)

    if (T[key] ~= nil) and (T[key] ~= value) then
        printf("WARNING: Replacing existing table key='%s' value='%s' with value='%s'.", tostring(key), tostring(T[key]), tostring(value))
        if v then
            printf("         in file %s on line %s\n", tostring(v.filename), tostring(v.line))
        end
    end

    T[key] = value
end

-- --------------------------------------------------------------------------
-- Returns the number of elements in the table
function CountTable(T)
    local n = 0

    for k, v in pairs(T) do
        n = n + 1
    end

    return n
end

-- --------------------------------------------------------------------------
-- Returns true if the table is empty, else false
function IsEmptyTable(T)
    for k, v in pairs(T) do
        return false
    end

    return true
end

-- ---------------------------------------------------------------------------
-- Replacement for pairs(table) that sorts them alphabetically, returns iterator
--  Code from "Programming in Lua" by Roberto Ierusalimschy
--  the input is a Lua table and optional comp function (see table.sort)
-- ---------------------------------------------------------------------------
function pairs_sort(atable, comp_func)
    local a = {}
    for n in pairs(atable) do table.insert(a, n) end
    table.sort(a, table_sort_comp)
    local i = 0                -- iterator variable
    local iter = function ()   -- iterator function
        i = i + 1
        if a[i] == nil then return nil
        else return a[i], atable[a[i]] end
    end
    return iter
end

function table_sort_comp(a, b)
    local ta = type(a)
    local tb = type(b)

    if (ta ~= tb) then
        return ta < tb
    end

    return a < b
end

-- --------------------------------------------------------------------------
-- http://www2.dcs.elf.stuba.sk/TeamProject/2003/team05/produkt/player/utils/serialize/serialize.lua
--! Serialization

--% Serializes a lua variable (good for table visualization)
--@ o (any) Variable to serialize
--@ d (number) INTERNAL (RECURSIVE FUNCTION)
function Serialize(o, d)
    if not d then d = 0 end
    local s = ""

    if type(o) == "number" then
        s = s..o
    elseif type(o) == "string" then
        s = s..string.format("%q", o)
    elseif type(o) == "boolean" then
        if(o) then s = s.."true" else s = s.."false" end
    elseif type(o) == "table" then
        s = s.."{\n"
        for k,v in pairs_sort(o) do

            for f = 1,d do
                s = s.."  "
            end

            if type(k) == "string" and not string.find(k, "[^%w_]") then
                s = s.."  "..k.." = "
            else
                s = s.."  ["
                s = s..Serialize(k)
                s = s.."] = "
            end

            s = s..Serialize(v, d + 1)
            if type(v) ~= "table" then s = s..",\n" end
        end

        for f = 1,d do
            s = s.."  "
        end

        s = s.."}"
        if d ~= 0 then
            s = s..","
        end
        s = s.."\n"
    elseif type(o) == "function" then
        s = s..tostring(o)
    else
        error("cannot serialize a "..type(o))
    end

    return s
end

-- --------------------------------------------------------------------------
function printf(fmt, ...)
    print(string.format(fmt, ...))
end


-- --------------------------------------------------------------------------
-- --------------------------------------------------------------------------

-- --------------------------------------------------------------------------
-- Parse an XML file and return the lines of the file in a Lua table as well
-- as a parsed version of the XML from ParseXMLString().
-- --------------------------------------------------------------------------

function ParseXMLFile(filename)
    local T_file = {}
    local T_line_chars = {}
    local last_line_char = 0

    for line in io.lines(filename) do
        T_file[#T_file+1] = line

        last_line_char = last_line_char + #line
        T_line_chars[#T_line_chars+1] = last_line_char
    end

    local s = table.concat(T_file)

    local T_xml = ParseXMLString(s, T_line_chars)

    T_xml.xml_filename = filename

    return T_file, T_xml
end

-- --------------------------------------------------------------------------
-- Generic Lua XML parser. Original code written by Roberto Ierusalimschy.
-- License : MIT
-- http://lua-users.org/wiki/LuaXml
-- It has been modified to also save the line number, replace HTML chars, and
-- throw out comments.
--
-- The returned Lua table is numerically indexed for each <>...</> full item
-- with the keys of "label", "xarg", "empty", and "line"
-- e.g. <innerclass refid="classwx_brush" prot="public">wxBrush</innerclass>
--      T_xml.label="innerclass"; T_xml[1]="wxBrush"; T_xml.line=file line number
--      T_xml.xargs = {"refid"="classwx_brush", "prot"="public"}
--      note that T_xml[1] is a table if the item has children.
-- --------------------------------------------------------------------------

function ParseXMLString(s, T_line_chars)
  local function UnHTMLString(s)
    if string_find(s, "&", 1, 1) then
        s = string_gsub(s, "&amp;",  "&")
        s = string_gsub(s, "&quot;", "\"")
        s = string_gsub(s, "&apos;", "'")
        s = string_gsub(s, "&gt;",   ">")
        s = string_gsub(s, "&lt;",   "<")
    end
    return s
  end

  local function parseargs(s)
    local arg = nil
    string_gsub(s, "([%:%w]+)=([\"'])(.-)%2",
        function (w, _, a) arg = arg or {}; arg[w] = a end)

    return arg
  end

  local find_line = function (i) return nil end -- line table may not be provided

  if T_line_chars then
    local i_linetable = 1
    find_line = function (i_char)
      while (i_linetable < #T_line_chars) and (i_char > T_line_chars[i_linetable]) do
        i_linetable = i_linetable + 1
      end
      return i_linetable
    end
  end

  local stack = {}
  local top = {}
  stack[#stack+1] = top
  local ni,c,label,xarg, empty
  local i, j = 1, 1
  while true do
    ni,j,c,label,xarg, empty = string_find(s, "<(%/?)([%w:]+)(.-)(%/?)>", i)
    if not ni then break end
    label = UnHTMLString(label)
    xarg  = UnHTMLString(xarg)
    local text = string_sub(s, i, ni-1)
    if not string_find(text, "^%s*$") then
      if not string_find(text, "<!--") then
        top[#top+1] = UnHTMLString(text)
      end
    end
    if empty == "/" then  -- empty element tag
      top[#top+1] = {label=label, xarg=parseargs(xarg), empty=1, line=find_line(i)}
    elseif c == "" then   -- start tag
      top = {label=label, xarg=parseargs(xarg), line=find_line(i)}
      stack[#stack+1] = top   -- new level
    else  -- end tag
      local toclose = table.remove(stack)  -- remove top
      top = stack[#stack]
      if #stack < 1 then
        error("nothing to close with "..label)
      end
      if toclose.label ~= label then
        error("trying to close "..toclose.label.." with "..label)
      end
      top[#top+1] = toclose
    end
    i = j+1
  end
  local text = string_sub(s, i)
  if not string_find(text, "^%s*$") then
    table_insert(stack[#stack], UnHTMLString(text))
  end
  if #stack > 1 then
    error("unclosed "..stack[stack.n].label)
  end
  return stack[1]
end
