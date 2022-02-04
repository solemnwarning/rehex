# rehex help generation

## Layout

- `contents.txt` - Listing of pages used to include in the table of contents
- `template.pl` - Page generation script
- `pages/` - Page templates
- `content/` - Static content to include in each target

- `{chm,wx,online}/content/` - Static content to include in specific target
- `{chm,wx,online}/templates/` - Target-specific templates
- `{chm,wx,online}/output/` - Output directory

## Editing

Each page in the manual should have a `<pagename>.tt` file under the `pages` directory, which uses the target-specific `page.tt` template as a wrapper.

Any HTML which is target-specific should be encapsulated in a target-specific template, such as `code.tt` which encapsulates a block of inline code to be displayed verbatim.

Any page resources should go in the top-level `content` directory - page resources may also exist in the target content directories if target-specific overrides are required.

### List of templates for use by page templates

- `page.tt` - Use with the `WRAPPER` directive to encapsulate the full page content.
- `code.tt` - Use with the `WRAPPER` directive to encapsulate a block of inline code.

## Compiling

To compile the help you will need GNU Make, Perl and Template::Toolkit.

Compiling the "chm" (Windows) help also requires the Microsoft HTML Help Workshop (downloadable from http://web.archive.org/web/20160201063255if_/https://download.microsoft.com/download/0/A/9/0A939EF6-E31C-430F-A3DF-DFAE7960D564/htmlhelp.exe at the time of writing).

Compiling the "wx" (Linux/Mac) help also requires the zip command.

    $ make rehex.chm    # Builds rehex.chm in current directory
    $ make rehex.htb    # Builds rehex.htb in current directory
    $ make online-help  # Builds online help in online/output/
