# REHex File Formats

## Metadata (`*.rehex-meta`)

Metadata files contain the comments, data types and any other annotations assigned to a file opened in the editor.

The file structure is a single blob of JSON which is detailed below:

```js
/* Root node is an object. */
{
	/* Whether or not the "Write protect file data" option was enabled (and should be restored).
	 * Defaults to false if not present.
	*/
	"write_protect": false,

	"comments": [
		{
			"offset": 10,
			"length": 0,
			"text": "A comment encapsulating no data at byte offset 10.",
		},

		{
			"offset": [ 20, 2 ],
			"length": [ 0, 4 ],
			"text": "A comment encapsulating 4 bits from byte offset 20 bit offset 2.",
		},

		...
	],

	/* Highlight colours used in this document. */
	"highlight-colours": [
		{
			/* Highlight colour index (valid range 0..63) */
			"index": 3,

			/* Primary (background) colour, if default colour has been overridden. */
			"primary-colour": "#xxxxxx",

			/* Secondary (foreground) colour, if default colour has been overridden. */
			"secondary-colour": "#xxxxxx",

			/* User-defined label for the highlight, if specified. */
			"label": "Something relevant to this file",
		},

		...
	],

	/* Ranges of highlighted bytes/bits. */
	"highlights": [
		{
			/* Offset to start of range, as a byte or [ byte, bit ]. */
			"offset": 1234,

			/* Length of range, as a byte or [ byte, bit ]. */
			"length": [ 456, 4 ],

			/* Colour index corresponding to a highlight colour in the highlight-colours table. */
			"colour-idx": 3,
		},

		...
	],

	/* Data type annotations. */
	"data_types": [
		{
			/* Offset to start of range, as a byte or [ byte, bit ]. */
			"offset": 1234,

			/* Length of range, as a byte or [ byte, bit ]. */
			"length": [ 456, 4 ],

			/* Data type name. */
			"type": "text:UTF-8",

			/* Data type parameters. Omitted if not used by this type. */
			"options": "...",
		},

		...
	],

	/* Virtual memory address mappings. */
	"virt_mappings": [
		{
			/* Byte offset of segment within file as a JSON integer. */
			"real_offset": 1234,

			/* Memory address of segment as a JSON integer. */
			"virt_offset": 4567,

			/* Length of segment in bytes as a JSON integer. */
			"length": 1024,
		},

		...
	],
}
```

## Workspace (`*.rehex-workspace`)

Workspace files store serialised windows and open documents within for restoring the session later.

A workspace file begins with the 16 byte string `REHEX.WORKSPACE1`, after this, the file is encoded as a series of TLV (Type Length Value) records. Unless otherwise noted, all binary values are in little endian byte order.

```c
struct {
	char type[4];       /* Type of record, ASCII characters only by convention. */
	uint32_t length;    /* Length of payload. */
	char data[length];  /* Arbitrary payload data. */
}
```

### Record types

#### `WIND`

A serialised instance of a `MainWindow`. The payload of this record contains further TLV records.

#### `WIND`.`SIZE`

Optional record describing the size of the window.

```c
uint32_t width;
uint32_t height;
```

#### `WIND`.`WMAX`

Optional record indicating the window is maximised. Has no payload.

#### `WIND`.`POS `

Optional record describing the position of the window in screen co-ordinates.

```c
uint32_t x;
uint32_t y;
```

#### `WIND`.`TAB `

A record containing a serialised tab. May occur any number of times. The payload of this record contains further TLV records.

#### `WIND`.`TAB `.`VIEW`

The "view" of the tab - that is, any opened tools and their states as a serialied `wxFileConfig`.

#### `WIND`.`TAB `.`DOC `

A fully serialised document. This is used when the workspace has been saved in response to a `wxEVT_END_SESSION` event and the document has unsaved changes only. The payload of this record contains further TLV records.

#### `WIND`.`TAB `.`DOC `.`BUFF`

The serialised `REHex::Buffer` object of the file data.

#### `WIND`.`TAB `.`DOC`.`BUFF`.`FNAM`

The path to the underlying backing file. Omitted if there is no backing file.

#### `WIND`.`TAB `.`DOC `.`BUFF`.`BMRK`

The NSURL "bookmark" to the underlying backing file (macOS only). Omitted if there is no backing file.

#### `WIND`.`TAB `.`DOC `.`BUFF`.`MTIM`

Modification time of the underlying backing file. Omitted if there is no backing file.

```c
int64_t tv_sec;
int32_t tv_nsec;
```

#### `WIND`.`TAB `.`DOC `.`BUFF`.`FDEL`

Flag indicating backing file has been deleted by an external process. No payload.

#### `WIND`.`TAB `.`DOC `.`BUFF`.`FMOD`

Flag indicating backing file has been modified by an external process. No payload.

#### `WIND`.`TAB `.`DOC `.`BUFF`.`BLCK`

Serialised real offset and virtual length of a block. These must be written sequentially and the virtual offset is the sum of the virtual lengths of all blocks so far.

```c
int64_t real_offset;
int64_t virt_length;
```

#### `WIND`.`TAB `.`DOC `.`BUFF`.`DBLK`

Serialied data from a dirty block.

```c
int64_t virt_offset;
uint8_t data[<all remaining data in record>];
```

#### `WIND`.`TAB `.`DOC `.`TITL`

Title of the document (locale-dependent string).

#### `WIND`.`TAB `.`DOC `.`META`

Serialised document metadata (JSON).

#### `WIND`.`TAB `.`DOC `.`DBYT`

Indicates a range of bytes in the backing file which have not been saved to disk. May occur any number of times.

```c
int64_t offset;
int64_t length;
```

#### `WIND`.`TAB `.`FILE`

Path to the file to be re-opened. Will not be present if a `DOC ` record was serialised.

#### `WIND`.`TAB `.`BMRK`

NSURL "bookmark" of the file to be re-opened (macOS only). Will not be present if a `DOC ` record was serialised.
