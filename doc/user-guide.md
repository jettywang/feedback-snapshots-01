# User's guide

This is a brief user's guide for **pyelftools**.

## Getting started

The easiest way to get started with **pyelftools** is by examining the
examples it comes with (in the `examples/` directory of the source
distribution). Examples are heavily commented, and each begins with a
short comment describing its purpose.

If you have a basic grasp of Python and are somewhat familiar with the
problem domain **pyelftools** aims to address (ELF and DWARF formats),
you should be able to get going just from looking at the examples -
reading this guide is not necessary.

## Directory structure

Directories:

-   `./`: root of the distribution, with a `README`, `LICENSE` and other
    informational files.
-   `./elftools`: the source of the library/package itself. This is the
    directory that will get placed into your `site-packages` by the
    setup process.
    -   `./elftools/elf`: classes for parsing and decoding ELF.
    -   `./elftools/dwarf`: classes for parsing and decoding DWARF.
    -   `./elftools/common`: common utilities for the ELF and DWARF
        parts.
    -   `./elftools/construct`: the \"construct\" library used by
        **pyelftools** for low-level binary stream parsing.
-   `./examples`: examples.
-   `./scripts`: some useful scripts and tools built on top of the
    `elftools` package. For example - a clone of `readelf`.
-   `./test`: tests for **pyelftools**, of interest mainly to those who
    wish to modify or extend the library, rather than simply use it. See
    the [Hacking guide](hacking-guide.rst) for more details.

From this point on, `elftools` is going to refer only to the Python
library, and **pyelftools** to the whole source distribution which
includes, in addition to the library, also examples, scripts and tests.

### Running the examples

Running the examples is very easy. After installing **pyelftools** you
can run them from anywhere by executing:

``` text
> python <path_to_pyelftools>/examples/<example_name> --test <elf_filename>
```
## Scripts and tools

A variety of useful scripts and tools can be built on-top of the
`elftools` library. As an example, one such script packaged
with **pyelftools** is `scripts/readelf.py`, which is a (fairly
faithful) clone of the `readelf` program from GNU binutils. `readelf.py`
serves at least these purposes:

1.  A showcase for the abilities of `elftools`. Its existence and
    ability to clone a lot of the functionality of GNU readelf is a
    powerful proof of concept for the library, showing that it indeed
    provides comprehensive ELF and DWARF parsing and decoding services.
2.  A helpful example of usage for the library. You can examine its
    output and then look at the source code to see how it uses
    `elftools` to produce such output.
3.  It\'s being used in the testing of `elftools`.

## Detailed usage

### Basic concepts

All the classes mentioned in this and subsequent sections have
comprehensive documentation strings that explain how to construct them
and to use their methods. For convenience, whenever this guide mentions
a class for the first time, it will also specify the file in which it
can be found relative to the source distribution directory of
**pyelftools**. The user is expected to examine this documentation for
the classes that are of interest.

If you find any part of the documentation lacking, don\'t hesitate to
file a report in the issue tracker
(<https://github.com/eliben/pyelftools/issues>).

### API levels

**pyelftools** can be seen as providing two different levels of APIs
(although this isn\'t directly evident in the code). There\'s a
low-level API that directly exposes the parsed contents of the streams
representing ELF and DWARF data. Most of the code, however, is geared
towards providing a high-level API that encapsulates these details in
Python classes with attributes and behavior. This guide mostly focuses
on the high-level API. For the low-level API take a look at the
\"Structs and headers\" section and some of the examples.

### Main entry point

The main entry point to **pyelftools** is the `ELFFile` class (in file
`elftools/elf/elffile.py`). It simply accepts a stream object (which can
be an open file or any other stream-like Python
object), and does some basic analysis, such as verifying that the stream
indeed contains a valid ELF object. Methods of this class allow you to
enumerate the sections and segments it contains, as well as extracting
the debug information contained within it.

### ELF sections

The main informational unit of an ELF file is a \"section\". The
`ELFFile` entry point class has several methods for conveniently
accessing the sections in an ELF file (for example, count the sections,
get the Nth sections, iterate over all sections, etc.)

The object returned to represent a section will always implement at
least the interface defined by the `Section` class
(`elftools/elf/sections.py`). This class represents a generic ELF
section, allowing dictionary-like access to its header, and getting its
data as a buffer.

Some sections in ELF are special and their semantics is at least
partially defined by the standard and various platform ABIs.
**pyelftools** knows about these sections, and has special classes for
representing them. For example, when reading a symbol table section from
the stream, `ELFFile` will return a `SymbolTableSection` class (also in
`elftools/elf/sections.py`). This class provides additional methods for
interacting with the symbol table. There are other special sections
**pyelftools** is familiar with, for example `StringTableSection` (in
the same file) and `RelocationSection` (in
`elftools/elf/relocation.py`).

### ELF segments

Similarly to sections, an ELF segment has a class in **pyelftools** to
represent it. This is `Segment` (in file `elftools/elf/segments.py`). To
get to the object\'s segments, use the relevant methods in `ELFFile` to
count and enumerate them. There are also some special segment classes
that have more information about well-known segments. Take a look at
`elftools/elf/segments.py` for more details.

### Structs and headers

Most objects in ELF and DWARF have \"headers\", and such objects usually
provide dictionary-like access to attributes in these headers. The names
of fields in the headers try to match the ELF and DWARF standards
whenever possible. In any case, it is easy to examine the whole header
by printing the `header` attribute (when it exists, it\'s mentioned as a
publicly accessible attribute in the documentation string of the
relevant class).

Enum fields such as `e_machine`, `sh_type`, `p_type`, and `d_tag` return
symbolic names (`str`) for recognized values and the original numbers
(`int`) for unrecognized ones. For example, `elffile['e_machine']` may be
`'EM_X86_64'` or an unknown machine number. Check `isinstance(value, str)`
before using string operations on these fields.

This behavior, enabled by `_default_=Pass` in `elftools/elf/enums.py`,
allows inspection of files containing newer or vendor-specific values.
An unrecognized value does not necessarily mean the file is invalid.
Fields needed to determine the file's layout, such as ELF class and byte
order, still require recognized values.

In addition, it\'s possible to see how these headers are parsed in the
parts of **pyelftools** which define \"structs\". For ELF this is in
`elftools/elf/structs.py`, and for DWARF this is in
`elftools/dwarf/structs.py`. A word of warning: these are parts of the
low-level API, use them at your own peril.

### DWARF information

The main entry point for DWARF information in **pyelftools** is the
class `DWARFInfo` in `elftools/dwarf/dwarfinfo.py`. Care was taken to
make `DWARFInfo` independent of `ELFFile`, to allow its usage
independently of any specific container (for example, to parse DWARF
data directly emitted into memory or dumped to a file).

That said, the easiest way to get a `DWARFInfo` object is just to ask
`ELFFile` for it. The latter has a method named `has_dwarf_info` which
checks whether the ELF object has debugging information in it at all. If
the answer is positive, use the `get_dwarf_info` method to get a
`DWARFInfo` object representing this DWARF information. `ELFFile` does
all the required book-keeping (including even relocation of DWARF
sections), and the resulting `DWARFInfo` is ready for usage.

To follow a type reference, use `die.get_DIE_from_attribute('DW_AT_type')`.
Reference forms such as `DW_FORM_ref4` store offsets relative to the compilation
unit, so their attribute values cannot be compared directly with `DIE.offset`.
The [type references example](../examples/dwarf_type_references.py) demonstrates
following these references through typedefs and other types, and displays both
the stored values and the resolved DIE offsets.

#### Attribute provenance

A DIE does not always carry every attribute needed to describe its entity. A
concrete inlined instance usually gets its name and declaration information from
its `DW_AT_abstract_origin`, and the abstract instance may in turn refer to a
non-defining declaration through `DW_AT_specification`. The reference can cross
compilation units or point into a supplementary debug object that has already
been bound to the main `DWARFInfo`.

Use `die.get_attribute_provenance(name)` (or
`dwarfinfo.get_attribute_provenance(die, name)`) to resolve such an attribute
without modifying the DIE:

```python
result = die.get_attribute_provenance('DW_AT_name')
if result.is_resolved:
    print(result.value)          # effective value
    print(result.status)         # 'direct' or 'inherited'
    for link in result.chain:
        print(link.attribute, link.source.unit, link.target)
```

The result distinguishes direct values from inherited values. A direct value
takes precedence, but inherited branches that were shadowed remain available in
`result.candidates`. Each `ReferenceLink` records the attribute name, form, raw
value, and the identities of the source and target DIEs. A `DIEIdentity` includes
a `UnitIdentity`, so two units at the same offset in different containers (for
example a main file and its supplementary file) remain distinct.

Unresolved situations are explicit: `missing`, `broken_reference`, `cycle`, and
`conflict`. A broken reference, a cycle, or contradictory values from different
branches is reported as such rather than being replaced with the first non-empty
value. Use `die.get_resolved_attributes()` to resolve every attribute reachable
through the graph in one pass. The underlying implementation is in
`elftools/dwarf/provenance.py`.

Contrary to ELF with its structured set of sections and segments, DWARF
information is quite ad hoc for the special needs it serves. Each DWARF
section contains different information that has to be decoded and
interpreted in a special manner. **pyelftools** attempts to provide a
convenient Pythonic API for this information whenever possible. There\'s
no way around it - to even understand the API one must have some grasp
of the [DWARF standard](https://dwarfstd.org/).
