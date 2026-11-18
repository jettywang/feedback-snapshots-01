# UEFI Firmware Parser

[![CI status](https://github.com/theopolis/uefi-firmware-parser/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/theopolis/uefi-firmware-parser/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/uefi_firmware.svg)](https://pypi.org/project/uefi_firmware/)
[![Supported Python versions](https://img.shields.io/pypi/pyversions/uefi_firmware.svg)](https://pypi.org/project/uefi_firmware/)

`uefi_firmware` is a Python module and command-line tool for parsing, extracting,
and recreating UEFI firmware. Beyond UEFI firmware volumes and capsules, it also
parses Intel flash descriptors, Intel ME modules, Dell PFS updates, and AMI Aptio
capsules.

## Installation

The package is published on PyPI as [`uefi_firmware`](https://pypi.org/project/uefi_firmware/)
and requires Python 3.10 or newer.

```sh
pip install uefi_firmware
```

Pre-built wheels are available for Linux, macOS, and Windows. On other platforms pip
builds the bundled C compression extension from source, which needs a C compiler and
the Python development headers (the `python3-dev` package on Debian and Ubuntu).

To install from a checkout of this repository:

```sh
git clone https://github.com/theopolis/uefi-firmware-parser
cd uefi-firmware-parser
pip install .
```

## Command-line usage

Installing the package adds a `uefi-firmware-parser` command:

```console
$ uefi-firmware-parser -h
usage: uefi-firmware-parser [-h] [-b] [--superbrute] [--depex] [-q]
                            [--color {always,never,auto}] [-p] [-o OUTPUT]
                            [-O] [-c] [-e] [-g GENERATE] [-j] [--index]
                            [--test] [--verbose]
                            file [file ...]

Parse, and optionally output, details and data on UEFI-related firmware.

positional arguments:
  file                  The file(s) to work on

options:
  -h, --help            show this help message and exit
  -b, --brute           The input is a blob and may contain FV headers.
  --superbrute          The input is a blob and may contain any sort of
                        firmware object
  --depex               The input is a DEPEX blob
  -q, --quiet           Do not show info.
  --color {always,never,auto}
                        Control the use of ANSI colors in the output. (auto is
                        default)
  -p, --nocolor         Plain text output. Do not use ANSI colors. (Alias for
                        --color=never)
  -o, --output OUTPUT   Dump firmware objects to this folder.
  -O, --outputfolder    Dump firmware objects to a folder based on filename
                        ${FILENAME}_output/
  -c, --echo            Echo the filename before parsing or extracting.
  -e, --extract         Extract all files/sections/volumes.
  -g, --generate GENERATE
                        Generate a FDF, implies extraction (volumes only)
  -j, --json            Output in JSON format
  --index               List the structure without decoding compressed
                        branches
  --test                Test file parsing, output name/success.
  --verbose             Enable verbose logging while parsing
```

Use `--test` to identify the format of one or more files without parsing them fully:

```console
$ uefi-firmware-parser --test ~/firmware/*
~/firmware/E5X70-1.3.6.pfs: DellPFS
~/firmware/MBP111_0138_B16_LOCKED.scap: EFICapsule
~/firmware/Latitude-E6410-A10.flash: FlashDescriptor
~/firmware/ESX70-1.3.6.me: IntelME
~/firmware/MINNOW1.fd: UEFIFirmwareVolume
~/firmware/Dell-A02.rom: unknown
```

Run without `--test` to print the full object hierarchy, add `-j` for JSON instead
of the tree view, or add `-e -o DIR` to extract every volume, file, and section
into `DIR`.

A few options help with larger jobs:

- `-O` writes each input's output to its own `${FILENAME}_output/` folder, which is
  convenient when extracting many files at once.
- `--echo` prints each input filename before parsing, which helps when you grep the
  combined output.
- `-g FOLDER` dumps each firmware volume into `FOLDER`, with an FDF named after the
  volume (`volume-0.fdf`, for example) that refers to the dumped files. Sections the
  generator cannot describe appear in the FDF as comments.
- If `--test` reports `unknown`, the format checker did not find a known header at
  the start of the file. Try `-b` to search the blob for firmware volume headers, or
  `--superbrute` to try every known format at every byte offset. The latter is slow
  on large images.

```console
$ uefi-firmware-parser --test ~/firmware/Dell-A02.rom
~/firmware/Dell-A02.rom: unknown
$ uefi-firmware-parser --superbrute ~/firmware/Dell-A02.rom
[...]
```

## Python usage

The simplest way to detect and parse a file is the `AutoParser` class:

```python
import uefi_firmware

with open("/path/to/firmware.rom", "rb") as fh:
    data = fh.read()

parser = uefi_firmware.AutoParser(data)
if parser.type() != "unknown":
    firmware = parser.parse()
    firmware.showinfo()
```

The `uefi`, `pfs`, `me`, and `flash` modules contain classes for each format. Each
class takes the raw file contents in its constructor and implements:

- `process()` parses the data and returns `True` on success, `False` otherwise.
- `showinfo()` prints the object hierarchy.
- `to_dict()` returns the object hierarchy as a JSON-serializable `dict`.
- `dump()` walks the hierarchy and writes each object to a file.

### Deferred branches

A full parse decodes every compressed section it meets while it builds the tree.
When you only need a few drivers out of a large image, `index()` builds the same
tree without running the decoders. Compressed sections and GUID-defined wrappers
are listed with an `unexpanded` state and the bytes they were parsed from:

```python
parser = uefi_firmware.AutoParser(data)
firmware = parser.index()

# The tree has the usual shape; nothing below a compressed wrapper is decoded.
for branch in firmware.iter_unexpanded():
    print(branch.wrapper, branch.compression_kind, len(branch.raw_data))

# Decode just the branch you need. The result is cached, so a second call is free.
branch = firmware.iter_unexpanded().__next__()
branch.expand()
print(branch.subsections[0].data)

# Or decode everything, for the same tree parse() would have built.
firmware.expand_all()
```

`parse()` is still the full parser and is unchanged. `parse(lazy=True)` is the
same as `index()`, `AutoParser(data, lazy=True)` makes that the default, and
calling `parse()` on an instance that already has an index expands it. A class
used on its own, such as `FirmwareVolume(data).process(lazy=True)`, also builds
an index. Each object reports `parse_state`: `parsed` for a decoded branch (the
same state the full parser assigns), `unexpanded` for a known wrapper that has
not been decoded, `failed` for a branch whose decoder rejected its payload, and
`opaque` for a GUID-defined wrapper the parser has no rule for. `raw_data` keeps
the original bytes for any of these, and `to_index()` returns the structure as
nested dicts (`to_index_json()` leaves out the object references). The
`--index` command-line option prints the same list and `--index -j` prints it
as JSON.

A branch that fails to decode is never retried, and it is not shown as an empty
subtree: `parse_state`, `failed`, and `parse_error` say what happened while
`raw_data` keeps the input. Expanding the whole index gives the same objects,
`to_dict()` output, and dumps as `parse()`.

## Features

Supported formats:

- UEFI firmware volumes, capsules, file systems, files, and sections
- AMI Aptio signed and unsigned capsules
- Intel PCH flash descriptors and regions
- Intel ME modules and partition manifests (ME, TXE, and others)
- Dell PFS (HDR) updates
- DEPEX (dependency expression) blobs

Other capabilities:

- Tiano/EFI and LZMA compression and decompression, implemented in a bundled C extension
- JSON output of the parsed object hierarchy
- FDF (flash description file) generation from parsed firmware volumes
- Replacement of sections and files in a firmware volume by GUID

## Helper scripts

The `scripts/` directory in the repository contains a few tools that are not
installed with the package.

**GUID injection.** `scripts/fv_injector.py` replaces a section within a UEFI
firmware file, or a file within a firmware file system, identified by GUID. It can
only replace objects; it cannot add or remove them. When injecting into a firmware
file (`-f`), the script prompts you to choose which section to replace, so this mode
cannot be scripted yet.

The input is a firmware volume unless you pass `-c` for a capsule or `-p` for a Dell
PFS. The payload replaces the whole file, so it must include its FFS file header.
Compressed sections that contain the file are recompressed, and PFS sizes and
checksums are updated. Signatures are not, so a signed image will no longer verify.

```sh
python scripts/fv_injector.py --guid GUID --injection payload.efi -o patched.rom firmware.rom
```

**IDA labels.** `scripts/uefi_guids.py` lists the GUIDs found in a firmware image.
With `-g LABEL` it prints them as a Python dictionary that you can import into IDA
using Snare's plugins.

Run any script with `-h` for its full options.

## Tested vendors

The parser has been tested on BIOS, UEFI, and firmware updates from ASRock, Apple,
Dell, Gigabyte, HP, Intel, Lenovo, MSI, Qualcomm, and VMware. Not every update for
every product will parse. Some updates are wrapped in a vendor installer (usually a
PE executable) and need to be extracted or decompressed before the parser can read
them. The parser does unwrap Dell BIOS update executables, finding and
decompressing the PFS inside them.

## Development

Install the package in editable mode with the test dependencies:

```sh
pip install -e '.[tests]'
```

Run the unit tests the same way CI does:

```sh
cd tests
python -bb -m unittest discover
```

CI also runs the parser against the sample files in
[uefi-firmware-samples](https://github.com/theopolis/uefi-firmware-samples):

```sh
git clone https://github.com/theopolis/uefi-firmware-samples samples
cd samples
python -bb ./test_samples.py
```

Releases are published to PyPI automatically when a version tag is pushed. The
package version comes from the git tag through `setuptools-scm`.

## License

MIT. See [LICENSE](https://github.com/theopolis/uefi-firmware-parser/blob/main/LICENSE).

The bundled Tiano and LZMA compression code in `uefi_firmware/compression` keeps
its original licenses, which are given in each source file.
