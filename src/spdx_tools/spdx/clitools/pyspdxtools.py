#!/usr/bin/env python3

# Copyright (c) 2020 Yash Varshney
# Copyright (c) 2023 spdx contributors
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
import sys
from json import JSONDecodeError
from xml.parsers.expat import ExpatError
from xml.sax import SAXParseException

import click
from beartype.typing import List
from yaml.scanner import ScannerError

from spdx_tools.spdx.annotation_export import (
    AnnotationExportPolicy,
    export_annotations_for_sharing,
    load_annotation_export_policy,
    write_annotation_audit_file,
)
from spdx_tools.spdx.graph_generation import export_graph_from_document
from spdx_tools.spdx.model import Document
from spdx_tools.spdx.parser.error import SPDXParsingError
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.validation.validation_message import ValidationMessage
from spdx_tools.spdx.writer.tagvalue import tagvalue_writer
from spdx_tools.spdx.writer.write_anything import write_file


@click.command()
@click.option("--infile", "-i", required=True, help="The file containing the document to be validated or converted.")
@click.option(
    "--outfile",
    "-o",
    help="The file to write the converted document to (write a dash for output to stdout or omit for no conversion). "
    "If you add the option --graph to the command the generated graph will be written to this file.",
)
@click.option(
    "--version",
    help='The SPDX version to be used during parsing and validation ("SPDX-2.2" or "SPDX-2.3"). '
    "Will be read from the document if not provided.",
    default=None,
)
@click.option("--novalidation", is_flag=True, help="Don't validate the provided document.")
@click.option(
    "--graph",
    is_flag=True,
    default=False,
    help="Generate a relationship graph from the input file. "
    "The generated graph is saved to the file specified with --outfile. "
    "Note: You need to install the optional dependencies 'networkx' and 'pygraphviz' for this feature.",
)
@click.option(
    "--annotation-policy",
    "annotation_policy_file",
    default=None,
    help="JSON file describing which annotations are restricted and which fields may be exported. "
    "Restricted annotations keep their target SPDXID and are replaced by a stable audit reference.",
)
@click.option(
    "--annotation-audit-out",
    "annotation_audit_file",
    default=None,
    help="Write the internal-only mapping from stable annotation references back to the original "
    "records to this JSON file. This file must not be shared with the exported document.",
)
@click.option(
    "--annotation-redact-all",
    is_flag=True,
    default=False,
    help="Treat every annotation as restricted when exporting. Requires --annotation-policy for field selection "
    "or uses the default approved fields (annotation type, annotator and date).",
)
def main(
    infile: str,
    outfile: str,
    version: str,
    novalidation: bool,
    graph: bool,
    annotation_policy_file: str,
    annotation_audit_file: str,
    annotation_redact_all: bool,
):
    """
    CLI-tool for validating SPDX documents and converting between RDF, TAG-VALUE, JSON, YAML and XML formats.
    Formats are determined by the file endings.
    To use, run: 'pyspdxtools --infile <input file name> --outfile <output file name>'
    """
    try:
        document: Document = parse_file(infile)

        if not novalidation:
            if not version:
                version = document.creation_info.spdx_version

            if version not in ["SPDX-2.2", "SPDX-2.3"]:
                logging.error(f"This tool only supports SPDX versions SPDX-2.2 and SPDX-2.3, but got: {version}")
                sys.exit(1)

            validation_messages: List[ValidationMessage] = validate_full_spdx_document(document, version)
            if validation_messages:
                log_string = "\n".join(
                    ["The document is invalid. The following issues have been found:"]
                    + [message.validation_message for message in validation_messages]
                )
                logging.error(log_string)
                sys.exit(1)
            else:
                logging.info("The document is valid.")

        export_result = None
        if annotation_policy_file or annotation_redact_all or annotation_audit_file:
            if annotation_audit_file and not (annotation_policy_file or annotation_redact_all):
                logging.error("--annotation-audit-out requires --annotation-policy or --annotation-redact-all")
                sys.exit(1)
            if not outfile or outfile == "-":
                logging.error(
                    "--annotation-policy, --annotation-redact-all and --annotation-audit-out require --outfile "
                    "with a file name (not stdout)"
                )
                sys.exit(1)
            if graph:
                logging.error("annotation export options cannot be combined with --graph")
                sys.exit(1)

        if annotation_policy_file or annotation_redact_all:
            try:
                policy = (
                    load_annotation_export_policy(annotation_policy_file, require_selectors=not annotation_redact_all)
                    if annotation_policy_file
                    else AnnotationExportPolicy()
                )
            except ValueError as err:
                logging.error(f"Invalid annotation export policy: {err}")
                sys.exit(1)

            if annotation_redact_all:
                policy = AnnotationExportPolicy.restrict_all(
                    allowed_fields=policy.allowed_fields,
                    comment_template=policy.comment_template,
                    salt=policy.salt,
                    redacted_annotator=policy.redacted_annotator,
                    redacted_annotation_type=policy.redacted_annotation_type,
                    redacted_annotation_date=policy.redacted_annotation_date,
                )
            export_result = export_annotations_for_sharing(document, policy)
            document = export_result.document

            if not novalidation:
                validation_messages = validate_full_spdx_document(document, document.creation_info.spdx_version)
                if validation_messages:
                    log_string = "\n".join(
                        ["The exported document is invalid. The following issues have been found:"]
                        + [message.validation_message for message in validation_messages]
                    )
                    logging.error(log_string)
                    sys.exit(1)

        if outfile == "-":
            tagvalue_writer.write_document(document, sys.stdout)

        elif graph:
            try:
                export_graph_from_document(document, outfile)
            except ImportError:
                logging.error(
                    "To be able to draw a relationship graph of the parsed document "
                    "you need to install 'networkx' and 'pygraphviz'. Run 'pip install \".[graph_generation]\"'."
                )
                sys.exit(1)

        elif outfile:
            write_file(document, outfile, validate=False)
            if export_result is not None and annotation_audit_file:
                write_annotation_audit_file(export_result.audit_entries, annotation_audit_file)

    except NotImplementedError as err:
        logging.error(
            err.args[0]
            + "\nPlease note that this project is currently undergoing a major refactoring and therefore missing "
            "a few features which will be added in time (refer to https://github.com/spdx/tools-python/issues "
            "for insights into the current status).\n"
            "In the meantime, please use the current PyPI release version."
        )
        sys.exit(1)

    except SPDXParsingError as err:
        log_string = "\n".join(
            ["There have been issues while parsing the provided document:"]
            + [message for message in err.get_messages()]
        )
        logging.error(log_string)
        sys.exit(1)

    except JSONDecodeError as err:
        logging.error(f"Invalid JSON provided: {err.args[0]}")
        sys.exit(1)

    except ScannerError as err:
        logging.error("Invalid YAML provided: " + "\n".join([str(arg) for arg in err.args]))
        sys.exit(1)

    except ExpatError as err:
        logging.error(f"Invalid XML provided: {err.args[0]}")
        sys.exit(1)

    except SAXParseException as err:
        logging.error(f"Invalid RDF-XML provided: {str(err)}")
        sys.exit(1)

    except FileNotFoundError as err:
        logging.error(f"{err.strerror}: {err.filename}")
        sys.exit(1)


if __name__ == "__main__":
    main()
