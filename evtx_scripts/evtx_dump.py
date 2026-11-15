#!/usr/bin/env python
#    This file is part of python-evtx.
#
#   Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#   Version v0.1.1
import Evtx.Evtx as evtx
import Evtx.Views as e_views


def main():
    import argparse

    import Evtx.XmlEncoding as e_xml

    parser = argparse.ArgumentParser(description="Dump a binary EVTX file into XML.")
    parser.add_argument(
        "--mode",
        choices=(e_xml.STRICT_MODE, e_xml.DISPLAY_MODE),
        default=e_xml.STRICT_MODE,
        help=(
            "strict (default): reject records with unrepresentable XML characters and report the "
            "offending field; display: emit parser readable XML with an anomaly ledger that retains "
            "the raw data"
        ),
    )
    parser.add_argument("evtx", type=str, help="Path to the Windows EVTX event log file")
    args = parser.parse_args()

    with evtx.Evtx(args.evtx) as log:
        print(e_views.XML_HEADER)
        print("<Events>")
        for record in log.records():
            if args.mode == e_xml.DISPLAY_MODE:
                print(record.xml_display())
            else:
                print(record.xml())
        print("</Events>")


if __name__ == "__main__":
    main()
