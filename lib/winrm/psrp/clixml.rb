# Copyright 2016 Matt Wrock <matt@mattwrock.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

module WinRM
  module PSRP
    # Decodes the `_xHHHH_` character escapes that PowerShell writes into
    # CLIXML text (mirrors .NET System.Xml.XmlConvert.DecodeName semantics).
    #
    # Each token stands for one UTF-16 code unit, so a run of adjacent tokens
    # is interpreted together. That keeps surrogate pairs intact
    # (e.g. `_xD83D__xDE00_` => U+1F600) while an unpaired surrogate is
    # replaced with U+FFFD instead of raising.
    #
    # The input is text an XML parser already produced, so XML entities such as
    # `&lt;` have been resolved upstream and are never handled here. The text
    # is scanned exactly once left-to-right and the output is never re-scanned,
    # which is what allows a literal `_x0041_` (carried on the wire as
    # `_x005F_x0041_`) to round-trip correctly.
    module Clixml
      # A complete `_xHHHH_` token. The `/n` modifier keeps the pattern ASCII
      # byte oriented so match offsets are byte offsets even when the
      # surrounding literal text contains multibyte UTF-8 characters. Matching
      # only full tokens and consuming them in one left-to-right pass rules out
      # nested re-decoding.
      ESCAPE_PATTERN = Regexp.new('_x(\h{4})_', Regexp::NOENCODING).freeze

      # Written for code units that cannot form valid text (lone surrogates).
      REPLACEMENT_CHARACTER = "�".freeze

      class << self
        # Decode the CLIXML escapes in already XML-parsed text.
        # @param text [String, nil] UTF-8 text returned by an XML parser
        # @return [String, nil] UTF-8 text with escapes interpreted once
        def decode(text)
          return if text.nil?

          bytes = text.b
          result = +''.b
          code_units = []
          cursor = 0

          bytes.to_enum(:scan, ESCAPE_PATTERN).each do
            match = Regexp.last_match
            emit_literal(result, code_units, bytes, cursor, match.begin(0))
            code_units << match[1].hex
            cursor = match.end(0)
          end
          emit_literal(result, code_units, bytes, cursor, bytes.bytesize)
          flush(result, code_units)
          result.force_encoding('utf-8')
        end

        private

        def emit_literal(result, code_units, bytes, start, stop)
          return if start >= stop

          flush(result, code_units)
          result << bytes.byteslice(start, stop - start)
        end

        def flush(result, code_units)
          return if code_units.empty?

          result << transcode(code_units).b
          code_units.clear
        end

        def transcode(code_units)
          code_units.pack('S*').force_encoding('utf-16le').encode(
            'utf-8',
            invalid: :replace,
            undef: :replace,
            replace: REPLACEMENT_CHARACTER
          )
        end
      end
    end
  end
end
