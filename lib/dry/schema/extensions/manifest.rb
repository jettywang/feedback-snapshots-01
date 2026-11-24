# frozen_string_literal: true

# Opt-in extension installing `#manifest` on schema processors
#
# The data model lives in `dry/schema/manifest` and can be loaded on its own
# for offline verification:
#
#   require "dry/schema/manifest"
#   Dry::Schema::Manifest.verify(document)
#
# Loading this extension additionally makes `schema.manifest` available:
#
#   Dry::Schema.load_extensions(:manifest)
#
require "dry/schema/manifest"
require "dry/schema/manifest/schema_methods"
