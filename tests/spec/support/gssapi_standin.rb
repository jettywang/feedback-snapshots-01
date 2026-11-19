# Loads the offline GSSAPI stand-in instead of the real gem.
#
# Specs that exercise WinRM::HTTP::HttpGSSAPI add this directory to $LOAD_PATH,
# so `require 'gssapi'` resolves to tests/spec/support/gssapi_standin/gssapi.rb
# rather than the installed gem. No Kerberos installation, realm, or keytab is
# involved.
$LOAD_PATH.unshift(File.expand_path('gssapi_standin', __dir__))
require 'gssapi'
