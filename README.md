# Net::FTP

This class implements the File Transfer Protocol.  If you have used a
command-line FTP program, and are familiar with the commands, you will be
able to use this class easily.  Some extra features are included to take
advantage of Ruby's style and strengths.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'net-ftp'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install net-ftp

## Usage

### Example 1

```ruby
ftp = Net::FTP.new('example.com')
ftp.login
files = ftp.chdir('pub/lang/ruby/contrib')
files = ftp.list('n*')
ftp.getbinaryfile('nif.rb-0.91.gz', 'nif.gz', 1024)
ftp.close
```

### Example 2

```ruby
Net::FTP.open('example.com') do |ftp|
  ftp.login
  files = ftp.chdir('pub/lang/ruby/contrib')
  files = ftp.list('n*')
  ftp.getbinaryfile('nif.rb-0.91.gz', 'nif.gz', 1024)
end
```

### Dual-channel FTPS certificate policy

When the control and data endpoints use the same managed certificate, require
the data certificate to be identical to the authenticated control certificate:

```ruby
ftp = Net::FTP.new(
  "archive.example.test",
  ssl: true,
  certificate_policy: :same_certificate
)
```

When data connections are served by a separately issued gateway certificate,
approve that certificate, fingerprint, or a custom verifier:

```ruby
policy = Net::FTP::CertificatePolicy.new(
  relation: :same_or_approved,
  approved_data_certificates: [File.read("data-gateway.crt")]
)

ftp = Net::FTP.new(
  "archive.example.test",
  ssl: true,
  certificate_policy: policy,
  data_hostname: "data-gateway.example.test"
)
```

The policy runs after each data TLS handshake and before the first data block is
read or written. Every transfer is checked again. If a positive preliminary
reply (`150`/`125`) was received but the data certificate is rejected, rescue
`Net::FTP::DataChannelCertificateError` and inspect
`control_reply_finished?` and `reusable?`. Call `recover_control_reply` to read
the server's final reply; a completed `4xx`/`5xx` reply leaves the control
connection available for an ordinary command such as `NOOP`.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/ruby/net-ftp.
