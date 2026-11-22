require_relative '../spec_helper'

describe 'hash_public_cache plugin' do
  cache_file = "spec/tmp-hash-public-cache-#{$$}.json"

  before do
    app(:bare) do
      plugin :hash_public_cache, cache_file, root: 'spec/views'

      route do |r|
        hash_path(r.path_info[1..100])
      end
    end
  end

  after do
    File.delete(cache_file) if File.file?(cache_file)
  end

  it '.load_hash_public_cache_file loads the cache file' do
    File.write(cache_file, {"x" => "1"}.to_json)
    app.load_hash_public_cache_file
    body('/x').must_equal "/static/1/x"
  end

  it '.load_hash_public_cache_file handles case where file does not exist' do
    app.load_hash_public_cache_file
    body('/about.erb').must_equal "/static/zg5iunHNVtpPLbHhl02yuHOuZhIYC7KS8NgRiL7n9bU/about.erb"
  end

  it '.scan_hash_public_cache_dir scans public directory for files to calculate digests on' do
    app.scan_hash_public_cache_dir
    app.opts[:hash_public_cache]["about.erb"].must_equal "zg5iunHNVtpPLbHhl02yuHOuZhIYC7KS8NgRiL7n9bU"
    app.opts[:hash_public_cache].size.must_be :>, 1
  end

  it '.scan_hash_public_cache_dir does not rescan files that already have digests' do
    app.opts[:hash_public_cache]["about.erb"] = "1"
    app.scan_hash_public_cache_dir
    app.opts[:hash_public_cache]["about.erb"].must_equal "1"
    app.opts[:hash_public_cache].size.must_be :>, 1
  end

  it '.scan_hash_public_cache_dir respects block' do
    app.scan_hash_public_cache_dir{|f| f == "about.erb"}
    app.opts[:hash_public_cache]["about.erb"].must_equal "zg5iunHNVtpPLbHhl02yuHOuZhIYC7KS8NgRiL7n9bU"
    app.opts[:hash_public_cache].size.must_equal 1
  end

  it '.dump_hash_public_cache_file dumps cache to file' do
    app.opts[:hash_public_cache]["about.erb"] = "1"
    app.dump_hash_public_cache_file
    JSON.parse(File.read(cache_file)).must_equal({"about.erb" => "1"})
  end

  it '.load_hash_public_cache_file works as expected after .scan_hash_public_cache_dir and .dump_hash_public_cache_file' do
    app.scan_hash_public_cache_dir{|f| f == "about.erb"}
    app.opts[:hash_public_cache]["about.erb"].must_equal "zg5iunHNVtpPLbHhl02yuHOuZhIYC7KS8NgRiL7n9bU"
    app.opts[:hash_public_cache].size.must_equal 1
    app.dump_hash_public_cache_file
    app.opts[:hash_public_cache].clear
    app.load_hash_public_cache_file
    app.opts[:hash_public_cache]["about.erb"].must_equal "zg5iunHNVtpPLbHhl02yuHOuZhIYC7KS8NgRiL7n9bU"
    app.opts[:hash_public_cache].size.must_equal 1
  end
end

describe 'hash_public_cache plugin release publishing' do
  require 'fileutils'
  require 'tmpdir'

  def write_file(dir, path, content)
    file = File.join(dir, path)
    FileUtils.mkdir_p(File.dirname(file))
    File.write(file, content)
    file
  end

  def digest(content)
    d = OpenSSL::Digest::SHA256.base64digest(content)
    d.chomp!('=')
    d.tr!('+/', '-_')
    d
  end

  def build_app(cache_file, root, opts={})
    app(:bare) do
      plugin :hash_public_cache, cache_file, **{:root=>root}.merge(opts)

      route do |r|
        r.hash_public
        r.get('digest'){ hash_path('app.css') }
      end
    end
  end

  it 'publishes one of two prepared directories and keeps old addresses bound to old content' do
    Dir.mktmpdir do |dir|
      release_a = File.join(dir, 'release-a')
      release_b = File.join(dir, 'release-b')
      write_file(release_a, 'app.css', 'body { color: red }')
      write_file(release_b, 'app.css', 'body { color: blue }')
      cache_file = File.join(dir, 'cache.json')

      build_app(cache_file, release_a)
      app.publish_hash_public_cache(release_a).must_equal true

      old_digest = digest('body { color: red }')
      body("/static/#{old_digest}/app.css").must_equal 'body { color: red }'
      body('/digest').must_equal "/static/#{old_digest}/app.css"

      app.publish_hash_public_cache(release_b).must_equal true

      new_digest = digest('body { color: blue }')
      body('/digest').must_equal "/static/#{new_digest}/app.css"
      body("/static/#{new_digest}/app.css").must_equal 'body { color: blue }'

      # The old address must not start serving the new content.
      status("/static/#{old_digest}/app.css").must_equal 404
    end
  end

  it 'keeps the previous release active when a candidate directory cannot be fully read' do
    Dir.mktmpdir do |dir|
      release_a = File.join(dir, 'release-a')
      release_b = File.join(dir, 'release-b')
      write_file(release_a, 'app.css', 'old content')
      write_file(release_b, 'app.css', 'new content')
      unreadable = write_file(release_b, 'locked.css', 'secret')
      cache_file = File.join(dir, 'cache.json')

      build_app(cache_file, release_a)
      app.publish_hash_public_cache(release_a).must_equal true
      old_digest = digest('old content')

      File.chmod(0o000, unreadable)
      begin
        app.publish_hash_public_cache(release_b).must_equal false
      ensure
        File.chmod(0o644, unreadable)
      end

      # Previous release still served, and nothing from the failed candidate
      # became visible.
      body("/static/#{old_digest}/app.css").must_equal 'old content'
      status("/static/#{digest('new content')}/app.css").must_equal 404
      status("/static/#{digest('secret')}/locked.css").must_equal 404
      app.public_root.must_equal File.expand_path(release_a)
    end
  end

  it 'does not install a verified cache file when one entry is unreadable' do
    Dir.mktmpdir do |dir|
      release_a = File.join(dir, 'release-a')
      release_b = File.join(dir, 'release-b')
      write_file(release_a, 'app.css', 'old content')
      unreadable = write_file(release_b, 'app.css', 'new content')
      cache_file = File.join(dir, 'cache.json')

      build_app(cache_file, release_a)
      app.publish_hash_public_cache(release_a).must_equal true
      old_digest = digest('old content')

      File.write(cache_file, { 'app.css' => digest('new content') }.to_json)
      File.chmod(0o000, unreadable)
      begin
        app.verify_hash_public_cache_file(cache_file, root: release_b).must_equal false
        app.load_hash_public_cache_file(root: release_b).must_equal false
      ensure
        File.chmod(0o644, unreadable)
      end

      body("/static/#{old_digest}/app.css").must_equal 'old content'
      status("/static/#{digest('new content')}/app.css").must_equal 404
    end
  end

  it 'refuses manifests with mismatched digests or unsafe paths' do
    Dir.mktmpdir do |dir|
      release = File.join(dir, 'release')
      write_file(release, 'app.css', 'content')
      cache_file = File.join(dir, 'cache.json')

      build_app(cache_file, release)
      app.verify_hash_public_cache({ 'app.css' => 'wrong' }, root: release).must_equal false
      app.verify_hash_public_cache({ '../outside.css' => digest('x') }, root: release).must_equal false
      app.verify_hash_public_cache({ '/etc/passwd' => digest('x') }, root: release).must_equal false
      app.install_hash_public_cache({ 'app.css' => 'wrong' }, root: release).must_equal false

      app.verify_hash_public_cache({ 'app.css' => digest('content') }, root: release).must_equal true
      app.hash_public_cache.must_equal({})
    end
  end

  it 'rejects symbolic links that resolve outside the release directory' do
    Dir.mktmpdir do |dir|
      release = File.join(dir, 'release')
      outside = File.join(dir, 'outside.css')
      File.write(outside, 'outside')
      write_file(release, 'app.css', 'content')
      File.symlink(outside, File.join(release, 'linked.css'))
      cache_file = File.join(dir, 'cache.json')

      build_app(cache_file, release)
      app.verify_hash_public_release(release).must_equal false
      app.publish_hash_public_cache(release).must_equal false
      app.hash_public_cache.must_equal({})
    end
  end

  it 'switches to the new release and immediately retires the old addresses' do
    Dir.mktmpdir do |dir|
      release_a = File.join(dir, 'release-a')
      release_b = File.join(dir, 'release-b')
      write_file(release_a, 'app.css', 'old')
      write_file(release_a, 'extra.js', 'extra-old')
      write_file(release_b, 'app.css', 'new')
      cache_file = File.join(dir, 'cache.json')

      build_app(cache_file, release_a)
      app.publish_hash_public_cache(release_a).must_equal true
      old_css = digest('old')
      old_js = digest('extra-old')
      body("/static/#{old_css}/app.css").must_equal 'old'
      body("/static/#{old_js}/extra.js").must_equal 'extra-old'

      app.publish_hash_public_cache(release_b).must_equal true
      new_css = digest('new')

      # The new release is served, and files that were only in the old release
      # are no longer served under any address.
      body("/static/#{new_css}/app.css").must_equal 'new'
      status("/static/#{old_css}/app.css").must_equal 404
      status("/static/#{old_js}/extra.js").must_equal 404

      # A digest that never appeared in the new manifest is not accepted for
      # a file that does exist in the new release.
      status("/static/#{old_css}/../#{new_css}/app.css").must_equal 404
      status("/static/#{digest('new')}/extra.js").must_equal 404
    end
  end

  it 'leaves the existing cache intact when a scan hits an unreadable file' do
    Dir.mktmpdir do |dir|
      release = File.join(dir, 'release')
      write_file(release, 'app.css', 'content')
      unreadable = write_file(release, 'locked.css', 'secret')
      cache_file = File.join(dir, 'cache.json')

      build_app(cache_file, release)
      app.opts[:hash_public_cache]['seed'] = 'seed-digest'
      before = app.hash_public_cache.dup

      File.chmod(0o000, unreadable)
      begin
        app.scan_hash_public_cache_dir.must_equal false
      ensure
        File.chmod(0o644, unreadable)
      end

      app.hash_public_cache.must_equal before
    end
  end

  it 'writes the cache file atomically and leaves no temporary file' do
    Dir.mktmpdir do |dir|
      release = File.join(dir, 'release')
      write_file(release, 'app.css', 'content')
      cache_file = File.join(dir, 'cache.json')

      build_app(cache_file, release)
      app.scan_hash_public_cache_dir
      app.dump_hash_public_cache_file

      parsed = JSON.parse(File.read(cache_file))
      parsed['app.css'].must_equal digest('content')
      Dir[File.join(dir, 'cache.json.tmp*')].must_be_empty
    end
  end
end

describe 'hash_public_cache plugin atomic release switching' do
  require 'fileutils'
  require 'tmpdir'

  def write_file(dir, path, content)
    file = File.join(dir, path)
    FileUtils.mkdir_p(File.dirname(file))
    File.write(file, content)
    file
  end

  def digest(content)
    d = OpenSSL::Digest::SHA256.base64digest(content)
    d.chomp!('=')
    d.tr!('+/', '-_')
    d
  end

  def release_app(cache_file, root)
    app(:bare) do
      plugin :hash_public_cache, cache_file, root: root

      route do |r|
        r.hash_public
        r.get('digest'){ hash_path('app.css') }
      end
    end
  end

  it 'switches a served release only after the complete manifest verifies' do
    Dir.mktmpdir do |dir|
      a = File.join(dir, 'a')
      b = File.join(dir, 'b')
      write_file(a, 'app.css', 'A')
      write_file(b, 'app.css', 'B')
      cache_file = File.join(dir, 'cache.json')

      release_app(cache_file, a)
      app.publish_hash_public_cache(a).must_equal true
      a_digest = digest('A')
      body("/static/#{a_digest}/app.css").must_equal 'A'

      # A candidate with a mismatched manifest digest is rejected.
      app.install_hash_public_cache({ 'app.css' => 'not-the-digest' }, root: b).must_equal false
      body("/static/#{a_digest}/app.css").must_equal 'A'
      status("/static/#{digest('B')}/app.css").must_equal 404

      # The same release can be switched by a verified cache file.
      File.write(cache_file, { 'app.css' => digest('B') }.to_json)
      app.load_hash_public_cache_file(root: b).must_equal true
      body("/static/#{digest('B')}/app.css").must_equal 'B'

      # The old content-hashed address no longer resolves to new content.
      status("/static/#{a_digest}/app.css").must_equal 404
    end
  end

  it 'requires a complete manifest before switching' do
    Dir.mktmpdir do |dir|
      a = File.join(dir, 'a')
      b = File.join(dir, 'b')
      write_file(a, 'app.css', 'A')
      write_file(b, 'app.css', 'B')
      write_file(b, 'missing.css', 'M')
      cache_file = File.join(dir, 'cache.json')

      release_app(cache_file, a)
      app.publish_hash_public_cache(a).must_equal true

      # Manifest names a file that does not exist in the candidate directory.
      app.install_hash_public_cache(
        { 'app.css' => digest('B'), 'missing.css' => digest('M'), 'absent.css' => digest('X') },
        root: b
      ).must_equal false

      body("/static/#{digest('A')}/app.css").must_equal 'A'
    end
  end
end

describe 'hash_public_cache plugin candidate verification' do
  require 'fileutils'
  require 'tmpdir'

  def write_file(dir, path, content)
    file = File.join(dir, path)
    FileUtils.mkdir_p(File.dirname(file))
    File.write(file, content)
    file
  end

  def digest(content)
    d = OpenSSL::Digest::SHA256.base64digest(content)
    d.chomp!('=')
    d.tr!('+/', '-_')
    d
  end

  it 'verifies a candidate while continuing to serve the current release' do
    Dir.mktmpdir do |dir|
      a = File.join(dir, 'a')
      b = File.join(dir, 'b')
      write_file(a, 'app.css', 'A')
      write_file(b, 'app.css', 'B')
      cache_file = File.join(dir, 'cache.json')

      app(:bare) do
        plugin :hash_public_cache, cache_file, root: a

        route do |r|
          r.hash_public
          r.get('digest'){ hash_path('app.css') }
        end
      end

      app.publish_hash_public_cache(a).must_equal true

      # The candidate is verified against its own manifest without changing
      # what is currently served.
      app.verify_hash_public_release(b, manifest: { 'app.css' => digest('B') }).must_equal true
      body("/static/#{digest('A')}/app.css").must_equal 'A'
      app.public_root.must_equal File.expand_path(a)

      # The same candidate is then installed; only now does the served release
      # change.
      app.publish_hash_public_cache(b, manifest: { 'app.css' => digest('B') }).must_equal true
      body("/static/#{digest('B')}/app.css").must_equal 'B'
      status("/static/#{digest('A')}/app.css").must_equal 404
    end
  end

  it 'does not switch when the candidate verification fails' do
    Dir.mktmpdir do |dir|
      a = File.join(dir, 'a')
      b = File.join(dir, 'b')
      write_file(a, 'app.css', 'A')
      write_file(b, 'app.css', 'B')
      unreadable = write_file(b, 'locked.css', 'L')
      cache_file = File.join(dir, 'cache.json')

      app(:bare) do
        plugin :hash_public_cache, cache_file, root: a

        route do |r|
          r.hash_public
          r.get('digest'){ hash_path('app.css') }
        end
      end
      app.publish_hash_public_cache(a).must_equal true

      File.chmod(0o000, unreadable)
      begin
        app.verify_hash_public_release(b).must_equal false
        app.publish_hash_public_cache(b).must_equal false
      ensure
        File.chmod(0o644, unreadable)
      end

      app.public_root.must_equal File.expand_path(a)
      body("/static/#{digest('A')}/app.css").must_equal 'A'
      status("/static/#{digest('B')}/app.css").must_equal 404
      status("/static/#{digest('L')}/locked.css").must_equal 404
    end
  end
end

describe 'hash_public_cache plugin frozen applications' do
  require 'fileutils'
  require 'tmpdir'

  def write_file(dir, path, content)
    file = File.join(dir, path)
    FileUtils.mkdir_p(File.dirname(file))
    File.write(file, content)
    file
  end

  def digest(content)
    d = OpenSSL::Digest::SHA256.base64digest(content)
    d.chomp!('=')
    d.tr!('+/', '-_')
    d
  end

  it 'switches a release on a frozen application' do
    Dir.mktmpdir do |dir|
      a = File.join(dir, 'a')
      b = File.join(dir, 'b')
      write_file(a, 'app.css', 'A')
      write_file(b, 'app.css', 'B')
      cache_file = File.join(dir, 'cache.json')

      app(:bare) do
        plugin :hash_public_cache, cache_file, root: a
        plugin :freeze_request_response

        route do |r|
          r.hash_public
          r.get('digest'){ hash_path('app.css') }
        end

        freeze
      end

      app.publish_hash_public_cache(a).must_equal true
      body("/static/#{digest('A')}/app.css").must_equal 'A'

      app.publish_hash_public_cache(b).must_equal true
      body("/static/#{digest('B')}/app.css").must_equal 'B'
      status("/static/#{digest('A')}/app.css").must_equal 404
    end
  end
end

describe 'hash_public_cache plugin generation binding' do
  require 'fileutils'
  require 'tmpdir'

  def write_file(dir, path, content)
    file = File.join(dir, path)
    FileUtils.mkdir_p(File.dirname(file))
    File.write(file, content)
    file
  end

  def digest(content)
    d = OpenSSL::Digest::SHA256.base64digest(content)
    d.chomp!('=')
    d.tr!('+/', '-_')
    d
  end

  it 'uses a single release generation for the manifest and served files' do
    Dir.mktmpdir do |dir|
      a = File.join(dir, 'a')
      b = File.join(dir, 'b')
      write_file(a, 'app.css', 'A')
      write_file(b, 'app.css', 'B')
      cache_file = File.join(dir, 'cache.json')

      app(:bare) do
        plugin :hash_public_cache, cache_file, root: a

        route do |r|
          r.hash_public
          r.get('digest'){ hash_path('app.css') }
        end
      end

      app.publish_hash_public_cache(a)
      gen = app.hash_public_generation
      gen[:root].must_equal File.expand_path(a)

      app.publish_hash_public_cache(b)
      new_gen = app.hash_public_generation
      new_gen.wont_be_same_as gen

      # The old generation object keeps pointing at the old root and manifest.
      gen[:root].must_equal File.expand_path(a)
      gen[:release]['app.css'].must_equal digest('A')
      new_gen[:root].must_equal File.expand_path(b)
      new_gen[:release]['app.css'].must_equal digest('B')

      # Only the installed generation's addresses are served.
      status("/static/#{digest('A')}/app.css").must_equal 404
      body("/static/#{digest('B')}/app.css").must_equal 'B'
    end
  end
end

describe 'hash_public_cache plugin symlinked release roots' do
  require 'fileutils'
  require 'tmpdir'

  def write_file(dir, path, content)
    file = File.join(dir, path)
    FileUtils.mkdir_p(File.dirname(file))
    File.write(file, content)
    file
  end

  def digest(content)
    d = OpenSSL::Digest::SHA256.base64digest(content)
    d.chomp!('=')
    d.tr!('+/', '-_')
    d
  end

  it 'publishes a release directory reached through a symbolic link' do
    Dir.mktmpdir do |dir|
      real = File.join(dir, 'releases', '1')
      link = File.join(dir, 'current')
      write_file(real, 'app.css', 'linked')
      File.symlink(real, link)
      cache_file = File.join(dir, 'cache.json')

      app(:bare) do
        plugin :hash_public_cache, cache_file, root: link

        route do |r|
          r.hash_public
        end
      end

      app.publish_hash_public_cache(link).must_equal true
      body("/static/#{digest('linked')}/app.css").must_equal 'linked'
    end
  end

  it 'treats an empty candidate directory as incomplete' do
    Dir.mktmpdir do |dir|
      release = File.join(dir, 'release')
      FileUtils.mkdir_p(release)
      cache_file = File.join(dir, 'cache.json')

      app(:bare) do
        plugin :hash_public_cache, cache_file, root: release

        route do |r|
          r.hash_public
        end
      end

      app.publish_hash_public_cache(release).must_equal false
      app.verify_hash_public_release(release).must_equal false
    end
  end
end

describe 'hash_public_cache plugin HEAD requests' do
  require 'fileutils'
  require 'tmpdir'

  def write_file(dir, path, content)
    file = File.join(dir, path)
    FileUtils.mkdir_p(File.dirname(file))
    File.write(file, content)
    file
  end

  def digest(content)
    d = OpenSSL::Digest::SHA256.base64digest(content)
    d.chomp!('=')
    d.tr!('+/', '-_')
    d
  end

  it 'does not serve a published path for HEAD without the head plugin' do
    Dir.mktmpdir do |dir|
      release = File.join(dir, 'release')
      write_file(release, 'app.css', 'content')
      cache_file = File.join(dir, 'cache.json')

      app(:bare) do
        plugin :hash_public_cache, cache_file, root: release

        route do |r|
          r.hash_public
        end
      end

      app.publish_hash_public_cache(release).must_equal true
      status("/static/#{digest('content')}/app.css", 'REQUEST_METHOD'=>'HEAD').must_equal 404
    end
  end

  it 'serves a published path for HEAD with the head plugin' do
    Dir.mktmpdir do |dir|
      release = File.join(dir, 'release')
      write_file(release, 'app.css', 'content')
      cache_file = File.join(dir, 'cache.json')

      app(:bare) do
        plugin :head
        plugin :hash_public_cache, cache_file, root: release

        route do |r|
          r.hash_public
        end
      end

      app.publish_hash_public_cache(release).must_equal true
      s, h, b = req("/static/#{digest('content')}/app.css", 'REQUEST_METHOD'=>'HEAD')
      s.must_equal 200
      h['content-length'].must_equal '7'
      b.must_equal []
    end
  end
end
