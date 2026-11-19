require_relative '../common'
require 'net/ssh/authentication/ed25519_loader'
require 'net/ssh/key_factory'
require 'base64'

module Authentication
  class TestED25519 < NetSSHTest
    def setup
      skip "Ed25519 is not available" unless Net::SSH::Authentication::ED25519Loader::LOADED
    end

    def test_no_pwd_key
      pub = Net::SSH::Buffer.new(Base64.decode64(public_key_no_pwd.split(' ')[1]))
      _type = pub.read_string
      pub_data = pub.read_string
      priv = private_key_no_pwd

      pub_key = Net::SSH::Authentication::ED25519::PubKey.new(pub_data)
      priv_key = Net::SSH::Authentication::ED25519::PrivKey.read(priv, nil)

      shared_secret = "Hello"
      signed = priv_key.ssh_do_sign(shared_secret)
      self.assert_equal(true, pub_key.ssh_do_verify(signed, shared_secret))
      self.assert_equal(priv_key.public_key.fingerprint, pub_key.fingerprint)
      self.assert_equal(pub_key.fingerprint, key_fingerprint_md5_no_pwd)
      self.assert_equal(pub_key.fingerprint('sha256'), key_fingerprint_sha256_no_pwd)
    end

    def test_no_pwd_key_with_newlines
      pub = Net::SSH::Buffer.new(Base64.decode64(public_key_no_pwd.split(' ')[1]))
      _type = pub.read_string
      pub_data = pub.read_string
      priv = private_key_no_pwd_with_newlines

      pub_key = Net::SSH::Authentication::ED25519::PubKey.new(pub_data)
      priv_key = Net::SSH::Authentication::ED25519::PrivKey.read(priv, nil)

      shared_secret = "Hello"
      signed = priv_key.ssh_do_sign(shared_secret)
      self.assert_equal(true, pub_key.ssh_do_verify(signed, shared_secret))
      self.assert_equal(priv_key.public_key.fingerprint, pub_key.fingerprint)
      self.assert_equal(pub_key.fingerprint, key_fingerprint_md5_no_pwd)
      self.assert_equal(pub_key.fingerprint('sha256'), key_fingerprint_sha256_no_pwd)
    end

    def test_no_pwd_key_with_windows_newlines
      pub = Net::SSH::Buffer.new(Base64.decode64(public_key_no_pwd.split(' ')[1]))
      _type = pub.read_string
      pub_data = pub.read_string
      priv = private_key_no_pwd_with_windows_newlines

      pub_key = Net::SSH::Authentication::ED25519::PubKey.new(pub_data)
      priv_key = Net::SSH::Authentication::ED25519::PrivKey.read(priv, nil)

      shared_secret = "Hello"
      signed = priv_key.ssh_do_sign(shared_secret)
      self.assert_equal(true, pub_key.ssh_do_verify(signed, shared_secret))
      self.assert_equal(priv_key.public_key.fingerprint, pub_key.fingerprint)
      self.assert_equal(pub_key.fingerprint, key_fingerprint_md5_no_pwd)
      self.assert_equal(pub_key.fingerprint('sha256'), key_fingerprint_sha256_no_pwd)
    end

    def test_pwd_key
      if defined?(JRUBY_VERSION)
        puts "Skipping password protected ED25519 for JRuby"
        return
      end
      pub = Net::SSH::Buffer.new(Base64.decode64(public_key_pwd.split(' ')[1]))
      _type = pub.read_string
      pub_data = pub.read_string
      priv = private_key_pwd

      pub_key = Net::SSH::Authentication::ED25519::PubKey.new(pub_data)
      priv_key = Net::SSH::Authentication::ED25519::PrivKey.read(priv, 'pwd')

      shared_secret = "Hello"
      signed = priv_key.ssh_do_sign(shared_secret)
      self.assert_equal(true, pub_key.ssh_do_verify(signed, shared_secret))
      self.assert_equal(priv_key.public_key.fingerprint, pub_key.fingerprint)
      self.assert_equal(pub_key.fingerprint, key_fingerprint_md5_pwd)
      self.assert_equal(pub_key.fingerprint('sha256'), key_fingerprint_sha256_pwd)
    end

    def test_aes128_gcm_pwd_key
      assert_pwd_key_matches_public_key(private_key_aes128_gcm_pwd, public_key_aes128_gcm_pwd)
    end

    def test_aes256_gcm_pwd_key
      assert_pwd_key_matches_public_key(private_key_aes256_gcm_pwd, public_key_aes256_gcm_pwd)
    end

    def test_chacha20_poly1305_pwd_key
      skip "chacha20-poly1305@openssh.com is not available" unless
        Net::SSH::Transport::ChaCha20Poly1305CipherLoader::LOADED

      assert_pwd_key_matches_public_key(private_key_chacha20_poly1305_pwd, public_key_chacha20_poly1305_pwd)
    end

    def test_aead_pwd_key_with_wrong_password_is_retryable
      skip "chacha20-poly1305@openssh.com is not available" unless
        Net::SSH::Transport::ChaCha20Poly1305CipherLoader::LOADED

      error = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::DecryptError) do
        Net::SSH::Authentication::ED25519::PrivKey.read(private_key_chacha20_poly1305_pwd, 'wrong')
      end

      assert error.encrypted_key?
    end

    def test_no_pwd_key_does_not_require_bcrypt_pbkdf
      Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader.expects(:require_bcrypt_pbkdf).never

      Net::SSH::Authentication::ED25519::PrivKey.read(private_key_no_pwd, nil)
    end

    def test_pwd_key_without_bcrypt_pbkdf_raises_targeted_decrypt_error
      Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader.expects(:require_bcrypt_pbkdf)
                                                                .raises(LoadError)

      error = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::DecryptError) do
        Net::SSH::Authentication::ED25519::PrivKey.read(private_key_pwd, 'pwd')
      end

      refute error.encrypted_key?
      assert_match(/bcrypt_pbkdf is required/, error.message)
    end

    def test_pwd_key_without_bcrypt_pbkdf_does_not_prompt_for_more_passphrases
      Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader.expects(:require_bcrypt_pbkdf)
                                                                .raises(LoadError)
      prompt = mock('prompt')
      prompt.expects(:start).never

      error = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::DecryptError) do
        Net::SSH::KeyFactory.load_data_private_key(private_key_pwd, nil, true, '', prompt)
      end

      refute error.encrypted_key?
      assert_match(/bcrypt_pbkdf is required/, error.message)
    end

    def test_pwd_key_should_ask
      pub = Net::SSH::Buffer.new(Base64.decode64(public_key_pwd.split(' ')[1]))
      _type = pub.read_string
      pub_data = pub.read_string
      priv = private_key_pwd

      prompt = OpenStruct.new
      def prompt.start(opts)
        prompter = OpenStruct.new
        def prompter.ask(*opts)
          return "pwd"
        end
        prompter
      end

      pub_key = Net::SSH::Authentication::ED25519::PubKey.new(pub_data)
      priv_key = Net::SSH::KeyFactory.load_data_private_key(priv, nil, true, "", prompt)

      shared_secret = "Hello"
      signed = priv_key.ssh_do_sign(shared_secret)
      self.assert_equal(true, pub_key.ssh_do_verify(signed, shared_secret))
      self.assert_equal(priv_key.public_key.fingerprint, pub_key.fingerprint)
      self.assert_equal(pub_key.fingerprint, key_fingerprint_md5_pwd)
      self.assert_equal(pub_key.fingerprint('sha256'), key_fingerprint_sha256_pwd)
    end

    def test_pwd_key_blank
      self.assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::DecryptError) do
        Net::SSH::Authentication::ED25519::PrivKey.read(private_key_no_rounds, '')
      end
    end

    def test_priv_key_no_rounds_should_raise
      self.assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::DecryptError) do
        Net::SSH::Authentication::ED25519::PrivKey.read(private_key_no_rounds, 'pwd')
      end
    end

    def test_key_with_too_many_bcrypt_rounds_is_rejected_without_running_the_kdf
      Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader.expects(:bcrypt_pbkdf_key).never

      error = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::KdfBudgetError) do
        Net::SSH::Authentication::ED25519::PrivKey.read(private_key_max_rounds, 'pwd')
      end
      assert_equal 4294967295, error.rounds
      assert_equal Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::DEFAULT_MAX_KDF_ROUNDS, error.limit
      refute error.retryable?
      assert_match(/rounds 4294967295 exceeds/, error.message)
    end

    def test_configurable_kdf_budget_rejects_normal_rounds_without_derivation
      # The encrypted fixture uses 16 rounds; a smaller configured budget must
      # refuse it before bcrypt_pbkdf runs, even though it is under the default cap.
      Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader.expects(:bcrypt_pbkdf_key).never

      error = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::KdfBudgetError) do
        Net::SSH::Authentication::ED25519::PrivKey.read(private_key_pwd, 'pwd', max_kdf_rounds: 15)
      end
      assert_equal 16, error.rounds
      assert_equal 15, error.limit
      refute error.retryable?
    end

    def test_kdf_budget_at_or_above_rounds_still_derives_the_key
      counting_real_kdf_derivations do |counter|
        key = Net::SSH::Authentication::ED25519::PrivKey.read(private_key_pwd, 'pwd', max_kdf_rounds: 16)
        assert_equal "ssh-ed25519", key.ssh_type
        assert_equal 1, counter[:calls]
      end
    end

    def test_unsupported_cipher_is_classified_as_unsupported_format
      error = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::UnsupportedFormatError) do
        Net::SSH::Authentication::ED25519::PrivKey.read(openssh_key_with_cipher("aes999-cbc"), 'pwd')
      end
      refute error.retryable?
      assert_match(/aes999-cbc.*not supported/, error.message)
    end

    def test_unsupported_kdf_is_classified_as_unsupported_format
      error = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::UnsupportedFormatError) do
        Net::SSH::Authentication::ED25519::PrivKey.read(openssh_key_with_kdf("pbkdf2"), 'pwd')
      end
      refute error.retryable?
    end

    def test_bad_magic_is_classified_as_malformed
      raw = openssh_raw(private_key_pwd)
      raw.setbyte(0, raw.getbyte(0) ^ 0xFF)
      error = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::MalformedKeyError) do
        Net::SSH::Authentication::ED25519::PrivKey.read(wrap_openssh_container(raw), 'pwd')
      end
      refute error.retryable?
    end

    def test_truncated_container_is_classified_as_malformed
      truncated = wrap_openssh_container(openssh_raw(private_key_pwd).byteslice(0, 40))
      error = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::MalformedKeyError) do
        Net::SSH::Authentication::ED25519::PrivKey.read(truncated, 'pwd')
      end
      refute error.retryable?
    end

    def test_garbage_payload_is_classified_as_malformed
      error = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::MalformedKeyError) do
        Net::SSH::Authentication::ED25519::PrivKey.read(wrap_openssh_container("\x00\x01\x02"), 'pwd')
      end
      refute error.retryable?
    end

    def test_unsupported_inner_key_type_is_unsupported_format
      inner = Net::SSH::Buffer.from(:long, 1, :long, 1, :string, "ssh-xyz-unsupported", :string, "x").to_s
      public_section = Net::SSH::Buffer.from(:string, "ssh-xyz-unsupported", :string, "x").to_s
      body = Net::SSH::Buffer.from(
        :string, "none", :string, "none", :string, "".b, :long, 1, :string, public_section,
        :long, inner.bytesize, :raw, inner
      ).to_s
      key_text = wrap_openssh_container("openssh-key-v1\x00".b + body)

      error = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::UnsupportedFormatError) do
        Net::SSH::Authentication::ED25519::PrivKey.read(key_text, nil)
      end
      refute error.retryable?
      assert_match(/ssh-xyz-unsupported/, error.message)
    end

    def test_correct_passphrase_but_corrupt_inner_key_is_malformed_and_runs_the_kdf_once
      counting_real_kdf_derivations do |counter|
        error = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::MalformedKeyError) do
          Net::SSH::Authentication::ED25519::PrivKey.read(corrupted_encrypted_private_key, 'pwd')
        end
        refute error.retryable?
        assert_equal 1, counter[:calls]
        # Error text must describe the structural problem without exposing key bytes.
        refute_match(/BEGIN OPENSSH PRIVATE KEY/, error.message)
      end
    end

    def test_structural_errors_are_not_reprompted_even_with_a_correct_passphrase
      prompt = CountingPrompt.new('pwd')

      # Supply the correct passphrase up front: the KDF runs and decryption
      # succeeds, but the decoded inner key is corrupt. A missing-passphrase
      # prompt must not be conflated with that structural failure, so no prompt
      # should ever be shown.
      assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::MalformedKeyError) do
        Net::SSH::KeyFactory.load_data_private_key(corrupted_encrypted_private_key, 'pwd', true, '', prompt)
      end
      assert_equal 0, prompt.asks
    end

    def test_structural_errors_stop_the_retry_loop_after_the_first_wrong_passphrase
      prompt = CountingPrompt.new('pwd')

      # The first attempt has no passphrase (one prompt), then the supplied
      # passphrase decrypts successfully but reveals a corrupt key: the loop
      # stops instead of burning the remaining two tries.
      assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::MalformedKeyError) do
        Net::SSH::KeyFactory.load_data_private_key(corrupted_encrypted_private_key, nil, true, '', prompt)
      end
      assert_equal 1, prompt.asks
    end

    def test_unencrypted_corrupt_key_is_malformed_and_never_prompts
      prompt = CountingPrompt.new('pwd')

      assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::MalformedKeyError) do
        Net::SSH::KeyFactory.load_data_private_key(corrupted_unencrypted_private_key, nil, true, '', prompt)
      end
      assert_equal 0, prompt.asks
    end

    def test_wrong_passphrase_is_reprompted_three_times_and_then_raises
      prompt = CountingPrompt.new('wrong')

      error = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::DecryptError) do
        Net::SSH::KeyFactory.load_data_private_key(private_key_pwd, nil, true, '', prompt)
      end
      assert error.retryable?
      assert_equal 3, prompt.asks
    end

    def test_correct_passphrase_is_asked_once_and_succeeds
      prompt = CountingPrompt.new('pwd')

      key = Net::SSH::KeyFactory.load_data_private_key(private_key_pwd, nil, true, '', prompt)
      assert_equal "ssh-ed25519", key.ssh_type
      assert_equal 1, prompt.asks
    end

    def test_over_budget_key_is_rejected_without_any_prompt
      prompt = CountingPrompt.new('pwd')

      assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::KdfBudgetError) do
        Net::SSH::KeyFactory.load_data_private_key(private_key_pwd, nil, true, '', prompt, max_kdf_rounds: 15)
      end
      assert_equal 0, prompt.asks
    end

    def test_unsupported_format_is_rejected_without_any_prompt
      prompt = CountingPrompt.new('pwd')

      assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::UnsupportedFormatError) do
        Net::SSH::KeyFactory.load_data_private_key(openssh_key_with_cipher("aes999-cbc"), nil, true, '', prompt)
      end
      assert_equal 0, prompt.asks
    end

    def test_malformed_container_is_rejected_without_any_prompt
      prompt = CountingPrompt.new('pwd')

      assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::MalformedKeyError) do
        Net::SSH::KeyFactory.load_data_private_key(wrap_openssh_container("\x00\x01\x02"), nil, true, '', prompt)
      end
      assert_equal 0, prompt.asks
    end

    def test_rsa_and_ec_openssh_keys_share_the_same_budget_and_retry_categories
      rsa_data = fixture_openssh_key("rsa_enc")
      ec_data = fixture_openssh_key("ec_enc")

      rsa_key = Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader.read(rsa_data, 'secret')
      assert_kind_of OpenSSL::PKey::RSA, rsa_key
      ec_key = Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader.read(ec_data, 'secret')
      assert_kind_of OpenSSL::PKey::EC, ec_key

      [rsa_data, ec_data].each do |data|
        wrong = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::DecryptError) do
          Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader.read(data, 'wrong')
        end
        assert wrong.retryable?

        budget = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::KdfBudgetError) do
          Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader.read(data, 'secret', max_kdf_rounds: 15)
        end
        refute budget.retryable?
      end
    end

    def test_parse_error_messages_do_not_contain_private_key_material
      corrupted = corrupted_encrypted_private_key
      error = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::MalformedKeyError) do
        Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader.read(corrupted, 'pwd')
      end
      refute_includes error.message, corrupted
      refute_match(/[A-Za-z0-9+\/]{60,}/, error.message)
    end

    def test_encrypted_key_without_passphrase_does_not_run_the_kdf
      require 'bcrypt_pbkdf'
      BCryptPbkdf.expects(:key).never

      error = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::DecryptError) do
        Net::SSH::KeyFactory.load_data_private_key(private_key_pwd, nil, false)
      end
      assert error.encrypted_key?
    end

    def assert_pwd_key_matches_public_key(private_key, public_key)
      pub = Net::SSH::Buffer.new(Base64.decode64(public_key.split(' ')[1]))
      _type = pub.read_string
      pub_data = pub.read_string

      pub_key = Net::SSH::Authentication::ED25519::PubKey.new(pub_data)
      priv_key = Net::SSH::Authentication::ED25519::PrivKey.read(private_key, 'pwd')

      shared_secret = "Hello"
      signed = priv_key.ssh_do_sign(shared_secret)
      self.assert_equal(true, pub_key.ssh_do_verify(signed, shared_secret))
      self.assert_equal(priv_key.public_key.fingerprint, pub_key.fingerprint)
    end

    # Records how often a passphrase is asked for so the retry budget can be
    # asserted without touching a real terminal.
    class CountingPrompt
      attr_reader :asks

      def initialize(answer)
        @answer = answer
        @asks = 0
      end

      def start(_info)
        self
      end

      def ask(_message, _echo)
        @asks += 1
        @answer
      end

      def success; end
    end

    # Counts real bcrypt_pbkdf derivations while still running the original
    # implementation (mocha 2.x cannot stub-and-call-through).
    def counting_real_kdf_derivations
      require 'bcrypt_pbkdf'
      counter = { calls: 0 }
      BCryptPbkdf.singleton_class.send(:alias_method, :key_without_counter, :key)
      BCryptPbkdf.define_singleton_method(:key) do |*args|
        counter[:calls] += 1
        key_without_counter(*args)
      end
      yield counter
    ensure
      BCryptPbkdf.singleton_class.send(:alias_method, :key, :key_without_counter)
      BCryptPbkdf.singleton_class.send(:remove_method, :key_without_counter)
    end

    OPENSSH_MAGIC = "openssh-key-v1\x00".b

    # Decodes the base64 body of an OpenSSH private key text into raw bytes.
    def openssh_raw(key_text)
      Base64.decode64(key_text.gsub(/-----(BEGIN|END) OPENSSH PRIVATE KEY-----/, '').gsub(/\s+/, ''))
    end

    # Wraps raw container bytes back into the OpenSSH PEM-style text form.
    def wrap_openssh_container(raw)
      "-----BEGIN OPENSSH PRIVATE KEY-----\n" + [raw].pack('m') + "-----END OPENSSH PRIVATE KEY-----\n"
    end

    # Parses the top-level fields of an OpenSSH private key container so a
    # single field can be swapped to craft small malformed inputs.
    def rebuild_openssh_container(key_text)
      buffer = Net::SSH::Buffer.new(openssh_raw(key_text)[OPENSSH_MAGIC.bytesize..-1])
      fields = {
        cipher: buffer.read_string,
        kdf: buffer.read_string,
        kdfopts: buffer.read_string,
        num_keys: buffer.read_long,
        pubkey: buffer.read_string,
        length: buffer.read_long
      }
      fields[:encrypted] = buffer.read(fields[:length])
      fields
    end

    def openssh_key_with_cipher(ciphername)
      fields = rebuild_openssh_container(private_key_pwd)
      wrap_openssh_container(OPENSSH_MAGIC + Net::SSH::Buffer.from(
        :string, ciphername,
        :string, fields[:kdf], :string, fields[:kdfopts],
        :long, fields[:num_keys], :string, fields[:pubkey],
        :long, fields[:length], :raw, fields[:encrypted]
      ).to_s)
    end

    def openssh_key_with_kdf(kdfname)
      fields = rebuild_openssh_container(private_key_pwd)
      wrap_openssh_container(OPENSSH_MAGIC + Net::SSH::Buffer.from(
        :string, fields[:cipher],
        :string, kdfname, :string, fields[:kdfopts],
        :long, fields[:num_keys], :string, fields[:pubkey],
        :long, fields[:length], :raw, fields[:encrypted]
      ).to_s)
    end

    # Flips a byte three CBC blocks into the encrypted section. The checkints in
    # the first block survive, so with the correct passphrase decryption
    # succeeds but the decoded inner key no longer parses: a structural failure
    # rather than a bad passphrase.
    def corrupted_encrypted_private_key
      @corrupted_encrypted_private_key ||= begin
        fields = rebuild_openssh_container(private_key_pwd)
        corrupted = fields[:encrypted].dup
        offset = 16 * 3
        corrupted.setbyte(offset, corrupted.getbyte(offset) ^ 0xFF)
        body = Net::SSH::Buffer.from(
          :string, fields[:cipher],
          :string, fields[:kdf], :string, fields[:kdfopts],
          :long, fields[:num_keys], :string, fields[:pubkey],
          :long, fields[:length], :raw, corrupted
        ).to_s
        wrap_openssh_container(OPENSSH_MAGIC + body)
      end
    end

    # Flips a byte well inside an unencrypted ("none" KDF) private section, past
    # the checkints and key type, so the decoded Ed25519 key fails validation.
    def corrupted_unencrypted_private_key
      @corrupted_unencrypted_private_key ||= begin
        fields = rebuild_openssh_container(private_key_no_pwd)
        corrupted = fields[:encrypted].dup
        corrupted.setbyte(60, corrupted.getbyte(60) ^ 0xFF)
        body = Net::SSH::Buffer.from(
          :string, fields[:cipher],
          :string, fields[:kdf], :string, fields[:kdfopts],
          :long, fields[:num_keys], :string, fields[:pubkey],
          :long, fields[:length], :raw, corrupted
        ).to_s
        wrap_openssh_container(OPENSSH_MAGIC + body)
      end
    end

    # Fixed, throwaway OpenSSH-format keys generated solely for this suite with
    # `ssh-keygen -a 16`; they are not used anywhere outside these tests.
    def fixture_openssh_key(name)
      File.read(File.expand_path("../fixtures/#{name}", __dir__))
    end

    def private_key_pwd
      @pwd_key = <<~EOF
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABBxwCvr3V
        /8pWhC/xvTnGJhAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAICaHkFaGXqYhUVFc
        aZ10TPUbkIvmaFXwYRoOS5qE8MciAAAAsNUAhbNQKwNcOr0eNq3nhtjoyeVyH8hRrpWsiY
        46vPiECi6R6OdYGSd7W3fdzUDeyOYCY9ZVIjAzENG+9FsygYzMi6XCuw00OuDFLUp4fL4K
        i/coUIVqouB4TPQAmsCVXiIRVTWQtRG0kWfFaV3qRt/bc22ZCvCT6ZZ1UmtulqqfUhSlKM
        oPcTikV1iWH5Xc+GxRFRRGTN/6HvBf0AKDB1kMXlDhGnBnHGeNH1pk44xG
        -----END OPENSSH PRIVATE KEY-----
      EOF
    end

    def private_key_aes128_gcm_pwd
      <<~EOF
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAAFmFlczEyOC1nY21Ab3BlbnNzaC5jb20AAAAGYmNyeXB0AA
        AAGAAAABD7fJqyikc+oGFRyPNFeYW+AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAA
        ICjavy2Z6HRO1gnczDXj/li91GQ/yyd2UTk4cpHN3XotAAAAoHdc7A78wsOAwOzeuxuC5G
        VeHz6StESIIrc/u0a2k1H4tHsAfVK1QphPTuhigypuko1cxbAjWDJ3l2m4TnGMltYNixBt
        rcmDaMxhAVu2W1XQds7sfUw0BqbgkQDjAH5LQzv/897+QMdOziGWfR6jC+VBo+Gzgnbv4a
        xivRbVdrUjhon9jdg2HiUZDLE14FOegWCSrc76UqS9gaScVQEc3WObuoxFZP3OTYMsg8FV
        MnJJ
        -----END OPENSSH PRIVATE KEY-----
      EOF
    end

    def private_key_aes256_gcm_pwd
      <<~EOF
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAAFmFlczI1Ni1nY21Ab3BlbnNzaC5jb20AAAAGYmNyeXB0AA
        AAGAAAABAIYrZ1Iy7viUsL4JBEZBUQAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAA
        IOEnJoGcYaqIKnB8qUdFbCxewkX78jQop1KRb4F6xX/tAAAAkAue/lM/EQ+M8fbjG+ab3x
        hrWZuaRvEbnzpe2+oPCxyGklVIC5pkNgDAfm4wGE+e81FGV0b323yMNbFZBWp61g+QLPEO
        kK0U0L/oK8pbJc4sIu2X3dOnCsmgptbi7L/L1ABzbaD2nKKJ4JV1MDwGawKOryD4XAcVCG
        4xrbZV1uR5iiq7wNQ3e6MVDbMlR7657aA7IBJ6zTlN8Ih9W6gb21w=
        -----END OPENSSH PRIVATE KEY-----
      EOF
    end

    def private_key_chacha20_poly1305_pwd
      <<~EOF
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAAHWNoYWNoYTIwLXBvbHkxMzA1QG9wZW5zc2guY29tAAAABm
        JjcnlwdAAAABgAAAAQF0S3Ou3bJxwGdfaAdynA5gAAABgAAAABAAAAMwAAAAtzc2gtZWQy
        NTUxOQAAACBGlIfrlzFWtRPdTGzaIT4D84KuBCzLbukafbUIlslwjAAAAJALFmJsY67YcH
        B01Fy7YoHRKUNL/82vC3uxTkhmqHhbDPeLdCdIyvdFpyKp5lrGtIx5K44PKOEU98hDL+Nk
        QGM5HAurbKxg20ZaiYIaF/lmmXSIoEXDJjmxMZhf5c7UkqozXl4puRs6oxQChcg9Rzj9LO
        b6XVrFTWbbgxAwzFkAs5qF0aPI5nsKgTdQX17M4afu86UIj6vPaHF4oMypei5N
        -----END OPENSSH PRIVATE KEY-----
      EOF
    end

    # From GHSA-rpq3-v334-f5pm: claims 0xffffffff bcrypt rounds.
    def private_key_max_rounds
      <<~EOF
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCNmyk3pe
        r1LJ4Z+9EboO8D/////wAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIBTvH51xZ8CJVjAS
        FzQ2cwRJeuYwOSWEly5MrEBsJIehAAAAkBVBwCyurZ2G1x2fxuiXaXLZQOz1c39x0PTOw6
        PeU2FE0kmF2Zz6wZxGhUJfZ1Mze+J0/2NOLiEvICCj3oOU11sq0/uRkANNUE0i88fR96qG
        K7TZUtAemYFmjIR0/B+nNZdgqdtDk2I9KHLE5e86zBAv55Vm1a5AxmMRtFObyUCMiu+T41
        NZbcUtBBoQJDzxbw==
        -----END OPENSSH PRIVATE KEY-----
      EOF
    end

    def private_key_no_rounds
      @private_key_no_rounds = <<~EOF
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAA
        ABBxwCvr3V/8pWhC/xvTnGJhAAAAAAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5
        AAAAICaHkFaGXqYhUVFcaZ10TPUbkIvmaFXwYRoOS5qE8MciAAAAsNUAhbNQ
        KwNcOr0eNq3nhtjoyeVyH8hRrpWsiY46vPiECi6R6OdYGSd7W3fdzUDeyOYC
        Y9ZVIjAzENG+9FsygYzMi6XCuw00OuDFLUp4fL4Ki/coUIVqouB4TPQAmsCV
        XiIRVTWQtRG0kWfFaV3qRt/bc22ZCvCT6ZZ1UmtulqqfUhSlKMoPcTikV1iW
        H5Xc+GxRFRRGTN/6HvBf0AKDB1kMXlDhGnBnHGeNH1pk44xG
        -----END OPENSSH PRIVATE KEY-----
      EOF
    end

    def public_key_pwd
      'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICaHkFaGXqYhUVFcaZ10TPUbkIvmaFXwYRoOS5qE8Mci vagrant@vagrant-ubuntu-trusty-64'
    end

    def key_fingerprint_md5_pwd
      'c8:89:92:60:12:1b:01:5e:ca:58:55:68:7e:5e:1a:f1'
    end

    def key_fingerprint_sha256_pwd
      'SHA256:Uz5Qk/fB+f8Bu7FTxNcDh7+atpB29Q3tBBJX/gnUfGw'
    end

    def public_key_aes128_gcm_pwd
      'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICjavy2Z6HRO1gnczDXj/li91GQ/yyd2UTk4cpHN3Xot aes128gcm-test'
    end

    def public_key_aes256_gcm_pwd
      'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOEnJoGcYaqIKnB8qUdFbCxewkX78jQop1KRb4F6xX/t aesgcm-test'
    end

    def public_key_chacha20_poly1305_pwd
      'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEaUh+uXMVa1E91MbNohPgPzgq4ELMtu6Rp9tQiWyXCM chacha-test'
    end

    def private_key_no_pwd
      @anonymous_key = <<~EOF
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACAwdjQYeBiTz1DdZFzzLvG+t913L+eVqCgtzpAYxQG8yQAAAKjlHzLo5R8y
        6AAAAAtzc2gtZWQyNTUxOQAAACAwdjQYeBiTz1DdZFzzLvG+t913L+eVqCgtzpAYxQG8yQ
        AAAEBPrD+n4901Y+NYJ2sry+EWRdltGFhMISvp91TywJ//mTB2NBh4GJPPUN1kXPMu8b63
        3Xcv55WoKC3OkBjFAbzJAAAAIHZhZ3JhbnRAdmFncmFudC11YnVudHUtdHJ1c3R5LTY0AQ
        IDBAU=
        -----END OPENSSH PRIVATE KEY-----
      EOF
    end

    def private_key_no_pwd_with_newlines
      @anonymous_key = <<~EOF
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACAwdjQYeBiTz1DdZFzzLvG+t913L+eVqCgtzpAYxQG8yQAAAKjlHzLo5R8y
        6AAAAAtzc2gtZWQyNTUxOQAAACAwdjQYeBiTz1DdZFzzLvG+t913L+eVqCgtzpAYxQG8yQ
        AAAEBPrD+n4901Y+NYJ2sry+EWRdltGFhMISvp91TywJ//mTB2NBh4GJPPUN1kXPMu8b63
        3Xcv55WoKC3OkBjFAbzJAAAAIHZhZ3JhbnRAdmFncmFudC11YnVudHUtdHJ1c3R5LTY0AQ
        IDBAU=
        -----END OPENSSH PRIVATE KEY-----


      EOF
    end

    def private_key_no_pwd_with_windows_newlines
      @anonymous_key = <<~EOF
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACAwdjQYeBiTz1DdZFzzLvG+t913L+eVqCgtzpAYxQG8yQAAAKjlHzLo5R8y
        6AAAAAtzc2gtZWQyNTUxOQAAACAwdjQYeBiTz1DdZFzzLvG+t913L+eVqCgtzpAYxQG8yQ
        AAAEBPrD+n4901Y+NYJ2sry+EWRdltGFhMISvp91TywJ//mTB2NBh4GJPPUN1kXPMu8b63
        3Xcv55WoKC3OkBjFAbzJAAAAIHZhZ3JhbnRAdmFncmFudC11YnVudHUtdHJ1c3R5LTY0AQ
        IDBAU=
        -----END OPENSSH PRIVATE KEY-----


      EOF

      @anonymous_key.encode(crlf_newline: true)
    end

    def public_key_no_pwd
      'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDB2NBh4GJPPUN1kXPMu8b633Xcv55WoKC3OkBjFAbzJ vagrant@vagrant-ubuntu-trusty-64'
    end

    def key_fingerprint_md5_no_pwd
      '2f:7f:97:21:76:a4:0f:38:c4:fe:d8:b4:6a:39:72:30'
    end

    def key_fingerprint_sha256_no_pwd
      'SHA256:u6mXnY8P1b0FODGp8mckqOB33u8+jvkSCtJbD5Q9klg'
    end
  end
end
