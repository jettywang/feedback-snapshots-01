""" scope contract for PGPKey.unlock

These tests pin down the behavior of nested unlock scopes, partial subkey
unlock failure, exceptions inside a scope, different passphrases, unprotected
keys and concurrent use of a shared PGPKey instance.
"""
import copy
import threading
import warnings

import pytest

from pgpy import PGPKey
from pgpy import PGPUID
from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import SymmetricKeyAlgorithm
from pgpy.errors import PGPDecryptionError
from pgpy.errors import PGPError

PASSPHRASE = "QwertyUiop"


@pytest.fixture
def enc_key():
    key, _ = PGPKey.from_file('tests/testdata/keys/rsa.1.enc.asc')
    return key


@pytest.fixture
def sec_key():
    key, _ = PGPKey.from_file('tests/testdata/keys/rsa.1.sec.asc')
    return key


@pytest.fixture
def pub_key():
    key, _ = PGPKey.from_file('tests/testdata/keys/rsa.1.pub.asc')
    return key


@pytest.fixture
def split_passphrase_key():
    # primary key and first subkey use pass-A; the second subkey uses pass-B
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_uid(PGPUID.new('Scope Test', comment='nested', email='scope@x.local'),
                hashes=[HashAlgorithm.SHA224])

    sub1 = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    sub2 = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_subkey(sub1, usage={KeyFlags.Sign})
    key.add_subkey(sub2, usage={KeyFlags.EncryptCommunications})

    key.protect("pass-A", SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    with key.unlock("pass-A"):
        sub2._key.protect("pass-B", SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

    return key


def component_states(key):
    return [key.is_unlocked] + [sk.is_unlocked for sk in key.subkeys.values()]


def private_mpis_zero(key):
    components = [key] + list(key.subkeys.values())
    for component in components:
        fields = component._key.keymaterial.__privfields__
        if any(int(getattr(component._key.keymaterial, name)) != 0 for name in fields):
            return False
    return True


def assert_fully_locked(key):
    assert all(state is False for state in component_states(key))
    assert private_mpis_zero(key)
    with pytest.raises(PGPError):
        key.sign("locked")


class TestNestedUnlock:
    def test_inner_exit_keeps_outer_scope_usable(self, enc_key):
        # path 1: nested success; the outer scope must still sign a second file
        assert component_states(enc_key) == [False, False, False]

        with enc_key.unlock(PASSPHRASE):
            enc_key.sign("first document")

            with enc_key.unlock(PASSPHRASE):
                assert all(component_states(enc_key))
                enc_key.sign("inner document")

            # the inner scope must not have removed material the outer scope owns
            assert all(component_states(enc_key))
            enc_key.sign("second document")

        assert_fully_locked(enc_key)

    def test_arbitrary_nesting_depth(self, enc_key):
        with enc_key.unlock(PASSPHRASE):
            for _ in range(5):
                with enc_key.unlock(PASSPHRASE):
                    enc_key.sign("deep")
            assert all(component_states(enc_key))
        assert_fully_locked(enc_key)

    def test_exception_in_inner_scope_does_not_clear_outer(self, enc_key):
        with enc_key.unlock(PASSPHRASE):
            with enc_key.unlock(PASSPHRASE):
                with pytest.raises(ValueError):
                    with enc_key.unlock(PASSPHRASE):
                        raise ValueError("inner boom")
            # outer scopes survive an exception thrown inside an inner block
            assert all(component_states(enc_key))
            enc_key.sign("still working")
        assert_fully_locked(enc_key)

    def test_nested_wrong_passphrase_is_rejected_without_state_change(self, enc_key):
        with enc_key.unlock(PASSPHRASE):
            with pytest.raises(PGPDecryptionError):
                with enc_key.unlock("not the passphrase"):
                    pytest.fail("body must not run when the identity does not match")

            # the rejected inner scope neither relocks nor disturbs the outer scope
            assert all(component_states(enc_key))
            enc_key.sign("outer still valid")

        assert_fully_locked(enc_key)

    def test_nested_scope_does_not_decrypt_twice(self, enc_key):
        # the nested scope verifies the passphrase instead of re-running unprotect;
        # if it re-decrypted, the clear() on its exit would wipe the outer material
        calls = []
        original = enc_key._key.unprotect

        def tracking_unprotect(passphrase):
            calls.append(passphrase)
            return original(passphrase)

        enc_key._key.unprotect = tracking_unprotect
        try:
            with enc_key.unlock(PASSPHRASE):
                with enc_key.unlock(PASSPHRASE):
                    pass
        finally:
            enc_key._key.unprotect = original

        assert calls == [PASSPHRASE]


class TestPartialFailure:
    def test_second_subkey_failure_is_atomic(self, split_passphrase_key):
        # path 2: the primary key and sub1 accept pass-A, sub2 rejects it
        assert component_states(split_passphrase_key) == [False, False, False]

        with pytest.raises(PGPDecryptionError):
            with split_passphrase_key.unlock("pass-A"):
                pytest.fail("body must not run when a subkey cannot be unlocked")

        # nothing stays in plaintext and signing is impossible afterwards
        assert component_states(split_passphrase_key) == [False, False, False]
        assert private_mpis_zero(split_passphrase_key)
        with pytest.raises(PGPError):
            split_passphrase_key.sign("after failure")

    def test_failed_inner_entry_leaves_outer_scope_untouched(self, enc_key):
        # an outer scope holds valid material; a nested entry that fails verification
        # must roll back nothing, because it never decrypted anything itself
        with enc_key.unlock(PASSPHRASE):
            before = component_states(enc_key)
            with pytest.raises(PGPDecryptionError):
                with enc_key.unlock("pass-A"):
                    pytest.fail("body must not run")
            assert component_states(enc_key) == before
            enc_key.sign("outer scope survived")
        assert_fully_locked(enc_key)

    def test_wrong_passphrase_rolls_back_decrypted_components(self, enc_key):
        with pytest.raises(PGPDecryptionError):
            with enc_key.unlock("wrong"):
                pytest.fail("body must not run")
        assert_fully_locked(enc_key)


class TestExceptionExit:
    def test_exception_in_outer_scope_still_locks_everything(self, enc_key):
        # path 3: an abnormal exit must still guarantee cleanup
        with pytest.raises(RuntimeError):
            with enc_key.unlock(PASSPHRASE):
                assert all(component_states(enc_key))
                enc_key.sign("inside")
                raise RuntimeError("boom")

        assert_fully_locked(enc_key)

    def test_keyboard_interrupt_path_cleans_up(self, enc_key):
        with pytest.raises(KeyboardInterrupt):
            with enc_key.unlock(PASSPHRASE):
                raise KeyboardInterrupt()
        assert_fully_locked(enc_key)


class TestUnprotectedAndPublic:
    def test_unprotected_key_emits_warning_and_remains_usable(self, sec_key):
        assert sec_key.is_protected is False
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with sec_key.unlock("anything") as unlocked:
                assert unlocked is sec_key
                unlocked.sign("no passphrase needed")

        assert any("not protected with a passphrase" in str(w.message) for w in caught)
        # an unprotected key is never recorded as an unlock scope
        assert sec_key._PGPKey__unlock_depth == 0
        assert sec_key._PGPKey__unlock_owner is None

    def test_public_key_emits_warning_and_is_a_noop(self, pub_key):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with pub_key.unlock("anything") as unlocked:
                assert unlocked is pub_key

        assert any("Public keys cannot be passphrase-protected" in str(w.message) for w in caught)
        assert pub_key._PGPKey__unlock_depth == 0

    def test_unprotected_components_are_skipped_not_managed(self):
        key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
        key.add_uid(PGPUID.new('Mixed', email='mixed@x.local'), hashes=[HashAlgorithm.SHA224])
        sub = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
        key.add_subkey(sub, usage={KeyFlags.EncryptCommunications})
        sub._key.protect("sub-pass", SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

        # the primary is unprotected, so unlocking through it is a warning no-op and
        # must not touch the protected subkey or register a scope
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with key.unlock("sub-pass"):
                assert key.is_unlocked
                assert sub.is_unlocked is False
        assert any("not protected with a passphrase" in str(w.message) for w in caught)
        assert key._PGPKey__unlock_depth == 0

        # the protected subkey can still be managed through its own scope
        with sub.unlock("sub-pass"):
            assert sub.is_unlocked
        assert sub.is_unlocked is False
        assert private_mpis_zero(sub)


class TestConcurrentSharedInstance:
    def test_second_thread_is_rejected_while_scope_is_held(self, enc_key):
        barrier = threading.Barrier(2)
        outcomes = []

        def holder():
            with enc_key.unlock(PASSPHRASE):
                barrier.wait()
                threading.Event().wait(0.2)
                outcomes.append(("holder", "signed", enc_key.sign("holder") is not None))

        def contender():
            barrier.wait()
            try:
                with enc_key.unlock(PASSPHRASE):
                    outcomes.append(("contender", "unexpectedly entered"))
            except PGPError as exc:
                outcomes.append(("contender", "rejected", str(exc)))

        holder_thread = threading.Thread(target=holder)
        contender_thread = threading.Thread(target=contender)
        holder_thread.start()
        contender_thread.start()
        holder_thread.join()
        contender_thread.join()

        assert ("holder", "signed", True) in outcomes
        name, verdict, _ = next(item for item in outcomes if item[0] == "contender")
        assert (name, verdict) == ("contender", "rejected")
        assert_fully_locked(enc_key)

    def test_same_thread_may_nest_but_other_thread_may_not_join(self, enc_key):
        with enc_key.unlock(PASSPHRASE):
            ready = threading.Event()
            done = threading.Event()
            outcome = []

            def other_thread():
                ready.set()
                try:
                    with enc_key.unlock(PASSPHRASE):
                        outcome.append("entered")
                except PGPError:
                    outcome.append("rejected")
                finally:
                    done.set()

            thread = threading.Thread(target=other_thread)
            thread.start()
            ready.wait()
            done.wait()
            thread.join()

            assert outcome == ["rejected"]
            # the owning thread keeps full signing ability
            assert all(component_states(enc_key))
            enc_key.sign("owner only")


class TestCopyIsolation:
    def test_copy_has_independent_scope_bookkeeping(self, enc_key):
        with enc_key.unlock(PASSPHRASE):
            duplicate = copy.copy(enc_key)
            # the copy gets its own, unused scope bookkeeping
            assert duplicate._PGPKey__unlock_depth == 0
            assert duplicate._PGPKey__unlock_owner is None
            assert duplicate is not enc_key

        assert_fully_locked(enc_key)
