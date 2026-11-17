import struct
import unittest

from uefi_firmware.uefi import (
    NVARVariableEvidence,
    NVARVariableStore,
)

ATTR_GUID = 0x04
ATTR_DATA = 0x08
ATTR_VALID = 0x80

GUID_A = bytes(range(16))
GUID_B = bytes(range(16, 32))
GUID_INLINE = bytes(range(32, 48))


def utf16(name):
    return name.encode("utf-16le") + b"\x00\x00"


def named_indexed(guid_index, name, value):
    return bytes([guid_index]) + utf16(name) + value


def named_inline(guid, name, value):
    return guid + utf16(name) + value


def data_only(value):
    return b"\x00" + value


def entry(attributes, body, next_offset):
    size = 10 + len(body)
    return b"NVAR" + struct.pack("<H", size) + \
        next_offset.to_bytes(3, "little") + bytes([attributes]) + body


def build_store(specs, guid_table=()):
    '''Assemble a store from specs. Links are entry indices, ("raw", off)
    for an arbitrary offset, or None for a terminal link.'''
    offsets = []
    position = 0
    for spec in specs:
        offsets.append(position)
        position += 10 + len(spec["body"])
    blob = b""
    for spec in specs:
        link = spec.get("next")
        if link is None:
            next_offset = 0
        elif isinstance(link, tuple):
            next_offset = link[1]
        else:
            next_offset = offsets[link]
        blob += entry(spec["attr"], spec["body"], next_offset)
    for guid in guid_table:
        blob += guid
    return blob, offsets


def demo_specs():
    '''Two updates of "Setup", one deletion of "Old", one bad link.'''
    return [
        # Setup, generation 1 (invalidated by the first update).
        {"attr": 0, "body": named_indexed(0, "Setup", b"v1")},
        # Setup, generation 2 (invalidated by the second update).
        {"attr": 0, "body": named_indexed(0, "Setup", b"v2")},
        # Setup, generation 3 (valid), linked to a data-only successor.
        {"attr": ATTR_VALID, "body": named_indexed(0, "Setup", b"v3"),
         "next": 3},
        {"attr": ATTR_VALID | ATTR_DATA, "body": data_only(b"+extra")},
        # Old: deleted (invalidated, no newer generation).
        {"attr": ATTR_GUID, "body": named_inline(GUID_INLINE, "Old", b"x")},
        # Broken: valid, but its Next pointer targets nowhere.
        {"attr": ATTR_VALID, "body": named_indexed(1, "Broken", b"data"),
         "next": ("raw", 0x400)},
    ]


def build_demo_store():
    return build_store(demo_specs(), guid_table=(GUID_A, GUID_B))


def parse_view(data):
    store = NVARVariableStore(data)
    assert store.process()
    return store, store.chain_evidence()


def by_name(view, name):
    for evidence in view.variables:
        if evidence.name == name:
            return evidence
    return None


class NVARChainEvidenceTest(unittest.TestCase):

    def setUp(self):
        self.data, self.offsets = build_demo_store()
        self.store, self.view = parse_view(self.data)

    def test_guid_table_is_connected(self):
        self.assertEqual(self.view.guid_table, [GUID_A, GUID_B])
        self.assertEqual(self.view.guid_table_offset,
                         self.offsets[-1] + 10 + len(demo_specs()[-1]["body"]))

    def test_indexed_and_inline_guids_are_distinguished(self):
        setup = by_name(self.view, "Setup")
        old = by_name(self.view, "Old")
        self.assertEqual(setup.guid, GUID_A)
        self.assertEqual(old.guid, GUID_INLINE)
        newest = setup.generations[-1]
        self.assertFalse(newest.guid_inline)
        self.assertEqual(newest.guid_index, 0)
        self.assertTrue(old.generations[-1].guid_inline)

    def test_two_updates_leave_two_history_nodes(self):
        setup = by_name(self.view, "Setup")
        self.assertEqual(setup.status, NVARVariableEvidence.STATUS_CURRENT)
        self.assertEqual(len(setup.generations), 3)
        self.assertEqual([node.data for node in setup.history],
                         [b"v1", b"v2"])
        # Every generation keeps its raw position in the store.
        self.assertEqual([node.offset for node in setup.generations],
                         self.offsets[:3])
        self.assertEqual(len(setup.invalidated_predecessors), 2)

    def test_data_only_successor_extends_current_chain(self):
        setup = by_name(self.view, "Setup")
        chain = setup.chains[setup.current.offset]
        self.assertTrue(chain.closed)
        self.assertEqual([node.role for node in chain.nodes],
                         ["named", "data"])
        self.assertEqual(chain.nodes[1].data, b"+extra")
        self.assertEqual(chain.nodes[1].offset, self.offsets[3])

    def test_deletion_has_no_current(self):
        old = by_name(self.view, "Old")
        self.assertEqual(old.status, NVARVariableEvidence.STATUS_DELETED)
        self.assertIsNone(old.current)
        self.assertEqual(len(old.history), 1)

    def test_bad_link_keeps_uncertainty(self):
        broken = by_name(self.view, "Broken")
        self.assertEqual(broken.status, NVARVariableEvidence.STATUS_UNCERTAIN)
        self.assertIsNone(broken.current)
        # The last parseable bytes stay a candidate, not a confirmation.
        self.assertEqual([node.data for node in broken.candidates],
                         [b"data"])
        self.assertTrue(any("bad-link" in issue
                            for issue in broken.issues))

    def test_current_and_history_views_are_separate(self):
        currents = self.view.current_variables()
        self.assertEqual([evidence.name for evidence in currents], ["Setup"])
        self.assertEqual([evidence.name
                          for evidence in self.view.uncertain_variables()],
                         ["Broken"])
        history = self.view.history()
        self.assertEqual(len(history), 4)  # v1, v2, Old, Broken candidate
        self.assertNotIn(by_name(self.view, "Setup").current, history)

    def test_reordering_unrelated_variables_keeps_associations(self):
        # Interleave the three variables differently, keeping each
        # variable's own generations in order and rewriting links.
        specs = demo_specs()
        order = [4, 0, 1, 5, 2, 3]  # Broken, v1, v2, Old, v3, data
        reordered = [dict(specs[i]) for i in order]
        for spec in reordered:
            if spec.get("next") == 3:
                spec["next"] = order.index(3)
        blob, _ = build_store(reordered, guid_table=(GUID_A, GUID_B))

        _, view = parse_view(blob)
        for name in ("Setup", "Old", "Broken"):
            before = by_name(self.view, name)
            after = by_name(view, name)
            self.assertEqual(before.status, after.status)
            self.assertEqual(before.guid, after.guid)
            self.assertEqual([node.data for node in before.generations],
                             [node.data for node in after.generations])
            self.assertEqual([node.data for node in before.history],
                             [node.data for node in after.history])
        # The v3 -> data-only link survives the move.
        setup = by_name(view, "Setup")
        chain = setup.chains[setup.current.offset]
        self.assertEqual([node.role for node in chain.nodes],
                         ["named", "data"])

    def test_loop_is_reported(self):
        # A link back to offset 0 reads as a terminal link, so loop
        # between the second and third entries instead.
        specs = [
            {"attr": ATTR_VALID, "body": named_indexed(0, "Other", b"z")},
            {"attr": ATTR_VALID, "body": named_indexed(0, "Loopy", b"a"),
             "next": 2},
            {"attr": ATTR_VALID | ATTR_DATA, "body": data_only(b"b"),
             "next": 1},
        ]
        blob, _ = build_store(specs, guid_table=(GUID_A,))
        _, view = parse_view(blob)
        loopy = by_name(view, "Loopy")
        self.assertEqual(loopy.status, NVARVariableEvidence.STATUS_UNCERTAIN)
        self.assertTrue(any("loop" in issue for issue in loopy.issues))

    def test_still_valid_predecessor_is_a_duplicate_identity(self):
        specs = [
            {"attr": ATTR_VALID, "body": named_indexed(0, "Dup", b"one")},
            {"attr": ATTR_VALID, "body": named_indexed(0, "Dup", b"two")},
        ]
        blob, _ = build_store(specs, guid_table=(GUID_A,))
        _, view = parse_view(blob)
        dup = by_name(view, "Dup")
        self.assertTrue(any("duplicate-identity" in issue
                            for issue in dup.issues))

    def test_show_renders_all_sections(self):
        import io
        from contextlib import redirect_stdout
        out = io.StringIO()
        with redirect_stdout(out):
            self.view.show()
        text = out.getvalue()
        self.assertIn("chains: 5", text)
        self.assertIn("GUID table", text)
        self.assertIn("status= current", text)
        self.assertIn("status= deleted", text)
        self.assertIn("status= uncertain", text)
        self.assertIn("@0x%06x" % self.offsets[0], text)


if __name__ == '__main__':
    unittest.main()
