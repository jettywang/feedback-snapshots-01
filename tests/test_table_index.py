"""
Differential and adversarial tests for the indexed HeaderTable search.

These tests pin the optimized ``HeaderTable`` against ``NaiveHeaderTable``,
an independent reimplementation of the original linear-scan algorithm, to
prove the auxiliary indexes preserve the exact encoding semantics while
doing strictly less work per lookup.
"""
import random
from collections import deque

from hpack import InvalidTableIndex
from hpack.hpack import Decoder, Encoder
from hpack.table import HeaderTable, table_entry_size


class NaiveHeaderTable:
    """
    Independent reference implementation: the original linear-scan table.
    """

    DEFAULT_SIZE = HeaderTable.DEFAULT_SIZE
    STATIC_TABLE = HeaderTable.STATIC_TABLE
    STATIC_TABLE_LENGTH = HeaderTable.STATIC_TABLE_LENGTH
    STATIC_TABLE_MAPPING = HeaderTable.STATIC_TABLE_MAPPING

    def __init__(self):
        self._maxsize = self.DEFAULT_SIZE
        self._current_size = 0
        self.resized = False
        self.dynamic_entries = deque()
        #: Number of dynamic entries examined by ``search`` so far.
        self.steps = 0

    def get_by_index(self, index):
        original_index = index
        index -= 1
        if 0 <= index:
            if index < self.STATIC_TABLE_LENGTH:
                return self.STATIC_TABLE[index]
            index -= self.STATIC_TABLE_LENGTH
            if index < len(self.dynamic_entries):
                return self.dynamic_entries[index]
        raise InvalidTableIndex("Invalid table index %d" % original_index)

    def add(self, name, value):
        size = table_entry_size(name, value)
        if size > self._maxsize:
            self.dynamic_entries.clear()
            self._current_size = 0
        else:
            self.dynamic_entries.appendleft((name, value))
            self._current_size += size
            self._shrink()

    def search(self, name, value):
        partial = None
        header_name_search_result = self.STATIC_TABLE_MAPPING.get(name)
        if header_name_search_result:
            index = header_name_search_result[1].get(value)
            if index is not None:
                return index, name, value
            else:
                partial = (header_name_search_result[0], name, None)

        offset = self.STATIC_TABLE_LENGTH + 1
        for (i, (n, v)) in enumerate(self.dynamic_entries):
            self.steps += 1
            if n == name:
                if v == value:
                    return i + offset, n, v
                elif partial is None:
                    partial = (i + offset, n, None)
        return partial

    @property
    def maxsize(self):
        return self._maxsize

    @maxsize.setter
    def maxsize(self, newmax):
        newmax = int(newmax)
        oldmax = self._maxsize
        self._maxsize = newmax
        self.resized = (newmax != oldmax)
        if newmax <= 0:
            self.dynamic_entries.clear()
            self._current_size = 0
        elif oldmax > newmax:
            self._shrink()

    def _shrink(self):
        cursize = self._current_size
        while cursize > self._maxsize:
            name, value = self.dynamic_entries.pop()
            cursize -= table_entry_size(name, value)
        self._current_size = cursize


class CountingDict(dict):
    """Dict that counts ``get`` probes, used to meter optimized lookups."""

    def __init__(self, counter):
        super().__init__()
        self._counter = counter

    def get(self, *args):
        self._counter[0] += 1
        return super().get(*args)


def make_metered_table():
    """
    Build an optimized HeaderTable whose auxiliary-index probes are counted.
    """
    table = HeaderTable()
    counter = [0]
    table._name_ticks = CountingDict(counter)
    table._perfect_ticks = CountingDict(counter)
    return table, counter


def auxiliary_index_size(table):
    """Total number of tick references held by the auxiliary indexes."""
    return (
        sum(len(ticks) for ticks in table._name_ticks.values())
        + sum(len(ticks) for ticks in table._perfect_ticks.values())
    )


def assert_tables_agree(optimized, naive):
    assert list(optimized.dynamic_entries) == list(naive.dynamic_entries)
    assert optimized._current_size == naive._current_size
    # The auxiliary indexes must reference exactly the live entries: no
    # evicted value is retained and nothing grows faster than the table.
    # Every live entry contributes exactly one tick to each index.
    assert auxiliary_index_size(optimized) == 2 * len(optimized.dynamic_entries)
    for ticks in optimized._name_ticks.values():
        assert list(ticks) == sorted(ticks)
    for ticks in optimized._perfect_ticks.values():
        assert list(ticks) == sorted(ticks)


def run_op_sequence(ops, optimized, naive):
    """Apply (op, args) to both tables, comparing all observable state."""
    for op, args in ops:
        if op == "add":
            optimized.add(*args)
            naive.add(*args)
        elif op == "resize":
            optimized.maxsize = args
            naive.maxsize = args
        elif op == "search":
            assert optimized.search(*args) == naive.search(*args)
        assert_tables_agree(optimized, naive)


class TestDifferentialRandom:
    def test_random_operation_sequence(self):
        rng = random.Random(20261114)
        names = (
            [b":authority", b"user-agent", b"cookie", b":path", b"host"]
            + [b"x-custom-%d" % i for i in range(12)]
        )
        values = [b"v%d" % i for i in range(20)] + [b"", b"GET", b"/"]
        ops = []
        for _ in range(4000):
            roll = rng.random()
            name = rng.choice(names)
            value = rng.choice(values)
            if roll < 0.45:
                ops.append(("add", (name, value)))
            elif roll < 0.90:
                ops.append(("search", (name, value)))
            elif roll < 0.97:
                ops.append(("resize", rng.choice([0, 1, 64, 256, 1024, 4096])))
            else:
                # Oversized entry: forces a full table clear.
                ops.append(("add", (b"x-huge", b"h" * 8192)))
        optimized, naive = HeaderTable(), NaiveHeaderTable()
        run_op_sequence(ops, optimized, naive)


class TestAdversarialSequences:
    def fill(self, table, count):
        """Fill ``table`` with ``count`` distinct same-size entries."""
        added = []
        for i in range(count):
            name = b"n%04x" % i
            value = b"v%08x" % i
            table.add(name, value)
            added.append((name, value))
        assert len(table.dynamic_entries) == count
        return added

    def test_repeated_tail_hits(self):
        """
        Attacker repeatedly searches the oldest (tail) entry: the linear
        scan walks the whole table every time, the index does not.
        """
        optimized, counter = make_metered_table()
        naive = NaiveHeaderTable()
        optimized.maxsize = naive.maxsize = 8192
        added = self.fill(optimized, 100)
        self.fill(naive, 100)

        tail = added[0]  # first added == oldest == tail of the deque
        for _ in range(50):
            before_probes, before_steps = counter[0], naive.steps
            opt_result = optimized.search(*tail)
            naive_result = naive.search(*tail)
            assert opt_result == naive_result
            # Linear scan examines every one of the 100 entries.
            assert naive.steps - before_steps == 100
            # Indexed lookup is a constant number of dict probes.
            assert counter[0] - before_probes <= 2
            # The tail entry is at the highest dynamic index.
            offset = HeaderTable.STATIC_TABLE_LENGTH + 1
            assert opt_result == (offset + 99, tail[0], tail[1])

    def test_continuous_eviction(self):
        """
        Sustained adds at a tight capacity: every insert evicts the oldest
        entry and shifts every dynamic index. Searches must track the
        moving indices exactly and the index must not retain evicted data.
        """
        optimized, _ = make_metered_table()
        naive = NaiveHeaderTable()
        optimized.maxsize = naive.maxsize = 512

        live = deque()
        for i in range(600):
            name = b"churn-%06x" % i
            value = b"value-%06x" % i
            optimized.add(name, value)
            naive.add(name, value)
            live.appendleft((name, value))
            while sum(32 + len(n) + len(v) for n, v in live) > 512:
                live.pop()
            assert list(optimized.dynamic_entries) == list(live)
            assert auxiliary_index_size(optimized) == 2 * len(live)

            # Probe the newest, the oldest and a long-evicted entry.
            evicted = (b"churn-%06x" % max(0, i - 100),
                       b"value-%06x" % max(0, i - 100))
            for probe in (live[0], live[-1], evicted):
                assert optimized.search(*probe) == naive.search(*probe)

        # Evicted entries left no trace in the auxiliary indexes.
        assert b"churn-000000" not in optimized._name_ticks
        assert all(key[0] != b"churn-000000"
                   for key in optimized._perfect_ticks)

    def test_same_name_many_values_and_duplicates(self):
        """
        Same name with different values, plus exact duplicates: the most
        recent matching entry (lowest index) must always win, and duplicate
        spam must not grow the index beyond the live entry count.
        """
        optimized, naive = HeaderTable(), NaiveHeaderTable()
        ops = []
        for i in range(40):
            ops.append(("add", (b"x-repeat", b"value-%d" % i)))
        for _ in range(30):
            ops.append(("add", (b"x-repeat", b"value-0")))  # exact duplicate
        ops.append(("search", (b"x-repeat", b"value-0")))
        ops.append(("search", (b"x-repeat", b"value-39")))
        ops.append(("search", (b"x-repeat", b"absent")))
        ops.append(("resize", 200))  # force eviction of older entries
        ops.append(("search", (b"x-repeat", b"value-0")))
        ops.append(("search", (b"x-repeat", b"absent")))
        run_op_sequence(ops, optimized, naive)

        # Only duplicates survive the shrink, collapsed under single keys
        # holding exactly one tick per live entry.
        survivors = len(optimized.dynamic_entries)
        assert survivors > 0
        assert set(optimized.dynamic_entries) == {(b"x-repeat", b"value-0")}
        assert list(optimized._name_ticks) == [b"x-repeat"]
        assert list(optimized._perfect_ticks) == [(b"x-repeat", b"value-0")]
        assert len(optimized._name_ticks[b"x-repeat"]) == survivors
        assert len(optimized._perfect_ticks[(b"x-repeat", b"value-0")]) == survivors

    def test_static_table_priority(self):
        """
        Dynamic entries sharing static names must not shadow static
        results: static perfect matches win outright, static partials win
        over dynamic partials, dynamic perfects win over static partials.
        """
        optimized, naive = HeaderTable(), NaiveHeaderTable()
        ops = [
            ("add", (b":method", b"GET")),      # dup of static entry 2
            ("add", (b":path", b"/custom")),    # name in static, value not
            ("add", (b"user-agent", b"agent-1")),
            ("search", (b":method", b"GET")),   # static perfect, not dynamic
            ("search", (b":path", b"/other")),  # static partial, not dynamic
            ("search", (b":path", b"/custom")),  # dynamic perfect beats it
            ("search", (b"user-agent", b"agent-2")),  # static partial only
            ("search", (b"user-agent", b"agent-1")),  # dynamic perfect
        ]
        run_op_sequence(ops, optimized, naive)
        assert optimized.search(b":method", b"GET") == (2, b":method", b"GET")
        assert optimized.search(b":path", b"/other") == (4, b":path", None)

    def test_oversized_entry_and_zero_resize_clear_index(self):
        optimized, naive = HeaderTable(), NaiveHeaderTable()
        ops = [
            ("add", (b"x-a", b"1")),
            ("add", (b"x-b", b"2")),
            ("add", (b"x-huge", b"h" * 8192)),  # clears the whole table
            ("search", (b"x-a", b"1")),
            ("add", (b"x-c", b"3")),
            ("resize", 0),                      # clears again via resize
            ("search", (b"x-c", b"3")),
            ("resize", 4096),
            ("add", (b"x-c", b"3")),
            ("search", (b"x-c", b"3")),
        ]
        run_op_sequence(ops, optimized, naive)
        assert list(optimized._name_ticks) == [b"x-c"]
        assert list(optimized._perfect_ticks) == [(b"x-c", b"3")]
        assert auxiliary_index_size(optimized) == 2

    def test_capacity_shrink_evicts_from_index(self):
        optimized, naive = HeaderTable(), NaiveHeaderTable()
        added = self.fill(optimized, 60)
        for name, value in added:
            naive.add(name, value)
        optimized.maxsize = 512
        naive.maxsize = 512
        assert_tables_agree(optimized, naive)
        # Every still-live entry is found at the same index in both tables;
        # every evicted entry is gone from both, and from the index.
        for name, value in added:
            assert optimized.search(name, value) == naive.search(name, value)
        live_names = {n for n, _ in optimized.dynamic_entries}
        assert set(optimized._name_ticks) == live_names


class TestEncodedOutputIdentical:
    def adversarial_header_stream(self, blocks=400):
        """
        Deterministic attacker-flavoured stream: a growing pool of headers,
        constant re-sends of the oldest entry (tail hits), duplicate spam
        and static-name traffic.
        """
        rng = random.Random(141421)
        stream = []
        pool = []
        for i in range(blocks):
            roll = rng.random()
            if roll < 0.35 or not pool:
                header = (b"x-h%05d" % i, b"payload-%05d" % i)
                pool.append(header)
            elif roll < 0.70:
                header = pool[0]  # tail hit: oldest known header
            elif roll < 0.85:
                header = pool[-1]  # exact duplicate of the newest entry
            else:
                header = (b"user-agent", b"agent-%d" % rng.randrange(8))
            stream.append(([header], rng.choice([True, False])))
        return stream

    def test_identical_bytes_and_decoding(self):
        optimized_encoder = Encoder()
        naive_encoder = Encoder()
        naive_encoder.header_table = NaiveHeaderTable()

        stream = self.adversarial_header_stream()
        # Shrink the table mid-stream to force eviction while encoding.
        optimized_encoder.header_table_size = 1024
        naive_encoder.header_table_size = 1024

        for headers, huffman in stream:
            optimized_block = optimized_encoder.encode(headers, huffman=huffman)
            naive_block = naive_encoder.encode(headers, huffman=huffman)
            # Byte-identical output: the index changed only the work done
            # to choose an encoding, never the encoding chosen.
            assert optimized_block == naive_block

        # Full round-trip: a decoder mirroring the optimized encoder must
        # reconstruct every header block exactly.
        optimized_encoder = Encoder()
        optimized_encoder.header_table_size = 1024
        decoder = Decoder()
        decoder.max_allowed_table_size = 1024
        for headers, huffman in stream:
            block = optimized_encoder.encode(headers, huffman=huffman)
            decoded = decoder.decode(block, raw=True)
            assert [(n, v) for n, v in decoded] == [
                (n, v) for n, v in headers
            ]

    def test_lookup_work_diverges_under_attack(self):
        """
        Same adversarial workload through both tables: the naive table's
        examined-entry count grows linearly per lookup while the optimized
        table's index probes stay a small constant.
        """
        optimized, counter = make_metered_table()
        naive = NaiveHeaderTable()
        optimized.maxsize = naive.maxsize = 8192

        # Fill with 100 entries, then hammer the tail entry.
        filler = [(b"n%04d" % i, b"v%04d" % i) for i in range(100)]
        for name, value in filler:
            optimized.add(name, value)
            naive.add(name, value)
        tail = filler[0]
        rounds = 200
        for _ in range(rounds):
            assert optimized.search(*tail) == naive.search(*tail)

        assert naive.steps == 100 * rounds
        assert counter[0] <= 2 * rounds
        assert auxiliary_index_size(optimized) == 2 * len(
            optimized.dynamic_entries
        )
