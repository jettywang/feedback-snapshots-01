import datetime
import sys
import struct
import unittest

sys.path.insert(0, "../../volatility3")
from volatility3.plugins.windows.registry import scheduled_tasks

# Shared fixtures extracted from the existing decoder tests.  The composite
# sets below only append/slice these exact bytes; no fixture is re-encoded.
EXE_ACTION_SET_FIXTURE = bytes.fromhex(
    "0300160000004c006f00630061006c00530079007300740065006d006666000000006e0000002500"
    "770069006e0064006900720025005c00730079007300740065006d00330032005c00570069006e00"
    "64006f007700730050006f007700650072005300680065006c006c005c00760031002e0030005c00"
    "70006f007700650072007300680065006c006c002e00650078006500620100002d00450078006500"
    "63007500740069006f006e0050006f006c00690063007900200055006e0072006500730074007200"
    "6900630074006500640020002d004e006f006e0049006e0074006500720061006300740069007600"
    "650020002d004e006f00500072006f00660069006c00650020002d00570069006e0064006f007700"
    "5300740079006c0065002000480069006400640065006e0020002200260020002500770069006e00"
    "64006900720025005c00730079007300740065006d00330032005c00570069006e0064006f007700"
    "730050006f007700650072005300680065006c006c005c00760031002e0030005c004d006f006400"
    "75006c00650073005c0053006d006200530068006100720065005c00440069007300610062006c00"
    "650055006e00750073006500640053006d00620031002e0070007300310020002d00530063006500"
    "6e006100720069006f00200043006c00690065006e0074002200000000000000"
)

LOGON_TRIGGER_SET_FIXTURE = bytes.fromhex(
    "170000000000000000b9611aa8b9611a000000000000000000b9611aa8b9611affffffffffffffff"
    "08a14042484848487a7f59dc48484848220000004848484849006e00740065007200610063007400"
    "69007600650055007300650072007300000048484848484800000000484848480048484848484848"
    "004848484848484805000000484848480c0000004848484801010000000000050400000048484848"
    "00000000484848482c0000004848484800000000ffffffff80510100ffffffff0700000000000000"
    "000000000000000000000000000000000000000048484848aaaa00000000000000b9611aa8b9611a"
    "000000000000000000b9611aa8b9611affffffffffffffff2c010000ffffffff0000000000000000"
    "0000000000c1d90401000000000000000f0000000000000000000000484848480148484848484848"
)

ALL_TRIGGERS_FIXTURE = bytes.fromhex(
    "170000000000000000daaf8d09000000000000000000000000daaf8d09000000ffffffffffffffff"
    "3821414248484848a012a0a4484848480e0000004848484841007500740068006f00720000004848"
    "00000000484848480048484848484848004848484848484801000000484848481c00000048484848"
    "01050000000000051500000069ce282aced81f77379ce244f4010000484848484000000048484848"
    "4400450053004b0054004f0050002d0045003300380038004400380050005c00410064006d006900"
    "6e006900730074007200610074006f0072000000000000002c0000004848484800000000ffffffff"
    "80f40300ffffffff0700000000000000000000000000000000000000000000000000000048484848"
    "dddd00000000000001070a0000000900804811f8361adb0100000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000ffffffff000000000000000000000000"
    "00012ee20100000000000000c23100000000000048484848aaaa00000000000000daaf8d09000000"
    "000000000000000000daaf8d09000000ffffffffffffffff00000000ffffffff0000000000000000"
    "00000000000100000100000000000000000000000000000000000000484848480148484848484848"
    "ffff00000000000000daaf8d09000000000000000000000000daaf8d09000000ffffffffffffffff"
    "00000000ffffffff0000000000000000000000000000000001000000000000000000000000000000"
    "0000000048484848eeee00000000000000daaf8d09000000000000000000000000daaf8d09000000"
    "ffffffffffffffff00000000ffffffff000000000000000000000000000000000100000000000000"
    "00000000000000000000000048484848cccc00000000000000000000000000000000000000000000"
    "0000000000000000ffffffffffffffff00000000ffffffff00000000000000000000000000000000"
    "01006500780065002200200053007400000000004848484884000000000000003c00510075006500"
    "720079004c006900730074003e003c00510075006500720079002000490064003d00220030002200"
    "200050006100740068003d00220049006e007400650072006e006500740020004500780070006c00"
    "6f0072006500720022003e003c00530065006c00650063007400200050006100740068003d002200"
    "49006e007400650072006e006500740020004500780070006c006f0072006500720022003e002a00"
    "5b00530079007300740065006d005b004500760065006e007400490044003d0032005d005d003c00"
    "2f00530065006c006500630074003e003c002f00510075006500720079003e003c002f0051007500"
    "6500720079004c006900730074003e00000048484848484800000000000000000000000000000000"
    "00000000000000008888000000000000000000000000000000000000000000000000000000000000"
    "ffffffffffffffff00000000ffffffff000000000000000000000000000000000100000000000000"
    "00000000000000000000000048484848777700000000000000000000000000000000000000000000"
    "0000000000000000ffffffffffffffff00000000ffffffff00000000000000000000000000010000"
    "01ffffff000000000000000000000000000000004848484803000000000000000148484848484848"
    "7777000000000000000000000000000000000000000000000000000000000000ffffffffffffffff"
    "00000000ffffffff0000000000000000000000000001000001000000000000000000000000000000"
    "00000000484848480400000000000000004848484848484800484848484848480100000048484848"
    "1c0000004848484801050000000000051500000069ce282aced81f77379ce244f401000048484848"
    "40000000484848484400450053004b0054004f0050002d0045003300380038004400380050005c00"
    "410064006d0069006e006900730074007200610074006f0072000000000000007777000000000000"
    "000000000000000000000000000000000000000000000000ffffffffffffffff00000000ffffffff"
    "0000000000000000000000000001000001ffffff0000000000000000000000000000000048484848"
    "07000000000000000148484848484848777700000000000000000000000000000000000000000000"
    "0000000000000000ffffffffffffffff00000000ffffffff00000000000000000000000000010000"
    "01ffffff000000000000000000000000000000004848484808000000000000000048484848484848"
    "004848484848484801000000484848481c0000004848484801050000000000051500000069ce282a"
    "ced81f77379ce244f40100004848484840000000484848484400450053004b0054004f0050002d00"
    "45003300380038004400380050005c00410064006d0069006e006900730074007200610074006f00"
    "7200000000000000"
)

# --- Reused short fixture blocks -------------------------------------------

# Actions: the Exe action occupies bytes 0..512 of the 512-byte fixture.
# Triggers: the 224-byte trigger header (version, boundaries, job bucket) comes
# from the logon-trigger fixture; the Time and Boot blocks come from the
# all-triggers fixture.
TRIGGER_HEADER_BLOCK = LOGON_TRIGGER_SET_FIXTURE[0:224]
LOGON_TRIGGER_BLOCK = LOGON_TRIGGER_SET_FIXTURE[224:320]
TIME_TRIGGER_BLOCK = ALL_TRIGGERS_FIXTURE[280:384]
BOOT_TRIGGER_BLOCK = ALL_TRIGGERS_FIXTURE[480:568]


def _bstring(text):
    encoded = text.encode("utf-16le") + b"\x00\x00"
    return struct.pack("<I", len(encoded)) + encoded


# A COM handler action appended after the Exe action.  Its CLSID and arguments
# must never be pulled into the preceding Exe action's argument field.
COM_HANDLER_BLOCK = (
    struct.pack("<H", 0x7777)
    + struct.pack("<I", 0)
    + bytes.fromhex("00112233445566778899aabbccddeeff")
    + _bstring("-p payload")
)

COMPOSITE_ACTION_SET_FIXTURE = EXE_ACTION_SET_FIXTURE + COM_HANDLER_BLOCK
COMPOSITE_TRIGGER_SET_FIXTURE = (
    TRIGGER_HEADER_BLOCK + LOGON_TRIGGER_BLOCK + TIME_TRIGGER_BLOCK + BOOT_TRIGGER_BLOCK
)

# Explicit field positions for the composite action set.  The offsets are
# independent of the decoder; the layout tests assert the fixture bytes match
# them before any decoding happens.
ACTION_LAYOUT = {
    "version": (0, 2),
    "context_length": (2, 6),
    "context_value": (6, 28),
    "exe_magic": (28, 30),
    "exe_identifier_length": (30, 34),
    "exe_command_length": (34, 38),
    "exe_command_value": (38, 148),
    "exe_arguments_length": (148, 152),
    "exe_arguments_value": (152, 506),
    "exe_working_directory_length": (506, 510),
    "exe_flags": (510, 512),
    "com_magic": (512, 514),
    "com_identifier_length": (514, 518),
    "com_clsid": (518, 534),
    "com_arguments_length": (534, 538),
    "com_arguments_value": (538, 560),
}

TRIGGER_LAYOUT = {
    "version": (0, 1),
    "job_bucket_flags": (40, 44),
    "job_bucket_crc32": (44, 48),
    "principal_id_length": (56, 60),
    "principal_id_value": (64, 98),
    "display_name_length": (104, 108),
    "sid_length": (136, 140),
    "optional_settings_length": (168, 172),
    "logon_magic": (224, 226),
    "logon_generic_payload": (232, 304),
    "logon_identifier_length": (304, 308),
    "logon_identifier_padding": (308, 312),
    "logon_user_info": (312, 320),
    "time_magic": (320, 322),
    "time_schedule": (328, 416),
    "time_identifier_length": (416, 420),
    "time_identifier_padding": (420, 424),
    "boot_magic": (424, 426),
    "boot_generic_payload": (432, 504),
    "boot_identifier_length": (504, 508),
    "boot_identifier_padding": (508, 512),
}


def _slice(data, name):
    start, end = TRIGGER_LAYOUT.get(name, ACTION_LAYOUT.get(name))
    return data[start:end]


def _patch_u32(data, offset, value):
    mutated = bytearray(data)
    struct.pack_into("<I", mutated, offset, value)
    return bytes(mutated)


def _action_summary(action_set):
    return [
        (
            action.action_type.name,
            action.action,
            action.action_args,
            action.working_directory,
        )
        for action in action_set.actions
    ]


def _trigger_types(trigger_set):
    return [trigger.trigger_type.name for trigger in trigger_set.triggers]


class TestActionsDecoding(unittest.TestCase):
    def test_decode_exe_action(self):
        try:
            actions = scheduled_tasks.ActionSet.decode(EXE_ACTION_SET_FIXTURE).actions
            self.assertEqual(len(actions), 1)
            self.assertEqual(actions[0].action_type, scheduled_tasks.ActionType.Exe)
        except Exception:
            self.fail("ActionSet.decode should not raise an exception")

    def test_decode_all_triggers(self):
        """The existing 1808-byte all-triggers fixture must still decode."""
        triggers = scheduled_tasks.TriggerSet.decode(ALL_TRIGGERS_FIXTURE)
        self.assertIsNotNone(triggers)
        self.assertEqual(len(triggers.triggers), 10)

    def test_decode_triggers(self):
        triggers = scheduled_tasks.TriggerSet.decode(LOGON_TRIGGER_SET_FIXTURE)
        self.assertIsNotNone(triggers)
        self.assertEqual(len(triggers.triggers), 1)
        self.assertEqual(triggers.triggers[0].trigger_type.name, "Logon")


class TestScheduledTaskFieldLayout(unittest.TestCase):
    """Pins field positions independently of the decoder implementation."""

    def test_action_field_layout_and_association(self):
        fixture = COMPOSITE_ACTION_SET_FIXTURE
        self.assertEqual(len(fixture), 560)
        self.assertEqual(fixture[:2], struct.pack("<H", 3))
        self.assertEqual(len(EXE_ACTION_SET_FIXTURE), 512)
        self.assertEqual(
            _slice(fixture, "context_value").decode("utf-16le").rstrip("\x00"),
            "LocalSystem",
        )
        self.assertEqual(
            struct.unpack("<I", _slice(fixture, "context_length"))[0],
            len(_slice(fixture, "context_value")),
        )
        self.assertEqual(
            struct.unpack("<I", _slice(fixture, "exe_identifier_length"))[0], 0
        )

        self.assertEqual(struct.unpack("<H", _slice(fixture, "exe_magic"))[0], 0x6666)
        self.assertEqual(
            struct.unpack("<I", _slice(fixture, "exe_command_length"))[0], 110
        )
        self.assertEqual(
            struct.unpack("<I", _slice(fixture, "exe_arguments_length"))[0], 354
        )
        self.assertEqual(
            struct.unpack("<I", _slice(fixture, "exe_working_directory_length"))[0], 0
        )
        self.assertEqual(struct.unpack("<H", _slice(fixture, "exe_flags"))[0], 0)
        self.assertEqual(struct.unpack("<H", _slice(fixture, "com_magic"))[0], 0x7777)
        self.assertEqual(
            struct.unpack("<I", _slice(fixture, "com_identifier_length"))[0], 0
        )
        self.assertEqual(
            struct.unpack("<I", _slice(fixture, "com_arguments_length"))[0], 22
        )

        # Field ranges must not overlap: the Exe argument value ends before
        # the Exe flags, which end before the COM magic.
        self.assertLessEqual(
            ACTION_LAYOUT["exe_arguments_value"][1], ACTION_LAYOUT["exe_flags"][0]
        )
        self.assertLessEqual(
            ACTION_LAYOUT["exe_flags"][1], ACTION_LAYOUT["com_magic"][0]
        )

        action_set = scheduled_tasks.ActionSet.decode(fixture)
        self.assertEqual(
            _action_summary(action_set),
            [
                (
                    "Exe",
                    "%windir%\\system32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "-ExecutionPolicy Unrestricted -NonInteractive -NoProfile "
                    '-WindowStyle Hidden "& %windir%\\system32\\WindowsPowerShell'
                    '\\v1.0\\Modules\\SmbShare\\DisableUnusedSmb1.ps1 -Scenario '
                    'Client"',
                    None,
                ),
                (
                    "ComHandler",
                    "{33221100-5544-7766-8899-aabbccddeeff}",
                    "-p payload",
                    None,
                ),
            ],
        )
        self.assertEqual(action_set.context, "LocalSystem")

        # Each decoded value comes from its own field range.
        exe = action_set.actions[0]
        self.assertEqual(
            exe.action,
            _slice(fixture, "exe_command_value").decode("utf-16le").rstrip("\x00"),
        )
        self.assertEqual(
            exe.action_args,
            _slice(fixture, "exe_arguments_value").decode("utf-16le").rstrip("\x00"),
        )
        com = action_set.actions[1]
        self.assertEqual(
            com.action,
            "{33221100-5544-7766-8899-aabbccddeeff}",
        )
        self.assertEqual(
            com.action_args,
            _slice(fixture, "com_arguments_value").decode("utf-16le").rstrip("\x00"),
        )
        # The Exe arguments stop at 506 and must not contain COM bytes.
        self.assertNotIn("-p payload", exe.action_args)
        self.assertNotIn(
            struct.pack("<H", 0x7777), _slice(fixture, "exe_arguments_value")
        )

    def test_trigger_field_layout(self):
        fixture = COMPOSITE_TRIGGER_SET_FIXTURE
        self.assertEqual(len(fixture), 512)
        self.assertEqual(fixture[0], 0x17)
        self.assertNotEqual(
            struct.unpack("<I", _slice(fixture, "job_bucket_flags"))[0], 0
        )
        self.assertNotEqual(
            struct.unpack("<I", _slice(fixture, "job_bucket_crc32"))[0], 0
        )
        self.assertTrue(_slice(fixture, "logon_generic_payload").startswith(b"\x00"))
        self.assertTrue(_slice(fixture, "time_schedule").startswith(b"\x01\x07\x0a"))
        self.assertTrue(_slice(fixture, "boot_generic_payload").startswith(b"\x00"))

        self.assertEqual(
            struct.unpack("<H", _slice(fixture, "logon_magic"))[0], 0xAAAA
        )
        self.assertEqual(struct.unpack("<H", _slice(fixture, "time_magic"))[0], 0xDDDD)
        self.assertEqual(struct.unpack("<H", _slice(fixture, "boot_magic"))[0], 0xFFFF)
        for field in (
            "logon_identifier_length",
            "time_identifier_length",
            "boot_identifier_length",
        ):
            self.assertEqual(struct.unpack("<I", _slice(fixture, field))[0], 0)
        self.assertEqual(
            struct.unpack("<I", _slice(fixture, "optional_settings_length"))[0], 0x2C
        )
        # Alignment padding after every empty trigger id is the sentinel 0x48.
        for field in (
            "logon_identifier_padding",
            "time_identifier_padding",
            "boot_identifier_padding",
        ):
            self.assertEqual(_slice(fixture, field), b"\x48" * 4)

        self.assertEqual(
            _slice(fixture, "principal_id_value").decode("utf-16le").rstrip("\x00"),
            "InteractiveUsers",
        )

        trigger_set = scheduled_tasks.TriggerSet.decode(fixture)
        self.assertEqual(_trigger_types(trigger_set), ["Logon", "Time", "Boot"])
        logon, time, boot = trigger_set.triggers
        self.assertTrue(logon.enabled)
        self.assertEqual(logon.repetition_interval_seconds, 0)
        self.assertTrue(boot.enabled)
        # Each trigger block was decoded from its own bytes, not its neighbour.
        self.assertEqual(
            time.start_boundary,
            datetime.datetime(
                2024, 10, 9, 10, 35, 33, tzinfo=datetime.timezone.utc
            ),
        )
        self.assertIsNone(logon.start_boundary)
        self.assertIsNone(boot.start_boundary)


class TestActionSetRegressions(unittest.TestCase):
    """Length/version mutations must change the action list, not recycle bytes."""

    def test_normal_action_set_decodes_both_actions(self):
        action_set = scheduled_tasks.ActionSet.decode(COMPOSITE_ACTION_SET_FIXTURE)
        self.assertEqual(
            [action[0] for action in _action_summary(action_set)],
            ["Exe", "ComHandler"],
        )

    def test_exe_arguments_length_cannot_consume_com_handler(self):
        """Confirmed: 354 is the only valid Exe argument length."""
        for declared in (356, 1000, 0):
            with self.subTest(declared=declared):
                mutated = _patch_u32(
                    COMPOSITE_ACTION_SET_FIXTURE,
                    ACTION_LAYOUT["exe_arguments_length"][0],
                    declared,
                )
                action_set = scheduled_tasks.ActionSet.decode(mutated)
                self.assertEqual(action_set.actions, [])
                self.assertNotIn(
                    "payload",
                    " ".join(
                        action.action_args or "" for action in action_set.actions
                    ),
                )

    def test_truncated_exe_arguments_are_rejected(self):
        _, end = ACTION_LAYOUT["exe_arguments_value"]
        mutated = (
            COMPOSITE_ACTION_SET_FIXTURE[: end - 2]
            + COMPOSITE_ACTION_SET_FIXTURE[end:]
        )
        self.assertEqual(
            scheduled_tasks.ActionSet.decode(mutated).actions,
            [],
        )

    def test_truncated_exe_command_is_rejected(self):
        _, end = ACTION_LAYOUT["exe_command_value"]
        mutated = (
            COMPOSITE_ACTION_SET_FIXTURE[: end - 2]
            + COMPOSITE_ACTION_SET_FIXTURE[end:]
        )
        self.assertEqual(scheduled_tasks.ActionSet.decode(mutated).actions, [])

    def test_truncated_com_arguments_drop_only_com_handler(self):
        mutated = COMPOSITE_ACTION_SET_FIXTURE[:-2]
        action_set = scheduled_tasks.ActionSet.decode(mutated)
        self.assertEqual([action[0] for action in _action_summary(action_set)], ["Exe"])
        self.assertEqual(
            action_set.actions[0].action_args,
            _slice(
                COMPOSITE_ACTION_SET_FIXTURE, "exe_arguments_value"
            ).decode("utf-16le").rstrip("\x00"),
        )

    def test_short_com_clsid_drops_com_handler(self):
        start, end = ACTION_LAYOUT["com_clsid"]
        mutated = (
            COMPOSITE_ACTION_SET_FIXTURE[: start + 4]
            + COMPOSITE_ACTION_SET_FIXTURE[end:]
        )
        action_set = scheduled_tasks.ActionSet.decode(mutated)
        self.assertEqual(
            [action[0] for action in _action_summary(action_set)], ["Exe"]
        )

    def test_version_three_flags_are_required(self):
        start, end = ACTION_LAYOUT["exe_flags"]
        mutated = (
            COMPOSITE_ACTION_SET_FIXTURE[:start]
            + COMPOSITE_ACTION_SET_FIXTURE[end:]
        )
        self.assertEqual(scheduled_tasks.ActionSet.decode(mutated).actions, [])

    def test_version_two_layout_excludes_flags_word(self):
        """Confirmed: v2 has no flags word, v3 requires it."""
        v2_fixture = (
            struct.pack("<H", 2)
            + COMPOSITE_ACTION_SET_FIXTURE[2: ACTION_LAYOUT["exe_flags"][0]]
            + COMPOSITE_ACTION_SET_FIXTURE[ACTION_LAYOUT["exe_flags"][1]:]
        )
        action_set = scheduled_tasks.ActionSet.decode(v2_fixture)
        self.assertEqual(
            [action[0] for action in _action_summary(action_set)],
            ["Exe", "ComHandler"],
        )
        # Reusing the v3 body under a v2 header misaligns the COM magic.
        self.assertEqual(
            scheduled_tasks.ActionSet.decode(
                struct.pack("<H", 2) + COMPOSITE_ACTION_SET_FIXTURE[2:]
            ).actions,
            [],
        )
        # Reusing the v2 body under a v3 header leaves the flags word absent.
        self.assertEqual(
            scheduled_tasks.ActionSet.decode(
                struct.pack("<H", 3) + v2_fixture[2:]
            ).actions,
            [],
        )


class TestTriggerSetRegressions(unittest.TestCase):
    """Trigger blocks are alignment-delimited; neighbours must stay separate."""

    def test_normal_trigger_set_decodes_all_three(self):
        trigger_set = scheduled_tasks.TriggerSet.decode(COMPOSITE_TRIGGER_SET_FIXTURE)
        self.assertEqual(_trigger_types(trigger_set), ["Logon", "Time", "Boot"])

    def test_omitted_identifier_padding_breaks_alignment(self):
        """Confirmed: dropping the 4-byte id padding loses following triggers."""
        start, end = TRIGGER_LAYOUT["time_identifier_padding"]
        mutated = (
            COMPOSITE_TRIGGER_SET_FIXTURE[:start]
            + COMPOSITE_TRIGGER_SET_FIXTURE[end:]
        )
        trigger_set = scheduled_tasks.TriggerSet.decode(mutated)
        self.assertEqual(_trigger_types(trigger_set), ["Logon"])

        start, end = TRIGGER_LAYOUT["boot_identifier_padding"]
        mutated = (
            COMPOSITE_TRIGGER_SET_FIXTURE[:start]
            + COMPOSITE_TRIGGER_SET_FIXTURE[end:]
        )
        self.assertEqual(
            _trigger_types(scheduled_tasks.TriggerSet.decode(mutated)),
            ["Logon", "Time"],
        )

    def test_time_identifier_length_consumes_padding(self):
        """Confirmed: a non-zero id length shifts the next magic out of range."""
        for declared in (8, 16):
            with self.subTest(declared=declared):
                mutated = _patch_u32(
                    COMPOSITE_TRIGGER_SET_FIXTURE,
                    TRIGGER_LAYOUT["time_identifier_length"][0],
                    declared,
                )
                trigger_set = scheduled_tasks.TriggerSet.decode(mutated)
                self.assertEqual(_trigger_types(trigger_set), ["Logon"])

    def test_truncated_boot_trigger_is_not_reported(self):
        self.assertEqual(
            _trigger_types(
                scheduled_tasks.TriggerSet.decode(COMPOSITE_TRIGGER_SET_FIXTURE[:-2])
            ),
            ["Logon", "Time"],
        )
        self.assertEqual(
            _trigger_types(
                scheduled_tasks.TriggerSet.decode(COMPOSITE_TRIGGER_SET_FIXTURE[:-4])
            ),
            ["Logon", "Time"],
        )

    def test_truncated_logon_user_info_drops_logon(self):
        mutated = COMPOSITE_TRIGGER_SET_FIXTURE[
            : TRIGGER_LAYOUT["logon_user_info"][0] - 2
        ]
        self.assertEqual(
            _trigger_types(scheduled_tasks.TriggerSet.decode(mutated)), []
        )

    def test_version_changes_trigger_layout(self):
        """Confirmed: 0x16 has no principal/display fields, so the version 0x17
        header shifts and only the trailing Boot block is still reachable."""
        mutated = bytes([0x16]) + COMPOSITE_TRIGGER_SET_FIXTURE[1:]
        self.assertEqual(
            _trigger_types(scheduled_tasks.TriggerSet.decode(mutated)), ["Boot"]
        )
        mutated = bytes([0x15]) + COMPOSITE_TRIGGER_SET_FIXTURE[1:]
        self.assertEqual(_trigger_types(scheduled_tasks.TriggerSet.decode(mutated)), [])

    def test_principal_id_length_is_honoured(self):
        mutated = _patch_u32(
            COMPOSITE_TRIGGER_SET_FIXTURE,
            TRIGGER_LAYOUT["principal_id_length"][0],
            1000,
        )
        self.assertIsNone(scheduled_tasks.TriggerSet.decode(mutated))

    def test_display_name_length_is_honoured(self):
        mutated = _patch_u32(
            COMPOSITE_TRIGGER_SET_FIXTURE,
            TRIGGER_LAYOUT["display_name_length"][0],
            1000,
        )
        self.assertIsNone(scheduled_tasks.TriggerSet.decode(mutated))

    def test_sid_length_is_honoured(self):
        mutated = _patch_u32(
            COMPOSITE_TRIGGER_SET_FIXTURE, TRIGGER_LAYOUT["sid_length"][0], 40
        )
        self.assertIsNone(scheduled_tasks.TriggerSet.decode(mutated))

    def test_optional_settings_length_is_honoured(self):
        """Confirmed: claiming the larger 0x58 layout while the bytes are absent
        prevents any trigger in the set from being reported."""
        mutated = _patch_u32(
            COMPOSITE_TRIGGER_SET_FIXTURE,
            TRIGGER_LAYOUT["optional_settings_length"][0],
            0x58,
        )
        self.assertEqual(_trigger_types(scheduled_tasks.TriggerSet.decode(mutated)), [])
