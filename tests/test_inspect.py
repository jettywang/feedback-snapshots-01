"""
Test dynaconf.utils.inspect:inspect
"""

from __future__ import annotations

import copy
import os
from textwrap import dedent

import pytest

from dynaconf import Dynaconf
from dynaconf.utils.files import content_digest
from dynaconf.utils.forensics import compare_snapshots
from dynaconf.utils.forensics import get_forensic_snapshot
from dynaconf.utils.forensics import verify_file_digest
from dynaconf.utils.inspect import _ensure_serializable
from dynaconf.utils.inspect import _get_data_by_key
from dynaconf.utils.inspect import EnvNotFoundError
from dynaconf.utils.inspect import get_debug_info
from dynaconf.utils.inspect import get_history
from dynaconf.utils.inspect import inspect_settings
from dynaconf.utils.inspect import KeyNotFoundError
from dynaconf.utils.inspect import OutputFormatError
from dynaconf.validator import Validator

pytestmark = pytest.mark.usefixtures("no_deprecations")


def create_file(filename: str, data: str) -> str:
    with open(filename, "w") as f:
        f.write(dedent(data))
    return filename


def is_dict_subset(original: dict, partial: dict) -> bool:
    """Check if partial dict is subset of original dict."""
    return {**original, **partial} == original


@pytest.fixture(autouse=True, scope="function")
def teardown():
    backup = copy.deepcopy(os.environ)
    for key in os.environ.keys():
        if key.startswith(("DYNACONF_", "FLASK_", "DJANGO_")):
            del os.environ[key]
    yield
    os.environ.update(backup)


@pytest.fixture(autouse=True, scope="module")
def module_teardown():
    yield
    for key in os.environ.keys():
        if key.startswith(("DYNACONF_", "FLASK_", "DJANGO_")):
            del os.environ[key]


def test_ensure_serializable():
    settings = Dynaconf()
    settings.update(
        {
            "listy": [1, 2, 3, {"a": "A", "b": [4, 5, 6]}],
            "dicty": {"a": "A", "b": [1, 2, 3, {"a": "A", "b": "B"}]},
        }
    )
    normal_list = _ensure_serializable(settings.listy)
    normal_dict = _ensure_serializable(settings.dicty)
    assert normal_list.__class__ is list
    assert normal_list[3].__class__ is dict
    assert normal_list[3]["b"].__class__ is list

    assert normal_dict.__class__ is dict
    assert normal_dict["b"].__class__ is list  # type: ignore
    assert normal_dict["b"][3].__class__ is dict  # type: ignore


def test_get_data_by_key():
    data = {"a": "A", "b": [1, 2, 3, {"a": "A", "b": "B"}], "c": {"d": "D"}}
    assert _get_data_by_key(data, "a") == "A"
    # 2 cases below are not supported dynaconf idiom yet
    # assert _get_data_by_key(data, "b._1_") == 2
    # assert _get_data_by_key(data, "b._3_.b") == "B"
    assert _get_data_by_key(data, "c.d") == "D"
    assert _get_data_by_key(data, "this.doesnt.exist", default="foo") == "foo"


def test_get_history_general(tmp_path):
    """
    Given two yaml files
    Should return
        - list of length 2
        - per-file metadata containing: loader, identifier, env and value.
        - correct types: dicts and lists, not DataDict and DataList
    """
    file_a = tmp_path / "a.yml"
    file_b = tmp_path / "b.yml"
    create_file(
        file_a,
        """\
        dicty:
          a: A
          b:
            - 1
            - c: C
              d: D
        """,
    )
    create_file(
        file_b,
        """\
        listy:
          - 1
          - a: A
            b: B
            c:
              - 1
              - 2
        """,
    )
    settings = Dynaconf(settings_file=[file_a, file_b])
    history = get_history(settings)

    # metadata
    assert len(history) == 4
    assert is_dict_subset(
        history[0],
        {
            "loader": "set_method",
            "identifier": "init_kwargs",
            "env": "global",
            "merged": False,
        },
    )
    assert is_dict_subset(
        history[1],
        {
            "loader": "set_method",
            "identifier": "settings_module_method",
            "env": "global",
            "merged": False,
        },
    )
    assert is_dict_subset(
        history[2],
        {
            "loader": "yaml",
            "identifier": str(file_a),
            "env": "default",
            "merged": False,
        },
    )
    assert is_dict_subset(
        history[3],
        {
            "loader": "yaml",
            "identifier": str(file_b),
            "env": "default",
            "merged": False,
        },
    )

    # data integrity
    assert "SETTINGS_FILE_FOR_DYNACONF" in history[0]["value"]
    assert "SETTINGS_MODULE" in history[1]["value"]
    assert history[2]["value"]["DICTY"] == {
        "a": "A",
        "b": [1, {"c": "C", "d": "D"}],
    }
    assert history[3]["value"]["LISTY"] == [
        1,
        {"a": "A", "b": "B", "c": [1, 2]},
    ]

    # types has been normalized
    assert history[2]["value"]["DICTY"].__class__ is dict
    assert history[3]["value"]["LISTY"].__class__ is list


def test_get_history_env_false__file_plus_envvar(tmp_path):
    """
    Given environments=False and sources=file+envvar
    Should return correct metadata history
    """
    os.environ["DYNACONF_FOO"] = "from_environ"
    file_a = tmp_path / "a.yml"
    create_file(file_a, "foo: from_file")

    settings = Dynaconf(settings_file=file_a)
    history = get_history(settings)

    # metadata
    assert len(history) == 4
    assert is_dict_subset(
        history[2],
        {
            "loader": "yaml",
            "identifier": str(file_a),
            "env": "default",
            "merged": False,
        },
    )
    assert is_dict_subset(
        history[3],
        {
            "loader": "env_global",
            "identifier": "DYNACONF",
            "env": "global",
            "merged": False,
        },
    )


def test_get_history_history_limit(tmp_path):
    """
    Given a history longer than history_limit
    Should return only the first history_limit entries
    """
    file_a = tmp_path / "a.yml"
    create_file(file_a, "foo: from_file")
    settings = Dynaconf(settings_file=file_a, environments=False)

    full = get_history(settings)
    assert len(full) > 1

    limited = get_history(settings, history_limit=1)
    assert len(limited) == 1
    assert limited == full[:1]


def test_get_history_history_limit_larger_than_history(tmp_path):
    """
    Given a history_limit larger than the history
    Should return the whole history unchanged
    """
    file_a = tmp_path / "a.yml"
    create_file(file_a, "foo: from_file")
    settings = Dynaconf(settings_file=file_a, environments=False)

    full = get_history(settings)
    assert get_history(settings, history_limit=len(full) + 10) == full


def test_get_history_env_false__val_default_plus_envvar():
    """
    Given environments=False and sources=validation-default+envvar
    Should return correct metadata history
    """
    os.environ["DYNACONF_FOO"] = "from_environ"

    settings = Dynaconf(
        validators=[Validator("bar", default="from_val_default")]
    )
    history = get_history(settings)

    # metadata (validation_default runs after envvar loading)
    assert len(history) == 3
    assert is_dict_subset(
        history[0],
        {
            "loader": "env_global",
            "identifier": "DYNACONF",
            "env": "global",
            "merged": False,
        },
    )
    assert is_dict_subset(
        history[1],
        {
            "loader": "setdefault",
            "identifier": "unique",
            "env": "main",
            "merged": False,
        },
    )


def test_get_history_env_false__merge_marks(tmp_path):
    """
    Given environments=False and sources=envvar+file
    Should return correct metadata history
    """
    os.environ["DYNACONF_LISTY"] = "@merge [10,11,12]"
    file_a = tmp_path / "file_a.toml"
    file_b = tmp_path / "file_b.toml"
    file_c = tmp_path / "file_c.toml"
    create_file(file_a, "listy=[1,2,3]")
    create_file(file_b, "listy=[4,5,6, 'dynaconf_merge']")
    create_file(file_c, "dynaconf_merge=true\nlisty=[7,8,9]")

    settings = Dynaconf(settings_file=[file_a, file_b, file_c])
    history = get_history(settings)

    # metadata
    assert len(history) == 6
    assert history[2] == {
        "loader": "toml",
        "identifier": str(file_a),
        "env": "default",
        "merged": False,
        "value": {"LISTY": [1, 2, 3]},
    }
    assert history[3] == {
        "loader": "toml",
        "identifier": str(file_b),
        "env": "default",
        "merged": True,
        "value": {"LISTY": [4, 5, 6, "dynaconf_merge"]},
    }
    assert history[4] == {
        "loader": "toml",
        "identifier": str(file_c),
        "env": "default",
        "merged": True,
        "value": {"LISTY": [7, 8, 9]},
    }
    assert is_dict_subset(
        history[5],
        {
            "loader": "env_global",
            "identifier": "DYNACONF",
            "env": "global",
            "merged": True,
        },
    )
    # when using @merge the value outputs as `Merge(....)`
    assert "Merge" in history[5]["value"]["LISTY"]


def test_get_history_env_true__file_plus_envvar(tmp_path):
    """
    Given environments=True and sources=file+envvar
    Should return correct metadata history
    """
    os.environ["DYNACONF_FOO"] = "from_environ"
    file_a = tmp_path / "a.toml"
    create_file(
        file_a,
        """\n
        default.foo="from_default_env"
        development.foo="from_development_env"
        """,
    )

    settings = Dynaconf(settings_file=file_a, environments=True)
    history = get_history(settings)

    assert len(history) == 5
    assert history[2] == {
        "loader": "toml",
        "identifier": str(file_a),
        "env": "default",
        "merged": False,
        "value": {"FOO": "from_default_env"},
    }
    assert history[3] == {
        "loader": "toml",
        "identifier": str(file_a),
        "env": "development",
        "merged": False,
        "value": {"FOO": "from_development_env"},
    }
    assert history[4] == {
        "loader": "env_global",
        "identifier": "DYNACONF",
        "env": "global",
        "merged": False,
        "value": {"FOO": "from_environ"},
    }


def test_get_history_env_true__val_default_plus_file(tmp_path):
    """
    Given environments=True and sources=validation-default+file
    Should return correct metadata history
    """
    file_a = tmp_path / "a.toml"
    create_file(
        file_a,
        """\
        default.foo="from_default_file"
        development.foo="from_development_file"
        """,
    )
    settings = Dynaconf(
        validators=[
            Validator("bar", default="from_val_default_current_env"),
            Validator(
                "baz", env="production", default="from_val_default_prod"
            ),
        ],
        settings_file=file_a,
        environments=True,
    )
    history = get_history(settings)

    assert len(history) == 8
    assert history[2] == {
        "loader": "toml",
        "identifier": str(file_a),
        "env": "default",
        "merged": False,
        "value": {"FOO": "from_default_file"},
    }
    assert history[3] == {
        "loader": "toml",
        "identifier": str(file_a),
        "env": "development",
        "merged": False,
        "value": {"FOO": "from_development_file"},
    }
    assert history[4] == {
        "loader": "setdefault",
        "identifier": "unique",
        "env": "development",
        "merged": False,
        "value": {"BAR": "from_val_default_current_env"},
    }
    # REVIEW: history[5] is not correct, validation default on other env should
    # not have side effect on current object but only on its copy/clone
    # history[6] == switching to production env, so it sets ENV_FOR_DYNACONF
    assert history[7] == {
        "loader": "setdefault",
        "identifier": "unique",
        "env": "production",
        "merged": False,
        "value": {"BAZ": "from_val_default_prod"},
    }


def test_get_history_env_true__merge_marks(tmp_path):
    """
    Given environments=True and sources=envvar+file
    Should return correct metadata history
    """
    os.environ["DYNACONF_LISTY"] = "@merge [10,11,12]"
    file_a = tmp_path / "file_a.toml"
    file_b = tmp_path / "file_b.toml"
    file_c = tmp_path / "file_c.toml"
    create_file(file_a, "listy=[1,2,3]")
    create_file(file_b, "listy=[4,5,6, 'dynaconf_merge']")
    create_file(file_c, "dynaconf_merge=true\nlisty=[7,8,9]")

    settings = Dynaconf(settings_file=[file_a, file_b, file_c])
    history = get_history(settings)

    # metadata
    assert len(history) == 6
    assert history[2] == {
        "loader": "toml",
        "identifier": str(file_a),
        "env": "default",
        "merged": False,
        "value": {"LISTY": [1, 2, 3]},
    }
    assert history[3] == {
        "loader": "toml",
        "identifier": str(file_b),
        "env": "default",
        "merged": True,
        "value": {"LISTY": [4, 5, 6, "dynaconf_merge"]},
    }
    assert history[4] == {
        "loader": "toml",
        "identifier": str(file_c),
        "env": "default",
        "merged": True,
        "value": {"LISTY": [7, 8, 9]},
    }
    assert is_dict_subset(
        history[5],
        {
            "loader": "env_global",
            "identifier": "DYNACONF",
            "env": "global",
            "merged": True,
        },
    )
    # when using @merge the value outputs as `Merge(....)`
    assert "Merge" in history[5]["value"]["LISTY"]


def test_get_history_key_filter(tmp_path):
    """Asserts key filtering through get_history param works"""
    file_a = tmp_path / "file_a.toml"
    file_b = tmp_path / "file_b.toml"
    file_c = tmp_path / "file_c.toml"
    create_file(file_a, "a='aA'\nb='aB'\nc='aC'")
    create_file(file_b, "a='bA'\nb='bB'\nc='bC'")
    create_file(file_c, "a='cA'\nb='cB'\nc='cC'")

    settings = Dynaconf(settings_file=[file_a, file_b, file_c])
    history = get_history(settings, key="a")
    assert history[0]["value"] == "aA"
    assert history[1]["value"] == "bA"
    assert history[2]["value"] == "cA"


def test_get_history_key_filter_nested(tmp_path):
    """Asserts key filtering through get_history param works"""
    file_a = tmp_path / "file_a.toml"
    file_b = tmp_path / "file_b.toml"
    file_c = tmp_path / "file_c.toml"
    create_file(file_a, "a.b='aB'\na.c='aC'")
    create_file(file_b, "a.b='bB'\na.c='bC'")
    create_file(file_c, "a.b='cB'\na.c='cC'")

    settings = Dynaconf(settings_file=[file_a, file_b, file_c])
    history = get_history(settings, key="a.c")
    assert len(history) == 3
    assert history[0]["value"] == "aC"
    assert history[1]["value"] == "bC"
    assert history[2]["value"] == "cC"


def test_get_history_env_filter(tmp_path):
    """Asserts env filtering through env_filter function works"""
    file_a = tmp_path / "file_a.toml"
    file_b = tmp_path / "file_b.toml"
    create_file(
        file_a,
        """\
        [default]
        foo="from_default_a"
        [development]
        foo="from_development_a"
        [prod]
        foo="from_prod_a"
        """,
    )
    create_file(
        file_b,
        """\
        [default]
        foo="from_default_b"
        [development]
        foo="from_development_b"
        [prod]
        foo="from_prod_b"
        """,
    )

    settings = Dynaconf(settings_file=[file_a, file_b], environments=True)
    settings.from_env("prod")  # CAVEAT: activate loading of prod
    history = get_history(
        settings, filter_callable=lambda x: x.env.lower() == "prod"
    )

    assert len(history) == 2
    assert history[0]["value"] == {"FOO": "from_prod_a"}
    assert history[1]["value"] == {"FOO": "from_prod_b"}


def test_get_history_env_and_key_filter(tmp_path):
    """Asserts combined use of filters works"""
    file_a = tmp_path / "file_a.toml"
    file_b = tmp_path / "file_b.toml"
    create_file(
        file_a,
        """\
        [default]
        foo="from_default_a"
        bar="from_default_a"
        [development]
        foo="from_development_a"
        bar="from_development_a"
        [prod]
        foo="from_prod_a"
        bar="from_prod_a"
        """,
    )
    create_file(
        file_b,
        """\
        [default]
        foo="from_default_b"
        bar="from_default_b"
        [development]
        foo="from_development_b"
        bar="from_development_b"
        [prod]
        foo="from_prod_b"
        bar="from_prod_b"
        """,
    )

    settings = Dynaconf(settings_file=[file_a, file_b], environments=True)
    settings.from_env("prod")  # CAVEAT: activate loading of prod
    history = get_history(
        settings,
        key="bar",
        filter_callable=lambda x: x.env.lower() == "prod",
    )
    assert len(history) == 2
    assert history[0]["value"] == "from_prod_a"
    assert history[1]["value"] == "from_prod_b"


def tests_get_history_with_variable_interpolation():
    """Variable interpolation is not evaluated.
    https://github.com/dynaconf/dynaconf/issues/1180

    The original issue was about an exception being raised when there was
    variable interpolation involved. But in the end, the get_history shouldnt
    evaluate the interpolations:

    - History should accurately inform the order and content of what the user loaded.
    - For a key with a interpolation value, the accurate representation is not the evaluated
      value, but the original template string.
    - The evaluated depends on other keys, so for
      history inspecting it is more reliable to show what variables were used so the user
      can verify if everything happened as expected.
    """
    data = {
        "a": {
            "b": "foo",
            "c": "bar",
            "d": "@format {this.a.b} {this.a.c}",
        }
    }

    settings = Dynaconf(**data)

    assert settings.a.d == "foo bar"
    history = get_history(settings, "a.d")
    # shows the not-evaluated (raw) value
    assert history[0]["value"] == "@format {this.a.b} {this.a.c}"


def test_caveat__get_history_env_true(tmp_path):
    """
    Given environments=True and sources=file
    Should return correct metadata history

    Caveat:
        An environment that is not a builtin env name, like (default,
        global, development) and that is not the 'current_env' will not
        be loaded and, thus, will not be shown in history.

        Possible workaround:
        a) leave for the user to trigger this env loaded.
           >>> settings.from_env("production")
        b) add a global config for loading all envs, even if they are
           not in the builtin env names.
    """
    file_a = tmp_path / "a.toml"
    create_file(
        file_a,
        """\n
        default.foo="from_default_env"
        development.foo="from_development_env"
        production.foo="from_production_env"
        """,
    )

    settings = Dynaconf(settings_file=file_a, environments=True)
    history = get_history(settings)
    assert len(history) == 4
    assert history[2] == {
        "loader": "toml",
        "identifier": str(file_a),
        "env": "default",
        "merged": False,
        "value": {"FOO": "from_default_env"},
    }
    assert history[3] == {
        "loader": "toml",
        "identifier": str(file_a),
        "env": "development",
        "merged": False,
        "value": {"FOO": "from_development_env"},
    }

    with pytest.raises(IndexError):
        assert history[4] == {
            "loader": "toml",
            "identifier": str(file_a),
            "env": "production",
            "merged": False,
            "value": {"FOO": "from_production_env"},
        }


def test_caveat__get_history_env_true_workaround(tmp_path):
    """
    Given environments=True and sources=file
    Should return correct metadata history

    Caveat: see original test
    Workaround: force loading with desired 'current_env'
    """
    file_a = tmp_path / "a.toml"
    create_file(
        file_a,
        """\n
        default.foo="from_default_env"
        development.foo="from_development_env"
        production.foo="from_production_env"
        """,
    )

    settings = Dynaconf(settings_file=file_a, environments=True)
    settings.from_env("production")
    history = get_history(settings)
    assert len(history) == 6
    assert history[2] == {
        "loader": "toml",
        "identifier": str(file_a),
        "env": "default",
        "merged": False,
        "value": {"FOO": "from_default_env"},
    }
    assert history[3] == {
        "loader": "toml",
        "identifier": str(file_a),
        "env": "development",
        "merged": False,
        "value": {"FOO": "from_development_env"},
    }

    assert history[5] == {
        "loader": "toml",
        "identifier": str(file_a),
        "env": "production",
        "merged": False,
        "value": {"FOO": "from_production_env"},
    }


def test_inspect_key_filter(tmp_path):
    os.environ["DYNACONF_FOO"] = "from_environ"
    os.environ["DYNACONF_BAR"] = "environ_only"
    filename = create_file(tmp_path / "a.yaml", "foo: from_yaml")
    settings = Dynaconf(settings_file=filename)

    result = inspect_settings(settings, key="foo", dumper="yaml")

    assert result["header"]["key_filter"] == "foo"
    assert result["current"] == "from_environ"
    assert result["history"] == [
        {
            "loader": "env_global",
            "identifier": "DYNACONF",
            "env": "global",
            "merged": False,
            "value": "from_environ",
        },
        {
            "loader": "yaml",
            "identifier": str(filename),
            "env": "default",
            "merged": False,
            "value": "from_yaml",
        },
    ]


def test_inspect_no_filter(tmp_path):
    os.environ["DYNACONF_FOO"] = "from_environ"
    os.environ["DYNACONF_BAR"] = "environ_only"
    filename = create_file(tmp_path / "a.yaml", "foo: from_yaml")
    settings = Dynaconf(settings_file=filename)
    result = inspect_settings(settings, dumper="yaml")

    assert result["header"]["key_filter"] == "None"
    assert result["header"]["env_filter"] == "None"
    assert result["current"] == {"FOO": "from_environ", "BAR": "environ_only"}

    # first two entries
    assert result["history"][:2] == [
        {
            "env": "global",
            "identifier": "DYNACONF",
            "loader": "env_global",
            "merged": False,
            "value": {"BAR": "environ_only", "FOO": "from_environ"},
        },
        {
            "env": "default",
            "identifier": str(filename),
            "loader": "yaml",
            "merged": False,
            "value": {"FOO": "from_yaml"},
        },
    ]


def test_inspect_env_filter(tmp_path):
    """
    Caveat: env filter will show current default env values too.
            History will be filtered properly.
    """
    filename = create_file(
        tmp_path / "a.toml",
        """\
        default.foo="from_env_default"
        development.foo="from_env_dev"
        prod.bar="prod_only"
        """,
    )

    settings = Dynaconf(settings_file=filename, environments=True)
    result = inspect_settings(settings, dumper="yaml", env="prod")
    assert result["header"]["env_filter"] == "prod"
    assert result["header"]["key_filter"] == "None"
    assert result["current"] == {"FOO": "from_env_default", "BAR": "prod_only"}
    assert result["history"] == [
        {
            "loader": "toml",
            "identifier": str(filename),
            "env": "prod",
            "merged": False,
            "value": {"BAR": "prod_only"},
        }
    ]


def test_inspect_to_file(tmp_path):
    """Assert file is written correctly with 'to_file' option"""
    os.environ["DYNACONF_FOO"] = "from_environ"
    os.environ["DYNACONF_BAR"] = "environ_only"
    filename = create_file(tmp_path / "a.yaml", "foo: from_yaml")
    settings = Dynaconf(settings_file=filename)

    file_out = tmp_path / "output.yml"
    inspect_settings(settings, dumper="yaml", to_file=file_out)

    # open created file
    assert file_out.read_text() == dedent(
        f"""\
        header:
          env_filter: None
          key_filter: None
          new_first: 'True'
          history_limit: None
          include_internal: 'False'
        current:
          FOO: from_environ
          BAR: environ_only
        history:
        - loader: env_global
          identifier: DYNACONF
          env: global
          merged: false
          value:
            FOO: from_environ
            BAR: environ_only
        - loader: yaml
          identifier: {filename}
          env: default
          merged: false
          value:
            FOO: from_yaml
        - loader: set_method
          identifier: settings_module_method
          env: global
          merged: false
          value:
            SETTINGS_MODULE: {filename}
        - loader: set_method
          identifier: init_kwargs
          env: global
          merged: false
          value:
            SETTINGS_FILE_FOR_DYNACONF: {filename}
          """
    )


def test_inspect_exception_key_not_found():
    settings = Dynaconf()
    with pytest.raises(KeyNotFoundError):
        inspect_settings(settings, key="non_existent")


def test_inspect_empty_settings():
    settings = Dynaconf()
    result = inspect_settings(settings)
    assert result["history"] == []


def test_inspect_exception_env_not_found():
    settings = Dynaconf(environments=True)
    with pytest.raises(EnvNotFoundError):
        inspect_settings(settings, env="non_existent")


def test_inspect_exception_invalid_format():
    settings = Dynaconf()
    with pytest.raises(OutputFormatError):
        inspect_settings(settings, dumper="invalid_format")


def test_get_debug_info(tmp_path):
    file_a = tmp_path / "a.yml"
    file_b = tmp_path / "b.yml"
    file_c = tmp_path / "c.py"
    create_file(
        file_a,
        """\
        dicty:
          a: A
          b:
            - 1
            - c: C
              d: D
        """,
    )
    create_file(
        file_b,
        """\
        listy:
          - 1
          - a: A
            b: B
            c:
              - 1
              - 2
        """,
    )
    create_file(
        file_c,
        """\
        from dynaconf import post_hook

        FRUIT = "tomato"

        @post_hook
        def set_name_to_foo2(settings):
            return {"name": "foo2"}
        """,
    )

    def set_name_to_foo(settings):
        return {"name": "foo"}

    settings = Dynaconf(
        settings_file=[file_a, file_b],
        post_hooks=[
            set_name_to_foo,
            lambda settings: {"bar": "baz"},
        ],
        hello="world",
        validators=[Validator("name", required=True)],
    )

    settings.load_file(file_c)

    debug_info = get_debug_info(settings)
    assert "dynaconf" in debug_info["versions"]
    assert debug_info["root_path"] == str(tmp_path)
    assert len(debug_info["validators"]) == 1
    assert len(debug_info["post_hooks"]) == 3
    assert len(debug_info["loaded_hooks"]) == 3
    assert len(debug_info["loaded_files"]) == 3
    assert len(debug_info["history"]) == 11

    # Now including keys
    debug_info = get_debug_info(settings, verbosity=1)
    assert debug_info["history"][0]["data"] == [
        "POST_HOOKS",
        "HELLO",
        "SETTINGS_FILE_FOR_DYNACONF",
    ]
    assert debug_info["history"][0]["identifier"] == "init_kwargs"
    assert len(debug_info["history"][1]["data"]) > 1
    assert debug_info["history"][1]["identifier"] == "default_settings"
    assert debug_info["history"][2]["data"] == ["SETTINGS_MODULE"]
    assert debug_info["history"][2]["identifier"] == "settings_module_method"
    assert debug_info["history"][3]["data"] == ["DICTY"]
    assert debug_info["history"][3]["identifier"] == str(file_a)
    assert debug_info["history"][4]["data"] == ["LISTY"]
    assert debug_info["history"][4]["identifier"] == str(file_b)
    assert debug_info["history"][5]["data"] == ["NAME"]
    assert debug_info["history"][5]["identifier"] == "set_name_to_foo@instance"
    assert debug_info["history"][6]["data"] == ["BAR"]
    assert "lambda_" in debug_info["history"][6]["identifier"]
    assert debug_info["history"][9]["data"] == ["FRUIT"]

    c_identifier = str(file_c).rstrip(".py")

    assert debug_info["history"][9]["identifier"] == c_identifier
    assert debug_info["history"][10]["data"] == ["NAME"]
    assert (
        debug_info["history"][10]["identifier"]
        == f"set_name_to_foo2@{c_identifier}"
    )
    assert debug_info["loaded_files"] == [
        str(file_a),
        str(file_b),
        str(file_c),
    ]
    assert debug_info["loaded_hooks"][0]["data"] == ["name"]
    assert debug_info["loaded_hooks"][0]["hook"] == "set_name_to_foo@instance"
    assert debug_info["loaded_hooks"][1]["data"] == ["bar"]
    assert "lambda_" in debug_info["loaded_hooks"][1]["hook"]
    assert debug_info["loaded_hooks"][2]["data"] == ["name"]
    assert (
        debug_info["loaded_hooks"][2]["hook"]
        == f"set_name_to_foo2@{c_identifier}"
    )
    assert "set_name_to_foo" in debug_info["post_hooks"][0]
    assert "lambda" in debug_info["post_hooks"][1]
    assert "set_name_to_foo2" in debug_info["post_hooks"][2]

    # Now including keys and values
    debug_info = get_debug_info(settings, verbosity=2)
    assert debug_info["history"][0]["data"]["HELLO"] == "world"
    assert debug_info["history"][3]["data"]["DICTY"] == {
        "a": "A",
        "b": [1, {"c": "C", "d": "D"}],
    }
    assert debug_info["history"][4]["data"]["LISTY"] == [
        1,
        {"a": "A", "b": "B", "c": [1, 2]},
    ]
    assert debug_info["history"][5]["data"]["NAME"] == "foo"
    assert debug_info["history"][6]["data"]["BAR"] == "baz"
    assert debug_info["history"][9]["data"]["FRUIT"] == "tomato"
    assert debug_info["history"][10]["data"]["NAME"] == "foo2"
    assert debug_info["loaded_hooks"][0]["data"]["name"] == "foo"
    assert debug_info["loaded_hooks"][1]["data"]["bar"] == "baz"
    assert debug_info["loaded_hooks"][2]["data"]["name"] == "foo2"

    # Now passing a specific key
    debug_info = get_debug_info(settings, key="DICTY")
    # assert the passed key is present on its own entry
    # assert other keys are not present
    assert debug_info["history"][0]["data"] == {}
    assert debug_info["history"][1]["data"] == {}
    assert debug_info["history"][2]["data"] == {}
    assert debug_info["history"][3]["data"]["DICTY"] == {
        "a": "A",
        "b": [1, {"c": "C", "d": "D"}],
    }
    assert debug_info["history"][4]["data"] == {}
    assert debug_info["history"][5]["data"] == {}
    assert debug_info["history"][6]["data"] == {}
    assert debug_info["history"][7]["data"] == {}
    assert debug_info["history"][8]["data"] == {}
    assert debug_info["history"][9]["data"] == {}
    assert debug_info["history"][10]["data"] == {}
    assert debug_info["loaded_hooks"][0]["data"] == {}
    assert debug_info["loaded_hooks"][1]["data"] == {}


# ---------------------------------------------------------------------------
# Forensic snapshots: existing loading records -> evidence, generations, gaps
# ---------------------------------------------------------------------------


def _snapshot_run(
    files, *, env_name=None, env=None, label=None, previous=None
):
    """Build a settings generation and its forensic snapshot."""
    if env_name is not None:
        os.environ["DYNACONF_NAME"] = env_name
    settings = Dynaconf(settings_file=files, environments=True)
    return settings, get_forensic_snapshot(
        settings, label=label, previous=previous
    )


def _sources_by_file(snapshot, filename):
    return [
        source
        for source in snapshot["sources"]
        if os.path.basename(source["identifier"]) == filename
    ]


def test_forensic_snapshot_separates_direct_and_merged_evidence(tmp_path):
    """Three sources: two files and one envvar.

    The direct value from each source is recorded separately from the value
    that was effective after merging, and the winning source per key is known.
    """
    base = create_file(
        tmp_path / "base.toml",
        """\
        [default]
        name = "from_base"
        port = 8000
        nested = {a = 1, b = 2}
        items = [1, 2]
        """,
    )
    overrides = create_file(
        tmp_path / "overrides.toml",
        """\
        [default]
        port = 9000
        nested = {b = 3}
        items = [3, "dynaconf_merge"]
        """,
    )
    _, snapshot = _snapshot_run(
        [base, overrides], env_name="from_env", label="run-1"
    )

    # Application sources: base file, override file, its merge record and the
    # envvar. The merge record is kept apart from the plain file record.
    assert [source["identifier"] for source in snapshot["sources"]] == [
        str(base),
        str(overrides),
        str(overrides),
        "DYNACONF",
    ]
    assert [source["merged"] for source in snapshot["sources"]] == [
        False,
        False,
        True,
        False,
    ]

    base_source = _sources_by_file(snapshot, "base.toml")[0]
    assert base_source["keys"]["PORT"]["direct"] == 8000
    assert base_source["keys"]["PORT"]["effective"] == 8000
    assert base_source["keys"]["PORT"]["changed"] is True

    override_source = _sources_by_file(snapshot, "overrides.toml")[0]
    # File defaults still replace earlier values as usual.
    assert override_source["keys"]["PORT"] == {
        "direct": 9000,
        "before": 8000,
        "effective": 9000,
        "changed": True,
        "change": "modified",
    }
    # A plain nested override replaces the mapping (no implicit merge).
    assert override_source["keys"]["NESTED"]["direct"] == {"b": 3}
    assert override_source["keys"]["NESTED"]["before"] == {"a": 1, "b": 2}
    assert override_source["keys"]["NESTED"]["effective"] == {"b": 3}

    # The merge record is a distinct source record with its own digest/merge
    # evidence; the raw marker is kept separate from the merged outcome.
    merge_record = _sources_by_file(snapshot, "overrides.toml")[1]
    assert merge_record["merged"] is True
    item = merge_record["keys"]["ITEMS"]
    assert item["direct"] == [3, "dynaconf_merge"]
    assert item["effective"] == [1, 2, 3]
    assert item["merged"] is True
    assert merge_record["merged_keys"] == ["ITEMS"]

    env_source = snapshot["sources"][-1]
    assert env_source["loader"] == "env_global"
    assert env_source["keys"]["NAME"] == {
        "direct": "from_env",
        "before": "from_base",
        "effective": "from_env",
        "changed": True,
        "change": "modified",
    }

    # Final merged state and its winning sources.
    assert snapshot["current"] == {
        "NAME": "from_env",
        "PORT": 9000,
        "NESTED": {"b": 3},
        "ITEMS": [1, 2, 3],
    }
    assert snapshot["keys"]["NAME"]["source"]["identifier"] == "DYNACONF"
    assert snapshot["keys"]["PORT"]["source"]["identifier"] == str(overrides)
    assert snapshot["keys"]["ITEMS"]["source"]["merged"] is True
    assert snapshot["keys"]["ITEMS"]["direct"] == [3, "dynaconf_merge"]

    # Each file source carries a digest that can be looked up again.
    assert override_source["digest"]["algorithm"] == "sha256"
    assert snapshot["files"][str(overrides)]["value"] == content_digest(
        overrides
    )["value"]


def test_forensic_snapshot_two_runs_report_changed_keys_and_order(tmp_path):
    """Two generations: content change in one file plus an envvar change."""
    base = create_file(
        tmp_path / "base.toml", '[default]\nname = "base"\nport = 8000\n'
    )
    overrides = create_file(
        tmp_path / "overrides.toml", "[default]\nport = 9000\n"
    )

    _, first = _snapshot_run(
        [base, overrides], env_name="first", label="run-1"
    )
    assert first["generation"]["label"] == "run-1"
    assert first["current"]["NAME"] == "first"
    assert first["generation"]["id"].startswith("sha256:")

    create_file(
        tmp_path / "base.toml", '[default]\nname = "base"\nport = 8100\n'
    )
    _, second = _snapshot_run(
        [base, overrides],
        env_name="second",
        label="run-2",
        previous=first,
    )

    assert second["generation"]["id"] != first["generation"]["id"]

    # Only NAME changes in the final state: PORT is still overridden by the
    # later file, even though base.toml's raw default for PORT changed.
    changes = {change["key"]: change for change in second["changes"]}
    assert set(changes) == {"NAME"}
    assert changes["NAME"]["previous"] == "first"
    assert changes["NAME"]["current"] == "second"
    assert changes["NAME"]["source"]["identifier"] == "DYNACONF"
    assert changes["NAME"]["previous_source"]["identifier"] == "DYNACONF"

    # The base file content change is still visible in the source evidence,
    # including the keys whose raw contributed value changed.
    source_changes = {
        change["change"]: change
        for change in second["comparison"]["source_changes"]
    }
    content_change = source_changes["content_changed"]
    assert content_change["identifier"] == str(base)
    assert (
        content_change["previous_digest"]
        != content_change["current_digest"]
    )
    assert set(content_change["changed_keys"]) == {"NAME", "PORT"}

    # Override order is preserved across generations.
    assert [source["identifier"] for source in second["sources"]] == [
        str(base),
        str(overrides),
        "DYNACONF",
    ]


def test_forensic_snapshot_missing_source_reports_evidence_gap(tmp_path):
    """Dropping a source must produce an explicit evidence gap."""
    base = create_file(
        tmp_path / "base.toml", '[default]\nname = "base"\nport = 8000\n'
    )
    overrides = create_file(
        tmp_path / "overrides.toml", "[default]\nport = 9000\n"
    )

    _, first = _snapshot_run([base, overrides], env_name="one", label="run-1")
    _, second = _snapshot_run(
        [base], env_name="one", label="run-2", previous=first
    )

    # Runtime behaviour is unchanged: base.toml default wins again.
    assert second["current"]["PORT"] == 8000

    missing = [
        gap for gap in second["gaps"] if gap["kind"] == "source_missing"
    ]
    assert len(missing) == 1
    gap = missing[0]
    assert gap["identifier"] == str(overrides)
    assert gap["previous_digest"]["value"] == content_digest(overrides)[
        "value"
    ]
    assert gap["keys_previously_loaded"] == ["PORT"]
    assert gap["keys_no_longer_covered"] == ["PORT"]

    source_change = [
        change
        for change in second["comparison"]["source_changes"]
        if change["change"] == "source_missing"
    ]
    assert len(source_change) == 1
    assert source_change[0]["source"] == (
        f"toml|{overrides}|default|direct"
    )


def test_forensic_snapshot_missing_source_not_a_gap_when_covered(tmp_path):
    """A dropped source is not a gap when another source still covers a key."""
    base = create_file(
        tmp_path / "base.toml", '[default]\nshared = "base"\nbase_only = 1\n'
    )
    extra = create_file(
        tmp_path / "extra.toml",
        '[default]\nshared = "extra"\nextra_only = 2\n',
    )
    _, first = _snapshot_run([base], env_name="one", label="run-1")
    _, second = _snapshot_run(
        [base, extra], env_name="one", label="run-2", previous=first
    )

    # Adding a source is not a gap.
    assert second["gaps"] == []
    assert second["comparison"]["source_changes"] == [
        {
            "source": f"toml|{extra}|default|direct",
            "change": "source_added",
            "loader": "toml",
            "identifier": str(extra),
            "env": "default",
            "changed_keys": ["EXTRA_ONLY", "SHARED"],
        }
    ]
    # The newly added source changes only the keys it actually overtakes.
    added = second["comparison"]["source_changes"][0]
    assert added["changed_keys"] == ["EXTRA_ONLY", "SHARED"]
    assert second["keys"]["SHARED"]["source"]["identifier"] == str(extra)
    assert second["keys"]["BASE_ONLY"]["source"]["identifier"] == str(base)


def test_forensic_snapshot_missing_file_is_recorded_even_on_first_run(
    tmp_path,
):
    """A requested-but-absent source must be a gap without a previous run."""
    base = create_file(
        tmp_path / "base.toml", "[default]\nname = \"base\"\n"
    )
    missing = tmp_path / "missing.toml"

    _, snapshot = _snapshot_run(
        [base, missing], env_name=None, label="run-1"
    )

    gaps = [
        gap
        for gap in snapshot["gaps"]
        if gap["kind"] == "source_unavailable"
    ]
    assert len(gaps) == 1
    assert gaps[0]["identifier"] == str(missing)
    assert gaps[0]["missing"] is True
    assert "not evidenced" in gaps[0]["detail"]


def test_forensic_snapshot_verify_file_digest(tmp_path):
    """The recorded file digest can be re-checked against current bytes."""
    base = create_file(tmp_path / "base.toml", "[default]\nname = \"base\"\n")
    _, snapshot = _snapshot_run([base], label="run-1")

    match = verify_file_digest(snapshot, str(base))
    assert match["status"] == "match"
    assert match["match"] is True

    create_file(tmp_path / "base.toml", "[default]\nname = \"changed\"\n")
    mismatch = verify_file_digest(snapshot, str(base))
    assert mismatch["status"] == "mismatch"
    assert mismatch["match"] is False
    assert mismatch["expected"]["value"] != mismatch["actual"]["value"]

    unknown = verify_file_digest(snapshot, "does-not-exist.toml")
    assert unknown["status"] == "not_recorded"


def test_forensic_snapshot_compare_snapshots_is_order_independent(tmp_path):
    """Comparison uses source identity, not incidental list ordering."""
    base = create_file(tmp_path / "base.toml", "[default]\na = 1\n")
    _, first = _snapshot_run([base], label="run-1")

    shuffled = copy.deepcopy(first)
    shuffled["sources"].reverse()
    shuffled["keys"] = dict(reversed(list(shuffled["keys"].items())))

    assert compare_snapshots(shuffled, first)["changes"] == []
    assert compare_snapshots(shuffled, first)["source_changes"] == []


def test_forensic_snapshot_winner_matches_parent_after_from_env(tmp_path):
    """from_env merges child records into the parent.

    The snapshot must keep the winning source consistent with the value that
    is actually effective on the object being inspected.
    """
    filename = create_file(
        tmp_path / "a.toml",
        """\
        [default]
        name = "base"
        [production]
        name = "prod"
        port = 7000
        """,
    )
    settings = Dynaconf(settings_file=filename, environments=True)
    settings.from_env("production")

    snapshot = get_forensic_snapshot(settings)

    # The parent object is still on the default/development env.
    assert settings.current_env == "DEVELOPMENT"
    assert snapshot["current"]["NAME"] == "base"
    assert snapshot["keys"]["NAME"]["source"]["env"] == "default"
    # A key loaded only by the child env is retained as historical evidence,
    # but it is explicitly not effective on the parent.
    assert snapshot["keys"]["PORT"]["state"] == "not_effective"
    assert snapshot["keys"]["PORT"]["source"] is None


def test_forensic_snapshot_runtime_set_merge_is_evidenced(tmp_path):
    """A runtime `set("@merge ...")` is direct evidence, not internals."""
    filename = create_file(tmp_path / "a.toml", "[default]\nitems = [1, 2]\n")
    settings = Dynaconf(settings_file=filename, environments=True)
    settings.set("ITEMS", "@merge [9]")

    snapshot = get_forensic_snapshot(settings)

    runtime_sources = [
        source
        for source in snapshot["sources"]
        if source["loader"] == "set_method"
        and source["identifier"] == "undefined"
    ]
    assert len(runtime_sources) == 1
    runtime = runtime_sources[0]
    assert runtime["merged"] is True
    assert runtime["keys"]["ITEMS"]["direct"] == "@merge [9]"
    assert runtime["keys"]["ITEMS"]["before"] == [1, 2]
    assert runtime["keys"]["ITEMS"]["effective"] == [1, 2, 9]
    assert snapshot["current"]["ITEMS"] == [1, 2, 9]
    # No Dynaconf internal setting leaks into a default snapshot.
    assert "RENAMED_VARS" not in snapshot["current"]
    assert not any(
        key.endswith("_FOR_DYNACONF") for key in snapshot["current"]
    )


def test_forensic_snapshot_three_loader_types_and_generation_sequence(
    tmp_path,
):
    """TOML, YAML and envvar sources, with generations numbered per run."""
    toml_file = create_file(
        tmp_path / "a.toml", '[default]\nport = 8000\nname = "toml"\n'
    )
    yaml_file = create_file(
        tmp_path / "b.yaml",
        """\
        default:
          port: 8100
          name: yaml
        """,
    )
    os.environ["DYNACONF_NAME"] = "envvar"

    settings = Dynaconf(
        settings_file=[toml_file, yaml_file], environments=True
    )
    first = get_forensic_snapshot(settings, label="run-1")

    assert first["generation"]["sequence"] == 1
    assert [source["loader"] for source in first["sources"]] == [
        "toml",
        "yaml",
        "env_global",
    ]
    assert [source["order"] for source in first["sources"]] == sorted(
        source["order"] for source in first["sources"]
    )
    # YAML overrides TOML defaults; envvar overrides both.
    assert first["keys"]["PORT"]["source"]["loader"] == "yaml"
    assert first["keys"]["NAME"]["source"]["loader"] == "env_global"
    assert first["current"] == {"PORT": 8100, "NAME": "envvar"}

    os.environ["DYNACONF_NAME"] = "envvar-2"
    settings = Dynaconf(
        settings_file=[toml_file, yaml_file], environments=True
    )
    second = get_forensic_snapshot(
        settings, label="run-2", previous=first
    )

    assert second["generation"]["sequence"] == 2
    assert [change["key"] for change in second["changes"]] == ["NAME"]
    assert second["changes"][0]["source"]["loader"] == "env_global"
    # The file sources are unchanged, so no content change is reported.
    assert second["comparison"]["source_changes"] == []
