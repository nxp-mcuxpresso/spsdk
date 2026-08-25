#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for spsdk.utils.autocomplete static shell completion generation."""

import json
from pathlib import Path

import click
import pytest

from spsdk.utils.autocomplete import (
    _collect_all_flags,
    _collect_paths,
    _get_powershell_profile,
    _param_to_dict,
    _tool_vbase,
    _var_seg,
    generate_bash_dispatcher,
    generate_powershell_script,
    generate_shell_data,
    generate_zsh_dispatcher,
    get_completions_dir,
    setup_bash_profile,
    setup_powershell_profile,
    setup_shell_completion,
    setup_zsh_profile,
    walk_command_tree,
    write_bash_completion,
    write_completion_json,
    write_powershell_completion,
    write_shell_data,
    write_zsh_completion,
)

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@click.command(name="leaf")
@click.option("-c", "--config", type=click.Path(), help="Config file")
@click.option(
    "-f", "--family", type=click.Choice(["lpc55", "rt1050"], case_sensitive=False), help="Family"
)
@click.option("--verbose", is_flag=True, help="Be verbose")
def _leaf_cmd() -> None:
    """A leaf command for testing."""


@click.group(name="root")
def _root_cmd() -> None:
    """Root group."""


_root_cmd.add_command(_leaf_cmd)


@click.group(name="nested")
def _nested_cmd() -> None:
    """Nested group."""


@click.command(name="deep")
@click.option("--count", type=click.types.IntParamType(), default=1, help="Count")
def _deep_cmd() -> None:
    """Deep command."""


_nested_cmd.add_command(_deep_cmd)
_root_cmd.add_command(_nested_cmd)


# ---------------------------------------------------------------------------
# _param_to_dict
# ---------------------------------------------------------------------------


class TestParamToDict:
    """Tests for _param_to_dict serialisation."""

    def test_path_option(self) -> None:
        """Path type option is serialised with type='path'."""
        param = _leaf_cmd.params[0]  # -c / --config  (Path)
        result = _param_to_dict(param)
        assert result["opts"] == ["-c", "--config"]
        assert result["type"] == "path"
        assert result["is_flag"] is False
        assert result["choices"] is None
        assert result["is_argument"] is False

    def test_choice_option(self) -> None:
        """Choice type option serialises choices list."""
        param = _leaf_cmd.params[1]  # -f / --family  (Choice)
        result = _param_to_dict(param)
        assert result["type"] == "choice"
        assert result["choices"] == ["lpc55", "rt1050"]

    def test_flag_option(self) -> None:
        """is_flag=True is preserved."""
        param = _leaf_cmd.params[2]  # --verbose  (flag)
        result = _param_to_dict(param)
        assert result["is_flag"] is True
        assert result["type"] == "string"


# ---------------------------------------------------------------------------
# walk_command_tree
# ---------------------------------------------------------------------------


class TestWalkCommandTree:
    """Tests for walk_command_tree."""

    def test_leaf_command(self) -> None:
        """Leaf command produces no 'commands' entries."""
        tree = walk_command_tree(_leaf_cmd, "leaf")
        assert tree["name"] == "leaf"
        assert tree["commands"] == {}
        assert len(tree["params"]) == 3  # config, family, verbose

    def test_group_command(self) -> None:
        """Group command includes sub-command names."""
        tree = walk_command_tree(_root_cmd, "root")
        assert "leaf" in tree["commands"]
        assert "nested" in tree["commands"]

    def test_nested_recursion(self) -> None:
        """Nested groups are walked recursively."""
        tree = walk_command_tree(_root_cmd, "root")
        nested = tree["commands"]["nested"]
        assert "deep" in nested["commands"]

    def test_param_serialisation_inside_tree(self) -> None:
        """Params inside sub-commands are serialised."""
        tree = walk_command_tree(_root_cmd, "root")
        leaf_params = tree["commands"]["leaf"]["params"]
        types = {p["opts"][0]: p["type"] for p in leaf_params if p["opts"]}
        assert types["-c"] == "path"
        assert types["-f"] == "choice"


# ---------------------------------------------------------------------------
# _var_seg / _tool_vbase
# ---------------------------------------------------------------------------


class TestVarHelpers:
    """Tests for variable-name helper functions."""

    def test_var_seg_hyphens(self) -> None:
        """Hyphens are replaced with underscores."""
        assert _var_seg("write-memory") == "write_memory"

    def test_var_seg_clean(self) -> None:
        """Clean names are unchanged."""
        assert _var_seg("blhost") == "blhost"

    def test_tool_vbase(self) -> None:
        """Tool vbase has _spsdk__ prefix."""
        assert _tool_vbase("blhost") == "_spsdk__blhost"
        assert _tool_vbase("el2go-host") == "_spsdk__el2go_host"


# ---------------------------------------------------------------------------
# generate_shell_data
# ---------------------------------------------------------------------------


class TestGenerateShellData:
    """Tests for generate_shell_data."""

    @pytest.fixture()
    def tree(self) -> dict:
        """Return a sample command tree."""
        return walk_command_tree(_root_cmd, "root")

    def test_contains_cmds_var(self, tree: dict) -> None:
        """Data file contains __cmds variable for subcommands."""
        data = generate_shell_data("root", tree)
        assert '_spsdk__root__cmds="leaf nested"' in data

    def test_contains_words_var(self, tree: dict) -> None:
        """Data file contains __words variable."""
        data = generate_shell_data("root", tree)
        assert "_spsdk__root__words=" in data

    def test_choices_in_data(self, tree: dict) -> None:
        """Choice values appear in the data file."""
        data = generate_shell_data("root", tree)
        assert "lpc55" in data
        assert "rt1050" in data

    def test_file_option_in_data(self, tree: dict) -> None:
        """File options appear in __files variable."""
        data = generate_shell_data("root", tree)
        assert "__files=" in data
        assert "--config" in data

    def test_sourceable_syntax(self, tree: dict) -> None:
        """Data file lines are valid VAR=VALUE assignments."""
        data = generate_shell_data("root", tree)
        for line in data.splitlines():
            if line and not line.startswith("#"):
                assert "=" in line, f"Non-assignment line: {line!r}"

    def test_no_shell_logic(self, tree: dict) -> None:
        """Data file contains no shell logic keywords."""
        data = generate_shell_data("root", tree)
        for keyword in ("if [", "for (", "case ", "while "):
            assert keyword not in data

    def test_allflags_in_data(self, tree: dict) -> None:
        """Data file contains __allflags variable with flag options."""
        data = generate_shell_data("root", tree)
        assert "__allflags=" in data
        assert "--verbose" in data

    def test_allflags_no_value_options(self, tree: dict) -> None:
        """Value-taking options (like --config) are NOT in __allflags."""
        data = generate_shell_data("root", tree)
        # Extract the allflags line
        allflags_line = next((ln for ln in data.splitlines() if "__allflags=" in ln), "")
        assert "--config" not in allflags_line
        assert "--family" not in allflags_line


class TestCollectAllFlags:
    """Tests for _collect_all_flags helper."""

    def test_collects_flags_from_root(self) -> None:
        """Root-level flags are collected."""
        tree = walk_command_tree(_root_cmd, "root")
        flags = _collect_all_flags(tree)
        assert "--verbose" in flags

    def test_excludes_value_options(self) -> None:
        """Value-taking options are not collected."""
        tree = walk_command_tree(_root_cmd, "root")
        flags = _collect_all_flags(tree)
        assert "--config" not in flags
        assert "--family" not in flags

    def test_collects_from_subcommands(self) -> None:
        """Flags from nested subcommands are also collected."""

        @click.group(name="parent")
        @click.option("--flag-a", is_flag=True)
        def _parent() -> None:
            pass

        @click.command(name="child")
        @click.option("--flag-b", is_flag=True)
        def _child() -> None:
            pass

        _parent.add_command(_child)
        tree = walk_command_tree(_parent, "parent")
        flags = _collect_all_flags(tree)
        assert "--flag-a" in flags
        assert "--flag-b" in flags

    def test_empty_when_no_flags(self) -> None:
        """Empty list when no flag options exist."""

        @click.command(name="noflag")
        @click.option("--name", help="A string option")
        def _noflag() -> None:
            pass

        tree = walk_command_tree(_noflag, "noflag")
        flags = _collect_all_flags(tree)
        assert "--name" not in flags


# ---------------------------------------------------------------------------
# generate_bash_dispatcher
# ---------------------------------------------------------------------------


class TestGenerateBashDispatcher:
    """Tests for generate_bash_dispatcher."""

    @pytest.fixture()
    def dispatcher(self) -> str:
        """Return a sample bash dispatcher."""
        return generate_bash_dispatcher("root", Path("/tmp/root.sh"))

    def test_function_defined(self, dispatcher: str) -> None:
        """Dispatcher defines _spsdk_cmp_root function."""
        assert "_spsdk_cmp_root()" in dispatcher

    def test_complete_directive(self, dispatcher: str) -> None:
        """complete -F directive is present."""
        assert "complete -F _spsdk_cmp_root root" in dispatcher

    def test_sources_data_file(self, dispatcher: str) -> None:
        """Dispatcher sources the data file."""
        assert "/tmp/root.sh" in dispatcher

    def test_lazy_load_uses_allflags(self, dispatcher: str) -> None:
        """Lazy-load sentinel checks __allflags (not __words)."""
        assert "__allflags" in dispatcher

    def test_indirect_expansion(self, dispatcher: str) -> None:
        """Bash indirect expansion ${!...} is used."""
        assert "${!" in dispatcher

    def test_no_python_invocation(self, dispatcher: str) -> None:
        """Dispatcher does not spawn Python."""
        assert "python" not in dispatcher.lower()

    def test_no_case_blocks(self, dispatcher: str) -> None:
        """Dispatcher has no per-command case blocks (data-driven)."""
        # There should be at most the case for arg type dispatch, not per-path cases
        assert dispatcher.count("case") <= 3


# ---------------------------------------------------------------------------
# generate_zsh_dispatcher
# ---------------------------------------------------------------------------


class TestGenerateZshDispatcher:
    """Tests for generate_zsh_dispatcher."""

    @pytest.fixture()
    def dispatcher(self) -> str:
        """Return a sample zsh dispatcher."""
        return generate_zsh_dispatcher("root", Path("/tmp/root.sh"))

    def test_compdef_header(self, dispatcher: str) -> None:
        """Script starts with #compdef."""
        assert dispatcher.startswith("#compdef root\n")

    def test_function_defined(self, dispatcher: str) -> None:
        """Dispatcher defines _root function."""
        assert "_root() {" in dispatcher

    def test_sources_data_file(self, dispatcher: str) -> None:
        """Dispatcher sources the data file."""
        assert "/tmp/root.sh" in dispatcher

    def test_lazy_load_uses_allflags(self, dispatcher: str) -> None:
        """Lazy-load sentinel checks __allflags (not __words)."""
        assert "__allflags" in dispatcher

    def test_indirect_expansion(self, dispatcher: str) -> None:
        """Zsh indirect expansion ${(P)...} is used."""
        assert "${(P)" in dispatcher

    def test_no_python_invocation(self, dispatcher: str) -> None:
        """Dispatcher does not spawn Python."""
        assert "python" not in dispatcher.lower()

    def test_entry_point_call(self, dispatcher: str) -> None:
        """Script ends with calling the root function."""
        assert '_root "$@"' in dispatcher


# ---------------------------------------------------------------------------
# get_completions_dir
# ---------------------------------------------------------------------------


class TestGetCompletionsDir:
    """Tests for get_completions_dir."""

    def test_returns_path(self) -> None:
        """Result is a Path with 'spsdk' in it ending in 'completions'."""
        d = get_completions_dir()
        assert isinstance(d, Path)
        assert "spsdk" in str(d).lower()
        assert d.name == "completions"


# ---------------------------------------------------------------------------
# write_shell_data / write_zsh_completion / write_bash_completion
# ---------------------------------------------------------------------------


class TestFileWriting:
    """Integration tests for file writers."""

    def test_write_json(self, tmp_path: Path) -> None:
        """JSON file is written with expected structure (utility function)."""
        path = write_completion_json("root", _root_cmd, tmp_path)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["name"] == "root"
        assert "commands" in data

    def test_write_shell_data(self, tmp_path: Path) -> None:
        """Shell data file is named <tool>.sh."""
        tree = walk_command_tree(_root_cmd, "root")
        path = write_shell_data("root", tree, tmp_path)
        assert path.name == "root.sh"
        assert path.read_text().startswith("# SPSDK")

    def test_write_zsh(self, tmp_path: Path) -> None:
        """Zsh file is named _<tool> and starts with #compdef."""
        tree = walk_command_tree(_root_cmd, "root")
        data_path, zsh_path = write_zsh_completion("root", tree, tmp_path)
        assert zsh_path.name == "_root"
        assert zsh_path.read_text().startswith("#compdef root")
        assert data_path.name == "root.sh"
        assert data_path.exists()

    def test_write_bash(self, tmp_path: Path) -> None:
        """Bash file is named <tool>.bash."""
        tree = walk_command_tree(_root_cmd, "root")
        data_path, bash_path = write_bash_completion("root", tree, tmp_path)
        assert bash_path.suffix == ".bash"
        assert data_path.name == "root.sh"
        assert data_path.exists()


# ---------------------------------------------------------------------------
# setup_shell_completion
# ---------------------------------------------------------------------------


class TestSetupShellCompletion:
    """Tests for the high-level setup_shell_completion function."""

    def test_zsh_dry_run(self) -> None:
        """Dry run returns success without writing files."""
        ok, msg = setup_shell_completion("root", _root_cmd, shell="zsh", dry_run=True)
        assert ok is True
        assert "dry-run" in msg.lower()

    def test_unsupported_shell(self) -> None:
        """Unsupported shell (fish) returns failure."""
        ok, msg = setup_shell_completion("root", _root_cmd, shell="fish")
        assert ok is False
        assert "fish" in msg

    def test_bash_dry_run(self) -> None:
        """Bash dry run returns success without writing files."""
        ok, msg = setup_shell_completion("root", _root_cmd, shell="bash", dry_run=True)
        assert ok is True
        assert "dry-run" in msg.lower()
        assert ".bash" in msg

    def test_bash_writes_files(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Bash write produces .sh + .bash files."""
        monkeypatch.setattr("spsdk.utils.autocomplete.get_completions_dir", lambda: tmp_path)
        ok, _ = setup_shell_completion("root", _root_cmd, shell="bash", dry_run=False)
        assert ok is True
        assert (tmp_path / "root.sh").exists()
        assert (tmp_path / "root.bash").exists()

    def test_powershell_dry_run(self) -> None:
        """PowerShell dry run returns success without writing files."""
        ok, msg = setup_shell_completion("root", _root_cmd, shell="powershell", dry_run=True)
        assert ok is True
        assert "dry-run" in msg.lower()
        assert ".ps1" in msg

    def test_powershell_writes_files(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """PowerShell write produces .ps1 file."""
        monkeypatch.setattr("spsdk.utils.autocomplete.get_completions_dir", lambda: tmp_path)
        ok, _ = setup_shell_completion("root", _root_cmd, shell="powershell", dry_run=False)
        assert ok is True
        assert (tmp_path / "root.ps1").exists()

    def test_zsh_writes_files(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Zsh write produces .sh + _root files."""
        monkeypatch.setattr("spsdk.utils.autocomplete.get_completions_dir", lambda: tmp_path)
        ok, _ = setup_shell_completion("root", _root_cmd, shell="zsh", dry_run=False)
        assert ok is True
        assert (tmp_path / "root.sh").exists()
        assert (tmp_path / "_root").exists()


# ---------------------------------------------------------------------------
# setup_zsh_profile
# ---------------------------------------------------------------------------


class TestSetupZshProfile:
    """Tests for setup_zsh_profile."""

    def test_dry_run_returns_string(self, tmp_path: Path) -> None:
        """Dry run returns description without writing."""
        msg = setup_zsh_profile(tmp_path, dry_run=True)
        assert "dry-run" in msg.lower()
        assert "fpath" in msg

    def test_writes_block(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Block is written to ~.zshrc (mocked)."""
        zshrc = tmp_path / ".zshrc"
        zshrc.write_text("# existing content\n")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        completions_dir = tmp_path / "completions"
        setup_zsh_profile(completions_dir, dry_run=False)

        content = zshrc.read_text()
        assert "SPSDK completions begin" in content
        assert "fpath" in content
        assert "autoload -Uz compinit" in content

    def test_idempotent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Running twice results in exactly one block."""
        zshrc = tmp_path / ".zshrc"
        zshrc.write_text("")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        completions_dir = tmp_path / "completions"
        setup_zsh_profile(completions_dir, dry_run=False)
        setup_zsh_profile(completions_dir, dry_run=False)

        content = zshrc.read_text()
        assert content.count("SPSDK completions begin") == 1


# ---------------------------------------------------------------------------
# generate_powershell_script
# ---------------------------------------------------------------------------


class TestGeneratePowerShellScript:
    """Tests for generate_powershell_script."""

    @pytest.fixture()
    def tree(self) -> dict:
        """Return a sample command tree."""
        return walk_command_tree(_root_cmd, "root")

    def test_register_argument_completer(self, tree: dict) -> None:
        """Script contains Register-ArgumentCompleter call."""
        script = generate_powershell_script("root", tree)
        assert "Register-ArgumentCompleter" in script

    def test_tool_name_in_script(self, tree: dict) -> None:
        """Tool name appears in the CommandName parameter."""
        script = generate_powershell_script("root", tree)
        assert "-CommandName 'root'" in script

    def test_exe_variant_registered(self, tree: dict) -> None:
        """Script also registers completion for tool.exe."""
        script = generate_powershell_script("root", tree)
        assert "-CommandName 'root.exe'" in script

    def test_choices_in_hashtable(self, tree: dict) -> None:
        """Choice values appear in the data hashtable."""
        script = generate_powershell_script("root", tree)
        assert "lpc55" in script
        assert "rt1050" in script

    def test_short_option_in_choices(self, tree: dict) -> None:
        """Short form (-f) and long form (--family) are both choice keys."""
        script = generate_powershell_script("root", tree)
        assert "'-f'" in script
        assert "'--family'" in script

    def test_no_python_invocation(self, tree: dict) -> None:
        """Generated script does not spawn Python."""
        script = generate_powershell_script("root", tree)
        assert "python" not in script.lower()

    def test_allflags_variable_present(self, tree: dict) -> None:
        """Script contains allflags variable for option-value skipping."""
        script = generate_powershell_script("root", tree)
        assert "_root_allflags" in script
        assert "--verbose" in script

    def test_prevword_uses_allElems(self, tree: dict) -> None:
        """Script uses allElems for correct prevWord when wordToComplete is empty."""
        script = generate_powershell_script("root", tree)
        assert "allElems" in script
        assert "wordToComplete -eq ''" in script

    def test_cmdpath_uses_data_ContainsKey(self, tree: dict) -> None:
        """Token loop distinguishes subcommands from positional args via data lookup."""
        script = generate_powershell_script("root", tree)
        assert "data.ContainsKey" in script
        assert "inArgs" in script

    def test_scriptblock_assigned_to_variable(self, tree: dict) -> None:
        """ScriptBlock is stored in a variable so it can be reused for .exe."""
        script = generate_powershell_script("root", tree)
        assert "$_root_script = {" in script

    def test_skipNext_skips_option_values(self, tree: dict) -> None:
        """Token loop uses skipNext to skip over option values."""
        script = generate_powershell_script("root", tree)
        assert "skipNext" in script
        assert "allFlags -notcontains" in script

    def test_write_ps1_file(self, tmp_path: Path, tree: dict) -> None:
        """write_powershell_completion creates a .ps1 file."""
        path = write_powershell_completion("root", tree, tmp_path)
        assert path.suffix == ".ps1"
        assert path.read_text().startswith("# SPSDK")

    def test_tokens_array_unwrap_safe(self, tree: dict) -> None:
        """Token removal uses @(if...) to prevent PowerShell from unwrapping a
        single-element array into a bare String (which would cause character indexing)."""
        script = generate_powershell_script("root", tree)
        # The safe form wraps the if-expression in @()
        assert "$tokens = @(if" in script

    def test_subpartial_variable_present(self, tree: dict) -> None:
        """Script contains subPartial variable for partial subcommand prefix tracking."""
        script = generate_powershell_script("root", tree)
        assert "subPartial" in script

    def test_wordfilter_variable_present(self, tree: dict) -> None:
        """Script contains wordFilter variable used for filtering word completions."""
        script = generate_powershell_script("root", tree)
        assert "wordFilter" in script

    def test_choice_substring_fallback_present(self, tree: dict) -> None:
        """Script contains substring fallback logic for choice completions."""
        script = generate_powershell_script("root", tree)
        # prefix attempt
        assert (
            '"$wordToComplete*"' in script
            or "'$wordToComplete*'" in script
            or "wordToComplete*" in script
        )
        # substring fallback
        assert '"*$wordToComplete*"' in script or "*$wordToComplete*" in script


# ---------------------------------------------------------------------------
# _collect_paths
# ---------------------------------------------------------------------------


class TestCollectPaths:
    """Tests for the _collect_paths helper."""

    def test_root_included(self) -> None:
        """Root node (empty path) is included."""
        paths: list = []
        _collect_paths(walk_command_tree(_root_cmd, "root"), [], paths)
        path_strs = [p[0] for p in paths]
        assert "" in path_strs

    def test_all_paths_present(self) -> None:
        """Nested paths are all collected."""
        paths: list = []
        _collect_paths(walk_command_tree(_root_cmd, "root"), [], paths)
        path_strs = [p[0] for p in paths]
        assert "leaf" in path_strs
        assert "nested" in path_strs
        assert "nested deep" in path_strs


# ---------------------------------------------------------------------------
# setup_bash_profile / setup_powershell_profile
# ---------------------------------------------------------------------------


class TestSetupBashProfile:
    """Tests for setup_bash_profile."""

    def test_dry_run(self, tmp_path: Path) -> None:
        """Dry run returns description without writing."""
        msg = setup_bash_profile(tmp_path, dry_run=True)
        assert "dry-run" in msg.lower()

    def test_writes_block(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Block is written to ~/.bashrc."""
        bashrc = tmp_path / ".bashrc"
        bashrc.write_text("")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        setup_bash_profile(tmp_path / "completions", dry_run=False)
        content = bashrc.read_text()
        assert "SPSDK completions begin" in content
        assert "*.bash" in content

    def test_idempotent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Running twice keeps exactly one block."""
        bashrc = tmp_path / ".bashrc"
        bashrc.write_text("")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        d = tmp_path / "completions"
        setup_bash_profile(d, dry_run=False)
        setup_bash_profile(d, dry_run=False)
        assert bashrc.read_text().count("SPSDK completions begin") == 1


class TestGetPowerShellProfile:
    """Tests for _get_powershell_profile."""

    def test_uses_subprocess_result(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returns path reported by the PowerShell binary when available."""
        import subprocess

        expected = str(tmp_path / "PS" / "profile.ps1")
        fake_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=expected + "\n", stderr=""
        )
        monkeypatch.setattr(subprocess, "run", lambda *_a, **_kw: fake_result)
        assert _get_powershell_profile() == Path(expected)

    def test_falls_back_when_powershell_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Falls back to hardcoded path when no PowerShell binary is found."""
        import platform
        import subprocess

        monkeypatch.setattr(
            subprocess, "run", lambda *_a, **_kw: (_ for _ in ()).throw(FileNotFoundError())
        )
        profile = _get_powershell_profile()
        if platform.system() == "Windows":
            assert "PowerShell" in str(profile)
        else:
            assert ".config" in str(profile) or "powershell" in str(profile).lower()

    def test_falls_back_on_nonzero_returncode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Falls back to hardcoded path when PowerShell returns non-zero exit code."""
        import subprocess

        fake_result = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error")
        monkeypatch.setattr(subprocess, "run", lambda *_a, **_kw: fake_result)
        profile = _get_powershell_profile()
        assert "powershell" in str(profile).lower() or "PowerShell" in str(profile)


class TestSetupPowerShellProfile:
    """Tests for setup_powershell_profile."""

    def test_dry_run(self, tmp_path: Path) -> None:
        """Dry run returns description without writing."""
        msg = setup_powershell_profile(tmp_path, dry_run=True)
        assert "dry-run" in msg.lower()

    def test_writes_block(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Block is written to PowerShell profile."""
        import spsdk.utils.autocomplete as ac

        monkeypatch.setattr(ac, "_get_powershell_profile", lambda: tmp_path / "profile.ps1")
        setup_powershell_profile(tmp_path / "completions", dry_run=False)
        content = (tmp_path / "profile.ps1").read_text()
        assert "SPSDK completions begin" in content
        assert "*.ps1" in content

    def test_idempotent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Running twice keeps exactly one block."""
        import spsdk.utils.autocomplete as ac

        monkeypatch.setattr(ac, "_get_powershell_profile", lambda: tmp_path / "profile.ps1")
        (tmp_path / "profile.ps1").write_text("")
        d = tmp_path / "completions"
        setup_powershell_profile(d, dry_run=False)
        setup_powershell_profile(d, dry_run=False)
        assert (tmp_path / "profile.ps1").read_text().count("SPSDK completions begin") == 1


# ---------------------------------------------------------------------------
# Positional argument support
# ---------------------------------------------------------------------------


@click.command(name="write-memory")
@click.argument("address")
@click.argument("data_source", type=click.Path())
@click.argument("memory_id", default="0")
@click.option("--key", "-k", help="Encryption key")
def _write_memory_cmd() -> None:
    """Simulate blhost write-memory with positional args."""


@click.group(name="blhost")
def _blhost_cmd() -> None:
    """Blhost-like group for positional arg tests."""


_blhost_cmd.add_command(_write_memory_cmd)


class TestPositionalArgSupport:
    """Tests for positional argument completion in all three generators."""

    @pytest.fixture()
    def tree(self) -> dict:
        """Command tree with positional arguments."""
        return walk_command_tree(_blhost_cmd, "blhost")

    def test_param_to_dict_is_argument(self) -> None:
        """click.Argument param is serialised with is_argument=True."""
        arg_param = _write_memory_cmd.params[0]  # address
        result = _param_to_dict(arg_param)
        assert result["is_argument"] is True
        assert result["opts"] == ["address"]

    def test_param_to_dict_option_is_not_argument(self) -> None:
        """click.Option param has is_argument=False."""
        opt_param = _write_memory_cmd.params[3]  # --key
        result = _param_to_dict(opt_param)
        assert result["is_argument"] is False

    def test_param_to_dict_path_argument_type(self) -> None:
        """click.Argument with Path type has type='path'."""
        path_param = _write_memory_cmd.params[1]  # data_source  (Path)
        result = _param_to_dict(path_param)
        assert result["is_argument"] is True
        assert result["type"] == "path"

    def test_shell_data_args_variable(self, tree: dict) -> None:
        """Data file contains __args variable with positional specs."""
        data = generate_shell_data("blhost", tree)
        assert "__args=" in data
        assert "s:f" in data  # address=s, data_source=f (path)

    def test_shell_data_no_positionals_in_words(self, tree: dict) -> None:
        """Positional arg names do NOT appear in __words."""
        data = generate_shell_data("blhost", tree)
        # words should only have options, not positional names like 'address'
        for line in data.splitlines():
            if "__write_memory__words=" in line:
                assert "address" not in line
                assert "data_source" not in line

    def test_bash_dispatcher_sources_data(self, tree: dict) -> None:
        """Bash dispatcher references the data file path."""
        data_path = Path("/tmp/blhost.sh")
        disp = generate_bash_dispatcher("blhost", data_path)
        assert data_path.as_posix() in disp

    def test_bash_args_dispatch_logic(self, tree: dict) -> None:
        """Bash dispatcher contains positional arg dispatch logic."""
        data_path = Path("/tmp/blhost.sh")
        disp = generate_bash_dispatcher("blhost", data_path)
        assert "__args" in disp
        assert "_aspecs" in disp

    def test_zsh_dispatcher_sources_data(self, tree: dict) -> None:
        """Zsh dispatcher references the data file path."""
        data_path = Path("/tmp/blhost.sh")
        disp = generate_zsh_dispatcher("blhost", data_path)
        assert data_path.as_posix() in disp

    def test_zsh_args_dispatch_logic(self, tree: dict) -> None:
        """Zsh dispatcher contains positional arg dispatch logic."""
        data_path = Path("/tmp/blhost.sh")
        disp = generate_zsh_dispatcher("blhost", data_path)
        assert "__args" in disp
        assert "_aspecs" in disp

    def test_powershell_positionals_key(self, tree: dict) -> None:
        """PowerShell data hashtable contains positionals for write-memory."""
        script = generate_powershell_script("blhost", tree)
        assert "positionals" in script
        assert "type='file'" in script

    def test_powershell_positional_dispatch_block(self, tree: dict) -> None:
        """PowerShell scriptblock contains positional dispatch logic."""
        script = generate_powershell_script("blhost", tree)
        assert "posIndex" in script
        assert "entry.positionals" in script


# ---------------------------------------------------------------------------
# PowerShell subcommand prefix matching and choice substring fallback
# ---------------------------------------------------------------------------


@click.group(name="demo")
@click.version_option("1.0")
def _demo_cmd() -> None:
    """Demo tool for PowerShell completion tests."""


@_demo_cmd.group(name="ahab")
def _demo_ahab() -> None:
    """AHAB sub-group."""


@_demo_ahab.command(name="export")
@click.option(
    "-f", "--family", type=click.Choice(["mimx8ulp", "mimx8ulpa", "lpc55s69"], case_sensitive=False)
)
def _demo_ahab_export(family: str) -> None:
    """Export ahab image."""


@_demo_cmd.group(name="mbi")
def _demo_mbi() -> None:
    """MBI sub-group."""


@_demo_mbi.command(name="export")
@click.option("-f", "--family", type=click.Choice(["lpc55s69", "lpc55s36"], case_sensitive=False))
def _demo_mbi_export(family: str) -> None:
    """Export MBI image."""


class TestPowerShellPrefixAndSubstring:
    """Tests for subcommand prefix matching and choice substring fallback in PS script."""

    @pytest.fixture()
    def script(self) -> str:
        """Generated PowerShell script for the demo tool."""
        tree = walk_command_tree(_demo_cmd, "demo")
        return generate_powershell_script("demo", tree)

    def test_subpartial_logic_present(self, script: str) -> None:
        """Script contains subPartial logic for partial subcommand detection."""
        assert "subPartial" in script
        assert "isSub" in script

    def test_wordfilter_applied_to_words(self, script: str) -> None:
        """Word completions use $wordFilter instead of $wordToComplete directly."""
        assert "wordFilter" in script
        # The words completion line must reference $wordFilter, not only $wordToComplete
        assert 'wordFilter*"' in script

    def test_choice_substring_fallback(self, script: str) -> None:
        """Choice completions fall back to substring when prefix yields nothing."""
        # Prefix attempt
        assert "wordToComplete*" in script
        # Substring fallback
        assert "*$wordToComplete*" in script

    def test_subpartial_cleared_on_exact_match(self, script: str) -> None:
        """subPartial is reset to '' when a full subcommand is matched."""
        assert "subPartial = ''" in script

    def test_partial_subcommand_uses_cur_entry_words(self, script: str) -> None:
        """Partial subcommand detection inspects the current entry's words list."""
        assert "curEntry" in script
        assert "curEntry.words" in script
