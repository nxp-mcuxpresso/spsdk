#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Static shell autocomplete generation for SPSDK tools.

This module walks the Click command tree of each SPSDK tool, serialises it
to a per-tool ``.sh`` data file, and generates a small static dispatcher
script for each supported shell.  The dispatcher sources the data file
**once** (lazily, on first TAB press) and contains only generic logic — no
Python process is spawned during completion.

Supported shells: zsh, bash, powershell.

Typical usage::

    from spsdk.utils.autocomplete import setup_shell_completion
    setup_shell_completion("nxpimage", nxpimage.main, shell="zsh", dry_run=False)
"""

import json
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import click

from spsdk import version as spsdk_version

# ---------------------------------------------------------------------------
# Directory helpers
# ---------------------------------------------------------------------------


def get_completions_dir() -> Path:
    """Return the directory where SPSDK stores completion files.

    Uses ``platformdirs`` when available, falls back to ``~/.config/spsdk``.

    :return: Path to the completions directory (not yet created).
    """
    try:
        from platformdirs import user_config_dir

        base = Path(user_config_dir("spsdk"))
    except ImportError:
        base = Path.home() / ".config" / "spsdk"
    return base / "completions"


# ---------------------------------------------------------------------------
# Click command tree → JSON
# ---------------------------------------------------------------------------


def _param_to_dict(param: click.Parameter) -> dict[str, Any]:
    """Serialise a Click parameter to a JSON-serialisable dict.

    :param param: Click Option or Argument instance.
    :return: Dict with keys: opts, is_argument, is_flag, nargs, type, choices, help, required.
    """
    opts: list[str] = list(param.opts)
    is_argument = isinstance(param, click.Argument)
    is_flag = isinstance(param, click.Option) and bool(param.is_flag)
    nargs = param.nargs

    param_type = param.type
    type_name: str
    choices: list[str] | None = None

    if isinstance(param_type, click.Choice):
        type_name = "choice"
        choices = list(param_type.choices)
    elif isinstance(param_type, click.Path):
        type_name = "path"
    elif isinstance(param_type, click.File):
        type_name = "file"
    elif isinstance(param_type, click.types.IntParamType):
        type_name = "integer"
    elif isinstance(param_type, click.types.FloatParamType):
        type_name = "float"
    else:
        type_name = "string"

    help_text = ""
    if isinstance(param, click.Option):
        help_text = param.help or ""

    return {
        "opts": opts,
        "is_argument": is_argument,
        "is_flag": is_flag,
        "nargs": nargs,
        "type": type_name,
        "choices": choices,
        "help": help_text,
        "required": bool(param.required),
    }


def walk_command_tree(cmd: click.Command, name: str | None = None) -> dict[str, Any]:
    """Recursively walk a Click command tree and return a JSON-serialisable dict.

    :param cmd: Root Click command or group.
    :param name: Override name (defaults to ``cmd.name``).
    :return: Nested dict representing the command tree.
    """
    node: dict[str, Any] = {
        "name": name or cmd.name or "",
        "help": (cmd.help or "").strip(),
        "params": [_param_to_dict(p) for p in (cmd.params or []) if p.opts],
        "commands": {},
    }
    if isinstance(cmd, click.Group):
        for sub_name, sub_cmd in (cmd.commands or {}).items():
            node["commands"][sub_name] = walk_command_tree(sub_cmd, sub_name)
    return node


def write_completion_json(tool_name: str, cmd: click.Command, dest_dir: Path) -> Path:
    """Walk the Click tree of *cmd* and write a JSON completion data file.

    :param tool_name: The executable name (e.g. ``"nxpimage"``).
    :param cmd: Root Click command.
    :param dest_dir: Directory where the JSON file will be written.
    :return: Path to the written JSON file.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    tree = walk_command_tree(cmd, name=tool_name)
    payload = {
        "_meta": {"tool": tool_name, "spsdk_version": str(spsdk_version)},
        **tree,
    }
    out = dest_dir / f"{tool_name}.json"
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Shell data file generation  (shared by bash and zsh)
# ---------------------------------------------------------------------------

# Double-underscore segment separator keeps variable names valid and readable.
_V_SEP = "__"


def _var_seg(name: str) -> str:
    """Normalise a command/tool name to a valid shell variable segment.

    Hyphens and any other non-alphanumeric characters are replaced with
    underscores.

    :param name: Raw name (e.g. ``"write-memory"``).
    :return: Variable-safe segment (e.g. ``"write_memory"``).
    """
    return re.sub(r"[^a-zA-Z0-9]", "_", name)


def _tool_vbase(tool_name: str) -> str:
    """Return the variable-name prefix for *tool_name*.

    :param tool_name: Executable name.
    :return: Variable prefix string, e.g. ``"_spsdk__blhost"``.
    """
    return f"_spsdk{_V_SEP}{_var_seg(tool_name)}"


def _collect_all_flags(node: dict[str, Any]) -> list[str]:
    """Recursively collect all flag option names from the entire command tree.

    Used to build the ``__allflags`` variable that allows the dispatcher to
    distinguish between flags (no value consumed) and value-taking options.

    :param node: Command node dict from the walk tree.
    :return: List of flag option strings (e.g. ``["--verbose", "-v", "--help"]``).
    """
    flags: list[str] = []
    for p in node.get("params", []):
        if p.get("is_flag") and not p.get("is_argument"):
            flags.extend(o for o in p["opts"] if o.startswith("-"))
    for sub_node in node.get("commands", {}).values():
        flags.extend(_collect_all_flags(sub_node))
    return flags


def _arg_spec_str(arg: dict[str, Any]) -> str:
    """Return the positional-arg type spec token for a single argument.

    :param arg: Argument dict from the walk tree.
    :return: One of ``"f"``, ``"s"``, or ``"c=v1|v2..."``.
    """
    if arg["choices"]:
        return "c=" + "|".join(arg["choices"])
    if arg["type"] in ("path", "file"):
        return "f"
    return "s"


def _emit_choice_vars(option_params: list[dict[str, Any]], vbase: str, lines: list[str]) -> None:
    """Emit ``__ch__X`` choice variables for all options that have choices.

    :param option_params: List of option parameter dicts.
    :param vbase: Variable base for the current node.
    :param lines: Output list to append to.
    """
    for p in option_params:
        if not p["choices"]:
            continue
        choices_str = " ".join(p["choices"])
        for opt in p["opts"]:
            if opt.startswith("-"):
                okey = re.sub(r"[^a-zA-Z0-9]", "_", opt.lstrip("-"))
                lines.append(f'{vbase}{_V_SEP}ch{_V_SEP}{okey}="{choices_str}"')


def _emit_arg_vars(arg_params: list[dict[str, Any]], vbase: str, lines: list[str]) -> None:
    """Emit the ``__args`` colon-separated positional-arg type spec variable.

    :param arg_params: List of positional argument dicts.
    :param vbase: Variable base for the current node.
    :param lines: Output list to append to.
    """
    if not arg_params:
        return
    specs = [_arg_spec_str(arg) for arg in arg_params]
    lines.append(f'{vbase}{_V_SEP}args="{":".join(specs)}"')


def _collect_data_lines(node: dict[str, Any], vbase: str, lines: list[str]) -> None:
    """Recursively emit variable assignments for one command node.

    Variables written per node (all optional, omitted when empty):

    * ``__cmds``     -- space-separated subcommand names (path-matching)
    * ``__words``    -- all completable tokens: subcommands + option names
    * ``__files``    -- space-separated options whose values are file paths
    * ``__ch__X``    -- space-separated choices for option ``X``
    * ``__args``     -- colon-separated positional-arg type specs

    Positional-arg spec tokens: ``s`` (string), ``f`` (file),
    ``c=v1|v2|...`` (explicit choices).

    :param node: Command node dict from the walk tree.
    :param vbase: Variable base for this node.
    :param lines: Output list; variable assignment lines are appended.
    """
    params = node.get("params", [])
    option_params = [p for p in params if not p.get("is_argument")]
    arg_params = [p for p in params if p.get("is_argument")]
    cmds = list(node.get("commands", {}).keys())

    if cmds:
        lines.append(f'{vbase}{_V_SEP}cmds="{" ".join(cmds)}"')

    all_opts = [o for p in option_params for o in p["opts"] if o.startswith("-")]
    words = cmds + all_opts
    if words:
        lines.append(f'{vbase}{_V_SEP}words="{" ".join(words)}"')

    file_opts = [
        o
        for p in option_params
        for o in p["opts"]
        if o.startswith("-") and not p["is_flag"] and p["type"] in ("path", "file")
    ]
    if file_opts:
        lines.append(f'{vbase}{_V_SEP}files="{" ".join(file_opts)}"')

    _emit_choice_vars(option_params, vbase, lines)
    _emit_arg_vars(arg_params, vbase, lines)

    for sub_name, sub_node in node.get("commands", {}).items():
        _collect_data_lines(sub_node, vbase + _V_SEP + _var_seg(sub_name), lines)


def generate_shell_data(tool_name: str, tree: dict[str, Any]) -> str:
    """Generate a POSIX-sourceable ``.sh`` data file for *tool_name*.

    The file defines only shell variable assignments -- no logic.  It is
    sourced lazily by the bash and zsh dispatchers on the first TAB press.

    :param tool_name: Executable name (e.g. ``"nxpimage"``).
    :param tree: Command tree dict as returned by :func:`walk_command_tree`.
    :return: Complete shell data file as a string.
    """
    vbase = _tool_vbase(tool_name)
    lines: list[str] = [
        f"# SPSDK {spsdk_version} \u2014 completion data for {tool_name}",
        "# Auto-generated \u2014 do not edit.  Sourceable by bash and zsh.",
        "",
    ]
    # Emit a single __allflags variable for the entire tool so dispatchers can
    # distinguish flags (no value consumed) from value-taking options when
    # parsing the completed command line to determine the current context.
    all_flags = list(dict.fromkeys(_collect_all_flags(tree)))  # deduplicated
    if all_flags:
        lines.append(f'{vbase}{_V_SEP}allflags="{" ".join(all_flags)}"')
    _collect_data_lines(tree, vbase, lines)
    lines.append("")
    return "\n".join(lines)


def write_shell_data(tool_name: str, tree: dict[str, Any], dest_dir: Path) -> Path:
    """Write the ``.sh`` completion data file for *tool_name*.

    :param tool_name: Executable name.
    :param tree: Command tree dict.
    :param dest_dir: Destination directory (created if absent).
    :return: Path to the written data file.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    out = dest_dir / f"{tool_name}.sh"
    out.write_text(generate_shell_data(tool_name, tree), encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Bash completion dispatcher
# ---------------------------------------------------------------------------

# Template placeholders -- chosen to be impossible in normal shell code.
_T_TOOL = "SPSDK_TMPL_TOOL"  # tool executable name
_T_FUNC = "SPSDK_TMPL_FUNC"  # function-safe tool name  (hyphens -> underscores)
_T_DATA = "SPSDK_TMPL_DATA"  # absolute path to the .sh data file
_T_VBAS = "SPSDK_TMPL_VBASE"  # variable base prefix  (_spsdk__blhost)
_T_VER = "SPSDK_TMPL_VER"  # spsdk version string

_BASH_DISPATCHER_TMPL = """# SPSDK SPSDK_TMPL_VER -- bash completion for SPSDK_TMPL_TOOL
# Auto-generated -- do not edit.
# shellcheck disable=all
_spsdk_cmp_SPSDK_TMPL_FUNC() {
    local _D="SPSDK_TMPL_DATA"
    local _V="SPSDK_TMPL_VBASE"
    local _flv="${_V}__allflags"
    [[ -z "${!_flv+x}" ]] && . "$_D"
    local cur prev i
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    local _flv="${_V}__allflags"
    local -a _toks=()
    local _ev=0
    for ((i=1; i<COMP_CWORD; i++)); do
        local _w="${COMP_WORDS[i]}"
        if (( _ev )); then _ev=0; continue; fi
        if [[ "${_w:0:1}" == "-" ]]; then
            [[ "${_w}" != *=* && " ${!_flv} " != *" ${_w} "* ]] && _ev=1
            continue
        fi
        _toks+=("$_w")
    done
    local _vbase="$_V"
    local _pidx=0 _in_args=0 _tok
    for _tok in "${_toks[@]}"; do
        local _cmds_v="${_vbase}__cmds"
        if [[ $_in_args -eq 0 && " ${!_cmds_v} " == *" $_tok "* ]]; then
            _vbase="${_vbase}__${_tok//-/_}"
        else
            _in_args=1
            ((_pidx++))
        fi
    done
    if [[ "${prev:0:1}" == "-" ]]; then
        local _okey="${prev##*-}"
        _okey="${_okey//-/_}"
        local _cv="${_vbase}__ch__${_okey}"
        if [[ -n "${!_cv+x}" ]]; then
            COMPREPLY=($(compgen -W "${!_cv}" -- "$cur"))
            return
        fi
        local _fv="${_vbase}__files"
        if [[ -n "${!_fv}" && " ${!_fv} " == *" $prev "* ]]; then
            COMPREPLY=($(compgen -f -- "$cur"))
            return
        fi
        # Non-flag option with unrecognised value type — let shell handle
        [[ " ${!_flv} " != *" $prev "* ]] && return
    fi
    if [[ "${cur:0:1}" != "-" ]]; then
        local _av="${_vbase}__args"
        if [[ -n "${!_av}" ]]; then
            local -a _aspecs=()
            IFS=: read -ra _aspecs <<< "${!_av}"
            local _pc=$(( _pidx < ${#_aspecs[@]} ? _pidx : ${#_aspecs[@]} - 1 ))
            local _aspec="${_aspecs[$_pc]:-s}"
            case "$_aspec" in
                f)   COMPREPLY=($(compgen -f -- "$cur")); return ;;
                s)   return ;;
                c=*) local _ch="${_aspec#c=}"
                     COMPREPLY=($(compgen -W "${_ch//|/ }" -- "$cur")); return ;;
            esac
        fi
    fi
    local _wv2="${_vbase}__words"
    COMPREPLY=($(compgen -W "${!_wv2}" -- "$cur"))
}
complete -F _spsdk_cmp_SPSDK_TMPL_FUNC SPSDK_TMPL_TOOL
"""


def generate_bash_dispatcher(tool_name: str, data_path: Path) -> str:
    """Generate the bash completion dispatcher script for *tool_name*.

    The dispatcher is a small, static shell function that sources
    *data_path* lazily on the first TAB press and contains only generic
    dispatch logic -- no per-command ``case`` blocks.

    :param tool_name: Executable name (e.g. ``"nxpimage"``).
    :param data_path: Absolute path to the corresponding ``.sh`` data file.
    :return: Complete bash dispatcher script as a string.
    """
    func = _var_seg(tool_name)
    return (
        _BASH_DISPATCHER_TMPL.replace(_T_VER, str(spsdk_version))
        .replace(_T_TOOL, tool_name)
        .replace(_T_FUNC, func)
        .replace(_T_DATA, data_path.as_posix())
        .replace(_T_VBAS, _tool_vbase(tool_name))
    )


def write_bash_completion(
    tool_name: str, tree: dict[str, Any], dest_dir: Path
) -> tuple[Path, Path]:
    """Write the ``.sh`` data file and bash dispatcher for *tool_name*.

    :param tool_name: Executable name.
    :param tree: Command tree dict.
    :param dest_dir: Destination directory (created if absent).
    :return: Tuple of (data_path, dispatcher_path).
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    data_path = write_shell_data(tool_name, tree, dest_dir)
    dispatcher = generate_bash_dispatcher(tool_name, data_path)
    out = dest_dir / f"{tool_name}.bash"
    out.write_text(dispatcher, encoding="utf-8")
    return data_path, out


# ---------------------------------------------------------------------------
# Zsh completion dispatcher
# ---------------------------------------------------------------------------

_ZSH_DISPATCHER_TMPL = """#compdef SPSDK_TMPL_TOOL
# SPSDK SPSDK_TMPL_VER -- zsh completion for SPSDK_TMPL_TOOL
# Auto-generated -- do not edit.
_SPSDK_TMPL_FUNC() {
    local _D="SPSDK_TMPL_DATA"
    local _V="SPSDK_TMPL_VBASE"
    local _flv="${_V}__allflags"
    [[ -z "${(P)_flv}" ]] && builtin source "$_D"
    local cur="${words[CURRENT]}"
    local prev="${words[CURRENT-1]}"
    local -a _toks=()
    local _ev=0 _w
    for _w in "${words[@]:1:$((CURRENT-2))}"; do
        if (( _ev )); then _ev=0; continue; fi
        if [[ "${_w:0:1}" == "-" ]]; then
            [[ "${_w}" != *=* && " ${(P)_flv} " != *" ${_w} "* ]] && _ev=1
            continue
        fi
        _toks+=("$_w")
    done
    local _vbase="$_V"
    local _pidx=0 _in_args=0 _tok
    for _tok in "${_toks[@]}"; do
        local _cmds_v="${_vbase}__cmds"
        if [[ $_in_args -eq 0 && " ${(P)_cmds_v} " == *" $_tok "* ]]; then
            _vbase="${_vbase}__${_tok//-/_}"
        else
            _in_args=1
            ((_pidx++))
        fi
    done
    if [[ "${prev:0:1}" == "-" ]]; then
        local _okey="${prev##*-}"
        _okey="${_okey//-/_}"
        local _cv="${_vbase}__ch__${_okey}"
        if [[ -n "${(P)_cv}" ]]; then
            compadd -- ${=${(P)_cv}}
            return
        fi
        local _fv="${_vbase}__files"
        if [[ -n "${(P)_fv}" && " ${(P)_fv} " == *" $prev "* ]]; then
            _files
            return
        fi
        # Non-flag option with unrecognised value type — let shell handle
        [[ " ${(P)_flv} " != *" $prev "* ]] && return
    fi
    if [[ "${cur:0:1}" != "-" ]]; then
        local _av="${_vbase}__args"
        local _args_str="${(P)_av}"
        if [[ -n "$_args_str" ]]; then
            local -a _aspecs=("${(s/:/)_args_str}")
            local _pc=$(( _pidx < ${#_aspecs} ? _pidx : ${#_aspecs} - 1 ))
            local _aspec="${_aspecs[$((_pc+1))]:-s}"
            case "$_aspec" in
                f)   _files; return ;;
                s)   return ;;
                c=*) local _ch="${_aspec#c=}"; compadd -- ${(s:|:)_ch}; return ;;
            esac
        fi
    fi
    local _wv2="${_vbase}__words"
    compadd -- ${=${(P)_wv2}}
}
_SPSDK_TMPL_FUNC "$@"
"""


def generate_zsh_dispatcher(tool_name: str, data_path: Path) -> str:
    """Generate the zsh completion dispatcher script for *tool_name*.

    The file follows the zsh ``#compdef`` convention and is intended to be
    placed in a directory on ``$fpath``.  It sources *data_path* lazily.

    :param tool_name: Executable name (e.g. ``"nxpimage"``).
    :param data_path: Absolute path to the corresponding ``.sh`` data file.
    :return: Complete zsh dispatcher script as a string.
    """
    func = _var_seg(tool_name)
    return (
        _ZSH_DISPATCHER_TMPL.replace(_T_VER, str(spsdk_version))
        .replace(_T_TOOL, tool_name)
        .replace(_T_FUNC, func)
        .replace(_T_DATA, data_path.as_posix())
        .replace(_T_VBAS, _tool_vbase(tool_name))
    )


def write_zsh_completion(tool_name: str, tree: dict[str, Any], dest_dir: Path) -> tuple[Path, Path]:
    """Write the ``.sh`` data file and zsh dispatcher for *tool_name*.

    :param tool_name: Executable name.
    :param tree: Command tree dict.
    :param dest_dir: Destination directory (created if absent).
    :return: Tuple of (data_path, dispatcher_path).
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    data_path = write_shell_data(tool_name, tree, dest_dir)
    dispatcher = generate_zsh_dispatcher(tool_name, data_path)
    out = dest_dir / f"_{tool_name}"
    out.write_text(dispatcher, encoding="utf-8")
    return data_path, out


# ---------------------------------------------------------------------------
# PowerShell completion script generation
# ---------------------------------------------------------------------------


def _ps_string(s: str) -> str:
    """Escape a string for embedding in a PowerShell single-quoted string.

    :param s: Raw string.
    :return: Escaped string.
    """
    return s.replace("'", "''")


def _collect_paths(
    node: dict[str, Any],
    path: list[str],
    result: list[tuple[str, dict[str, Any]]],
) -> None:
    """Recursively collect (path_string, node) pairs for all command nodes.

    :param node: Current command node.
    :param path: Command path accumulated so far.
    :param result: Output list of (path_str, node) tuples.
    """
    result.append((" ".join(path), node))
    for sub_name, sub_node in node.get("commands", {}).items():
        _collect_paths(sub_node, path + [sub_name], result)


def _ps_build_choice_block(option_params: list[dict[str, Any]]) -> tuple[str, list[str]]:
    """Build PowerShell choice-map and file-opts blocks for a command node.

    :param option_params: Option parameter dicts for this node.
    :return: Tuple of (choice_block_str, file_opts_list).
    """
    choice_entries: list[str] = []
    file_opts: list[str] = []
    for p in option_params:
        opts = [o for o in p["opts"] if o.startswith("-")]
        if not opts or p["is_flag"]:
            continue
        if p["choices"]:
            choices_str = ", ".join(f"'{_ps_string(c)}'" for c in p["choices"])
            for o in opts:
                choice_entries.append(f"        '{_ps_string(o)}' = @({choices_str})")
        elif p["type"] in ("path", "file"):
            file_opts.extend(opts)

    choice_block = ""
    if choice_entries:
        choice_block = "; choices = @{\n" + ";\n".join(choice_entries) + "\n    }"
    return choice_block, file_opts


def _ps_build_entry(path_str: str, node: dict[str, Any]) -> str:
    """Build the PowerShell hashtable entry string for one command path.

    :param path_str: Space-joined command path (e.g. ``"nxpimage ahab export"``).
    :param node: Command node dict from the walk tree.
    :return: One-line (or multi-line) hashtable entry string.
    """
    params = node.get("params", [])
    sub_cmds = list(node.get("commands", {}).keys())
    key = _ps_string(path_str)
    option_params = [p for p in params if not p.get("is_argument")]
    arg_params = [p for p in params if p.get("is_argument")]

    all_opts = [o for p in option_params for o in p["opts"] if o.startswith("-")]
    words_str = ", ".join(f"'{_ps_string(w)}'" for w in sub_cmds + all_opts)

    choice_block, file_opts = _ps_build_choice_block(option_params)

    file_block = ""
    if file_opts:
        fo_str = ", ".join(f"'{_ps_string(o)}'" for o in file_opts)
        file_block = f"; files = @({fo_str})"

    pos_block = ""
    if arg_params:
        entries = [_ps_arg_entry(arg) for arg in arg_params]
        pos_block = "; positionals = @(" + ", ".join(entries) + ")"

    return f"    '{key}' = @{{ words = @({words_str}){choice_block}{file_block}{pos_block} }}"


def _ps_arg_entry(arg: dict[str, Any]) -> str:
    """Return the PowerShell hashtable fragment for one positional argument.

    :param arg: Argument dict from the walk tree.
    :return: PowerShell hashtable string, e.g. ``"@{type='file'}"``.
    """
    if arg["choices"]:
        ch = ", ".join(f"'{_ps_string(c)}'" for c in arg["choices"])
        return f"@{{type='choices'; values=@({ch})}}"
    if arg["type"] in ("path", "file"):
        return "@{type='file'}"
    return "@{type='string'}"


def generate_powershell_script(tool_name: str, tree: dict[str, Any]) -> str:
    """Generate a static PowerShell ``Register-ArgumentCompleter`` script.

    The script pre-builds a hashtable keyed by command-path string.  A single
    ``Register-ArgumentCompleter`` scriptblock dispatches completions from
    that data — no Python is spawned at TAB time.

    The scriptblock is assigned to a variable first, then registered for both
    ``tool`` and ``tool.exe`` so completion works regardless of how the
    executable is invoked on Windows.

    :param tool_name: Executable name (e.g. ``"nxpimage"``).
    :param tree: Command tree dict as returned by :func:`walk_command_tree`.
    :return: Complete PowerShell completion script as a string.
    """
    safe_var = re.sub(r"[^a-zA-Z0-9]", "_", tool_name)

    paths: list[tuple[str, dict[str, Any]]] = []
    _collect_paths(tree, [], paths)

    # All flag options (options that don't consume a value) across the whole tree.
    # Used by the dispatcher to skip over option values when building the command path.
    all_flags = list(dict.fromkeys(_collect_all_flags(tree)))
    all_flags_ps = ", ".join(f"'{_ps_string(f)}'" for f in all_flags)

    lines: list[str] = [
        f"# SPSDK {spsdk_version} — auto-generated PowerShell completion for {tool_name}",
        "",
        f"$_{safe_var}_allflags = @({all_flags_ps})",
        "",
        f"$_{safe_var}_data = @{{",
    ]

    for path_str, node in paths:
        lines.append(_ps_build_entry(path_str, node))

    lines.append("}")
    lines.append("")

    # Store the scriptblock in a variable so it can be registered for both
    # 'tool' and 'tool.exe' without duplicating the logic.
    lines.append(f"$_{safe_var}_script = {{")
    lines.append("    param($wordToComplete, $commandAst, $cursorPosition)")
    lines.append(f"    $data = $_{safe_var}_data")
    lines.append(f"    $allFlags = $_{safe_var}_allflags")
    lines.append("")
    lines.append("    # prevWord: the token immediately before the word being completed.")
    lines.append("    # When wordToComplete is '' the cursor is after a space, so the last")
    lines.append("    # AST element (e.g. '--family') IS the previous word.")
    lines.append(
        "    $allElems = @($commandAst.CommandElements | ForEach-Object { $_.ToString() })"
    )
    lines.append("    if ($wordToComplete -eq '') {")
    lines.append("        $prevWord = if ($allElems.Count -ge 1) { $allElems[-1] } else { '' }")
    lines.append("    } else {")
    lines.append("        $prevWord = if ($allElems.Count -ge 2) { $allElems[-2] } else { '' }")
    lines.append("    }")
    lines.append("")
    lines.append("    # Build command path: skip the tool name (index 0), skip option tokens")
    lines.append("    # and their values (using allFlags to distinguish flags from value-taking")
    lines.append("    # options), and stop extending the path once positional args start.")
    lines.append("    $tokens = @($allElems | Select-Object -Skip 1)")
    lines.append(
        "    if ($wordToComplete -ne '' -and $tokens.Count -gt 0 -and $tokens[-1] -eq $wordToComplete) {"
    )
    # Wrap the entire if-expression in @() to prevent PowerShell from unwrapping a
    # single-element array result into a bare String.  If that happened, $tokens[i]
    # would return characters instead of subcommand strings.
    lines.append(
        "        $tokens = @(if ($tokens.Count -gt 1) { $tokens[0..($tokens.Count - 2)] } else { })"
    )
    lines.append("    }")
    lines.append("    $cmdPath = @()")
    lines.append("    $posIndex = 0")
    lines.append("    $skipNext = $false")
    lines.append("    $inArgs = $false")
    lines.append("    $currentCmd = ''")
    lines.append("    $subPartial = ''")
    lines.append("    for ($i = 0; $i -lt $tokens.Count; $i++) {")
    lines.append("        $t = $tokens[$i]")
    lines.append("        if ($skipNext) { $skipNext = $false; continue }")
    lines.append("        if ($t -like '-*') {")
    lines.append(
        "            if ($t -notlike '*=*' -and $allFlags -notcontains $t) { $skipNext = $true }"
    )
    lines.append("            continue")
    lines.append("        }")
    lines.append('        $testCmd = if ($currentCmd) { "$currentCmd $t" } else { $t }')
    lines.append("        if (-not $inArgs -and $data.ContainsKey($testCmd)) {")
    lines.append("            $cmdPath += $t")
    lines.append("            $currentCmd = $testCmd")
    lines.append("            $subPartial = ''")
    lines.append("        } elseif (-not $inArgs) {")
    lines.append("            # Check if $t is a prefix of any subcommand at the current level.")
    lines.append(
        "            # If so, treat it as a partial subcommand and keep the filter for word completions."
    )
    lines.append("            $curEntry = $data[$currentCmd]")
    lines.append(
        "            $isSub = $curEntry -and "
        "($curEntry.words | Where-Object { $_ -notlike '-*' -and $_ -like \"$t*\" })"
    )
    lines.append("            if ($isSub) { $subPartial = $t }")
    lines.append("            else { $inArgs = $true; $posIndex++ }")
    lines.append("        } else {")
    lines.append("            $posIndex++")
    lines.append("        }")
    lines.append("    }")
    lines.append("    $cmd = $cmdPath -join ' '")
    lines.append("    $entry = $data[$cmd]")
    lines.append("    if (-not $entry) { return }")
    lines.append(
        "    # When the user typed a partial subcommand followed by a space (e.g. 'nxpimage ah<space>'),",
    )
    lines.append(
        "    # $subPartial holds the prefix and $wordToComplete is empty.  Use it to filter words."
    )
    lines.append(
        "    $wordFilter = if ($subPartial -ne '' -and $wordToComplete -eq '') { $subPartial } else { $wordToComplete }"
    )
    lines.append("")
    lines.append("    # Choice completions for previous option (prefix first, substring fallback)")
    lines.append("    if ($entry.choices -and $entry.choices.ContainsKey($prevWord)) {")
    lines.append(
        '        $choices = @($entry.choices[$prevWord] | Where-Object { $_ -like "$wordToComplete*" })'
    )
    lines.append("        if (-not $choices) {")
    lines.append(
        '            $choices = @($entry.choices[$prevWord] | Where-Object { $_ -like "*$wordToComplete*" })'
    )
    lines.append("        }")
    lines.append("        $choices | ForEach-Object {")
    lines.append(
        "            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)"
    )
    lines.append("        }")
    lines.append("        return")
    lines.append("    }")
    lines.append("")
    lines.append("    # File completions for previous option")
    lines.append("    if ($entry.files -and $prevWord -in $entry.files) {")
    lines.append(
        '        Get-ChildItem -Path "${wordToComplete}*" -ErrorAction SilentlyContinue | ForEach-Object {'
    )
    lines.append(
        "            $n = if ($_.PSIsContainer) { $_.Name + [System.IO.Path]::DirectorySeparatorChar } else { $_.Name }"
    )
    lines.append(
        "            [System.Management.Automation.CompletionResult]::new($n, $n, 'ProviderItem', $n)"
    )
    lines.append("        }")
    lines.append("        return")
    lines.append("    }")
    lines.append("")
    lines.append("    # Positional argument completions")
    lines.append(
        "    if ($entry.positionals -and $wordToComplete -notlike '-*' -and $posIndex -lt $entry.positionals.Count) {"
    )
    lines.append("        $pa = $entry.positionals[$posIndex]")
    lines.append("        if ($pa.type -eq 'choices') {")
    lines.append(
        '            $paChoices = @($pa.values | Where-Object { $_ -like "$wordToComplete*" })'
    )
    lines.append("            if (-not $paChoices) {")
    lines.append(
        '                $paChoices = @($pa.values | Where-Object { $_ -like "*$wordToComplete*" })'
    )
    lines.append("            }")
    lines.append("            $paChoices | ForEach-Object {")
    lines.append(
        "                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)"
    )
    lines.append("            }")
    lines.append("            return")
    lines.append("        } elseif ($pa.type -eq 'file') {")
    lines.append(
        '            Get-ChildItem -Path "${wordToComplete}*" -ErrorAction SilentlyContinue | ForEach-Object {'
    )
    _ps_container = (
        "                $n = if ($_.PSIsContainer) "
        "{ $_.Name + [System.IO.Path]::DirectorySeparatorChar } else { $_.Name }"
    )
    lines.append(_ps_container)
    lines.append(
        "                [System.Management.Automation.CompletionResult]::new($n, $n, 'ProviderItem', $n)"
    )
    lines.append("            }")
    lines.append("            return")
    lines.append("        }")
    lines.append("    }")
    lines.append("")
    lines.append("    # Word / subcommand completions")
    lines.append('    $entry.words | Where-Object { $_ -like "$wordFilter*" } | ForEach-Object {')
    lines.append(
        "        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)"
    )
    lines.append("    }")
    lines.append("}")
    lines.append("")
    # Register for both 'tool' and 'tool.exe' so completion works regardless of
    # how the executable is invoked on Windows.
    lines.append(
        f"Register-ArgumentCompleter -Native -CommandName '{_ps_string(tool_name)}'"
        f" -ScriptBlock $_{safe_var}_script"
    )
    lines.append(
        f"Register-ArgumentCompleter -Native -CommandName '{_ps_string(tool_name)}.exe'"
        f" -ScriptBlock $_{safe_var}_script"
    )
    lines.append("")

    return "\n".join(lines)


def write_powershell_completion(tool_name: str, tree: dict[str, Any], dest_dir: Path) -> Path:
    """Write a static PowerShell completion file for *tool_name*.

    :param tool_name: Executable name.
    :param tree: Command tree dict.
    :param dest_dir: Destination directory (created if absent).
    :return: Path to the written completion file.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    script = generate_powershell_script(tool_name, tree)
    out = dest_dir / f"{tool_name}.ps1"
    out.write_text(script, encoding="utf-8")
    return out


_ZSH_BLOCK_BEGIN = "# >>> SPSDK completions begin <<<"
_ZSH_BLOCK_END = "# <<< SPSDK completions end >>>"
_BASH_BLOCK_BEGIN = _ZSH_BLOCK_BEGIN
_BASH_BLOCK_END = _ZSH_BLOCK_END
_PS_BLOCK_BEGIN = _ZSH_BLOCK_BEGIN
_PS_BLOCK_END = _ZSH_BLOCK_END

# Single canonical pair used internally.
_BLOCK_BEGIN = _ZSH_BLOCK_BEGIN
_BLOCK_END = _ZSH_BLOCK_END


# ---------------------------------------------------------------------------
# PowerShell profile location helper
# ---------------------------------------------------------------------------


def _get_powershell_profile() -> Path:
    """Return the path to the current user's PowerShell profile.

    Queries the active PowerShell binary (``pwsh`` first, then ``powershell``)
    for its ``$PROFILE`` value so that non-standard installations — including
    PowerShell from the Windows Store — are handled correctly.

    Falls back to the platform-standard location when no PowerShell binary is
    reachable:

    - Windows:  ``~/Documents/PowerShell/Microsoft.PowerShell_profile.ps1``
    - Linux/macOS: ``~/.config/powershell/Microsoft.PowerShell_profile.ps1``

    :return: Path to the profile file (may not exist yet).
    """
    import platform
    import subprocess

    for binary in ("pwsh", "powershell"):
        try:
            result = subprocess.run(
                [binary, "-NoProfile", "-NonInteractive", "-Command", "Write-Output $PROFILE"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            profile_path = result.stdout.strip()
            if result.returncode == 0 and profile_path:
                return Path(profile_path)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue

    home = Path.home()
    if platform.system() == "Windows":
        return home / "Documents" / "PowerShell" / "Microsoft.PowerShell_profile.ps1"
    return home / ".config" / "powershell" / "Microsoft.PowerShell_profile.ps1"


# ---------------------------------------------------------------------------
# Abstract shell backend
# ---------------------------------------------------------------------------


class ShellBackend(ABC):
    """Abstract base class for a per-shell completion backend.

    Each concrete subclass handles one shell (bash, zsh, PowerShell) by
    implementing three abstract methods:

    * :meth:`write_completion` — generate and write completion file(s).
    * :meth:`build_profile_block` — produce the shell snippet to add/update
      in the user's shell profile.
    * :meth:`get_profile_path` — locate the profile file.

    The shared :meth:`setup_profile` method handles reading, patching, and
    writing the profile — the same logic for every shell.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Shell identifier string (e.g. ``"bash"``)."""

    @abstractmethod
    def write_completion(
        self, tool_name: str, tree: dict[str, Any], dest_dir: Path
    ) -> tuple[Path, ...]:
        """Generate and write completion file(s) for *tool_name*.

        :param tool_name: Executable name.
        :param tree: Command tree dict from :func:`walk_command_tree`.
        :param dest_dir: Destination directory (created if absent).
        :return: Tuple of paths to the written files.
        """

    @abstractmethod
    def build_profile_block(self, completions_dir: Path) -> str:
        """Return the shell snippet that activates SPSDK completions.

        :param completions_dir: Directory where completion files are stored.
        :return: Multi-line shell snippet string.
        """

    @abstractmethod
    def get_profile_path(self) -> Path:
        """Return the path to the user's shell profile file.

        :return: Path to the profile (may not exist yet).
        """

    def setup_profile(self, completions_dir: Path, dry_run: bool = False) -> str:
        """Add or update the SPSDK completion block in the shell profile.

        The block is wrapped in begin/end markers, making the operation
        idempotent — re-running replaces the existing block in place.

        :param completions_dir: Path containing the generated completion files.
        :param dry_run: When True, return a description without writing.
        :return: Human-readable status message.
        """
        profile = self.get_profile_path()
        block = self.build_profile_block(completions_dir)
        original = profile.read_text(encoding="utf-8") if profile.exists() else ""
        pattern = re.compile(
            re.escape(_BLOCK_BEGIN) + r".*?" + re.escape(_BLOCK_END) + r"\n?",
            re.DOTALL,
        )
        cleaned = pattern.sub("", original)
        updated = cleaned.rstrip("\n") + "\n\n" + block
        if dry_run:
            return f"[dry-run] Would write to {profile}:\n{block}"
        profile.parent.mkdir(parents=True, exist_ok=True)
        profile.write_text(updated, encoding="utf-8")
        return f"Updated {profile}"


# ---------------------------------------------------------------------------
# Concrete backends: Bash, Zsh, PowerShell
# ---------------------------------------------------------------------------


class BashBackend(ShellBackend):
    """Completion backend for bash."""

    @property
    def name(self) -> str:
        """Return the shell identifier ``"bash"``."""
        return "bash"

    def write_completion(
        self, tool_name: str, tree: dict[str, Any], dest_dir: Path
    ) -> tuple[Path, Path]:
        """Write the ``.sh`` data file and bash dispatcher for *tool_name*.

        :param tool_name: Executable name.
        :param tree: Command tree dict.
        :param dest_dir: Destination directory (created if absent).
        :return: Tuple of (data_path, dispatcher_path).
        """
        return write_bash_completion(tool_name, tree, dest_dir)

    def build_profile_block(self, completions_dir: Path) -> str:
        """Return the ~/.bashrc source loop for SPSDK completions.

        :param completions_dir: Path to the completions directory.
        :return: Multi-line bash snippet.
        """
        d = str(completions_dir)
        return (
            f"{_BLOCK_BEGIN}\n"
            f'for _spsdk_f in "{d}"/*.bash; do [ -r "$_spsdk_f" ] && source "$_spsdk_f"; done\n'
            "unset _spsdk_f\n"
            f"{_BLOCK_END}\n"
        )

    def get_profile_path(self) -> Path:
        """Return ``~/.bashrc``.

        :return: Path to the bash profile.
        """
        return Path.home() / ".bashrc"


class ZshBackend(ShellBackend):
    """Completion backend for zsh."""

    @property
    def name(self) -> str:
        """Return the shell identifier ``"zsh"``."""
        return "zsh"

    def write_completion(
        self, tool_name: str, tree: dict[str, Any], dest_dir: Path
    ) -> tuple[Path, Path]:
        """Write the ``.sh`` data file and zsh dispatcher for *tool_name*.

        :param tool_name: Executable name.
        :param tree: Command tree dict.
        :param dest_dir: Destination directory (created if absent).
        :return: Tuple of (data_path, dispatcher_path).
        """
        return write_zsh_completion(tool_name, tree, dest_dir)

    def build_profile_block(self, completions_dir: Path) -> str:
        """Return the ~/.zshrc fpath block for SPSDK completions.

        :param completions_dir: Path to the completions directory.
        :return: Multi-line zsh snippet.
        """
        d = str(completions_dir)
        return (
            f"{_BLOCK_BEGIN}\n"
            f'fpath=("{d}" $fpath)\n'
            "autoload -Uz compinit && compinit\n"
            f"{_BLOCK_END}\n"
        )

    def get_profile_path(self) -> Path:
        """Return ``~/.zshrc``.

        :return: Path to the zsh profile.
        """
        return Path.home() / ".zshrc"


class PowerShellBackend(ShellBackend):
    """Completion backend for PowerShell."""

    @property
    def name(self) -> str:
        """Return the shell identifier ``"powershell"``."""
        return "powershell"

    def write_completion(self, tool_name: str, tree: dict[str, Any], dest_dir: Path) -> tuple[Path]:
        """Write a static PowerShell completion file for *tool_name*.

        :param tool_name: Executable name.
        :param tree: Command tree dict.
        :param dest_dir: Destination directory (created if absent).
        :return: Tuple containing the path to the written ``.ps1`` file.
        """
        return (write_powershell_completion(tool_name, tree, dest_dir),)

    def build_profile_block(self, completions_dir: Path) -> str:
        """Return the PowerShell profile dot-source block for SPSDK completions.

        :param completions_dir: Path to the completions directory.
        :return: Multi-line PowerShell snippet.
        """
        d = str(completions_dir).replace("\\", "\\\\")
        return (
            f"{_BLOCK_BEGIN}\n"
            f"Get-ChildItem '{d}' -Filter '*.ps1' -ErrorAction SilentlyContinue"
            " | ForEach-Object { . $_.FullName }\n"
            f"{_BLOCK_END}\n"
        )

    def get_profile_path(self) -> Path:
        """Return the path to the active PowerShell profile.

        :return: Path to the profile file (may not exist yet).
        """
        return _get_powershell_profile()


#: Registry of all supported shell backends, keyed by shell name.
SHELL_BACKENDS: dict[str, ShellBackend] = {
    "bash": BashBackend(),
    "zsh": ZshBackend(),
    "powershell": PowerShellBackend(),
}


# ---------------------------------------------------------------------------
# Backward-compatible module-level helpers (thin wrappers over ShellBackend)
# ---------------------------------------------------------------------------


def _build_zsh_block(completions_dir: Path) -> str:
    """Build the ~/.zshrc block that activates SPSDK completions.

    :param completions_dir: Path to the completions directory.
    :return: Multi-line shell snippet.
    """
    return SHELL_BACKENDS["zsh"].build_profile_block(completions_dir)


def setup_zsh_profile(completions_dir: Path, dry_run: bool = False) -> str:
    """Add (or update) the SPSDK fpath block in ``~/.zshrc``.

    :param completions_dir: Path containing the generated completion files.
    :param dry_run: When True, return the diff text without writing anything.
    :return: Human-readable status message.
    """
    return SHELL_BACKENDS["zsh"].setup_profile(completions_dir, dry_run)


def _build_bash_block(completions_dir: Path) -> str:
    """Build the ~/.bashrc block that sources SPSDK bash completions.

    :param completions_dir: Path to the completions directory.
    :return: Multi-line shell snippet.
    """
    return SHELL_BACKENDS["bash"].build_profile_block(completions_dir)


def setup_bash_profile(completions_dir: Path, dry_run: bool = False) -> str:
    """Add (or update) the SPSDK source block in ``~/.bashrc``.

    :param completions_dir: Path containing the generated ``.bash`` files.
    :param dry_run: When True, return the description without writing.
    :return: Human-readable status message.
    """
    return SHELL_BACKENDS["bash"].setup_profile(completions_dir, dry_run)


def _build_ps_block(completions_dir: Path) -> str:
    """Build the PowerShell profile block that dot-sources SPSDK completions.

    :param completions_dir: Path to the completions directory.
    :return: Multi-line PowerShell snippet.
    """
    return SHELL_BACKENDS["powershell"].build_profile_block(completions_dir)


def setup_powershell_profile(completions_dir: Path, dry_run: bool = False) -> str:
    """Add (or update) the SPSDK dot-source block in the PowerShell profile.

    :param completions_dir: Path containing the generated ``.ps1`` files.
    :param dry_run: When True, return the description without writing.
    :return: Human-readable status message.
    """
    return SHELL_BACKENDS["powershell"].setup_profile(completions_dir, dry_run)


def setup_shell_completion(
    tool_name: str,
    cmd: click.Command,
    shell: str,
    dry_run: bool = False,
) -> tuple[bool, str]:
    """Generate static completion files for one tool and one shell.

    :param tool_name: Executable name (e.g. ``"nxpimage"``).
    :param cmd: Root Click command of the tool.
    :param shell: Target shell: ``"zsh"``, ``"bash"``, or ``"powershell"``.
    :param dry_run: When True, describe actions without writing any files.
    :return: Tuple of (success: bool, message: str).
    """
    backend = SHELL_BACKENDS.get(shell)
    if backend is None:
        supported = ", ".join(SHELL_BACKENDS)
        return False, f"Shell '{shell}' not supported. Use: {supported}"

    if dry_run:
        completions_dir = get_completions_dir()
        if shell == "bash":
            dry_msg = (
                f"[dry-run] Would write {completions_dir / (tool_name + '.sh')},"
                f" {completions_dir / (tool_name + '.bash')}"
            )
        elif shell == "zsh":
            dry_msg = (
                f"[dry-run] Would write {completions_dir / (tool_name + '.sh')},"
                f" {completions_dir / ('_' + tool_name)}"
            )
        elif shell == "powershell":
            dry_msg = f"[dry-run] Would write {completions_dir / (tool_name + '.ps1')}"
        else:
            dry_msg = f"[dry-run] Would write completions for {tool_name} ({shell})"
        return True, dry_msg

    completions_dir = get_completions_dir()
    tree = walk_command_tree(cmd, name=tool_name)

    if dry_run:
        return (
            True,
            f"[dry-run] Would write completions for {tool_name} ({shell}) to {completions_dir}",
        )

    paths = backend.write_completion(tool_name, tree, completions_dir)
    names = ", ".join(p.name for p in paths)
    return True, f"  {names}"
