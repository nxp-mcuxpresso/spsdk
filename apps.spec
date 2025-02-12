# -*- mode: python ; coding: utf-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Configuration file for PyInstaller for SPSDK Applications."""

import importlib
import importlib.resources
import os
import re
import shutil
from typing import Dict, List, Tuple

import cmsis_pack_manager
import jinja2
from libusbsio import LIBUSBSIO
from PyInstaller.building.build_main import BUNDLE, COLLECT, EXE, MERGE, PYZ, Analysis
from PyInstaller.compat import is_darwin
from PyInstaller.config import CONF
from PyInstaller.utils.hooks import copy_metadata


def create_resource_symlinks(app_dir: str, symlink_list: List[Tuple[str, str, str]]) -> None:
    """Creates symlinks from Resources to shared libraries.

    This must be done in the MacOS in order to be signed and notarized.

    :param app_dir: directory where the PyInstaller creates the layout
    :param symlink_list: list of tuples with source directory, relative directory and name of the package
    """
    for _source, relative, extra_dir in symlink_list:
        rsrc_path = os.path.join(app_dir, "Contents", "Resources", extra_dir, relative)
        bin_path = os.path.join(app_dir, "Contents", "MacOS", "tools_bin", extra_dir, relative)
        os.makedirs(os.path.dirname(bin_path), exist_ok=True)
        shutil.move(rsrc_path, bin_path)
        # number of folders - by splitting by "/" means how many times we should go back using ../
        back_cnt = len(relative.split("/")) + 1
        os.symlink("../" * back_cnt + "MacOS/tools_bin/" + extra_dir + "/" + relative, rsrc_path)


USE_BLOCK_CIPHER = None
datas = []

# setuptools_scm checks the version of setuptools and if not satisfied, it complains in console
datas.extend(copy_metadata("setuptools", recursive=False))

# exclude imports and make them available outside of the executable
# smartcard is LGPL so make it external outside of the executable so it can be replaced
excluded_imports = ["smartcard"]
macos_dirs_to_copy = list()
for pkg in excluded_imports:
    module = importlib.import_module(pkg)
    mod_path = module.__path__[0]
    if is_darwin:
        # on MacOS it is needed to split the library into correct place, PyInstaller does it incorrectly
        macos_dirs_to_copy.append(mod_path)
    else:
        # Windows and Linux, just put it as data
        datas.append((mod_path, os.path.basename(mod_path)))


hidden_imports = {"pkg_resources", "spsdk_pyocd", "spsdk_lauterbach", "pyocd.rtos.threadx"}


# List of packages that should have there Distutils entrypoints included.
def create_runtime_hook_entry_points(
    ep_packages: List[str], template_path: str = "pyinst_pkg_hook.j2"
) -> Dict[str, List[str]]:
    """Creates runtime hook configured to simulate entry_points.

    :param ep_packages: list of packages to be analyzed for entry points
    :param template_path: path to the jinja template with the runtime hook
    :return: dictionary with entry point name and appropriate list of items
    """
    hook_ep_packages: Dict[str, List[str]] = {}
    import importlib
    from importlib_metadata import entry_points

    for ep_package in ep_packages:
        for entry_point in importlib.metadata.entry_points(group=ep_package):
            if ep_package in hook_ep_packages:
                package_entry_point = hook_ep_packages[ep_package]
            else:
                package_entry_point = []
                hook_ep_packages[ep_package] = package_entry_point
            module_name, _, attr = entry_point.value.partition(":")
            package_entry_point.append(f"{entry_point.name} = {module_name}:{attr}")
            hidden_imports.add(module_name)

    with open(template_path) as f:
        # jinja2.Template doesn't have __init__, therefor the awkward type-hint
        template: jinja2.Template = jinja2.Template(f.read())
    os.makedirs("./generated", exist_ok=True)
    with open("./generated/pkg_resources_hook.py", "w", newline="") as f:
        f.write(template.render(packages=str(hook_ep_packages)))
    return hook_ep_packages


entries = create_runtime_hook_entry_points(
    [],
    template_path="tools/pyinstaller/pyinst_pkg_hook.j2",
)
# take from entry items the package name - line is in form "package:class"
for k, v in entries.items():
    for line in v:
        match = re.match(r"(.* = )(\w+):", line)
        if match:
            hidden_imports.add(match[2])


# add library for cmsis_pack_manager
cmsis_mod_dir = os.path.dirname(cmsis_pack_manager.__file__)
shared_binaries = [
    (cmsis_mod_dir + "/cmsis_pack_manager/*.so", "cmsis_pack_manager/cmsis_pack_manager/")
]

# add library for libusbsio
usblib = LIBUSBSIO()
usblib.LoadDLL()
shared_binaries.append(
    # pylint: disable=protected-access  # there's no other way
    (usblib._dllpath, os.path.dirname(usblib._dllpath[usblib._dllpath.find("libusbsio") :]))
)

# optionally add libraries for PQC
try:
    import spsdk_pqc

    spsdk_pqc_dir = os.path.dirname(spsdk_pqc.__file__)
    shared_binaries.append((spsdk_pqc_dir + "/*.so", "spsdk_pqc"))

except ImportError:
    pass

# add libuuu libraries
try:
    import libuuu

    uuudll = libuuu.LibUUU().DLL
    shared_binaries.append((uuudll, "libuuu/lib"))
except OSError:
    pass

datas.extend([("spsdk/data", "spsdk/data")])


# Additional PyOCD resources
SEQUENCE_LARK = "sequences.lark"

with importlib.resources.files("pyocd.debug.sequences") as package_path:
    resource_path = package_path / SEQUENCE_LARK

datas.extend([(resource_path, "pyocd/debug/sequences")])


def analyze(sources: List[str]) -> Analysis:
    """Helper for analysis the sources using PyInstaller.

    :param sources: array of python sources to be analyzed
    :return: Analysis instance
    """
    return Analysis(
        sources,
        pathex=["./"],
        binaries=shared_binaries,
        datas=datas,
        hiddenimports=list(hidden_imports),
        hookspath=["./tools/pyinstaller/hooks"],
        runtime_hooks=["./generated/pkg_resources_hook.py"],
        excludes=excluded_imports,
        win_no_prefer_redirects=False,
        win_private_assemblies=False,
        cipher=USE_BLOCK_CIPHER,
        noarchive=False,
    )


def executable(analysis: Analysis, name: str, version: str) -> EXE:
    """Creates PyInstaller executable information.

    :param analysis: Analysis instance from analyze function
    :param name: name of the application (no exe extension)
    :param version: (relative) path to version file
    :return: EXE instance
    """
    pyz = PYZ(analysis.pure, analysis.zipped_data, cipher=USE_BLOCK_CIPHER)
    return EXE(
        pyz,
        analysis.scripts,
        [],
        exclude_binaries=True,
        name=name,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=True,
        version=version,
        console=True,
    )


# analysis
a_blhost = analyze(["spsdk/apps/blhost.py"])
a_sdphost = analyze(["spsdk/apps/sdphost.py"])
a_sdpshost = analyze(["spsdk/apps/sdpshost.py"])
a_nxpdebugmbox = analyze(["spsdk/apps/nxpdebugmbox.py"])
a_pfr = analyze(["spsdk/apps/pfr.py"])
a_nxpele = analyze(["spsdk/apps/nxpele.py"])
a_nxpdevhsm = analyze(["spsdk/apps/nxpdevhsm.py"])
a_nxpimage = analyze(["spsdk/apps/nxpimage.py"])
a_shadowregs = analyze(["spsdk/apps/shadowregs.py"])
a_tphost = analyze(["spsdk/apps/tphost.py"])
a_tpconfig = analyze(["spsdk/apps/tpconfig.py"])
a_nxpdevscan = analyze(["spsdk/apps/nxpdevscan.py"])
a_ifr = analyze(["spsdk/apps/ifr.py"])
a_nxpcrypto = analyze(["spsdk/apps/nxpcrypto.py"])
a_nxpmemcfg = analyze(["spsdk/apps/nxpmemcfg.py"])
a_nxpwpc = analyze(["spsdk/apps/nxpwpc.py"])
a_el2go_host = analyze(["spsdk/apps/el2go.py"])
a_dk6prog = analyze(["spsdk/apps/dk6prog.py"])
a_lpcprog = analyze(["spsdk/apps/lpcprog.py"])
a_nxpdice = analyze(["spsdk/apps/nxpdice.py"])
a_nxpfuses = analyze(["spsdk/apps/nxpfuses.py"])
a_nxpuuu = analyze(["spsdk/apps/nxpuuu.py"])

# merge the dependencies together so the (first) blhost contains all required dependencies from all tools
MERGE(
    (a_blhost, "blhost", "blhost"),
    (a_sdphost, "sdphost", "sdphost"),
    (a_sdpshost, "sdpshost", "sdpshost"),
    (a_nxpdebugmbox, "nxpdebugmbox", "nxpdebugmbox"),
    (a_pfr, "pfr", "pfr"),
    (a_nxpele, "nxpele", "nxpele"),
    (a_nxpdevhsm, "nxpdevhsm", "nxpdevhsm"),
    (a_nxpimage, "nxpimage", "nxpimage"),
    (a_shadowregs, "shadowregs", "shadowregs"),
    (a_tphost, "tphost", "tphost"),
    (a_tpconfig, "tpconfig", "tpconfig"),
    (a_ifr, "ifr", "ifr"),
    (a_nxpdevscan, "nxpdevscan", "nxpdevscan"),
    (a_nxpcrypto, "nxpcrypto", "nxpcrypto"),
    (a_nxpmemcfg, "nxpmemcfg", "nxpmemcfg"),
    (a_nxpwpc, "nxpwpc", "nxpwpc"),
    (a_el2go_host, "el2go-host", "el2go-host"),
    (a_dk6prog, "dk6prog", "dk6prog"),
    (a_lpcprog, "lpcprog", "lpcprog"),
    (a_nxpdice, "nxpdice", "nxpdice"),
    (a_nxpfuses, "nxpfuses", "nxpfuses"),
    (a_nxpuuu, "nxpuuu", "nxpuuu"),
)


# fmt: off
# executables
exe_blhost = executable(a_blhost, "blhost", "tools/pyinstaller/blhost_version_info.txt")
exe_sdphost = executable(a_sdphost, "sdphost", "tools/pyinstaller/sdphost_version_info.txt")
exe_sdpshost = executable(a_sdpshost, "sdpshost", "tools/pyinstaller/sdpshost_version_info.txt")
exe_nxpdebugmbox = executable(a_nxpdebugmbox, "nxpdebugmbox", "tools/pyinstaller/nxpdebugmbox_version_info.txt")
exe_pfr = executable(a_pfr, "pfr", "tools/pyinstaller/pfr_version_info.txt")
exe_nxpele = executable(a_nxpele, "nxpele", "tools/pyinstaller/nxpele_version_info.txt")
exe_nxpdevhsm = executable(a_nxpdevhsm, "nxpdevhsm", "tools/pyinstaller/nxpdevhsm_version_info.txt")
exe_nxpimage = executable(a_nxpimage, "nxpimage", "tools/pyinstaller/nxpimage_version_info.txt")
exe_shadowregs = executable(a_shadowregs, "shadowregs", "tools/pyinstaller/shadowregs_version_info.txt")
exe_tphost = executable(a_tphost, "tphost", "tools/pyinstaller/tphost_version_info.txt")
exe_tpconfig = executable(a_tpconfig, "tpconfig", "tools/pyinstaller/tpconfig_version_info.txt")
exe_nxpdevscan = executable(a_nxpdevscan, "nxpdevscan", "tools/pyinstaller/nxpdevscan_version_info.txt")
exe_ifr = executable(a_ifr, "ifr", "tools/pyinstaller/ifr_version_info.txt")
exe_nxpcrypto = executable(a_nxpcrypto, "nxpcrypto", "tools/pyinstaller/nxpcrypto_version_info.txt")
exe_nxpmemcfg = executable(a_nxpmemcfg, "nxpmemcfg", "tools/pyinstaller/nxpmemcfg_version_info.txt")
exe_nxpwpc = executable(a_nxpwpc, "nxpwpc", "tools/pyinstaller/nxpwpc_version_info.txt")
exe_el2go_host = executable(a_el2go_host, "el2go-host", "tools/pyinstaller/el2go_version_info.txt")
exe_dk6prog = executable(a_dk6prog, "dk6prog", "tools/pyinstaller/dk6prog_version_info.txt")
exe_lpcprog = executable(a_lpcprog, "lpcprog", "tools/pyinstaller/lpcprog_version_info.txt")
exe_nxpdice = executable(a_nxpdice, "nxpdice", "tools/pyinstaller/nxpdice_version_info.txt")
exe_nxpfuses = executable(a_nxpfuses, "nxpfuses", "tools/pyinstaller/nxpfuses_version_info.txt")
exe_nxpuuu = executable(a_nxpuuu, "nxpuuu", "tools/pyinstaller/nxpuuu_version_info.txt")
# fmt: on
# collect all bundles together
coll_apps = COLLECT(
    exe_blhost,
    exe_sdphost,
    exe_nxpdebugmbox,
    exe_pfr,
    exe_nxpele,
    exe_nxpdevhsm,
    exe_nxpdice,
    exe_nxpimage,
    exe_nxpuuu,
    exe_shadowregs,
    exe_tphost,
    exe_tpconfig,
    exe_nxpdevscan,
    exe_ifr,
    exe_nxpcrypto,
    exe_nxpfuses,
    exe_nxpmemcfg,
    exe_nxpwpc,
    exe_el2go_host,
    exe_dk6prog,
    exe_lpcprog,
    exe_sdpshost,
    a_blhost.binaries,
    a_blhost.zipfiles,
    a_blhost.datas,
    a_sdphost.binaries,
    a_sdphost.zipfiles,
    a_sdphost.datas,
    a_nxpdebugmbox.binaries,
    a_nxpdebugmbox.zipfiles,
    a_nxpdebugmbox.datas,
    a_pfr.binaries,
    a_pfr.zipfiles,
    a_pfr.datas,
    a_nxpele.binaries,
    a_nxpele.zipfiles,
    a_nxpele.datas,
    a_nxpdevhsm.binaries,
    a_nxpdevhsm.zipfiles,
    a_nxpdevhsm.datas,
    a_nxpimage.binaries,
    a_nxpimage.zipfiles,
    a_nxpimage.datas,
    a_shadowregs.binaries,
    a_shadowregs.zipfiles,
    a_shadowregs.datas,
    a_tphost.binaries,
    a_tphost.zipfiles,
    a_tphost.datas,
    a_tpconfig.binaries,
    a_tpconfig.zipfiles,
    a_tpconfig.datas,
    a_nxpdevscan.binaries,
    a_nxpdevscan.zipfiles,
    a_nxpdevscan.datas,
    a_ifr.binaries,
    a_ifr.zipfiles,
    a_ifr.datas,
    a_nxpcrypto.binaries,
    a_nxpcrypto.zipfiles,
    a_nxpcrypto.datas,
    a_nxpmemcfg.binaries,
    a_nxpmemcfg.zipfiles,
    a_nxpmemcfg.datas,
    a_nxpwpc.binaries,
    a_nxpwpc.zipfiles,
    a_nxpwpc.datas,
    a_el2go_host.binaries,
    a_el2go_host.zipfiles,
    a_el2go_host.datas,
    a_dk6prog.binaries,
    a_dk6prog.zipfiles,
    a_dk6prog.datas,
    a_lpcprog.binaries,
    a_lpcprog.zipfiles,
    a_lpcprog.datas,
    a_nxpfuses.datas,
    a_nxpfuses.binaries,
    a_nxpfuses.zipfiles,
    a_nxpuuu.datas,
    a_nxpuuu.binaries,
    a_nxpuuu.zipfiles,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="spsdk",
)

if is_darwin:
    app = BUNDLE(
        coll_apps,
        name="spsdk.app",
        # icon='resources/securep.icns',
        bundle_identifier=None,
    )
    DIST_ROOT = os.path.join(CONF["distpath"], app.name)
    DIST_RSRCS = os.path.join(DIST_ROOT, "Contents", "Resources")
    DIST_MACOS = os.path.join(DIST_ROOT, "Contents", "MacOS")
    DIST_FRMWK = os.path.join(DIST_ROOT, "Contents", "Frameworks")
    # copy modules into the resources folder and make symlinks for binaries
    macos_symlinks = list()
    for mod_path in macos_dirs_to_copy:
        mod_name = os.path.basename(mod_path)
        # get files that should be soft-linked
        for root, dirs, files in os.walk(mod_path):
            for f in list(filter(lambda x: x.endswith(".so"), files)):
                macos_symlinks.append(
                    (
                        os.path.join(root, f),
                        os.path.relpath(os.path.join(root, f), mod_path),
                        os.path.basename(mod_path),
                    )
                )
        # copy all files into the Resources and create a soft link in the main binary directory
        shutil.copytree(mod_path, os.path.join(DIST_RSRCS, mod_name))
        os.symlink("../Resources/" + mod_name, os.path.join(DIST_FRMWK, mod_name))
    # move binary executables into tools_bin directory and create a soft link
    create_resource_symlinks(DIST_ROOT, macos_symlinks)
