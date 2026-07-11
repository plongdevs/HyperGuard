#!/usr/bin/env python
# coding=utf-8
import argparse
import os
import re
import sys
import json
import io
import glob
import zipfile
import traceback

from os import path
from logging import getLogger, INFO
from androguard.core import androconf
from androguard.core.analysis import analysis
from androguard.core.androconf import show_logging
from androguard.core.bytecodes import apk, dvm
from androguard.util import read
from HyperGuard.compiler import HyperGuard
from HyperGuard.util import (
    JniLongName,
    get_method_triple,
    get_access_method,
    is_synthetic_method,
    is_native_method,
)
from subprocess import check_call, STDOUT, run
from random import choice
from string import ascii_letters, digits
from shutil import copy, move, make_archive, rmtree, copytree
from pystyle import Colorate, Colors, Center, Write

BANNER = r"""
  ┬ ┬┬ ┬┌─┐┌─┐┬─┐┌─┐┬ ┬┌─┐┬─┐┌┬┐
  ├─┤└┬┘├─┘├┤ ├┬┘│ ┬│ │├─┤├┬┘ ││
  ┴ ┴ ┴ ┴  └─┘┴└─└─┘└─┘┴ ┴┴└──┴┘
"""

SUBTITLE = "  HyperGuard  ·  HyperGuard  ·  by plongdev\n"


def _c(text):
    return Colorate.Horizontal(Colors.red_to_white, text)


def _err(text):
    return f"\033[1;91m{text}\033[0m"


def _ok(text):
    return f"\033[92m{text}\033[0m"


def _dim(text):
    return f"\033[2m{text}\033[0m"


def _section(title):
    bar = "─" * 58
    print(_c(f"\n┌{bar}┐"))
    print(_c(f"│  {title:<56}│"))
    print(_c(f"└{bar}┘\n"))


def print_banner():
    print(_c(Center.XCenter(BANNER)))
    print(_c(Center.XCenter(SUBTITLE)))



APKTOOL = "tools/apktool.jar"
APKTOOL2 = 'tools/apktool.bat'
APKTOOL3 = 'tools/apktool'
SIGNJAR = "tools/apksigner.jar"
MANIFEST_EDITOR = "tools/manifest-editor.jar"
NDKBUILD = "ndk-build"
LLVM_STRIP = None  # Fix (Phase 2): resolved at startup from ndk_dir, used to strip .so symbols

SKIP_SYNTHETIC_METHODS = False
IGNORE_APP_LIB_ABIS = False
Logger = getLogger("HyperGuard")


def is_windows():
    return os.name == "nt"


def cpu_count():
    num_processes = os.cpu_count()
    if num_processes is None:
        num_processes = 2
    return num_processes


def create_tmp_directory():
    Logger.info("Creating .tmp folder")
    if not path.exists(".tmp"):
        os.mkdir(".tmp")


def get_random_str(length=8):
    characters = ascii_letters + digits
    result = "".join(choice(characters) for i in range(length))
    return result


def make_temp_dir(prefix="HyperGuard"):
    random_str = get_random_str()
    tmp = path.join(".tmp", prefix + random_str)

    while path.exists(tmp) and path.isdir(tmp):
        random_str = get_random_str()
        tmp = path.join(".tmp", prefix + random_str)
    os.mkdir(tmp)

    return tmp


def make_temp_file(suffix=""):
    random_str = get_random_str()
    tmp = path.join(".tmp", random_str + suffix)

    while path.exists(tmp) and path.isfile(tmp):
        random_str = get_random_str()
        tmp = path.join(".tmp", random_str + suffix)
    open(tmp, "w")

    return tmp


def clean_tmp_directory():
    tmpdir = ".tmp"
    try:
        Logger.info("Removing .tmp folder")
        rmtree(tmpdir)
    except OSError as e:
        run(["rd", "/s", "/q", tmpdir], shell=True)


def save_detailed_error_log(error_message, log_file=".HyperGuard_error.log"):
    try:
        timestamp = str(os.popen('date').read()).strip()
        with open(log_file, 'a') as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"Error Timestamp: {timestamp}\n")
            f.write(f"{'='*60}\n")
            f.write(f"{error_message}\n")
            f.write(f"{'='*60}\n\n")
        
        Logger.info(f"Error details saved to: {log_file}")
        return log_file
    except Exception as e:
        Logger.error(f"Error saving error log: {e}")
        return None


class ApkTool(object):
    HyperGuard_cfg = {}
    with open("HyperGuard.cfg") as fp:
        HyperGuard_cfg = json.load(fp)

    APKTOOL = HyperGuard_cfg["apktool"]

    @staticmethod
    def decompile(apk):
        outdir = make_temp_dir("HyperGuard-apktool-")
        if is_windows():
            check_call([APKTOOL2, 'd', '-r', '-f', '-o', outdir, apk])
        else:
            check_call(['bash', APKTOOL3, 'd', '-r', '-f', '-o', outdir, apk])
        return outdir

    @staticmethod
    def compile(decompiled_dir):
        unsiged_apk = make_temp_file("-unsigned.apk")
        check_call(
            [
                "java",
                "-jar",
                APKTOOL,
                "b",
                "--advanced",
                "-o",
                unsiged_apk,
                decompiled_dir,
            ],
            stderr=STDOUT,
        )
        return unsiged_apk


def change_min_sdk(command=list(), min_sdk="21", update_existing=True):
    if "--min-sdk-version" in command:
        if update_existing:
            min_sdk_value_index = command.index("--min-sdk-version") + 1
            command[min_sdk_value_index] = min_sdk
        else:
            return
    else:
        command.append("--min-sdk-version")
        command.append(min_sdk)


def change_max_sdk(command=list(), max_sdk="33", update_existing=True):
    if "--max-sdk-version" in command:
        if update_existing:
            max_sdk_value_index = command.index("--max-sdk-version") + 1
            command[max_sdk_value_index] = max_sdk
        else:
            return
    else:
        command.append("--max-sdk-version")
        command.append(max_sdk)


def sign(unsigned_apk, signed_apk):
    signature = {}
    keystore = ""

    Logger.info(f"Signing {unsigned_apk} -> {signed_apk}")

    with open("HyperGuard.cfg") as fp:
        HyperGuard_cfg = json.load(fp)
        signature = HyperGuard_cfg["signature"]
        keystore = signature["keystore_path"]

    if (
        signature["v1_enabled"] is False
        and signature["v2_enabled"] is False
        and signature["v3_enabled"] is False
    ):
        Logger.warning("At least one signing scheme should be enabled from v1, v2 & v3")
        move_unsigned(unsigned_apk, signed_apk)
        return

    if not path.exists(keystore) or not path.isfile(keystore):
        Logger.error("KeyStore not found in defined path or not recognized as a file")
        move_unsigned(unsigned_apk, signed_apk)
        return

    command = [
        "java",
        "-jar",
        SIGNJAR,
        "sign",
        "--in",
        unsigned_apk,
        "--out",
        signed_apk,
        "--ks",
        keystore,
        "--ks-key-alias",
        signature["alias"],
        "--ks-pass",
        "pass:" + signature["keystore_pass"],
        "--key-pass",
        "pass:" + signature["store_pass"],
    ]

    command.append("--v1-signing-enabled")
    command.append("true" if signature["v1_enabled"] is True else "false")
    command.append("--v2-signing-enabled")
    command.append("true" if signature["v2_enabled"] is True else "false")
    command.append("--v3-signing-enabled")
    command.append("true" if signature["v3_enabled"] is True else "false")
    command.append("--v4-signing-enabled")
    command.append("false")

    if signature["v1_enabled"] is True:
        change_min_sdk(command, "21")
        change_max_sdk(command, "23")
        command.append("--v1-signer-name")
        command.append("ANDROID")

    if signature["v2_enabled"] is True:
        change_min_sdk(command, "24", False)
        change_max_sdk(command, "26")

    if signature["v3_enabled"] is True:
        change_min_sdk(command, "28", False)
        change_max_sdk(command, "29")

    try:
        check_call(command, stderr=STDOUT)
    except Exception as ex:
        Logger.error("Signing %s failed!" % unsigned_apk, exc_info=True)
        print(f"{str(ex)}")
        move_unsigned(unsigned_apk, signed_apk)


def move_unsigned(unsigned_apk, signed_apk):
    Logger.info("Moving unsigned apk -> " + signed_apk)
    copy(unsigned_apk, signed_apk)


def build_project(project_dir, num_processes=0):
    check_call([NDKBUILD, "-j5", "-C", project_dir], stderr=STDOUT)


def find_llvm_strip(ndk_dir):
    """
    Fix (Phase 2): Locate llvm-strip inside the configured NDK toolchain.
    Searches all host-tag prebuilt dirs since the exact tag (linux-x86_64,
    darwin-x86_64, windows-x86_64, etc.) is environment-dependent.
    """
    if not ndk_dir or not path.exists(ndk_dir):
        return None
    patterns = [
        path.join(ndk_dir, "toolchains", "llvm", "prebuilt", "*", "bin", "llvm-strip"),
        path.join(ndk_dir, "toolchains", "llvm", "prebuilt", "*", "bin", "llvm-strip.exe"),
    ]
    for pattern in patterns:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]
    return None


def strip_compiled_libs(project_dir):
    """
    Fix (Phase 2): Strip all symbols/debug info from compiled .so libraries.
    Without this, function names, file paths and other metadata used by the
    Dex2C toolchain remain readable in the final binary via `nm`/`readelf`.
    Run this right after build_project(), before the libs are copied into
    the decompiled APK.
    """
    global LLVM_STRIP

    if not LLVM_STRIP:
        ndk_dir = ApkTool.HyperGuard_cfg.get("ndk_dir")
        LLVM_STRIP = find_llvm_strip(ndk_dir)

    if not LLVM_STRIP:
        Logger.warning(
            "llvm-strip không tìm thấy trong ndk_dir — bỏ qua bước strip "
            "(symbol có thể vẫn còn trong .so, khuyến nghị kiểm tra ndk_dir trong HyperGuard.cfg)"
        )
        return

    libs_dir = path.join(project_dir, "libs")
    if not path.exists(libs_dir):
        return

    stripped_count = 0
    for abi_name in os.listdir(libs_dir):
        abi_dir = path.join(libs_dir, abi_name)
        if not path.isdir(abi_dir):
            continue
        for fname in os.listdir(abi_dir):
            if not fname.endswith(".so"):
                continue
            so_path = path.join(abi_dir, fname)
            try:
                check_call([LLVM_STRIP, "--strip-all", so_path], stderr=STDOUT)
                stripped_count += 1
            except Exception as e:
                Logger.warning(f"Strip thất bại cho {so_path}: {e}")

    if stripped_count:
        Logger.info(_ok(f"  ✓ Đã strip symbol cho {stripped_count} file .so"))


def enforce_release_optim(application_mk_path="project/jni/Application.mk"):
    """
    Fix (Phase 2): Force APP_OPTIM := release in Application.mk.
    Without this the NDK may build in debug mode (-O0), leaving the compiled
    C++ far easier to read in a decompiler (Ghidra/IDA) than an optimized
    release build (-O2/-O3 + inlining + dead-code elimination).
    """
    if not path.exists(application_mk_path):
        Logger.warning(f"{application_mk_path} không tồn tại — bỏ qua APP_OPTIM enforcement")
        return

    found = False
    lines = []
    with open(application_mk_path, "r") as f:
        for line in f:
            if line.strip().startswith("APP_OPTIM"):
                lines.append("APP_OPTIM := release\n")
                found = True
            else:
                lines.append(line)

    if not found:
        lines.append("APP_OPTIM := release\n")

    with open(application_mk_path, "w") as f:
        f.writelines(lines)

    Logger.info(_ok("  ✓ Application.mk: APP_OPTIM := release"))


def auto_vm(filename):
    ret = androconf.is_android(filename)

    if ret == "APK":
        dex_files = list()

        for dex in apk.APK(filename).get_all_dex():
            dex_files.append(dvm.DalvikVMFormat(dex))

        return dex_files

    elif ret == "DEX":
        return list(dvm.DalvikVMFormat(read(filename)))

    elif ret == "DEY":
        return list(dvm.DalvikVMFormat(read(filename)))

    raise Exception("Unsupported file %s" % filename)


class MethodFilter(object):
    def __init__(self, configure, vm):
        self._compile_filters = []
        self._keep_filters = []
        self._compile_full_match = set()

        self.conflict_methods = set()
        self.native_methods = set()
        self.annotated_methods = set()

        self._load_filter_configure(configure)
        self._init_conflict_methods(vm)
        self._init_native_methods(vm)
        self._init_annotation_methods(vm)

    def _load_filter_configure(self, configure):
        if not path.exists(configure):
            return

        with open(configure) as fp:
            for line in fp:
                line = line.strip()
                if not line or line[0] == "#":
                    continue

                if line[0] == "!":
                    line = line[1:].strip()
                    self._keep_filters.append(re.compile(line))
                elif line[0] == "=":
                    line = line[1:].strip()
                    self._compile_full_match.add(line)
                else:
                    self._compile_filters.append(re.compile(line))

    def _init_conflict_methods(self, vm):
        all_methods = {}
        for m in vm.get_methods():
            method_triple = get_method_triple(m, return_type=False)
            if method_triple in all_methods:
                self.conflict_methods.add(m)
                self.conflict_methods.add(all_methods[method_triple])
            else:
                all_methods[method_triple] = m

    def _init_native_methods(self, vm):
        for m in vm.get_methods():
            cls_name, name, _ = get_method_triple(m)

            access = get_access_method(m.get_access_flags())
            if "native" in access:
                self.native_methods.add((cls_name, name))

    def _add_annotation_method(self, method):
        if not is_synthetic_method(method) and not is_native_method(method):
            self.annotated_methods.add(method)

    def _init_annotation_methods(self, vm):
        for c in vm.get_classes():
            adi_off = c.get_annotations_off()
            if adi_off == 0:
                continue

            adi = vm.CM.get_obj_by_offset(adi_off)
            annotated_class = False
            # ref:https://github.com/androguard/androguard/issues/175
            if adi.get_class_annotations_off() != 0:
                ann_set_item = vm.CM.get_obj_by_offset(adi.get_class_annotations_off())
                for aoffitem in ann_set_item.get_annotation_off_item():
                    annotation_item = vm.CM.get_obj_by_offset(
                        aoffitem.get_annotation_off()
                    )
                    encoded_annotation = annotation_item.get_annotation()
                    type_desc = vm.CM.get_type(encoded_annotation.get_type_idx())
                    if type_desc.endswith("HyperGuard;"):
                        annotated_class = True
                        for method in c.get_methods():
                            self._add_annotation_method(method)
                        break

            if not annotated_class:
                for mi in adi.get_method_annotations():
                    method = vm.get_method_by_idx(mi.get_method_idx())
                    ann_set_item = vm.CM.get_obj_by_offset(mi.get_annotations_off())

                    for aoffitem in ann_set_item.get_annotation_off_item():
                        annotation_item = vm.CM.get_obj_by_offset(
                            aoffitem.get_annotation_off()
                        )
                        encoded_annotation = annotation_item.get_annotation()
                        type_desc = vm.CM.get_type(encoded_annotation.get_type_idx())
                        if type_desc.endswith("HyperGuard;"):
                            self._add_annotation_method(method)

    def should_compile(self, method):
        # don't compile functions that have same parameter but differ return type
        if method in self.conflict_methods:
            return False

        # synthetic method
        if is_synthetic_method(method) and SKIP_SYNTHETIC_METHODS:
            return False

        # native method
        if is_native_method(method):
            return False

        method_triple = get_method_triple(method)
        cls_name, name, _ = method_triple

        if name == "<clinit>":
            return False

        if (cls_name, name) in self.native_methods:
            return False

        full_name = "".join(method_triple)
        for rule in self._keep_filters:
            if rule.search(full_name):
                return False

        if full_name in self._compile_full_match:
            return True

        if method in self.annotated_methods:
            return True

        for rule in self._compile_filters:
            if rule.search(full_name):
                return True

        return False


def copy_compiled_libs(project_dir, decompiled_dir):
    compiled_libs_dir = path.join(project_dir, "libs")
    decompiled_libs_dir = path.join(decompiled_dir, "lib")
    if not path.exists(compiled_libs_dir):
        return
    if not path.exists(decompiled_libs_dir):
        copytree(compiled_libs_dir, decompiled_libs_dir)
        return

    for abi in os.listdir(decompiled_libs_dir):
        dst = path.join(decompiled_libs_dir, abi)
        src = path.join(compiled_libs_dir, abi)
        if not path.exists(src) and abi == "armeabi":
            src = path.join(compiled_libs_dir, "armeabi-v7a")
            Logger.warning("Use armeabi-v7a for armeabi")

        if not path.exists(src):
            if IGNORE_APP_LIB_ABIS:
                continue
            else:
                raise Exception("ABI %s is not supported!" % abi)
        # n
        android_mk_filename = "project/jni/Android.mk"
        local_module_value = None
        with open(android_mk_filename, "r") as android_mk_file:
            for line in android_mk_file:
                if line.startswith("LOCAL_MODULE"):
                    _, local_module_value = line.split(":=", 1)
                    local_module_value = local_module_value.strip()
                    break

        libnc = path.join(src, "lib" + local_module_value + ".so")
        copy(libnc, dst)


def native_class_methods(smali_path, compiled_methods):
    def next_line():
        return fp.readline()

    def handle_annotanion():
        while True:
            line = next_line()
            if not line:
                break
            s = line.strip()
            code_lines.append(line)
            if s == ".end annotation":
                break
            else:
                continue

    def handle_method_body():
        while True:
            line = next_line()
            if not line:
                break
            s = line.strip()
            if s == ".end method":
                break
            elif s.startswith(".annotation runtime") and s.find("HyperGuard") < 0:
                code_lines.append(line)
                handle_annotanion()
            else:
                continue

    code_lines = []
    class_name = ""
    with open(smali_path, "r") as fp:
        while True:
            line = next_line()
            if not line:
                break
            code_lines.append(line)
            line = line.strip()
            if line.startswith(".class"):
                class_name = line.split(" ")[-1]
            elif line.startswith(".method"):
                current_method = line.split(" ")[-1]
                param = current_method.find("(")
                name, proto = current_method[:param], current_method[param:]
                if (class_name, name, proto) in compiled_methods:
                    if line.find(" native ") < 0:
                        code_lines[-1] = code_lines[-1].replace(
                            current_method, "native " + current_method
                        )
                    handle_method_body()
                    code_lines.append(".end method\n")

    with open(smali_path, "w") as fp:
        fp.writelines(code_lines)


def native_compiled_dexes(decompiled_dir, compiled_methods):
    classes_output = list(
        filter(lambda x: x.find("smali") >= 0, os.listdir(decompiled_dir))
    )
    todo = []
    for classes in classes_output:
        for method_triple in compiled_methods.keys():
            cls_name, name, proto = method_triple
            cls_name = cls_name[1:-1]  # strip L;
            smali_path = path.join(decompiled_dir, classes, cls_name) + ".smali"
            if path.exists(smali_path):
                todo.append(smali_path)

    for smali_path in todo:
        native_class_methods(smali_path, compiled_methods)


def write_compiled_methods(project_dir, compiled_methods):
    source_dir = path.join(project_dir, "jni", "nc")
    if not path.exists(source_dir):
        os.makedirs(source_dir)

    for method_triple, code in compiled_methods.items():
        full_name = JniLongName(*method_triple)
        filepath = path.join(source_dir, full_name) + ".cpp"
        if path.exists(filepath):
            Logger.warning("Overwrite file %s %s" % (filepath, method_triple))

        try:
            with open(filepath, "w") as fp:
                fp.write('#include "HyperGuard.h"\n' + code)
        except Exception as e:
            print(f"{str(e)}\n")

    with open(path.join(source_dir, "compiled_methods.txt"), "w") as fp:
        fp.write("\n".join(list(map("".join, compiled_methods.keys()))))


def get_split_lib_names(base_name, num=5):
    """Generate num distinct lib names derived from base_name."""
    import hashlib
    names = [base_name]
    for i in range(1, num):
        seed = f"{base_name}_{i}"
        suffix = hashlib.md5(seed.encode()).hexdigest()[:4]
        names.append(f"{base_name}_{suffix}")
    return names


def write_compiled_methods_split(project_dir, compiled_methods, num_libs=5):
    """Distribute compiled .cpp files across num_libs subfolders (nc1..nc5)."""
    # Create nc1..ncN dirs
    for i in range(1, num_libs + 1):
        nc_dir = path.join(project_dir, "jni", f"nc{i}")
        if not path.exists(nc_dir):
            os.makedirs(nc_dir)

    methods_list = list(compiled_methods.items())
    for idx, (method_triple, code) in enumerate(methods_list):
        bucket = (idx % num_libs) + 1          # 1..5
        nc_dir = path.join(project_dir, "jni", f"nc{bucket}")
        full_name = JniLongName(*method_triple)
        filepath = path.join(nc_dir, full_name) + ".cpp"
        try:
            with open(filepath, "w") as fp:
                fp.write('#include "HyperGuard.h"\n' + code)
        except Exception as e:
            print(f"{str(e)}\n")

    # Write manifest of compiled methods (optional, for debug)
    nc_dir = path.join(project_dir, "jni", "nc1")
    with open(path.join(nc_dir, "compiled_methods.txt"), "w") as fp:
        fp.write("\n".join(list(map("".join, compiled_methods.keys()))))


def generate_split_android_mk(project_dir, lib_names, unified_mode=False, base_lib_name=None):
    """Write Android.mk with one LOCAL_MODULE per lib."""
    mk_path = path.join(project_dir, "jni", "Android.mk")
    lines = ["LOCAL_PATH := $(call my-dir)\n\n"]
    
    if unified_mode:
        abis = ["armeabi-v7a", "arm64-v8a", "x86", "x86_64"]
        for abi in abis:
            lib_name = get_unified_lib_name(base_lib_name, abi)
            lines.append(f"# ── Module for {abi}: {lib_name} ──────────────────────\n")
            lines.append("include $(CLEAR_VARS)\n")
            lines.append(f"LOCAL_MODULE    := {lib_name}\n")
            lines.append("LOCAL_LDLIBS    := -llog\n")
            lines.append("LOCAL_C_INCLUDES := $(LOCAL_PATH)/nc\n")
            # All source files in one lib
            lines.append(
                f"LOCAL_SRC_FILES := nc/HyperGuard.cpp nc/well_known_classes.cpp "
                f"$(patsubst $(LOCAL_PATH)/%,%,$(wildcard $(LOCAL_PATH)/nc1/*.cpp))\n"
            )
            # Only build for the specific ABI
            lines.append(f"ifeq ($(TARGET_ARCH_ABI),{abi})\n")
            lines.append("include $(BUILD_SHARED_LIBRARY)\n")
            lines.append("endif\n\n")
    else:
        for i, lib_name in enumerate(lib_names, start=1):
            lines.append(f"# ── Module {i}: {lib_name} ──────────────────────\n")
            lines.append("include $(CLEAR_VARS)\n")
            lines.append(f"LOCAL_MODULE    := {lib_name}\n")
            lines.append("LOCAL_LDLIBS    := -llog\n")
            lines.append("LOCAL_C_INCLUDES := $(LOCAL_PATH)/nc\n")
            # Each module: shared runtime (HyperGuard.cpp + well_known_classes.cpp) + its own ncX/*.cpp
            lines.append(
                f"LOCAL_SRC_FILES := nc/HyperGuard.cpp nc/well_known_classes.cpp "
                f"$(patsubst $(LOCAL_PATH)/%,%,$(wildcard $(LOCAL_PATH)/nc{i}/*.cpp))\n"
            )
            lines.append("include $(BUILD_SHARED_LIBRARY)\n\n")
    with open(mk_path, "w") as f:
        f.writelines(lines)


def get_unified_lib_name(base_name, abi):
    """Generate a unified lib name based on ABI."""
    import hashlib
    suffix = hashlib.md5(base_name.encode()).hexdigest()[:4]
    abi_map = {
        "armeabi-v7a": "a32",
        "arm64-v8a": "a64",
        "x86": "x86",
        "x86_64": "x64",
        "armeabi": "a32"
    }
    v_suffix = abi_map.get(abi, "stub")
    return f"{base_name}_{suffix}_{v_suffix}"


def copy_compiled_libs_unified(project_dir, decompiled_dir, base_lib_name):
    """Copy unified .so files into the decompiled APK lib dirs."""
    compiled_libs_dir = path.join(project_dir, "libs")
    decompiled_libs_dir = path.join(decompiled_dir, "lib")
    
    if not path.exists(compiled_libs_dir):
        return
    if not path.exists(decompiled_libs_dir):
        copytree(compiled_libs_dir, decompiled_libs_dir)
        return

    for abi in os.listdir(decompiled_libs_dir):
        dst_dir = path.join(decompiled_libs_dir, abi)
        src_abi = abi
        if not path.exists(path.join(compiled_libs_dir, abi)) and abi == "armeabi":
            src_abi = "armeabi-v7a"
            Logger.warning("Use armeabi-v7a for armeabi")
            
        src_dir = path.join(compiled_libs_dir, src_abi)
        if not path.exists(src_dir):
            if IGNORE_APP_LIB_ABIS:
                continue
            else:
                raise Exception(f"ABI {abi} is not supported!")
        
        lib_name = get_unified_lib_name(base_lib_name, src_abi)
        so_src = path.join(src_dir, f"lib{lib_name}.so")
        so_dst = path.join(dst_dir, f"lib{lib_name}.so")
        
        if path.exists(so_src):
            copy(so_src, so_dst)
            Logger.info(_ok(f"  ✓ Copied lib{lib_name}.so → {abi}"))
        else:
            # Try to find any .so in that dir if the specific one isn't there (fallback)
            so_files = [f for f in os.listdir(src_dir) if f.endswith(".so")]
            if so_files:
                copy(path.join(src_dir, so_files[0]), so_dst)
                Logger.info(_ok(f"  ✓ Copied {so_files[0]} → {abi} as lib{lib_name}.so"))
            else:
                Logger.warning(f"  ✗ Unified lib for {abi} not found in {src_dir}")


def generate_unified_loader(loader_path, custom_loader, base_lib_name, method_name):
    """Generate Loader.smali that loads the unified lib for the current ABI."""
    loader_class = "L" + custom_loader.replace(".", "/") + ";"
    loader_pkg = "/".join(custom_loader.split(".")[:-1])
    ui_hijack_class = f"L{loader_pkg}/UIHijackingDetect;"

    import hashlib
    suffix = hashlib.md5(base_lib_name.encode()).hexdigest()[:4]
    
    smali = f'''.class public {loader_class[:-1]};
.super Landroid/app/Application;

# direct methods
.method static constructor <clinit>()V
    .registers 0
    invoke-static {{}}, {loader_class}->loadLibraries()V
    return-void
.end method

.method public constructor <init>()V
    .registers 1
    invoke-direct {{p0}}, Landroid/app/Application;-><init>()V
    return-void
.end method

.method protected attachBaseContext(Landroid/content/Context;)V
    .registers 2
    invoke-super {{p0, p1}}, Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V
    
    # Khởi tạo core native sớm nhất có thể
    invoke-static {{p1}}, {loader_class}->initCore(Landroid/content/Context;)V
    
    return-void
.end method

.method public onCreate()V
    .registers 1
    invoke-super {{p0}}, Landroid/app/Application;->onCreate()V
    
    # Kích hoạt bảo vệ UI
    invoke-static {{p0}}, {ui_hijack_class}->init(Landroid/app/Application;)V
    
    return-void
.end method

.method private static native initCore(Landroid/content/Context;)V
.end method

# Hàm giải mã chuỗi native (Virbox-style)
.method public static native a([B)Ljava/lang/String;
.end method

.method private static loadLibraries()V
    .registers 2
    sget-object v0, Landroid/os/Build;->SUPPORTED_ABIS:[Ljava/lang/String;
    const/4 v1, 0x0
    aget-object v0, v0, v1
    const-string v1, "arm64-v8a"
    invoke-virtual {{v0, v1}}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v1
    if-eqz v1, :cond_arm64_no
    const-string v0, "{base_lib_name}_{suffix}_a64"
    goto :goto_load
    :cond_arm64_no
    const-string v1, "armeabi-v7a"
    invoke-virtual {{v0, v1}}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v1
    if-eqz v1, :cond_arm32_no
    const-string v0, "{base_lib_name}_{suffix}_a32"
    goto :goto_load
    :cond_arm32_no
    const-string v1, "x86_64"
    invoke-virtual {{v0, v1}}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v1
    if-eqz v1, :cond_x64_no
    const-string v0, "{base_lib_name}_{suffix}_x64"
    goto :goto_load
    :cond_x64_no
    const-string v1, "x86"
    invoke-virtual {{v0, v1}}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v0
    if-eqz v0, :cond_default
    const-string v0, "{base_lib_name}_{suffix}_x86"
    goto :goto_load
    :cond_default
    const-string v0, "{base_lib_name}_{suffix}_a32"
    :goto_load
    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method

.method public static final native {method_name}()V
.end method
'''
    with open(loader_path, "w") as f:
        f.write(smali)


def generate_split_loader(loader_path, lib_names, custom_loader, method_name):
    """Generate Loader.smali that loads all split libs."""
    loader_class = "L" + custom_loader.replace(".", "/") + ";"
    loader_pkg = "/".join(custom_loader.split(".")[:-1])
    ui_hijack_class = f"L{loader_pkg}/UIHijackingDetect;"

    load_lines = ""
    for lib in lib_names:
        load_lines += f'''
    const-string v0, "{lib}"
    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
'''
    smali = f'''.class public {loader_class[:-1]};
.super Landroid/app/Application;

# direct methods
.method static constructor <clinit>()V
    .registers 0
    invoke-static {{}}, {loader_class}->loadLibraries()V
    return-void
.end method

.method public constructor <init>()V
    .registers 1
    invoke-direct {{p0}}, Landroid/app/Application;-><init>()V
    return-void
.end method

.method protected attachBaseContext(Landroid/content/Context;)V
    .registers 2
    invoke-super {{p0, p1}}, Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V
    
    # Khởi tạo core native sớm nhất có thể
    invoke-static {{p1}}, {loader_class}->initCore(Landroid/content/Context;)V
    
    return-void
.end method

.method public onCreate()V
    .registers 1
    invoke-super {{p0}}, Landroid/app/Application;->onCreate()V
    
    # Kích hoạt bảo vệ UI
    invoke-static {{p0}}, {ui_hijack_class}->init(Landroid/app/Application;)V
    
    return-void
.end method

.method private static native initCore(Landroid/content/Context;)V
.end method

# Hàm giải mã chuỗi native (Virbox-style)
.method public static native a([B)Ljava/lang/String;
.end method

.method private static loadLibraries()V
    .registers 1
{load_lines}
    return-void
.end method

.method public static final native {method_name}()V
.end method
'''
    with open(loader_path, "w") as f:
        f.write(smali)


def copy_compiled_libs_split(project_dir, decompiled_dir, lib_names):
    """Copy all split .so files into the decompiled APK lib dirs."""
    compiled_libs_dir = path.join(project_dir, "libs")
    decompiled_libs_dir = path.join(decompiled_dir, "lib")
    if not path.exists(compiled_libs_dir):
        return
    if not path.exists(decompiled_libs_dir):
        copytree(compiled_libs_dir, decompiled_libs_dir)
        return

    for abi in os.listdir(decompiled_libs_dir):
        dst_dir = path.join(decompiled_libs_dir, abi)
        src_dir = path.join(compiled_libs_dir, abi)
        if not path.exists(src_dir) and abi == "armeabi":
            src_dir = path.join(compiled_libs_dir, "armeabi-v7a")
            Logger.warning("Use armeabi-v7a for armeabi")
        if not path.exists(src_dir):
            if IGNORE_APP_LIB_ABIS:
                continue
            else:
                raise Exception(f"ABI {abi} is not supported!")
        for lib_name in lib_names:
            so_src = path.join(src_dir, f"lib{lib_name}.so")
            so_dst = path.join(dst_dir, f"lib{lib_name}.so")
            if path.exists(so_src):
                copy(so_src, so_dst)
                Logger.info(_ok(f"  ✓ Copied lib{lib_name}.so → {abi}"))
            else:
                Logger.warning(f"  ✗ lib{lib_name}.so not found in {src_dir}")

def archive_compiled_code(project_dir):
    outfile = make_temp_file("-HyperGuard")
    outfile = make_archive(outfile, "zip", project_dir)
    return outfile


def compile_dex(apkfile, filtercfg, obfus):
    dex_files = auto_vm(apkfile)
    dex_analysis = analysis.Analysis()

    X_compiled_method_code = {}
    X_errors = []

    for dex in dex_files:
        dex_analysis.add(dex)

    for dex in dex_files:
        method_filter = MethodFilter(filtercfg, dex)

        compiler = HyperGuard(dex, dex_analysis, obfus)

        compiled_method_code = {}
        errors = []

        for m in dex.get_methods():
            method_triple = get_method_triple(m)

            jni_longname = JniLongName(*method_triple)
            full_name = "".join(method_triple)

            if len(jni_longname) > 220:
                Logger.debug("Name to long %s(> 220) %s" % (jni_longname, full_name))
                continue

            if method_filter.should_compile(m):
                Logger.debug("compiling %s" % (full_name))
                try:
                    code = compiler.get_source_method(m)
                except Exception as e:
                    Logger.warning(
                        "compile method failed:%s (%s)" % (full_name, str(e)),
                        exc_info=True,
                    )
                    errors.append("%s:%s" % (full_name, str(e)))
                    X_errors.extend(errors)
                    continue

                if code:
                    compiled_method_code[method_triple] = code
                    X_compiled_method_code.update(compiled_method_code)

    return X_compiled_method_code, X_errors


def is_apk(name):
    return name.endswith(".apk")


# n
def get_heap_size():
    return


# n
def get_application_name_from_manifest(apk_file):
    a = apk.APK(apk_file)
    manifest_data = a.get_android_manifest_xml()
    application_element = manifest_data.find("application")
    application_name = application_element.get(
        "{http://schemas.android.com/apk/res/android}name", ""
    )
    return application_name


# n
def get_smali_folders(decompiled_dir):
    folders = os.listdir(decompiled_dir)
    folders = [
        folder
        for folder in folders
        if path.isdir(path.join(decompiled_dir, folder)) and folder.startswith("smali")
    ]
    return folders


# n
def get_application_class_file(decompiled_dir, smali_folders, application_name):
    if not application_name == "":
        fileName = application_name.replace(".", os.sep) + ".smali"

        for smali_folder in smali_folders:
            filePath = path.join(decompiled_dir, smali_folder, fileName)

            if path.exists(filePath):
                return filePath

    return ""


# n
def backup_jni_project_folder():
    Logger.info("Backing up jni folder")

    src_path = path.join("project", "jni")
    dest_path = make_temp_dir("jni-")

    copytree(src_path, dest_path, dirs_exist_ok=True)
    return dest_path


# n
def restore_jni_project_folder(src_path):
    Logger.info("Restoring jni folder")

    dest_path = path.join("project", "jni")

    if path.exists(dest_path) and path.isdir(dest_path):
        rmtree(dest_path)

    copytree(src_path, dest_path)


# n
def adjust_application_mk(apkfile):
    Logger.info("Adjusting Application.mk file using available abis from apk")

    supported_abis = {"armeabi-v7a", "arm64-v8a", "x86_64", "x86"}
    depreacated_abis = {"armeabi"}
    available_abis = set()

    if is_apk(apkfile):
        zip_file = zipfile.ZipFile(io.BytesIO(bytearray(read(apkfile))), mode="r")

        for file_name in zip_file.namelist():
            if file_name.startswith("lib/"):
                abi_name = file_name.split("/")[1].strip()

                if len(file_name.split("/")) <= 2:
                    continue

                if abi_name in supported_abis:
                    available_abis.add(abi_name)
                elif abi_name in depreacated_abis:
                    Logger.warning(
                        "ABI 'armeabi' is depreacated, using 'armeabi-v7a' instead"
                    )
                    available_abis.add("armeabi-v7a")
                else:
                    raise Exception(
                        f"ABI '{abi_name}' is unsupported, please remove it from apk or use flag --force-keep-libs and try again"
                    )

        if len(available_abis) == 0:
            Logger.info(
                "No lib abis found in apk, using the ones defined in Application.mk file"
            )
            return

        application_mk_path = "project/jni/Application.mk"
        temp_application_mk_path = make_temp_file("-application.mk")

        with open(application_mk_path, "r") as application_mk_file:
            with open(temp_application_mk_path, "w") as temp_application_mk_file:
                for line in application_mk_file:
                    if line.startswith("APP_ABI"):
                        line = "APP_ABI := " + " ".join(available_abis) + "\n"
                    temp_application_mk_file.write(line)

        os.remove(application_mk_path)
        copy(temp_application_mk_path, application_mk_path)
    else:
        raise Exception(f"{apkfile} is not an apk file")


# n
def HyperGuard_main(
    apkfile,
    obfus,
    filtercfg,
    custom_loader,
    outapk,
    do_compile=True,
    project_dir=None,
    source_archive="project-source.zip",
    lib_name=None,
    num_split_libs=5,
    unified_mode=True,
):
    if not path.exists(apkfile):
        Logger.error("Input apk file %s does not exist", apkfile)
        return

    if not outapk:
        Logger.error("\033[31mOutput file name required\n\033[0m")
        return

    if custom_loader.rfind(".") == -1:
        Logger.error(
            "\n[ERROR] Custom Loader must have at least one package, such as \033[31mDemo.%s\033[0m\n",
            custom_loader,
        )
        return

    # Store the original HyperGuard.cpp content to restore later
    with open("project/jni/nc/HyperGuard.cpp", "r", encoding="utf-8") as file:
        orig_cpp_data = file.read()

    # Update JNI method names and JNI_OnLoad in C++
    HyperGuard_file_data = orig_cpp_data
    jni_prefix = "Java_" + custom_loader.replace(".", "_")
    HyperGuard_file_data = re.sub(
        r'Java_[a-zA-Z0-9_]+?_(Native|Loader)',
        jni_prefix,
        HyperGuard_file_data
    )
    
    # Update all FindClass calls for the Loader/Native class (JNI_OnLoad and others)
    HyperGuard_file_data = re.sub(
        r'env->FindClass\("([a-zA-Z0-9_/]+?)/(Native|Loader)"\);',
        'env->FindClass("' + custom_loader.replace(".", "/") + '");',
        HyperGuard_file_data
    )
    
    # Update placeholder native method if exists
    method_name = lib_name + "_HyperGuard_Pro" if lib_name else "PLongDeveloper_HyperGuard_Pro"
    HyperGuard_file_data = re.sub(
        r'(_PLongDeveloper_HyperGuard_Pro__)',
        "_" + method_name + "__",
        HyperGuard_file_data
    )

    with open("project/jni/nc/HyperGuard.cpp", "w") as file:
        file.write(HyperGuard_file_data)

    if not IGNORE_APP_LIB_ABIS:
        adjust_application_mk(apkfile)

    # Fix (Phase 2): luôn force release optim, bất kể IGNORE_APP_LIB_ABIS
    enforce_release_optim()

    # Convert dex to cpp
    compiled_methods, errors = compile_dex(apkfile, filtercfg, obfus)

    if errors:
        Logger.warning("================================")
        Logger.warning("\n".join(errors))
        Logger.warning("================================")

    if len(compiled_methods) == 0:
        Logger.info("No methods compiled! Check your filter file.")
        return

    # ── Determine lib names ─────────────────────────────────────────────
    if unified_mode:
        num_split_libs = 1 # All in one folder nc1
        Logger.info(_c(f"  ▶  Unified mode enabled"))

    if not lib_name:
        with open("project/jni/Android.mk", "r") as _f:
            for _line in _f:
                if _line.startswith("LOCAL_MODULE"):
                    lib_name = _line.split(":=", 1)[1].strip()
                    break
    
    split_lib_names = get_split_lib_names(lib_name, num_split_libs)
    if not unified_mode:
        Logger.info(_c(f"  ▶  Split mode: {num_split_libs} libs — {split_lib_names}"))

    if project_dir:
        if not path.exists(project_dir):
            copytree("project", project_dir)
        write_compiled_methods_split(project_dir, compiled_methods, num_split_libs)
    else:
        project_dir = make_temp_dir("HyperGuard-project-")
        rmtree(project_dir)
        copytree("project", project_dir)
        write_compiled_methods_split(project_dir, compiled_methods, num_split_libs)

        if not do_compile:
            src_zip = archive_compiled_code(project_dir)
            move(src_zip, source_archive)

    # Generate Android.mk
    generate_split_android_mk(project_dir, split_lib_names, unified_mode, lib_name)

    if do_compile:
        build_project(project_dir)
        # Fix (Phase 2): strip toàn bộ symbol khỏi .so vừa build trước khi copy vào APK
        strip_compiled_libs(project_dir)

    if is_apk(apkfile) and outapk:
        decompiled_dir = ApkTool.decompile(apkfile)
        native_compiled_dexes(decompiled_dir, compiled_methods)
        
        if unified_mode:
            copy_compiled_libs_unified(project_dir, decompiled_dir, lib_name)
        else:
            copy_compiled_libs_split(project_dir, decompiled_dir, split_lib_names)

        # Get smali folders
        smali_folders = get_smali_folders(decompiled_dir)
        android_mk_file_path = "project/jni/Android.mk"
        loader_file_path = "loader/Native.smali"
        temp_loader = make_temp_file("-Native.smali")

        # Use provided lib_name if available, otherwise read from Android.mk
        local_module_value = lib_name
        if not local_module_value:
            with open(android_mk_file_path, "r") as android_mk_file:
                for line in android_mk_file:
                    if line.startswith("LOCAL_MODULE"):
                        _, local_module_value = line.split(":=", 1)
                        local_module_value = local_module_value.strip()
                        break

        if not local_module_value:
            raise Exception("Invalid LOCAL_MODULE defined in project/jni/Android.mk")

        # Generate Loader.smali
        method_name = local_module_value + "_HyperGuard_Pro"
        if unified_mode:
            generate_unified_loader(temp_loader, custom_loader, lib_name, method_name)
        else:
            generate_split_loader(temp_loader, split_lib_names, custom_loader, method_name)


        apk_file_path = apkfile
        application_class_name = get_application_name_from_manifest(apk_file_path)
        file_path = get_application_class_file(
            decompiled_dir, smali_folders, application_class_name
        )

        if application_class_name == "" or file_path == "":
            try:
                Logger.info(
                    "\nApplication class not found in the AndroidManifest.xml or doesn't exist in dex, adding \033[32m"
                    + custom_loader
                    + "\033[0m\n"
                )

                check_call(
                    [
                        "java",
                        "-jar",
                        MANIFEST_EDITOR,
                        path.join(decompiled_dir, "AndroidManifest.xml"),
                        custom_loader,
                    ],
                    stderr=STDOUT,
                )
            except Exception as e:
                Logger.error(f"Error: {e.returncode} - {e.output}", exec_info=True)
        else:
            Logger.info(
                "\nApplication class from AndroidManifest.xml, \033[32m"
                + application_class_name
                + "\033[0m\n"
            )

            check_call(
                [
                    "java",
                    "-jar",
                    MANIFEST_EDITOR,
                    path.join(decompiled_dir, "AndroidManifest.xml"),
                    application_class_name,
                ],
                stderr=STDOUT,
            )

            line_to_insert = (
                "    invoke-static {}, L"
                + custom_loader.replace(".", "/")
                + ";->" + method_name + "()V\n"
            )

            code_block_to_append = f"""
.method static final constructor <clinit>()V
    .registers 0

{line_to_insert}

    return-void
.end method
"""

            with open(file_path, "r") as file:
                content = file.readlines()

            index = next(
                (i for i, line in enumerate(content) if "<clinit>" in line), None
            )

            if index is not None:
                locals_index = next(
                    (
                        i
                        for i, line in enumerate(content[index:])
                        if ".locals" in line or ".registers" in line
                    ),
                    None,
                )
                if locals_index is not None:
                    content.insert(index + locals_index + 1, line_to_insert)
                else:
                    Logger.error("Couldn't read <clinit> method in Application class")
            else:
                content.append(code_block_to_append)

            with open(file_path, "w") as file:
                file.writelines(content)

        if custom_loader.rfind(".") > -1:
            loaderDir = path.join(
                decompiled_dir,
                smali_folders[-1],
                custom_loader[0 : custom_loader.rfind(".")].replace(".", os.sep),
            )
            try:
                rmtree(loaderDir)
            except OSError as e:
                run(["rd", "/s", "/q", loaderDir], shell=True)
            os.makedirs(loaderDir)

        copy(
            temp_loader,
            path.join(
                loaderDir,
                custom_loader.split(".")[-1] + ".smali",
            ),
        )
        
        # Copy and patch UIHijackingDetect.smali and Anti-Crack stub
        ui_source = "loader/UIHijackingDetect.smali"
        anti_crack_source = "loader/HyperGuard.smali"
        
        try:
            # Detect original package name from APK
            from androguard.core.bytecodes import apk
            a_obj = apk.APK(apkfile)
            original_package_name = a_obj.get_package()
            Logger.info(_ok(f"  ✓ Detected package name: {original_package_name}"))

            loader_pkg = "/".join(custom_loader.split(".")[:-1])

            # 1. UIHijackingDetect
            with open(ui_source, "r", encoding="utf-8") as f:
                ui_content = f.read()
            new_ui_class = f"L{loader_pkg}/UIHijackingDetect;"
            ui_content = ui_content.replace("Lplongdev/HyperGuardPro/UIHijackingDetect;", new_ui_class)
            # Patch Anti-Crack reference inside UIHijackingDetect if it exists
            ui_content = ui_content.replace("Lplongdev/HyperGuardPro/HyperGuard;", f"L{loader_pkg}/HyperGuard;")
            with open(path.join(loaderDir, "UIHijackingDetect.smali"), "w", encoding="utf-8") as f:
                f.write(ui_content)

            # 2. HyperGuard (Anti-Crack)
            with open(anti_crack_source, "r", encoding="utf-8") as f:
                ac_content = f.read()
            new_ac_class = f"L{loader_pkg}/HyperGuard;"
            ac_content = ac_content.replace("Lplongdev/HyperGuardPro/HyperGuard;", new_ac_class)
            # Inject detected package name
            ac_content = ac_content.replace("PACKAGE_NAME_PLACEHOLDER", original_package_name)
            
            with open(path.join(loaderDir, "HyperGuard.smali"), "w", encoding="utf-8") as f:
                f.write(ac_content)

            Logger.info(_ok(f"  ✓ Patched and copied UI and Anti-Crack (Package: {original_package_name}) stubs to {loader_pkg}"))
        except Exception as e:
            Logger.error(f"  ✗ Lỗi khi xử lý stubs: {e}")
            copy(ui_source, path.join(loaderDir, "UIHijackingDetect.smali"))
            copy(anti_crack_source, path.join(loaderDir, "HyperGuard.smali"))
        
        unsigned_apk = ApkTool.compile(decompiled_dir)
        sign(unsigned_apk, outapk)

    # ── Restore original files ───────────────────────────────────────
    try:
        with open("project/jni/nc/HyperGuard.cpp", "w", encoding="utf-8") as f:
            f.write(orig_cpp_data)
        
        with open("project/jni/Android.mk", "r", encoding="utf-8") as f:
            mk_content = f.read()
        mk_content = re.sub(r'LOCAL_MODULE\s*:=\s*\w+', 'LOCAL_MODULE := HyperGuard', mk_content)
        with open("project/jni/Android.mk", "w", encoding="utf-8") as f:
            f.write(mk_content)
        Logger.info(_ok("  ✓ Đã khôi phục project/jni/nc/HyperGuard.cpp và Android.mk"))
    except Exception as e:
        Logger.error(f"  ✗ Lỗi khi khôi phục file: {e}")


def get_user_input(prompt, default=None, input_type=str, valid_options=None):
    """Get user input with styled validation and default value."""
    while True:
        hint = _dim(f"[{default}]") if default is not None else ""
        arrow = _c("  ›› ")
        display_prompt = f"{arrow}{_c(prompt)} {hint}{_c(': ')}"

        user_input = input(display_prompt).strip()

        if not user_input and default is not None:
            return default

        if not user_input:
            print(_err("  ✗ Không được để trống!\n"))
            continue

        if valid_options and user_input not in valid_options:
            print(_err(f"  ✗ Lựa chọn không hợp lệ. Nhập một trong: {', '.join(valid_options)}\n"))
            continue

        if input_type == bool:
            if user_input.lower() in ('y', 'yes', 'true', '1'):
                return True
            elif user_input.lower() in ('n', 'no', 'false', '0'):
                return False
            else:
                print(_err("  ✗ Chỉ nhập 'y' hoặc 'n'\n"))
                continue

        try:
            return input_type(user_input)
        except ValueError:
            print(_err(f"  ✗ Giá trị không hợp lệ. Vui lòng nhập {input_type.__name__} hợp lệ\n"))


def interactive_mode():
    os.system("cls" if os.name == "nt" else "clear")
    print_banner()
    _section("HyperGuard  —  BƯỚC 1 / 7  —  File APK đầu vào")

    while True:
        input_apk = get_user_input("Đường dẫn file APK đầu vào")
        if path.exists(input_apk) and path.isfile(input_apk):
            print(_ok(f"  ✓ File hợp lệ: {input_apk}\n"))
            break
        else:
            print(_err(f"  ✗ File không tồn tại hoặc không hợp lệ: '{input_apk}'\n"))

    _section("BƯỚC 2 / 7  —  File APK đầu ra")
    while True:
        out_apk = get_user_input("Đường dẫn file APK đầu ra", default="output.apk")
        if out_apk.lower().endswith(".apk"):
            print(_ok(f"  ✓ Output: {out_apk}\n"))
            break
        else:
            print(_err(f"  ✗ File đầu ra phải có đuôi '.apk' (bạn nhập: '{out_apk}')\n"))

    _section("BƯỚC 3 / 7  —  Obfuscate")
    obfus = get_user_input("Obfuscate string constants? (y/n)", default="n", input_type=bool)

    _section("BƯỚC 4 / 7  —  Filter")
    while True:
        filtercfg = get_user_input("File cấu hình filter", default="filter.txt")
        if path.exists(filtercfg) and path.isfile(filtercfg):
            print(_ok(f"  ✓ Filter: {filtercfg}\n"))
            break
        else:
            print(_err(f"  ✗ File filter không tồn tại: '{filtercfg}'\n"))

    _section("BƯỚC 5 / 7  —  Custom Loader")
    while True:
        custom_loader = get_user_input(
            "Tên class loader (vd: com.abc.Native)",
            default="plongdev.HyperGuardPro.Native"
        )
        if '.' not in custom_loader:
            print(_err(f"  ✗ Loader phải có ít nhất một package (vd: com.abc hoặc com.demo.app)\n"
                       f"  ✗ Bạn không thể nhập chỉ một từ như: '{custom_loader}'\n"))
        else:
            print(_ok(f"  ✓ Loader: {custom_loader}\n"))
            break

    _section("BƯỚC 6 / 7  —  Tùy chọn build")
    skip_synthetic = get_user_input("Bỏ qua synthetic methods? (y/n)", default="n", input_type=bool)
    # Force keep libs and Unified mode are now always enabled
    force_keep_libs = True
    unified_mode = True
    do_compile     = get_user_input("Build native code? (y/n)", default="y", input_type=bool)

    lib_name = None
    change_lib_name = get_user_input("Đổi tên library? (y/n)", default="n", input_type=bool)
    if change_lib_name:
        _section("BƯỚC 7 / 7  —  Tên Library")
        while True:
            lib_name = get_user_input("Tên library mới (không có tiền tố 'lib')", default="stub")
            if not all(c.isalnum() or c in '-_' for c in lib_name):
                print(_err("  ✗ Tên library chỉ được chứa chữ/số, gạch ngang (-), gạch dưới (_)\n"))
                continue
            if lib_name.startswith('lib'):
                print(_err("  ✗ Tên library không được bắt đầu bằng 'lib'\n"))
                continue
            print(_ok(f"  ✓ Library name: {lib_name}\n"))
            break

        android_mk_path = "project/jni/Android.mk"
        try:
            with open(android_mk_path, 'r') as f:
                content = f.read()
            content = re.sub(r'LOCAL_MODULE\s*:=\s*\w+', f'LOCAL_MODULE := {lib_name}', content)
            with open(android_mk_path, 'w') as f:
                f.write(content)
            print(_ok(f"  ✓ Đã đổi tên library thành: {lib_name}\n"))
        except Exception as e:
            print(_err(f"  ✗ Lỗi khi đổi tên library: {e}\n"))

    source_archive = "project-source.zip"
    project_dir = None

    _section("TÓM TẮT CẤU HÌNH")
    rows = [
        ("Input APK",          input_apk),
        ("Output APK",         out_apk),
        ("Obfuscate",          "Có" if obfus else "Không"),
        ("Filter config",      filtercfg),
        ("Custom loader",      custom_loader),
        ("Skip synthetic",     "Có" if skip_synthetic else "Không"),
        ("Force keep libs",    "Bật (Mặc định)"),
        ("Build native code",  "Có" if do_compile else "Không"),
        ("Unified mode",       "Bật (Mặc định)"),
    ]
    if lib_name:
        rows.append(("Library name", lib_name))

    for label, value in rows:
        print(_c(f"  {'·'} {label:<22}") + f"  {value}")

    print()
    confirm = get_user_input("Bắt đầu biên dịch? (y/n)", default="y", input_type=bool)
    if not confirm:
        print(_err("\n  ✗ Đã hủy bỏ.\n"))
        sys.exit(0)

    print(_ok("\n  ▶  Đang bắt đầu quá trình biên dịch...\n"))
    return input_apk, out_apk, obfus, filtercfg, custom_loader, skip_synthetic, force_keep_libs, do_compile, source_archive, project_dir, lib_name, unified_mode


sys.setrecursionlimit(5000)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-a", "--input", nargs="?", help="Input apk file path")
    parser.add_argument("-o", "--out", nargs="?", help="Output apk file path")
    parser.add_argument("-p", "--obfuscate", action="store_true", default=False,
        help="Obfuscate string constants.",
    )
    parser.add_argument(
        "--filter", default="filter.txt", help="Method filters configuration file."
    )
    parser.add_argument(
        "--custom-loader",
        default="plongdev.HyperGuardPro.Native",
        help="Loader class, default: plongdev.HyperGuardPro.Native",
    )
    parser.add_argument(
        "--skip-synthetic",
        action="store_true",
        default=False,
        help="Skip synthetic methods in all classes.",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        default=False,
        help="Do not build the compiled code",
    )
    parser.add_argument(
        "--force-keep-libs",
        action="store_true",
        default=False,
        help="Forcefully keep the lib abis defined in Application.mk, regardless of the abis already available in the apk",
    )
    parser.add_argument("--source-dir", help="The compiled cpp code output directory.")
    parser.add_argument(
        "--project-archive",
        default="project-source.zip",
        help="Converted cpp code, compressed as zip output file.",
    )

    args = vars(parser.parse_args())
    
    if args["input"] is None and args["out"] is None:
        result = interactive_mode()
        input_apk, out_apk, obfus, filtercfg, custom_loader, SKIP_SYNTHETIC_METHODS, IGNORE_APP_LIB_ABIS, do_compile, source_archive, project_dir, lib_name, unified_mode = result
    else:
        input_apk = args["input"]
        out_apk = args["out"]
        obfus = args["obfuscate"]
        filtercfg = args["filter"]
        custom_loader = args["custom_loader"]
        SKIP_SYNTHETIC_METHODS = args["skip_synthetic"]
        IGNORE_APP_LIB_ABIS = True # Force enabled
        do_compile = not args["no_build"]
        source_archive = args["project_archive"]
        lib_name = None  # Not supported in command-line mode yet
        unified_mode = True # Force enabled

        if args["source_dir"]:
            project_dir = args["source_dir"]
        else:
            project_dir = None

    HyperGuard_cfg = {}
    with open("HyperGuard.cfg") as fp:
        HyperGuard_cfg = json.load(fp)

    if "ndk_dir" in HyperGuard_cfg and path.exists(HyperGuard_cfg["ndk_dir"]):
        ndk_dir = HyperGuard_cfg["ndk_dir"]
        if is_windows():
            NDKBUILD = path.join(ndk_dir, "ndk-build.cmd")
        else:
            NDKBUILD = path.join(ndk_dir, "ndk-build")

        if not path.exists(NDKBUILD):
            raise Exception("Invalid ndk_dir path, file not found at " + NDKBUILD)

    if "apktool" in HyperGuard_cfg and path.exists(HyperGuard_cfg["apktool"]):
        APKTOOL = HyperGuard_cfg["apktool"]

    show_logging(level=INFO)

    # n
    create_tmp_directory()

    backup_jni_folder_path = backup_jni_project_folder()

    try:
        HyperGuard_main(
            input_apk,
            obfus,
            filtercfg,
            custom_loader,
            out_apk,
            do_compile,
            project_dir,
            source_archive,
            lib_name,
            num_split_libs=5,
            unified_mode=unified_mode,
        )
        Logger.info(_ok("  ✓ HyperGuard compilation successful!\n"))
       
            
    except Exception as e:
        error_msg = f"Compile {input_apk} failed!\n{str(e)}\n{traceback.format_exc()}"
        Logger.error(error_msg, exc_info=True)

        error_log = save_detailed_error_log(error_msg)
        print(_err(f"\n  ✗ Biên dịch thất bại!"))
        print(_dim(f"  · Chi tiết lỗi: {error_log}\n"))
    finally:
        # n
        restore_jni_project_folder(backup_jni_folder_path)
        clean_tmp_directory()