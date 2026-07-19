"""LLDB bridge for Frida Gadget page-plan requests on jailed iOS 26+.

Load this file from Xcode's LLDB console before continuing the attached app:

    command script import /absolute/path/to/frigad_lldb.py

If the process is already stopped at ``brk #1337``, run this once and continue:

    frigad-page-plan
    continue
"""

import shlex
import struct

import lldb


_MAGIC = 1337
_SUCCESS = 0x1337
_ACTION_RESUME = 1
_ACTION_PAGE_PLAN = 3
_BRK_1337 = struct.pack("<I", 0xD420A720)
_DEFAULT_IOS_PAGE_SIZE = 0x4000
_MAX_PLAN_SIZE = 16 * 1024 * 1024
_MAX_BLOCKS = 1_000_000
_MAX_PAGES = 16_000_000


class PagePlanError(RuntimeError):
    pass


def _register_value(frame, name):
    register = frame.FindRegister(name)
    if not register.IsValid():
        raise PagePlanError("register {} is unavailable".format(name))
    return register.GetValueAsUnsigned()


def _set_register(frame, name, value):
    register = frame.FindRegister(name)
    if not register.IsValid():
        raise PagePlanError("register {} is unavailable".format(name))

    error = lldb.SBError()
    changed = register.SetValueFromCString(hex(value), error)
    if not changed or not error.Success():
        description = error.GetCString() or "unknown LLDB error"
        raise PagePlanError("unable to set {}: {}".format(name, description))


def _read_memory(process, address, size):
    error = lldb.SBError()
    data = process.ReadMemory(address, size, error)
    if not error.Success():
        description = error.GetCString() or "unknown LLDB error"
        raise PagePlanError(
            "unable to read {} bytes at {:#x}: {}".format(
                size, address, description
            )
        )

    if isinstance(data, str):
        data = data.encode("latin-1")
    if len(data) != size:
        raise PagePlanError(
            "short memory read at {:#x}: expected {}, got {}".format(
                address, size, len(data)
            )
        )
    return data


def _write_memory(process, address, data):
    error = lldb.SBError()
    written = process.WriteMemory(address, data, error)
    if not error.Success() or written != len(data):
        description = error.GetCString() or "unknown LLDB error"
        raise PagePlanError(
            "unable to write {} bytes at {:#x}: {} (wrote {})".format(
                len(data), address, description, written
            )
        )


class _PlanReader:
    def __init__(self, data):
        self._data = data
        self._offset = 0

    def _take(self, size):
        end = self._offset + size
        if end > len(self._data):
            raise PagePlanError("truncated page-plan packet")
        value = self._data[self._offset : end]
        self._offset = end
        return value

    def uint32(self):
        return struct.unpack("<I", self._take(4))[0]

    def pointer(self):
        return struct.unpack("<Q", self._take(8))[0]

    def bytes(self, size):
        return self._take(size)

    @property
    def remaining(self):
        return len(self._data) - self._offset


def _apply_page_plan(process, plan_address, plan_size, page_size):
    if plan_size < 4 or plan_size > _MAX_PLAN_SIZE:
        raise PagePlanError("invalid page-plan size: {}".format(plan_size))
    if page_size <= 0 or (page_size & (page_size - 1)) != 0:
        raise PagePlanError("invalid page size: {:#x}".format(page_size))

    reader = _PlanReader(_read_memory(process, plan_address, plan_size))
    block_count = reader.uint32()
    if block_count == 0 or block_count > _MAX_BLOCKS:
        raise PagePlanError("invalid page-plan block count: {}".format(block_count))

    total_pages = 0
    total_writes = 0
    for _ in range(block_count):
        start = reader.pointer()
        page_count = reader.uint32()
        if page_count == 0 or page_count > _MAX_PAGES - total_pages:
            raise PagePlanError("invalid page count: {}".format(page_count))
        if (start & (page_size - 1)) != 0:
            raise PagePlanError(
                "page block is not {:#x}-aligned: {:#x}".format(
                    page_size, start
                )
            )

        page_bytes = reader.bytes(page_count)
        for page_index in range(0, page_count, 2):
            write_count = min(2, page_count - page_index)
            write_address = (
                start + page_index * page_size + page_size - 1
            )
            _write_memory(
                process,
                write_address,
                page_bytes[page_index : page_index + write_count],
            )
            total_writes += 1

        total_pages += page_count

    if reader.remaining != 0:
        raise PagePlanError(
            "page-plan packet has {} trailing bytes".format(reader.remaining)
        )

    return block_count, total_pages, total_writes


def _handle_frida_breakpoint(exe_ctx, page_size):
    process = exe_ctx.GetProcess()
    thread = exe_ctx.GetThread()
    if not process.IsValid() or not thread.IsValid():
        return False, None

    frame = thread.GetFrameAtIndex(0)
    if not frame.IsValid():
        return False, None

    try:
        pc = _register_value(frame, "pc")
        x1 = _register_value(frame, "x1")
        x2 = _register_value(frame, "x2")
        action = _register_value(frame, "x3")
    except PagePlanError:
        return False, None

    if x1 != _MAGIC or x2 != _MAGIC:
        return False, None

    try:
        if _read_memory(process, pc, len(_BRK_1337)) != _BRK_1337:
            return False, None

        if action == _ACTION_PAGE_PLAN:
            plan_size = _register_value(frame, "x4")
            plan_address = _register_value(frame, "x5")
            block_count, page_count, write_count = _apply_page_plan(
                process, plan_address, plan_size, page_size
            )
            _set_register(frame, "x0", _SUCCESS)
            _set_register(frame, "pc", pc + 4)
            return True, (
                "handled Frida page-plan: {} blocks, {} pages, {} writes"
            ).format(block_count, page_count, write_count)

        if action == _ACTION_RESUME:
            _set_register(frame, "pc", pc + 4)
            return True, "handled Frida resume breakpoint"

        return False, "unsupported Frida breakpoint action {}".format(action)
    except PagePlanError as error:
        return False, "Frida page-plan failed: {}".format(error)


class FridaPagePlanStopHook:
    """Automatically services Frida's jailed-iOS debugger page-plan protocol."""

    def __init__(self, target, extra_args):
        del target, extra_args
        self.page_size = _DEFAULT_IOS_PAGE_SIZE

    def handle_stop(self, exe_ctx, stream):
        handled, message = _handle_frida_breakpoint(
            exe_ctx, self.page_size
        )
        if message:
            stream.Print("[FrigadLLDB] {}".format(message))

        # False votes to auto-continue, but only after a recognized request was
        # successfully handled. All normal Xcode breakpoints still stop.
        return not handled


def frigad_page_plan(debugger, command, exe_ctx, result, internal_dict):
    """Handle the current Frida page-plan stop. Optional arg: page size."""
    del debugger, internal_dict

    try:
        arguments = shlex.split(command)
        if len(arguments) > 1:
            raise PagePlanError("usage: frigad-page-plan [page-size]")
        page_size = (
            int(arguments[0], 0)
            if arguments
            else _DEFAULT_IOS_PAGE_SIZE
        )

        handled, message = _handle_frida_breakpoint(exe_ctx, page_size)
        if not handled:
            raise PagePlanError(message or "current stop is not a Frida page-plan")

        result.AppendMessage("[FrigadLLDB] {}".format(message))
        result.AppendMessage("[FrigadLLDB] registers updated; run 'continue'")
    except (PagePlanError, ValueError) as error:
        result.SetError(str(error))


def __lldb_init_module(debugger, internal_dict):
    del internal_dict
    debugger.HandleCommand(
        "command script add -f frigad_lldb.frigad_page_plan "
        "frigad-page-plan"
    )
    debugger.HandleCommand(
        "target stop-hook add -P frigad_lldb.FridaPagePlanStopHook"
    )
    print(
        "[FrigadLLDB] page-plan stop-hook installed "
        "(iOS page size 0x{:x})".format(_DEFAULT_IOS_PAGE_SIZE)
    )
