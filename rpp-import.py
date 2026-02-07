"""
rp++ Gadget Importer Plugin for IDA Pro (HCLI / Plugin Manager compatible)
===========================================================================


Install via HCLI:
    hcli plugin install rpp-gadget-importer

Manual install:
    Copy this folder to $IDAUSR/plugins/rpp-gadget-importer/

Usage:
    - Right-click in disassembly -> "rp++ Gadgets" submenu
    - Edit > Plugins > rp++ Gadget Importer
    - Hotkey: Ctrl+Shift+Z
"""

import re
import ida_bytes
import ida_kernwin
import ida_nalt
import ida_idaapi
import idc
import idaapi

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
PLUGIN_NAME    = "rp++ Gadget Importer"
PLUGIN_HOTKEY  = "Ctrl+Shift+Z"
PLUGIN_COMMENT = "Import and annotate rp++ ROP gadgets with color coding"
PLUGIN_VERSION = "1.0.0"

COLOR_RET   = 0xAAFFAA  # green
COLOR_CALL  = 0xAAEEFF  # yellow/orange
COLOR_JMP   = 0xAAAAFF  # red
COLOR_OTHER = 0xDDDDDD  # grey

GADGET_RE = re.compile(
    r'^(0x[0-9a-fA-F]+):\s+(.+?)\s*;\s*\(\d+ found\)\s*$'
)

TAG_PREFIX = "ROP"

# --------------------------------------------------------------------------
# Core logic
# --------------------------------------------------------------------------

def classify_gadget(disasm):
    parts = [p.strip() for p in disasm.split(';') if p.strip()]
    if not parts:
        return "other"
    last = parts[-1].lower()
    if last.startswith("ret"):
        return "ret"
    elif last.startswith("call"):
        return "call"
    elif last.startswith("jmp"):
        return "jmp"
    return "other"


def color_for_type(gtype):
    return {"ret": COLOR_RET, "call": COLOR_CALL, "jmp": COLOR_JMP}.get(gtype, COLOR_OTHER)


def parse_rpp_output(text):
    gadgets = []
    for line in text.splitlines():
        m = GADGET_RE.match(line.strip())
        if m:
            gadgets.append((int(m.group(1), 16), m.group(2).strip()))
    return gadgets


def apply_gadgets(gadgets, base_delta=0):
    counts = {"ret": 0, "call": 0, "jmp": 0, "other": 0}
    for addr, disasm in gadgets:
        ea = addr + base_delta
        gtype = classify_gadget(disasm)
        counts[gtype] += 1
        idc.set_color(ea, idc.CIC_ITEM, color_for_type(gtype))
        tag = "[{}-{}]".format(TAG_PREFIX, gtype.upper())
        comment = "{} {}".format(tag, disasm)
        existing = idc.get_cmt(ea, 1) or ""
        if existing and tag not in existing:
            comment = existing + "\n" + comment
        idc.set_cmt(ea, comment, 1)
    return counts


def clear_gadgets(gadgets, base_delta=0):
    for addr, disasm in gadgets:
        ea = addr + base_delta
        idc.set_color(ea, idc.CIC_ITEM, 0xFFFFFFFF)
        existing = idc.get_cmt(ea, 1) or ""
        lines = [l for l in existing.splitlines()
                 if not l.strip().startswith("[{}-".format(TAG_PREFIX))]
        idc.set_cmt(ea, "\n".join(lines) if lines else "", 1)


def ask_base_delta():
    s = ida_kernwin.ask_str("0", 0,
        "Base delta (hex, e.g. 0x1000 or -0x1000).\n"
        "Use 0 if rp++ base matches IDA imagebase.")
    if not s:
        return 0
    try:
        s = s.strip()
        neg = s.startswith("-")
        if neg:
            s = s[1:]
        val = int(s, 16) if "x" in s.lower() else int(s, 0)
        return -val if neg else val
    except ValueError:
        return 0


def format_summary(total, counts):
    return (
        "Applied {} gadgets:\n"
        "  Green  (RET):  {}\n"
        "  Yellow (CALL): {}\n"
        "  Red    (JMP):  {}\n"
        "  Grey   (OTHER): {}"
    ).format(total, counts["ret"], counts["call"], counts["jmp"], counts["other"])


# --------------------------------------------------------------------------
# Shared state
# --------------------------------------------------------------------------
class _GadgetState:
    gadgets = []
    base_delta = 0
    loaded = False

_state = _GadgetState()

# --------------------------------------------------------------------------
# Import workflows
# --------------------------------------------------------------------------

def _do_import(text):
    gadgets = parse_rpp_output(text)
    if not gadgets:
        ida_kernwin.warning("No gadgets found.\nExpected format:\n"
                            "0x<addr>: instr ; instr ; ... ; (N found)")
        return

    print("[rp++] Parsed {} gadgets".format(len(gadgets)))
    base_delta = ask_base_delta()

    filt = ida_kernwin.ask_buttons(
        "All", "RET only", "Cancel", 1,
        "Import which gadget types? ({} total)".format(len(gadgets)))
    if filt == 0:
        return
    if filt == -1:
        gadgets = [(a, d) for a, d in gadgets if classify_gadget(d) == "ret"]
        print("[rp++] Filtered to {} RET gadgets".format(len(gadgets)))

    counts = apply_gadgets(gadgets, base_delta)
    _state.gadgets = gadgets
    _state.base_delta = base_delta
    _state.loaded = True

    summary = format_summary(len(gadgets), counts)
    print("[rp++] " + summary)
    ida_kernwin.info(summary)


def import_from_file():
    path = ida_kernwin.ask_file(0, "*.txt", "Select rp++ output file")
    if not path:
        return
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        _do_import(f.read())


def import_from_clipboard():
    text = ida_kernwin.ask_text(0, "", "Paste rp++ output:")
    if text:
        _do_import(text)


def clear_current():
    if not _state.loaded:
        ida_kernwin.info("No gadgets currently loaded.")
        return
    clear_gadgets(_state.gadgets, _state.base_delta)
    n = len(_state.gadgets)
    _state.gadgets = []
    _state.loaded = False
    print("[rp++] Cleared {} gadgets".format(n))
    ida_kernwin.info("Cleared {} gadget annotations.".format(n))


def jump_to_gadget():
    if not _state.loaded or not _state.gadgets:
        ida_kernwin.info("No gadgets loaded. Import first.")
        return
    GadgetChooser(_state.gadgets, _state.base_delta).Show()


# --------------------------------------------------------------------------
# Chooser
# --------------------------------------------------------------------------

class GadgetChooser(ida_kernwin.Choose):
    def __init__(self, gadgets, base_delta):
        super().__init__(
            "rp++ Gadgets",
            [["Address", 18], ["Type", 6], ["Gadget", 70]],
            flags=ida_kernwin.Choose.CH_MODAL
        )
        self.items = []
        for addr, disasm in gadgets:
            ea = addr + base_delta
            gtype = classify_gadget(disasm).upper()
            self.items.append(("0x{:016X}".format(ea), gtype, disasm, ea))

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return [self.items[n][0], self.items[n][1], self.items[n][2]]

    def OnSelectLine(self, n):
        idc.jumpto(self.items[n][3])
        return (ida_kernwin.Choose.NOTHING_CHANGED, )


# --------------------------------------------------------------------------
# Action handlers
# --------------------------------------------------------------------------

class ImportFileAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        import_from_file()
        return 1
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ImportPasteAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        import_from_clipboard()
        return 1
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ClearAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        clear_current()
        return 1
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class JumpAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        jump_to_gadget()
        return 1
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

# Action IDs
ACT_FILE  = "rpp:import_file"
ACT_PASTE = "rpp:import_paste"
ACT_CLEAR = "rpp:clear"
ACT_JUMP  = "rpp:jump"

ACTIONS = [
    (ACT_FILE,  "rp++ Import from File",      ImportFileAction(), "Ctrl+Shift+R"),
    (ACT_PASTE, "rp++ Import from Clipboard",  ImportPasteAction(), None),
    (ACT_CLEAR, "rp++ Clear Gadget Markings",  ClearAction(), None),
    (ACT_JUMP,  "rp++ Browse Gadgets",         JumpAction(), None),
]

# --------------------------------------------------------------------------
# UI hooks — inject into right-click context menu
# --------------------------------------------------------------------------

class RPPUIHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        wtype = ida_kernwin.get_widget_type(widget)
        if wtype in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
            ida_kernwin.attach_action_to_popup(widget, popup, "-", None)
            ida_kernwin.attach_action_to_popup(widget, popup, ACT_FILE,
                "rp++ Gadgets/")
            ida_kernwin.attach_action_to_popup(widget, popup, ACT_PASTE,
                "rp++ Gadgets/")
            ida_kernwin.attach_action_to_popup(widget, popup, ACT_JUMP,
                "rp++ Gadgets/")
            ida_kernwin.attach_action_to_popup(widget, popup, ACT_CLEAR,
                "rp++ Gadgets/")


# --------------------------------------------------------------------------
# Plugin class
# --------------------------------------------------------------------------

class RPPGadgetPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = PLUGIN_COMMENT
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        for act_id, label, handler, hotkey in ACTIONS:
            desc = ida_kernwin.action_desc_t(act_id, label, handler, hotkey)
            ida_kernwin.register_action(desc)

        for act_id, _, _, _ in ACTIONS:
            ida_kernwin.attach_action_to_menu(
                "Edit/Plugins/", act_id, ida_kernwin.SETMENU_APP)

        self.hooks = RPPUIHooks()
        self.hooks.hook()

        print("[rp++] Plugin v{} loaded. Right-click -> 'rp++ Gadgets' or {}"
              .format(PLUGIN_VERSION, PLUGIN_HOTKEY))
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        import_from_file()

    def term(self):
        self.hooks.unhook()
        for act_id, _, _, _ in ACTIONS:
            ida_kernwin.unregister_action(act_id)
        print("[rp++] Plugin unloaded.")


def PLUGIN_ENTRY():
    return RPPGadgetPlugin()
