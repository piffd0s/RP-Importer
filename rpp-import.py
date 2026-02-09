"""
rp++ Gadget Importer Plugin for IDA Pro (HCLI / Plugin Manager compatible)
===========================================================================
Imports rp++ output, annotates IDA with colors/comments, and persists
gadget data inside the IDB via netnodes so you never need to re-import.


Usage:
    - Right-click in disassembly -> "rp++ Gadgets" submenu
    - Edit > Plugins > rp++ Gadget Importer
    - Hotkey: Ctrl+Shift+Z
"""

import json
import re
import ida_bytes
import ida_kernwin
import ida_nalt
import ida_netnode
import ida_idaapi
import idc
import idaapi

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
PLUGIN_NAME    = "rp++ Gadget Importer"
PLUGIN_HOTKEY  = "Ctrl+Shift+Z"
PLUGIN_COMMENT = "Import and annotate rp++ ROP gadgets with color coding"
PLUGIN_VERSION = "1.1.0"

COLOR_RET   = 0xAAFFAA
COLOR_CALL  = 0xAAEEFF
COLOR_JMP   = 0xAAAAFF
COLOR_OTHER = 0xDDDDDD

GADGET_RE = re.compile(
    r'^(0x[0-9a-fA-F]+):\s+(.+?)\s*;\s*\(\d+ found\)\s*$'
)

TAG_PREFIX = "ROP"

# Netnode name for persistent storage in the IDB
NETNODE_NAME = "$ rpp_gadget_importer"

# Blob tags (single ASCII char) — used with getblob/setblob
BLOB_TAG_GADGETS = ord('G')  # gadget data (arbitrary size)
BLOB_TAG_META    = ord('M')  # meta JSON (small)

# --------------------------------------------------------------------------
# IDB persistence via netnodes — blob storage
#
# supvals are limited to MAXSPECSIZE (~1024 bytes), so we use the
# blob API (setblob/getblob) which supports arbitrary sizes.
# --------------------------------------------------------------------------

def _get_node():
    """Get or create our netnode."""
    return ida_netnode.netnode(NETNODE_NAME, 0, True)


def save_gadgets_to_idb(gadgets, base_delta):
    """Persist gadgets into the IDB using blob storage."""
    node = _get_node()

    # Serialize gadgets
    payload = json.dumps([[a, d] for a, d in gadgets]).encode("utf-8")

    # Store gadgets as a blob (no size limit)
    node.setblob(payload, 0, BLOB_TAG_GADGETS)

    # Store meta as a separate small blob
    meta = json.dumps({
        "version": PLUGIN_VERSION,
        "count": len(gadgets),
        "base_delta": base_delta,
    }).encode("utf-8")
    node.setblob(meta, 0, BLOB_TAG_META)

    print("[rp++] Saved {} gadgets to IDB ({:.1f} MB)"
          .format(len(gadgets), len(payload) / (1024 * 1024)))


def load_gadgets_from_idb():
    """Load persisted gadgets from the IDB. Returns (gadgets, base_delta) or (None, None)."""
    node = ida_netnode.netnode(NETNODE_NAME, 0, False)
    if node == ida_netnode.BADNODE:
        return None, None

    # Read meta blob
    raw_meta = node.getblob(0, BLOB_TAG_META)
    if not raw_meta:
        return None, None

    try:
        meta = json.loads(raw_meta.decode("utf-8").rstrip('\x00'))
    except (json.JSONDecodeError, ValueError) as e:
        print("[rp++] Failed to read meta from IDB: {}".format(e))
        return None, None

    base_delta = meta.get("base_delta", 0)

    # Read gadgets blob
    raw_gadgets = node.getblob(0, BLOB_TAG_GADGETS)
    if not raw_gadgets:
        print("[rp++] No gadget data blob found in IDB")
        return None, None

    try:
        gadgets = [(a, d) for a, d in json.loads(raw_gadgets.decode("utf-8").rstrip('\x00'))]
        return gadgets, base_delta
    except (json.JSONDecodeError, ValueError) as e:
        print("[rp++] Failed to parse gadgets from IDB: {}".format(e))
        return None, None


def delete_gadgets_from_idb():
    """Remove persisted gadget data from the IDB."""
    node = ida_netnode.netnode(NETNODE_NAME, 0, False)
    if node != ida_netnode.BADNODE:
        node.delblob(0, BLOB_TAG_GADGETS)
        node.delblob(0, BLOB_TAG_META)
        print("[rp++] Cleared gadget data from IDB")


def has_saved_gadgets():
    """Check if we have gadgets stored in the IDB."""
    node = ida_netnode.netnode(NETNODE_NAME, 0, False)
    if node == ida_netnode.BADNODE:
        return False
    return bool(node.getblob(0, BLOB_TAG_META))


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


def clear_gadget_annotations(gadgets, base_delta=0):
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
# Shared runtime state
# --------------------------------------------------------------------------
class _GadgetState:
    gadgets = []
    base_delta = 0
    loaded = False

_state = _GadgetState()


def _load_state_from_idb():
    """Try to restore runtime state from IDB on plugin init."""
    gadgets, delta = load_gadgets_from_idb()
    if gadgets:
        _state.gadgets = gadgets
        _state.base_delta = delta
        _state.loaded = True
        return True
    return False


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

    # Apply visual annotations
    counts = apply_gadgets(gadgets, base_delta)

    # Update runtime state
    _state.gadgets = gadgets
    _state.base_delta = base_delta
    _state.loaded = True

    # Persist to IDB
    save_gadgets_to_idb(gadgets, base_delta)

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


def reapply_colors():
    """Re-apply colors/comments from IDB-stored gadgets (e.g. after reopening)."""
    if not _state.loaded:
        if not _load_state_from_idb():
            ida_kernwin.info("No gadgets stored in this IDB.")
            return
    counts = apply_gadgets(_state.gadgets, _state.base_delta)
    summary = "Re-applied from IDB:\n" + format_summary(len(_state.gadgets), counts)
    print("[rp++] " + summary)
    ida_kernwin.info(summary)


def clear_current():
    if not _state.loaded:
        if not _load_state_from_idb():
            ida_kernwin.info("No gadgets to clear.")
            return

    choice = ida_kernwin.ask_buttons(
        "Annotations Only", "Annotations + IDB Data", "Cancel", 1,
        "What to clear?\n\n"
        "• Annotations Only: remove colors/comments, keep data in IDB\n"
        "• Annotations + IDB Data: remove everything, next time\n"
        "  you open this IDB the gadgets will be gone")
    if choice == 0:
        return

    clear_gadget_annotations(_state.gadgets, _state.base_delta)
    n = len(_state.gadgets)

    if choice == -1:  # full clear
        delete_gadgets_from_idb()
        _state.gadgets = []
        _state.loaded = False
        print("[rp++] Cleared {} annotations + IDB data".format(n))
        ida_kernwin.info("Cleared {} annotations and removed data from IDB.".format(n))
    else:
        print("[rp++] Cleared {} annotations (data kept in IDB)".format(n))
        ida_kernwin.info("Cleared {} annotations.\nData is still in the IDB — "
                         "use 'Re-apply Colors' to restore.".format(n))


def jump_to_gadget():
    if not _state.loaded:
        if not _load_state_from_idb():
            ida_kernwin.info("No gadgets in this IDB. Import first.")
            return
    GadgetChooser(_state.gadgets, _state.base_delta).Show()


def show_idb_info():
    """Show info about what's stored in the current IDB."""
    gadgets, delta = load_gadgets_from_idb()
    if not gadgets:
        ida_kernwin.info("No rp++ gadgets stored in this IDB.")
        return

    types = {"ret": 0, "call": 0, "jmp": 0, "other": 0}
    for _, d in gadgets:
        types[classify_gadget(d)] += 1

    msg = (
        "rp++ data stored in IDB:\n\n"
        "  Total gadgets: {}\n"
        "  Base delta:    0x{:X}\n\n"
        "  RET:   {}\n"
        "  CALL:  {}\n"
        "  JMP:   {}\n"
        "  OTHER: {}"
    ).format(len(gadgets), delta,
             types["ret"], types["call"], types["jmp"], types["other"])
    ida_kernwin.info(msg)


# --------------------------------------------------------------------------
# Chooser
# --------------------------------------------------------------------------

class GadgetChooser(ida_kernwin.Choose):
    def __init__(self, gadgets, base_delta):
        super().__init__(
            "rp++ Gadgets ({} loaded)".format(len(gadgets)),
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

class ReapplyAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        reapply_colors()
        return 1
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class InfoAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        show_idb_info()
        return 1
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

# Action IDs
ACT_FILE    = "rpp:import_file"
ACT_PASTE   = "rpp:import_paste"
ACT_CLEAR   = "rpp:clear"
ACT_JUMP    = "rpp:jump"
ACT_REAPPLY = "rpp:reapply"
ACT_INFO    = "rpp:info"

ACTIONS = [
    (ACT_FILE,    "rp++ Import from File",         ImportFileAction(),  "Ctrl+Shift+Z"),
    (ACT_PASTE,   "rp++ Import from Clipboard",    ImportPasteAction(), None),
    (ACT_JUMP,    "rp++ Browse Gadgets",            JumpAction(),       None),
    (ACT_REAPPLY, "rp++ Re-apply Colors from IDB",  ReapplyAction(),    None),
    (ACT_CLEAR,   "rp++ Clear Gadget Markings",     ClearAction(),      None),
    (ACT_INFO,    "rp++ IDB Storage Info",           InfoAction(),       None),
]

# --------------------------------------------------------------------------
# UI hooks
# --------------------------------------------------------------------------

class RPPUIHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        wtype = ida_kernwin.get_widget_type(widget)
        if wtype in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
            ida_kernwin.attach_action_to_popup(widget, popup, "-", None)
            for act_id, _, _, _ in ACTIONS:
                ida_kernwin.attach_action_to_popup(
                    widget, popup, act_id, "rp++ Gadgets/")


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

        # Auto-load from IDB if available
        if _load_state_from_idb():
            print("[rp++] Plugin v{} loaded. Restored {} gadgets from IDB."
                  .format(PLUGIN_VERSION, len(_state.gadgets)))
        else:
            print("[rp++] Plugin v{} loaded. No saved gadgets in this IDB."
                  .format(PLUGIN_VERSION))

        print("[rp++] Right-click -> 'rp++ Gadgets' or {}".format(PLUGIN_HOTKEY))
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
