#!/usr/bin/env python3
"""
Don't get pwned
"""

import os, sys, math, json, hashlib, struct, argparse, glob
from pathlib import Path
from datetime import datetime

SUPPORTS_COLOR = sys.stdout.isatty() or os.environ.get("FORCE_COLOR")

def c(code, text):
    return f"\033[{code}m{text}\033[0m" if SUPPORTS_COLOR else text

def RED(t):     return c("1;31", t)
def YELLOW(t):  return c("33",   t)
def GREEN(t):   return c("32",   t)
def CYAN(t):    return c("36",   t)
def BOLD(t):    return c("1",    t)
def DIM(t):     return c("2",    t)

SEV_COLOR = {
    "CRITICAL": RED,
    "HIGH":     lambda t: c("31", t),
    "MEDIUM":   YELLOW,
    "LOW":      CYAN,
    "INFO":     DIM,
}

# ── Threat data ───────────────────────────────────────────────
#feel free to add more 
KNOWN_BAD_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR test file",
    "e45d2c22d2fe5ec75f0ca1a2b57a81be": "CobaltStrike beacon DLL",
}

SUSPICIOUS_EXPORTS = {
    "ReflectiveLoader", "DllInstall", "XorEncrypt", "InjectCode",
    "shellcode", "RunPE", "LoadShellcode",
}

SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtUnmapViewOfSection", "SetWindowsHookEx", "GetAsyncKeyState",
    "URLDownloadToFile", "RegSetValueEx", "CreateServiceA",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "ShellExecuteEx",
}

IMPORT_THRESHOLD = 3

class PEParser:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        self.is_valid_pe = False
        self.is_dll = False
        self.timestamp = None
        self.sections = []
        self.imports = []
        self.exports = []
        self.warnings = []
        self._parse()

    def _u16(self, o): return struct.unpack_from("<H", self.data, o)[0]
    def _u32(self, o): return struct.unpack_from("<I", self.data, o)[0]

    def _parse(self):
        if len(self.data) < 64 or self.data[:2] != b"MZ":
            self.warnings.append("Not a valid MZ/PE file"); return
        pe_off = self._u32(0x3C)
        if pe_off + 4 > len(self.data) or self.data[pe_off:pe_off+4] != b"PE\x00\x00":
            self.warnings.append("PE signature not found"); return
        self.is_valid_pe = True
        coff = pe_off + 4
        num_sec        = self._u16(coff + 2)
        self.timestamp = self._u32(coff + 4)
        opt_size       = self._u16(coff + 16)
        chars          = self._u16(coff + 18)
        self.is_dll    = bool(chars & 0x2000)
        opt_off        = coff + 20
        if opt_size < 2: return
        magic = self._u16(opt_off)
        if   magic == 0x10B: dd_off = opt_off + 96
        elif magic == 0x20B: dd_off = opt_off + 112
        else: self.warnings.append(f"Unknown PE magic {hex(magic)}"); return
        sec_off = opt_off + opt_size
        for i in range(num_sec):
            s = sec_off + i * 40
            if s + 40 > len(self.data): break
            name     = self.data[s:s+8].rstrip(b"\x00").decode("ascii", errors="replace")
            raw_off  = self._u32(s + 20)
            raw_size = self._u32(s + 16)
            chars_s  = self._u32(s + 36)
            sec_data = self.data[raw_off:raw_off+raw_size] if raw_off else b""
            self.sections.append({
                "name": name, "raw_size": raw_size,
                "entropy": _entropy(sec_data),
                "exec": bool(chars_s & 0x20000000),
                "write": bool(chars_s & 0x80000000),
            })
        if dd_off + 8 <= len(self.data):
            self._parse_imports(self._u32(dd_off + 8), opt_off, magic)
            self._parse_exports(self._u32(dd_off),     opt_off, magic)

    def _rva(self, rva):
        pe_off  = self._u32(0x3C)
        coff    = pe_off + 4
        opt_sz  = self._u16(coff + 16)
        num_sec = self._u16(coff + 2)
        sb      = coff + 20 + opt_sz
        for i in range(num_sec):
            s   = sb + i * 40
            va  = self._u32(s + 12)
            vsz = self._u32(s + 8)
            ro  = self._u32(s + 20)
            rsz = self._u32(s + 16)
            if va <= rva < va + max(vsz, rsz):
                return ro + (rva - va)
        return None

    def _str(self, off, n=256):
        end = self.data.find(b"\x00", off, off + n)
        return self.data[off:end if end != -1 else off+n].decode("ascii", errors="replace")

    def _parse_imports(self, rva, opt_off, magic):
        if not rva: return
        off = self._rva(rva)
        if off is None: return
        while off + 20 <= len(self.data):
            lrva = self._u32(off); nrva = self._u32(off + 12)
            if lrva == 0 and nrva == 0: break
            to = self._rva(lrva) if lrva else None
            esz = 8 if magic == 0x20B else 4
            while to and to + esz <= len(self.data):
                th = struct.unpack_from("<Q", self.data, to)[0] if esz == 8 else self._u32(to)
                if th == 0: break
                oflag = (1 << 63) if esz == 8 else (1 << 31)
                if not (th & oflag):
                    ho = self._rva(th & 0x7FFFFFFFFFFFFFFF)
                    if ho and ho + 2 < len(self.data):
                        self.imports.append(self._str(ho + 2))
                to += esz
            off += 20

    def _parse_exports(self, rva, opt_off, magic):
        if not rva: return
        off = self._rva(rva)
        if off is None or off + 40 > len(self.data): return
        num  = self._u32(off + 24)
        nrva = self._u32(off + 32)
        noff = self._rva(nrva)
        if not noff: return
        for i in range(min(num, 1000)):
            po = noff + i * 4
            if po + 4 > len(self.data): break
            fo = self._rva(self._u32(po))
            if fo: self.exports.append(self._str(fo))

def _entropy(data):
    if not data: return 0.0
    freq = [0] * 256
    for b in data: freq[b] += 1
    n = len(data)
    return round(-sum((f/n)*math.log2(f/n) for f in freq if f), 3)

def _md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
    return h.hexdigest()

def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
    return h.hexdigest()

WEIGHTS = {"CRITICAL": 100, "HIGH": 25, "MEDIUM": 10, "LOW": 3}

def analyze(path):
    flags = []
    result = {"file": path, "md5": None, "sha256": None,
              "is_pe": False, "is_dll": False, "timestamp": None,
              "sections": [], "imports": 0, "exports": 0,
              "flags": [], "score": 0}

    if not os.path.isfile(path):
        result["flags"] = [("INFO", "File not found")]
        return result

    result["md5"]    = _md5(path)
    result["sha256"] = _sha256(path)

    if result["md5"] in KNOWN_BAD_HASHES:
        flags.append(("CRITICAL", f"Known malicious hash — {KNOWN_BAD_HASHES[result['md5']]}"))

    pe = PEParser(path)
    result.update(is_pe=pe.is_valid_pe, is_dll=pe.is_dll,
                  timestamp=pe.timestamp, sections=pe.sections,
                  imports=len(pe.imports), exports=len(pe.exports))

    if not pe.is_valid_pe:
        result["flags"] = [("INFO", w) for w in pe.warnings] or [("INFO", "Not a valid PE file")]
        return result

    ts = pe.timestamp or 0
    if ts == 0:
        flags.append(("LOW", "Compile timestamp is zeroed (common in packed/stripped malware)"))
    elif ts > int(datetime.now().timestamp()):
        flags.append(("MEDIUM", f"Timestamp is in the future: {datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d')}"))

    for s in pe.sections:
        if s["entropy"] > 7.0:
            flags.append(("HIGH",   f"Section '{s['name']}' entropy={s['entropy']} — likely packed/encrypted"))
        elif s["entropy"] > 6.5:
            flags.append(("MEDIUM", f"Section '{s['name']}' entropy={s['entropy']} — elevated"))
        if s["exec"] and s["write"]:
            flags.append(("HIGH",   f"Section '{s['name']}' is writable AND executable — shellcode risk"))

    bad_imp = [fn for fn in pe.imports if fn in SUSPICIOUS_IMPORTS]
    if len(bad_imp) >= IMPORT_THRESHOLD:
        flags.append(("HIGH",   f"Suspicious import cluster ({len(bad_imp)}): {', '.join(bad_imp)}"))
    elif bad_imp:
        flags.append(("MEDIUM", f"Suspicious imports: {', '.join(bad_imp)}"))

    for ex in pe.exports:
        if ex in SUSPICIOUS_EXPORTS:
            flags.append(("HIGH", f"Suspicious export: '{ex}'"))

    if Path(path).suffix.lower() == ".dll" and not pe.is_dll:
        flags.append(("MEDIUM", "File has .dll extension but PE DLL flag is not set"))

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    result["flags"] = sorted(flags, key=lambda x: sev_order.get(x[0], 9))
    result["score"] = sum(WEIGHTS.get(s, 0) for s, _ in flags)
    return result

def verdict_label(score):
    if score == 0:   return GREEN("✔  CLEAN"),    "No suspicious indicators found."
    if score < 10:   return CYAN("ℹ  LOW RISK"),  "Minor anomalies — probably fine."
    if score < 25:   return YELLOW("⚠  SUSPICIOUS"), "Multiple concerns — review carefully."
    if score < 100:  return c("31","⚠  HIGH RISK"), "Strong malware indicators present."
    return RED("✘  CRITICAL"), "Known malicious or extremely suspicious!"

def entropy_bar(val):
    filled = int(val / 8 * 16)
    bar = "█" * filled + "░" * (16 - filled)
    if val > 7.0: return RED(bar)
    if val > 6.5: return YELLOW(bar)
    return DIM(bar)

def print_result(r, verbose=False):
    W = 64
    print("\n" + "─" * W)
    print(f"  {BOLD(Path(r['file']).name)}")
    print(f"  {DIM(r['file'])}")
    print()

    vl, vm = verdict_label(r["score"])
    score_str = f"score={r['score']}"
    print(f"  Verdict   {vl}  {DIM(score_str)}")
    print(f"            {DIM(vm)}")
    print()
    print(f"  MD5       {DIM(r['md5'] or 'N/A')}")
    print(f"  SHA-256   {DIM(r['sha256'] or 'N/A')}")

    if r["is_pe"]:
        ts = r["timestamp"]
        ts_str = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M UTC") if ts else "N/A"
        print(f"  Type      {'DLL' if r['is_dll'] else 'EXE/other'}")
        print(f"  Compiled  {ts_str}")
        print(f"  Imports   {r['imports']}   Exports {r['exports']}")

    if r["flags"]:
        print(f"\n  Findings:")
        for sev, msg in r["flags"]:
            col = SEV_COLOR.get(sev, DIM)
            tag = col(f"[{sev}]".ljust(10))
            print(f"    {tag} {msg}")
    else:
        print(f"\n  {GREEN('No issues found.')}")

    if verbose and r.get("sections"):
        print(f"\n  Sections:")
        for s in r["sections"]:
            wx = RED(" W+X!") if s["exec"] and s["write"] else ""
            print(f"    {s['name']:<12} {entropy_bar(s['entropy'])} {s['entropy']}{wx}")

    print("─" * W)

def collect_dlls(path, recursive=False):
    p = Path(path)
    if p.is_file(): return [str(p)]
    if p.is_dir():
        pattern = "**/*.dll" if recursive else "*.dll"
        return sorted(str(f) for f in p.glob(pattern))
    matches = glob.glob(path, recursive=recursive)
    return sorted(matches)
  
def ask(prompt, default=None):
    hint = f" [{default}]" if default else ""
    try:
        val = input(f"  {CYAN('?')} {prompt}{hint}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); sys.exit(0)
    return val if val else default

def choose(prompt, options):
    print(f"\n  {BOLD(prompt)}")
    for i, (label, _) in enumerate(options, 1):
        print(f"    {CYAN(str(i))}.  {label}")
    while True:
        try:
            raw = input(f"\n  {CYAN('>')} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); sys.exit(0)
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1][1]
        print(f"  {YELLOW(f'Please enter 1–{len(options)}')}")

def banner():
    print(BOLD("""
  ╔══════════════════════════════════════╗
  ║      DLL  SECURITY  CHECKER  v1     ║
  ╚══════════════════════════════════════╝"""))
    print(DIM("  Scans DLL files for malware indicators"))
    print(DIM("  No installs needed — pure Python 3\n"))


def interactive_mode():
    banner()

    mode = choose("What do you want to scan?", [
        ("A single DLL file",                       "file"),
        ("All DLLs in a folder  (not recursive)",   "folder"),
        ("All DLLs in a folder  (recursive)",       "recursive"),
    ])

    if mode == "file":
        path = ask("Path to the DLL")
        if not path: print(RED("  No path given.")); return
        targets   = [path]
        recursive = False
    else:
        path = ask("Folder path", default=".")
        targets   = [path or "."]
        recursive = (mode == "recursive")

    verbose = choose("Show PE section entropy details?", [
        ("No  — just show the findings",  False),
        ("Yes — show all PE sections",    True),
    ])

    save = choose("Save results to a JSON file?", [
        ("No",   None),
        ("Yes",  "yes"),
    ])
    out_file = None
    if save:
        out_file = ask("Output filename", default="dll_report.json")

    # Collect + scan
    files = []
    for t in targets:
        files += collect_dlls(t, recursive)

    if not files:
        print(RED(f"\n  No DLL files found in: {targets[0]}")); return

    print(f"\n  {BOLD(str(len(files)))} file(s) found. Scanning...\n")

    results = []
    for i, f in enumerate(files, 1):
        label = Path(f).name[:45]
        print(f"  [{i:>3}/{len(files)}] {DIM(label):<46}", end="\r", flush=True)
        results.append(analyze(f))

    print(" " * 60, end="\r")  # clear progress line

    for r in results:
        print_result(r, verbose=verbose)

    # Summary table
    crit  = sum(1 for r in results if r["score"] >= 100)
    high  = sum(1 for r in results if 25 <= r["score"] < 100)
    med   = sum(1 for r in results if 10 <= r["score"] < 25)
    low   = sum(1 for r in results if 0 < r["score"] < 10)
    clean = sum(1 for r in results if r["score"] == 0)

    print(f"\n  {BOLD('═══ SUMMARY ═══')}")
    print(f"  Scanned   {len(results)}")
    if crit:  print(f"  {RED('Critical')}  {crit}")
    if high:  print(f"  {c('31','High')}      {high}")
    if med:   print(f"  {YELLOW('Medium')}    {med}")
    if low:   print(f"  {CYAN('Low')}       {low}")
    print(f"  {GREEN('Clean')}     {clean}")

    # Worst offenders
    bad = [r for r in results if r["score"] > 0]
    bad.sort(key=lambda x: -x["score"])
    if bad:
        print(f"\n  {BOLD('Top findings:')}")
        for r in bad[:5]:
            vl, _ = verdict_label(r["score"])
            print(f"    {vl}  {Path(r['file']).name}")

    if out_file:
        export = []
        for r in results:
            e = dict(r); e.pop("sections", None)
            e["flags"] = [{"severity": s, "message": m} for s, m in r["flags"]]
            export.append(e)
        with open(out_file, "w") as jf:
            json.dump(export, jf, indent=2)
        print(f"\n  {GREEN('✔')} Report saved → {BOLD(out_file)}")

    print()

def cli_mode():
    p = argparse.ArgumentParser(
        prog="dll_checker",
        description="DLL Security Checker — run with no args for interactive mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dll_checker.py                        # interactive menu
  python dll_checker.py suspicious.dll         # scan one file
  python dll_checker.py C:\\Temp -r            # recursive folder scan
  python dll_checker.py C:\\Temp -r --json -o report.json
  python dll_checker.py C:\\Temp --min-score 25 -v
        """
    )
    p.add_argument("targets",      nargs="*",    help="Files or folders (omit for interactive)")
    p.add_argument("-r","--recursive", action="store_true")
    p.add_argument("-v","--verbose",   action="store_true")
    p.add_argument("--min-score",  type=int, default=0, metavar="N",
                   help="Only report files with risk score >= N")
    p.add_argument("--json",       action="store_true", help="Print JSON output")
    p.add_argument("-o","--output",default=None, metavar="FILE", help="Save JSON to file")
    args = p.parse_args()

    if not args.targets:
        interactive_mode(); return

    files = []
    for t in args.targets:
        files += collect_dlls(t, args.recursive)

    if not files:
        print(RED("No DLL files found.")); sys.exit(1)

    print(f"Scanning {len(files)} file(s)...\n")
    results = []
    for f in files:
        r = analyze(f)
        if r["score"] >= args.min_score:
            results.append(r)
            if not args.json: print_result(r, verbose=args.verbose)

    if args.json or args.output:
        export = []
        for r in results:
            e = dict(r); e.pop("sections", None)
            e["flags"] = [{"severity": s, "message": m} for s, m in r["flags"]]
            export.append(e)
        out = json.dumps(export, indent=2)
        if args.output:
            with open(args.output, "w") as jf: jf.write(out)
            print(GREEN(f"Saved → {args.output}"))
        else:
            print(out)
        return

    crit  = sum(1 for r in results if r["score"] >= 100)
    high  = sum(1 for r in results if 25 <= r["score"] < 100)
    clean = sum(1 for r in results if r["score"] == 0)
    print(f"\nSummary: {len(results)} scanned | "
          f"{RED(str(crit))} critical | {c('31',str(high))} high | {GREEN(str(clean))} clean")

if __name__ == "__main__":
    try:
        cli_mode()
    except KeyboardInterrupt:
        print(f"\n{YELLOW('Cancelled.')}"); sys.exit(0)
