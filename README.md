# Bad_DLL_Detector

# DLL Security Checker v2

A simple DLL scanning utility that helps identify potentially suspicious or insecure DLL files.

---

## Usage

### Interactive Mode

Run the tool without any arguments:

```bash
python dll_checker.py
```

The program launches an interactive menu and guides you through the scan process step by step—no command-line flags to memorize.

```text
╔══════════════════════════════════════╗
║      DLL SECURITY CHECKER v2        ║
╚══════════════════════════════════════╝

What do you want to scan?
  1. A single DLL file
  2. All DLLs in a folder (not recursive)
  3. All DLLs in a folder (recursive)

> _
```

---

### Command-Line Mode

You can also run scans directly from the command line.

#### Scan a Single DLL

```bash
python dll_checker.py bad.dll
```

#### Recursively Scan a Directory

```bash
python dll_checker.py C:\Temp -r
```

#### Export Results as JSON

```bash
python dll_checker.py C:\Temp --min-score 25 --json -o out.json
```

---

## Examples

| Command                                            | Description                       |
| -------------------------------------------------- | --------------------------------- |
| `python dll_checker.py`                            | Launch interactive mode           |
| `python dll_checker.py bad.dll`                    | Scan a single DLL                 |
| `python dll_checker.py C:\Temp`                    | Scan all DLLs in a folder         |
| `python dll_checker.py C:\Temp -r`                 | Recursively scan all DLLs         |
| `python dll_checker.py C:\Temp --min-score 25`     | Show only results with score ≥ 25 |
| `python dll_checker.py C:\Temp --json -o out.json` | Export results to JSON            |

---

## Features

* Interactive menu-driven mode
* Single DLL scanning
* Folder scanning
* Recursive folder scanning
* Score-based filtering
* JSON export support
* Simple one-line command usage

