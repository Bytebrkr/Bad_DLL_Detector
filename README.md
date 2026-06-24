# Bad_DLL_Detector

Interactive mode — just run it with no arguments:
python dll_checker.py
It walks you through everything step by step — numbered menus, no flags to memorize:
  ╔══════════════════════════════════════╗
  ║      DLL  SECURITY  CHECKER  v2     ║
  ╚══════════════════════════════════════╝

  What do you want to scan?
    1.  A single DLL file
    2.  All DLLs in a folder  (not recursive)
    3.  All DLLs in a folder  (recursive)

  > _
Still works as a one-liner if you know what you want:
bashpython dll_checker.py bad.dll              # single file
python dll_checker.py C:\Temp -r          # recursive scan
python dll_checker.py C:\Temp --min-score 25 --json -o out.json
