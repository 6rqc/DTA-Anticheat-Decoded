DTA Broom v3.5 - Full analysis package
========================================

WHAT IS THIS
------------
DTA Broom v3.5 (C:\Users\Administrator\Downloads\DTA Broom v3_5.exe) is an
anti-cheat client written in Python 3.12, distributed as a PyInstaller 6.19.0
bundle.  It monitors a Dead-by-Daylight player's machine during championship
matches and forwards a signed report to a backend hosted on Render.com.

It is NOT malware, though six of its detections triggered the ML classifiers
of VirusTotal (Wacatac.B!ml / malicious_confidence_100%) because it behaves
like spyware (VM / debugger / hardware-fingerprint collection).

FILES IN THIS FOLDER
--------------------
00_README.txt              This file.
01_dtabroom_clean.py       Rebuilt Python source of the author's script.
                           ~90 % came from a patched pycdc build; the six
                           generator-heavy functions were rewritten from
                           bytecode by hand and are tagged as such.

02_ac_core_secrets.txt     Deobfuscated HMAC key, endpoint URL, and the
                           search for a hardcoded TLS certificate pin.
                           The .pyd's `_ac_core.pyx` source cannot be
                           recovered (Cython -> native C); we reconstructed
                           its API from its exported symbols and the
                           readable Cython string table.

03_data_schema.txt         Field-by-field table of what leaves the machine
                           when the client sends a report, and to which
                           HTTP endpoints.

04_bytecode_reference.txt  Raw Python 3.12 disassembly of the entire
                           dtabroom module and of _ac_core's exported
                           entry points, for anyone who wants to
                           double-check the rebuilt source.

05_pyd_exports.txt         Full symbol table + import table of
                           _ac_core.cp312-win_amd64.pyd, plus the
                           printable strings embedded in it (including
                           the Cython docstrings).

06_module_tree.txt         Full list of every module bundled inside the
                           PyInstaller archive, with a note of which
                           ones matched the official Python 3.12.0 /
                           library releases byte-for-byte.

WHAT WAS NOT DONE
-----------------
- No dynamic analysis: the exe was never executed and the backend was
  never touched.  Doing either would reveal your machine identity to
  the tournament organizer.
- The TLS certificate pin used by PinningAdapter (inside _ac_core.pyd)
  could not be recovered from static byte-pattern searches.  It is
  probably stored as raw bytes without any obvious signature; a full
  reverse of the .pyd in IDA/Ghidra would be needed.

LEGAL / ETHICAL NOTES
---------------------
This package is intended for personal review of software you were asked
to install.  Redistributing the anti-cheat's source, using the extracted
HMAC key to forge reports, or otherwise trying to cheat the tournament
is unfair to other players and likely violates its terms of use.
