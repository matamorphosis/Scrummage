#!/bin/bash
# Compiles main.py to a binary file.

echo "[+] Install the pyinstaller package."
pip3 install pyinstaller
pyinstaller --onefile Scrummage.py
mv dist/Scrummage Scrummage
echo "[+] Cleaning up files."
rm -r dist
rm -r build
rm Scrummage.spec
echo "[+] Scrummage Compilation Finished."