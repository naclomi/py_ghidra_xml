#!/bin/env python3
import py_ghidra_xml
import sys

if __name__ == "__main__":
    env = py_ghidra_xml.loadGhidraEnvironment(sys.argv[1], force_refresh=True)