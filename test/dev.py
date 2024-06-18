#!/bin/env python3
import py_ghidra_xml
import sys


def extractRootBlock(base_addr, env):
    header = env.getMemParsedStruct(base_addr, "CartAssetHeader")
    return env.getMemBytes(base_addr + 8, header.size - 8)

if __name__ == "__main__":
    env = py_ghidra_xml.loadGhidraEnvironment(sys.argv[1], force_refresh=True)
    print(env.dtypes.keys())
    print(env.dtypes["RootAssetListHeader"].format.export_ksy())
    print(env.dtypes["CartAssetHeader"].format.export_ksy())
    b = extractRootBlock(0xB00B0464, env)
    print(len(b))
    print(env.dtypes["RootAssetListHeader"].format.parse(b))