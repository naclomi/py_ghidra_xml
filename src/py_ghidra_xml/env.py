import json
import os
import pickle
import tempfile
import uuid

import construct
import untangle

CACHE_DIR = os.path.join(tempfile.gettempdir(), __name__)


def _canonical_path(path):
    return os.path.abspath(os.path.expanduser(os.path.expandvars(path)))


def loadGhidraEnvironment(xml_filename, cache_dir=CACHE_DIR, force_refresh=False):
    os.makedirs(cache_dir, exist_ok=True)
    lock_filename = os.path.join(cache_dir, "cache.lock")
    with open(lock_filename, "a+") as f:
        f.seek(0)
        try:
            cache_lock = json.load(f)
        except json.decoder.JSONDecodeError:
            cache_lock = {}
        canoncial_xml_path = _canonical_path(xml_filename)
        last_modified = int(os.path.getmtime(canoncial_xml_path))
        if force_refresh is True or cache_lock.get(canoncial_xml_path, ("",0))[1] < last_modified:
            env = GhidraEnvironment(canoncial_xml_path)
            pickle_path = os.path.join(cache_dir, "{:}.env.bin".format(uuid.uuid4()))
            with open(pickle_path, "wb") as pickle_file:
                pickle.dump(env, pickle_file)
            cache_lock[canoncial_xml_path] = [pickle_path, last_modified]
            f.seek(0)
            f.truncate(0)
            json.dump(cache_lock, f)
        else:
            pickle_path = cache_lock[canoncial_xml_path][0]
            with open(pickle_path, "rb") as pickle_file:
                env = pickle.load(pickle_file)
    return env


DTYPE_CONSTRUCT_MAPPINGS = {
    "undefined": construct.Bytes(1),
    "undefined2": construct.Bytes(2),
    "undefined4": construct.Bytes(4),
    "int": construct.Int32ub
}


class GhidraStruct(object):
    def __init__(self, xml_node):
        self.xml = xml_node
        self.size = int(xml_node["SIZE"], 0)

        format_members = []
        for element in xml_node.children:
            construct_dtype = DTYPE_CONSTRUCT_MAPPINGS.get(
                element["DATATYPE"],
                construct.Bytes(int(element["SIZE"], 0))
            )
            format_members.append(element["NAME"] / construct_dtype)
        self.format = construct.Struct(*format_members)


class GhidraEnvironment(object):
    def __init__(self, xml_filename):
        self.xml_filename = xml_filename

        self.memmap = []
        self.dtypes = {}

        self.file_handles = {}

        with open(xml_filename, "r") as f:
            xml = untangle.parse(f)
        for dtype in xml.PROGRAM.DATATYPES.children:
            if dtype._name == "STRUCTURE":
                self.dtypes[dtype["NAME"]] = GhidraStruct(dtype)
        for mem_section in xml.PROGRAM.MEMORY_MAP.children:
            start_addr = int(mem_section['START_ADDR'],16)
            if len(mem_section.children) > 0:
                mapping = (mem_section.children[0]['FILE_NAME'],
                           int(mem_section.children[0]['FILE_OFFSET'], 0))
            else:
                mapping = None
            section = (
                (start_addr, start_addr + int(mem_section['LENGTH'], 0)),
                mapping
            )
            self.memmap.append(section)

    def getMemBytes(self, addr, n_bytes):
        for section in self.memmap:
            if section[0][0] <= addr < section[0][1]:
                break
        else:
            raise Exception("Memory not mapped at base address 0x{:08X}".format(addr))
        if section[1] is None:
            raise Exception("Memory not statically readable at base address 0x{:08X}".format(addr))
        if section[1][0] not in self.file_handles:
            data_filename = os.path.join(os.path.dirname(self.xml_filename),
                                         section[1][0])
            self.file_handles[section[1][0]] = open(data_filename, "rb")
        data_file = self.file_handles[section[1][0]]
        section_offset = addr - section[0][0]
        data_file.seek(section[1][1] + section_offset)
        return data_file.read(n_bytes)

    def getMemParsedStruct(self, addr, dtype_name):
        dtype = self.dtypes[dtype_name]
        raw = self.getMemBytes(addr, dtype.size)
        return dtype.format.parse(raw)


