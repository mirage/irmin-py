import cffi  # type: ignore
import os

self_path = os.path.dirname(__file__)
libirmin_prefix = os.getenv("LIBIRMIN_PREFIX", "")


def check(prefix_list):
    for prefix in prefix_list:
        if os.path.exists(os.path.join(
                prefix, "lib", "libirmin.so")) and os.path.exists(
                    os.path.join(prefix, "include", "irmin.h")):
            return prefix
    raise Exception(
        "Unable to detect libirmin path, try setting LIBIRMIN_PREFIX")


prefix = check([
    libirmin_prefix,
    self_path,
    os.path.expanduser("~/.local"),
    os.path.join(os.getenv("OPAM_SWITCH_PREFIX", "_opam"), "lib", "libirmin"),
    "/usr/local",
])

ffi = cffi.FFI()
with open(os.path.join(prefix, "include", "irmin.h")) as h_file:
    lines = h_file.readlines()
    lines = [
        line for line in lines if '#include' not in line
        and '#define' not in line and 'static' not in line
    ]
    lines.append("void free(void*);")
    ffi.cdef('\n'.join(lines))

lib = ffi.dlopen(os.path.join(prefix, "lib", "libirmin.so"))
