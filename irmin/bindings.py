import cffi  # type: ignore
import os


def find_path(paths):
    for prefix in paths:
        if os.path.exists(
            os.path.join(prefix, "lib", "libirmin.so")
        ) and os.path.exists(os.path.join(prefix, "include", "irmin.h")):
            return prefix
    return None


prefix = find_path(
    [
        os.getenv("LIBIRMIN_PREFIX", ""),
        os.path.join(os.getenv("OPAM_SWITCH_PREFIX", "_opam"), "lib", "libirmin"),
        os.path.dirname(__file__),
        os.path.expanduser("~/.local"),
        "/usr/local",
        "/usr",
    ]
)

if prefix is None:
    raise Exception(
        "Unable to detect libirmin path, try installing libirmin"
        "using `opam install libirmin` or setting LIBIRMIN_PREFIX"
    )

ffi = cffi.FFI()
with open(os.path.join(prefix, "include", "irmin.h")) as h_file:
    lines = h_file.readlines()
    lines = [line for line in lines if "#" not in line and "static" not in line]
    ffi.cdef("\n".join(lines))

lib = ffi.dlopen(os.path.join(prefix, "lib", "libirmin.so"))
