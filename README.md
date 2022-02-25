# irmin-py

[irmin](https://irmin.org) bindings for Python

This crate enables you to call directly into irmin from your Python application and
can be used to open an existing irmin store from Python that may have been created
by an application written in OCaml.

## Dependencies

- `cffi`
- `pytest` (for testing)

## Installation

After installing [libirmin](https://github.com/mirage/irmin) using opam, you can run:

```
$ pip3 install git+https://github.com/mirage/irmin-py.git --user
```

Or from the root of the project:

Using pip:
```
$ pip3 install . --user
```

Using poetry:
```
$ POETRY_VIRTUALENVS_CREATE=false poetry install
```

And the build script should be able to find the location of the `libirmin` library and header files.

If `libirmin.so` and `irmin.h` were not installed using opam and they're not in `~/.local` or
`/usr/local`, then you can specify where to look for them using the `LIBIRMIN_PREFIX` env
variable.

## Testing

Run the tests:

```
$ poetry run pytest
```
