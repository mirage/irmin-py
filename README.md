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

```
$ pip3 install . --user
```

And the build script should be able to find the location of the `libirmin` library and header files.

## Testing

Run the tests:

```
$ py.test test.py
```
