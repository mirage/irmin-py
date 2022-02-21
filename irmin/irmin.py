from .bindings import ffi, lib  # type: ignore

from typing import Optional, Sequence, Any, List, Union, Callable, TypeVar
import json

PathType = Union["Path", str, Sequence[str]]

T = TypeVar("T")


class IrminError(Exception):
    pass


class String(str):
    """
    Wrapper for OCaml string
    """

    _length: int
    _buffer: Any
    _ptr: ffi.CData

    def __new__(cls, ptr):
        if isinstance(ptr, str):
            ptr = str.encode(ptr)
            cls._ptr = lib.irmin_string_new(ptr, len(ptr))
        elif isinstance(ptr, bytes):
            cls._ptr = lib.irmin_string_new(ptr, len(ptr))
        else:
            cls._ptr = ptr
        if cls._ptr == ffi.NULL:
            raise IrminError("NULL string")
        length = lib.irmin_string_length(cls._ptr)
        s = lib.irmin_string_data(cls._ptr)
        b = ffi.buffer(s, length)
        t = super().__new__(cls, bytes.decode(bytes(b), errors="ignore"))
        t._ptr = cls._ptr
        t._buffer = b
        t._length = length
        return t

    def __len__(self) -> int:
        return self._length

    def __bytes__(self) -> bytes:
        return bytes(self._buffer)

    def to_bytes(self) -> bytes:
        return bytes(self)

    def __del__(self):
        lib.irmin_string_free(self._ptr)

    def __repr__(self) -> str:
        return f'String("{str(self)}")'


def error_msg(repo: "Repo") -> Optional[String]:
    """
    Get error message
    """
    s = lib.irmin_repo_get_error(repo._repo)
    if s == ffi.NULL:
        return None
    return String(s)


def check(repo, res, value=ffi.NULL):
    if res == value:
        err = error_msg(repo)
        if err is not None:
            raise IrminError(err)
    return res


class Bytes(bytes):
    """
    Wrapper for OCaml bytes
    """

    _length: int
    _ptr: ffi.CData

    def __new__(cls, ptr):
        if isinstance(ptr, str):
            ptr = str.encode(ptr)
            cls._ptr = lib.irmin_string_new(ptr, len(ptr))
        elif isinstance(ptr, bytes):
            cls._ptr = lib.irmin_string_new(ptr, len(ptr))
        else:
            cls._ptr = ptr
        if cls._ptr == ffi.NULL:
            raise IrminError("NULL bytes")
        length = lib.irmin_string_length(cls._ptr)
        s = lib.irmin_string_data(cls._ptr)
        b = ffi.buffer(s, length)
        t = super().__new__(cls, b)
        t._ptr = cls._ptr
        t._length = length
        return t

    def to_string(self) -> str:
        return bytes.decode(self)

    def __len__(self) -> int:
        return self._length

    def __del__(self):
        lib.irmin_string_free(self._ptr)


class Type:
    """
    Wrapper for Irmin.Type
    """

    def __init__(self, ptr):
        """
        Create a Type from IrminType pointer
        """
        if ptr == ffi.NULL:
            raise IrminError("Bad type")
        self._type = ptr

    @staticmethod
    def unit() -> "Type":
        """
        Irmin.Type.unit
        """
        return Type(lib.irmin_type_unit())

    @staticmethod
    def string() -> "Type":
        """
        Irmin.Type.string
        """
        return Type(lib.irmin_type_string())

    @staticmethod
    def int() -> "Type":
        """
        Irmin.Type.int
        """
        return Type(lib.irmin_type_int())

    @staticmethod
    def float() -> "Type":
        """
        Irmin.Type.float
        """
        return Type(lib.irmin_type_float())

    @staticmethod
    def bool() -> "Type":
        """
        Irmin.Type.bool
        """
        return Type(lib.irmin_type_bool())

    @staticmethod
    def json() -> "Type":
        """
        Irmin.Contents.Json.t
        """
        return Type(lib.irmin_type_json())

    @staticmethod
    def json_value() -> "Type":
        """
        Irmin.Contents.Json_value.t
        """
        return Type(lib.irmin_type_json_value())

    @staticmethod
    def path(repo) -> "Type":
        """
        Path type for the given repo
        """
        return Type(lib.irmin_type_path(repo._repo))

    @staticmethod
    def hash(repo) -> "Type":
        """
        Hash type for the given repo
        """
        return Type(lib.irmin_type_hash(repo._repo))

    @staticmethod
    def tree(repo) -> "Type":
        """
        Tree type for the given repo
        """
        return Type(lib.irmin_type_tree(repo._repo))

    @staticmethod
    def commit(repo) -> "Type":
        """
        Commit type for the given repo
        """
        return Type(lib.irmin_type_commit(repo._repo))

    @staticmethod
    def contents(repo) -> "Type":
        """
        Contents type for the given repo
        """
        return Type(lib.irmin_type_contents(repo._repo))

    @staticmethod
    def commit_key(repo) -> "Type":
        """
        CommitKey type for the given repo
        """
        return Type(lib.irmin_type_commit_key(repo._repo))

    @staticmethod
    def kinded_key(repo) -> "Type":
        """
        KindedKey type for the given repo
        """
        return Type(lib.irmin_type_kinded_key(repo._repo))

    @staticmethod
    def metadata(repo) -> "Type":
        """
        Metadata type for the given repo
        """
        return Type(lib.irmin_type_metadata(repo._repo))

    @property
    def name(self) -> str:
        """
        Type name
        """
        s = lib.irmin_type_name(self._type)
        return String(s)

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"<irmin.Type name={self.name}>"

    def __eq__(self, other: "Type") -> bool:  # type: ignore
        return self.name == other.name

    def __del__(self):
        lib.irmin_type_free(self._type)


class Value:
    """
    Wrapper for OCaml values that correspond with Type
    """

    def __init__(self, ptr, ty: Type):
        """
        Create new value from pointer and Type
        """
        if ptr == ffi.NULL:
            raise IrminError("Bad value")
        self.type = ty
        self._value = ptr

    def __eq__(self, other: "Value") -> bool:  # type: ignore
        return lib.irmin_value_equal(self.type._type, self._value, other._value)

    @staticmethod
    def contents_of_hash(repo: "Repo", h: "Hash") -> Optional["Value"]:
        """
        Find the contents that correspond with the provided hash, or return None
        """
        t = Type.contents(repo)
        r = lib.irmin_contents_of_hash(repo._repo, h._hash)
        if r == ffi.NULL:
            return None
        return Value(r, t)

    def hash_contents(self, repo: "Repo") -> "Hash":
        """
        Get hash of contents value
        """
        h = lib.irmin_contents_hash(repo._repo, self._value)
        return Hash(repo, h)

    @staticmethod
    def make(ty: Type, x):
        """
        Clone a value and cast the the given type
        """
        return Value(lib.irmin_value_clone(ffi.cast("IrminValue*", x)), ty)

    @staticmethod
    def unit() -> "Value":
        """
        unit value
        """
        return Value(lib.irmin_value_unit(), Type.unit())

    @staticmethod
    def int(i: int) -> "Value":
        """
        int value
        """
        return Value(lib.irmin_value_int(i), Type.int())

    @staticmethod
    def float(f: float) -> "Value":
        """
        float value
        """
        return Value(lib.irmin_value_float(f), Type.float())

    @staticmethod
    def bool(f: bool) -> "Value":
        """
        bool value
        """
        return Value(lib.irmin_value_bool(f), Type.bool())

    @staticmethod
    def string(s: str) -> "Value":
        """
        string value
        """
        b = str.encode(str(s))
        return Value(lib.irmin_value_string(b, len(b)), Type.string())

    @staticmethod
    def bytes(b: bytes) -> "Value":
        """
        string value from Python bytes
        """
        return Value(lib.irmin_value_string(b, len(b)), Type.string())

    @staticmethod
    def json(d: dict) -> "Value":
        """
        JSON value from Python dict
        """
        t = Type.json()
        s = str.encode(json.dumps(d))
        v = lib.irmin_value_of_string(t._type, s, len(s))
        return Value(v, t)

    @staticmethod
    def json_value(d: Any) -> "Value":
        """
        JSON value from any Python object
        """
        t = Type.json_value()
        s = str.encode(json.dumps(d))
        return Value(lib.irmin_value_of_string(t._type, s, len(s)), t)

    def wrap(x: Any) -> "Value":
        """
        Try to convert a python value to OCaml representation
        """
        if isinstance(x, bool):
            return Value.bool(x)
        elif isinstance(x, int):
            return Value.int(x)
        elif isinstance(x, float):
            return Value.float(x)
        elif isinstance(x, str):
            return Value.string(x)
        elif isinstance(x, bytes):
            return Value.bytes(x)
        elif isinstance(x, dict):
            return Value.json(x)
        elif isinstance(x, Value):
            return x
        else:
            raise TypeError("Unknown Value type")

    def get_string(self) -> str:
        """
        Get string from string value
        """
        s = lib.irmin_value_get_string(self._value)
        return String(s)

    def get_bytes(self) -> Bytes:
        """
        Get Python bytes from string value
        """
        s = lib.irmin_value_get_string(self._value)
        return Bytes(s)

    def to_bin(self) -> Bytes:
        """
        Encode a value using Irmin's binary encoding
        """
        s = lib.irmin_value_to_bin(self.type._type, self._value)
        return Bytes(s)

    @staticmethod
    def of_bin(t: Type, b) -> "Value":
        """
        Decode a value for the given type using Irmin's binary encoding
        """
        v = lib.irmin_value_of_bin(t._type, b, len(b))
        return Value(v, t)

    def to_string(self) -> String:
        """
        Encode a value using Irmin's string encoding
        """
        s = lib.irmin_value_to_string(self.type._type, self._value)
        return String(s)

    @staticmethod
    def of_string(t: Type, s: str) -> "Value":
        """
        Decode a value for the given type using Irmin's string encoding
        """
        b = str.encode(s)
        return Value.of_bytes(t, b)

    def to_bytes(self) -> Bytes:
        """
        Same as to_string but returns Python bytes
        """
        s = lib.irmin_value_to_string(self.type._type, self._value)
        return Bytes(s)

    @staticmethod
    def of_bytes(t: Type, b) -> "Value":
        """
        Same as of_string but accepts Python bytes
        """
        v = lib.irmin_value_of_string(t._type, b, len(b))
        return Value(v, t)

    def to_json(self) -> String:
        """
        Encode a value using Irmin's JSON encoding
        """
        s = lib.irmin_value_to_json(self.type._type, self._value)
        return String(s)

    def to_dict(self) -> dict:
        """
        Encode a value to JSON and parse it into a Python dict
        """
        return json.loads(self.to_string())

    @staticmethod
    def of_json(t: Type, b) -> "Value":
        """
        Decode a value using Irmin's JSON decoder
        """
        v = lib.irmin_value_of_json(t._type, b, len(b))
        return Value(v, t)

    def __bytes__(self):
        return self.to_bytes()

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return f"<irmin.Value type={self.type.name} data={self.to_string()}>"

    def __del__(self):
        lib.irmin_value_free(self._value)


class Contents:
    """
    Converts between Python values and Irmin Contents
    """

    def __init__(
        self,
        name: str,
        to_value: Callable[[T], Value],
        from_value: Callable[[Value], T],
        ty: Type,
        py_ty: object,
    ):
        self.name = name
        self.type = py_ty
        self.to_value = to_value
        self.from_value = from_value
        self.irmin_type = ty

    def _as_contents(self, v):
        return ffi.cast("IrminContents*", v._value)

    def hash(self, repo, v):
        """
        Get contents hash
        """
        v = self.to_value(v)
        h = lib.irmin_contents_hash(repo._repo, self._as_contents(v))
        return Hash(repo, h)

    def of_hash(self, repo, h: "Hash"):
        """
        Find contents from hash
        """
        v = lib.irmin_contents_of_hash(repo._repo, h._hash)
        v = Value(ffi.cast("IrminValue*", v), self.irmin_type)
        return self.from_value(v)


content_types = {
    "string": Contents("string", Value.string, Value.get_string, Type.string(), str),
    "bytes": Contents("string", Value.bytes, Value.get_bytes, Type.string(), bytes),
    "json": Contents("json", Value.json, Value.to_dict, Type.json(), dict),
    "json-value": Contents(
        "json-value",
        Value.json_value,
        lambda x: json.loads(Value.to_string(x)),
        Type.json_value(),
        Any,
    ),
}


def log_level(level: Optional[str]):
    """
    Update Irmin log level
    """
    if level is None:
        lib.irmin_log_level(ffi.NULL)
    else:
        lib.irmin_log_level(str.encode(level))


class Config:
    def __init__(
        self, ptr, contents: Contents, backend: str, root: Optional[str] = None
    ):
        """
        Create a new config from IrminConfig pointer and contents name
        """
        if ptr == ffi.NULL:
            raise IrminError("Invalid config")
        self._config = ptr
        self.contents = contents
        self.backend = backend
        if root is not None:
            self.root(root)

    def root(self, root: str):
        """
        Set the root key
        """
        value = Value.string(root)
        lib.irmin_config_set(self._config, b"root", value.type._type, value._value)

    def __setitem__(self, key: str, value: Any):
        """
        Set config key
        """
        value = Value.wrap(value)
        lib.irmin_config_set(
            self._config, str.encode(key), value.type._type, value._value
        )

    def __del__(self):
        lib.irmin_config_free(self._config)

    @staticmethod
    def tezos(root=None) -> "Config":
        """
        Configure a tezos context store
        """
        return Config(
            lib.irmin_config_tezos(),
            contents=content_types["bytes"],
            root=root,
            backend="tezos",
        )

    @staticmethod
    def git(contents="string", root=None) -> "Config":
        """
        Configure an on-disk git store
        """
        c = content_types[contents]
        return Config(
            lib.irmin_config_git(str.encode(c.name)),
            contents=c,
            root=root,
            backend="git",
        )

    @staticmethod
    def git_mem(contents="string") -> "Config":
        """
        Configure an in-memory git store
        """
        c = content_types[contents]
        return Config(
            lib.irmin_config_git_mem(str.encode(c.name)), contents=c, backend="git-mem"
        )

    @staticmethod
    def pack(contents="string", hash: Optional[str] = None, root=None) -> "Config":
        """
        Configure an Irmin_pack store
        """
        c = content_types[contents]
        h = ffi.NULL if hash is None else str.encode(hash)
        return Config(
            lib.irmin_config_pack(h, str.encode(c.name)),
            contents=c,
            root=root,
            backend="pack",
        )

    @staticmethod
    def mem(contents="string", hash: Optional[str] = None) -> "Config":
        """
        Configure an in-memory store
        """
        c = content_types[contents]
        h = ffi.NULL if hash is None else str.encode(hash)
        return Config(
            lib.irmin_config_mem(h, str.encode(c.name)), contents=c, backend="mem"
        )

    @staticmethod
    def fs(contents="string", hash: Optional[str] = None, root=None) -> "Config":
        """
        Configure store using Irmin_fs
        """
        c = content_types[contents]
        h = ffi.NULL if hash is None else str.encode(hash)
        return Config(
            lib.irmin_config_fs(h, str.encode(c.name)),
            contents=c,
            root=root,
            backend="irf",
        )

    def __repr__(self):
        return f"<irmin.Config backend={self.backend} \
                contents={self.contents.name}>"


class Repo:
    def __init__(self, config: Config):
        """
        Create repo from Config
        """
        self.config = config
        self._repo = lib.irmin_repo_new(self.config._config)
        if self._repo == ffi.NULL:
            raise IrminError("Unable to create repo")

    def contents_of_hash(self, h: "Hash"):
        """
        Find contents that correspond with the given hash
        """
        return self.config.contents.of_hash(self, h)

    def hash_contents(self, c) -> "Hash":
        """
        Generate hash for contents
        """
        return self.config.contents.hash(self, c)

    def type(self):
        """
        Get contents type
        """
        return self.config.contents.type

    def irmin_type(self) -> Type:
        """
        Get contents OCaml type
        """
        return self.config.contents.irmin_type

    def error_msg(self) -> Optional[String]:
        """
        Get the current error message
        """
        return error_msg(self)

    @property
    def branches(self) -> List[String]:
        """
        List all available branches
        """
        b = lib.irmin_repo_branches(self._repo)
        n = lib.irmin_branch_array_length(self._repo, b)
        dest = []
        for i in range(n):
            dest.append(String(lib.irmin_branch_array_get(self._repo, b, i)))
        lib.irmin_branch_array_free(b)
        return dest

    def path(self, p) -> "Path":
        """
        Create a new path
        """
        return Path.wrap(self, p)

    def info(self, author: str, message: str) -> "Info":
        """
        Create new info
        """
        return Info(self, author, message)

    def commit(
        self, parents: Sequence["Commit"], tree: "Tree", info: "Info"
    ) -> "Commit":
        """
        Create new commit
        """
        return Commit.new(self, parents, tree, info)

    def tree(self) -> "Tree":
        """
        Create an empty tree
        """
        return Tree(self)

    def __del__(self):
        lib.irmin_repo_free(self._repo)

    def __repr__(self):
        return f"<irmin.Repo backend={self.config.backend} \
                contents={self.config.contents.name}>"


class Metadata:
    def __init__(self, repo: Repo, ptr):
        check(repo, ptr)
        self._metadata = ptr
        self.repo = repo

    def __str__(self):
        t = Type.metadata(self.repo)
        return Value(self._metadata, t).to_string()

    def __repr__(self):
        return f"<irmin.Metadata value={str(self)}>"

    def __del__(self):
        lib.irmin_metadata_free(self._metadata)


class Path:
    def __init__(self, repo: Repo, ptr):
        """
        Create a new path for the given repo using a list of str objects
        """
        self._path = None
        self.repo = repo
        if isinstance(ptr, (tuple, list)):
            a = [ffi.new("char[]", str.encode(arg)) for arg in ptr]
            a.append(ffi.NULL)
            x = ffi.new("char*[]", a)
            ptr = lib.irmin_path(self.repo._repo, x)
        elif isinstance(ptr, str):
            b = str.encode(ptr)
            ptr = lib.irmin_path_of_string(repo._repo, b, len(b))
        elif not isinstance(ptr, ffi.CData):
            raise IrminError("Invalid path type: " + str(type(ptr)))
        check(repo, ptr)
        self._path = ptr

    @staticmethod
    def empty(repo: Repo) -> "Path":
        """
        Create an empty path
        """
        p = lib.irmin_path_empty(repo._repo)
        return Path(repo, p)

    def append(self, s):
        """
        Append to a path, returning a new path
        """
        path = Path.wrap(self.repo, s)
        ptr = lib.irmin_path_append_path(self.repo._repo, self._path, path._path)

        return Path(self.repo, ptr)

    def parent(self):
        """
        Get a path's parent
        """
        ptr = lib.irmin_path_parent(self.repo._repo, self._path)
        if ptr == ffi.NULL:
            check(self.repo, ptr)
            return None
        return Path(self.repo, ptr)

    def __str__(self):
        s = lib.irmin_path_to_string(self.repo._repo, self._path)
        return String(s)

    def __repr__(self):
        return f"<irmin.Path value={str(self)}>"

    def __eq__(self, other: PathType) -> bool:  # type: ignore
        other = Path.wrap(self.repo, other)
        return lib.irmin_path_equal(self.repo._repo, self._path, other._path)

    @staticmethod
    def wrap(repo: Repo, path: PathType) -> "Path":
        if isinstance(path, Path):
            return path
        return Path(repo, path)

    @staticmethod
    def of_string(repo: Repo, s: str) -> "Path":
        """
        Convert from str to Path
        """
        b = str.encode(s)
        v = lib.irmin_path_of_string(repo._repo, b, len(b))
        return Path(repo, v)

    def __del__(self):
        lib.irmin_path_free(self._path)


class CommitKey:
    def __init__(self, repo: Repo, c):
        check(repo, c)
        self.repo = repo
        self._key = c

    def __del__(self):
        lib.irmin_commit_key_free(self._key)

    @staticmethod
    def of_string(repo, s):
        """
        Parse str containing a hash into IrminCommitKey
        """
        b = str.encode(s)
        t = Type.commit_key(repo)
        h = lib.irmin_value_of_string(t, b, len(b))
        return CommitKey(repo, h)

    def __str__(self):
        t = Type.commit_key(self.repo)
        return Value.make(t, self._key).to_string()

    def __repr__(self):
        return f"<irmin.CommitKey value={str(self)}>"


class Hash:
    def __init__(self, repo: Repo, h):
        check(repo, h)
        self.repo = repo
        self._hash = h

    def __eq__(self, other: "Hash") -> bool:  # type: ignore
        return lib.irmin_hash_equal(self.repo._repo, self._hash, other._hash)

    def __bytes__(self):
        s = lib.irmin_hash_to_string(self.repo._repo, self._hash)
        return Bytes(s)

    @staticmethod
    def of_string(repo, s):
        """
        Parse str containing a hash into IrminHash
        """
        b = str.encode(s)
        h = lib.irmin_hash_of_string(repo._repo, b, len(b))
        return Hash(repo, h)

    def __str__(self):
        return bytes.decode(self.__bytes__())

    def __del__(self):
        lib.irmin_hash_free(self._hash)

    def __repr__(self):
        return f"<irmin.Hash value={str(self)}>"


class Info:
    def __init__(self, repo: Repo, i, message=None):
        """
        Create info from repo and IrminInfo pointer
        """
        if isinstance(i, str) and isinstance(message, str):
            i = lib.irmin_info_new(repo._repo, str.encode(i), str.encode(message))
        elif not isinstance(i, ffi.CData):
            raise TypeError("Invalid pointer in Info.__init__")
        check(repo, i)
        self.repo = repo
        self._info = i

    @property
    def date(self) -> int:
        """
        Get date
        """
        return lib.irmin_info_date(self.repo._repo, self._info)

    @property
    def author(self) -> str:
        """
        Get author
        """
        s = lib.irmin_info_author(self.repo._repo, self._info)
        return String(s)

    @property
    def message(self) -> str:
        """
        Get message
        """
        s = lib.irmin_info_message(self.repo._repo, self._info)
        return String(s)

    def __del__(self):
        lib.irmin_info_free(self._info)

    def __repr__(self):
        return f"<irmin.Info date={self.date} author={self.author} \
            message={self.message}>"


class Commit:
    def __init__(self, repo: Repo, c):
        check(repo, c)
        self.repo = repo
        self._commit = c

    @property
    def hash(self) -> Hash:
        """
        Get commit hash
        """
        h = lib.irmin_commit_hash(self.repo._repo, self._commit)
        return Hash(self.repo, h)

    @property
    def key(self) -> CommitKey:
        """
        Get commit key
        """
        h = lib.irmin_commit_key(self.repo._repo, self._commit)
        return CommitKey(self.repo, h)

    def __eq__(self, other: "Commit") -> bool:  # type: ignore
        return lib.irmin_commit_equal(self.repo._repo, self._commit, other._commit)

    @property
    def info(self) -> Info:
        return Info(self.repo, lib.irmin_commit_info(self.repo._repo, self._commit))

    @property
    def tree(self) -> "Tree":
        return Tree(self.repo, lib.irmin_commit_tree(self.repo._repo, self._commit))

    @staticmethod
    def new(
        repo: Repo, parents: Sequence["Commit"], tree: "Tree", info: Info
    ) -> "Commit":
        """
        Create a new commit
        """
        n = len(parents)
        a = [ffi.new("IrminCommit*", arg._commit) for arg in parents]
        b = ffi.new("IrminCommit*[]", a)
        c = lib.irmin_commit_new(repo._repo, b, n, tree._tree, info._info)
        check(repo, c)
        return Commit(repo, c)

    @staticmethod
    def of_hash(repo: Repo, hash: Hash) -> Optional["Commit"]:
        """
        Find the commit associated with the given hash
        """
        c = lib.irmin_commit_of_hash(repo._repo, hash._hash)
        if c == ffi.NULL:
            return None
        return Commit(repo, c)

    @staticmethod
    def of_key(repo: Repo, key: CommitKey) -> Optional["Commit"]:
        """
        Find the commit associated with the given key
        """
        c = lib.irmin_commit_of_key(repo._repo, key._key)
        if c == ffi.NULL:
            return None
        return Commit(repo, c)

    @property
    def parents(self) -> List["Commit"]:
        """
        Commit parents
        """
        list = lib.irmin_commit_parents(self.repo._repo, self._commit)
        n = lib.irmin_commit_array_length(self.repo._repo, list)
        d = [lib.irmin_commit_array_get(self.repo._repo, list, i) for i in range(n)]
        d = [Commit(self.repo, x) for x in d if x != ffi.NULL]
        lib.irmin_commit_array_free(list)
        return d

    def __del__(self):
        lib.irmin_commit_free(self._commit)

    def __str__(self):
        return self.hash.__str__()

    def __repr__(self):
        return f"<irmin.Commit hash={self.hash.__str__()} \
                key={self.key.__str__()}>"


class Tree:
    def __init__(self, repo: Repo, t=None):
        """
        Create a tree
        """
        self.repo = repo
        if t is not None:
            self._tree = t
        else:
            self._tree = lib.irmin_tree_new(self.repo._repo)
        check(repo, self._tree)

    def __eq__(self, other: "Tree") -> bool:  # type: ignore
        return lib.irmin_tree_equal(self.repo._repo, self._tree, other._tree)

    def __setitem__(self, path: PathType, v):
        if isinstance(v, Tree):
            return self.set_tree(path, v)
        return self.set(path, v)

    def set(self, path: PathType, v):
        path = Path.wrap(self.repo, path)
        value = self.repo.config.contents.to_value(v)
        x = lib.irmin_tree_add(
            self.repo._repo,
            self._tree,
            path._path,
            ffi.cast("IrminContents*", value._value),
            ffi.NULL,
        )
        check(self.repo, x, False)

    def __getitem__(self, path: PathType):
        return self.get(path)

    def get(self, path: PathType):
        path = Path.wrap(self.repo, path)
        v = lib.irmin_tree_find(self.repo._repo, self._tree, path._path)
        if v == ffi.NULL:
            return None
        return self.repo.config.contents.from_value(
            Value(ffi.cast("IrminValue*", v), self.repo.config.contents.irmin_type)
        )

    def __delitem__(self, path: PathType):
        return self.remove(path)

    def remove(self, path: PathType):
        path = Path.wrap(self.repo, path)
        x = lib.irmin_tree_remove(self.repo._repo, self._tree, path._path)
        check(self.repo, x, False)

    def __contains__(self, path: PathType) -> bool:
        return self.mem(path)

    def mem(self, path: PathType) -> bool:
        path = Path.wrap(self.repo, path)
        return lib.irmin_tree_mem(self.repo._repo, self._tree, path._path)

    def mem_tree(self, path: PathType) -> bool:
        """
        Check for the existence of a tree at the given path
        """
        path = Path.wrap(self.repo, path)
        return lib.irmin_tree_mem_tree(self.repo._repo, self._tree, path._path)

    def tree(self, path: PathType) -> Optional["Tree"]:
        """
        Get the tree at the given path
        """
        path = Path.wrap(self.repo, path)
        x = lib.irmin_tree_find_tree(self.repo._repo, self._tree, path._path)
        if x == ffi.NULL:
            return None
        return Tree(self.repo, x)

    def metadata(self, path: PathType) -> Optional[Metadata]:
        """
        Get metadata at the given path
        """
        path = Path.wrap(self.repo, path)
        x = lib.irmin_tree_find_metadata(self.repo._repo, self._tree, path._path)
        if x == ffi.NULL:
            return None
        return Metadata(self.repo, x)

    def set_tree(self, path: PathType, tree: "Tree"):
        """
        Set a tree at the given path
        """
        path = Path.wrap(self.repo, path)
        x = lib.irmin_tree_set_tree(self.repo._repo, self._tree, path._path, tree._tree)
        check(self.repo, x, False)

    def to_json(self) -> str:
        """
        Convert to JSON representation
        """
        t = Type.tree(self.repo)
        v = Value.make(t, self._tree)
        return v.to_string()

    def to_dict(self) -> dict:
        """
        Convert to dict using JSON representation
        """
        return json.loads(self.to_json())

    def list(self, path: PathType) -> List[Path]:
        """
        List paths
        """
        path = Path.wrap(self.repo, path)
        paths = lib.irmin_tree_list(self.repo._repo, self._tree, path._path)
        n = lib.irmin_path_array_length(self.repo._repo, paths)
        dest = []
        for i in range(n):
            p = lib.irmin_path_array_get(self.repo._repo, paths, i)
            if p == ffi.NULL:
                continue
            dest.append(Path(self.repo, p))
        lib.irmin_path_array_free(paths)
        return dest

    def hash(self) -> Hash:
        """
        Get hash of tree
        """
        hash = lib.irmin_tree_hash(self.repo._repo, self._tree)
        return Hash(self.repo, hash)

    @staticmethod
    def of_hash(hash) -> Optional["Tree"]:
        """
        Get tree from hash
        """
        t = lib.irmin_tree_of_hash(hash.repo._repo, hash._hash)
        if t == ffi.NULL:
            return None
        return Tree(hash.repo, t)

    def __del__(self):
        lib.irmin_tree_free(self._tree)

    def __repr__(self):
        return f"<irmin.Tree hash={self.hash()}>"


class Remote:
    def __init__(self, repo: Repo, ptr, url: Optional[str]):
        """
        See Remote.store and Remote.url
        """
        self.repo = repo
        self._remote = ptr
        self._url = url
        check(repo, self._remote)

    @staticmethod
    def store(store: "Store") -> "Remote":
        """
        Remote store on disk
        """
        ptr = lib.irmin_remote_store(store.repo._repo, store)
        return Remote(store.repo, ptr, None)

    @staticmethod
    def url(
        repo: Repo, url: str, user: Optional[str] = None, token: Optional[str] = None
    ) -> "Remote":
        """
        Remote URL
        """
        if user is not None:
            u = user.encode()
            t = ffi.NULL if token is None else token.encode()
            ptr = lib.irmin_remote_with_auth(repo._repo, url.encode(), u, t)
        else:
            ptr = lib.irmin_remote(repo._repo, url.encode())
        return Remote(repo, ptr, url)

    def __repr__(self):
        if self._url is None:
            return f"<irmin.Remote url={self._url}>"
        else:
            return "<irmin.Remote>"

    def __del__(self):
        lib.irmin_remote_free(self._remote)


class Store:
    def __init__(self, repo: Repo, branch: Union[str, Commit] = "main"):
        self.repo = repo
        if isinstance(branch, str):
            self._store = lib.irmin_of_branch(self.repo._repo, str.encode(branch))
        else:
            self._store = lib.irmin_of_commit(self.repo._repo, branch._commit)
        check(repo, self._store)

    def __del__(self):
        lib.irmin_free(self._store)

    def __getitem__(self, path: PathType):
        return self.get(path)

    def get(self, path: PathType):
        path = Path.wrap(self.repo, path)
        x = lib.irmin_find(self._store, path._path)
        if x == ffi.NULL:
            return None
        return self.repo.config.contents.from_value(
            Value(ffi.cast("IrminValue*", x), self.repo.config.contents.irmin_type)
        )

    def tree(self, path: PathType):
        """
        Get the tree at the given path
        """
        path = Path.wrap(self.repo, path)
        x = lib.irmin_find_tree(self._store, path._path)
        if x == ffi.NULL:
            return None
        return Tree(self.repo, x)

    def metadata(self, path: PathType) -> Optional[Metadata]:
        """
        Get metadata at the given path
        """
        path = Path.wrap(self.repo, path)
        x = lib.irmin_find_metadata(self._store, path._path)
        if x == ffi.NULL:
            return None
        return Metadata(self.repo, x)

    def __setitem__(self, path: PathType, value):
        if isinstance(value, Tree):
            return self.set_tree(path, value)
        return self.set(path, value)

    def __delitem__(self, path: PathType):
        return self.remove(path)

    def remove(self, path: PathType):
        path = Path.wrap(self.repo, path)
        x = lib.irmin_remove(self._store, path._path)
        check(self.repo, x, False)

    def __contains__(self, path: PathType) -> bool:
        return self.mem(path)

    def mem(self, path: PathType) -> bool:
        path = Path.wrap(self.repo, path)
        return lib.irmin_mem(self._store, path._path)

    def info(self, author: str = "", message: str = "") -> Info:
        return Info(self.repo, author, message)

    def set(self, path: PathType, value, info: Optional[Info] = None):
        """
        Store a value at the given path and create a new commit
        """
        path = Path.wrap(self.repo, path)
        value = self.repo.config.contents.to_value(value)
        if info is None:
            info = self.info("irmin", "set")
        x = lib.irmin_set(
            self._store,
            path._path,
            ffi.cast("IrminContents*", value._value),
            info._info,
        )
        check(self.repo, x, False)

    def test_and_set(
        self, path: PathType, old, value, info: Optional[Info] = None
    ) -> bool:
        """
        Update the value stored at the given path as long as it
        matches the `old` argument
        """
        path = Path.wrap(self.repo, path)
        old = self.repo.config.contents._as_contents(old) if value is not None else None
        value = (
            self.repo.config.contents._as_contents(value) if value is not None else None
        )
        if info is None:
            info = self.info("irmin", "set")
        return check(
            self.repo,
            lib.irmin_test_and_set(
                self._store,
                path._path,
                ffi.cast("IrminContents*", old._value) if old is not None else ffi.NULL,
                ffi.cast("IrminContents*", value._value)
                if value is not None
                else ffi.NULL,
                info._info,
            ),
            False,
        )

    def set_tree(self, path: PathType, tree: Tree, info: Optional[Info] = None) -> bool:
        """
        Update the tree stored at the given path
        """
        path = Path.wrap(self.repo, path)
        if info is None:
            info = self.info("irmin", "set_tree")
        return check(
            self.repo,
            lib.irmin_set_tree(self._store, path._path, tree._tree, info._info),
            False,
        )

    def test_and_set_tree(
        self,
        path: PathType,
        old: Optional[Tree],
        tree: Optional[Tree],
        info: Optional[Info] = None,
    ) -> bool:
        """
        Update the tree stored at the given path as long as it
        matches the `old` argument
        """
        path = Path.wrap(self.repo, path)
        if info is None:
            info = self.info("irmin", "set_tree")
        return check(
            self.repo,
            lib.irmin_test_and_set_tree(
                self._store,
                path._path,
                old._tree if old is not None else ffi.NULL,
                tree._tree if tree is not None else ffi.NULL,
                info._info,
            ),
            False,
        )

    def mem_tree(self, path: PathType) -> bool:
        """
        Check for the existence of a tree at the given path
        """
        path = Path.wrap(self.repo, path)
        return lib.irmin_mem_tree(self._store, path._path)

    @property
    def head(self) -> Optional[Commit]:
        """
        Get head commit
        """
        c = lib.irmin_get_head(self._store)
        if c == ffi.NULL:
            check(self.repo, c)
            return None
        return Commit(self.repo, c)

    def set_head(self, c: Commit):
        """
        Set head commit
        """
        lib.irmin_set_head(self._store, c._commit)

    def fast_forward(self, c: Commit) -> bool:
        """
        Update the current branch to the given commit
        """
        return check(self.repo, lib.irmin_fast_forward(self._store, c._commit), False)

    def merge_with_branch(self, branch: str, info: Optional[Info] = None) -> bool:
        """
        Merge with another branch
        """
        if info is None:
            info = self.info("irmin", "merge")
        return check(
            self.repo,
            lib.irmin_merge_with_branch(self._store, str.encode(branch), info._info),
            False,
        )

    def merge_with_commit(self, commit: Commit, info: Optional[Info] = None) -> bool:
        """
        Merge with another commit
        """
        if info is None:
            info = self.info("irmin", "merge commit")
        return check(
            self.repo,
            lib.irmin_merge_with_branch(self._store, commit._commit, info._info),
            False,
        )

    def merge(self, store: "Store", info: Optional[Info] = None) -> bool:
        """
        Merge with another store
        """
        if info is None:
            info = self.info("irmin", "merge store")
        return check(
            self.repo,
            lib.irmin_merge_into(self._store, store._store, info._info),
            False,
        )

    def list(self, path: PathType) -> List[Path]:
        """
        Get a list of paths
        """
        path = Path.wrap(self.repo, path)
        paths = lib.irmin_list(self._store, path._path)
        n = lib.irmin_path_array_length(self.repo._repo, paths)
        dest = []
        for i in range(n):
            p = lib.irmin_path_array_get(self.repo._repo, paths, i)
            if p == ffi.NULL:
                continue
            dest.append(Path(self.repo, p))
        lib.irmin_path_array_free(paths)
        return dest

    def fetch(self, remote: Union[str, "Store", Remote], depth=-1) -> Optional[Commit]:
        """
        Fetch data from remote repo
        """
        if isinstance(remote, str):
            remote = Remote.url(self.repo, remote)
        elif isinstance(remote, Store):
            remote = Remote.store(remote)
        elif not isinstance(remote, Remote):
            raise TypeError("Invalid type for remote argument: " + str(type(remote)))
        c = lib.irmin_fetch(self._store, depth, remote._remote)
        if c == ffi.NULL:
            check(self.repo, c)
            return None
        return Commit(self.repo, c)

    def pull(
        self, remote: Union[str, "Store", Remote], depth=-1, info=None
    ) -> Optional[Commit]:
        """
        Pull data from remote repo, if `info` is not `None`
        then a merge commit will be created
        """
        if isinstance(remote, str):
            remote = Remote.url(self.repo, remote)
        elif isinstance(remote, Store):
            remote = Remote.store(remote)
        elif not isinstance(remote, Remote):
            raise TypeError("Invalid type for remote argument: " + str(type(remote)))
        info_p = ffi.NULL if info is None else info._info
        c = lib.irmin_pull(self._store, depth, remote._remote, info_p)
        if c == ffi.NULL:
            check(self.repo, c)
            return None
        return Commit(self.repo, c)

    def push(self, remote: Union[str, "Store", Remote], depth=-1) -> Optional[Commit]:
        """
        Push data to remote repo
        """
        if isinstance(remote, str):
            remote = Remote.url(self.repo, remote)
        elif isinstance(remote, Store):
            remote = Remote.store(remote)
        elif not isinstance(remote, Remote):
            raise TypeError("Invalid type for remote argument: " + str(type(remote)))
        c = lib.irmin_push(self._store, depth, remote._remote)
        if c == ffi.NULL:
            check(self.repo, c)
            return None
        return Commit(self.repo, c)

    def __repr__(self):
        head = self.head
        if head is None:
            h = "None"
        else:
            h = str(head.hash)
        return f"<irmin.Store head={h} backend={self.repo.config.backend} \
                contents={self.repo.config.contents.name}>"
