from irmin import Config, Store, Commit, Repo, Type, Hash, Value, String, log_level
import shutil

log_level("error")


def init(contents="json"):
    config = Config.git_mem(contents=contents)
    repo = Repo(config)
    return repo, Store(repo)


def test_irmin_type():
    assert Type.string().name == "string"
    assert Type.bool().name == "bool"
    assert Type.string() == Type.string()
    assert Type.unit() != Type.string()


def test_irmin_value():
    foo_a = Value.string("foo")
    foo_b = Value.string("foo")
    bar = Value.string("bar")
    assert foo_a == foo_b
    assert foo_a != bar

    a = Value.bool(True)
    s = Value.to_string(a)
    assert type(s) == String
    assert s == "true"


def test_bytes():
    repo, store = init("bytes")
    store["foo"] = b"bar"
    assert store["foo"] == b"bar"


def test_irmin_head():
    repo, store = init()
    assert store.head.parents == []
    store["test", "a"] = {"x": "foo"}
    c = store.head
    assert len(c.parents) == 1
    store["test", "a"] = {"x": "bar"}
    d = store.head
    if d is not None:
        assert d.parents[0].hash == c.hash
        assert d.parents[0] == c
    assert store["test", "a"] == {"x": "bar"}
    if c is not None:
        store.set_head(c)
    assert store["test", "a"] == {"x": "foo"}
    head = store.head
    if head is not None:
        assert head.hash == c.hash
        assert Hash.of_string(repo, str(head.hash)) == head.hash
        assert Commit.of_hash(repo, head.hash) == c
        tree = head.tree
        assert tree["test", "a"] == {"x": "foo"}
    assert repo.branches == ["main"]


def test_tree():
    repo, store = init()
    store["a", "b", "c"] = {"foo": "bar"}

    assert store.mem_tree(["a"])

    t = store.tree(["a", "b"])
    if t is not None:
        assert ["c"] in t
        assert t["c"] == {"foo": "bar"}
        t["d"] = {"x": 0}
        store.set_tree(["a", "b"], t)

    assert ["a", "b", "c"] in store
    assert ["a", "b", "d"] in store

    assert store["a", "b", "c"] == {"foo": "bar"}
    assert store["a", "b", "d"] == {"x": 0}

    paths = store.list(["a", "b"])
    assert repo.path(["c"]) in paths
    assert repo.path(["d"]) in paths
    assert str(t.hash()) == "309491aeeea8efe39b6a8412261c242379ef82f2"

    d = t.to_dict()
    assert d == {"Node": {"key": "309491aeeea8efe39b6a8412261c242379ef82f2"}}


def test_contents():
    repo, store = init()
    store["a", "b", "c"] = {"foo": "bar"}

    hash = repo.hash_contents({"foo": "bar"})
    v = repo.contents_of_hash(hash)
    assert v == {"foo": "bar"}


def test_pull_url():
    shutil.rmtree("/tmp/irmin-py-test", ignore_errors=True)
    config = Config.git(root="/tmp/irmin-py-test")
    repo = Repo(config)
    store = Store(repo)
    head = store.pull("https://github.com/mirage/irmin-py")
    assert head is not None
    assert ["README.md"] in store
