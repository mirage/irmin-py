from util import *
from irmin import *
import sys

if len(sys.argv) < 3:
    print("usage: python3 tezos.py /path/to/tezos/context <commit-hash>")
    sys.exit(0)

root = sys.argv[1]

# Configure tezos store
config = Config.tezos(root=root)
config["readonly"] = True

# Initialize the repo
repo = Repo(config)

commit_hash = Hash.of_string(repo, sys.argv[2])
commit = Commit.of_hash(repo, commit_hash)

# Open the `master` branch
store = Store(repo, branch=commit)


def list_path(store, path):
    """
    Prints all content paths
    """
    for k in store.list(path):
        p = path.append(k)
        if p in store:
            print(p)
        else:
            list_path(store, p)


# Print contract paths
list_path(store, Path(store.repo, ["data", "contracts"]))
