import hashlib

import pytest
from dumbo_utils.console import console

from hashcash_tree.primitives import HashFunction, Hashcash, HashcashTree, UINT


def test_sha256_apply():
    assert HashFunction.sha256().apply(b"foo") == hashlib.sha256(b"foo").digest()


def test_sha256_length():
    assert HashFunction.sha256().length == 256


def test_sha256_verify():
    assert HashFunction.sha256().verify(
        message=b"foo",
        digest=bytes.fromhex("2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae")
    )


def test_hashcash_prefix_length():
    assert Hashcash(hash_function=HashFunction.sha256(), prefix_length=0).prefix_length == 0
    assert Hashcash(hash_function=HashFunction.sha256(), prefix_length=1).prefix_length == 1
    assert Hashcash(hash_function=HashFunction.sha256(), prefix_length=HashFunction.sha256().length).prefix_length == \
           HashFunction.sha256().length
    with pytest.raises(ValueError):
        assert Hashcash(hash_function=HashFunction.sha256(), prefix_length=-1)
    with pytest.raises(ValueError):
        assert Hashcash(hash_function=HashFunction.sha256(), prefix_length=HashFunction.sha256().length + 1)


def test_hashcash_apply():
    pair = [(None, None) for _ in range(13)]
    for i in range(13):
        pair[i] = Hashcash(hash_function=HashFunction.sha256(), prefix_length=i).apply(b"foo")
        if i > 0:
            a: Hashcash.Result = pair[i]
            b: Hashcash.Result = pair[i-1]
            assert a.witness >= b.witness


def test_hashcash_verify():
    hashcash = Hashcash(hash_function=HashFunction.sha256(), prefix_length=8)
    hashcash.verify_result(message=b"foo", result=hashcash.apply(b"foo"))
    hashcash.verify(
        message=b"foo",
        digest=bytes.fromhex("0086fab7949f80c43d9c1dec531e1ba59b8fcf5907135985ddd7e96ff8fccb4a"),
        witness=UINT(269)
    )


def test_hashcash_tree_apply():
    hashcash_tree = HashcashTree.of(prefix_length=8, size=UINT(15))
    result = hashcash_tree.apply(b"foo")
    assert result.root().digest.hex() == "0014e1b4b9f344b1f36de9087bde887c643e39c156bb604572e691c8ab37b75f"


def test_hashcash_tree_verify_must_specify_a_leaf_index():
    hashcash_tree = HashcashTree.of(prefix_length=8, size=UINT(15))
    with pytest.raises(ValueError):
        hashcash_tree.verify(b"foo", 0, HashcashTree.ValidationData())
    with pytest.raises(ValueError):
        hashcash_tree.verify(b"foo", 9, HashcashTree.ValidationData())


def test_hashcash_tree_verify():
    hashcash_tree = HashcashTree.of(prefix_length=8, size=UINT(15))
    result = hashcash_tree.apply(b"foo")
    print(result.extract_nodes_for_validation(1))
    assert hashcash_tree.verify(message=b"foo", leaf_index=1,
                                digests_and_witnesses=result.extract_nodes_for_validation(1))


def test_hashcash_tree_verify_on_missing_leaf():
    hashcash_tree = HashcashTree.of(prefix_length=8, size=UINT(8))
    result = hashcash_tree.apply(b"foo")
    leaf = 5
    assert hashcash_tree.verify(message=b"foo", leaf_index=leaf,
                                digests_and_witnesses=result.extract_nodes_for_validation(leaf))
