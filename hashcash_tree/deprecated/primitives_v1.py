import dataclasses
import hashlib
from collections import namedtuple
from concurrent.futures import ProcessPoolExecutor
from dataclasses import InitVar
from typing import Callable, Optional, Final

import numpy as np
import typeguard
from dumbo_utils.primitives import PrivateKey
from rich.tree import Tree
from valid8 import validate

UINT: Final = np.uint16
ZERO: Final = UINT(0)
ONE: Final = UINT(1)
TWO: Final = UINT(2)
UINT_MAX: Final = UINT(0xFFFF)


@typeguard.typechecked
@dataclasses.dataclass(frozen=True)
class HashFunction:
    function: Callable
    length: int

    key: InitVar[PrivateKey]
    __key = PrivateKey()

    def __post_init__(self, key: PrivateKey):
        self.__key.validate(key)

    def apply(self, message: bytes) -> bytes:
        return self.function(message).digest()

    def verify(self, message: bytes, digest: bytes) -> bool:
        return self.apply(message) == digest

    @staticmethod
    def sha256() -> 'HashFunction':
        return HashFunction(
            function=hashlib.sha256,
            length=256,
            key=HashFunction.__key,
        )


@typeguard.typechecked
@dataclasses.dataclass(frozen=True)
class Hashcash:
    hash_function: HashFunction
    prefix_length: int

    Result = namedtuple("Result", ["digest", "witness"])

    def __post_init__(self):
        validate("prefix_length", self.prefix_length, min_value=0, max_value=self.hash_function.length)

    def apply(self, message: bytes) -> "Hashcash.Result":
        x = ZERO
        while True:
            digest = self.hash_function.apply(message + x)
            if self.count_leading_zeros(digest) >= self.prefix_length:
                return Hashcash.Result(digest, x)
            x += ONE

    def verify_result(self, message: bytes, result: "Hashcash.Result") -> bool:
        return Hashcash.count_leading_zeros(result.digest) >= self.prefix_length and \
            self.hash_function.verify(message=message + result.witness, digest=result.digest)

    def verify(self, message: bytes, digest: bytes, witness: UINT) -> bool:
        return self.verify_result(message=message, result=self.Result(digest, witness))

    @staticmethod
    def count_leading_zeros(digest: bytes) -> int:
        res = 0
        for byte in digest:
            if byte:
                return res + 8 - byte.bit_length()
            res += 8
        return res


def _apply_parallel_task(hashcash, message, index):
    res = hashcash.apply(message)
    return index, res.digest, res.witness


@dataclasses.dataclass(frozen=True)
class HashcashTree:
    hashcash: Hashcash
    size: UINT

    key: InitVar[PrivateKey]
    __key = PrivateKey()

    @staticmethod
    def validate_key(key: PrivateKey):
        HashcashTree.__key.validate(key)

    def __post_init__(self, key: PrivateKey):
        self.__key.validate(key)
        validate("size", self.size, min_value=1)

    @staticmethod
    def of(prefix_length: int, size: UINT, *, hash_function: HashFunction = HashFunction.sha256()):
        return HashcashTree(
            hashcash=Hashcash(hash_function=hash_function, prefix_length=prefix_length),
            size=size,
            key=HashcashTree.__key,
        )

    def apply(self, message: bytes) -> "HashcashTree.Result":
        nodes: list[Optional[Hashcash.Result]] = [None for _ in range(self.size + 1)]
        index = UINT(self.size)
        while index > ZERO:
            left = nodes[TWO * index].digest if TWO * index <= self.size else b""
            right = nodes[TWO * index + ONE].digest if TWO * index + ONE <= self.size else b""
            nodes[index] = self.hashcash.apply(message + index + left + right)
            index -= ONE

        return HashcashTree.Result(tuple(nodes), key=self.__key)

    def apply_parallel(self, message: bytes, workers: int = 1) -> "HashcashTree.Result":
        nodes: list[Optional[Hashcash.Result]] = [None for _ in range(self.size + 1)]
        index = UINT(self.size)
        with ProcessPoolExecutor(max_workers=workers) as pool:
            while index > ZERO:
                next_level = index // TWO
                futures = []
                while index > next_level:
                    left = nodes[TWO * index].digest if TWO * index <= self.size else b""
                    right = nodes[TWO * index + ONE].digest if TWO * index + ONE <= self.size else b""
                    futures.append(pool.submit(_apply_parallel_task, self.hashcash, message + index + left + right, index))
                    index -= ONE
                for future in futures:
                    idx, digest, witness = future.result()
                    nodes[idx] = self.hashcash.Result(digest, witness)
        return HashcashTree.Result(tuple(nodes), key=self.__key)

    def verify(self, message: bytes, leaf_index: int, digests_and_witnesses: "HashcashTree.ValidationData") -> bool:
        number_of_leaves = np.power(2, np.floor(np.log2(self.size)))
        validate("leaf_index", leaf_index, min_value=1, max_value=number_of_leaves)
        index = UINT(number_of_leaves - 1 + leaf_index)
        if index <= self.size and not self.hashcash.verify_result(message=message+index, result=digests_and_witnesses.hashcash_result(index)):
            return False
        while index > ONE:
            parity = index % TWO
            index //= TWO
            sibling = TWO * index + ONE - parity
            if sibling <= self.size and \
                    not Hashcash.count_leading_zeros(digests_and_witnesses.digest(sibling)) >= self.hashcash.prefix_length:
                return False
            if not self.hashcash.verify_result(
                    message=message + index + digests_and_witnesses.digest(TWO * index) +
                            digests_and_witnesses.digest(TWO * index + ONE),
                    result=digests_and_witnesses.hashcash_result(index),
            ):
                return False
        return True

    @dataclasses.dataclass(frozen=True)
    class Result:
        nodes: tuple[Optional[Hashcash.Result], ...]

        key: InitVar[PrivateKey]

        def __post_init__(self, key: PrivateKey):
            HashcashTree.validate_key(key)
            validate("nodes", self.nodes, min_len=2)
            validate("nodes", self.nodes[0] is None, equals=True)

        def root(self) -> Hashcash.Result:
            return self.nodes[1]

        def to_rich_tree(self):
            def node_to_str(node):
                return f"{node.digest.hex()} ({node.witness})"

            nodes: list[Optional[Tree]] = [None for _ in self.nodes]
            nodes[1] = Tree(node_to_str(self.root()))
            for index in range(2, len(nodes)):
                nodes[index] = nodes[index // 2].add(node_to_str(self.nodes[index]))
            return nodes[1]

        def extract_nodes_for_validation(self, leaf_index: int) -> "HashcashTree.ValidationData":
            number_of_leaves = int(np.power(2, np.floor(np.log2(len(self.nodes) - 1))))
            validate("leaf_index", leaf_index, min_value=1, max_value=number_of_leaves)
            res = HashcashTree.ValidationData()
            index = number_of_leaves - 1 + leaf_index
            while True:
                if index < len(self.nodes):
                    res.add(index, self.nodes[index].digest, self.nodes[index].witness)
                else:
                    res.add(index, b'')
                if index == 1:
                    return res
                parity = index % 2
                index //= 2
                sibling = 2 * index + 1 - parity
                res.add(sibling, self.nodes[sibling].digest if sibling < len(self.nodes) else b'')

    @dataclasses.dataclass(frozen=True)
    class ValidationData:
        __digests: dict = dataclasses.field(default_factory=dict, init=False)
        __witnesses: dict = dataclasses.field(default_factory=dict, init=False)

        def add(self, index: int, digest: bytes, witness: Optional[int] = None):
            self.__digests[index] = digest
            if witness is not None:
                self.__witnesses[index] = witness

        def digest(self, index: int) -> bytes:
            return self.__digests[index]

        def witness(self, index: int) -> int:
            return self.__witnesses[index]

        def hashcash_result(self, index: int) -> Hashcash.Result:
            return Hashcash.Result(digest=self.digest(index), witness=self.witness(index))

        def to_dict(self) -> dict:
            res = {}
            for key, value in self.__digests.items():
                res[key] = [value.hex(), int(self.__witnesses[key])] if key in self.__witnesses else [value.hex()]
            return res

        @staticmethod
        def of_dict(init: dict) -> "HashcashTree.ValidationData":
            res = HashcashTree.ValidationData()
            for key, value in init.items():
                res.add(key, bytes.fromhex(value[0]), UINT(value[1]) if len(value) == 2 else None)
            return res