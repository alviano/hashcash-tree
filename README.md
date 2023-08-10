# Hashcash Tree

A simple data structure combining [hashcash](https://en.wikipedia.org/wiki/Hashcash) and [hash trees](https://en.wikipedia.org/wiki/Merkle_tree) to mitigate for denial of service (DoS) attacks.
Labels of nodes in a hashcash tree are obtained by running hashcash with relatively small prefixes (the suggested prefix is `0b0000`).
The root is sent to the verifier as a commitment, and the prover is challenged to provide evidence that a labels in a randomly selected path have been computed.


## Usage

A hashcash tree generator is instantiated by using the factory method `HashcashTree::of` by specifying the prefix length and the size.
A hashcash tree can be computed by calling the `apply` method, providing an array of bytes in input.
A rich visualization of the result can be obtained by calling the `to_rich_tree` method. 

```python
from dumbo_utils.console import console
from hashcash_tree.primitives import HashcashTree, UINT

hashcash_tree = HashcashTree.of(prefix_length=4, size=UINT(7))
result = hashcash_tree.apply(b"foo")
console.print(result.to_rich_tree())
```

The above snippet of code produces the following output:
```
034cffa20d5e8d0a510b3b1539e998362b7ccd9105e5b2fa5efc617006d5df01 (5)
├── 07749bf34fc4e0f5c4e6842883638f8dac4952a292e1bedf5fbc4f38a39a7a7b (21)
│   ├── 0e08dd9c6fc2376721fae3327aa9a397d05e21b42c87e28cb1f56bddda87c498 (48)
│   └── 0435c20fbac1a2ba5f374afb25f9b784efcc5307fdb071764578df353b08271d (28)
└── 069c28f849fe7eb0ccfb2f3827214a6966764e4518dc2bc87a05cbdf746fbcf9 (3)
    ├── 0616a78fc5cd325a872537d8d92f741df5b7700a224ab81f435386179fd4ac87 (4)
    └── 0b94682dd4e6435f6cbb23a7c667f33918ee9bf38ac429f161cda0856943df38 (16)
```

The validation data can be extracted from the hashcash tree by calling the method `extract_nodes_for_validation`, providing the leaf index in input (the first leaf has index 1).
Finally, the validation data can be verified by calling the `verify` method of the hashcash tree generator, as shown below.

```python
from hashcash_tree.primitives import HashcashTree, UINT

hashcash_tree = HashcashTree.of(prefix_length=4, size=UINT(7))
result = hashcash_tree.apply(b"foo")
validation_data = result.extract_nodes_for_validation(1)
assert hashcash_tree.verify(message=b"foo", leaf_index=1,
                            digests_and_witnesses=validation_data)
```


# Client Puzzle Protocol

An example server is implemented in `server.py`.
A client performing 1K requests, possibly in parallel, is provided in `client.py`.
