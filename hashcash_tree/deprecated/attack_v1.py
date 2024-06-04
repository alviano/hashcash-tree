from typing import Final

import typer
from dumbo_utils.console import console

from hashcash_tree.deprecated.primitives_v1 import HashcashTree, UINT

PAYLOAD: Final = b"Attack the hashcash tree v1!"


def main(
        prefix_length: int = typer.Option(4, "--prefix-length", "-p", help="Number of zeros in hash values"),
        size: int = typer.Option(15, "--size", "-s", help="Number of nodes in the hashcash tree"),
        workers: int = typer.Option(1, "--workers", "-w", help="Number of concurrent jobs"),
        with_check: bool = typer.Option(False, "--with-check", "-c", help="Check the hashcash tree")
):
    hashcash_tree = HashcashTree.of(prefix_length=prefix_length, size=UINT(size))
    result = hashcash_tree.apply_parallel(PAYLOAD, workers=workers)
    if with_check:
        assert hashcash_tree.verify(message=PAYLOAD, leaf_index=1,
                                    digests_and_witnesses=result.extract_nodes_for_validation(1))
    console.log("All done!")


if __name__ == "__main__":
    typer.run(main)
