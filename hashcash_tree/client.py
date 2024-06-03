import os
import time
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

import requests
from dumbo_utils.console import console
from rich.progress import Progress
from starlette.status import HTTP_200_OK

from hashcash_tree.primitives import HashcashTree, UINT
from hashcash_tree.server import HASH_FUNCTION, GeneratePuzzleResponse, PuzzleSolvedResponse, \
    VerifyPuzzleResponse, ParametersResponse

SERVER = "http://localhost:8123"

PREFIX_LENGTH = 4
ALLOTTED_TIME = 10


def fetch_parameters():
    global PREFIX_LENGTH
    global ALLOTTED_TIME
    response = requests.get(f"{SERVER}/parameters/")
    data = ParametersResponse(**response.json())
    PREFIX_LENGTH = data.prefix_length
    ALLOTTED_TIME = data.allotted_time
    console.log(f"PREFIX_LENGTH = {PREFIX_LENGTH}")
    console.log(f"ALLOTTED_TIME = {ALLOTTED_TIME}")


def measure_process_time(fun, *args):
    begin = time.process_time_ns()
    try:
        res = fun(*args)
    except Exception as e:
        res = e
    return res, (time.process_time_ns() - begin)


def validate_status_code(response):
    if response.status_code != HTTP_200_OK:
        console.log(response.json()["message"])
        raise ValueError


def perform_request(payload: int):
    req = f"AN EXPENSIVE REQUEST INCLUDING A NONCE: {payload}"
    req_hash = HASH_FUNCTION.apply(req.encode()).hex()

    response = requests.get(f"{SERVER}/generate-puzzle/{req_hash}/")
    validate_status_code(response)
    data = GeneratePuzzleResponse(**response.json())
    console.log(f"Received puzzle: {data}")
    message = data.message
    size = data.size
    timestamp = data.timestamp

    hashcash_tree = HashcashTree.of(prefix_length=PREFIX_LENGTH, size=UINT(size), hash_function=HASH_FUNCTION)
    solution = hashcash_tree.apply(message.encode())
    response = requests.post(f"{SERVER}/puzzle-solved/{req_hash}/", json={
        "solution": solution.root().digest.hex(),
        "message": message,
        "size": size,
        "timestamp": timestamp,
    })
    validate_status_code(response)
    data = PuzzleSolvedResponse(**response.json())
    console.log(f"Server asked for verification: {data}")
    leaf = data.leaf
    leaf_hash = data.leaf_hash

    validation_data = solution.extract_nodes_for_validation(leaf)
    response = requests.post(f"{SERVER}/verify-puzzle/{req_hash}/", json={
        "request": req,
        "validation_data": validation_data.to_dict(),
        "leaf": leaf,
        "leaf_hash": leaf_hash,
        "message": message,
        "size": size,
        "timestamp": timestamp,
    })
    validate_status_code(response)
    data = VerifyPuzzleResponse(**response.json())
    console.log(f"All done! {data}")


def perform_request_and_measure_time(payload):
    res = measure_process_time(perform_request, payload)
    console.print(f"[red]Request completed in {res[1] / 1_000_000_000:0.3f}s")


def main():
    fetch_parameters()

    number_of_tasks = 1_0
    payloads = [payload for payload in range(number_of_tasks)]  # random.randint(0, 1_000_000)

    workers = int(os.environ["WORKERS"]) if "WORKERS" in os.environ else 1
    if "PROCESS_POOL_EXECUTOR" in os.environ:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            pool.map(perform_request_and_measure_time, payloads)
    else:
        with Progress(console=console) as progress:
            sent_task = progress.add_task("[cyan]Sent tasks...", total=number_of_tasks)
            completed_task = progress.add_task("[green]Completed tasks...", total=number_of_tasks)
            failed_task = progress.add_task("[red]Failed tasks...", total=number_of_tasks)
            terminated_task = progress.add_task("[cyan]Terminated tasks...", total=number_of_tasks)

            def task(payload):
                progress.update(sent_task, advance=1)
                try:
                    perform_request_and_measure_time(payload)
                    progress.update(completed_task, advance=1)
                except ValueError:
                    progress.update(failed_task, advance=1)
                progress.update(terminated_task, advance=1)

            with ThreadPoolExecutor(max_workers=workers) as pool:
                pool.map(task, payloads)


if __name__ == "__main__":
    main()
