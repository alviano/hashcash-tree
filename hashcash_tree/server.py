import datetime
import os
import random
import uuid
from builtins import Exception

import numpy as np
from dumbo_utils.console import console
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.responses import JSONResponse
from typing_extensions import Final
from valid8 import validate

from hashcash_tree.primitives import HashFunction, UINT, HashcashTree

HASH_FUNCTION: Final = HashFunction.sha256()
PREFIX_LENGTH: Final = int(os.environ["PREFIX_LENGTH"]) if "PREFIX_LENGTH" in os.environ else 4

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:80"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


MASTER_KEY: Final = bytes.fromhex(os.environ["MASTER_KEY"]) if "MASTER_KEY" in os.environ else uuid.uuid4().bytes
# console.log("MASTER_KEY:", MASTER_KEY.hex())
ALLOTTED_TIME: Final = int(os.environ["ALLOTTED_TIME"]) if "ALLOTTED_TIME" in os.environ else 10
DIFFICULTY: Final = os.environ["DIFFICULTY"] if "DIFFICULTY" in os.environ else 15


class ParametersResponse(BaseModel):
    allotted_time: int
    prefix_length: int


class GeneratePuzzleResponse(BaseModel):
    message: str
    size: int
    timestamp: float


class PuzzleSolvedModel(BaseModel):
    solution: str
    message: str
    size: int
    timestamp: float


class PuzzleSolvedResponse(BaseModel):
    leaf: int
    leaf_hash: str


class VerifyPuzzleModel(BaseModel):
    request: str
    validation_data: dict[int, (tuple[str] | tuple[str, int])]
    leaf: int
    leaf_hash: str
    message: str
    size: int
    timestamp: float


class VerifyPuzzleResponse(BaseModel):
    status: str
    result: str


@app.get("/parameters/")
async def parameters() -> ParametersResponse:
    return ParametersResponse(
        allotted_time=ALLOTTED_TIME,
        prefix_length=PREFIX_LENGTH,
    )


@app.get("/generate-puzzle/{request_hash}/")
async def generate_puzzle(request_hash: str) -> GeneratePuzzleResponse:
    size = DIFFICULTY
    timestamp = np.float64((datetime.datetime.now() + datetime.timedelta(seconds=ALLOTTED_TIME)).timestamp())

    return GeneratePuzzleResponse(
        message=HASH_FUNCTION.apply(MASTER_KEY + bytes.fromhex(request_hash) + UINT(size) + timestamp).hex(),
        size=size,
        timestamp=timestamp,
    )


def __validate_message(request_hash, data):
    timestamp = np.float64(data.timestamp)
    validate("timestamp", timestamp, min_value=np.float64(datetime.datetime.now().timestamp()),
             help_msg="The puzzle expired. Try again.")
    validate("message", data.message, equals=HASH_FUNCTION.apply(MASTER_KEY + bytes.fromhex(request_hash) +
                                                                 UINT(data.size) + timestamp).hex(),
             help_msg="Message signature corrupted.")


@app.post("/puzzle-solved/{request_hash}/")
async def puzzle_solved(request_hash: str, data: PuzzleSolvedModel) -> PuzzleSolvedResponse:
    __validate_message(request_hash, data)

    leaf = random.randint(1, int(np.power(2, np.floor(np.log2(data.size)))))
    leaf_hash = HASH_FUNCTION.apply(MASTER_KEY + bytes.fromhex(request_hash) + bytes.fromhex(data.solution) + UINT(leaf))
    console.log(f"Valid data in puzzle_solved. Ask for leaf #{leaf}")

    return PuzzleSolvedResponse(
        leaf=leaf,
        leaf_hash=leaf_hash.hex(),
    )


@app.post("/verify-puzzle/{request_hash}/")
async def verify_puzzle(request_hash: str, data: VerifyPuzzleModel) -> VerifyPuzzleResponse:
    __validate_message(request_hash, data)
    validate("leaf_hash", data.leaf_hash,
             equals=HASH_FUNCTION.apply(MASTER_KEY + bytes.fromhex(request_hash) +
                                        bytes.fromhex(data.validation_data[1][0]) + UINT(data.leaf)).hex(),
             help_msg="Leaf signature corrupted.")
    console.log("Valid data in verify_puzzle. Checking the hashcash tree...")

    hashcash_tree = HashcashTree.of(prefix_length=PREFIX_LENGTH, size=UINT(data.size), hash_function=HASH_FUNCTION)
    validate("hashcash_tree", hashcash_tree.verify(
        message=data.message.encode(),
        leaf_index=data.leaf,
        digests_and_witnesses=HashcashTree.ValidationData.of_dict(data.validation_data)
    ), equals=True, help_msg="Hashcash tree validation failed.")

    console.log("Valid hashcash tree. Serving the request...")

    validate("request_hash", request_hash, equals=HASH_FUNCTION.apply(data.request.encode()).hex(),
             help_msg="The hash value of the request is invalid.")

    return VerifyPuzzleResponse(
        status="complete",
        result=data.request,
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=406,
        content={"message": f"Oops! {exc.get_help_msg() if hasattr(exc, 'get_help_msg') else 'Something went wrong.'}"},
    )
