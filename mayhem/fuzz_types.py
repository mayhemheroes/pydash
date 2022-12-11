#!/usr/bin/env python3
import atheris
import logging
import sys

from typing import List, Set, Dict, Tuple, Any

with atheris.instrument_imports():
    import pydash

@atheris.instrument_func
def _handle_type(fdp: atheris.FuzzedDataProvider, ty_queue: List[type]) -> Any:
    """
    Handles the fuzzing of a single type.
    :param fdp: FuzzedDataProvider object
    :param ty_queue: The current stack of types to be used for fuzzing
    :return: The fuzzed element
    """
    if not ty_queue:
        return None
    ty = ty_queue.pop(0)
    if ty is bytes:
        return fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 100))
    elif ty is bytearray:
        return bytearray(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 100)))
    elif ty is str:
        return fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100))
    elif ty is float:
        return fdp.ConsumeRegularFloat()
    elif ty is bool:
        return fdp.ConsumeBool()
    elif ty is int:
        return fdp.ConsumeInt(4)
    elif ty is dict:
        return build_fuzz_dict(fdp, ty_queue)
    elif ty is list:
        return build_fuzz_list(fdp, ty_queue)
    elif ty is set:
        return build_fuzz_set(fdp, ty_queue)
    elif ty is tuple:
        return build_fuzz_tuple(fdp, ty_queue)
    else:
        return None

@atheris.instrument_func
def build_fuzz_list(fdp: atheris.FuzzedDataProvider, ty_queue: List[type]) -> List[Any]:
    """
    Builds a list with fuzzer-defined elements.
    :param fdp: FuzzedDataProvider object
    :param ty_queue: The current stack of types to be used for fuzzing
    :return: The list
    """
    if not ty_queue:
        return []
    elem_count = fdp.ConsumeIntInRange(1, 5)
    gen_list = []

    for _ in range(elem_count):
        passed_queue = ty_queue.copy()
        elem = _handle_type(fdp, passed_queue)
        if elem is not None:
            gen_list.append(elem)
    ty_queue.pop(0)  # Pop elem type

    return gen_list



@atheris.instrument_func
def build_fuzz_set(fdp: atheris.FuzzedDataProvider, ty_queue: List[type]) -> Set[Any]:
    """
    Builds a set with fuzzer-defined elements.
    :param fdp: FuzzedDataProvider object
    :param ty_queue: The current stack of types to be used for fuzzing
    :return: The set
    """
    if not ty_queue:
        return set()
    ty_queue.insert(0, list)

    fuzz_list = _handle_type(fdp, ty_queue)
    return set(fuzz_list)


@atheris.instrument_func
def build_fuzz_tuple(fdp: atheris.FuzzedDataProvider, ty_queue: List[type]) -> Tuple[Any]:
    """
    Builds a tuple with fuzzer-defined elements.
    :param fdp: FuzzedDataProvider object
    :param ty_queue: The current stack of types to be used for fuzzing
    :return: The tuple
    """
    if not ty_queue:
        return tuple()
    ty_queue.insert(0, list)

    fuzz_list = _handle_type(fdp, ty_queue)
    return tuple(fuzz_list)

@atheris.instrument_func
def build_fuzz_dict(fdp: atheris.FuzzedDataProvider, ty_queue: List[type]) -> Dict[Any, Any]:
    """
    Builds a dictionary with fuzzer-defined keys and values.
    :param fdp: FuzzedDataProvider object
    :param ty_queue: The current stack of types to be used for fuzzing
    :return: The dictionary
    """
    if not ty_queue:
        return {}

    ty_queue.insert(0, list)  # handle key
    key_list = _handle_type(fdp, ty_queue)
    ty_queue.insert(0, list)  # handle key
    val_list = _handle_type(fdp, ty_queue)

    # Shrink lists to match
    if len(key_list) > len(val_list):
        key_list = key_list[:len(val_list)]
    elif len(val_list) > len(key_list):
        val_list = val_list[:len(key_list)]

    return dict(zip(key_list, val_list))

@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    pydash.flatten(build_fuzz_list(fdp, [list, list, int]))
    pydash.flatten_deep(build_fuzz_list(fdp, [list, list, int]))
    pydash.map_(build_fuzz_list(fdp, [dict, str, str]), fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100)))
    curried = pydash.curry(lambda a, b, c: a + b + c)
    curried(fdp.ConsumeInt(4), fdp.ConsumeInt(4))(fdp.ConsumeInt(4))
    pydash.omit(build_fuzz_dict(fdp, [str, str]), fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100)))
    pydash.chain(build_fuzz_list(fdp, [int])).without(fdp.ConsumeInt(4), fdp.ConsumeInt(4)).reject(lambda x: x > fdp.ConsumeInt(4)).value()

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
if __name__ == '__main__':
    main()
