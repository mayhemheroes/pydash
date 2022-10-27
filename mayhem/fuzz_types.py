#! /usr/bin/python3
import atheris
import logging
import sys
with atheris.instrument_imports():
    import pydash
    from fuzz_helpers import build_fuzz_dict, build_fuzz_list

@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    pydash.flatten(build_fuzz_list(fdp, [list, list, int]))
    pydash.flatten_deep(build_fuzz_list(fdp, [list, list, int]))
    pydash.map_(build_fuzz_list(fdp, [dict, str, str]), fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100)))
    curried = pydash.curry(lambda a, b, c: a + b + c)
    curried(fdp.ConsumeInt(4), fdp.ConsumeInt(4))(fdp.ConsumeInt(4))
    pydash.omit(build_fuzz_dict(fdp, [str, str]), fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100)))
    pydash.times(fdp.ConsumeInt(4), lambda index: index)
    pydash.chain(build_fuzz_list(fdp, [int])).without(fdp.ConsumeInt(4), fdp.ConsumeInt(4)).reject(lambda x: x > fdp.ConsumeInt(4)).value()

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
if __name__ == '__main__':
    main()