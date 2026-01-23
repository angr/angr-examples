#!/usr/bin/env python3

import os
import unittest

import angr
import claripy
from angr.rustylib.fuzzer import Fuzzer, InMemoryCorpus, ClientStats
from angr import sim_options as so


def create_corpus():
    return [
        b"<!DOCTYPE a [<!ENTITY x 'y'>]><a>&y;</a>",  # one byte flip ('y'->'x') enables entity resolution path
    ]


def apply_fn(state: angr.SimState, data: bytes) -> None:
    # Arrange a recognizable return address
    p = state.project
    if p is not None:
        ra = p.factory.cc().return_addr
        if ra is not None:
            ra.set_value(state, 0xDEADBEEF)
    s = state.posix.stdin
    s.content = [(claripy.BVV(data), claripy.BVV(len(data), state.arch.bits))]
    if hasattr(s, "pos"):
        s.pos = 0


# SEED VALUE NEEDED FOR TEST
def main(verbose=True, seed=12751):
    target = os.path.join(os.path.dirname(__file__), "xmllint_bin")

    # xmllint CLI: read from stdin with '-' and keep output quiet/nonet
    xmllint_args = [target, "--noout", "--nonet", "--recover", "--noent", "-"]

    project = angr.Project(target, auto_load_libs=True, use_sim_procedures=False)
    base_state = project.factory.entry_state(
        args=xmllint_args,
        add_options={
            so.ZERO_FILL_UNCONSTRAINED_MEMORY,
            so.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )

    corpus = InMemoryCorpus.from_list(create_corpus())
    solutions = InMemoryCorpus()

    fuzzer = Fuzzer(
        base_state=base_state,
        apply_fn=apply_fn,
        corpus=corpus,
        solutions=solutions,
        timeout=0,
        seed=seed,
    )

    def progress_callback(stats: ClientStats, type_: str, _client_id: int):
        msg = (
            f"[{type_}] "
            f"C: {stats.corpus_size}, O: {stats.objective_size}, "
            f"E: {stats.executions}, E/s: {stats.execs_per_sec_pretty}, "
            f"Cov: {stats.edges_hit}/{stats.edges_total}"
        )
        print(msg)

    before = len(fuzzer.corpus())
    idx = fuzzer.run_once(progress_callback=progress_callback if verbose else None)
    after = len(fuzzer.corpus())
    # take last mutation (should be the new one)
    new_input = fuzzer.corpus()[after - 1]
    if verbose:
        print(f"Corpus now has {len(fuzzer.corpus())} inputs.")
        print(f"Corpus inputs: \n{fuzzer.corpus().to_bytes_list()}")
        print(f"Found {len(fuzzer.solutions())} solutions.")
        print(f"Found the following solutions: \n{fuzzer.solutions().to_bytes_list()}")
    return idx, before, after, new_input


@unittest.skip("disabled")
def test():
    idx, before, after, new_input = main(verbose=False)
    # Basic corpus growth sanity checks
    assert after == before + 1
    assert 0 <= idx < after

    # Desired mutation check: change entity reference '&y;' -> '&x;'
    expected = b"<!DOCTYPE a [<!ENTITY x 'y'>]><a>&x;</a>"
    assert new_input == expected
    return True


# looks for right seed to get deterministic answer
def search_for_seed():
    seed = 1
    expected = b"<!DOCTYPE a [<!ENTITY x 'y'>]><a>&x;</a>"
    while True:
        print(f"Attempting Seed: {seed}")
        _, _, _, new_input = main(verbose=False, seed=seed)
        if expected == new_input:
            print(f"Found Seed: {seed}")
            break
        seed += 1


if __name__ == "__main__":
    main()
