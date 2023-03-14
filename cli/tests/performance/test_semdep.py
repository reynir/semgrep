from pathlib import Path
from time import time

import pytest


@pytest.mark.parametrize(
    "file_size,target,max_time",
    [
        (file_size, target, max_time)
        # These times are set relative to Github Actions, they should be lower when running locally
        # Local time expectation is more like 1, 5, 10
        for file_size, max_time in [("10k", 3), ("50k", 15), ("100k", 30)]
        for target in [
            "Gemfile.lock",
            "go.sum",
            "gradle.lockfile",
            "maven_dep_tree.txt",
            "package-lock.json",
            "poetry.lock",
            "requirements.txt",
            "yarn.lock",
            "Pipfile.lock",
        ]
    ],
)
def test_dependency_aware_timing(
    parse_lockfile_path_in_tmp, file_size, target, max_time
):
    start = time()
    parse_lockfile_path_in_tmp(
        Path(f"targets/dependency_aware/perf/{file_size}/{target}")
    )
    end = time()
    exec_time = end - start
    assert exec_time < max_time