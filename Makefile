PYTHON ?= python

.PHONY: help install install-dev test env experiment clean

help:
	@echo "AEX-TFANET targets:"
	@echo "  make install       pip install -e ."
	@echo "  make install-dev   pip install -e .[dev]"
	@echo "  make test          run pytest"
	@echo "  make env           probe local environment"
	@echo "  make experiment    run Phase-1 experiment scaffold"

install:
	$(PYTHON) -m pip install -e .

install-dev:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest

env:
	$(PYTHON) -m aex_tfanet env

experiment:
	$(PYTHON) -m aex_tfanet experiment --config experiments/configs/normal.yaml

clean:
	$(PYTHON) -c "import pathlib, shutil; [shutil.rmtree(p, ignore_errors=True) for p in map(pathlib.Path, ['.pytest_cache','htmlcov','src/aex_tfanet.egg-info'])]"
