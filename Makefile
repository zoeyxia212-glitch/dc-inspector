.PHONY: install lint fmt typecheck test cov check run bench audit

install:      ## dev environment
	pip install -e ".[dev]"

lint:         ## ruff lint + format check
	ruff check .
	ruff format --check .

fmt:          ## auto-fix lint and format
	ruff check --fix .
	ruff format .

typecheck:
	mypy

test:
	pytest -q

cov:          ## tests with the coverage gate used in CI
	pytest --cov --cov-report=term

audit:        ## known vulnerabilities in dependencies
	pip-audit -r requirements.txt --strict

check: lint typecheck cov   ## everything CI runs on a PR

run:          ## local dev server on http://127.0.0.1:8000
	python -m inspector.main init
	python -m inspector.main server

bench:
	python scripts/benchmark.py --hosts 2000 --rounds 10
