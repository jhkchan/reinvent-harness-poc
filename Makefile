# reinvent-harness-poc -- Makefile
# Targets: setup (venv + deps), demo (live Bedrock), test (pytest).

PY ?= python3
VENV := .venv
BIN := $(VENV)/bin
AWS_PROFILE ?= voteetech
AWS_REGION ?= us-east-1

.PHONY: setup demo test test-live clean

setup:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install boto3 opentelemetry-sdk pytest
	@echo "setup done. Run 'make demo' or 'make test'."

demo:
	AWS_PROFILE=$(AWS_PROFILE) AWS_REGION=$(AWS_REGION) $(BIN)/python -m harness.demo

# Fast + free: hard-check + judge tests use a fake Bedrock client.
test:
	$(BIN)/python -m pytest -q

# Opt-in: also runs the live Bedrock judge test.
test-live:
	HARNESS_LIVE=1 AWS_PROFILE=$(AWS_PROFILE) AWS_REGION=$(AWS_REGION) $(BIN)/python -m pytest -q

clean:
	rm -rf $(VENV) .pytest_cache **/__pycache__ harness/__pycache__ tests/__pycache__
