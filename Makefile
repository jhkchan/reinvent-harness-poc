# reinvent-harness-poc -- Makefile
# Targets: setup (venv + deps), test (offline pytest), demo (live Bedrock),
# test-live (adds the live Bedrock tests), sandbox-live (rail 6, live MicroVM),
# agentcore-live (rails 1, 2, 4 and 5 on a live AgentCore harness + Gateway).
#
# Credentials come from the default AWS credential chain. To use a named
# profile, export AWS_PROFILE in your shell before running make.

PY ?= python3
VENV := .venv
BIN := $(VENV)/bin
AWS_REGION ?= us-east-1

.PHONY: setup demo test test-live sandbox-live sandbox-cleanup-check \
	agentcore-live agentcore-cleanup-check clean

setup:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -r requirements.txt
	@echo "setup done. Run 'make test' or 'make demo'."

demo:
	AWS_REGION=$(AWS_REGION) $(BIN)/python -m harness.demo

# Fast + free: no AWS calls (fake Bedrock and fake MicroVM clients).
test:
	$(BIN)/python -m pytest -q

# Opt-in: also runs the live Bedrock judge tests.
test-live:
	HARNESS_LIVE=1 AWS_REGION=$(AWS_REGION) $(BIN)/python -m pytest -q

# Rail 6 live: creates one MicroVM image + microVM + 2 IAM roles + 1 S3
# bucket (all prefixed harness-sandbox-), runs one tiny script, tears all of
# it down, then writes logs/sandbox.log and logs/sandbox-cleanup.log.
sandbox-live:
	AWS_REGION=$(AWS_REGION) $(BIN)/python -m harness.sandbox

# List anything left with the harness-sandbox prefix (must be 0).
sandbox-cleanup-check:
	AWS_REGION=$(AWS_REGION) $(BIN)/python -c "from harness.sandbox import cleanup_check, SandboxLog; import sys; sys.exit(1 if cleanup_check(log=SandboxLog())['total'] else 0)"

# Rails on AgentCore, live: creates one AgentCore harness, Gateway + Lambda
# target, Policy engine + 3 Cedar policies, 2 Lambda functions, 1 DynamoDB
# table and 4 IAM roles (all named harness-agentcore / harness_agentcore),
# runs the scenarios, tears all of it down, then writes logs/agentcore.log
# and logs/agentcore-cleanup.log.
agentcore-live:
	AWS_REGION=$(AWS_REGION) $(BIN)/python -m harness.agentcore

# List anything left with the harness-agentcore names (must be 0).
agentcore-cleanup-check:
	AWS_REGION=$(AWS_REGION) $(BIN)/python -c "from harness.agentcore import cleanup_check; from harness.sandbox import SandboxLog; import sys; sys.exit(1 if cleanup_check(log=SandboxLog())['total'] else 0)"

clean:
	rm -rf $(VENV) .pytest_cache harness/__pycache__ tests/__pycache__
