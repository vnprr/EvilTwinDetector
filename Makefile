# Everyday commands. Python runs through uv (https://docs.astral.sh/uv/), the dashboard through npm.

DEMO := /tmp/wiguard-demo
FIXTURES := tests/pcap_fixtures/synthetic

.PHONY: install check lint types test api-types demo

install:            ## Python and dashboard dependencies, exactly as locked
	uv sync --frozen
	cd dashboard && npm ci

check: lint types test  ## everything CI runs

lint:
	uv run ruff check src tests
	uv run ruff format --check src tests
	cd dashboard && npm run lint

types:
	uv run mypy
	cd dashboard && npm run typecheck

test:
	uv run pytest
	cd dashboard && npm test

api-types:          ## regenerate the dashboard's TypeScript types after changing the API
	uv run wiguard api --print-openapi > dashboard/openapi.json
	cd dashboard && npm run api:types

demo:               ## replay the classic Evil Twin scenario and serve it to the dashboard
	uv run wiguard enroll --pcap $(FIXTURES)/enroll_home.pcap --output $(DEMO)/profiles.json
	rm -f $(DEMO)/state.db
	uv run wiguard replay $(FIXTURES)/classic_evil_twin.pcap --profiles $(DEMO)/profiles.json --state-path $(DEMO)/state.db --step 1
	uv run wiguard api --profiles $(DEMO)/profiles.json --state-path $(DEMO)/state.db
