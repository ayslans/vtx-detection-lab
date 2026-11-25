.PHONY: install test cov validate replay docker-replay clean

install:
	pip install -e ".[dev]"

test:
	pytest -v

cov:
	pytest --cov=vtx_detection_lab --cov-report=term-missing

validate:
	python -m vtx_detection_lab.main validate

replay:
	python -m vtx_detection_lab.main replay --strict

docker-replay:
	docker compose --profile replay up --build --abort-on-container-exit

clean:
	rm -rf .pytest_cache .coverage htmlcov build dist src/*.egg-info
	find . -type d -name "__pycache__" -exec rm -rf {} +
