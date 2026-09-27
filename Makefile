install:
	python -m pip install -r requirements.txt

run-lab:
	uvicorn lab.vulnerable_app:app --reload --port 8001

run-app:
	uvicorn app.main:app --reload --port 8000

test:
	python -m pytest -q
