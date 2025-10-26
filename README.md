# megalodon

A tshark web interface for huge pcaps.

## Running the test suite

The project uses `pytest` with `pytest-django`. Install the project in editable mode with the
optional testing dependencies and then execute the tests:

```bash
python -m pip install --upgrade pip
pip install -e .[test]
pytest
```

Tests expect a PostgreSQL database by default. The CI workflow provisions PostgreSQL automatically.
For local development you can opt into an on-disk SQLite database instead:

```bash
DJANGO_USE_SQLITE=1 pytest
```

## Continuous integration

The GitHub Actions workflow defined in [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
installs the package with the testing extras, starts PostgreSQL via a service container, runs
Django migrations, and executes the pytest suite. The workflow triggers on pushes to the `main`
branch and for every pull request.

## Publishing to PyPI

Packaging is driven by `pyproject.toml` using `setuptools`. Two helper scripts are provided:

- `scripts/build` installs `build` and produces source + wheel artifacts under `dist/`.
- `scripts/publish` installs the release tooling, rebuilds the artifacts, and uploads them via
  `twine`. Set `TWINE_USERNAME` and `TWINE_PASSWORD` in the environment before invoking it.

Typical release flow:

```bash
# Ensure version metadata in pyproject.toml is up to date
./scripts/build
./scripts/publish  # requires PyPI credentials in TWINE_USERNAME/TWINE_PASSWORD
```
