FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Standard isolated install — pip fetches its own fresh copy of the
# build backend (setuptools/wheel) regardless of what's already in the
# image. Slightly slower than --no-build-isolation but doesn't depend
# on requirements.txt having installed an exactly-compatible backend
# first, which is what broke this step twice before.
RUN pip install --no-cache-dir -e .
ENTRYPOINT ["python", "-m", "xetra.cli"]
CMD ["run", "--config", "config/config.yaml"]
