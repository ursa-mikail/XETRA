FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Standard isolated install — pip fetches its own build backend.
RUN pip install --no-cache-dir -e .
EXPOSE 8420
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8420/healthz')"
ENTRYPOINT ["python", "-m", "xetra.cli"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8420", "--evidence-dir", "evidence_output", "--config", "config/config.yaml"]
