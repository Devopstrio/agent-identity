FROM python:3.12-slim

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y gcc postgresql-client && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY pyproject.toml .
RUN pip install .

# Copy application code
COPY src/ src/

# Run the API
CMD ["python", "src/agent_identity/main.py"]
