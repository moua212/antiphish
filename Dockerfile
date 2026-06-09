# Base image
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Prevent pip/Poetry timeouts
ENV PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=10 \
    POETRY_REQUESTS_TIMEOUT=120

# System deps
RUN apt-get update && apt-get install -y \
    git \
    iputils-ping \
    dnsutils \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app/phishing_model.pkl /app/app/

# Upgrade pip tools (IMPORTANT for numpy/pandas wheels)
RUN pip install --upgrade pip setuptools wheel

# Install Poetry
RUN pip install poetry

# Avoid creating virtualenv inside Docker
RUN poetry config virtualenvs.create false

# Copy dependency files first (better cache usage)
COPY pyproject.toml poetry.lock ./

# Install dependencies (more stable flags)
RUN poetry install --no-root --no-interaction --no-ansi

# Copy application code
COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]