FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Debug: List the build context
RUN echo "Build context contents:"
COPY . .
RUN find /app -type f -name "*.py" | sort

# Create a symbolic link for imports
RUN ln -s /app /app/api

# Debug: Print the directory structure to verify
RUN echo "Directory structure after copying:"
RUN ls -la && ls -la /app/api

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]