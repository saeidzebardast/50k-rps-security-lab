FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./
RUN useradd -r app
USER app
EXPOSE 8000
# Overridden per service in docker-compose.yml
CMD ["uvicorn", "vulnerable:app", "--host", "0.0.0.0", "--port", "8000"]
