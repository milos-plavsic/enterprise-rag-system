FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN useradd --system --uid 10001 --create-home appuser
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/data/uploads && chown -R appuser:appuser /app/data
USER appuser
EXPOSE 8000
CMD ["uvicorn","app.api:app","--host","0.0.0.0","--port","8000","--workers","1"]
