FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright PORT=10000
WORKDIR /app
RUN pip install --no-cache-dir flask==3.1.2 gunicorn==23.0.0 playwright==1.56.0 && python -m playwright install --with-deps chromium && useradd -m lookup
COPY cloud_server.py local_server.py provider_pages.py ./
COPY src/page-extract.js ./src/page-extract.js
USER lookup
CMD ["sh","-c","exec gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 150 cloud_server:app"]
