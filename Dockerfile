# PhishLens — production image for DeployXA (or any Docker host).
# Builds the trained model at image-build time: datasets are downloaded
# (they are not committed to the repo) and scripts/train.py retrains the
# Random Forest, so the deployed app never needs the model file shipped.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Fetch training data (public feeds), train the model, warm up the checker
# (first SHAP call compiles numba — do it at build time so the first live
# user request is fast instead of hanging for minutes on a throttled CPU),
# then collect static files.
RUN mkdir -p data \
    && curl --retry 3 -fsSL -o data/online-valid.csv http://data.phishtank.com/data/online-valid.csv \
    && curl --retry 3 -fsSL -o data/top-1m.csv.zip https://tranco-list.eu/top-1m.csv.zip \
    && python scripts/train.py \
    && python -c "import django, os; os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'phishlens.settings'); django.setup(); from detector import model; model.check_url('https://example.com'); print('warm-up done')" \
    && python manage.py collectstatic --noinput \
    && python manage.py migrate --noinput

# One worker: the model + SHAP are heavy for a 512 MB free plan.
CMD ["sh", "-c", "gunicorn phishlens.wsgi:application --bind 0.0.0.0:${PORT:-8000} --workers 1 --threads 4 --timeout 120"]
