FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RADAR_PORT=3000

WORKDIR /app

# Устанавливаем зависимости проекта, если requirements.txt существует.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Копируем приложение после зависимостей для лучшего cache hit.
COPY . .

# Не запускаем приложение от root.
RUN useradd --create-home --shell /usr/sbin/nologin radar \
    && chown -R radar:radar /app

USER radar

EXPOSE 3000

CMD ["python", "run.py"]