FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    tor \
    wget \
    gnupg \
    unzip \
    curl \
    chromium \
    chromium-driver \
    xvfb \
    && rm -rf /var/lib/apt/lists/*

ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMEDRIVER_PATH=/usr/bin/chromedriver
ENV DISPLAY=:99

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Bake a real browser engine into the image so the bot never falls back to raw HTTP.
RUN python -m playwright install chromium && python -m playwright install-deps chromium

COPY . .

EXPOSE 8080

CMD Xvfb :99 -screen 0 1920x1080x24 & python app.py
