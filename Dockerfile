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

COPY . .

EXPOSE 8080

CMD Xvfb :99 -screen 0 1920x1080x24 & python app.py
