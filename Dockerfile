FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GROK_REG_DATA_DIR=/app/data \
    GROK_REG_IN_DOCKER=1 \
    GROK_REG_HEADLESS=0 \
    TZ=Asia/Shanghai

WORKDIR /app

# amd64 安装 Google Chrome（反检测更友好），arm64 回退到 Chromium
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget gnupg \
    && if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg \
        && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list \
        && apt-get update \
        && apt-get install -y --no-install-recommends google-chrome-stable \
        && ln -sf /usr/bin/google-chrome-stable /usr/bin/browser; \
    else \
        apt-get install -y --no-install-recommends chromium \
        && ln -sf /usr/bin/chromium /usr/bin/browser; \
    fi \
    && apt-get install -y --no-install-recommends \
        fonts-noto-cjk \
        fonts-liberation \
        fonts-dejavu-core \
        fonts-noto-color-emoji \
        libasound2 \
        libatk-bridge2.0-0 \
        libgtk-3-0 \
        libnss3 \
        libx11-xcb1 \
        libxcomposite1 \
        libxdamage1 \
        libxrandr2 \
        libgbm1 \
        libu2f-udev \
        xauth \
        xvfb \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

ENV CHROME_BIN=/usr/bin/browser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/data

EXPOSE 8787

CMD ["uvicorn", "web_app:app", "--host", "0.0.0.0", "--port", "8787"]
