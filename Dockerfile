FROM golang:1.25-bookworm AS tools

ENV GOTOOLCHAIN=auto

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libpcap0.8 && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --from=tools /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=tools /go/bin/naabu /usr/local/bin/naabu
COPY --from=tools /go/bin/httpx /usr/local/bin/httpx

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
