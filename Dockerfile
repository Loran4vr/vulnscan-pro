FROM node:22-slim

# Install Go and tools
RUN apt-get update && apt-get install -y curl unzip openssl chromium && \
    curl -sL https://go.dev/dl/go1.22.0.linux-amd64.tar.gz | tar -C /usr/local -xzf - && \
    export PATH=$PATH:/usr/local/go/bin && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/v2/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    cp ~/go/bin/* /usr/local/bin/ && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ENV PATH=$PATH:/usr/local/go/bin

WORKDIR /app
COPY package.json bot/package.json* ./
RUN npm install && cd bot && npm install 2>/dev/null || true

COPY . .

EXPOSE 3000

# Run both bot and web server
CMD ["sh", "-c", "node bot/index.js & node web-server.js & wait"]
