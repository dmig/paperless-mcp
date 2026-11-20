FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY paperless_mcp_oidc ./paperless_mcp_oidc

RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 mcp \
    && mkdir -p /home/mcp/outbox /home/mcp/auth \
    && chmod 700 /home/mcp/auth \
    && chown -R mcp:mcp /home/mcp

USER 10001
ENV DIRECT_AUTH_DB_PATH=/home/mcp/auth/paperless-mcp-auth.sqlite3

EXPOSE 8000

CMD ["paperless-mcp-oidc"]
