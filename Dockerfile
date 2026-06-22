FROM python:3.12-slim
WORKDIR /app
COPY guard ./guard
COPY http_mcp.py ./
ENV PORT=8080
EXPOSE 8080
CMD ["python", "http_mcp.py"]
