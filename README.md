# Cerberus

A network sentinel project for analyzing devices on a local network and discovering vulnerabilities.

## Local Testing Environment

The Docker Compose configuration creates an isolated network containing several test targets:

- Nginx: `172.28.0.10`
- Redis: `172.28.0.20`
- DVWA: `172.28.0.30`

Start the test environment with:

```bash
docker compose up -d
```

Scanners that need to access them should run in a container connected to the `sentinel-net` network. DVWA is intentionally vulnerable and should only be used in this isolated local testing environment.