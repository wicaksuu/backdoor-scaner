# Traefik Dashboard Setup Tutorial

## Step 1: Prerequisites
Make sure you have the following installed on your server:
- Docker
- Docker Compose
- A public-facing domain name (e.g., `example.com`) with DNS pointing to your server's IP address.
- Ports `80` and `443` open on your server firewall.

---

## Step 2: Directory Setup
Create a dedicated directory for Traefik and navigate into it:

```bash
mkdir -p ~/traefik && cd ~/traefik
```

---

## Step 3: Create `docker-compose.yml`
Create a file named `docker-compose.yml` with the following content:

```yaml
version: "3.8"

services:
  traefik:
    image: "traefik:v2.10"
    container_name: "traefik"
    restart: always
    ports:
      - "80:80"         # HTTP traffic
      - "443:443"       # HTTPS traffic
      - "8080:8080"     # Traefik dashboard
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"   # Access Docker for auto service discovery
      - "./traefik.yml:/etc/traefik/traefik.yml:ro"      # Main configuration file
      - "./dynamic.yml:/etc/traefik/dynamic.yml:ro"      # Dynamic configurations for routes and middlewares
      - "./letsencrypt:/letsencrypt"                    # Persistent volume for SSL certificates
    networks:
      - traefik

networks:
  traefik:
    name: traefik_network
    driver: bridge
```

---

## Step 4: Create `traefik.yml`
Create a file named `traefik.yml` to define the main configuration for Traefik:

```yaml
global:
  checkNewVersion: true
  sendAnonymousUsage: false

entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

api:
  dashboard: true
  insecure: true  # Use only for testing. Disable in production.

providers:
  docker:
    endpoint: "unix:///var/run/docker.sock"
    exposedByDefault: false
  file:
    filename: "/etc/traefik/dynamic.yml"

certificatesResolvers:
  letsencrypt:
    acme:
      email: "admin@example.com" # Replace with your email
      storage: "/letsencrypt/acme.json"
      httpChallenge:
        entryPoint: web
```

---

## Step 5: Create `dynamic.yml`
Create a file named `dynamic.yml` to define dynamic configurations, such as middleware and routing rules:

```yaml
http:
  middlewares:
    redirect-to-https:
      redirectScheme:
        scheme: https
    security-headers:
      headers:
        frameDeny: true
        contentTypeNosniff: true
        browserXssFilter: true
        stsSeconds: 63072000
        stsIncludeSubdomains: true
        stsPreload: true
```

---

## Step 6: Create Persistent Volume for SSL Certificates
Create a directory for storing SSL certificates:

```bash
mkdir -p ./letsencrypt
chmod 600 ./letsencrypt
```

---

## Step 7: Start Traefik
Launch Traefik with Docker Compose:

```bash
docker compose up -d
```

---

## Step 8: Access the Dashboard
- By default, the dashboard is accessible at:
  - **`http://<your-server-ip>:8080/dashboard/`**
- If using a domain, update DNS to point to your server, and configure Traefik to expose the dashboard through a specific subdomain (e.g., `traefik.example.com`).

---

## Step 9: (Optional) Configure Secure Access to Dashboard
1. Disable `insecure: true` in `traefik.yml`.
2. Add authentication middleware in `dynamic.yml`:

```yaml
http:
  middlewares:
    dashboard-auth:
      basicAuth:
        users:
          - "admin:$apr1$xyz$hash-password"
```

3. Update the router in `dynamic.yml` to use this middleware:

```yaml
http:
  routers:
    dashboard:
      rule: "Host(`traefik.example.com`)"
      service: api@internal
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt
      middlewares:
        - dashboard-auth
```

---

## Step 10: Verify and Test
- Check the Traefik logs for errors:

```bash
docker logs -f traefik
```

- Verify the dashboard is working and SSL certificates are generated correctly.
