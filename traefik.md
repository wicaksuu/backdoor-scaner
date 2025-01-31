# Traefik Dashboard Setup Tutorial (Full Secure Configuration)

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
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: ":443"
    http:
      middlewares:
        - security-headers

api:
  dashboard: true
  insecure: false

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
    security-headers:
      headers:
        frameDeny: true
        contentTypeNosniff: true
        browserXssFilter: true
        stsSeconds: 63072000
        stsIncludeSubdomains: true
        stsPreload: true
        forceSTSHeader: true
    dashboard-auth:
      basicAuth:
        users:
          - "admin:$apr1$xyz$hashed-password" # Replace with a hashed password

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

## Step 8: Update DNS for Dashboard Access
Ensure that you add a DNS record for `traefik.example.com` pointing to your server's IP address. This is necessary to access the secure dashboard.

---

## Step 9: Verify and Test
1. **Check Traefik Logs:**
   ```bash
   docker logs -f traefik
   ```
2. **Access the Dashboard:**
   - **URL:** `https://traefik.example.com`
   - **Username:** `admin`
   - **Password:** Use the one configured in `dynamic.yml` (hashed).
3. **Ensure HTTPS is enforced** for all services and check for valid SSL certificates.

---

## Security Notes
- **Disable `insecure: true` for production** to prevent the dashboard from being exposed on HTTP.
- Use strong and hashed passwords for `basicAuth`.
- Regularly monitor and update Traefik to the latest stable version.
