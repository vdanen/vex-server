# Running vex-server in Podman

This guide explains how to run the vex-server application in a Podman container.

## Prerequisites

- Podman installed on your system
- Podman Compose (optional, for easier management)

## Quick Start

### Using Podman directly

1. **Build the container image:**
   ```bash
   podman build -t vex-server .
   ```

2. **Create instance directory:**
   ```bash
   mkdir -p instance
   ```

3. **Create configuration file:**
   ```bash
   cp instance/config.py.example instance/config.py
   # Edit instance/config.py with your settings
   ```

4. **Run the container:**
   ```bash
   podman run -d \
     --name vex-server \
     -p 8080:8080 \
     -v ./instance:/app/instance \
     vex-server
   ```

5. **Access the application:**
   Open your browser to `http://localhost:8080`

### Using Podman Compose

1. **Create instance directory and config:**
   ```bash
   mkdir -p instance
   cp instance/config.py.example instance/config.py
   # Edit instance/config.py with your settings
   ```

2. **Build and start:**
   ```bash
   podman-compose up -d
   ```

3. **View logs:**
   ```bash
   podman-compose logs -f
   ```

4. **Stop the container:**
   ```bash
   podman-compose down
   ```

## Configuration

The application requires a configuration file at `instance/config.py`. Copy the example file and customize it:

```bash
cp instance/config.py.example instance/config.py
```

Important settings:
- `CACHE_DIRECTORY`: Should be `/app/cache` (default in container)
- `SECRET_KEY`: Set a secure secret key
- `VULNCHECK_API_TOKEN`: Optional, for VulnCheck KEV lookups

## Volumes

The container uses one volume mount:
- `./instance:/app/instance` - Contains configuration file

Note: The cache directory is created inside the container and will be cleared on each container restart.

## Ports

The application listens on port 8080 inside the container (port 5000 is blocked by Chrome/Safari). The default mapping exposes it on `localhost:8080`. You can change the host port by modifying the port mapping:

```bash
podman run -p 3000:8080 ...
```

Or in `container-compose.yml`:
```yaml
ports:
  - "3000:8080"
```

## Troubleshooting

- **Check container logs:**
  ```bash
  podman logs vex-server
  ```

- **Check if container is running:**
  ```bash
  podman ps
  ```

- **Access container shell:**
  ```bash
   podman exec -it vex-server /bin/bash
  ```


