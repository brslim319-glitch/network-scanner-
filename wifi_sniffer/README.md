# WiFi Sniffer Web App

## Production Deployment

1. Edit `deploy.sh` and set your domain and email:
   - `DOMAIN="yourdomain.com"`
   - `EMAIL="admin@yourdomain.com"`
2. Run the deployment script:
   ```bash
   chmod +x deploy.sh
   ./deploy.sh
   ```
3. The script will:
   - Install all dependencies
   - Set up Python venv and install requirements
   - Set up PostgreSQL and update config
   - Run DB migrations
   - Configure Gunicorn with eventlet
   - Set up Nginx as a reverse proxy
   - Obtain and configure HTTPS with Certbot
   - Start the app as a systemd service

Visit `https://yourdomain.com` after completion. 