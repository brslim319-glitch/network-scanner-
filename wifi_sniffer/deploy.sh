#!/bin/bash
set -e

# Variables
APP_DIR="$(dirname $(realpath $0))/websniffer"
DOMAIN="bomba.io"
EMAIL="brslim319@gmail.com"

# Update and install dependencies
sudo apt update
sudo apt install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx postgresql postgresql-contrib

# Set up Python virtual environment
cd "$APP_DIR"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r ../requirements.txt

# Set up PostgreSQL
sudo -u postgres psql -c "CREATE USER snifferuser WITH PASSWORD 'snifferpass';"
sudo -u postgres psql -c "CREATE DATABASE snifferdb OWNER snifferuser;"

# Update config.py for PostgreSQL
sed -i "s|SQLALCHEMY_DATABASE_URI = .*|SQLALCHEMY_DATABASE_URI = 'postgresql://snifferuser:snifferpass@localhost/snifferdb'|" $APP_DIR/config.py

# Run DB migrations
python3 -c 'from app import db, app; with app.app_context(): db.create_all()'

# Create systemd service for Gunicorn
sudo tee /etc/systemd/system/websniffer.service > /dev/null <<EOL
[Unit]
Description=Gunicorn instance to serve websniffer
After=network.target

[Service]
User=$USER
Group=www-data
WorkingDirectory=$APP_DIR
Environment="PATH=$APP_DIR/venv/bin"
ExecStart=$APP_DIR/venv/bin/gunicorn --worker-class eventlet -w 1 -b 127.0.0.1:5000 wsgi:app

[Install]
WantedBy=multi-user.target
EOL

sudo systemctl daemon-reload
sudo systemctl enable websniffer
sudo systemctl start websniffer

# Configure Nginx
sudo tee /etc/nginx/sites-available/websniffer > /dev/null <<EOL
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOL

sudo ln -sf /etc/nginx/sites-available/websniffer /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Obtain SSL certificate
sudo certbot --nginx -d $DOMAIN --email $EMAIL --agree-tos --non-interactive

# Done
echo "Deployment complete. Visit https://$DOMAIN" 