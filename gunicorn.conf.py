import os
import sys

# Add the project directory to Python path
project_dir = '/opt/SEU_APIM/APIM'
if project_dir not in sys.path:
    sys.path.insert(0, project_dir)

# Change to project directory
os.chdir(project_dir)

# Gunicorn configuration
bind = "0.0.0.0:8001"
workers = 3
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2
max_requests = 1000
max_requests_jitter = 100
preload_app = True