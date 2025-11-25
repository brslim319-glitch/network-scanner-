import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Application settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here')
    DEBUG = True
    
    # Network interface settings
    INTERFACE = os.environ.get('INTERFACE', 'Wi-Fi')
    DEFAULT_FILTER = os.environ.get('DEFAULT_FILTER', '')
    
    # Directory settings
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    CAPTURE_DIR = os.path.join(BASE_DIR, 'captures')
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    REPORT_DIR = os.path.join(BASE_DIR, 'reports')
    
    # GeoIP settings
    GEOIP_DB_PATH = os.path.join(DATA_DIR, 'GeoLite2-City.mmdb')
    
    # Alert thresholds
    ALERT_THRESHOLDS = {
        'syn_flood': 100,  # SYN packets per second
        'dns_tunnel': 50,  # DNS queries per second
        'arp_spoof': 5,    # ARP responses per second
    }
    
    # Packet capture settings
    MAX_PACKETS = 10000  # Maximum number of packets to store in memory
    
    # User credentials (in production, use a proper authentication system)
    USERS = {
        'admin': 'admin123',
        'user': 'user123'
    }
    
    # Threat intelligence settings
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
    
    # Logging settings
    LOG_LEVEL = 'INFO'
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Create necessary directories
    @classmethod
    def init_app(cls, app):
        os.makedirs(cls.CAPTURE_DIR, exist_ok=True)
        os.makedirs(cls.DATA_DIR, exist_ok=True)
        os.makedirs(cls.REPORT_DIR, exist_ok=True)

    # For development (default):
    SQLALCHEMY_DATABASE_URI = 'sqlite:///../instance/websniffer.db'
    # For production (uncomment and set via deploy.sh):
    # SQLALCHEMY_DATABASE_URI = 'postgresql://snifferuser:snifferpass@localhost/snifferdb'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # API Keys
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
    
    # Sniffer Settings
    PACKET_TIMEOUT = 30  # seconds
    
    # Machine Learning Settings
    ML_TRAINING_INTERVAL = 3600  # 1 hour
    ML_ANOMALY_THRESHOLD = 0.95  # 95% confidence threshold
    
    # UI Settings
    THEME = os.getenv('THEME', 'light')
    MOBILE_BREAKPOINT = 768  # pixels 