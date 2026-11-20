import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'netsentry-ai-enterprise-secret-2026-key')
    DATABASE_PATH = os.path.join(BASE_DIR, 'netsentry.db')
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{DATABASE_PATH}'
    
    # Upload configurations
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    SAMPLE_PCAP_FOLDER = os.path.join(BASE_DIR, 'sample_pcaps')
    MAX_CONTENT_LENGTH = 64 * 1024 * 1024  # 64 MB maximum file size
    ALLOWED_EXTENSIONS = {'pcap', 'cap', 'pcapng'}
    
    # Model storage
    MODEL_DIR = os.path.join(BASE_DIR, 'ai_engine', 'saved_models')
    
    # Reports
    REPORT_DIR = os.path.join(BASE_DIR, 'reports', 'generated')
    
    # Risk scoring default weights (sum = 1.0)
    RISK_WEIGHT_ISOLATION_FOREST = 0.30
    RISK_WEIGHT_RANDOM_FOREST = 0.30
    RISK_WEIGHT_BEHAVIOR_DEVIATION = 0.20
    RISK_WEIGHT_VOLUME_ANOMALY = 0.10
    RISK_WEIGHT_DEST_REPUTATION = 0.10
    
    # Risk Severity thresholds (0 to 100)
    RISK_THRESHOLD_LOW = 40
    RISK_THRESHOLD_MEDIUM = 70
    RISK_THRESHOLD_HIGH = 85
    
    # Anomaly sensitivity
    ISOLATION_ANOMALY_THRESHOLD = 0.60
    
    # Live simulation default interval (seconds)
    SIMULATION_INTERVAL = 2.0
