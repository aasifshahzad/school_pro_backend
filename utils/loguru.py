from loguru import logger
from datetime import datetime
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Fetch configuration from environment variables
LOG_DIR = os.getenv("LOG_DIR")
LOG_FILE_PREFIX = os.getenv("LOG_FILE_PREFIX")
LOG_ROTATION = os.getenv("LOG_ROTATION")
LOG_RETENTION = os.getenv("LOG_RETENTION")  # Can be a number or duration
LOG_LEVEL = os.getenv("LOG_LEVEL")

# Create logs directory if it doesn't exist
logs_dir = os.path.abspath(LOG_DIR)
os.makedirs(logs_dir, exist_ok=True)

# Define log file path with timestamp
log_file = os.path.join(logs_dir, f'{LOG_FILE_PREFIX}{datetime.now().strftime("%Y%m%d")}.log')

# Configure loguru
logger.remove()  # Remove default logger
logger.add(
    log_file,
    rotation=LOG_ROTATION,
    retention=LOG_RETENTION,
    encoding='utf-8',
    enqueue=True,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}",
    level=LOG_LEVEL
)
logger.add(
    sink=lambda msg: print(msg, end=""),
    level=LOG_LEVEL
)

# Optional manual cleanup (not necessary if using loguru's built-in retention)
def cleanup_old_logs(max_files=5):
    """Delete old log files keeping only the most recent ones"""
    try:
        log_files = [f for f in os.listdir(logs_dir) if f.startswith(LOG_FILE_PREFIX) and f.endswith('.log')]
        log_files.sort(reverse=True)  # Newest first

        files_to_delete = log_files[max_files:]
        if files_to_delete:
            logger.info(f"Found {len(files_to_delete)} old log files to clean up")
            for old_file in files_to_delete:
                file_path = os.path.join(logs_dir, old_file)
                os.remove(file_path)
                logger.info(f"Deleted old log file: {old_file}")
            logger.info("Log cleanup completed successfully")
        else:
            logger.info("No old log files to clean up")
    except Exception as e:
        logger.exception(f"Error during log cleanup: {e}")
        raise

# Call cleanup manually if needed (can be skipped if relying on loguru's retention)
cleanup_old_logs(int(LOG_RETENTION) if LOG_RETENTION.isdigit() else 5)
