"""
Centralized logging utility with colorama support for LogCopilot.
"""
import logging
import sys
from typing import Optional
from colorama import Fore, Back, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colorama colors for different log levels."""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Back.WHITE + Style.BRIGHT,
    }
    
    def format(self, record):
        # Get the original formatted message
        log_message = super().format(record)
        
        # Add color based on log level
        color = self.COLORS.get(record.levelname, '')
        if color:
            # Color the entire message
            return f"{color}{log_message}{Style.RESET_ALL}"
        return log_message

def setup_logger(
    name: str = "logcopilot",
    level: str = "INFO",
    format_string: Optional[str] = None,
    enable_colors: bool = True
) -> logging.Logger:
    """
    Set up a logger with colorama support.
    
    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_string: Custom format string
        enable_colors: Whether to enable colored output
    
    Returns:
        Configured logger instance
    """
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    # Remove existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, level.upper()))
    
    # Set format string
    if format_string is None:
        format_string = (
            f"{Fore.BLUE}[%(asctime)s]{Style.RESET_ALL} "
            f"{Fore.MAGENTA}[%(name)s]{Style.RESET_ALL} "
            f"{Fore.CYAN}[%(levelname)s]{Style.RESET_ALL} "
            f"{Fore.WHITE}%(message)s{Style.RESET_ALL}"
        )
    
    # Create formatter
    if enable_colors:
        formatter = ColoredFormatter(format_string)
    else:
        formatter = logging.Formatter(
            "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s"
        )
    
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger

def get_logger(name: str = "logcopilot") -> logging.Logger:
    """
    Get a logger instance. If not configured, sets up default configuration.
    
    Args:
        name: Logger name (usually module name)
    
    Returns:
        Logger instance
    """
    logger = logging.getLogger(name)
    
    # If logger has no handlers, set up default configuration
    if not logger.handlers:
        return setup_logger(name)
    
    return logger

# Create default logger instance
default_logger = setup_logger("logcopilot", "INFO")
