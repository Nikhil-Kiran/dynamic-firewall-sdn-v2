"""Compatibility bridge so imports of 'event_sender' route cleanly to 'log_client'."""
from log_client import send_security_event, send_event, DEFAULT_LOGGER_IP, DEFAULT_LOGGER_PORT
