#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import os
import yaml
from typing import Dict

# Get logger for config loading itself
logger = logging.getLogger('ConfigLoader')

# --- Default Configuration Values ---

DEFAULT_LOGGING_CONFIG = {
    "log_dir": "logs",
    "log_filename": "firewall.log",
    "file_level": logging.INFO,
    "signal_level": logging.DEBUG,
    "format": '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    "max_bytes": 10 * 1024 * 1024, # 10 MB
    "backup_count": 5,
}

DEFAULT_RULES_CONFIG = {
    "rules_file": "rules.yaml", # Relative to project root or where main.py is run
}

DEFAULT_PERFORMANCE_CONFIG = {
    'use_queue_model': False,
    'num_workers': 2,
    'use_packet_pool': True,
    'packet_pool_size': 100, 
    'skip_local_packets': True,
    'allow_private_network': True,
    # Add other performance defaults if needed
}

DEFAULT_INTERCEPTOR_CONFIG = {
    "queue_len": 8192,
    "queue_time": 2000, # ms
    "filter_string": "tcp or udp", # Default WinDivert filter
}

DEFAULT_UI_CONFIG = {
    "log_max_rows": 500, # Default max rows for the log table in UI
    "status_update_interval": 1000, # ms
}

# --- Configuration Loading Logic ---

def _merge_configs(default: Dict, loaded: Dict) -> Dict:
    """Recursively merge loaded config into default config."""
    merged = default.copy()
    for key, value in loaded.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_configs(merged[key], value)
        else:
            # Loaded value overrides default, even if type differs (log warning later if needed)
            merged[key] = value
    return merged

def load_config_from_file(filepath: str = "config.yaml") -> Dict:
    """Loads configuration from a YAML file, merging with defaults."""
    
    # Start with all defaults
    config = {
        "logging": DEFAULT_LOGGING_CONFIG.copy(),
        "rules": DEFAULT_RULES_CONFIG.copy(),
        "performance": DEFAULT_PERFORMANCE_CONFIG.copy(),
        "interceptor": DEFAULT_INTERCEPTOR_CONFIG.copy(),
        "ui": DEFAULT_UI_CONFIG.copy(), # Add UI defaults
    }

    try:
        if os.path.isfile(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                loaded_config = yaml.safe_load(f)
                if isinstance(loaded_config, dict):
                    # Merge loaded config into defaults
                    config = _merge_configs(config, loaded_config)
                    logger.info(f"Configuration loaded and merged from {filepath}")
                else:
                    logger.warning(f"Configuration file {filepath} is not a valid dictionary. Using defaults.")
        else:
            logger.info(f"Configuration file {filepath} not found. Using defaults.")
            # Optionally save default config if file doesn't exist
            # try:
            #     with open(filepath, 'w', encoding='utf-8') as f:
            #         yaml.dump(config, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
            #     logger.info(f"Default configuration saved to {filepath}")
            # except Exception as e:
            #     logger.error(f"Could not save default configuration to {filepath}: {e}")

    except yaml.YAMLError as e:
        logger.error(f"Error parsing configuration file {filepath}: {e}. Using defaults.")
    except Exception as e:
        logger.error(f"Error loading configuration from {filepath}: {e}. Using defaults.")

    # --- Post-processing / Validation (Example for logging levels) ---
    # Convert string log levels from file to logging constants
    log_level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    if isinstance(config["logging"].get("file_level"), str):
        level_str = config["logging"]["file_level"].upper()
        config["logging"]["file_level"] = log_level_map.get(level_str, logging.INFO)
    if isinstance(config["logging"].get("signal_level"), str):
        level_str = config["logging"]["signal_level"].upper()
        config["logging"]["signal_level"] = log_level_map.get(level_str, logging.DEBUG)
        
    # Add more validation as needed for other sections

    return config

# Load the configuration once when the module is imported
CONFIG = load_config_from_file()

# Example usage:
# if __name__ == "__main__":
#     print("Loaded Configuration:")
#     import json
#     print(json.dumps(CONFIG, indent=2, default=str)) # Use default=str for non-serializable logging levels
