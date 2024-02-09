# Capacity base utilities

import os
import sys
import time
import re
import logging
import logging.handlers
import traceback
import lzma
import shutil

# Define various constants.


# Ensure a default value on a config: If cfgname doesn't exist in config, set it to cfgdefault.
def config_default(config, config_name, default_value, defaults_dict={}):
    if config_name not in config:
        config[config_name] = defaults_dict[config_name] if config_name in defaults_dict else default_value


# Parse a number-of-bytes string (with suffix) into an integer
def parse_bytestring(bytestring):
    if isinstance(bytestring, int):
        return bytestring
    if isinstance(bytestring, str):
        match = re.search(r'^(\d+)([kMGT])$', bytestring)
        if match:
            if match.group(2) == 'k':
                return int(match.group(1)) * 1024
            elif match.group(2) == 'M':
                return int(match.group(1)) * (1024 ** 2)
            elif match.group(2) == 'G':
                return int(match.group(1)) * (1024 ** 3)
            elif match.group(2) == 'T':
                return int(match.group(1)) * (1024 ** 4)
    return int(bytestring)


def strtobool(input_string):
    return input_string.lower() in {"y", "yes", "t", "true", "on", "1"}


def printable_version(version_string):
    if version_string == "x.y.z":
        return "testing"
    if version_string == "0.1a":
        return "alpha"
    match = re.search(r'^(.*)\-\d+$', version_string)
    if match:
        return match.group(1)
    return version_string


def get_file_data(file_path, binary=None, logger=None):
    if os.path.isfile(file_path):
        try:
            if binary is None:
                binary = not file_path.endswith(".html") and not file_path.endswith(".txt") and not file_path.endswith(".csv")
            with open(file_path, "rb" if binary else "r") as open_file:
                file_data = open_file.read()
        except:
            if logger:
                logger.error("Error reading data from file: %s (%s)" % (sys.exc_info()[0], sys.exc_info()[1]))
            return None
    else:
        if logger:
            logger.error("File not found: %s" % file_path)
        return None
    return file_data


def log(logger, log_level, *args, bt=False):
    if logger:
        rn, level_num = get_log_levels(log_level, False)
        logger.log(level_num, *args)
        if sys.exc_info()[0]:
            if type(bt) == str:
                rn, bt_level_num = get_log_levels(bt, False)
                bt = logger.isEnabledFor(bt_level_num)
            if bt:
                traceback.print_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2])


def get_log_levels(config_log_level, app_debug):
    if config_log_level.lower() == "critical":
        root_log_level = logging.CRITICAL
        app_log_level = logging.CRITICAL
    elif config_log_level.lower() == "error":
        root_log_level = logging.ERROR
        app_log_level = logging.ERROR
    elif config_log_level.lower() in ["warning", "warn"]:
        root_log_level = logging.WARNING
        app_log_level = logging.WARNING
    elif config_log_level.lower() == "info":
        root_log_level = logging.INFO
        app_log_level = logging.INFO
    elif config_log_level.lower() == "debug":
        root_log_level = logging.INFO
        app_log_level = logging.DEBUG
    elif config_log_level.lower() == "notset":
        root_log_level = logging.INFO
        app_log_level = logging.NOTSET
    elif app_debug:
        root_log_level = logging.DEBUG
        app_log_level = logging.DEBUG
    else:
        root_log_level = logging.INFO
        app_log_level = logging.INFO
    return root_log_level, app_log_level


def logfile_namer(name):
    newname = name
    match = re.search(r'^(.+)\.\d+$', name)
    if match:
        # This is a rollover name, let's use a date instead of the integer though
        newname = match.group(1) + "." + time.strftime("%Y-%m-%d_%H-%M") + ".xz"
    return newname


def logfile_rotator(source, dest):
    if os.path.exists(source):
        with open(source, 'rt') as in_file, lzma.open(dest, 'wt') as out_file:
            shutil.copyfileobj(in_file, out_file)
        os.remove(source)


def get_logfile_handler(path, maxbytes):
    # file_handler = logging.handlers.WatchedFileHandler(path)  # no rotation
    file_handler = logging.handlers.RotatingFileHandler(path, maxBytes=maxbytes, backupCount=1)
    file_handler.namer = logfile_namer
    file_handler.rotator = logfile_rotator
    file_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s:%(name)s - %(message)s"))
    return file_handler
