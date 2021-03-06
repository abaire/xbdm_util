from .debug_logging import register_logging_level
from .debug_logging import register_super_verbose_logging_level

from .ansi_formatter import *


def register_colorized_logging_level(name: str, format: str):
    """Registers a new log level with the given colorized format.

    :returns Method that will print a string to the new log level.
    """
    ret, level = register_logging_level(name)
    FORMATTER.set_log_format(level, format)
    return ret


def register_colorized_super_verbose_logging_level(name: str, format: str):
    """Registers a new log level lower than DEBUG with the given colorized format.

    :returns Method that will print a string to the new log level.
    """
    ret, level = register_super_verbose_logging_level(name)
    FORMATTER.set_log_format(level, format)
    return ret
