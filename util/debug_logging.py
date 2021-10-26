import logging

SUPER_VERBOSE = 0

_NEXT_DEBUG_LOGGING_LEVEL = logging.DEBUG + 1
_NEXT_SUPER_VERBOSE_LOGGING_LEVEL = SUPER_VERBOSE + 1


def get_next_logging_level() -> int:
    """Returns the next unused logging level."""
    global _NEXT_DEBUG_LOGGING_LEVEL
    ret = _NEXT_DEBUG_LOGGING_LEVEL
    assert ret < logging.INFO
    _NEXT_DEBUG_LOGGING_LEVEL += 1
    return ret


def get_next_super_verbose_logging_level() -> int:
    """Returns the next unused logging level."""
    global _NEXT_SUPER_VERBOSE_LOGGING_LEVEL
    ret = _NEXT_SUPER_VERBOSE_LOGGING_LEVEL
    assert ret < logging.DEBUG
    _NEXT_SUPER_VERBOSE_LOGGING_LEVEL += 1
    return ret


def _make_log_fun(level):
    def log(inst, message, *args, **kws):
        if inst.isEnabledFor(level):
            inst._log(level, message, args, **kws)

    return log


def register_logging_level(name: str):
    """Registers a new logging level.

    :returns (log_func, level)
    """
    level = get_next_logging_level()
    logging.addLevelName(level, name)
    return _make_log_fun(level), level


def register_super_verbose_logging_level(name: str):
    """Registers a new logging level lower than DEBUG.

    :returns (log_func, level)
    """
    level = get_next_super_verbose_logging_level()
    logging.addLevelName(level, name)
    return _make_log_fun(level), level
