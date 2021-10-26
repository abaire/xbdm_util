import logging

_NEXT_DEBUG_LOGGING_LEVEL = logging.DEBUG + 1


def get_next_logging_level() -> int:
    """Returns the next unused logging level."""
    global _NEXT_DEBUG_LOGGING_LEVEL
    ret = _NEXT_DEBUG_LOGGING_LEVEL
    assert ret < logging.INFO
    _NEXT_DEBUG_LOGGING_LEVEL += 1
    return ret


def register_logging_level(name: str):
    """Registers a new logging level.

    :returns (log_func, level)
    """
    level = get_next_logging_level()
    logging.addLevelName(level, name)

    log = (
        lambda inst, message, *args, **kws: inst._log(level, message, args, **kws)
        if inst.isEnabledFor(level)
        else None
    )
    return log, level
