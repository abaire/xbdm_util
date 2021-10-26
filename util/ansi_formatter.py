import logging


ANSI_BLACK = "\x1b[30m"
ANSI_RED = "\x1b[31m"
ANSI_GREEN = "\x1b[32m"
ANSI_YELLOW = "\x1b[33m"
ANSI_BLUE = "\x1b[34m"
ANSI_MAGENTA = "\x1b[35m"
ANSI_CYAN = "\x1b[36m"
ANSI_WHITE = "\x1b[37m"

ANSI_BRIGHT_BLACK = "\x1b[90m"
ANSI_BRIGHT_RED = "\x1b[91m"
ANSI_BRIGHT_GREEN = "\x1b[92m"
ANSI_BRIGHT_YELLOW = "\x1b[93m"
ANSI_BRIGHT_BLUE = "\x1b[94m"
ANSI_BRIGHT_MAGENTA = "\x1b[95m"
ANSI_BRIGHT_CYAN = "\x1b[96m"
ANSI_BRIGHT_WHITE = "\x1b[97m"

ANSI_BLACK_BACKGROUND = "\x1b[40m"
ANSI_RED_BACKGROUND = "\x1b[41m"
ANSI_GREEN_BACKGROUND = "\x1b[42m"
ANSI_YELLOW_BACKGROUND = "\x1b[43m"
ANSI_BLUE_BACKGROUND = "\x1b[44m"
ANSI_MAGENTA_BACKGROUND = "\x1b[45m"
ANSI_CYAN_BACKGROUND = "\x1b[46m"
ANSI_WHITE_BACKGROUND = "\x1b[47m"
ANSI_BRIGHT_BLACK_BACKGROUND = "\x1b[100m"
ANSI_BRIGHT_RED_BACKGROUND = "\x1b[101m"
ANSI_BRIGHT_GREEN_BACKGROUND = "\x1b[102m"
ANSI_BRIGHT_YELLOW_BACKGROUND = "\x1b[103m"
ANSI_BRIGHT_BLUE_BACKGROUND = "\x1b[104m"
ANSI_BRIGHT_MAGENTA_BACKGROUND = "\x1b[105m"
ANSI_BRIGHT_CYAN_BACKGROUND = "\x1b[106m"
ANSI_BRIGHT_WHITE_BACKGROUND = "\x1b[107m"

ANSI_DEFAULT = "\x1b[39m"

ANSI_RESET = "\x1b[0m"
ANSI_BOLD = "\x1b[1m"
ANSI_UNDERLINE = "\x1b[4m"
ANSI_REVERSED = "\x1b[7m"


def _make_format(prefix: str) -> str:
    return prefix + r"%s" + ANSI_RESET


class ANSIFormatter(logging.Formatter):
    DEFAULT_FORMAT_STR = "%(levelname)-8s [%(filename)s:%(lineno)d] %(message)s"

    DEFAULT_FORMATS = {
        logging.DEBUG: _make_format(ANSI_BRIGHT_BLACK),
        logging.INFO: _make_format(ANSI_GREEN),
        logging.WARNING: _make_format(ANSI_YELLOW),
        logging.ERROR: _make_format(ANSI_RED),
        logging.CRITICAL: _make_format(ANSI_REVERSED),
    }

    def __init__(self, fmt: str = DEFAULT_FORMAT_STR, **kw):
        super().__init__(fmt=fmt, **kw)

        self.formats = dict(self.DEFAULT_FORMATS)

    def format(self, record):
        log_fmt = self.formats.get(record.levelno) % self._fmt
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

    def set_log_format(self, level: int, ansi_prefix: str):
        self.formats[level] = _make_format(ansi_prefix)


FORMATTER = ANSIFormatter()


def colorize_logs() -> ANSIFormatter:
    """Enables ANSI colorization of logs."""
    global FORMATTER
    for h in logging.root.handlers:
        h.setFormatter(FORMATTER)

    return FORMATTER
