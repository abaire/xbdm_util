# gdb_xbdm_bridge

Sets up a GDB stub and bridges communication with an XBOX devkit.

See https://xboxdevwiki.net/Xbox_Debug_Monitor for a description of the XBDM protocol.

## git hooks

This project uses [git hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
to automate some aspects of keeping the code base healthy.

Please copy the files from the `githooks` subdirectory into `.git/hooks` to
enable them.
