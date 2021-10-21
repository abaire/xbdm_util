"""Defines the ConnectionInfo tuple."""
import collections

ConnectionInfo = collections.namedtuple(
    "ConnectionInfo", ["listen_addr", "xbox_name", "xbox_addr"]
)
