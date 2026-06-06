#!/bin/sh

# Keep plugin configuration portable: prefer HEKATESSH_BIN when a user needs an
# absolute path, otherwise resolve hekatessh through the host runtime PATH.
bin="${HEKATESSH_BIN:-hekatessh}"
exec "$bin" hook
