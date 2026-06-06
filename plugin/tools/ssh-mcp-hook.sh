#!/bin/sh

# Keep plugin configuration portable: prefer SSH_MCP_BIN when a user needs an
# absolute path, otherwise resolve ssh-mcp through the host runtime PATH.
bin="${SSH_MCP_BIN:-ssh-mcp}"
exec "$bin" hook
