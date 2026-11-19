"""A browser the scope filter sits inside.

The agent drives a real Chromium through MCP tools. Every request the page
makes (navigation, script, image, XHR, fetch, form post) passes a route
handler that asks the engagement's enforced scope before it is allowed to
leave, so a page cannot pull the browser off-scope with a redirect, an
embedded resource or script. Blocked requests are logged to the audit root.

Where the engagement requires approval for state-changing requests, the
browser is read-only: anything but GET / HEAD / OPTIONS is aborted, and the
agent is told to send that exact request through the capture gateway, where
a human can approve it.
"""
