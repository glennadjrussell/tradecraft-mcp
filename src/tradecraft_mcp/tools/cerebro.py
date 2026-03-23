"""Cerebro tools — social account lookup and image analysis for intel indicators."""

import logging

from mcp.server.fastmcp import Context, FastMCP

log = logging.getLogger(__name__)


def _get_session(ctx: Context):
    return ctx.request_context.lifespan_context.http_session


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def social_account_search(
        identifier: str, ctx: Context, identifier_type: str = "username"
    ) -> str:
        """Look up a user across social platforms by username, phone number, or email.

        Args:
            identifier: The user ID, phone number, or social media handle to search for.
            identifier_type: One of "username", "phone", or "email".
        """
        return (
            f"# Social Account Search\n\n"
            f"- **Identifier:** {identifier}\n"
            f"- **Type:** {identifier_type}\n\n"
            f"*This tool is not yet implemented.*"
        )

    @mcp.tool()
    async def vision_analyse(image_url: str, ctx: Context) -> str:
        """Analyse an image for intelligence indicators (faces, text, landmarks, metadata).

        Args:
            image_url: URL of the image to analyse.
        """
        return (
            f"# Vision Analysis\n\n"
            f"- **Image URL:** {image_url}\n\n"
            f"*This tool is not yet implemented.*"
        )
