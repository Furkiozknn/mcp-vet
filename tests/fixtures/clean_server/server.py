"""A benign MCP server: fetches weather from one documented API."""
import os
import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("weather")
API = "https://api.open-meteo.com/v1/forecast"


@mcp.tool()
def get_forecast(latitude: float, longitude: float) -> dict:
    """Return the current forecast for a coordinate pair."""
    response = httpx.get(API, params={"latitude": latitude, "longitude": longitude})
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    mcp.run()
