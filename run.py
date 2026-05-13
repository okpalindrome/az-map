"""Entry point for az-map.  Run: python run.py"""
import sys


# Windows requires ProactorEventLoop for asyncio subprocess support.
# Must be set before any asyncio import or uvicorn startup.
if sys.platform == "win32":
    import asyncio
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())


def check_dependencies():
    try:
        import fastapi, uvicorn, azure.identity, sqlalchemy, networkx, httpx
    except ImportError as e:
        print(f"[!] Missing dependency: {e}")
        print("[*] Run: pip install -r requirements.txt")
        sys.exit(1)


def main():
    check_dependencies()

    import uvicorn
    print("=" * 60)
    print("  az-map  |  Azure Security Analysis Tool")
    print("=" * 60)
    print("[*] Starting server at http://localhost:8000")
    print("[*] Make sure you are logged in via: az login")
    print("[*] Press Ctrl+C to stop\n")

    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="warning",
        access_log=False,
    )


if __name__ == "__main__":
    main()
