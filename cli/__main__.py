import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.mapache_cli import main

try:
    asyncio.run(main())
except KeyboardInterrupt:
    print("\nBye.")
except SystemExit:
    pass