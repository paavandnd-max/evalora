import os
import sys

# Ensure demo mode is enabled
os.environ["EVALORA_DEMO_MODE"] = "1"

import server

# Seed database and start server on port 8080 to prevent conflicts with port 8000
server.load_demo_database()
print("Evalora running at http://127.0.0.1:8080", flush=True)
server.ThreadingHTTPServer(("127.0.0.1", 8080), server.Handler).serve_forever()
