import time
import os
import sys

# Add parent dir to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import database

print("Starting sync...")
start = time.time()
database._sync_all_documentation_sync()
end = time.time()
print(f"Sync took {end - start:.4f} seconds.")
