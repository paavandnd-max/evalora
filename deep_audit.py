import inspect
import json
import re
from genuine_handlers import GENUINE_HANDLERS

with open('data/test_catalogue.json', 'r', encoding='utf-8') as f:
    cat = json.load(f)['tests']

cat_map = {item['id']: item for item in cat}

std_keys = {'files', 'repository_url', 'inspect_files', 'parse_github_repository_url'}

flag_handlers = []
static_file_handlers = []

for cid, fn in sorted(GENUINE_HANDLERS.items()):
    src = inspect.getsource(fn)
    found_flags = set(re.findall(r'context\.get\(["\']([a-zA-Z0-9_]+)["\']', src)) - std_keys
    has_file_check = ('info["files"]' in src or 'info["content_all"]' in src or 'info["names"]' in src or 'inspector' in src)
    
    if found_flags:
        flag_handlers.append((cid, sorted(list(found_flags)), has_file_check))
    else:
        static_file_handlers.append((cid, has_file_check))

print(f"Total handlers: {len(GENUINE_HANDLERS)}")
print(f"Handlers using context flags/simulations: {len(flag_handlers)}")
print(f"Handlers relying solely on static file/repo inspection: {len(static_file_handlers)}")

print("\n--- Handlers using context flags ---")
for cid, flags, has_files in flag_handlers:
    print(f"{cid} (has_file_fallback={has_files}): {flags}")
