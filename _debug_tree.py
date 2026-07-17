import json
with open(r'C:\Users\Stas\.local\share\opencode\tool-output\tool_f6ea4f686001NsCqmX2hZluOEl') as f:
    data = json.loads(f.read())
tree = data.get('tree', [])
count = 0
for item in tree:
    if item.get('type') == 'blob' and count < 65:
        path = item.get('path', '')
        size = item.get('size', 0)
        print(f'{path} ({size} bytes)')
        count += 1
