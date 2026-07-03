import json
import os

log_path = r"C:\Users\Lijo\.gemini\antigravity\brain\0ed4c5d4-08ef-4227-a33b-e86d23da65e7\.system_generated\logs\transcript.jsonl"

if os.path.exists(log_path):
    print("Log file found.")
    with open(log_path, 'r', encoding='utf-8') as f:
        for idx, line in enumerate(f):
            try:
                data = json.loads(line)
                content = data.get("content", "")
                if not content:
                    # check tool calls or responses
                    content = str(data)
                if "1500" in content:
                    print(f"--- Step {data.get('step_index', idx)} ---")
                    # print truncated content
                    print(content[:500] + ("..." if len(content) > 500 else ""))
            except Exception as e:
                pass
else:
    print("Log file not found.")
