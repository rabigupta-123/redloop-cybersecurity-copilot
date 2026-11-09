import subprocess
import csv
import io

out = subprocess.check_output(['tasklist', '/FO', 'CSV']).decode('latin-1')
reader = csv.reader(io.StringIO(out))
rows = list(reader)
header = rows[0]
proc_list = []
for r in rows[1:]:
    if len(r) >= 5:
        mem_str = r[4].replace(',', '').replace(' K', '').strip()
        try:
            mem_kb = int(mem_str)
            proc_list.append((r[0], r[1], mem_kb))
        except:
            pass

proc_list.sort(key=lambda x: x[2], reverse=True)
print('Top 20 memory-consuming processes:')
for name, pid, kb in proc_list[:20]:
    print(f'  {name:<30} PID {pid:<8}: {kb/1024:.1f} MB')
