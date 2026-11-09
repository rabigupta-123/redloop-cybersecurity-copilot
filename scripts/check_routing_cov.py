import coverage

cov = coverage.Coverage()
cov.load()

# Get analysis for orchestrator.py
target_file = r"C:\Users\rabig\OneDrive\Desktop\claude code project\my-new-project\src\redloop\assessment\orchestrator.py"
analysis = cov.analysis(target_file)
executed = set(analysis[1])
missing = set(analysis[2])

# Intent routing code lines: 308 to 740
routing_lines = [line for line in range(308, 741) if line in executed or line in missing]
executed_routing = [line for line in routing_lines if line in executed]
missing_routing = [line for line in routing_lines if line in missing]

cov_rate = len(executed_routing) / len(routing_lines) if routing_lines else 0.0
print(f"Routing code (lines 308-740):")
print(f"Total executable statements: {len(routing_lines)}")
print(f"Executed: {len(executed_routing)}")
print(f"Missing: {len(missing_routing)}")
print(f"Coverage: {cov_rate:.2%}")
if missing_routing:
    print(f"Missing lines: {missing_routing[:20]}")

