import os
import subprocess
import sys

def install_matplotlib():
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("Matplotlib not found. Installing it now...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "matplotlib"])
        print("Matplotlib installed successfully!")

# Ensure matplotlib is installed
install_matplotlib()
import matplotlib.pyplot as plt

# Data for the charts
sprints = ['Sprint 1', 'Sprint 2', 'Sprint 3', 'Sprint 4', 'Sprint 5']
x = [1, 2, 3, 4, 5]

# --- Burn Down Chart ---
# Starts at 100, goes to 0
remaining_work = [85, 65, 40, 15, 0]
start_point = [0, 100] # Sprint 0 is start

fig, ax = plt.subplots(figsize=(8, 5))
ax.plot([0] + x, [100] + remaining_work, marker='o', color='red', linestyle='-', linewidth=2, label='Remaining Work')
ax.set_title('Burn Down Chart', fontsize=16, fontweight='bold')
ax.set_xlabel('Sprints', fontsize=12)
ax.set_ylabel('Remaining Work (Story Points)', fontsize=12)
ax.set_xticks([0, 1, 2, 3, 4, 5])
ax.set_xticklabels(['Start', 'Sprint 1', 'Sprint 2', 'Sprint 3', 'Sprint 4', 'Sprint 5'])
ax.set_ylim(-5, 105)
ax.grid(True, linestyle='--', alpha=0.6)
ax.legend()
plt.tight_layout()

# Save the Burn Down chart
burn_down_path = os.path.join(os.getcwd(), 'burn_down_chart.png')
plt.savefig(burn_down_path, dpi=300)
print(f"✅ Generated: {burn_down_path}")
plt.close()


# --- Burn Up Chart ---
# Starts at 0, goes to 100
completed_work = [15, 35, 60, 85, 100]
total_scope = [100, 100, 100, 100, 100, 100]

fig, ax = plt.subplots(figsize=(8, 5))
ax.plot([0] + x, [0] + completed_work, marker='o', color='green', linestyle='-', linewidth=2, label='Completed Work')
ax.plot([0] + x, total_scope, color='black', linestyle='--', linewidth=1.5, label='Total Scope')
ax.set_title('Burn Up Chart', fontsize=16, fontweight='bold')
ax.set_xlabel('Sprints', fontsize=12)
ax.set_ylabel('Cumulative Work (Story Points)', fontsize=12)
ax.set_xticks([0, 1, 2, 3, 4, 5])
ax.set_xticklabels(['Start', 'Sprint 1', 'Sprint 2', 'Sprint 3', 'Sprint 4', 'Sprint 5'])
ax.set_ylim(-5, 110)
ax.grid(True, linestyle='--', alpha=0.6)
ax.legend(loc='lower right')
plt.tight_layout()

# Save the Burn Up chart
burn_up_path = os.path.join(os.getcwd(), 'burn_up_chart.png')
plt.savefig(burn_up_path, dpi=300)
print(f"✅ Generated: {burn_up_path}")
plt.close()

print("Both charts have been successfully generated and saved in your directory!")
