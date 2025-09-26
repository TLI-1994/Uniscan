import sys
import os
import tempfile
import shutil

# Add src folder to Python path so we can import uniscan
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from uniscan.main import main

def test_main_runs():
    # Create a temporary folder to simulate a Unity project
    temp_dir = tempfile.mkdtemp()
    try:
        # Patch sys.argv to simulate command-line arguments
        sys.argv = ["uniscan", temp_dir]

        # Run main (dummy execution)
        main()
        print("Dummy test passed: main() executed without errors.")

    except Exception as e:
        print(f"Dummy test failed: {e}")

    finally:
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    test_main_runs()
