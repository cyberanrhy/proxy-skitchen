# PyInstaller runtime hook for the CLI build.
# Sets an env var so the app knows it is the console build and
# shows the interactive menu on start (instead of the GUI).
import os

os.environ.setdefault("PROXY_SKITCHEN_CLI", "1")