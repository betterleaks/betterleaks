from pathlib import Path
from runpy import run_path

package_dir = Path(__file__).resolve().parent
helper = package_dir / "native_build.py"
if not helper.is_file():
    helper = package_dir.parent / "native_build.py"
run_path(str(helper))["configure"](package_dir, "betterleaks_cli")
