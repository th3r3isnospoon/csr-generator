# One shared runtime, separate console and GUI entry points.
from pathlib import Path
import sys

root = Path(SPECPATH).parent
# Some standalone Python distributions keep Tcl/Tk libraries outside ldconfig paths.
tk_libraries = []
if sys.platform == 'linux':
    for pattern in ('libtcl*.so*', 'libtk*.so*'):
        tk_libraries.extend((str(path), '.') for path in (Path(sys.base_prefix) / 'lib').glob(pattern))
common = dict(pathex=[str(root)], binaries=tk_libraries, datas=[(str(root / 'LICENSE'), '.')],
              hiddenimports=[], hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=[])
gui = Analysis([str(root / 'csr_generator_gui_full.py')], **common)
cli = Analysis([str(root / 'scripts' / 'cli_entry.py')], **common)
gui_exe = EXE(PYZ(gui.pure), gui.scripts, [], exclude_binaries=True,
              name='csr-generator-gui', console=False, icon=str(root / 'packaging' / 'csr-generator.ico'))
cli_exe = EXE(PYZ(cli.pure), cli.scripts, [], exclude_binaries=True,
              name='csr-generator', console=True, icon=str(root / 'packaging' / 'csr-generator.ico'))
coll = COLLECT(gui_exe, cli_exe, gui.binaries, cli.binaries, gui.datas, cli.datas,
               strip=False, upx=False, name='CSR-Generator')
