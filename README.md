# CSR Generator GUI

A cross-platform Python GUI for generating and viewing CSRs, decoding certificates, and building PEM bundles.  
Includes dark mode, SAN support, and optional self-signed cert generation.

## 🧰 Requirements

### Linux:
```bash
sudo apt install python3 python3-tk openssl
python3 csr_generator_gui_full.py
```

### Windows:
Run the included `build_exe.bat` to generate a portable `.exe` with PyInstaller.

## 🧱 AppImage Build
Unzip the `AppDir` folder and run `appimagetool` to create a standalone `.AppImage`.

## 🧪 Features
- CSR Generator with full subject + SAN support
- Self-signed certificate toggle
- PEM builder with intermediate & root chaining
- Certificate and CSR viewer
- Dark mode 🌙
