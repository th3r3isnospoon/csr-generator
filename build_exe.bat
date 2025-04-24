@echo off
pip install pyinstaller
pyinstaller --onefile --noconsole --name "CSR_Generator_GUI" csr_generator_gui_full.py
pause
