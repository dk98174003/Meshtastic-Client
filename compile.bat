d:
cd D:\SynologyDrive\GIT\Meshtastic\Meshtastic_client

pyinstaller --clean --noconsole --onefile --name "MeshtasticClient" --icon="meshtastic.ico" --add-data "meshtastic.ico;." "meshtastic_client.py"

del MeshtasticClient.spec
rmdir /S /Q build
copy dist\*.exe .
rmdir /S /Q dist