# Unknown Cyber IDA Plugin
The Unknown Cyber IDA Plugin is designed to integrate Unknown Cyber technologies seamlessly with IDA.
- Key Features
  * Binary, IDB, and disassembly uploading
  * Project creation
  * CRUD operations for procedures, procedure groups, and file notes/tags
  * File and procedure similarity matching
  * Assembly code comparison for matched procedures

## Built and Verified for
- IDA Pro 8.2.230124 (64-bit) GUI version
- IDAPython 64-bit v7.4.0
- Python 3.7
- Ubuntu 22.04.2 LTS

## Prerequisites
- IDAPro installation.
- IDAPro key.
- ([Unknown Cyber](https://unknowncyber.com/)) user account.

## Installation
The following walkthrough uses the tarball delivery. Change instructions where necessary if using the zipfile.
- Download `unknowncyeridaplugin.tgz` from a ([release](https://github.com/Unknown-Cyber-Inc/ida/releases/)).
- Verify the download with the release's checksum.
- Extract
  * `tar xvzf unknowncyberidaplugin.tgz`
- Install dependencies
  * `python3 pip install -r requirements.txt`
- Edit `plugins/idamagic/.env`
  * `MAGIC_API_HOST` - Use `https://api.magic.unknowncyber.com` unless using an offline Unknown Cyber system.
  * `MAGIC_API_KEY` - Replace with your Unknown Cyber api key.
- Move just the contents of the `plugins` to the IDA plugins directory. Location can vary.
  - Typically on Linux it is either:
    * `~/.idapro/plugins`
    * `/opt/ida/plugins`
  - Typically on Windows it is either:
    * `C:\Program Files\IDA Pro 8.0\plugins`
    * `%APPDATA%\Hex-Rays\IDA Pro\plugins`
