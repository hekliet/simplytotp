# SimplyTOTP

Simple GUI TOTP 2FA code utility.

## Usage

**Install requirements:**

```shell
pip install -r requirements.txt
```

**Start simplytotp:**

```shell
python -m simplytotp
```

## Features

- Import from and export to plaintext Aegis JSON.
- Add record from image file containing QR code.
- Keeps records in an encrypted vault in the current directory.
- Does not require a system keyring. (Simple password input on startup.)
