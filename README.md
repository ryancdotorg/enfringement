# enfringement

Tools for working with EnGenius WiFi hardware.

## `decrypt.py`

Decrypt a firmware file using EnGenius’s static xor key.

## `extract_squashfs.py`

Attempt to automatically extract a squashfs root filesystem image from a
firmware file. The file is scanned without decrypting it first, but decryption
will be done automatically as required.

Supports the following types of firmware images:
* gzip’d tar file
* Proprietary EnGenius firmware containing raw SquashFS image
* Proprietary EnGenius firmware containing SquashFS image inside UBI image

## `enfringement.py`

Manipulate an EnSky-series WAP via its web interface.

    usage: enfringement.py COMMAND [options]

    Manage EnGenius EnSky WiFi Access Points.

    positional arguments:
      COMMAND               command to perform {getstatus, getmac, getconfig,
                            putconfig, putfirmware, gethwid, jailbreak}

    available commands:
      getstatus             get the device's network status
      getmac                get the device's model number and mac address
      getconfig             download the current config
      putconfig             upload a config bundle
      putfirmware           flash a firmware file
      gethwid               extract device's hardware info to a template config
      jailbreak             enable root login via ssh

    optional arguments:
      -h, --help            show this help message and exit
      -v, --verbose         enable verbose output
      -u USER, --username USER
                            login username (default: "admin")
      -p PASS, --password PASS
                            login password (default: `EAP_PASSWORD` environment
                            variable if set, otherwise "admin")
      -i FILE, --input FILE
                            input filename (default: stdin)
      -o FILE, --output FILE
                            output filename (default: stdout)
      -a URL, --url URL     device IP address or URL
      -W, --wait            wait for access point to reboot after put operations
                            (default: false)
      --dropbear FILE       location of dropbear binary to inject for jailbreak
                            (default: bundled)
