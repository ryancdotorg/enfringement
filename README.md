# enfringement

Tools for working with EnGenius EnSky series WAPs

    usage: enfringement.py COMMAND [options]

    Manage EnGenius EnSky WiFi Access Points.

    positional arguments:
      COMMAND               command to perform {getconfig, putconfig, putfirmware,
                            jailbreak}

    optional arguments:
      -h, --help            show this help message and exit
      -u USER, --username USER
                            login username (default: admin)
      -p PASS, --password PASS
                            login password (default: admin)
      -i FILE, --input FILE
                            input filename (default: stdin)
      -o FILE, --output FILE
                            output filename (default: stdout)
      -a URL, --url URL     AP URL
      -W, --wait            wait for access point to reboot after put operations (default: false)
      --dropbear FILE       location of dropbear binary to inject for jailbreak
                            (default: bundled)
