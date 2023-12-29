# sshscan

## Introduction
sshscan is an open source penetration testing tool, able to perform a password spraying attack against ssh services. It can also automatically execute bash code on the target machine after gaining acces


## Installation


### Linux distro
```bash
pip install -r requirements.txt
 ```

### From virtual env
```bash
python3 -m venv sshscan
source sshscan/bin/activate
pip install -r requirements.txt

 ```

## Usage
```bash

python sshscan.py scan --help

NAME
    sshscan.py scan

SYNOPSIS
    sshscan.py scan START_IP END_IP USER_FILE PASSWORD_FILE <flags>

POSITIONAL ARGUMENTS
    START_IP
    END_IP
    USER_FILE
    PASSWORD_FILE

FLAGS
    -v, --verbose=VERBOSE
        Default: False
    -p, --port=PORT
        Default: 22
    -m, --max_thread=MAX_THREAD
        Default: 10
    -t, --timeout=TIMEOUT
        Default: 3
    -c, --command=COMMAND
        Type: Optional[]
        Default: None

NOTES
    You can also use flags syntax for POSITIONAL ARGUMENTS
(END)


```
## Examples

### Default scan
```bash

python sshscan.py scan 192.168.178.1 192.168.254 user.txt password.txt


```

### Execute command
```bash

python sshscan.py scan 192.168.178.1 192.168.254 user.txt password.txt --port 22 -m 5 -t 5 -c "whoami && ls -all"


```

