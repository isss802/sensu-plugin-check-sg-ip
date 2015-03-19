# Overview

Check IP of security group plugin for Sensu.

# Installation

Put `check-sg-ip.py` into `/etc/sensu/plugins`.

# Usage

```
usage: check-sg-ip.py [-h] [-a AWS_ACCESS_KEY_ID] [-s AWS_SECRET_ACCESS_KEY]
                      -r REGION -g SGIDS -i CHECKIP

Check IP of security group

optional arguments:
  -h, --help            show this help message and exit
  -a AWS_ACCESS_KEY_ID, --aws-access-key-id AWS_ACCESS_KEY_ID
                        AWS Access Key
  -s AWS_SECRET_ACCESS_KEY, --aws-secret-access-key AWS_SECRET_ACCESS_KEY
                        AWS Secret Access Key
  -r REGION, --region REGION
                        AWS Region
  -g SGIDS, --sgid SGIDS
                        AWS Security Group ID
  -i CHECKIP, --ip CHECKIP
                        IP Adress
```

You can omit `--aws-access-key-id`, `--aws-secret-access-key`, `--profile` and `--region`. If so, this script will try obtaining credentials/region from instance's IAM role and region.

# Example

```
# ./check-sg-ip.py -r ap-northeast-1 -g sg-xxxxxxxx -i 123.123.123.123/32
111.222.111.222/32
10.100.0.0/16
None
Check OK

#./check-sg-ip.py -r ap-northeast-1 -g sg-xxxxxxxx -i 10.100.0.0/16
CRITICAL:Match IP 10.100.0.0/16
```

# Changelog

