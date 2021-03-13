#!/usr/bin/env python3
# MIT License

# Copyright (c) 2021 Chris Farris

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import json
import csv
import boto3
from botocore.exceptions import ClientError


import logging
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)



def main(args):

    client = boto3.client('ec2')
    instances = get_instances(client)

    for i in instances.keys():
        if 'Name' not in instances[i]:
            print(f"No Name for {i}")
            continue

        desc = f"2021 SECCDC Regionals {i} {instances[i]['Name']}"
        print(desc)

        response = client.create_snapshots(
            Description=desc,
            InstanceSpecification={
                'InstanceId': i,
                'ExcludeBootVolume': False
            }
        )


0f354cd754de41f3d

def get_instances(client):
    instances = {}

    response = client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}])

    for r in response['Reservations']:
        for i in r['Instances']:
            if 'Tags' in i:
                for t in i['Tags']:
                    if t['Key'] == "Name":
                        i['Name'] = t['Value']
        instances[i['InstanceId']] = i
    return(instances)


if __name__ == '__main__':

    # Process Arguments
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="print debugging info", action='store_true')
    parser.add_argument("--error", help="print error info only", action='store_true')
    args = parser.parse_args()

    # Logging idea stolen from: https://docs.python.org/3/howto/logging.html#configuring-logging
    # create console handler and set level to debug
    ch = logging.StreamHandler()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.error:
        logger.setLevel(logging.ERROR)
    else:
        logger.setLevel(logging.INFO)
    # create formatter
    # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    # add formatter to ch
    ch.setFormatter(formatter)
    # add ch to logger
    logger.addHandler(ch)

    # Wrap in a handler for Ctrl-C
    try:
        exit(main(args))
    except KeyboardInterrupt:
        exit(1)