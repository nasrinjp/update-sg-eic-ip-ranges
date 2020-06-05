from logging import getLogger, INFO
import urllib.request
import json
import boto3
import os

logger = getLogger()
logger.setLevel(INFO)


def get_request(url):
    request = urllib.request.Request(url)
    with urllib.request.urlopen(request) as response:
        body = response.read()
    return body


def get_eic_cidr(ip_ranges, region='ap-northeast-1'):
    for cidr_info in ip_ranges:
        if cidr_info['service'] == 'EC2_INSTANCE_CONNECT' and cidr_info['region'] == region:
            sg_cidr = cidr_info['ip_prefix']
    return sg_cidr


def generate_ip_permission(cidr, sg_entry_description):
    return [
        {
            'FromPort': 22,
            'IpProtocol': 'tcp',
            'IpRanges': [
                {
                    'CidrIp': cidr,
                    'Description': sg_entry_description
                }
            ],
            'ToPort': 22
        }
    ]


def lambda_handler(event, context):
    maintenance_sg = os.getenv('maintenance_sg')
    sg_entry_description = os.getenv('sg_entry_description')
    url = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
    ip_ranges = json.loads(get_request(url).decode('utf8'))['prefixes']
    eic_cidr = get_eic_cidr(ip_ranges)

    ec2 = boto3.resource('ec2')
    security_group = ec2.SecurityGroup(maintenance_sg)
    current_cidr = 'empty'
    for entry in security_group.ip_permissions:
        if entry['IpRanges'][0]['Description'] == sg_entry_description:
            current_cidr = entry['IpRanges'][0]['CidrIp']
            break

    logger.info(
        f'The result of getting from ip-ranges is {eic_cidr}, the CIDR of current security group entry is {current_cidr}.')

    if current_cidr != eic_cidr:
        if current_cidr != 'empty':
            security_group.revoke_ingress(
                IpPermissions=generate_ip_permission(
                    current_cidr, sg_entry_description)
            )
        security_group.authorize_ingress(
            IpPermissions=generate_ip_permission(
                eic_cidr, sg_entry_description)
        )
    else:
        logger.info(
            f'The security group {maintenance_sg} is not changed because the CIDR for EIC is not updated.')
