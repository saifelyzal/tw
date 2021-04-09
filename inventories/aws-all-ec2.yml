#!/usr/bin/env python
#
import boto3
#import re
import json

# Paginate function
def paginate(method, **kwargs):
    client = method.__self__
    paginator = client.get_paginator(method.__name__)
    for page in paginator.paginate(**kwargs).result_key_iters():
        for result in page:
            yield result

organization_service_role = 'OrganizationAccountAccessRole'
sts_role_session_name = 'org-session'

session = boto3.Session(region_name='us-east-1')
org_session = session.client('organizations')
regions = [regions['RegionName'] for regions in session.client('ec2').describe_regions()['Regions']]

session = boto3.Session(region_name='us-east-1')
org_session = session.client('organizations')

# Get list of ACTIVE accounts in the organization, this list contains only accounts that have been created or accepted
# an invitation to the organization.  This list will also contain those accounts without the Organization service role.

org_accounts = []
for key in paginate(org_session.list_accounts):
  if key['Status'] == 'ACTIVE':
    org_accounts.append(str(key['Id']))

result = {}
all_hosts = []

#org_accounts = ['191156823442','917848291101']

for account in org_accounts:
  # Iterate through sub accounts
  sts_client = session.client('sts')

  #regions = ['us-east-1','us-west-2']

  for region in regions:  

##############################################################################################################
##############################################################################################################
      # # Use STS to assume a temporary role in the sub account that has the Organization service role.
      # # If the sub account does not have the Organization service role it will be excepted.
      try:
        role_arn = 'arn:aws:iam::' + account + ':role/' + organization_service_role
        sts_response = sts_client.assume_role(
          RoleArn=role_arn,
          RoleSessionName=sts_role_session_name,
          DurationSeconds=900
        )
        # Create boto3 session for account.
        sts_session = boto3.Session(
          aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
          aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
          aws_session_token=sts_response['Credentials']['SessionToken'],
        region_name=region
      )
      except:
      # If sub account does not have Organization service role we log it and ignore the account.
        sts_session = ''
        print('failed to assume role for account', account)
        break
      # else:
      #   sts_session = session 
      
  ##############################################################################################################
  ##############################################################################################################

      if sts_session != '':
      
        #### Code to execute against all regions in every account
        ec2 = sts_session.client('ec2', region_name=region)
        #print('Processing account', account, " and region ", region)
        try:
          instances = ec2.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['pending','stopped','stopping','running']}]
            )

          for i in instances['Reservations']:
            for j in i['Instances']:
              all_hosts.append(j['PrivateIpAddress'])
              #print (j['PrivateIpAddress'])
        except Exception as e:
          print ('Exception: ', 'Account: ', account, ' Region: ', region ,' ', e)
          continue

      else:
        print('No valid session')

result['all'] = all_hosts
print(result)
