import logging
from flask_login import login_user, logout_user
from ais_service_discovery import call
from json import loads
from datetime import timedelta, datetime
from os import environ
from superset import config

def has_resource_access(privileges):
    for config in privileges['level']['tenant']['tenants']:
      if config['tenant'] == environ['TENANT']:
          for resource in config['resources']:
            if ('appId' in resource) and (resource['appId'] in ['customerAi', 'demandAi']):
              return True
    return False

def has_solution_write_access(privileges):
    for config in privileges['level']['tenant']['tenants']:
      if config['tenant'] == environ['TENANT']:
          for resource in config['resources']:
            if (resource['name'] == 'SOLUTION MANAGER') and (resource['action'] == 'write'):
              return True
    return False

def authorize(token, sm):
    auth_response={}
    MAX_RETRY = 5
    role='Gamma'
    for x in range(MAX_RETRY):
      try:
        auth_response = loads(call(
        'ais-{}'.format(environ['STAGE']),
        'authentication',
        'auth', {
            'authorizationToken': token
        }))['context']
        break
      except ConnectionResetError:
        logging.info('Connection Error, Retrying...')
    if not auth_response['tenant'] == environ['TENANT']:
        raise Exception('Tenant mismatch in token')
    if auth_response['role'] in ['tenantManager', 'tenantAdmin']:
        role = 'Admin'
    else:
        privileges = loads(auth_response['privileges'])
        if has_solution_write_access(privileges):
            role = 'peak_user'
        elif not has_resource_access(privileges):
            raise Exception('Insufficient Resource Permissions')
    user = sm.find_user(auth_response['email'].split('@')[0])
    if not user:
        sm.add_user(
            auth_response['email'].split('@')[0],
            auth_response['firstName'],
            auth_response['lastName'],
            auth_response['email'],
            sm.find_role(role),
            password="general",
        )
        user = sm.find_user(auth_response['email'].split('@')[0])
    login_user(user, remember=False,
            duration=timedelta(
            auth_response['exp'] - int(
                datetime.now().timestamp())))

