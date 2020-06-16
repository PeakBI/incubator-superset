import functools
from datetime import timedelta, datetime
from json import loads
from os import environ

from flask import redirect, g, flash, request, make_response, jsonify
from flask_appbuilder.security.views import AuthDBView
from flask_appbuilder.security.views import expose
from flask_login import login_user
from ais_service_discovery import call

from superset.security import SupersetSecurityManager

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


def use_ip_auth(f):
    """
    Use this wrapper to enable IP whitelisting on the APIs
    By default VPC CIDR range is whitelisted
    Will return 404 for unknown IPs
    """
    def wraps(self, *args, **kwargs):
        print('REQUEST RECIEVED')
        print(request)
        client_ip = request.headers['x-forwarded-for'] if request.headers.get('x-forwarded-for') else request.remote_addr
        try:
            loads(call(
                'ais-{}'.format(environ['STAGE']),
                'authentication',
                'ipAuth', {
                    'clientIp': client_ip
                }))
            print('IP AUTH SCCESS')
            return f(self, *args, **kwargs)
        except Exception as e:
            print('IP ERROR {}'.format(e))
            response = make_response(
                jsonify({'message': 'Not Found', }),
                404
            )
            response.headers['Content-Type'] = "application/json"
            return response

    return functools.update_wrapper(wraps, f)


class CustomAuthDBView(AuthDBView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        redirect_url = self.appbuilder.get_url_for_index
        user = 'guest'
        print('REQUEST RECIEVED')
        print(request)
        try:
            if request.args.get('redirect') is not None:
                redirect_url = request.args.get('redirect')

            if request.args.get('authToken') is not None:
                token = 'Bearer {}'.format(request.args.get('authToken'))
                print('GOT TOKEN {}'.format(token))
                auth_response = loads(call(
                    'ais-{}'.format(environ['STAGE']),
                    'authentication',
                    'auth', {
                        'authorizationToken': token
                    }))['context']
                print('AUTH RESPONSE {}'.format(auth_response))
                if not auth_response['tenant'] == environ['TENANT']:
                    raise Exception('Tenant mismatch in token')
                if auth_response['role'] in ['tenantManager', 'tenantAdmin']:
                    user = 'admin'
                else:
                    privileges = loads(auth_response['privileges'])
                    if has_solution_write_access(privileges):
                        user = 'peakuser'
                    elif not has_resource_access(privileges):
                        raise Exception('Insufficient Resource Permissions')
                print("LET US GET USER")
                user = self.appbuilder.sm.find_user(user)
                print('GOT USER', user)
                login_user(user, remember=False,
                           duration=timedelta(
                            auth_response['exp'] - int(
                                datetime.now().timestamp())))
                print('LOGIN SUCCESSFUL')
                return redirect(redirect_url)
            elif g.user is not None and g.user.is_authenticated:
                return redirect(redirect_url)
            else:
                raise Exception('Login is valid only through "authToken"')
        except Exception as e:
            print('FAATA')
            print(e)
            flash(e, 'warning')
            return super(CustomAuthDBView, self).login()


class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView

    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)
