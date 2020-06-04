from flask import redirect, g, flash, request, make_response, jsonify
from flask_appbuilder.security.views import UserDBModelView, AuthDBView
from superset.security import SupersetSecurityManager
from flask_appbuilder.security.views import expose
from flask_appbuilder.security.manager import BaseSecurityManager
from superset import authorizer


class CustomAuthDBView(AuthDBView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        redirect_url = self.appbuilder.get_url_for_index
        try:
            print('h2')
            if request.args.get('redirect') is not None:
                redirect_url = request.args.get('redirect')
            if request.args.get('authToken') is not None:
                token = 'Bearer {}'.format(request.args.get('authToken'))
                authorizer.authorize(token, self.appbuilder.sm)
                return redirect(redirect_url)
            elif request.args.get('apiToken') is not None:
                apiToken = request.args.get('apiToken')
                authorizer.authorizeApiToken(apiToken)
                return redirect(redirect_url)
            elif g.user is not None and g.user.is_authenticated:
                return redirect(redirect_url)
            else:
                raise Exception('Login is valid only through "authToken"')
        except Exception as e:
            flash(e, 'warning')
            return super(CustomAuthDBView, self).login()


class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView

    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)
