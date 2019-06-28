# -*- coding: utf-8 -*-
# © 2019 Coop IT Easy (http://www.coopiteasy.be)
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import logging
from openerp import tools
from openerp.tools.translate import _

from openerp import http
from openerp.http import request
from openerp.addons.auth_signup.res_users import SignupError
from openerp.addons.auth_signup.controllers.main import AuthSignupHome
from openerp.addons.base_iban import base_iban
from openerp.exceptions import ValidationError

_logger = logging.getLogger(__name__)

FORM_FIELDS = ['login', 'firstname', 'password', 'phone', 'street',
               'city', 'zip_code', 'country_id']


class AuthSignupHome(AuthSignupHome):
    def _signup_with_values(self, token, values):
        user_obj = request.env['res.users']
        db, login, password = user_obj.sudo().signup(values, token)
        # as authenticate will use its own cursor we need to commit
        # the current transaction
        request.cr.commit()
        uid = request.session.authenticate(db, login, password)
        if not uid:
            raise SignupError(_('Authentication Failed.'))
        return uid

    def do_signup(self, qcontext):
        """ Shared helper that creates a res.partner out of a token """
        bank_obj = request.env['res.partner.bank']
        lang_obj = request.env['res.lang']

        values = dict((key, qcontext.get(key)) for key in FORM_FIELDS)
        assert any([k for k in values.values()]),"The form was not properly filled in."
        assert values.get('password') == qcontext.get('confirm_password'), "Passwords do not match; please retype them."
        supported_langs = [lang['code'] for lang
                           in lang_obj.sudo().search_read([], ['code'])]
        if request.lang in supported_langs:
            values['lang'] = request.lang
        values['lastname'] = qcontext.get('name')
        values['name'] = values.get('firstname') + ' ' + values.get('lastsname')
        values['zip'] = values['zip_code']
        uid = self._signup_with_values(qcontext.get('token'), values)
        iban = qcontext.get('iban')
        user = request.env['res.users'].sudo().search([('id', '=', uid)])
        bank_obj.sudo().create({'partner_id': user.partner_id.id,
                                'acc_number': iban})
        request.cr.commit()

    @http.route('/web/signup', type='http', auth='public', website=True)
    def web_auth_signup(self, *args, **kw):
        qcontext = self.get_auth_signup_qcontext()
        users_obj = request.env["res.users"]
        country_obj = request.env['res.country']

        if qcontext.get("login", False) and not tools.single_email_re.match(qcontext.get("login", "")):
            qcontext["error"] = _("That does not seem to be an email address.")
        if qcontext.get("iban", False):
            try:
                base_iban.validate_iban(qcontext.get("iban"))
            except ValidationError:
                qcontext["error"] = _("Please give a correct IBAN number.")
        if not qcontext.get('token') and not qcontext.get('signup_enabled'):
            raise werkzeug.exceptions.NotFound()

        if 'error' not in qcontext and request.httprequest.method == 'POST':
            try:
                self.do_signup(qcontext)
                return super(AuthSignupHome, self).web_login(*args, **kw)
            except (SignupError, AssertionError), e:
                domain = [("login", "=", qcontext.get("login"))]
                if users_obj.sudo().search(domain):
                    qcontext["error"] = _("Another user is already registered "
                                          "using this email address.")
                else:
                    _logger.error(e.message)
                    qcontext['error'] = _("Could not create a new account.")
        if not qcontext.get('raliment_point_id', False):
            qcontext['raliment_point_id'] = 0
        if not qcontext.get('delivery_point_id', False):
            qcontext['delivery_point_id'] = 0
        qcontext['countries'] = country_obj.sudo().search([])
        qcontext['country_id'] = '21'

        return request.render('auth_signup.signup', qcontext)
