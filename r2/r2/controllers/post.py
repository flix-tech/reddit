# The contents of this file are subject to the Common Public Attribution
# License Version 1.0. (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://code.reddit.com/LICENSE. The License is based on the Mozilla Public
# License Version 1.1, but Sections 14 and 15 have been added to cover use of
# software over a computer network and provide for limited attribution for the
# Original Developer. In addition, Exhibit A has been modified to be consistent
# with Exhibit B.
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for
# the specific language governing rights and limitations under the License.
#
# The Original Code is reddit.
#
# The Original Developer is the Initial Developer.  The Initial Developer of
# the Original Code is reddit Inc.
#
# All portions of the code written by reddit are Copyright (c) 2006-2015 reddit
# Inc. All Rights Reserved.
###############################################################################
from pylons import request
from pylons import tmpl_context as c
from pylons import app_globals as g
from pylons import url
from pylons.controllers.util import redirect
from pylons.i18n import _

from r2.lib.pages import *
from reddit_base import set_over18_cookie, delete_over18_cookie
from api import ApiController
from r2.lib.utils import query_string, UrlParser
from r2.lib.emailer import opt_in, opt_out
from r2.lib.validator import *
from r2.lib.validator.preferences import (
    filter_prefs,
    PREFS_VALIDATORS,
    set_prefs,
)
from r2.lib.csrf import csrf_exempt
from r2.models.recommend import ExploreSettings
from r2.controllers.login import handle_login, handle_register, handle_oidc_register
from r2.models import *
from r2.config import feature

from oic.oic import Client
from oic.oic.message import RegistrationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

import json
import hashlib
import hmac
from oic import rndstr

from r2.lib.utils import query_string, UrlParser
from oic.oic.message import AuthorizationResponse

import os


class PostController(ApiController):
    @csrf_exempt
    @validate(pref_lang = VLang('lang'),
              all_langs = VOneOf('all-langs', ('all', 'some'), default='all'))
    def POST_unlogged_options(self, all_langs, pref_lang):
        prefs = {"pref_lang": pref_lang}
        set_prefs(c.user, prefs)
        c.user._commit()
        return self.redirect(request.referer)

    @validate(VUser(), VModhash(),
              all_langs=VOneOf('all-langs', ('all', 'some'), default='all'),
              **PREFS_VALIDATORS)
    def POST_options(self, all_langs, **prefs):
        if feature.is_enabled("autoexpand_media_previews"):
            validator = VOneOf('media_preview', ('on', 'off', 'subreddit'))
            value = request.params.get('media_preview')
            prefs["pref_media_preview"] = validator.run(value)

        u = UrlParser(c.site.path + "prefs")

        filter_prefs(prefs, c.user)
        if c.errors.errors:
            for error in c.errors.errors:
                if error[1] == 'stylesheet_override':
                    u.update_query(error_style_override=error[0])
                else:
                    u.update_query(generic_error=error[0])
            return self.redirect(u.unparse())

        set_prefs(c.user, prefs)
        c.user._commit()
        u.update_query(done='true')
        return self.redirect(u.unparse())

    def GET_over18(self):
        return InterstitialPage(
            _("over 18?"),
            content=Over18Interstitial(),
        ).render()

    @validate(
        dest=VDestination(default='/'),
    )
    def GET_quarantine(self, dest):
        sr = UrlParser(dest).get_subreddit()

        # if dest doesn't include a quarantined subreddit,
        # redirect to the homepage or the original destination
        if not sr:
            return self.redirect('/')
        elif isinstance(sr, FakeSubreddit) or sr.is_exposed(c.user):
            return self.redirect(dest)

        errpage = InterstitialPage(
            _("quarantined"),
            content=QuarantineInterstitial(
                sr_name=sr.name,
                logged_in=c.user_is_loggedin,
                email_verified=c.user_is_loggedin and c.user.email_verified,
            ),
        )
        request.environ['usable_error_content'] = errpage.render()
        self.abort403()

    @csrf_exempt
    @validate(
        over18=nop('over18'),
        dest=VDestination(default='/'),
    )
    def POST_over18(self, over18, dest):
        if over18 == 'yes':
            if c.user_is_loggedin and not c.errors:
                c.user.pref_over_18 = True
                c.user._commit()
            else:
                set_over18_cookie()
            return self.redirect(dest)
        else:
            if c.user_is_loggedin and not c.errors:
                c.user.pref_over_18 = False
                c.user._commit()
            else:
                delete_over18_cookie()
            return self.redirect('/')

    @validate(
        VModhash(fatal=False),
        sr=VSRByName('sr_name'),
        accept=VBoolean('accept'),
        dest=VDestination(default='/'),
    )
    def POST_quarantine(self, sr, accept, dest):
        can_opt_in = c.user_is_loggedin and c.user.email_verified

        if accept and can_opt_in and not c.errors:
            QuarantinedSubredditOptInsByAccount.opt_in(c.user, sr)
            g.events.quarantine_event('quarantine_opt_in', sr,
                request=request, context=c)
            return self.redirect(dest)
        else:
            if c.user_is_loggedin and not c.errors:
                QuarantinedSubredditOptInsByAccount.opt_out(c.user, sr)
            g.events.quarantine_event('quarantine_interstitial_dismiss', sr,
                request=request, context=c)
            return self.redirect('/')

    @csrf_exempt
    @validate(msg_hash = nop('x'))
    def POST_optout(self, msg_hash):
        email, sent = opt_out(msg_hash)
        if not email:
            return self.abort404()
        return BoringPage(_("opt out"),
                          content = OptOut(email = email, leave = True,
                                           sent = True,
                                           msg_hash = msg_hash)).render()

    @csrf_exempt
    @validate(msg_hash = nop('x'))
    def POST_optin(self, msg_hash):
        email, sent = opt_in(msg_hash)
        if not email:
            return self.abort404()
        return BoringPage(_("welcome back"),
                          content = OptOut(email = email, leave = False,
                                           sent = True,
                                           msg_hash = msg_hash)).render()


    @csrf_exempt
    @validate(dest = VDestination(default = "/"))
    def POST_login(self, dest, *a, **kw):
        super(PostController, self).POST_login(*a, **kw)
        c.render_style = "html"
        response.content_type = "text/html"

        if not c.user_is_loggedin:
            return LoginPage(user_login = request.POST.get('user'),
                             dest = dest).render()

        return self.redirect(dest)

    @csrf_exempt
    @validate(dest = VDestination(default = "/"))
    def POST_reg(self, dest, *a, **kw):
        super(PostController, self).POST_register(*a, **kw)
        c.render_style = "html"
        response.content_type = "text/html"

        if not c.user_is_loggedin:
            return LoginPage(user_reg = request.POST.get('user'),
                             dest = dest).render()

        return self.redirect(dest)

    def GET_login(self, *a, **kw):
        return self.redirect('/login' + query_string(dict(dest="/")))

    @validatedForm(
        VUser(),
        VModhash(),
        personalized=VBoolean('pers', default=False),
        discovery=VBoolean('disc', default=False),
        rising=VBoolean('ris', default=False),
        nsfw=VBoolean('nsfw', default=False),
    )
    def POST_explore_settings(self,
                              form,
                              jquery,
                              personalized,
                              discovery,
                              rising,
                              nsfw):
        ExploreSettings.record_settings(
            c.user,
            personalized=personalized,
            discovery=discovery,
            rising=rising,
            nsfw=nsfw,
        )
        return redirect(url(controller='front', action='explore'))

    @csrf_exempt
    @validate(dest = VDestination(default = "/"))
    def GET_oidc(self, dest, *a, **kw):

        client = self.getOidcClient()
        c.oidc_state = rndstr()
        c.oidc_nonce = rndstr()
        redirect_url = g.config.get("default_scheme") + "://" + g.config.get("domain") + "/post/oidc"

        args = {
            "client_id": client.client_id,
            "response_type": ["id_token"],
            "scope": ["openid"],
            "state": c.oidc_state,
            "nonce": c.oidc_nonce,
            "redirect_uri": redirect_url,
            "response_mode": "form_post"
        }

        setattr(c.user, "pref_oidc_nonce", c.oidc_nonce)
        setattr(c.user, "pref_oidc_state", c.oidc_state)
        c.user._commit()

        auth_req = client.construct_AuthorizationRequest(request_args=args)
        login_url = auth_req.request(client.authorization_endpoint)

        return redirect(login_url)

    @csrf_exempt
    @validate(dest = VDestination(default = "/"))
    @validatedForm(
        VRatelimit(rate_ip=True, prefix="rate_register_"),
    )
    def POST_oidc(self, form, responder, dest, *a, **kw):

        client = self.getOidcClient()
        r = request.environ["webob._parsed_post_vars"][-1].read() # reads the post vars

        aresp = client.parse_response(AuthorizationResponse, info=r, sformat="urlencoded")

        session_nonce = getattr(c.user, "pref_oidc_nonce")
        if "id_token" in aresp and aresp["id_token"]["nonce"] != session_nonce:
            raise "The OIDC nonce does not match."

        session_state = getattr(c.user, "pref_oidc_state")
        assert aresp["state"] == session_state

        try:
            username = aresp["id_token"]["unique_name"]
            username = username.replace('@flixbus.com', '')
            username = username.replace('@flixbus.de', '')
            account = Account._by_name(username)

            kw.update(dict(
                controller=self,
                form=form,
                responder=responder,
                user=account,
            ))
            handle_login(**kw)

            if c.user.name in g.admins:
                self.enable_admin_mode(c.user)

            return redirect("/")

        except NotFound:

            username = aresp["id_token"]["unique_name"]
            username = username.replace('@flixbus.com', '')
            username = username.replace('@flixbus.de', '')

            kw.update(dict(
                controller=self,
                responder=responder,
                form=form,
                name=username,
                email=aresp["id_token"]["upn"],
            ))
            handle_oidc_register(**kw)

            if c.user.name in g.admins:
                self.enable_admin_mode(c.user)

            c.user.email_verified = True
            c.user._commit()

            return redirect("/")

    def getOidcClient(self):
        client = Client(client_authn_method=CLIENT_AUTHN_METHOD)

        issuer = g.config.get("oidc_issuer_url")
        client_id = g.config.get("oidc_client_id")
        client_secret = g.config.get("oidc_client_secret")

        client_info = {"client_id": client_id, "client_secret": client_secret}
        client_reg = RegistrationResponse(**client_info)
        client.client_info = client_reg
        client.client_id = client_id

        provider_info = client.provider_config(issuer)
        client.provider_info = provider_info

        return client