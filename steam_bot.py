import requests
from cookielib import LWPCookieJar, FileCookieJar, Cookie
import os
from sys import platform
import time
from rsa import encode
import datetime
from email_reader import EmailReader, GLOBAL_CHECK_INTERVAL, GLOBAL_CHECK_RETRIES
import json
from hashlib import sha1
import base64
import hmac
COOKIE_PATH = "/usr/share/www/cookies/"
# from . import COOKIE_PATH
from BeautifulSoup import BeautifulSoup
import re
import logging
import sys
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger("steam_bot")

GLOBAL_AUTHENTICATOR_FINALIZING_TRIES = 20

if platform == "linux" or platform == "linux2" or platform == "darwin":
    COOKIE_FOLDER = COOKIE_PATH
elif platform == "win32":
    COOKIE_FOLDER = ''


class LWPSaveLoadCookieJar(LWPCookieJar, FileCookieJar):
    def __init__(self, filename):
        if not os.path.isfile(os.path.abspath(filename)):
            self.create_empty_lwp_file(filename)
        FileCookieJar.__init__(self, filename)

    @staticmethod
    def create_empty_lwp_file(filename):
        f = open(filename, "w")
        f.write("#LWP-Cookies-2.0\n")
        f.close()


class CookieProcessor():
    def __init__(self, cookie_jar=None):
        import cookielib

        if cookie_jar is None:
            cookie_jar = cookielib.CookieJar()
        self.cookie_jar = cookie_jar

    def load_cookie_on_request(self):
        self.cookie_jar.load(ignore_discard=True)

    def save_cookie_on_response(self):
        for domain_key, domain in self.cookie_jar._cookies.iteritems():
            domain_cookie = domain.get('/')
            if domain_cookie is not None:
                for cookie_key, cookie in domain_cookie.iteritems():
                    if cookie_key != 'steamCountry':
                        cookie.discard = False
        self.cookie_jar.save()


def web_request(func):
    def wrapper(self, *args, **kwargs):
        if isinstance(self, WebClient):
            self._cookie_processor.load_cookie_on_request()
            response = func(self, *args, **kwargs)
            self._cookie_processor.save_cookie_on_response()
            return response
        else:
            raise Exception("This decorator could wrap only WebClient's methods")

    return wrapper


def login_required(func):
    def wrapper(self, *args, **kwargs):
        if isinstance(self, SteamBot) and self._logged_in is True:
            return func(self, *args, **kwargs)
        else:
            raise Exception("Steam Web logon required for this method")

    return wrapper


class CacheConfigurator(object):
    def __init__(self, filename):
        self._cache_config_path = filename
        self._cache = {}

        if os.path.exists(self._cache_config_path):
            with open(self._cache_config_path, 'r+') as input_file:
                self._cache = json.load(input_file)
        else:
            with open(self._cache_config_path, 'w+') as output_file:
                json.dump(self._cache, output_file)

    def update_cache_config(self, cache_dict):
        self._cache = cache_dict
        with open(self._cache_config_path, 'w+') as output_file:
                json.dump(self._cache, output_file)

    def cache_dict(self):
        return self._cache


class WebClient(object):
    def __init__(self, cookie_file_name='default.cookie', cookie_handler=LWPSaveLoadCookieJar):
        self._cookie_file_name = cookie_file_name
        self._cookie_jar = cookie_handler(cookie_file_name)
        self._cookie_processor = CookieProcessor(self._cookie_jar)
        self._session = requests.Session()
        self._session.cookies = self._cookie_jar

        self._default_headers = [
            {
                "User-Agent": "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30"
            }
        ]

        self._default_cookies = []

        self._set_default_headers()
        self._set_default_cookies()

    def _set_default_headers(self):
        for header in self._default_headers:
            self._session.headers.update(header)

    def _set_default_cookies(self):
        for cookie in self._default_cookies:
            self._session.cookies.set_cookie(cookie)

    def enable_mobile(self):
        self._default_cookies = [
            Cookie(version=0, name='mobileClientVersion', value="0 (2.1.3)", port=None, port_specified=False,
                   domain='steamcommunity.com', domain_specified=False, domain_initial_dot=False, path='/',
                   path_specified=True, secure=False, expires=None, discard=False, comment=None, comment_url=None,
                   rest={}, rfc2109=False),
            Cookie(version=0, name='mobileClient', value="android", port=None, port_specified=False,
                   domain='steamcommunity.com', domain_specified=False, domain_initial_dot=False, path='/',
                   path_specified=True, secure=False, expires=None, discard=False, comment=None, comment_url=None,
                   rest={}, rfc2109=False),
            Cookie(version=0, name='Steam_Language', value="english", port=None, port_specified=False,
                   domain='steamcommunity.com', domain_specified=False, domain_initial_dot=False, path='/',
                   path_specified=True, secure=False, expires=None, discard=False, comment=None, comment_url=None,
                   rest={}, rfc2109=False)
        ]

        self._default_headers = [
            {
                "User-Agent": "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30"
            },
            {
                "Accept": "text/javascript, text/html, application/xml, text/xml, */*"
            },
            {
                "X-Requested-With": "com.valvesoftware.android.steam.community"
            },
            {
                "Referer": "https://steamcommunity.com/mobilelogin?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client"
            }
        ]
        self._set_default_headers()
        self._set_default_cookies()

    @web_request
    def post(self, url, data=None, json=None, **kwargs):
        response = self._session.post(url, data=data, json=json, **kwargs)
        return response

    @web_request
    def get(self, url, **kwargs):
        response = self._session.get(url, **kwargs)
        return response


class TimeAligner(object):
    def __init__(self):
        self._aligned = False
        self._time_difference = datetime.timedelta(0, 0, 0, 0, 0, 0, 0)

    def _align_time(self):
        local_timestamp = self._unix_time().total_seconds()
        steam_time_url = 'https://api.steampowered.com/ITwoFactorService/QueryTime/v0001'
        response = requests.post('%s?steamid=0' % steam_time_url)
        time_data = response.json()
        self._time_difference = int(
            time_data.get('response', {}).get('server_time', local_timestamp)) - local_timestamp
        self._aligned = True

    def _unix_time(self):
        return datetime.datetime.utcnow() - datetime.datetime(1970, 1, 1)

    def steam_time(self):
        if self._aligned:
            return self._unix_time().total_seconds() + self._time_difference
        else:
            self._align_time()
            return self._unix_time().total_seconds() + self._time_difference


class SteamBot(object):
    def __init__(self, username, email=None, email_password=None):
        self.username = username
        self.email = None
        self._email_password = None
        self.email_reader = None
        self._logged_in = False
        self._time_aligner = TimeAligner()
        if self.username:
            self._cache_configurator = CacheConfigurator(os.path.join(COOKIE_FOLDER, '%s-cache.json' % username))
            self._web_client = WebClient(os.path.join(COOKIE_FOLDER, '%s.cookie' % username))
            self._cached = self._cache_configurator.cache_dict()
        else:
            self._cached = {}

        if email and email_password:
            self.email = email
            self._email_password = email_password
            self.email_reader = EmailReader(self.email, self._email_password)

    def _get_steam_rsa_key(self):
        url = "https://steamcommunity.com/login/getrsakey/"
        post_data = {
            "username": self.username,
            "donotcache": int(time.time())
        }
        response = self._web_client.post(url, data=post_data)
        if response.status_code < 400:
            return response.json()
        raise Exception("Cannot retrieve steam RSA key")

    def _update_cache_json(self):
        self._cache_configurator.update_cache_config(self._cached)

    @staticmethod
    def convert_steam_id(n):
        if not isinstance(n, str):
            n = str(n)

        return str(int(n[3:]) - 61197960265728)

    @staticmethod
    def _encrypt_password(rsa_key, password):
        return encode(password, rsa_key["publickey_mod"], rsa_key["publickey_exp"])

    @staticmethod
    def _generate_device_id():
        random_bytes = bytearray(os.urandom(8))
        random_hash = sha1(random_bytes)
        random32 = random_hash.hexdigest().decode("utf-8").replace("-", "").lower()[:32]
        device_id = "android:"
        ratios = [8, 4, 4, 4, 12]
        pos = 0
        for index, ratio in enumerate(ratios):
            device_id += random32[pos:pos + ratio]
            pos += ratio

            if index < len(ratios) - 1:
                device_id += "-"
        return str(device_id)

    def _get_steam_time(self):
        return long(self._time_aligner.steam_time())

    def _get_last_auth_code(self, auth_time):
        auth_code = None
        connect_tries = 0
        while connect_tries < GLOBAL_CHECK_RETRIES and auth_code is None:
            auth_code = self.email_reader.find_fresh_auth_code(auth_time)

            if auth_code is None:
                time.sleep(GLOBAL_CHECK_INTERVAL)
            connect_tries += 1
        if auth_code is None:
            raise Exception("Cannot retrieve fresh auth code from email")

        return auth_code

    def mobile_login(self, password):
        self._web_client.enable_mobile()
        return self.web_login(password, is_mobile=True)

    def web_login(self, password, auth_code=None, is_mobile=False, two_factor=False):
        main_data = {}
        login_url = "https://steamcommunity.com/login/dologin/"
        rsa_key = self._get_steam_rsa_key()

        login_data = {
            "password": self._encrypt_password(rsa_key, password),
            "username": self.username,
            "emailauth": "",
            "captchagid": main_data.get("captcha_gid", "-1"),
            "donotcache": int(time.time()),
            "captcha_text": "",
            "emailsteamid": main_data.get("emailsteamid", ""),
            "rsatimestamp": rsa_key["timestamp"],
            "remember_login": True,
            "twofactorcode": "",
            "loginfriendlyname": "",
            "oauth_client_id": "DE45CD61",
            "oauth_scope": "read_profile write_profile read_client write_client"
        }
        if is_mobile:
            login_data["loginfriendlyname"] = "#login_emailauth_friendlyname_mobile"

        if auth_code is not None:
            if two_factor:
                login_data["twofactorcode"] = auth_code
            else:
                login_data["emailauth"] = auth_code

        auth_time = datetime.datetime.utcnow()
        auth_response = self._web_client.post(login_url, data=login_data)
        if auth_response.status_code < 400:
            main_data = auth_response.json()
        else:
            raise Exception("web_login: Authentication error")

        if main_data.get("captcha_gid", -1) != -1:
            raise Exception("web_login: Captcha resolve required")

        if not main_data.get("success", False) and main_data != {}:
            if main_data.get('message', '') == "Error verifying humanity":
                raise Exception("web_login: Captcha resolve required")
            elif main_data.get("emailauth_needed", False):
                if self.email and self._email_password:
                    auth_code = self._get_last_auth_code(auth_time)
                    if auth_code:
                        return self.web_login(password, auth_code=auth_code, is_mobile=is_mobile)
                    raise Exception("web_login: Getting Auth code retries exceeded")
                else:
                    raise Exception("web_login: Email auth required, but none of email credentials provided")
            elif main_data.get("requires_twofactor", False):
                return self.web_login(password, auth_code=self._generate_steam_guard_code(self._get_steam_time()),
                                      is_mobile=is_mobile, two_factor=True)

        if main_data.get("login_complete", False):
            oauth_data = json.loads(main_data['oauth'])
            self._cache_param('steam_id', oauth_data.get('steamid'))
            self._cache_param('oauth_token', oauth_data.get('oauth_token'))
            self._cache_param('wgtoken', oauth_data.get('wgtoken'))
            self._cache_param('wgtoken_secure', oauth_data.get('wgtoken_secure'))
            self._update_cache_json()

            if not is_mobile:
                url = main_data.get("transfer_urls")[0].replace('\\', '')
                main_data["transfer_parameters"]["remember_login"] = True
                self._web_client.post(url, main_data["transfer_parameters"])

            self._web_client.get("http://steamcommunity.com/market/")
            self._logged_in = True
            return True

        return False

    def check_logon(self):
        response = self._web_client.get("http://steamcommunity.com/market/")
        if response.content.find(self.username) != -1:
            self._logged_in = True
            return True
        self._logged_in = False
        return False

    def _cache_param(self, param, val):
        self._cached[param] = val

    def _generate_steam_guard_code(self, authenticator_time):
        if not self._cached.get('shared_secret', None):
            return ""

        shared_secret = self._cached.get('shared_secret', None)
        steam_guard_code_translations = bytearray([50, 51, 52, 53, 54, 55, 56, 57, 66, 67, 68, 70, 71, 72, 74, 75, 77,
                                                   78, 80, 81, 82, 84, 86, 87, 88, 89])
        shared_secret_array = bytearray(base64.b64decode(shared_secret))
        _time = authenticator_time / long(30)
        time_array = bytearray(8)

        for index in range(8, 0, -1):
            time_array[index - 1] = _time & 0xFF
            _time >>= 8

        time_array = bytearray(time_array)

        hashed_data = bytearray(hmac.new(shared_secret_array, time_array, sha1).digest())
        code_array = bytearray(5)
        try:
            b = hashed_data[19] & 0xF
            code_point = (hashed_data[b] & 0x7F) << 24 | (hashed_data[b + 1] & 0xFF) << 16 | (hashed_data[b + 2] & 0xFF) << 8 | (hashed_data[b + 3] & 0xFF)

            for index in range(0, 5):
                code_array[index] = steam_guard_code_translations[code_point % len(steam_guard_code_translations)]
                code_point /= len(steam_guard_code_translations)
        except:
            return None

        return code_array.decode("UTF-8")

    def _generate_steam_confirmation_code(self, authenticator_time, tag=None):
        if not self._cached.get('identity_secret', None):
            return ""

        identity_secret = self._cached.get('identity_secret', None)
        identity_secret_array = bytearray(base64.b64decode(identity_secret))
        _time = long(authenticator_time)

        n2 = 8
        if tag:
            if len(tag) > 32:
                n2 += 32
            else:
                n2 += len(tag)
        time_array = bytearray(n2)
        n3 = 8
        while True:
            n4 = n3 - 1
            if n3 <= 0:
                break
            time_array[n4] = _time & 0xFF
            _time >>= 8
            n3 = n4

        if tag:
            tag_bytearray = bytearray(tag)
            pos = len(tag) - 1
            for index in range(n2 - 1, n2 - len(tag) - 1, -1):
                time_array[index] = tag_bytearray[pos]
                pos -= 1

        try:
            hashed_data = bytearray(hmac.new(identity_secret_array, time_array, sha1).digest())
            encoded_data = base64.b64encode(hashed_data)
            return encoded_data
        except:
            return None

    def _generate_confirmation_query(self, tag="conf"):
        steam_time = self._get_steam_time()
        return "p=" + self._cached.get('device_id', "") + "&a=" + self._cached.get('steam_id', "") + "&k="\
               + self._generate_steam_confirmation_code(steam_time, tag=tag) + "&t="\
               + str(steam_time) + "&m=android&tag=" + tag

    def _confirm_action(self, confirmation, action):
        url = "https://steamcommunity.com/mobileconf/ajaxop?op=" + action + "&"\
              + self._generate_confirmation_query(tag=action) + "&cid=" + confirmation["id"] + "&ck=" + confirmation["key"]
        additional_headers = {
                "Referer": "https://steamcommunity.com/mobileconf/conf?" + self._generate_confirmation_query("conf")
            }

        return self._web_client.get(url, headers=additional_headers, timeout=20).json().get("success", False)

    @login_required
    def refresh_session(self):
        refresh_url = "https://api.steampowered.com//IMobileAuthService/GetWGToken/v0001"
        post_data = {
            "access_token": self._cached.get('oauth_token', None)
        }
        response = self._web_client.post(refresh_url, data=post_data)

        if response.status_code < 399:
            main_data = response.json().get("response")
            if main_data:
                token = self._cached.get("steam_id") + "%7C%7C" + main_data.get("token")
                token_secure = self._cached.get("steam_id") + "%7C%7C" + main_data.get("token_secure")
                self._cache_param("steamLogin", token)
                self._cache_param("steamLoginSecure", token_secure)
                self._update_cache_json()
                return True

        return False

    @login_required
    def _has_phone_number(self):
        bot_cookies = self._web_client._cookie_jar._cookies["steamcommunity.com"]["/"]
        post_data = {
            "op": "has_phone",
            "arg": "null",
            "sessionid": bot_cookies["sessionid"].value
        }

        response = self._web_client.post('https://steamcommunity.com//steamguard/phoneajax', data=post_data)
        return response.json().get('has_phone', False)

    @login_required
    def _check_sms_code(self, sms_code):
        bot_cookies = self._web_client._cookie_jar._cookies["steamcommunity.com"]["/"]
        post_data = {
                "op": "check_sms_code",
                "arg": str(sms_code),
                "sessionid": bot_cookies["sessionid"].value,
        }
        finalize_url = "https://steamcommunity.com/steamguard/phoneajax"

        response = self._web_client.post(finalize_url, data=post_data)
        return response.json().get('success', False)

    @login_required
    def _add_phone_number(self, phone_number):
        if not self._has_phone_number():
            bot_cookies = self._web_client._cookie_jar._cookies["steamcommunity.com"]["/"]
            post_data = {
                "op": "add_phone_number",
                "arg": str(phone_number),
                "sessionid": bot_cookies["sessionid"].value,
            }
            response = self._web_client.post('https://steamcommunity.com/steamguard/phoneajax', data=post_data)
            self._cache_param('phone_number', phone_number)
            self._update_cache_json()
            return response.json().get('success', False)
        return True

    @login_required
    def add_authenticator(self, phone_number):
        if self._add_phone_number(phone_number):
            if not self._cached.get('device_id', False):
                self._cache_param('device_id', self._generate_device_id())
                self._update_cache_json()

            post_data = {
                "access_token": self._cached.get('oauth_token', None),
                "steamid": self.steam_id(),
                "authenticator_type": 1,
                "device_identifier": self._cached.get('device_id'),
                "sms_phone_id": 1
            }

            response = self._web_client.post("https://api.steampowered.com/ITwoFactorService/AddAuthenticator/v0001",
                                             data=post_data)
            main_data = response.json().get('response', {})
            status = int(main_data.get("status"))

            if status == 29:
                return True

            elif status == 1:
                self._cache_param("identity_secret", main_data.get("identity_secret", None))
                self._cache_param("revocation_code", main_data.get("revocation_code", None))
                self._cache_param("secret_1", main_data.get("secret_1", None))
                self._cache_param("shared_secret", main_data.get("shared_secret", None))
                self._update_cache_json()
                return True

        return False

    @login_required
    def remove_authenticator(self, scheme=2):
        if self._has_phone_number():

            post_data = {
                "access_token": self._cached.get('oauth_token', None),
                "steamid": self.steam_id(),
                "revocation_code": self._cached.get('revocation_code'),
                "steamguard_scheme": str(scheme)
            }

            response = self._web_client.post("https://api.steampowered.com/ITwoFactorService/RemoveAuthenticator/v0001",
                                             data=post_data)
            main_data = response.json().get('response', {})
            if main_data.get('success', False):
                self._cache_param("authenticator_enabled", False)
                self._cache_param("phone_approved", False)
                self._cache_param("revocation_code", None)
                self._update_cache_json()
                return True

        return False

    @login_required
    def finalize_authenticator(self, sms_code):
        if not self._cached.get('phone_approved', False):
            if self._check_sms_code(sms_code):
                self._cache_param('phone_approved', True)
                self._update_cache_json()
                self.add_authenticator(self._cached.get('phone_number', None))
                return False
            raise Exception("Unable to confirm the phone number")

        post_data = {
            "access_token": self._cached.get('oauth_token', None),
            "steamid": self.steam_id(),
            "activation_code": sms_code,
            "authenticator_code": None,
            "authenticator_time": None
        }

        tries = 0
        while tries <= GLOBAL_AUTHENTICATOR_FINALIZING_TRIES:
            post_data["authenticator_code"] = self._generate_steam_guard_code(self._get_steam_time())
            post_data["authenticator_time"] = str(self._get_steam_time())

            finalize_url = "https://api.steampowered.com/ITwoFactorService/FinalizeAddAuthenticator/v0001"

            response = self._web_client.post(finalize_url, data=post_data)

            if response.status_code > 399:
                raise Exception("Finalize API is not responding")

            main_data = response.json()
            if not main_data.get("response"):
                raise Exception("Empty response")

            response = main_data["response"]
            status = int(response.get("status"))

            if status == 89:
                raise Exception("Invalid SMS Code provided")
            elif status == 88:
                if tries > GLOBAL_AUTHENTICATOR_FINALIZING_TRIES:
                    raise Exception("Cannot generate correct code")

            if not response.get('success', False):
                raise Exception("Unsuccessful response")

            if response.get('want_more', False):
                tries += 1
                continue

            self._cache_param("authenticator_enabled", True)
            self._update_cache_json()
            return True
        return False

    @login_required
    def api_key(self):
        if not self._cached.get("steam_api_key", None):
            api_key_url = "https://steamcommunity.com/dev/apikey?l=en"
            response = self._web_client.get(api_key_url)
            if response.content.find("Your Steam Web API Key") != -1:
                first_tilt = "<p>Key: "
                api_key = response.content[response.content.find(first_tilt) + len(first_tilt):].split('</p>')[0]
                self._web_client.get("http://steamcommunity.com/market/")
                self._cache_param("steam_api_key", api_key)
                self._update_cache_json()
                return api_key
            else:
                register_key_url = "https://steamcommunity.com/dev/registerkey?l=en"
                cookies = self._web_client._cookie_jar._cookies['steamcommunity.com']['/']
                self._web_client.post(register_key_url, data={
                    "domain": "fightoo.com",
                    "agreeToTerms": "agreed",
                    "Submit": "Register",
                    "l": "en",
                    "sessionid": cookies["sessionid"].value
                })
                return self.api_key()
        return self._cached["steam_api_key"]

    @login_required
    def steam_id(self):
        steam_id = self._cached.get("steam_id", self._web_client._cookie_jar._cookies["steamcommunity.com"]["/"][
                                                    "steamLogin"].value[:17])
        if not self._cached.get("steam_api_key", None):
            self._cache_param("steam_id", steam_id)
            self._update_cache_json()
        return steam_id

    @login_required
    def check_trade_availability(self):
        response = self._web_client.get(
            'https://steamcommunity.com/tradeoffer/new/?partner=%s&token=%s' % ('18934441', 'fYFrN25o'))
        if response.content.find('Sorry, some kind of error has occurred') == -1:
            return True
        response_soup = BeautifulSoup(response.content)
        error_msg = response_soup.find("div", attrs={"id": "error_msg"}).text
        return error_msg

    @login_required
    def send_tradeoffer(self, receiver_steam_id, receiver_trade_token, receiver_items, bot_items, message=''):
        tradeoffer_id = None
        receiver_steam_id_short = self.convert_steam_id(receiver_steam_id)
        context_id = 2
        version = 1

        bot_cookies = self._web_client._cookie_jar._cookies["steamcommunity.com"]["/"]
        processed_receiver_items = []
        processed_bot_items = []

        for item in receiver_items:
            processed_receiver_items.append({
                "appid": int(item["appid"]),
                "contextid": str(context_id),
                "amount": int(1),
                "assetid": item.get("id", item.get("assetid"))
            })
            version += 1

        for item in bot_items:
            processed_bot_items.append({
                "appid": int(item["appid"]),
                "contextid": str(context_id),
                "amount": int(1),
                "assetid": item.get("id", item.get("assetid"))
            })
            version += 1

        response = self._web_client.get("https://steamcommunity.com/tradeoffer/new/?partner=%s&token=%s" %
                                        (receiver_steam_id_short, receiver_trade_token))

        if response.content.find("Sorry, some kind of error has occurred") == -1:
            trade_offer_data = {
                "newversion": True,
                "version": version,
                "me": {
                    "assets": processed_bot_items,
                    "currency": [],
                    "ready": False
                },
                "them": {
                    "assets": processed_receiver_items,
                    "currency": [],
                    "ready": False
                },
            }

            post_data = {
                "serverid": 1,
                "sessionid": bot_cookies["sessionid"].value,
                "partner": str(receiver_steam_id),
                "json_tradeoffer": json.dumps(trade_offer_data, separators=(",", ":")),
                "trade_offer_create_params": json.dumps({"trade_offer_access_token": str(receiver_trade_token)}),
                "tradeoffermessage": str(message),
                "captcha": ""
            }

            logger.debug("send_tradeoffer: post_data", post_data)

            additional_headers = {
                "Referer": "https://steamcommunity.com/tradeoffer/new/?partner=%s&token=%s" % (
                    receiver_steam_id_short, receiver_trade_token)
            }

            tradeoffer_response = self._web_client.post("https://steamcommunity.com/tradeoffer/new/send", post_data,
                                                        headers=additional_headers)

            if tradeoffer_response.status_code == 200:
                tradeoffer_id = str(tradeoffer_response.json()["tradeofferid"])
            else:
                raise Exception("Request Error, %s" % tradeoffer_response.status_code)
            self._web_client.get("http://steamcommunity.com/market/")

            logger.debug("send_tradeoffer: tradeoffer_response", tradeoffer_response)
            return tradeoffer_id
        response_soup = BeautifulSoup(response.content)
        error_msg = response_soup.find("div", attrs={"id": "error_msg"}).text
        logger.debug("send_tradeoffer: error_msg", error_msg)
        raise Exception("Trade Offer Error, %s" % error_msg)

    @login_required
    def accept_tradeoffer(self, tradeoffer_id):
        bot_cookies = self._web_client._cookie_jar._cookies["steamcommunity.com"]["/"]
        data = {
            "serverid": 1,
            "sessionid": bot_cookies["sessionid"].value,
            "tradeofferid": str(tradeoffer_id)
        }

        additional_headers = {
            "Referer": "https://steamcommunity.com/tradeoffer/%s/" % tradeoffer_id
        }

        self._web_client.post('https://steamcommunity.com/tradeoffer/%s/accept' % tradeoffer_id, data,
                              headers=additional_headers)

    @login_required
    def cancel_tradeoffer(self, tradeoffer_id):
        bot_cookies = self._web_client._cookie_jar._cookies["steamcommunity.com"]["/"]
        url = "https://steamcommunity.com/tradeoffer/%s/cancel" % tradeoffer_id
        response = self._web_client.post(url, data={'sessionid': bot_cookies['sessionid'].value})
        response_data = response.json()
        if response_data.get('tradeofferid') == tradeoffer_id:
            return True

        return False

    @login_required
    def get_tradeoffer(self, tradeoffer_id):
        url = 'http://api.steampowered.com/IEconService/GetTradeOffer/v1/?key=%s&tradeofferid=%s&language=en_us' % (
              self._cached.get("steam_api_key", self.api_key()), tradeoffer_id)
        response = self._web_client.get(url)
        response_data = response.json()
        if response_data.get("response", False):
            return response_data["response"]

        return None

    @login_required
    def inventory(self, appid=730):
        inventory_response = self._web_client.get(
            'http://steamcommunity.com/profiles/%s/inventory/json/%s/2?l=en' % (
                self._cached.get("steam_id", self.steam_id()), appid))
        if inventory_response.status_code == 200:
            return inventory_response.json()
        raise Exception("Inventory load error, %s" % inventory_response.status_code)

    @login_required
    def fetch_confirmations(self, tag="conf"):
        url = "https://steamcommunity.com/mobileconf/conf?" + self._generate_confirmation_query(tag)
        confirmations = self._web_client.get(url, timeout=30)
        parsed_html = BeautifulSoup(confirmations.content)
        found_confirmations = []
        confirmations_parsed = parsed_html.findAll(attrs={"class": "mobileconf_list_entry"})
        for confirmation_parsed in list(confirmations_parsed):
            if confirmation_parsed.get("data-confid", False) and confirmation_parsed.get("data-key", False):
                found_confirmations.append({"id": confirmation_parsed["data-confid"], "key": confirmation_parsed["data-key"]})

        return found_confirmations

    @login_required
    def accept_confirmation(self, confirmation):
        return self._confirm_action(confirmation, "allow")

    @login_required
    def deny_confirmation(self, confirmation):
        return self._confirm_action(confirmation, "cancel")










