# coding=utf-8
import imaplib
import datetime
import email
import email.header

GLOBAL_CHECK_RETRIES = 20
GLOBAL_CHECK_INTERVAL = 60
GLOBAL_MESSAGES_TO_CHECK = 25

IMAP_LIST = {
    "imap.mail.yahoo.com": ["yahoo.com"],
    "imap.zoho.com": ["zoho.com"],
    "imap.mail.ru": ["inbox.ru", "bk.ru", "mail.ru"]
}


def get_imap_server(_email):
    for key, value in IMAP_LIST.items():
        if _email.split("@")[1] in value:
            return key
    return None


class EmailReader(object):
    def __init__(self, email, password, imap_server=None):
        self.imap_server = get_imap_server(email)
        self.email = email
        self.password = password
        self.imap_conn = None
        self.messages = []
        self.connect()
        self.login()

    def connect(self):
        self.imap_conn = imaplib.IMAP4_SSL(self.imap_server)

    def login(self):
        try:
            rv, data = self.imap_conn.login(self.email, self.password)
        except imaplib.IMAP4.error:
            raise Exception("Login to IMAP error")

    def logout(self):
        self.imap_conn.logout()

    def close(self):
        self.imap_conn.close()

    def mailboxes(self):
        rv, mailboxes = self.imap_conn.list()
        if rv == 'OK':
            return mailboxes
        else:
            raise Exception("Cannot retrieve mailboxes")

    def load_messages(self, mailbox, search='ALL'):
        rv, data = self.imap_conn.select(mailbox)
        if rv == 'OK':

            rv, data = self.imap_conn.search(None, search)
            if rv != 'OK':
                self.messages = []
                self.close()
                return

            messages = []
            for num in data[0].split():
                rv, data = self.imap_conn.fetch(num, '(RFC822)')
                if rv != 'OK':
                    self.close()
                    raise Exception("Cannot fetch messages")

                msg = email.message_from_string(data[0][1])
                self.imap_conn.store(num, '+FLAGS', '\Seen')
                messages.append(msg)

            self.messages = messages
            self.close()

    def find_fresh_auth_code(self, sent_date):
        auth_code = None
        earliest_code_arrival = None
        earliest_message = None
        self.load_messages('inbox', search='(UNSEEN)')

        if len(self.messages) > 0:
            for message in self.messages:
                if message['subject'].find('Your Steam account: Access from new') != -1:
                    date_tuple = email.utils.parsedate_tz(message['Date'])
                    date_object = datetime.datetime.fromtimestamp(
                        email.utils.mktime_tz(date_tuple))

                    if date_object > sent_date:
                        if earliest_code_arrival is None:
                            earliest_code_arrival = date_object
                            earliest_message = message
                        elif earliest_code_arrival < date_object:
                            earliest_code_arrival = date_object
                            earliest_message = message

            if earliest_message is not None:
                message_body = earliest_message.get_payload()[0]._payload
                first_tilt_code = ":\r\n\r\n"
                second_tilt_code = "\r\n\r\n\r\n\r\nThis email"
                first_tilt = message_body.find(first_tilt_code)
                second_tilt = message_body.find(second_tilt_code)
                auth_code = message_body[first_tilt+len(first_tilt_code):second_tilt].replace('\n', '').replace(' ', '')

        self.logout()
        return auth_code

# test

# info = {
#     'user': '*',
#     'password': '*',
#     'email': '*',
#     'email_password': '*'
# }
#
# er = EmailReader(info['email'], info['email_password'])
# er.find_fresh_auth_code(datetime.datetime.utcnow())
