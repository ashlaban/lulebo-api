#!/usr/bin/env python3

import argparse
import inspect
import getpass
import keyring
import requests
import sys

from json.decoder import JSONDecodeError
from requests.exceptions import ConnectionError


def debug_print(msg):
    frame_info = inspect.stack()[1]
    file = frame_info.filename
    line = frame_info.lineno
    fn = frame_info.function
    print('{}:{}::{}  {}'.format(file, line, fn, msg))


class UserInfo(object):

    def __init__(self, username, password):
        try:
            user_info = self._get(username, password)
        except JSONDecodeError as e:
            print('Error retrieving data from server')
            sys.exit(1)

        self.username = username
        self.email = user_info['email']
        self.lulebo_username = user_info['lulebo_username']
        self.uuid = user_info['uuid']

    def _get(self, username=None, password=None):
        url = url_generator.generate(endpoint='u')
        if args.debug: debug_print(url)

        if username is None or password is None:
            # Assumed user is logged in via cookie
            r = requests.get(url)
        else:
            # HTTPS basic auth
            r = requests.get(url, auth=(username, password))

        if args.debug:
            try:
                r.json()
            except JSONDecodeError:
                debug_print(r.text)

        return r.json()['data']

    def print_user_info(self):
        if args.verbose: print()
        if args.verbose: print('=== User ===')
        print('username: {}'.format(self.username))
        print('email: {}'.format(self.email))
        print('lulebo.username: {}'.format(self.lulebo_username))
        print('lulebo.password: {}'.format('*** Not shown ***'))
        print('uuid: {}'.format(self.uuid))
        if args.verbose: print()

    def print_uuid(self):
        if args.verbose:
            print()
            print('UUID:', self.uuid)
            print()
        else:
            print(self.uuid)

    # def __str__():
    #     pass

    def __repr__():
        return '<UserInfo {}>'.format(username)


class UrlGenerator(object):
    def __init__(self, base_url='https://lulebo.ash.nu'):
        self.base_url = base_url

        self.prefix = {
            'signup': '',
            'login': 'lulebo',
            'u': '',
            'cord': 'lulebo',
            'direct-start': 'lulebo',
            'object-status': 'lulebo',
            'object-info': 'lulebo',
            'site-info': 'lulebo',
            'session-info': 'lulebo'
        }

    def generate(self, endpoint, uuid=None):
        if endpoint not in self.prefix:
            raise ValueError('Endpoint "{}" does not exist'.format(endpoint))

        elif uuid is None:
            prefix = self.prefix[endpoint]
            if prefix != '':
                url = '{base_url}/{prefix}/{endpoint}'.format(
                    base_url=self.base_url, prefix=prefix, endpoint=endpoint)
            else:
                url = '{base_url}/{endpoint}'.format(
                    base_url=self.base_url, endpoint=endpoint)
        else:
            url = '{base_url}/u/{uuid}/{endpoint}'.format(
                base_url=self.base_url, uuid=uuid, endpoint=endpoint)
        return url

    def print_url(self, uuid=None, endpoint='heater_start',
                  verbose_message=None):
        url = self.generate(uuid=uuid, endpoint=endpoint)

        if args.verbose:
            if verbose_message is None:
                raise ValueError('verbose_message cannot be None')
            print()
            print('{}:'.format(verbose_message))
            print(url)
            print()
        else:
            print(url)


class LuleboException(Exception):
    '''Base excpetion for lulebo-api-client'''
    def __init__(self, msg): self.msg = msg


class LuleboMissingCredentialsException(LuleboException):
    ''''''


def get_email(prompt='E-mail: '):
    try: return input(prompt)
    except: return None


def get_username(prompt='Username: ', username=None, force=False):
    if force:
        try: return input(prompt)
        except: return None
    elif username is None:
        return getpass.getuser()
    else:
        return username


def get_password(prompt='Password', username=None, force=False):
    if username is None:
        prompt = '{}: '.format(prompt)
    else:
        prompt = '{} for {}: '.format(prompt, username)

    if force or username is None:
        password = getpass.getpass(prompt)
    else:
        password = keyring.get_password('system', username)

        if password is None:
            password = getpass.getpass(prompt)
            if args.save_password:
                keyring.set_password('system', username, password)

    return password


def get_user_pass(username=None, password=None):
    username = get_username(username=username)
    password = get_password(username=username)

    return username, password


def change(username, password, user):
    if username is None or password is None:
        raise LuleboMissingCredentialsException('No username/password entered')

    url = url_generator.generate(endpoint='u')

    r = requests.patch(url, json=user, auth=(username, password))
    if args.debug: debug_print(r.json())
    return


def signup(user):
    url = url_generator.generate(endpoint='signup')

    r = requests.post(url, json=user)
    if args.debug: debug_print(r.json())
    return r


# lulebo signup
# lulebo heater start
# lulebo heater schedule
#
# lulebo change password lulebo.username
#
# lulebo info
# lulebo info uuid
# lulebo info uuid email
#
# lulebo info site
#
# lulebo url heater-start
#

def add_default_args(parser):
    parser.add_argument('--username', '--user', '-u', default=None, help='')
    parser.add_argument('--password', '--pass', '-p', default=None, help='')
    parser.add_argument('--email', '-e', default=None, help='')
    parser.add_argument('--debug', '-D', action='store_true')
    parser.add_argument('--dev', '-d', action='store_true')
    parser.add_argument('--verbose', '-v', action='count')
    parser.add_argument('--save-password', '-s', action='store_true')
    parser.add_argument('--wipe-saved-password', action='store_true')


def main():
    global args
    global url_generator

    parser = argparse.ArgumentParser(description='')

    subparsers = parser.add_subparsers(dest='command')

    parser_change = subparsers.add_parser('change', help='User something somet')
    parser_heater = subparsers.add_parser('heater', help='Control the car heater')
    parser_user = subparsers.add_parser('user', help='User something somet')
    parser_signup = subparsers.add_parser('signup', help='Register a new user')
    parser_url = subparsers.add_parser('url', help='Register a new user')


    # add_default_args(parser)
    add_default_args(parser_heater)
    add_default_args(parser_change)
    add_default_args(parser_signup)
    add_default_args(parser_user)
    add_default_args(parser_url)


    # Heater
    parser_heater.add_argument('subcommand',
                               choices=['start', 'status', 'info', 'site', 'cord'])

    # Change
    parser_change.add_argument('key',
                               nargs='*',
                               choices=['password', 'email',
                                        'lulebo.username', 'lulebo.password'])

    # Signup

    # Info
    parser_user.add_argument('subcommand',
                             nargs='?',
                             choices=['info', 'uuid', 'email'],
                             default='info')

    # url
    parser_url.add_argument('subcommand',
                            choices=['start', 'info', 'status', 'site'])

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.debug:
        debug_print(args)

    if args.dev:
        url_generator = UrlGenerator('http://localhost:8081')
    else:
        url_generator = UrlGenerator()

    if args.wipe_saved_password:
        username = get_username(username=args.username)
        keyring.delete_password('system', username)
        print('Stored password for user "{}"" removed'.format(username))
        sys.exit(0)

    try:
        if args.command == 'heater':
            username, password = get_user_pass(args.username, args.password)
            userinfo = UserInfo(username, password)

            if args.subcommand == 'cord':
                url = url_generator.generate(uuid=userinfo.uuid,
                                             endpoint='cord')

                print('Warning: This operation may take up to a minute to complete')

                r = requests.get(url)
                data = r.json()

                if args.debug: debug_print(data)

                if data['data']['cordConnected']:
                    print('Cord is connected')
                else:
                    print('Cord is _not_ connected')

            if args.subcommand == 'start':
                url = url_generator.generate(uuid=userinfo.uuid,
                                             endpoint='direct-start')
                r = requests.get(url)
                print(r.json())

            if args.subcommand == 'status':
                url = url_generator.generate(uuid=userinfo.uuid,
                                             endpoint='object-status')
                r = requests.get(url)
                print(r.json())

            if args.subcommand == 'info':
                url = url_generator.generate(uuid=userinfo.uuid,
                                             endpoint='object-info')
                r = requests.get(url)
                print(r.json())

            if args.subcommand == 'site':
                url = url_generator.generate(uuid=userinfo.uuid,
                                             endpoint='site-info')
                r = requests.get(url)
                print(r.json())

        if args.command == 'signup':
            username = get_username(username=args.username)

            user = {}

            user['username'] = username

            val = get_password(prompt='Password', username=username)
            validation = get_password(prompt='Validate password',
                                      username=username, force=True)

            if val == validation and val is not None:
                user['password'] = val
                user['passvalid'] = validation
            else:
                print('Passwords mismatch')
                sys.exit(-1)

            val = get_email(prompt='e-mail: ')
            if val is not None:
                user['email'] = val

            val = get_username(prompt='lulebo.username: ', force=True)
            if val is not None:
                user['lulebo_username'] = val

            val = get_password(prompt='lulebo.password: ', force=True)
            if val is not None:
                user['lulebo_password'] = val

            r = signup(user)
            print(r.text)

        if args.command == 'change':
            username, password = get_user_pass(args.username, args.password)

            user = {}

            if 'password' in args.key:
                val = get_password(prompt='New password')
                validation = get_password(prompt='Validate password')

                if val == validation and val is not None:
                    user['password'] = val
                    user['passvalid'] = validation
                else:
                    print('Passwords mismatch')
                    sys.exit(-1)

            if 'email' in args.key:
                val = get_email(prompt='New e-mail: ')
                if val is not None:
                    user['email'] = val

            if 'lulebo.username' in args.key:
                val = get_username(prompt='New lulebo.username: ', force=True)
                if val is not None:
                    user['lulebo_username'] = val

            if 'lulebo.password' in args.key:
                val = get_password(prompt='New lulebo.password: ', force=True)
                if val is not None:
                    user['lulebo_password'] = val

            change(username, password, user)

        if args.command == 'user':
            username, password = get_user_pass(args.username, args.password)
            userinfo = UserInfo(username, password)

            if args.subcommand == 'info':
                userinfo.print_user_info()

            if args.subcommand == 'uuid':
                userinfo.print_uuid()

        if args.command == 'url':
            username, password = get_user_pass(args.username, args.password)
            userinfo = UserInfo(username, password)

            if args.subcommand == 'start':
                url_generator.print_url(
                    uuid=userinfo.uuid,
                    endpoint='direct-start',
                    verbose_message='Loginless link to start engine heater'
                )

            if args.subcommand == 'info':
                url_generator.print_url(
                    uuid=userinfo.uuid,
                    endpoint='object-info',
                    verbose_message='Advanced use'
                    )

            if args.subcommand == 'status':
                url_generator.print_url(
                    uuid=userinfo.uuid,
                    endpoint='object-status',
                    verbose_message='Advanced use'
                    )

            if args.subcommand == 'site':
                url_generator.print_url(
                    uuid=userinfo.uuid,
                    endpoint='site-info',
                    verbose_message='Advanced use'
                    )

    except KeyboardInterrupt:
        # User pressed ctrl-c, exit program
        pass
    except JSONDecodeError:
        print('ERROR: Error decoding server response. Try running in debug mode.')
        sys.exit(1)
    except ConnectionError:
        print('ERROR: Could not connect to server "{}"'.format(url_generator.base_url))
        sys.exit(1)
    # except Exception as e:
    #     if args.debug:
    #         raise(e)
    #     else:
    #         print('ERROR: Unknown exception occurred. :(')

url_generator = None
args = None

if __name__ == '__main__':
    main()
