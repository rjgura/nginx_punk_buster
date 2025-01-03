import configparser
import csv
import ipaddress
import json
import logging
import re
from io import StringIO

import requests
import sqlite3
import sys
import urllib3

from datetime import datetime
from logging.handlers import RotatingFileHandler
from pyparsing import Word, nums, alphanums, Suppress, quotedString, Group, \
    Combine, Regex, Optional, Literal, removeQuotes, SkipTo, ParseResults

#
# Constants
#
# Local Script Config Settings:
CONFIG_PATH = r'LocalConfig/Settings.ini'
KNOWN_IPS_LIST = r'LocalConfig/known_ips.json'
SQLite_DB = r'LocalConfig/nginx_punk_buster.db'
CSV_PATH = r'LocalConfig/'

# Locations of logs for parsing:
NGINX_ERROR_LOG = r'LocalConfig/error.log.2'
BLACKLIST_LOCATION = r'LocalConfig/BlackListAssholes.txt'

# Ubiquiti Network Controller API Endpoints
UBNT_LOGIN_URL = 'https://192.168.1.4:8443/api/login'
UBNT_LOGOUT_URL = 'https://192.168.1.4:8443/api/logout'
UBNT_FW_GROUP_URL = 'https://192.168.1.4:8443/api/s/566dua2v/rest/firewallgroup/65337212ce5caf38ad0796f6'

#
# Logging
#
LOG_FILENAME = r'LocalConfig/NginxPunkBuster.log'
'''
LOG_FILENAME = '/var/log/NginxPunkBuster.log' for Linux
LOG_FILENAME = 'NginxPunkBuster.log' for Windows (Not tested)
'''
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
FORMATTER = logging.Formatter('[%(asctime)s][%(levelname)s]: %(message)s', DATE_FORMAT)

logger = logging.getLogger('logger')
logger.setLevel(logging.DEBUG)

sh = logging.StreamHandler(sys.stdout)
sh.setLevel(logging.DEBUG)
sh.setFormatter(FORMATTER)
logger.addHandler(sh)

fh = RotatingFileHandler(LOG_FILENAME,
                         mode='a',
                         maxBytes=5*1024*1024,
                         backupCount=2,
                         encoding=None,
                         delay=False
                         )

fh.setLevel(logging.DEBUG)
fh.setFormatter(FORMATTER)
logger.addHandler(fh)

# Check if running on a linux system, but not from terminal
# This fix stops output going to an unattached terminal if being run by cron
if sys.platform[0:5] == 'linux' and not sys.stdout.isatty():
    logger.debug(f'Script running in Linux with no Terminal Connected, removing stream handler')
    logger.removeHandler(sh)

config = configparser.ConfigParser()
config.read(CONFIG_PATH)

logger.debug(f'Loading config file: {CONFIG_PATH}')
try:
    ABUSEIPDB_API_KEY = config['CREDENTIALS']['AbuseIPDB_API_Key']
    UBNT_USERNAME = config['CREDENTIALS']['UBNT_Username']
    UBNT_PASSWORD = config['CREDENTIALS']['UBNT_Password']
    UBNT_LOGIN_PAYLOAD = {
        "username": UBNT_USERNAME,
        "password": UBNT_PASSWORD
    }

except KeyError:
    logger.error('Error loading config file: check that file exists and settings inside are correct')
    quit()

#
# Global Settings
#

# Disable SSL verification warning globally to remove
# warnings about the Ubiquiti untrusted certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# This stuff handles a deprecation warning for SQLite handling of datetime
# Register adapters and converters for datetime
def adapt_datetime(dt):
    """Convert datetime to string for storage."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def convert_datetime(value):
    """Convert string back to datetime object."""
    return datetime.strptime(value.decode("utf-8"), "%Y-%m-%d %H:%M:%S")

# Register the adapter and converter
sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter("DATETIME", convert_datetime)




class LogReader(object):
    def __init__(self, log_location: str):
        if not isinstance(log_location, str):
                raise TypeError('log_location should be a string')
        self.log_location = log_location
        self.known_ips = self._get_known_ips()
        self.ubnt_blacklist = self.get_ubnt_blacklist()

    # Validate format of IPs or subnets
    @staticmethod
    def _is_valid_ip_or_subnet(entry):
        try:
            # Check if it is an IP or subnet
            ipaddress.ip_network(entry, strict=False)  # Handles both cases
            return True
        except ValueError:
            return False

    @staticmethod
    def _get_known_ips():
        with open(KNOWN_IPS_LIST, 'r') as file:
            data = json.load(file)
            return data

    def _write_known_ips(self):
        file: StringIO
        data = self.known_ips
        with open(KNOWN_IPS_LIST, 'w') as file:
            json.dump(data, file, indent=4)

    @staticmethod
    def _write_csv_list_of_dicts(list_of_dicts, file_path):
        try:
            file: StringIO
            with open(file_path, mode='w', newline='') as file:
                # Define the fieldnames (this will be the header row in the CSV)
                fieldnames = list_of_dicts[0].keys()
                writer = csv.DictWriter(file, fieldnames=fieldnames)

                # Write the header row
                writer.writeheader()

                # Write data rows
                writer.writerows(list_of_dicts)

        except PermissionError as e:
            logger.error(f'Permission error, file may be open: {e}')


    @staticmethod
    def _write_list_of_strs(list_of_strs, file_path):
        try:
            file: StringIO
            with open(file_path, mode='w') as file:

                for string in list_of_strs:
                    file.write(string + '\n')

        except PermissionError as e:
            logger.error(f'Permission error, file may be open: {e}')


    @staticmethod
    def create_sqlite_connection(db_name=SQLite_DB):
        conn = sqlite3.connect(db_name)
        return conn

    @staticmethod
    def _table_exists(cursor, table_name):
        cursor.execute("""
            SELECT name FROM sqlite_master WHERE type='table' AND name=?;
        """, (table_name,))
        return cursor.fetchone() is not None

    @staticmethod
    def get_ubnt_blacklist():
        # Disable SSL verification (use caution in production)
        session = requests.Session()
        session.verify = False  # Disable SSL verification (optional)

        # Authenticate and get the session ID
        login_response = session.post(UBNT_LOGIN_URL, json=UBNT_LOGIN_PAYLOAD, verify=False)

        if login_response.status_code == 200:
            logger.debug(f'UBNT API login successful')
            # Extract the session cookie after successful login
            session_id = session.cookies.get('unifises')
        else:
            logger.error(f"UBNT API login failed. Status Code: {login_response.status_code}")
            logger.debug(f'{login_response.json()}')
            exit()

        headers = {
            "Content-Type": "application/json",
            "Cookie": f"unifises={session_id}"  # Include the session ID cookie
        }

        firewall_group_response = session.get(UBNT_FW_GROUP_URL, headers=headers, verify=False)

        if firewall_group_response.status_code == 200:
            logger.info(f'UBNT Firewall group fetched successful')

        else:
            logger.error(f"Failed to get UBNT Firewall group. Status Code: {firewall_group_response.status_code}")
            logger.debug(f'{firewall_group_response.json()}')
            quit()

        data = firewall_group_response.json()

        logout_response = session.post(UBNT_LOGOUT_URL, verify=False)

        if logout_response.status_code == 200:
            logger.info(f'UBNT API logout successful')

        else:
            logger.error(f"UBNT API logout failed. Status Code: {logout_response.status_code}")
            logger.debug(f'{logout_response.json()}')

        return data['data'][0]['group_members']

    def set_ubnt_blacklist(self, list_to_add):
        logger.debug(f'Starting an update to the UBNT Blacklist')
        if not isinstance(list_to_add, list):
            raise TypeError('list_to_add should be a list')

        if not list_to_add:
            logger.warning(f'The list is empty, nothing to add to Blacklist')
            return 1

        # Disable SSL verification (use caution in production)
        session = requests.Session()
        session.verify = False  # Disable SSL verification (optional)

        # Authenticate and get the session ID
        logger.debug(f'Logging into UBNT API')
        login_response = session.post(UBNT_LOGIN_URL, json=UBNT_LOGIN_PAYLOAD, verify=False)

        if login_response.status_code == 200:
            logger.debug(f'UBNT API login successful')
            # Extract the session cookie after successful login
            session_id = session.cookies.get('unifises')
        else:
            logger.error(f"UBNT API login failed. Status Code: {login_response.status_code}")
            logger.debug(f'{login_response.json()}')
            exit()

        headers = {
            "Content-Type": "application/json",
            "Cookie": f"unifises={session_id}"  # Include the session ID cookie
        }

        # Refresh self.ubnt_blacklist so that we don't lose any IPs from the list
        logger.debug(f'Getting Firewall Group for Blacklist')
        firewall_group_response = session.get(UBNT_FW_GROUP_URL, headers=headers, verify=False)

        if firewall_group_response.status_code == 200:
            logger.info(f'Firewall Group for Blacklist fetched successfully')

        else:
            logger.error(f"Could not get firewall group for Blacklist. Status Code: {login_response.status_code}")
            logger.error(f'Could not get the latest UBNT Blacklist, stopping update attempt')
            logger.debug(f'{login_response.json()}')
            quit()

        data = firewall_group_response.json()
        self.ubnt_blacklist.clear()
        self.ubnt_blacklist = data['data'][0]['group_members']

        list_to_add = [entry for entry in list_to_add if entry not in self.ubnt_blacklist]

        if list_to_add:

            updated_blacklist = self.ubnt_blacklist + list_to_add

            # Prepare the payload (data to be sent in the body of the PUT request)
            payload = {
                "group_members": updated_blacklist,
            }

            # Send the PUT request
            update_response = requests.put(
                UBNT_FW_GROUP_URL,
                headers=headers,
                data=json.dumps(payload),
                verify=False  # Disable SSL verification (optional, use with caution)
            )

            # Check the response
            if update_response.status_code == 200:
                logger.info(f'Updated the UBNT Blacklist successfully')
                logger.info(f'{len(list_to_add)} new IPs added to UBNT Blacklist')
                print(update_response.json())
            else:
                print(f'Failed to update group. Status Code: {update_response.status_code}')
                print(update_response.json())

        else:
            logger.warning(f'No new IPs to add to Blacklist')

        logout_response = session.post(UBNT_LOGOUT_URL, verify=False)
        if logout_response.status_code == 200:
            logger.debug(f'UBNT API logout successful')


        else:
            logger.error(f'UBNT API logout failed. Status Code: {login_response.status_code}')
            logger.debug(f'{login_response.json()}')

    def insert_into_blacklist(self, list_to_insert):
        logger.debug(f'Starting an insert into the blacklist table in SQLite')
        if not isinstance(list_to_insert, list):
            raise TypeError('list_to_insert should be a list')

        conn = self.create_sqlite_connection()
        query = """
                CREATE TABLE IF NOT EXISTS blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL UNIQUE,
                    date_added DATETIME NOT NULL
            )
            """
        conn.execute(query)
        conn.commit()

        valid_entries = [entry for entry in list_to_insert if self._is_valid_ip_or_subnet(entry)]

        now = datetime.now()
        cursor = conn.cursor()
        data_to_insert = [(entry, now) for entry in valid_entries]

        cursor.executemany(
            "INSERT OR IGNORE INTO blacklist (ip_address, date_added) VALUES (?, ?)",
            data_to_insert
        )

        conn.commit()
        conn.close()
        logger.info(f'Insert into blacklist table in SQLite completed successfully')


    def insert_into_blacklist_from_file(self):
        # Will read a text file in format address <ip_address>
        # and insert each IP in blacklist table if IP does not exist.
        # If table doesn't exist it will create it.
        conn = self.create_sqlite_connection()
        query =  """
        CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            date_added DATETIME NOT NULL
    )
    """
        conn.execute(query)
        conn.commit()

        with open(BLACKLIST_LOCATION, 'r') as file:
            logger.info(f'Loading current blacklist to SQLite: {BLACKLIST_LOCATION}')
            data = file.read()
            entries = re.findall(r'address ([\d./]+)', data)

            valid_entries = [entry for entry in entries if self._is_valid_ip_or_subnet(entry)]

            cursor = conn.cursor()

            now = datetime.now()
            data_to_insert = [(entry, now) for entry in valid_entries]

            cursor.executemany(
                "INSERT OR IGNORE INTO blacklist (ip_address, date_added) VALUES (?, ?)",
                data_to_insert
            )

            conn.commit()
            conn.close()
            logger.info(f'Loading current blacklist to SQLite completed successfully')


    def sync_blacklist_table_from_ubnt(self):
        self.ubnt_blacklist = self.get_ubnt_blacklist()
        self.insert_into_blacklist(self.ubnt_blacklist)


    @staticmethod
    def insert_into_abuse_ip_db(cursor, ip_address, abuse_confidence_score,
                                reported_count, distinct_reporter_count,
                                country_code, country_name,
                                usage_type, isp, domain,
                                is_public, is_whitelisted, is_tor,
                                last_reported_at, date_added):
        query = """
            CREATE TABLE IF NOT EXISTS abuse_ip_db (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                abuse_confidence_score INTEGER,
                reported_count INTEGER,
                distinct_reporter_count INTEGER,
                country_code TEXT,
                country_name TEXT,
                usage_type TEXT,
                isp TEXT,
                domain TEXT,
                is_public TEXT,
                is_whitelisted TEXT,
                is_tor TEXT,
                last_reported_at DATETIME,
                date_added DATETIME NOT NULL
        )
        """
        cursor.execute(query)

        """Insert data into the table."""
        insert_query = """
        INSERT OR IGNORE INTO abuse_ip_db (ip_address, abuse_confidence_score, reported_count,
        distinct_reporter_count, country_code, country_name, usage_type, isp, domain,
        is_public, is_whitelisted, is_tor, last_reported_at, date_added)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        cursor.execute(insert_query, (ip_address, abuse_confidence_score, reported_count, distinct_reporter_count,
                             country_code, country_name,
                             usage_type, isp, domain,
                             is_public, is_whitelisted, is_tor, last_reported_at, date_added))


    def add_abuseipdb_for_blacklist_ips(self):
        # Add info from AbuseIPDB to abuse_ip_db table in SQLite
        # for each IP address in blacklist table
        ip_addresses = None
        abuse_ips = None

        conn = self.create_sqlite_connection()
        cursor = conn.cursor()

        try:
            if self._table_exists(cursor, 'blacklist'):
                cursor.execute('SELECT ip_address FROM blacklist')
                # Get list of IPs from the blacklist table
                ip_addresses = [row[0] for row in cursor.fetchall()]

            else:
                logger.info(f'blacklist has not been created in SQLite yet, add a blacklist table')
                quit()

            if self._table_exists(cursor, 'abuse_ip_db'):
                cursor.execute('SELECT ip_address FROM abuse_ip_db')
                # Get list of IPs from abuse_ip_db, because I don't want to call API if already in there
                abuse_ips = [row[0] for row in cursor.fetchall()]

            else:
                logger.info(f'abuse_ip_db has not been created in SQLite yet, skipping for now')
                abuse_ips = []

        except sqlite3.OperationalError as e:
            logger.error(f'Error while updating AbuseIPDB: {e}')

        logger.debug(f'Beginning Loop Through Blacklist IP Addresses')
        for ip_address in ip_addresses:
            if ip_address not in abuse_ips:
                logger.debug(f'Calling AbuseIPDB API for: {ip_address}')
                data = self.abuse_ipdb_check_ip(ip_address)
                logger.debug(f'Received AbuseIPDB Data: {data}')
                abuse_confidence_score = data.get('abuseConfidenceScore', 0)
                reported_count = data.get('totalReports', 0)
                distinct_reporter_count = data.get('numDistinctUsers', 0)
                country_code = data.get('countryCode', '??')
                country_name = data.get('countryName', 'Unknown')
                usage_type = data.get('usageType')
                isp = data.get('isp')
                domain = data.get('domain')
                is_public = data.get('isPublic')
                is_whitelisted = data.get('isWhitelisted')
                is_tor = data.get('isTor')
                last_reported_at = data.get('lastReportedAt')
                date_added = datetime.now()

                logger.debug(f'Inserting AbuseIPDB Data into abuse_ip_db table in SQLite')
                self.insert_into_abuse_ip_db(cursor, ip_address,abuse_confidence_score,
                                             reported_count, distinct_reporter_count,
                                             country_code, country_name, usage_type, isp,
                                             domain, is_public, is_whitelisted, is_tor,
                                             last_reported_at, date_added)

        conn.commit()
        conn.close()


    @staticmethod
    def abuse_ipdb_check_ip(ip_address):
        url = f'https://api.abuseipdb.com/api/v2/check'
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
            "verbose": True
        }

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            logger.debug(f'AbuseIPDB API Response Code: {response.status_code}')
            data = response.json()['data']
            return data

        else:
            return {"error": f"Request failed with status code {response.status_code}", "details": response.text}


    @staticmethod
    def get_all_data_as_dict(conn):
        """Fetch all data and return as a list of dictionaries."""
        conn.row_factory = sqlite3.Row  # Enables dictionary-like access
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM abuse_ip_db")
        rows = cursor.fetchall()
        conn.row_factory = None
        return [dict(row) for row in rows]




class NginxErrorLogReader(LogReader):
    def __init__(self, log_location):
        super().__init__(log_location)
        # Define basic components of a log entry
        self.parsed_results = []
        self.not_parsed_results = []
        self.integer = Word(nums)
        self.ip_address = Combine(Word(nums) + ('.' + Word(nums)) * 3)
        self.datetime_part = Combine(Word(nums, exact=4) + '/' +
                                     Word(nums, exact=2) + '/' +
                                     Word(nums, exact=2))
        self.time_part = Combine(Word(nums, exact=2) + ':' +
                                 Word(nums, exact=2) + ':' +
                                 Word(nums, exact=2))
        self.process_ids = Combine(self.integer + '#' + self.integer)
        self.request_id = Suppress(':') + Suppress('*') + self.integer

        # Define other parts of the log entry
        self.datetime_expr = Combine(self.datetime_part + ' ' + self.time_part)('datetime')
        self.error_level = Literal("[error]")
        # self.client_expr = Suppress("[client") + self.ip_address + Suppress("]")
        self.client_expr = (Optional(Suppress("[client")) +
                            self.ip_address +
                            Optional(Suppress("]")))
        self.client_expr.setParseAction(lambda t: t[0])
        self.http_code = Literal("ModSecurity: Access denied with code") + self.integer
        self.http_code.setParseAction(lambda t: t[1])
        self.field_value = Group(
            Suppress('[') +
            Word(alphanums)('field') +
            quotedString.setParseAction(removeQuotes)('value') +
            Suppress(']')
        )
        self.fields = (self.field_value[...])
        self.fields.setParseAction(self._fields_to_dict)

        # Define the full line structure
        self.log_line = (
            self.datetime_expr("datetime") +
            self.error_level("level") +
            self.process_ids("process_ids") +
            self.request_id("request_id") +
            self.client_expr("client_ip") +
            self.http_code("http_code") +
            Optional(SkipTo('[')) +
            self.fields('fields') +
            Optional(Regex(".*"))  # Capture the remaining part of the message if needed
        )


    @staticmethod
    def _fields_to_dict(tokens):
        fields = {}
        for token in tokens:
            # Check if the token is a ParseResults with named fields
            if isinstance(token, ParseResults) and 'field' in token and 'value' in token:
                key, value = token['field'], token['value']
            elif isinstance(token, list) and len(token) == 2:
                key, value = token  # For flat tokens
            else:
                logger.error(f"Unexpected token format: {token}")
                continue

            # Handle duplicate keys
            if key in fields:
                if isinstance(fields[key], list):
                    fields[key].append(value)
                else:
                    fields[key] = [fields[key], value]
            else:
                fields[key] = value

        return fields


    # Function to parse each line of the log file
    def parse_log_file(self):
        num_lines = 0
        with open(self.log_location, 'r') as file:
            for line in file:
                try:
                    logger.debug(f'Attempting to parse nginx error log: {line}')
                    parsed = self.log_line.parseString(line)
                    if parsed['client_ip'] not in self.known_ips.values():
                        parsed_dict = {
                            'Datetime': parsed['datetime'],
                            'ClientIP': parsed['client_ip'],
                            'HTTP_Code': parsed['http_code'],
                            'Severity': parsed['fields']['severity'],
                            'Message': parsed['fields']['msg'],
                            'URI': parsed['fields']['uri']
                        }
                        logger.debug(f'Attempting to append with: {parsed_dict}')
                        self.parsed_results.append(parsed_dict)
                        logger.debug(f'Parsed line: {parsed}')
                        # TODO: Send known IP lines to their own dictionary
                    num_lines += 1

                except Exception as e:
                    logger.error(f'Failed to parse line: {line}')
                    # TODO: Save lines that were not parsed for later analysis
                    self.not_parsed_results.append(line)
                    logger.error(f'Error: {e}')

        logger.info(f'Finished parsing nginx error log. Number of rows parsed: {num_lines}')
        self._create_ban_list()


    def print_log_to_console(self):
        if self.parsed_results is not None:
            for result in self.parsed_results:
                print(result)
        else:
            logger.error(f'There are no parsed results to print')


    def _create_ban_list(self):
        self.ban_list = []
        self.ban_list_ips = []
        for result in self.parsed_results:
            ip = result['ClientIP']
            if ip not in [entry['ClientIP'] for entry in self.ban_list]:
                ip_count = sum(1 for entry in self.parsed_results if entry.get('ClientIP') == ip)
                result['Count'] = ip_count
                self.ban_list.append(result)

        for entry in self.ban_list:
            self.ban_list_ips.append(entry['ClientIP'])


    def add_abuseipdb_for_ban_list(self):
        # Add info from AbuseIPDB to abuse_ip_db table in SQLite
        # for each IP address in the ban list
        abuse_ip_data = None
        conn = self.create_sqlite_connection()
        cursor = conn.cursor()

        try:
            if self._table_exists(cursor, 'abuse_ip_db'):
                cursor.execute('SELECT ip_address FROM abuse_ip_db')
                # Get list of IPs from abuse_ip_db, because I don't want to call API if already in there
                abuse_ip_data = self.get_all_data_as_dict(conn)
                index = {data['ip_address']: data for data in abuse_ip_data}
                abuse_ip_data = index

            else:
                logger.info(f'abuse_ip_db has not been created in SQLite yet, skipping for now')
                abuse_ip_data = []

        except sqlite3.OperationalError as e:
            logger.error(f'Error while updating AbuseIPDB: {e}')

        logger.debug(f'Beginning Loop Through Ban List IP Addresses')
        for entry in self.ban_list:
            if entry['ClientIP'] in abuse_ip_data:
                logger.debug(f'Found in abuse_ip_db table in SQLite: {entry['ClientIP']}')
                result = abuse_ip_data.get(entry['ClientIP'])

                abuse_confidence_score = result.get('abuse_confidence_score', 0)
                reported_count = result.get('reported_count', 0)
                distinct_reporter_count = result.get('distinct_reporter_count', 0)
                country_code = result.get('country_code', '??')
                country_name = result.get('country_name', 'Unknown')
                usage_type = result.get('usage_type')
                isp = result.get('isp')
                domain = result.get('domain')
                is_public = result.get('is_public')
                is_whitelisted = result.get('is_whitelisted')
                is_tor = result.get('is_tor')
                last_reported_at = result.get('last_reported_at')
                date_added = datetime.now()

            else:
                logger.debug(f'Calling AbuseIPDB API for: {entry['ClientIP']}')
                data = self.abuse_ipdb_check_ip(entry['ClientIP'])
                logger.debug(f'Received AbuseIPDB Data: {data}')

                abuse_confidence_score = data.get('abuseConfidenceScore', 0)
                reported_count = data.get('totalReports', 0)
                distinct_reporter_count = data.get('numDistinctUsers', 0)
                country_code = data.get('countryCode', '??')
                country_name = data.get('countryName', 'Unknown')
                usage_type = data.get('usageType')
                isp = data.get('isp')
                domain = data.get('domain')
                is_public = data.get('isPublic')
                is_whitelisted = data.get('isWhitelisted')
                is_tor = data.get('isTor')
                last_reported_at = data.get('lastReportedAt')
                date_added = datetime.now()

                logger.debug(f'Inserting AbuseIPDB Data into abuse_ip_db table in SQLite')
                self.insert_into_abuse_ip_db(cursor, entry['ClientIP'], abuse_confidence_score,
                                             reported_count, distinct_reporter_count,
                                             country_code, country_name, usage_type, isp,
                                             domain, is_public, is_whitelisted, is_tor,
                                             last_reported_at, date_added)

            entry.update(
                {
                    'abuse_confidence_score': abuse_confidence_score,
                    'reported_count': reported_count,
                    'distinct_reporter_count': distinct_reporter_count,
                    'country_code': country_code,
                    'country_name': country_name,
                    'usage_type': usage_type,
                    'isp': isp,
                    'domain': domain,
                    'is_public': is_public,
                    'is_whitelisted': is_whitelisted,
                    'is_tor': is_tor,
                    'last_reported_at': last_reported_at,
                    'date_added': date_added
                }
            )

        conn.commit()
        conn.close()


    def write_ban_list_csv(self):
        file_name = r'ban_list.csv'
        csv_path = CSV_PATH + file_name
        logger.debug(f'write_ban_list_csv writing: {csv_path}')
        self._write_csv_list_of_dicts(self.ban_list, csv_path)


    def write_parsed_results_csv(self):
        file_name = r'parsed_results.csv'
        csv_path = CSV_PATH + file_name
        logger.debug(f'write_parsed_results_csv writing: {csv_path}')
        self._write_csv_list_of_dicts(self.parsed_results, csv_path)


    def write_not_parsed_results(self):
        file_name = r'not_parsed_results.txt'
        txt_path = CSV_PATH + file_name
        logger.debug(f'write_not_parsed_results writing: {txt_path}')
        self._write_list_of_strs(self.not_parsed_results, txt_path)




class LogReaderFactory:
    # noinspection PyMethodMayBeStatic
    def create_log_reader(self, log_reader_type):
        if log_reader_type == 'NGINX Error Log':
            pass
        elif log_reader_type == 'NGINX Access Log':
            pass
        elif log_reader_type == 'ModSecurity Audit Log':
            pass
        else:
            raise ValueError(f'Unknown LogReader Type: {log_reader_type}')




def main():

    readit = NginxErrorLogReader(NGINX_ERROR_LOG)

    #
    # Parse nginx error log for ModSecurity entries
    # Use entries to create a ban list
    # Write results to csv
    #
    # Read nginx error log and spit out csv
    readit.parse_log_file()
    readit.add_abuseipdb_for_ban_list()
    readit.write_ban_list_csv()
    readit.write_not_parsed_results()
    # readit.write_parsed_results_csv()
    readit.sync_blacklist_table_from_ubnt()

    #
    # Use the ban list to update firewall group for blacklist
    # on Ubiquiti Network Controller
    #
    readit.set_ubnt_blacklist(readit.ban_list_ips)
    readit.insert_into_blacklist(readit.ban_list_ips)

    #
    # Insert data from AbuseIPDB API into abuse_ip_db using Blacklisted IPs
    #
    readit.add_abuseipdb_for_blacklist_ips()


    # readit.add_abuseipdb_for_ban_list()

    # readit.print_log_to_console()

    # Update blacklist from this variable
    # new_list = [
    #     '192.189.2.218',
    #     '20.118.68.251',
    #     '104.209.34.203',
    #     '70.39.75.135',
    #     '4.151.229.99',
    #     '104.40.75.76',
    #     '66.94.114.121',
    #     '81.161.238.40',
    #     '47.251.103.74',
    #     '4.246.246.232',
    #     '193.177.182.8',
    #     '20.225.3.119',
    #     '138.197.27.249',
    #     '66.240.236.116',
    #     '4.151.230.245',
    #     '70.39.75.151'
    # ]
    # readit.insert_into_blacklist(new_list)

    # Update list of Blacklisted IPs from a text file
    # readit.load_current_blacklist()

    # readit.write_known_ips()


if __name__ == '__main__':
    main()

