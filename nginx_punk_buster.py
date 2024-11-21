import configparser
import csv
import ipaddress
import json
import logging
import re
import requests
import sqlite3
import sys

from datetime import datetime
from pyparsing import Word, nums, alphanums, Suppress, quotedString, Group, Combine, Regex, Optional, Literal, \
    removeQuotes, SkipTo, ParseResults

CONFIG_PATH = r'LocalConfig/Settings.ini'
NGINX_ERROR_LOG = r'LocalConfig/error.log.1'
KNOWN_IPS_LIST = r'LocalConfig/known_ips.json'
CSV_PATH = r'LocalConfig/'
SQLite_DB = r'LocalConfig/nginx_punk_buster.db'
BLACKLIST_LOCATION = r'LocalConfig/BlackListAssholes.txt'

UBNT_LOGIN_URL = 'https://192.168.1.4:8443/api/login'
UBNT_LOGOUT_URL = 'https://192.168.1.4:8443/api/logout'
UBNT_FW_GROUP_URL = 'https://192.168.1.4:8443/api/s/566dua2v/rest/firewallgroup/673e8652f46fb86a9ec297fd'

DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
FORMATTER = logging.Formatter('[%(asctime)s][%(levelname)s]: %(message)s', DATE_FORMAT)

logger = logging.getLogger('logger')
logger.setLevel(logging.DEBUG)

sh = logging.StreamHandler(sys.stdout)
sh.setLevel(logging.DEBUG)
sh.setFormatter(FORMATTER)
logger.addHandler(sh)

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

    # Function to validate IPs or subnets
    def _is_valid_ip_or_subnet(self, entry):
        try:
            # Check if it is an IP or subnet
            ipaddress.ip_network(entry, strict=False)  # Handles both cases
            return True
        except ValueError:
            return False

    def _get_known_ips(self):
        with open(KNOWN_IPS_LIST, 'r') as file:
            data = json.load(file)
            return data

    def _write_known_ips(self):
        data = self.known_ips
        with open(KNOWN_IPS_LIST, 'w') as file:
            json.dump(data, file, indent=4)

    def _write_csv(self, list_of_dicts, file_path):
        with open(file_path, mode='w', newline='') as file:
            # Define the fieldnames (this will be the header row in the CSV)
            fieldnames = list_of_dicts[0].keys()

            # Create a DictWriter object
            writer = csv.DictWriter(file, fieldnames=fieldnames)

            # Write the header row
            writer.writeheader()

            # Write data rows
            writer.writerows(list_of_dicts)

    def create_sqlite_connection(self, db_name=SQLite_DB):
        conn = sqlite3.connect(db_name)
        return conn

    def _table_exists(self, cursor, table_name):
        cursor.execute("""
            SELECT name FROM sqlite_master WHERE type='table' AND name=?;
        """, (table_name,))
        return cursor.fetchone() is not None

    def get_ubnt_blacklist(self):
        # Disable SSL verification (use caution in production)
        session = requests.Session()
        session.verify = False  # Disable SSL verification (optional)

        # Authenticate and get the session ID
        login_response = session.post(UBNT_LOGIN_URL, json=UBNT_LOGIN_PAYLOAD)

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

        firewall_group_response = session.get(UBNT_FW_GROUP_URL, headers=headers)
        data = firewall_group_response.json()
        logout_response = session.post(UBNT_LOGOUT_URL)
        if logout_response.status_code == 200:
            logger.info(f'UBNT API logout successful')

        else:
            logger.error(f"UBNT API logout failed. Status Code: {login_response.status_code}")
            logger.debug(f'{login_response.json()}')

        return data['data'][0]['group_members']

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

            now = datetime.now()
            cursor = conn.cursor()
            data_to_insert = [(entry, now) for entry in valid_entries]
            cursor.executemany(
                "INSERT OR IGNORE INTO blacklist (ip_address, date_added) VALUES (?, ?)",
                data_to_insert
            )

            conn.commit()
            conn.close()
            logger.info(f'Loading current blacklist to SQLite completed successfully')

    def insert_into_abuse_ip_db(self, cursor, ip_address, abuse_confidence_score,
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



    def get_all_data_as_dict(self, conn):
        """Fetch all data and return as a list of dictionaries."""
        conn.row_factory = sqlite3.Row  # Enables dictionary-like access
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM abuse_ip_db")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


    def add_abuseipdb_for_blacklist_ips(self):
        # Add info from AbuseIPDB to abuse_ip_db table in SQLite
        # for each IP address in blacklist table
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


    def abuse_ipdb_check_ip(self, ip_address):
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





class NginxErrorLogReader(LogReader):
    def __init__(self, log_location):
        super().__init__(log_location)
        # Define basic components of a log entry
        self.parsed_results = []
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

    def _fields_to_dict(self, tokens):
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


                except Exception as e:
                    logger.error(f'Failed to parse line: {line}')
                    # TODO: Save lines that were not parsed for later analysis
                    logger.error(f'Error: {e}')

        self._create_ban_list()


    def print_log_to_console(self):
        if self.parsed_results is not None:
            for result in self.parsed_results:
                print(result)
        else:
            logger.error(f'There are no parsed results to print')


    def aggregate_logs(self):
        self._remove_known_ips()

    def _remove_known_ips(self):
        pass

    def _create_ban_list(self):
        self.ban_list = []
        for result in self.parsed_results:
            ip = result['ClientIP']
            if ip not in [entry['ClientIP'] for entry in self.ban_list]:
                ip_count = sum(1 for entry in self.parsed_results if entry.get('ClientIP') == ip)
                result['Count'] = ip_count
                self.ban_list.append(result)

    def add_abuseipdb_for_ban_list(self):
        # Add info from AbuseIPDB to abuse_ip_db table in SQLite
        # for each IP address in the ban list
        conn = self.create_sqlite_connection()
        cursor = conn.cursor()

        try:
            if self._table_exists(cursor, 'abuse_ip_db'):
                cursor.execute('SELECT ip_address FROM abuse_ip_db')
                # Get list of IPs from abuse_ip_db, because I don't want to call API if already in there
                abuse_ips = [row[0] for row in cursor.fetchall()]
            else:
                logger.info(f'abuse_ip_db has not been created in SQLite yet, skipping for now')
                abuse_ips = []

        except sqlite3.OperationalError as e:
            logger.error(f'Error while updating AbuseIPDB: {e}')

        logger.debug(f'Beginning Loop Through Ban List IP Addresses')
        for entry in self.ban_list:
            if entry['ClientIP'] not in abuse_ips:
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

        conn.commit()
        conn.close()

    def write_ban_list_csv(self):
        file_name = r'ban_list.csv'
        csv_path = CSV_PATH + file_name
        logger.debug(f'write_ban_list_csv writing: {csv_path}')
        self._write_csv(self.ban_list, csv_path)

    def write_parsed_results_csv(self):
        file_name = r'parsed_results.csv'
        csv_path = CSV_PATH + file_name
        logger.debug(f'write_parsed_results_csv writing: {csv_path}')
        self._write_csv(self.parsed_results, csv_path)





class LogReaderFactory:
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

    # Add data from AbuseIPDB API to abuse_ip_db using Blacklisted IPs
    # readit.add_abuseipdb_for_blacklist_ips()

    # Update list of Blacklisted IPs
    # readit.load_current_blacklist()

    # Read nginx error log and spit out csv
    readit.parse_log_file()
    # readit.write_ban_list_csv()
    # readit.write_parsed_results_csv()
    # readit.add_abuseipdb_for_ban_list()

    # readit.print_log_to_console()
    # readit.write_known_ips()


if __name__ == '__main__':
    main()

