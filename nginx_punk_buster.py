import configparser
import csv
import json
import logging
import sys

from pyparsing import Word, nums, alphanums, Suppress, quotedString, Group, Combine, Regex, Optional, Literal, \
    removeQuotes, SkipTo, ParseResults

CONFIG_PATH = r'LocalConfig/Settings.ini'
NGINX_ERROR_LOG = r'LocalConfig/error.log.1'
KNOWN_IPS_LIST = r'LocalConfig/known_ips.json'
CSV_PATH = r'LocalConfig/'

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

except KeyError:
    logger.error('Error loading config file: check that file exists and settings inside are correct')
    quit()


class LogReader(object):
    def __init__(self, log_location: str):
        if not isinstance(log_location, str):
                raise TypeError('log_location should be a string')
        self.log_location = log_location
        self.known_ips = self._get_known_ips()

    def _get_known_ips(self):
        with open(KNOWN_IPS_LIST, 'r') as file:
            data = json.load(file)
            return data

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

    def write_known_ips(self):
        data = self.known_ips
        with open(KNOWN_IPS_LIST, 'w') as file:
            json.dump(data, file, indent=4)





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
    readit.parse_log_file()
    readit.print_log_to_console()
    readit.write_known_ips()
    readit.write_ban_list_csv()
    readit.write_parsed_results_csv()
    # print(log_results[0]['client_ip'])
    # print(log_results[0]['datetime'])
    # print(log_results[0]['date'])
    # print(log_results[0]['time'])
    # print(log_results[0]['http_code'])
    # print(log_results[0]['msg'])
    # for field in log_results[0]['fields']:
        # print(field)

if __name__ == '__main__':
    main()

