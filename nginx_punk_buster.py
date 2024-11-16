import json
import logging
import sys

from pyparsing import Word, nums, alphas, alphanums, Suppress, quotedString, Group, Combine, OneOrMore, delimitedList, \
    ParseException, Regex, Optional, Literal, removeQuotes, SkipTo

NGINX_ERROR_LOG = r'LocalConfig/error.log'
KNOWN_IPS_LIST = r'LocalConfig/known_ips.json'

DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
FORMATTER = logging.Formatter('[%(asctime)s][%(levelname)s]: %(message)s', DATE_FORMAT)

logger = logging.getLogger('logger')
logger.setLevel(logging.DEBUG)

sh = logging.StreamHandler(sys.stdout)
sh.setLevel(logging.DEBUG)
sh.setFormatter(FORMATTER)
logger.addHandler(sh)


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

    def write_known_ips(self):
        data = self.known_ips
        with open(KNOWN_IPS_LIST, 'w') as file:
            json.dump(data, file, indent=4)





class NginxErrorLogReader(LogReader):
    def __init__(self, log_location):
        super().__init__(log_location)
        # Define basic components of a log entry
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
        self.datetime_expr = (self.datetime_part("date") + self.time_part("time"))
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
        self.fields = Group(self.field_value[...])
        # self.msg = (Optional(Suppress('[')) +
        #             Literal('msg') +
        #             quotedString.setParseAction(removeQuotes) +
        #             Optional(Suppress(']')))

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
            # self.msg("msg") +
            Optional(Regex(".*"))  # Capture the remaining part of the message if needed
        )

    # Function to parse each line of the log file
    def parse_log_file(self):
        parsed_results = []
        with open(self.log_location, 'r') as file:
            for line in file:
                try:
                    parsed = self.log_line.parseString(line)
                    parsed['datetime'] = f'{parsed['date']} {parsed['time']}'
                    logger.debug(f'Parsed line: {parsed}')
                    logger.debug(f'Client IP: {parsed["client_ip"]}')
                    logger.debug(f'Datetime: {parsed["datetime"]}')
                    if parsed['client_ip'] not in self.known_ips.values():
                        parsed_results.append(parsed)

                except Exception as e:
                    logger.error(f'Failed to parse line: {line}')
                    logger.error(f'Error: {e}')

        return parsed_results

    def print_log_to_console(self, parsed_results):
        for result in parsed_results:
            if result['client_ip'] in self.known_ips.values():
                print(f'{result['date']} {result['time']} {result['client_ip']} FRIENDLY')
            else:
                print(f'{result['date']} {result['time']} {result['client_ip']}')

    def aggregate_logs(self):
        self._remove_known_ips()

    def _remove_known_ips(self):
        pass

    def _de_dupe_logs(self):
        pass





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
    log_results = readit.parse_log_file()
    readit.print_log_to_console(log_results)
    readit.write_known_ips()
    # print(log_results[0]['client_ip'])
    # print(log_results[0]['datetime'])
    # print(log_results[0]['date'])
    # print(log_results[0]['time'])
    print(log_results[0]['http_code'])
    # print(log_results[0]['msg'])
    for field in log_results[0]['fields']:
        print(field)

if __name__ == '__main__':
    main()

