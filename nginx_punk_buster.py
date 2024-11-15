import json
from pyparsing import Word, nums, alphas, alphanums, Suppress, quotedString, Group, Combine, OneOrMore, delimitedList, \
    ParseException, Regex, Optional

NGINX_ERROR_LOG = r'/LocalConfig/error.log'
KNOWN_IPS_LIST = r'LocalConfig/known_ips.json'



class LogReader(object):
    def __init__(self):
        self.known_ips = self._get_known_ips()


    def _get_known_ips(self):
        with open(KNOWN_IPS_LIST, 'r') as file:
            data = json.loads(file)
            return data

    def write_known_ips(self):
        data = self.known_ips
        with open(KNOWN_IPS_LIST, 'w') as file:
            json.dump(data, file, indent=4)




# Define basic components
integer = Word(nums)
ip_address = Combine(Word(nums) + ('.' + Word(nums)) * 3)
datetime_part = Word(nums, exact=4) + '/' + Word(nums, exact=2) + '/' + Word(nums, exact=2)
time_part = Word(nums, exact=2) + ':' + Word(nums, exact=2) + ':' + Word(nums, exact=2)

# Define the new pattern for process ID and request ID
process_ids = Combine(integer + '#' + integer)
request_id = Suppress(':') + Suppress('*') + integer

# Define other parts of the log line
datetime_expr = datetime_part + time_part
error_level = Literal("[error]")
client_expr = Suppress("[client") + ip_address + Suppress("]")
modsecurity_msg = Literal("ModSecurity: Access denied with code") + integer

# Define the full line structure
log_line = (
    datetime_expr("datetime") +
    error_level("level") +
    process_ids("process_ids") +
    request_id("request_id") +
    client_expr("client_ip") +
    modsecurity_msg +
    Optional(Regex(".*"))  # Capture the remaining part of the message if needed
)

# Function to parse each line of the log file
def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        for line in file:
            try:
                parsed = log_line.parseString(line)
                print("Parsed line:", parsed)
            except Exception as e:
                print("Failed to parse line:", line)
                print("Error:", e)


# Usage
readit = LogReader()
readit.write_known_ips()
log_file_path = NGINX_ERROR_LOG
parse_log_file(log_file_path)

