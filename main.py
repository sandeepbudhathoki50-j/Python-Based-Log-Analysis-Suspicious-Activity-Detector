import datetime

KNOWN_IPS = ["192.168.1.10", "10.0.0.5"]
FAILED_LOGIN_THRESHOLD = 3
ABNORMAL_START_HOUR = 0
ABNORMAL_END_HOUR = 5

def read_log_file(filename):
    with open(filename, "r") as file:
        logs = file.readlines()
    return logs
