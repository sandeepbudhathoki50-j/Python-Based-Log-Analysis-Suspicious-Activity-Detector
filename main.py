import datetime

KNOWN_IPS = ["192.168.1.10", "10.0.0.5"]
FAILED_LOGIN_THRESHOLD = 3
ABNORMAL_START_HOUR = 0
ABNORMAL_END_HOUR = 5

def read_log_file(filename):
    with open(filename, "r") as file:
        logs = file.readlines()
    return logs

def parse_log_entry(entry):
    parts = entry.strip().split()
    date = parts[0]
    time = parts[1]
    status = parts[2]
    user = parts[3]
    ip = parts[4]
    timestamp = datetime.datetime.strptime(date + " " + time, "%Y-%m-%d %H:%M:%S")
    return {
        "timestamp": timestamp,
        "status": status,
        "user": user,
        "ip": ip
    }
