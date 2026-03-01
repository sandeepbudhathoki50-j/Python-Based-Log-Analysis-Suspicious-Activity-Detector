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

def detect_failed_logins(log_entries):
    failed_counts = {}
    suspicious_users = []
    for entry in log_entries:
        if entry["status"] == "LOGIN_FAILED":
            user = entry["user"]
            failed_counts[user] = failed_counts.get(user, 0) + 1
    for user, count in failed_counts.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            suspicious_users.append((user, count))
    return suspicious_users

def detect_unknown_ips(log_entries):
    unknown_ip_attempts = []
    for entry in log_entries:
        if entry["ip"] not in KNOWN_IPS:
            unknown_ip_attempts.append(entry)
    return unknown_ip_attempts

def detect_abnormal_time(log_entries):
    abnormal_entries = []
    for entry in log_entries:
        hour = entry["timestamp"].hour
        if ABNORMAL_START_HOUR <= hour <= ABNORMAL_END_HOUR:
            abnormal_entries.append(entry)
    return abnormal_entries

def main():
    filename = input("Enter log file name (e.g., sample_log.txt): ")
    logs = read_log_file(filename)
    parsed_logs = [parse_log_entry(log) for log in logs]
    failed_logins = detect_failed_logins(parsed_logs)
    unknown_ips = detect_unknown_ips(parsed_logs)
    abnormal_times = detect_abnormal_time(parsed_logs)
