SYSTEM_PATHS = [
    "C:\\Program Files".lower(),
    "C:\\Program Files (x86)".lower(),
    "C:\\ProgramData".lower(),
    "C:\\Windows".lower(),
    "\\\\?\\Volume".lower()
]

FILENAMES = [
    "ConsoleHost_history.txt".lower(),
    "StartupProfileData-Interactive".lower()
]

PERSISTENCE_PATH = [
    'Software\\Microsoft\\Windows\\CurrentVersion\\Run'.lower(),
    'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'.lower(),
    'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx'.lower(),
    'Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'.lower(),
    'Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree'.lower(),
    'Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks'.lower()
]