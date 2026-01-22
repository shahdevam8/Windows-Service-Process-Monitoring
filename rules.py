SUSPICIOUS_PARENT_CHILD = [
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
]

SUSPICIOUS_PATHS = [
    "AppData",
    "Temp",
    "Downloads"
]

ALLOWED_SYSTEM_PATHS = [
    "C:\\Windows\\System32",
    "C:\\Program Files",
    "C:\\Program Files (x86)"
]
