import re

def is_strong_password(password):
    pattern = (
        r'^(?=.*[A-Z])'
        r'(?=.*[a-z])'
        r'(?=.*\d)'
        r'(?=.*[!@#$%^&*()-_=+[\]{}|;:\'",.<>?/])'
        r'[^\s]{8,}$'
    )

    return bool(re.match(pattern, password))
