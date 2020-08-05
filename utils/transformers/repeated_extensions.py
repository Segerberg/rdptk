import os
import re

REPEATED_PATTERN = r'\.(\w+)(\.(\1))+'

def clean(filename):
    filename = re.sub(REPEATED_PATTERN, '.\\1', filename)
    return filename