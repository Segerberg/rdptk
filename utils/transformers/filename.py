import string
import unicodedata
import os


DEFAULT_WHITELIST_FILE = "-_. %s%s" % (string.ascii_letters, string.digits)
DEFAULT_WHITELIST_DIR = "-_\\// %s%s" % (string.ascii_letters, string.digits)

def clean(path, whitelist_file=None, whitelist_dir=None, replace=None, normalize_unicode=True, lower=True):

    if whitelist_file is None:
        whitelist_file = DEFAULT_WHITELIST_FILE

    if whitelist_dir is None:
        whitelist_dir = DEFAULT_WHITELIST_DIR

    if replace is None:
        replace = {' ': '_'}

    filename = (os.path.basename(path))
    dir_name = os.path.dirname(path)

    for k, v in replace.items():
        filename = filename.replace(k, v)

    for k, v in replace.items():
        dir_name = dir_name.replace(k, v)

    if normalize_unicode:
        # keep only valid ascii chars
        filename = unicodedata.normalize('NFKD', filename).encode('ASCII', 'ignore').decode()
        dir_name =  unicodedata.normalize('NFKD', dir_name).encode('ASCII', 'ignore').decode()

    if lower:
        filename = filename.lower()
        dir_name = dir_name.lower()

    new_filename = ''.join(c for c in filename if c in whitelist_file)
    new_dirname = ''.join(c for c in dir_name if c in whitelist_dir)

    return (new_dirname, new_filename)