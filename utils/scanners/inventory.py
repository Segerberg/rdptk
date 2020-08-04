import os
import hashlib
import json
import csv
import re
import platform
from datetime import datetime
import shutil
import logging
from utils.scanners.format import FormatIdentifier
import tempfile
from tabulate import tabulate
import pyfiglet
import pathlib

def log_file_handler():
    cwd = os.getcwd()
    temp_dir = tempfile.mkdtemp(dir=cwd)
    fh = logging.FileHandler(os.path.join(temp_dir, 'prov.log'), encoding="utf-8")
    return fh, temp_dir

def setup_logging(fh):
    logger = logging.getLogger('rdptk')
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    return logger

class ChecksumError(BaseException):
    """Raised when checksums not match"""
    pass

class Inventory():

    def __init__(self):
        self.db = {}
        self.ignore_dotdirs = None
        self.in_dir = None
        self.puid_freq = {}
        self.mime_freq = {}
        self.total_size = 0
        self.total_files = 0
        self.read_errors = []
        self.zero_byte_files = []
        self.total_folders = set()
        self.fi = FormatIdentifier()
        self.log_fh, self.temp_dir = log_file_handler()
        self.logger = setup_logging(self.log_fh)
        self.logger.info('Using Fido with signature files: %s', self.fi.get_versions())


    def read(self, in_dir, extensions=[], ignore_dotfiles=True, ignore_dotdirs = True):
        self.db = {}
        self.in_dir = in_dir
        self.ignore_dotdirs = ignore_dotdirs
        os.chdir(in_dir)
        extensions = [e.lower().strip('.') for e in extensions]
        for dirpath, dirnames, filenames in os.walk(in_dir):

            if ignore_dotdirs:
                for dirs in dirnames:
                    if dirs.startswith('.'):
                        self.logger.info('ignoring directory %s', dirs)
                        dirnames.remove(dirs)



            for filename in filenames:

                path = os.path.join(dirpath, filename)
                self.total_files += 1
                self.total_folders.add(dirpath)


                if ignore_dotfiles:
                    if filename.startswith('.'):
                        self.logger.info('ignoring dot file %s', path)
                        continue

                    name, ext = os.path.splitext(path)
                    if extensions and ext.lower().strip('.') in extensions:
                        self.logger.info('ignoring %s', path)
                        continue

                self.add(path)


    def write_json(self, out_dir):
        data = {'items': []}
        for sha256, meta in self.items():
            data['items'].append({
                'path': meta['path'],
                'sha256': meta['sha256'],
                'original_paths': meta['paths'],
                'created': datetime.utcfromtimestamp(meta['creation']).strftime('%Y-%m-%d %H:%M:%S'),
                'modified': datetime.utcfromtimestamp(meta['modified']).strftime('%Y-%m-%d %H:%M:%S'),
                'size': meta['size'],
                'format': meta['format'],

            })
        json.dump(data, open(os.path.join(out_dir, 'data.json'), 'w', encoding="utf-8"), indent=2)


    def write_csv(self, out_dir):
        fieldnames = ['sha256', 'path', 'original_paths', 'created', 'modified', 'size', 'format_name', 'registry_key', 'format_mime']
        fh = open(os.path.join(out_dir, 'data.csv'), 'w', encoding="utf-8")
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for sha256, meta in self.items():
            if len(meta['paths']) == 1:
                original_paths = meta['paths'][0]
            else:
                original_paths = ','.join(['"%s"' % p for p in meta['paths']])

            writer.writerow({
                'path': meta['path'],
                'sha256': meta['sha256'],
                'original_paths': original_paths,
                'created': datetime.utcfromtimestamp(meta['creation']).strftime('%Y-%m-%d %H:%M:%S'),
                'modified': datetime.utcfromtimestamp(meta['modified']).strftime('%Y-%m-%d %H:%M:%S'),
                'size': meta['size'],
                'format_name': meta['format']['format_name'],
                'registry_key': meta['format']['registry_key'],
                'format_mime': meta['format']['format_mime']
            })

    def items(self):
        keys = sorted(self.db.keys())
        for key in keys:
            yield key, self.db[key]

    def add(self, path):
        try:
            sha256 = get_sha256(path)
            format = self.fi.identify_file_format(path)
            if format['format_mime']:
                if format['format_mime'] in self.mime_freq:
                    self.mime_freq[format['format_mime']] += 1
                else:
                    self.mime_freq[format['format_mime']] = 1

            if format['registry_key']:
                self.logger.info('Identified %s as %s ', path, format['registry_key'])
                if format['registry_key'] in self.puid_freq:
                    self.puid_freq[format['registry_key']] += 1
                else:
                    self.puid_freq[format['registry_key']] = 1
            else:
                self.logger.warning('Failed to identify format of %s', path)
            creation = get_creation_ts(path)
            modified = os.path.getmtime(path)
            size = os.path.getsize(path)
            if size == 0:
                self.zero_byte_files.append(path)
            self.total_size += size
            #print(os.path.relpath(path))
            if sha256 in self.db:
                self.logger.info('found duplicate %s', path)
                self.db[sha256]['paths'].append(os.path.relpath(path))
            else:
                self.db[sha256] = {'paths': [os.path.relpath(path)], 'sha256': sha256,'creation':creation, 'format':format, 'modified':modified, 'size':size}
        except (OSError, UnicodeEncodeError):
            self.logger.warning('Failed reading file %s', path)
            self.read_errors.append(path)



    def write(self, out_dir):
        if not os.path.isdir(out_dir):
            self.logger.info('creating output directory %s', out_dir)
            os.makedirs(out_dir)
            os.makedirs(os.path.join(out_dir, 'metadata'))


        for sha256, meta in self.items():
            id = str(sha256)
            src = meta['paths'][0]
            filename, ext = os.path.splitext(src)
            ext = ext.lower()

            # if it doesn't look like an extension don't use it
            if not re.match('^\.[a-z0-9]+$', ext):
                ext = ''

            dst = os.path.join(out_dir, id + ext)
            shutil.copy2(src, dst)
            meta['path'] = dst.replace(out_dir + os.sep, '')
            self.logger.info('copied %s to %s', src, dst)

            if sha256 != get_sha256(dst):
                raise ChecksumError("Checksums don't match")


        self.write_json(os.path.join(out_dir, 'metadata'))
        self.write_csv(os.path.join(out_dir, 'metadata'))
        shutil.copy(os.path.join(self.temp_dir, 'prov.log'), os.path.join(out_dir, 'metadata', 'prov.log'))
        self.log_fh.close()
        shutil.rmtree(self.temp_dir)



    def txt_report(self, out_dir):
        fieldnames = ['path', 'created', 'modified', 'size']
        data = []
        pronom = {k: v for k, v in sorted(self.puid_freq.items(), reverse=True, key=lambda item: item[1])}
        mime = {k: v for k, v in sorted(self.mime_freq.items(), reverse=True, key=lambda item: item[1])}
        sd_header = ['PUID', 'Count']
        with open (os.path.join(out_dir, 'metadata', 'report.txt'), 'w', encoding='utf-8') as f:

            f.write(pyfiglet.figlet_format("REPORT"))
            f.write('\n')
            f.write(f'Report generated UTC: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")}')
            f.write('\n')

            f.write(pyfiglet.figlet_format("Overview", font='small'))
            f.write('\n')
            f.write(f'Files: {self.total_files}')
            f.write('\n')
            f.write(f'Subfolders: {len(self.total_folders)}')
            f.write('\n')
            f.write(f'Size: {convert_bytes(self.total_size)}')
            f.write('\n')
            f.write(f'Unreadable files: {len(self.read_errors)}')
            f.write('\n')

            if len(self.zero_byte_files) > 0:
                f.write(pyfiglet.figlet_format("Zero byte files", font='small'))
                f.write('\n')
                f.write(f'The following {len(self.zero_byte_files)} file(s) are empty.')
                f.write('\n')
                f.write('\n')
                for i in self.zero_byte_files:
                    f.write(i)
                    f.write('\n')
            f.write('\n')

            if len( self.read_errors) > 0:
                f.write(pyfiglet.figlet_format("Read Errors", font='small'))
                f.write('\n')
                f.write(f'The following {len(self.read_errors)} file(s) could not be read.')
                f.write('\n')
                f.write('\n')
                for e in self.read_errors:
                    f.write(e)
                    f.write('\n')
            f.write('\n')
            f.write('\n')

            f.write(pyfiglet.figlet_format("Formats",font='small'))
            f.write('\n')
            f.write(tabulate(pronom.items(), tablefmt="github", headers=sd_header))
            f.write('\n')
            f.write('\n')

            f.write(pyfiglet.figlet_format("MIME", font='small'))
            f.write(tabulate(mime.items(), tablefmt="github", headers=sd_header))
            f.write('\n')
            f.write('\n')

            f.write(pyfiglet.figlet_format("Directory tree", font='small'))
            f.write('\n')
            for dir in self.directory_tree_for_print(self.in_dir):
                f.write(dir)
                f.write('\n')
            f.write('\n')

            f.write(pyfiglet.figlet_format("FileList", font='small'))
            f.write('\n')
            for sha256, meta in self.items():
                if len(meta['paths']) == 1:
                    original_folder, original_filename = os.path.split(meta['paths'][0])

                else:
                    filenames = []
                    folders = []
                    for p in meta['paths']:
                        filenames.append(os.path.split(meta['paths'][0])[1])
                        folders.append(os.path.split(meta['paths'][0])[0])

                    original_filename = ','.join(['%s' % p for p in filenames])
                    original_folder = ','.join(['%s' % p for p in folders])

                data.append( {
                    'sha256': meta['sha256'],
                    'created': datetime.utcfromtimestamp(meta['creation']).strftime('%Y-%m-%d %H:%M:%S'),
                    'modified': datetime.utcfromtimestamp(meta['modified']).strftime('%Y-%m-%d %H:%M:%S'),
                    'size': meta['size'],
                    'puid': meta['format']['registry_key'],
                    'mime': meta['format']['format_mime'],
                    'original filename': original_filename,
                    'original folder': original_folder,
                })

            f.write(tabulate(data, tablefmt="github", headers="keys"))

    def directory_tree_for_print(self, path):
        dir_tree = []
        for root, dirs, files in os.walk(path):
            if self.ignore_dotdirs:
                for dir in dirs:
                    if dir.startswith('.'):
                        dirs.remove(dir)

            level = root.replace(path, '').count(os.sep)
            indent = ' ' * 4 * (level)
            dir_tree.append('{}{}/'.format(indent, os.path.basename(root)))
        return dir_tree

    def restore(self, spec, out_dir):
        if not os.path.isdir(out_dir):
            os.makedirs(out_dir)

        with open(spec,'r') as f:
            data = json.load(f)
            for item in data['items']:
                for p in item['original_paths']:
                    parent_dir = pathlib.Path(spec).parent.parent
                    cur_dir = os.path.dirname(os.path.relpath(p))

                    if not os.path.exists(os.path.join(out_dir,cur_dir)) and cur_dir:
                        os.makedirs(os.path.join(out_dir,cur_dir))

                    shutil.copy2(os.path.join(parent_dir,item['path']), os.path.join(out_dir, p))





def get_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        buff = None
        while buff != b'':
            buff = fh.read(1024)
            h.update(buff)
    sha256 = h.hexdigest()
    #print('sha256 %s %s', path, sha256)
    return sha256


def get_creation_ts(path):
    """
    Try to get the date that a file was created,
    """
    if platform.system() == 'Windows':
        return os.path.getctime(path)
    else:
        stat = os.stat(path)
        try:
            return stat.st_birthtime
        except AttributeError:
            return None

def convert_bytes(num):
    step_unit = 1000.0
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < step_unit:
            return "%3.1f %s" % (num, x)
        num /= step_unit

x = Inventory()
x.read('C:\git\\test')
x.write('C:/git/rdptk/testkopi')
#x.txt_report('C:/git/rdptk/testkopi')
x.restore("C:\\git\\rdptk\\testkopi\\metadata\\data.json",'C:/git/rdptk/testrestore')