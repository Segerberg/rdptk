from fido.fido import Fido
import mimetypes
import os
import time

MB = 1024 * 1024
DEFAULT_MIMETYPE = 'application/octet-stream'
class FormatIdentifier:
    _fido = None

    def __init__(self, allow_unknown_file_types=False, allow_encrypted_files=False):
        self.allow_unknown_file_types = allow_unknown_file_types
        self.allow_encrypted_files = allow_encrypted_files

    @property
    def fido(self):
        if self._fido is None:
            #logger.debug('Initiating fido')
            self._fido = Fido(handle_matches=self.handle_matches)
            #logger.info('Initiated fido')

        return self._fido

    def get_versions(self):
        return [self.fido.containersignature_file] + self.fido.format_files

    def handle_matches(self, fullname, matches, delta_t, matchtype=''):
        if len(matches) == 0:

            self.format_name = 'Unknown File Format'
            self.format_version = None
            self.format_registry_key = None
            return

           # raise ValueError("No matches for %s" % fullname)

        f, _ = matches[-1]


        try:
            self.format_name = f.find('name').text
        except AttributeError:
            self.format_name = None
        try:
            self.format_mime= f.find('mime').text
        except AttributeError:
            self.format_mime = DEFAULT_MIMETYPE

        try:
            self.format_version = f.find('version').text
        except AttributeError:
            self.format_version = None

        try:
            self.format_registry_key = f.find('puid').text
        except AttributeError:
            self.format_registry_key = None


    def identify_file_format(self, filename):
        """
        Identifies the format of the file using the fido library
        Args:
            filename: The filename to identify
        Returns:
            A tuple with the format name, version and registry key
        """

        if os.name == 'nt':
            start_time = time.perf_counter()
        else:
            start_time = time.time()

        #logger.debug("Identifying file format of %s ..." % (filename,))

        self.fido.identify_file(filename)

        if os.name == 'nt':
            end_time = time.perf_counter()
        else:
            end_time = time.time()

        time_elapsed = end_time - start_time
        size = os.path.getsize(filename)
        size_mb = size / MB

        try:
            mb_per_sec = size_mb / time_elapsed
        except ZeroDivisionError:
            mb_per_sec = size_mb

        file_format = {'format_name':self.format_name,'format_version':self.format_version,'registry_key': self.format_registry_key,
                       'format_mime':self.format_mime}
        #logger.info
        #print(
        #    "Identified the format of %s at %s MB/Sec (%s sec): %s" % (
        #        filename, mb_per_sec, time_elapsed, file_format
        #    )
        #)

        return file_format


