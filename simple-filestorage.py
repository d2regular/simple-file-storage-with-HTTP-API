#!/usr/bin/env python3

from hashlib import md5
from re import match
from os import path, getcwd, mkdir, rmdir, remove, replace
from io import BytesIO
from datetime import datetime
from collections import namedtuple
from tempfile import NamedTemporaryFile
from http.server import HTTPServer, BaseHTTPRequestHandler

ResponseStatus = namedtuple('HTTPStatus', 'code message')

ResponseData = namedtuple('ResponseData', 'status content_type '
                                          'content_length data_stream')
# set default values for 'content_type', 'content_length', 'data_stream'
ResponseData.__new__.__defaults__ = (None, None, None)

HTTP_STATUS = {"OK": ResponseStatus(code=200, message="OK"),
               "CREATED": ResponseStatus(code=201, message="Created"),
               "BAD_REQUEST": ResponseStatus(code=400, message="Bad request"),
               "NOT_FOUND": ResponseStatus(code=404, message="Not found"),
               "INTERNAL_SERVER_ERROR":
                   ResponseStatus(code=500, message="Internal server error")}

# buffer size that is used to hash, read, write files
CHUNK_SIZE = 16 * 1024
# path of directory where files are stored
FILES_DIR = getcwd() + '/files/'
SERVER_ADDRESS = ('127.0.0.1', 8080)


def main():
    print('Http server is starting...')
    httpd = HTTPServer(SERVER_ADDRESS, RequestsHandler)
    print('Http server is running...')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print('Http server closes...')


def md5_hash_hex(file):
    """read file by chunks and return hash md5"""
    data_hash = md5()
    if file.seekable():
        file.seek(0)
    while True:
        copied_bytes = file.read(CHUNK_SIZE)
        data_hash.update(copied_bytes)
        if len(copied_bytes) < CHUNK_SIZE:
            break
    return data_hash.hexdigest()


def date_now():
    return datetime.now().strftime('[%d/%b/%Y %H:%M:%S]')


def copyfile(in_stream, out_stream, content_len=None):
    """Copy data from in_stream to  out_stream by chunks.
    Return number of recorded bytes"""

    recorded_bytes = 0

    if content_len is not None:
        if content_len < CHUNK_SIZE:
            copied_bytes = in_stream.read(content_len)
            out_stream.write(copied_bytes)
            recorded_bytes = len(copied_bytes)
        else:
            # Data is copied by chunks. Since "rifle" allows to read only
            # the exact number of bytes, so the length of the last chunk
            # depends on the content_len
            n = content_len // CHUNK_SIZE
            for i in range(n):
                copied_bytes = in_stream.read(CHUNK_SIZE)
                out_stream.write(copied_bytes)
                recorded_bytes += len(copied_bytes)
            # record last chunk what less CHUNK_SIZE
            end_bytes = content_len % CHUNK_SIZE
            if end_bytes:
                copied_bytes = in_stream.read(end_bytes)
                out_stream.write(copied_bytes)
                recorded_bytes += len(copied_bytes)
    else:
        while True:
            copied_bytes = in_stream.read(CHUNK_SIZE)
            out_stream.write(copied_bytes)
            recorded_bytes += len(copied_bytes)
            if len(copied_bytes) < CHUNK_SIZE:
                break

    return recorded_bytes


class HTTPStatusError(Exception):
    """Exception wrapping a value from http.server.HTTPStatus"""

    def __init__(self, status, description=None):
        """
        Constructs an error instance from a tuple of
        (code, message, description), see http.server.HTTPStatus
        """
        # super(HTTPStatusError, self).__init__()
        # self.code = status.code
        # self.message = status.message
        # self.explain = description
        self.code = status.code
        self.message = status.message
        self.explain = description


class RequestsHandler(BaseHTTPRequestHandler):
    """
    Simple HTTP request handler with GET/DELETE/POST commands
    This class implements API.
    Base url API: /v1/files/
    The name and the unique identifier of a file is the value of
    MD5 hash function where the function argument is a file. It looks like
    a string which consists of hexadecimal digits.

    """

    def do_POST(self):
        """Handles GET-requests by url /v1/files/[md5_hash]
        Returns a file if it exists
        """

        url_path = self.path.rstrip()

        print("{0}\t[START]: Received POST for {1}".format(date_now(),
                                                           url_path))

        try:
            if match(r'^/v1/files/?$', url_path):
                response = self.upload_file()
                self.send_headers(response.status, response.content_type,
                                  response.content_length)
                if response.data_stream:
                    self.wfile.write(response.data_stream)

            else:
                self.handle_not_found()
        except HTTPStatusError as err:
            self.send_error(err.code, err.message, err.explain)
        print("{}\t[END]".format(date_now()))

    def do_GET(self):
        """Handles GET-requests by url /v1/files/[md5_hash]
        Returns a file if it exists
        """

        url_path = self.path.rstrip()

        print("{0}\t[START]: Received GET for {1}".format(date_now(),
                                                          url_path))

        try:
            if match(r'^/v1/files/[0-9a-fA-F]{32}/?$', url_path):
                response = self.download_file()
                self.send_headers(response.status, response.content_type,
                                  response.content_length)
                if response.data_stream:
                    try:
                        copyfile(response.data_stream, self.wfile)
                    except OSError as err:
                        raise HTTPStatusError(
                            HTTP_STATUS["INTERNAL_SERVER_ERROR"], str(err))
                    finally:
                        if response.data_stream is not None:
                            response.data_stream.close()
            else:
                self.handle_not_found()
        except HTTPStatusError as err:
            self.send_error(err.code, err.message, err.explain)

        print("{}\t[END]".format(date_now()))

    def do_DELETE(self):
        """Handles DELETE-requests by url /v1/files/[md5_hash]
        Deletes a file if it exists
        """

        url_path = self.path.rstrip()

        print("{0}\t[START]: Received DELETE for {1}".format(date_now(),
                                                             url_path))

        try:
            if match(r'^/v1/files/[0-9a-fA-F]{32}/?$', url_path):
                response = self.delete_file()
                self.send_headers(response.status)
            else:
                self.handle_not_found()
        except HTTPStatusError as err:
            self.send_error(err.code, err.message, err.explain)

        print("{}\t[END]".format(date_now()))

    def handle_not_found(self):
        """Handles routing for unexpected paths"""
        raise HTTPStatusError(HTTP_STATUS["NOT_FOUND"], "File not found")

    def send_headers(self, status, content_type=None, content_length=None):
        """Send out the group of headers for a successful request"""

        self.send_response(status.code, status.message)
        if content_type:
            self.send_header('Content-Type', content_type)
        if content_length:
            self.send_header('Content-Length', content_length)
        self.end_headers()

    def upload_file(self):
        """Upload file to server and return response data"""

        payload = None

        try:
            str_content_len = self.headers['Content-Length']
            content_len = int(str_content_len) if str_content_len else 0

            if content_len:

                payload = BytesIO()
                copyfile(self.rfile, payload, content_len)
                payload.seek(0)

                file_hash = md5_hash_hex(payload)
                payload.seek(0)

                try:
                    mkdir(FILES_DIR)
                except FileExistsError as err:
                    print(err)

                file_dir = FILES_DIR + file_hash[:2] + '/'
                file_path = file_dir + file_hash

                if not path.exists(file_path):
                    try:
                        mkdir(file_dir)
                    except FileExistsError as err:
                        print(err)

                    # protection against race condition
                    # create temporary file then replace it with name file_path
                    with NamedTemporaryFile(dir=FILES_DIR,
                                            delete=False) as tf:
                        copyfile(payload, tf)
                        tf.flush()
                        tmp_file = tf.name
                        replace(tmp_file, file_path)

                    data = bytes(file_hash.encode('UTF-8'))
                    content_len = len(data)
                    return ResponseData(
                        status=HTTP_STATUS['CREATED'],
                        content_type='text/plain; charset=utf-8',
                        content_length=content_len, data_stream=data)

                return ResponseData(status=HTTP_STATUS['OK'])
            else:
                raise HTTPStatusError(HTTP_STATUS["BAD_REQUEST"],
                                      "Wrong parameters")
        except OSError as err:
            raise HTTPStatusError(HTTP_STATUS["INTERNAL_SERVER_ERROR"],
                                  str(err))
        finally:
            if payload is not None:
                payload.close()

    def download_file(self):
        """If requested file exists return response data for downloading"""

        url_path = self.path.rstrip()
        file_hash = url_path.split('/')[-1]
        file_dir = FILES_DIR + file_hash[:2] + '/'
        file_path = file_dir + file_hash
        f = None

        if path.exists(file_path):
            try:
                f = open(file_path, 'br')
                data_stream = BytesIO()
                content_len = copyfile(f, data_stream)
                data_stream.seek(0)
                return ResponseData(
                    status=HTTP_STATUS['OK'],
                    content_type='application/octet-stream',
                    content_length=content_len, data_stream=data_stream)

            except OSError as err:
                raise HTTPStatusError(HTTP_STATUS["INTERNAL_SERVER_ERROR"],
                                      str(err))
            finally:
                if f is not None:
                    f.close()
        else:
            self.handle_not_found()

    def delete_file(self):
        """Delete file if exists"""

        url_path = self.path.rstrip()
        file_hash = url_path.split('/')[-1]
        file_dir = FILES_DIR + file_hash[:2] + '/'
        file_path = file_dir + file_hash

        if path.exists(file_path):
            try:
                remove(file_path)
                try:
                    rmdir(file_dir)
                except OSError as err:
                    print(err)
                return ResponseData(status=HTTP_STATUS['OK'])
            except OSError as err:
                raise HTTPStatusError(HTTP_STATUS["INTERNAL_SERVER_ERROR"],
                                      str(err))
        else:
            self.handle_not_found()


if __name__ == '__main__':
    main()
