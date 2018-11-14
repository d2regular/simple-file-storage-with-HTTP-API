from hashlib import sha3_256, md5
from re import match
from os import path, getcwd, mkdir, replace
from io import BytesIO
from datetime import datetime
from collections import namedtuple
from tempfile import NamedTemporaryFile
from shutil import copyfileobj
from http.server import HTTPServer, BaseHTTPRequestHandler
import random

ResponseStatus = namedtuple('HTTPStatus', 'code message')

ResponseData = namedtuple('ResponseData', 'status content_type '
                                          'content_length data_stream')
# set default values for 'content_type', 'data_stream'
ResponseData.__new__.__defaults__ = (None, None, None)
HTTP_STATUS = {"OK": ResponseStatus(code=200, message="OK"),
               "CREATED": ResponseStatus(code=201, message="Created"),
               "BAD_REQUEST": ResponseStatus(code=400, message="Bad request"),
               "NOT_FOUND": ResponseStatus(code=404, message="Not found"),
               "INTERNAL_SERVER_ERROR":
                   ResponseStatus(code=500, message="Internal server error")}
FILES_DIR = getcwd() + '/files/'
CHUNK_SIZE = 16 * 1024


def main():
    print('Http server is starting...')
    server_address = ('127.0.0.1', 8080)
    httpd = HTTPServer(server_address, RequestsHandler)
    print('Http server is running...')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print('Http server closes...')

    # def main():
    # data = b''
    # for x in range(1024):
    #     data += bytes(random.randint(0, 300))
    # md5_hash_hex(data)

    # with open('./data/testfile', 'rb') as f:
    #     print(f.read())
    #     f.seek(0)
    #     print(md5_hash_hex(f))
    # pass

    # def md5_hash_hex_1(data):
    start_copy = 0
    stop_copy = CHUNK_SIZE
    data_hash = md5()
    # all_copied = b''
    # while True:
    # copied_bytes = data[start_copy:stop_copy]
    # data_hash.update(copied_bytes)
    # all_copied += copied_bytes
    # print('start: {0}, stop: {1}, step: {2}, len_copied:  {3}, all: {4}, '
    #       'copied: {5}, left: {6}'.format(start_copy, stop_copy,
    #                                       (stop_copy-start_copy),
    #                                       len(copied_bytes), len(data),
    #                                       len(all_copied),
    #                                       (len(data) - len(all_copied))))
    # start_copy = stop_copy
    # stop_copy += CHUNK_SIZE
    # if len(copied_bytes) < CHUNK_SIZE:
    #     break
    # print(data_hash.hexdigest())
    # return data_hash.hexdigest()


def md5_hash_hex(file):
    """read file by chunks and return hash md5"""
    data_hash = md5()
    while True:
        copied_bytes = file.read(CHUNK_SIZE)
        data_hash.update(copied_bytes)
        if len(copied_bytes) < CHUNK_SIZE:
            break
    file.seek(0)
    return data_hash.hexdigest()


def date_now():
    return datetime.now().strftime('[%d/%b/%Y %H:%M:%S]')


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
            print(err.code, err.message, err.explain)
        print("{}\t[END]".format(date_now()))

    def do_GET(self):
        pass

    def do_DELETE(self):
        pass

    def handle_not_found(self):
        """Handles routing for unexpected paths"""
        raise HTTPStatusError(HTTP_STATUS["NOT_FOUND"], "File not found")

    def send_headers(self, status, content_type=None, content_length=None):
        """Send out the group of headers for a successful request"""

        self.send_response(status.code, status.message)
        if content_type:
            self.send_header('Content-type', content_type)
        if content_length:
            self.send_header('Content-Length', content_length)
        self.end_headers()

    def copy_body(self, out_stream, content_len):
        """Read request body by chunks and write to output stream"""

        if content_len < CHUNK_SIZE:
            copied_bytes = self.rfile.read(content_len)
            out_stream.write(copied_bytes)
        else:
            while True:
                copied_bytes = self.rfile.read(CHUNK_SIZE)
                out_stream.write(copied_bytes)
                if len(copied_bytes) < CHUNK_SIZE:
                    break

    def write_body(self, in_stream):
        pass

    def upload_file(self):
        """Upload file to server and return response data"""

        payload = None

        try:
            str_content_len = self.headers['Content-Length']
            content_len = int(str_content_len) if str_content_len else 0

            if content_len:

                payload = BytesIO()
                self.copy_body(payload, content_len)
                file_hash = md5_hash_hex(payload)

                try:
                    mkdir(FILES_DIR)
                except OSError as err:
                    print(err)

                file_path = FILES_DIR + file_hash[:2] + file_hash

                if not path.exists(file_path):
                    # protection against race condition
                    # create temporary file then replace it with name file_path
                    with NamedTemporaryFile(dir=FILES_DIR,
                                            delete=False) as tf:
                        while True:
                            copied_bytes = payload.read(CHUNK_SIZE)
                            tf.write(copied_bytes)
                            if len(copied_bytes) < CHUNK_SIZE:
                                break
                        tf.flush()
                        tmp_file = tf.name
                    replace(tmp_file, file_path)

                    print('File created {}'.format(file_hash))

                    data = bytes(file_hash.encode('UTF-8'))
                    content_length = len(data)
                    return ResponseData(
                        status=HTTP_STATUS['CREATED'],
                        content_type='text/plain; charset=utf-8',
                        content_length=content_length,
                        data_stream=data)

                print('File already exists {}'.format(file_hash))
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
        pass

    def delete_file(self):
        pass


if __name__ == '__main__':
    main()
