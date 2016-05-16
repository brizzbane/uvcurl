import pyuv
from uvcurl import cURLHTTPRequest, cURLHTTPClient

def read_result(future):
    result = future.result()
    print(result.body)


ioloop = pyuv.Loop.default_loop()

request = cURLHTTPRequest('http://google.com')
client = cURLHTTPClient(ioloop)

future = client.req(request)
future.add_done_callback(read_result)
ioloop.run()