import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from radar.api import Handler, STATE


class APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, path, data=None):
        headers = {}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = Request(self.url + path, data=json.dumps(data).encode() if data is not None else None, headers=headers)
        return urlopen(req)

    def test_scan_filter_and_csv_without_key(self):
        with self.request("/") as response:
            self.assertEqual(response.headers.get_content_type(), "text/html")
            self.assertIn(b"Identity Risk Analyzer", response.read())
        with self.request("/api/v1/scans", {"source": "demo"}) as response:
            self.assertEqual(response.status, 200)
            self.assertGreater(json.load(response)["inventory"]["privileged_accounts"], 0)
        with self.request("/api/v1/findings?severity=Critical") as response:
            body = json.load(response)
            self.assertTrue(all(f["severity"] == "Critical" for f in body["items"]))
        with self.request("/api/v1/export.csv") as response:
            self.assertEqual(response.headers.get_content_type(), "text/csv")
            self.assertTrue(response.read().startswith(b"\xef\xbb\xbf"))
        self.assertIsNotNone(STATE["report"])

    def test_scan_request_rejects_user_data(self):
        with self.assertRaises(HTTPError) as caught:
            self.request("/api/v1/scans", {"users": [{"name": "injected"}]})
        self.assertEqual(caught.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
