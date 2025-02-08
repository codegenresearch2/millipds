import unittest
from dataclasses import dataclass
import aiohttp
import asyncio

@dataclass
class PDSInfo:
    endpoint: str
    db: object

class TestExample(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.session = aiohttp.ClientSession()

    @classmethod
    def tearDownClass(cls):
        asyncio.get_event_loop().run_until_complete(cls.session.close())

    async def test_hello_world(self):
        async with self.session.get('http://example.com') as response:
            self.assertEqual(response.status, 200)
            self.assertIn('Hello', await response.text())

    @unittest.skip('Example of a skipped test')
    def test_example_skipped(self):
        pass

if __name__ == '__main__':
    unittest.main()