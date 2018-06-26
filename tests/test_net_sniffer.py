from unittest import  TestCase
from strawberry import core


class Test(TestCase):
    def test_default(self):
        snf = core.Sniffer()
        try:
            snf.run()
        except KeyboardInterrupt:
            snf.close()