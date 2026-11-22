import unittest

from calculator import add


class CalculatorTests(unittest.TestCase):
    def test_add_positive_numbers(self):
        self.assertEqual(add(2, 3), 5)

    def test_add_negative_number(self):
        self.assertEqual(add(-2, 3), 1)

