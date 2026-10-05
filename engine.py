import re

class AlgorithmicEngine:
    _d = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 1, 2, 3, 4],
        [6, 5, 9, 8, 7, 1, 0, 1, 2, 3], [7, 6, 5, 9, 8, 2, 1, 0, 1, 2],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 1], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    ]
    _p = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
    ]

    @staticmethod
    def validate_luhn(card_number: str) -> bool:
        digits = [int(d) for d in re.sub(r'\D', '', card_number)]
        if not (13 <= len(digits) <= 19):
            return False
        checksum = 0
        for i, digit in enumerate(digits[::-1]):
            if i % 2 == 1:
                doubled = digit * 2
                checksum += doubled - 9 if doubled > 9 else doubled
            else:
                checksum += digit
        return checksum % 10 == 0

    @classmethod
    def validate_verhoeff(cls, number_str: str) -> bool:
        digits = [int(d) for d in re.sub(r'\D', '', number_str)]
        if len(digits) != 12:
            return False
        c = 0
        for i, item in enumerate(reversed(digits)):
            c = cls._d[c][cls._p[i % 8][item]]
        return c == 0

    @staticmethod
    def validate_luhn(card_number: str) -> bool:
        digits = [int(d) for d in re.sub(r'\D', '', card_number)]
        if not (13 <= len(digits) <= 19):
            return False
        checksum = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                doubled = digit * 2
                checksum += doubled - 9 if doubled > 9 else doubled
            else:
                checksum += digit
        return checksum % 10 == 0

    @classmethod
    def validate_verhoeff(cls, number_str: str) -> bool:
        digits = [int(d) for d in re.sub(r'\D', '', number_str)]
        if len(digits) != 12:
            return False
        c = 0
        for i, item in enumerate(reversed(digits)):
            c = cls._d[c][cls._p[i % 8][item]]
        return c == 0

    @staticmethod
    def validate_ssn(ssn_str: str) -> bool:
        clean_ssn = re.sub(r'\D', '', ssn_str)
        if len(clean_ssn) != 9:
            return False
        area, group, serial = int(clean_ssn[:3]), int(clean_ssn[3:5]), int(clean_ssn[5:])
        if area == 0 or area == 666 or area >= 900 or group == 0 or serial == 0:
            return False
        return True

    @staticmethod
    def validate_pan(pan_str: str) -> bool:
        return bool(re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]{1}$', pan_str))