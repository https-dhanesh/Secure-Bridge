from detector.hybrid_detector import HybridDetector


TEST_CASES = [

    # =========================================================
    # DETERMINISTIC PII
    # =========================================================

    (
        "My email is test@example.com",
        ["EMAIL"]
    ),

    (
        "My PAN is ABCDE1234F",
        ["PAN"]
    ),

    (
        "My card number is 4532015112830366",
        ["CREDIT_CARD"]
    ),

    # =========================================================
    # CONTEXTUAL PII
    # =========================================================

    (
        "My name is Rahul Sharma",
        ["PERSON_NAME"]
    ),

    (
        "Contact Rahul Sharma at rahul.sharma@example.com",
        ["PERSON_NAME", "EMAIL"]
    ),

    # =========================================================
    # PHONE CONTEXT
    # =========================================================

    (
        "Call me on 9876543210",
        ["MOBILE_NUMBER"]
    ),

    (
        "My order ID is 9876543210",
        []
    ),

    (
        "Transaction reference number is 9876543210",
        []
    ),

    (
        "Employee ID is 9876543210",
        []
    ),

    # =========================================================
    # MIXED PII
    # =========================================================

    (
        "My name is Rahul Sharma, email is rahul@example.com "
        "and PAN is ABCDE1234F",
        ["PERSON_NAME", "EMAIL", "PAN"]
    ),
]


def run_test(text, expected_categories):

    print("\n" + "=" * 80)

    print("INPUT:")
    print(text)

    result = HybridDetector.detect(text)

    actual_categories = [
        detection.category
        for detection in result.detections
    ]

    print("\nMODEL USED:")
    print(result.model_used)

    print("\nLATENCY:")
    print(result.latency_ms, "ms")

    print("\nDETECTIONS:")

    for detection in result.detections:
        print(
            detection.to_dict()
        )

    print("\nEXPECTED:")
    print(expected_categories)

    print("\nACTUAL:")
    print(actual_categories)

    if sorted(actual_categories) == sorted(
        expected_categories
    ):
        print("\nRESULT: PASS")
        return True

    print("\nRESULT: FAIL")
    return False


def main():

    passed = 0
    failed = 0

    for text, expected in TEST_CASES:

        success = run_test(
            text,
            expected
        )

        if success:
            passed += 1
        else:
            failed += 1

    print("\n")
    print("=" * 80)
    print("FINAL TEST SUMMARY")
    print("=" * 80)

    print("Total :", len(TEST_CASES))
    print("Passed:", passed)
    print("Failed:", failed)

    if failed == 0:
        print("\nALL TESTS PASSED")
    else:
        print("\nSOME TESTS FAILED")


if __name__ == "__main__":
    main()