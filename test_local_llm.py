from llm_detector import LocalLLMDetector


TESTS = [
    "Call me on 9876543210",
    "Employee ID is 9876543210",
    "My order ID is 9876543210",
    "Transaction reference number is 9876543210",
    "My name is Rahul Sharma",
]


def run_test(text: str):
    print("\n" + "=" * 80)
    print("INPUT:")
    print(text)

    result = LocalLLMDetector.detect(text)

    print("\nSUCCESS:")
    print(result.get("success"))

    print("\nMODEL:")
    print(result.get("model"))

    print("\nLATENCY:")
    print(result.get("latency_ms"), "ms")

    print("\nDETECTIONS:")

    for detection in result.get("detections", []):
        print(detection)

    if not result.get("success"):
        print("\nERROR:")
        print(result.get("error"))

    print("\nRAW MODEL RESPONSE:")
    print(result.get("raw_response", "N/A"))


def main():
    print("=" * 80)
    print("SECURE BRIDGE - LOCAL QWEN TEST")
    print("=" * 80)

    print("\nUsing local Qwen model through llama-cpp-python.")
    print("Ollama is NOT required.")

    for text in TESTS:
        run_test(text)

    print("\n" + "=" * 80)
    print("TESTING COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()  