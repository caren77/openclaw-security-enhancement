import unittest

from osef.client import OpenClawClient


class ClientTests(unittest.TestCase):
    def test_extract_response(self) -> None:
        self.assertEqual(OpenClawClient.extract_response('{"reply":"hello"}'), "hello")
        self.assertEqual(OpenClawClient.extract_response("plain text"), "plain text")

    def test_command_is_argument_list(self) -> None:
        client = OpenClawClient(["openclaw", "agent", "--message", "{prompt}"], __import__('pathlib').Path('.'), 1)
        command = client.build_command("line 1\nline 2", "session")
        self.assertEqual(command[-1], "line 1\nline 2")


if __name__ == "__main__":
    unittest.main()


def test_extract_nested_final_assistant_text():
    import json
    from osef.client import OpenClawClient

    stdout = json.dumps({"result": {"finalAssistantVisibleText": "正常回答"}}, ensure_ascii=False)
    assert OpenClawClient.extract_response(stdout) == "正常回答"


def test_extract_response_prefers_meta_visible_text_then_payload():
    import json
    preferred = {
        "result": {
            "payloads": [{"text": "fallback"}],
            "meta": {"finalAssistantVisibleText": "visible"},
        }
    }
    fallback = {"result": {"payloads": [{"text": "fallback"}], "meta": {}}}
    assert OpenClawClient.extract_response(json.dumps(preferred)) == "visible"
    assert OpenClawClient.extract_response(json.dumps(fallback)) == "fallback"
