import json


class CodeGeneratorService:
    @staticmethod
    def generate(defn: dict) -> str:
        method = defn['method'].lower()
        body_line = ''
        if defn.get('json_body') is not None:
            body_line = f"            json={json.dumps(defn['json_body'], indent=12)},\n"
        elif defn.get('form_body') is not None:
            body_line = f"            data={json.dumps(defn['form_body'], indent=12)},\n"
        elif defn.get('raw_body') is not None:
            body_line = f"            content={json.dumps(defn['raw_body'])},\n"
        code = (
            "import httpx\n\n"
            "def run_request():\n"
            "    with httpx.Client(timeout=20.0) as client:\n"
            f"        response = client.{method}(\n"
            f"            {json.dumps(defn['url'])},\n"
            f"            headers={json.dumps(defn.get('headers', {}), indent=12)},\n"
            f"            cookies={json.dumps(defn.get('cookies', {}), indent=12)},\n"
            f"            params={json.dumps(defn.get('query_params', {}), indent=12)},\n"
            f"{body_line}"
            "        )\n"
            "        print(response.status_code)\n"
            "        print(response.text[:500])\n\n"
            "if __name__ == '__main__':\n"
            "    run_request()\n"
        )
        return code
