class DependencyResolverService:
    @staticmethod
    def detect_from_definition(definition: dict) -> list[dict]:
        deps = [{'package_name': 'httpx', 'version_spec': '>=0.28,<1.0', 'is_direct': True, 'is_approved': True}]
        body = definition.get('raw_body') or ''
        if '<html' in body.lower():
            deps.append({'package_name': 'beautifulsoup4', 'version_spec': '>=4,<5', 'is_direct': False, 'is_approved': True})
        return deps
