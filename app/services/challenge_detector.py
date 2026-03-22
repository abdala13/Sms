class ChallengeDetectorService:
    MARKERS = {
        'recaptcha': ['g-recaptcha', 'recaptcha/api.js'],
        'hcaptcha': ['hcaptcha', 'h-captcha'],
        'challenge': ['verify you are human', 'captcha', 'attention required'],
    }

    @classmethod
    def detect(cls, text: str, headers: dict | None = None) -> dict | None:
        hay = (text or '').lower()
        for label, markers in cls.MARKERS.items():
            if any(m in hay for m in markers):
                return {'type': 'challenge.detected', 'label': label}
        return None
