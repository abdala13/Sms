
# Sentinel Verify Platform — Lite

نسخة حقيقية وخفيفة للرفع من الهاتف، مبنية على Flask وبعدد ملفات قليل.

## ما الذي تفعله؟
- فحص مواقع وروابط تطبيقات
- إدخال متعدد عبر textarea
- زحف داخلي لنفس الدومين
- اكتشاف:
  - Phone Collection
  - SMS Verification
  - OTP Entry
  - Signup Flow
  - Post-Signup Phone Binding
  - 2FA / Security
  - Recovery Flow
- صفحة إعدادات
- نتائج بجدول + بطاقات
- صفحة تفاصيل
- اختبار للمواقع المملوكة فقط عبر allowlist

## تشغيل محلي
```bash
pip install -r requirements.txt
python app.py
```

## على Render
Build Command:
```bash
pip install -r requirements.txt
```

Start Command:
```bash
python app.py
```

إذا أردت دعم Playwright على Render:
```bash
pip install -r requirements.txt && python -m playwright install chromium
```
