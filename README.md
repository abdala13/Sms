# Sentinel Verify Platform

منصة ويب جاهزة لـ Render لتحليل المواقع وروابط التطبيقات بحثًا عن مؤشرات التحقق بالهاتف وSMS/OTP، مع إمكانية تشغيل اختبار Playwright على مواقعك المسموح بها.

## المزايا
- فحص targets متعددة من textarea واحدة
- يدعم: sender / domain / url / Google Play link / direct APK link
- تحليل ويب: HTML + JS clues + crawling
- تحليل تطبيقات: Play metadata أو static APK inspection
- واجهة جميلة وعملية
- صفحة إعدادات لحفظ رقم الهاتف والدومينات المسموح اختبارها
- زر Test يظهر تلقائيًا للنتائج المؤهلة
- تخزين النتائج والاختبارات في SQLite

## تشغيل محلي
```bash
pip install -r requirements.txt
python app.py
```

ثم افتح:
```bash
http://127.0.0.1:10000
```

## Playwright
إذا أردت تفعيل الاختبارات:
```bash
playwright install chromium
```

## النشر على Render
1. ارفع الملفات إلى GitHub.
2. أنشئ Web Service جديد في Render.
3. سيقرأ Render ملف `render.yaml` تلقائيًا.
4. أضف متغيرات البيئة إن أردت:
   - `SECRET_KEY`
   - `PORT` (اختياري)

## ملاحظات
- زر الاختبار مخصص لنتائج الويب فقط.
- يجب إضافة الدومينات المسموح اختبارها من صفحة Settings.
- تحليل التطبيق هنا static/metadata فقط، بدون تشغيل التطبيق فعليًا.
