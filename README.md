# CurlFlow Manager

منصة FastAPI لإدارة وتحويل طلبات cURL إلى تعريفات طلب آمنة، مع عرض Preview لكود Python، وإدارة تشغيلات HTTP مع مراقبة حية ولوجات أساسية.

## ما الذي تم بناؤه في هذه النسخة
- تسجيل/دخول بسيط بالجلسات
- تحليل cURL إلى Request Definition
- توليد Preview لكود Python باستخدام `httpx`
- حفظ السكربتات في قاعدة البيانات
- إدارة المدخلات الخاصة بكل سكربت
- تشغيلات عبر Celery + Redis
- Live Monitor عبر SSE
- تصنيف أخطاء أساسي
- اكتشاف challenge أساسي وتعليق المهمة بدل تجاوزها
- Approved Packages registry
- إعدادات مشتركة أولية

## حدود هذه النسخة
هذه نسخة MVP قوية كنقطة انطلاق، وليست المنتج النهائي بكل التفاصيل المتفق عليها. ستحتاج إلى تطوير إضافي في:
- التحليل المتقدم لـ cURL
- تقارير أوسع
- أدوار وصلاحيات أدق
- Alembic migrations الحقيقية
- تحسين إدارة التوقف/الاستئناف
- اختبار E2E أوسع

## تشغيل محلي
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL=sqlite:///./curlflow.db
export REDIS_URL=redis://localhost:6379/0
./scripts/migrate.sh
uvicorn app.main:app --reload
```

في نافذة ثانية:
```bash
celery -A app.tasks.celery_app.celery_app worker --loglevel=INFO
```
