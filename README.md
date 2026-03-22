# CurlFlow Manager v3

منصة FastAPI لإدارة وتحويل طلبات cURL إلى تعريفات طلب آمنة، مع عرض Preview لكود Python، وإدارة تشغيلات HTTP مع مراقبة حية ولوجات وتقارير أقوى.

## إضافات v3
- استيراد سكربتات JSON من الواجهة
- Runtime Profiles أساسية وربطها بالسكريبت
- Queue Panel مستقلة لمراقبة التشغيلات النشطة والحديثة
- تحسين Filters في صفحة Logs
- تقارير آخر 7 أيام
- تحسين parser لدعم `-G`, cookies داخل header, وتجميع data flags
- تحديث بيانات السكربت بعد الإنشاء (اسم/وصف/وسوم/Profile)

## التشغيل المحلي
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL=sqlite:///./curlflow.db
export REDIS_URL=redis://localhost:6379/0
./scripts/migrate.sh
uvicorn app.main:app --reload
```

وفي نافذة ثانية:
```bash
celery -A app.tasks.celery_app.celery_app worker --loglevel=INFO
```

## ملاحظات
- التنفيذ ما زال يعتمد على Execution Engine آمن وليس على تشغيل كود Python نصي.
- Challenge detection موجود للتعليق والتسجيل فقط.
- Runtime Profiles في هذه النسخة أولية وتمهّد لتوسعات أكبر لاحقًا.
