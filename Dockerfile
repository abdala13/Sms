FROM python:3.11-slim

WORKDIR /app

# تحسين pip
RUN pip install --upgrade pip

# نسخ المتطلبات أولًا (cache optimization)
COPY requirements.txt .

# تثبيت الحزم
RUN pip install --no-cache-dir -r requirements.txt

# نسخ المشروع
COPY . .

# تشغيل السيرفر
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "10000"]
