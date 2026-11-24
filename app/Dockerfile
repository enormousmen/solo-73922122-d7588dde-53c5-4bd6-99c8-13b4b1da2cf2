FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /srv/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080
EXPOSE 9999/udp
# 诊断工具，使用 Flask 内置服务器（threaded）即可；UDP 接收/超时清扫在独立线程中运行
CMD ["python", "app.py"]
