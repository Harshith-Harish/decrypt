FROM python:3.9

ENV PYTHONUNBUFFERED True

ENV APP_HOME /app
WORK_DIR $APP_HOME
COPY . ./


RUN pip install -r requirements.txt
RUN apt-get update && apt-get install -y gnupg


CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 decryprtion_over_cloud_run:decryprtion_over_cloud_run