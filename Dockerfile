FROM python:3.7-alpine
VOLUME /root/templates /root/.aws
COPY secrets_manager.py /root/secrets_manager.py
RUN pip3 install boto3 jinja2
ENTRYPOINT ["python3", "/root/secrets_manager.py"]
