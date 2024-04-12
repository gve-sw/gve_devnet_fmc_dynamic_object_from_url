FROM python:3.11-slim-buster
WORKDIR /app
COPY ./requirements.txt /app
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "./update_object_from_url.py"]