FROM python:3.11-alpine

WORKDIR /app
COPY requirements.txt /app/
RUN pip install -r requirements.txt

COPY fenjing /app/fenjing
ENTRYPOINT ["python", "-m", "fenjing"]
