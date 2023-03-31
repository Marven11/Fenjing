FROM python:3.9

WORKDIR /app
COPY requirements.txt /app/
RUN pip install -r requirements.txt

COPY fenjing /app/fenjing
ENTRYPOINT ["python", "-m", "fenjing"]
