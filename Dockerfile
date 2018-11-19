FROM python:3

WORKDIR /app

COPY requirements.txt requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN pip install --editable .

ENTRYPOINT ["trustymail"]
CMD ["--help"]
