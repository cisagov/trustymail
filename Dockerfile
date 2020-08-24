FROM python:3

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip setuptools wheel

COPY requirements.txt .

RUN pip install --no-cache-dir --requirement requirements.txt

COPY . .

RUN pip install --editable .

ENTRYPOINT ["trustymail"]
CMD ["--help"]
