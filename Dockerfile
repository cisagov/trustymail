FROM python:3

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip setuptools wheel

COPY requirements.txt .

COPY src/trustymail/ src/trustymail/

COPY README.md .

COPY requirements-dev.txt .

COPY setup.py .

RUN pip install --no-cache-dir --requirement requirements.txt

ENTRYPOINT ["trustymail"]
CMD ["--help"]
