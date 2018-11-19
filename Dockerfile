FROM python:3

WORKDIR /app

COPY . .
RUN pip install --no-cache-dir .

ENTRYPOINT ["trustymail"]
CMD ["--help"]
