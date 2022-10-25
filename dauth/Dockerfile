
FROM python:3.8-slim

WORKDIR /app
RUN pip install Flask Flask-SQLAlchemy PyCryptodome PyJWT PyOpenSSL akamai-edgeauth asn1 cachetools gunicorn
COPY . .

CMD ["gunicorn", "-b", "0.0.0.0:8000", "main:app"]
