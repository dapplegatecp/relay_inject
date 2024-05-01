FROM python:alpine3.19

RUN apk --no-cache update
RUN mkdir -p /app
RUN pip3 install scapy

WORKDIR /app

COPY ./app.py /app/app.py

EXPOSE 67/udp

CMD ["python3", "app.py"]

