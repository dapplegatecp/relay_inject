FROM python:3.12

ARG DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get install -y \
    iproute2 \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app
RUN pip3 install scapy

WORKDIR /app

COPY ./app.py /app/app.py
COPY ./entrypoint.sh /app/entrypoint.sh

ENTRYPOINT [ "/app/entrypoint.sh" ]

CMD ["python3", "app.py"]
