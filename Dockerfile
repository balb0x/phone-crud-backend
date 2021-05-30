FROM python:3.8
ENV DOCKER_RUNNING Yes
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app/ .

## WAIT SCRIPT. IT WAITS TO MONGO SERVICE TO BE AVAILABLE
ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.2.1/wait /wait
RUN chmod +x /wait

CMD /wait && python main.py

