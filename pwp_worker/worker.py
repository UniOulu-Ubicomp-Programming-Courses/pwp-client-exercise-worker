import hashlib
import math
import os
import ssl
import sys
import random
import time
import json
import pika
import requests
from datetime import datetime

class RabbitBackend(object):

    def __init__(self, broker, user, passwd):
        host, port = broker.split(":")
        self.host = host
        self.port = int(port)
        self.user = user
        self.passwd = passwd
        self.credentials = pika.PlainCredentials(self.user, self.passwd)

    def get_connection(self, vhost="/"):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return pika.BlockingConnection(pika.ConnectionParameters(
            self.host,
            self.port,
            vhost,
            self.credentials,
            ssl_options=pika.SSLOptions(context)
        ))


backend = RabbitBackend(
    broker=os.environ["PWP_RABBIT_URI"],
    user=os.environ["PWP_RABBIT_USER"],
    passwd=os.environ["PWP_RABBIT_PASSWD"]
)
api_key = os.environ["PWP_API_KEY"]


def generate_certificate(salt):
    message = os.environ["PWP_CERT_MSG"].encode("utf-8")
    h = hashlib.blake2b(salt=salt.encode("utf-8"))
    h.update(message)
    return h.hexdigest()

    
def send_notification(vhost, namespace, ctrl):
    connection = backend.get_connection(vhost)
    channel = connection.channel()
    channel.exchange_declare(
        exchange="notifications",
        exchange_type="fanout"
    )
    channel.basic_publish(
        exchange="notifications",
        routing_key="",
        body=json.dumps({
            "@namespaces": namespace,
            "@controls": {
                "pwpex:get-certificate": ctrl
            }
        })
    )
    connection.close()

def log_error(channel, message):
    channel.basic_publish(
        exchange="logs",
        routing_key="",
        body=json.dumps({
            "timestamp": datetime.now().isoformat(),
            "content": message
        })
    )
    
def handle_task(channel, method, properties, body):
    try:
        # try to parse data and return address from the message body
        task = json.loads(body)
        group = task["group"]
        salt = task["salt"]
        vhost = task["vhost"]
        ctrl = task["@controls"]["pwpex:create-certificate"]
        ns = task["@namespaces"]
        res_ctrl = task["@controls"]["pwpex:get-certificate"]
    except (KeyError, json.JSONDecodeError) as e:
        log_error(f"Task parse error: {e}")
    else:
        body = {}
        body["certificate"] = generate_certificate(salt)
        body["generated"] = datetime.now().isoformat()
        body["group"] = group
    
        # send the results back to the API
        with requests.Session() as session:
            resp = session.request(
                ctrl["method"],
                ctrl["href"],
                json=body,
                headers={
                    "Pwp-Api-Key": api_key
                },
                verify=False
            )
    
        if resp.status_code != 201:
            # log error 
            log_error(channel, f"Unable to send result")
        else:
            send_notification(vhost, ns, res_ctrl)
    finally:
        # acknowledge the task regardless of outcome
        print("Task handled")
        channel.basic_ack(delivery_tag=method.delivery_tag)

def main():
    connection = backend.get_connection()
    channel = connection.channel()
    channel.exchange_declare(
        exchange="logs",
        exchange_type="fanout"
    )
    channel.queue_declare(queue="tasks")
    channel.basic_consume(queue="tasks", on_message_callback=handle_task)
    print("Service started")
    channel.start_consuming()
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
