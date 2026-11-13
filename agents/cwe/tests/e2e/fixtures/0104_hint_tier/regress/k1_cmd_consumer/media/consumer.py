import json

from kafka import KafkaConsumer

from media.convert import transcode


def run():
    consumer = KafkaConsumer("crates", bootstrap_servers="broker:9092")
    for record in consumer:
        event = json.loads(record.value)
        transcode(event["object_key"])
