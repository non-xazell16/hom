# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from __future__ import absolute_import
from __future__ import print_function

import argparse
import json
import logging
import os
import random
import signal
import sys
import time
import traceback
from datetime import datetime

from awscrt import io, mqtt
from awsiot import iotshadow, mqtt_connection_builder

from grovepi import *
#from get_data import DHT

# - Overview -
# This sample shows 1) how to connect AWS IoT Core. 2) How to use AWS IoT
# Device Shadow

BASE_TOPIC = "data/"
DEFAULT_WAIT_TIME =600
SHADOW_MOISTUER_KEY="moistuer"
SHADOW_WAIT_TIME_KEY = "wait_time"
KEEP_ALIVE = 300

mqtt_connection = None
shadow_client = None
wait_time = DEFAULT_WAIT_TIME
device_name = None

logger = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)
logger.setLevel(logging.INFO)
logging.basicConfig()


def arg_check():
    """
    argument check
    """
/SHADOW_WAIT_TIME_KEY
    except Exception as e:
        exit_sample(e)


def on_update_shadow_accepted(response):
    """
    callback for shadow update accepted
    https://docs.aws.amazon.com/ja_jp/iot/latest/developerguide/device-shadow-mqtt.html#update-accepted-pub-sub-topic

    Parameters
    ----------
    response: iotshadow.UpdateShadowResponse
    """
    logging.info("on_update_shadow_accepted")
    logging.debug(response)


def on_update_shadow_rejected(error):
    """
    callback for shadow update rejected
    https://docs.aws.amazon.com/ja_jp/iot/latest/developerguide/device-shadow-mqtt.html#update-rejected-pub-sub-topic

    Parameters
    ----------
    error: iotshadow.ErrorResponse
    """
    logging.error("on_update_shadow_rejected")
    logging.error("  Update request was rejected. code:%s message:'%s'",
                  error.code, error.message)


def on_get_shadow_accepted(response):
    """
    callback for get shadow accepted
    https://docs.aws.amazon.com/ja_jp/iot/latest/developerguide/device-shadow-mqtt.html#get-accepted-pub-sub-topic

    Parameters
    ----------
    response: iotshadow.GetShadowResponse
    """
    global wait_time
    try:
        logger.info("Finished getting initial shadow state.")

        if response.state:
            if response.state.delta:
                value = response.state.delta.get(SHADOW_WAIT_TIME_KEY)
                if value:
                    logger.info("  Shadow contains delta wait_time: '%s'", value)
                    logger.info("  Update local wait_time: '%s' to '%s'", wait_time, value)
                    wait_time = value
                    change_shadow_value(wait_time)
                    return
            elif response.state.desired:
                desired_value = response.state.desired.get(SHADOW_WAIT_TIME_KEY)
                if desired_value:
                    wait_time = desired_value
                    logger.info("  Shadow contains desired wait_time '%s'", wait_time)
                    if not response.state.reported:
                        change_shadow_value(desired_value)
            elif response.state.reported:
                reported_value = response.state.reported.get(SHADOW_WAIT_TIME_KEY)
/SHADOW_WAIT_TIME_KEY
            error.code, error.message))


def on_publish_update_shadow(future):
    """
    callback for publish shadow update
    https://docs.aws.amazon.com/ja_jp/iot/latest/developerguide/device-shadow-mqtt.html#update-pub-sub-topic

    Parameters
    ----------
    future: Future
    """
    try:
        future.result()
        logger.info("Update request published.")
    except Exception as e:
        logger.error("Failed to publish update request.")
        exit_sample(e)


def change_shadow_value(value):
    """
    Update shadow reported state

    Parameters
    ----------
    value: int
    """
    logger.info("Updating reported shadow to...")
    new_state = iotshadow.ShadowState(
        reported={SHADOW_WAIT_TIME_KEY: value}
    )
    request = iotshadow.UpdateShadowRequest(
        thing_name=device_name,
        state=new_state
    )
    future = shadow_client.publish_update_shadow(request, mqtt.QoS.AT_LEAST_ONCE)
    future.add_done_callback(on_publish_update_shadow)


def unsubscribe_get_shadow_events():
    """
    Un subscribe Shadow get events
    """
    logger.info("un subscribe from get shadow events")
    shadow_client.unsubscribe("$aws/things/{}/shadow/get/accepted".format(device_name))
    shadow_client.unsubscribe("$aws/things/{}/shadow/get/rejected".format(device_name))


def device_main():
    """
    main loop for dummy device
    """
    global device_name, mqtt_connection, shadow_client

    ondo = 8

    #print(dht(ondo,0))

    sensor =0

    #print(dht(ondo,0))
"device_main.py" 452 lines, 898964 characters written

def exit_handler(_signal, frame):
    """
    Exit sample
    """
    exit_sample(" Key abort")


if __name__ == "__main__":

    ondo = 8

    #print(dht(ondo,0))
    signal.signal(signal.SIGINT, exit_handler)

    device_main()
pi@raspberrypi:~/dummy_client $ ^C
pi@raspberrypi:~/dummy_client $ python3 device_main.py --device_name nonchan-20210704 --endpoint a6jwuuv50jxiy-ats.iot.ap-northeast-1.amazonaws.com
device_name: nonchan-20210704
endpoint: a6jwuuv50jxiy-ats.iot.ap-northeast-1.amazonaws.com
rootca cert: ./certs/AmazonRootCA1.pem
private key: ./certs/dd08fa9977dcf64cf9dc4baa825d3728dd9c8f4d4efb6fc808f99729bdd8d9e9-private.pem.key
certificate: ./certs/dd08fa9977dcf64cf9dc4baa825d3728dd9c8f4d4efb6fc808f99729bdd8d9e9-certificate.pem.crt
Check latest Shadow status
Subscribing to Shadow Delta events...
Finished getting initial shadow state.
  Shadow contains reported wait_time: '5'
un subscribe from get shadow events
Subscribing to Shadow Update responses...
topic: data/nonchan-20210704
^CExiting:  Key abort
pi@raspberrypi:~/dummy_client $ ls
__pycache__  certs  device_main.py  device_main_ondo.py  get_data.py  grove_moisture_sensor-ja.py  log.log  set_display.py  test_ondo.py
pi@raspberrypi:~/dummy_client $ python3 device_main.py --device_name nonchan-20210704 --endpoint a6jwuuv50jxiy-ats.iot.ap-northeast-1.amazonaws.com
device_name: nonchan-20210704
endpoint: a6jwuuv50jxiy-ats.iot.ap-northeast-1.amazonaws.com
rootca cert: ./certs/AmazonRootCA1.pem
private key: ./certs/dd08fa9977dcf64cf9dc4baa825d3728dd9c8f4d4efb6fc808f99729bdd8d9e9-private.pem.key
certificate: ./certs/dd08fa9977dcf64cf9dc4baa825d3728dd9c8f4d4efb6fc808f99729bdd8d9e9-certificate.pem.crt
Check latest Shadow status
Subscribing to Shadow Delta events...
Finished getting initial shadow state.
  Shadow contains reported wait_time: '5'
un subscribe from get shadow events
Subscribing to Shadow Update responses...
topic: data/nonchan-20210704
^CExiting:  Key abort
pi@raspberrypi:~/dummy_client $ vi device_main.py
pi@raspberrypi:~/dummy_client $ python3 device_main.py --device_name nonchan-20210704 --endpoint a6jwuuv50jxiy-ats.iot.ap-northeast-1.amazonaws.com
device_name: nonchan-20210704
endpoint: a6jwuuv50jxiy-ats.iot.ap-northeast-1.amazonaws.com
rootca cert: ./certs/AmazonRootCA1.pem
private key: ./certs/dd08fa9977dcf64cf9dc4baa825d3728dd9c8f4d4efb6fc808f99729bdd8d9e9-private.pem.key
certificate: ./certs/dd08fa9977dcf64cf9dc4baa825d3728dd9c8f4d4efb6fc808f99729bdd8d9e9-certificate.pem.crt
Check latest Shadow status
Subscribing to Shadow Delta events...
Finished getting initial shadow state.
  Shadow contains reported wait_time: '5'
un subscribe from get shadow events
Subscribing to Shadow Update responses...
topic: data/nonchan-20210704
^CExiting:  Key abort
pi@raspberrypi:~/dummy_client $ vi device_main.py
pi@raspberrypi:~/dummy_client $ car device_main.py
-bash: car: コマンドが見つかりません
pi@raspberrypi:~/dummy_client $ cat device_main.py
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from __future__ import absolute_import
from __future__ import print_function

import argparse
import json
import logging
import os
import random
import signal
import sys
import time
import traceback
from datetime import datetime

from awscrt import io, mqtt
from awsiot import iotshadow, mqtt_connection_builder

from grovepi import *
#from get_data import DHT

# - Overview -
# This sample shows 1) how to connect AWS IoT Core. 2) How to use AWS IoT
# Device Shadow

BASE_TOPIC = "data/"
DEFAULT_WAIT_TIME =600
SHADOW_MOISTUER_KEY="moistuer"
SHADOW_WAIT_TIME_KEY = "wait_time"
KEEP_ALIVE = 300

mqtt_connection = None
shadow_client = None
wait_time = DEFAULT_WAIT_TIME
device_name = None

logger = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)
logger.setLevel(logging.INFO)
logging.basicConfig()


def arg_check():
    """
    argument check
    """

    logging.debug("start: arg_check")
    parser = argparse.ArgumentParser()
    parser.add_argument("--device_name", required=True,
                        help="[Must], AWS IoT Core Thing Name")
    parser.add_argument("--endpoint", required=True,
                        help="[Must], AWS IoT endpoint URI")
    parser.add_argument("--root_ca", required=False,
                        help="AWS IoT Core root ca file name with path")
    parser.add_argument("--cert", required=False,
                        help="device cert file name with path")
    parser.add_argument("--private", required=False,
                        help="private cert key file name with path")
    parser.add_argument('--verbosity', choices=[x.name for x in io.LogLevel],
                        default=io.LogLevel.NoLogs.name, help='Logging level')

    args = parser.parse_args()

    log_level = getattr(io.LogLevel, args.verbosity, "error")
    io.init_logging(log_level, 'stderr')
    loglevel_map = [
        logging.INFO, logging.INFO, logging.INFO,
        logging.INFO, logging.INFO, logging.DEBUG,
        logging.DEBUG]
    logger.setLevel(loglevel_map[log_level])
    logging.basicConfig()

    cert_list = find_certs_file()
    if args.root_ca is not None:
        cert_list[0] = args.root_ca
    if args.private is not None:
        cert_list[1] = args.private
    if args.cert is not None:
        cert_list[2] = args.cert

    logging.debug(cert_list)
    file_exist_check(cert_list)

    init_dict = {
        "device_name": args.device_name,
        "endpoint": args.endpoint,
        "certs": cert_list
    }
    return init_dict


def file_exist_check(cert_list):
    """
    Check the files exists
    all certs must placed in ./certs directory

    Parameters
    ----------
    cert_list: Array
    """

    for file in cert_list:
        if not os.path.exists(file):
            # if file not found, raise
            logger.error("cert file not found:%s", file)
            raise RuntimeError("file_not_exists")


def find_certs_file():
    """
    Find the certificates file from ./certs directory

    Returns
    ----------
    file_list: Array
        0: Root CA Cert, 1: private key, 2: certificate
    """

    certs_dir = "./certs"
    file_list = ["AmazonRootCA1.pem", "private.pem", "certificate.crt"]
    for _, _, names in os.walk(certs_dir):
        for file in names:
            if "AmazonRootCA1.pem" in file:
                file_list[0] = certs_dir + "/" + file
            elif "private" in file:
                file_list[1] = certs_dir + "/" + file
            elif "certificate" in file:
                file_list[2] = certs_dir + "/" + file

    return file_list


def on_shadow_delta_updated(delta):
    """
    callback for shadow delta update
    https://docs.aws.amazon.com/ja_jp/iot/latest/developerguide/device-shadow-mqtt.html#update-delta-pub-sub-topic

    Parameters
    ----------
    delta: iotshadow.ShadowDeltaUpdatedEvent
    """
    global wait_time
    try:
        logger.info("Received shadow delta event.")
        if delta.state and (SHADOW_WAIT_TIME_KEY in delta.state):
            value = delta.state[SHADOW_WAIT_TIME_KEY]
            if value is None:
                logger.info("  Delta reports that '%s' was deleted. Resetting defaults...", SHADOW_WAIT_TIME_KEY)
                change_shadow_value(DEFAULT_WAIT_TIME)
                return
            else:
                logger.info("  Delta reports that desired value is '%s'. Changing local value from '%s' to '%s'", value,
                            wait_time, value)
                wait_time = value
                change_shadow_value(wait_time)

    except Exception as e:
        exit_sample(e)


def on_update_shadow_accepted(response):
    """
    callback for shadow update accepted
    https://docs.aws.amazon.com/ja_jp/iot/latest/developerguide/device-shadow-mqtt.html#update-accepted-pub-sub-topic

    Parameters
    ----------
    response: iotshadow.UpdateShadowResponse
    """
    logging.info("on_update_shadow_accepted")
    logging.debug(response)


def on_update_shadow_rejected(error):
    """
    callback for shadow update rejected
    https://docs.aws.amazon.com/ja_jp/iot/latest/developerguide/device-shadow-mqtt.html#update-rejected-pub-sub-topic

    Parameters
    ----------
    error: iotshadow.ErrorResponse
    """
    logging.error("on_update_shadow_rejected")
    logging.error("  Update request was rejected. code:%s message:'%s'",
                  error.code, error.message)


def on_get_shadow_accepted(response):
    """
    callback for get shadow accepted
    https://docs.aws.amazon.com/ja_jp/iot/latest/developerguide/device-shadow-mqtt.html#get-accepted-pub-sub-topic

    Parameters
    ----------
    response: iotshadow.GetShadowResponse
    """
    global wait_time
    try:
        logger.info("Finished getting initial shadow state.")

        if response.state:
            if response.state.delta:
                value = response.state.delta.get(SHADOW_WAIT_TIME_KEY)
                if value:
                    logger.info("  Shadow contains delta wait_time: '%s'", value)
                    logger.info("  Update local wait_time: '%s' to '%s'", wait_time, value)
                    wait_time = value
                    change_shadow_value(wait_time)
                    return
            elif response.state.desired:
                desired_value = response.state.desired.get(SHADOW_WAIT_TIME_KEY)
                if desired_value:
                    wait_time = desired_value
                    logger.info("  Shadow contains desired wait_time '%s'", wait_time)
                    if not response.state.reported:
                        change_shadow_value(desired_value)
            elif response.state.reported:
                reported_value = response.state.reported.get(SHADOW_WAIT_TIME_KEY)
                if reported_value:
                    wait_time = reported_value
                    logger.info("  Shadow contains reported wait_time: '%s'", wait_time)

        unsubscribe_get_shadow_events()
    except Exception as e:
        exit_sample(e)


def on_get_shadow_rejected(error):
    """
    callback for get shadow rejected
    https://docs.aws.amazon.com/ja_jp/iot/latest/developerguide/device-shadow-mqtt.html#get-rejected-pub-sub-topic

    Parameters
    ----------
    error: iotshadow.ErrorResponse
    """
    if error.code == 404:
        logger.info("Thing has no shadow document. Creating with defaults...")
        unsubscribe_get_shadow_events()
        change_shadow_value(DEFAULT_WAIT_TIME)
    else:
        exit_sample("Get request was rejected. code:{} message:'{}'".format(
            error.code, error.message))


def on_publish_update_shadow(future):
    """
    callback for publish shadow update
    https://docs.aws.amazon.com/ja_jp/iot/latest/developerguide/device-shadow-mqtt.html#update-pub-sub-topic

    Parameters
    ----------
    future: Future
    """
    try:
        future.result()
        logger.info("Update request published.")
    except Exception as e:
        logger.error("Failed to publish update request.")
        exit_sample(e)


def change_shadow_value(value):
    """
    Update shadow reported state

    Parameters
    ----------
    value: int
    """
    logger.info("Updating reported shadow to...")
    new_state = iotshadow.ShadowState(
        reported={SHADOW_WAIT_TIME_KEY: value}
    )
    request = iotshadow.UpdateShadowRequest(
        thing_name=device_name,
        state=new_state
    )
    future = shadow_client.publish_update_shadow(request, mqtt.QoS.AT_LEAST_ONCE)
    future.add_done_callback(on_publish_update_shadow)


def unsubscribe_get_shadow_events():
    """
    Un subscribe Shadow get events
    """
    logger.info("un subscribe from get shadow events")
    shadow_client.unsubscribe("$aws/things/{}/shadow/get/accepted".format(device_name))
    shadow_client.unsubscribe("$aws/things/{}/shadow/get/rejected".format(device_name))


def device_main():
    """
    main loop for dummy device
    """
    global device_name, mqtt_connection, shadow_client

    ondo = 8

    #print(dht(ondo,0))

    sensor =0

    #print(dht(ondo,0))
    init_info = arg_check()
    device_name = init_info['device_name']
    iot_endpoint = init_info['endpoint']
    rootca_file = init_info['certs'][0]
    private_key_file = init_info['certs'][1]
    certificate_file = init_info['certs'][2]

    logger.info("device_name: %s", device_name)
    logger.info("endpoint: %s", iot_endpoint)
    logger.info("rootca cert: %s", rootca_file)
    logger.info("private key: %s", private_key_file)
    logger.info("certificate: %s", certificate_file)

    # Spin up resources
    event_loop_group = io.EventLoopGroup(1)
    host_resolver = io.DefaultHostResolver(event_loop_group)
    client_bootstrap = io.ClientBootstrap(event_loop_group, host_resolver)

    mqtt_connection = mqtt_connection_builder.mtls_from_path(
        endpoint=iot_endpoint,
        cert_filepath=certificate_file,
        pri_key_filepath=private_key_file,
        client_bootstrap=client_bootstrap,
        ca_filepath=rootca_file,
        client_id=device_name,
        clean_session=False,
        keep_alive_secs=KEEP_ALIVE)

    connected_future = mqtt_connection.connect()
    shadow_client = iotshadow.IotShadowClient(mqtt_connection)
    connected_future.result()

    print("Check latest Shadow status")
    get_accepted_subscribed_future, _ = shadow_client.subscribe_to_get_shadow_accepted(
        request=iotshadow.GetShadowSubscriptionRequest(device_name),
        qos=mqtt.QoS.AT_LEAST_ONCE,
        callback=on_get_shadow_accepted)

    get_rejected_subscribed_future, _ = shadow_client.subscribe_to_get_shadow_rejected(
        request=iotshadow.GetShadowSubscriptionRequest(device_name),
        qos=mqtt.QoS.AT_LEAST_ONCE,
        callback=on_get_shadow_rejected)

    # Wait for subscriptions to succeed
    get_accepted_subscribed_future.result()
    get_rejected_subscribed_future.result()

    publish_get_future = shadow_client.publish_get_shadow(
        request=iotshadow.GetShadowRequest(device_name),
        qos=mqtt.QoS.AT_LEAST_ONCE)

    # Ensure that publish succeeds
    publish_get_future.result()

    logger.info("Subscribing to Shadow Delta events...")
    delta_subscribed_future, _ = shadow_client.subscribe_to_shadow_delta_updated_events(
        request=iotshadow.ShadowDeltaUpdatedSubscriptionRequest(device_name),
        qos=mqtt.QoS.AT_LEAST_ONCE,
        callback=on_shadow_delta_updated)

    # Wait for subscription to succeed
    delta_subscribed_future.result()

    logger.info("Subscribing to Shadow Update responses...")
    update_accepted_subscribed_future, _ = shadow_client.subscribe_to_update_shadow_accepted(
        request=iotshadow.UpdateShadowSubscriptionRequest(device_name),
        qos=mqtt.QoS.AT_LEAST_ONCE,
        callback=on_update_shadow_accepted)

    update_rejected_subscribed_future, _ = shadow_client.subscribe_to_update_shadow_rejected(
        request=iotshadow.UpdateShadowSubscriptionRequest(device_name),
        qos=mqtt.QoS.AT_LEAST_ONCE,
        callback=on_update_shadow_rejected)

    # Wait for subscriptions to succeed
    update_accepted_subscribed_future.result()
    update_rejected_subscribed_future.result()

    # Start sending dummy data
    topic = BASE_TOPIC + device_name
    logging.info("topic: %s", topic)
    while True:
        now = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
#        humi, temp = dht(ondo, 0)
        temp = analogRead(sensor)
        payload = {"DEVICE_NAME": device_name, "TIMESTAMP": now, "MOISTUER": int(temp)}
        logger.debug("  payload: %s", payload)

        mqtt_connection.publish(
            topic=topic,
            payload=json.dumps(payload),
            qos=mqtt.QoS.AT_LEAST_ONCE)

        time.sleep(600)


def exit_sample(msg_or_exception):
    """
    Exit sample with cleaning

    Parameters
    ----------
    msg_or_exception: str or Exception
    """
    if isinstance(msg_or_exception, Exception):
        logger.error("Exiting sample due to exception.")
        traceback.print_exception(msg_or_exception.__class__, msg_or_exception, sys.exc_info()[2])
    else:
        logger.info("Exiting: %s", msg_or_exception)

    if not mqtt_connection:
        logger.info("Disconnecting...")
        mqtt_connection.disconnect()
    sys.exit(0)


def exit_handler(_signal, frame):
    """
    Exit sample
    """
    exit_sample(" Key abort")


if __name__ == "__main__":

    ondo = 8

    #print(dht(ondo,0))
    signal.signal(signal.SIGINT, exit_handler)

    device_main()