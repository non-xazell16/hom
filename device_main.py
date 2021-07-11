# 20210710################################################
# 水くれミント用RaspberryPiのクライアント
# AWS IoT Core へ MQTT で接続し指定時間置きにメッセージ送信
###########################################################
import argparse
import json
import logging
import os
import signal
import sys
import time
import traceback
from datetime import datetime

import board
import digitalio
from PIL import Image, ImageDraw, ImageFont
import adafruit_ssd1306


from awscrt import io, mqtt
from awsiot import iotshadow, mqtt_connection_builder
from grovepi import analogRead


# 定数定義 ############################################
BASE_TOPIC = "data/"

# Shadowプロパティ初期値
DEFAULT_WAIT_TIME =1800
DEFAULT_STATE_TIME =''
DEFAULT_MOISTER =0

# Shadow用キー名
SHADOW_MOISTUER_KEY="moistuer"
SHADOW_SUTATE_TIME_KEY="state_time"
SHADOW_WAIT_TIME_KEY = "wait_time"

KEEP_ALIVE = 300    # タイムアウトまで
SENSER =0           # GrobePiアナログセンサー接続位置


# 変数 ############################################
# 接続用object
mqtt_connection = None
shadow_client = None
device_name = None

# Shadowプロパティ情報保持用
wait_time = DEFAULT_WAIT_TIME
state_time = DEFAULT_STATE_TIME
moistuer = DEFAULT_MOISTER

# ログ用
logger = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)
logger.setLevel(logging.INFO)
logging.basicConfig()

# 引数のチェックと取得、設定
def arg_check():
    """
        起動時の引数とヘルプを定義
        python3 device_main.py --device_name nonchan-20210704 --endpoint a6jwuuv50jxiy-ats.iot.ap-northeast-1.amazonaws.com
    """
    logging.debug("start: arg_check")
    parser = argparse.ArgumentParser()
    # 必須　AWS IOTのモノの名前
    parser.add_argument("--device_name", required=True,
                        help="[Must], AWS IoT Core Thing Name")
    # 必須　AWS IOTのエンドポイント
    parser.add_argument("--endpoint", required=True,
                        help="[Must], AWS IoT endpoint URI")
    # 任意　ルート証明書（ルート認証局の公開鍵）
    parser.add_argument("--root_ca", required=False,
                        help="AWS IoT Core root ca file name with path")
    # 任意　証明書
    parser.add_argument("--cert", required=False,
                        help="device cert file name with path")
    # 任意　証明書
    parser.add_argument("--private", required=False,
                        help="private cert key file name with path")
    # 任意　ログレベル
    parser.add_argument('--verbosity', choices=[x.name for x in io.LogLevel],
                        default=io.LogLevel.NoLogs.name, help='Logging level')

    # パラメータ取得
    args = parser.parse_args()

    log_level = getattr(io.LogLevel, args.verbosity, "error")
    io.init_logging(log_level, 'stderr')
    loglevel_map = [
        logging.INFO, logging.INFO, logging.INFO,
        logging.INFO, logging.INFO, logging.DEBUG,
        logging.DEBUG]
    logger.setLevel(loglevel_map[log_level])
    logging.basicConfig()

    # デフォルト証明書探す
    cert_list = find_certs_file()
    # 引数であればそっちの証明書優先
    if args.root_ca is not None:
        cert_list[0] = args.root_ca
    if args.private is not None:
        cert_list[1] = args.private
    if args.cert is not None:
        cert_list[2] = args.cert

    logging.debug(cert_list)
    # 証明書ファイルの存在チェック
    file_exist_check(cert_list)

    # 接続情報返却
    init_dict = {
        "device_name": args.device_name,
        "endpoint": args.endpoint,
        "certs": cert_list
    }
    return init_dict


# ファイルの存在チェック
def file_exist_check(cert_list):
    for file in cert_list:
        if not os.path.exists(file):
            # if file not found, raise
            logger.error("cert file not found:%s", file)
            raise RuntimeError("file_not_exists")

# このファイルと同じ階層のcertsディレクトリの証明書探す。
def find_certs_file():
    """
     ./certs 

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

# モニター表示用処理
def moniter_view(text):

    # Load default font.
    font = ImageFont.load_default()

    # Draw Some Text
    text = "Hello World!"
    (font_width, font_height) = font.getsize(text)
    draw.text(
        (oled.width // 2 - font_width // 2, oled.height // 2 - font_height // 2),
        text,
        font=font,
        fill=255,
    )

    # Display image
    oled.image(image)
    oled.show()

# 顔文字判定
def mint_check(moistuer):
    
    if moistuer > 500 :
        moniter_view("٩(ˊᗜˋ*)و")
    elif moistuer > 300 :
        moniter_view("(๑`·ᴗ·´๑)")
    elif moistuer < 280 :
        moniter_view("(´·ω·`)")
    elif moistuer < 250 :
        moniter_view("(´._.`)")
    else:
        moniter_view("ヽ(`Д´)ﾉ")

# shadowの変更指示があった時
def on_shadow_delta_updated(delta):
    """
    callback for shadow delta update
    https://docs.aws.amazon.com/ja_jp/iot/latest/developerguide/device-shadow-mqtt.html#update-delta-pub-sub-topic

    Parameters
    ----------
    delta: iotshadow.ShadowDeltaUpdatedEvent
    """
    global wait_time, state_time, moistuer
    try:
        # 待ち時間の変更
        if delta.state and (SHADOW_WAIT_TIME_KEY in delta.state):    
            wait_val = DEFAULT_WAIT_TIME if delta.state[SHADOW_WAIT_TIME_KEY] is None else delta.state[SHADOW_WAIT_TIME_KEY]
            wait_time = wait_val
        # センサー取得指示
        if delta.state and (SHADOW_SUTATE_TIME_KEY in delta.state):
            state_val = DEFAULT_STATE_TIME if delta.state[SHADOW_SUTATE_TIME_KEY] is None else delta.state[SHADOW_SUTATE_TIME_KEY]
            moistuer = analogRead(SENSER)
            mint_check(moistuer)
            state_time = state_val

        change_shadow_value(wait_time,state_time,moistuer)

    except Exception as e:
        exit_sample(e)


def on_get_shadow_accepted(response):
    """
    callback for get shadow accepted
    https://docs.aws.amazon.com/ja_jp/iot/latest/developerguide/device-shadow-mqtt.html#get-accepted-pub-sub-topic

    Parameters
    ----------
    response: iotshadow.GetShadowResponse
    """
    global wait_time
    global state_time
    global moistuer
    try:
        logger.info("Finished getting initial shadow state.")

        if response.state:
            wait_val = response.state.desired.get(SHADOW_WAIT_TIME_KEY)
            state_val = response.state.desired.get(SHADOW_SUTATE_TIME_KEY)

            if response.state.delta:
                if wait_val or state_val:
                    wait_time = wait_val if wait_val else wait_time
                    state_time = state_val if state_val else state_time
                    change_shadow_value(wait_time,state_time,moistuer)
                    return
            elif response.state.desired:
                if state_val or wait_val:
                    wait_time = wait_val if wait_val else wait_time
                    state_time = state_val if state_val else state_time
                    if not response.state.reported:
                        change_shadow_value(wait_time,state_time,moistuer)


            elif response.state.reported:
                if wait_val:
                    wait_time = wait_val
                if state_val:
                    state_time = state_val

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
        change_shadow_value(DEFAULT_WAIT_TIME,DEFAULT_STATE_TIME,DEFAULT_MOISTER)
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

# Update shadow reported state
def change_shadow_value(wait,state,moistuer):
    
    logger.info("Updating reported shadow to...")
    new_state = iotshadow.ShadowState(
        reported={SHADOW_WAIT_TIME_KEY: wait,SHADOW_SUTATE_TIME_KEY: state,SHADOW_MOISTUER_KEY: moistuer}
    )
    request = iotshadow.UpdateShadowRequest(
        thing_name=device_name,
        state=new_state
    )
    future = shadow_client.publish_update_shadow(request, mqtt.QoS.AT_LEAST_ONCE)
    future.add_done_callback(on_publish_update_shadow)

# Un subscribe Shadow get events
def unsubscribe_get_shadow_events():

    logger.info("un subscribe from get shadow events")
    shadow_client.unsubscribe("$aws/things/{}/shadow/get/accepted".format(device_name))
    shadow_client.unsubscribe("$aws/things/{}/shadow/get/rejected".format(device_name))

# メイン処理
def device_main():
    """
    main loop for dummy device
    """
    global device_name, mqtt_connection, shadow_client,moistuer,wait_time

    # 引数整理、接続情報取得
    init_info = arg_check()
    # 接続情報を設定
    device_name = init_info['device_name']
    iot_endpoint = init_info['endpoint']
    rootca_file = init_info['certs'][0]
    private_key_file = init_info['certs'][1]
    certificate_file = init_info['certs'][2]

    # log出力
    logger.info("device_name: %s", device_name)
    logger.info("endpoint: %s", iot_endpoint)
    logger.info("rootca cert: %s", rootca_file)
    logger.info("private key: %s", private_key_file)
    logger.info("certificate: %s", certificate_file)

    # ソケット通信の為のおまじない
    event_loop_group = io.EventLoopGroup(1)
    host_resolver = io.DefaultHostResolver(event_loop_group)
    # ソケット通信アクティビティを処理する共通ランタイムオブジェクト
    client_bootstrap = io.ClientBootstrap(event_loop_group, host_resolver)

    # MQTT プロトコルを使用して AWS IoT Core との接続を確立
    mqtt_connection = mqtt_connection_builder.mtls_from_path(
        endpoint=iot_endpoint,
        cert_filepath=certificate_file,
        pri_key_filepath=private_key_file,
        client_bootstrap=client_bootstrap,
        ca_filepath=rootca_file,
        client_id=device_name,
        clean_session=False,
        keep_alive_secs=KEEP_ALIVE)

    # コネクション確率
    connected_future = mqtt_connection.connect()
    # shadowクライアント作成
    shadow_client = iotshadow.IotShadowClient(mqtt_connection)
    connected_future.result()

    print("Check latest Shadow status")
    # 受信
    get_accepted_subscribed_future, _ = shadow_client.subscribe_to_get_shadow_accepted(
        request=iotshadow.GetShadowSubscriptionRequest(device_name),
        qos=mqtt.QoS.AT_LEAST_ONCE,
        callback=on_get_shadow_accepted)

    # 受信が成功するのを待つ
    get_accepted_subscribed_future.result()

    # 送信
    publish_get_future = shadow_client.publish_get_shadow(
        request=iotshadow.GetShadowRequest(device_name),
        qos=mqtt.QoS.AT_LEAST_ONCE)

    # 送信成功することを確認します
    publish_get_future.result()

    # Shadowの状態と指示の差分チェック
    logger.info("Subscribing to Shadow Delta events...")
    delta_subscribed_future, _ = shadow_client.subscribe_to_shadow_delta_updated_events(
        request=iotshadow.ShadowDeltaUpdatedSubscriptionRequest(device_name),
        qos=mqtt.QoS.AT_LEAST_ONCE,
        callback=on_shadow_delta_updated)

    delta_subscribed_future.result()

    # Start sending dummy data
    topic = BASE_TOPIC + device_name
    logging.info("topic: %s", topic)
   
    while True:
        now = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        # センサーで値取得
        moistuer = analogRead(SENSER)
        # 画面表示
        mint_check(moistuer)

        payload = {"DEVICE_NAME": device_name, "TIMESTAMP": now, "MOISTUER": int(moistuer)}
        logger.debug("  payload: %s", payload)
        # MQTTでIotにパブリッシュ
        mqtt_connection.publish(
            topic=topic,
            payload=json.dumps(payload),
            qos=mqtt.QoS.AT_LEAST_ONCE)
        # 指定時間毎に送信するため
        time.sleep(int(wait_time))


# Contlorl+Cで停止するための設定
def exit_sample(msg_or_exception):
    if isinstance(msg_or_exception, Exception):
        logger.error("Exiting sample due to exception.")
        traceback.print_exception(msg_or_exception.__class__, msg_or_exception, sys.exc_info()[2])
    else:
        logger.info("Exiting: %s", msg_or_exception)

    if not mqtt_connection:
        logger.info("Disconnecting...")
        mqtt_connection.disconnect()
    sys.exit(0)

# Contlorl+Cで停止するための設定
def exit_handler(_signal, frame):

    exit_sample(" Key abort")



if __name__ == "__main__":
    # Contlorl+Cで停止するための設定
    signal.signal(signal.SIGINT, exit_handler)
    # モニタ
    moniter_view("Hello World!")
    # メイン処理
    device_main()


##モニター初期処理################################################################
# Define the Reset Pin
oled_reset = digitalio.DigitalInOut(board.D4)

# モニターサイズ（128×64）
WIDTH = 128
HEIGHT = 64
BORDER = 2

# Use for I2C.
i2c = board.I2C()
oled = adafruit_ssd1306.SSD1306_I2C(WIDTH, HEIGHT, i2c, addr=0x3C, reset=oled_reset)

# Clear display.
oled.fill(0)
oled.show()

# Create blank image for drawing.
# Make sure to create image with mode '1' for 1-bit color.
image = Image.new("1", (oled.width, oled.height))

# Get drawing object to draw on image.
draw = ImageDraw.Draw(image)

# Draw a white background
draw.rectangle((0, 0, oled.width, oled.height), outline=255, fill=255)

# Draw a smaller inner rectangle
draw.rectangle(
    (BORDER, BORDER, oled.width - BORDER - 1, oled.height - BORDER - 1),
    outline=0,
    fill=0,
)


########################################################################################