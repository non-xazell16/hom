import signal
import sys
import time

import logging


logger = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)
logger.setLevel(logging.INFO)
logging.basicConfig()

def exit_sample(msg_or_exception):
    """
    Exit sample with cleaning

    Parameters
    ----------
    msg_or_exception: str or Exception
    """
    if isinstance(msg_or_exception, Exception):
        logger.error("Exiting sample due to exception.")
    else:
        logger.info("Exiting: %s", msg_or_exception)

    sys.exit(0)


def exit_handler(_signal, frame):
    """
    Exit sample
    """
    exit_sample(" Key abort")


if __name__ == "__main__":
    logger.info("Exiting: %s", "aa")
    #signal.signal(signal.SIGINT, exit_handler)
    while True:
        print("aaapopo")
        time.sleep(1)