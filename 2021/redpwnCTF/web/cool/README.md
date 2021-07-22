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

A user is created on startup called `ginkoid`, with it's password being the flag. Using the SQL injection in the password field, we can perform a blind injection to pull the user's credentials from the webserver.

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

### Exploitation - Local

Using my CVE Hunting setup, I ran the provided source code with a few [modifications](https://raw.githubusercontent.com/0xgrey/CTF-Writeups/main/2021/redpwnCTF/web/cool/modified_app.py) to the code for simplicity.

First, I added `db/db.sqlite3` to the app's directory to prevent runtime errors. Then, I ran the modified application on VSCode with debug mode enabled to view the SQL queries being executed.



### Exploitation - Remote
