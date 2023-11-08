# “HeadBook” Example Project (INF226, 2023)

* Flask docs: https://flask.palletsprojects.com/en/3.0.x/
* Flask login docs: https://flask-login.readthedocs.io/en/latest/
* Using "Log in with *social network*": https://python-social-auth.readthedocs.io/en/latest/configuration/flask.html

## To Use

### Set up virtual environment and install dependencies

Use the [`venv`](https://docs.python.org/3/library/venv.html) command to create a virtual environment. E.g., on Unix (see web page for how to use it on Windows and with non-Bourne-like shells):

```sh
cd 226book
python -m venv .venv  # or possibly python3
. .venv/bin/activate  # yes there's a dot at the beginning of the line
pip install -r requirements.txt
```

You can exit the virtual environment with the command `deactivate`.

### Run it

```sh
flask -A headbook:app run --reload
```
# Task 2a

We can make a fake user by SQL injection at the login window. 

In the field for inputing username we will instead of typing in a username type:
';INSERT INTO users (username, password, info) VALUES ('fakeuser, 'password', '{}')--

This will trick the received form into thinking that the string end before ', and we can then use SQL queries to add code that will execute afterwards. 

In the password field we will just input an arbitrary combination of letters.
Having done this we can then log in to HeadBook with our prompted username and password that we injected earlier.

# Task 2b 

Injecting JavaScript code to 'about' field in profile with:
< img src="x" onerror="alert('u got hacked')" >

This script is a Cross Site Scripting (XSS) attack which will trigger an alert to the user if the profile injected with the code is interacted with.

The way the script works is that we make use of the image upload field to input a faulty source location, and then use our own onerror message to alert the user that they have been hacked.

With the use of Content Security Policy we will be able to prevent XSS attacks.
By visiting /users/me, the data received will be fetched by json and rendered to HTML, which makes it so that the server does not execute the attempted injected code.

# Task 2c
Appears that there are no requirements for password length, but there are requirements for having there be an input, and that the password entered in both input fields need to be equal.

In order for it to be more in line with standard security practices, it should demand a minimum character length, and combinations of digits, upper and lower case characters, and special characters.

It is not possible for a user to change another user's profile because of the implementation of my_profile() function where the user can only edit their own profile while logged in as themselves.

# Task 2d
The security key should be stored in a configuration file outside of project folder.
Bearer authentication should be implemented instead of basic base64 authentication, since bearer is based on access tokens that represents the user's identity without revealing their password.
To further prevent SQL injection attacks we could implement extra defense mechanisms like "least privilege" and "Allow-list input validation".
We could continue to better the access control, and assign roles to different users where only users with the appropriate role are able to perform certain actions.

# Copyright

* `unknown.png` – from [OpenMoji](https://openmoji.org/about/) ([Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/))
* `favicon.(png|ico)` – from [Game Icons](https://game-icons.net/1x1/skoll/knockout.html) ([CC BY 3.0](http://creativecommons.org/licenses/by/3.0/))
* `uhtml.js` – from [µHTML](https://github.com/WebReflection/uhtml) (Copyright (c) 2020, Andrea Giammarchi, [ISC License](https://opensource.org/license/isc-license-txt/))
* Base code by Anya
