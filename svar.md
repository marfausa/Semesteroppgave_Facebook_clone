
# Task2a
We can make a fake user by SQL injection at the login window. 
In the field for inputing username we will instead of typing in a username type:
';INSERT INTO users (username, password, info) VALUES ('fakeuser, 'password', '{}')--
This will trick the received form into thinking that the string end before ', and we can then use SQL queries to add code that will execute afterwards. 
In the password field we will just input an arbitrary combination of letters.
Having done this we can then log in to HeadBook with our prompted username and password that we injected earlier.

# Task2b
Injecting JavaScript code to 'about' field in profile with:
<img src="x" onerror="alert('u got hacked')">
This script is a Cross Site Scripting (XSS) attack which will trigger an alert to the user if the profile injected with the code is interacted with.
The way the script works is that we make use of the image upload field to input a faulty source location, and then use our own onerror message to alert the user that they have been hacked.
With the use of Content Security Policy we will be able to prevent XSS attacks.
By visiting /users/me, the data received will be fetched by json and rendered to HTML, which makes it so that the server does not execute the attempted injected code.


# Task2c
Appears that there are no requirements for password length, but there are requirements for having there be an input, and that the password entered in both input fields need to be equal.
In order for it to be more in line with standard security practices, it should demand a minimum character length, and combinations of digits, upper and lower case characters, and special characters.
There is not possible for a user to change another user's profile because of the implementation of my_profile() function where the user can only edit their own profile while logged in as themselves.

# Task2d
The security key should be stored in a configuration file outside of project folder.
Bearer authentication should be implemented instead of basic base64 authentication, since bearer is based on access tokens that represents the user's identity without revealing their password.
To further prevent SQL injection attacks we could implement extra defense mechanisms like "least privilege" and "Allow-list input validation".
We could continue to better the access control, and assign roles to different users where only users with the appropriate role are able to perform certain actions.