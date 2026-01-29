# Messenger
My basic messenger system used to allow communication between people in school.

## Setup
To test or run this yourself, you need a few Python modules, run `pip install -r requirements.txt` when you clone or download as zip

Also, you need to create users.json with the contents of:
```
{
    "admin": {
        "password": "$pbkdf2-sha256$29000$9t6bc.4dQyjlvJcy5nzPGQ$FQ8jmn5Ik8Sergfu2/h./ncLtoYBkS82BvCDh1YiWXQ",
        "banned": false,
        "role": "admin"
    }
}
```
You can then sign in as the admin with password `iamadmin` to create yourself an admin account. You should add it as a normal account then change it in the json.
Then please delete the original admin account from the users file and if you want your own username to be admin just change what the placeholder account is.
