# Passwault

This is Passwault. A command-line tool where you can save passwords to databases, generate secure passwords and encode your password into an image.

## Why?

I needed a better way to manage my passwords without relying on third-party software, so I'm developing Passwault. This tool saves passwords in a local database, with plans to expand to secure cloud storage. Additionally, it integrates a steganography project to encode passwords into images by embedding them in the image bytes for enhanced security

## 🚀 Quick Start

1. Install the dependencies with poetry
    ```bash
    $ poetry install
    $ poetry shell
    ```
2. Run the module help menu
    ```bash
    $ python3 -m passwault --help
    ```
    
    it should show something like
    ```
    usage: __main__.py [-h] {register,login,logout,generate,save_password,load_password,imagepass} ...

    ---- PASSWAULT: a password manager

    positional arguments:
    {register,login,logout,generate,save_password,load_password,imagepass}
                            Available commands
        register            register a new user
        login               login into the system
        logout              logout from the system
        generate            Generates a new password
        save_password       Saves a new password to database
        load_password       Gets the password from database
        imagepass           Encode or Decode passwords in Image

    options:
    -h, --help            show this help message and exit
    ```

## Contributing