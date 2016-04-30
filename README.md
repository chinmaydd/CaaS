# CaaS

Confidentiality as a service is an innovative paradigm for preserving privacy between a user and a cloud service provider(CSP).

We have implemented a small prototype system which uses CaaS, a central authority which acts as a authenticator. The implementation is inspired from [*this*](http://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=6295970) research paper.

This project was developed as a part of our Web-Services(IT450) course.

## Usage

* Clone the repository and register for an app on Dropbox and get an APPKEY and an APPSECRET. Add these to the `settings_template.py` file and rename it to `settings.py`.

* Register for a new Gmail account for your CaaS provider and add account information in `main.py`.

* Start up the CaaS server and send a POST request in the form `{'Email': 'abcd@xyz.com', 'Password': 'pass12345'}` to the server. Check your mail for a secure-string used for registration with the CaaS.

* Send a POST request of the form `{'Email': 'abcd@xyz.com', 'Secure_String': '1337_secure'}` to the `/verify` endpoint of the CaaS server. You are now registered.

* Start up `main.py` and follow the instructions! You can use it with options `-e` for encryption and `-d` for decryption. 

* Use `-h` for help.

## Developers

[Kishor](https://github.com/therealkbhat),
[Chinmay](https://github.com/chinmaydd),
[Sagar](https://github.com/gitsagar),
[Sarvjeet](https://github.com/sssarvjeet)

## Contributing

The implementation is still a work in progress. We would love contributions from all!

## License

MIT
