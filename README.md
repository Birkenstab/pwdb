# pwdb [alpha]
pwdb is a password manager like 1Password but it works right in your browser and is fully open-source. Your passwords will be accesible from everywhere around the world but they are fully encrypted using your master password, even on the server. The pwdb server uses nodejs.  
It is still in development.

# How to install
* [Node](http://nodejs.org) has to be installed
* You need the node modules sqlite3, express, body-parser, q and scrypt. You can install them using this Terminal command: ``npm install sqlite3 express body-parser q scrypt``
* Configure the config.js file
* To start the pwdb server run ``node pwdb_node.js``

Note: pwdb uses the WebCrypto-Api which requires a modern browser.

#Techincal details
This is simplified description of the security mechanism used in pwdb.

##Registration
1.  The client generates a random salt
2.  The password gets hashed with the salt using scrypt
3.  Salt, hashed password and username are sent to the server:
```
{"username":"Test",
"password":"0a8db1719d6d4e5edf013932ecc6ed89995c96594461223223cca6e3ea8f4232f37d3ee99bc1a049d1f323379122942ca578932cd21a907caf8014ada5f246bc",
"salt":[187,209,30,89,221,75,69,139,87,201,232,152,210,135,122,107,234,184,39,236,108,212,230,231,179,44,246,220,165,241,80,178,106,66,146,154,192,131,96,15,147,30,203,195,0,114,43,227,238,170,40,18,227,6,205,60,37,118,59,93,221,1,195,212]}
```

##Login
1.  The salt is retrieved from the server:
```
[187,209,30,89,221,75,69,139,87,201,232,152,210,135,122,107,234,184,39,236,108,212,230,231,179,44,246,220,165,241,80,178,106,66,146,154,192,131,96,15,147,30,203,195,0,114,43,227,238,170,40,18,227,6,205,60,37,118,59,93,221,1,195,212]
```
2.  The password gets hashed with the salt using scrypt
3.  Hashed password and username are sent to the server:
```
{"username":"Test2","password":"0a8db1719d6d4e5edf013932ecc6ed89995c96594461223223cca6e3ea8f4232f37d3ee99bc1a049d1f323379122942ca578932cd21a907caf8014ada5f246bc"}
```
4.  The server returns a session token:
```
YCXlFH8BJ7a8i3KBeSDIQoqe54RKj2w5dLvnWVdXOEK5ygqo9mR10avjdzQ3G9zINnAmkqrnBU2IVtSP3n+LqcQ5C40IWHoNpssMxWRD/vq+0cMU2Qje6pHLmpSO6Mnz3noyAA==
```
5.  The unhashed password is stored in a JavaScript variable for field encryption

##Field encryption
All fields (website name, username, password, notes) in pwdb are fully encrypted
1.  A SHA-256-hash of the password is generated so that the password always has the same length of 256 bits.
2.  An initialization vector of 16 bytes random values is generated
3.  The field value is encrypted using AES-CBC with the initialization vector and the SHA-256 hashe password:
```
{"data":[149,124,145,56,111,213,150,37,251,104,168,186,244,66,144,229],
"iv":[38,92,228,134,81,108,52,27,160,116,48,109,234,212,229,45]}
```


#Client libraries
* [jQuery](http://jquery.com)
* [Bootstrap](http://getbootstrap.com)
* [scrypt.js](https://github.com/tonyg/js-scrypt)
* [Underscore](http://underscorejs.org)
* [Backbone](http://backbonejs.org/)
* [Font Awesome](http://fortawesome.github.io/Font-Awesome/)

#Server libraries (node modules)
* sqlite3
* express
* body-parser
* q
* scrypt
