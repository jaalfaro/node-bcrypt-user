# bcrypt-user

Abstract library to create, update and authenticate users using bcrypt.

## Examples
### Create a new user
Create a new user named "foo" with the password "secr3t".

    var User = require('bcrypt-user');

    // setup a user database resolver, this is a custom storage engine
    // empty stub example:
    var res = {
      insert: function(user, cb) {
        // insert and call back with error or null
        process.nextTick(function() {
          // do some stuff
          cb(null);
        });
      },
      updateHash: function(lookup, hash, cb) {
        // update and call back with error or null
        process.nextTick(function() {
          // do some stuff
          cb(null);
        });
      },
      find: function(lookup, cb) {
        // update and call back with error or null, and user or null
        process.nextTick(function() {
          // do some stuff
          cb(err, user);
        });
      },
    };

    // then use
    var user = new User(res, 'foo');
    user.register('secr3t', function(err) {
      if (err) { throw err; }
      console.log('user created');
    });

### Find and verify a user
Find a user names "foo" and verify password "raboof".

    // same setup as previous example

    var user = new User(res, 'foo');
    user.verifyPassword('raboof', function(err, correct) {
      if (err) { throw err; }
      if (correct === true) {
        console.log('password correct');
      } else {
        console.log('password incorrect');
      }
    });

## Installation

    $ npm install bcrypt-user

## API
### object oriented

#### new User(db, username, [realm])
* db {Object} resolver that implements find, updateHash and insert methods
* username {String} the name of the user to bind this instance to
* realm {String, default: _default} optional realm the user belongs to

Create a new User object. Either for maintenance, verification or registration.
A user may be bound to a realm.

Three functions db must support:

    find should accept: lookup, callback
      lookup {Object}:
        realm {String}
        username {String}
      callback {Function} should call back with:
        err {Object}     error object or null
        user {Object}    user object

    updateHash should accept: lookup, hash, callback
      lookup {Object}:
        realm {String}
        username {String}
      hash {String}      bcrypt hash
      callback {Function} should call back with:
        err {Object}     error object or null

    insert should accept: user, callback
      user {Object}:
        realm {String}
        username {String}
      callback {Function} should call back with:
        err {Object}     error object or null

#### user.find(cb)
* cb {Function} first parameter will be an error or null, second parameter
  will be true when user is found, otherwise false.

Return a user from the database.

#### user.exists(cb)
* cb {Function} first parameter will be an error or null, second parameter
  contains a boolean about whether this user exists or not.

Return whether or not the user already exists in the database.

#### user.verifyPassword(password, cb)
* password {String} the password to verify
* cb {Function} first parameter will be an error or null, second parameter
  contains a boolean about whether the password is valid or not.

Verify if the given password is valid.

#### user.setPassword(password, cb)
* password {String} the password to use
* cb {Function} first parameter will be either an error object or null on success.

Update the password.

Note: the user has to exist in the database.

#### user.register(password, cb)
* password {String} the password to use, at least 6 characters
* cb {Function} first parameter will be either an error object or null on success.

Register a new user with a certain password.

## Tests

    $ npm test

## License

ISC

Copyright (c) 2014, 2015 Tim Kuijsten

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
