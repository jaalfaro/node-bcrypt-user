# bcrypt-user

Create user accounts, verify and update passwords using bcrypt. The library can be
used in a stateless way or in an object oriented way.

## Examples
### object oriented

Create a new user named "foo" with the password "secr3t".

    var User = require('bcrypt-user');

    // setup a user database resolver
    var res = {
      insert: function(user, cb) {
        // insert and call back with error or null
        process.nextTick(function() {
          cb(null);
        });
      },
      updateHash: function(lookup, hash, cb) {
        // update and call back with error or null
        process.nextTick(function() {
          cb(null);
        });
      },
      find: function(lookup, cb) {
        // update and call back with error or null, and user or null
        process.nextTick(function() {
          cb(err, user);
        });
      },
    };

    var user = new User(res, 'foo');
    user.register('secr3t', function(err) {
      if (err) { throw err; }
      console.log('user created');
    });

Check if the password "raboof" is correct for user "foo" in the realm "bar".

    // same setup as previous example

    var user = new User(res, 'foo', 'bar');
    user.verifyPassword('raboof', function(err, correct) {
      if (err) { throw err; }
      if (correct === true) {
        console.log('password correct');
      } else {
        console.log('password incorrect');
      }
    });

### stateless

Create a new user named "foo" with the password "secr3t".

    var User = require('bcrypt-user');

    // setup a resolver
    var res = {
      insert: function(user, cb) {
        // insert and call back with error or null
        process.nextTick(function() {
          cb(null);
        });
      },
      updateHash: function(lookup, hash, cb) {
        // update and call back with error or null
        process.nextTick(function() {
          cb(null);
        });
      },
      find: function(lookup, cb) {
        // update and call back with error or null, and user or null
        process.nextTick(function() {
          cb(err, user);
        });
      },
    };

    User.register(res, 'foo', 'secr3t', function(err) {
      if (err) { throw err; }
      console.log('user created');
    });

Check if the password "raboof" is correct for user "foo" in the realm "bar".

    // same setup as previous example

    User.verifyPassword(res, 'foo', 'raboof', 'bar', function(err, correct) {
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

### stateless

Furthermore a stateless variant of each object oriented function is available
where the user db, the username and optionally the realm are given at each
function invocation.

#### User.exists(db, username, [realm], cb)
#### User.verifyPassword(db, username, password, [realm], cb)
#### User.setPassword(db, username, password, [realm], cb)
#### User.register(db, username, password, [realm], cb)

## Tests

    $ npm test

## License

MIT

Copyright (c) 2014 Tim Kuijsten

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
