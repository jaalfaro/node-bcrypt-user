# bcryptjs-user

Abstract library to create, update and authenticate users using bcrypt.

Use this module to implement a user account module that uses bcrypt passwords with
your own storage engine. See `mongo-bcryptjs-user` and `array-bcrypt-user` for two
real world implementations.

## Example
### Implementation using array based storage

Note, this example is based on `array-bcrypt-user` and uses the `match` npm.

    var util = require('util');

    var BcryptUser = require('bcryptjs-user');
    var async = require('async');
    var match = require('match-object');

    // store and verify user accounts in an array named `db` using bcrypt passwords
    function User(db, username, opts) {
      if (!Array.isArray(db)) { throw new TypeError('db must be an array'); }
      if (typeof username !== 'string') { throw new TypeError('username must be a string'); }

      // setup a user database resolver, this is a custom storage engine
      var resolver = {
        find: function(lookup, cb) {
          var found = null;
          async.some(db, function(user, cb2) {
            if (match(lookup, user)) {
              found = user;
              cb2(true);
              return;
            }
            cb2(false);
          }, function() { cb(null, found); });
        },
        insert: function(user, cb) {
          db.push(user);
          process.nextTick(cb);
        },
        updateHash: function(lookup, hash, cb) {
          async.some(db, function(user, cb2) {
            if (match(lookup, user)) {
              user.password = hash;
              cb2(true);
              return;
            }
            cb2(false);
          }, function(result) {
            if (!result) {
              cb(new Error('failed to update password'));
              return;
            }

            cb(null);
          });
        }
      };

      BcryptUser.call(this, resolver, username, opts || {});
    }

    util.inherits(User, BcryptUser);
    module.exports = User;

    // create a new user with a certain password and save it to the database
    User.register = function register(db, username, password, realm, cb) {
      if (!Array.isArray(db)) { throw new TypeError('db must be an array'); }
      if (typeof realm === 'function') {
        cb = realm;
        realm = '_default';
      }

      try {
        var user = new User(db, username, { realm: realm });
        user.register(password, function(err) {
          if (err) { cb(err); return; }

          cb(null, user);
        });
      } catch(err) {
        process.nextTick(function() {
          cb(err);
        });
        return;
      }
    };

    // find and return a user from the database
    User.find = function find(db, username, realm, cb) {
      if (!Array.isArray(db)) { throw new TypeError('db must be an array'); }
      if (typeof realm === 'function') {
        cb = realm;
        realm = '_default';
      }

      try {
        var user = new User(db, username, { realm: realm });
        user.find(function(err) {
          if (err) { cb(err); return; }

          cb(null, user);
        });
      } catch(err) {
        process.nextTick(function() {
          cb(err);
        });
        return;
      }
    };

Use the above, create a new user named "foo" with the password "secr3t".

    var assert = require('assert');
    var User = // previously created module

    var db = [];

    User.register(db, 'foo', 'secr3t', function(err, user) {
      if (err) { throw err; }
      assert.equal(db.length, 1);
    });

Check if the password "secr3t" is correct for user "foo".

    // same setup as previous example

    User.find(db, 'foo', 'bar', function(err, user) {
      if (err) { throw err; }
      user.verifyPassword('secr3t', function(err, correct) {
        if (err) { throw err; }
        assert(correct, true);
      });
    });

## Installation

    $ npm install bcryptjs-user

## API

### new User(db, username, [opts])
* db {Object} resolver that implements find, updateHash and insert methods
* username {String} the name of the user to bind this instance to
* [opts] {Object} object containing optional parameters

opts:
* realm {String, default "_default"}  optional realm the user belongs to
* debug {Boolean, default false} whether to do extra console logging or not
* hide {Boolean, default false} whether to suppress errors or not (for testing)

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

### user.find(cb)
* cb {Function} first parameter will be an error or null, second parameter
  will be true when user is found, otherwise false.

Return a user from the database. This method should be implemented.

Note, the following keys are illegal and should not exist in the user db object:
* _protectedDbKeys
* _illegalDbKeys
* _db
* _debug
* _hide

### user.verifyPassword(password, cb)
* password {String} the password to verify
* cb {Function} first parameter will be an error or null, second parameter
  contains a boolean about whether the password is valid or not.

Verify if the given password is valid.

### user.setPassword(password, cb)
* password {String} the password to use
* cb {Function} first parameter will be either an error object or null on success.

Update the password.

Note: the user has to exist in the database.

### user.register(password, cb)
* password {String} the password to use, at least 6 characters
* cb {Function} first parameter will be either an error object or null on success.

Register a new user with a certain password. This method should be implemented.

## Tests

    $ npm test

## License

ISC

Copyright (c) 2017 John Alfaro
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
