/**
 * Copyright (c) 2014, 2015 Tim Kuijsten
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

'use strict';

var bcrypt = require('bcrypt');

/**
 * Check parameters and throw if type is incorrect, or length out of bounds.
 *
 * @param {Object} db  throw if not an object
 * @param {String} username  throw if not a String
 * @param {String} password  throw if not a String
 * @param {String} realm  throw if not a String
 * @param {Function} cb  throw if not a Function
 * @return {undefined}
 */
function _checkAllWithPassword(db, username, password, realm, cb) {
  /*jshint maxcomplexity:11*/
  if (typeof db !== 'object') { throw new TypeError('db must be an object'); }
  if (typeof username !== 'string') { throw new TypeError('username must be a string'); }
  if (typeof password !== 'string') { throw new TypeError('password must be a string'); }
  if (typeof realm !== 'string') { throw new TypeError('realm must be a string'); }
  if (typeof cb !== 'function') { throw new TypeError('cb must be a function'); }

  if (username.length < 2) { throw new Error('username must be at least 2 characters'); }
  if (username.length > 128) { throw new Error('username can not exceed 128 characters'); }
  if (password.length < 6) { throw new TypeError('password must be at least 6 characters'); }
  if (realm.length < 1) { throw new Error('realm must be at least 1 character'); }
  if (realm.length > 128) { throw new Error('realm can not exceed 128 characters'); }
}

/**
 * Create a new User object. Either for maintenance, verification or registration.
 * A user may be bound to a realm.
 *
 * @param {Object} db  object that implements find, updateHash and insert methods
 * @param {String} username  the name of the user to bind this instance to
 * @param {String, default: _default} [realm]  optional realm the user belongs to
 *
 * Three functions db must support:
 * find should accept: lookup, callback
 *   lookup {Object}:
 *     realm {String}
 *     username {String}
 *   callback {Function} should call back with:
 *     err {Object}     error object or null
 *     user {Object}    user object
 *
 * updateHash should accept: lookup, hash, callback
 *   lookup {Object}:
 *     realm {String}
 *     username {String}
 *   hash {String}      bcrypt hash
 *   callback {Function} should call back with:
 *     err {Object}     error object or null
 *
 * insert should accept: user, callback
 *   user {Object}:
 *     realm {String}
 *     username {String}
 *   callback {Function} should call back with:
 *     err {Object}     error object or null
 */
function User(db, username, realm) {
  if (typeof realm === 'undefined') {
    realm = '_default';
  }

  _checkAllWithPassword(db, username, 'xxxxxx', realm, function() {});

  this._db = db;
  this._realm = realm;
  this._username = username;
}
module.exports = User;

User._checkAllWithPassword = _checkAllWithPassword;

/////////////////////////////
//// Stateless functions ////
/////////////////////////////


/**
 * Find a user in the database.
 *
 * @param {Object} db  the database that contains all user accounts
 * @param {String} username  the username to check
 * @param {String, default: _default} [realm]  optional realm the user belongs to
 * @param {Function} cb  first parameter will be an error or null, second parameter
 *                       contains the user or null if not found.
 */
function find(db, username, realm, cb) {
  if (typeof realm === 'function') {
    cb = realm;
    realm = '_default';
  }
  _checkAllWithPassword(db, username, 'xxxxxx', realm, cb);

  var lookup = {
    realm: realm,
    username: username
  };

  db.find(lookup, function(err, user) {
    if (err) { cb(err); return; }
    cb(null, user);
  });
}
User.find = find;

/**
 * Return whether or not the user already exists in the database.
 *
 * @param {Object} db  the database that contains all user accounts
 * @param {String} username  the username to check
 * @param {String, default: _default} [realm]  optional realm the user belongs to
 * @param {Function} cb  first parameter will be an error or null, second parameter
 *                       contains a boolean about whether this user exists or not.
 */
function exists(db, username, realm, cb) {
  if (typeof realm === 'function') {
    cb = realm;
    realm = '_default';
  }
  _checkAllWithPassword(db, username, 'xxxxxx', realm, cb);

  find(db, username, realm, function(err, user){
    if (err) { cb(err); return; }
    if (user) { cb(null, true); return; }
    cb(null, false);
  });
}
User.exists = exists;

/**
 * Verify if the given password is valid for the given username.
 *
 * @param {Object} db  the database that contains all user accounts
 * @param {String} username  the username to use
 * @param {String} password  the password to verify
 * @param {String, default: _default} [realm]  optional realm the user belongs to
 * @param {Function} cb  first parameter will be an error or null, second parameter
 *                       contains a boolean about whether the password is valid or
 *                       not.
 */
function verifyPassword(db, username, password, realm, cb) {
  if (typeof realm === 'function') {
    cb = realm;
    realm = '_default';
  }
  _checkAllWithPassword(db, username, password, realm, cb);

  var lookup = {
    realm: realm,
    username: username
  };

  db.find(lookup, function(err, user) {
    if (err) { cb(err); return; }

    if (!user) { cb(null, false, null); return; }

    bcrypt.compare(password, user.password, function(err, res) {
      if (err) { cb(err); return; }
      if (res === true) { cb(null, true); return; }

      cb(null, false);
    });
  });
}
User.verifyPassword = verifyPassword;

/**
 * Update the password for the given username.
 *
 * Note: the user has to exist in the database.
 *
 * @param {Object} db  the database that contains all user accounts
 * @param {String} username  the username to use
 * @param {String} password  the password to use, at least 6 characters
 * @param {String, default: _default} [realm]  optional realm the user belongs to
 * @param {Function} cb  first parameter will be either an error object or null on
 *                       success.
 */
function setPassword(db, username, password, realm, cb) {
  if (typeof realm === 'function') {
    cb = realm;
    realm = '_default';
  }
  _checkAllWithPassword(db, username, password, realm, cb);

  bcrypt.hash(password, 10, function(err, hash) {
    if (err) { cb(err); return; }

    var lookup = {
      realm: realm,
      username: username
    };

    db.updateHash(lookup, hash, cb);
  });
}
User.setPassword = setPassword;

/**
 * Register a new user with a certain password.
 *
 * @param {Object} db  the database that contains all user accounts
 * @param {String} username  the username to use
 * @param {String} password  the password to use
 * @param {String, default: _default} [realm]  optional realm the user belongs to
 * @param {Function} cb  first parameter will be either an error object or null on
 *                       success, second parameter will be either a user object or
 *                       null on failure.
 */
function register(db, username, password, realm, cb) {
  if (typeof realm === 'function') {
    cb = realm;
    realm = '_default';
  }
  _checkAllWithPassword(db, username, password, realm, cb);

  var user = {
    realm: realm,
    username: username
  };

  exists(db, username, realm, function(err, doesExist) {
    if (doesExist) { cb(new Error('username already exists')); return; }

    db.insert(user, function(err) {
      if (err) { cb(err); return; }

      setPassword(db, username, password, realm, function(err) {
        if (err) { cb(err); return; }

        db.find(user, cb);
      });
    });
  });
}
User.register = register;


/////////////////////////////////////////
//// Object methods of each function ////
/////////////////////////////////////////


/**
 * Wrapper around User.exists.
 *
 * @param {Function} cb  first parameter will be an error or null, second parameter
 *                       contains a boolean about whether this user exists.
 */
User.prototype.exists = function(cb) {
  if (typeof cb !== 'function') { throw new TypeError('cb must be a function'); }

  exists(this._db, this._username, this._realm, cb);
};

/**
 * Wrapper around User.find.
 *
 * @param {Function} cb  first parameter will be an error or null, second parameter
 *                       contains a user object or null if not found.
 */
User.prototype.find = function(cb) {
  if (typeof cb !== 'function') { throw new TypeError('cb must be a function'); }

  find(this._db, this._username, this._realm, cb);
};

/**
 * Wrapper around User.verifyPassword.
 *
 * @param {String} password  the password to verify
 * @param {Function} cb  first parameter will be an error or null, second parameter
 *                       contains a boolean about whether the password is valid or
 *                       not.
 */
User.prototype.verifyPassword = function(password, cb) {
  if (typeof password !== 'string') { throw new TypeError('password must be a string'); }
  if (typeof cb !== 'function') { throw new TypeError('cb must be a function'); }

  verifyPassword(this._db, this._username, password, this._realm, cb);
};

/**
 * Wrapper around User.setPassword.
 *
 * Note: the user has to exist in the database.
 *
 * @param {String} password  the password to use
 * @param {Function} cb  first parameter will be either an error object or null on
 *                       success.
 */
User.prototype.setPassword = function(password, cb) {
  if (typeof password !== 'string') { throw new TypeError('password must be a string'); }
  if (typeof cb !== 'function') { throw new TypeError('cb must be a function'); }

  setPassword(this._db, this._username, password, this._realm, cb);
};

/**
 * Wrapper around User.register.
 *
 * @param {String} password  the password to use
 * @param {Function} cb  first parameter will be either an error object or null on
 *                       success.
 */
User.prototype.register = function(password, cb) {
  if (typeof password !== 'string') { throw new TypeError('password must be a string'); }
  if (typeof cb !== 'function') { throw new TypeError('cb must be a function'); }

  register(this._db, this._username, password, this._realm, cb);
};
