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
 * Create a new User object. Either for maintenance, verification or registration.
 * A user may be bound to a realm.
 *
 * @param {Object} db  object that implements find, updateHash and insert methods
 * @param {String} username  the name of the user to bind this instance to
 * @param {Object} [opts]  object containing optional parameters
 *
 * opts:
 *  realm {String, default "_default"}  optional realm the user belongs to
 *  debug {Boolean, default false} whether to do extra console logging or not
 *  hide {Boolean, default false} whether to suppress errors or not (for testing)
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
function User(db, username, opts) {
  if (typeof db !== 'object') { throw new TypeError('db must be an object'); }
  if (typeof username !== 'string') { throw new TypeError('username must be a string'); }

  opts = opts || {};
  if (typeof opts !== 'object') { throw new TypeError('opts must be an object'); }

  var realm = '_default';
  if (typeof opts.realm !== 'undefined') {
    if (typeof opts.realm !== 'string') { throw new TypeError('opts.realm must be a string'); }
    realm = opts.realm;
  }
  if (typeof opts.debug !== 'undefined' && typeof opts.debug !== 'boolean') { throw new TypeError('opts.debug must be a boolean'); }
  if (typeof opts.hide !== 'undefined' && typeof opts.hide !== 'boolean') { throw new TypeError('opts.hide must be a boolean'); }

  if (username.length < 2) { throw new Error('username must be at least 2 characters'); }
  if (username.length > 128) { throw new Error('username can not exceed 128 characters'); }
  if (realm.length < 1) { throw new Error('opts.realm must be at least 1 character'); }
  if (realm.length > 128) { throw new Error('opts.realm can not exceed 128 characters'); }

  this._db = db;
  this._username = username;
  this._realm = realm;

  this._debug = opts.debug || false;
  this._hide = opts.hide || false;

  // keys that should be mapped from the user object that is stored in the user db
  this._protectedDbKeys = {
    realm: true,
    username: true,
    password: true
  };

  // keys that can not be used in the user object that is stored in the user db
  this._illegalDbKeys = {
    _protectedDbKeys: true,
    _illegalDbKeys: true,
    _db: true,
    _debug: true,
    _hide: true
  };
}
module.exports = User;

/**
 * Find a user in the database.
 *
 * @param {Function} cb  first parameter will be an error or null, second parameter
 *                       will be true when user is found, otherwise false.
 */
User.prototype.find = function find(cb) {
  if (typeof cb !== 'function') { throw new TypeError('cb must be a function'); }

  var lookup = {
    realm: this._realm,
    username: this._username
  };

  var that = this;
  this._db.find(lookup, function(err, user) {
    if (err) { cb(err, false); return; }

    if (user) {
      var ok = Object.keys(user).every(function(key) {
        if (that._illegalDbKeys[key]) {
          if (!that._hide) { console.error('object in user db contains an illegal key: ', key, user); }
          return false;
        }

        if (that._protectedDbKeys[key]) {
          that['_' + key] = user[key];
        } else {
          that[key] = user[key];
        }

        return true;
      });

      if (!ok) {
        cb(new Error('object in user db contains an illegal key'));
        return;
      }

      cb(null, true);
      return;
    }

    cb(null, false);
  });
};

/**
 * Verify if the given password is valid.
 *
 * @param {String} password  the password to verify
 * @param {Function} cb  first parameter will be an error or null, second parameter
 *                       contains a boolean about whether the password is valid or
 *                       not.
 */
User.prototype.verifyPassword = function verifyPassword(password, cb) {
  if (typeof password !== 'string') { throw new TypeError('password must be a string'); }
  if (typeof cb !== 'function') { throw new TypeError('cb must be a function'); }

  var that = this;
  that.find(function(err, found) {
    if (err) { cb(err); return; }

    if (!found) { cb(null, false); return; }

    bcrypt.compare(password, that._password, cb);
  });
};

/**
 * Update the password for the given username.
 *
 * Note: the user has to exist in the database.
 *
 * @param {String} password  the password to use
 * @param {Function} cb  first parameter will be either an error object or null on
 *                       success.
 */
User.prototype.setPassword = function setPassword(password, cb) {
  if (typeof password !== 'string') { throw new TypeError('password must be a string'); }
  if (typeof cb !== 'function') { throw new TypeError('cb must be a function'); }

  var that = this;
  bcrypt.hash(password, 10, function(err, hash) {
    if (err) { cb(err); return; }

    var lookup = {
      realm: that._realm,
      username: that._username
    };

    that._db.updateHash(lookup, hash, cb);
  });
};

/**
 * Register a new user with a certain password.
 *
 * @param {String} password  the password to use
 * @param {Function} cb  first parameter will be either an error object or null on
 *                       success.
 */
User.prototype.register = function register(password, cb) {
  if (typeof password !== 'string') { throw new TypeError('password must be a string'); }
  if (typeof cb !== 'function') { throw new TypeError('cb must be a function'); }

  var that = this;
  var user = {
    realm: that._realm,
    username: that._username
  };

  that.find(function(err, found) {
    if (err) { cb(err); return; }

    if (found) { cb(new Error('username already exists')); return; }

    that._db.insert(user, function(err) {
      if (err) { cb(err); return; }

      that.setPassword(password, function(err) {
        if (err) { cb(err); return; }

        // update this instance
        that.find(cb);
      });
    });
  });
};
