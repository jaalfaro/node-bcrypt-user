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

  if (typeof db !== 'object') { throw new TypeError('db must be an object'); }
  if (typeof username !== 'string') { throw new TypeError('username must be a string'); }
  if (typeof realm !== 'string') { throw new TypeError('realm must be a string'); }

  if (username.length < 2) { throw new Error('username must be at least 2 characters'); }
  if (username.length > 128) { throw new Error('username can not exceed 128 characters'); }
  if (realm.length < 1) { throw new Error('realm must be at least 1 character'); }
  if (realm.length > 128) { throw new Error('realm can not exceed 128 characters'); }

  this._db = db;
  this._realm = realm;
  this._username = username;

  this.protectedProps = {
    _db: true,
    _realm: true,
    _username: true
  };
}
module.exports = User;

/**
 * Find a user in the database.
 *
 * @param {Function} cb  first parameter will be an error or null, second parameter
 *                       will be true when user is found, otherwise false.
 */
User.prototype.find = function(cb) {
  if (typeof cb !== 'function') { throw new TypeError('cb must be a function'); }

  var that = this;
  var lookup = {
    realm: that._realm,
    username: that._username
  };

  this._db.find(lookup, function(err, user) {
    if (err) { cb(err, false); return; }

    if (user) {
      Object.keys(user).forEach(function(prop) {
        if (!that.protectedProps[prop]) { that[prop] = user[prop]; }
      });
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
User.prototype.verifyPassword = function(password, cb) {
  if (typeof password !== 'string') { throw new TypeError('password must be a string'); }
  if (typeof cb !== 'function') { throw new TypeError('cb must be a function'); }

  var that = this;
  that.find(function(err, found) {
    if (err) { cb(err); return; }

    if (!found) { cb(null, false); return; }

    bcrypt.compare(password, that.password, function(err, res) {
      if (err) { cb(err); return; }
      if (res === true) { cb(null, true); return; }

      cb(null, false);
    });
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
User.prototype.setPassword = function(password, cb) {
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
User.prototype.register = function(password, cb) {
  if (typeof password !== 'string') { throw new TypeError('password must be a string'); }
  if (typeof cb !== 'function') { throw new TypeError('cb must be a function'); }

  var that = this;
  var user = {
    realm: that._realm,
    username: that._username
  };

  that.find(function(err, found) {
    if (found) { cb(new Error('username already exists')); return; }

    that._db.insert(user, function(err) {
      if (err) { cb(err); return; }

      that.setPassword(password, function(err){
        if (err) { cb(err); return; }

        that.find(cb);
      });
    });
  });
};
