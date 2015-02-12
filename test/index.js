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

/*jshint -W068 */

var should = require('should');
var bcrypt = require('bcrypt');
var async = require('async');

var User = require('../index');
var match = require('match-object');

// setup a resolver
var db = {
  users: [],
  find: function(lookup, cb) {
    var found = null;
    async.some(db.users, function(user, cb2) {
      if (match(lookup, user)) {
        found = user;
        cb2(true);
        return;
      }
      cb2(false);
    }, function() { cb(null, found); });
  },
  insert: function(user, cb) {
    db.users.push(user);
    process.nextTick(cb);
  },
  updateHash: function(lookup, hash, cb) {
    async.some(db.users, function(user, cb2) {
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

var findOne = db.find;

describe('User', function () {
  describe('constructor', function () {
    it('should require db to be an object', function() {
      (function() { var user = new User(''); return user; }).should.throw('db must be an object');
    });

    it('should require username to be a string', function() {
      (function() { var user = new User(db); return user;}).should.throw('username must be a string');
    });

    it('should require realm to be a string', function() {
      (function() { var user = new User(db, '', 1); return user;}).should.throw('realm must be a string');
    });

    it('should require username to be at least 2 characters', function() {
      (function() { var user = new User(db, 'a', ''); return user;}).should.throw('username must be at least 2 characters');
    });

    it('should require username to not exceed 128 characters', function() {
      var username = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      (function() { var user = new User(db, username, ''); return user;}).should.throw('username can not exceed 128 characters');
    });

    it('should require realm to be at least 1 character', function() {
      (function() { var user = new User(db, 'foo', ''); return user;}).should.throw('realm must be at least 1 character');
    });

    it('should require realm to not exceed 128 characters', function() {
      var realm = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      (function() { var user = new User(db, 'foo', realm); return user;}).should.throw('realm can not exceed 128 characters');
    });

    it('should not throw', function() {
      var user = new User(db, 'foo', 'raboof');
      return user;
    });
  });

  describe('register', function () {
    it('should register', function(done) {
      var user = new User(db, 'baz', 'ooregister');
      user.register('p4ssword', function(err) {
        should.strictEqual(err, null);
        should.strictEqual(user.realm, 'ooregister');
        should.strictEqual(user.username, 'baz');

        // bcrypt password example: '$2a$10$VnQeImV1DVqtQ7hXa.Sgsug9cCLVa65W4jO09w.I5tXcuYRbRVevu'
        should.strictEqual(user.password.length, 60);
        user.password.should.match(/^\$2a\$10\$/);

        bcrypt.compare('p4ssword', user.password, function(err, res) {
          if (err) { throw err; }
          if (res !== true) { throw new Error('passwords don\'t match'); }
          done();
        });
      });
    });

    it('should fail if username already exists', function(done) {
      var user = new User(db, 'baz', 'ooregister');
      user.register('password', function(err, user) {
        should.strictEqual(user, undefined);
        should.strictEqual(err.message, 'username already exists');
        done();
      });
    });
  });

  describe('find', function () {
    it('should find that the user does not exist', function(done) {
      var user = new User(db, 'qux');
      user.find(function(err, found) {
        if (err) { throw err; }
        should.strictEqual(found, false);
        done();
      });
    });

    it('needs a user to exist', function(done) {
      var user = new User(db, 'qux');
      user.register('password', done);
    });

    it('should find the user', function(done) {
      var user = new User(db, 'qux');
      user.find(function(err, found) {
        if (err) { throw err; }
        should.strictEqual(found, true);
        should.strictEqual(user.username, 'qux');
        should.strictEqual(user.realm, '_default');
        done();
      });
    });

    it('should find that the user does not exist in other realm', function(done) {
      var user = new User(db, 'qux', 'otherRealm');
      user.find(function(err, found) {
        if (err) { throw err; }
        should.strictEqual(found, false);
        done();
      });
    });
  });

  describe('verifyPassword', function () {
    // use previously created user

    it('should find that the password is invalid', function(done) {
      var user = new User(db, 'baz', 'ooregister');
      user.find(function(err) {
        if (err) { throw err; }
        user.verifyPassword('secret', function(err, correct) {
          if (err) { throw err; }
          should.strictEqual(correct, false);
          done();
        });
      });
    });

    it('should find that the password is valid', function(done) {
      var user = new User(db, 'baz', 'ooregister');
      user.find(function(err) {
        if (err) { throw err; }
        user.verifyPassword('p4ssword', function(err, correct) {
          if (err) { throw err; }
          should.strictEqual(correct, true);
          done();
        });
      });
    });

    it('needs a user to exist', function(done) {
      var user = new User(db, 'foo', 'verifyPasswordRealm');
      user.register('secr3t', done);
    });

    it('should find that the password is invalid', function(done) {
      var user = new User(db, 'foo', 'verifyPasswordRealm');
      user.find(function(err, found){
        if (err) { throw err; }
        if (!found) { throw new Error('user not found'); }

        user.verifyPassword('secret', function(err, correct) {
          if (err) { throw err; }
          should.strictEqual(correct, false);
          done();
        });
      });
    });

    it('should find that the password is invalid for non-existant users', function(done) {
      var user = new User(db, 'wer', 'verifyPasswordRealm');
      user.find(function(err){
        if (err) { throw err; }
        user.verifyPassword('secr3t', function(err, valid) {
          if (err) { throw err; }
          should.strictEqual(valid, false);
          done();
        });
      });
    });

    it('should find that the password is invalid for users in non-existant realms', function(done) {
      var user = new User(db, 'foo', 'verifyPasswordRealm2');
      user.verifyPassword('secr3t', function(err, valid) {
        if (err) { throw err; }
        should.strictEqual(valid, false);
        done();
      });
    });
  });

  describe('setPassword', function () {
    // use previously created user

    it('should update the password', function(done) {
      var user = new User(db, 'baz', 'ooregister');
      user.find(function(err){
        if (err) { throw err; }
        user.setPassword('secret', function(err) {
          if (err) { throw err; }
          findOne({ username: 'baz', realm: 'ooregister' }, function(err, user) {
            should.strictEqual(err, null);
            should.strictEqual(user.realm, 'ooregister');
            should.strictEqual(user.username, 'baz');

            // bcrypt password example: '$2a$10$VnQeImV1DVqtQ7hXa.Sgsug9cCLVa65W4jO09w.I5tXcuYRbRVevu'
            should.strictEqual(user.password.length, 60);
            user.password.should.match(/^\$2a\$10\$/);

            bcrypt.compare('secret', user.password, function(err, res) {
              if (err) { throw err; }
              if (res !== true) { throw new Error('passwords don\'t match'); }
              done();
            });
          });
        });
      });
    });

    it('should require that the user exists in the given realm (wrong realm)', function(done) {
      var user = new User(db, 'baz', 'ooregister2');
      user.setPassword('secret', function(err) {
        should.strictEqual(err.message, 'failed to update password');
        done();
      });
    });

    it('should require that the user exists in the given realm (wrong username)', function(done) {
      var user = new User(db, 'foo', 'ooregister');
      user.setPassword('secret', function(err) {
        should.strictEqual(err.message, 'failed to update password');
        done();
      });
    });
  });
});
