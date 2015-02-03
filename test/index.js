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
  describe('_checkAllWithPassword', function () {
    it('should require db to be an object', function() {
      (function() { User._checkAllWithPassword(''); }).should.throw('db must be an object');
    });

    it('should require username to be a string', function() {
      (function() { User._checkAllWithPassword(db); }).should.throw('username must be a string');
    });

    it('should require password to be a string', function() {
      (function() { User._checkAllWithPassword(db, ''); }).should.throw('password must be a string');
    });

    it('should require realm to be a string', function() {
      (function() { User._checkAllWithPassword(db, '', ''); }).should.throw('realm must be a string');
    });

    it('should require cb to be a function', function() {
      (function() { User._checkAllWithPassword(db, '', '', ''); }).should.throw('cb must be a function');
    });

    it('should require username to be at least 2 characters', function() {
      (function() { User._checkAllWithPassword(db, 'a', '', '', function() {}); }).should.throw('username must be at least 2 characters');
    });

    it('should require username to not exceed 128 characters', function() {
      var username = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      (function() { User._checkAllWithPassword(db, username, '', '', function() {}); }).should.throw('username can not exceed 128 characters');
    });

    it('should require password to be at least 6 characters', function() {
      (function() { User._checkAllWithPassword(db, 'foo', 'fubar', '', function() {}); }).should.throw('password must be at least 6 characters');
    });

    it('should require realm to be at least 1 character', function() {
      (function() { User._checkAllWithPassword(db, 'foo', 'raboof', '', function() {}); }).should.throw('realm must be at least 1 character');
    });

    it('should require realm to not exceed 128 characters', function() {
      var realm = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      (function() { User._checkAllWithPassword(db, 'foo', 'raboof', realm, function() {}); }).should.throw('realm can not exceed 128 characters');
    });

    it('should not throw', function() {
      User._checkAllWithPassword(db, 'foo', 'raboof', 'bar', function() {});
    });
  });

  describe('stateless', function () {
    describe('register', function () {
      it('should require db to be an object', function() {
        (function() { User.register(''); }).should.throw('db must be an object');
      });
      // assume all checks are handled by the previously tested User._checkAllWithPassword

      it('should register', function(done) {
        User.register(db, 'bar', 'password', function(err) {
          should.strictEqual(err, null);
          findOne({ username: 'bar', realm: '_default' }, function(err, user) {
            should.strictEqual(err, null);
            should.strictEqual(user.realm, '_default');
            should.strictEqual(user.username, 'bar');

            // bcrypt password example: '$2a$10$VnQeImV1DVqtQ7hXa.Sgsug9cCLVa65W4jO09w.I5tXcuYRbRVevu'
            should.strictEqual(user.password.length, 60);
            user.password.should.match(/^\$2a\$10\$/);

            bcrypt.compare('password', user.password, function(err, res) {
              if (err) { throw err; }
              if (res !== true) { throw new Error('passwords don\'t match'); }
              done();
            });
          });
        });
      });

      it('should fail if username already exists', function(done) {
        User.register(db, 'bar', 'password', function(err, user) {
          should.strictEqual(user, undefined);
          should.strictEqual(err.message, 'username already exists');
          done();
        });
      });
    });

    describe('exists', function () {
      it('should require db to be an object', function() {
        (function() { User.exists(''); }).should.throw('db must be an object');
      });
      // assume all checks are handled by the previously tested User._checkAllWithPassword

      it('should find that the user does not exist', function(done) {
        User.exists(db, 'foo', function(err, doesExist) {
          if (err) { throw err; }
          should.strictEqual(doesExist, false);
          done();
        });
      });

      it('needs a user to exist', function(done) {
        User.register(db, 'foo', 'password', done);
      });

      it('should find that the user does exist', function(done) {
        User.exists(db, 'foo', function(err, doesExist) {
          if (err) { throw err; }
          should.strictEqual(doesExist, true);
          done();
        });
      });

      it('should find that the user does exist in this realm', function(done) {
        User.exists(db, 'foo', 'otherRealm', function(err, doesExist) {
          if (err) { throw err; }
          should.strictEqual(doesExist, false);
          done();
        });
      });
    });

    describe('find', function () {
      it('should require db to be an object', function() {
        (function() { User.find(''); }).should.throw('db must be an object');
      });
      // assume all checks are handled by the previously tested User._checkAllWithPassword

      it('should find that the user does not exist', function(done) {
        User.find(db, 'qux', function(err, user) {
          if (err) { throw err; }
          should.strictEqual(user, null);
          done();
        });
      });

      it('needs a user to exist', function(done) {
        User.register(db, 'qux', 'password', done);
      });

      it('should find the user', function(done) {
        User.find(db, 'qux', function(err, user) {
          if (err) { throw err; }
          should.strictEqual(user.username, 'qux');
          should.strictEqual(user.realm, '_default');
          done();
        });
      });

      it('should find that the user does not exist in other realm', function(done) {
        User.find(db, 'qux', 'otherRealm', function(err, user) {
          if (err) { throw err; }
          should.strictEqual(user, null);
          done();
        });
      });
    });

    describe('verifyPassword', function () {
      it('should require db to be an object', function() {
        (function() { User.verifyPassword(''); }).should.throw('db must be an object');
      });
      // assume all checks are handled by the previously tested User._checkAllWithPassword

      it('needs a user to exist', function(done) {
        User.register(db, 'foo', 'secr3t', 'verifyPasswordRealm', done);
      });

      it('should find that the password is invalid', function(done) {
        User.verifyPassword(db, 'foo', 'secret', 'verifyPasswordRealm', function(err, valid) {
          if (err) { throw err; }
          should.strictEqual(valid, false);
          done();
        });
      });

      it('should find that the password is valid', function(done) {
        User.verifyPassword(db, 'foo', 'secr3t', 'verifyPasswordRealm', function(err, valid) {
          if (err) { throw err; }
          should.strictEqual(valid, true);
          done();
        });
      });

      it('should not return the user when password is valid', function(done) {
        User.verifyPassword(db, 'foo', 'secr3t', 'verifyPasswordRealm', function(err, valid, user) {
          if (err) { throw err; }
          should.strictEqual(valid, true);
          should.strictEqual(user, undefined);
          done();
        });
      });

      it('should find that the password is invalid for non-existant users', function(done) {
        User.verifyPassword(db, 'foo2', 'secr3t', function(err, valid, user) {
          if (err) { throw err; }
          should.strictEqual(valid, false);
          should.strictEqual(user, null);
          done();
        });
      });

      it('should find that the password is invalid for users in non-existant realms', function(done) {
        User.verifyPassword(db, 'foo', 'secr3t', 'verifyPasswordRealm2', function(err, valid) {
          if (err) { throw err; }
          should.strictEqual(valid, false);
          done();
        });
      });
    });

    describe('setPassword', function () {
      it('should require db to be an object', function() {
        (function() { User.setPassword(''); }).should.throw('db must be an object');
      });
      // assume all checks are handled by the previously tested User._checkAllWithPassword

      it('needs a user to exist', function(done) {
        User.register(db, 'foo', 'secr3t', 'setPasswordRealm', done);
      });

      it('should update the password', function(done) {
        User.setPassword(db, 'foo', 'secret', 'setPasswordRealm', function(err) {
          if (err) { throw err; }
          findOne({ username: 'foo', realm: 'setPasswordRealm' }, function(err, user) {
            should.strictEqual(err, null);
            should.strictEqual(user.realm, 'setPasswordRealm');
            should.strictEqual(user.username, 'foo');

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

      it('should require that the user exists in the given realm (wrong realm)', function(done) {
        User.setPassword(db, 'foo', 'secret', 'setPasswordRealm2', function(err) {
          should.strictEqual(err.message, 'failed to update password');
          done();
        });
      });

      it('should require that the user exists in the given realm (wrong username)', function(done) {
        User.setPassword(db, 'baz', 'secret', 'setPasswordRealm', function(err) {
          should.strictEqual(err.message, 'failed to update password');
          done();
        });
      });
    });
  });

  describe('object oriented', function () {
    describe('constructor', function () {
      it('should require db to be an object', function() {
        (function() { var user = new User(''); return user; }).should.throw('db must be an object');
      });
      // assume all checks are handled by the previously tested User._checkAllWithPassword
    });

    describe('register', function () {
      it('should register', function(done) {
        var user = new User(db, 'baz', 'ooregister');
        user.register('p4ssword', function(err, usr) {
          should.strictEqual(err, null);
          should.strictEqual(usr.realm, 'ooregister');
          should.strictEqual(usr.username, 'baz');

          // bcrypt password example: '$2a$10$VnQeImV1DVqtQ7hXa.Sgsug9cCLVa65W4jO09w.I5tXcuYRbRVevu'
          should.strictEqual(usr.password.length, 60);
          usr.password.should.match(/^\$2a\$10\$/);

          bcrypt.compare('p4ssword', usr.password, function(err, res) {
            if (err) { throw err; }
            if (res !== true) { throw new Error('passwords don\'t match'); }
            done();
          });
        });
      });
    });

    describe('exists', function () {
      // use previously created user
      it('should find that the user does exist', function(done) {
        var user = new User(db, 'baz', 'ooregister');
        user.exists(function(err, doesExist) {
          if (err) { throw err; }
          should.strictEqual(doesExist, true);
          done();
        });
      });
    });

    describe('verifyPassword', function () {
      // use previously created user

      it('should find that the password is invalid', function(done) {
        var user = new User(db, 'baz', 'ooregister');
        user.verifyPassword('secret', function(err, correct) {
          if (err) { throw err; }
          should.strictEqual(correct, false);
          done();
        });
      });

      it('should find that the password is valid', function(done) {
        var user = new User(db, 'baz', 'ooregister');
        user.verifyPassword('p4ssword', function(err, correct) {
          if (err) { throw err; }
          should.strictEqual(correct, true);
          done();
        });
      });
    });

    describe('setPassword', function () {
      // use previously created user

      it('should update the password', function(done) {
        var user = new User(db, 'baz', 'ooregister');
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
});
