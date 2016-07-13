// Copyright IBM Corp. 2014,2016. All Rights Reserved.
// Node module: generator-loopback
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

/*global describe, beforeEach, afterEach, it */
'use strict';
var path = require('path');
var helpers = require('yeoman-test');
var wsModels = require('loopback-workspace').models;
var SANDBOX =  path.resolve(__dirname, 'sandbox');
var expect = require('chai').expect;
var common = require('./common');
var fs = require('fs-extra');
var app = require('loopback-workspace/server/server');
var PackageDefinition = app.models.PackageDefinition;

describe('loopback:acl generator', function() {
  beforeEach(function createSandbox(done) {
    helpers.testDirectory(SANDBOX, done);
  });

  beforeEach(function createProject(done) {
    common.createDummyProject(SANDBOX, 'test-app', done);
  });

  afterEach(common.resetWorkspace);

  beforeEach(function createCarModel(done) {
    var test = this;
    wsModels.ModelDefinition.create(
      {
        name: 'Car',
        facetName: 'common'
      },
      function(err, model) {
        if(err) {
          return done(err);
        }
        test.Model = model;
        // Create another model
        wsModels.ModelDefinition.create(
          {
            name: 'Location',
            facetName: 'common'
          }, done);
      });
  });

  it('adds an entry to models.json', function(done) {
    var aclGen = givenAclGenerator();
    helpers.mockPrompt(aclGen, {
      model: 'Car',
      scope: 'all',
      accessType: '*',
      role: '$everyone',
      permission: 'AUDIT'
    });

    aclGen.run(function() {
      var def = common.readJsonSync('common/models/car.json');
      var carAcls = def.acls;

      expect(carAcls).to.eql([{
        accessType: '*',
        permission: 'AUDIT',
        principalType: 'ROLE',
        principalId: '$everyone'
      }]);
      done();
    });
  });

  it('skips accessType is the scope is method', function(done) {
    var aclGen = givenAclGenerator();
    helpers.mockPrompt(aclGen, {
      model: 'Car',
      scope: 'method',
      property: 'find',
      role: '$everyone',
      permission: 'AUDIT'
    });

    aclGen.run(function() {
      var def = common.readJsonSync('common/models/car.json');
      var carAcls = def.acls;

      expect(carAcls).to.eql([{
        accessType: 'EXECUTE',
        property: 'find',
        permission: 'AUDIT',
        principalType: 'ROLE',
        principalId: '$everyone'
      }]);
      done();
    });
  });

  it('adds an entry to models.json for custom role', function(done) {
    var aclGen = givenAclGenerator();
    helpers.mockPrompt(aclGen, {
      model: 'Car',
      scope: 'all',
      accessType: '*',
      role: 'other',
      customRole: 'myRole',
      permission: 'DENY'
    });

    aclGen.run(function() {
      var def = common.readJsonSync('common/models/car.json');
      var carAcls = def.acls;

      expect(carAcls).to.eql([{
        accessType: '*',
        permission: 'DENY',
        principalType: 'ROLE',
        principalId: 'myRole'
      }]);
      done();
    });
  });

  it('adds an entry to all models.json', function(done) {
    var aclGen = givenAclGenerator();
    helpers.mockPrompt(aclGen, {
      scope: 'all',
      accessType: '*',
      role: '$owner',
      permission: 'ALLOW'
    });

    aclGen.run(function() {
      var def = common.readJsonSync('common/models/car.json');
      var carAcls = def.acls;

      expect(carAcls).to.eql([{
        accessType: '*',
        permission: 'ALLOW',
        principalType: 'ROLE',
        principalId: '$owner'
      }]);

      def = common.readJsonSync('common/models/location.json');
      var locationACLs = def.acls;

      expect(locationACLs).to.eql([{
        accessType: '*',
        permission: 'ALLOW',
        principalType: 'ROLE',
        principalId: '$owner'
      }]);

      done();
    });
  });

  it('mfp test - with scope method and componentConfig', function (done) {
    addDepToPackageJson('loopback-oauth-mfp').then(function () {
      var aclGen = givenAclGenerator();
      helpers.mockPrompt(aclGen, {
        model: 'Car',
        scope: 'method',
        property: 'find',
        role: '$everyone',
        permission: 'SECURITY_SCOPE',
        authProvider: 'mfp',
        authServerName: 'Create a new auth server',
        newAuthServerName: 'My MFP Server',
        authServerURL: 'http://localhost:9080/mfp/api',
        authScope: 'scope1',
      });

      aclGen.run(function () {
        var def = common.readJsonSync('common/models/car.json');
        var carAcls = def.acls;

        expect(carAcls).to.eql([{
          accessType: 'EXECUTE',
          principalType: 'ROLE',
          principalId: '$everyone',
          permission: 'SECURITY_SCOPE',
          property: 'find',
          authScope: 'scope1',
          authServerName: 'My MFP Server'
        }]);

        var componentConfigPath = 'server/component-config.json';
        var config = fs.readJsonSync(componentConfigPath, { throws: false });
        var actualRes = config['loopback-oauth-mfp'].authorizationServers;
        expect(actualRes).to.eql([{
          'name': 'My MFP Server',
          'url': 'http://localhost:9080/mfp/api'
        }]);
        done();
      });
    }).catch(function (err) {
      console.log('error: ' + err);
    });
  });

  it('mfp test - with scope all', function (done) {
    addDepToPackageJson('loopback-oauth-mfp').then(function () {
      var aclGen = givenAclGenerator();
      helpers.mockPrompt(aclGen, {
        model: 'Car',
        scope: 'all',
        accessType: '*',
        role: '$everyone',
        permission: 'SECURITY_SCOPE',
        authProvider: 'mfp',
        authServerName: 'My MFP Server',
        authScope: 'scope1 scope2',
      });
      aclGen.run(function () {
        var def = common.readJsonSync('common/models/car.json');
        var carAcls = def.acls;

        expect(carAcls).to.eql([{
          accessType: '*',
          principalType: 'ROLE',
          principalId: '$everyone',
          permission: 'SECURITY_SCOPE',
          authServerName: 'My MFP Server',
          authScope: 'scope1 scope2',
        }]);
        done();
      });
    }).catch(function (err) {
      console.log('error: ' + err);
    });
  });

  it('mfp test - with scope all and customRole', function (done) {
    addDepToPackageJson('loopback-oauth-mfp').then(function () {
      var aclGen = givenAclGenerator();
      helpers.mockPrompt(aclGen, {
        model: 'Car',
        scope: 'all',
        accessType: '*',
        role: 'other',
        customRole: 'myRole',
        permission: 'SECURITY_SCOPE',
        authProvider: 'mfp',
        authServerName: 'My MFP Server',
        authScope: 'scope1 scope2 scope3',
      });
      aclGen.run(function () {
        var def = common.readJsonSync('common/models/car.json');
        var carAcls = def.acls;

        expect(carAcls).to.eql([{
          accessType: '*',
          principalType: 'ROLE',
          principalId: 'myRole',
          permission: 'SECURITY_SCOPE',
          authServerName: 'My MFP Server',
          authScope: 'scope1 scope2 scope3',
        }]);
        done();
      });
    }).catch(function (err) {
      console.log('error: ' + err);
    });
  });

  function addDepToPackageJson(moduleName) {
    return new Promise(function (fulfill, reject) {
      PackageDefinition.findOne({}, function (err, pkg) {
        if (err)
          reject('package.json not found');

        pkg.dependencies[moduleName] = '1.0.0';
        pkg.save(fulfill);
      });
    });
  }

  function givenAclGenerator() {
    var name = 'loopback:acl';
    var path = '../../acl';
    var gen = common.createGenerator(name, path);
    return gen;
  }
});
