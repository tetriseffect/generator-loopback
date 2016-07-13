// Copyright IBM Corp. 2014,2016. All Rights Reserved.
// Node module: generator-loopback
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
/* jshint maxlen: 200 */
var app = require('loopback-workspace/server/server');
var PackageDefinition = app.models.PackageDefinition;

var yeoman = require('yeoman-generator');
var async = require('async');
var fs = require('fs-extra');
var events = require('events');

var wsModels = require('loopback-workspace').models;
var ModelAccessControl = wsModels.ModelAccessControl;
var ACL = require('loopback').ACL;

var actions = require('../lib/actions');
var helpers = require('../lib/helpers');

var COMPONENT_CONFIG_PATH = 'server/component-config.json';
var LOOPBACK_OAUTH_MODULE_PREFIX = 'loopback-oauth-';
var CREATE_NEW_AUTH_SERVER_STRING = 'Create a new auth server';

var authServersList = [];
var chosenProvider;

var loadAuthServersEventEmitter = new events.EventEmitter();
loadAuthServersEventEmitter.on('loadAuthServersEvent', loadAuthorizationServersList);

var methodNames = [];  // 12 base methods that every module should have
// these methods will be shown in the choice-list, in case if "all existing models" is chosen
methodNames.push('create');
methodNames.push('upsert');
methodNames.push('exists');
methodNames.push('findById');
methodNames.push('find');
methodNames.push('findOne');
methodNames.push('destroyAll');
methodNames.push('updateAll');
methodNames.push('updateAll');
methodNames.push('deleteById');
methodNames.push('count');
methodNames.push('updateAttributes');
methodNames.push('createChangeStream');

module.exports = yeoman.Base.extend({
  // NOTE(bajtos)
  // This generator does not track file changes via yeoman,
  // as loopback-workspace is editing (modifying) files when  
  // saving project changes.

  help: function() {
    return helpers.customHelp(this);
  },
  
  init: function() {
    this.saveAuthServerHelperMethod = function(authServerName, authServerURL) {
		  var config = fs.readJsonSync(COMPONENT_CONFIG_PATH, {throws: false});
      var loopbackComponentModuleName = LOOPBACK_OAUTH_MODULE_PREFIX + chosenProvider;
		  if (!config[loopbackComponentModuleName]){
        config[loopbackComponentModuleName] = {};
        config[loopbackComponentModuleName].authorizationServers = [];
		  }
        
      // building server object {serverName + serverUrl}
      var serverObj = {};
      serverObj.name = authServerName;
      serverObj.url = authServerURL;
      config[loopbackComponentModuleName].authorizationServers.push(serverObj);
        
		  fs.writeJsonSync(COMPONENT_CONFIG_PATH, config);
    };
  },
  
  loadProject: actions.loadProject,

  loadModels: actions.loadModels,

  loadAccessTypeValues: function() {
    var done = this.async();
    ModelAccessControl.getAccessTypes(function(err, list) {
      this.accessTypeValues = list;
      done(err);
    }.bind(this));
  },

  loadRoleValues: function() {
    var done = this.async();
    ModelAccessControl.getBuiltinRoles(function(err, list) {
      this.roleValues = list;
      done(err);
    }.bind(this));
  },

  loadPermissionValues: function() {
    var done = this.async();
    ModelAccessControl.getPermissionTypes(function(err, list) {
      this.permissionValues = list;
      done(err);
    }.bind(this));
  },
  
  // NOTE(romanso)
  // Custom oauth provider name should conform with the loopback-oauth-<your-custom-oauth-provider-name> module
  // For example if the oauth provider name is 'mfp', then the oauth-provider-component module name should be 'loopback-oauth-mfp'
  // The oauth-providers list is built based on the project's package.json dependencies section.
  loadOAuthProviders: function () {
    var done = this.async();
    this.oauthProviders = [];
    
    PackageDefinition.findOne({}, function(err, pkg) {
      if (err)
        return done(err);
      
      for (var m in pkg.dependencies) {
        if (m.startsWith(LOOPBACK_OAUTH_MODULE_PREFIX)) {
          var oauthModule = m.substr(LOOPBACK_OAUTH_MODULE_PREFIX.length);
          this.oauthProviders.push(oauthModule);
        }
      }
      
      if (this.oauthProviders.length === 0) {
        for (var i in this.permissionValues) {
          var value = this.permissionValues[i].value;
          if (value === ACL.SECURITY_SCOPE) {
            this.permissionValues.splice(i, 1);
           }
         }        
       }
       
      done(err);
    }.bind(this));
  },

  askForModel: function() {
    var modelChoices =
      [{ name: '(all existing models)', value: null }]
      .concat(this.editableModelNames);

    var prompts = [
      {
        name: 'model',
        message: 'Select the model to apply the ACL entry to:',
        type: 'list',
        default: 0,
        choices: modelChoices
      }
    ];

    return this.prompt(prompts).then(function(answers) {
      this.modelName = answers.model;
      if (this.modelName) {
        this.modelDefinition = this.projectModels.filter(function(m) {
          return m.name === answers.model;
        })[0];
      }
    }.bind(this));
  },
  
  loadChosenModelMethods: function() {
    var done = this.async();
	  var subProcessModuleForRunningSLServer = '/aclSubprocess.js';
	
	  var cp = require('child_process');
	  var invokePath = require.resolve(__dirname + subProcessModuleForRunningSLServer);
	  var child = cp.fork(invokePath, [this.modelName], { silent: true });  // args = [this.modelName]
	
	  var childProcessSentResponse = false;

	  child.once('message', function(methodNamesArray) {
		  childProcessSentResponse = true;
          if (methodNamesArray.length > 0) {
            methodNames = [];       
            methodNames = methodNames.concat(methodNamesArray);
            methodNames.push('other');
          }
		  done();
	  }.bind(this));
	
	  setTimeout(function() {
		  if (!childProcessSentResponse) {
			  done();
		  }
	  }, 5000);
  },
  
  askForParameters: function() {
    var prompts = [
      {
        name: 'scope',
        message: 'Select the ACL scope:',
        type: 'list',
        default: 'all',
        choices: [
          { name: 'All methods and properties', value: 'all' },
          { name: 'A single method', value: 'method' },
          /* not supported by loopback yet
          { name: 'A single property', value: 'property' }
          */
        ]
      },
      {
        name: 'property',
        message: 'Select the method name:',
        type: 'list',
        choices: methodNames,
        when: function(answers) {
          return answers.scope === 'method';
        }
      },
      {
        name: 'property',
        message: 'Enter the method name',
        when: function(answers) {
          return answers.property === 'other';
        }
      },
      {
        name: 'property',
        message: 'Enter the property name',
        when: function(answers) {
          return answers.scope === 'property';
        }
      },
      {
        name: 'accessType',
        message: 'Select the access type:',
        type: 'list',
        default: '*',
        when: function(answers) {
          return answers.scope === 'all';
        },
        choices: this.accessTypeValues,
      },
      {
        name: 'role',
        message: 'Select the role',
        type: 'list',
        default: '$everyone',
        choices: this.roleValues.concat(['other']),
      },
      {
        name: 'customRole',
        message:
          'Enter the role name:',
        when: function(answers) {
          return answers.role === 'other';
        }
      },
      {
        name: 'permission',
        message: 'Select the permission to apply',
        type: 'list',
        choices: this.permissionValues,
      },  
      {
        name: 'authProvider',
        message: 'Select the auth provider:',
        type: 'list',
        choices: this.oauthProviders,
        when: function(answers) {
          return (answers.permission === ACL.SECURITY_SCOPE);
        }
      },
      {
        name: 'authServerName',
        message: 'Select the auth server:',
        type: 'list',
        choices: authServersList,
        when: function(answers) {
          chosenProvider = answers.authProvider;
          loadAuthServersEventEmitter.emit('loadAuthServersEvent');
          return (answers.permission === ACL.SECURITY_SCOPE);
        }
      },
      {
        name: 'newAuthServerName',
        message: 'Enter auth server name:',
        type: 'string',
        when: function(answers) {
          return (answers.authServerName === CREATE_NEW_AUTH_SERVER_STRING);
        }
      },
      {
        name: 'authServerURL',
        message: 'Enter auth server url:',
        type: 'string',
        store: true,
        when: function(answers) {
          return (answers.authServerName === CREATE_NEW_AUTH_SERVER_STRING);
        }
      },
      {
        name: 'authScope',
        message: 'Enter scope:',
        type: 'string',
        store: true,
        when: function(answers) {
          return answers.permission === ACL.SECURITY_SCOPE;
        }
      }
    ];

    return this.prompt(prompts).then(function(answers) {
      var accessType = answers.accessType;
      if (answers.scope === 'method') {
        accessType = 'EXECUTE';
      }
      if (answers.authServerName) {
        if (answers.newAuthServerName) {
          this.authServerName = answers.newAuthServerName;
          this.authServerURL = answers.authServerURL;
          this.addNewServerURL = true;
        }
        else {
          this.authServerName = answers.authServerName;
          var endOfServerNameIndex = this.authServerName.indexOf(' <url: ');
          if (endOfServerNameIndex !== -1) {
				        this.authServerName = this.authServerName.substring(0, endOfServerNameIndex);
          }
        }
      }

      this.aclDef = {
        property: answers.property,
        accessType: accessType,
        principalType: 'ROLE', // TODO(bajtos) support all principal types
        principalId: answers.customRole || answers.role,
        permission: answers.permission,
        authScope: answers.authScope,
        authServerName: this.authServerName
      };
    }.bind(this));
  },

  authServerDetailsGeneration: function() {
	  var done = this.async();
	  if (this.aclDef.permission === ACL.SECURITY_SCOPE && this.addNewServerURL) {
        this.saveAuthServerHelperMethod(this.authServerName, this.authServerURL);
	  }
    done();
  },
  
  acl: function() {
    var done = this.async();

    var aclDef = this.aclDef;
    var filter = this.modelName ?
      { where: { name: this.modelName }, limit: 1 } :
    {} /* all models, force refresh */;

    wsModels.ModelDefinition.find(filter, function(err, models) {
      if (err) {
        return done(err);
      }

      var firstError = true;
      async.eachSeries(models, function(model, cb) {
        model.accessControls.create(aclDef, function(err) {
          if (err && firstError) {
            helpers.reportValidationError(err);
            firstError = false;
          }
          cb(err);
        });
      }, done);
    });
  },

  saveProject: actions.saveProject
});

function loadAuthorizationServersList() {
  var config = fs.readJsonSync(COMPONENT_CONFIG_PATH, { throws: false });
  var loopbackOAuthComponentModuleName = LOOPBACK_OAUTH_MODULE_PREFIX + chosenProvider;
  var indexToEnterLastElementAt = 0;
  // extracting the chosen auth provider servers list
  if (config[loopbackOAuthComponentModuleName]) {
    var authServerObjectsArray = config[loopbackOAuthComponentModuleName].authorizationServers;
    // Iterate through the JSON array of authorization servers in component-config file
    indexToEnterLastElementAt = authServerObjectsArray.length;
    for (var i in authServerObjectsArray) {
      authServersList[i] = authServerObjectsArray[i].name;
      authServersList[i] += ' <url: ';
      authServersList[i] += authServerObjectsArray[i].url;
      authServersList[i] += '>';
    }
  }
  authServersList[indexToEnterLastElementAt] = CREATE_NEW_AUTH_SERVER_STRING;
}

