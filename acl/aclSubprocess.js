'use strict';

// start SL server
var app = require(process.cwd() + '/server/server.js');
app.start();

// receive the model name from the parent process
var modelName = process.argv[2];
var methodNames = [];

Object.keys(app.models).forEach(function (model) {
    if (model === modelName) {
        var appModel = app.models[model];
        var modelMethods = appModel.sharedClass._methods;
        for (var i = 0; i < modelMethods.length; i++) {
            var methodInfo = modelMethods[i];
            methodNames.push(methodInfo.name);
        }
    }
});

// send method names array to the parent process
process.send(methodNames);
app.stop();