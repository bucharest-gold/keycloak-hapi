'use strict';

const Hapi = require('hapi');
const hogan = require('hapi-hogan');
const Keycloak = require('../');

const server = new Hapi.Server();

server.connection({
    port: 3000
});

const yarOptions = {
    cookieOptions: {
        isSecure: false,
        password: 'the-password-must-be-at-least-32-characters-long'
    }
};

server.register([require('vision'), {register: require('yar'), options: yarOptions }, {register: Keycloak, options: {config: {store: 'yar'}}}], (err) => {
    if (err) {
        throw err;
    }

    server.auth.strategy('keycloak', 'keycloak');

    server.views({
        relativeTo:__dirname,
        path:'./views',
        engines: {
            html:{
                module: hogan,
                compileMode: 'sync'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/',
        handler: (req, res) => {
            res.view('index');
        }
    });

    server.route({
        method: 'GET',
        path: '/login',
        config: {
            auth: 'keycloak'
        },
        handler: (req, res) => {
            res.view('index', {
                result: JSON.stringify(JSON.parse(req.auth.credentials['keycloak-token']), null, 4),
                event: '1. Authentication\n2. Login'
            });
        }
    });

    server.start((err) => {
        if (err) {
            throw err;
        }

        console.log(`Server running at: ${server.info.uri}`);
    });
});
