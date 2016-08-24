'use strict';

const Boom = require('boom');
const URL = require('url');

const UUID = require('./uuid');
const BearerStore = require('./stores/bearer-store');
// const CookieStore = require('./stores/cookie-store');
// const SessionStore = require('./stores/session-store');
const Config = require('keycloak-auth-utils').Config;
const GrantManager = require('keycloak-auth-utils').GrantManager;

// Declare internals
const internals = {};

exports.register = (plugin, options, next) => {
  // If options.keycloakConfig is null, Config() will search for `keycloak.json`.
  internals.config = new Config(options.keycloakConfig);
  internals.grantManager = new GrantManager(internals.config);
  internals.stores = [BearerStore];

  if (options.config && options.config.store && options.cookies) {
    throw new Error('Either `store` or `cookies` may be set, but not both');
  }

  // if (options.config && options.config.store) {
  //     internals.stores.push(new SessionStore(options.config.store))
  // } else if (options.config && options.config.cookies) {
  //     internals.stores.push(CookieStore)
  // }

  plugin.auth.scheme('keycloak', internals.implementation);
  next();
};

exports.register.attributes = {
  pkg: require('../package.json')
};

internals.implementation = (server, options) => {
  server.route({
    path: '/logout',
    method: 'GET',
    handler: (request, reply) => {
      if (request.yar.id) {
        // Delete tokens from yar
        request.yar.clear(request.yar.id);
      }

      const host = request.info.host;
      const protocol = request.connection.info.protocol;
      // const url = request.url.path;

      const redirectUrl = `${protocol}://${host}/`;

      reply.redirect(internals.logoutUrl(redirectUrl));
    }
  });

  return {
    authenticate: (request, reply) => {
      internals.result = {
        credentials: {}
      };

      internals.setup(request);

      internals.postAuth(request, reply, (grant) => {
        internals.getGrant(request, reply, (grant) => {
          request.kauth.grant = grant;
          internals.protect(request, reply);
        });
      });
    }
  };
};

internals.setup = (request) => {
  request.kauth = {};
};

internals.getGrant = (request, reply, next) => {
  const sessionId = request.yar.id;
  const yarSession = request.yar.get(sessionId);

  if (!yarSession || !yarSession.grant) {
    return next();
  }

  const grantFromYar = yarSession.grant;

  // next(grantFromYar)
  const grant = internals.grantManager.createGrant(grantFromYar.__raw);

  // console.log(grant)

  // next(grantFromYar)

  internals.grantManager.ensureFreshness(grant).then((grant) => {
    next(grant);
  }).catch(() => {
    next();
  });
};

internals.forceLogin = (request, reply) => {
  const host = request.info.host;
  const protocol = request.connection.info.protocol;
  const url = request.url.path;

  const redirectUrl = `${protocol}://${host}${url}?auth_callback=1`;

  if (request.yar) {
    console.log(request.yar.id);
    request.yar.set(request.yar.id, {'auth_redirect_uri': redirectUrl});
  }

  const uuid = UUID();

  const loginUrl = internals.loginUrl(uuid, redirectUrl);

  return reply.redirect(loginUrl);
};

internals.postAuth = (request, reply, next) => {
  if (!request.query.auth_callback) {
    return next();
  }

  if (request.query.error) {
    return reply(Boom.forbidden('Access denied'));
  }

  // do grant stuff
  internals.getGrantFromCode(request.query.code, request, reply, (err, grant) => {
    if (err) {
      return reply(Boom.forbidden('Access denied'));
    }

    // Store the grant in the yar jar
    const sessionId = request.yar.id;
    const currentYarStore = request.yar.get(sessionId);
    const mergedStore = Object.assign({}, currentYarStore, {grant: grant});

    request.yar.set(sessionId, mergedStore);

    let urlParts = {
      pathname: request.url.pathname,
      query: request.query
    };

    delete urlParts.query.code;
    delete urlParts.query.auth_callback;
    delete urlParts.query.state;

    let cleanUrl = URL.format(urlParts);

    reply.redirect(cleanUrl);
  // next(grant)
  });
};

internals.getGrantFromCode = (code, request, reply, next) => {
  // if (internals.stores.length < 2) {
  //     // bearer-only, cannot do this
  //     throw new Error('Cannot exchange code for grant in bearer-only mode')
  // }

  const sessionId = request.yar.id;
  const authUrl = request.yar.get(request.yar.id);

  // THe auth-utils is expecting our request object to look like express's request.session
  const req = {
    session: {
      auth_redirect_uri: authUrl.auth_redirect_uri
    }
  };
  internals.grantManager.obtainFromCode(req, code, sessionId, null, next);
};

internals.protect = (request, reply) => {
  let guard;

  if (request.kauth && request.kauth.grant) {
    if (!guard) {
      return reply.continue({credentials: {'keycloak-token': request.kauth.grant.__raw}});
    }

    return internals.accessDenied(reply);
  }

  if (internals.config.bearerOnly) {
    return internals.accessDenied(reply);
  } else {
    return internals.forceLogin(request, reply);
  }
};

internals.accessDenied = (reply) => {
  return reply(Boom.forbidden('Access denied'));
};

internals.loginUrl = (uuid, redirectUrl) => {
  return internals.config.realmUrl +
    '/protocol/openid-connect/auth' +
    '?client_id=' + encodeURIComponent(internals.config.clientId) +
    '&state=' + encodeURIComponent(uuid) +
    '&redirect_uri=' + encodeURIComponent(redirectUrl) +
    '&scope=openid' +
    '&response_type=code';
};

internals.logoutUrl = (redirectUrl) => {
  return internals.config.realmUrl +
    '/protocol/openid-connect/logout' +
    '?redirect_uri=' + encodeURIComponent(redirectUrl);
};
