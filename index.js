/**
 * index.js
 * OpenIDConnect provider
 * Based on OAuth 2.0 provider by Amir Malik
 *
 * @author Agustín Moyano
 */

var EventEmitter = require('events').EventEmitter,
querystring = require('querystring'),
//serializer = require('serializer'),
//hashlib = require('hashlib2'),
modelling = require('modelling'),
sailsRedis = require('sails-redis'),
crypto = require('crypto'),
_ = require('lodash'),
extend = require('extend'),
url = require('url'),
Q = require('q'),
jwt = require('jsonwebtoken'),
util = require('util'),
base64url = require('base64url'),
cleanObj = require('clean-obj');


var defaults = {
        login_url: '/login',
        consent_url: '/consent',
        error_url: '/error',
        logger: null,
        iss: null,
        key: null,
        scopes: {
            openid: {
              info: 'Informs the Authorization Server that the Client is making an OpenID Connect request.',
              claims: null
            },
            profile:{
              info: 'Access to the End-User\'s default profile Claims.',
              claims: ['name', 'family_name', 'given_name', 'middle_name', 'nickname', 'preferred_username', 'profile', 'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at']
            },
            email: {
              info: 'Access to the email and email_verified Claims.',
              claims: ['email', 'email_verified']
            },
            address: {
              info: 'Access to the address Claim.',
              claims: ['address']
            },
            phone: {
              info: 'Access to the phone_number and phone_number_verified Claims.',
              claims: ['phone_number', 'phone_number_verified']
            },
            offline_access: {
              info: 'Grants access to the End-User\'s UserInfo Endpoint even when the End-User is not present (not logged in).',
              claims: null
            }
        },
        policies:{
            loggedIn: function(req, res, next) {
                if(req.session.user) {
                    next();
                } else {
                    var q = req.originalUrl;
                    if(req.parsedParams) {
                      q = req.path+'?'+querystring.stringify(req.parsedParams);
                      req.session.acr_values = req.parsedParams.acr_values;
                      req.session.client_id = req.parsedParams.client_id;
                    }
                    res.redirect(this.settings.login_url+'?'+querystring.stringify({return_url: q}));
                }
            },
        },
        adapters: {
            redis: sailsRedis
        },
        connections: {
            def: {
                adapter: 'redis'
            }
        },
        models: {
                user: {
                    identity: 'user',
                    connection: 'def',
                    schema: true,
                    policies: 'loggedIn',
                    attributes: {
                        name: {type: 'string', required: true, unique: true},
                        given_name: {type: 'string', required: true},
                        middle_name: 'string',
                        family_name: {type: 'string', required: true},
                        profile: 'string',
                        email: {type: 'string', email: true, required: true, unique: true},
                        password: 'string',
                        picture: 'binary',
                        birthdate: 'date',
                        gender: 'string',
                        phone_number: 'string',
                        samePassword: function(clearText) {
                            var sha256 = crypto.createHash('sha256');
                            sha256.update(clearText);
                            return this.password == sha256.digest('hex');
                        }
                    },
                    beforeCreate: function(values, next) {
                        if(values.password) {
                            if(values.password != values.passConfirm) {
                                return next('Password and confirmation does not match');
                            }
                            var sha256 = crypto.createHash('sha256');
                            sha256.update(values.password);
                            values.password = sha256.digest('hex');
                        }
                        next();
                    },
                    beforeUpdate: function(values, next) {
                        if(values.password) {
                            if(values.password != values.passConfirm) {
                                return next('Password and confirmation does not match');
                            }
                            var sha256 = crypto.createHash('sha256');
                            sha256.update(values.password);
                            values.password = sha256.digest('hex');
                        }
                        next();
                    }
                },
                client: {
                    identity: 'client',
                    connection: 'def',
                    schema: true,
                    policies: 'loggedIn',
                    attributes: {
                        key: {type: 'string', required: true, unique: true},
                        secret: {type: 'string', required: true, unique: true},
                        simmetricKey: {type: 'string', required: true},
                        name: {type: 'string', required: true},
                        image: 'binary',
                        user: {model: 'user'},
                        redirect_uris: {type:'array', required: true},
                        credentialsFlow: {type: 'boolean', defaultsTo: false}
                    },
                    beforeCreate: function(values, next) {
                        if(!values.key) {
                            var sha256 = crypto.createHash('sha256');
                            sha256.update(values.name);
                            sha256.update(Math.random()+'');
                            values.key = sha256.digest('hex');
                        }
                        if(!values.secret) {
                            var sha256 = crypto.createHash('sha256');
                            sha256.update(values.key);
                            sha256.update(values.name);
                            sha256.update(Math.random()+'');
                            values.secret = sha256.digest('hex');
                        }
                        if(!values.simmetricKey) {
                            var sha256 = crypto.createHash('sha256');
                            sha256.update(values.key);
                            sha256.update(values.name);
                            sha256.update(values.secret);
                            sha256.update(Math.random()+'');
                            values.simmetricKey = sha256.digest('hex');
                        }
                        next();
                    }
                },
                consent: {
                    identity: 'consent',
                    connection: 'def',
                    policies: 'loggedIn',
                    attributes: {
                        user: {model: 'user', required: true},
                        client: {model: 'client', required: true},
                        scopes: 'array'
                    }
                },
                auth: {
                    identity: 'auth',
                    connection: 'def',
                    policies: 'loggedIn',
                    attributes: {
                        client: {model: 'client',   required: true},
                        scope: {type: 'array', required: true},
                        user: {model: 'user', required: true},
                        sub: {type: 'string', required: true},
                        code: {type: 'string', required: true},
                        redirectUri: {type: 'url', required: true},
                        responseType: {type: 'string', required: true},
                        status: {type: 'string', required: true},
                        accessTokens: {
                            collection: 'access',
                            via: 'auth'
                        },
                        refreshTokens: {
                            collection: 'refresh',
                            via: 'auth'
                        }
                    }
                },
                access: {
                    identity: 'access',
                    connection: 'def',
                    attributes: {
                        token: {type: 'string', required: true},
                        type: {type: 'string', required: true},
                        idToken: 'string',
                        expiresIn: 'integer',
                        scope: {type: 'array', required: true},
                        client: {model: 'client', required: true},
                        user: {model: 'user', required: true},
                        auth: {model: 'auth'}
                    }
                },
                refresh: {
                    identity: 'refresh',
                    connection: 'def',
                    attributes: {
                        token: {type: 'string', required: true},
                        scope: {type: 'array', required: true},
                        auth: {model: 'auth', required: true},
                        status: {type: 'string', required: true}
                    }
                }
        }
};

function parse_authorization(authorization) {
    if(!authorization)
        return null;

    var parts = authorization.split(' ');

    if(parts.length != 2 || parts[0] != 'Basic')
        return null;

    var creds = new Buffer(parts[1], 'base64').toString(),
    i = creds.indexOf(':');

    if(i == -1)
        return null;

    var username = creds.slice(0, i);
    password = creds.slice(i + 1);

    return [username, password];
}


function log(self, s) {
  if(self.settings.logger) self.settings.logger('OIDC module - '+s);
}


function logError(self, s) {
  if(self.settings.errorLogger) self.settings.errorLogger('OIDC module - '+s);
}


function OpenIDConnect(options) {
    this.settings = extend(true, {}, defaults, options);

    //allow removing attributes, by marking them as null
    cleanObj(this.settings.models, true);

    for(var i in this.settings.policies) {
        this.settings.policies[i] = this.settings.policies[i].bind(this);
    }

    if(this.settings.alien) {
        for(var i in alien) {
            if(this.settings.models[i]) delete this.settings.models[i];
        }
    }

    if(this.settings.orm) {
        this.orm = this.settings.orm;
        for(var i in this.settings.policies) {
            this.orm.setPolicy(true, i, this.settings.policies[i]);
        }
    } else {

        this.orm = new modelling({
            models: this.settings.models,
            adapters: this.settings.adapters,
            connections: this.settings.connections,
            app: this.settings.app,
            policies: this.settings.policies
        });
    }
}

OpenIDConnect.prototype = new EventEmitter();

OpenIDConnect.prototype.done = function() {
    this.orm.done();
};

OpenIDConnect.prototype.model = function(name) {
    return this.orm.model(name);
}

OpenIDConnect.prototype.use = function(name) {
    var alien = {};
    if(this.settings.alien) {
        var self = this;
        if(!name) {
            alien = this.settings.alien;
        } else {
            var m;
            if(_.isPlainObject(name) && name.models) {
                m = name.models;
            }
            if(util.isArray(m||name)) {
                (m||name).forEach(function(model) {
                    if(self.settings.alien[model]) {
                        alien[model] = self.settings.alien[model];
                    }
                });
            } else if(self.settings.alien[m||name]) {
                alien[m||name] = self.settings.alien[m||name];
            }
        }
    }
    return [this.orm.use(name), function(req, res, next) {
        extend(req.model, alien);
        next();
    }];
};

OpenIDConnect.prototype.getOrm = function() {
    return this.orm;
}
/*OpenIDConnect.prototype.getClientParams = function() {
    return this.orm.client.getParams();
};*/

/*OpenIDConnect.prototype.searchClient = function(parts, callback) {
    return new this.orm.client.reverse(parts, callback);
};

OpenIDConnect.prototype.getUserParams = function() {
    return this.orm.user.getParams();
};

OpenIDConnect.prototype.user = function(params, callback) {
    return new this.orm.user(params, callback);
};

OpenIDConnect.prototype.searchUser = function(parts, callback) {
    return new this.orm.user.reverse(parts, callback);
};*/

OpenIDConnect.prototype.errorHandle = function(req, res, uri, error, desc) {
    if(uri) {
        var redirect = url.parse(uri,true);
        if(redirect.search) delete redirect.search;
        redirect.query.error = error; //'invalid_request';
        redirect.query.error_description = desc; //'Parameter '+x+' is mandatory.';
        //if(req.param('state')) redirect.query.state = req.param('state');
        res.redirect(url.format(redirect));
    } else {
        res.redirect(this.settings.error_url+'?'+querystring.stringify({
          error: error,
          error_description: desc
        }));
    }
};

OpenIDConnect.prototype.endpointParams = function (spec, req, res, next) {
    try {
        req.parsedParams = this.parseParams(req, res, next, spec);
        next();
    } catch(err) {
        this.errorHandle(req, res, err.uri, err.error, err.msg);
    }
}

OpenIDConnect.prototype.parseParams = function(req, res, next, spec) {
    var params = {};
    var r = req.query.redirect_uri||req.body.redirect_uri||null;
    for(var i in spec) {
        var x = req.query[i]||req.body[i];
        if(x) {
            params[i] = x;
        }
    }

    for(var i in spec) {
        var x = params[i];
        if(!x) {
            var error = false;
            if(typeof spec[i] == 'boolean') {
                error = spec[i];
            } else if (_.isPlainObject(spec[i])) {
                for(var j in spec[i]) {
                    if(!util.isArray(spec[i][j])) {
                        spec[i][j] = [spec[i][j]];
                    }
                    spec[i][j].forEach(function(e) {
                        if(!error) {
                            if(util.isRegExp(e)) {
                                error = e.test(params[j]);
                            } else {
                                error = e == params[j];
                            }
                        }
                    });
                }
            } else if (_.isFunction(spec[i])) {
                error = spec[i](params);
            }

            if(error) {
                throw {type: 'error', uri: r, error: 'invalid_request', msg: 'Parameter '+i+' is mandatory'};
                //this.errorHandle(req, res, r, 'invalid_request', 'Parameter '+i+' is mandatory.');
                //return;
            }
        }
    }
    return params;
};

/**
 * login
 *
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 *
 * app.post('/login', oidc.login(),  afterLogin, loginErrorHandler);
 *
 * This calls verification strategy and creates session.
 * Verification strategy must have two parameters: req and callback function with two parameters: error and user
 *
 *
 */

OpenIDConnect.prototype.login = function(validateUser) {
    var self = this;

    return [self.use({policies: {loggedIn: false}, models: 'user'}),
            function(req, res, next) {
                validateUser(req, /*next:*/function(error,user) {
                    if(!error && !user) {
                        error = new Error('User not validated');
                    }
                    if(!error) {
                        if(user.id) {
                            req.session.user = user.id;
                        } else {
                            delete req.session.user;
                        }
                        if(user.sub) {
                            if(typeof user.sub ==='function') {
                                req.session.sub = user.sub();
                            } else {
                                req.session.sub = user.sub;
                            }
                        } else {
                            delete req.session.sub;
                        }
                        return next();
                    } else {
                        return next(error);
                    }
                });
    }];
};

/**
 * auth
 *
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 *
 * app.get('/authorization', oidc.auth());
 *
 * This is the authorization endpoint, as described in http://tools.ietf.org/html/rfc6749#section-3.1
 *
 */
OpenIDConnect.prototype.auth = function() {
    var self = this;
    var spec = {
            response_type: true,
            client_id: true,
            scope: true,
            redirect_uri: true,
            state: false,
            nonce: function(params){
                return params.response_type.indexOf('id_token')!==-1;
            },
            display: false,
            prompt: false,
            max_age: false,
            ui_locales: false,
            claims_locales: false,
            id_token_hint: false,
            login_hint: false,
            acr_values: false,
            response_mode: false
    };
    return [function(req, res, next) {
                self.endpointParams(spec, req, res, next);
            },
            self.use(['client', 'consent', 'auth', 'access']),
            function(req, res, next) {
                log(self, 'Auth EP - params are '+JSON.stringify(req.parsedParams));
                Q(req.parsedParams).then(function(params) {
                    //Step 2: Check if response_type is supported, client_id is valid and redirect_uri is registered

                    var deferred = Q.defer();
                    switch(params.response_type) {
                    case 'none':
                    case 'code':
                    case 'token':
                    case 'id_token':
                        break;
                    default:
                        //var error = false;
                        var sp = params.response_type.split(' ');
                        sp.forEach(function(response_type) {
                            if(['code', 'token', 'id_token'].indexOf(response_type) == -1) {
                                throw {type: 'error', uri: params.redirect_uri, error: 'unsupported_response_type', msg: 'Response type '+response_type+' not supported.'};
                            }
                        });
                    }
                    req.model.client.findOne({key: params.client_id}, function(err, client) {
                        if(err || !client || client === '') {
                            deferred.reject({type: 'error', uri: params.redirect_uri, error: 'invalid_client', msg: 'Client '+params.client_id+' doesn\'t exist.'});
                        } else {
                            req.session.client_id = client.id;
                            req.session.client_secret = client.secret;
                            req.session.client_simmetricKey = client.simmetricKey;
                            if(client.redirect_uris.indexOf(params.redirect_uri) === -1) {
                              deferred.reject({type: 'error', uri: null, error: 'invalid_uri', msg: 'Redirect uri is not valid'});
                            }
                            else {
                              deferred.resolve(params);
                            }
                        }
                    });

                    return deferred.promise;
                }).then(function(params){
                    //Step 3: Check if scopes are valid, and if consent was given.

                    var deferred = Q.defer();
                    if(typeof params.scope !== 'string') {
                      throw {type: 'error', uri: params.redirect_uri, error: 'invalid_scope', msg: 'Malformed scope definition'};
                    }
                    var reqsco = params.scope.split(' ');
                    req.session.scopes = {};
                    var promises = [];
                    req.model.consent.findOne({user: req.session.user, client: req.session.client_id}, function(err, consent) {
                            if(reqsco.indexOf('openid') === -1) {
                                var innerDef = Q.defer();
                                innerDef.reject({type: 'error', uri: params.redirect_uri, error: 'invalid_scope', msg: 'Missing openid scope'});
                                promises.push(innerDef.promise);
                            }
                            reqsco.forEach(function(scope) {
                                var innerDef = Q.defer();
                                if(!self.settings.scopes[scope]) {
                                    innerDef.reject({type: 'error', uri: params.redirect_uri, error: 'invalid_scope', msg: 'Scope '+scope+' not supported'});
                                }
                                else if(!consent) {
                                    req.session.scopes[scope] = {ismember: false, explain: self.settings.scopes[scope].info};
                                    innerDef.resolve(true);
                                } else {
                                    var inScope = consent.scopes.indexOf(scope) !== -1;
                                    req.session.scopes[scope] = {ismember: inScope, explain: self.settings.scopes[scope].info};
                                    innerDef.resolve(!inScope);
                                }
                                promises.push(innerDef.promise);
                            });

                            Q.allSettled(promises).then(function(results){
                                var pError = {};
                                for(var i = 0; i<results.length; i++) {
                                    if(results[i].state !== 'fulfilled') {
                                        pError = results[i].reason;
                                        break;
                                    }
                                }
                                if(!pError.type) {
                                  for(var i = 0; i<results.length; i++) {
                                    if(results[i].value) {
                                      var q = req.path+'?'+querystring.stringify(params);
                                      pError.type = 'redirect';
                                      pError.uri = self.settings.consent_url+'?'+querystring.stringify({return_url: q});
                                      break;
                                    }
                                  }
                                }
                                if(pError.type) {
                                    deferred.reject(pError);
                                } else {
                                    deferred.resolve(params);
                                }
                            });
                    });

                    return deferred.promise;
                }).then(function(params){
                    //Step 5: create responses
                    if(params.response_type == 'none') {
                        return {params: params, resp: {}};
                    } else {
                        var deferred = Q.defer();
                        var promises = [];

                        var rts = params.response_type.split(' ');

                        rts.forEach(function(rt) {
                            var def = Q.defer();
                            promises.push(def.promise);
                            switch(rt) {
                            case 'code':
                                var createToken = function() {
                                    var token = crypto.createHash('md5').update(params.client_id).update(Math.random()+'').digest('hex');
                                    req.model.auth.findOne({code: token}, function(err, auth){
                                        if(!auth) {
                                            setToken(token);
                                        } else {
                                            createToken();
                                        }
                                    });
                                };
                                var setToken = function(token) {
                                    req.model.auth.create({
                                        client: req.session.client_id,
                                        scope: params.scope.split(' '),
                                        user: req.session.user,
                                        sub: req.session.sub||req.session.user,
                                        code: token,
                                        nonce: params.nonce,
                                        acr: req.session.acr,
                                        amr: req.session.amr,
                                        auth_time: new Date(),
                                        redirectUri: params.redirect_uri,
                                        responseType: params.response_type,
                                        status: 'created'
                                    }).exec(function(err, auth) {
                                        if(!err && auth) {
                                            setTimeout(function() {
                                                req.model.auth.findOne({code: token}, function(err, auth) {
                                                    if(auth && auth.status == 'created') {
                                                        auth.destroy();
                                                    }
                                                });
                                            }, 1000*60*10); //10 minutes
                                            def.resolve({code: token});
                                        } else {
                                            def.reject(err||'Could not create auth');
                                        }
                                    });

                                };
                                createToken();
                                break;
                            case 'id_token':
                                var d = Math.round(new Date().getTime()/1000);
                                //var id_token = {
                                def.resolve({id_token: {
                                        iss: self.settings.iss||req.protocol+'://'+req.headers.host,
                                        sub: req.session.sub||req.session.user,
                                        aud: new Array(params.client_id),
                                        exp: d+3600,
                                        iat: d,
                                        nonce: params.nonce,
                                        azp: params.client_id
                                }});
                                //def.resolve({id_token: jwt.encode(id_token, req.session.client_secret)});
                                break;
                            case 'token':
                                var createToken = function() {
                                    var token = crypto.createHash('md5').update(params.client_id).update(Math.random()+'').digest('hex');
                                    req.model.access.findOne({token: token}, function(err, access) {
                                        if(!access) {
                                            setToken(token);
                                        } else {
                                            createToken();
                                        }
                                    });
                                };
                                var setToken = function(token) {
                                    var obj = {
                                            token: token,
                                            type: 'Bearer',
                                            expiresIn: 3600,
                                            user: req.session.user,
                                            client: req.session.client_id,
                                            scope: params.scope.split(' ')
                                    };
                                    req.model.access.create(obj, function(err, access) {
                                        if(!err && access) {
                                            setTimeout(function() {
                                                access.destroy();
                                            }, 1000*3600); //1 hour

                                            def.resolve({
                                                access_token: obj.token,
                                                token_type: obj.type,
                                                expires_in: obj.expiresIn
                                            });
                                        }
                                    });
                                };
                                createToken();
                                break;
                            }
                        });

                        Q.allSettled(promises).then(function(results) {
                            var resp = {};
                            for(var i in results) {
                                resp = extend(resp, results[i].value||{});
                            }
                            if(resp.access_token && resp.id_token) {
                                var hbuf = crypto.createHmac('sha256', req.session.client_simmetricKey).update(resp.access_token).digest();
                                resp.id_token.at_hash = base64url(hbuf.toString('ascii', 0, hbuf.length/2));
                                var p = {};
                                p.azp = resp.id_token.azp;
                                //p.at_hash = resp.id_token.at_hash;
                                if(resp.id_token.nonce) p.nonce = resp.id_token.nonce;
                                var opt = {};
                                opt.audience = resp.id_token.aud;
                                opt.subject = resp.id_token.sub;
                                opt.issuer = resp.id_token.iss;
                                opt.expiresIn = 3600;
                                opt.headers = self.settings.key?{kid: self.settings.key.kid}:{};
                                //opt.algorithm = 'RS256';
                                var key = self.settings.key?self.settings.key.val:req.session.client_simmetricKey;
                                resp.id_token = jwt.sign(p, key, opt);
                            }
                            deferred.resolve({params: params, type: params.response_type != 'code'?'f':'q', resp: resp});
                        });

                        return deferred.promise;
                    }
                })
                .then(function(obj) {
                    var params = obj.params;
                    var resp = obj.resp;
                    var uri = url.parse(params.redirect_uri, true);
                    if(uri.search) delete uri.search;
                    if(params.state) {
                        resp.state = params.state;
                    }
                    if(params.redirect_uri) {
                        if(obj.type == 'f') {
                            uri.hash = querystring.stringify(resp);
                        } else {
                            uri.query = extend(uri.query, resp);
                        }
                        log(self, 'Auth response is '+JSON.stringify(uri));
                        res.redirect(url.format(uri));
                    }
                })
                .fail(function(error) {
                    logError(self, 'Auth EP - '+JSON.stringify(error));
                    if(error.type == 'error') {
                        self.errorHandle(req, res, error.uri, error.error, error.msg);
                    } else {
                        res.redirect(error.uri);
                    }
                });
            }
            ];
};

/**
 * consent
 *
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 *
 * app.post('/consent', oidc.consent());
 *
 * This method saves the consent of the resource owner to a client request, or returns an access_denied error.
 *
 */
OpenIDConnect.prototype.consent = function() {
    var self = this;
    return [self.use('consent'),
    function(req, res, next) {
        var accept = req.body.accept;
        var return_url = req.body.return_url||req.query.return_url;
        //var client_id = req.query.client_id || req.body.client_id || false;
        if(accept) {
            var scopes = [];
            for(var i in req.session.scopes) {
                scopes.push(i);
            }
            req.model.consent.destroy({user: req.session.user, client: req.session.client_id}, function(err, result) {
                req.model.consent.create({user: req.session.user, client: req.session.client_id, scopes: scopes}, function(err, consent) {
                    res.redirect(return_url);
                });
            });
        } else {
            var returl = url.parse(return_url, true);
            var redirect_uri = returl.query.redirect_uri;
            logError(self, 'Consent - access denied');
            self.errorHandle(req, res, redirect_uri, 'access_denied', 'Resource Owner denied Access.');
        }
    }];
};


/**
 * token
 *
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 *
 * app.get('/token', oidc.token());
 *
 * This is the token endpoint, as described in http://tools.ietf.org/html/rfc6749#section-3.2
 *
 */
OpenIDConnect.prototype.token = function() {
    var self = this;
    var spec = {
            grant_type: false,
            code: false,
            redirect_uri: false,
            refresh_token: false,
            scope: false
    };

    return [
        function(req, res, next) {
            self.endpointParams(spec, req, res, next)
        },

        self.use({policies: {loggedIn: false}, models:['client', 'consent', 'auth', 'access', 'refresh']}),

        function(req, res, next) {
            log(self, 'Token EP - params are '+JSON.stringify(req.parsedParams));
            var params = req.parsedParams;

            var client_key = req.body.client_id;
            var client_secret = req.body.client_secret;
            var client_simmetricKey = req.body.client_simmetricKey;

            if(!client_key || !client_secret) {
                var authorization = parse_authorization(req.headers.authorization);
                if(authorization) {
                    client_key = authorization[0];
                    client_secret = authorization[1];
                }
            }
            if(!client_key || !client_secret) {
                var error = {};
                error.error = 'invalid_client';
                error.msg = 'No client credentials found';
                logError(self, 'Token EP - '+JSON.stringify(error));
                res.append('Cache-Control', 'no-store');
                res.append('Pragma', 'no-cache');
                res.status(400).json({error: error.error, error_description: error.msg});
            } else {

                Q.fcall(function() {
                    //Step 2: check if client and secret are valid
                    var deferred = Q.defer();
                    req.model.client.findOne({key: client_key, secret: client_secret}, function(err, client){
                        if(err || !client) {
                            deferred.reject({type: 'error', error: 'invalid_client', msg: 'Client doesn\'t exist or invalid secret.'});
                        } else {
                            deferred.resolve(client);
                        }
                    });
                    return deferred.promise;
                })
                .then(function(client) {

                    var deferred = Q.defer();

                    switch(params.grant_type) {
                    //Client is trying to exchange an authorization code for an access token
                    case 'authorization_code':
                        //Step 3: check if code is valid and not used previously
                        req.model.auth.findOne({code: params.code})
                        .populate('accessTokens')
                        .populate('refreshTokens')
                        .populate('client')
                        .exec(function(err, auth) {
                            if(!err && auth) {
                                if(auth.status != 'created') {
                                    auth.refreshTokens.forEach(function(refresh) {
                                        refresh.destroy();
                                    });
                                    auth.accessTokens.forEach(function(access) {
                                        access.destroy();
                                    });
                                    auth.destroy();
                                    deferred.reject({type: 'error', error: 'invalid_grant', msg: 'Authorization code already used.'});
                                } else {
                                    //obj.auth = a;
                                    deferred.resolve({auth: auth, scope: auth.scope, client: client, user: auth.user, sub: auth.sub});
                                }
                            } else {
                                deferred.reject({type: 'error', error: 'invalid_grant', msg: 'Authorization code is invalid.'});
                            }
                        });

                        //Extra checks, required if grant_type is 'authorization_code'
                        return deferred.promise.then(function(obj){
                            //Step 4: check if grant_type is valid

                            if(obj.auth.responseType != 'code') {
                                throw {type: 'error', error: 'unauthorized_client', msg: 'Client cannot use this grant type.'};
                            }

                            //Step 5: check if redirect_uri is valid
                            if((obj.auth.redirectUri || params.redirect_uri) && obj.auth.redirectUri != params.redirect_uri) {
                                throw {type: 'error', error: 'invalid_grant', msg: 'Redirection URI does not match.'};
                            }

                            return obj;
                        });

                        break;

                        //Client is trying to exchange a refresh token for an access token
                    case 'refresh_token':

                        //Step 3: check if refresh token is valid and not used previously
                        req.model.refresh.findOne({token: params.refresh_token}, function(err, refresh) {
                            if(!err && refresh) {
                                req.model.auth.findOne({id: refresh.auth})
	                            .populate('accessTokens')
	                            .populate('refreshTokens')
                                .populate('client')
                                .exec(function(err, auth) {
                                    if(refresh.status != 'created') {
                                        auth.accessTokens.forEach(function(access){
                                            access.destroy();
                                        });
                                        auth.refreshTokens.forEach(function(refresh){
                                            refresh.destroy();
                                        });
                                        auth.destroy();
                                        deferred.reject({type: 'error', error: 'invalid_grant', msg: 'Refresh token already used.'});
                                    } else {
                                        refresh.status = 'used';
                                        refresh.save();
                                        deferred.resolve({auth: auth, client: client, user: auth.user, sub: auth.sub});
                                    }
                                });
                            } else {
                                deferred.reject({type: 'error', error: 'invalid_grant', msg: 'Refresh token is not valid.'});
                            }
                        });
                        return deferred.promise.then(function(obj){
                            if(params.scope) {
                                var scopes = params.scope.split(' ');
                                if(scopes.length) {
                                    scopes.forEach(function(scope) {
                                        if(obj.auth.scope.indexOf(scope) == -1) {
                                            throw {type: 'error', uri: params.redirect_uri, error: 'invalid_scope', msg: 'Scope '+scope+' was not granted for this token.'};
                                        }
                                    });
                                    obj.scope = scopes;
                                }
                            } else {
                                obj.scope = obj.auth.scope;
                            }

                            return obj;
                        });
                        break;
                    case 'client_credentials':
                        if(!client.credentialsFlow) {
                            deferred.reject({type: 'error', error: 'unauthorized_client', msg: 'Client cannot use this grant type.'});
                        } else {
                            deferred.resolve({scope: params.scope, auth: false, client: client});
                        }
                        return deferred.promise;
                        break;
                    default:
                        throw {type: 'error', error: 'unsupported_grant_type', msg: 'Invalid grant type value'};
                    }

                })
                .then(function(obj) {
                    //Check if code was issued for client
                    if(params.grant_type != 'client_credentials' && obj.auth.client.key != client_key) {
                        throw {type: 'error', error: 'invalid_grant', msg: 'The code was not issued for this client.'};
                    }

                    return obj;

                })
                .then(function(prev){
                    //Create access token
                    /*var scopes = obj.scope;
                    var auth = obj.auth;*/

                    var createToken = function(model, cb) {
                        var token = crypto.createHash('md5').update(Math.random()+'').digest('hex');
                        model.findOne({token: token}, function(err, response) {
                            if(!response) {
                                cb(token);
                            } else {
                                createToken(model, cb);
                            }
                        });
                    };
                    var setToken = function(access, refresh) {
                        req.model.refresh.create({
                            token: refresh,
                            scope: prev.scope,
                            status: 'created',
                            auth: prev.auth?prev.auth.id:null
                        },
                        function(err, refresh) {
                            setTimeout(function() {
                                refresh.destroy();
                                if(refresh.auth) {
                                    req.model.auth.findOne({id: refresh.auth})
		                            .populate('accessTokens')
		                            .populate('refreshTokens')
                                    .exec(function(err, auth) {
                                        if(auth && !auth.accessTokens.length && !auth.refreshTokens.length) {
                                            auth.destroy();
                                        }
                                    });
                                }
                            }, 1000*3600*5); //5 hours

                            var d = Math.round(new Date().getTime()/1000);
                            var id_token = {
                                    iss: self.settings.iss||req.protocol+'://'+req.headers.host,
                                    sub: prev.sub||prev.user||null,
                                    aud: new Array(prev.client.key),
                                    exp: d+3600,
                                    iat: d,
                                    azp: prev.client.key
                            };
                            if(prev.auth.nonce) {
                              id_token.nonce = prev.auth.nonce;
                            }
                            if(prev.auth.acr) id_token.acr = prev.auth.acr;
                            if(prev.auth.amr) id_token.amr = prev.auth.amr;
                            if(prev.auth.auth_time) id_token.auth_time = Math.floor(new Date(prev.auth.auth_time).getTime()/1000);
                            var p = {};
                            p.azp = id_token.azp;
                            var hbuf = crypto.createHmac('sha256', prev.client.simmetricKey).update(access).digest();
                            //p.at_hash = base64url(hbuf.toString('ascii', 0, hbuf.length/2));
                            //p.auth_time = prev.auth.createdAt;
                            if(id_token.nonce) p.nonce = id_token.nonce;
                            if(id_token.acr) p.acr = id_token.acr;
                            if(id_token.amr) p.amr = id_token.amr;
                            if(id_token.auth_time) p.auth_time = id_token.auth_time;
                            var opt = {};
                            opt.audience = id_token.aud;
                            opt.subject = id_token.sub;
                            opt.issuer = id_token.iss;
                            opt.expiresIn = 3600;
                            opt.headers = self.settings.key?{kid: self.settings.key.kid}:{};
                            //opt.algorithm = 'RS256';
                            var key = self.settings.key?self.settings.key.val:prev.client.simmetricKey;
                            req.model.access.create({
                                    token: access,
                                    type: 'Bearer',
                                    expiresIn: 3600,
                                    user: prev.user||null,
                                    client: prev.client.id,
                                    idToken: jwt.sign(p, key, opt),
                                    scope: prev.scope,
                                    auth: prev.auth?prev.auth.id:null
                            },
                            function(err, access) {
                                if(!err && access) {
                                    if(prev.auth) {
                                        prev.auth.status = 'used';
                                        prev.auth.save();
                                    }

                                    setTimeout(function() {
                                        access.destroy();
                                        if(access.auth) {
                                            req.model.auth.findOne({id: access.auth})
				                            .populate('accessTokens')
				                            .populate('refreshTokens')
                                            .exec(function(err, auth) {
                                                if(auth && !auth.accessTokens.length && !auth.refreshTokens.length) {
                                                    auth.destroy();
                                                }
                                            });
                                        }
                                    }, 1000*3600); //1 hour

                                    log(self, 'Id token is '+access.idToken);
                                    log(self, 'Access token is '+access.token);
                                    log(self, 'Refresh token is '+refresh.token);
                                    res.append('Cache-Control', 'no-store');
                                    res.append('Pragma', 'no-cache');
                                    res.json({
                                        access_token: access.token,
                                        token_type: access.type,
                                        expires_in: access.expiresIn,
                                        refresh_token: refresh.token,
                                        id_token: access.idToken
                                    });
                                }
                            });
                        });
                    };
                    createToken(req.model.access, function(access) {
                        createToken(req.model.refresh, function(refresh){
                            setToken(access, refresh);
                        });
                    });
                })
                .fail(function(error) {
                    logError(self, 'Token EP - '+JSON.stringify(error));
                    res.append('Cache-Control', 'no-store');
                    res.append('Pragma', 'no-cache');
                    res.status(400).json({error: error.error, error_description: error.msg});
                });
            }
    }];
};


/**
 * check
 *
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 *
 * app.get('/api/user', oidc.check('openid', /profile|email/), function(req, res, next) { ... });
 *
 * If no arguments are given, checks if access token is valid.
 *
 * The other arguments may be of type string or regexp.
 *
 * This function is used to check if user logged in, if an access_token is present, and if certain scopes where granted to it.
 */
OpenIDConnect.prototype.check = function() {
    var scopes = Array.prototype.slice.call(arguments, 0);
    if(!util.isArray(scopes)) {
        scopes = [scopes];
    }
    var self = this;
    spec = {
            access_token: false
    };

    return [
        function(req, res, next) {
            self.endpointParams(spec, req, res, next);
        },
        self.use({policies: {loggedIn: false}, models:['access', 'auth']}),
        function(req, res, next) {
            var params = req.parsedParams;
            req.check = req.check||{};
            if(!scopes.length) {
                next();
            } else {
                if(!params.access_token) {
                    if((req.headers['authorization'] || '').indexOf('Bearer ') === 0) params.access_token = req.headers['authorization'].replace('Bearer', '').trim();
                }
                if(params.access_token) {
                    req.model.access.findOne({token: params.access_token})
                    .exec(function(err, access) {
                        if(!err && access) {
                            var errors = [];

                            scopes.forEach(function(scope) {
                                if(typeof scope == 'string') {
                                    if(access.scope.indexOf(scope) == -1) {
                                        errors.push(scope);
                                    }
                                } else if(util.isRegExp(scope)) {
                                    var inS = false;
                                    access.scope.forEach(function(s){
                                        if(scope.test(s)) {
                                            inS = true;
                                        }
                                    });
                                    !inS && errors.push('('+scope.toString().replace(/\//g,'')+')');
                                }
                            });
                            if(errors.length == 0) {
                                req.check.scopes = access.scope;
                            }
                        }
                        next();
                    });
                } else {
                    next();
                }
            }
        }
    ];
};

/**
 * userInfo
 *
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 *
 * app.get('/api/user', oidc.userInfo());
 *
 * This function returns the user info in a json object. Checks for scope and login are included.
 */
OpenIDConnect.prototype.userInfo = function() {
    var self = this;
    return [
            function(req, res, next) {
                log(self, 'User Info EP - params are '+JSON.stringify(req.parsedParams));
                next();
            },
            self.check('openid'),
            self.use({policies: {loggedIn: false}, models: ['access', 'user']}),
            function(req, res, next) {
                //log(self, 'User Info EP - params are '+JSON.stringify(req.parsedParams));
                if(!req.parsedParams.access_token) {
                  logError(self, 'User Info EP - missing access token');
                  res.append('WWW-Authenticate', 'error="invalid_request", error_description="Access token is not specified"');
                  res.status(401).send();
                  return;
                }
                req.model.access.findOne({token: req.parsedParams.access_token})
                .exec(function(err, access) {
                    if(!err && access) {
                        req.model.user.findOne({id: access.user}, function(err, user) {
                            var result = {
                              sub: user.sub
                            };
                            req.check.scopes.forEach(function(s) {
                              if(self.settings.scopes[s]['claims']) {
                                self.settings.scopes[s]['claims'].forEach(function(c) {
                                  if(user[c]) result[c] = user[c];
                                });
                              }
                              if(s=='profile') result['updated_at'] = Math.round(user['updatedAt'].getTime()/1000);
                            });
                            log(self, 'userInfo returns '+JSON.stringify(result));
                            res.json(result);
                        });
                    } else {
                        //self.errorHandle(req, res, null, 'unauthorized_client', 'Access token is not valid.');
                        if(err) logError(self, 'User Info EP - '+JSON.stringify(err));
                        else logError(self, 'User Info EP - access token not found');
                        res.append('WWW-Authenticate', 'error="invalid_token", error_description="Access token is not valid"');
                        res.status(401).send();
                    }
                });
    }];
};

/**
 * removetokens
 *
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 *
 * app.get('/logout', oidc.removetokens(), function(req, res, next) { ... });
 *
 * this function removes all tokens that were issued to the user
 * access_token is required either as a parameter or as a Bearer token
 */
OpenIDConnect.prototype.removetokens = function() {
    var self = this,
        spec = {
            access_token: false //parameter not mandatory
        };

    return [
            function(req, res, next) {
                self.endpointParams(spec, req, res, next);
            },
            self.use({policies: {loggedIn: false}, models: ['access','auth']}),
            function(req, res, next) {
                var params = req.parsedParams;

                if(!params.access_token) {
                    params.access_token = (req.headers['authorization'] || '').indexOf('Bearer ') === 0 ? req.headers['authorization'].replace('Bearer', '').trim() : false;
                }
                if(params.access_token) {
                    //Delete the provided access token, and other tokens issued to the user
                    req.model.access.findOne({token: params.access_token})
                    .exec(function(err, access) {
                        if(!err && access) {
                            req.model.auth.findOne({user: access.user})
                            .populate('accessTokens')
                            .populate('refreshTokens')
                            .exec(function(err, auth) {
                                if(!err && auth) {
                                    auth.accessTokens.forEach(function(access){
                                        access.destroy();
                                    });
                                    auth.refreshTokens.forEach(function(refresh){
                                        refresh.destroy();
                                    });
                                    auth.destroy();
                                };
                                req.model.access.find({user:access.user})
                                .exec(function(err,accesses){
                                    if(!err && accesses) {
                                        accesses.forEach(function(access) {
                                            access.destroy();
                                        });
                                    };
                                    return next();
                                });
                            });
                        } else {
                            self.errorHandle(req, res, null, 'unauthorized_client', 'Access token is not valid.');
                        }
                    });
                } else {
                    self.errorHandle(req, res, null, 'unauthorized_client', 'No access token found.');
                }
            }
            ];
};


OpenIDConnect.prototype.setKey = function(val) {
};

/*
OpenIDConnect.prototype.cleanAllAuths = function() {
    var self = this;

    return [
        function(req, res, next) {
            self.endpointParams(spec, req, res, next);
        },
        self.use({policies: {loggedIn: false}, models: ['access','auth', 'refresh']}),
        function(req, res, next) {
            req.model.access.destroy({}, function(err, a) {
              if(err) console.log('access destroy error: '+err);
              else console.log('access destroyed!');
            });
            req.model.refresh.destroy({}, function(err, r) {
              if(err) console.log('refresh destroy error: '+err);
              else console.log('refresh destroyed!');
            });
            req.model.auth.destroy({}, function(err, a) {
              if(err) console.log('auth destroy error: '+err);
              else console.log('auth destroyed!');
            });
            return next();
        }
    ];
};


OpenIDConnect.prototype.showAllAuths = function() {
    var self = this;

    return [
        function(req, res, next) {
            self.endpointParams(spec, req, res, next);
        },
        self.use({policies: {loggedIn: false}, models: ['access','auth', 'refresh']}),
        function(req, res, next) {
            req.model.access.find({}, function(err, a) {
              if(err) {
                console.log('access get error: '+err);
              }
              else {
                for(var i in a) {
                  console.log('Access '+i+': '+JSON.stringify(a[i]));
                }
              }
            });
            req.model.refresh.find({}, function(err, a) {
              if(err) {
                console.log('refresh get error: '+err);
              }
              else {
                for(var i in a) {
                  console.log('Refresh '+i+': '+JSON.stringify(a[i]));
                }
              }
            });
            req.model.auth.find({}, function(err, a) {
              if(err) {
                console.log('auth get error: '+err);
              }
              else {
                for(var i in a) {
                  console.log('Auth '+i+': '+JSON.stringify(a[i]));
                }
              }
            });
            return next();
        }
    ];
};
*/

exports.oidc = function(options) {
    return new OpenIDConnect(options);
};

exports.defaults = function() {
    return defaults;
}
