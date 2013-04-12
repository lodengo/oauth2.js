var querystring= require('querystring'),
    crypto= require('crypto'),
    https= require('https'),
    http= require('http'),
    URL= require('url');
  
function OAuth2(clientId, clientSecret, baseSite, redirectUri, authorizePath, accessTokenPath, storeTokenInSession, accessTokenName, authMethod, useAuthorizationHeaderForGET, authorizationGrantType, customHeaders){
	this._clientId= clientId;
	this._clientSecret= clientSecret;
	this._baseSite= baseSite;
	this._redirectUri = redirectUri;	
	this._authorizeUrl= authorizePath || "/oauth/authorize";
	this._accessTokenUrl= accessTokenPath || "/oauth/access_token";
	this._storeTokenInSession = storeTokenInSession;
	
	this._accessTokenName= accessTokenName || "access_token";
	this._authMethod= authMethod || "Bearer";
	
	this._useAuthorizationHeaderForGET = useAuthorizationHeaderForGET;
	this._authorizationGrantType = authorizationGrantType || 'authorization_code'; //authorization_code, implicit, password, client_credentials
	this._customHeaders = customHeaders || {};
}

OAuth2.prototype.route = function(app){
	var self = this;
	var pathName = URL.parse( self._redirectUri).pathname;
	app.all(pathName,  function(req, res){self._authorizeRedirectCallback(req, res);});		
}

OAuth2.prototype.setAuthorizationCallback = function(callback){
	var self = this;
	self._authorizationCallback = callback;
}

OAuth2.prototype.obtainingAuthorization = function(req, res, params){
	var self = this;
	params = params || {};
	if(self._authorizationGrantType == 'authorization_code'){	
		params['response_type'] = 'code';
		params['client_id'] = self._clientId;		
		params['redirect_uri'] = self._redirectUri;
		res.redirect(self.authorizationEndpoint(params));
	}
	else if(self._authorizationGrantType == 'implicit'){
		params['response_type'] = 'token';
		params['client_id'] = self._clientId;
		params['redirect_uri'] = self._redirectUri;
		res.redirect(self.authorizationEndpoint(params));
	}
	else if(self._authorizationGrantType == 'password'){		
		params['grant_type'] = 'password';
		params['client_id'] = self._clientId;
		params['client_secret'] = self._clientSecret;
		
		var post_data= querystring.stringify( params );
		
		self._request("POST", self.tokenEndpoint(), {}, post_data, null, function(error, data) {
			self._accessTokenCallback(req, res, error, data);
		});
		
	}
	else if(self._authorizationGrantType == 'client_credentials'){
		params['grant_type'] = 'client_credentials';
		params['client_id'] = self._clientId;
		params['client_secret'] = self._clientSecret;
		var post_data= querystring.stringify( params );
		
		self._request("POST", self.tokenEndpoint(), {}, post_data, null, function(error, data) {
			self._accessTokenCallback(req, res, error, data);
		});
	}
}

OAuth2.prototype.accessProtectedResource= function(req, res, method, url, params, callback) {
	var self = this;
	var token = self._getAccessToken(req);
	
	var access_token = token['access_token'];
	var expires_in = token['expires_in'];
	var state = token['state'];
	
	if( self._useAuthorizationHeaderForGET ) {
		var headers= {'Authorization': self._authMethod + ' ' + access_token }
		access_token= null;
	}
	else {
		headers= {};
	}
	
	self._request(method, url, headers, params, access_token, function(error, data) {
		callback(error, JSON.parse( data ));
	});
}

OAuth2.prototype.authorizationEndpoint= function(params) {
	var self = this;
	var params= params || {};		
	return self._baseSite + self._authorizeUrl + "?" + querystring.stringify(params);
}

OAuth2.prototype.tokenEndpoint= function() {
	var self = this;
   return self._baseSite + self._accessTokenUrl; 
}

OAuth2.prototype._authorizeRedirectCallback = function(req, res){
	var self = this;
	var error = req.query.error;
	var state = req.query.state;
	if(error){
		var error_description = req.query.error_description;
		var error_uri = req.query.error_uri;
		res.redirect(error_uri);
	}
	else{
		if(self._authorizationGrantType == 'authorization_code'){
			var code = req.query.code;
			
			var params= {};
			params['grant_type'] = 'authorization_code';
			params['code'] = code;
			params['redirect_uri'] = self._redirectUri;
			
			params['client_id'] = self._clientId;
			params['client_secret'] = self._clientSecret;		

			var post_data= querystring.stringify( params );

			self._request("POST", self.tokenEndpoint(), {}, post_data, null, function(error, data) {
				self._accessTokenCallback(req, res, error, data);
			});				
		}
		else if(self._authorizationGrantType == 'implicit'){
			self._accessTokenCallback(req, res, null, req.query);			
		}
		
	}			
}

OAuth2.prototype._accessTokenCallback = function(req, res, error, data){	
	var self = this;
	var results;
	try {			
		results= JSON.parse( data );
	}
	catch(e) {			
		results= querystring.parse( data );
	}
	
	if(results.error){
		var error_description = results.error_description;
		var error_uri = results.error_uri;
		res.redirect(error_uri);
	}
	else{					
		self._storeAccessToken(req, res, results);
		if(self._authorizationCallback){
			self._authorizationCallback(req, res, error, data);
		}
	}			
}

OAuth2.prototype._getAccessToken = function(req){
	var self = this;
	if(self._storeTokenInSession){
		return req.session.access_token;
	}
	else{
		return req.cookies.access_token;
	}
}

OAuth2.prototype._storeAccessToken = function(req, res, access_token){
	var self = this;
	if(self._storeTokenInSession){
		req.session.access_token = access_token;
	}
	else{
		res.cookie('access_token', access_token);
	}
}

OAuth2.prototype._request= function(method, url, headers, params, access_token, callback) {
	var self = this;
	if(method == "POST" || method =="PUT"){
	
	}
	else{
		url = url + ((url.indexOf('?') < 0) ? '?' : '&') + querystring.parse(params || {});
		params = null;
	}

	var http_library= https;
	var creds = crypto.createCredentials({ });
	var parsedUrl= URL.parse( url, true );
	if( parsedUrl.protocol == "https:" && !parsedUrl.port ) {
		parsedUrl.port= 443;
	}

  // As this is OAUth2, we *assume* https unless told explicitly otherwise.
	if( parsedUrl.protocol != "https:" ) {
		http_library= http;
	}

	var realHeaders= {}; 
	for( var key in self._customHeaders ) {
		realHeaders[key]= self._customHeaders[key];
	}
	if( headers ) {
		for(var key in headers) {
			realHeaders[key] = headers[key];
		}
	}
	realHeaders['Host']= parsedUrl.host;

	realHeaders['Content-Length']= params ? Buffer.byteLength(params) : 0;
	if(realHeaders['Content-Length'] > 0) {
		realHeaders['Content-Type'] = "application/x-www-form-urlencoded";
	}
  
	if( access_token && !('Authorization' in realHeaders)) {
		if( ! parsedUrl.query ) parsedUrl.query= {};
		parsedUrl.query[self._accessTokenName]= access_token;
	}

	var queryStr= querystring.stringify(parsedUrl.query);
	if( queryStr ) queryStr=  "?" + queryStr;
	var options = {
		host:parsedUrl.hostname,
		port: parsedUrl.port,
		path: parsedUrl.pathname + queryStr,
		method: method,
		headers: realHeaders
	};

	self._executeRequest( http_library, options, params, callback );
}

OAuth2.prototype._executeRequest= function( http_library, options, post_body, callback ) {  
	var self = this;
	var allowEarlyClose= options.host.match(".*google(apis)?.com$");
	var callbackCalled= false;
	function passBackControl( response, result ) {
		if(!callbackCalled) {
		callbackCalled=true;
		if( response.statusCode != 200 && (response.statusCode != 301) && (response.statusCode != 302) ) {
			callback({ statusCode: response.statusCode, data: result });
		} 
		else {
			callback(null, result, response);
		}
    }
  }

  var result= "";

  var request = http_library.request(options, function (response) {
    response.on("data", function (chunk) {
      result+= chunk
    });
    response.on("close", function (err) {
      if( allowEarlyClose ) {
        passBackControl( response, result );
      }
    });
    response.addListener("end", function () {
      passBackControl( response, result );
    });
  });
  request.on('error', function(e) {
    callbackCalled= true;
    callback(e, {});
  });

   if( (options.method == "POST" || options.method =="PUT") && post_body != null && post_body != "" ) {
      request.write(post_body);
    }
  request.end();  
}


exports.OAuth2 = OAuth2;
