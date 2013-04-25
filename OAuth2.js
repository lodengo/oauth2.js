var querystring= require('querystring'),
    crypto= require('crypto'),
    https= require('https'),
    http= require('http'),
    URL= require('url');
	

var defaultOAuth2Conf = {
	clientId: ''
	, clientSecret: ''
	, authorizationEndpoint: ''
	, tokenEndpoint : ''
	, redirectUri: ''
	, accessTokenName: 'access_token'
	, useAuthorizationHeaderForGET: true
	, authMethod: 'Bearer'
	, storeTokenInSession: true
	, authorizationGrantType: 'authorization_code' //'implicit', 'password', 'client_credentials'
	, clientAuthenticationUseBasic: true
	, customHeaders: {}
	, authorizationCallback: function(req, res, error, result){res.json({error:error, result:result});}
	, tokenNamespace: ''
	, accessTokenKey: 'access_token'
	
};

function OAuth2(conf){
	this.conf = {};
	for(var k in defaultOAuth2Conf){
		this.conf[k] = defaultOAuth2Conf[k];
	}
	for(var k in conf){
		this.conf[k] = conf[k];
	}
	
	if(!this.conf.tokenNamespace){
		this.conf.tokenNamespace = URL.parse(this.conf.tokenEndpoint).hostname;	
	}	
}

OAuth2.prototype.setAuthorizationCallback = function(callback){
	var self = this;
	self.conf.authorizationCallback = callback;
}

OAuth2.prototype.obtainingAuthorization = function(req, res, params){
	var self = this;
	params = params || {};
	if(self.conf.authorizationGrantType == 'authorization_code'){	
		params['response_type'] = 'code';
		params['client_id'] = self.conf.clientId;		
		params['redirect_uri'] = self.conf.redirectUri;
		
		res.redirect(self.conf.authorizationEndpoint + "?" + querystring.stringify(params));
	}
	else if(self.conf.authorizationGrantType == 'implicit'){
		params['response_type'] = 'token';
		params['client_id'] = self.conf.clientId;		
		params['redirect_uri'] = self.conf.redirectUri;
		
		res.redirect(self.conf.authorizationEndpoint + "?" + querystring.stringify(params));
	}
	else if(self.conf.authorizationGrantType == 'password'){		
		params['grant_type'] = 'password';
		
		var headers = {};
		if(self.conf.clientAuthenticationUseBasic){
			headers = self._clientBasicAuthenticationHeader();
		}
		else{
			params['client_id'] = self.conf.clientId;
			params['client_secret'] = self.conf.clientSecret;	
		}	
		
		var post_data= querystring.stringify( params );
		
		self._request("POST", self.conf.tokenEndpoint, headers, post_data, null, function(error, data) {
			self._accessTokenCallback(req, res, error, data);
		});
		
	}
	else if(self.conf.authorizationGrantType == 'client_credentials'){
		params['grant_type'] = 'client_credentials';
		
		var headers = {};
		if(self.conf.clientAuthenticationUseBasic){
			headers = self._clientBasicAuthenticationHeader();
		}
		else{
			params['client_id'] = self.conf.clientId;
			params['client_secret'] = self.conf.clientSecret;	
		}	
		
		var post_data= querystring.stringify( params );
		
		self._request("POST", self.conf.tokenEndpoint, headers, post_data, null, function(error, data) {
			self._accessTokenCallback(req, res, error, data);
		});
	}
}

OAuth2.prototype.accessProtectedResource= function(req, res, method, url, params, callback) {
	var self = this;
	var token = self._getAccessToken(req);
	
	var access_token = token[self.conf.accessTokenKey];	
	
	if( self.conf.useAuthorizationHeaderForGET ) {
		var headers= {'Authorization': self.conf.authMethod + ' ' + access_token }
		access_token= null;
	}
	else {
		headers= {};
	}
	
	self._request(method, url, headers, params, access_token, function(error, data) {
		if(error){
			callback(error, null);
		}
		else{
			callback(error, data);
		}
	});
}

OAuth2.prototype.route = function(app){
	var self = this;
	var pathName = URL.parse( self.conf.redirectUri).pathname;
	app.all(pathName,  function(req, res){self._redirectCallback(req, res);});		
}

OAuth2.prototype._redirectCallback = function(req, res){
	var self = this;
	var error = req.query.error;
	var state = req.query.state;
	if(error){
		self.conf.authorizationCallback(req, res, req.query.error, req.query);
	}
	else{
		if(self.conf.authorizationGrantType == 'authorization_code'){
			var code = req.query.code;
			
			var params= {};
			params['grant_type'] = 'authorization_code';
			params['code'] = code;
			params['redirect_uri'] = self.conf.redirectUri;
			
			var headers = {};
			if(self.conf.clientAuthenticationUseBasic){
				headers = self._clientBasicAuthenticationHeader();
			}
			else{
				params['client_id'] = self.conf.clientId;
				params['client_secret'] = self.conf.clientSecret;	
			}			

			var post_data= querystring.stringify( params );

			self._request("POST", self.conf.tokenEndpoint, headers, post_data, null, function(error, data) {
				self._accessTokenCallback(req, res, error, data);
			});				
		}
		else if(self.conf.authorizationGrantType == 'implicit'){
			self._accessTokenCallback(req, res, null, req.query);			
		}
		
	}			
}

OAuth2.prototype._clientBasicAuthenticationHeader = function(){
	var self = this;
	var auth = "Basic " + new Buffer(self.conf.clientId + ":" + self.conf.clientSecret).toString("base64");
	return {'Authorization': auth};
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
	
	if(!error){
		error = results.error;
	}
	
	if(error){
		self.conf.authorizationCallback(req, res, error, data);
	}
	else{					
		self._storeAccessToken(req, res, results);
		self.conf.authorizationCallback(req, res, error, data);
	}			
}

OAuth2.prototype._getAccessToken = function(req){
	var self = this;
	if(self.conf.storeTokenInSession){
		return req.session['access_token.'+self.conf.tokenNamespace];
	}
	else{
		return req.cookies['access_token.'+self.conf.tokenNamespace];
	}
}

OAuth2.prototype._storeAccessToken = function(req, res, access_token){
	var self = this;
	
	if(self.conf.storeTokenInSession){
		req.session['access_token.'+self.conf.tokenNamespace] = access_token;
	}
	else{
		res.cookie('access_token.'+self.conf.tokenNamespace, access_token);
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
	for( var key in self.conf.customHeaders ) {
		realHeaders[key]= self.conf.customHeaders[key];
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
		parsedUrl.query[self.conf.accessTokenName]= access_token;
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

module.exports = OAuth2;

