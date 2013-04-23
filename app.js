
/**
 * Module dependencies.
 */

var express = require('express')  
  , http = require('http')
  , path = require('path');

var app = express();


app.configure(function(){
  app.set('port', process.env.PORT || 80);  
  app.use(express.logger('dev'));
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(express.cookieParser('your secret here'));
  app.use(express.session());
  app.use(app.router);  
});

app.configure('development', function(){
  app.use(express.errorHandler());
})

var OAuth2 = require('./OAuth2')(app);
var weibo2 = new OAuth2(require('./setting').weibo_conf);
weibo2.setAuthorizationCallback(function(req, res, error, data){
	if(error){
		res.json({error:error, data:data});
	}
	else{
		res.send('<a href="/statuses/public_timeline">/statuses/public_timeline</a> </p><a href="/statuses/friends_timeline">/statuses/friends_timeline</a> </p><a href="/statuses/home_timeline">/statuses/home_timeline</a> </p>');
	}
});

var douban = new OAuth2(require('./setting').douban_conf);
douban.setAuthorizationCallback(function(req, res, error, data){
	if(error){
		res.json({error:error, data:data});
	}
	else{
		res.send('<a href="/movie/nowplaying">/movie/nowplaying</a> </p><a href="/movie/coming">/movie/coming</a> ');
	}
}); 

app.get('/', function(req, res){	
	res.send('<a href="/weibo">weibo</a></p><a href="/douban">douban</a>');
});

app.get('/weibo', function(req, res){
	weibo2.obtainingAuthorization(req, res);
});

app.get('/douban', function(req, res){
	douban.obtainingAuthorization(req, res);
});

app.get('/statuses/public_timeline', function(req, res){
	weibo2.accessProtectedResource(req, res, 'GET', 'https://api.weibo.com/2/statuses/public_timeline.json', {}, function(error, data){
		res.json(data);
	});
});
app.get('/statuses/friends_timeline', function(req, res){
	weibo2.accessProtectedResource(req, res, 'GET', 'https://api.weibo.com/2/statuses/friends_timeline.json', {}, function(error, data){
		res.json(data);
	});
});
app.get('/statuses/home_timeline', function(req, res){
	weibo2.accessProtectedResource(req, res, 'GET', 'https://api.weibo.com/2/statuses/home_timeline.json', {}, function(error, data){
		res.json(data);
	});
});

app.get('/movie/nowplaying', function(req, res){
	douban.accessProtectedResource(req, res, 'GET', 'https://api.douban.com/v2/movie/nowplaying', {}, function(error, data){
		res.json(data);
	});
});

app.get('/movie/coming', function(req, res){
	douban.accessProtectedResource(req, res, 'GET', 'https://api.douban.com/v2/movie/coming', {}, function(error, data){
		res.json(data);
	});
});

http.createServer(app).listen(app.get('port'), function(){
  console.log("Express server listening on port " + app.get('port'));
});
