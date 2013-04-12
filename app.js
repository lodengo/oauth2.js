
/**
 * Module dependencies.
 */

var express = require('express')  
  , http = require('http')
  , path = require('path');

var app = express();


app.configure(function(){
  app.set('port', process.env.PORT || 80);
  //app.set('views', __dirname + '/views');
  //app.set('view engine', 'ejs');
  //app.use(express.favicon());
  app.use(express.logger('dev'));
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(express.cookieParser('your secret here'));
  app.use(express.session());
  app.use(app.router);
  //app.use(express.static(path.join(__dirname, 'public')));
});

app.configure('development', function(){
  app.use(express.errorHandler());
});

var weibo2 = require('./setting').weibo2;
weibo2.route(app);
weibo2.setAuthorizationCallback(function(req, res, error, data){
  res.send('<a href="/statuses/public_timeline">/statuses/public_timeline</a> </p><a href="/statuses/friends_timeline">/statuses/friends_timeline</a> </p><a href="/statuses/home_timeline">/statuses/home_timeline</a> </p>');
});


app.get('/', function(req, res){	
	weibo2.obtainingAuthorization(req, res);
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

http.createServer(app).listen(app.get('port'), function(){
  console.log("Express server listening on port " + app.get('port'));
});