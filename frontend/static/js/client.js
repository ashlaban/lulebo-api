function show_response(response) {
	var id = document.getElementById('response');
	id.innerHTML = JSON.stringify(response);
}

function lulebo_simple_send(path) {
	var session_id = sessionStorage.getItem('session_id');

	return new Promise( function(resolve, reject) {
		show_response({message:'Waiting for '+path})
		superagent.post("http://localhost:8080/api/lulebo"+path)
		.send({session_id:session_id})
		.end(function(err, res) {
			err ? reject(error) : resolve(res);
		});
	});
}

function send_lulebo_login() {
	var user_id = sessionStorage.getItem('user_id');

	superagent.post("http://localhost:8080/api/lulebo/login")
	.send({user_id:user_id})
	.end(function(err, res) {
		sessionStorage.setItem('session_id', res.body.session_id);
		console.log(res.body);
		show_response(res.body);
	});
}

function send_lulebo_direct_start() {
	lulebo_simple_send('/direct_start').then( function(res){show_response(res.body)} );
}
function send_lulebo_object_info() {
	lulebo_simple_send('/object_info').then( function(res){show_response(res.body)} );
}
function send_lulebo_object_status() {
	lulebo_simple_send('/object_status').then( function(res){show_response(res.body)} );
}

function send_create_db() {
	superagent.post("http://localhost:8080/api/create_db")
	.send()
	.end(function(err, res) {
		console.log(res.body);
		show_response(res.body);
	});
}

function send_login() {
	superagent.post("http://localhost:8080/login")
	.send({
		username: document.getElementById('username').value,
		password: document.getElementById('password').value,
	})
	.end(function(err, res) {
		console.log(res);
		var user_id = res.body.user.id;
		sessionStorage.setItem('user_id', user_id);
		console.log('login',res.body);
		show_response(res.body);
	});
}

function send_login_debug(username, password) {
	superagent.post("http://localhost:8080/login")
	.send({
		username: username,
		password: password,
	})
	.end(function(err, res) {
		if (!err) {
			console.log(res);

			var user_id = res.body.user.id;
			sessionStorage.setItem('user_id', user_id);
			console.log('login',res.body);
			show_response(res.body);
		} else {
			console.log(err)
		}
	});
}

function send_user_create() {
	superagent.post("http://localhost:8080/signup")
	.send({
		username: document.getElementById('username').value,
		password: document.getElementById('password').value,
		lulebo_user: document.getElementById('lulebo_user').value,
		lulebo_pass: document.getElementById('lulebo_pass').value,
		email: document.getElementById('email').value,
	})
	.end(function(err, res) {
		console.log('user_create::',res.body);
		show_response(res.body);
	});
}

function send_user_exists() {
	superagent.post("http://localhost:8080/api/user_exists")
	.send({
		username: document.getElementById('username').value,
	})
	.end(function(err, res) {
		console.log('user_exists',res.body);
		show_response(res.body);
	});
}