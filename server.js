const express = require("express");
const mongoose = require("mongoose");
const shoppingRoute = require("./routes/shoppingroute");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const userModel = require("./models/user");
const sessionModel = require("./models/session");

let app = express();
//MOI
const mongo_url = process.env.MONGODB_URL;
const mongo_user = process.env.MONGODB_USERNAME;
const mongo_password = process.env.MONGODB_PASSWORD;

const url = "mongodb+srv://" + mongo_user + ":" + mongo_password + "@" + mongo_url + "/shoppingdatabase?retryWrites=true&w=majority"

app.use("/", express.static("public"));

//MOI

app.use(express.json());

mongoose.connect(url).then(
	() => console.log("Connected to MongoDB"),
	(err) => console.log("Failed to connect to MongoDB. Reason", err)
)

//MIDDLEWARES

const time_to_live_diff = 3600000;

createToken = () => {
	let token = crypto.randomBytes(64);
	return token.toString("hex");
}

isUserLogged = (req, res, next) => {
	if (!req.headers.token) {
		return res.status(403).json({ "Message": "Forbidden" })
	}
	sessionModel.findOne({ "token": req.headers.token }).then(function (session) {
		if (!session) {
			return res.status(403).json({ "Message": "Forbidden" })
		}
		let now = Date.now();
		if (now > session.ttl) {
			sessionModel.deleteOne({ "_id": session._id }).then(function () {
				return res.status(403).json({ "Message": "Forbidden" })
			}).catch(function (err) {
				console.log(err);
				return res.status(403).json({ "Message": "Forbidden" })
			})
		} else {
			session.ttl = now + time_to_live_diff;
			req.session = {};
			req.session.user = session.user;
			session.save().then(function () {
				return next();
			}).catch(function (err) {
				console.log(err);
				return next();
			})
		}
	}).catch(function (err) {
		console.log(err);
		return res.status(403).json({ "Message": "Forbidden" })
	})
}

//LOGIN API

app.post("/register", function (req, res) {
	if (!req.body) {
		return res.status(400).json({ "Message": "Bad request" })
	}
	if (!req.body.username || !req.body.password) {
		return res.status(400).json({ "Message": "Bad request" })
	}
	if (req.body.username < 4 || req.body.password < 8) {
		return res.status(400).json({ "Message": "Bad request" })
	}
	bcrypt.hash(req.body.password, 14, function (err, hash) {
		if (err) {
			console.log(err);
			return res.status(500).json({ "Message": "Internal Server Error" })
		}
		let user = new userModel({
			"username": req.body.username,
			"password": hash
		})
		user.save().then(function () {
			return res.status(200).json({ "Message": "Register Success" })
		}).catch(function (err) {
			if (err.code === 11000) {
				return res.status(409).json({ "Message": "Username is already in use" })
			}
			console.log(err);
			return res.status(500).json({ "Message": "Internal Server Error" });
		})
	})
})

app.post("/login", function (req, res) {
	if (!req.body) {
		return res.status(400).json({ "Message": "Bad request" })
	}
	if (!req.body.username || !req.body.password) {
		return res.status(400).json({ "Message": "Bad request" })
	}
	if (req.body.username < 4 || req.body.password < 8) {
		return res.status(400).json({ "Message": "Bad request" })
	}
	userModel.findOne({ "username": req.body.username }).then(function (user) {
		if (!user) {
			return res.status(401).json({ "Message": "Unauthorized" })
		}
		bcrypt.compare(req.body.password, user.password, function (err, success) {
			if (err) {
				console.log(err);
				return res.status(500).json({ "Message": "Internal Server Error" })
			}
			if (!success) {
				return res.status(401).json({ "Message": "Unauthorized" })
			}
			let token = createToken();
			let now = Date.now();
			let session = new sessionModel({
				"user": req.body.username,
				"ttl": now + time_to_live_diff,
				"token": token
			})
			session.save().then(function (session) {
				return res.status(200).json({ "token": token })
			}).catch(function (err) {
				console.log(err);
				return res.status(500).json({ "Message": "Internal Server Error" })
			})
		})
	}).catch(function (err) {
		console.log(err);
		return res.status(500).json({ "Message": "Internal Server Error" })
	})
})

app.post("/logout", function (req, res) {
	if (!req.headers.token) {
		return res.status(404).json({ "Message": "Not found" })
	}
	sessionModel.deleteOne({ "token": req.headers.token }).then(function () {
		return res.status(200).json({ "Message": "Logged out" })
	}).catch(function (err) {
		console.log(err);
		return res.status(500).json({ "Message": "Internal Server Error" })
	})
})

app.use("/api", isUserLogged, shoppingRoute);

let port = process.env.PORT || 3000;

app.listen(port);

console.log("Running in port", port);

