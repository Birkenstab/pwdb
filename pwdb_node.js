var fs = require("fs");
var bodyParser = require('body-parser');
var sqlite3 = require('sqlite3');
var https = require('https');
var express = require('express');
var Q = require("q");
var scrypt = require("scrypt");
var crypto = require("crypto");
var config = require("./config.js");

if (!config.port) {
    throw Error("A config must me specified");
}

var app = express();
var db = new sqlite3.Database('/home/knoten/pwdb/pwdb.db3');
var fields = ["website","username","password","notes"];
var files = ["backbone-min.js","index.html","jquery-2.1.0.min.js","pwdb.css","pwdb.js","scrypt.js","underscore-min.js","bootstrap/css/bootstrap.min.css","bootstrap/js/bootstrap.min.js","font-awesome/css/font-awesome.min.css","font-awesome/fonts/fontawesome-webfont.eot","font-awesome/fonts/fontawesome-webfont.svg","font-awesome/fonts/fontawesome-webfont.ttf","font-awesome/fonts/fontawesome-webfont.woff","font-awesome/fonts/FontAwesome.otf"]; //Files that can be accessed via webserver

var scryptParams = scrypt.params(0.7);
console.log(scryptParams);

//UserGroup 1000 ist Admin alles andere normalert Benutzer
db.run("CREATE TABLE IF NOT EXISTS User (UserID INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL, Username TEXT UNIQUE NOT NULL, Password TEXT NOT NULL, Salt TEXT NOT NULL, RegisterDate TEXT NOT NULL, Banned NUMERIC, Banreason TEXT, Activated NUMERIC, UserGroup NUMERIC, SessionToken TEXT UNIQUE);");
db.run("CREATE TABLE IF NOT EXISTS Access (AccessID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, UserID INTEGER, PotentialUser TEXT, SessionToken TEXT, IP TEXT NOT NULL, UserAgent TEXT, isLoginRequest NUMERIC, Date TEXT);");
db.run("CREATE TABLE IF NOT EXISTS Records (UUID TEXT NOT NULL UNIQUE, UserID INTEGER, Modified TEXT, Created TEXT, " + fields.join(" TEXT, ") + " TEXT);");

Q.longStackSupport = true;

db.serialize();

if (config.useProxy && config.trustProxy)
    app.set("trust proxy", config.trustProxy);

app.use(bodyParser.json());
app.use(checknLogRequest);

if (!config.useProxy) {
    var options = {
      key: fs.readFileSync(config.sslKey),
      cert: fs.readFileSync(config.sslCert)
    };
}

//Je nachdem ob man eine Proxy verwenden will oder nicht
if (config.useProxy) {
    app.listen(config.port,config.hostBind); 
} else {
    var server = https.createServer(options, app);
    server.listen(config.port, config.hostBind);
}

console.log("pwdb-server is running…");

app.get('/', indexSite);
app.post("/register",register);
app.post("/usersalt",getUserSalt);
app.post("/login",login);
app.post("/logout",logout);

app.post("/records",records);

app.get("/resources/*",resources);


function checknLogRequest(req,res,next) {
    var sessionToken = req.body.sessiontoken;
    var session;
    var isLoginRequest = Number(["/register","/login","/usersalt"].indexOf(req.path) !== -1);
    return getSession(sessionToken).then(function(sessionInfos) {
            session = sessionInfos || {};
        if (!req.body)
            req.body = {};
        var values = {
            $UserID: session.UserID || "",
            $PotentialUser: req.body.username || "",
            $SessionToken: sessionToken || "",
            $IP: req.ips[0] || req.ip,
            $UserAgent: req.get("User-Agent") || "",
            $isLoginRequest: isLoginRequest,
            $Date: new Date().getTime()
        };
        return Q.ninvoke(db,"run","INSERT INTO Access (UserID,PotentialUser,SessionToken,IP,UserAgent,isLoginRequest,Date) VALUES ($UserID,$PotentialUser,$SessionToken,$IP,$UserAgent,$isLoginRequest,$Date)",values);
    }).then(function() {
        if (!isLoginRequest)
            return false;
        return Q.ninvoke(db,"all","SELECT * FROM Access WHERE isLoginRequest = 1 AND Date >= ? AND ((PotentialUser = ? AND PotentialUser <> '') OR (UserID = ? AND UserID <> 0));",
                         new Date().getTime() - config.passwordAttempts[config.passwordAttempts.length-1].period, req.body.username, session.UserID);
    }).then(function(result) {
        if (!isLoginRequest) 
            return false;
        
        for (var i = config.passwordAttempts.length-1; i >= 0; i--) {
            var toRemove = [];
            for (var j = 0; j < result.length; j++) {
                if (result[j].Date < new Date().getTime() - config.passwordAttempts[i].period) {
                    toRemove.push(j);
                }
            }
            for (var j = 0; j < toRemove.length; j++) {
                result.splice(toRemove[i],1);
            }
            if (result.length > config.passwordAttempts[i].skip) {
                var delay = Math.pow(result.length - config.passwordAttempts[i].skip,config.passwordAttemptExponent)*config.passwordAttempts[i].multiplicator;
                console.log(result);
                console.log(new Date().getTime() - config.passwordAttempts[i].period);
                console.log("Verzögerung (" + config.passwordAttempts[i].period/1000 + " s; " + result.length + "x): " + delay);
                return Q.delay(true,delay);
            }
        }
        console.log("Keine Verzögerung");
        return true;
    }).then(function() {
        next();
    },function(error) {
        console.error(error);
        res.status(500).send({error: {msg:"error.server.undefined"} });
    });
}

function getUserSalt(req,res) {
    var username = req.body.username;
    
    doGetUserSalt(username)
    .then(handleSuccess.bind(this,res),handleFail.bind(this,res));
}

function login(req,res) {
    var username = req.body.username;
	var password = req.body.password;
    
    checkUserPassword(username,password)
    .then(function(result) {
        if (result === true) {
            return createSession(username);
        }
        else {
            return Q.reject({msg:"error.login.wrongPassword",cerror:true});
        }
    }).then(function(sessionToken) {
        return {sessiontoken: sessionToken};
    })
    .then(handleSuccess.bind(this,res),handleFail.bind(this,res));
}

function logout(req,res) {
    var sessionToken = req.body.sessiontoken;
    removeSession(sessionToken).then(function() {
        return true;
    }).then(handleSuccess.bind(this,res),handleFail.bind(this,res));
}

function register(req,res) {
	var username = req.body.username;
	var password = req.body.password;
	var salt = req.body.salt;
	
	userExist(username).then(function(result) {
		if (result === true) {
			console.log("Username Moritz already exists");
			return Q.reject({msg:"error.register.alreadySameUsername",cerror:true});
		}
		console.log("Moritz existiert: " + result);
	}).then(function() {
		console.log("Hallo 5");
		return addNewUser(username,password,salt);
	}).then(handleSuccess.bind(this,res),handleFail.bind(this,res));
}

function records(req,res) {
    var m = req.body.method;
    var sessionToken = req.body.sessiontoken;
    var recordID = req.body.id;
    if (m === "GET")
        getRecords(sessionToken,recordID,res);
    else if (m === "POST")
        postRecord(sessionToken,req.body.data,res);
    else if (m === "PUT")
        updateRecord(sessionToken,recordID,req.body.data,res);
    else if (m === "DELETE")
        deleteRecord(sessionToken,recordID,res);
    else
        res.status(400).send({msg:"error.records.unknownMethod"});
}

function indexSite(req,res) {
    getFile("index.html",res);
}

function resources(req,res) {
    var filename = req.params[0];
    getFile(filename,res);
}





function getFile(filename,res) {
    var index = files.indexOf(filename);
    if (index == -1) {
        res.status(404).send("File not found");
        return;
    }
    
    Q.ninvoke(fs,"readFile","/home/knoten/pwdb/resources/" + files[index]).then(function(result) {
        if (filename.match(".html$")) {
            res.set("Content-Type", "text/html");
        } else if (filename.match(".js$")) {
            res.set("Content-Type", "application/javascript");
        } else if (filename.match(".css$")) {
            res.set("Content-Type", "text/css");
        } else if (filename.match(".svg$")) {
            res.set("Content-Type", "image/svg+xml");
        } else if (filename.match(".woff$")) {
            res.set("Content-Type", "application/x-font-woff");
        } else if (filename.match(".eot$")) {
            res.set("Content-Type", "application/vnd.ms-fontobject");
        }
        res.send(result);
        return;
    },function(error) {
        console.error(error);
        res.status(500).send("Error reading file");
        return;
    });
}

function deleteRecord(sessionToken,recordID,res) {
    getSession(sessionToken).then(function(result) {
        if (!result) 
            return Q.reject({msg:"error.invalidSession",cerror:true});
        return removeRecord(result.UserID,recordID);
    }).then(handleSuccess.bind(this,res),handleFail.bind(this,res));
}

function updateRecord(sessionToken,recordID,data,res) {
    getSession(sessionToken).then(function(result) {
        if (!result) 
            return Q.reject({msg:"error.invalidSession",cerror:true});
        var values = {
            $Modified: new Date().getTime(),
            $UserID: result.UserID,
            $UUID: recordID
        };
        var query = "";
        for (var i = 0; i < fields.length; i++) {
            values["$" + fields[i]] = data[fields[i]];
            query +=  ", " + fields[i] + " = " + "$" + fields[i];
        }
        console.info("Updating record…");
        console.log("Query: " + "UPDATE Records SET Modified = $Modified" + query + " WHERE UserID = $UserID AND UUID = $UUID;");
        return Q.ninvoke(db,"run","UPDATE Records SET Modified = $Modified" + query + " WHERE UserID = $UserID AND UUID = $UUID;",values).then(function() {
            console.log("Record " + recordID + " updated");
            return true;
        });
    }).then(handleSuccess.bind(this,res),handleFail.bind(this,res));
}

function postRecord(sessionToken,record,res) {
    console.log("Objekt anlegen: " + JSON.stringify(record));
    getSession(sessionToken).then(function(result) {
        if (!result) 
            return Q.reject({msg:"error.invalidSession",cerror:true});
        console.log(result);
        return addRecord(result.UserID,record);
    }).then(function(recordID) {
        return {id:recordID};
    }).then(handleSuccess.bind(this,res),handleFail.bind(this,res));
}

function getRecords(sessionToken,recordID,res) {
    getSession(sessionToken).then(function(result) {
        if (!result) 
            return Q.reject({msg:"error.invalidSession",cerror:true});
        if (!recordID) 
            return getAllRecords(result.UserID);
        else
            return getRecordByID(recordID,result.UserID);
    }).then(function(result) {
        if (result instanceof Array) {
            var data = [];
            for (var i = 0; i < result.length; i++) {
                data.push(mapFields(result[i]));
            }
            return data;
        } else {
            return mapFields(result);
        }
    }).then(handleSuccess.bind(this,res),handleFail.bind(this,res));
}

function removeRecord(userID,recordID) {
    return Q.ninvoke(db,"run","DELETE FROM Records WHERE UserID = ? AND UUID = ?;",userID,recordID).then(function() {
        console.log("Record " + recordID + " removed");
        return true;
    });
}


function mapFields(result) {
    var data = {};
    for (var i = 0; i < fields.length; i++) {
        data[fields[i]] = result[fields[i]];
    }
    data.id = result.UUID;
    return data
}

function addRecord(userID,data) {
    do {
        var recordID = crypto.randomBytes(25).toString("base64");
    } while (recordID[0] == "c")
    //Eventuell noch schauen obs die ID schon gibt
    var values = {
        $UUID: recordID,
        $UserID: userID,
        $Created: new Date().getTime(),
        $Modified: new Date().getTime()
    };
    for (var i = 0; i < fields.length; i++) {
        values["$" + fields[i]] = data[fields[i]];
    }
    console.info("Adding record…");
    return Q.ninvoke(db,"run","INSERT INTO Records (UUID, UserID, Created, Modified, " + fields.join(", ") + ") VALUES ($UUID, $UserID, $Created, $Modified, $" + fields.join(", $") + ");",values).then(function() {
        console.log("Record " + recordID + " created");
        return recordID;
    });
}

function recordExist(recordID,userID) {
    return getRecordByID(recordID,userID).then(function(result) {
        return !!result;
    });
}

function getRecordByID(recordID,userID) {
    return Q.ninvoke(db,"all","SELECT UUID," + fields.join(",") + " FROM Records WHERE UserID = ? AND UUID = ?;",userID,recordID).then(function(rows) {
        if (rows.length != 1) {
            return null;
        }
        return rows[0];
    });
}

function getAllRecords(userID) {
    return Q.ninvoke(db,"all","SELECT UUID," + fields.join(",") + " FROM Records WHERE UserID = ?;",userID).then(function(rows) {
        return rows;
    });
}

function createSession(username) {
    var sessionToken = crypto.randomBytes(100).toString("base64");
    //Eventuell noch schauen obs die Session schon gibt
    
    return addSession(username,sessionToken).then(function() {
        console.log("Session " + sessionToken + " created");
        return sessionToken;
    });
}

function addSession(username,sessionToken) {
    console.info("Set Session: " + username + " to " + sessionToken);
    return Q.ninvoke(db,"run","UPDATE User SET SessionToken = ? WHERE Username = ? COLLATE NOCASE;",sessionToken,username);
}

function removeSession(sessionToken) {
    console.info("Removing session " + sessionToken);
    return Q.ninvoke(db,"run","UPDATE User SET SessionToken = NULL WHERE SessionToken = ?;",sessionToken);
}

function getSession(sessionToken) {
    console.info("Getting session " + sessionToken + " …");
    return Q.ninvoke(db,"all","SELECT Username,UserID,Banned,Banreason,Activated FROM User WHERE SessionToken = ? AND Banned is not 1 AND Activated = 1;",sessionToken).then(function(rows) {
        console.info("Got session");
        if (rows.length != 1) {
            return null;
        }
        return rows[0];
    });
}

function sessionExist(sessionToken) {
    return getSession(sessionToken).then(function(result) {
        return !!result;
    });
}

function checkUserPassword(username,password) {
    return Q.ninvoke(db,"all","SELECT Password,Banned,Banreason,Activated FROM User WHERE Username = ? COLLATE NOCASE;",username).then(function(rows) {
        if (rows.length === 1) {
            scrypt.verify.config.hashEncoding = "base64";
            scrypt.verify.config.keyEncoding  = "hex";
            console.log("ok");
            console.log(rows[0].Password);
            
            var deferred = Q.defer();
            scrypt.verify(rows[0].Password, password, scryptParams, deferred.makeNodeResolver());
            return deferred.promise.then(function(result) {
                if (result === true) {
                    if (rows[0].Banned == 1) {
                        return Q.reject({msg:"error.login.userBanned",banreason:rows[0].Banreason,cerror:true});
                    } else if (rows[0].Activated != 1) {
                        return Q.reject({msg:"error.login.userNotActivated",cerror:true});
                    }
                }
                return result;
            },function(error) {
                if (error.scrypt_err_code === 11) //Passwörter stimmen nicht überein
                    return Q(false);
                else 
                    return error;
            });
        } else {
            return false;
        }
    });
}

function handleSuccess(res,result) {
    console.log("fertig");
    res.send({success:true,result:result});
}

function handleFail(res,error) {
    if (error.cerror === true) {
        console.log(error);
        delete error.cerror;
        res.status(400).send({error: error });
    } else {
        console.error(error);
        res.status(500).send({error: {msg:"error.server.undefined"} });
    }
}

function userExist(username) {
	return Q.ninvoke(db,"all","SELECT UserID FROM User WHERE Username = ? COLLATE NOCASE;",username).then(function(rows) {
		return rows.length !== 0;
	});
}

function addNewUser(username,password,salt) {
	scrypt.hash.config.keyEncoding = "hex";
	scrypt.hash.config.outputEncoding = "base64";
	console.log("ok");
    
    var deferred = Q.defer();
    scrypt.hash(password, scryptParams, deferred.makeNodeResolver());
    return deferred.promise.then(function(result) {
        console.log(result);
        return Q.ninvoke(db,"run","INSERT INTO User (Username, Password, Salt, RegisterDate,Activated) VALUES ($username, $password, $salt, $date, $Activated)",{
            $username: username,
            $password: result,
            $salt: JSON.stringify(salt),
            $date: new Date().getTime(),
            $Activated: Number(config.skipAccountActivation)
        });
    });
}

function doGetUserSalt(username) {
    return Q.ninvoke(db,"all","SELECT Salt FROM User WHERE Username = ? COLLATE NOCASE;",username).then(function(rows) {
        if (rows.length !== 1) {
            return Q.reject({msg:"error.getUserSalt.userDoesNotExist",cerror:true});
        }
        else {
            return JSON.parse(rows[0].Salt);
        }
    });
}