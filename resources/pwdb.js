var serverRoot = "/pwdb/";
var getUserSaltTimer;
var userSalt = {};
var session = {}; //token, password, username
var fields = [
    {name:"website", type:"text", title: "Website"},
    {name:"username", type:"text", title: "Benutzername"},
    {name:"password", type:"password",title: "Passwort"},
    {name:"notes", type:"textarea",title: "Notizen"}
];
var recordModel;
var records;
var currentRecord;
var searchJobs = [];
var loadingCounter = 0;
var touch = !!('ontouchstart' in window);

var _passwordDummy = "NotThePassword";

function sendToServer(path,data,success,error) {
    data.sessiontoken = session.token;
    addLoad();
	$.ajax(serverRoot + path,{
		type: "POST",
		contentType: "application/json",
		data: JSON.stringify(data),
		success: handleAJAXSuccess.bind(this,error,success),
		error: handleAJAXError.bind(this,error) 
	});
}

function handleAJAXSuccess(errorCallback,successCallback,result,textStatus,xhr) {
    removeLoad();
    if (result.error && errorCallback) 
        errorCallback(xhr,xhr.status,textStatus,result.error);
    else if (!result.error && successCallback)
        successCallback(result.result,xhr.status,xhr);
}

function handleAJAXError(errorCallback,xhr,textStatus,error) {
    removeLoad();
    result = xhr.responseJSON || {};
    if (errorCallback) {
        errorCallback(xhr,xhr.status,textStatus,result.error);
    }
}

function init() {
    recordModel = Backbone.Model.extend({
        initialize: function() {
            this.on("change",function() {
                var eintrag = getRecordInList(this);
                this.getHeading().then(function(result) {
                    eintrag.find("h4").text(result);
                });
                this.getText().then(function(result) {
                    eintrag.find("p").text(result);
                });
                clearTimeout(this.saveTimer);
                this.saveTimer = setTimeout(this.save.bind(this),500);
            });
            this.jobs = {};
        },
        getText: function() {
            return this.getE("username").then(function(result) {
                return result || "(empty)";
            },function() {
                return "(error)";
            });
        },
        getHeading: function() {
            return this.getE("website").then(function(result) {
                return result || "(empty)";
            },function() {
                return "(error)";
            });
        },
        saveTimer: null,
        getE: function(attr) {
            var val = this.get(attr);
            if (val === "" || val == null) {
                return Promise.resolve(val);
            }
            try {
                val = $.parseJSON(val);
                val.iv = new Uint8Array(val.iv);
                val.data = new Uint8Array(val.data);
                return decryptData(str2ab(session.password),val).then(function(result) {
                    return ab2str(result);
                });
            } catch(e) {
                console.error("Could not decrypt field content");
                return Promise.reject("Could not decrypt field content");
            }
        },
        setE: function(key, val, options) {
            var me = this;
            this.abortJobs(key);
            var job = {};
            this.addJob(key,job);
            
            var salt;
            if (this.changedAttributes()) {
                try {
                    salt = new Uint8Array(JSON.parse(this.get(key)).iv);
                } catch(e) {
                    salt = undefined;
                }
            }
            return encryptData(str2ab(session.password),str2ab(val),salt).then(function(encryptedData) { //Wenn dieser Record schon geändert wurde, dann Salz vom letzten mal nehmen -> schneller
                if (job.abort) {
                    return;
                }
                var result = {};
                result.data = Array.apply(Array,new Uint8Array(encryptedData.data));
                result.iv = Array.apply(Array,encryptedData.iv);
                return me.set(key,JSON.stringify(result),options);
            });
        },
        jobs: undefined, //Wird in initialize als Objekt angelegt, weil es sonst dasselbe Objekt wäre
        addJob: function(attr,job) {
            if (!this.jobs[attr])
                this.jobs[attr] = [];
            this.jobs[attr].push(job);
        },
        abortJobs: function(attr) {
            if (!this.jobs[attr])
                return;
            for (var i = 0; i < this.jobs[attr].length; i++) {
                this.jobs[attr][i].abort = true;
                this.jobs[attr].splice(i,1);
            }
        }
    });
    
    $("#searchField").on("input",function() {
        search($(this).val());
    });
    $("#addRecordButton").action(addRecord);
    ladenFertig();
	showLoginScreen();
    $("#LogoutButton").action(logout);
    $("#Liste").on("keydown",handleListeKeyDown);
    $(window).on("keydown",handleWindowKeyDown);
    $("#showTrafficButton").action(showTraffic);
}

function handleWindowKeyDown(event) {
    if (event.metaKey && (event.keyCode == 78 || event.keyCode == 187)) {
        event.preventDefault();
        addRecord();
    }
}
                   
function handleListeKeyDown(event) {
        if (event.keyCode == 38) {
            event.preventDefault();
            var record = $("#Liste").children(".active").prev().data("record");
            if (record)
                selectRecord(record);
        } else if (event.keyCode == 40) {
            event.preventDefault();
            var record = $("#Liste").children(".active").next().data("record");
            if (record)
                selectRecord(record);
        } else if (event.keyCode == 8) {
            removeRecord(currentRecord);
        }
}

function getRecordInList(record) {
    return $("#Liste").children().filterData("record",record);
}

function ladenFertig() {
	PopUpSchliessen("LadenPopUp");
}

function showLoginScreen() {
	PopUp(createLoginScreen(),"LoginPopUp");
}

function register(username,password) {
    disableRegisterControls();
    clearRegisterMsg();
    
    window.URL = window.URL || window.webkitURL;
    var blob = new Blob(['importScripts("https://' + location.host + serverRoot + 'resources/scrypt.js"); onmessage = function(e) {var scrypt = scrypt_module_factory(); self.postMessage(scrypt.to_hex(scrypt.crypto_scrypt(scrypt.encode_utf8(e.data.password), e.data.salz, 16384, 8, 1, 64)));}']);
    var blobURL = window.URL.createObjectURL(blob); //Create blob-URL for hashing
    
    var salz = window.crypto.getRandomValues(new Uint8Array(64));
    
    var worker = new Worker(blobURL);
    worker.onmessage = function(e) {
        var hashHex = e.data;
        sendToServer("register",{username:username,password:hashHex,salt:Array.apply(Array,salz)},function() { //Das Uint8Array wird in ein normales Array umgewandelt
            enableRegisterControls();
            userSalt = {}; //Salz löschen, damit da nicht mehr drin steht, dass der gerade angelegte Account nicht existiert
            xhrs = []; //Aufrufe löschen, falls danach nicht angemeldet wird
            showRegisteredMsg();
        },function(xhr,status,textStatus,pwdbError) {
            enableRegisterControls();
            xhrs = []; //Aufrufe löschen, damit ein mögliches Passwort nicht im log steht
            if (pwdbError && pwdbError.msg == "error.register.alreadySameUsername") {
                showRegisterMsg("Dieser Benutzername existiert bereits");
            } else if (status == 0) {
                showRegisterMsg("Es konnte keine Verbindung zum Server hergestellt werden");
            } else if (status != 200) {
                showRegisterMsg("Es ist ein Server-Fehler aufgetreten");
            } else {
                showRegisterMsg("Es ist ein unbekannter Fehler beim Registrieren aufgetreten");
            }
        });
    };
    worker.postMessage({password:password,salz:salz});
}

function showRegisteredMsg() {
    $register = $("#register");
    $register.html(null);
    $register.append(
        $.create("h3").text("Sie haben sich erfolgreich registriert ").append($.create("br")).append(
            $.create("small").text("Sie können sich nun anmelden")
        )
    );
}

function doRegisterForm(event) {
	event.preventDefault();
	var username = $(this).find(".username").val();
	var password = $(this).find(".password").val();
    if (!username || !password)
        return;
	register.call(this,username,password);
}

function showRegisterMsg(msg) {
    $("#register").find(".warningLabel").html(nen(msg));
}

function clearRegisterMsg() {
    $("#register").find(".warningLabel").text("");
}

function disableRegisterControls() {
    $("#register").find("input,button").attr("disabled","disabled");
}

function enableRegisterControls() {
    $("#register").find("input,button").removeAttr("disabled");
}

function doGetUserSalt(callback) {
    var username = $("#login .username").val();
    if (username != "" && !userSalt.hasOwnProperty(username)) {
        sendToServer("usersalt",{username:username},function(result) {
            userSalt[username] = new Uint8Array(result);
            if (callback)
                callback();
        },function(xhr,status,statusText,pwdbError) {
            if (pwdbError && pwdbError.msg === "error.getUserSalt.userDoesNotExist") {
                userSalt[username] = undefined;
            } else if (status == 0) {
                showLoginMsg("Es konnte keine Verbindung zum Server hergestellt werden");
            } else if (status != 200) {
                showLoginMsg("Es ist ein Server-Fehler aufgetreten");
            } else {
                showLoginMsg("Es ist ein unbekannter Fehler beim Verbinden mit dem Server aufgetreten");
            }
            
            if (callback)
                callback();
        });
    } else {
        if (callback)
            callback();
    }
}

function getUserSalt() {
    clearTimeout(getUserSaltTimer);
    getUserSaltTimer = setTimeout(doGetUserSalt,500);
    currentSalt = undefined;
}

function logout() {
    disableLogoutControls();
    sendToServer("logout",{}, function() {
        enableLogoutControls();
        session.password = "";
        session = {};
        xhrs = [];
        records.reset();
        currentRecord = undefined;
        abortJobs();
        searchJobs = [];
        hideUsername();
        showLoginScreen();
        removeFields();
    },function() {
        enableLogoutControls();
        alert("Could not logout");
    });
}

function disableLogoutControls() {
    $("#LogoutButton").attr("disabled","disabled");
}

function enableLogoutControls() {
    $("#LogoutButton").removeAttr("disabled");
}

function showLoginMsg(msg) {
    $("#login").find(".warningLabel").html(nen(msg));
}

function clearLoginMsg() {
    $("#login").find(".warningLabel").text("");
}

function login(username,password) {
    if (!userSalt.hasOwnProperty(username)) {
        enableLoginControls();
        return;
    }
    
    if (userSalt[username] === undefined) {
        enableLoginControls();
        showLoginMsg("User does not exist");
        return;
    }
    
    var salt = userSalt[username];
    
    disableLoginControls();
    window.URL = window.URL || window.webkitURL;
    var blob = new Blob(['importScripts("https://' + location.host + serverRoot + 'resources/scrypt.js"); onmessage = function(e) {var scrypt = scrypt_module_factory(); self.postMessage(scrypt.to_hex(scrypt.crypto_scrypt(scrypt.encode_utf8(e.data.password), e.data.salz, 16384, 8, 1, 64)));}']);
    var blobURL = window.URL.createObjectURL(blob); //Create blob-URL for hashing
    
    var worker = new Worker(blobURL);
    worker.onmessage = function(e) {
        var hashHex = e.data;
        sendToServer("login",{username:username,password:hashHex},function(result) {
            session.token = result.sessiontoken;
            session.password = password;
            session.username = username;
            PopUpSchliessen("LoginPopUp");
            showUsername();
            getData();
        },function(xhr,status,textStatus,pwdbError) {
            enableLoginControls();
            xhrs = []; //Falls man sich dann nicht mehr einloggt, damit niemand das Passwort erraten kann
            if (pwdbError && pwdbError.msg === "error.login.wrongPassword") {
                showLoginMsg("Falsches Passwort");
            } else if (pwdbError && pwdbError.msg === "error.login.userNotActivated") {
                showLoginMsg("Dieser Account ist noch nicht aktiviert. Bitte fragen sie einen Admin");
            } else if (pwdbError && pwdbError.msg === "error.login.userBanned") {
                showLoginMsg("Dieser Account wurde gesperrt" + ((pwdbError.banreason) ? "\nGrund: " + pwdbError.banreason : ""));
            } else if (status == 0) {
                showLoginMsg("Es konnte keine Verbindung zum Server hergestellt werden");
            } else if (status != 200) {
                showLoginMsg("Es ist ein Server-Fehler aufgetreten");
            } else {
                showLoginMsg("Es ist ein unbekannter Fehler beim Anmelden aufgetreten");
            }
        });
    };
    worker.postMessage({password:password,salz: salt});
}

function disableLoginControls() {
    $("#login").find("input,button").attr("disabled","disabled");
}

function enableLoginControls() {
    $("#login").find("input,button").removeAttr("disabled");
}

function doLoginForm(event) {
    event.preventDefault();
    clearLoginMsg();
    var username = $(this).find(".username").val();
	var password = $(this).find(".password").val();
    if (!username || !password)
        return;
    disableLoginControls();
    if (!userSalt.hasOwnProperty(username)) {
        doGetUserSalt(function() {
            login.call(this,username,password);
        }.bind(this));
        return;
    }
    login.call(this,username,password);
}

function addLoad() {
    loadingCounter++;
    showLoading();
}

function removeLoad() {
    if (--loadingCounter <= 0)
        hideLoading();
}

function showLoading() {
    $("#brandSpin").addClass("loading");
}

function hideLoading() {
    $("#brandSpin").removeClass("loading");
}

function addRecord(event) {
    if (event)
        event.preventDefault();
    records.add({});
    var record = records.last();
    record.setE("website","Neuer Eintrag").then(function() {
        selectRecord(record);
        $("#Content").find("input,textarea").filterID(fields[0].name).select();
        selectShowPasswordButton();
        showPassword({noFocus:true});
    },function(error) {
        console.error(error);
    });
}

function deselect() {
    $("#Content").find("input,textarea").val("");
    $("#Content").find("input,textarea,button").attr("disabled","disabled");
    currentRecord = null;
    hidePassword();
    deselectShowPasswordButton();
}

function deselectAllRecords() {
    $("#Liste").find(".active").removeClass("active");
}

function deselectShowPasswordButton() {
    var button = $("#TogglePasswordButton");
    if (button.hasClass("active"))
        button.button("toggle");
}

function selectShowPasswordButton() {
    var button = $("#TogglePasswordButton");
    if (!button.hasClass("active"))
        button.button("toggle");
}

function selectRecord(record) {
    hidePassword();
    $("#Content").find("input,textarea,button").removeAttr("disabled");
    deselectShowPasswordButton();
    currentRecord = record;
    deselectAllRecords();
    var eintrag = getRecordInList(record);
    $("#Liste").ScrollTo(eintrag);
    eintrag.addClass("active");
    
    for (var i = 0; i < fields.length; i++) {
        setFieldValue(fields[i].name,record);
    }
}
                                                              
function setFieldValue(field,record) {
    var element = $("#Content").find("input,textarea").filterID(field)
    if (field === "password") {
        element.val(_passwordDummy);
        element.attr("readonly","readonly");
        return;
    }
    element.removeAttr("readonly");
    
    record.getE(field).then(function(result) {
        element.val(result);
    },function() {
        alert("Could not decrypt " + field);
        element.val("");
    });
}

function addRecordToList(record) {
    var eintrag = $.create("a").attr("href","#").addClass("list-group-item").action(function(event) {
        event.preventDefault();
        selectRecord(record);
    }).data("record",record);
    var heading = $.create("h4").addClass("list-group-item-heading").text("Loading…")
    var text = $.create("p").addClass("list-group-item-text").text("Loading…");
   
    record.getHeading().then(function(result) {
        heading.text(result);
    });
    record.getText().then(function(result) {
        text.text(result);
    });
    
    eintrag.append(heading).append(text);
    $("#Liste").append(eintrag);
    
}

function removeRecordFromList(record) {
    getRecordInList(record).remove();
    deselect();
}

function resetList() {
    deselect();
    $("#Liste").children().remove();
}

function removeFields() {
    $("#Content").children().remove();
}

function makeFields() {
    removeFields();
    for (var i = 0; i < fields.length; i++) {
        addField(fields[i],i);
    }
    var btnGroup = $.create("div").addClass("btn-group").attr("role","group").appendTo("#Content");
    btnGroup.append(
         $.create("button").attr("type","button").addClass("btn btn-danger btn-lg").text("Löschen").action(function() {
             removeRecord(currentRecord);
         })
    );
     btnGroup.append(
         $.create("button").attr("type","button").addClass("btn btn-primary btn-lg").attr("id","TogglePasswordButton").attr("data-toggle","button").attr("aria-pressed","false").attr("autocomplete","off").text("Passwort einblenden").action(togglePassword)
     );
    if (!touch) {
        btnGroup.append(
             $.create("button").attr("type","button").addClass("btn btn-primary btn-lg").text("Passwort kopieren").action(copyPassword)
         );
    }
    deselect();
}

function addField(field,index) {
    var formGroup = $.create("div").addClass("form-group")
    formGroup.append(
        $.create("label").attr("for",field.name).addClass("col-sm-2 control-label").text(field.title)
    );
    formGroup.append(
        $.create("div").addClass("col-sm-10").append(
            $.create((field.type == "textarea") ? "textarea" : "input").attr("type", field.type).attr("tabindex",index+1).attr("id",field.name).addClass("form-control").on("input",function() {
                if (!$(this).attr("readonly"))
                  currentRecord.setE(field.name,$(this).val());
            })
        )
    );
    $("#Content").append(formGroup);
}

function removeRecord(record) {
    if (confirm("Wirklich löschen?")) {
        var oldRecord = getRecordInList(record);
        var newRecord = oldRecord.next().data("record") || oldRecord.prev().data("record");
        record.destroy();
        if (newRecord)
            selectRecord(newRecord);
    }
}

function getData() {
    records = new Backbone.Collection([], {
        model: recordModel
    });
    records.on("add",addRecordToList);
    records.on("remove",removeRecordFromList);
    records.on("reset",resetList);
    
    records.fetch();
    
    makeFields();
}

function showUsername() {
    $("#AngemeldetText").text("Angemeldet als " + session.username);
}

function hideUsername() {
    $("#AngemeldetText").text("Nicht angemeldet");
}

function togglePassword() {
    if ($(this).hasClass("active"))
        hidePassword();
    else
        showPassword();
}

function hidePassword() {
    var element = $("#Content").find("input,textarea").filterID("password");
    element.attr("readonly","readonly");
    element.attr("type","password");
    element.val(_passwordDummy);
}

function showPassword(options) {
    options = options || {};
    var element = $("#Content").find("input,textarea").filterID("password")
    currentRecord.getE("password").then(function(result) {
        element.val(result);
        element.removeAttr("readonly");
        element.attr("type","text");
        if (!options.noFocus)
            element.select().focus();
    },function() {
        alert("Could not decrypt password");
        element.val("");
        element.removeAttr("readonly");
        element.attr("type","text");
    });
}

function copyPassword() {
    currentRecord.getE("password").then(function(result) {
        result = result || " "; //Wenn das Passwort leer ist, wird ein Leerzeichen benutzt, weil man nichts nicht markieren und kopieren kann
        var closeFunc = function() {
            $("html").off("click",closeFunc); //Click-Event wird deaktiviert
            PopUpSchliessen("CopyPasswordPopUp");
        };
        var field = $.create("input").attr("type","text").attr("readonly","readonly").val(result).addClass("hiddenPasswordField").blur(closeFunc).on("keydown",function(event) {
            if (event.metaKey && event.keyCode == 67) { //Wenn cmd + c gedrückt wird, wird das PopUp nach 100 ms geschlossen
                setTimeout(closeFunc,100); //Erst nach 100 ms, damit das Kopieren überhaupt stattfindet
            }
        }); //Das Feld wird außerhalb des Viewports angezeigt
        PopUp($.create("h2").html("Drücken sie jetzt <kbd><kbd>cmd</kbd> + <kbd>c</kbd></kbd> zum Kopieren").add(field),"CopyPasswordPopUp");
        $("html").on("click",closeFunc);
        field.select().focus();
    },function() {
        alert("Fehler");
    });
}

function notSupported() {
    PopUp($.create("h2").text("Dieser Browser wird wahrscheinlich nicht unterstützt").append($.create("br")).append($.create("small").text("Bitte verwenden sie die neueste Version von Chrome, Firefox oder Safari")).add($.create("button").text("OK").addClass("btn btn-lg btn-primary").action(PopUpSchliessen.bind(this,"NotSupportedPopUp"))),"NotSupportedPopUp");
}

function checkSupport() {
    //Überprüfen, ob die benötigten Crypto-Apis vorhanden sind. Es wird jedoch nur geprüft, ob die Funktionen da sind und nicht, ob z.B. SHA verfügbar ist
    if (!(crypto.getRandomValues && cryptoSub && cryptoSub.digest && cryptoSub.importKey && cryptoSub.encrypt && cryptoSub.decrypt)) {
        notSupported();
        return;
    }
}


var cryptoSub = crypto.subtle || crypto.webkitSubtle || crypto.msSubtle;
checkSupport();

//Funktion zum Verschlüsseln der Daten
function encryptData(password, data, salt) {
    return cryptoSub.digest({ name: "SHA-256" }, password).then(function (digestHash) { //SHA-256-Hash erzeugen
        return cryptoSub.importKey("raw", digestHash, { name: "AES-CBC" }, true, ["encrypt","decrypt"]);
        
    }).then(function (digestKey) {
        if (!salt)
            salt = crypto.getRandomValues(new Uint8Array(16));
        var aesAlgorithmEncrypt = {
            name: "AES-CBC",
            iv: salt
        };
        return cryptoSub.encrypt(aesAlgorithmEncrypt, digestKey, data);
        
    }).then(function (ciphertextArrayBuffer) {
        return {data:ciphertextArrayBuffer,iv:salt};
    });

}

//Funktion zum Entschlüsseln der Daten
//siehe encryptData
function decryptData(password, data) {
    return cryptoSub.digest({ name: "SHA-256" }, password).then(function (digestHash) {
        return cryptoSub.importKey("raw", digestHash, { name: "AES-CBC" }, true, ["encrypt","decrypt"]);
        
    }).then(function (digestKey) {
        var aesAlgorithmEncrypt = {
            name: "AES-CBC",
            iv: data.iv
        };
        return cryptoSub.decrypt(aesAlgorithmEncrypt, digestKey, data.data);
        
    }).then(function (ciphertextArrayBuffer) {
        return ciphertextArrayBuffer;
    }); 

}

//Such-Jobs abbrechen, damit die erste Suche nicht vor der zweiten fertig wird und dadurch die falsche angezeigt wird
function abortJobs() {
    for (var i = 0; i < searchJobs.length; i++) {
        searchJobs[i].abort = true;
        searchJobs.splice(i,1);
    }
}

function search(value) {
    abortJobs();
    var job = {};
    searchJobs.push(job);
    if (value == "" || value == null) {
        showAll();
        return;
    }
    filterRecords(value).then(function(result) {
        if (job.abort) {
            return;
        }
        resetList();
        var unique = _.unique(result);
        for (var i = 0; i < unique.length; i++) {
            addRecordToList(unique[i]);
        }
    },function(error) {
        console.error(error);
    });
}

function showAll() {
    resetList();
    for (var i = 0; i < records.length; i++) {
        addRecordToList(records.at(i));
    }
}

function filterRecords(value) {
    var filtered = [];
    var proms = [];
    for (var i = 0; i < records.length; i++) {
        for (var j = 0; j < fields.length; j++) {
            if (fields[j].type != "password")
                applyFilter(value,proms,filtered,fields[j],records.at(i));
        }
    }
    return Promise.all(proms).then(function() {
        return filtered;
    });
}

function applyFilter(value,proms,filtered,field,r) {
    proms.push(r.getE(field.name).then(function(result) {
        if (result != null && result.toLocaleLowerCase().indexOf(value.toLocaleLowerCase()) != -1) {
            filtered.push(r);
        }
    },function(error) {
        console.error("Could not search: " + error);
    }));
}




function createLoginScreen() {
	var els = $.create("div").attr("role","tabpanel").append(
		$.create("ul").addClass("nav nav-tabs").attr("role","tablist").append(
			$.create("li").attr("role","presentation").addClass("active").append(
				$.create("a").attr("href","#login").attr("aria-controls","login").attr("role","tab").attr("data-toggle","tab").text("Anmelden")
			)
		).append(
			$.create("li").attr("role","presentation").append(
				$.create("a").attr("href","#register").attr("aria-controls","register").attr("role","tab").attr("data-toggle","tab").text("Registrieren")
			)
		)
	).append(
		$.create("div").addClass("tab-content").append(
			$.create("div").attr("role","tabpanel").addClass("tab-pane active").attr("id","login").append(
				$.create("form").attr("role","form").addClass("form-signin").on("submit",doLoginForm).append(
					$.create("h2").addClass("form-signin-heading").text("Anmelden")
				).append(
					$.create("input").attr("type","text").addClass("form-control username").attr("placeholder","Benutzername").attr("require","required").on("input",getUserSalt)
				).append(
					$.create("input").attr("type","password").addClass("form-control password").attr("placeholder","Passwort").attr("require","required")
                ).append(
                    $.create("p").addClass("text-danger warningLabel")
				).append(
					$.create("button").attr("type","submit").addClass("btn btn-lg btn-primary btn-block").text("Anmelden")
				)
			)
		).append(
			$.create("div").attr("role","tabpanel").addClass("tab-pane").attr("id","register").append(
				$.create("form").attr("role","form").addClass("form-signin").on("submit",doRegisterForm).append(
					$.create("h2").addClass("form-signin-heading").text("Registrieren")
				).append(
					$.create("input").attr("type","text").addClass("form-control username").attr("placeholder","Benutzername").attr("require","required")
				).append(
					$.create("input").attr("type","password").addClass("form-control password").attr("placeholder","Passwort").attr("require","required")
				).append(
                    $.create("p").addClass("text-danger warningLabel")
				).append(
					$.create("button").attr("type","submit").addClass("btn btn-lg btn-primary btn-block").text("Registrieren")
				)
			)
		)
	);
	return els;
}




//Modifizierter Backbone-Sync
Backbone.sync = function(method, model, options) {
    addLoad();
    var type = methodMap[method]; //HTTP-Funktion raussuchen
    
    var data = {method:type,sessiontoken:session.token}; //Body-Data vorbereiten
    data.id = model.id;
      
    if (method === "create" || method === "update") { //Zu sendende Daten vom Model vorbereiten
      data.data = model.toJSON(options);
    }
    
    var params = {type: "POST", dataType: 'json'};
    params.url = serverRoot + "records";
    params.contentType = "application/json";
    params.data = JSON.stringify(data);
    params.processData = false; //Damit jQuery das nicht in die URL-Parameter packt
    params.success = function(resp) {
        removeLoad();
        if (options.success)
            options.success(resp.result);
    };
    params.error = function(xhr) {
        removeLoad();
        if (options.error)
            options.error(xhr);
        if (xhr.responseJSON && xhr.responseJSON.error && xhr.responseJSON.error.msg == "error.invalidSession") {
            alert("Die Session ist ungültig. Versuchen Sie sich erneut anzumelden.");
        } else if (status == 0) {
            alert("Es konnte keine Verbindung zum Server hergestellt werden");
        } else if (status != 200) {
            alert("Es ist ein Server-Fehler beim Speichern aufgetreten");
        } else {
            alert("Es ist ein unbekannter Fehler beim Speichern aufgetreten");
        }
    };
    
    var xhr = options.xhr = Backbone.ajax(params);
    model.trigger('request', model, xhr, options);
    return xhr;
  };

  var methodMap = {
    'create': 'POST',
    'update': 'PUT',
    'delete': 'DELETE',
    'read':   'GET'
  };



//Für Datenverkehraufzeichnung

function showTraffic() {
    function getHeadersAsString(headers) {
        var erg = "";
        for (var i = 0; i < headers.length; i++) {
            erg += headers[i].name + ": " + headers[i].value + "\n";
        }
        return erg;
    }
    
    var element = $.create("ul").attr("id","TrafficList").text("Au Sicherheitsgründen enthält dieses Prokoll nur die Daten seit dem letzten Login");
    for (var i = 0; i < xhrs.length; i++) {
        element.append(
            $.create("li").html(nen(xhrs[i].methode + " " + xhrs[i].url + "\n" + getHeadersAsString(xhrs[i].header) + "\n" + xhrs[i].parameter))
        );
    }
    element.append(
        $.create("button").attr("type","button").action(function() {
            PopUpSchliessen("TrafficPopUp");
        }).addClass("btn btn-lg btn-primary").text("Schließen")
    );
    
    PopUp(element,"TrafficPopUp");
}

var xhrs;

function enableProtocol() {
    xhrs = [];
    var oldSend = XMLHttpRequest.prototype.send;
    var oldOpen = XMLHttpRequest.prototype.open;
    var oldSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
    XMLHttpRequest.prototype.send = function(parameter) {
        this.protocolXHRs.parameter = parameter;
        xhrs.push(this.protocolXHRs);
        oldSend.apply(this,arguments);
    };
    XMLHttpRequest.prototype.open = function(methode,url) {
        this.protocolXHRs = {};
        this.protocolXHRs.methode = methode;
        this.protocolXHRs.url = url;
        oldOpen.apply(this,arguments);
    };
    XMLHttpRequest.prototype.setRequestHeader = function(name,value) {
        if (!this.protocolXHRs.header)
            this.protocolXHRs.header = [];
        this.protocolXHRs.header.push({name:name,value:value});
        oldSetRequestHeader.apply(this,arguments);
    };
}

enableProtocol();
$(init);



//Aus gemeinsam.js:

$.fn.action = function(Action, ActionAtStart, noPrevent)
{
	if (touch == true)
	{
		ButtonAction($(this), function(event)
		{
			Action.call($(this),event);
		},ActionAtStart,noPrevent);
	}
	else
	{
		$(this).bind("click",function(event)
		{
			Action.call($(this),event);
		});
	}
	
	return $(this);
}

$.fn.removeAction = function(Action)
{
	if (touch == true)
	{
		ClearButtonActions(this,Action);
	}
	else
	{
		$(this).unbind("click",Action);
	}
}

function ButtonAction(Element, Action, ActionAtStart, noPrevent)
{
	if (ActionAtStart == true)
	{
		Element.bind("touchstart", function(event)
		{
			Action.call(this,event);
		});
		return;
	}
	
	Element.bind("touchend", function(event)
	{
		if ($(this).data("ignoreTouchEnd") != true)
		{
			if (noPrevent != true) event.preventDefault();
			Action.call(this,event);
		}
		$(this).data("ignoreTouchEnd", null);
	});
	Element.bind("touchcancel", function()
	{
		$(this).data("Ydelta", null);
		$(this).data("Xdelta", null);
		$(this).data("ignoreTouchEnd", null);
	});
	Element.bind("touchmove", function()
	{
		if (Math.abs($(this).data("Ydelta") - event.pageY) >= 10 || Math.abs($(this).data("Xdelta") - event.pageX) >= 10)
		{
			$(this).data("Ydelta", null);
			$(this).data("Xdelta", null);
			$(this).data("ignoreTouchEnd", true);
		}
	});
	Element.bind("touchstart", function()
	{
		$(this).data("Ydelta", event.pageY);
		$(this).data("Xdelta", event.pageX);
	});
}

function ClearButtonActions(Element,Action)
{
	Element.unbind("touchend",Action);
	Element.unbind("touchcancel",Action);
	Element.unbind("touchmove",Action);
	Element.unbind("touchstart",Action);
};

$.fn.ScrollTo = function(ScrollElement,ForceCenter,SpacingTop,SpacingBottom)
{
	if (SpacingTop == null) SpacingTop = 0;
	if (SpacingBottom == null) SpacingBottom = 0;
	
	if ($(this).is($(window)))
	{
		if (ForceCenter != true)
		{
			if ($(ScrollElement).position().top - SpacingTop < $(this).scrollTop())
			{
				var ScrollPos = $(ScrollElement).position().top - SpacingTop;
				$(this).scrollTop(ScrollPos);
				return ScrollPos;
			}
			else if($(ScrollElement).position().top + $(ScrollElement).outerHeight(true) + SpacingBottom > $(this).innerHeight() + $(this).scrollTop())
			{
				var ScrollPos = ($(ScrollElement).position().top - $(this).innerHeight() + $(ScrollElement).outerHeight()) + SpacingBottom;
				$(this).scrollTop(ScrollPos);
				return ScrollPos;
			}
		}
		else
		{
			var ScrollPos = $(ScrollElement).offset().top - $(ScrollElement).outerHeight(true)/2 - $(this).innerHeight()/2;
			$(this).scrollTop(ScrollPos);
			return ScrollPos;
		}
	}
	else
	{
		if (ForceCenter != true)
		{
			if ($(ScrollElement).position().top - SpacingTop < 0)
			{
				var ScrollPos = $(this).scrollTop() + $(ScrollElement).position().top - SpacingTop;
				$(this).scrollTop(ScrollPos);
				return ScrollPos;
			}
			else if($(ScrollElement).position().top + $(ScrollElement).outerHeight(true) + SpacingBottom > $(this).innerHeight())
			{
				var ScrollPos = $(this).scrollTop() + ($(ScrollElement).position().top - $(this).innerHeight() + $(ScrollElement).outerHeight()) + SpacingBottom;
				$(this).scrollTop(ScrollPos);
				return ScrollPos;
			}
		}
		else
		{
			var ScrollPos = $(ScrollElement).offset().top - $(ScrollElement).outerHeight(true)/2 - $(this).innerHeight()/2;
			ScrollPos += $(this).scrollTop();
			$(this).scrollTop(ScrollPos);
			return ScrollPos;
		}
	}
	   
};

//http://stackoverflow.com/questions/4191386/jquery-how-to-find-an-element-based-on-a-data-attribute-value
$.fn.filterData = function(prop, val) {
    return this.filter(
        function() { 
        	if ($(this).data(prop) instanceof Date && val instanceof Date)
        		return $(this).data(prop) <= val && $(this).data(prop) >= val
        	return $(this).data(prop)==val;
		}
    );
}

$.fn.filterID = function(val) {
    return this.filter(
        function() {
        	return $(this).attr("id")==val;
		}
    );
}

$.create = function(tag)
{
	return ($(document.createElement(tag)));
};

function htmlEncode( html ) {
    return document.createElement( 'a' ).appendChild( 
        document.createTextNode( html ) ).parentNode.innerHTML;
};

function htmlDecode( html ) {
    var a = document.createElement( 'a' ); a.innerHTML = html;
    return a.textContent;
};

function nl2br (str, is_xhtml) {   
    var breakTag = (is_xhtml || typeof is_xhtml === 'undefined') ? '<br />' : '<br>';    
    return (str + '').replace(/([^>\r\n]?)(\r\n|\n\r|\r|\n)/g, '$1'+ breakTag +'$2');
}

function nen(Text)
{
	return nl2br(htmlEncode(Text));
}

function PopUp(Inhalt,id)
{
	var Overlay = $.create("div").addClass("Overlay");
	if (id)
		Overlay.attr("id",id);
	$("body").append(Overlay);
	
	var Rahmen = $.create("div").addClass("OverlayRahmen");
	
	function UpdateSize()
	{
		Overlay.css("line-height",$(".Overlay").height() + "px");
		Rahmen.css("max-height",$(".Overlay").height() + "px");
		Rahmen.css("max-width",$(".Overlay").width() + "px");
	}
	
	UpdateSize();
	$(window).resize(UpdateSize);
	
	Rahmen.append(Inhalt);
	Overlay.append(Rahmen);
}

function PromptPopUp(Content,OkCaption,CancelCaption)
{
	var promise = new Parse.Promise();
	PopUp(
		$.create("div").css("text-align","right").append(
			$.create("h2").text(Content)
		).add(
			$.create("button").addClass("white").text(OkCaption).action(function()
			{
				PopUpSchliessen(Content);
				promise.resolve();
			})
		).add(
			$.create("button").addClass("white").text(CancelCaption).action(function()
			{
				PopUpSchliessen(Content);
				promise.reject();
			})
		)
	,Content);
	return promise;
}

function PopUpSchliessen(id)
{
	if (id)
	{
		$(".Overlay").filterID(id).remove();
	}
	else
	{
		$(".Overlay").remove();
	}
}

function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint16Array(buf));
}

function str2ab(str) {
  var buf = new ArrayBuffer(str.length*2); // 2 bytes for each char
  var bufView = new Uint16Array(buf);
  for (var i=0, strLen=str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}