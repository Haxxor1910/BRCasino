// CONFIG
const config = require("./config");
const SERVER = config.server;
const AUTH = config.authentication;
// 

const md5 = require("md5");
const sha256 = require("sha256");
const uuid4 = require("uuid4");
const express = require("express");
const app = express();

const fs = require("fs");
const path = require("path");

const sslOptions = {
    cert: fs.readFileSync(path.join(__dirname, "certs/cl.crt")),
    key: fs.readFileSync(path.join(__dirname, "certs/cl.key")),
    requestCert: false
};

const server = require('https').Server(sslOptions, app);
// const server = require('http').Server(app);
const io = require('socket.io')(server);
const sharedsession = require("express-socket.io-session");
const session = require('express-session');
const redis = require('redis');
const redisClient = redis.createClient();
const redisStore = require('connect-redis')(session);
const bodyParser = require('body-parser');
const rateLimit = require("express-rate-limit");
const mysql = require('mysql');
const pool = mysql.createConnection(config.mysql);
const crypto = require("crypto");

const request = require("request");

const SECURE_TOKEN = config.secure_token;

const passport = require("passport");
const SteamStrategy = require("passport-steam").Strategy;

passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(obj, done) {
    done(null, obj);
});

passport.use(new SteamStrategy({
    returnURL: 'https://casino.bloodrage.eu/auth/steam/return',
    realm: 'https://casino.bloodrage.eu/',
    apiKey: '43CC694EA0BA16312630E648A134E99A'
  },
  function(identifier, profile, done) {
    process.nextTick(function () {
      profile.identifier = identifier;
      return done(null, profile);
    });
  }
));

redisClient.on('error', (err) => {
    console.error('Redis error: ', err);
});

pool.connect((err) => {
  if (err) return console.error(err);
  console.log('Database connected!');
  setInterval(() => {
    pool.query("SELECT 1");
  }, 60 * 60 * 1000);
});

server.listen(SERVER.port, "0.0.0.0", () => {
    console.log(`[SERVER] Listening to port :${SERVER.port}!`);
});

app.set('view engine', 'pug');
app.use('/', express.static('public'));
app.use(bodyParser.urlencoded({
    extended: true
}));
const SESSION = session({
    secret: AUTH.secret,
    name: "Bloodrage",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
    store: new redisStore({ host: 'localhost', port: 6379, client: redisClient, ttl: 86400 }),
});
app.use(passport.initialize());
app.use(SESSION);

io.use(sharedsession(SESSION, {
    autoSave: true
}));

app.get('/', authentication, (req, res) => {
    req.session.page = "/";
    req.session.save();
    checkIfBanned(req, res, () => {
        res.render('index', {
            user: req.user
        }); 
    });
});

app.get('/duels', authentication, (req, res) => {
    req.session.page = "/duels";
    req.session.save();
    checkIfBanned(req, res, () => {
        res.render('duels', {
            user: req.user
        });
    });
});

app.get('/jackpot', authentication, (req, res) => {
    req.session.page = "/jackpot";
    req.session.save();
    checkIfBanned(req, res, () => {
        res.render('jackpot', {
            user: req.user
        });
    });
});

app.get('/fair', authentication, (req, res) => {
    req.session.page = "/fair";
    req.session.save();
    checkIfBanned(req, res, () => {
        res.render('fair', {
            user: req.user
        });
    });
});

app.get('/profile', authentication, (req, res) => {
    req.session.page = "/profile";
    req.session.save();
    checkIfBanned(req, res, () => {
        if(!req.session.secret) return res.redirect("/");
        res.render('profile', {
            user: req.user
        });
    });
});

app.get('/affiliates', authentication, (req, res) => {
    req.session.page = "/affiliates";
    req.session.save();
    checkIfBanned(req, res, () => {
        if(!req.session.secret) return res.redirect("/");
        res.render('affiliates', {
            user: req.user
        });
    });
});

// GLOBALS
var antispamroulette;
var antispamduels;
var antispamjackpot;
var antispamendpoints;
var antispamchat;
var Roulette = {
    roundid: -1,
    fair: {},
    state: 0,
    ntimer: 10,
    timer: 20,
    curr_timer: 0,
    min_bet: 10,
    max_bet: 50000,
    bets: [],
    user_bets: {},
    history: [],
    rng: -1
};
var LRounds;
var User = {};

var CFS = {};

var Jackpot = {
    id: -1,
    state: -1,
    time: 0,
    amount: 0,
    hash: null,
    secret: null,
    timestamp: null,
    players: [],
    tickets: [],
    cplayers: [],
    colors: [
        "#F11745",
        "#F15BB5",
        "#FEE440",
        "#00BBF9",
        "#00F5D4",
        "#9d4edd",
        "#ffff3f",
        "#70e000",
        "#b9faf8",
        "#fb6376",
        "#b69121",
        "#4ecdc4",
        "#5465ff",
        "#adf7b6",
        "#2176ff",
        "#f9b4ed"
    ]
};

var CHATS = [];

var ousers = {};

// USER INTERFACE
init();
// 

io.on('connection', (socket) => {

    var user = false;
    var page = socket.handshake.session.page;

    if(page == "/") socket.emit("roulette timer", Roulette.fair.time_start, Roulette.fair.roundhash, fixRouletteTimer(Roulette.curr_timer));
    if(Roulette.history.length > 0 && page == "/") socket.emit("roulette history", Roulette.history);
    if(Roulette.rng > -1 && page == "/") socket.emit("roulette insta roll", Roulette.rng);

    if(page == "/" || page == "/duels" || page == "/jackpot") if(CHATS.length > 0) socket.emit("user messages", CHATS);

    socket.on("roulette", function(type, props) {
        if(type == "timer") socket.emit("roulette timer", Roulette.fair.time_start, Roulette.fair.roundhash, fixRouletteTimer(Roulette.curr_timer));
    });

    if(Roulette.bets.length > 0 && page == "/") socket.emit("roulette bets", Roulette.bets);

    if(page == "/fair") socket.emit("fair rounds", LRounds);

    // USER
    socket.on("user view profile", function(uuid) {
        pool.query("SELECT hidden, username, avatar, wagered, deposited, withdrawn, rbets, registered FROM users WHERE uuid = ?",[uuid], function(a,b) {
            if(a) throw a;

            if(b[0].hidden) socket.emit("view user profile", 0, {username: b[0].username, avatar: b[0].avatar});
            else socket.emit("view user profile", 1, b);
        });
    });
    // 

    // SEND CF DUELS
    if(page == "/duels") {
        sendDuels(socket);
    }
    // 

    // ADD ONLINE USER
    if(!ousers.hasOwnProperty(socket.request.connection.remoteAddress)) {
        ousers[socket.request.connection.remoteAddress] = 1;
        io.emit("online users", Object.keys(ousers).length);
    }
    // 

    // JACKPOT EMITS
    if(page == "/jackpot") {
        emitJackpotPlayers(socket);
        emitJackpotTimer(socket);
        emitJackpotRound(socket);
    }
    // 

    if(socket && socket.handshake && socket.handshake.session && socket.handshake.session.uid) {
        user = socket.handshake.session;
        var ip_address = socket.handshake.address;
        socket.join(user.uid);
        socket.join(user.steamid);

        User[user.uid] = user;

        if(page == "/profile") {
            pool.query("SELECT wagered, deposited, withdrawn, rbets FROM users WHERE id = ?", [user.uid], function(a,b) {
                if(a) throw a;

                User[user.uid].rbets = b[0].rbets;
                User[user.uid].wagered = b[0].wagered;
                User[user.uid].deposited = b[0].deposited;
                User[user.uid].withdrawn = b[0].withdrawn;

                socket.emit("user profile", User[user.uid]);
            });

            pool.query("SELECT * FROM transactions WHERE uid = ? ORDER BY id DESC LIMIT 20", [user.uid], function(a,b) {
                if(a) throw a;

                socket.emit("user transactions", b);
            });
        }

        if(page == "/deposit") {

        }

        if(page == "/affiliates") {
            pool.query("SELECT aff, aff_code, aff_earnings, aff_claimed FROM users WHERE id = ?", [user.uid], function(a,b) {
                if(a) throw a;

                pool.query("SELECT COUNT(`id`) AS users FROM users WHERE aff = ?", [user.uid], function(aa,bb) {
                    if(aa) throw aa;

                    let USERS = 0;
                    if(bb.length > 0) USERS = parseInt(bb[0].users);

                    pool.query("SELECT COUNT(`id`) AS depositors FROM users WHERE aff = ? AND deposited > 0", [user.uid], function(aaa,bbb) {
                        if(aaa) throw aaa;
    
                        pool.query("SELECT aff_code FROM users WHERE id = ?", [b[0].aff], function(aaaa,bbbb) {
                            if(aaaa) throw aaaa;

                            let affocode = "";
                            if(bbbb.length > 0) affocode = bbbb[0].aff_code;
                            let DEPOSITORS = 0;
                            if(bbb.length > 0) DEPOSITORS = parseInt(bbb[0].depositors);
    
                            socket.emit("user affiliates", {users: USERS, depositors: DEPOSITORS, earnings: b[0].aff_earnings, claimed: b[0].aff_claimed, aff: b[0].aff, affocode: affocode, affcode: b[0].aff_code});
                        });
                    });
                });
            });
        }
    }

    socket.on("disconnect", () => {
        if(ousers.hasOwnProperty(socket.request.connection.remoteAddress)) {
            delete ousers[socket.request.connection.remoteAddress];
            io.emit("online users", Object.keys(ousers).length);
        }
    });
});



// INIT
function init() {
    // LIMITERS
    antispamroulette = rateLimit({
        windowMs: 250,
        max: 1,
        message:
        "Please slow down!"
    });
    antispamduels = rateLimit({
        windowMs: 250,
        max: 1,
        message:
        "Please slow down!"
    });
    antispamjackpot = rateLimit({
        windowMs: 250,
        max: 1,
        message:
        "Please slow down!"
    });
    antispamendpoints = rateLimit({
        windowMs: 250,
        max: 1,
        message:
        "Please slow down!"
    });
    antispamchat = rateLimit({
        windowMs: 250,
        max: 1,
        message:
        "Please slow down!"
    });
    userInterface();
    startRoulette();

    // ROULETTE FUNCS
    getLastRRounds();

    // CHAT FUNCS
    getChatHistory();

    // LOAD UNFINISHED DUELS
    loadUnfinishedDuels();

    // LOAD OR CREATE NEW JACKPOT GAME ONCE SERVER STARTED
    createJackpotGame(1);
}





// DEFAULT FUNCTIONS
function sendUserBalance(uid) {
    pool.query("SELECT balance FROM users WHERE id = ?", [uid], function(a,b) {
        if(a) throw a;
        console.log(b);
        io.to(uid).emit("user balance", b[0].balance);
    });
}

function sendUserBalanceSTEAMID(steamid) {
    pool.query("SELECT balance FROM users WHERE steamid = ?", [steamid], function(a,b) {
        if(a) throw a;
        console.log(b);
        io.to(steamid).emit("user balance", b[0].balance);
    });
}

function getChatHistory() {
    pool.query("SELECT id, props FROM chat_log WHERE cleared = 0 ORDER BY id DESC LIMIT 20", function(a,b) {
        if(a) throw a;
        if(b.length == 0) return;

        for(let x in b) {
            let props = JSON.parse(b[x].props);
            CHATS.unshift({
                id: b[x].id,
                uuid: props.uuid,
                username: props.username,
                avatar: props.avatar,
                crank: props.crank,
                msg: props.msg
            });
        }

        console.log(`Got ${CHATS.length} chat messages from DB!`);
    });
}
// 





function authentication(req, res, next) {
    if(req.session.username && req.session.secret) {
        pool.query("SELECT secret FROM users WHERE username = ?", [req.session.username], function(a,b) {
            if(a) throw a;

            if(b.length == 0) {
                console.error(`NO USER FOUND BY USERNAME ${req.session.username} - SECRET: ${req.session.secret} - ANTI EXPLOIT`);
                pool.query("INSERT INTO logs SET type = 'exploit', msg = ?, time = ?", [`Someone is trying to access website with not found USERNAME - USERNAME: ${req.session.username} | SECRET: ${req.session.secret}`, ltime()]);
                req.session.destroy();
                res.redirect("/");
                return;
            }

            const SECRET = encryptSecret(b[0].secret);
            if(SECRET == req.session.secret) {
                getBalance(req.session.steamid, (balance) => {
                    req.session.balance = balance;
                    req.session.save();
                    req.user = req.session;
                    next();
                });
            }
            else {
                console.error(`THE SECRET IS NOT SAME AS IN DB, SECRET: ${req.session.secret} - USERNAME: ${req.session.username} - ANTI EXPLOIT`);
                pool.query("INSERT INTO logs SET type = 'exploit', msg = ?, time = ?", [`Someone is trying to access website with corrupted SECRET - SECRET: ${req.session.secret} | USERNAME: ${req.session.username}`, ltime()]);
                req.session.destroy();
                res.redirect("/");
                return;
            }
        });
    } else next();
}

function pauthentication(req, res, next) {
    if(req.session.username && req.session.secret) {

        pool.query("SELECT secret FROM users WHERE username = ?", [req.session.username], function(a,b) {
            if(a) throw a;

            if(b.length == 0) return res.json({success: false, error: `You are not logged in to interact with website!`});

            const SECRET = encryptSecret(b[0].secret);
            if(SECRET == req.session.secret) next(); else return res.json({success: false, error: `You are not logged in to interact with website!`});
        });

    } else return res.json({success: false, error: `You are not logged in to interact with website!`});
}

function userInterface() {
    app.get("/fake/login", (req, res) => {

        const USER = {
            steamid: "76561198407018607",
            personaname: "Another username",
            avatarfull: "https://64.media.tumblr.com/6e0b8b4914e014bf9f75ab3dac9bbf8e/tumblr_psbktlFQop1vsss7oo1_250.jpg"
        };

        const USER_SECRET = createSecret(USER.steamid, USER.personaname);
        const USER_AVATAR = USER.avatarfull;

        pool.query("SELECT * FROM users WHERE steamid = ?", [USER.steamid], function(a,b) {
           if(a) throw a; 

           pool.query("UPDATE users SET username = ?, avatar = ?, secret = ? WHERE steamid = ?", [
            USER.personaname, USER_AVATAR, USER_SECRET, USER.steamid
        ], function(e,r) {
            if(e) throw e;

            req.session.uid = b[0].id;
            req.session.steamid = USER.steamid;
            req.session.username = USER.personaname;
            req.session.registered = b[0].registered;
            req.session.uuid = b[0].uuid;
            req.session.avatar = USER_AVATAR;
            req.session.crank = b[0].crank;
            req.session.secret = encryptSecret(USER_SECRET);
            req.session.save();

            res.redirect("/");
        });
        });
    });


    app.get('/auth/steam',
        passport.authenticate('steam', { failureRedirect: '/' }),
    function(req, res) {
        res.redirect('/');
    });

    app.get('/auth/steam/return',
        passport.authenticate('steam', { failureRedirect: '/' }),
    function(req, res) {

        const USER = req.user["_json"];

        pool.query("SELECT id, registered, uuid, crank FROM users WHERE steamid = ?", [USER.steamid], function(a,b) {
            if(a) throw a;
            if(b.length == 0) {

                const USER_SECRET = createSecret(USER.steamid, USER.personaname);
                const USER_AVATAR = USER.avatarfull;
                const USER_REGISTERED = new Date().toDateString();
                const USER_UUID = uuid4();
        
                pool.query(`INSERT INTO users SET steamid = ?, uuid = ?, username = ?, avatar = ?, registered = ?, secret = ?`, [
                    USER.steamid, USER_UUID, USER.personaname, USER_AVATAR, USER_REGISTERED, USER_SECRET
                ], function(e,r) {
                    if(e) throw e;

                    req.session.uid = r.insertId;
                    req.session.steamid = USER.steamid;
                    req.session.username = USER.personaname;
                    req.session.registered = USER_REGISTERED;
                    req.session.uuid = USER_UUID;
                    req.session.avatar = USER_AVATAR;
                    req.session.crank = b[0].crank;
                    req.session.secret = encryptSecret(USER_SECRET);
                    req.session.save();
        
                    res.redirect("/");
                });
                return;
            } else {

                const USER_SECRET = createSecret(USER.steamid, USER.personaname);
                const USER_AVATAR = USER.avatarfull;

                pool.query("UPDATE users SET username = ?, avatar = ?, secret = ? WHERE steamid = ?", [
                    USER.personaname, USER_AVATAR, USER_SECRET, USER.steamid
                ], function(e,r) {
                    if(e) throw e;

                    req.session.uid = b[0].id;
                    req.session.steamid = USER.steamid;
                    req.session.username = USER.personaname;
                    req.session.registered = b[0].registered;
                    req.session.uuid = b[0].uuid;
                    req.session.avatar = USER_AVATAR;
                    req.session.crank = b[0].crank;
                    req.session.secret = encryptSecret(USER_SECRET);
                    req.session.save();

                    res.redirect("/");
                });

                return;
            }
        });
    });

    // AFFILIATES
    app.post("/affiliates/redeem", pauthentication, antispamendpoints, (req, res) => {

        const { code } = req.body;
        let USER = req.session;

        pool.query("SELECT id FROM users WHERE aff_code = ?", [code], function(a,b) {
            if(a) throw a;
            if(b.length == 0) return res.json({success: false, error: "This code doesn't exists!"});

            if(b[0].id == USER.uid) return res.json({success: false, error: "You can't redeem your own code!"});

            pool.query("SELECT aff FROM users WHERE id = ?", [USER.uid], function(as, da) {
                if(as) throw as;
                if(da[0].aff > 0) return res.json({success: false, error: "You've already redeemed a code!"});

                setBalance(USER.steamid, `10`, (bal) => {
                    io.to(USER.steamid).emit("user balance", bal);
                    res.json({success: true, msg: `You have successfully redeemed <strong>${code}</strong> and got 10 COINS!`});
                });
            });
        });

    });

    app.post("/affiliates/create", pauthentication, antispamendpoints, (req, res) => {

        const { code } = req.body;
        let USER = req.session;

        if(!/^[a-zA-Z0-9]+$/i.test(code)) return res.json({success: false, error: `Code can only contain A-Z, a-z, 0-9!`});
        if(code.length < 3) return res.json({success: false, error: "The code needs to be at least 3 characters long!"});
        if(code.length > 12) return res.json({success: false, error: "The code can be maximum 12 characters long!"});

        pool.query("SELECT aff_code FROM users WHERE id = ?", [USER.uid], function(a,b) {
            if(a) throw a;
            if(b[0].aff_code) return res.json({success: false, error: "You already created your own code!"});

            pool.query("SELECT id FROM users WHERE aff_code = ?", [code], function(aa,bb) {
                if(aa) throw aa;
                if(bb.length > 0) return res.json({success: false, error: "This code is already used by someone else!"});

                pool.query("UPDATE users SET aff_code = ? WHERE id = ?",[code, USER.uid], function(aaa,bbb) {
                    if(aaa) throw aaa;
                    res.json({success: true, msg: `You have successfully created the code <strong>${code}</strong>!`});
                });
            });
        });

    });

    app.post("/affiliates/collect", pauthentication, antispamendpoints, (req, res) => {

        let USER = req.session;

        pool.query("SELECT aff_earnings FROM users WHERE id = ?", [USER.uid],function(a,b) {
            if(a) throw a;

            if(b[0].aff_earnings < 100) return res.json({success: false, error: "You can collect the affiliates earnings if you have more than 100 coins!"});

            pool.query("SELECT COUNT(`id`) AS depositors FROM users WHERE aff = ? AND deposited > 0", [USER.uid],function(aa,bb) {
                if(aa) throw aa;
                let depositors = 0;
                if(bb.length > 0) depositors = bb[0].depositors;

                if(depositors < 10) return res.json({success: false, error: "You can collect affiliates earnings if you have more than 10 depositors!"});

                let earnings = b[0].aff_earnings;

                setBalance(USER.steamid, earnings, (bal) => {
                    pool.query("UPDATE users SET aff_earnings = 0, aff_claimed = aff_claimed + ? WHERE id = ?", [earnings, USER.uid], function(ab,bd) {
                       if(ab) throw ab;

                       io.to(USER.steamid).emit("user balance", bal);
                       res.json({success: true, msg: `You have successfully collect ${earnings} coins!`});
                    });
                });
            });
        });

    });
    // 

    // WITHDRAW
    app.post("/withdraw/create", pauthentication, antispamendpoints, (req, res) => {

    });
    // 

    app.post("/chat/message", pauthentication, antispamchat, (req, res) => {

        const { message } = req.body;
        let MSG = decodeURIComponent(message);
        let USER = req.session;

        if(MSG.length < 2) return res.json({success: false, error: `The length of the message is too short!`});
        else if(MSG.length > 100) return res.json({success: false, error: `The length of the message is too long!`});

        if(USER.crank == 100) nstep();
        else ismuted();

        function ismuted() {
            pool.query("SELECT mute FROM users WHERE id = ?", [USER.uid], function(a,b) {
                if(a) throw a;
                let muted = b[0].mute;
                if(muted-stime() > 0) return res.json({success: false, error: `You are muted! (Left: ${parseInt(muted-stime())}s)`});
                nstep();
            });
        }

        function nstep() {
            // COMMAND LINE
            if(MSG.startsWith("/")) {

                // args[0] == cmd;
                let args = MSG.split("/")[1].split(" ");

                if(args.length == 3 && args[0] == "mute" && USER.crank >= 1) {
                    let user = args[1];
                    let seconds = args[2];

                    pool.query("SELECT id FROM users WHERE uuid = ?", [user], function(a,b) {
                        if(a) throw a;
                        if(b.length == 0) return res.json({success: false, error: "User not found"});

                        if(isNaN(parseInt(seconds))) return res.json({success: false, error: "Second argument needs to be a valid seconds!"});

                        let muted = parseInt(parseInt(stime())+parseInt(seconds));

                        pool.query("UPDATE users SET mute = ? WHERE id = ?", [muted, b[0].id], function(e,r) {
                            if(e) throw e;
                            res.json({success: true, msg: `User successfully muted ${seconds} seconds!`});
                            pool.query("INSERT INTO logs SET type = ?, msg = ?, time = ?", [
                                'mute', `User ${b[0].id} got muted by mod/admin ${USER.username} for ${seconds} seconds`, ltime()
                            ]);
                        });
                    });

                    return;
                } else if(args.length == 3 && args[0] == "atip" && USER.crank == 100) {
                    let user = args[1];
                    let amount = parseInt(args[2]);

                    pool.query("SELECT id FROM users WHERE uuid = ?", [user], function(a,b) {
                        if(a) throw a;
                        if(b.length == 0) return res.json({success: false, error: "User not found"});

                        if(isNaN(parseInt(amount))) return res.json({success: false, error: "Second argument needs to be a valid amount!"});

                        return res.json({success: false, error: `Command disabled!`});

                        pool.query("UPDATE users SET balance = balance + ? WHERE id = ?", [amount, b[0].id], function(e,r) {
                            if(e) throw e;

                            res.json({success: true, msg: `You have successfully updated user's balance with ${amount} coins!`});

                            pool.query("INSERT INTO logs SET type = ?, msg = ?, time = ?", [
                                'atip', `Admin ${USER.uid} tipped user ${b[0].id} with ${amount} coins!`, ltime()
                            ]);
                        });
                    });

                    return;
                } else if(args.length == 3 && args[0] == "tip") {
                    let user = args[1];
                    let amount = parseInt(args[2]);

                    return res.json({success: false, error: `Command disabled!`});

                    pool.query("SELECT id FROM users WHERE uuid = ?", [user], function(a,b) {
                        if(a) throw a;
                        if(b.length == 0) return res.json({success: false, error: "User not found"});

                        if(isNaN(parseInt(amount))) return res.json({success: false, error: "Second argument needs to be a valid amount!"});

                        pool.query("SELECT balance, deposited, username FROM users WHERE id = ?", [USER.uid], function(er, ro) {
                            if(er) throw er;

                            let balance = parseInt(ro[0].balance);
                            let deposited = parseInt(ro[0].deposited);

                            if(user == USER.uuid) return res.json({success: false, error: "You can't tip yourself!"});
                            if(balance < amount) return res.json({success: false, error: "You don't have enough balance to tip!"});
                            if(deposited < 500) return res.json({success: false, error: "You are able to tip users after depositing minimum $5.00!"});

                            pool.query("UPDATE users SET balance = balance - ? WHERE id = ?", [amount, USER.uid], function(as,bd) {
                                if(as) throw as;

                                pool.query("UPDATE users SET balance = balance + ? WHERE id = ?", [amount, b[0].id], function(e,r) {
                                    if(e) throw e;
        
                                    sendUserBalance(USER.uid);
                                    sendUserBalance(b[0].id);
                                    io.to(b[0].id).emit("msg", "success", `You have received <strong>${amount}</strong> coins from <strong>${ro[0].username}</strong>`)
                                    res.json({success: true, msg: `You have successfully updated user's balance with ${amount} coins!`});

                                    pool.query("INSERT INTO logs SET type = ?, msg = ?, time = ?", [
                                        'tip', `User ${USER.uid} tipped user ${b[0].id} with ${amount} coins!`, ltime()
                                    ]);
                                });
                            });
                        });
                    });

                    return;
                } else if(args.length == 2 && args[0] == "ban" && USER.crank == 100) {
                
                    let USERID = args[1];

                    pool.query("SELECT id, username, steamid FROM users WHERE steamid = ? OR uuid = ?", [USERID, USERID], function(a,b) {
                        if(a) throw a;
                        if(b.length == 0) return res.json({success: false, error: `This user does not exists in DB!`});

                        pool.query("UPDATE users SET banned = ? WHERE id = ?", [1, b[0].id], function(e,r) {
                            if(e) throw e;

                            io.to(b[0].steamid).emit("user refresh");
                            res.json({success: true, msg: `User ${b[0].username} has been banned successfully!`});
                        });
                    });

                    return;

                } else if(args.length == 2 && args[0] == "unban" && USER.crank == 100) {
                
                    let USERID = args[1];

                    pool.query("SELECT id, username, steamid FROM users WHERE steamid = ? OR uuid = ?", [USERID, USERID], function(a,b) {
                        if(a) throw a;
                        if(b.length == 0) return res.json({success: false, error: `This user does not exists in DB!`});

                        pool.query("UPDATE users SET banned = ? WHERE id = ?", [0, b[0].id], function(e,r) {
                            if(e) throw e;

                            io.to(b[0].steamid).emit("user refresh");
                            res.json({success: true, msg: `User ${b[0].username} has been unbanned successfully!`});
                        });
                    });

                    return;

                } else if(args.length == 1 && args[0] == "clear" && USER.crank >= 1) {

                    CHATS = [];
                    io.emit("chat clear");
                    res.json({success: true, msg: "Chat cleared!"});

                    pool.query("UPDATE chat_log SET cleared = 1 WHERE cleared = 0");

                    return;
                }

                return res.json({success: false, error: `Command not found!`});


            } else dstep();
        }

        function dstep() {
            let props = {
                uuid: USER.uuid,
                username: USER.username,
                avatar: USER.avatar,
                crank: USER.crank,
                msg: escapeHtml(MSG)
            };

            pool.query("INSERT INTO chat_log SET uid = ?, props = ?, time = ?", [
                USER.uid, JSON.stringify(props), ltime()
            ], function(a,b) {
                if(a) throw a;

                props.id = b.insertId;

                CHATS.push(props);
                if(CHATS.length > 20) CHATS.shift();
                io.emit("user message", props);
            });
        }

    });

    app.post("/jackpot/bet", pauthentication, antispamjackpot, (req, res) => {

        const { amount } = req.body;

        if(Jackpot.state > 1) return res.json({success: false, error: `You can place a bet in the next Jackpot round!`});

        if(amount <= 0) return res.json({success: false, error: `You can't place a negative bet amount!`});
        if(isNaN(amount)) return res.json({success: false, error: `Invalid bet amount!`});
        if(amount > 100000) return res.json({success: false, error: `Maximum bet is 100,000 balance!`});

        getJPTotalBets(req.session.uid, (bets) => {

            if(bets >= 3) return res.json({success: false, error: `You can place maximum 3 bets per Jackpot round!`});

            getBalance(req.session.steamid, (balance) => {
                const BALANCE = parseInt(balance);

                if(amount > BALANCE) return res.json({success: false, error: `You don't have enough balance to bet!`});

                setBalance(req.session.steamid, `-${amount}`, (new_balance) => {

                    pool.query("UPDATE users SET wagered = wagered + ?, rbets = rbets + 1 WHERE steamid = ?", [amount, req.session.steamid], function(eee,rrr) {
                        if(eee) throw eee;

                        const NEW_BALANCE = parseInt(new_balance);

                        const MINTICKET = parseInt(Jackpot.amount);
                        const MAXTICKET = parseInt(MINTICKET) + parseInt(amount) - 1;

                        Jackpot.amount = parseInt(Jackpot.amount) + parseInt(amount);
                        
                        if(Jackpot.cplayers.indexOf(req.session.steamid) == -1) Jackpot.cplayers.push(req.session.steamid);

                        const props = {
                            uid: req.session.uid,
                            steamid: req.session.steamid,
                            name: req.session.username,
                            avatar: req.session.avatar,
                            amount: amount,
                            color: Jackpot.colors[Jackpot.cplayers.indexOf(req.session.steamid)]
                        };

                        Jackpot.players.push(props);
                        Jackpot.tickets.push({
                            uid: req.session.uid,
                            steamid: req.session.steamid,
                            min: MINTICKET,
                            max: MAXTICKET
                        });

                        io.sockets.emit("jackpot players", Jackpot.players, Jackpot.amount);

                        res.json({success: true, msg: `You have successfully placed ${amount} coins on Jackpot!`});

                        emitJackpotRound();
                        checkJPPlayers();
                    });
                });
            });
        });
    });

    app.post('/roulette/bet', pauthentication, antispamroulette, (req, res) => {

        const acc_colors = ["red", "green", "black"];
        const { amount, color } = req.body;

        if(Roulette.state != 1) return res.json({success: false, error: `You can place a bet in the next Roulette round!`});

        if(amount <= 0) return res.json({success: false, error: `You can't place a negative bet amount!`});
        if(isNaN(amount)) return res.json({success: false, error: `Invalid bet amount!`});
        if(amount > 100000) return res.json({success: false, error: `Maximum bet is 100,000 balance!`});

        if(getTotalBets(req.session.uid) == 3) return res.json({success: false, error: `You can place maximum 3 bets per round!`});

        getBalance(req.session.steamid, (balance) => {
            const BALANCE = parseInt(balance);

            if(amount > BALANCE) return res.json({success: false, error: `You don't have enough balance to bet!`});
            if(acc_colors.indexOf(color) == -1) return res.json({success: false, error: `Invalid color bet!`});

            setBalance(req.session.steamid, `-${amount}`, (new_balance) => {
                pool.query("UPDATE users SET wagered = wagered + ?, rbets = rbets + 1 WHERE steamid = ?", [amount, req.session.steamid], function(eee,rrr) {
                    if(eee) throw eee;

                    pool.query("INSERT INTO bets SET roundid = ?, uid = ?, amount = ?, color = ?, win = 0, time = ?", [
                        Roulette.roundid, req.session.uid, amount, color, ltime()
                    ], function(aaa,bbb) {
                        if(aaa) throw aaa;
    
                        const NEW_BALANCE = parseInt(new_balance);
    
                        const USER_BET = {
                            id: bbb.insertId,
                            uid: req.session.uid,
                            username: req.session.username,
                            avatar: req.session.avatar,
                            amount: amount,
                            color: color,
                            won: 0
                        };
            
                        Roulette.bets.push(USER_BET);
            
                        if(Roulette.user_bets.hasOwnProperty(req.session.uid)) Roulette.user_bets[req.session.uid][color]++;
                        else {
                            Roulette.user_bets[req.session.uid] = {
                                red: 0,
                                green: 0,
                                black: 0
                            };
                            Roulette.user_bets[req.session.uid][color]++;
                        }
    
                        io.emit("roulette bet", USER_BET);
                        io.to(req.session.uid).emit("user balance", NEW_BALANCE);
    
                        res.json({success: true, msg: `You have successfully placed ${amount} coins on color ${color}!`});
                    });
                });
            });
        });
    });

    app.post("/duels/create", pauthentication, antispamduels, (req, res) => {

        let user = req.session;
        let { amount, players } = req.body;
        players = parseInt(players);
        if(amount < 10 || amount > 100000) return res.json({success: false, error: `The bet amount can only be between 10-100,000 balance!`});
        let acc_players = [2,3,4];
        if(acc_players.indexOf(players) == -1) return res.json({success: false, error: `Max players can only be between 2-4!`});

        getBalance(user.steamid, (balance) => {
            if(balance < amount) return res.json({success: false, error: `You don't have enough balance to create a Duel!`});

            const SECRET = crypto.createHash("md5").update(Date.now().toString()).digest("Base64");

            let props = {
                uid: user.uid,
                creator: {
                    uid: user.uid,
                    avatar: user.avatar,
                    name: user.username
                },
                mpls: players,
                amount: amount,
                players: [],
                winner: null,
                hash: null,
                secret: SECRET,
                state: 0
            };
            props.players.push({
                uid: user.uid,
                name: user.username,
                avatar: user.avatar
            });

            createDuel(res, user, props);
        });
    });


    app.post("/duels/join", pauthentication, antispamduels, (req, res) => {
        
        let user = req.session;
        let { duelid } = req.body;
        if(!CFS.hasOwnProperty(duelid)) return res.json({success: false, error: `This Duel does not exists!`});
        if(CFS[duelid].state != 0) return res.json({success: false, error: `You can't join this Duel anymore!`});
        if(CFS[duelid].players.length == CFS[duelid].mpls) return res.json({success: false, error: `You can't join this Duel anymore!`});
        if(CFS[duelid].players[0].uid == user.uid && user.crank != 100) return res.json({success: false, error: `You can't join your Duel!`});
        let amount = CFS[duelid].amount;

        getBalance(user.steamid, (balance) => {
            if(balance < amount) return res.json({success: false, error: `You don't have enough balance to join this Duel!`});

            let curr_players = CFS[duelid].players.length;
            curr_players++;
            if(curr_players == CFS[duelid].mpls) CFS[duelid].state = 1;

            let props = {
                duelid: duelid,
                uid: user.uid,
                avatar: user.avatar,
                name: user.username
            };

            joinDuel(res, user, props);
        });
    });

    app.post("/logout", (req, res) => {
        if(req.session.username) {
            req.session.destroy();
            res.json({success: true});
        }
    });

}

// DUEL FUNCTIONS
function sendDuels(socket) {
    let cfs = {};
    for(let d in CFS) {
        let cf = CFS[d];
        cfs[d] = cf;
    }
    socket.emit("duels", "all", cfs);
}

function loadUnfinishedDuels() {
    pool.query("SELECT * FROM duels WHERE state = ?", [0], function(a,b) {
        if(a) throw a;
        if(b.length == 0) return;
       
        for(let d in b) {
            let cf = b[d];
            CFS[cf.id] = {
                players: JSON.parse(cf.players),
                amount: parseInt(cf.amount),
                mpls: cf.mpls,
                secret: cf.secret,
                state: 0
            };
            console.log(`[RESUMED] Duel #${cf.id} was resumed successfully!`);
        }
    });
}

function joinDuel(res, user, props) {

    let duel = CFS[props.duelid];
    let players = duel.players;
    let uid = user.uid;
    let steamid = user.steamid;

    setBalance(steamid, `-${duel.amount}`, (new_balance) => {
        pool.query("UPDATE users SET wagered = wagered + ?, rbets = rbets + 1 WHERE steamid = ?", [duel.amount, steamid], function(eee,rrr) {
            if(eee) throw eee;

            players.push({
                uid: uid,
                name: props.name,
                avatar: props.avatar
            });
    
            let state = 0;
            let curr_players = CFS[props.duelid].players.length;
            if(curr_players == CFS[props.duelid].mpls) state = 1;
    
            pool.query("UPDATE duels SET players = ?, state = ? WHERE id = ?", [JSON.stringify(players), state, props.duelid], function(e,r) {
                if(e) throw e;
    
                io.sockets.emit("duels", "edit", { id: props.duelid, game: CFS[props.duelid] });
                io.to(steamid).emit("user balance", new_balance);
    
                if(state == 1) endDuelDuel(props.duelid);
    
                res.json({success: true, msg: `You have successfully joined Duel #${props.duelid}!`});
            });
        });
    });
}

function createDuel(res, user, props) {
    let uid = user.uid;
    let steamid = user.steamid;
    setBalance(steamid, `-${props.amount}`, (new_balance) => {
        pool.query("UPDATE users SET wagered = wagered + ?, rbets = rbets + 1 WHERE steamid = ?", [props.amount, steamid], function(eee,rrr) {
            if(eee) throw eee;

            pool.query("INSERT INTO duels SET uid = ?, creator = ?, mpls = ?, amount = ?, players = ?, winner = ?, hash = ?, secret = ?, state = ?", [
                props.uid,
                JSON.stringify(props.creator),
                props.mpls,
                props.amount,
                JSON.stringify(props.players),
                props.winner,
                props.hash,
                props.secret,
                props.state
            ], function(e,r) {
                if(e) throw e;
    
                CFS[r.insertId] = {
                    players: [],
                    amount: props.amount,
                    mpls: props.mpls,
                    secret: props.secret,
                    state: 0
                };
    
                CFS[r.insertId].players.push({
                    uid: props.creator.uid,
                    name: props.creator.name,
                    avatar: props.creator.avatar
                });
    
                console.log(`Duel #${r.insertId} with amount ${props.amount} and ${props.mpls} max players created by UID: ${props.uid}!`);
    
                io.sockets.emit("duels", "create", { id: r.insertId, game: CFS[r.insertId] });
                io.to(steamid).emit("user balance", new_balance);
    
                res.json({success: true, msg: `You have successfully created Duel #${r.insertId}!`})
            });
        });
    });
}

function endDuelDuel(id) {
    let CF = CFS[id];

    // ANIMATION CIRCLE DEGREE CALC: 180 + 360 * 5 + (48.5/100) * 360
    // 48.5 --> TICKET MODULE NUMBER.

    const SECRET = CF.secret;
    const PLAYERS = JSON.stringify(CF.players);
    const TIMESTAMP = Date.now();
    const HASH = crypto.createHash("sha512").update(SECRET + PLAYERS + TIMESTAMP).digest("hex");

    const TICKET_WINNER = CFgetTicketNumber(HASH);

    const DEGREE_ANIM = 180 + 360 * 5 + (TICKET_WINNER/100) * 360;

    let WINNER_DETAILS;
    let WINNER_SLOT;

    let HALFMEAN = 100 / CF.players.length;
    let CURRPOINTS = 0;
    for(let x in CF.players) {
        let NEXT_POINTS = CURRPOINTS + HALFMEAN;
        if(TICKET_WINNER >= CURRPOINTS && TICKET_WINNER <= NEXT_POINTS) {
            console.log(TICKET_WINNER);
            console.log(`[DUELS] Duel #${id} - Winner is: ${CF.players[x].name} - SLOT: ${x}`);
            WINNER_DETAILS = CF.players[x];
            WINNER_SLOT = x;
            nextStep();
            break;
        }
        CURRPOINTS = parseFloat(CURRPOINTS) + HALFMEAN;
    }

    function nextStep() {

        let windetails = {
            player: WINNER_DETAILS,
            slot: WINNER_SLOT,
            degree_anim: DEGREE_ANIM,
            ticket_number: TICKET_WINNER
        };

        CFS[id].state = 2;
        CFS[id].winner = windetails;
        CFS[id].seconds = true;
        CFS[id].animation = true;
        CFS[id].hash = HASH;
        CFS[id].timestamp = TIMESTAMP;

        io.sockets.emit("duels", "edit", { id: id, game: CFS[id] });

        delete CFS[id].seconds;

        pool.query("UPDATE duels SET winner = ?, players = ?, hash = ?, timestamp = ?, state = ? WHERE id = ?", [
            JSON.stringify(windetails),
            PLAYERS,
            HASH,
            TIMESTAMP,
            2,
            id
        ], function(a,b) {
            if(a) throw a;

            addDuelWinner(id, CFS[id]);
        });

    }

}

function addDuelWinner(id, cf) {
    let winner_id = cf.winner.player.uid;
    let duelamount = cf.amount;
    let commission = 5/100;
    let win_amount_no_commission = parseInt(duelamount * cf.mpls);
    let win_amount = parseInt(win_amount_no_commission - (commission * win_amount_no_commission));

    addWinBalance(winner_id, win_amount);
    function addWinBalance(uid, bal) {
        setTimeout(() => {

            pool.query("SELECT steamid FROM users WHERE id = ?", [uid], function(ee,rr) {
                if(ee) throw ee;

                let steamid = rr[0].steamid;
                setBalance(steamid, bal, (new_balance) => {
                    io.to(steamid).emit("user balance", new_balance);

                    io.to(uid).emit("msg", "success", `You have successfully won ${win_amount} coins from Duel #${id}!`);

                    // HIDE DUEL
                    hideDuel(id);
                });
            });
        }, 9000);
    }
}

function hideDuel(id) {
    setTimeout(() => {
        delete CFS[id];
        io.sockets.emit("duels", "remove", { id: id });
    }, 60000);
}

function CFgetTicketNumber(h) {
    return parseFloat(parseFloat((parseInt(h, 16) % 10000 + 1)/100).toFixed(2));
}
















// ROULETTE FUNCTIONS
function startRoulette() {
    Roulette.state = 1;
    Roulette.curr_timer = time() + (Roulette.timer*1000);
    setTimeout(() => {
        rollRoulette();
    }, Roulette.timer*1000);

    if(Roulette.roundid == -1) {
        pool.query("SELECT MAX(`id`) AS roundid FROM rolls", function(a,b) {
            if(a) throw a;
            Roulette.roundid = b[0].roundid;
            Roulette.roundid++;
            console.log(`Round ID set to ${Roulette.roundid}!`);
        });
    } else Roulette.roundid++;

    var time_start = new Date().toLocaleString();
    Roulette.fair = {
        time_start: time_start,
        roundhash: md5(time_start),
        secret: makeSecret(),
        time_end: null
    };

    Roulette.bets = [];
    Roulette.user_bets = {};
    io.emit("roulette timer", Roulette.fair.time_start, Roulette.fair.roundhash, Roulette.timer*1000);
    io.emit("roulette new");
    // console.log(`Roulette timer initiated!`);
}

function rollRoulette() {
    Roulette.state = 2;

    Roulette.fair.time_end = new Date().toLocaleString();
    const { fair } = Roulette;
    const HASH = sha256(`${fair.roundhash}-${fair.secret}-${fair.time_end}`);
    const a = getRollFromHash(HASH);

    pool.query(`INSERT INTO rolls SET hash = ?, secret = ?, roll = ?, time_start = ?, time_end = ?`,
    [fair.roundhash, fair.secret, a, fair.time_start, fair.time_end], function(e,r) {
        if(e) throw e;

        addLastRRound({hash: fair.roundhash, secret: fair.secret, roll: a, time_start: fair.time_start, time_end: fair.time_end});
    });

    io.emit("roulette roll", a);
    setTimeout(() => {
        io.emit("roulette insta roll", a);
        Roulette.rng = a;
        creditUsersRoulette(Roulette.rng, Roulette.bets);
        addRouletteHistory(a);
    }, 6000);
    setTimeout(() => {
        startRoulette();
    }, Roulette.ntimer*1000);

    // console.log(`Rolling number ${a}!`);
}

function addRouletteHistory(a) {
    Roulette.history.unshift(a);
    if(Roulette.history.length >= 10) Roulette.history.pop();
    io.emit("roulette history", Roulette.history);
}

function creditUsersRoulette(rng, bets) {
    var COLOR_WON = "";
    if(rng >= 1 && rng <= 7) COLOR_WON = "red";
    else if(rng >= 8 && rng <= 14) COLOR_WON = "black";
    else COLOR_WON = "green";

    for(let x in bets) {
        if(bets[x].color == COLOR_WON) creditUserRoulette(bets[x]);
    }
}

function creditUserRoulette(bet) {
    const MULTIPLIER = {"red": 2, "green": 14, "black": 2};
    pool.query("UPDATE bets SET win = 1 WHERE id = ?", [bet.id], function(a,b) {
        if(a) throw a;

        pool.query("SELECT steamid FROM users WHERE id = ?", [bet.uid], function(ee,rr) {
           if(ee) throw ee;
           let steamid = rr[0].steamid;
           
           setBalance(steamid, parseInt(MULTIPLIER[bet.color]*bet.amount), (new_balance) => {
                io.to(steamid).emit("user balance", new_balance);
           });
        });
    });
}

function getTotalBets(uid) {
    if(Roulette.user_bets.hasOwnProperty(uid)) {
        const TOTAL_BETS = Roulette.user_bets[uid]["red"] + Roulette.user_bets[uid]["green"] + Roulette.user_bets[uid]["black"];
        return TOTAL_BETS
    } else return 0;
}

function getJPTotalBets(uid, cb) {
    let pls = Jackpot.players;
    let bets = 0;
    for(let x in pls) {
        if(pls[x].uid == uid) bets++;
    }
    cb(bets);
}

function getLastRRounds() {
    LRounds = [];
    pool.query("SELECT * FROM rolls ORDER BY id DESC LIMIT 50", function(a,b) {
        if(a) throw a;
        if(b.length == 0) return;
        for(let x in b) { LRounds.push(b[x]); }
        console.log("Last Rounds loaded!");
    });
}

function addLastRRound(props) {
    LRounds.unshift(props);
    if(LRounds.length > 50) LRounds.pop();
    // console.log(`Added new Round to Last Rounds -> ${props.hash}`);
}
// 


// BALANCE SYSTEMS
async function getBalance(steamid, cb) {
    // sendUserBalanceSTEAMID(steamid);
    // pool.query("SELECT balance FROM users WHERE steamid = ?", [steamid], function(aa,bb) {
    //    if(aa) throw aa;
    //    return cb(bb[0].balance); 
    // });
    // return;
    await request.get(`http://194.26.183.32:6969/api/get/${steamid}/${SECURE_TOKEN}`, function(err, res, body) {
        console.log(err);
        console.log(body);

        if(err) {
            cb(0);
            console.error(err);
            return;
        }
        
        let resp = JSON.parse(body);
        if(!resp.success) return cb(0);

        pool.query("UPDATE users SET balance = ? WHERE steamid = ?", [
            resp.balance, steamid
        ], function(e,r) {
            if(e) throw e;
            sendUserBalanceSTEAMID(steamid);
            return cb(resp.balance);
        });
    });
}

async function setBalance(steamid, curr, cb) {
    // let xx;
    // if(curr < 0) xx = 1;
    // else xx = 2;

    // let amount = parseInt(curr.replace("-", ""));

    // if(xx == 1) {
    //     pool.query("UPDATE users SET balance = balance - ? WHERE steamid = ?", [
    //         amount, steamid
    //     ], function(e,r) {
    //         if(e) throw e;
    //         pool.query("SELECT balance FROM users WHERE steamid = ?", [steamid], function(aa,bb) {
    //             if(aa) throw aa;
    //             return cb(bb[0].balance); 
    //         });
    //         sendUserBalanceSTEAMID(steamid);
    //     });
    // } else {
    //     pool.query("UPDATE users SET balance = balance + ? WHERE steamid = ?", [
    //         amount, steamid
    //     ], function(e,r) {
    //         if(e) throw e;
    //         pool.query("SELECT balance FROM users WHERE steamid = ?", [steamid], function(aa,bb) {
    //             if(aa) throw aa;
    //             return cb(bb[0].balance); 
    //         });
    //         sendUserBalanceSTEAMID(steamid);
    //     });
    // }




    // return;
    await request.get(`http://194.26.183.32:6969/api/edit/${steamid}/${curr}/${SECURE_TOKEN}`, async (err, res, body) => {
        console.log(err);
        console.log(body);    
    
        if(err) {
            cb(0);
            console.error(err);
            return;
        }

        let resp = JSON.parse(body);
        if(!resp.success) return cb(0);

        await request.get(`http://95.156.230.163:6969/api/edit/${steamid}/${curr}/${SECURE_TOKEN}`, function(err, res, body) {
            console.log(err);
            console.log(body);    
        
            if(err) {
                cb(0);
                console.error(err);
                return;
            }
    
            let resp = JSON.parse(body);
            if(!resp.success) return cb(0);
    
            pool.query("UPDATE users SET balance = ? WHERE steamid = ?", [
                resp.balance, steamid
            ], function(e,r) {
                if(e) throw e;
                sendUserBalanceSTEAMID(steamid);
                return cb(resp.balance);
            });
        });
    });
}
//

// JACKPOT
function checkJPPlayers() {
    let unique_players = 1;
    let first_player = 0;

    for(let x in Jackpot.players) {
        let it = Jackpot.players[x];

        if(first_player != 0 && it.uid != first_player) unique_players++;

        if(first_player == 0) first_player = it.uid;
    }

    if(Jackpot.state == 0 && unique_players >= 2) {
        Jackpot.state = 1;
        startJackpotTimer();
    }
}

function startJackpotTimer() {
    Jackpot.time = stime() + 60;
    io.sockets.emit("jackpot time", 60);
    setTimeout(() => {
        calcJackpotWinner();
    }, 61500);
}

function emitJackpotTimer(socket) {
    if(Jackpot.state == 1) {
        let time = parseInt(parseInt(Jackpot.time) - stime());
        socket.emit("jackpot time", time);
    }
}

function emitJackpotPlayers(socket) {
    let potamount = Jackpot.amount;
    socket.emit("jackpot players", Jackpot.players, potamount);
}

function emitJackpotRound(socket) {
    let props = {
        id: Jackpot.id,
        amount: Jackpot.amount,
        players: Jackpot.players,
        secret: Jackpot.secret
    };

    if(Jackpot.state == 1) {
        props.players = Jackpot.players;
    }

    if(Jackpot.state == 2) {
        props.players = Jackpot.players;
        props.timestamp = Jackpot.timestamp;
        props.hash = Jackpot.hash;
        props.winner_props = Jackpot.winner_props;
    }

    if(socket) {
        socket.emit("jackpot round", props);
    } else {
        io.sockets.emit("jackpot round", props);
    }
}

function calcJackpotWinner() {

    let jp_total = parseInt(Jackpot.amount);
    let secret = Jackpot.secret;
    let players = JSON.stringify(Jackpot.players);
    let timestamp = Date.now();

    const HASH = crypto.createHash("sha512").update(secret + players + timestamp).digest("hex");

    Jackpot.hash = HASH;
    Jackpot.timestamp = timestamp;
    Jackpot.state = 2;

    const TICKET_NUMBER = getTicketNumber(HASH);

    var WINNER_UID = 0;

    let TICKETS = Jackpot.tickets;

    for(let x in TICKETS) {
        let it = TICKETS[x];
        let ticko = parseInt(parseInt(Jackpot.amount) * (parseFloat(TICKET_NUMBER/10000)));
        if(ticko >= it.min && ticko <= it.max) {
            WINNER_UID = it.steamid;
            console.log(`Winner FOUND:`);
            console.log(it);
            nextStep();
        } else console.log(`Ticket number not between ${it.min}-${it.max} ( req: ${ticko} )!`);
    }

    function nextStep() {

        let commission = 5;
        let winner_receives = parseInt( Jackpot.amount ) - parseInt( (commission/100) * Jackpot.amount );

        let winner_amount = 0;
        let winner_chance = 0.00;

        for(let g in Jackpot.players) {
            let it = Jackpot.players[g];
            if(it.steamid == WINNER_UID) winner_amount = parseInt(winner_amount) + parseInt(it.amount);
        }

        winner_chance = 100 - ( ( jp_total - winner_amount ) / jp_total ) * 100;

        const DEGREE_ANIM = 180 + 360 * 5 + (TICKET_NUMBER/10000) * 360;

        let winner_props = {
            winner_uid: WINNER_UID,
            degree_anim: DEGREE_ANIM,
            ticket_number: TICKET_NUMBER
        };

        Jackpot.winner_props = winner_props;

        pool.query("UPDATE jackpots SET amount = ?, players = ?, tickets = ?, hash = ?, timestamp = ?, winnerprops = ?, state = ? WHERE id = ?", [
            winner_receives, JSON.stringify(Jackpot.players), JSON.stringify(Jackpot.tickets), Jackpot.hash, Jackpot.timestamp, JSON.stringify(winner_props), Jackpot.state, Jackpot.id
        ], function(a,b) {
            if(a) throw a;

            io.sockets.emit("jackpot animation", Jackpot.players, winner_props);

            emitJackpotRound();

            setTimeout(() => {

                setBalance(WINNER_UID, `${winner_receives}`, (new_balance) => {
                    io.to(WINNER_UID).emit("msg", "success", `You have successfully won ${winner_receives} points on Jackpot!`);
                    
                    setTimeout(() => {
                        createJackpotGame(0);
                    }, 3700);
                });

            }, 6300);
        });
    }
}

function createJackpotGame(check) {

    if(!check) {

        const SECRET = crypto.createHash("md5").update(Date.now().toString()).digest("Base64");

        pool.query("INSERT INTO jackpots SET amount = ?, players = ?, tickets = ?, secret = ?, state = ?", [
            0,
            "[]",
            "[]",
            SECRET,
            0
        ], function(a,b) {
            if(a) throw a;

            Jackpot.id = b.insertId;
            Jackpot.state = 0;
            Jackpot.time = 0;
            Jackpot.amount = 0;
            Jackpot.hash = null;
            Jackpot.secret = SECRET;
            Jackpot.timestamp = null;
            Jackpot.players = [];
            Jackpot.cplayers = [];
            Jackpot.tickets = [];

            emitJackpotRound();
        });
        return;
    } else {

        pool.query("SELECT * FROM jackpots WHERE state = 0 LIMIT 1", function(a,b) {
            if(a) throw a;
            if(b.length == 0) return createJackpotGame(0);
           
            let jp = b[0];

            Jackpot.id = jp.id;
            Jackpot.state = jp.state;
            Jackpot.time = 0;
            Jackpot.amount = 0;
            Jackpot.hash = null;
            Jackpot.secret = jp.secret;
            Jackpot.timestamp = null;
            Jackpot.players = []
            Jackpot.cplayers = []
            Jackpot.tickets = []

            emitJackpotRound();
        });

    }

}

function getTicketNumber(h) {
    return parseFloat((parseInt(h, 16) % 10000 + 1));
}
// 

// 
function checkIfBanned(req, res, cb) {
    pool.query("SELECT banned FROM users WHERE id = ?", [req.session.uid], function(a,b) {
        if(a) throw a;
        if(b.length == 0) return cb();

        if(b[0].banned == 1) return res.render("banned");
        cb();
    });
}



// OTHER FUNCTIONS
function encryptPassword(pw) {
    return md5(`ESCorev1.0-${pw}-Password-System`).toUpperCase();
}

function createSecret(username, password) {
    return sha256(username + password + time());
}

function encryptSecret(s) {
    return md5(`ESCorev1.0-${s}-Secret-System`).toUpperCase();
}

function createAvatar(e) {
    return `https://www.gravatar.com/avatar/${md5(e.toLowerCase())}?s=256`;
}

function fixRouletteTimer(ts) {
    return ts-time();
}

function time() {
    return parseInt(new Date().getTime());
}

function ltime() {
    return new Date().toLocaleString();
}

function stime() {
    return parseInt(new Date().getTime()/1000);
}

function getRollFromHash(hash) {
    return hexdec(hash.substr(0, 8)) % 15;
}

function hexdec(hexString) {
    hexString = (hexString + '').replace(/[^a-f0-9]/gi, '')
    return parseInt(hexString, 16)
}

function makeSecret() {
    var length           = 12;
    var result           = '';
    var characters       = 'ESCorev1';
    var charactersLength = characters.length;
    for ( var i = 0; i < length; i++ ) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function validateEmail(email) {
    const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
}

function passwordFormatter(text) {
    var map = {
      '&': 'WRONG_CHARACTER',
      '<': 'WRONG_CHARACTER',
      '>': 'WRONG_CHARACTER',
      '"': 'WRONG_CHARACTER',
      "'": 'WRONG_CHARACTER'
    };
    
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}

function escapeHtml(text) {
    var map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };
    
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}

// EXCEPTION THROW
process
  .on('unhandledRejection', (reason, p) => {
    console.error(reason, 'Unhandled Rejection at Promise', p);
  })
  .on('uncaughtException', err => {
    console.error(err, 'Uncaught Exception thrown');
  });