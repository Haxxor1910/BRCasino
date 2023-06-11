const NAME = "Bloodrage";
var tpage;

$(function() {

    var chatInt = true;
    var socket;
    var rint;
    var focused = true;
    var ntimer = false;

    var duelcolors = ["#c32d4f", "#45b5da", "#2DFF0E", "#E3E91F"];
    var CFCharts = {};
    var JPChart;

    window.onfocus = function() {
        focused = true;
        if(ntimer) {
            ntimer = false;
            socket.emit("roulette", "timer", {});
        }
    };
    window.onblur = function() {
        focused = false;
        ntimer = true;
        clearInterval(rint);
        document.title = NAME;
    };

    getWindowPath();

    initWheel();
    initContextmenu();
    connect();

    function connect() {

        socket = io();

        socket.on("connect", function() {
            console.log(`WebSocket connected successfully to ${NAME}!`);
        });

        // ALERTS
        socket.on("msg", function(type, msg) { sendAlert(type,msg); });

        // ROULETTE SOCKETS
        if(window.location.pathname == "/") {
            socket.on("roulette timer", function(ts, rh, seconds) { clearInterval(rint); rouletteTimer(seconds); $(".round_info").text(`Round hash: ${rh} - Round created: ${ts} (Server Time)`) });
            socket.on("roulette roll", function(a) { rouletteRoll(a); });
            socket.on("roulette insta roll", function(a) { setWheelPosition(a); });
            socket.on("roulette history", function(h) { rouletteHistory(h); });
            socket.on("roulette bet", function(r) { rouletteBet(r); });
            socket.on("roulette bets", function(r) { rouletteBets(r); });
            socket.on("roulette new", function() { clearRouletteBets(); });
        }

        // DUELS
        if(window.location.pathname == "/duels") {
            socket.on("duels", function(type, props) {
                if(type == "all") duelsHistory(props);
                else if(type == "create") duelsCreate(props);
                else if(type == "edit") duelsEdit(props);
                else if(type == "remove") duelsRemove(props);
            });
        }

        // JACKPOT
        if(window.location.pathname == "/jackpot") {

            socket.on("jackpot players", function(players, pamount) {
                jackpotPlayers(players, pamount);
            });

            socket.on("jackpot time", function(time) {
                jackpotTime(time);
            });

            socket.on("jackpot animation", function(pls, anim) {
                jackpotAnimation(pls, anim);
            });

            socket.on("jackpot round", function(round) {
                jackpotRound(round);
            });

        }

        // USER REFRESH
        socket.on("user refresh", function() {
            window.location.href = '/';
        });

        // FAIR SOCKETS
        socket.on("fair rounds", function(s) { fairRounds(s); });

        // USER SOCKETS
        socket.on("user balance", function(b) {
            $(".user-balance").html(`Balance: <i class="fas fa-coins gold"></i>&nbsp;${b}`);
        });
        socket.on("user profile", function(a) { userProfile(a); });
        socket.on("view user profile", function(a,b) { viewUserProfile(a,b); });
        socket.on("user message", function(a) { userChatMessage(a); });
        socket.on("user messages", function(a) { userChatMessages(a); });
        socket.on("user affiliates", function(a) { userAffiliates(a); } );
        socket.on("user xrp address", function(a, b) { userDepositAddress(a, b); });
        socket.on("user transactions", function(a) { userTransactions(a); });
        socket.on("online users", function(a) { chatUsersOnline(a); } );

        // ADMIN
        socket.on("chat clear", function() { chatClear(); });

        hljs.highlightAll();
    }


    // USER DOCUMENT FUNCTIONS
    $(document).on("click", "#goto_register_btn", function() { $("#loginModal").modal("hide"); setTimeout(() => { $("#registerModal").modal(); }, 150); });
    $(document).on("click", "#register_btn", function() { userRegister(); });
    $(document).on("click", "#login_btn", function() { userLogin(); });
    $(document).on("keypress", "#LPassword", function(e) { if(e.which == 13) userLogin(); });
    $(document).on("click", "#logout", function() { user("logout", "POST", {}, (err, res) => { if(!err && res.success) location.href = '/'; }) });
    $(document).on("click", ".rbet", function() { RBet($(this).attr("data-action")); });
    $(document).on("click", ".rbetbtn", function() { userRBet($(this).attr("data-bet")); });
    $(document).on("click", ".chatInt", function() { userChat(); });
    $(document).on("click", ".chat-btn", function() { userSendChat(); });
    $(document).on("keyup", ".chat-input", function(e) { if (e.keyCode == 13) { userSendChat(); } });
    $(document).on("click", "#aff_redemcodebtn", function() { userRedeemcode(); });
    $(document).on("click", "#aff_createcodebtn", function() { userCreatecode(); });
    $(document).on("click", "#aff_collectearningsbtn", function() { userAffCollect(); });
    $(document).on("click", "#withdraw_btn", function() { userWithdrawFunds(); });
    $(document).on("click", "#createduel_btn", function() { CFCreateDuel(); });
    $(document).on({
        mouseenter: function () {
            showJoinDuelBtn($(this));
        },
        mouseleave: function () {
            hideJoinDuelBtn($(this));
        }
    }, ".duels .games .game .join_game");
    $(document).on("click", "#joinduel_btn", function() { CFJoinDuel($(this)); });
    $(document).on("click", ".showDuelsFair", function() {
        

        let secret = $(this).attr("data-secret");
        let players = decodeURIComponent($(this).attr("data-players")).toString();
        let timestamp = $(this).attr("data-timestamp");
        let hash = $(this).attr("data-hash");
        let winner = $(this).attr("data-winner");

        $(".duel_secret").text(secret);
        $(".duel_players").text(players);
        $(".duel_timestamp").text(timestamp);
        $(".duel_hash").text(hash);
        $(".duel_ticket_number").text(winner);
        
        $("#duelFair").modal();
    
    
    });

    $(document).on("click", "#jackpotbet", function() {
        let amount = $("#jpbetamount").val();
        user("jackpot/bet", "POST", {amount: amount}, (err, res) => {
            if(err) return toastr.error(`Stop flood!`);
            if(!err && res.success) toastr.success(res.msg);
            else toastr.error(res.error);
        });
    });

    $(document).on("click", ".jpFair", function() {

        let secret = $(this).attr("data-secret");
        let hash = $(this).attr("data-hash");
        let timestamp = $(this).attr("data-timestamp");
        let players = $(this).attr("data-players");
        let winner_props = $(this).attr("data-winnerprops");

        $(".jp_secret").text(secret);
        $(".jp_hash").text(hash);
        $(".jp_timestamp").text(timestamp);
        $(".jp_players").text(players);
        if(winner_props) $(".jp_ticket_number").text(JSON.parse(winner_props).ticket_number);
        else $(".jp_ticket_number").text("");

        $("#jackpotFair").modal();
    });

    // USER FUNCTIONS
    function userRegister() {
        let username = $("#RUsername").val();
        let email = $("#REmail").val();
        let password = $("#RPassword").val();
        let cpassword = $("#RPassword2").val();
        user("register", "POST", {username: username, email: email, password: password, cpassword: cpassword}, (err, res) => {
            if(err) return toastr.error(`Stop flood!`);
            if(!err && res.success) {
                toastr.success(`You have been sucessfully register, you can now login!`);
            } else toastr.error(res.error);
        });
    }

    function userLogin() {
        let username = $("#LUsername").val();
        let password = $("#LPassword").val();
        user("login", "POST", {username: username, password: password}, (err, res) => {
            if(err) return toastr.error(`Stop flood!`);
            if(!err && res.success) {
                toastr.success(`You have been sucessfully logged in!`);
                setTimeout(() => {
                    location.href = '/';
                }, 500);
            } else toastr.error(res.error);
        });
    }

    function userProfile(u) {
        $(".profile .avatar").html(`<img src="${u.avatar}">`);
        $(".profile .info .name").text(u.username);
        $(".profile .info .registered").html(`Registered on <strong>${u.registered}</strong>`);
        $(".profile .info .uuid").html(`UUID: <strong>${u.uuid}</strong>`);
        $(".pstatistics .rbets").text(formatAmount(u.rbets));
        $(".pstatistics .deposited").text(formatAmount(u.deposited));
        $(".pstatistics .withdrawn").text(formatAmount(u.withdrawn));
        $(".pstatistics .wagered").text(formatAmount(u.wagered));
    }

    function userRBet(color) {
        let x = parseInt($("#RBet").val());
        user("roulette/bet", "POST", {amount: x, color: color}, (err, res) => {
            if(err) return toastr.error(`Stop flood!`);
            if(!err && res.success) toastr.success(res.msg);
            else toastr.error(res.error);
        });
    }

    function userChat() {
        if(chatInt) {
            chatInt = false;
            $("#chatInt").css("display", "block");
            $(".roulette").animate({width: "100%"}, 1000);
            $(".duels").animate({width: "100%"}, 1000);
            $(".jackpot").animate({width: "100%"}, 1000);
            $(".chat").animate({width: "0%"}, 1000);
            setTimeout(() => { $(".chat").css("display", "none"); }, 800);
            $("#chatInt").removeClass("hidden");
            $("#chatInt").animate({opacity: "1"}, 500);
        } else {
            chatInt = true;
            $(".chat").css("display", "block");
            $(".roulette").animate({width: "80%"}, 1000);
            $(".duels").animate({width: "80%"}, 1000);
            $(".jackpot").animate({width: "80%"}, 1000);
            $(".chat").animate({width: "20%"}, 1000);
            $("#chatInt").animate({opacity: "0"}, 500);
            setTimeout(() => { $("#chatInt").css("display", "none"); }, 500);
        }
    }

    function userChatMessage(a) {
        $(".chat-messages").append(formatChatMessage(a));
        scrollChat();
    }

    function userChatMessages(a) {
        let $msgs = "";
        for(let x in a) {
            $msgs += formatChatMessage(a[x]);
        }
        $(".chat-messages").html($msgs);
        scrollChat();
    }

    function chatClear() {
        $(".chat-messages").empty();
    }

    function formatChatMessage(x) {
        return `
            <div class="chat-message" data-uuid="${x.uuid}">
                <div class="avatar">
                    <img src="${x.avatar}">
                </div>
                <div class="user">
                    <div class="name">${formatChatRank(x.crank)}${x.username}</div>
                    <div class="message">${x.msg}</div>
                </div>
            </div>
        `;
    }

    function formatChatRank(crank) {
        if(!crank) return "";
        const RANKS = {
            0: "",
            100: `<span style="color: red;">ADMIN&nbsp;</span>`
        };
        return RANKS[crank];
    }

    function userSendChat() {
        let x = $(".chat-input").val();
        user("chat/message", "POST", {message: x}, (err, res) => {
            if(err) return toastr.error(`Stop flood!`);
            if(!err && res.success) toastr.success(res.msg);
            else toastr.error(res.error);
        });
        $(".chat-input").val("");
    }

    function userAffCollect() {
        user("affiliates/collect", "POST", {}, (err, res) => {
            if(err) return toastr.error(`Stop flood!`);
            if(!err && res.success) {
                toastr.success(res.msg);
                setTimeout(() => {
                    window.location.href = '/affiliates';
                }, 1000);
            }
            else toastr.error(res.error);
        });
    }

    function userDepositAddress(a, b) {
        $("#deposit_address").val(a);
        $("#destination_tag").val(b);
        $(".xrpqrimage").attr("src", `https://chart.googleapis.com/chart?cht=qr&chs=200x200&chl=${a}`);
    }

    function userRedeemcode() {
        let x = $("#aff_redeemcode").val();
        user("affiliates/redeem", "POST", {code: x}, (err, res) => {
            if(err) return toastr.error(`Stop flood!`);
            if(!err && res.success) {
                $("#aff_redemcodebtn").prop("disabled", true);
                $("#aff_redemcodebtn").css("cursor", "not-allowed");
                $("#aff_redemcodebtn").removeClass("btn-success").addClass("btn-danger");
                $("#aff_redeemcode").prop("readonly", true);
                $("#aff_redeemcode").css("cursor", "not-allowed");
                $("#aff_redeemcode").val(x);
                toastr.success(res.msg);
            }
            else toastr.error(res.error);
        });
    }

    function userCreatecode() {
        let x = $("#aff_createcode").val();
        user("affiliates/create", "POST", {code: x}, (err, res) => {
            if(err) return toastr.error(`Stop flood!`);
            if(!err && res.success) {
                $("#aff_createcodebtn").prop("disabled", true);
                $("#aff_createcodebtn").css("cursor", "not-allowed");
                $("#aff_createcodebtn").removeClass("btn-success").addClass("btn-danger");
                $("#aff_createcode").prop("readonly", true);
                $("#aff_createcodee").css("cursor", "not-allowed");
                $("#aff_createcode").val(x);
                toastr.success(res.msg);
            }
            else toastr.error(res.error);
        });
    }

    function userTransactions(a) {
        let $transactions = "";

        for(let x in a) {
            let i = a[x];

            let $status = `<span style="color: orange;">Pending</span>`;
            if(i.status == 2 && i.type == "withdraw") $status = `<span style="color: lightgreen;">Sent</span>`;
            if(i.status == 1 && i.type == "deposit") $status = `<span style="color: lightgreen;">Credited</span>`;

            $transactions += `
                <tr>
                    <td>${i.type.toUpperCase()}</td>
                    <td><i style="color: gold;" class="fas fa-coins"></i>&nbsp;${i.amount}</td>
                    <td>${i.txid ? `<a target="_blank" href="https://etherscan.io/tx/${i.txid}">${i.txid}</a>` : `processing txid..` }</td>
                    <td>${i.timestamp} (Server Time)</td>
                    <td>${$status}</td>
                </tr>
            `;
        }

        $('.pTransactions').html($transactions);
    }

    function userAffiliates(a) {
        console.log(a);
        $(".aff_users").html(`<i style="color: royalblue;" class="fas fa-user"></i>&nbsp;${a.users}`);
        $(".aff_depositors").html(`<i style="color: royalblue;" class="fas fa-user"></i>&nbsp;${a.depositors}`);
        $(".aff_earnings").html(`<i style="color: gold;" class="fas fa-coins"></i>&nbsp;${a.earnings}`);
        $(".aff_claimed").html(`<i style="color: gold;" class="fas fa-coins"></i>&nbsp;${a.claimed}`);
        $("#aff_collectearningsbtn").html(`<i class="fas fa-user-edit"></i> Collect <i class="fas fa-coins gold"></i> ${a.earnings}`);

        if(a.aff) {
            $("#aff_redemcodebtn").prop("disabled", true);
            $("#aff_redemcodebtn").css("cursor", "not-allowed");
            $("#aff_redemcodebtn").removeClass("btn-success").addClass("btn-danger");
            $("#aff_redeemcode").prop("readonly", true);
            $("#aff_redeemcode").css("cursor", "not-allowed");
            $("#aff_redeemcode").val(a.affocode);
        }

        if(a.affcode) {
            $("#aff_createcodebtn").prop("disabled", true);
            $("#aff_createcodebtn").css("cursor", "not-allowed");
            $("#aff_createcodebtn").removeClass("btn-success").addClass("btn-danger");
            $("#aff_createcode").prop("readonly", true);
            $("#aff_createcodee").css("cursor", "not-allowed");
            $("#aff_createcode").val(a.affcode);
        }
    }

    function userWithdrawFunds() {
        let x = $("#withdraw_address").val();
        let y = $("#withdraw_dest_tag").val();
        let a = $("#withdraw_amount").val();
        user("withdraw/create", "POST", {address: x, amount: a, dest_tag: y}, (err, res) => {
            if(err) return toastr.error(`Stop flood!`);
            if(!err && res.success) toastr.success(res.msg);
            else toastr.error(res.error);
        });
    }

    // FAIR FUNCTIONS
    function fairRounds(s) {
        let $H = "";
        for(let x in s) {
            let H = s[x];
            $H += `
                <tr style="color: ${formatLRoundC(H.roll)}">
                    <td>${H.hash}</td>
                    <td>${H.time_start}</td>
                    <td>${H.time_end}</td>
                    <td>${H.secret}</td>
                    <td><div class="ball ${formatRoll(H.roll)}">${H.roll}</div></td>
                </tr>
            `;
        }
        $(".lastRounds").html($H);
    }

    function chatUsersOnline(a) {
        $(".onlineusers").text(a);
        console.log(a);
    }


    // ROULETTE FUNCTIONS
    function rouletteTimer(s) {
        var t = s;
        rint = setInterval(() => {
            t = t - 100;
            let sec = parseFloat(t/1000).toFixed(1);
            $(".roll-text").text(`ROLLING IN ${sec}S`);
            let p = 100 - ((20000-t)/20000) * 100;
            if(focused) if(tpage == "/") document.title = `${sec}s - ${NAME}`;
            $(".progress .progress-bar").css("width", `${p}%`);
            if(t <= 0) {
                $(".roll-text").text(`ROLLING!`);
                clearInterval(rint);
                if(tpage == "/") document.title = `ROLLING! - ${NAME}`;
            }
        }, 100);
    }

    function rouletteBet(r) {
        const { amount, color, username, avatar } = r;
        const $H = `<div class="player-bet" data-amount="${amount}"><div class="player"><img src="${avatar}"><span>${username}</span></div><div class="coins"><i class="fas fa-coins"></i>&nbsp;${formatAmount(amount)}</div></div>`;
        $(`.${color}-players`).append($H);
        let newDiv = $(`.${color}-players .player-bet`).sort(function(a,b) {
            var A = $(a).attr("data-amount");
            var B = $(b).attr("data-amount");
            return B-A;
        });
        $(`.${color}-players`).html(newDiv);
    }

    function rouletteBets(h) {
        let OBJ = {"red": "", "green": "", "black": ""};
        for(let r in h) {
            const { amount, color, username, avatar } = h[r];
            OBJ[color] += `<div class="player-bet" data-amount="${amount}"><div class="player"><img src="${avatar}"><span>${username}</span></div><div class="coins"><i class="fas fa-coins"></i>&nbsp;${formatAmount(amount)}</div></div>`;
        }
        for(let x in OBJ) {
            $(`.${x}-players`).html(OBJ[x]);
        }
        sortRouletteBets();
    }

    function rouletteRoll(a) {
        spinWheel(a);
        clearInterval(rint);
        if(tpage == "/") $(".roll-text").text(`ROLLING!`);
        document.title = `ROLLING! - ${NAME}`;
        if(tpage == "/") $(".progress .progress-bar").css("width", `0%`);
    }

    function sortRouletteBets() {
        const colors = ["red", "green", "black"];
        for(let x in colors) {
            let newDiv = $(`.${colors[x]}-players .player-bet`).sort(function(a,b) {
                var A = $(a).attr("data-amount");
                var B = $(b).attr("data-amount");
                return B-A;
            }); 
            $(`.${colors[x]}-players`).html(newDiv);
        }
    }

    function clearRouletteBets() {
        const colors = ["red", "green", "black"];
        for(let x in colors) {
            $(`.${colors[x]}-players`).empty();
        }
    }

    function RBet(act) {
        let x = parseInt($("#RBet").val());
        switch(act) {
            case "clear":
                x = 0;
            break;
            case "+10":
                x += 10;
            break;
            case "+100":
                x += 100;
            break;
            case "+1000":
                x += 1000;
            break;
            case "+10000":
                x += 10000;
            break;
            case "+100000":
                x += 100000;
            break;
            case "1/2":
                x = parseInt(x/2);
            break;
            case "x2":
                x = parseInt(x*2);
            break;
        }
        $("#RBet").val(x);
    }

    function rouletteType(x) {
        if(x >= 1 && x <= 7) return "red";
        else if(x >= 8 && x <= 14) return "black";
        else return "green";
    }

    function rouletteHistory(h) {
        let $hist = "";
        for(let x in h) {
            $hist += `<div class="bhist ${rouletteType(h[x])}">${h[x]}</div>`;
        }
        $(".rollsHistory").html($hist);
    }

    // DUELS FUNCTIONS
    function CFCreateDuel() {
        let betamount = $("#CCBetAmount").val();
        let maxplayers = parseInt($("#CCPlayers").val());
        let acc_players = [2,3,4];
        if(acc_players.indexOf(maxplayers) == -1) return toastr.error("Max players can only be between 2-4!");
        user("duels/create", "POST", { amount: betamount, players: maxplayers }, (err, res) => {
            if(err) return toastr.error(`Stop flood!`);
            if(!err && res.success) toastr.success(res.msg);
            else toastr.error(res.error);
        });
    }

    function CFJoinDuel(t) {
        let duelid = t.attr("data-gameid");
        user("duels/join", "POST", { duelid: duelid }, (err, res) => {
            if(err) return toastr.error("Stop flood!");
            if(!err && res.success) toastr.success(res.msg);
            else toastr.error(res.error);
        });
    }
    // 

    function showJoinDuelBtn(t) {
        t.find("button").css("opacity", "1");
        t.parent().find(".top").css("opacity", "0.4");
        t.parent().find(".canvas").css("opacity", "0.4");
        t.parent().find(".game_number").css("opacity", "0.4");
        t.parent().find(".players").css("opacity", "0.4");
    }

    function hideJoinDuelBtn(t) {
        t.find("button").css("opacity", "0");
        t.parent().find(".top").css("opacity", "1");
        t.parent().find(".canvas").css("opacity", "1");
        t.parent().find(".game_number").css("opacity", "1");
        t.parent().find(".players").css("opacity", "1");
    }

    // USER INTERFACE FUNCTION
    function user(type, method, obj, cb) {
        let TYPE = `/${type}`;
        if(method == "GET") TYPE = `/${type}?${obj}`;
        $.ajax({
            url: TYPE,
            method: method,
            data: obj,
            success: (resp) => {
                cb(0, resp);
            },
            error: (err) => {
                cb(1, err);
            }
        });
    }

    // JACKPOT MAIN FUNCTIONS
    function jackpotPlayers(players, pamount) {

        let $pls = "";

        for(let x in players) {
            let it = players[x];

            let chance = 100 - ( ( pamount - it.amount ) / pamount ) * 100; 

            $pls += `
                <div class="player" style="background-color: ${it.color}">
                    <div class="chance">${parseFloat(chance).toFixed(2)}%</div>
                    <div class="image">
                        <img src="${it.avatar}">
                    </div>
                    <div class="user">
                        <div class="name">${it.name}</div>
                        <div class="amount">
                            <i class="fas fa-coins gold"></i>&nbsp;${formatAmount(parseInt(it.amount))}
                        </div>
                    </div>
                </div>
            `;
        }

        $("#jpPlayers").html($pls);
        createJackpotCanvas(players);
    }

    function jackpotTime(time) {

        let seconds = time;

        var intervalul = setInterval(() => {
            
            seconds = seconds - 1;

            $(".jpSeconds").text(seconds);

            if(seconds <= 0) {
                $(".jpSeconds").text(0);
                clearInterval(intervalul);
            }

        }, 1000);

    }

    function jackpotAnimation(players, anim) {
        let winner;
        for(let x in players) {
            if(players[x].steamid == anim.winner_uid) winner = players[x];
        }

        $(`.jackpot .top .canvas canvas`).css("transition", `all 6000ms cubic-bezier(0.005, 0.005, 0.455, 0.99) 0s`);
        $(`.jackpot .top .canvas canvas`).css("transform", `rotate(-${anim.degree_anim}deg)`);

        setTimeout(() => {
            $(".jackpot .top .pointer").css("color", winner.color);
        }, 6150);
    }

    function jackpotRound(round) {
        $(".jpFair").attr("title", `Secret: ${round.secret}`);
        $(".jpFair").attr("data-toggle", "tooltip");
        $(".jpFair").attr("data-placement", "left");
        $(".jpFair").attr("data-players", JSON.stringify(round.players));
        $(".jpFair").attr("data-secret", round.secret);
        $(".jpFair").attr("data-hash", round.hash);
        $(".jpFair").attr("data-timestamp", round.timestamp);
        $(".jpFair").attr("data-winnerprops", JSON.stringify(round.winner_props));
        $(".jpFair").tooltip();

        $(".jpAmount").html(`
            <i class="fas fa-coins gold"></i>&nbsp;${formatAmount(round.amount)}
        `);

        if(round.players.length == 0) {
            $("#jpPlayers").html("");
            createJackpotCanvas(round.players);

            $(`.jackpot .top .canvas canvas`).css("transition", `all 3000ms cubic-bezier(0.005, 0.005, 0.455, 0.99) 0s`);
            $(`.jackpot .top .canvas canvas`).css("transform", `rotate(0deg)`);

            $(".jpFair").attr("data-players", "[]");
            $(".jpFair").attr("data-hash", "");
            $(".jpFair").attr("data-timestamp", "");
            $(".jpFair").attr("data-winnerprops", "");

            $(".jackpot .top .pointer").css("color", "#adafae");
        }
    }

    function createJackpotCanvas(players) {
        let pamount = 0;

        let coptions = {
            type: "doughnut",
            data: {
              datasets: []
            },
            options: {
                cutoutPercentage: 85,
                responsive: true,
                maintainAspectRatio: false,
                showLines: false,
                animation: {},
                hover: {
                  intersect: false
                },
                elements: {
                  arc: {
                    borderWidth: 0
                  }
                },
                tooltips: {
                  enabled: false
                },
                legend: {
                  display: false
                }
            }
        };

        let DATA = [];
        let BGCOLOR = [];

        for(let d in players) {
            let it = players[d];
            DATA.push(it.amount);
            BGCOLOR.push(it.color);
        }

        if(players.length == 0) {
            DATA = [
                100
            ];
            BGCOLOR = [
                "grey"
            ];
        }

        coptions.data.datasets[0] = {
            data: DATA,
            backgroundColor: BGCOLOR
        };

        let ctx = document.getElementById(`jackpot-chart`).getContext('2d');

        $(".jpAmount").html(`
            <i class="fas fa-coins gold"></i>&nbsp;${formatAmount(pamount)}
        `);

        if(JPChart) {
            JPChart.data.datasets[0] = coptions.data.datasets[0];
            JPChart.update();
        } else {
            let chart = new Chart(ctx, coptions);
            JPChart = chart;
        }
    }

    // DUELS MAIN FUNCTIONS
    function duelsHistory(props) {
        let $html = "";
        CFCharts = {};

        for(let d in props) {
            let cf = props[d];
            $html += formatDuelsShow(d, cf, 1);
        }

        $(".duels .games").html($html);

        setTimeout(() => {
            for(let x in props) {
                let cf = props[x];
                createDuelsCanvas(x, cf);
            }
        }, 10);
    }

    function duelsCreate(props) {
        $(".duels .games").append(formatDuelsShow(props.id, props.game, 1));

        setTimeout(() => {
            createDuelsCanvas(props.id, props.game);
        }, 10);
    }

    function duelsEdit(props) {
        delete CFCharts[props.id];
        $(`.duels .games .game[data-id="${props.id}"]`).html(formatDuelsShow(props.id, props.game));

        setTimeout(() => {
            createDuelsCanvas(props.id, props.game);
        }, 10);
    }

    function duelsRemove(props) {
        delete CFCharts[props.id];
        $(`.duels .games .game[data-id="${props.id}"]`).remove();
    }

    function createDuelsCanvas(id, cf) {
        $(`[data-toggle="tooltip"]`).tooltip();
        if(!CFCharts.hasOwnProperty(id)) {
            let coptions = {
                type: "doughnut",
                data: {
                  datasets: []
                },
                options: {
                    cutoutPercentage: 90,
                    responsive: true,
                    maintainAspectRatio: false,
                    showLines: false,
                    animation: {},
                    hover: {
                      intersect: false
                    },
                    elements: {
                      arc: {
                        borderWidth: 0
                      }
                    },
                    tooltips: {
                      enabled: false
                    },
                    legend: {
                      display: false
                    }
                }
            };

            let CDATA = createDuelsData(cf);
            let CCOLORS = createDuelsColors(cf);
            coptions.data.datasets[0] = {
                data: CDATA,
                backgroundColor: CCOLORS
            };

            let chart = new Chart(document.getElementById(`chart-duel-${id}`).getContext('2d'), coptions);
            CFCharts[id] = chart;
        } else {
            let CDATA = createDuelsData(cf);
            let CCOLORS = createDuelsColors(cf);
            CFCharts[id].data.datasets[0] = {
                data: CDATA,
                backgroundColor: CCOLORS
            };
            CFCharts[id].update();
        }
    }

    function createDuelsData(cf) {
        let data = [];
        for(let x = 0; x < cf.mpls; x++) {
            data.push(cf.amount);
        }
        return data;
    }

    function createDuelsColors(cf) {
        let colors = [];
        let pcount = 0;
        for(let x in cf.players) {
            colors.unshift(duelcolors[pcount]);
            pcount++;
        }
        if(pcount < cf.mpls) {
            let pleft = parseInt(cf.mpls-pcount);
            for(let i = 0; i < pleft; i++) {
                colors.unshift("grey");
            }
        }
        return colors;
    }

    function formatDuelsShow(id, cf, n) {

        let $players = "";
        let pcount = 0;
        for(let x in cf.players) {
            let p = cf.players[x];
            $players += `
                <div class="player" data-slot="${x}">
                    <div class="img"><img style="border: 1px solid ${duelcolors[pcount]}" src="${p.avatar}"></div>
                    <div class="name" style="color: ${duelcolors[pcount]};">${p.name}</div>
                </div>
            `;
            pcount++;
        }

        if(pcount < cf.mpls) {
            let pleft = parseInt(cf.mpls-pcount);
            for(let i = 0; i < pleft; i++) {
                $players += `
                    <div class="player">
                        <div class="img"><img src="https://i.pinimg.com/originals/44/f3/1f/44f31f3e46483f8565f5de3fdf88ff0c.png"></div>
                        <div class="name">Empty Slot</div>
                    </div>
                `;
            }
        }

        let $joinduel = "";
        if(cf.state == 0) $joinduel = `
        <div class="join_game">
            <button type="button" class="btn btn-success" id="joinduel_btn" data-gameid="${id}">JOIN DUEL</button>
        </div>`;

        let $seconds = "";
        if(cf.state == 2 && cf.seconds) {
            $seconds = `
            <div class="seconds">
                <div>3</div>
            </div>
            `;

            var secs = 3;
            var int = setInterval(() => {
                secs = secs - 1;
                $(`.duels .games .game[data-id="${id}"] .seconds div`).html(secs);
                if(secs == 0) {
                    clearInterval(int);
                    $(`.duels .games .game[data-id="${id}"] .seconds`).remove();
                    $(`.duels .games .game[data-id="${id}"] .canvas canvas`).css("transition", `all 6000ms cubic-bezier(0.005, 0.005, 0.455, 0.99) 0s`);
                    $(`.duels .games .game[data-id="${id}"] .canvas canvas`).css("transform", `rotate(${cf.winner.degree_anim}deg)`);
                    setTimeout(() => {
                        $(`.duels .games .game[data-id="${id}"] .pointer`).css("color", duelcolors[cf.winner.slot]);
                    }, 6250);
                }
            }, 1000);
        } else if(cf.state == 2 && cf.animation) {
            setTimeout(() => { $(`.duels .games .game[data-id="${id}"] .pointer`).css("color", duelcolors[cf.winner.slot]); $(`.duels .games .game[data-id="${id}"] .canvas canvas`).css("transition", `all 1000ms cubic-bezier(0.005, 0.005, 0.455, 0.99) 0s`); $(`.duels .games .game[data-id="${id}"] .canvas canvas`).css("transform", `rotate(${cf.winner.degree_anim}deg)`); }, 1000);
        }

        return `
            ${n == 1 ? `<div class="game" data-id="${id}">` : ``}
                ${$joinduel}
                ${$seconds}
                <div class="top">
                    <div class="left">
                        <div class="i fas fa-coins"></div>
                        &nbsp;${formatAmount(cf.amount)}
                    </div>
                    <div class="right showDuelsFair" data-secret="${cf.secret}" data-winner="${cf.winner ? cf.winner.ticket_number : ``}" data-hash="${cf.hash ? cf.hash : ``}" data-players="${cf.winner ? encodeURIComponent(JSON.stringify(cf.players)) : ``}" data-timestamp="${cf.timestamp ? cf.timestamp : ``}" title="Secret: ${cf.secret}" data-toggle="tooltip" data-placement="left">
                        <i class="fas fa-info-circle"></i>
                    </div>
                </div>
                <div class="canvas">
                    <canvas id="chart-duel-${id}" width="130" height="130"></canvas>
                    <div class="pointer">
                        <i class="fas fa-caret-down"></i>
                    </div>
                </div>
                <div class="game_number">#${id}</div>
                <div class="players">${$players}</div>
            ${n == 1 ? `</div>`: ``}
        `;
    }
    // 

    // CONTEXT MENU
    function initContextmenu() {
        $.contextMenu({
            selector: '.chat .chat-messages .chat-message', 
            callback: function(key, options) {
                switch(key) {
                    case "copy_uuid":
                        copyUUID($(this));
                        toastr.success("UUID copied to clipboard!");
                    break;
                }
            },
            items: {
                "copy_uuid": {name: "Copy UUID", icon: "fas fa-copy"},
            }
        });
    }

    function copyUUID(x) {
        let uuid = x.attr("data-uuid");
        copyToClipboard(uuid);
    }

    function copyToClipboard(text) {
        var $temp = $("<input>");
        $("body").append($temp);
        $temp.val(text).select();
        document.execCommand("copy");
        $temp.remove();
    }

    function sendAlert(type, msg) {
        toastr[type](msg);
        console.log(type, msg);
    }
});

// ROULETTE FUNCTIONS

function initWheel() {
    let $wheel = $(".roulette-wrapper .wheel"), row = "";

    row += `
        <div class="roww">
            <div class="card red">1</div>
            <div class="card black">14</div>
            <div class="card red">2</div>
            <div class="card black">13</div>
            <div class="card red">3</div>
            <div class="card black">12</div>
            <div class="card red">4</div>
            <div class="card green">0</div>
            <div class="card black">11</div>
            <div class="card red">5</div>
            <div class="card black">10</div>
            <div class="card red">6</div>
            <div class="card black">9</div>
            <div class="card red">7</div>
            <div class="card black">8</div>
        </div>
    `;

    for(let x = 0; x < 29; x++) { $wheel.append(row); }
}

function spinWheel(roll){
  var $wheel = $('.roulette-wrapper .wheel'),
  		order = [0, 11, 5, 10, 6, 9, 7, 8, 1, 14, 2, 13, 3, 12, 4],
      position = order.indexOf(roll);
            
  var rows = 12,
  		card = 75 + 3 * 2,
      landingPosition = (rows * 15 * card) + (position * card);
  	
    var randomize = 0;
    
  landingPosition = landingPosition + randomize;
    
  var object = {
		x: Math.floor(Math.random() * 50) / 100,
    y: Math.floor(Math.random() * 20) / 100
	};
  
  $wheel.css({
		'transition-timing-function':'cubic-bezier(0,'+ object.x +','+ object.y + ',1)',
		'transition-duration':'6s',
		'transform':'translate3d(-'+landingPosition+'px, 0px, 0px)'
	});
  
  setTimeout(function(){
		$wheel.css({
			'transition-timing-function':'',
			'transition-duration':'',
		});
    
    var resetTo = -(position * card + randomize);
        $wheel.css('transform', 'translate3d('+resetTo+'px, 0px, 0px)');
        
        if(tpage == "/") $(".roll-text").text(`ROLLED ${roll}!`);
        if(tpage == "/") document.title = `ROLLED ${roll}! - ${NAME}`;
  }, 6 * 1000);
}

function setWheelPosition(roll) {
    var $wheel = $('.roulette-wrapper .wheel'),
        order = [0, 11, 5, 10, 6, 9, 7, 8, 1, 14, 2, 13, 3, 12, 4],
    position = order.indexOf(roll);
        
    var rows = 12,
        card = 75 + 3 * 2,
    landingPosition = (rows * 15 * card) + (position * card);

    var randomize = 0;

    landingPosition = landingPosition + randomize;

    var object = {
        x: Math.floor(Math.random() * 50) / 100,
        y: Math.floor(Math.random() * 20) / 100
    };

    $wheel.css({
        'transition-timing-function':'cubic-bezier(0,'+ object.x +','+ object.y + ',1)',
        'transition-duration':'0s',
        'transform':'translate3d(-'+landingPosition+'px, 0px, 0px)'
    });

    setTimeout(function(){
        $wheel.css({
            'transition-timing-function':'',
            'transition-duration':'',
        });

        var resetTo = -(position * card + randomize);
        $wheel.css('transform', 'translate3d('+resetTo+'px, 0px, 0px)');

        if(tpage == "/") $(".roll-text").text(`ROLLED ${roll}!`);
        if(tpage == "/") document.title = `ROLLED ${roll}! - ${NAME}`;
    }, 0);
}

// COOKIE FUNCTION
function getCookie(cname) {
    var name = cname + "=";
    var decodedCookie = decodeURIComponent(document.cookie);
    var ca = decodedCookie.split(';');
    for(var i = 0; i <ca.length; i++) {
      var c = ca[i];
      while (c.charAt(0) == ' ') {
        c = c.substring(1);
      }
      if (c.indexOf(name) == 0) {
        return c.substring(name.length, c.length);
      }
    }
    return "";
  }


// WINDOW PAHT
function getWindowPath() {
    var page = window.location.pathname;
    tpage = page;
    $(`.nav-item[data-link="${page}"]`).addClass("active");
}

// FORMAT NUMBER
function formatAmount(x) {
    return x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// FORMAT ROLL
function formatRoll(x) {
    if(x >= 1 && x <= 7) return "red";
    else if(x >= 8 && x <= 14) return "black";
    else return "green";
}

function formatLRoundC(x) {
    if(x >= 1 && x <= 7) return "#f95146";
    else if(x >= 8 && x <= 14) return "grey";
    else return "#00c74d";
}

// scroll chat
function scrollChat() {
    setTimeout(() => {
        $(".chat-messages").scrollTop(999999);
    }, 100);
}