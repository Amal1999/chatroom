"use strict";


var gravatar = require('gravatar');
var manager = require('./manager.js');
var crypto = require("crypto-js");
var serverVersion = manager.generateGuid(); // a unique version for every startup of server
var globalChannel = "environment"; // add any authenticated user to this channel
var chat = {}; // socket.io
var loginExpireTime = 3600 * 1000; // 3600sec
const CertificateAuthority = require('./certif_authority');
var ldap = require('ldapjs');


/*var client = ldap.createClient({
    url: 'ldap://0.0.0.0:1389'
});




function saveToLDAP(username) {

    var certPem = fs.readFileSync("server/certifs/" + username + '_certif.pem');

    var cert = forge.pki.certificateFromPem(certPem);

    // Add the certificate to an LDAP entry
    var entry = {
        dn: 'cn=' + username + ',ou=users,dc=example,dc=com',
        attributes: {
            objectclass: ['User'],
            cn: username,
            userCertificate: certPem
        }
    };

    client.add(entry.dn, entry.attributes, function (err) {
        if (err) {
            console.log('--------------------- errrooooor -----------');
            console.log(err);
            return;
        }
        console.log('Certificate added to LDAP directory');
    });

    // Bind to the LDAP server using the certificate
    client.bind(entry.dn, cert, function (err) {
        if (err) {
            console.log(err);
            return;
        }
        console.log('Bound to LDAP server with certificate');
    });
}*/


module.exports = function (app, io) {
    // Initialize a new socket.io application
    chat = io;
    let certifAuth = new CertificateAuthority()

    io.on('connection', function (socket) {
        console.info(`socket: ${socket.id} connected`);

        // When the client emits 'login', save his name and avatar and add them to the channel
        socket.on('login', data => {
            // check login password from decrypt cipher by nonce password (socket.id)
            var userHashedPass = crypto.TripleDES.decrypt(data.password, socket.id).toString(crypto.enc.Utf8);

            var user = manager.clients[data.email.hashCode()];
            if (user) { // exist user                
                if (user.password == userHashedPass) {
                    // check user sign expiration
                    if (user.lastLoginDate + loginExpireTime > Date.now()) { // expire after 60min
                        if (certifAuth.verficateCertification(user.username)) {
                            userSigned(user, socket);
                        }
                    }
                    else {
                        socket.emit("resign");
                    }
                    user.lastLoginDate = Date.now(); // update user login time
                }
                else { // exist user, entry password is incorrect
                    socket.emit("exception", "The username or password is incorrect!");
                    console.info(`User <${user.username}> can't login, because that password is incorrect!`);
                }
            }
            else { // new user
                // Use the socket object to store data.
                var user = {
                    "socketid": socket.id, // just solid for this connection and changed for another connecting times
                    "id": data.email.hashCode(), // unique for this email
                    "username": data.username, // display name, unique
                    "email": data.email, // unique email address for any users                                       
                    "password": userHashedPass, // Store Password Hashing for client login to authenticate one user per email
                    "avatar": gravatar.url(data.email, { s: '140', r: 'x', d: 'mm' }), // user avatar picture's
                    "status": "online", // { "online", "offline" }
                    "lastLoginDate": Date.now() // last login time accourding by server time
                };
                manager.clients[user.id] = user;
                certifAuth.createCertification(user.username)
                userSigned(user, socket);
            }
        });

    });

}


function userSigned(user, socket) {
    user.status = "online";
    user.socketid = socket.id;
    socket.user = user;

    // send success ack to user
    socket.emit("signed", {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "avatar": user.avatar,
        "status": user.status,
        "serverVersion": serverVersion, // chance of this version caused to refresh clients cached data
    });

    socket.join(globalChannel); // join all users in global authenticated group

    // add user to all joined channels
    var userChannels = manager.getUserChannels(user.id, true);
    for (var channel in userChannels) {
        socket.join(channel);
    }

    updateAllUsers();
    defineSocketEvents(socket);

    console.info(`User <${user.username}> by socket <${user.socketid}> connected`)
}

function updateAllUsers() {
    // when new user added
    chat.sockets.in(globalChannel).emit("update", { users: manager.getUsers(), channels: manager.getChannels() });
}

function createChannel(name, user, p2p) {
    var channel = { name: name, p2p: p2p, adminUserId: user.id, status: "online", users: [user.id] };
    manager.channels[name] = channel;
    chat.sockets.connected[user.socketid].join(name);
    return channel;
}

function defineSocketEvents(socket) {

    // Somebody left the chat
    socket.on('disconnect', () => {
        // find user who abandon sockets
        var user = socket.user || manager.findUser(socket.id);
        if (user) {
            console.warn(`User <${user.username}> by socket <${user.socketid}> disconnected!`);
            user.status = "offline";

            // Notify the other person in the chat channel
            socket.broadcast.to(globalChannel).emit('leave',
                { username: user.username, id: user.id, avatar: user.avatar, status: user.status });
        }
    });

    // Sending messages
    socket.on("msg", data => {
        var from = socket.user || manager.findUser(socket.id);
        var channel = manager.channels[data.to];

        if (from != null && channel != null && channel.users.indexOf(from.id) != -1) {
            var msg = manager.messages[channel.name];
            if (msg == null)
                msg = manager.messages[channel.name] = [];

            data.date = Date.now();
            data.type = "msg";
            // When the server receives a message, it sends it to the all clients, so also to sender
            chat.sockets.in(channel.name).emit('receive', data);
            msg.push(data);
        }
    });

    // Handle the request of users for chat
    socket.on("request", data => {

        // find user who requested to this chat by socket id
        var from = socket.user || manager.findUser(socket.id);

        // if user authenticated 
        if (from) {
            data.from = from.id;

            // find user who should we send request to
            var adminUser = manager.getAdminFromChannelName(data.channel, from.id)

            if (adminUser) {
                if (adminUser.status == "offline") {
                    var p2p = (manager.channels[data.channel] == null ? true : manager.channels[data.channel].p2p);
                    socket.emit("reject", { from: adminUser.id, channel: data.channel, p2p: p2p, msg: "admin user is offline" });
                }
                else
                    chat.to(adminUser.socketid).emit("request", data)
                return;
            }
        }
        socket.emit("exception", "The requested chat not found!");
    });

    // Handle the request of users for chat
    socket.on("accept", data => {

        var from = socket.user || manager.findUser(socket.id);
        var to = manager.clients[data.to];

        if (from != null && to != null) {
            var channel = manager.channels[data.channel];

            if (channel == null) {
                channel = createChannel(data.channel, from, true)
            }
            channel.users.push(to.id);
            chat.sockets.connected[to.socketid].join(channel.name);

            // send accept msg to user which requested to chat
            socket.to(to.socketid).emit("accept", { from: from.id, channel: channel.name, p2p: channel.p2p, channelKey: data.channelKey })
        }
    });

    // Handle the request to create channel
    socket.on("createChannel", name => {
        var from = socket.user;
        var channel = manager.channels[name];

        if (channel) {
            // the given channel name is already exist!
            socket.emit("reject", { from: from.id, p2p: false, channel: channel, msg: "The given channel name is already exist" })
            return;
        }

        channel = createChannel(name, from, false);
        updateAllUsers();

        console.info(`Channel <${channel.name}> created by user <${from.username}: ${channel.adminUserId}>`)
    });


    // Handle the request of users for chat
    socket.on("reject", data => {

        var from = socket.user || manager.findUser(socket.id);
        var to = manager.clients[data.to];

        if (from != null && to != null) {
            var channel = manager.channels[data.channel];
            socket.to(to.socketid).emit("reject", { from: from.id, p2p: (channel == null), channel: data.channel })
        }
    });

    // Handle the request of users for chat
    socket.on("fetch-messages", channelName => {
        var fetcher = socket.user || manager.findUser(socket.id);

        var channel = manager.channels[channelName];

        // check fetcher was a user of channel
        if (fetcher != null && channel != null && channel.users.indexOf(fetcher.id) !== -1)
            socket.emit("fetch-messages", { channel: channel.name, messages: manager.messages[channel.name] });
        else
            socket.emit("exception", `you are not joined in <${channelName}> channel or maybe the server was lost your data!!!`);
    });

    socket.on("typing", channelName => {
        var user = socket.user || manager.findUser(socket.id);
        var channel = manager.channels[channelName];

        if (user && channel && channel.users.indexOf(user.id) !== -1) {
            chat.sockets.in(channel.name).emit("typing", { channel: channel.name, user: user.id });
        }
    });

}