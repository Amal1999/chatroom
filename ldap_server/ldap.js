var ldap = require('ldapjs');

var server = ldap.createServer();

server.bind('cn=root', function(req, res, next) {
    if (req.dn.toString() !== 'cn=root' || req.credentials !== 'secret')
      return next(new ldap.InvalidCredentialsError());

    res.end();
    return next();
});

server.search('o=myhost', function(req, res, next) {
  var obj = {
    dn: req.dn.toString(),
    attributes: {
      objectclass: ['organization', 'top'],
      o: 'myhost'
    }
  };

  if (req.filter.matches(obj.attributes))
    res.send(obj);

  res.end();
});

server.listen(1389, function() {
  console.log('LDAP server listening at %s', server.url);
});
