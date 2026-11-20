// One DOM sink per numbered line, then safe look-alikes that must not count.
function render(user, el, frame, target) {
  el.innerHTML = "<b>" + user.name + "</b>";
  el.outerHTML = user.bio;
  document.write(user.footer);
  el.insertAdjacentHTML("beforeend", user.card);
  eval(user.expr);
  var f = new Function("a", user.body);
  setTimeout("refresh(" + user.id + ")", 100);
  window.location.href = target + "?next=" + user.next;
  frame.contentWindow.postMessage({token: user.id}, "*");
  window.addEventListener("message", function (e) { render(e.data); });
}

// Safe look-alikes below.
function safe(el, frame, ev) {
  el.innerHTMLFoo = "x";
  var copy = el.innerHTML;
  if (el.innerHTML == "") {}
  // eval(user.expr);
  /* document.write(x); new Function("y"); */
  var help = "call eval(x) or el.innerHTML = y in a string";
  setTimeout(function () { tick(); }, 100);
  window.location.href = "/home";
  location = "/login";
  frame.contentWindow.postMessage("ping", "https://app.acme.test");
  window.addEventListener("message", function (e) {
    if (e.origin !== "https://app.acme.test") { return; }
    ev(e.data);
  });
  var re = /eval\(/g;
  myeval(1);
}
