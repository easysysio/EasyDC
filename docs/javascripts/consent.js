// Make "Accept" on the cookie banner mean accept.
//
// The theme's Accept button only submits the checkboxes as they stand. After a
// visitor has rejected, the theme restores every box unticked — so opening
// "Cookie settings" again and pressing Accept saved "nothing accepted" a second
// time, with no sign that it had. Here Accept ticks every box first, unless the
// "Manage settings" list is open, where it saves exactly what is ticked.
document.addEventListener("click", function (event) {
  var button = event.target.closest(".md-consent__controls button");
  if (!button || button.type === "reset") return;

  var form = document.forms.consent;
  var settings = document.getElementById("__settings");
  if (!form || (settings && settings.checked)) return;

  Array.prototype.forEach.call(form.elements, function (input) {
    if (input.name) input.checked = true;
  });
});
