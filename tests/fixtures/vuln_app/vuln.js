// Intentionally vulnerable sample for BugHunter SAST tests. Test data only.

function render(el, html) {
  el.innerHTML = html;
}

function renderDocument(name) {
  document.write("<h1>hello " + name + "</h1>");
}

function calculate(expr) {
  return eval(expr);
}
