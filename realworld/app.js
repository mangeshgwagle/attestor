// Deliberately buggy "real-world" JavaScript. Sample input for the detector.
// Not meant to run.

function isSame(a, b) {
  // js-loose-equality: == coerces types (0 == "", null == undefined ...).
  return a == b;
}

function render(userInput) {
  // js-innerhtml: injecting unsanitized input as live HTML (XSS).
  document.getElementById("out").innerHTML = userInput;
}

function runIt(code) {
  // dangerous-eval: eval on input is arbitrary code execution.
  return eval(code);
}

const httpsOptions = {
  // tls-verify-disabled: accepts any certificate (MITM).
  rejectUnauthorized: false,
};

// js-settimeout-string: the string is compiled and run like eval.
setTimeout("doStuff()", 1000);

// js-var (deep): function-scoped, hoisted; prefer let/const.
var counter = 0;
