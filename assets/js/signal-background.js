(function () {
  function onReady(callback) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", callback, { once: true });
      return;
    }
    callback();
  }

  onReady(function () {
    var root = document.documentElement;
    if (root.dataset.siteSignalBackground !== "true" && root.dataset.recipeBrowserPage !== "true") return;

    var canvas = document.getElementById("homeSignalCanvas");
    if (!canvas) {
      canvas = document.createElement("canvas");
      canvas.id = "homeSignalCanvas";
      canvas.className = "home-signal-canvas";
      canvas.setAttribute("aria-hidden", "true");
      document.body.insertBefore(canvas, document.body.firstChild);
    }

    if (!document.querySelector(".site-ambient")) {
      var ambient = document.createElement("div");
      ambient.className = "site-ambient";
      ambient.setAttribute("aria-hidden", "true");
      for (var s = 0; s < 3; s += 1) {
        ambient.appendChild(document.createElement("span"));
      }
      canvas.insertAdjacentElement("afterend", ambient);
    }

    if (!canvas.getContext) return;

    var ctx = canvas.getContext("2d", { alpha: true });
    var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    var width = 0;
    var height = 0;
    var dpr = 1;
    var points = [];
    var pointer = {
      x: window.innerWidth * 0.72,
      y: window.innerHeight * 0.34,
      tx: window.innerWidth * 0.72,
      ty: window.innerHeight * 0.34
    };
    var raf = null;
    var didReveal = false;

    function noise(value) {
      var raw = Math.sin(value * 12.9898) * 43758.5453;
      return raw - Math.floor(raw);
    }

    function lerp(a, b, amount) {
      return a + (b - a) * amount;
    }

    function buildPoints() {
      var columns = Math.ceil(width / 105);
      var rows = Math.ceil(height / 100);
      points = [];

      for (var y = -1; y <= rows; y += 1) {
        for (var x = -1; x <= columns; x += 1) {
          points.push({
            x: x * 105 + (y % 2) * 36 + noise(x * 3.1 + y) * 24,
            y: y * 100 + noise(y * 4.8 - x) * 24,
            phase: noise(x * 12.3 + y * 9.7) * Math.PI * 2,
            cx: 0,
            cy: 0
          });
        }
      }
    }

    function draw(time) {
      var t = reduceMotion.matches ? 0 : time;
      ctx.clearRect(0, 0, width, height);
      ctx.save();
      ctx.globalCompositeOperation = "lighter";

      for (var i = 0; i < points.length; i += 1) {
        var point = points[i];
        var wobble = Math.sin(t * 0.001 + point.phase) * 9;
        var px = point.x + wobble + Math.sin(t * 0.0007 + point.phase) * 8;
        var py = point.y + Math.cos(t * 0.0009 + point.phase) * 8;
        var dx = pointer.x - px;
        var dy = pointer.y - py;
        var distance = Math.hypot(dx, dy);
        var pull = Math.max(0, 1 - distance / 260) * 22;
        point.cx = px - (dx / Math.max(distance, 1)) * pull;
        point.cy = py - (dy / Math.max(distance, 1)) * pull;
      }

      for (var a = 0; a < points.length; a += 1) {
        for (var b = a + 1; b < points.length; b += 1) {
          var start = points[a];
          var end = points[b];
          var gap = Math.hypot(start.cx - end.cx, start.cy - end.cy);
          if (gap < 145) {
            ctx.strokeStyle = "rgba(103, 232, 249, " + (0.14 * (1 - gap / 145)) + ")";
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(start.cx, start.cy);
            ctx.lineTo(end.cx, end.cy);
            ctx.stroke();
          }
        }
      }

      for (var p = 0; p < points.length; p += 1) {
        var dot = points[p];
        var near = Math.max(0, 1 - Math.hypot(pointer.x - dot.cx, pointer.y - dot.cy) / 280);
        ctx.fillStyle = p % 7 === 0 ? "#fbbf24" : p % 3 === 0 ? "#67e8f9" : "#2dd4bf";
        ctx.globalAlpha = 0.18 + near * 0.62;
        ctx.beginPath();
        ctx.arc(dot.cx, dot.cy, 1.7 + near * 2.7, 0, Math.PI * 2);
        ctx.fill();
      }

      ctx.restore();
    }

    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      canvas.style.width = width + "px";
      canvas.style.height = height + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      buildPoints();
      draw(0);
    }

    function movePointer(event) {
      pointer.tx = event.clientX;
      pointer.ty = event.clientY;
      if (reduceMotion.matches) {
        pointer.x = pointer.tx;
        pointer.y = pointer.ty;
        draw(0);
      }
    }

    function frame(time) {
      pointer.x = lerp(pointer.x, pointer.tx, 0.09);
      pointer.y = lerp(pointer.y, pointer.ty, 0.09);
      draw(time);
      if (!reduceMotion.matches) {
        raf = window.requestAnimationFrame(frame);
      }
    }

    function start() {
      if (raf !== null) {
        window.cancelAnimationFrame(raf);
        raf = null;
      }
      if (reduceMotion.matches) {
        draw(0);
      } else {
        raf = window.requestAnimationFrame(frame);
      }
    }

    function revealBackground() {
      if (didReveal) return;
      didReveal = true;
      window.requestAnimationFrame(function () {
        window.requestAnimationFrame(function () {
          document.documentElement.dataset.signalBackgroundReady = "true";
        });
      });
    }

    window.addEventListener("resize", resize);
    window.addEventListener("pointermove", movePointer, { passive: true });
    if (reduceMotion.addEventListener) {
      reduceMotion.addEventListener("change", start);
    }

    resize();
    start();
    revealBackground();
  });
})();
