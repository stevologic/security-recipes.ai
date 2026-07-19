(function () {
  "use strict";

  function mount() {
    var canvas = document.getElementById("homeSignalCanvas");
    if (!canvas || !canvas.getContext) return;

    var ctx = canvas.getContext("2d", { alpha: true });
    if (!ctx) return;

    var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    var width = 0;
    var height = 0;
    var dpr = 1;
    var points = [];
    var gridColumns = 0;
    var pointer = {
      x: window.innerWidth * 0.72,
      y: window.innerHeight * 0.34,
      tx: window.innerWidth * 0.72,
      ty: window.innerHeight * 0.34,
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
      gridColumns = columns + 2;
      points = [];

      for (var y = -1; y <= rows; y += 1) {
        for (var x = -1; x <= columns; x += 1) {
          points.push({
            x: x * 105 + (y % 2) * 36 + noise(x * 3.1 + y) * 24,
            y: y * 100 + noise(y * 4.8 - x) * 24,
            phase: noise(x * 12.3 + y * 9.7) * Math.PI * 2,
            cx: 0,
            cy: 0,
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

      var maxGap = 145;
      var maxGapSquared = maxGap * maxGap;
      var span = gridColumns + 2;
      for (var a = 0; a < points.length; a += 1) {
        var start = points[a];
        var endIndex = Math.min(points.length, a + span);
        for (var b = a + 1; b < endIndex; b += 1) {
          var end = points[b];
          var gapX = start.cx - end.cx;
          var gapY = start.cy - end.cy;
          var gapSquared = gapX * gapX + gapY * gapY;
          if (gapSquared >= maxGapSquared) continue;
          var gap = Math.sqrt(gapSquared);
          ctx.strokeStyle =
            "rgba(103, 232, 249, " + 0.12 * (1 - gap / maxGap) + ")";
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(start.cx, start.cy);
          ctx.lineTo(end.cx, end.cy);
          ctx.stroke();
        }
      }

      for (var p = 0; p < points.length; p += 1) {
        var dot = points[p];
        var near = Math.max(
          0,
          1 - Math.hypot(pointer.x - dot.cx, pointer.y - dot.cy) / 280,
        );
        ctx.fillStyle =
          p % 11 === 0 ? "#fbbf24" : p % 3 === 0 ? "#67e8f9" : "#2dd4bf";
        ctx.globalAlpha = 0.13 + near * 0.5;
        ctx.beginPath();
        ctx.arc(dot.cx, dot.cy, 1.45 + near * 2.4, 0, Math.PI * 2);
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
      if (!reduceMotion.matches) raf = window.requestAnimationFrame(frame);
    }

    function stop() {
      if (raf === null) return;
      window.cancelAnimationFrame(raf);
      raf = null;
    }

    function start() {
      stop();
      if (reduceMotion.matches || document.hidden) {
        draw(0);
        return;
      }
      raf = window.requestAnimationFrame(frame);
    }

    function reveal() {
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
    document.addEventListener("visibilitychange", start);
    if (reduceMotion.addEventListener) {
      reduceMotion.addEventListener("change", start);
    }

    resize();
    start();
    reveal();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mount, { once: true });
  } else {
    mount();
  }
})();
