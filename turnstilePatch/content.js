// Turnstile Patch - 增强 stealth + WebGL/Canvas 反指纹，不在注册早期页面补丁 turnstile API。
// 原因：在 OTP/邮箱路由阶段注入 pageHook 会干扰 xAI SPA 过渡，
// 表现为 verify-email 200 后长期停在 "An error occurred"。
// Turnstile 观测 hook 改由 Python 在资料页 fill_profile_and_submit 时 CDP 注入。

(function () {
    "use strict";

    // 1. 隐藏 navigator.webdriver
    try {
        Object.defineProperty(navigator, "webdriver", {
            get: function () {
                return false;
            },
            configurable: true,
        });
    } catch (e) {}

    // 2. 覆盖 permissions.query 的 notifications 异常路径
    try {
        var origQuery = navigator.permissions.query.bind(navigator.permissions);
        navigator.permissions.query = function (params) {
            if (params && params.name === "notifications") {
                return Promise.resolve({ state: Notification.permission });
            }
            return origQuery(params);
        };
    } catch (e) {}

    // 3. languages 保持常见桌面画像
    try {
        Object.defineProperty(navigator, "languages", {
            get: function () {
                return ["en-US", "en"];
            },
            configurable: true,
        });
    } catch (e) {}

    // 4. platform —— 根据 UA 动态推导
    try {
        var ua = navigator.userAgent || "";
        var p = "Linux x86_64";
        if (/Windows/.test(ua)) p = "Win32";
        else if (/Macintosh/.test(ua)) p = "MacIntel";
        Object.defineProperty(navigator, "platform", { get: function () { return p; }, configurable: true });
    } catch (e) {}

    // 5. WebGL vendor/renderer 伪装 —— 仅替换 SwiftShader / llvmpipe 等软件渲染
    try {
        var FAKE_WGL_VENDOR = "Google Inc. (Intel)";
        var FAKE_WGL_RENDERER = "ANGLE (Intel, Mesa Intel(R) UHD Graphics 630 (CFL GT2), OpenGL 4.6)";

        var isSoftwareRenderer = (function () {
            try {
                var c = document.createElement("canvas");
                var gl = c.getContext("webgl") || c.getContext("experimental-webgl");
                if (!gl) return false;
                var ext = gl.getExtension("WEBGL_debug_renderer_info");
                if (!ext) return false;
                var r = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || "";
                return /swiftshader|llvmpipe|softpipe|software.*rasterizer|mesa.*swrast/i.test(r);
            } catch (e) { return false; }
        })();

        if (isSoftwareRenderer) {
            var hookGetParam = function (proto) {
                if (!proto || !proto.getParameter) return;
                var orig = proto.getParameter;
                proto.getParameter = function (param) {
                    if (param === 37445) return FAKE_WGL_VENDOR;
                    if (param === 37446) return FAKE_WGL_RENDERER;
                    return orig.call(this, param);
                };
            };
            try { hookGetParam(WebGLRenderingContext.prototype); } catch (e) {}
            try { hookGetParam(WebGL2RenderingContext.prototype); } catch (e) {}
        }
    } catch (e) {}

    // 6. Canvas 指纹噪声 —— 对 toDataURL/toBlob 注入微量确定性噪声
    try {
        var origToDataURL = HTMLCanvasElement.prototype.toDataURL;
        var origToBlob = HTMLCanvasElement.prototype.toBlob;
        var _noiseOff = ((window.location.hostname || "").length * 7 + 3) % 5 + 1;

        function _canvasInjectNoise(canvas) {
            try {
                var ctx = canvas.getContext("2d");
                if (!ctx || canvas.width < 1 || canvas.height < 1) return;
                var img = ctx.getImageData(0, 0, 1, 1);
                img.data[3] = (img.data[3] + _noiseOff) & 0xFF;
                ctx.putImageData(img, 0, 0);
            } catch (e) {}
        }

        HTMLCanvasElement.prototype.toDataURL = function () {
            _canvasInjectNoise(this);
            return origToDataURL.apply(this, arguments);
        };
        if (origToBlob) {
            HTMLCanvasElement.prototype.toBlob = function () {
                _canvasInjectNoise(this);
                return origToBlob.apply(this, arguments);
            };
        }
    } catch (e) {}

    // 7. 资料页若出现可见 Turnstile iframe，尝试轻点（跨域失败则忽略）
    function autoClickTurnstile() {
        var checkCount = 0;
        var maxChecks = 80;
        var timer = setInterval(function () {
            checkCount++;
            if (checkCount > maxChecks) {
                clearInterval(timer);
                return;
            }
            try {
                var iframes = document.querySelectorAll(
                    'iframe[src*="challenges.cloudflare.com"], iframe[src*="turnstile"]'
                );
                if (!iframes.length) return;
                for (var i = 0; i < iframes.length; i++) {
                    var iframe = iframes[i];
                    try {
                        var body = iframe.contentDocument || iframe.contentWindow.document;
                        var checkbox = body.querySelector('input[type="checkbox"], .mark');
                        if (checkbox && !checkbox.checked) checkbox.click();
                    } catch (e) {
                        // 跨域，无法直接点
                    }
                }
            } catch (e) {}
        }, 500);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", autoClickTurnstile);
    } else {
        autoClickTurnstile();
    }
})();
