// Turnstile Patch - 全面 stealth + 原型级反指纹 + 帧隔离，不在注册早期页面补丁 turnstile API。
// 原因：在 OTP/邮箱路由阶段注入 pageHook 会干扰 xAI SPA 过渡，
// 表现为 verify-email 200 后长期停在 "An error occurred"。
// Turnstile 观测 hook 改由 Python 在资料页 fill_profile_and_submit 时 CDP 注入。
//
// 关键修复（与 Python stealth 脚本同步）：
// 1. 所有 navigator 属性在 Navigator.prototype 上覆盖，避免 hasOwnProperty 检测
// 2. webdriver 返回 false 而非 undefined
// 3. chrome.runtime/csi/loadTimes 仅在顶层 frame 注入（跨域 iframe 中不应存在）
// 4. chrome.csi/loadTimes 返回完整字段
// 5. 新增 userAgentData / maxTouchPoints / connection 覆盖
// 6. WebGL getSupportedExtensions 也替换（SwiftShader 扩展列表不同）

(function () {
    "use strict";
    var isTop = (window.top === window.self);

    // 1. navigator.webdriver —— 仅当仍为 true/undefined 时在原型上覆盖为 false
    try {
        var wd = navigator.webdriver;
        if (wd === true || wd === undefined) {
            Object.defineProperty(Navigator.prototype, "webdriver", { get: function () { return false; }, configurable: true, enumerable: true });
        }
    } catch (e) {}

    // 2. chrome 对象 —— 仅在顶层 frame 添加（跨域 iframe 中不应有 chrome.runtime/csi/loadTimes）
    try {
        if (isTop) {
            if (!window.chrome) window.chrome = {};
            if (!window.chrome.runtime) window.chrome.runtime = {};
            if (!window.chrome.csi) {
                var _t = Date.now();
                window.chrome.csi = function () { return { startE: _t - 2000, onloadT: _t - 500, pageT: 2000, tran: 15 }; };
            }
            if (!window.chrome.loadTimes) {
                window.chrome.loadTimes = function () {
                    var now = Date.now() / 1000;
                    return {
                        commitLoadTime: now - 2, connectionInfo: "h2",
                        finishDocumentLoadTime: now - 1, finishLoadTime: now - 0.5,
                        firstPaintAfterLoadTime: 0, firstPaintTime: now - 1.5,
                        navigationType: "Other", npnNegotiatedProtocol: "h2",
                        requestTime: now - 3, startLoadTime: now - 2.5,
                        wasAlternateProtocolAvailable: false, wasFetchedViaSPDY: true,
                        wasNpnNegotiated: true
                    };
                };
            }
        }
    } catch (e) {}

    // 3. permissions.query —— 在 Permissions.prototype 上覆盖
    try {
        if (window.navigator.permissions && window.navigator.permissions.query) {
            var origQuery = Permissions.prototype.query;
            Object.defineProperty(Permissions.prototype, "query", {
                value: function (parameters) {
                    if (parameters && parameters.name === "notifications") {
                        return Promise.resolve({ state: Notification.permission });
                    }
                    return origQuery.call(this, parameters);
                },
                configurable: true, writable: true,
            });
        }
    } catch (e) {}

    // 4. languages —— 在 Navigator.prototype 上覆盖
    try {
        Object.defineProperty(Navigator.prototype, "languages", { get: function () { return ["en-US", "en"]; }, configurable: true, enumerable: true });
    } catch (e) {}

    // 5. platform + userAgent + appVersion —— 全部在 Navigator.prototype 上覆盖
    try {
        var ua = navigator.userAgent || "";
        var p = "Linux x86_64";
        var fakeUa = ua;
        if (/Windows/.test(ua)) { p = "Win32"; }
        else if (/Macintosh/.test(ua)) { p = "MacIntel"; }
        else if (/Linux/.test(ua)) { p = "Win32"; fakeUa = ua.replace("X11; Linux x86_64", "Windows NT 10.0; Win64; x64"); }
        Object.defineProperty(Navigator.prototype, "platform", { get: function () { return p; }, configurable: true, enumerable: true });
        if (fakeUa !== ua) {
            Object.defineProperty(Navigator.prototype, "userAgent", { get: function () { return fakeUa; }, configurable: true, enumerable: true });
        }
        var effectiveUa = fakeUa !== ua ? fakeUa : ua;
        Object.defineProperty(Navigator.prototype, "appVersion", { get: function () { return effectiveUa.replace("Mozilla/", ""); }, configurable: true, enumerable: true });
    } catch (e) {}

    // 6. maxTouchPoints —— 桌面为 0
    try {
        Object.defineProperty(Navigator.prototype, "maxTouchPoints", { get: function () { return 0; }, configurable: true, enumerable: true });
    } catch (e) {}

    // 7. navigator.connection —— 容器中可能缺失
    try {
        if (!navigator.connection) {
            Object.defineProperty(Navigator.prototype, "connection", {
                get: function () { return { effectiveType: "4g", rtt: 50, downlink: 10, saveData: false }; },
                configurable: true, enumerable: true,
            });
        }
    } catch (e) {}

    // 8. navigator.userAgentData —— Docker Chrome 中 platform 为 "Linux"，需覆盖为 "Windows"
    try {
        if (navigator.userAgentData) {
            var ua2 = navigator.userAgent || "";
            var cm = ua2.match(/Chrome\/(\d+)/);
            var cv = cm ? cm[1] : "150";
            var isWin = /Windows/.test(ua2);
            var fakeUAD = {
                brands: [
                    { brand: "Google Chrome", version: cv },
                    { brand: "Chromium", version: cv },
                    { brand: "Not_A Brand", version: "24" },
                ],
                mobile: false,
                platform: isWin ? "Windows" : "macOS",
                getHighEntropyValues: function (hints) {
                    return Promise.resolve({
                        brands: [
                            { brand: "Google Chrome", version: cv },
                            { brand: "Chromium", version: cv },
                            { brand: "Not_A Brand", version: "24" },
                        ],
                        mobile: false,
                        platform: isWin ? "Windows" : "macOS",
                        platformVersion: isWin ? "10.0.0" : "13.6.0",
                        architecture: "x86", bitness: "64", model: "",
                        uaFullVersion: cv + ".0.0.0",
                        fullVersionList: [
                            { brand: "Google Chrome", version: cv + ".0.0.0" },
                            { brand: "Chromium", version: cv + ".0.0.0" },
                            { brand: "Not_A Brand", version: "24.0.0.0" },
                        ],
                    });
                },
                toJSON: function () {
                    return {
                        brands: [
                            { brand: "Google Chrome", version: cv },
                            { brand: "Chromium", version: cv },
                            { brand: "Not_A Brand", version: "24" },
                        ],
                        mobile: false,
                        platform: isWin ? "Windows" : "macOS",
                    };
                },
            };
            Object.defineProperty(Navigator.prototype, "userAgentData", { get: function () { return fakeUAD; }, configurable: true, enumerable: true });
        }
    } catch (e) {}

    // 9. WebGL vendor/renderer/extensions —— 始终 hook，调用时判断
    try {
        var FAKE_WGL_VENDOR = "Google Inc. (Intel)";
        var FAKE_WGL_RENDERER = "ANGLE (Intel, Mesa Intel(R) UHD Graphics 630 (CFL GT2), OpenGL 4.6)";
        var SW_RE = /swiftshader|llvmpipe|softpipe|software[\s_-]*rasterizer|mesa[\s_-]*swrast/i;
        var FAKE_WGL1_EXTS = [
            "ANGLE_instanced_arrays","EXT_blend_minmax","EXT_color_buffer_half_float",
            "EXT_disjoint_timer_query","EXT_float_blend","EXT_frag_depth",
            "EXT_shader_texture_lod","EXT_texture_compression_bptc",
            "EXT_texture_compression_rgtc","EXT_texture_filter_anisotropic",
            "EXT_sRGB","OES_element_index_uint","OES_fbo_render_mipmap",
            "OES_standard_derivatives","OES_texture_float","OES_texture_float_linear",
            "OES_texture_half_float","OES_texture_half_float_linear","OES_vertex_array_object",
            "WEBGL_color_buffer_float","WEBGL_compressed_texture_s3tc",
            "WEBGL_compressed_texture_s3tc_srgb","WEBGL_debug_renderer_info",
            "WEBGL_debug_shaders","WEBGL_depth_texture","WEBGL_draw_buffers",
            "WEBGL_lose_context","WEBGL_multi_draw"
        ];
        var FAKE_WGL2_EXTS = [
            "EXT_color_buffer_float","EXT_color_buffer_half_float","EXT_disjoint_timer_query_webgl2",
            "EXT_float_blend","EXT_texture_compression_bptc","EXT_texture_compression_rgtc",
            "EXT_texture_filter_anisotropic","EXT_texture_norm16","KHR_parallel_shader_compile",
            "OES_draw_buffers_indexed","OES_texture_float_linear","OVR_multiview2",
            "WEBGL_compressed_texture_s3tc","WEBGL_compressed_texture_s3tc_srgb",
            "WEBGL_debug_renderer_info","WEBGL_debug_shaders","WEBGL_lose_context",
            "WEBGL_multi_draw","WEBGL_provoking_vertex"
        ];

        var hookWebGL = function (proto, fakeExts) {
            if (!proto || !proto.getParameter) return;
            var origGetParam = proto.getParameter;
            var origGetExts = proto.getSupportedExtensions;
            var isSW = function (gl) { try { return SW_RE.test(String(origGetParam.call(gl, 37446))); } catch (e) { return false; } };

            proto.getParameter = function (param) {
                var result = origGetParam.call(this, param);
                if (param === 37446 && SW_RE.test(String(result))) return FAKE_WGL_RENDERER;
                if (param === 37445 && isSW(this)) return FAKE_WGL_VENDOR;
                return result;
            };
            if (origGetExts) {
                proto.getSupportedExtensions = function () {
                    if (isSW(this)) return fakeExts;
                    return origGetExts.call(this);
                };
            }
        };
        try { hookWebGL(WebGLRenderingContext.prototype, FAKE_WGL1_EXTS); } catch (e) {}
        try { hookWebGL(WebGL2RenderingContext.prototype, FAKE_WGL2_EXTS); } catch (e) {}
    } catch (e) {}

    // 10. Canvas 指纹噪声
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

    // 11. AudioContext 指纹噪声
    try {
        var origGetChannelData = AudioBuffer.prototype.getChannelData;
        AudioBuffer.prototype.getChannelData = function (channel) {
            var data = origGetChannelData.call(this, channel);
            if (data && data.length > 0) {
                var off = ((this.length || 0) * 3 + 1) % 7 / 100000;
                data[0] = data[0] + off;
            }
            return data;
        };
    } catch (e) {}

    // 12. WebRTC 屏蔽 + enumerateDevices —— 在原型上覆盖
    try {
        if (window.RTCPeerConnection || window.webkitRTCPeerConnection) {
            var _RTC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
            var _origSetConfig = _RTC.prototype.setConfiguration;
            if (_origSetConfig) {
                _RTC.prototype.setConfiguration = function (config) {
                    if (config && config.iceTransportPolicy === undefined) {
                        config.iceTransportPolicy = "relay";
                    }
                    return _origSetConfig.call(this, config);
                };
            }
        }
        if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
            var _origEnum = MediaDevices.prototype.enumerateDevices;
            MediaDevices.prototype.enumerateDevices = function () {
                return _origEnum.call(this).then(function (d) { return d.filter(function (x) { return x.kind !== "videoinput"; }); });
            };
        }
    } catch (e) {}

    // 13. 资料页若出现可见 Turnstile iframe，尝试轻点（跨域失败则忽略）
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
