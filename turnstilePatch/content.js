// Turnstile Patch - 隐藏自动化标识，加速 Turnstile 验证
// 在 document_start 阶段执行，确保在页面脚本之前生效

(function () {
    "use strict";

    injectPageHook();

    // 1. 隐藏 navigator.webdriver 标识
    // Chrome 自动化模式下 navigator.webdriver = true，Turnstile 会检测此属性
    try {
        Object.defineProperty(navigator, "webdriver", {
            get: function () {
                return false;
            },
            configurable: true,
        });
    } catch (e) {}

    // 2. 移除 Chrome 自动化相关的 Runtime 属性
    try {
        if (window.chrome && window.chrome.runtime) {
            delete window.chrome.runtime.onConnect;
            delete window.chrome.runtime.onMessage;
        }
    } catch (e) {}

    // 3. 覆盖 permissions.query，隐藏 notifications 权限异常
    try {
        var origQuery = navigator.permissions.query.bind(navigator.permissions);
        navigator.permissions.query = function (params) {
            if (params.name === "notifications") {
                return Promise.resolve({ state: Notification.permission });
            }
            return origQuery(params);
        };
    } catch (e) {}

    // 4. 修补 plugin 数量，模拟正常浏览器
    try {
        Object.defineProperty(navigator, "plugins", {
            get: function () {
                return [1, 2, 3, 4, 5];
            },
            configurable: true,
        });
    } catch (e) {}

    // 5. 修补 languages 属性
    try {
        Object.defineProperty(navigator, "languages", {
            get: function () {
                return ["en-US", "en"];
            },
            configurable: true,
        });
    } catch (e) {}

    // 6. 页面加载完成后，自动监控并点击 Turnstile 复选框
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", autoClickTurnstile);
    } else {
        autoClickTurnstile();
    }

    function autoClickTurnstile() {
        // 定时检查 Turnstile iframe 是否出现
        var checkCount = 0;
        var maxChecks = 100; // 最多检查 100 次（约 50 秒）
        var timer = setInterval(function () {
            checkCount++;
            if (checkCount > maxChecks) {
                clearInterval(timer);
                return;
            }
            try {
                // 查找 Turnstile iframe
                var iframes = document.querySelectorAll(
                    'iframe[src*="challenges.cloudflare.com"], iframe[src*="turnstile"]'
                );
                for (var i = 0; i < iframes.length; i++) {
                    var iframe = iframes[i];
                    try {
                        // 尝试访问 iframe 内部的 checkbox
                        var body = iframe.contentDocument || iframe.contentWindow.document;
                        var checkbox = body.querySelector(
                            'input[type="checkbox"], .mark, #cf-chl-widget-nomu1_resp'
                        );
                        if (checkbox && !checkbox.checked) {
                            checkbox.click();
                        }
                    } catch (e) {
                        // 跨域限制，尝试通过 postMessage 触发
                        try {
                            iframe.contentWindow.postMessage(
                                { type: "turnstile-auto-click" },
                                "*"
                            );
                        } catch (e2) {}
                    }
                }

                // 也尝试直接操作 Turnstile API
                if (
                    window.turnstile &&
                    typeof window.turnstile.getResponse === "function"
                ) {
                    var resp = window.turnstile.getResponse();
                    if (resp && resp.length > 0) {
                        clearInterval(timer); // 已获得 token，停止检查
                    }
                }
            } catch (e) {}
        }, 500);
    }

    function injectPageHook() {
        var code = "(" + installTurnstileHook.toString() + ")();";
        function appendScript() {
            try {
                var script = document.createElement("script");
                if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.getURL) {
                    script.src = chrome.runtime.getURL("pageHook.js");
                } else {
                    script.textContent = code;
                }
                (document.documentElement || document.head || document.body).appendChild(script);
                script.onload = function () {
                    script.remove();
                };
            } catch (e) {}
        }
        if (document.documentElement || document.head || document.body) {
            appendScript();
        } else {
            document.addEventListener("readystatechange", appendScript, { once: true });
        }
    }

    function installTurnstileHook() {
        if (window.__grokTurnstileHookInstalled) return;
        window.__grokTurnstileHookInstalled = true;
        window.__grokTurnstile = window.__grokTurnstile || {
            widgets: [],
            lastToken: "",
            callbackCount: 0,
            renderCount: 0,
            executeCount: 0,
            errors: [],
        };

        function recordError(step, error) {
            try {
                window.__grokTurnstile.errors.push({
                    step: step,
                    message: String((error && error.message) || error || "").slice(0, 180),
                });
            } catch (e) {}
        }

        function patch(api) {
            if (!api || api.__grokPatched) return api;
            try {
                var originalRender = typeof api.render === "function" ? api.render.bind(api) : null;
                var originalExecute = typeof api.execute === "function" ? api.execute.bind(api) : null;
                var originalReset = typeof api.reset === "function" ? api.reset.bind(api) : null;
                if (originalRender) {
                    api.render = function (container, options) {
                        var opts = options || {};
                        var originalCallback = opts.callback;
                        var wrappedOptions = Object.assign({}, opts);
                        wrappedOptions.callback = function (token) {
                            try {
                                window.__grokTurnstile.lastToken = String(token || "");
                                window.__grokTurnstile.callbackCount += 1;
                                var input = document.querySelector('input[name="cf-turnstile-response"]');
                                if (input && token) {
                                    input.value = token;
                                    input.dispatchEvent(new Event("input", { bubbles: true }));
                                    input.dispatchEvent(new Event("change", { bubbles: true }));
                                }
                            } catch (e) {
                                recordError("callback", e);
                            }
                            if (typeof originalCallback === "function") {
                                return originalCallback.apply(this, arguments);
                            }
                        };
                        var id = originalRender(container, wrappedOptions);
                        try {
                            window.__grokTurnstile.renderCount += 1;
                            window.__grokTurnstile.widgets.push({
                                id: id,
                                sitekey: String(wrappedOptions.sitekey || ""),
                                action: String(wrappedOptions.action || ""),
                                cData: String(wrappedOptions.cData || ""),
                                size: String(wrappedOptions.size || ""),
                                theme: String(wrappedOptions.theme || ""),
                            });
                        } catch (e) {
                            recordError("render-record", e);
                        }
                        return id;
                    };
                }
                if (originalExecute) {
                    api.execute = function () {
                        try {
                            window.__grokTurnstile.executeCount += 1;
                            window.__grokTurnstile.lastExecuteArgs = Array.from(arguments).map(function (item) {
                                if (typeof item === "string") return item;
                                if (item && item.nodeType === 1) return item.tagName + "#" + (item.id || "");
                                if (item && typeof item === "object") return Object.keys(item).join(",");
                                return String(item);
                            });
                        } catch (e) {}
                        return originalExecute.apply(api, arguments);
                    };
                }
                if (originalReset) {
                    api.reset = function () {
                        return originalReset.apply(api, arguments);
                    };
                }
                Object.defineProperty(api, "__grokPatched", { value: true, configurable: true });
            } catch (e) {
                recordError("patch", e);
            }
            return api;
        }

        var current = window.turnstile;
        try {
            Object.defineProperty(window, "turnstile", {
                configurable: true,
                get: function () {
                    return current;
                },
                set: function (value) {
                    current = patch(value);
                },
            });
            if (current) current = patch(current);
        } catch (e) {
            recordError("defineProperty", e);
        }

        var attempts = 0;
        var timer = setInterval(function () {
            attempts += 1;
            if (window.turnstile) patch(window.turnstile);
            if ((window.turnstile && window.turnstile.__grokPatched) || attempts > 120) {
                clearInterval(timer);
            }
        }, 250);
    }
})();
