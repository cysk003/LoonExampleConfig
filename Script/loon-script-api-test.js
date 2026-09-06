/*
 * Loon 脚本数据、DNS 与 AES API 黑盒验收脚本。
 * 适用版本：Loon Build 988 或更高版本。
 *
 * 测试目标：
 * 1. 使用小、中、大三档真实混合数据验证 gzip 压缩和解压缩。
 * 2. 先用公开的 NIST 向量验证 AES 算法结果，再用三档数据验证完整加解密往返。
 * 3. 从协议、服务器、自动识别、重复调用、并发调用和非法参数等角度验证 DNS API。
 *
 * 本脚本故意不在首个失败处退出。每个用例都会独立记录结果，便于一次运行定位
 * 某个数据规模、AES 模式或 DNS 传输协议的问题。DNS API 固定查询 A 和 AAAA，
 * 因此所有 DNS options 都不会传入 type 字段。
 */

(function () {
    "use strict";

    // 正向协议用例显式使用最长 5 秒的 DNS 超时。测试再预留网络和队列调度时间，
    // 10 秒仍未收到 callback 时记录失败并继续，避免单个用例阻塞整份报告。
    var DNS_CASE_WATCHDOG_MS = 10000;
    var startedAt = Date.now();
    var finished = false;
    var failures = [];
    var report = {
        ok:false,
        startedAt:new Date(startedAt).toISOString(),
        gzip:[],
        aes:{
            vectors:[],
            workloads:[],
            negative:[]
        },
        dns:{
            sequential:[],
            negative:[],
            concurrent:[]
        },
        failures:failures
    };

    /**
     * 输出带统一前缀的日志，方便从包含其他脚本输出的日志中筛选本次测试。
     *
     * @param {string} message 要输出的日志内容。
     */
    function log(message) {
        console.log("[LNScriptAPI] " + message);
    }

    /**
     * 在条件不成立时抛出错误，让当前用例进入失败记录。
     *
     * @param {boolean} condition 需要成立的条件。
     * @param {string} message 条件不成立时使用的错误信息。
     */
    function assert(condition, message) {
        if (!condition) {
            throw new Error(message);
        }
    }

    /**
     * 把任意异常转换为稳定的字符串，避免不同 JavaScript 运行时序列化 Error 时丢失信息。
     *
     * @param {*} error 捕获到的异常值。
     * @return {string} 适合写入 JSON 报告的错误描述。
     */
    function errorDescription(error) {
        if (error && error.message) {
            return error.code ? String(error.code) + ": " + error.message : error.message;
        }
        return String(error);
    }

    /**
     * 记录失败，但不中断后续用例。
     *
     * @param {string} category 用例分类。
     * @param {string} name 用例名称。
     * @param {*} error 捕获到的错误值。
     */
    function recordFailure(category, name, error) {
        var description = errorDescription(error);
        failures.push({category:category, name:name, error:description});
        log("FAIL " + category + "/" + name + " - " + description);
    }

    /**
     * 执行同步用例并记录耗时。work 返回的对象会合并到该用例的报告中。
     *
     * @param {Array} target 用例结果数组。
     * @param {string} category 用例分类。
     * @param {string} name 用例名称。
     * @param {Function} work 实际测试逻辑。
     */
    function runSyncCase(target, category, name, work) {
        var caseStartedAt = Date.now();
        log("START " + category + "/" + name);
        try {
            var detail = work() || {};
            detail.name = name;
            detail.ok = true;
            detail.elapsedMs = Date.now() - caseStartedAt;
            target.push(detail);
            log("PASS " + category + "/" + name + " (" + detail.elapsedMs + " ms)");
        } catch (error) {
            var failedDetail = {
                name:name,
                ok:false,
                elapsedMs:Date.now() - caseStartedAt,
                error:errorDescription(error)
            };
            target.push(failedDetail);
            recordFailure(category, name, error);
        }
    }

    /**
     * 把十六进制字符串转换为 Uint8Array。该函数只用于长度很小的标准测试向量。
     *
     * @param {string} value 不含 0x 前缀的偶数字节十六进制字符串。
     * @return {Uint8Array} 转换后的字节数组。
     */
    function bytesFromHex(value) {
        assert(typeof value === "string" && value.length % 2 === 0, "十六进制字符串长度必须为偶数");
        var result = new Uint8Array(value.length / 2);
        for (var index = 0; index < result.length; index++) {
            var byteValue = parseInt(value.substr(index * 2, 2), 16);
            assert(!isNaN(byteValue), "十六进制字符串包含非法字符");
            result[index] = byteValue;
        }
        return result;
    }

    /**
     * 把小字节数组转换为十六进制字符串，用于对比 NIST 标准向量。
     * 大数据用例采用逐字节比较，不执行这种会显著增加内存占用的转换。
     *
     * @param {Uint8Array} bytes 输入字节数组。
     * @return {string} 小写十六进制字符串。
     */
    function hexFromBytes(bytes) {
        var result = "";
        for (var index = 0; index < bytes.length; index++) {
            var item = bytes[index].toString(16);
            result += item.length === 1 ? "0" + item : item;
        }
        return result;
    }

    /**
     * 在不依赖 TextEncoder 的情况下把字符串转换为 UTF-8。
     * 这样脚本可以同时在 WebView 和 tvOS JavaScriptCore 环境中运行。
     *
     * @param {string} value 输入字符串。
     * @return {Uint8Array} UTF-8 字节数组。
     */
    function utf8Bytes(value) {
        var bytes = [];
        for (var index = 0; index < value.length; index++) {
            var code = value.charCodeAt(index);
            if (code < 0x80) {
                bytes.push(code);
            } else if (code < 0x800) {
                bytes.push(0xc0 | (code >> 6));
                bytes.push(0x80 | (code & 0x3f));
            } else if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
                var low = value.charCodeAt(++index);
                var fullCode = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                bytes.push(0xf0 | (fullCode >> 18));
                bytes.push(0x80 | ((fullCode >> 12) & 0x3f));
                bytes.push(0x80 | ((fullCode >> 6) & 0x3f));
                bytes.push(0x80 | (fullCode & 0x3f));
            } else {
                bytes.push(0xe0 | (code >> 12));
                bytes.push(0x80 | ((code >> 6) & 0x3f));
                bytes.push(0x80 | (code & 0x3f));
            }
        }
        return new Uint8Array(bytes);
    }

    /**
     * 生成接近实际脚本内容的确定性测试数据。
     * 主体由 JSON、HTTP Header、中文日志和 emoji 组成，并定期插入伪随机二进制字节。
     * 同一个 seed 每次都生成相同数据，既能验证压缩效果，也便于复现加解密错误。
     *
     * @param {number} length 需要生成的总字节数。
     * @param {number} seed 伪随机序列种子。
     * @param {string} label 写入数据的规模标签。
     * @return {Uint8Array} 指定长度的混合数据。
     */
    function makePayload(length, seed, label) {
        var template = utf8Bytes(
            "{\"service\":\"Loon\",\"case\":\"" + label +
            "\",\"message\":\"脚本数据压缩与加密往返测试 🚀\",\"status\":200}\n" +
            "Content-Type: application/json; charset=utf-8\r\n" +
            "Cache-Control: no-cache\r\n" +
            "X-Loon-Test: deterministic-payload\r\n\r\n"
        );
        var result = new Uint8Array(length);
        var state = seed >>> 0;
        for (var index = 0; index < length; index++) {
            result[index] = template[index % template.length];
            // 每 19 字节插入一个确定性二进制值，模拟协议数据、图片片段等非纯文本内容。
            if (index % 19 === 0) {
                state ^= state << 13;
                state ^= state >>> 17;
                state ^= state << 5;
                result[index] = state & 0xff;
            }
        }
        return result;
    }

    /**
     * 逐字节比较两个数组，遇到首个差异时给出准确偏移。
     *
     * @param {Uint8Array} actual 实际数据。
     * @param {Uint8Array} expected 预期数据。
     * @param {string} message 错误信息前缀。
     */
    function assertBytesEqual(actual, expected, message) {
        assert(Object.prototype.toString.call(actual) === "[object Uint8Array]", message + "：结果不是 Uint8Array");
        assert(actual.length === expected.length, message + "：长度 " + actual.length + " != " + expected.length);
        for (var index = 0; index < expected.length; index++) {
            if (actual[index] !== expected[index]) {
                throw new Error(message + "：第 " + index + " 字节不一致，实际 " + actual[index] + "，预期 " + expected[index]);
            }
        }
    }

    /**
     * 计算轻量校验值，仅用于报告中确认每档数据确实不同。
     * 数据正确性仍由完整逐字节比较保障，校验值本身不承担安全用途。
     *
     * @param {Uint8Array} bytes 输入数据。
     * @return {string} 八位十六进制校验值。
     */
    function checksum(bytes) {
        var first = 1;
        var second = 0;
        for (var index = 0; index < bytes.length; index++) {
            first = (first + bytes[index]) % 65521;
            second = (second + first) % 65521;
        }
        var value = ((second << 16) | first) >>> 0;
        return ("00000000" + value.toString(16)).slice(-8);
    }

    /**
     * 验证脚本运行时是否完整注入了本测试需要的公开 API。
     */
    function validateAPIs() {
        assert(typeof $utils === "object" && typeof $utils.gzip === "function" && typeof $utils.ungzip === "function", "$utils.gzip/ungzip 不可用");
        assert(typeof $crypto === "object" && $crypto.aes && typeof $crypto.aes.encrypt === "function" && typeof $crypto.aes.decrypt === "function", "$crypto.aes.encrypt/decrypt 不可用");
        assert(typeof $dns === "object" && typeof $dns.query === "function", "$dns.query 不可用");
    }

    /**
     * 对小、中、大三档数据执行真实 gzip 压缩和解压缩。
     * 每档数据都检查 gzip Header、压缩率和完整字节往返，而不只检查返回值是否存在。
     */
    function runGzipTests() {
        var cases = [
            {name:"small-8KB", length:8 * 1024 + 37, seed:0x13572468},
            {name:"medium-256KB", length:256 * 1024 + 113, seed:0x24681357},
            {name:"large-2MB", length:2 * 1024 * 1024 + 509, seed:0x10293847}
        ];
        for (var index = 0; index < cases.length; index++) {
            (function (testCase) {
                runSyncCase(report.gzip, "gzip", testCase.name, function () {
                    var input = makePayload(testCase.length, testCase.seed, "gzip-" + testCase.name);
                    var compressStartedAt = Date.now();
                    var compressed = $utils.gzip(input);
                    var compressMs = Date.now() - compressStartedAt;
                    assert(Object.prototype.toString.call(compressed) === "[object Uint8Array]", "gzip 返回值不是 Uint8Array");
                    assert(compressed.length > 10, "gzip 结果长度异常");
                    assert(compressed[0] === 0x1f && compressed[1] === 0x8b, "gzip Header 不是 1f8b");
                    assert(compressed.length < input.length, "可压缩的混合数据没有得到更小的 gzip 结果");

                    var decompressStartedAt = Date.now();
                    var restored = $utils.ungzip(compressed);
                    var decompressMs = Date.now() - decompressStartedAt;
                    assertBytesEqual(restored, input, "gzip 解压后数据不一致");
                    return {
                        inputBytes:input.length,
                        compressedBytes:compressed.length,
                        compressionRatio:Number((compressed.length / input.length).toFixed(4)),
                        checksum:checksum(input),
                        compressMs:compressMs,
                        decompressMs:decompressMs
                    };
                });
            })(cases[index]);
        }
    }

    /**
     * 使用公开标准向量检查 AES 输出是否严格正确。
     * 往返测试只能证明 encrypt/decrypt 相互兼容，标准向量还能发现二者以同一种错误方式实现的情况。
     */
    function runAESVectorTests() {
        var commonKey = bytesFromHex("2b7e151628aed2a6abf7158809cf4f3c");
        var commonPlaintext = bytesFromHex("6bc1bee22e409f96e93d7e117393172a");
        var vectors = [
            {
                name:"NIST-AES-128-ECB",
                data:commonPlaintext,
                expected:"3ad77bb40d7a3660a89ecaf32466ef97",
                options:{mode:"ecb", key:commonKey, padding:"none"}
            },
            {
                name:"NIST-AES-128-CBC",
                data:commonPlaintext,
                expected:"7649abac8119b246cee98e9b12e9197d",
                options:{mode:"cbc", key:commonKey, iv:bytesFromHex("000102030405060708090a0b0c0d0e0f"), padding:"none"}
            },
            {
                name:"NIST-AES-128-CTR",
                data:commonPlaintext,
                expected:"874d6191b620e3261bef6864990db6ce",
                options:{mode:"ctr", key:commonKey, iv:bytesFromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")}
            },
            {
                name:"NIST-AES-128-GCM",
                data:bytesFromHex("00000000000000000000000000000000"),
                expected:"0388dace60b6a392f328c2b971b2fe78",
                expectedTag:"ab6e47d42cec13bdf53a67b21257bddf",
                options:{mode:"gcm", key:bytesFromHex("00000000000000000000000000000000"), iv:bytesFromHex("000000000000000000000000")}
            }
        ];

        for (var index = 0; index < vectors.length; index++) {
            (function (vector) {
                runSyncCase(report.aes.vectors, "aes-vector", vector.name, function () {
                    var encrypted = $crypto.aes.encrypt(vector.data, vector.options);
                    assert(encrypted && Object.prototype.toString.call(encrypted.ciphertext) === "[object Uint8Array]", "AES encrypt 返回结构异常");
                    assert(hexFromBytes(encrypted.ciphertext) === vector.expected, "密文与 NIST 向量不一致");
                    if (vector.expectedTag) {
                        assert(encrypted.tag && hexFromBytes(encrypted.tag) === vector.expectedTag, "GCM Tag 与 NIST 向量不一致");
                    }

                    // 解密使用标准给定的密文，而不是刚刚生成的密文，保证解密路径也独立匹配标准。
                    var decryptOptions = {};
                    for (var key in vector.options) {
                        if (Object.prototype.hasOwnProperty.call(vector.options, key)) {
                            decryptOptions[key] = vector.options[key];
                        }
                    }
                    if (vector.expectedTag) {
                        decryptOptions.tag = bytesFromHex(vector.expectedTag);
                    }
                    var decrypted = $crypto.aes.decrypt(bytesFromHex(vector.expected), decryptOptions);
                    assertBytesEqual(decrypted, vector.data, "标准密文解密结果不一致");
                    return {
                        mode:vector.options.mode,
                        keyBits:vector.options.key.length * 8,
                        plaintextBytes:vector.data.length,
                        ciphertextHex:vector.expected,
                        tagHex:vector.expectedTag || null
                    };
                });
            })(vectors[index]);
        }
    }

    /**
     * 使用四种 AES 模式和三档数据进行 12 组完整加解密。
     * 三档分别使用 128、192、256 位 Key；ECB/CBC 使用非块对齐数据来实际覆盖 PKCS#7 Padding。
     */
    function runAESWorkloadTests() {
        var sizes = [
            {name:"small-4KB", length:4 * 1024 + 7, seed:0x11223344, key:bytesFromHex("603deb1015ca71be2b73aef0857d7781")},
            {name:"medium-128KB", length:128 * 1024 + 29, seed:0x55667788, key:bytesFromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")},
            {name:"large-1MB", length:1024 * 1024 + 113, seed:0x99aabbcc, key:bytesFromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")}
        ];
        var modes = ["ecb", "cbc", "ctr", "gcm"];
        var blockIV = bytesFromHex("000102030405060708090a0b0c0d0e0f");
        var gcmIV = bytesFromHex("cafebabefacedbaddecaf888");

        for (var sizeIndex = 0; sizeIndex < sizes.length; sizeIndex++) {
            for (var modeIndex = 0; modeIndex < modes.length; modeIndex++) {
                (function (sizeCase, mode) {
                    var caseName = mode.toUpperCase() + "-" + sizeCase.name;
                    runSyncCase(report.aes.workloads, "aes-workload", caseName, function () {
                        var input = makePayload(sizeCase.length, sizeCase.seed + mode.length, "aes-" + caseName);
                        var options = {mode:mode, key:sizeCase.key};
                        if (mode === "ecb") {
                            options.padding = "pkcs7";
                        } else if (mode === "cbc") {
                            options.iv = blockIV;
                            options.padding = "pkcs7";
                        } else if (mode === "ctr") {
                            options.iv = blockIV;
                        } else {
                            options.iv = gcmIV;
                            options.aad = utf8Bytes("Loon AES workload:" + caseName);
                        }

                        var encryptStartedAt = Date.now();
                        var encrypted = $crypto.aes.encrypt(input, options);
                        var encryptMs = Date.now() - encryptStartedAt;
                        assert(encrypted && Object.prototype.toString.call(encrypted.ciphertext) === "[object Uint8Array]", "AES encrypt 返回结构异常");
                        assert(encrypted.ciphertext.length > 0, "AES 密文为空");
                        assert(encrypted.ciphertext[0] !== input[0] || encrypted.ciphertext[1] !== input[1], "AES 密文开头与明文相同，疑似未加密");

                        if (mode === "ecb" || mode === "cbc") {
                            assert(encrypted.ciphertext.length % 16 === 0, "块模式密文没有按 16 字节对齐");
                            assert(encrypted.ciphertext.length > input.length, "PKCS#7 Padding 后密文长度没有增加");
                            assert(!encrypted.tag, "非 GCM 模式不应返回 Tag");
                        } else {
                            assert(encrypted.ciphertext.length === input.length, mode.toUpperCase() + " 密文长度应与明文相同");
                        }
                        if (mode === "gcm") {
                            assert(Object.prototype.toString.call(encrypted.tag) === "[object Uint8Array]" && encrypted.tag.length === 16, "GCM 必须返回 16 字节 Tag");
                        }

                        var decryptOptions = {};
                        for (var key in options) {
                            if (Object.prototype.hasOwnProperty.call(options, key)) {
                                decryptOptions[key] = options[key];
                            }
                        }
                        if (mode === "gcm") {
                            decryptOptions.tag = encrypted.tag;
                        }
                        var decryptStartedAt = Date.now();
                        var decrypted = $crypto.aes.decrypt(encrypted.ciphertext, decryptOptions);
                        var decryptMs = Date.now() - decryptStartedAt;
                        assertBytesEqual(decrypted, input, "AES 解密后数据不一致");
                        return {
                            mode:mode,
                            keyBits:sizeCase.key.length * 8,
                            plaintextBytes:input.length,
                            ciphertextBytes:encrypted.ciphertext.length,
                            tagBytes:encrypted.tag ? encrypted.tag.length : 0,
                            checksum:checksum(input),
                            encryptMs:encryptMs,
                            decryptMs:decryptMs
                        };
                    });
                })(sizes[sizeIndex], modes[modeIndex]);
            }
        }
    }

    /**
     * 验证 AES 对非法 Key 和被篡改的 GCM Tag 必须明确失败。
     * 后者用于确认 GCM 解密真实执行了认证，而不是只做可逆的数据变换。
     */
    function runAESNegativeTests() {
        runSyncCase(report.aes.negative, "aes-negative", "invalid-15-byte-key", function () {
            var didThrow = false;
            try {
                $crypto.aes.encrypt(utf8Bytes("invalid key"), {mode:"ecb", key:new Uint8Array(15), padding:"pkcs7"});
            } catch (error) {
                didThrow = true;
            }
            assert(didThrow, "15 字节非法 Key 没有抛出异常");
            return {expected:"throw"};
        });

        runSyncCase(report.aes.negative, "aes-negative", "gcm-tampered-tag", function () {
            var input = makePayload(4096 + 19, 0xabcdef01, "gcm-tampered-tag");
            var options = {
                mode:"gcm",
                key:bytesFromHex("000102030405060708090a0b0c0d0e0f"),
                iv:bytesFromHex("101112131415161718191a1b"),
                aad:utf8Bytes("Loon authenticated data")
            };
            var encrypted = $crypto.aes.encrypt(input, options);
            var tamperedTag = new Uint8Array(encrypted.tag);
            tamperedTag[0] ^= 0x80;
            var didThrow = false;
            try {
                $crypto.aes.decrypt(encrypted.ciphertext, {
                    mode:options.mode,
                    key:options.key,
                    iv:options.iv,
                    aad:options.aad,
                    tag:tamperedTag
                });
            } catch (error) {
                didThrow = true;
            }
            assert(didThrow, "被篡改的 GCM Tag 没有导致解密失败");
            return {plaintextBytes:input.length, tagBytes:tamperedTag.length, expected:"throw"};
        });
    }

    /**
     * 粗粒度验证 IPv4 文本格式。DNS 的语义正确性由底层解析器负责，脚本侧重点是 API 结构。
     *
     * @param {string} value 待检查的地址。
     * @return {boolean} 是否为合法的点分十进制 IPv4。
     */
    function isIPv4(value) {
        if (typeof value !== "string") {
            return false;
        }
        var parts = value.split(".");
        if (parts.length !== 4) {
            return false;
        }
        for (var index = 0; index < parts.length; index++) {
            if (!/^\d{1,3}$/.test(parts[index])) {
                return false;
            }
            var number = Number(parts[index]);
            if (number < 0 || number > 255) {
                return false;
            }
        }
        return true;
    }

    /**
     * 对 DNS answers 做结构和类型检查，并生成紧凑摘要。
     * 每个成功用例必须同时含 A 与 AAAA，CNAME 允许出现在解析链中。
     *
     * @param {Array} answers API 返回的记录数组。
     * @return {Object} 各记录类型数量和少量样本。
     */
    function validateAndSummarizeAnswers(answers) {
        assert(Array.isArray(answers) && answers.length > 0, "DNS answers 为空或不是数组");
        var counts = {A:0, AAAA:0, CNAME:0};
        var sample = [];
        for (var index = 0; index < answers.length; index++) {
            var answer = answers[index];
            assert(answer && typeof answer === "object", "DNS answer 不是对象");
            assert(answer.type === "A" || answer.type === "AAAA" || answer.type === "CNAME", "未知 DNS answer type: " + answer.type);
            assert(typeof answer.name === "string" && answer.name.length > 0, "DNS answer name 无效");
            assert(typeof answer.value === "string" && answer.value.length > 0, "DNS answer value 无效");
            assert(typeof answer.ttl === "number" && isFinite(answer.ttl) && answer.ttl >= 0, "DNS answer ttl 无效");
            if (answer.type === "A") {
                assert(isIPv4(answer.value), "A 记录不是合法 IPv4: " + answer.value);
            } else if (answer.type === "AAAA") {
                assert(answer.value.indexOf(":") >= 0, "AAAA 记录不是 IPv6: " + answer.value);
            }
            counts[answer.type] += 1;
            if (sample.length < 4) {
                sample.push(answer.type + ":" + answer.value);
            }
        }
        assert(counts.A > 0, "默认 A+AAAA 查询没有返回 A 记录");
        assert(counts.AAAA > 0, "默认 A+AAAA 查询没有返回 AAAA 记录");
        return {counts:counts, sample:sample};
    }

    /**
     * 校验一次成功 DNS 查询的顶层结构以及服务器、协议、缓存语义。
     *
     * @param {Object} testCase 用例定义。
     * @param {Object} result DNS 成功结果。
     * @return {Object} 写入报告的紧凑结果。
     */
    function validateDNSResult(testCase, result) {
        assert(result && typeof result === "object", "DNS result 为空或不是对象");
        assert(result.domain === testCase.options.domain, "DNS result.domain 与请求不一致");
        assert(result.protocol === testCase.expectedProtocol, "DNS protocol 实际为 " + result.protocol + "，预期 " + testCase.expectedProtocol);
        assert(typeof result.server === "string", "DNS server 不是字符串");
        assert(typeof result.fromCache === "boolean", "DNS fromCache 不是 boolean");
        if (testCase.options.server) {
            assert(result.server === testCase.options.server, "DNS server 与显式配置不一致");
            assert(result.fromCache === false, "显式服务器查询不应命中通用 DNS 缓存");
        }
        var answerSummary = validateAndSummarizeAnswers(result.answers);
        return {
            domain:result.domain,
            protocol:result.protocol,
            server:result.server,
            fromCache:result.fromCache,
            counts:answerSummary.counts,
            sample:answerSummary.sample
        };
    }

    /**
     * 执行单个异步 DNS 用例。
     * 首次回调后额外等待 200ms，再确认回调没有重复触发；这可以发现 native 生命周期或完成态错误。
     *
     * @param {Object} testCase 用例定义。
     * @param {Array} target 用例结果数组。
     * @param {string} category 用例分类。
     * @param {Function} completion 用例完成回调。
     */
    function runDNSCase(testCase, target, category, completion) {
        var caseStartedAt = Date.now();
        var callbackCount = 0;
        var firstError;
        var firstResult;
        var caseFinished = false;
        var watchdogTimer;
        log("START " + category + "/" + testCase.name);
        assert(!Object.prototype.hasOwnProperty.call(testCase.options, "type"), "DNS options 不应包含 type");

        function completeAfterDuplicateWindow() {
            setTimeout(function () {
                if (caseFinished) {
                    return;
                }
                caseFinished = true;
                clearTimeout(watchdogTimer);
                var detail = {
                    name:testCase.name,
                    ok:false,
                    elapsedMs:Date.now() - caseStartedAt,
                    callbackCount:callbackCount
                };
                try {
                    assert(callbackCount === 1, "DNS callback 调用了 " + callbackCount + " 次");
                    if (testCase.expectedErrorCode) {
                        assert(firstError && typeof firstError === "object", "非法 DNS 参数没有返回 error");
                        assert(firstError.code === testCase.expectedErrorCode, "DNS error.code 实际为 " + (firstError && firstError.code) + "，预期 " + testCase.expectedErrorCode);
                        assert(firstResult === null || firstResult === undefined, "DNS 失败时不应同时返回 result");
                        detail.errorCode = firstError.code;
                    } else {
                        assert(firstError === null || firstError === undefined, "DNS 查询返回错误: " + errorDescription(firstError));
                        var successDetail = validateDNSResult(testCase, firstResult);
                        for (var key in successDetail) {
                            if (Object.prototype.hasOwnProperty.call(successDetail, key)) {
                                detail[key] = successDetail[key];
                            }
                        }
                    }
                    detail.ok = true;
                    target.push(detail);
                    log("PASS " + category + "/" + testCase.name + " (" + detail.elapsedMs + " ms)");
                } catch (error) {
                    detail.error = errorDescription(error);
                    target.push(detail);
                    recordFailure(category, testCase.name, error);
                }
                completion();
            }, 200);
        }

        watchdogTimer = setTimeout(function () {
            if (caseFinished) {
                return;
            }
            caseFinished = true;
            var error = new Error("DNS callback 超过 " + DNS_CASE_WATCHDOG_MS + "ms 未返回");
            target.push({
                name:testCase.name,
                ok:false,
                elapsedMs:Date.now() - caseStartedAt,
                callbackCount:callbackCount,
                error:errorDescription(error)
            });
            recordFailure(category, testCase.name, error);
            completion();
        }, DNS_CASE_WATCHDOG_MS);

        try {
            $dns.query(testCase.options, function (error, result) {
                if (caseFinished) {
                    log("LATE CALLBACK " + category + "/" + testCase.name);
                    return;
                }
                callbackCount += 1;
                if (callbackCount === 1) {
                    clearTimeout(watchdogTimer);
                    firstError = error;
                    firstResult = result;
                    completeAfterDuplicateWindow();
                }
            });
        } catch (error) {
            if (caseFinished) {
                return;
            }
            caseFinished = true;
            clearTimeout(watchdogTimer);
            target.push({
                name:testCase.name,
                ok:false,
                elapsedMs:Date.now() - caseStartedAt,
                callbackCount:callbackCount,
                error:errorDescription(error)
            });
            recordFailure(category, testCase.name, error);
            completion();
        }
    }

    /**
     * 串行执行 DNS 用例，避免大量外部查询同时发生时互相影响，方便单独观察每种传输协议。
     *
     * @param {Array} cases 用例数组。
     * @param {Array} target 用例结果数组。
     * @param {string} category 用例分类。
     * @param {Function} completion 全部完成后的回调。
     */
    function runDNSCasesSequentially(cases, target, category, completion) {
        var index = 0;
        function next() {
            if (index >= cases.length) {
                completion();
                return;
            }
            runDNSCase(cases[index++], target, category, next);
        }
        next();
    }

    /**
     * 并发执行 UDP、DoH、QUIC 三个查询，用于验证多请求状态和 callback ID 彼此隔离。
     *
     * @param {Array} cases 用例数组。
     * @param {Function} completion 全部完成后的回调。
     */
    function runDNSCasesConcurrently(cases, completion) {
        var remaining = cases.length;
        for (var index = 0; index < cases.length; index++) {
            runDNSCase(cases[index], report.dns.concurrent, "dns-concurrent", function () {
                remaining -= 1;
                if (remaining === 0) {
                    completion();
                }
            });
        }
    }

    /**
     * 定义并执行 DNS 全量矩阵。
     * 正向用例覆盖默认配置、两家 UDP/DoH 服务、DoH3、QUIC、协议自动识别和重复查询；
     * 负向用例验证错误码；最后再并发查询三种不同传输。
     *
     * @param {Function} completion 所有 DNS 用例完成后的回调。
     */
    function runDNSTests(completion) {
        var sequentialCases = [
            {name:"configured-default", options:{domain:"example.com"}, expectedProtocol:"auto"},
            {name:"udp-cloudflare", options:{domain:"example.com", protocol:"udp", server:"1.1.1.1:53", timeout:2000}, expectedProtocol:"udp"},
            {name:"udp-google", options:{domain:"cloudflare.com", protocol:"udp", server:"8.8.8.8:53", timeout:2000}, expectedProtocol:"udp"},
            {name:"udp-cloudflare-repeat", options:{domain:"example.com", protocol:"udp", server:"1.1.1.1:53", timeout:2000}, expectedProtocol:"udp"},
            {name:"auto-infer-udp", options:{domain:"google.com", server:"1.1.1.1:53", timeout:2000}, expectedProtocol:"udp"},
            // 加密 DNS 首次建连受网络环境影响；这里显式放宽到 5 秒，以测试协议结果而不是默认超时。
            {name:"doh-cloudflare", options:{domain:"example.com", protocol:"doh", server:"https://cloudflare-dns.com/dns-query", timeout:5000}, expectedProtocol:"doh"},
            {name:"auto-infer-doh", options:{domain:"cloudflare.com", server:"https://dns.google/dns-query", timeout:5000}, expectedProtocol:"doh"},
            {name:"doh3-cloudflare", options:{domain:"example.com", protocol:"doh3", server:"https://cloudflare-dns.com/dns-query", timeout:5000}, expectedProtocol:"doh3"},
            {name:"quic-adguard", options:{domain:"example.com", protocol:"quic", server:"quic://dns.adguard-dns.com:853", timeout:5000}, expectedProtocol:"quic"},
            {name:"auto-infer-quic", options:{domain:"cloudflare.com", server:"quic://dns.adguard-dns.com:853", timeout:5000}, expectedProtocol:"quic"}
        ];
        var negativeCases = [
            {name:"invalid-domain", options:{domain:"bad domain"}, expectedErrorCode:"INVALID_ARGUMENT"},
            {name:"unsupported-protocol", options:{domain:"example.com", protocol:"tcp", server:"1.1.1.1:53"}, expectedErrorCode:"UNSUPPORTED_PROTOCOL"},
            {name:"udp-missing-server", options:{domain:"example.com", protocol:"udp"}, expectedErrorCode:"INVALID_SERVER"},
            {name:"doh-with-udp-server", options:{domain:"example.com", protocol:"doh", server:"1.1.1.1:53"}, expectedErrorCode:"INVALID_SERVER"},
            {name:"auto-invalid-server", options:{domain:"example.com", server:"not-a-dns-server"}, expectedErrorCode:"INVALID_SERVER"},
            {name:"timeout-string", options:{domain:"example.com", timeout:"500"}, expectedErrorCode:"INVALID_ARGUMENT"},
            {name:"timeout-boolean", options:{domain:"example.com", timeout:true}, expectedErrorCode:"INVALID_ARGUMENT"},
            {name:"timeout-zero", options:{domain:"example.com", timeout:0}, expectedErrorCode:"INVALID_ARGUMENT"},
            // TEST-NET 地址不提供 DNS 服务，用很短的超时稳定验证 TIMEOUT 回调。
            {name:"timeout-expired", options:{domain:"example.com", protocol:"udp", server:"192.0.2.1:53", timeout:20}, expectedErrorCode:"TIMEOUT"}
        ];
        var concurrentCases = [
            {name:"parallel-udp", options:{domain:"example.com", protocol:"udp", server:"1.1.1.1:53", timeout:5000}, expectedProtocol:"udp"},
            {name:"parallel-doh", options:{domain:"cloudflare.com", protocol:"doh", server:"https://dns.google/dns-query", timeout:5000}, expectedProtocol:"doh"},
            {name:"parallel-quic", options:{domain:"google.com", protocol:"quic", server:"quic://dns.adguard-dns.com:853", timeout:5000}, expectedProtocol:"quic"}
        ];

        runDNSCasesSequentially(sequentialCases, report.dns.sequential, "dns-sequential", function () {
            runDNSCasesSequentially(negativeCases, report.dns.negative, "dns-negative", function () {
                runDNSCasesConcurrently(concurrentCases, completion);
            });
        });
    }

    /**
     * 输出一次最终报告并结束脚本。finished 防止异步异常导致重复调用 $done。
     */
    function finish() {
        if (finished) {
            return;
        }
        finished = true;
        report.ok = failures.length === 0;
        report.finishedAt = new Date().toISOString();
        report.durationMs = Date.now() - startedAt;
        var output = JSON.stringify(report, null, 2);
        log("FINISH ok=" + report.ok + " duration=" + report.durationMs + "ms failures=" + failures.length);
        console.log(output);

        if (typeof $request !== "undefined") {
            $done({
                response:{
                    status:report.ok ? 200 : 500,
                    headers:{"Content-Type":"application/json; charset=utf-8"},
                    body:output
                }
            });
        } else {
            $done({
                title:report.ok ? "Loon Script API 测试通过" : "Loon Script API 测试失败",
                content:"耗时 " + report.durationMs + " ms，失败 " + failures.length + " 项。完整结果请查看脚本日志。"
            });
        }
    }

    try {
        validateAPIs();
        runGzipTests();
        runAESVectorTests();
        runAESWorkloadTests();
        runAESNegativeTests();
        runDNSTests(finish);
    } catch (error) {
        recordFailure("fatal", "script", error);
        finish();
    }
})();
