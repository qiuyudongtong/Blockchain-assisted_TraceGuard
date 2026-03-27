package org.fisco.bcos.asset.client;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.fisco.bcos.asset.contract.TraceGuard;
import org.fisco.bcos.sdk.BcosSDK;
import org.fisco.bcos.sdk.abi.datatypes.DynamicArray;
import org.fisco.bcos.sdk.client.Client;
import org.fisco.bcos.sdk.crypto.keypair.CryptoKeyPair;
import org.fisco.bcos.sdk.model.TransactionReceipt;

import java.io.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.*;

public class TrafficWebServer {
    private static TraceGuard traceGuard;
    private static Client client;
    private static final Gson gson = new Gson();
    private static final String SALT = "My_Project_Salt_2026";
    private static final String IP_MAP_FILE = "ip_map.properties";

    public static void main(String[] args) throws Exception {
        // 1. 初始化区块链
        BcosSDK sdk = BcosSDK.build("dist/conf/config.toml");
        client = sdk.getClient(Integer.valueOf(1));
        CryptoKeyPair keyPair = client.getCryptoSuite().createKeyPair("YOUR_KEY");

        Properties prop = new Properties();
        prop.load(new FileInputStream("dist/conf/contract.properties"));
        traceGuard = TraceGuard.load(prop.getProperty("address"), client, keyPair);

        // 2. 启动服务
        HttpServer server = HttpServer.create(new InetSocketAddress(9000), 0);

        server.createContext("/", new StaticFileHandler());
        server.createContext("/api/list", new ListHandler());      // 全量
        server.createContext("/api/query", new QueryHandler());    // 多维度查询
        server.createContext("/api/add", new AddHandler());        // 增
        server.createContext("/api/revoke", new RevokeHandler());  // 删
        server.createContext("/api/update", new UpdateHandler());  // 改
        server.createContext("/api/stats", new StatsHandler());    // 看板统计
        server.createContext("/api/detect", new DetectHandler());  // 网页启动检测
        server.createContext("/api/details", new DetailsHandler());// 证据原件审计

        server.setExecutor(null);
        System.out.println("✅ TraceGuard 工业级后端已就绪: http://localhost:9000");
        server.start();
    }

    /**
     * 1. 网页触发 Python 检测 (第四阶段实现)
     */
    static class DetectHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String count = getParams(exchange).getOrDefault("count", "10");
            new Thread(() -> {
                try {
                    System.out.println(">>> [Web指令] 正在启动本地 Python 检测引擎...");
                    Process p = Runtime.getRuntime().exec("python3 ../detect_service.py " + count);
                    p.waitFor();
                    System.out.println(">>> [Web指令] Python 检测序列执行完毕。");
                } catch (Exception e) { e.printStackTrace(); }
            }).start();
            sendResponse(exchange, "{\"msg\":\"Detection sequence started\"}", 200);
        }
    }

    /**
     * 2. 证据详情获取 (已适配 Linux 路径)
     */
    static class DetailsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String featHash = getParams(exchange).get("hash");

            // 1. 定义虚拟机的绝对路径前缀
            String baseDir = ".../dl_detection/";

            // 2. 修改文件查找逻辑
            File file = new File(baseDir + "archived_evidence/evidence_" + featHash + ".json");
            if (!file.exists()) {
                file = new File(baseDir + "exchange_folder/evidence_" + featHash + ".json");
            }

            if (file.exists()) {
                String content = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
                sendResponse(exchange, content, 200);
            } else {
                sendResponse(exchange, "{\"error\":\"本地审计文件不存在\"}", 404);
            }
        }
    }
    /**
     * 3.  QueryHandler (实现 IP 哈希还原)
     */
    static class QueryHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Map<String, String> params = getParams(exchange);
            try {
                Object response;
                if (params.containsKey("ip") && !params.get("ip").isEmpty()) {
                    response = traceGuard.getHistoryByIp(hashIp(params.get("ip"), SALT));
                } else {
                    // 多维度筛选逻辑
                    long start = parseDate(params.get("start"), 0);
                    long end = parseDate(params.get("end"), Long.MAX_VALUE);
                    BigInteger minC = new BigInteger(params.getOrDefault("minConf", "0"));
                    response = traceGuard.getHistoryAdvanced(BigInteger.valueOf(start), BigInteger.valueOf(end), minC, params.getOrDefault("version", ""));
                }
                sendResponse(exchange, gson.toJson(serializeList(response)), 200);
            } catch (Exception e) { sendResponse(exchange, "[]", 200); }
        }
    }

    /**
     * 将链上 Hash 还原为明文 IP
     */
    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> serializeList(Object response) {
        List<TraceGuard.Struct0> history;
        if (response instanceof DynamicArray) {
            history = (List<TraceGuard.Struct0>) ((DynamicArray<?>) response).getValue();
        } else {
            history = (List<TraceGuard.Struct0>) response;
        }

        // 加载本地映射字典
        Map<String, String> ipLookup = loadIpMappings();

        List<Map<String, Object>> result = new ArrayList<>();
        if (history != null) {
            for (TraceGuard.Struct0 row : history) {
                Map<String, Object> map = new HashMap<>();
                map.put("id", row.id.toString());
                map.put("evidenceHash", row.evidenceHash);

                // 还原明文 IP
                String plainIp = ipLookup.getOrDefault(row.ipHash, row.ipHash.substring(0, 8) + "...");
                map.put("ipHash", plainIp); // 存的是翻译后的 IP

                map.put("modelVersion", row.modelVersion);
                map.put("timestamp", row.timestamp.toString());
                map.put("blockHeight", row.blockHeight.toString());
                map.put("confidence", row.confidence.toString());
                map.put("status", row.status);
                result.add(map);
            }
        }
        return result;
    }

    private static Map<String, String> loadIpMappings() {
        Map<String, String> map = new HashMap<>();
        try {
            Properties prop = new Properties();
            File file = new File(IP_MAP_FILE);
            if (file.exists()) {
                try (FileInputStream fis = new FileInputStream(file)) { prop.load(fis); }
                for (String key : prop.stringPropertyNames()) map.put(key, prop.getProperty(key));
            }
        } catch (Exception ignored) {}
        return map;
    }

    // --- 基础 Handler 和工具 ---

    static class ListHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            try {
                Object response = traceGuard.getHistoryAdvanced(BigInteger.ZERO, BigInteger.valueOf(Long.MAX_VALUE), BigInteger.ZERO, "");
                sendResponse(exchange, gson.toJson(serializeList(response)), 200);
            } catch (Exception e) { sendResponse(exchange, "[]", 200); }
        }
    }

    static class StatsHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            try {
                Object response = traceGuard.getHistoryAdvanced(BigInteger.ZERO, BigInteger.valueOf(Long.MAX_VALUE), BigInteger.ZERO, "");
                List<Map<String, Object>> allData = serializeList(response);
                Map<String, Object> stats = new HashMap<>();
                stats.put("total", allData.size());
                stats.put("blockHeight", client.getBlockNumber().getBlockNumber().toString());
                long invalid = allData.stream().filter(m -> "Invalid".equals(m.get("status"))).count();
                stats.put("invalid", invalid);
                stats.put("active", allData.size() - invalid);

                Map<String, Integer> trend = new TreeMap<>();
                SimpleDateFormat sdf = new SimpleDateFormat("MM-dd");
                for (Map<String, Object> m : allData) {
                    String date = sdf.format(new Date(Long.parseLong(m.get("timestamp").toString())));
                    trend.put(date, trend.getOrDefault(date, 0) + 1);
                }
                stats.put("trend", trend);
                sendResponse(exchange, gson.toJson(stats), 200);
            } catch (Exception e) { sendResponse(exchange, "{}", 500); }
        }
    }

    // Add, Revoke, Update ...
    static class AddHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            Map<String, String> p = getParams(exchange);
            try {
                String ipHash = hashIp(p.get("ip"), SALT);
                TransactionReceipt r = traceGuard.uploadEvidence("web_man_"+System.currentTimeMillis(), ipHash, "Web-Portal", new BigInteger(p.get("confidence")));
                sendResponse(exchange, "{\"msg\":\"上链成功\",\"hash\":\""+r.getTransactionHash()+"\"}", 200);
            } catch (Exception e) { sendResponse(exchange, e.getMessage(), 500); }
        }
    }

    static class RevokeHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            try {
                TransactionReceipt r = traceGuard.revokeEvidence(new BigInteger(getParams(exchange).get("id")));
                sendResponse(exchange, "{\"status\":\""+r.getStatus()+"\"}", 200);
            } catch (Exception e) { sendResponse(exchange, "error", 500); }
        }
    }

    static class UpdateHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            try {
                Map<String, String> p = getParams(exchange);
                TransactionReceipt r = traceGuard.updateConfidence(new BigInteger(p.get("id")), new BigInteger(p.get("confidence")));
                sendResponse(exchange, "{\"status\":\""+r.getStatus()+"\"}", 200);
            } catch (Exception e) { sendResponse(exchange, "error", 500); }
        }
    }

    static class StaticFileHandler implements HttpHandler {
        @Override public void handle(HttpExchange exchange) throws IOException {
            File file = new File("src/main/resources/web/index.html");
            byte[] bytes = Files.readAllBytes(file.toPath());
            sendResponse(exchange, new String(bytes, StandardCharsets.UTF_8), 200);
        }
    }

    private static Map<String, String> getParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery();
        if (query == null) return result;
        for (String param : query.split("&")) {
            String[] entry = param.split("=");
            if (entry.length > 1) result.put(entry[0], entry[1]);
        }
        return result;
    }

    private static long parseDate(String s, long d) {
        try { return new SimpleDateFormat("yyyy-MM-dd").parse(s).getTime(); } catch(Exception e) { return d; }
    }

    private static String hashIp(String ip, String salt) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest((ip + salt).getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) { String hex = Integer.toHexString(0xff & b); if (hex.length() == 1) hexString.append('0'); hexString.append(hex); }
        return hexString.toString();
    }

    private static void sendResponse(HttpExchange exchange, String content, int code) throws IOException {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        String type = (content.startsWith("{") || content.startsWith("[")) ? "application/json" : "text/html";
        exchange.getResponseHeaders().set("Content-Type", type + "; charset=utf-8");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(code, bytes.length);
        OutputStream os = exchange.getResponseBody();
        os.write(bytes);
        os.close();
    }
}