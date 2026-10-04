package com.aethermc.luckpermssync.main;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import net.luckperms.api.LuckPerms;
import net.luckperms.api.context.Context;
import net.luckperms.api.model.group.Group;
import net.luckperms.api.model.user.User;
import net.luckperms.api.node.Node;
import org.bukkit.plugin.RegisteredServiceProvider;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * MAIN server side. Read-only: exposes LuckPerms groups and player nodes over HTTP.
 *   GET /groups        -> every group with all of its nodes
 *   GET /user/<uuid>   -> one player's nodes
 * Every request must carry the header "X-Sync-Key" with the shared secret.
 */
public final class AetherMCLuckPermsSyncMain extends JavaPlugin {

    private LuckPerms lp;
    private HttpServer http;
    private ExecutorService pool;
    private byte[] secret;
    private List<String> allowedIps;

    @Override
    public void onEnable() {
        saveDefaultConfig();

        String key = getConfig().getString("key", "");
        if (key.length() < 16 || key.startsWith("CHANGE_ME")) {
            getLogger().severe("Set a long random 'key' (16+ characters) in config.yml, then restart. Disabling.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        RegisteredServiceProvider<LuckPerms> reg = getServer().getServicesManager().getRegistration(LuckPerms.class);
        if (reg == null) {
            getLogger().severe("LuckPerms was not found. Disabling.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        lp = reg.getProvider();
        secret = key.getBytes(StandardCharsets.UTF_8);
        allowedIps = getConfig().getStringList("allowed-ips");

        int port = getConfig().getInt("port", 25599);
        String bind = getConfig().getString("bind-address", "0.0.0.0");
        try {
            http = HttpServer.create(new InetSocketAddress(bind, port), 0);
        } catch (IOException e) {
            getLogger().severe("Could not open " + bind + ":" + port + " - " + e.getMessage());
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        pool = Executors.newFixedThreadPool(2);
        http.setExecutor(pool);
        http.createContext("/", this::handle);
        http.start();
        getLogger().info("Sync endpoint listening on " + bind + ":" + port);
    }

    @Override
    public void onDisable() {
        if (http != null) http.stop(0);
        if (pool != null) pool.shutdownNow();
    }

    private void handle(HttpExchange ex) throws IOException {
        try {
            String ip = ex.getRemoteAddress().getAddress().getHostAddress();
            if (!allowedIps.isEmpty() && !allowedIps.contains(ip)) {
                send(ex, 403, error("forbidden"));
                return;
            }
            String given = ex.getRequestHeaders().getFirst("X-Sync-Key");
            if (given == null || !MessageDigest.isEqual(given.getBytes(StandardCharsets.UTF_8), secret)) {
                send(ex, 401, error("bad key"));
                return;
            }
            if (!"GET".equals(ex.getRequestMethod())) {
                send(ex, 405, error("method not allowed"));
                return;
            }

            String path = ex.getRequestURI().getPath();
            if (path.equals("/groups")) {
                send(ex, 200, groups().toString());
            } else if (path.startsWith("/user/")) {
                UUID id;
                try {
                    id = UUID.fromString(path.substring("/user/".length()));
                } catch (IllegalArgumentException bad) {
                    send(ex, 400, error("bad uuid"));
                    return;
                }
                send(ex, 200, user(id).toString());
            } else {
                send(ex, 404, error("not found"));
            }
        } catch (Exception e) {
            getLogger().warning("Request failed: " + e);
            send(ex, 500, error("internal error"));
        } finally {
            ex.close();
        }
    }

    private JsonObject groups() {
        lp.getGroupManager().loadAllGroups().join();
        JsonObject groups = new JsonObject();
        for (Group g : lp.getGroupManager().getLoadedGroups()) {
            groups.add(g.getName(), encode(g.data().toCollection()));
        }
        JsonObject root = new JsonObject();
        root.add("groups", groups);
        return root;
    }

    private JsonObject user(UUID id) {
        User u = lp.getUserManager().loadUser(id).join();
        JsonObject root = new JsonObject();
        root.add("nodes", encode(u.data().toCollection()));
        lp.getUserManager().cleanupUser(u); // unloads offline users again
        return root;
    }

    private static JsonArray encode(Collection<Node> nodes) {
        JsonArray arr = new JsonArray();
        for (Node n : nodes) {
            if (n.hasExpired()) continue;
            JsonObject o = new JsonObject();
            o.addProperty("key", n.getKey());
            o.addProperty("value", n.getValue());
            if (n.getExpiry() != null) o.addProperty("expiry", n.getExpiry().getEpochSecond());
            JsonArray ctx = new JsonArray();
            for (Context c : n.getContexts()) {
                JsonArray pair = new JsonArray();
                pair.add(c.getKey());
                pair.add(c.getValue());
                ctx.add(pair);
            }
            if (ctx.size() > 0) o.add("contexts", ctx);
            arr.add(o);
        }
        return arr;
    }

    private static void send(HttpExchange ex, int code, String body) throws IOException {
        byte[] data = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(code, data.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(data);
        }
    }

    private static String error(String msg) {
        JsonObject o = new JsonObject();
        o.addProperty("error", msg);
        return o.toString();
    }
}
