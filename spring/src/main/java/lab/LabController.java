package lab;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
public class LabController {

    // Vulnerable: nested quantifier -> catastrophic backtracking in java.util.regex.
    private static final Pattern SLUG_VULNERABLE = Pattern.compile("^([a-z0-9]+-?)*$");
    // Hardened: unambiguous -> linear.
    private static final Pattern SLUG_HARDENED = Pattern.compile("^[a-z0-9]+(?:-[a-z0-9]+)*$");

    private final boolean hardened;
    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(10);
    private final String aliceHash = bcrypt.encode("correct horse battery staple");
    private final Map<String, long[]> hits = new ConcurrentHashMap<>();

    public LabController(@Value("${lab.hardened:false}") boolean hardened) {
        this.hardened = hardened;
    }

    record Order(String sku, Integer qty) {}
    record Credentials(String username, String password) {}

    @GetMapping("/healthz")
    String healthz() {
        return "ok";
    }

    @GetMapping("/search")
    ResponseEntity<?> search(@RequestParam(defaultValue = "") String q) {
        if (hardened) {
            if (q.length() > 64) return ResponseEntity.badRequest().build();
            return ResponseEntity.ok(Map.of("q", q, "valid", SLUG_HARDENED.matcher(q).matches()));
        }
        return ResponseEntity.ok(Map.of("q", q, "valid", SLUG_VULNERABLE.matcher(q).matches()));
    }

    @PostMapping("/orders")
    ResponseEntity<Void> orders(@RequestBody Order o) {
        if (o.sku() == null || o.sku().length() > 64 || o.qty() == null || o.qty() < 1 || o.qty() > 100) {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/login")
    ResponseEntity<Void> login(@RequestBody Credentials c, HttpServletRequest req) {
        boolean limited = hardened
                // Socket peer. Spring Boot only rewrites it from X-Forwarded-For when
                // server.forward-headers-strategy is set, and then only for trusted proxies.
                ? rateLimited("ip:" + req.getRemoteAddr()) | rateLimited("user:" + c.username())
                // Vulnerable: first X-Forwarded-For entry, copied from a README.
                : rateLimited(firstForwardedFor(req));
        if (limited) return ResponseEntity.status(429).build();
        boolean ok = "alice".equals(c.username()) && c.password() != null && bcrypt.matches(c.password(), aliceHash);
        return ResponseEntity.status(ok ? 200 : 401).build();
    }

    @PostMapping("/hash")
    ResponseEntity<?> hash(@RequestBody Credentials c) throws Exception {
        String pw = c.password() == null ? "" : c.password();
        if (!hardened) {
            // Vulnerable: CPU-bound bcrypt on a virtual thread. Virtual threads
            // don't yield during pure CPU work, so a few of these pin every
            // carrier thread and cheap requests queue behind them.
            return ResponseEntity.ok(Map.of("hash", bcrypt.encode(pw)));
        }
        // Hardened: a bulkhead. Hashing runs on a small platform-thread pool with
        // a bounded queue; the carriers stay free and overflow gets a fast 503.
        try {
            return ResponseEntity.ok(Map.of("hash", HASH_POOL.submit(() -> bcrypt.encode(pw)).get()));
        } catch (RejectedExecutionException e) {
            return ResponseEntity.status(503).build();
        }
    }

    private static final ExecutorService HASH_POOL = new ThreadPoolExecutor(
            Math.max(1, Runtime.getRuntime().availableProcessors() / 2),
            Math.max(1, Runtime.getRuntime().availableProcessors() / 2),
            0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(64));

    private static String firstForwardedFor(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        return xff == null ? req.getRemoteAddr() : xff.split(",")[0].trim();
    }

    private boolean rateLimited(String key) {
        long now = System.nanoTime();
        long window = Duration.ofMinutes(1).toNanos();
        long[] e = hits.compute(key, (k, v) -> (v == null || now - v[0] > window) ? new long[] {now, 1} : new long[] {v[0], v[1] + 1});
        return e[1] > 5;
    }
}
