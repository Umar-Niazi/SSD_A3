package edu.nu.owaspapivulnlab.rate;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.Refill;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Component
public class RateLimiter {

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
    // store last wait for denied calls (7.x does not have estimateTimeToConsume)
    private final Map<String, Long> lastWaitNanos = new ConcurrentHashMap<>();

    public String keyFromIp(HttpServletRequest req, String label) {
        String xf = req.getHeader("X-Forwarded-For");
        String ip = (xf != null && !xf.isEmpty()) ? xf.split(",")[0].trim() : req.getRemoteAddr();
        return label + ":ip:" + ip;
    }

    public String keyFromUser(String username, String label) {
        if (username == null || username.isEmpty()) username = "anonymous";
        return "user:" + username + "|label:" + label;
    }

    public boolean tryConsume(String key, int capacity, Duration period) {
        Bucket b = buckets.computeIfAbsent(key, k -> newBucket(capacity, period));
        ConsumptionProbe probe = b.tryConsumeAndReturnRemaining(1);
        if (probe.isConsumed()) {
            // clear stale wait if previously set
            lastWaitNanos.remove(key);
            return true;
        } else {
            lastWaitNanos.put(key, probe.getNanosToWaitForRefill());
            return false;
        }
    }

    public long retryAfterSeconds(String key) {
        Long nanos = lastWaitNanos.get(key);
        if (nanos == null) return 60;
        long secs = TimeUnit.NANOSECONDS.toSeconds(nanos);
        return Math.max(1, secs);
    }

    private Bucket newBucket(int capacity, Duration period) {
        Bandwidth bw = Bandwidth.classic(capacity, Refill.greedy(capacity, period));
        return Bucket4j.builder().addLimit(bw).build();
    }
}
