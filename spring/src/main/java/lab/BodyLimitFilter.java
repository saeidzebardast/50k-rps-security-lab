package lab;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Tomcat limits form posts (server.tomcat.max-http-form-post-size) but not
 * JSON bodies. This filter rejects an oversized Content-Length up front and
 * counts bytes for chunked bodies.
 */
@Component
@Profile("hardened")
@Order(Ordered.HIGHEST_PRECEDENCE)
public class BodyLimitFilter extends OncePerRequestFilter {

    static final long MAX_BYTES = 64 * 1024;

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        if (req.getContentLengthLong() > MAX_BYTES) {
            res.setHeader("Connection", "close");
            res.sendError(413);
            return;
        }
        try {
            chain.doFilter(new Limited(req), res);
        } catch (Exception e) {
            if (hasCause(e, TooLarge.class) && !res.isCommitted()) {
                res.resetBuffer();
                res.setHeader("Connection", "close");
                res.sendError(413);
                return;
            }
            throw e;
        }
    }

    private static boolean hasCause(Throwable t, Class<?> type) {
        for (; t != null; t = t.getCause()) if (type.isInstance(t)) return true;
        return false;
    }

    static final class TooLarge extends IOException {
        TooLarge() { super("request body exceeds " + MAX_BYTES + " bytes"); }
    }

    private static final class Limited extends HttpServletRequestWrapper {
        private ServletInputStream stream;

        Limited(HttpServletRequest req) { super(req); }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (stream == null) {
                ServletInputStream in = super.getInputStream();
                stream = new ServletInputStream() {
                    long count;

                    private void add(long n) throws TooLarge {
                        if (n > 0 && (count += n) > MAX_BYTES) throw new TooLarge();
                    }

                    @Override public int read() throws IOException {
                        int b = in.read();
                        if (b >= 0) add(1);
                        return b;
                    }

                    @Override public int read(byte[] buf, int off, int len) throws IOException {
                        int n = in.read(buf, off, len);
                        add(n);
                        return n;
                    }

                    @Override public boolean isFinished() { return in.isFinished(); }
                    @Override public boolean isReady() { return in.isReady(); }
                    @Override public void setReadListener(ReadListener l) { in.setReadListener(l); }
                };
            }
            return stream;
        }
    }
}
