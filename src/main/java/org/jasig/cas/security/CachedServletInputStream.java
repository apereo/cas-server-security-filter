package org.jasig.cas.security;

import javax.servlet.ServletInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * A servlet input stream that caches the contents of
 * the given output stream.
 * @author Misagh Moayyed
 * @since 2.0.1
 */
public final class CachedServletInputStream extends ServletInputStream {
    private ByteArrayInputStream input;

    public CachedServletInputStream(final ByteArrayOutputStream cachedData) {
        input = new ByteArrayInputStream(cachedData.toByteArray());
    }

    @Override
    public int read() throws IOException {
        return input.read();
    }
}

