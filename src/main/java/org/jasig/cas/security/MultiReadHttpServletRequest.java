package org.jasig.cas.security;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

/**
 * A servlet request implementation which allows the request body
 * to be read more than once by caching the internal input stream. This is
 * required because once any filter consumes the request to check for
 * parameters, etc the request body is consumed and parameters lost specially
 * in the case of POST where parameters are submitted in the request body.
 * @author Misagh Moayyed
 * @since 2.0.1
 */
public final class MultiReadHttpServletRequest extends HttpServletRequestWrapper {

    private ByteArrayOutputStream cachedBytes;
    public MultiReadHttpServletRequest(final HttpServletRequest request) {
        super(request);

        try {
            cacheInputStream();
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        return new CachedServletInputStream(cachedBytes);
    }

    @Override
    public BufferedReader getReader() throws IOException {
        return new BufferedReader(new InputStreamReader(getInputStream()));
    }

    private void cacheInputStream() throws IOException {
        this.cachedBytes = new ByteArrayOutputStream();
        copyStream(super.getInputStream(), this.cachedBytes);
    }

    private long copyStream(final InputStream input, final OutputStream output)
            throws IOException {
        return copyStream(input, output, new byte[1024 * 4]);
    }

    private long copyStream(final InputStream input, final OutputStream output, final byte[] buffer)
            throws IOException {
        long count = 0;
        int n = 0;
        while (-1 != (n = input.read(buffer))) {
            output.write(buffer, 0, n);
            count += n;
        }
        return count;
    }
}
