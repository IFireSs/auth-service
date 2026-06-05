package com.project.auth_service.rate_limit;

import com.project.auth_service.exceptions.RequestBodyTooLargeException;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {
    private final byte[] body;

    public CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
        this(request, Integer.MAX_VALUE);
    }

    public CachedBodyHttpServletRequest(HttpServletRequest request, int maxBodyBytes) throws IOException {
        super(request);
        this.body = readBody(request, maxBodyBytes);
    }

    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(body);
        return new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return inputStream.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener listener) {
                throw new UnsupportedOperationException();
            }

            @Override
            public int read() {
                return inputStream.read();
            }
        };
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(getInputStream(), requestCharset()));
    }

    public byte[] getCachedBody() {
        return body;
    }

    private Charset requestCharset() {
        String encoding = getCharacterEncoding();
        if (encoding == null || encoding.isBlank()) {
            return StandardCharsets.UTF_8;
        }
        return Charset.forName(encoding);
    }

    private byte[] readBody(HttpServletRequest request, int maxBodyBytes) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(Math.min(maxBodyBytes, 1024));
        byte[] buffer = new byte[1024];
        int total = 0;
        int read;
        ServletInputStream inputStream = request.getInputStream();
        while ((read = inputStream.read(buffer)) != -1) {
            total += read;
            if (total > maxBodyBytes) {
                throw new RequestBodyTooLargeException(maxBodyBytes);
            }
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }
}
