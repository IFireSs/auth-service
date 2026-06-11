package com.project.auth_service.rate_limit;

import com.project.auth_service.config.RateLimitProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

@Component
public class ClientIpResolver {
    private static final String X_FORWARDED_FOR = "X-Forwarded-For";
    private static final int MAX_FORWARDED_ADDRESSES = 10;
    private static final Pattern IPV6_LITERAL = Pattern.compile("[0-9a-fA-F:.]+");

    private final List<TrustedProxy> trustedProxies;

    public ClientIpResolver(RateLimitProperties properties) {
        this.trustedProxies = properties.trustedProxies().stream()
                .filter(value -> value != null && !value.isBlank())
                .map(String::trim)
                .map(this::parseTrustedProxy)
                .toList();
    }

    public String resolve(HttpServletRequest request) {
        IpAddress remoteAddress = parseRequestAddress(request.getRemoteAddr());
        if (remoteAddress == null || !isTrustedProxy(remoteAddress)) {
            return remoteAddress == null ? request.getRemoteAddr() : remoteAddress.canonicalValue();
        }

        String forwardedFor = request.getHeader(X_FORWARDED_FOR);
        if (forwardedFor == null || forwardedFor.isBlank()) {
            return remoteAddress.canonicalValue();
        }

        String[] candidates = forwardedFor.split(",", -1);
        if (candidates.length > MAX_FORWARDED_ADDRESSES) {
            return remoteAddress.canonicalValue();
        }

        IpAddress current = remoteAddress;
        for (int index = candidates.length - 1; index >= 0; index--) {
            if (!isTrustedProxy(current)) {
                break;
            }
            IpAddress candidate = parseRequestAddress(candidates[index]);
            if (candidate == null) {
                return remoteAddress.canonicalValue();
            }
            current = candidate;
        }
        return current.canonicalValue();
    }

    private boolean isTrustedProxy(IpAddress address) {
        return trustedProxies.stream().anyMatch(proxy -> proxy.matches(address));
    }

    private TrustedProxy parseTrustedProxy(String value) {
        try {
            if (value.contains("/")) {
                String[] parts = value.split("/", 2);
                IpAddress network = parseIpLiteral(parts[0]);
                int prefixLength = Integer.parseInt(parts[1]);
                int maxPrefixLength = network.bytes().length * Byte.SIZE;
                if (prefixLength < 0 || prefixLength > maxPrefixLength) {
                    throw new IllegalArgumentException("CIDR prefix is out of range");
                }
                return new CidrProxy(network.bytes(), prefixLength);
            }
            return new ExactIpProxy(parseIpLiteral(value).bytes());
        } catch (Exception e) {
            throw new IllegalStateException("Invalid trusted proxy IP or CIDR: " + value, e);
        }
    }

    private IpAddress parseRequestAddress(String value) {
        try {
            return parseIpLiteral(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private IpAddress parseIpLiteral(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("IP address is blank");
        }
        String candidate = value.trim();
        byte[] bytes = candidate.contains(":")
                ? parseIpv6Literal(candidate)
                : parseIpv4Literal(candidate);
        try {
            return new IpAddress(bytes, InetAddress.getByAddress(bytes).getHostAddress());
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IP address: " + value, e);
        }
    }

    private byte[] parseIpv4Literal(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address: " + value);
        }

        byte[] address = new byte[4];
        for (int index = 0; index < parts.length; index++) {
            String part = parts[index];
            if (part.isBlank() || part.length() > 3 || !part.chars().allMatch(Character::isDigit)) {
                throw new IllegalArgumentException("Invalid IPv4 address: " + value);
            }
            int octet = Integer.parseInt(part);
            if (octet > 255) {
                throw new IllegalArgumentException("Invalid IPv4 address: " + value);
            }
            address[index] = (byte) octet;
        }
        return address;
    }

    private byte[] parseIpv6Literal(String value) {
        if (!IPV6_LITERAL.matcher(value).matches()) {
            throw new IllegalArgumentException("Invalid IPv6 address: " + value);
        }
        try {
            byte[] address = InetAddress.getByName(value).getAddress();
            if (address.length != 16) {
                throw new IllegalArgumentException("Invalid IPv6 address: " + value);
            }
            return address;
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IPv6 address: " + value, e);
        }
    }

    private interface TrustedProxy {
        boolean matches(IpAddress address);
    }

    private record ExactIpProxy(byte[] address) implements TrustedProxy {
        @Override
        public boolean matches(IpAddress candidate) {
            return Arrays.equals(address, candidate.bytes());
        }
    }

    private record CidrProxy(byte[] network, int prefixLength) implements TrustedProxy {
        @Override
        public boolean matches(IpAddress candidate) {
            byte[] address = candidate.bytes();
            if (network.length != address.length) {
                return false;
            }

            int completeBytes = prefixLength / Byte.SIZE;
            int remainingBits = prefixLength % Byte.SIZE;
            for (int index = 0; index < completeBytes; index++) {
                if (network[index] != address[index]) {
                    return false;
                }
            }
            if (remainingBits == 0) {
                return true;
            }
            int mask = 0xff << (Byte.SIZE - remainingBits);
            return (network[completeBytes] & mask) == (address[completeBytes] & mask);
        }
    }

    private record IpAddress(byte[] bytes, String canonicalValue) {
    }
}
