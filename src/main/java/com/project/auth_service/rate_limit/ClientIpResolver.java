package com.project.auth_service.rate_limit;

import com.project.auth_service.config.RateLimitProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

@Component
public class ClientIpResolver {
    private static final String X_FORWARDED_FOR = "X-Forwarded-For";

    private final List<TrustedProxy> trustedProxies;

    public ClientIpResolver(RateLimitProperties properties) {
        this.trustedProxies = properties.trustedProxies().stream()
                .filter(value -> value != null && !value.isBlank())
                .map(String::trim)
                .map(this::parseTrustedProxy)
                .filter(proxy -> proxy != null)
                .toList();
    }

    public String resolve(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        if (!isTrustedProxy(remoteAddr)) {
            return remoteAddr;
        }

        String forwardedFor = request.getHeader(X_FORWARDED_FOR);
        if (forwardedFor == null || forwardedFor.isBlank()) {
            return remoteAddr;
        }

        return firstForwardedAddress(forwardedFor).stream()
                .findFirst()
                .orElse(remoteAddr);
    }

    private List<String> firstForwardedAddress(String forwardedFor) {
        List<String> addresses = new ArrayList<>();
        for (String candidate : forwardedFor.split(",")) {
            String ip = candidate.trim();
            if (!ip.isBlank()) {
                addresses.add(ip);
                break;
            }
        }
        return addresses;
    }

    private boolean isTrustedProxy(String remoteAddr) {
        if (remoteAddr == null || remoteAddr.isBlank()) {
            return false;
        }
        return trustedProxies.stream().anyMatch(proxy -> proxy.matches(remoteAddr));
    }

    private TrustedProxy parseTrustedProxy(String value) {
        try {
            if (value.contains("/")) {
                String[] parts = value.split("/", 2);
                InetAddress network = InetAddress.getByName(parts[0]);
                int prefixLength = Integer.parseInt(parts[1]);
                if (!(network instanceof Inet4Address) || prefixLength < 0 || prefixLength > 32) {
                    return null;
                }
                return new Ipv4CidrProxy(ipv4ToInt(network), prefixLength);
            }
            return new ExactIpProxy(InetAddress.getByName(value).getHostAddress());
        } catch (Exception e) {
            return null;
        }
    }

    private int ipv4ToInt(InetAddress address) {
        byte[] bytes = address.getAddress();
        return ((bytes[0] & 0xff) << 24)
                | ((bytes[1] & 0xff) << 16)
                | ((bytes[2] & 0xff) << 8)
                | (bytes[3] & 0xff);
    }

    private interface TrustedProxy {
        boolean matches(String remoteAddr);
    }

    private record ExactIpProxy(String address) implements TrustedProxy {
        @Override
        public boolean matches(String remoteAddr) {
            try {
                return address.equals(InetAddress.getByName(remoteAddr).getHostAddress());
            } catch (Exception e) {
                return false;
            }
        }
    }

    private record Ipv4CidrProxy(int network, int prefixLength) implements TrustedProxy {
        @Override
        public boolean matches(String remoteAddr) {
            try {
                InetAddress address = InetAddress.getByName(remoteAddr);
                if (!(address instanceof Inet4Address)) {
                    return false;
                }
                int mask = prefixLength == 0 ? 0 : (int) (0xffffffffL << (32 - prefixLength));
                return (ipv4ToInt(address) & mask) == (network & mask);
            } catch (Exception e) {
                return false;
            }
        }

        private int ipv4ToInt(InetAddress address) {
            byte[] bytes = address.getAddress();
            return ((bytes[0] & 0xff) << 24)
                    | ((bytes[1] & 0xff) << 16)
                    | ((bytes[2] & 0xff) << 8)
                    | (bytes[3] & 0xff);
        }
    }
}
