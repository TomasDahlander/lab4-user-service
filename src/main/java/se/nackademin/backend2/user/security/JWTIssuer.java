package se.nackademin.backend2.user.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.core.GrantedAuthority;
import se.nackademin.backend2.user.domain.User;

import java.security.Key;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;


public class JWTIssuer {

    private final Key key;
    private final Duration validity;

    public JWTIssuer(final Key key, final Duration validity) {
        this.key = key;
        this.validity = validity;
    }

    public String generateToken(final User user) {

        final String authorities = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return Jwts.builder()
                .setSubject(user.getUsername())
                .claim("authorities", authorities)
                .signWith(key)
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(Instant.now().plus(validity)))
                .compact();
    }

    public User validate(String token) {
        Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();

        String authorities = (String) claims.get("authorities");
        List<String> roles = Arrays.stream(authorities.split(",")).map(r -> r.substring(5)).collect(Collectors.toList());
        return new User(claims.getSubject(), null, roles);
    }
}