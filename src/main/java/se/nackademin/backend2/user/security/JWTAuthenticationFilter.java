package se.nackademin.backend2.user.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import se.nackademin.backend2.user.domain.User;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Optional;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private static final Logger LOG = LoggerFactory.getLogger(JWTAuthenticationFilter.class);

    private AuthenticationManager authenticationManager;
    private JWTIssuer jwtIssuer;
    private ObjectMapper objectMapper;

    public JWTAuthenticationFilter(final AuthenticationManager authenticationManager, final JWTIssuer jwtIssuer, final ObjectMapper objectMapper) {
        this.authenticationManager = authenticationManager;
        this.jwtIssuer = jwtIssuer;
        this.objectMapper = objectMapper;
    }


    @Override
    public Authentication attemptAuthentication(final HttpServletRequest req,
                                                final HttpServletResponse res) throws AuthenticationException {
        return getPrincipal(req)
                .map(user -> authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                user.getUsername(),
                                user.getPassword(),
                                new ArrayList<>()))
                )
                .orElse(null);
    }

    private Optional<UserDto> getPrincipal(HttpServletRequest req) {
        try {
            return Optional.of(objectMapper.readValue(req.getInputStream().readAllBytes(), UserDto.class));
        } catch (IOException e) {
            LOG.info("Unable to fetch user from request");
            return Optional.empty();
        }
    }

    @Override
    protected void successfulAuthentication(final HttpServletRequest req,
                                            final HttpServletResponse res,
                                            final FilterChain chain,
                                            final Authentication auth) throws IOException {

        /*
            TODO: Uppgift 3
            Vi är nu i ett authentication filter. Dvs något där vi kan föra saker med requestet innan det kommer till applikationen.
            Det vi vill göra i detta filter är att vi vill istället för att returera "Du är inloggad!" så vill vi returnera
            en JWT-token.

            Vi har registrerat detta filter så att det kommer att köras efter det att en användare har authentiserats och med oss
            har vi en "Authentication auth" med användarinformationen. Du kan komma åt användaren genom
            User user = (User) auth.getPrincipal()

            Kolla på JWTIssuer för att se hur man genererar tokens.
            Returnera en JWT-token från denna klass.

            Testa i swagger att logga in igen, och då borde ni få en token tillbaka

            Öppna https://jwt.io/ och pasta in er token
            Kolla på resultatet.
         */

        User user = (User) auth.getPrincipal();

        String token = jwtIssuer.generateToken(user);

        res.getWriter().write(token);
        res.getWriter().flush();



    }


}