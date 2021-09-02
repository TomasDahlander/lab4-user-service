package se.nackademin.backend2.user.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import se.nackademin.backend2.user.domain.User;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
    private static final Logger LOG = LoggerFactory.getLogger(JWTAuthorizationFilter.class);

    private final JWTIssuer jwtIssuer;

    public JWTAuthorizationFilter(AuthenticationManager authManager, JWTIssuer jwtIssuer) {
        super(authManager);
        this.jwtIssuer = jwtIssuer;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        String header = req.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer")) {
            chain.doFilter(req, res);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        LOG.info("Försöker att logga in: {}", token);
        if (token.startsWith("Bearer ")) {
            token = token.substring("Bearer ".length());
            User user = jwtIssuer.validate(token);
            /*
                TODO: uppgift 5
                Vi har nu fått in vår token och vi vill validera så att den är valid samt titta i den för
                att hämta ut den inloggade användaren.

                Kolla i jwtIssuer.validate
                sen kan du testa att använda metoden. Tänk på att det enbart är token som ska in, så vi kanske måste
                städa det vi får in.

                User user = jwtIssuer.validate(token);

                testa igen att skapa två användare, en ADMIN, en CUSTOMER, och testa ropa på endpointen
             */
            if (user != null) {
                return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            }

            LOG.info("Kunde inte parsa token och därför inte logga in: {}", token);

            return null;
        }

        LOG.info("Kunde inte hitta token, har du en sådan i din header?");

        return null;
    }
}
