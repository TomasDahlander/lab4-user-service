package se.nackademin.backend2.user;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import se.nackademin.backend2.user.security.JWTAuthenticationFilter;
import se.nackademin.backend2.user.security.JWTAuthorizationFilter;
import se.nackademin.backend2.user.security.JWTIssuer;
import se.nackademin.backend2.user.domain.UserRepository;

import static java.lang.String.format;

@Configuration
class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JWTIssuer jwtIssuer;

    @Autowired
    public SecurityConfiguration(UserRepository userRepo, PasswordEncoder passwordEncoder, JWTIssuer jwtIssuer) {
        this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder;
        this.jwtIssuer = jwtIssuer;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        final JWTAuthenticationFilter filter = new JWTAuthenticationFilter(authenticationManager(), jwtIssuer, new ObjectMapper());
        final JWTAuthorizationFilter jwtAuthorizationFilter = new JWTAuthorizationFilter(authenticationManager(), jwtIssuer);

        http
                .csrf()
                .disable()
                .cors()
                .disable()
                .authorizeRequests()
                /* TODO: uppgift 1:
                    Testa att skapa en användare genom swagger. Du får ett fel. Endpointen kan inte kommas åt för att
                    spring security har låst ner din app.
                    Vi måste berätta att vi får komma åt allt under /user utan någon säkerhet

                    Att öppna en route kan man göra med permitAll()
                    .antMatchers(url-pattern).permitAll()

                    Se till att du kan skapa användare genom swagger.

                    200 ok! perfekt men jag får inget svar tillbaka?
                    Kolla i loggarna, vi får ett läskigt fel som vi ska se till att lösa i uppgift 2
                 */
                .antMatchers("/user/*").permitAll()
                .antMatchers("/swagger-ui/*", "/swagger-ui.html", "/webjars/**", "/v2/**", "/swagger-resources/**").permitAll()
                .antMatchers("/admin/*").hasRole("ADMIN")
                .antMatchers("/customer/*").hasRole("CUSTOMER")
                /*
                TODO: Upppgift 4:
                    Arbeta med roller
                    1. Skapa en användare i swagger med roll "ADMIN"
                    2. Skapa en använadre i swagger med roll "CUSTOMER"

                    Titta i UserResource längst ned finns det två endpoints
                    - helloAdmin
                    - helloCustomer

                   Bekanta dig med @AuthenticationPrincipal och se hur man gör för att få tillgång till den
                   inloggade användaren.

                   Begränsa dina endpoints!
                   En admin ska enbart kunna se helloAdmin
                   En customer ska enbart kunna se helloCustomer

                   Att begränsa en route till en viss roll görs genom
                   .antMatchers(url-pattern).hasRole(role-name)

                   testa att använda swagger
                   1. ropa på login och du ska då få en token tillbaka
                   2. logga in genom att trycka på Authorize uppe till höger och skriv Bearer din-token så
                   kommer den att läggas till i alla nästkommande anrop
                   3. testa att ropa på helloAdmin.
                   4. Det funkar inte :( men du borde se i loggarna att vi printar ut ditt inloggningsförsök
                   med din token.

                   Tror det är dags att leta efter uppgift 5.
                 */
                .anyRequest().authenticated().and()
                .addFilter(filter)
                .addFilter(jwtAuthorizationFilter)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /*
            TODO: Uppgift 2
                Det kraschar, tråkigt. Om vi kollar i stacktracen så får vi en nullpointer i
                JWTAuthenticationFilter.java på rad 38
                låt oss se vad den gör

                1. Vi deserialiserar användaren och det verkar gå bra (getPrincipal)
                2. Vi för söker authentisera användaren med ett UsernamePasswordAuthenticationToken och där verkar det
                smälla för att authmanagern är null. Låt oss konfigurera den,

                Vi behöver
                1. berätta hur vi hämtar användare
                2. berätta hur vi hanterar lösenord

                auth.userDetailsService(hur-du-läser-upp-din användare))
                    .passwordEncoder(din-password-encoder);

                Vi använder en password encoder för att inte spara lösenord i klartext!

                Konfigurera en authManagern enligt exemplet ovan. Testa sen att logga in via swagger

                Du ska få "Du är inloggad!" som svar.
         */
        auth.userDetailsService((username) -> userRepo.findById(username).orElseThrow(() -> new UsernameNotFoundException(":(")))
        .passwordEncoder(passwordEncoder);
    }

}