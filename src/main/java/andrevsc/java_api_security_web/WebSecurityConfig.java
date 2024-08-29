package andrevsc.java_api_security_web;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.http.HttpMethod;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {

    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password("{noop}password")
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password("{noop}admin")
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // Desabilita CSRF para evitar complicações durante a configuração inicial
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers(HttpMethod.GET, "/welcome/user").hasAnyRole("USER", "ADMIN") // Apenas usuários com role USER
                .requestMatchers(HttpMethod.GET, "/welcome/admin").hasRole("ADMIN") // Apenas usuários com role ADMIN
                .requestMatchers("/welcome/all").permitAll() // Permitir acesso público a todos
                .anyRequest().authenticated() // Exigir autenticação para todas as outras requisições
            )
            .formLogin(form -> form
                .permitAll() // Usar a página de login padrão do Spring Security
            )
            .logout(logout -> logout
                .logoutUrl("/logout") // URL para logout
                .logoutSuccessUrl("/login?logout") // Redirecionar para o login após o logout
                .permitAll()
            );

        return http.build();
    }
}
